"""Static indirect-call target derivation (indirect_call_target): site
validation, the bounded runner, grading and limitations that keep a
potential table target apart from a dispatch and a dispatch apart from a
reachable path, ledger identity and replay, and the grounded planner action.
The census subprocess is replaced by recorded documents; one test runs the
real census tool when the gitignored census database is present."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from types import SimpleNamespace

import pytest

from aptrace_agent.indirect_target import (
    IndirectTargetInputError,
    IndirectTargetRunner,
    planner_summary,
    validate_site,
)
from aptrace_agent.ledger.models import EvidenceGrade
from aptrace_agent.ledger.operations import DETERMINISTIC_TOOLS, TOOL_INPUTS
from aptrace_agent.ledger.semantics import (
    DERIVATION_PARTIAL,
    DISPATCH_NOT_REACHABILITY,
    INTRAPROCEDURAL,
    POTENTIAL_TARGET,
    evidence_grade,
    evidence_limitations,
)
from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchController, ResearchSession
from aptrace_agent.research.admission import admit
from aptrace_agent.research.history import HistoricalOperations
from aptrace_agent.schemas import EvidenceObservation

from ledger_support import stack
from test_research_controller import FakePlannerClient, FakeReconciler


IMAGE = b"\x00\x01" * 64
IMAGE_SHA = hashlib.sha256(IMAGE).hexdigest()
SITES = [0xC6D8, 0xC74C, 0xEE60]
ARTIFACTS = {name: "d" * 64 for name in TOOL_INPUTS["indirect_call_target"] if name != "census_db"}


def site_doc(site="0x0000c74c", **overrides):
    doc = {
        "analysis": "indirect_target", "analysis_version": 1, "firmware_key": "autopilot868",
        "firmware_sha256": IMAGE_SHA, "site": site, "bounds": {"max_blocks": 64, "max_depth": 3},
        "mnemonic": "bx", "target_reg": "r3", "instruction_shape": "reg-indirect",
        "containing_function": None, "containing_block": "0x0000c744", "function_attributed": False,
        "pattern": "vtable-slot", "derivation_status": "PARTIAL", "resolution_status": "CONDITIONALLY_POSSIBLE",
        "patterns": [{"pattern": "vtable-slot", "load_addr": "0x0000c74a", "load_instruction": "ldr r3, [r3, #0x20]",
                      "slot_offset": 32, "slot_index": 8, "table_pointer_load": "0x0000c744",
                      "table_pointer_instruction": "ldr r3, [r0]", "table_pointer_offset": 0,
                      "receiver": {"kind": "multiple", "count": 2, "kinds": ["block-live-in", "indirect-entry"]}}],
        "candidate_targets": [{"raw_value": "0x0000c7c1", "thumb_bit": 1, "target": "0x0000c7c0",
                               "normalization": "thumb-bit-cleared", "is_code_pointer": True, "vtable": "0x00014900",
                               "entry_addr": "0x00014920", "basis": "word at vtable 0x00014900 + 0x20, IF ..."}],
        "vtables_supplied": ["0x00014900"],
        "limitations": ["a derivation is a possible target relationship, not an observed or reachable dispatch"],
    }
    doc.update(overrides)
    return {"sites": [doc]}


class FakeTool:
    def __init__(self, doc, returncode=0, raise_timeout=False):
        self.doc, self.returncode, self.raise_timeout, self.argv = doc, returncode, raise_timeout, None

    def __call__(self, argv):
        self.argv = argv
        if self.raise_timeout:
            raise subprocess.TimeoutExpired(argv, 1)
        return subprocess.CompletedProcess(argv, self.returncode, json.dumps(self.doc), "boom\n")


def runner(tmp_path, tool, sites=SITES):
    image = tmp_path / "fw.bin"
    image.write_bytes(IMAGE)
    return IndirectTargetRunner(python=tmp_path / "python3", script=tmp_path / "indirect_target.py",
                                firmware_key="autopilot868", firmware_image=image, expected_sha256=IMAGE_SHA,
                                db_path=tmp_path / "census.sqlite3", sites=lambda: sites, run=tool)


# -- runner ----------------------------------------------------------------------------------


@pytest.mark.parametrize("site", ["0xdeadbeef", "c74e", "FUN_0000c74c", "../../etc/passwd", "0xc74c --db x", "", None])
def test_only_census_indirect_sites_are_accepted(tmp_path, site):
    tool = FakeTool(site_doc())
    with pytest.raises(IndirectTargetInputError):
        runner(tmp_path, tool).resolve(site)
    assert tool.argv is None


def test_site_spellings_normalize_and_argv_is_bound(tmp_path):
    assert validate_site("0xC74C", SITES) == validate_site("c74c", SITES) == 0xC74C
    tool = FakeTool(site_doc())
    result = runner(tmp_path, tool).resolve("0xc74c")
    assert tool.argv[1:] == [str(tmp_path / "indirect_target.py"), "autopilot868", "--db",
                             str(tmp_path / "census.sqlite3"), "--site", "0x0000c74c", "--vtables-from-installations"]
    assert result.status == "ok" and result.pattern == "vtable-slot"
    assert result.resolution_status == "CONDITIONALLY_POSSIBLE"
    assert result.provenance["analysis"] == "indirect_call_target" and result.provenance["firmware_sha256"] == IMAGE_SHA


def test_bounded_failures_conclude_nothing(tmp_path):
    timed = runner(tmp_path, FakeTool(site_doc(), raise_timeout=True)).resolve("0xc74c")
    assert timed.status.startswith("bounded: timeout") and not timed.candidate_targets
    failed = runner(tmp_path, FakeTool(site_doc(), returncode=1)).resolve("0xc74c")
    assert failed.status == "failed" and "boom" in failed.planner_summary
    (tmp_path / "fw.bin").write_bytes(b"other")
    r = IndirectTargetRunner(python=tmp_path / "p", script=tmp_path / "s", firmware_key="autopilot868",
                             firmware_image=tmp_path / "fw.bin", expected_sha256=IMAGE_SHA, db_path=tmp_path / "d",
                             sites=lambda: SITES, run=FakeTool(site_doc()))
    assert r.resolve("0xc74c").status == "firmware_unavailable"


def test_mismatched_documents_are_refused(tmp_path):
    with pytest.raises(RuntimeError):
        runner(tmp_path, FakeTool(site_doc(firmware_sha256="0" * 64))).resolve("0xc74c")
    with pytest.raises(RuntimeError):
        runner(tmp_path, FakeTool(site_doc(site="0x0000c6d8"))).resolve("0xc74c")


def test_summary_keeps_potential_targets_conditional(tmp_path):
    result = runner(tmp_path, FakeTool(site_doc())).resolve("0xc74c")
    text = planner_summary(result)
    first = text.splitlines()[0]
    assert "vtable-slot" in first and "CONDITIONALLY_POSSIBLE" in first
    assert "slot +0x20 (index 8)" in text
    assert "potential target 0x0000c7c0 (IF the receiver's vptr is 0x00014900)" in text
    assert text.splitlines()[-1] == "  a potential target is not an observed dispatch, and a dispatch is not a reachable path"


# -- semantics -------------------------------------------------------------------------------


def test_grades_never_promote_a_potential_target():
    conditional = {"status": "ok", "derivation_status": "PARTIAL", "resolution_status": "CONDITIONALLY_POSSIBLE"}
    assert evidence_grade("indirect_call_target", conditional)[0] == EvidenceGrade.PROBABLE
    established = {"status": "ok", "derivation_status": "ESTABLISHED", "resolution_status": "STATICALLY_ESTABLISHED"}
    assert evidence_grade("indirect_call_target", established)[0] == EvidenceGrade.STRONG
    partial_but_constant = {"status": "ok", "derivation_status": "PARTIAL", "resolution_status": "STATICALLY_ESTABLISHED"}
    assert evidence_grade("indirect_call_target", partial_but_constant)[0] == EvidenceGrade.PROBABLE
    assert evidence_grade("indirect_call_target", {"status": "bounded: timeout 120s"})[0] == EvidenceGrade.UNKNOWN
    assert evidence_grade("indirect_call_target", {"status": "ok", "derivation_status": "UNKNOWN"})[0] == EvidenceGrade.UNKNOWN

    codes = dict(evidence_limitations("indirect_call_target", {}, conditional))
    assert {POTENTIAL_TARGET, DISPATCH_NOT_REACHABILITY, INTRAPROCEDURAL, DERIVATION_PARTIAL} <= set(codes)
    assert DERIVATION_PARTIAL not in dict(evidence_limitations("indirect_call_target", {}, established))


def test_a_possible_dispatch_does_not_admit_reachability_or_a_negative():
    result = site_doc()["sites"][0] | {"status": "ok"}
    ledger = {"E1": EvidenceObservation(id="E1", tool="indirect_call_target", arguments={"site": "0x0000c74c"},
                                        result=result)}
    session = SimpleNamespace(ledger=SimpleNamespace(get=lambda i: ledger[i]), continuity=None)

    def check(grade, claim_type, text):
        proposal = {"subject": "", "assertion": text, "grade": grade, "claim_type": claim_type, "evidence_ids": ["E1"]}
        return admit(proposal, session, round=1, function_exists=lambda name: True, peripherals=["SERCOM0"])

    assert check("STRONG", "PATH_EXISTS", "0x0000c74c dispatches to FUN_0000c7c0").decision == "rejected"
    assert check("STRONG", "UNREACHABLE", "FUN_0000c7c0 is unreachable").decision == "rejected"


# -- ledger identity and replay --------------------------------------------------------------


def test_identity_inputs_and_replay(tmp_path):
    assert "indirect_call_target" in DETERMINISTIC_TOOLS
    assert TOOL_INPUTS["indirect_call_target"][0] == "census_db"
    ledger, executor, context, ops = stack(tmp_path)
    context.artifacts.update(ARTIFACTS)
    result = runner(tmp_path, FakeTool(site_doc())).resolve("0xc74c").model_dump(mode="json")
    executor.drift["indirect_call_target"] = result
    invocation, artifact = ops.run("R-test", "indirect_call_target", {"site": "0x0000c74c"})
    assert set(invocation.input_artifacts) == set(TOOL_INPUTS["indirect_call_target"])
    other, _ = ops.run("R-test", "indirect_call_target", {"site": "0x0000c6d8"})
    assert other.operation_key != invocation.operation_key
    replay = ops.replay(invocation.invocation_id, run_id="R-replay")
    assert replay.matches
    stored, intact = ledger.evidence_result(artifact.evidence_id)
    assert intact and stored["resolution_status"] == "CONDITIONALLY_POSSIBLE"

    history = HistoricalOperations(ledger, context(), run_ids=[], evidence_ids=[artifact.evidence_id])
    assert history.lookup("indirect_call_target", {"site": "0x0000c74c"}).reusable
    context.artifacts["indirect_target_tool"] = "0" * 64
    refused = HistoricalOperations(ledger, context(), run_ids=[], evidence_ids=[artifact.evidence_id]).lookup(
        "indirect_call_target", {"site": "0x0000c74c"})
    assert not refused.reusable and "indirect_target_tool" in refused.reason


# -- planner action --------------------------------------------------------------------------


class RecordingExecutor:
    def __init__(self):
        self.calls = []

    def execute_operation(self, tool, arguments, *, evidence_id):
        self.calls.append((tool, dict(arguments)))
        if tool == "function_disassembly":
            result = {"name": "FUN_0000c5cc", "instructions": [
                {"address": "0x0000c6d8", "mnemonic": "blx", "operands": "r3"},
                {"address": "0x0000c6da", "mnemonic": "bx", "operands": "lr"}]}
        elif tool == "indirect_call_target":
            result = site_doc(arguments["site"])["sites"][0] | {"status": "ok"}
        else:
            result = {"name": arguments.get("function")}
        return EvidenceObservation(id=evidence_id, tool=tool, arguments=arguments, result=result)


def controller(**kwargs):
    return ResearchController(
        planner_client=FakePlannerClient(kwargs.pop("decisions", [])), planner_model="test", reconciler=FakeReconciler(),
        structural_tools=("function_effects", "indirect_call_target"), indirect_sites=kwargs.pop("sites", SITES), **kwargs)


def session_with(tool="function_disassembly"):
    registry = LeadRegistry()
    executor = RecordingExecutor()
    session = ResearchSession(objective="What can the indirect call in FUN_0000c5cc reach?", registry=registry,
                              follower=LeadFollower(registry=registry, executor=executor))
    session.record(executor.execute_operation(tool, {"function": "FUN_0000c5cc"}, evidence_id=session.ledger.next_id()))
    return session, executor


def test_action_is_offered_only_for_sites_present_in_evidence():
    c = controller()
    session, _ = session_with()
    palette = c._decision_palette(session)
    tool = next(t for t in palette.tools if t["function"]["name"] == "resolve_indirect_call")
    params = tool["function"]["parameters"]
    assert params["properties"]["site"]["enum"] == ["0x0000c6d8"]
    assert set(params["properties"]) == {"site"} and params["additionalProperties"] is False
    assert "not observed dispatches" in tool["function"]["description"]
    assert "resolve_indirect_call" in c._analysis_guidance(session, palette)

    facts_only, _ = session_with("function_facts")
    assert "resolve_indirect_call" not in c._decision_palette(facts_only).names()
    assert "resolve_indirect_call" not in controller(sites=())._decision_palette(session).names()


@pytest.mark.parametrize(
    "arguments, problem",
    [
        ({"site": "0x0000c74c"}, "one of the listed"),
        ({"site": "0x0000c6d9"}, "one of the listed"),
        ({"site": "0x0000c6d8", "max_blocks": 10**6}, "accepts only site"),
        ({"site": "0x0000c6d8", "vtables": ["0x14900"]}, "accepts only site"),
    ],
)
def test_planner_cannot_widen_the_operation(arguments, problem):
    c = controller()
    session, _ = session_with()
    outcome = c._parse_structural(session, c._decision_palette(session), "resolve_indirect_call", arguments)
    assert isinstance(outcome, str) and problem in outcome


def test_selection_executes_one_bounded_resolution_and_respects_the_cap():
    c = controller(decisions=[("resolve_indirect_call", {"site": "0x0000c6d8"}), ("finish", {"reason": "done"})],
                   max_indirect_targets=1, max_steps=3)
    session, executor = session_with()
    result = c.run(session)
    assert [call for call in executor.calls if call[0] == "indirect_call_target"] == [
        ("indirect_call_target", {"site": "0x0000c6d8"})]
    assert any(step.action == "indirect_target" for step in result.steps)
    assert "resolve_indirect_call" not in c._decision_palette(session).names()
    # With another grounded site still open, a repeat of a resolved site is a duplicate.
    session.record(EvidenceObservation(id=session.ledger.next_id(), tool="function_facts",
                                       arguments={"function": "FUN_0000ec48"}, result={"callers": ["0x0000ee60"]}))
    fresh = controller()
    palette = fresh._decision_palette(session)
    assert palette.indirect_sites == ["0x0000ee60"]
    duplicate = fresh._parse_structural(session, palette, "resolve_indirect_call", {"site": "0x0000c6d8"})
    assert isinstance(duplicate, str) and "already resolved" in duplicate


def test_facts_are_scoped_to_potential_targets():
    from aptrace_agent.research.fact_derivation import _indirect_target_facts

    (basis, text), = _indirect_target_facts(site_doc()["sites"][0] | {"status": "ok"})[0]
    assert basis == "static-dataflow"
    assert "slot +0x20 of the table its receiver points to" in text
    assert "potential targets 0x0000c7c0 if vptr 0x00014900" in text
    assert "not observed dispatches or reachable paths" in text
    assert _indirect_target_facts({"status": "bounded: timeout 120s"}) == ([], [])


# -- real census tool (gitignored census database) -------------------------------------------


def test_real_census_tool_on_the_slot_7_thunk():
    from aptrace_agent.census import performing_rigs_census
    from aptrace_agent.structural_wiring import performing_rigs_indirect_targets

    census = performing_rigs_census()
    if not census.db_path.is_file() or not census.firmware_image.is_file():
        pytest.skip("census database or firmware not present")
    r = performing_rigs_indirect_targets(census)
    assert 0xC74C in r.sites() and len(r.sites()) >= 56
    result = r.resolve("0xc74c")
    p = result.patterns[0]
    assert (result.pattern, p["slot_offset"], p["slot_index"]) == ("vtable-slot", 0x20, 8)
    targets = {(t["vtable"], t["target"]) for t in result.candidate_targets if t["is_code_pointer"]}
    assert ("0x00014900", "0x0000c7c0") in targets
    assert result.resolution_status == "CONDITIONALLY_POSSIBLE" and result.derivation_status == "PARTIAL"
    assert copy.deepcopy(result.model_dump()) == r.resolve("0x0000c74c").model_dump()
