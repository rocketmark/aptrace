"""One-hop caller-argument provenance (callback_argument_provenance): site
validation, the bounded runner, grades and limitations that keep a
caller-supplied value apart from a dispatch and a dispatch apart from a
reachable path, call-relation admission over its edges, ledger identity,
replay and historical reuse, and the grounded planner action. The census
subprocess is replaced by a recorded document shaped like the real
0xee60 result; one test runs the real census tool when the gitignored
census database is present."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from types import SimpleNamespace

import pytest

from aptrace_agent.callback_provenance import CallbackProvenanceRunner, IndirectTargetInputError, planner_summary
from aptrace_agent.ledger.call_relations import extract_call_facts
from aptrace_agent.ledger.claim_semantics import CallEdgeKind
from aptrace_agent.ledger.models import EvidenceGrade
from aptrace_agent.ledger.operations import DETERMINISTIC_TOOLS, TOOL_INPUTS
from aptrace_agent.ledger.semantics import (
    CALLER_SET_OPEN,
    DISPATCH_NOT_REACHABILITY,
    ONE_HOP,
    POTENTIAL_TARGET,
    PROVENANCE_BOUNDED,
    evidence_grade,
    evidence_limitations,
)
from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchController, ResearchSession
from aptrace_agent.research.admission import admit
from aptrace_agent.research.history import HistoricalOperations, current_analysis_versions
from aptrace_agent.schemas import EvidenceObservation

from ledger_support import stack
from test_research_controller import FakePlannerClient, FakeReconciler


IMAGE = b"\x00\x01" * 64
IMAGE_SHA = hashlib.sha256(IMAGE).hexdigest()
SITES = [0xC6D8, 0xC74C, 0xEE60, 0xF114]
ARTIFACTS = {name: "d" * 64 for name in TOOL_INPUTS["callback_argument_provenance"] if name != "census_db"}
CALLEE, CALLER, CALL_SITE, TARGET = "0x0000ec48", "0x0000e8a8", "0x0000eaac", "0x0000e882"


def caller(**overrides):
    rec = {
        "site": CALL_SITE, "transfer": "bl", "transfer_kind": "call", "instruction": "bl #0xec48",
        "block": "0x0000eaa0", "caller_function": CALLER, "caller_function_name": "FUN_0000e8a8",
        "conditional": False, "condition_code": None, "census_edge": True, "argument": "r3",
        "value_status": "CONCRETE", "complete": True,
        "components": [{"kind": "constant", "def_addr": "0x0000eaa6", "instruction": "ldr r3, [pc, #0x58]",
                        "basis": "literal at 0x0000eb00", "raw_value": "0x0000e883", "thumb_bit": 1, "region": "flash",
                        "validity": "VALID_THUMB_CODE_POINTER", "callable": True, "target": TARGET,
                        "target_function": "FUN_0000e882",
                        "target_reachability": {"status": "UNRESOLVED", "census": "NO_KNOWN_PATH"}}],
        "caller_reachability": {"status": "UNRESOLVED", "census": "NO_KNOWN_PATH"},
        "caller_static_path_to_transfer": True,
        "conditions": [f"{CALLEE} reaches 0x0000ee60 with the value unchanged: CFG path only, branch feasibility "
                       "not established"],
    }
    rec.update(overrides)
    return rec


def site_doc(site="0x0000ee60", target_set="OPEN", open_reasons=None, **overrides):
    c = caller()
    doc = {
        "analysis": "callback_provenance", "analysis_version": 1,
        "site_analysis": {"analysis": "indirect_target", "analysis_version": 2},
        "firmware_key": "autopilot868", "firmware_sha256": IMAGE_SHA, "site": site,
        "bounds": {"max_callers": 16, "max_blocks": 128}, "instruction": "blx r7", "target_register": "r7",
        "containing_function": CALLEE, "site_pattern": "argument", "site_derivation_status": "ESTABLISHED",
        "argument_origins": [{"function_entry": CALLEE, "function_name": "FUN_0000ec48", "argument": "r3", "arg": 3,
                              "location": "register", "callers": [c], "caller_set_complete": target_set == "CLOSED",
                              "address_taken": [] if target_set == "CLOSED" else [
                                  {"kind": "flash-word", "location": "0x0000eafc", "value": "0x0000ec49"}]}],
        "candidate_targets": [{"target": TARGET, "raw_values": ["0x0000e883"], "target_function": "FUN_0000e882",
                               "target_reachability": {"status": "UNRESOLVED"},
                               "via": [{"argument_function": CALLEE, "argument": "r3", "caller_site": CALL_SITE,
                                        "caller_function": CALLER, "basis": "literal at 0x0000eb00",
                                        "def_addr": "0x0000eaa6", "caller_value_status": "CONCRETE",
                                        "conditions": c["conditions"]}]}],
        "non_callable_values": [], "next_hops": [], "caller_value_statuses": {"CONCRETE": 1},
        "provenance_status": "CONCRETE", "target_set": target_set,
        "open_reasons": ([] if target_set == "CLOSED" else
                         [f"the entry {CALLEE} is address-taken; indirect callers are not enumerated"])
        if open_reasons is None else open_reasons,
        "incomplete_reasons": [], "recorded_coverage": {}, "work": {"blocks_visited": 0},
        "limitations": ["one hop: a caller's own incoming argument is reported as FORWARDED_ARGUMENT, never followed"],
    }
    doc.update(overrides)
    return {"sites": [doc]}


def forwarded_doc():
    fwd = caller(site="0x0000ed00", caller_function=CALLEE, value_status="FORWARDED_ARGUMENT",
                 components=[{"kind": "forwarded", "function_entry": CALLEE, "arg": 3, "argument": "r3"}],
                 next_hop=[{"function_entry": CALLEE, "argument": "r3"}])
    doc = site_doc("0x0000f114", provenance_status="FORWARDED_ARGUMENT", candidate_targets=[],
                   caller_value_statuses={"FORWARDED_ARGUMENT": 1}, containing_function="0x0000f0b4",
                   next_hops=[{"function_entry": CALLEE, "argument": "r3"}],
                   open_reasons=["caller 0x0000ed00 value is FORWARDED_ARGUMENT"])
    doc["sites"][0]["argument_origins"] = [{"function_entry": "0x0000f0b4", "argument": "stack argument 4", "arg": 4,
                                            "location": "stack", "callers": [fwd], "address_taken": []}]
    return doc


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
    return CallbackProvenanceRunner(python=tmp_path / "python3", script=tmp_path / "callback_provenance.py",
                                    firmware_key="autopilot868", firmware_image=image, expected_sha256=IMAGE_SHA,
                                    db_path=tmp_path / "census.sqlite3", sites=lambda: sites, run=tool)


# -- runner ----------------------------------------------------------------------------------


@pytest.mark.parametrize("site", ["0xdeadbeef", "ee61", "FUN_0000ec48", "../../etc/passwd", "0xee60 --db x", "", None,
                                  "0x20000100"])
def test_only_census_indirect_sites_are_accepted(tmp_path, site):
    tool = FakeTool(site_doc())
    with pytest.raises(IndirectTargetInputError):
        runner(tmp_path, tool).trace(site)
    assert tool.argv is None


def test_argv_is_bound_and_provenance_carried(tmp_path):
    tool = FakeTool(site_doc())
    result = runner(tmp_path, tool).trace("EE60")
    assert tool.argv[1:] == [str(tmp_path / "callback_provenance.py"), "autopilot868", "--db",
                             str(tmp_path / "census.sqlite3"), "--site", "0x0000ee60"]
    assert result.status == "ok" and result.provenance_status == "CONCRETE" and result.target_set == "OPEN"
    assert result.provenance["analysis"] == "callback_argument_provenance"
    assert result.provenance["engine"]["site_analysis"] == {"analysis": "indirect_target", "analysis_version": 2}
    assert result.provenance["firmware_sha256"] == IMAGE_SHA


def test_bounded_failures_conclude_nothing(tmp_path):
    timed = runner(tmp_path, FakeTool(site_doc(), raise_timeout=True)).trace("0xee60")
    assert timed.status.startswith("bounded: timeout") and not timed.candidate_targets
    failed = runner(tmp_path, FakeTool(site_doc(), returncode=1)).trace("0xee60")
    assert failed.status == "failed" and "boom" in failed.planner_summary and not failed.argument_origins
    (tmp_path / "fw.bin").write_bytes(b"other")
    r = CallbackProvenanceRunner(python=tmp_path / "p", script=tmp_path / "s", firmware_key="autopilot868",
                                 firmware_image=tmp_path / "fw.bin", expected_sha256=IMAGE_SHA, db_path=tmp_path / "d",
                                 sites=lambda: SITES, run=FakeTool(site_doc()))
    assert r.trace("0xee60").status == "firmware_unavailable"


def test_mismatched_documents_are_refused(tmp_path):
    with pytest.raises(RuntimeError):
        runner(tmp_path, FakeTool(site_doc(firmware_sha256="0" * 64))).trace("0xee60")
    with pytest.raises(RuntimeError):
        runner(tmp_path, FakeTool(site_doc(site="0x0000c6d8"))).trace("0xee60")


def test_summary_separates_values_from_dispatch(tmp_path):
    text = planner_summary(runner(tmp_path, FakeTool(site_doc())).trace("0xee60"))
    lines = text.splitlines()
    assert "provenance CONCRETE, target set OPEN" in lines[0] and "STATIC_ONE_HOP_CALLER_ARGUMENT" in lines[0]
    assert f"target = incoming r3 of {CALLEE}" in text
    assert f"{CALL_SITE} (bl, {CALLER}): CONCRETE 0x0000e883 -> {TARGET}" in text
    assert "open: the entry 0x0000ec48 is address-taken" in text
    assert lines[-1] == "  a caller-supplied value is a possible target, not an observed dispatch or a reachable path"
    fwd = planner_summary(runner(tmp_path, FakeTool(forwarded_doc())).trace("0xf114"))
    assert "FORWARDED_ARGUMENT its own incoming r3" in fwd
    assert f"next hop (not taken): what callers of {CALLEE} pass in r3" in fwd


# -- semantics -------------------------------------------------------------------------------


def test_grades_and_limitations():
    ok = lambda **kw: site_doc(**kw)["sites"][0] | {"status": "ok"}  # noqa: E731
    assert evidence_grade("callback_argument_provenance", ok(target_set="CLOSED"))[0] == EvidenceGrade.STRONG
    assert evidence_grade("callback_argument_provenance", ok())[0] == EvidenceGrade.PROBABLE
    assert evidence_grade("callback_argument_provenance", forwarded_doc()["sites"][0] | {"status": "ok"})[0] == \
        EvidenceGrade.PROBABLE
    unknown = ok(provenance_status="UNKNOWN", caller_value_statuses={"UNKNOWN": 1})
    assert evidence_grade("callback_argument_provenance", unknown)[0] == EvidenceGrade.UNKNOWN
    na = ok(provenance_status="NOT_APPLICABLE", caller_value_statuses={}, argument_origins=[])
    assert evidence_grade("callback_argument_provenance", na)[0] == EvidenceGrade.UNKNOWN
    assert evidence_grade("callback_argument_provenance", {"status": "bounded: timeout 120s"})[0] == EvidenceGrade.UNKNOWN

    codes = dict(evidence_limitations("callback_argument_provenance", {}, ok()))
    assert {ONE_HOP, POTENTIAL_TARGET, DISPATCH_NOT_REACHABILITY, CALLER_SET_OPEN} <= set(codes)
    assert CALLER_SET_OPEN not in dict(evidence_limitations("callback_argument_provenance", {}, ok(target_set="CLOSED")))
    bounded = dict(evidence_limitations("callback_argument_provenance", {},
                                        ok(incomplete_reasons=["caller bound 16 at 0x0000ec48"])))
    assert "caller bound 16" in bounded[PROVENANCE_BOUNDED]


# -- call relations --------------------------------------------------------------------------


def _session(doc):
    result = doc["sites"][0] | {"status": "ok"}
    ledger = {"E1": EvidenceObservation(id="E1", tool="callback_argument_provenance", arguments={"site": result["site"]},
                                        result=result)}
    return SimpleNamespace(ledger=SimpleNamespace(get=lambda i: ledger[i]), continuity=None)


def _admit(doc, text, grade="PROBABLE", claim_type="STRUCTURE"):
    proposal = {"subject": "", "assertion": text, "grade": grade, "claim_type": claim_type, "evidence_ids": ["E1"]}
    return admit(proposal, _session(doc), round=1, function_exists=lambda name: True, peripherals=["SERCOM0"])


def test_edges_are_direct_or_potential_never_categorical_indirect():
    facts = extract_call_facts([(SimpleNamespace(evidence_id="E1", tool="callback_argument_provenance",
                                                 arguments={}, grade=None),
                                 site_doc(target_set="CLOSED")["sites"][0] | {"status": "ok"})])
    kinds = {(e.source, e.target, e.kind) for e in facts.edges}
    assert (0xE8A8, 0xEC48, CallEdgeKind.DIRECT_CALL) in kinds
    assert (0xEC48, 0xE882, CallEdgeKind.POTENTIAL_INDIRECT) in kinds
    assert not any(e.kind == CallEdgeKind.ESTABLISHED_INDIRECT for e in facts.edges)
    potential = next(e for e in facts.edges if e.kind == CallEdgeKind.POTENTIAL_INDIRECT)
    assert 0xEAAC in potential.condition_addresses and "IF entered from caller site 0x0000eaac" in potential.conditions[0]


def test_admission_keeps_caller_grounded_targets_conditional():
    doc = site_doc()
    # The direct call the result decodes is an established relation.
    assert _admit(doc, "FUN_0000e8a8 calls FUN_0000ec48").decision == "admitted"
    # A categorical dispatch from a caller-supplied value is rejected.
    assert _admit(doc, "FUN_0000ec48 calls FUN_0000e882").decision == "rejected"
    assert _admit(doc, "FUN_0000ec48 can call FUN_0000e882").decision == "rejected"
    # Conditional wording that names the caller site is the evidence's own scope.
    record = _admit(doc, "FUN_0000ec48 may call FUN_0000e882 if entered from the call at 0x0000eaac")
    assert record.decision == "admitted", record.diagnostics
    # Reachability and absence are not supported by a possible target.
    assert _admit(doc, "FUN_0000e882 is reachable", claim_type="PATH_EXISTS").decision == "rejected"
    assert _admit(doc, "FUN_0000ec48 never calls FUN_0000c744", grade="STRONG",
                  claim_type="NO_KNOWN_PATH").decision == "rejected"
    # A forwarded value names no target: no dispatch claim is supported.
    assert _admit(forwarded_doc(), "FUN_0000f0b4 may call FUN_0000e882 if entered from 0x0000ed00").decision == "rejected"


# -- ledger identity and replay --------------------------------------------------------------


def test_identity_inputs_replay_and_reuse(tmp_path):
    assert "callback_argument_provenance" in DETERMINISTIC_TOOLS
    assert current_analysis_versions()["callback_argument_provenance"] == 1
    assert {"census_db", "callback_provenance_tool", "indirect_target_tool", "census_slot_dispatch"} <= \
        set(TOOL_INPUTS["callback_argument_provenance"])
    ledger, executor, context, ops = stack(tmp_path)
    context.artifacts.update(ARTIFACTS)
    result = runner(tmp_path, FakeTool(site_doc())).trace("0xee60").model_dump(mode="json")
    executor.drift["callback_argument_provenance"] = result
    invocation, artifact = ops.run("R-test", "callback_argument_provenance", {"site": "0x0000ee60"})
    assert set(invocation.input_artifacts) == set(TOOL_INPUTS["callback_argument_provenance"])
    other, _ = ops.run("R-test", "callback_argument_provenance", {"site": "0x0000f114"})
    assert other.operation_key != invocation.operation_key
    # Same site, other operation: identities differ.
    executor.drift["indirect_call_target"] = {"status": "ok", "site": "0x0000ee60"}
    sibling, _ = ops.run("R-test", "indirect_call_target", {"site": "0x0000ee60"})
    assert sibling.operation_key != invocation.operation_key
    replay = ops.replay(invocation.invocation_id, run_id="R-replay")
    assert replay.matches
    stored, intact = ledger.evidence_result(artifact.evidence_id)
    assert intact and stored["provenance_status"] == "CONCRETE" and stored["target_set"] == "OPEN"

    history = HistoricalOperations(ledger, context(), run_ids=[], evidence_ids=[artifact.evidence_id])
    assert history.lookup("callback_argument_provenance", {"site": "0x0000ee60"}).reusable
    assert history.lookup("callback_argument_provenance", {"site": "0x0000f114"}) is None
    versions = HistoricalOperations(ledger, context(), run_ids=[], evidence_ids=[artifact.evidence_id],
                                    analysis_versions={**current_analysis_versions(), "callback_argument_provenance": 2})
    assert not versions.lookup("callback_argument_provenance", {"site": "0x0000ee60"}).reusable
    for name in ("callback_provenance_tool", "indirect_target_tool", "census_slot_dispatch"):
        context.artifacts[name] = "0" * 64
        refused = HistoricalOperations(ledger, context(), run_ids=[], evidence_ids=[artifact.evidence_id]).lookup(
            "callback_argument_provenance", {"site": "0x0000ee60"})
        assert not refused.reusable and name in refused.reason
        context.artifacts[name] = "d" * 64


# -- planner action --------------------------------------------------------------------------


class RecordingExecutor:
    def __init__(self):
        self.calls = []

    def execute_operation(self, tool, arguments, *, evidence_id):
        self.calls.append((tool, dict(arguments)))
        if tool == "function_disassembly":
            result = {"name": "FUN_0000ec48", "instructions": [
                {"address": "0x0000ee60", "mnemonic": "blx", "operands": "r7"},
                {"address": "0x0000c6d8", "mnemonic": "blx", "operands": "r3"}]}
        elif tool == "indirect_call_target":
            pattern = "argument" if arguments["site"] == "0x0000f114" else "vtable-slot"
            result = {"status": "ok", "site": arguments["site"], "patterns": [{"pattern": pattern, "arg": 4}]}
        elif tool == "callback_argument_provenance":
            result = site_doc(arguments["site"])["sites"][0] | {"status": "ok"}
        else:
            result = {"name": arguments.get("function")}
        return EvidenceObservation(id=evidence_id, tool=tool, arguments=arguments, result=result)


def controller(**kwargs):
    return ResearchController(
        planner_client=FakePlannerClient(kwargs.pop("decisions", [])), planner_model="test", reconciler=FakeReconciler(),
        structural_tools=("indirect_call_target", "callback_argument_provenance"),
        indirect_sites=kwargs.pop("sites", SITES), **kwargs)


def session_with(tool="function_disassembly"):
    registry = LeadRegistry()
    executor = RecordingExecutor()
    session = ResearchSession(objective="Where does the callback in FUN_0000ec48 come from?", registry=registry,
                              follower=LeadFollower(registry=registry, executor=executor))
    session.record(executor.execute_operation(tool, {"function": "FUN_0000ec48"}, evidence_id=session.ledger.next_id()))
    return session, executor


def test_action_is_offered_only_for_grounded_sites():
    c = controller()
    session, _ = session_with()
    palette = c._decision_palette(session)
    tool = next(t for t in palette.tools if t["function"]["name"] == "trace_callback_argument")
    params = tool["function"]["parameters"]
    assert params["properties"]["site"]["enum"] == ["0x0000ee60", "0x0000c6d8"]
    assert set(params["properties"]) == {"site"} and params["additionalProperties"] is False
    assert "not a dispatch or a reachable path" in tool["function"]["description"]
    assert "trace_callback_argument" in c._analysis_guidance(session, palette)

    facts_only, _ = session_with("function_facts")
    assert "trace_callback_argument" not in c._decision_palette(facts_only).names()
    assert "trace_callback_argument" not in controller(sites=())._decision_palette(session).names()
    without = ResearchController(planner_client=FakePlannerClient([]), planner_model="test", reconciler=FakeReconciler(),
                                 structural_tools=("indirect_call_target",), indirect_sites=SITES)
    assert "trace_callback_argument" not in without._decision_palette(session).names()


def test_argument_sites_from_indirect_results_are_offered_first():
    c = controller()
    session, executor = session_with()
    session.record(executor.execute_operation("indirect_call_target", {"site": "0x0000f114"},
                                              evidence_id=session.ledger.next_id()))
    assert c._decision_palette(session).callback_sites[0] == "0x0000f114"


@pytest.mark.parametrize(
    "arguments, problem",
    [
        ({"site": "0x0000c74c"}, "one of the listed"),
        ({"site": "0x0000ee61"}, "one of the listed"),
        ({"site": "0x0000ee60", "max_callers": 10**6}, "accepts only site"),
        ({"site": "0x0000ee60", "hops": 3}, "accepts only site"),
        ({"site": "0x0000ee60", "path": "/etc/passwd"}, "accepts only site"),
    ],
)
def test_planner_cannot_widen_the_operation(arguments, problem):
    c = controller()
    session, _ = session_with()
    outcome = c._parse_structural(session, c._decision_palette(session), "trace_callback_argument", arguments)
    assert isinstance(outcome, str) and problem in outcome


def test_selection_executes_bounded_traces_and_respects_the_cap():
    c = controller(decisions=[("trace_callback_argument", {"site": "0x0000ee60"}),
                              ("trace_callback_argument", {"site": "0x0000c6d8"}),
                              ("finish", {"reason": "done"})], max_steps=4)
    session, executor = session_with()
    result = c.run(session)
    traced = [call for call in executor.calls if call[0] == "callback_argument_provenance"]
    assert traced == [("callback_argument_provenance", {"site": "0x0000ee60"}),
                      ("callback_argument_provenance", {"site": "0x0000c6d8"})]
    assert sum(step.action == "callback_provenance" for step in result.steps) == 2
    # The cap (two per session) withdraws the action.
    assert "trace_callback_argument" not in c._decision_palette(session).names()
    # With another grounded site still open, a repeat of a traced site is a duplicate.
    session.record(EvidenceObservation(id=session.ledger.next_id(), tool="function_facts",
                                       arguments={"function": "FUN_0000f0b4"}, result={"callers": ["0x0000f114"]}))
    fresh = controller(max_callback_traces=3)
    assert fresh._decision_palette(session).callback_sites == ["0x0000f114"]
    duplicate = fresh._parse_structural(session, fresh._decision_palette(session), "trace_callback_argument",
                                        {"site": "0x0000ee60"})
    assert isinstance(duplicate, str) and "already traced" in duplicate


def test_facts_are_scoped_to_caller_supplied_values():
    from aptrace_agent.research.fact_derivation import _callback_provenance_facts

    (basis, text), = _callback_provenance_facts(site_doc()["sites"][0] | {"status": "ok"})[0]
    assert basis == "static-dataflow"
    assert f"its target is incoming r3 of {CALLEE}" in text and f"{CALL_SITE} ({CALLER}) passes 0x0000e883 [CONCRETE]" in text
    assert "possible targets 0x0000e882" in text and "(set OPEN)" in text
    assert "not observed dispatches or reachable paths" in text
    _, questions = _callback_provenance_facts(forwarded_doc()["sites"][0] | {"status": "ok"})
    assert questions[0] == f"What do callers of {CALLEE} pass in r3? (next hop for 0x0000f114)"
    assert _callback_provenance_facts({"status": "bounded: timeout 120s"}) == ([], [])


# -- real census tool (gitignored census database) -------------------------------------------


def test_real_census_tool_on_the_e8a8_ec48_callback():
    from aptrace_agent.census import performing_rigs_census
    from aptrace_agent.structural_wiring import performing_rigs_callback_provenance

    census = performing_rigs_census()
    if not census.db_path.is_file() or not census.firmware_image.is_file():
        pytest.skip("census database or firmware not present")
    r = performing_rigs_callback_provenance(census)
    result = r.trace("0xee60")
    origin = result.argument_origins[0]
    assert (origin["function_entry"], origin["argument"]) == (CALLEE, "r3")
    (c,) = origin["callers"]
    assert (c["site"], c["caller_function"], c["value_status"]) == (CALL_SITE, CALLER, "CONCRETE")
    assert c["components"][0]["raw_value"] == "0x0000e883" and c["components"][0]["target"] == TARGET
    assert result.target_set == "OPEN" and any("address-taken" in x for x in result.open_reasons)
    assert "0x0000c744" not in {t["target"] for t in result.candidate_targets}
    assert copy.deepcopy(result.model_dump()) == r.trace("0x0000ee60").model_dump()
