"""Value forward use (value_forward_use, Ghidra p-code): origin validation,
the bounded runner, grades and limitations that keep a bounded negative
bounded, ledger identity, replay and historical reuse, historical
compatibility with other operations, and the grounded planner action. The
driver subprocess is replaced by recorded outputs of the framework's own
fixtures (tests/data/value_forward_use_fixtures.json, from
tools/ghidra/fixtures/pcode_forward_use); one test runs Ghidra end to end
on a fixture project when Ghidra is installed."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from aptrace_agent.ledger.models import EvidenceGrade
from aptrace_agent.ledger.operations import DETERMINISTIC_TOOLS, TOOL_INPUTS
from aptrace_agent.ledger.semantics import (
    ABI_MODEL,
    FORWARD_USE_INCOMPLETE,
    INTRAPROCEDURAL,
    NO_ESCAPE_BOUNDED,
    evidence_grade,
    evidence_limitations,
)
from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchController, ResearchSession
from aptrace_agent.research.history import HistoricalOperations, current_analysis_versions
from aptrace_agent.schemas import EvidenceObservation
from aptrace_agent.value_forward_use import (
    VALUE_FORWARD_USE_INPUTS,
    ValueForwardUseInputError,
    ValueForwardUseRunner,
    planner_summary,
)

from ledger_support import stack
from test_research_controller import FakePlannerClient, FakeReconciler


REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tools" / "ghidra" / "fixtures" / "pcode_forward_use"
RECORDED = json.loads((Path(__file__).parent / "data" / "value_forward_use_fixtures.json").read_text())
ARTIFACTS = {name: "e" * 64 for name in TOOL_INPUTS["value_forward_use"]}


def recorded(case):
    return copy.deepcopy(RECORDED[case]["doc"])


class FakeDriver:
    def __init__(self, doc, returncode=0, raise_timeout=False):
        self.doc, self.returncode, self.raise_timeout, self.argv = doc, returncode, raise_timeout, None

    def __call__(self, argv):
        self.argv = argv
        if self.raise_timeout:
            raise subprocess.TimeoutExpired(argv, 1)
        return subprocess.CompletedProcess(argv, self.returncode, json.dumps(self.doc), "boom\n")


def runner(tmp_path, driver, image="thumb_controls.bin", meta=None):
    fw = tmp_path / image
    shutil.copy2(FIXTURES / image, fw)
    sha = hashlib.sha256(fw.read_bytes()).hexdigest()
    identity = tmp_path / "meta.json"
    identity.write_text(json.dumps(meta if meta is not None else {
        "firmware_sha256": sha, "processor": "ARM:LE:32:Cortex", "cspec": "default", "load_base": "0x0",
        "ghidra_version": "12.1.3"}))
    return ValueForwardUseRunner(python=tmp_path / "python3", firmware_image=fw, expected_sha256=sha,
                                 project_dir=tmp_path / "project", project_name="fixture", program=image,
                                 project_identity=identity, run=driver)


# -- runner ----------------------------------------------------------------------------------


@pytest.mark.parametrize("origin", ["FUN_0000ec48", "../../etc/passwd", "0x0 --max-steps 9", "", None, "0x123456789"])
def test_only_addresses_are_accepted(tmp_path, origin):
    with pytest.raises(ValueForwardUseInputError):
        runner(tmp_path, FakeDriver(recorded("C1_compare_only"))).trace(origin)


@pytest.mark.parametrize("register", ["r3; rm", "--x", "a" * 40, ""])
def test_only_register_names_are_accepted(tmp_path, register):
    with pytest.raises(ValueForwardUseInputError):
        runner(tmp_path, FakeDriver(recorded("C1_compare_only"))).trace("0x0", register)


def test_argv_binds_target_from_the_project_identity(tmp_path):
    driver = FakeDriver(recorded("C1_compare_only"))
    out = runner(tmp_path, driver).trace("0")
    argv = driver.argv
    assert argv[1:3] == [str(VALUE_FORWARD_USE_INPUTS["pcode_forward_use_driver"]), "project"]
    assert argv[argv.index("--language") + 1] == "ARM:LE:32:Cortex"
    assert argv[argv.index("--cspec") + 1] == "default" and argv[argv.index("--base") + 1] == "0x0"
    assert argv[argv.index("--origin") + 1] == "0x00000000"
    assert out.status == "ok" and out.origin == "0x00000000"
    prov = out.provenance
    assert prov["analysis"] == "value_forward_use" and prov["analysis_version"] == 1
    assert prov["engine"]["name"] == "ghidra" and prov["engine"]["language_id"] == "ARM:LE:32:Cortex"
    assert prov["engine"]["compiler_spec_id"] == "default" and prov["walker_sha256"] and prov["driver_sha256"]


def test_complete_negative_is_bounded_and_scoped(tmp_path):
    out = runner(tmp_path, FakeDriver(recorded("C1_compare_only"))).trace("0x0")
    assert out.verdict == "NO_ESCAPE_WITHIN_SCOPE" and out.complete and out.escape_kinds == []
    assert out.origin_value["value"] == "0x00001001" and out.origin_value["code_address"] == "0x00001000"
    assert [u["kind"] for u in out.uses] == ["COMPARE", "ENDS_AT_RETURN", "DEAD"]
    result = out.model_dump(mode="json")
    assert evidence_grade("value_forward_use", result)[0] == EvidenceGrade.BOUNDED
    codes = dict(evidence_limitations("value_forward_use", {"origin": "0x00000000"}, result))
    assert {NO_ESCAPE_BOUNDED, INTRAPROCEDURAL, ABI_MODEL} <= set(codes)
    assert "other loads" in codes[NO_ESCAPE_BOUNDED]
    assert "this one value inside its containing function" in planner_summary(out)


def test_escape_is_probable_never_exact(tmp_path):
    out = runner(tmp_path, FakeDriver(recorded("C4_argument_via_move"))).trace("0xc0")
    assert out.verdict == "ESCAPE" and out.escape_kinds == ["ARGUMENT_ESCAPE"]
    assert evidence_grade("value_forward_use", out.model_dump(mode="json"))[0] == EvidenceGrade.PROBABLE
    assert "ARGUMENT at 0x000000c8" in planner_summary(out)


def test_incomplete_and_unsupported_conclude_nothing(tmp_path):
    out = runner(tmp_path, FakeDriver(recorded("N1_computed_jump")), image="thumb_negative.bin").trace("0x0")
    assert out.verdict == "INCOMPLETE" and not out.complete
    result = out.model_dump(mode="json")
    assert evidence_grade("value_forward_use", result)[0] == EvidenceGrade.UNKNOWN
    assert FORWARD_USE_INCOMPLETE in dict(evidence_limitations("value_forward_use", {}, result))
    assert "COMPUTED_FLOW_UNRESOLVED" in planner_summary(out)

    out = runner(tmp_path, FakeDriver(recorded("N6_ambiguous_origin")), image="thumb_negative.bin").trace("0x140")
    assert out.status == "unsupported" and out.verdict == "UNSUPPORTED"
    assert out.unsupported["code"] == "AMBIGUOUS_VALUE_OUTPUT"
    assert evidence_grade("value_forward_use", out.model_dump(mode="json"))[0] == EvidenceGrade.UNKNOWN


def test_bounded_failures_conclude_nothing(tmp_path):
    assert runner(tmp_path, FakeDriver({}, raise_timeout=True)).trace("0x0").status.startswith("bounded")
    failed = runner(tmp_path, FakeDriver({}, returncode=1)).trace("0x0")
    assert failed.status == "failed" and failed.verdict is None and "boom" in failed.planner_summary
    unavailable = recorded("C1_compare_only")
    unavailable["result"] = {"status": "engine_unavailable", "results": []}
    assert runner(tmp_path, FakeDriver(unavailable)).trace("0x0").status == "engine_unavailable"
    with pytest.raises(ValueForwardUseInputError):
        runner(tmp_path, FakeDriver({"status": "invalid_request", "error": "outside the image"}, returncode=2)).trace("0x0")


def test_mismatched_inputs_are_refused(tmp_path):
    r = runner(tmp_path, FakeDriver(recorded("C1_compare_only")), meta={"firmware_sha256": "0" * 64})
    assert r.trace("0x0").status == "project_unavailable"
    r = runner(tmp_path, FakeDriver(recorded("C1_compare_only")))
    r.expected_sha256 = "0" * 64
    assert r.trace("0x0").status == "firmware_unavailable"
    wrong = recorded("C1_compare_only")
    wrong["result"]["target"]["image_sha256"] = "1" * 64
    with pytest.raises(RuntimeError, match="different firmware"):
        runner(tmp_path, FakeDriver(wrong)).trace("0x0")
    with pytest.raises(RuntimeError, match="answered"):
        runner(tmp_path, FakeDriver(recorded("C1_compare_only"))).trace("0x2")


def test_architecture_comes_from_the_project_not_the_runner(tmp_path):
    doc = recorded("R1_compare_only")
    sha = hashlib.sha256((FIXTURES / "rv32_controls.bin").read_bytes()).hexdigest()
    driver = FakeDriver(doc)
    r = runner(tmp_path, driver, image="rv32_controls.bin",
               meta={"firmware_sha256": sha, "processor": "RISCV:LE:32:default", "cspec": "gcc", "load_base": "0x0"})
    out = r.trace("0x4")
    assert driver.argv[driver.argv.index("--language") + 1] == "RISCV:LE:32:default"
    assert out.verdict == "NO_ESCAPE_WITHIN_SCOPE" and out.provenance["engine"]["language_id"] == "RISCV:LE:32:default"
    assert out.tracked["storage"] == "a5"


# -- ledger -----------------------------------------------------------------------------------


def test_identity_inputs_replay_and_reuse(tmp_path):
    assert "value_forward_use" in DETERMINISTIC_TOOLS
    assert current_analysis_versions()["value_forward_use"] == 1
    assert set(TOOL_INPUTS["value_forward_use"]) == {
        "ghidra_cache_identity", "pcode_forward_use_walker", "pcode_forward_use_driver", "ghidra_headless_locator"}
    # The Python/Capstone analyses do not depend on the p-code walker, and vice versa.
    for tool in ("indirect_call_target", "callback_argument_provenance"):
        assert not set(TOOL_INPUTS[tool]) & set(TOOL_INPUTS["value_forward_use"])

    ledger, executor, context, ops = stack(tmp_path)
    context.artifacts.update(ARTIFACTS)
    result = runner(tmp_path, FakeDriver(recorded("C1_compare_only"))).trace("0x0").model_dump(mode="json")
    executor.drift["value_forward_use"] = result
    invocation, artifact = ops.run("R-test", "value_forward_use", {"origin": "0x00000000"})
    assert invocation.replayable and set(invocation.input_artifacts) == set(TOOL_INPUTS["value_forward_use"])
    other, _ = ops.run("R-test", "value_forward_use", {"origin": "0x000000c0"})
    named, _ = ops.run("R-test", "value_forward_use", {"origin": "0x00000000", "register": "r3"})
    assert len({invocation.operation_key, other.operation_key, named.operation_key}) == 3
    # Same address under an older operation: a different identity, never a substitute.
    executor.drift["callback_argument_provenance"] = {"status": "ok", "site": "0x00000000"}
    sibling, _ = ops.run("R-test", "callback_argument_provenance", {"site": "0x00000000"})
    assert sibling.operation_key != invocation.operation_key

    replay = ops.replay(invocation.invocation_id, run_id="R-replay")
    assert replay.matches
    stored, intact = ledger.evidence_result(artifact.evidence_id)
    assert intact and stored["verdict"] == "NO_ESCAPE_WITHIN_SCOPE"

    history = HistoricalOperations(ledger, context(), run_ids=[], evidence_ids=[artifact.evidence_id])
    assert history.lookup("value_forward_use", {"origin": "0x00000000"}).reusable
    assert history.lookup("value_forward_use", {"origin": "0x00000002"}) is None
    newer = HistoricalOperations(ledger, context(), run_ids=[], evidence_ids=[artifact.evidence_id],
                                 analysis_versions={**current_analysis_versions(), "value_forward_use": 2})
    assert not newer.lookup("value_forward_use", {"origin": "0x00000000"}).reusable
    for name in TOOL_INPUTS["value_forward_use"]:
        context.artifacts[name] = "0" * 64
        refused = HistoricalOperations(ledger, context(), run_ids=[], evidence_ids=[artifact.evidence_id]).lookup(
            "value_forward_use", {"origin": "0x00000000"})
        assert not refused.reusable and name in refused.reason
        context.artifacts[name] = "e" * 64


# -- planner action --------------------------------------------------------------------------

LOADS = [0x0, 0xC0, 0x140]


class RecordingExecutor:
    def __init__(self):
        self.calls = []

    def execute_operation(self, tool, arguments, *, evidence_id):
        self.calls.append((tool, dict(arguments)))
        if tool == "function_disassembly":
            result = {"name": "FUN_00000000", "instructions": [
                {"address": "0x00000000", "mnemonic": "ldr", "operands": "r3, [pc, #0xc]"},
                {"address": "0x000000c0", "mnemonic": "ldr", "operands": "r3, [pc, #0xc]"}]}
        elif tool == "value_forward_use":
            case = "C1_compare_only" if arguments["origin"] == "0x00000000" else "C4_argument_via_move"
            result = recorded(case)["result"]["results"][0] | {"status": "ok", "origin": arguments["origin"]}
        else:
            result = {"name": arguments.get("function")}
        return EvidenceObservation(id=evidence_id, tool=tool, arguments=arguments, result=result)


def controller(**kwargs):
    return ResearchController(
        planner_client=FakePlannerClient(kwargs.pop("decisions", [])), planner_model="test", reconciler=FakeReconciler(),
        structural_tools=("value_forward_use",), value_origins=kwargs.pop("origins", LOADS), **kwargs)


def session_with(tool="function_disassembly"):
    registry = LeadRegistry()
    executor = RecordingExecutor()
    session = ResearchSession(objective="Does the function pointer loaded in FUN_00000000 escape?", registry=registry,
                              follower=LeadFollower(registry=registry, executor=executor))
    session.record(executor.execute_operation(tool, {"function": "FUN_00000000"}, evidence_id=session.ledger.next_id()))
    return session, executor


def test_action_is_offered_only_for_grounded_loads():
    c = controller()
    session, _ = session_with()
    palette = c._decision_palette(session)
    tool = next(t for t in palette.tools if t["function"]["name"] == "trace_value_use")
    params = tool["function"]["parameters"]
    assert params["properties"]["origin"]["enum"] == ["0x00000000", "0x000000c0"]
    assert set(params["properties"]) == {"origin"} and params["additionalProperties"] is False
    assert "INCOMPLETE" in tool["function"]["description"] and "this one load only" in tool["function"]["description"]
    # Planner-facing text names no instruction set.
    assert not any(w in tool["function"]["description"].lower() for w in ("ldr", "blx", "thumb", "r3"))
    assert "trace_value_use" in c._analysis_guidance(session, palette)

    facts_only, _ = session_with("function_facts")
    assert "trace_value_use" not in c._decision_palette(facts_only).names()
    assert "trace_value_use" not in controller(origins=())._decision_palette(session).names()
    without = ResearchController(planner_client=FakePlannerClient([]), planner_model="test", reconciler=FakeReconciler(),
                                 structural_tools=("indirect_call_target",), indirect_sites=[0x10])
    assert "trace_value_use" not in without._decision_palette(session).names()


@pytest.mark.parametrize(
    "arguments, problem",
    [
        ({"origin": "0x00000140"}, "one of the listed"),
        ({"origin": "0x00000002"}, "one of the listed"),
        ({"origin": "0x00000000", "register": "r0"}, "accepts only origin"),
        ({"origin": "0x00000000", "max_steps": 10**9}, "accepts only origin"),
        ({"origin": "0x00000000", "project": "/etc"}, "accepts only origin"),
    ],
)
def test_planner_cannot_widen_the_operation(arguments, problem):
    c = controller()
    session, _ = session_with()
    outcome = c._parse_structural(session, c._decision_palette(session), "trace_value_use", arguments)
    assert isinstance(outcome, str) and problem in outcome


def test_selection_executes_bounded_traces_and_respects_the_cap():
    c = controller(decisions=[("trace_value_use", {"origin": "0x00000000"}),
                              ("trace_value_use", {"origin": "0x000000c0"}),
                              ("finish", {"reason": "done"})], max_steps=4)
    session, executor = session_with()
    result = c.run(session)
    traced = [call for call in executor.calls if call[0] == "value_forward_use"]
    assert traced == [("value_forward_use", {"origin": "0x00000000"}), ("value_forward_use", {"origin": "0x000000c0"})]
    assert sum(step.action == "value_forward_use" for step in result.steps) == 2
    assert "trace_value_use" not in c._decision_palette(session).names()
    fresh = controller(max_value_traces=3)
    assert fresh._decision_palette(session).value_origins == []


def test_facts_are_scoped_to_the_one_value():
    from aptrace_agent.research.fact_derivation import _value_forward_use_facts

    c1 = recorded("C1_compare_only")["result"]["results"][0] | {"status": "ok", "origin": "0x00000000"}
    (basis, text), = _value_forward_use_facts(c1)[0]
    assert basis == "static-dataflow" and "does not escape" in text and "one load only" in text
    assert "0x00001001 (code pointer to FUN_00001000)" in text
    c4 = recorded("C4_argument_via_move")["result"]["results"][0] | {"status": "ok", "origin": "0x000000c0"}
    (_, text), = _value_forward_use_facts(c4)[0]
    assert "may escape: argument at 0x000000c8" in text
    n1 = recorded("N1_computed_jump")["result"]["results"][0] | {"status": "ok", "origin": "0x00000000"}
    facts, questions = _value_forward_use_facts(n1)
    assert facts == [] and "COMPUTED_FLOW_UNRESOLVED" in questions[0]
    assert _value_forward_use_facts({"status": "failed"}) == ([], [])


# -- end to end (Ghidra installed) -----------------------------------------------------------


def _headless():
    import sys

    sys.path.insert(0, str(REPO / "tools" / "ghidra"))
    from headless import find_headless

    return find_headless()


@pytest.mark.skipif(_headless() is None, reason="Ghidra is not installed")
def test_real_driver_on_a_fixture_project(tmp_path):
    import sys

    image = tmp_path / "thumb_controls.bin"
    shutil.copy2(FIXTURES / "thumb_controls.bin", image)
    project = tmp_path / "project"
    project.mkdir()
    subprocess.run([str(_headless()), str(project), "fixture", "-import", str(image), "-processor", "ARM:LE:32:Cortex",
                    "-cspec", "default", "-loader", "BinaryLoader", "-loader-baseAddr", "0x0", "-noanalysis",
                    "-scriptPath", str(FIXTURES), "-preScript", "APTracePcodeForwardUseTestSeed.java", "0x800,0x0,0xc0"],
                   capture_output=True, check=True)
    sha = hashlib.sha256(image.read_bytes()).hexdigest()
    meta = tmp_path / "meta.json"
    meta.write_text(json.dumps({"firmware_sha256": sha, "processor": "ARM:LE:32:Cortex", "cspec": "default",
                                "load_base": "0x0"}))
    before = sorted((p.name, p.stat().st_size) for p in project.rglob("*"))
    r = ValueForwardUseRunner(python=Path(sys.executable), firmware_image=image, expected_sha256=sha, project_dir=project,
                              project_name="fixture", program=image.name, project_identity=meta)
    first = r.trace("0x0").model_dump(mode="json")
    assert first["verdict"] == "NO_ESCAPE_WITHIN_SCOPE" and first["complete"]
    assert r.trace("0xc0").escape_kinds == ["ARGUMENT_ESCAPE"]
    assert r.trace("0x0").model_dump(mode="json") == first
    assert sorted((p.name, p.stat().st_size) for p in project.rglob("*")) == before
