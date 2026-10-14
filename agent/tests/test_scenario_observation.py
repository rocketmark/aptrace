"""Scenario-aware caller observation (observed_call_arguments v2): scenario
and watch validation, scenario identity in the ledger, scenario-specific
limitations, the bounded planner action, claim boundaries, and equivalent
argument defaults in operation identity. No Unicorn, census or model: the
harness subprocess is replaced by recorded documents."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from aptrace_agent.call_observation import (
    ObservationInputError,
    ObservedCallArgumentsRunner,
    planner_summary,
    validate_watch,
)
from aptrace_agent.ledger.hashing import digest
from aptrace_agent.ledger.models import EvidenceGrade
from aptrace_agent.ledger.operations import TOOL_INPUTS, input_artifacts
from aptrace_agent.ledger.semantics import (
    EXECUTION_BUDGET,
    NON_BOOTED_STATE,
    SCENARIO_FAILED,
    SCENARIO_SPECIFIC,
    WATCH_ABSENCE,
    WRITE_LOG_TRUNCATED,
    canonical_arguments,
    evidence_grade,
    evidence_limitations,
)
from aptrace_agent.ledger.store import ResearchLedger
from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchController, ResearchSession
from aptrace_agent.research.admission import admit
from aptrace_agent.research.followups import FollowUpGenerator
from aptrace_agent.research.history import HistoricalOperations
from aptrace_agent.schemas import EvidenceObservation

from ledger_support import FIRMWARE, stack
from test_observed_call_arguments import IMAGE, IMAGE_SHA, OBSERVATION_ARTIFACTS, FakeHarness, harness_doc, value
from test_research_controller import FakePlannerClient, FakeReconciler


RAM = (0x20000000, 0x30000)
SCENARIOS = {
    "boot": {"kind": "boot-recipe", "firmware_keys": ["autopilot868"]},
    "vl-plus": {"kind": "virtual-link", "firmware_keys": ["autopilot868", "mando868"]},
    "vl-t-status": {"kind": "virtual-link", "firmware_keys": ["mando868"]},
}


def runner(tmp_path, harness):
    image = tmp_path / "fw.bin"
    image.write_bytes(IMAGE)
    (tmp_path / "python3").write_text("")
    return ObservedCallArgumentsRunner(
        python=tmp_path / "python3",
        script=tmp_path / "observe.py",
        firmware_key="autopilot868",
        firmware_image=image,
        expected_sha256=IMAGE_SHA,
        entry_allowed=lambda entry: True,
        static_call_sites=lambda name: [("0x0000a068", "FUN_0000a064"), ("0x0000b662", "FUN_0000b658")],
        function_extent=lambda name: None,
        resolve_register=lambda v: {0x41012000: "SERCOM2.CTRLA (0x41012000)", 0x40003000: "SERCOM0.CTRLA (0x40003000)"}.get(v),
        scenarios=SCENARIOS,
        ram=RAM,
        run=harness,
    )


def config(scenario):
    return {"id": scenario, **SCENARIOS[scenario], "registry_sha256": "9" * 64}


def vl_doc(**overrides):
    doc = {
        "status": "ok",
        "scenario": "vl-plus",
        "firmware_key": "autopilot868",
        "firmware_sha256": IMAGE_SHA,
        "scenario_failure": None,
        "scenario_config": config("vl-plus"),
        "run": {"legs": 2, "observed_legs": 1, "instructions_executed": 900, "budget_exhausted_legs": 0, "errored_legs": 0},
        "legs": [
            {"leg": 0, "firmware": "firmware_mando868.bin", "observed": False, "entry": "0x000049c4", "fresh": True,
             "instructions_executed": 50, "stop_reason": "reached stop address 0x2fff0010", "error": None},
            {"leg": 1, "firmware": "firmware_autopilot868.bin", "observed": True, "entry": "0x00007e2c", "fresh": True,
             "instructions_executed": 900, "stop_reason": "reached stop address 0x2fff0010", "error": None,
             "seeds": [{"addr": "0x20004144", "len": 4, "tag": "seed"}], "reg_seed": [["r0", "0x00000001"]],
             "stub_calls": ["0x0000b23a"], "forced": {}, "entries": 0},
        ],
        "geometry": [],
        "observation": {"analysis": "call_observation", "analysis_version": 2, "entry": "0x0000b4b4",
                        "observed_entries": 0, "call_sites": []},
    }
    doc.update(overrides)
    return doc


def watched_doc(*, changed_later=False, complete=True):
    events = [{"leg": 0, "instruction": 10, "pc": "0x0000b314", "function": "FUN_0000b312", "address": "0x20004c54",
               "width": 4, "previous": "0x00000000", "new": "0x41012000", "changed": True, "first_write": True,
               "addressing": {"form": "base+imm", "instruction": "str r1, [r0]", "base_register": "r0", "offset": 0,
                              "base_value": "0x20004c54"}}]
    return {
        "analysis": "watched_writes", "analysis_version": 2, "dropped_writes": 0 if complete else 3, "complete": complete,
        "fields": [{"name": "0x20004c54+4", "address": "0x20004c54", "size": 4, "events": events, "writes": 1,
                    "value_changing_writes": 1, "changed_after_initialization": changed_later,
                    "initialization": {"leg": 0, "instruction": 10, "pc": "0x0000b314", "function": "FUN_0000b312",
                                       "new": "0x41012000"},
                    "final_bytes": "00200141"}],
    }


def boot_doc(**overrides):
    doc = harness_doc(scenario_config=config("boot"))
    doc["run"]["budget_exhausted"] = True
    doc.update(overrides)
    return doc


# -- request validation ------------------------------------------------------------


def test_default_scenario_is_boot_and_is_passed_explicitly(tmp_path):
    harness = FakeHarness(boot_doc())
    result = runner(tmp_path, harness).observe("FUN_0000b4b4")
    assert result.scenario == "boot" and result.provenance["scenario"] == "boot"
    assert ["--scenario", "boot"] == harness.argv[0][harness.argv[0].index("--scenario"):][:2]
    assert result.provenance["scenario_registry_sha256"] == "9" * 64


@pytest.mark.parametrize("scenario", ["vl-unknown", "BOOT", "../boot", "", 7, "boot; rm -rf /"])
def test_unknown_scenarios_are_rejected_before_execution(tmp_path, scenario):
    harness = FakeHarness(boot_doc())
    with pytest.raises(ObservationInputError):
        runner(tmp_path, harness).observe("FUN_0000b4b4", scenario)
    assert harness.argv == []


def test_scenario_document_mismatch_is_refused(tmp_path):
    with pytest.raises(RuntimeError):
        runner(tmp_path, FakeHarness(boot_doc())).observe("FUN_0000b4b4", "vl-plus")


@pytest.mark.parametrize(
    "watch",
    [
        [{"address": 0x10000000, "size": 4}],                                   # not RAM
        [{"address": 0x2002FFFE, "size": 4}],                                   # runs past RAM
        [{"address": 0x20000000, "size": 0}],
        [{"address": 0x20000000, "size": 17}],
        [{"address": 0x20000000 + 32 * i, "size": 4} for i in range(9)],        # too many
        [{"address": 0x20000000, "size": 8}, {"address": 0x20000004, "size": 4}],  # overlap
        [{"address": 0x20000010, "size": 4, "object_base": 0x20000020}],       # base above field
        [{"address": 0x20000010, "size": 4, "code": "x"}],                      # unknown key
        [{"address": True, "size": 4}],
        "0x20000000:4",
    ],
)
def test_watch_requests_are_bounded(watch):
    with pytest.raises(ObservationInputError):
        validate_watch(watch, RAM)


def test_watch_is_canonicalized_and_passed_to_the_harness(tmp_path):
    fields = validate_watch([{"address": "0x20004c78", "size": 4},
                             {"address": 0x20004358, "size": 4, "object_base": "0x20004348"}], RAM)
    assert fields == [{"address": "0x20004358", "size": 4, "object_base": "0x20004348"},
                      {"address": "0x20004c78", "size": 4}]
    harness = FakeHarness(boot_doc(watched_fields=watched_doc()))
    runner(tmp_path, harness).observe("FUN_0000b4b4", "boot", fields)
    argv = harness.argv[0]
    watches = [argv[i + 1] for i, a in enumerate(argv) if a == "--watch"]
    assert watches == ["0x20004358:4@0x20004348", "0x20004c78:4"]


# -- scenario interpretation and limitations --------------------------------------------


def test_virtual_link_result_keeps_legs_assumptions_and_reports_unentered(tmp_path):
    result = runner(tmp_path, FakeHarness(vl_doc())).observe("FUN_0000b4b4", "vl-plus")
    assert result.scenario == "vl-plus" and result.scenario_config["kind"] == "virtual-link"
    assert [leg["leg"] for leg in result.legs] == [0, 1]
    # Only legs that executed the target firmware are its harness inputs.
    assert [a["leg"] for a in result.harness_assumptions] == [1]
    assert "1 seeded range(s)" in result.harness_assumptions[0]["detail"]
    assert all(site.status == "UNOBSERVED" for site in result.call_sites)
    data = result.model_dump(mode="json")
    assert evidence_grade("observed_call_arguments", data)[0] == EvidenceGrade.BOUNDED
    codes = dict(evidence_limitations("observed_call_arguments", {"function": "FUN_0000b4b4", "scenario": "vl-plus"}, data))
    assert {SCENARIO_SPECIFIC, NON_BOOTED_STATE} <= set(codes)
    assert "not independent corroboration" in codes[SCENARIO_SPECIFIC]


def test_unsupported_and_failed_scenarios_conclude_nothing(tmp_path):
    for status, failure in [("unsupported: scenario 'vl-t-status' does not execute autopilot868", None),
                            ("scenario_failed", "AssertionError: expected (1023, 0, 1)")]:
        doc = vl_doc(status=status, scenario="vl-t-status", scenario_config=config("vl-t-status"),
                     scenario_failure=failure, legs=[], run={"instructions_executed": 0})
        result = runner(tmp_path, FakeHarness(doc)).observe("FUN_0000b4b4", "vl-t-status")
        data = result.model_dump(mode="json")
        assert evidence_grade("observed_call_arguments", data)[0] == EvidenceGrade.UNKNOWN
        codes = dict(evidence_limitations("observed_call_arguments", {}, data))
        assert SCENARIO_FAILED in codes and "nothing about the function is concluded" in codes[SCENARIO_FAILED]


def test_watched_fields_budget_and_truncation_are_disclosed(tmp_path):
    result = runner(tmp_path, FakeHarness(boot_doc(watched_fields=watched_doc(complete=False)))).observe("FUN_0000b4b4")
    codes = dict(evidence_limitations("observed_call_arguments", {}, result.model_dump(mode="json")))
    assert EXECUTION_BUDGET in codes
    # No later change observed is a bounded negative, never immutability.
    assert "does not show the field cannot change" in codes[WATCH_ABSENCE] and "'boot'" in codes[WATCH_ABSENCE]
    assert WRITE_LOG_TRUNCATED in codes
    changed = runner(tmp_path, FakeHarness(boot_doc(watched_fields=watched_doc(changed_later=True)))).observe("FUN_0000b4b4")
    assert WATCH_ABSENCE not in dict(evidence_limitations("observed_call_arguments", {}, changed.model_dump(mode="json")))


def test_ram_word_holding_a_peripheral_address_is_rendered_as_content(tmp_path):
    correlation = [{"call_site": "0x0000a068", "call_kind": "BL", "register": "r0", "value": "0x20004c54",
                    "value_region": "RAM", "pointee_words": [{"word": "0x41012000", "region": "MMIO"}],
                    "field": "0x20004c54+4", "calls": 2, "field_state": "initialized value unchanged at every call"}]
    result = runner(tmp_path, FakeHarness(boot_doc(watched_fields=watched_doc(), correlation=correlation))).observe("FUN_0000b4b4")
    assert result.correlation[0]["pointee_words"][0]["register_name"] == "SERCOM2.CTRLA"
    text = planner_summary(result)
    assert "0x20004c54(RAM)->*=0x41012000(SERCOM2.CTRLA content)" in text
    assert "r0=0x20004c54(RAM) is field 0x20004c54+4: initialized value unchanged at every call" in text
    assert "initialized to 0x41012000 by FUN_0000b312; no later change observed" in text


# -- ledger identity --------------------------------------------------------------------


def _record(ops, executor, doc, arguments, run_id="R-test"):
    executor.drift["observed_call_arguments"] = doc
    return ops.run(run_id, "observed_call_arguments", arguments)


def test_scenarios_are_distinct_operations_and_never_reused_for_each_other(tmp_path):
    ledger, executor, context, ops = stack(tmp_path)
    context.artifacts.update(OBSERVATION_ARTIFACTS)
    boot = runner(tmp_path, FakeHarness(boot_doc())).observe("FUN_0000b4b4").model_dump(mode="json")
    plus = runner(tmp_path, FakeHarness(vl_doc())).observe("FUN_0000b4b4", "vl-plus").model_dump(mode="json")

    b_inv, b_art = _record(ops, executor, boot, {"function": "FUN_0000b4b4", "scenario": "boot"})
    p_inv, p_art = _record(ops, executor, plus, {"function": "FUN_0000b4b4", "scenario": "vl-plus"})
    assert b_inv.operation_key != p_inv.operation_key and b_art.evidence_id != p_art.evidence_id
    assert set(b_inv.input_artifacts) == set(TOOL_INPUTS["observed_call_arguments"])

    history = HistoricalOperations(ledger, context(), run_ids=[], evidence_ids=[b_art.evidence_id, p_art.evidence_id])
    assert history.lookup("observed_call_arguments", {"function": "FUN_0000b4b4", "scenario": "vl-plus"}).invocation.invocation_id == p_inv.invocation_id
    assert history.lookup("observed_call_arguments", {"function": "FUN_0000b4b4", "scenario": "vl-g"}) is None
    # The default scenario is boot: the omitted spelling is the same operation.
    omitted = history.lookup("observed_call_arguments", {"function": "FUN_0000b4b4"})
    assert omitted.reusable and omitted.invocation.invocation_id == b_inv.invocation_id

    # A watched variant of the same scenario is a different operation.
    watched = _record(ops, executor, boot, {"function": "FUN_0000b4b4", "scenario": "boot",
                                            "watch": [{"address": "0x20004c54", "size": 4}]})[0]
    assert watched.operation_key != b_inv.operation_key

    # A changed scenario corpus is a different operation (no reuse across it).
    context.artifacts["scenario_corpus"] = "0" * 64
    refused = HistoricalOperations(ledger, context(), run_ids=[], evidence_ids=[p_art.evidence_id]).lookup(
        "observed_call_arguments", {"function": "FUN_0000b4b4", "scenario": "vl-plus"})
    assert not refused.reusable and "scenario_corpus" in refused.reason


def test_replay_keeps_scenario_provenance(tmp_path):
    ledger, executor, context, ops = stack(tmp_path)
    context.artifacts.update(OBSERVATION_ARTIFACTS)
    plus = runner(tmp_path, FakeHarness(vl_doc())).observe("FUN_0000b4b4", "vl-plus").model_dump(mode="json")
    invocation, artifact = _record(ops, executor, plus, {"function": "FUN_0000b4b4", "scenario": "vl-plus"})
    replay = ops.replay(invocation.invocation_id, run_id="R-replay")
    assert replay.matches and replay.replay.arguments["scenario"] == "vl-plus"
    stored, intact = ledger.evidence_result(artifact.evidence_id)
    assert intact and stored["scenario"] == "vl-plus" and stored["provenance"]["scenario"] == "vl-plus"
    assert stored["scenario_config"]["kind"] == "virtual-link"


# -- equivalent argument defaults ----------------------------------------------------------


def test_effects_specialization_defaults_normalize_only_when_equivalent():
    inputs = {"census_db": "a" * 64, "svd": "c" * 64}
    key = lambda args: ResearchLedger.operation_key("function_effects", args, inputs, FIRMWARE)  # noqa: E731
    omitted, empty, null = key({"function": "FUN_0000b4b4"}), key({"function": "FUN_0000b4b4", "specialize": {}}), \
        key({"function": "FUN_0000b4b4", "specialize": None})
    assert omitted == empty == null
    assert key({"function": "FUN_0000b4b4", "specialize": {"r0": 0x40003000}}) != empty
    assert key({"function": "FUN_0000b4b4", "specialize": {"r0": 0x40003000}}) != key({"function": "FUN_0000b4b4", "specialize": {"r0": 0x40003400}})
    # Persisted keys (always recorded with the explicit {} form) are unchanged.
    legacy = digest({"tool": "function_effects", "arguments": {"function": "FUN_0000b4b4", "specialize": {}},
                     "inputs": inputs, "firmware_sha256": FIRMWARE})
    assert empty == legacy
    # Other tools are untouched.
    assert canonical_arguments("function_facts", {"function": "FUN_0000b4b4"}) == {"function": "FUN_0000b4b4"}
    assert canonical_arguments("callsite_context", {"function": "F", "address": "0x1"}) == {"function": "F", "address": "0x1"}


def test_historical_omitted_form_record_is_found_by_both_spellings(tmp_path):
    """A record keyed before canonicalization (omitted specialize) stays readable and reusable."""

    ledger, executor, context, ops = stack(tmp_path)
    executor.drift["function_effects"] = {"status": "complete", "function": "FUN_0000b4b4", "specialize": {},
                                          "provenance": {"analysis_version": 1}}
    invocation, artifact = ops.run("R-old", "function_effects", {"function": "FUN_0000b4b4"})
    # Simulate the pre-canonicalization record: key computed over the arguments as recorded.
    raw = ResearchLedger._key("function_effects", {"function": "FUN_0000b4b4"},
                              invocation.input_artifacts, FIRMWARE)
    legacy = invocation.model_copy(update={"operation_key": raw, "invocation_id": "TI-legacy0000000"})
    (ledger.root / "invocations" / "TI-legacy0000000.json").write_text(legacy.model_dump_json())
    legacy_run = SimpleNamespace(invocation_ids=["TI-legacy0000000"])
    ledger.run = lambda run_id: legacy_run if run_id == "R-legacy" else (_ for _ in ()).throw(KeyError(run_id))

    history = HistoricalOperations(ledger, context(), run_ids=["R-legacy"], analysis_versions={})
    for spelling in ({"function": "FUN_0000b4b4"}, {"function": "FUN_0000b4b4", "specialize": {}}):
        decision = history.lookup("function_effects", spelling)
        assert decision is not None and decision.reusable, decision
    assert history.lookup("function_effects", {"function": "FUN_0000b4b4", "specialize": {"r0": 1}}) is None

    frontier = FollowUpGenerator(ledger, context=context())
    lead = SimpleNamespace(tool="function_effects", arguments={"function": "FUN_0000b4b4", "specialize": {}})
    assert frontier._operation_key(lead) in frontier.performed()


# -- planner action ----------------------------------------------------------------------


def controller(**kwargs):
    return ResearchController(
        planner_client=FakePlannerClient(kwargs.pop("decisions", [])),
        planner_model="test",
        reconciler=FakeReconciler(),
        structural_tools=("function_effects", "observed_call_arguments"),
        observation_scenarios=kwargs.pop("scenarios", ("boot", "vl-plus")),
        **kwargs,
    )


class RecordingExecutor:
    def __init__(self):
        self.calls = []

    def execute_operation(self, tool, arguments, *, evidence_id):
        self.calls.append((tool, dict(arguments)))
        result = {"name": "FUN_0000b4b4"} if tool == "function_facts" else {"status": "ok", "observed_entries": 0}
        return EvidenceObservation(id=evidence_id, tool=tool, arguments=arguments, result=result)


def session_knowing(function="FUN_0000b4b4"):
    registry = LeadRegistry()
    executor = RecordingExecutor()
    session = ResearchSession(objective="Which values reach FUN_0000b4b4 r0?", registry=registry,
                              follower=LeadFollower(registry=registry, executor=executor))
    session.record(EvidenceObservation(id=session.ledger.next_id(), tool="function_facts",
                                       arguments={"function": function}, result={"name": function}))
    return session, executor


def test_planner_action_is_offered_with_only_registered_scenarios():
    c = controller()
    session, _ = session_knowing()
    palette = c._decision_palette(session)
    tool = next(t for t in palette.tools if t["function"]["name"] == "observe_call_arguments")
    params = tool["function"]["parameters"]
    assert params["properties"]["scenario"]["enum"] == ["boot", "vl-plus"]
    assert set(params["properties"]) == {"function", "scenario"} and params["additionalProperties"] is False
    assert "hypothetical" in tool["function"]["description"]
    assert "observe_call_arguments" in c._analysis_guidance(session, palette)

    assert "observe_call_arguments" not in controller(scenarios=())._decision_palette(session).names()
    bare = ResearchController(planner_client=FakePlannerClient([]), planner_model="t", reconciler=FakeReconciler(),
                              structural_tools=("function_effects",), observation_scenarios=("boot",))
    assert "observe_call_arguments" not in bare._decision_palette(session).names()


@pytest.mark.parametrize(
    "arguments, problem",
    [
        ({"function": "FUN_0000b4b4", "scenario": "vl-g"}, "scenario must be one of"),
        ({"function": "FUN_0000b4b4", "scenario": "boot", "watch": [{"address": 0x20004c54, "size": 4}]}, "accepts only"),
        ({"function": "FUN_0000b4b4", "scenario": "boot", "max_instructions": 10**9}, "accepts only"),
        ({"function": "FUN_0000c7c0", "scenario": "boot"}, "already present in evidence"),
        ({"function": "0xb4b4", "scenario": "boot"}, "already present in evidence"),
    ],
)
def test_planner_cannot_bypass_scenario_or_execution_limits(arguments, problem):
    c = controller()
    session, _ = session_knowing()
    palette = c._decision_palette(session)
    outcome = c._parse_structural(session, palette, "observe_call_arguments", arguments)
    assert isinstance(outcome, str) and problem in outcome


def test_planner_selection_executes_one_bounded_observation_and_respects_the_cap():
    c = controller(decisions=[("observe_call_arguments", {"function": "FUN_0000b4b4", "scenario": "vl-plus"}),
                              ("finish", {"reason": "done"})], max_observations=1, max_steps=3)
    session, executor = session_knowing()
    result = c.run(session)
    observed = [call for call in executor.calls if call[0] == "observed_call_arguments"]
    assert observed == [("observed_call_arguments", {"function": "FUN_0000b4b4", "scenario": "vl-plus"})]
    assert any(step.action == "observation" for step in result.steps)
    # The cap is reached: the action is no longer offered.
    assert "observe_call_arguments" not in c._decision_palette(session).names()
    duplicate = controller()._parse_structural(session, controller()._decision_palette(session), "observe_call_arguments",
                                               {"function": "FUN_0000b4b4", "scenario": "vl-plus"})
    assert isinstance(duplicate, str) and "already observed" in duplicate


# -- claim boundary ------------------------------------------------------------------------


def test_finite_scenario_coverage_does_not_admit_a_categorical_negative():
    """An unentered function in one scenario is BOUNDED evidence; admission keeps it a hypothesis."""

    unentered = {"status": "ok", "observed_entries": 0, "scenario": "boot", "call_sites": [], "harness_assumptions": []}
    ledger = {"E1": EvidenceObservation(id="E1", tool="observed_call_arguments",
                                        arguments={"function": "FUN_0000b658", "scenario": "boot"}, result=unentered)}
    session = SimpleNamespace(ledger=SimpleNamespace(get=lambda i: ledger[i]), continuity=None)

    def check(grade, claim_type, text):
        proposal = {"subject": "", "assertion": text, "grade": grade, "claim_type": claim_type, "evidence_ids": ["E1"]}
        return admit(proposal, session, round=1, function_exists=lambda name: True, peripherals=["SERCOM0"])

    assert check("STRONG", "UNREACHABLE", "FUN_0000b658 is unreachable").decision == "rejected"
    assert check("PROBABLE", "UNREACHABLE", "FUN_0000b658 is unreachable").decision == "rejected"
    assert check("STRONG", "NO_KNOWN_PATH", "no known path reaches FUN_0000b658").decision == "rejected"
    assert check("EXACT", "BEHAVIOR", "FUN_0000b658 never accesses SERCOM0").decision == "rejected"


def test_scenario_note_describes_kinds_without_new_parameters(tmp_path):
    note = runner(tmp_path, FakeHarness(boot_doc())).scenario_note()
    assert note == "boot: full boot from reset into the main loop; vl-plus: short protocol slices entered mid-firmware on non-booted RAM"
    c = controller(observation_note=note)
    session, _ = session_knowing()
    tool = next(t for t in c._decision_palette(session).tools if t["function"]["name"] == "observe_call_arguments")
    assert tool["function"]["description"].endswith(f"Scenarios: {note}.")
    assert set(tool["function"]["parameters"]["properties"]) == {"function", "scenario"}


def test_summary_leads_with_a_bounded_digest(tmp_path):
    """The planner's latest-result view may show one line: it must carry the values and regions."""

    from aptrace_agent.research.projection import summarize_observation

    result = runner(tmp_path, FakeHarness(boot_doc())).observe("FUN_0000b4b4")
    result.planner_summary = planner_summary(result)
    first = summarize_observation(EvidenceObservation(id="E3", tool="observed_call_arguments", arguments={},
                                                      result=result.model_dump(mode="json")), 330).splitlines()[0]
    assert "r0 0x20004c54(RAM), 0x40003000(SERCOM0.CTRLA)" in first and "1 unreached" in first
    assert "0x41012000(SERCOM2.CTRLA content)" in first and "MMIO accesses from its code 0" in first

    unentered = runner(tmp_path, FakeHarness(vl_doc())).observe("FUN_0000b4b4", "vl-plus")
    text = planner_summary(unentered)
    assert "not entered in this scenario" in text.splitlines()[0] and "MMIO accesses from its code" not in text


def test_observation_facts_are_scoped_to_their_scenario(tmp_path):
    from aptrace_agent.research.fact_derivation import _observation_facts

    result = runner(tmp_path, FakeHarness(boot_doc())).observe("FUN_0000b4b4").model_dump(mode="json")
    statements, questions = _observation_facts(result)
    (basis, text), = statements
    assert basis == "concrete-observed" and "under scenario boot" in text and "not excluded" in text
    assert "0x20004c54(RAM)" in text and "(content, not an access)" in text and "0 MMIO accesses from its code" in text
    assert questions == ["Unobserved call site 0x0000b662 (FUN_0000b658) of FUN_0000b4b4: argument values unknown, not excluded."]

    unentered = runner(tmp_path, FakeHarness(vl_doc())).observe("FUN_0000b4b4", "vl-plus").model_dump(mode="json")
    (basis, text), = _observation_facts(unentered)[0]
    assert "was not entered under scenario vl-plus" in text and "not thereby unreachable" in text

    failed = vl_doc(status="scenario_failed", scenario_failure="AssertionError")
    assert _observation_facts(runner(tmp_path, FakeHarness(failed)).observe("FUN_0000b4b4", "vl-plus").model_dump(mode="json")) == ([], [])
