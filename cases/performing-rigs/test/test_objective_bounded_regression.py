"""
Performing Rigs: objective-bounded investigation (objective-v1) replayed
against the two failed remote-to-motor agent runs.

The saved artifacts are read-only regression references:

    research/runs/agent/remote-to-motor-2026-10-17.json          (PORT drift)
    research/runs/agent/remote-to-motor-focused-2026-10-19.json  (vl-ampersand, effects timeout)

A scripted planner re-issues the choices Qwen made in those runs. Function
facts come from the real, freshness-checked Ghidra index; every other
operation is answered only from the saved results. An operation the saved
runs never executed gets an explicit replay failure, never an invented
firmware result. The relations and terms come from the case objective specs
in research/objectives/.

Run with the agent environment (needs the gitignored Ghidra cache):

    agent/.venv/bin/python -m pytest cases/performing-rigs/test/test_objective_bounded_regression.py
"""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from aptrace_agent.investigation_tools import performing_rigs_callsite_context
from aptrace_agent.research import LeadDeriver, LeadFollower, LeadRegistry, ResearchController, ResearchSession
from aptrace_agent.research.objective import FAILED, OBSERVED, STATIC, UNRESOLVED, ObjectiveSpec
from aptrace_agent.schemas import EvidenceObservation

CASE = Path(__file__).resolve().parents[1]
RUNS = CASE / "research" / "runs" / "agent"
OBJECTIVES = CASE / "research" / "objectives"
DRIFT_RUN = RUNS / "remote-to-motor-2026-10-17.json"
FOCUSED_RUN = RUNS / "remote-to-motor-focused-2026-10-19.json"
SCENARIOS = json.loads((CASE / "config" / "observation_scenarios.json").read_text())["scenarios"]
PERIPHERALS = ("PORT", "SERCOM0", "SERCOM2", "TC0", "USB")
REPLAY_MISS = "failed: replay has no saved result for this operation"


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


ARTIFACT_HASHES = {path: _digest(path) for path in (DRIFT_RUN, FOCUSED_RUN)}


@pytest.fixture(scope="module")
def ghidra():
    from aptrace_agent.ghidra_index import GhidraCacheStale, autopilot_ghidra_index

    try:
        return autopilot_ghidra_index()
    except (GhidraCacheStale, FileNotFoundError, SystemExit) as exc:
        pytest.skip(f"AutoPilot Ghidra cache unavailable: {exc}")


def _key(tool, arguments):
    arguments = {k: v for k, v in arguments.items() if k not in ("max_results", "purpose", "limit")}
    return tool, json.dumps(arguments, sort_keys=True)


class ReplayExecutor:
    """Saved results by (tool, arguments); function facts from the real index."""

    def __init__(self, ghidra):
        self.ghidra = ghidra
        self.calls = []
        self.saved = {}

        for path in (DRIFT_RUN, FOCUSED_RUN):
            for item in json.loads(path.read_text())["evidence"]:
                self.saved.setdefault(_key(item["tool"], item["arguments"]), item["result"])

    def execute_operation(self, tool, arguments, *, evidence_id):
        self.calls.append((tool, dict(arguments)))

        if tool == "function_facts":
            result = self.ghidra.function_facts(arguments["function"]).model_dump()
        else:
            result = self.saved.get(_key(tool, arguments)) or {"status": REPLAY_MISS}

        return EvidenceObservation(id=evidence_id, tool=tool, arguments=arguments, result=result)


class Reconciler:
    def run(self, session):
        pass


class ScriptedPlanner:
    """Replays a list of decisions; a decision may be a function of the offered tools."""

    def __init__(self, decisions):
        self.decisions = list(decisions)
        self.prompts, self.tools = [], []
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kwargs):
        self.prompts.append(kwargs["messages"][-1]["content"])
        self.tools.append(kwargs["tools"])
        decision = self.decisions.pop(0) if self.decisions else ("finish", {"reason": "script ended"})
        name, arguments = decision(kwargs["tools"]) if callable(decision) else decision
        call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=json.dumps(arguments)))
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[call]))])


def build(ghidra, spec_name, decisions, *, max_steps, seed=None):
    spec = ObjectiveSpec.model_validate_json((OBJECTIVES / spec_name).read_text())
    registry = LeadRegistry()
    executor = ReplayExecutor(ghidra)
    session = ResearchSession(
        objective=spec.question, registry=registry, follower=LeadFollower(registry=registry, executor=executor),
        deriver=LeadDeriver(registry=registry, callsite_reader=performing_rigs_callsite_context(), function_facts_reader=ghidra),
    )

    if seed:
        for tool in ("function_facts", "function_disassembly"):
            session.record(executor.execute_operation(tool, {"function": seed}, evidence_id=session.ledger.next_id()))

    planner = ScriptedPlanner(decisions)
    controller = ResearchController(
        planner_client=planner, planner_model="replay", reconciler=Reconciler(), max_steps=max_steps,
        census_peripherals=PERIPHERALS, structural_tools=("usb_inventory", "common_paths", "function_effects", "observed_call_arguments"),
        observation_scenarios=tuple(sorted(n for n, v in SCENARIOS.items() if "autopilot868" in v["firmware_keys"])),
        scenario_metadata=SCENARIOS, objective=spec, firmware_key="autopilot868",
    )
    return spec, controller, session, planner, executor


def lead_to(session, function):
    """Decision: follow the offered lead whose private action targets `function`."""

    def decide(tools):
        follow = next((t for t in tools if t["function"]["name"] == "follow_lead"), None)

        for lead_id in follow["function"]["parameters"]["properties"]["lead_id"]["enum"] if follow else []:
            if session.registry.resolve(lead_id).arguments.get("function") == function:
                return "follow_lead", {"lead_id": lead_id}

        return "follow_lead", {"lead_id": "L999"}

    return decide


def first_lead(tools):
    follow = next((t for t in tools if t["function"]["name"] == "follow_lead"), None)
    return ("follow_lead", {"lead_id": follow["function"]["parameters"]["properties"]["lead_id"]["enum"][0]}) if follow \
        else ("finish", {"reason": "no lead offered"})


# -- run 1: PORT drift ----------------------------------------------------------------


def test_drift_run_replay_spends_no_budget_on_port_inventory(ghidra):
    original = json.loads(DRIFT_RUN.read_text())
    assert [s["action"] for s in original["trajectory"]][:2] == ["discover", "analyze"]
    assert original["evidence"][1]["arguments"] == {"peripheral": "PORT", "limit": 25}

    holder = {}
    decisions = [
        # Qwen's step 1 and 2 choices, then the correction picks an endpoint.
        ("search_case_evidence", {"query": "mando868 firmware firmware pin function map"}),
        lambda tools: lead_to(holder["session"], "FUN_00005448")(tools),
        ("analyze_peripheral", {"peripheral": "PORT"}),
        lambda tools: lead_to(holder["session"], "FUN_00008258")(tools),
        # Qwen then followed census leads into PORT users (FUN_0000d388 ...).
        lambda tools: lead_to(holder["session"], "FUN_0000d388")(tools),
        lambda tools: lead_to(holder["session"], "FUN_00005ee8")(tools),
    ] + [first_lead] * 8
    spec, controller, session, planner, executor = build(ghidra, "remote-to-motor-2026-10-17.objective.json", decisions, max_steps=8)
    holder["session"] = session
    result = controller.run(session)

    # 1. The whole 1,017-character objective and its constraints reach every request.
    assert len(spec.question) > 640
    decision_prompts = [p for p in planner.prompts if "TASK: make exactly one tool call" in p]
    assert decision_prompts and all(spec.question in p and "Avoid broad census" in p for p in decision_prompts)
    assert all("objective clipped" not in p for p in planner.prompts)

    # 4. No PORT inventory or PORT-user crawl consumed budget.
    executed = [tool for tool, _ in executor.calls]
    assert "census_peripheral_usage" not in executed and "search_case_evidence" not in executed
    assert not [a for t, a in executor.calls if a.get("function") == "FUN_0000d388"]
    rejected = {r["action"] for r in controller.tracker.rejections}
    assert {"search_case_evidence", "analyze_peripheral"} <= rejected
    # No peripheral is named by the question or terms (R5's label mentions TC0,
    # which describes the edge and does not request inventory).
    assert all("analyze_peripheral" not in [t["function"]["name"] for t in tools] for tools in planner.tools)

    # 6. Termination carries an explicit per-relation report, never a composed chain.
    report = result.objective_report
    assert result.stop_reason in ("objective_stalled", "step_budget_exhausted")
    levels = {r["id"]: r["level"] for r in report["relations"]}
    assert levels["R1"] == STATIC and levels["R2"] == STATIC and levels["R4"] == STATIC
    assert levels["R0"] == UNRESOLVED and levels["R3"] == UNRESOLVED and levels["R5"] == UNRESOLVED
    r0 = next(r for r in report["relations"] if r["id"] == "R0")
    assert r0["source"] == "mando868:0x0000be94" and any("multi-image" in m for m in r0["missing"])
    assert report["answered"] is False and report["composition"].startswith("not attempted")
    assert report["anchors"]["mando868:0xbe94"] == "other-image"
    # TC0 handler -> STEP helper is not one call edge in Ghidra's graph.
    r5 = next(r for r in report["relations"] if r["id"] == "R5")
    inspected = {a["function"] for t, a in executor.calls if t == "function_facts"}
    if {"FUN_0000607c", "FUN_00005898"} & inspected:
        assert "needs a path capability" in r5["missing"][0]


# -- run 2: vl-ampersand and the effects timeout --------------------------------------------


def test_focused_run_replay_rejects_ampersand_records_failures_and_stops(ghidra):
    original = json.loads(FOCUSED_RUN.read_text())
    assert original["evidence"][3]["arguments"] == {"function": "FUN_00005448", "scenario": "vl-ampersand"}
    assert original["evidence"][2]["result"]["status"] == "bounded: timeout 300s"

    holder = {}
    decisions = [
        ("analyze_function_effects", {"function": "FUN_00005448"}),
        # Original request 2 repeated the timed-out analysis.
        ("analyze_function_effects", {"function": "FUN_00005448"}),
        ("observe_call_arguments", {"function": "FUN_00005448", "scenario": "vl-ampersand"}),
        ("observe_call_arguments", {"function": "FUN_00005448", "scenario": "vl-manual-f0e0"}),
        lambda tools: lead_to(holder["session"], "FUN_00004d18")(tools),
        lambda tools: lead_to(holder["session"], "FUN_0000e0fc")(tools),
    ]
    spec, controller, session, planner, executor = build(
        ghidra, "remote-to-motor-focused-2026-10-19.objective.json", decisions, max_steps=4, seed="FUN_00005448"
    )
    holder["session"] = session
    result = controller.run(session)

    # 2./3. F0 is the only relevant scenario; ampersand is rejected with the reason.
    observe = next(t for tools in planner.tools for t in tools if t["function"]["name"] == "observe_call_arguments")
    assert observe["function"]["parameters"]["properties"]["scenario"]["enum"] == ["vl-manual-f0e0"]
    ampersand = next(r for r in controller.tracker.rejections if r["target"] == "FUN_00005448@vl-ampersand")
    assert "relevant scenarios: vl-manual-f0e0" in ampersand["reason"]
    observed = [a for t, a in executor.calls if t == "observed_call_arguments"]
    assert observed == [{"function": "FUN_00005448", "scenario": "vl-manual-f0e0"}]

    # 5. The timeout is recorded once, shown to later requests, and not repeated.
    assert len([c for c in executor.calls if c[0] == "function_effects"]) == 1
    outcomes = controller.tracker.outcomes
    assert outcomes[0].outcome == FAILED and "timeout" in outcomes[0].note
    assert any("FAILED (do not repeat): E3" in p for p in planner.prompts[1:])
    # The replay has no saved F0 observation: recorded as a failure, not as evidence.
    assert outcomes[1].outcome == FAILED and REPLAY_MISS in outcomes[1].note

    # Repeated low-value steps end the run with the unresolved report.
    assert result.stop_reason == "objective_stalled"
    assert any("REPLAN:" in p for p in planner.prompts)
    report = result.objective_report
    r3 = next(r for r in report["relations"] if r["id"] == "R3")
    assert r3["level"] == UNRESOLVED
    assert any("timeout" in b["detail"] and "not absence" in b["detail"] for b in r3["blockers"])
    assert {r["id"]: r["level"] for r in report["relations"]}["R2"] == STATIC
    assert not any(r["level"] == OBSERVED for r in report["relations"])
    open_questions = [q.question for q in session.state.open_questions if q.source == "objective"]
    assert any(q.startswith("R3 FUN_00005448 -> 0x20001b14 is UNRESOLVED") for q in open_questions)


def test_saved_runs_are_unchanged():
    assert {path: _digest(path) for path in ARTIFACT_HASHES} == ARTIFACT_HASHES
