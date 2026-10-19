"""
Objective-bounded investigation (research/objective.py) with synthetic
firmware identities: objective persistence, operation relevance, progress
tracking and bounded termination. No case data; the Performing Rigs
regression replay is cases/performing-rigs/test/test_objective_bounded_regression.py.
"""

import json
from types import SimpleNamespace

import pytest

from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchController, ResearchSession
from aptrace_agent.research.objective import (
    FAILED,
    NO_PROGRESS,
    OBSERVED,
    STATIC,
    STRENGTHENED,
    SYMBOLIC,
    UNRESOLVED,
    ObjectiveSpec,
    ObjectiveTracker,
    load_spec,
    parse_relation,
    scenario_tokens,
)
from aptrace_agent.schemas import EvidenceObservation


SCENARIOS = {
    "boot": {"kind": "boot-recipe", "firmware_keys": ["fw"]},
    "vl-alpha": {"kind": "virtual-link", "runner": "run_alpha_roundtrip", "firmware_keys": ["fw"]},
    "vl-beta": {"kind": "virtual-link", "runner": "run_beta_roundtrip", "firmware_keys": ["fw"]},
    "vl-jog-f0": {"kind": "virtual-link", "runner": "run_manual_jog_f0_check", "firmware_keys": ["fw"]},
}

# Synthetic call graph: dispatcher -> handler -> motion; handler calls a helper.
GRAPH = {
    "FUN_00001000": {"callers": [], "callees": ["FUN_00002000"]},
    "FUN_00002000": {"callers": ["FUN_00001000"], "callees": ["FUN_00003000", "FUN_00004000"]},
    "FUN_00003000": {"callers": ["FUN_00002000"], "callees": []},
    "FUN_00004000": {"callers": ["FUN_00002000"], "callees": ["FUN_00005000"]},
    "FUN_00005000": {"callers": ["FUN_00004000"], "callees": []},
    "FUN_00009000": {"callers": [], "callees": []},
}

LONG_QUESTION = (
    "Trace the F0 jog command from the dispatcher through the handler to the motion update and the busy flag. "
    + "Keep static, concrete and symbolic evidence distinct and report every unsupported relation. " * 8
).strip()


def spec(**overrides):
    data = {
        "question": LONG_QUESTION,
        "constraints": ["Avoid peripheral inventory.", "Do not infer end-to-end execution."],
        "relations": [
            {"id": "R1", "source": "FUN_00001000", "target": "FUN_00002000", "label": "dispatch reaches handler"},
            {"id": "R2", "source": "FUN_00002000", "target": "FUN_00003000", "label": "handler updates motion"},
            {"id": "R3", "source": "FUN_00002000", "target": "0x20000100", "label": "handler sets busy flag"},
        ],
        "terms": ["jog", "F0"],
    }
    data.update(overrides)
    return ObjectiveSpec.model_validate(data)


class Reader:
    def function_facts(self, name):
        if name not in GRAPH:
            raise KeyError(name)
        return name


def facts(name):
    node = GRAPH.get(name, {"callers": [], "callees": []})
    return {
        "name": name,
        "callers": [{"function": f, "address": "0x0"} for f in node["callers"]],
        "callees": [{"function": f, "address": "0x0"} for f in node["callees"]],
    }


class Executor:
    """Synthetic results; tests override per (tool, function)."""

    def __init__(self, overrides=None):
        self.calls = []
        self.overrides = overrides or {}

    def execute_operation(self, tool, arguments, *, evidence_id):
        self.calls.append((tool, dict(arguments)))
        key = (tool, arguments.get("function") or arguments.get("peripheral"))

        if key in self.overrides:
            result = self.overrides[key]
        elif tool == "function_facts":
            result = facts(arguments["function"])
        elif tool == "census_peripheral_usage":
            result = {"status": "ok", "peripheral": arguments["peripheral"], "functions": [{"function": "FUN_00009000"}]}
        else:
            result = {"status": "ok"}

        return EvidenceObservation(id=evidence_id, tool=tool, arguments=arguments, result=result)


class Planner:
    """Scripted tool calls; records every prompt it was shown."""

    def __init__(self, decisions):
        self.decisions = list(decisions)
        self.prompts = []
        self.tools = []
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kwargs):
        self.prompts.append(kwargs["messages"][-1]["content"])
        self.tools.append([t["function"]["name"] for t in kwargs["tools"]])
        decision = self.decisions.pop(0) if self.decisions else ("finish", {"reason": "script ended"})

        if callable(decision):
            decision = decision(kwargs)

        name, arguments = decision
        call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=json.dumps(arguments)))
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[call]))])


class Reconciler:
    def run(self, session):
        raise AssertionError("no case evidence: reconciliation must not run")


def make(decisions, *, objective=None, overrides=None, max_steps=8, **kwargs):
    registry = LeadRegistry()
    executor = Executor(overrides)
    session = ResearchSession(
        objective=(objective.question if objective else "Investigate the jog handler"),
        registry=registry,
        follower=LeadFollower(registry=registry, executor=executor),
        deriver=SimpleNamespace(function_facts_reader=Reader(), derive=lambda obs: SimpleNamespace(leads=[], issues=[])),
    )
    planner = Planner(decisions)
    controller = ResearchController(
        planner_client=planner,
        planner_model="test",
        reconciler=Reconciler(),
        max_steps=max_steps,
        census_peripherals=("PORT", "SERCOM0"),
        structural_tools=("function_effects", "observed_call_arguments"),
        observation_scenarios=tuple(SCENARIOS),
        scenario_metadata=SCENARIOS,
        objective=objective,
        **kwargs,
    )
    return controller, session, planner, executor


# -- 1. objective persistence ---------------------------------------------------------


def test_objective_spec_is_bounded_and_cli_relations_parse(tmp_path):
    relation = parse_relation("FUN_00001000->0x20000100:sets busy", 1)
    assert (relation.source, relation.target, relation.label) == ("FUN_00001000", "0x20000100", "sets busy")

    with pytest.raises(ValueError):
        parse_relation("FUN_00001000 to FUN_00002000", 1)
    with pytest.raises(ValueError):
        parse_relation("main->FUN_00002000", 1)
    with pytest.raises(ValueError):
        ObjectiveSpec(question="q", constraints=["x" * 241])
    with pytest.raises(ValueError):
        ObjectiveSpec(question="q", relations=[parse_relation(f"FUN_0000100{i}->FUN_00002000", i) for i in range(9)])

    path = tmp_path / "objective.json"
    path.write_text(json.dumps({"question": "from file", "relations": [{"id": "R1", "source": "FUN_00001000", "target": "FUN_00002000"}]}))
    loaded = load_spec(str(path), relations=["FUN_00002000->FUN_00003000"], constraints=["c"])
    assert [r.id for r in loaded.relations] == ["R1", "R2"] and loaded.constraints == ["c"] and loaded.focused
    assert not ObjectiveSpec(question="no relations").focused


def test_objective_survives_every_planning_step_unclipped():
    objective = spec()
    assert len(objective.question) > 640
    controller, session, planner, _ = make(
        [("follow_lead", {"lead_id": "L1"}), ("follow_lead", {"lead_id": "L2"}), ("finish", {"reason": "done"})],
        objective=objective,
    )
    controller.run(session)

    assert len(planner.prompts) == 3

    for prompt in planner.prompts:
        assert objective.question in prompt
        assert all(constraint in prompt for constraint in objective.constraints)
        assert "R3 FUN_00002000 -> 0x20000100 'handler sets busy flag'" in prompt
        assert "BUDGET:" in prompt and "objective clipped" not in prompt

    assert "0 of 8 steps used, 8 left" in planner.prompts[0]
    assert "2 of 8 steps used, 6 left" in planner.prompts[2]


def test_unfocused_long_objective_discloses_clipping():
    controller, session, planner, _ = make([("finish", {"reason": "done"})])
    session.state.objective = LONG_QUESTION
    session.record(EvidenceObservation(id=session.ledger.next_id(), tool="function_facts",
                                       arguments={"function": "FUN_00002000"}, result=facts("FUN_00002000")))
    session.state.add_lead(session.registry.register(kind="x", description="d", tool="function_facts",
                                                     arguments={"function": "FUN_00003000"}))
    controller.run(session)
    assert "[objective clipped:" in planner.prompts[0]


# -- 2./3. operation relevance --------------------------------------------------------------


def test_scenario_relevance_uses_registry_metadata_not_case_names():
    tokens = scenario_tokens(SCENARIOS)
    # "run" and "vl" occur in most scenarios and discriminate nothing.
    assert "run" not in tokens["vl-jog-f0"] and "vl" not in tokens["vl-jog-f0"]
    tracker = ObjectiveTracker(spec=spec(), function_exists=lambda n: n in GRAPH, scenario_metadata=SCENARIOS)
    relevance = tracker.scenario_relevance(tuple(SCENARIOS), [])
    assert relevance.relevant == ("vl-jog-f0",)
    assert "f0" in relevance.basis["vl-jog-f0"] and "jog" in relevance.basis["vl-jog-f0"]

    declared = ObjectiveTracker(spec=spec(scenarios=["vl-beta"]), scenario_metadata=SCENARIOS)
    assert set(declared.scenario_relevance(tuple(SCENARIOS), []).relevant) == {"vl-beta", "vl-jog-f0"}
    assert declared.scenario_relevance(tuple(SCENARIOS), []).basis["vl-beta"] == "declared by the objective"

    # Evidence of an endpoint being entered establishes relevance too.
    entered = EvidenceObservation(id="E1", tool="observed_call_arguments",
                                  arguments={"function": "FUN_00002000", "scenario": "vl-alpha"},
                                  result={"status": "ok", "observed_entries": 2})
    assert "vl-alpha" in tracker.scenario_relevance(tuple(SCENARIOS), [entered]).relevant


def test_unrelated_scenario_is_withheld_and_rejected_relevant_one_runs():
    objective = spec()
    controller, session, planner, executor = make(
        [
            ("follow_lead", {"lead_id": "L2"}),  # FUN_00002000 facts
            ("observe_call_arguments", {"function": "FUN_00002000", "scenario": "vl-alpha"}),
            ("observe_call_arguments", {"function": "FUN_00002000", "scenario": "vl-jog-f0"}),
            ("finish", {"reason": "done"}),
        ],
        objective=objective,
    )
    controller.run(session)

    offered = [t for t in planner.tools if "observe_call_arguments" in t]
    assert offered, "a relevant scenario keeps the observation tool available"
    observed = [args for tool, args in executor.calls if tool == "observed_call_arguments"]
    assert observed == [{"function": "FUN_00002000", "scenario": "vl-jog-f0"}]
    rejection = controller.tracker.rejections[0]
    assert rejection["action"] == "observe_call_arguments" and rejection["target"] == "FUN_00002000@vl-alpha"
    assert "relevant scenarios: vl-jog-f0" in rejection["reason"]
    assert "REJECTED AS UNRELATED: observe_call_arguments FUN_00002000@vl-alpha" in planner.prompts[-1]


def test_scenario_enum_is_limited_to_relevant_scenarios():
    controller, session, _, _ = make([], objective=spec())
    controller._start_objective(session)
    session.follow_lead("L2")
    palette = controller._decision_palette(session)
    tool = next(t for t in palette.tools if t["function"]["name"] == "observe_call_arguments")
    assert tool["function"]["parameters"]["properties"]["scenario"]["enum"] == ["vl-jog-f0"]

    none = make([], objective=spec(terms=[], question="Does the dispatcher reach the handler?"))[0]
    none._start_objective(session)
    assert "observe_call_arguments" not in none._decision_palette(session).names()


def test_peripheral_inventory_is_withheld_unless_the_objective_names_it():
    controller, session, planner, executor = make(
        [("analyze_peripheral", {"peripheral": "PORT"}), ("follow_lead", {"lead_id": "L1"}), ("finish", {"reason": "done"})],
        objective=spec(),
    )
    controller.run(session)

    assert "analyze_peripheral" not in planner.tools[0]
    assert not [c for c in executor.calls if c[0] == "census_peripheral_usage"]
    assert controller.tracker.rejections[0]["action"] == "analyze_peripheral"
    assert "withheld in this objective-bounded run" in planner.prompts[1]

    named = make([], objective=spec(terms=["PORT"]))[0]
    named_session = make([], objective=spec())[1]
    named._start_objective(named_session)
    assert named._decision_palette(named_session).analyzable == ["PORT"]


def test_a_relation_label_does_not_request_peripheral_inventory():
    labelled = spec(relations=[{"id": "R1", "source": "FUN_00001000", "target": "FUN_00002000", "label": "PORT write path"}])
    tracker = ObjectiveTracker(spec=labelled)
    assert not tracker.peripheral_relevant("PORT")
    assert ObjectiveTracker(spec=spec(question="Does the PORT write path reach the handler?")).peripheral_relevant("PORT")


def test_claim_candidates_are_scoped_to_the_objective():
    from aptrace_agent.research.candidates import CandidateSet
    from aptrace_agent.research.objective import CANDIDATE_OUTSIDE_OBJECTIVE

    controller, session, _, _ = make([], objective=spec())
    controller._start_objective(session)
    session.follow_lead("L2")  # FUN_00002000 facts: neighbours become relevant

    def candidate(subject):
        return SimpleNamespace(candidate_id=f"K-{subject}", subject=subject, assertion=f"{subject} accesses PORT",
                               supporting_evidence_ids=["E1"])

    generated = CandidateSet(candidates=(candidate("FUN_00009000"), candidate("FUN_00004000")), withheld=())
    scoped = controller._objective_candidates(session, generated)
    assert [c.subject for c in scoped.candidates] == ["FUN_00004000"]
    assert [(w.code, w.fact) for w in scoped.withheld] == [(CANDIDATE_OUTSIDE_OBJECTIVE, "FUN_00009000 accesses PORT")]


def test_leads_off_the_objective_are_not_offered():
    controller, session, planner, _ = make([("finish", {"reason": "done"})], objective=spec())
    unrelated = session.registry.register(kind="census", description="PORT user", tool="function_facts",
                                          arguments={"function": "FUN_00009000"})
    session.state.add_lead(unrelated)
    controller.run(session)
    assert unrelated.id not in planner.prompts[0].split("LEADS (APTrace-validated)")[1]
    assert "Objective relation endpoint" not in planner.prompts[0]  # descriptions stay private


def test_unfocused_run_keeps_existing_palette_and_rules():
    controller, session, planner, _ = make([("analyze_peripheral", {"peripheral": "PORT"}), ("finish", {"reason": "done"})])
    session.state.add_lead(session.registry.register(kind="x", description="d", tool="function_facts",
                                                     arguments={"function": "FUN_00009000"}))
    result = controller.run(session)

    assert "analyze_peripheral" in planner.tools[0]
    assert "1) a subsystem the objective names is not under ALREADY RUN" in planner.prompts[0]
    assert "RELATIONS" not in planner.prompts[0]
    assert result.objective_report is None and controller.tracker is None
    assert ResearchController(planner_client=Planner([]), planner_model="t", reconciler=Reconciler(),
                              objective=ObjectiveSpec(question="no relations")).objective_spec is None


# -- 4./5. progress and failures -----------------------------------------------------------


def test_relation_levels_come_from_recorded_evidence():
    tracker = ObjectiveTracker(spec=spec(), function_exists=lambda n: n in GRAPH)
    obs = [EvidenceObservation(id="E1", tool="function_facts", arguments={"function": "FUN_00002000"}, result=facts("FUN_00002000"))]
    levels = {s.id: s.level for s in tracker.relation_status(obs)}
    assert levels == {"R1": STATIC, "R2": STATIC, "R3": UNRESOLVED}
    # Both endpoints inspected, no direct edge: a path question, not a missing lookup.
    hop = ObjectiveTracker(spec=spec(relations=[{"id": "R9", "source": "FUN_00001000", "target": "FUN_00003000"}]),
                           function_exists=lambda n: n in GRAPH)
    assert "function_facts of FUN_00001000 or FUN_00003000" in hop.relation_status(obs)[0].missing[0]
    inspected = obs + [EvidenceObservation(id="E9", tool="function_facts", arguments={"function": "FUN_00001000"},
                                           result=facts("FUN_00001000"))]
    assert "needs a path capability" in hop.relation_status(inspected)[0].missing[0]

    obs.append(EvidenceObservation(
        id="E2", tool="function_effects", arguments={"function": "FUN_00002000"},
        result={"status": "complete", "coverage": "complete", "calls": [{"pc": "0x2004", "target": "0x00003000"}],
                "accesses": [{"kind": "write", "address": "0x20000100", "guard": "conditional"}]},
    ))
    obs.append(EvidenceObservation(
        id="E3", tool="observed_call_arguments", arguments={"function": "FUN_00002000", "scenario": "vl-jog-f0"},
        result={"status": "ok", "observed_entries": 1,
                "call_sites": [{"caller": "FUN_00001000", "status": "OBSERVED"}]},
    ))
    statuses = {s.id: s for s in tracker.relation_status(obs)}
    assert statuses["R1"].level == OBSERVED and statuses["R2"].level == SYMBOLIC and statuses["R3"].level == SYMBOLIC
    assert "guard conditional" in statuses["R3"].evidence[-1]["detail"]
    assert any("observe_call_arguments of FUN_00003000" in m for m in statuses["R2"].missing)

    obs.append(EvidenceObservation(
        id="E4", tool="observed_call_arguments", arguments={"function": "FUN_00003000", "scenario": "vl-jog-f0"},
        result={"status": "ok", "observed_entries": 0, "call_sites": []},
    ))
    r2 = next(s for s in tracker.relation_status(obs) if s.id == "R2")
    assert r2.level == SYMBOLIC and "not entered under scenario vl-jog-f0" in r2.blockers[-1]["detail"]
    assert "scenario coverage gap" in r2.missing[-1] and "(E4)" in r2.missing[-1]


def test_other_image_endpoint_is_never_resolved_against_the_loaded_image():
    objective = spec(firmware="fw", relations=[
        {"id": "R0", "source": "0x1000", "target": "FUN_00002000", "source_firmware": "remote"},
    ])
    tracker = ObjectiveTracker(spec=objective, function_exists=lambda n: True, firmware_key="fw")
    status = tracker.relation_status([])[0]
    assert status.source == "remote:0x00001000" and tracker.anchors() == ["FUN_00002000"]
    assert any("multi-image" in m for m in status.missing)
    assert not any("function_effects" in m for m in status.missing)


def test_timeout_is_recorded_shown_and_never_absence():
    timeout = {"status": "bounded: timeout 300s", "coverage": "bounded: timeout 300s", "reads": 0, "writes": 0,
               "calls": [], "accesses": [], "planner_summary": "no result within the bound"}
    controller, session, planner, executor = make(
        [
            ("follow_lead", {"lead_id": "L2"}),
            ("analyze_function_effects", {"function": "FUN_00002000"}),
            ("analyze_function_effects", {"function": "FUN_00002000"}),
            ("finish", {"reason": "done"}),
        ],
        objective=spec(),
        overrides={("function_effects", "FUN_00002000"): timeout},
    )
    result = controller.run(session)

    effects = [c for c in executor.calls if c[0] == "function_effects"]
    assert len(effects) == 1, "the timed-out analysis is not repeated"
    outcome = controller.tracker.outcomes[-1]
    assert outcome.outcome == FAILED and "timeout" in outcome.note
    assert any("FAILED (do not repeat): E2" in p for p in planner.prompts[2:])
    relations = {r["id"]: r for r in result.objective_report["relations"]}
    assert relations["R3"]["level"] == UNRESOLVED and "not absence of effects" in relations["R3"]["blockers"][0]["detail"]
    assert "capability gap" in relations["R3"]["missing"][-1]
    assert any("R3 FUN_00002000 -> 0x20000100" in p and "needs: function_effects of FUN_00002000 failed (E2)" in p
               for p in planner.prompts[2:])
    # The handler's effects say nothing about whether the dispatcher calls it.
    assert relations["R1"]["blockers"] == [] and relations["R2"]["blockers"] != []


def test_outcomes_are_classified():
    controller, session, _, _ = make(
        [("follow_lead", {"lead_id": "L2"}), ("finish", {"reason": "done"})], objective=spec()
    )
    controller.run(session)
    assert controller.tracker.outcomes[0].outcome == STRENGTHENED
    assert set(controller.tracker.outcomes[0].relations) == {"R1", "R2"}

    tracker = ObjectiveTracker(spec=spec(), function_exists=lambda n: n in GRAPH)
    noise = EvidenceObservation(id="E1", tool="census_peripheral_usage", arguments={"peripheral": "PORT"}, result={"status": "ok"})
    record = tracker.record(step=1, action="analyze", tool="census_peripheral_usage", arguments={"peripheral": "PORT"},
                            observation=noise, observations=[noise], relevant=False)
    assert record.outcome == NO_PROGRESS and tracker.since_progress == 1


def test_repeated_low_value_steps_replan_then_stop_with_report():
    objective = spec(replan_after=1, stall_limit=2)
    controller, session, planner, executor = make(
        [
            # L1 is FUN_00004000 (registered below, before the run); the
            # endpoint leads follow: L2 FUN_00001000, L3 FUN_00002000, L4 FUN_00003000.
            ("follow_lead", {"lead_id": "L3"}),          # strengthens R1, R2
            ("follow_lead", {"lead_id": "L1"}),          # one hop from an endpoint: relevant, no level change
            ("follow_lead", {"lead_id": "L2"}),          # endpoint: relevant, no level change
            ("follow_lead", {"lead_id": "L4"}),          # never requested: stalled
        ],
        objective=objective,
        max_steps=10,
    )
    session.state.add_lead(session.registry.register(kind="x", description="d", tool="function_facts",
                                                     arguments={"function": "FUN_00004000"}))
    result = controller.run(session)

    assert result.stop_reason == "objective_stalled"
    assert [o.outcome for o in controller.tracker.outcomes] == [STRENGTHENED, "relevant_partial", "relevant_partial"]
    assert "REPLAN:" in planner.prompts[2] and "REPLAN:" not in planner.prompts[1]
    report = result.objective_report
    assert report["answered"] is False and report["unresolved_relations"] == ["R1", "R2", "R3"]
    assert report["stop_reason"] == "objective_stalled" and "consecutive steps without progress" in report["explanation"]
    assert report["composition"].startswith("not attempted")
    assert len(executor.calls) == 3


# -- 6. budget exhaustion ----------------------------------------------------------------


def test_budget_exhaustion_reports_unresolved_relations_as_open_questions():
    controller, session, _, _ = make(
        [("follow_lead", {"lead_id": "L2"}), ("follow_lead", {"lead_id": "L1"})], objective=spec(), max_steps=2
    )
    result = controller.run(session)

    assert result.stop_reason == "step_budget_exhausted"
    report = result.objective_report
    assert report["budget"] == {"max_steps": 2, "steps_used": 2}
    assert {r["id"]: r["level"] for r in report["relations"]} == {"R1": STATIC, "R2": STATIC, "R3": UNRESOLVED}
    questions = [q.question for q in session.state.open_questions if q.source == "objective"]
    assert len(questions) == 3 and any(q.startswith("R3 FUN_00002000 -> 0x20000100 is UNRESOLVED") for q in questions)
    assert result.proposed_claims == ()  # nothing is promoted by the report


def test_no_relevant_operation_stops_without_a_planner_call():
    objective = spec(relations=[{"id": "R1", "source": "0x20000100", "target": "0x20000200"}])
    controller, session, planner, _ = make([], objective=objective)
    result = controller.run(session)
    assert result.stop_reason == "objective_no_relevant_operation" and planner.prompts == []
    assert result.objective_report["relations"][0]["level"] == UNRESOLVED
