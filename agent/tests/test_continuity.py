"""
ResearchController continuity: historical-operation reuse, seeded-lead
priority, and budget accounting in follow-up sessions (research/history.py).

Builds on the investigation-continuity fixtures (test_followups): a
SERCOM-shaped Investigation A recorded in a temporary ledger, its follow-up
candidate, and Investigation B run by the real ResearchController with a
scripted planner. Scenario letters follow the continuity-v2 milestone.
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest

from aptrace_agent.investigator import AutonomousInvestigationRun
from aptrace_agent.ledger.models import ClaimState, InvestigationRun, SourceRevision
from aptrace_agent.ledger.recorder import RecordingExecutor, record_investigation
from aptrace_agent.ledger.store import now
from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchController, ResearchSession
from aptrace_agent.research.followups import generate_followups, seed_session
from aptrace_agent.research.history import HistoricalOperations
from aptrace_agent.work import handoff
from aptrace_agent.work.followups import followup_reference, materialize

from test_followups import (  # noqa: F401  (world is a fixture)
    CALLERS,
    GAP,
    INIT,
    PERIPHERAL,
    SerialExecutor,
    deriver_for,
    generate,
    world,
)
from work_support import snapshot


class Planner:
    """
    Scripted planner. Each request takes the next action:
      ("follow", text)      follow the shown lead whose line contains text
                            (or the first offered lead when text is None)
      ("call", name, args)  emit this tool call as is, offered or not
      ("finish",)           finish
    With no actions left it follows the first offered lead, or finishes.
    """

    def __init__(self, actions=(), claims: str = "") -> None:
        self.actions = list(actions)
        self.claims = claims
        self.requests: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        tools = {t["function"]["name"]: t for t in kwargs["tools"]}
        prompt = "\n".join(str(m.get("content") or "") for m in kwargs["messages"])

        if list(tools) == ["finish"]:
            return self._call("finish", {"reason": "budget", "claims": self.claims})

        action = self.actions.pop(0) if self.actions else ("follow", None)

        if action[0] == "call":
            return self._call(action[1], action[2])
        if action[0] == "finish" or "follow_lead" not in tools:
            return self._call("finish", {"reason": "done", "claims": self.claims})

        offered = tools["follow_lead"]["function"]["parameters"]["properties"]["lead_id"]["enum"]
        lead = offered[0]

        if action[1] is not None:
            match = re.search(rf"^(L\d+) .*{re.escape(action[1])}", prompt, re.MULTILINE)
            lead = match.group(1) if match and match.group(1) in offered else lead

        return self._call("follow_lead", {"lead_id": lead})

    @staticmethod
    def _call(name, arguments):
        call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=json.dumps(arguments)))
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[call]))])

    def prompts(self) -> list[str]:
        return ["\n".join(str(m.get("content") or "") for m in r["messages"]) for r in self.requests]


def follow_up(world, planner, *, history=True, context=None, candidate=None, seeds=(), max_steps=4, structural=("function_effects",), executor=None, work_item_id=None, tune=None):
    """Investigation B for the top candidate; returns (run record, executor, session, controller)."""

    candidate = candidate or generate(world).shortlist[0]
    context = context or world.context()
    executor = executor or SerialExecutor()
    recorder = RecordingExecutor(executor)
    registry = LeadRegistry()
    session = ResearchSession(objective=candidate.objective, registry=registry, follower=LeadFollower(registry=registry, executor=recorder), deriver=deriver_for(registry))

    for kind, description, tool, arguments in seeds:
        session.state.add_lead(registry.register(kind=kind, description=description, tool=tool, arguments=arguments))

    hist = HistoricalOperations.for_followup(world.ledger, context, candidate) if history else None
    seed_session(session, candidate, history=hist)

    if tune is not None:
        tune(session)

    controller = ResearchController(
        planner_client=planner, planner_model="scripted", reconciler=object(), max_steps=max_steps, claim_contract=True,
        structural_tools=structural, census_peripherals=(PERIPHERAL,),
    )
    result = controller.run(session)
    run = AutonomousInvestigationRun(
        objective=candidate.objective, seed_function=None, result=result, state=session.state.model_copy(deep=True),
        evidence=tuple(session.ledger.all()),
        continuity=session.continuity.record(max_steps=max_steps) if session.continuity else None,
    )
    recorded = record_investigation(
        world.ledger, run, context=context, recorder=recorder, model="scripted", execution_config={}, planner_version="test",
        budgets={"max_steps": max_steps}, started_at=now(), ended_at=now(), source=SourceRevision(), work_item_id=work_item_id,
        followup=candidate.provenance(),
    )
    return recorded, executor, session, controller


def executed(executor, tool):
    return [arguments for name, arguments in executor.calls if name == tool]


def invocations(world, run):
    return [world.ledger.invocation(i) for i in run.invocation_ids]


# -- A: compatible historical operation -------------------------------------------------


def test_a_compatible_history_is_used_by_reference_not_rerun(world):
    # The planner follows a lead whose operation run A already executed.
    seeds = [("function", f"Inspect {INIT}", "function_facts", {"function": INIT})]
    run, executor, session, _ = follow_up(world, Planner([("follow", f"function_facts {INIT}")]), seeds=seeds, max_steps=2)

    assert {"function": INIT} not in executed(executor, "function_facts")
    reuse = next(r for r in run.continuity.reused if r.trigger == "lead")
    original = next(i for i in invocations(world, world.run_a) if i.tool == "function_facts" and i.arguments == {"function": INIT})
    assert (reuse.invocation_id, reuse.evidence_id, reuse.source_run_id) == (original.invocation_id, original.evidence_id, world.run_a.run_id)
    assert run.trajectory[0]["reused_from"] == original.evidence_id

    # The cited prior analyses are preloaded as references, and none ran again.
    preloaded = {(r.tool, json.dumps(r.arguments, sort_keys=True)) for r in run.continuity.reused if r.trigger == "preload"}
    assert ("census_peripheral_usage", json.dumps({"limit": 25, "peripheral": PERIPHERAL}, sort_keys=True)) in preloaded
    assert ("function_effects", json.dumps({"function": GAP, "specialize": {}}, sort_keys=True)) in preloaded
    assert executed(executor, "census_peripheral_usage") == [] and executed(executor, "function_effects") == []


# -- B: changed firmware -------------------------------------------------------------------


def test_b_different_firmware_is_never_reused(world):
    other = world.context().model_copy(update={"firmware_sha256": "0" * 64})
    candidate = generate(world).shortlist[0]
    history = HistoricalOperations(world.ledger, other, run_ids=[world.run_a.run_id])
    decision = history.lookup("census_peripheral_usage", {"peripheral": PERIPHERAL, "limit": 25})

    assert decision is not None and not decision.reusable
    assert decision.reason.startswith("different firmware")

    run, executor, _session, _ = follow_up(world, Planner(), context=other, candidate=candidate, max_steps=1)
    assert not run.continuity.reused
    assert any(r.reason.startswith("different firmware") for r in run.continuity.refused)


# -- C: changed tool assumptions -----------------------------------------------------------


def test_c_changed_inputs_refuse_only_the_tools_that_read_them(world):
    world.context.artifacts["census_db"] = "d" * 64
    history = HistoricalOperations(world.ledger, world.context(), run_ids=[world.run_a.run_id])
    census = history.lookup("census_peripheral_usage", {"peripheral": PERIPHERAL, "limit": 25})
    facts = history.lookup("function_facts", {"function": GAP})

    assert not census.reusable and census.reason == "input artifacts differ: census_db"
    # function_facts reads only the Ghidra export, which did not change.
    assert facts.reusable


def test_c_changed_analysis_version_refuses_reuse(world):
    history = HistoricalOperations(world.ledger, world.context(), run_ids=[world.run_a.run_id], analysis_versions={"function_effects": 2})
    decision = history.lookup("function_effects", {"function": GAP, "specialize": {}})

    assert not decision.reusable
    assert decision.reason == "function_effects analysis version 1 differs from current 2"


def test_c_invalidated_or_tampered_evidence_is_not_reused(world):
    original = next(i for i in invocations(world, world.run_a) if i.tool == "function_facts" and i.arguments == {"function": GAP})
    world.ledger.invalidate_evidence(original.evidence_id, reason="test")
    history = HistoricalOperations(world.ledger, world.context(), run_ids=[world.run_a.run_id])

    assert history.lookup("function_facts", {"function": GAP}).reason.endswith("is INVALIDATED")

    census = next(i for i in invocations(world, world.run_a) if i.tool == "census_peripheral_usage")
    blob = world.ledger.blob_path(census.result_sha256)
    blob.write_text(blob.read_text().replace(PERIPHERAL, "SERCOM8"))
    assert "fails its integrity check" in history.lookup(census.tool, census.arguments).reason


def test_c_case_document_search_is_never_reused(world, tmp_path):
    history = HistoricalOperations(world.ledger, world.context(), run_ids=[world.run_a.run_id])
    decision = history._check(next(i for i in invocations(world, world.run_a)).model_copy(update={"tool": "search_case_evidence"}))

    assert not decision.reusable and "not a deterministic" in decision.reason


# -- D: prior analysis does not resolve a pending lead --------------------------------------


def test_d_inspected_function_does_not_resolve_its_open_call_site_leads(world):
    candidate = generate(world).shortlist[0]
    history = HistoricalOperations.for_followup(world.ledger, world.context(), candidate)
    # Run A inspected GAP's facts; the call-site leads into GAP are different operations.
    assert history.lookup("function_facts", {"function": GAP}).reusable
    assert all(history.lookup(lead.tool, lead.arguments) is None for lead in candidate.seeded_leads if lead.tool == "callsite_context")

    run, _executor, session, _ = follow_up(world, Planner([("finish",)]), candidate=candidate, max_steps=2)
    callsites = [o for o in run.continuity.seeded_leads if o.tool == "callsite_context"]

    assert callsites and all(o.outcome in ("offered", "not-offered") for o in callsites)
    assert all(lead.status.value == "OPEN" for lead in session.state.leads if lead.origin and lead.description.startswith("Inspect incoming"))


# -- E: redundant discovery request ----------------------------------------------------------


def test_e_peripheral_rediscovery_is_not_executed_and_seeded_leads_come_first(world):
    planner = Planner([("call", "analyze_peripheral", {"peripheral": PERIPHERAL})], claims="")
    run, executor, _session, _ = follow_up(world, planner, max_steps=3)

    assert executed(executor, "census_peripheral_usage") == []
    first = planner.prompts()[0]
    # SERCOM is already known from the prior run and offered nowhere.
    assert f"census:{PERIPHERAL}(E1=prior)" in first or "=prior)" in first
    assert "analyze_peripheral" not in [t["function"]["name"] for t in planner.requests[0]["tools"]]
    assert "0) [follow-up] leads" in first
    lead_lines = [line for line in first.splitlines() if re.match(r"L\d+ ", line)]
    assert lead_lines and lead_lines[0].endswith("[follow-up]")
    # The rejected request did not cost a step: three steps followed seeded leads.
    followed = [o for o in run.continuity.seeded_leads if o.outcome == "executed"]
    assert len(followed) == 3 and run.continuity.budget["steps_charged"] == 3


def test_e_without_preload_a_requested_historical_analysis_is_reused(world):
    candidate = generate(world).shortlist[0].model_copy(update={"evidence_ids": [], "seeded_leads": []})
    planner = Planner([("call", "analyze_peripheral", {"peripheral": PERIPHERAL}), ("finish",)])
    run, executor, _session, _ = follow_up(world, planner, candidate=candidate, max_steps=2)

    assert executed(executor, "census_peripheral_usage") == []
    assert [r.trigger for r in run.continuity.reused] == ["lead"]
    assert run.trajectory[0]["action"] == "analyze" and run.trajectory[0]["reused_from"]
    assert run.continuity.budget["steps_charged"] == 0 and run.continuity.budget["free_reuses"] == 1


# -- F: repeated reuse requests are bounded ----------------------------------------------------


def test_f_repeated_requests_for_a_historical_analysis_terminate(world):
    # The planner asks for the same prior analysis forever.
    planner = Planner([("call", "analyze_function_effects", {"function": GAP})] * 50)
    run, executor, _session, _ = follow_up(world, planner, max_steps=4)
    budget = run.continuity.budget

    assert executed(executor, "function_effects") == []
    assert budget["decisions"] <= budget["max_steps"] + budget["max_free_reuses"]
    # The planner never produced a usable decision; APTrace followed seeded
    # leads on its behalf, bounded, then stopped.
    assert 1 <= budget["fallbacks"] <= budget["max_fallbacks"]
    assert [s["action"] for s in run.trajectory][: budget["fallbacks"]] == ["fallback_lead"] * budget["fallbacks"]
    assert run.termination_reason in ("planner_contract_exhausted", "step_budget_exhausted")
    assert len(planner.requests) < 50


def test_f_free_reuses_are_capped_then_charged(world):
    seeds = [
        ("function", f"Inspect {INIT}", "function_facts", {"function": INIT}),
        ("function", f"Inspect {GAP}", "function_facts", {"function": GAP}),
    ]

    def one_free(session):
        session.continuity.max_free_reuses = 1

    candidate = generate(world).shortlist[0].model_copy(update={"evidence_ids": []})
    planner = Planner([("follow", f"function_facts {INIT}"), ("follow", f"function_facts {GAP}")])
    run, _executor, _session, _ = follow_up(world, planner, candidate=candidate, seeds=seeds, max_steps=2, tune=one_free)
    budget = run.continuity.budget

    assert [s.get("reused_from") is not None for s in run.trajectory[:3]] == [True, True, False]
    assert budget["free_reuses"] == 1 and budget["steps_charged"] == 2 and budget["decisions"] == 3


# -- G: provenance -------------------------------------------------------------------------------


def test_g_reuse_creates_no_new_observation_and_keeps_original_provenance(world):
    before = {p: h for p, h in snapshot(world.root).items() if p.startswith(("invocations/", "evidence/", "blobs/"))}
    # Claim cites E1, the preloaded census alias, and E-new from a seeded call site.
    planner = Planner([("follow", CALLERS[0][0])], claims=f"PROBABLE STRUCTURE E1 {GAP} loads the {PERIPHERAL} base address.")
    run, _executor, _session, _ = follow_up(world, planner, max_steps=1)
    reused = {r.evidence_id for r in run.continuity.reused}
    census = next(r for r in run.continuity.reused if r.tool == "census_peripheral_usage")

    # No invocation of B repeats a reused operation, and reused evidence is not B's evidence.
    assert not {i.operation_key for i in invocations(world, run)} & {r.operation_key for r in run.continuity.reused}
    assert not set(run.evidence_ids) & reused
    assert len(run.evidence_ids) == len(run.invocation_ids) == 1
    # Original records are untouched.
    after = snapshot(world.root)
    assert all(after[p] == h for p, h in before.items())
    # A claim citing the session alias cites the original evidence.
    claim = world.ledger.claim(run.claim_versions[0])
    assert claim.supporting_evidence_ids == [census.evidence_id]
    assert world.ledger.evidence(census.evidence_id).invocation_id == census.invocation_id


# -- H: backward compatibility ----------------------------------------------------------------------


def test_h_standalone_and_legacy_seeding_are_unchanged(world):
    raw = json.loads((world.root / "runs" / f"{world.run_a.run_id}.json").read_text())

    assert "continuity" not in raw and all("reused_from" not in step for step in raw["trajectory"])
    assert InvestigationRun.model_validate({k: v for k, v in raw.items()}).continuity is None

    # Seeding without history is the spike behaviour: no tracker, no origin, no preload.
    run, executor, session, _ = follow_up(world, Planner(), history=False, max_steps=1)
    assert session.continuity is None and run.continuity is None
    assert all(lead.origin is None for lead in session.state.leads)
    assert not any(o.reused_from for o in session.ledger.all())


# -- I: Beads hand-off ----------------------------------------------------------------------------------


def test_i_followup_work_item_runs_with_history_and_completion_verifies_nothing(world):
    candidate = generate(world).shortlist[0]
    item = materialize(world.store, candidate, context=world.context(), prefix="apt", source_item=world.item.id).item
    events_before = len(world.ledger.events())

    def investigate(objective, work_item_id):
        run_id, key = followup_reference(world.store.get_work(work_item_id))
        found = generate_followups(world.ledger, run_id, context=world.context(), deriver_for=deriver_for).find(key)
        run, _executor, _session, _ = follow_up(world, Planner(), candidate=found, max_steps=3, work_item_id=work_item_id)
        return run.run_id

    outcome = handoff.run_investigation(world.store, world.ledger, item.id, actor="tester", context=world.context(), lock_dir=world.locks, investigate=investigate)
    run = world.ledger.run(outcome.run_id)

    assert run.work_item_id == item.id and run.continuity is not None and run.continuity.reused
    assert outcome.reconciliation.state == handoff.AWAITING_COMPLETION
    assert world.store.get_work(item.id).assignee == "tester"

    rec = handoff.complete_investigation(world.store, world.ledger, item.id, actor="tester", lock_dir=world.locks)
    assert rec.state == handoff.COMPLETED
    assert world.ledger.state(world.claim) == ClaimState.PROPOSED
    assert all(e.subject != world.claim for e in world.ledger.events()[events_before:])


def test_planner_failure_after_followup_work_still_requests_final_claims(world):
    # Two valid follows, then the planner only emits invalid calls; once no
    # follow-up lead is left to fall back on, the run ends but is asked for claims.
    invalid = [("call", "no_such_tool", {})] * 20
    planner = Planner([("follow", CALLERS[0][0]), ("follow", CALLERS[1][0]), *invalid], claims=f"PROBABLE STRUCTURE E9 {GAP} is called by {CALLERS[0][0]}.")

    def no_fallback(session):
        session.continuity.max_fallbacks = 0

    run, _executor, _session, _ = follow_up(world, planner, max_steps=6, tune=no_fallback)

    assert run.termination_reason == "planner_contract_exhausted"
    assert [r["phase"] for r in run.planner_requests][-1] == "final-claims"
    assert run.claim_versions
