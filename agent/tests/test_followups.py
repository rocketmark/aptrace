"""
Investigation continuity: follow-up candidates for a recorded run, their
Beads materialization, and a seeded follow-up investigation.

Runs without Ghidra, a model, or Beads. Investigation A and B run the real
ResearchController with a scripted planner over a SERCOM-shaped fake
executor, and record through record_investigation; FakeWorkStore mirrors
bd 1.3.1 (work_support). Scenario letters follow the continuity spike.
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest

from aptrace_agent.investigator import AutonomousInvestigationRun
from aptrace_agent.ledger.models import AuditRecord, AuditVerdict, ClaimState, FollowUpRequest, SourceRevision
from aptrace_agent.ledger.operations import input_artifacts
from aptrace_agent.ledger.recorder import RecordingExecutor, record_investigation
from aptrace_agent.ledger.store import ResearchLedger, now
from aptrace_agent.research import LeadDeriver, LeadFollower, LeadRegistry, ResearchController, ResearchSession
from aptrace_agent.research.followups import (
    BLOCKED,
    CLAIM_FOLLOWUP,
    LEAD_GROUP,
    PROPOSED,
    REDUNDANT,
    continuity_review,
    generate_followups,
    seed_session,
)
from aptrace_agent.schemas import EvidenceObservation
from aptrace_agent.work import handoff
from aptrace_agent.work.followups import (
    PRIOR_FOLLOWUPS,
    RELATED_WORK,
    FollowUpRefused,
    followup_item_id,
    followup_reference,
    materialize,
)
from aptrace_agent.work.store import CLOSED, DuplicateWork

from ledger_support import FakeExecutor, MutableContext
from work_support import FakeWorkStore, snapshot


PERIPHERAL = "SERCOM9"
BASE = "0x40009000"
# Loads the peripheral base from its literal pool; reads through r0.
GAP = "FUN_00001000"
# Another constant loader with an unexplored callee path.
INIT = "FUN_00002000"
CALLERS = [("FUN_00003000", "0x00003004"), ("FUN_00003100", "0x00003104"), ("FUN_00003200", "0x00003204")]
CALLEES = [("FUN_00004000", "0x00002004"), ("FUN_00004000", "0x00002008"), ("FUN_00004100", "0x0000200c")]

ACCESS_CLAIM = f"STRONG RESOLUTION E1,E2 {GAP} is reachable and involves {PERIPHERAL} peripheral access."
DEVICE_CLAIM = f"PROBABLE BEHAVIOR E2 {PERIPHERAL} is connected to the sub-GHz radio."


def census() -> dict:
    def entry(function: str, pool: str) -> dict:
        return {
            "function": function,
            "constant_loads": [{"pool_address": pool, "value": BASE, "site": pool, "ref_type": "READ"}],
            "constant_load_count": 1,
            "mmio_site_count": 0,
            "mmio_sites": [],
        }

    return {"status": "ok", "peripheral": PERIPHERAL, "functions": [entry(GAP, "0x00001040"), entry(INIT, "0x00002040")]}


def effects(function: str, *, mmio: bool) -> dict:
    accesses = [
        {"address": "parametric", "depends_on": ["r0"], "kind": "read", "region": None, "width": 4},
        {"address": "0x1040", "depends_on": [], "kind": "read", "region": "FLASH", "width": 4},
    ]

    if mmio:
        accesses.append({"address": BASE, "depends_on": [], "kind": "write", "region": "MMIO", "width": 4})

    return {"function": function, "coverage": "complete", "accesses": accesses, "calls": []}


def facts(function: str) -> dict:
    if function == GAP:
        callers, callees = CALLERS, []
    elif function == INIT:
        callers, callees = [], CALLEES
    else:
        callers, callees = [], []

    return {
        "name": function,
        "entry": "0x0",
        "callers": [{"function": f, "address": a} for f, a in callers],
        "callees": [{"function": f, "address": a} for f, a in callees],
    }


class SerialExecutor(FakeExecutor):
    def __init__(self, *, mmio: bool = False) -> None:
        super().__init__()
        self.mmio = mmio

    def execute_operation(self, tool, arguments, *, evidence_id):
        if tool == "census_peripheral_usage" and arguments.get("peripheral") == PERIPHERAL:
            result = census()
        elif tool == "function_effects":
            result = effects(arguments["function"], mmio=self.mmio)
        elif tool == "function_facts":
            result = facts(arguments["function"])
        elif tool == "callsite_context":
            result = {"function": arguments["function"], "address": arguments["address"], "instructions": [{"address": arguments["address"], "mnemonic": "bl", "operands": GAP}]}
        else:
            return super().execute_operation(tool, arguments, evidence_id=evidence_id)

        self.calls.append((tool, dict(arguments)))
        return EvidenceObservation(id=evidence_id, tool=tool, arguments=arguments, result=result)


class Readers:
    """Accepts every call site and function (the fixture firmware is consistent)."""

    def context(self, function, address, before=8, after=8):
        return {}

    def function_facts(self, function):
        return facts(function)


def deriver_for(registry: LeadRegistry) -> LeadDeriver:
    return LeadDeriver(registry=registry, callsite_reader=Readers(), function_facts_reader=Readers())


class ScriptedPlanner:
    """Follows the named leads in order (else the first offered), then proposes claims."""

    def __init__(self, picks: list[str], claims: str) -> None:
        self.picks = list(picks)
        self.claims = claims
        self.requests: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        tools = {t["function"]["name"]: t for t in kwargs["tools"]}

        if "follow_lead" in tools:
            offered = tools["follow_lead"]["function"]["parameters"]["properties"]["lead_id"]["enum"]
            prompt = "\n".join(str(m.get("content") or "") for m in kwargs["messages"])
            # A pick is a lead id, or text of a lead line the prompt shows.
            shown = {p: m.group(1) for p in self.picks if (m := re.search(rf"^(L\d+) .*{re.escape(p)}", prompt, re.MULTILINE))}
            pick = next((p for p in self.picks if p in offered or shown.get(p) in offered), offered[0])
            pick, self.picks = shown.get(pick, pick), [p for p in self.picks if p != pick]

            name, arguments = "follow_lead", {"lead_id": pick}
        else:
            name, arguments = "finish", {"reason": "budget", "claims": self.claims}

        call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=json.dumps(arguments)))
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[call]))])

    def prompts(self) -> list[str]:
        return ["\n".join(str(m.get("content") or "") for m in request["messages"]) for request in self.requests]


def run_research(ledger, context, objective, work_item_id, *, planner, seeds=(), followup=None, executor=None, max_steps=4):
    """The `research --ledger` path: controller run, then record_investigation."""

    registry = LeadRegistry()
    recorder = RecordingExecutor(executor or SerialExecutor())
    session = ResearchSession(objective=objective, registry=registry, follower=LeadFollower(registry=registry, executor=recorder), deriver=deriver_for(registry))

    for kind, description, tool, arguments in seeds:
        session.state.add_lead(registry.register(kind=kind, description=description, tool=tool, arguments=arguments))

    if followup is not None:
        seed_session(session, followup)

    started = now()
    result = ResearchController(planner_client=planner, planner_model="scripted", reconciler=object(), max_steps=max_steps, claim_contract=True).run(session)
    run = AutonomousInvestigationRun(objective=objective, seed_function=None, result=result, state=session.state.model_copy(deep=True), evidence=tuple(session.ledger.all()))
    return record_investigation(
        ledger, run, context=context(), recorder=recorder, model="scripted", execution_config={}, planner_version="test",
        budgets={"max_steps": max_steps}, started_at=started, ended_at=now(), source=SourceRevision(), work_item_id=work_item_id,
        followup=followup.provenance() if followup is not None else None,
    ).run_id


SEEDS = [
    ("census", f"Analyze {PERIPHERAL} usage", "census_peripheral_usage", {"peripheral": PERIPHERAL, "limit": 25}),
    ("effects", f"Effects of {GAP}", "function_effects", {"function": GAP, "specialize": {}}),
    ("function", f"Inspect {GAP}", "function_facts", {"function": GAP}),
    ("function", f"Inspect {INIT}", "function_facts", {"function": INIT}),
]


@pytest.fixture
def world(tmp_path):
    """Investigation A, executed for a work item and recorded."""

    ledger = ResearchLedger(tmp_path / "ledger")
    context = MutableContext()
    store = FakeWorkStore()
    locks = tmp_path / "locks"
    item = handoff.create_investigation(store, context=context(), objective=f"Investigate {PERIPHERAL} usage")
    planner = ScriptedPlanner(["L2", "L1", "L3", "L4"], ACCESS_CLAIM + "\n" + DEVICE_CLAIM)
    outcome = handoff.run_investigation(
        store, ledger, item.id, actor="tester", context=context(), lock_dir=locks,
        investigate=lambda objective, work_item_id: run_research(ledger, context, objective, work_item_id, planner=planner, seeds=SEEDS),
    )
    run_a = ledger.run(outcome.run_id)
    claim, device = run_a.claim_versions
    return SimpleNamespace(ledger=ledger, context=context, store=store, locks=locks, item=item, run_a=run_a, claim=claim, device=device, root=tmp_path / "ledger")


def generate(world, **kwargs):
    return generate_followups(world.ledger, world.run_a.run_id, context=world.context(), deriver_for=deriver_for, **kwargs)


def by_category(report, category):
    return [c for c in report.candidates() if c.category == category]


# -- frontier -----------------------------------------------------------------


def test_frontier_is_rederived_from_durable_evidence_and_matches_recorded_count(world):
    report = generate(world)

    assert world.run_a.planner_requests[-1]["open_leads"] == 12
    assert report.frontier.status == "re-derived"
    assert len(report.frontier.leads) == report.frontier.recorded_open_count == 12
    assert "MISMATCH" not in report.frontier.detail
    # Every lead names the durable evidence it came from, never session ids.
    assert all(e.startswith("EV-") and e in world.run_a.evidence_ids for lead in report.frontier.leads for e in lead.source_evidence_ids)


def test_frontier_is_refused_when_inputs_changed(world):
    world.context.artifacts["ghidra_export"] = "f" * 64
    report = generate(world)

    assert report.frontier.status == "unavailable"
    assert "differs from current" in report.frontier.detail
    assert report.limitations and "only claim-based candidates" in report.limitations[0]
    assert not by_category(report, LEAD_GROUP)


def test_without_a_deriver_the_limitation_is_reported(world):
    report = generate_followups(world.ledger, world.run_a.run_id, context=world.context())

    assert report.frontier.status == "unavailable"
    assert any("frontier unavailable" in text for text in report.limitations)


# -- scenario A: related leads consolidate ------------------------------------------


def test_scenario_a_related_leads_are_consolidated_into_a_small_shortlist(world):
    report = generate(world)
    init = [c for c in by_category(report, LEAD_GROUP) if INIT in c.objective and c.lead_count > 1]

    assert len(init) == 1
    group = init[0]
    assert group.lead_count == 7  # 3 call sites + facts/disassembly of 2 callees
    assert {lead.anchor for lead in group.seeded_leads} == {INIT}
    assert "consolidates 7 open lead(s)" in " ".join(group.priority_basis)
    # 12 open leads -> 3 proposed candidates, not 12 work items.
    assert len(report.shortlist) == 3
    assert sum(c.lead_count for c in report.shortlist) == 12


# -- scenario B: unsupported claim ------------------------------------------------------


def test_scenario_b_constant_load_does_not_establish_peripheral_access(world):
    report = generate(world)
    top = report.shortlist[0]

    assert top.category == CLAIM_FOLLOWUP and top.rank == 1
    assert top.claim_versions == [world.claim]
    assert "PERIPHERAL_ACCESS_UNESTABLISHED" in top.priority_basis[0]
    assert "pattern-matched" in top.priority_basis[0]
    assert f"Does {GAP} read or write {PERIPHERAL} registers via the r0 address its callers supply" in top.objective
    assert "do not assume the claim is true" in top.objective
    assert "mmio_site_count 0" in top.reason and "0 MMIO accesses" in top.reason
    # The callers that supply r0 are seeded first; the gap function's own
    # census-derived disassembly lead is absorbed too.
    callers = [(lead.arguments["function"], lead.arguments["address"]) for lead in top.seeded_leads if lead.tool == "callsite_context"]
    assert callers == CALLERS
    assert ("function_disassembly", GAP) in {(lead.tool, lead.arguments.get("function")) for lead in top.seeded_leads}
    assert top.prior_hypotheses[0].startswith(f"[prior {world.claim} PROPOSED, unverified]")


def test_scenario_b_no_gap_when_effects_show_an_mmio_access(tmp_path):
    ledger = ResearchLedger(tmp_path / "ledger")
    context = MutableContext()
    planner = ScriptedPlanner(["L2", "L1", "L3", "L4"], ACCESS_CLAIM)
    run_id = run_research(ledger, context, "objective", None, planner=planner, seeds=SEEDS, executor=SerialExecutor(mmio=True))
    report = generate_followups(ledger, run_id, context=context(), deriver_for=deriver_for)

    assert not by_category(report, CLAIM_FOLLOWUP)
    assert any("no recorded audit, verification, or evidence-gap rule applies" in text for text in report.limitations)


# -- scenario C: already completed analyses ---------------------------------------------


def test_scenario_c_group_whose_analyses_were_already_recorded_is_redundant(world):
    report = generate(world)
    group = next(c for c in report.shortlist if c.category == LEAD_GROUP and c.lead_count == 7)
    context = world.context()
    executor = SerialExecutor()

    # Another run already executed every analysis in the group.
    for seq, lead in enumerate([lead for lead in report.frontier.leads if lead.anchor == INIT], start=1):
        observation = executor.execute_operation(lead.tool, lead.arguments, evidence_id=f"E{seq}")
        world.ledger.record_invocation(
            run_id="R-other", seq=seq, tool=lead.tool, arguments=lead.arguments, context=context,
            input_artifacts=input_artifacts(context, lead.tool), started_at=now(), ended_at=now(), runtime_ms=0.0, result=observation.result,
        )

    again = generate(world)
    same = again.find(group.key)

    assert same.status == REDUNDANT
    assert "all 7 analyses already recorded" in same.status_detail
    assert same in again.suppressed and same not in again.shortlist
    assert all("-> EV-" in line for line in same.analyses_performed if line.startswith(("callsite", "function_facts", "function_disassembly")))


# -- scenario D: audit challenge --------------------------------------------------------


def record_audit(ledger, claim, verdict, requests=(), challenges=()):
    audit = AuditRecord(
        audit_id=f"A-test-{len(requests)}-{verdict.value}",
        claim_version=claim,
        model="scripted-auditor",
        template_version="test",
        started_at=now(),
        ended_at=now(),
        termination_reason="verdict",
        initial_context="",
        verdict=verdict,
        challenges=list(challenges),
        follow_up_requests=[FollowUpRequest(question=q, suggested_tool=t) for q, t in requests],
    )
    return ledger.record_audit(audit)


def test_scenario_d_audit_request_becomes_a_followup_tied_to_audit_and_claim(world):
    audit = record_audit(
        world.ledger, world.claim, AuditVerdict.CHALLENGED,
        requests=[(f"Which callers pass a {PERIPHERAL} register address in r0?", "analyze_function_effects")],
        challenges=["constant load is not an access"],
    )
    # An audit follow-up item already exists from the existing audit path.
    audit_item, _ = handoff.followup_for_audit(world.store, world.ledger, audit.audit_id, prefix="apt")
    report = generate(world)
    top = report.shortlist[0]

    assert top.claim_versions == [world.claim] and top.audit_ids == [audit.audit_id]
    assert top.rank == 1
    assert any("AUDIT_REQUEST" in line for line in top.priority_basis)
    assert f"Which callers pass a {PERIPHERAL} register address in r0?" in top.objective

    made = materialize(world.store, top, context=world.context(), prefix="apt", source_item=world.item.id)

    assert made.created
    assert made.item.metadata["aptrace_audit_ids"] == [audit.audit_id]
    assert made.item.metadata[RELATED_WORK] == [audit_item.id]
    assert ClaimState(world.ledger.state(world.claim)) == ClaimState.PROPOSED


# -- scenario E: evidence unavailable ---------------------------------------------------


def test_scenario_e_device_identity_needs_hardware_and_is_blocked(world):
    report = generate(world)
    blocked = [c for c in report.suppressed if c.claim_versions == [world.device]]

    assert len(blocked) == 1
    assert blocked[0].status == BLOCKED
    assert "hardware-routing evidence" in blocked[0].blocker
    assert all(world.device not in c.claim_versions for c in report.shortlist if c.category == CLAIM_FOLLOWUP)

    with pytest.raises(FollowUpRefused):
        materialize(world.store, blocked[0], context=world.context(), prefix="apt")


def test_scenario_e_audit_request_for_an_unavailable_tool_is_blocked(world):
    record_audit(world.ledger, world.claim, AuditVerdict.UNRESOLVED, requests=[("Capture the SPI bus while the radio transmits", "logic_analyzer_capture")])
    report = generate(world)
    blocked = [c for c in report.suppressed if c.status == BLOCKED and c.audit_ids]

    assert len(blocked) == 1
    assert "'logic_analyzer_capture', which is not an APTrace operation" in blocked[0].blocker
    # The executable evidence gap on the same claim is still proposed.
    assert report.shortlist[0].claim_versions == [world.claim] and not report.shortlist[0].audit_ids


# -- scenario F: repeated generation and creation ------------------------------------------


def test_scenario_f_generation_is_stable_across_instances_and_reloads(world):
    first = generate(world).model_dump(mode="json")
    reloaded = generate_followups(ResearchLedger(world.root), world.run_a.run_id, context=world.context(), deriver_for=deriver_for).model_dump(mode="json")

    assert first == reloaded
    assert [c["key"] for c in first["shortlist"]] == [c["key"] for c in reloaded["shortlist"]]


def test_scenario_f_creation_is_idempotent_and_never_duplicates(world):
    report = generate(world)
    made = [materialize(world.store, c, context=world.context(), prefix="apt", source_item=world.item.id) for c in report.shortlist]
    count = len(world.store.items)
    again = [materialize(world.store, c, context=world.context(), prefix="apt", source_item=world.item.id) for c in generate(world).shortlist]

    assert all(m.created for m in made) and not any(a.created for a in again)
    assert len(world.store.items) == count
    assert [m.item.id for m in made] == [a.item.id for a in again]
    assert [m.item.priority for m in made] == [c.rank for c in report.shortlist]


def test_scenario_f_concurrent_creation_yields_one_item(world):
    class RacingStore(FakeWorkStore):
        def create_work(self, title, **kwargs):
            # Another process creates the same item between our check and create.
            super().create_work(title, **kwargs)
            raise DuplicateWork(f"issue {kwargs['item_id']} already exists")

    store = RacingStore()
    store.items = world.store.items
    candidate = generate(world).shortlist[0]
    made = materialize(store, candidate, context=world.context(), prefix="apt", source_item=world.item.id)

    assert not made.created and "created concurrently" in made.detail
    assert [i for i in store.items if i == followup_item_id("apt", candidate.key)] == [made.item.id]


def test_scenario_f_completed_followup_is_not_recreated(world):
    candidate = generate(world).shortlist[0]
    made = materialize(world.store, candidate, context=world.context(), prefix="apt")
    world.store.complete_work(made.item.id, "done")
    again = materialize(world.store, generate(world).shortlist[0], context=world.context(), prefix="apt")

    assert not again.created
    assert again.item.status == CLOSED and "completed; not recreated" in again.detail


def test_changed_evidence_basis_creates_a_new_item_linked_to_the_prior_one(world):
    old = generate(world).shortlist[0]
    first = materialize(world.store, old, context=world.context(), prefix="apt")
    world.store.complete_work(first.item.id, "done")
    world.context.artifacts["census_db"] = "e" * 64
    new = generate(world).shortlist[0]

    assert new.question_key == old.question_key and new.key != old.key
    made = materialize(world.store, new, context=world.context(), prefix="apt")

    assert made.created and made.item.id != first.item.id
    assert made.item.metadata[PRIOR_FOLLOWUPS] == [first.item.id]


# -- preview and creation write nothing they should not --------------------------------


def test_preview_writes_nothing(world):
    ledger_before = snapshot(world.root)
    store_before = world.store.snapshot()
    writes = world.store.writes

    generate(world)
    from aptrace_agent.work.followups import existing_followups

    for candidate in generate(world).candidates():
        existing_followups(world.store, candidate, prefix="apt")

    assert snapshot(world.root) == ledger_before
    assert world.store.snapshot() == store_before and world.store.writes == writes


def test_creation_does_not_touch_the_ledger_or_claim_state(world):
    before = snapshot(world.root)

    for candidate in generate(world).shortlist:
        materialize(world.store, candidate, context=world.context(), prefix="apt", source_item=world.item.id)

    assert snapshot(world.root) == before
    assert world.ledger.state(world.claim) == ClaimState.PROPOSED


# -- continuity: investigation A -> follow-up -> investigation B ------------------------------------


def test_followup_runs_through_the_work_item_path_with_bounded_prior_context(world):
    candidate = generate(world).shortlist[0]
    made = materialize(world.store, candidate, context=world.context(), prefix="apt", source_item=world.item.id)
    item = made.item

    # Beads holds references and the specific objective, not ledger content.
    assert item.metadata["aptrace_objective"] == candidate.objective
    assert item.metadata["aptrace_source_run"] == world.run_a.run_id
    assert (world.item.id, "discovered-from") in item.dependencies
    assert "constant_loads" not in json.dumps(item.metadata)

    planner = ScriptedPlanner([], f"PROBABLE STRUCTURE E1 {CALLERS[0][0]} calls {GAP}.")
    events_before = len(world.ledger.events())

    def investigate(objective, work_item_id):
        # As the CLI does: resolve the candidate from the item's references.
        run_id, key = followup_reference(world.store.get_work(work_item_id))
        followup = generate_followups(world.ledger, run_id, context=world.context(), deriver_for=deriver_for).find(key)
        return run_research(world.ledger, world.context, objective, work_item_id, planner=planner, followup=followup, max_steps=2)

    outcome = handoff.run_investigation(world.store, world.ledger, item.id, actor="tester", context=world.context(), lock_dir=world.locks, investigate=investigate)
    run_b = world.ledger.run(outcome.run_id)

    # The planner saw the specific objective, the gap question, the prior
    # claim as an unverified hypothesis, and the seeded caller leads...
    first = planner.prompts()[0]
    assert candidate.objective[:200] in first
    assert "PQ1[open]" in first and "PH1[hypothesis] [prior" in first
    assert CALLERS[0][0] in json.dumps(planner.requests[0]["tools"]) or CALLERS[0][0] in first
    # ...and not run A's raw evidence.
    assert "constant_loads" not in first and "pool_address" not in first
    assert len(first) < 6000

    # Durable linkage: parent run, supplied context, and per-invocation input evidence.
    assert run_b.parent_run_id == world.run_a.run_id
    assert run_b.work_item_id == item.id
    assert run_b.followup.followup_key == candidate.key
    assert run_b.followup.prior_evidence_ids == candidate.evidence_ids
    assert [lead["arguments"] for lead in run_b.followup.seeded_leads] == [lead.arguments for lead in candidate.seeded_leads]
    first_invocation = world.ledger.invocation(run_b.invocation_ids[0])
    assert first_invocation.input_evidence_ids and set(first_invocation.input_evidence_ids) <= set(world.run_a.evidence_ids)

    review = continuity_review(world.ledger, run_b.run_id)
    assert review["source_run_id"] == world.run_a.run_id
    assert review["new_evidence_ids"] and review["seeded_leads_followed"]
    assert review["originating_claims"] == {world.claim: "PROPOSED"}
    assert review["question_status"].startswith("OPEN")

    # Completing the work verifies nothing.
    rec = handoff.complete_investigation(world.store, world.ledger, item.id, actor="tester", lock_dir=world.locks)
    assert rec.state == handoff.COMPLETED
    assert world.ledger.state(world.claim) == ClaimState.PROPOSED
    assert all(e.subject != world.claim for e in world.ledger.events()[events_before:])

    # Regenerating does not repeat the investigated question.
    after = generate(world).find(candidate.key)
    assert after.status == REDUNDANT and run_b.run_id in after.status_detail
    assert after not in generate(world).shortlist


def test_input_evidence_never_names_a_later_session_observation(world):
    # Follow a seeded caller call site first, then the gap function's facts,
    # which re-derive that same call-site lead with a later source.
    candidate = generate(world).shortlist[0]
    seeds = [("function", f"Inspect {GAP}", "function_facts", {"function": GAP})]
    planner = ScriptedPlanner([CALLERS[0][0], f"function {GAP}"], "")
    run_id = run_research(world.ledger, world.context, candidate.objective, None, planner=planner, seeds=seeds, followup=candidate, max_steps=2)
    invocations = [world.ledger.invocation(i) for i in world.ledger.run(run_id).invocation_ids]

    assert [i.tool for i in invocations] == ["callsite_context", "function_facts"]
    assert invocations[0].input_evidence_ids and all(e.startswith("EV-") for i in invocations for e in i.input_evidence_ids)
    assert set(invocations[0].input_evidence_ids) <= set(world.run_a.evidence_ids)


def test_standalone_runs_are_unchanged(world):
    raw = json.loads((world.root / "runs" / f"{world.run_a.run_id}.json").read_text())

    assert "followup" not in raw and raw["parent_run_id"] is None
    assert world.run_a.followup is None
    assert continuity_review(world.ledger, world.run_a.run_id) == {"run_id": world.run_a.run_id, "followup": None}


def test_seed_session_bounds_what_it_seeds(world):
    candidate = generate(world).shortlist[0]
    registry = LeadRegistry()
    session = ResearchSession(objective=candidate.objective, registry=registry, follower=LeadFollower(registry=registry, executor=SerialExecutor()))
    seed_session(session, candidate)

    assert len(session.state.leads) == len(candidate.seeded_leads) <= 8
    assert [q.id for q in session.state.open_questions] == [f"PQ{i}" for i in range(1, len(candidate.open_questions) + 1)]
    assert all(len(q.question) <= 200 for q in session.state.open_questions)
    assert session.state.hypotheses[0].source == f"followup:{candidate.key}"
    # Prior evidence is referenced, never replayed into the session ledger.
    assert list(session.ledger.all()) == []
    assert candidate.status == PROPOSED


# -- CLI wiring ------------------------------------------------------------------------


def test_cli_preview_create_and_run_a_followup(world, monkeypatch, capsys):
    from aptrace_agent import cli, ledger_wiring, work_cli
    from aptrace_agent import executor as executor_module

    planner = ScriptedPlanner([], f"PROBABLE STRUCTURE E1 {CALLERS[0][0]} calls {GAP}.")
    received = {}

    def autonomous(objective, *, seed_function, max_steps, executor=None, claim_contract=False, followup=None):
        received.update(objective=objective, followup=followup)
        registry = LeadRegistry()
        session = ResearchSession(objective=objective, registry=registry, follower=LeadFollower(registry=registry, executor=executor), deriver=deriver_for(registry))
        seed_session(session, followup)
        result = ResearchController(planner_client=planner, planner_model="scripted", reconciler=object(), max_steps=2, claim_contract=claim_contract).run(session)
        return AutonomousInvestigationRun(objective=objective, seed_function=None, result=result, state=session.state.model_copy(deep=True), evidence=tuple(session.ledger.all()))

    def record(run, *, executor, recorder, ledger_dir_override, started_at, ended_at, max_steps, controller_cls, work_item_id=None, followup=None):
        return record_investigation(
            ResearchLedger(ledger_dir_override), run, context=world.context(), recorder=recorder, model="scripted", execution_config={},
            planner_version="test", budgets={"max_steps": max_steps}, started_at=started_at, ended_at=ended_at,
            source=SourceRevision(), work_item_id=work_item_id, followup=followup,
        ).run_id

    monkeypatch.setattr(executor_module, "EvidenceExecutor", SerialExecutor)
    monkeypatch.setattr(ledger_wiring, "context_provider", lambda _executor: world.context)
    monkeypatch.setattr(ledger_wiring, "lead_deriver_factory", lambda _executor: deriver_for)
    monkeypatch.setattr(cli, "run_autonomous_investigation", autonomous)
    monkeypatch.setattr(cli, "record_research_run", record)
    monkeypatch.setattr(work_cli, "_open", lambda args, initialize=False: (world.store, world.locks))

    def main(*argv):
        monkeypatch.setattr("sys.argv", ["aptrace-agent", *argv])
        cli.main()
        return capsys.readouterr().out

    ledger_before, store_before = snapshot(world.root), world.store.snapshot()
    preview = main("followups", world.run_a.run_id, "--ledger-dir", str(world.root))

    assert "frontier: re-derived: re-derived 12 open lead(s)" in preview
    assert preview.count("[rank ") == 4  # 3 shortlisted + 1 blocked
    assert "not created (would be apt-fq" in preview
    assert snapshot(world.root) == ledger_before and world.store.snapshot() == store_before

    created = main("followups", world.run_a.run_id, "--ledger-dir", str(world.root), "--create", "--select", "1")
    item_id = next(i for i in world.store.items if i.startswith("apt-fq"))
    assert f"created {item_id}" in created and len(world.store.items) == 2

    main("followups", world.run_a.run_id, "--ledger-dir", str(world.root), "--create", "--select", "1")
    assert len(world.store.items) == 2

    main("research", "--ledger", "--ledger-dir", str(world.root), "--work-item", item_id)
    run_b = next(run for run in world.ledger.runs() if run.work_item_id == item_id)

    assert received["objective"] == world.store.items[item_id]["metadata"]["aptrace_objective"]
    assert received["followup"].key == world.store.items[item_id]["metadata"]["aptrace_followup_key"]
    assert run_b.followup.followup_key == received["followup"].key and run_b.parent_run_id == world.run_a.run_id
    assert world.ledger.state(world.claim) == ClaimState.PROPOSED


# -- real Beads ---------------------------------------------------------------------------

from concurrent.futures import ThreadPoolExecutor  # noqa: E402

from aptrace_agent.work.beads import BeadsWorkStore, find_bd  # noqa: E402
from aptrace_agent.work.followups import QUESTION_KEY  # noqa: E402
from aptrace_agent.work.store import WorkStoreUnavailable  # noqa: E402


@pytest.mark.skipif(find_bd() is None, reason="Beads CLI not installed (set APTRACE_BD or put bd on PATH)")
def test_real_beads_followup_dedup_provenance_and_concurrency(world, tmp_path):
    home = tmp_path / "home"
    home.mkdir()

    def open_store() -> BeadsWorkStore:
        return BeadsWorkStore(tmp_path / "work" / ".beads", env={"HOME": str(home)}, actor="aptrace-test")

    store = open_store()
    store.initialize(prefix="apt")
    source = handoff.create_investigation(store, context=world.context(), objective=f"Investigate {PERIPHERAL} usage")
    candidate = generate(world).shortlist[0]

    def attempt(_n):
        try:
            return materialize(open_store(), candidate, context=world.context(), prefix="apt", source_item=source.id)
        except WorkStoreUnavailable as exc:  # embedded Dolt lock contention
            return exc

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(attempt, range(4)))

    made = [o for o in outcomes if not isinstance(o, Exception)]
    item_id = followup_item_id("apt", candidate.key)

    assert sum(o.created for o in made) == 1
    assert all(o.item.id == item_id for o in made)

    reopened = open_store()
    again = materialize(reopened, generate(world).shortlist[0], context=world.context(), prefix="apt", source_item=source.id)
    item = reopened.get_work(item_id)

    assert not again.created and again.item.id == item_id
    assert [i.id for i in reopened.find_work(QUESTION_KEY, candidate.question_key)] == [item_id]
    assert (source.id, "discovered-from") in item.dependencies
    assert item.metadata["aptrace_claim_versions"] == [world.claim]
    assert item.metadata["aptrace_source_run"] == world.run_a.run_id
    assert item.priority == candidate.rank
