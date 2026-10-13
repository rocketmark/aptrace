"""
Beads-backed work items and their hand-off to the research ledger.

Needs the Beads CLI (`bd`, pinned 1.3.1) on PATH or in APTRACE_BD; skipped
otherwise. No model, network, census, or Ghidra: investigations run the real
ResearchController with a scripted planner over the shared fake executor.
Every store lives under tmp_path with a sandbox HOME, outside any git tree.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from aptrace_agent.investigator import AutonomousInvestigationRun
from aptrace_agent.ledger.auditor import ClaimAuditor
from aptrace_agent.ledger.models import ClaimState, SourceRevision
from aptrace_agent.ledger.recorder import RecordingExecutor, record_investigation
from aptrace_agent.ledger.store import now
from aptrace_agent.ledger.verifier import ClaimVerifier
from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchController, ResearchSession
from aptrace_agent.work import handoff
from aptrace_agent.work.beads import PINNED_BEADS_VERSION, BeadsWorkStore, find_bd
from aptrace_agent.work.store import CLOSED, IN_PROGRESS, OPEN, ClaimConflict, WorkStoreError, WorkStoreUnavailable

from ledger_support import FakeExecutor, ScriptedAuditModel, irq_handlers, request, stack, verdict


BD = find_bd()
needs_bd = pytest.mark.skipif(BD is None, reason="Beads CLI not installed (set APTRACE_BD or put bd on PATH)")
SRC = Path(__file__).resolve().parents[1] / "src" / "aptrace_agent"


# -- fixtures -----------------------------------------------------------------


@pytest.fixture(scope="session")
def store_template(tmp_path_factory):
    """One `bd init` per session; each test gets a copy (init costs ~4 s)."""

    if BD is None:
        pytest.skip("Beads CLI not installed")

    root = tmp_path_factory.mktemp("beads-template")
    home = root / "home"
    home.mkdir()
    store = BeadsWorkStore(root / "work" / ".beads", env={"HOME": str(home)})
    store.initialize(prefix="apt")
    return root


@pytest.fixture
def work(store_template, tmp_path):
    shutil.copytree(store_template, tmp_path / "beads")
    return _open(tmp_path / "beads")


def _open(root: Path, actor: str = "aptrace-test") -> BeadsWorkStore:
    return BeadsWorkStore(root / "work" / ".beads", env={"HOME": str(root / "home")}, actor=actor)


def _snapshot(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


class _Planner:
    """Follows the first lead, then answers the finish-only claim request."""

    def __init__(self, claims: str):
        self.claims = claims
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        names = [t["function"]["name"] for t in kwargs["tools"]]

        if names == ["finish"]:
            name, arguments = "finish", {"reason": "budget", "claims": self.claims}
        else:
            lead = kwargs["tools"][0]["function"]["parameters"]["properties"]["lead_id"]["enum"][0]
            name, arguments = "follow_lead", {"lead_id": lead}

        call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=json.dumps(arguments)))
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[call]))])


def _investigator(ledger, context, claims="PROBABLE STRUCTURE E1 FUN_0000cc14 is the USB_OTHER interrupt handler."):
    """The `research --ledger` path: controller run, then record_investigation."""

    def investigate(objective: str) -> str:
        registry = LeadRegistry()
        executor = RecordingExecutor(FakeExecutor())
        session = ResearchSession(objective=objective, registry=registry, follower=LeadFollower(registry=registry, executor=executor))
        session.state.add_lead(registry.register(kind="function", description="USB handler", tool="function_facts", arguments={"function": "FUN_0000cc14"}))
        started = now()
        result = ResearchController(planner_client=_Planner(claims), planner_model="scripted", reconciler=object(), max_steps=1, claim_contract=True).run(session)
        run = AutonomousInvestigationRun(objective=objective, seed_function=None, result=result, state=session.state.model_copy(deep=True), evidence=tuple(session.ledger.all()))
        recorded = record_investigation(
            ledger, run, context=context(), recorder=executor, model="scripted", execution_config={}, planner_version="test",
            budgets={"max_steps": 1}, started_at=started, ended_at=now(), source=SourceRevision(),
        )
        return recorded.run_id

    return investigate


def _auditor(ledger, runner, decisions):
    return ClaimAuditor(
        ledger=ledger, runner=runner, client=ScriptedAuditModel(decisions), model="gemma-test",
        peripherals=["EIC", "TCC1", "SERCOM2"], irq_handlers=irq_handlers, retry_delay=0,
    )


def _usb_claim(ledger, runner):
    _inv, artifact = runner.run("R-setup", "census_usb_inventory", {})
    return ledger.propose_claim(
        subject="USB callback",
        assertion="The callback at 0x0000cc1a resolves to raw 0x0000c725, canonical 0x0000c724.",
        claim_type="RESOLUTION",
        proposed_grade="STRONG",
        proposed_by="test",
        supporting_evidence_ids=[artifact.evidence_id],
    )


OBJECTIVE = "Determine which handler services USB_OTHER and what it dispatches."


# -- A: durable investigation work --------------------------------------------


@needs_bd
def test_a_investigation_metadata_round_trips_and_survives_reopen(work, tmp_path):
    _ledger, _executor, context, _runner = stack(tmp_path)
    item = handoff.create_investigation(work, context=context(), objective=OBJECTIVE, priority=1)

    reopened = _open(tmp_path / "beads", actor="someone-else").get_work(item.id)

    assert reopened.status == OPEN and reopened.priority == 1
    assert reopened.metadata == {
        "aptrace_kind": "investigation",
        "aptrace_objective": OBJECTIVE,
        "aptrace_case": "performing-rigs",
        "aptrace_firmware_key": "autopilot868",
        "aptrace_firmware_sha256": context().firmware_sha256,
        "aptrace_context_id": context().context_id(),
    }
    assert [i.id for i in work.find_work("aptrace_firmware_sha256", context().firmware_sha256)] == [item.id]

    handoff.link_run(work, item.id, "R-20261013T000000-abcdef")
    assert _open(tmp_path / "beads").get_work(item.id).metadata["aptrace_run_ids"] == ["R-20261013T000000-abcdef"]


# -- B: dependency graph ------------------------------------------------------


@needs_bd
def test_b_ready_frontier_follows_blocking_dependencies_across_reopen(work, tmp_path):
    census = work.create_work("Rebuild census for firmware")
    inventory = work.create_work("USB structural inventory", depends_on=(census.id,))
    trace = work.create_work("Trace USB_OTHER dispatch")
    work.add_dependency(trace.id, inventory.id)  # trace depends on inventory
    independent = work.create_work("Unrelated SERCOM2 question")

    assert work.get_work(inventory.id).blockers == [census.id]
    assert work.get_work(trace.id).blockers == [inventory.id]
    assert {i.id for i in work.ready_work()} == {census.id, independent.id}

    work.complete_work(census.id, "done")
    assert {i.id for i in _open(tmp_path / "beads").ready_work()} == {inventory.id, independent.id}

    work.complete_work(inventory.id, "done")
    assert {i.id for i in _open(tmp_path / "beads").ready_work()} == {trace.id, independent.id}


# -- C: claiming --------------------------------------------------------------


@needs_bd
@pytest.mark.parametrize("round_", range(3))
def test_c_competing_processes_claim_one_item_exactly_once(work, round_):
    item = work.create_work(f"contended {round_}")

    def attempt(n: int):
        try:
            return n, work.claim_work(item.id, f"worker-{n}")
        except ClaimConflict as exc:
            return n, exc

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(8)))

    winners = [(n, r) for n, r in outcomes if not isinstance(r, Exception)]
    losers = [r for _n, r in outcomes if isinstance(r, Exception)]

    assert len(winners) == 1 and len(losers) == 7
    holder = f"worker-{winners[0][0]}"
    assert all(holder in str(exc) for exc in losers)
    assert (work.get_work(item.id).status, work.get_work(item.id).assignee) == (IN_PROGRESS, holder)


@needs_bd
def test_c_claim_next_never_assigns_one_item_twice(work):
    ids = {work.create_work(f"pool {n}").id for n in range(4)}

    with ThreadPoolExecutor(max_workers=8) as pool:
        claimed = list(pool.map(lambda n: (f"w{n}", work.claim_next(f"w{n}")), range(8)))

    got = [(actor, item.id) for actor, item in claimed if item is not None]

    assert len({item for _a, item in got}) == len(got)  # no item handed to two workers
    assert {item for _a, item in got} <= ids
    for actor, item_id in got:
        assert work.get_work(item_id).assignee == actor


@needs_bd
def test_c_holder_reclaim_is_idempotent_and_release_is_compare_and_swap(work):
    item = work.create_work("x")
    work.claim_work(item.id, "w1")
    work.claim_work(item.id, "w1")  # idempotent for the holder

    with pytest.raises(WorkStoreError):
        work.release_work(item.id, "w2", "not the holder")

    assert work.release_work(item.id, "w1", "crashed").status == OPEN
    assert work.claim_work(item.id, "w2").assignee == "w2"


# -- D: hand-off to a recorded investigation run ------------------------------


@needs_bd
def test_d_work_item_drives_existing_investigation_and_records_run_id(work, tmp_path):
    ledger, _executor, context, _runner = stack(tmp_path)
    item = handoff.create_investigation(work, context=context(), objective=OBJECTIVE)

    run_id = handoff.run_investigation(work, item.id, actor="controller", investigate=_investigator(ledger, context))

    run = ledger.run(run_id)
    done = work.get_work(item.id)
    assert run.objective == OBJECTIVE and run.case == "performing-rigs"
    assert done.status == CLOSED and done.metadata["aptrace_run_ids"] == [run_id]
    assert done.metadata["aptrace_run_link_basis"] == {run_id: handoff.LINK_DIRECT}
    assert "owned by the APTrace ledger" in done.close_reason
    # Closing the work did not touch the claims the run proposed.
    assert run.claim_versions and all(ledger.state(k) == ClaimState.PROPOSED for k in run.claim_versions)
    assert all(e.actor == "aptrace-ledger" for e in ledger.events())


# -- E: interruption and restart ----------------------------------------------


@needs_bd
def test_e_crash_before_any_run_means_restart(work, tmp_path):
    ledger, _executor, context, _runner = stack(tmp_path)
    item = handoff.create_investigation(work, context=context(), objective=OBJECTIVE)
    work.claim_work(item.id, "controller")
    work.update_metadata(item.id, {handoff.ATTEMPT_STARTED: now(), handoff.ATTEMPT_ACTOR: "controller"})
    # ... process dies here: the controller never finished, so no run exists.

    recovery = handoff.recover(_open(tmp_path / "beads"), ledger, item.id)

    assert recovery.next_action == "restart"
    assert (recovery.item.status, recovery.item.assignee) == (IN_PROGRESS, "controller")
    assert recovery.linked_runs == recovery.orphan_runs == []
    assert not ledger.runs()
    # The same controller may resume ownership; a different worker may not.
    work.claim_work(item.id, "controller")
    with pytest.raises(ClaimConflict):
        work.claim_work(item.id, "other-worker")


class _FailsAfterInvestigation:
    """A work store that becomes unavailable once the run is recorded."""

    def __init__(self, inner):
        self.inner = inner
        self.writes = 0

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def update_metadata(self, item_id, metadata):
        self.writes += 1

        if self.writes > 1:  # first write is the attempt marker
            raise WorkStoreUnavailable("simulated: bd died during run-id write-back")

        return self.inner.update_metadata(item_id, metadata)


@needs_bd
def test_e_run_recorded_but_not_linked_is_recovered_once_without_touching_ledger(work, tmp_path):
    ledger, _executor, context, _runner = stack(tmp_path)
    item = handoff.create_investigation(work, context=context(), objective=OBJECTIVE)

    with pytest.raises(WorkStoreUnavailable):
        handoff.run_investigation(_FailsAfterInvestigation(work), item.id, actor="controller", investigate=_investigator(ledger, context))

    (run,) = ledger.runs()
    before = _snapshot(ledger.root)
    fresh = _open(tmp_path / "beads")
    recovery = handoff.recover(fresh, ledger, item.id)

    assert recovery.next_action == "link-orphan-run" and recovery.orphan_runs == [run.run_id]

    with pytest.raises(ClaimConflict):  # another worker cannot take over a live claim
        handoff.apply_recovery(fresh, ledger, item.id, actor="other-worker")

    for _ in range(3):  # repeated recovery is idempotent
        final = handoff.apply_recovery(_open(tmp_path / "beads"), ledger, item.id, actor="controller")

    item = fresh.get_work(item.id)
    assert final.next_action == "none" and item.status == CLOSED
    assert item.metadata["aptrace_run_ids"] == [run.run_id]
    assert item.metadata["aptrace_run_link_basis"] == {run.run_id: handoff.LINK_RECOVERED}
    assert final.claim_states == {k: "PROPOSED" for k in run.claim_versions}
    assert _snapshot(ledger.root) == before  # recovery read the ledger only


@needs_bd
def test_e_recovery_from_a_fresh_python_process(work, tmp_path):
    ledger, _executor, context, _runner = stack(tmp_path)
    item = handoff.create_investigation(work, context=context(), objective=OBJECTIVE)

    with pytest.raises(WorkStoreUnavailable):
        handoff.run_investigation(_FailsAfterInvestigation(work), item.id, actor="controller", investigate=_investigator(ledger, context))

    script = textwrap.dedent(
        f"""
        import json
        from pathlib import Path
        from aptrace_agent.ledger.store import ResearchLedger
        from aptrace_agent.work.beads import BeadsWorkStore
        from aptrace_agent.work.handoff import recover
        root = Path({str(tmp_path / 'beads')!r})
        store = BeadsWorkStore(root / "work" / ".beads", env={{"HOME": str(root / "home")}})
        r = recover(store, ResearchLedger(Path({str(ledger.root)!r})), {item.id!r})
        print(json.dumps({{"status": r.item.status, "assignee": r.item.assignee, "objective": r.item.metadata["aptrace_objective"],
                          "orphans": r.orphan_runs, "next": r.next_action}}))
        """
    )
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120, env={**os.environ, "APTRACE_BD": BD})

    assert done.returncode == 0, done.stderr
    state = json.loads(done.stdout)
    assert state == {"status": IN_PROGRESS, "assignee": "controller", "objective": OBJECTIVE, "orphans": [ledger.runs()[0].run_id], "next": "link-orphan-run"}


@needs_bd
def test_e_restarting_reuses_evidence_but_proposes_new_claims(work, tmp_path):
    ledger, _executor, context, _runner = stack(tmp_path)
    investigate = _investigator(ledger, context)
    first = ledger.run(investigate(OBJECTIVE))
    second = ledger.run(investigate(OBJECTIVE))

    assert first.evidence_ids == second.evidence_ids  # content-addressed: no duplicate evidence
    assert len(ledger.all_evidence()) == len(first.evidence_ids)
    assert first.claim_versions != second.claim_versions  # claims are not deduplicated by APTrace


@pytest.mark.skipif(not os.environ.get("APTRACE_SLOW_TESTS"), reason="waits out the 5-minute Beads lease; set APTRACE_SLOW_TESTS=1")
@needs_bd
def test_e_abandoned_claim_is_reclaimed_after_lease_expiry(work):
    item = work.create_work("abandoned")
    work.claim_work(item.id, "dead-worker")
    work.reclaim_stale(older_than="0s")
    assert work.get_work(item.id).assignee == "dead-worker"  # lease still live

    time.sleep(5 * 60 + 10)
    work.reclaim_stale(older_than="0s")

    assert (work.get_work(item.id).status, work.get_work(item.id).assignee) == (OPEN, None)
    assert work.claim_work(item.id, "new-worker").assignee == "new-worker"


# -- F: adversarial follow-up -------------------------------------------------


@needs_bd
@pytest.mark.parametrize("value, state", [("CHALLENGED", ClaimState.BLOCKED), ("UNRESOLVED", ClaimState.PROPOSED)])
def test_f_challenged_or_unresolved_audit_opens_one_followup(work, tmp_path, value, state):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim = _usb_claim(ledger, runner)
    source = work.create_work("Investigate USB callback")
    audit = _auditor(ledger, runner, [
        request("function_disassembly", function="FUN_0000ccc4"),
        verdict(value, challenges=["writer FUN_0000ccc4 stores a different pointer"] if value == "CHALLENGED" else []),
    ]).audit(claim.key)
    ClaimVerifier(ledger, runner=runner).verify(claim.key)
    audit_file = (ledger.root / "audits" / f"{audit.audit_id}.json").read_text()
    events = len(ledger.events())

    item, created = handoff.followup_for_audit(work, ledger, audit.audit_id, prefix="apt", source_item=source.id)

    assert created and item.id == handoff.followup_id("apt", claim.key, audit.audit_id)
    assert item.metadata["aptrace_claim_version"] == claim.key
    assert item.metadata["aptrace_audit_id"] == audit.audit_id
    assert item.metadata["aptrace_audit_verdict"] == value
    assert item.metadata["aptrace_source_work"] == source.id and item.metadata["aptrace_followup_reason"]
    assert (source.id, "discovered-from") in item.dependencies
    assert item.id in {i.id for i in work.ready_work()}  # discovered-from does not block

    # Repeat, sequentially and concurrently: one item.
    again, created_again = handoff.followup_for_audit(work, ledger, audit.audit_id, prefix="apt", source_item=source.id)
    with ThreadPoolExecutor(max_workers=4) as pool:
        racing = list(pool.map(lambda _: handoff.followup_for_audit(work, ledger, audit.audit_id, prefix="apt", source_item=source.id), range(4)))

    assert (again.id, created_again) == (item.id, False)
    assert {r[0].id for r in racing} == {item.id} and not any(r[1] for r in racing)
    assert len(work.find_work("aptrace_audit_id", audit.audit_id)) == 1
    # Audit semantics and claim lifecycle are untouched.
    assert ledger.state(claim.key) == state and len(ledger.events()) == events
    assert (ledger.root / "audits" / f"{audit.audit_id}.json").read_text() == audit_file


@needs_bd
def test_f_supported_audit_opens_no_followup(work, tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim = _usb_claim(ledger, runner)
    audit = _auditor(ledger, runner, [request("function_disassembly", function="FUN_0000ccc4"), verdict("SUPPORTED")]).audit(claim.key)

    assert handoff.followup_for_audit(work, ledger, audit.audit_id, prefix="apt") == (None, False)


# -- G: verification authority ------------------------------------------------


@needs_bd
def test_g_closing_work_cannot_promote_a_claim(work, tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim = _usb_claim(ledger, runner)
    unresolved = _auditor(ledger, runner, [request("function_disassembly", function="FUN_0000ccc4"), verdict("UNRESOLVED")]).audit(claim.key)
    item, _ = handoff.followup_for_audit(work, ledger, unresolved.audit_id, prefix="apt")
    before = _snapshot(ledger.root)

    work.complete_work(item.id, "follow-up investigated; looked fine")
    handoff.link_run(work, item.id, "R-pretend")

    assert work.get_work(item.id).status == CLOSED
    assert ledger.state(claim.key) == ClaimState.PROPOSED
    assert _snapshot(ledger.root) == before
    # Only APTrace verification decides; with an UNRESOLVED latest audit it holds.
    assert ClaimVerifier(ledger, runner=runner).verify(claim.key).current == ClaimState.PROPOSED


def test_g_work_package_has_no_ledger_write_path():
    forbidden = ("transition(", "propose_claim(", "supersede_claim(", "record_audit(", "record_verification(",
                 "record_run(", "record_invocation(", "invalidate_evidence(", "propagate_staleness(", "_write_once(", "_append_event(")
    for path in (SRC / "work").glob("*.py"):
        text = path.read_text()
        assert not [f for f in forbidden if f in text], path.name


def test_ledger_and_research_do_not_import_work_package():
    for package in ("ledger", "research"):
        for path in (SRC / package).glob("*.py"):
            assert "aptrace_agent.work" not in path.read_text(), path


# -- H: history, export, import -----------------------------------------------


@needs_bd
def test_h_history_and_jsonl_round_trip_preserve_ids_links_and_dependencies(work, tmp_path, store_template):
    ledger, _executor, context, _runner = stack(tmp_path)
    first = handoff.create_investigation(work, context=context(), objective=OBJECTIVE)
    second = handoff.create_investigation(work, context=context(), objective="Second objective", depends_on=(first.id,))
    run_id = handoff.run_investigation(work, first.id, actor="controller", investigate=_investigator(ledger, context))

    events = [e["event_type"] for e in work.history(first.id)]
    assert {"created", "claimed", "closed"} <= set(events)

    exported = work.export_jsonl(tmp_path / "work.jsonl")
    target_root = tmp_path / "restored"
    shutil.copytree(store_template, target_root)
    target = _open(target_root)
    target.import_jsonl(exported)

    restored_first, restored_second = target.get_work(first.id), target.get_work(second.id)
    assert restored_first.metadata["aptrace_run_ids"] == [run_id] and restored_first.status == CLOSED
    assert restored_second.metadata == work.get_work(second.id).metadata
    assert restored_second.blockers == [first.id]
    assert ledger.run(run_id).run_id == run_id


# -- failure isolation ---------------------------------------------------------


def test_missing_beads_binary_is_unavailable_and_ledger_is_untouched(tmp_path):
    ledger, _executor, context, _runner = stack(tmp_path)
    store = BeadsWorkStore(tmp_path / "w" / ".beads", bd=str(tmp_path / "no-such-bd"))
    called = []

    with pytest.raises(WorkStoreUnavailable):
        store.version()
    with pytest.raises(WorkStoreUnavailable):
        handoff.run_investigation(store, "apt-x", actor="c", investigate=lambda o: called.append(o) or "R-x")

    assert called == [] and not ledger.root.exists()


@needs_bd
def test_missing_store_is_unavailable(tmp_path):
    with pytest.raises(WorkStoreUnavailable):
        BeadsWorkStore(tmp_path / "absent" / ".beads").ready_work()


@needs_bd
def test_research_still_records_without_any_work_store(tmp_path):
    ledger, _executor, context, _runner = stack(tmp_path)
    run = ledger.run(_investigator(ledger, context)(OBJECTIVE))
    assert run.claim_versions and ledger.state(run.claim_versions[0]) == ClaimState.PROPOSED


@needs_bd
def test_version_is_pinned(work):
    assert work.check_version() == PINNED_BEADS_VERSION


@needs_bd
def test_initialize_refuses_inside_a_git_work_tree(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / ".gitignore").write_text("dist/\n")

    with pytest.raises(WorkStoreError, match="inside git work tree"):
        BeadsWorkStore(repo / "work" / ".beads", env={"HOME": str(tmp_path)}).initialize()

    assert (repo / ".gitignore").read_text() == "dist/\n" and not (repo / "work" / ".beads" / "metadata.json").exists()
