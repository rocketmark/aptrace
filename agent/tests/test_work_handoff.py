"""
Work item -> research ledger hand-off, reconciliation, and ownership.

Runs without Beads: FakeWorkStore mirrors the bd 1.3.1 claim semantics (see
work_support). Investigations run the real ResearchController with a
scripted planner and record through record_investigation. Real-bd coverage
of the same paths is in test_work_beads.py.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap

import pytest

from aptrace_agent.ledger.models import ClaimState, InvestigationRun
from aptrace_agent.ledger.store import LedgerImmutableError, ResearchLedger, now
from aptrace_agent.ledger.verifier import ClaimVerifier
from aptrace_agent.work import handoff
from aptrace_agent.work.handoff import (
    ACTIVE,
    AWAITING_COMPLETION,
    CLAIMED_BY_OTHER,
    COMPLETED,
    CONFLICT,
    INTERRUPTED,
    LINK_RUNS,
    OPERATOR_REVIEW,
    READY,
    InvalidWorkItem,
    WorkRefused,
    WriteBackFailed,
)
from aptrace_agent.work.ownership import ItemLock
from aptrace_agent.work.store import CLOSED, IN_PROGRESS, OPEN, WorkActive, WorkStoreUnavailable

from ledger_support import stack
from work_support import OBJECTIVE, FakeWorkStore, investigator, snapshot


ACTOR = "aptrace-agent"


@pytest.fixture
def env(tmp_path):
    ledger, _executor, context, runner = stack(tmp_path)
    store = FakeWorkStore()
    item = handoff.create_investigation(store, context=context(), objective=OBJECTIVE)
    calls: list = []
    return type("Env", (), dict(
        ledger=ledger, context=context, runner=runner, store=store, item=item, calls=calls,
        locks=tmp_path / "locks", investigate=investigator(ledger, context, calls=calls),
    ))


def start(env, item_id=None, *, actor=ACTOR, investigate=None, **flags):
    return handoff.run_investigation(
        env.store, env.ledger, item_id or env.item.id, actor=actor, context=env.context(),
        investigate=investigate or env.investigate, lock_dir=env.locks, **flags,
    )


def rec(env, item_id=None, actor=ACTOR):
    item_id = item_id or env.item.id
    return handoff.reconcile(env.store, env.ledger, item_id, actor=actor, lock=ItemLock(env.locks, item_id))


def apply(env, item_id=None):
    return handoff.apply_reconciliation(env.store, env.ledger, item_id or env.item.id, actor=ACTOR, lock_dir=env.locks)


def write_run(ledger, context, *, run_id, work_item_id=None, objective=OBJECTIVE, started_at=None, **changes):
    ctx = context()
    fields = dict(
        run_id=run_id, case=ctx.case, firmware_key=ctx.firmware_key, firmware_sha256=ctx.firmware_sha256,
        context_id=ctx.context_id(), objective=objective, started_at=started_at or now(), ended_at=now(),
        termination_reason="planner_finished", work_item_id=work_item_id,
    )
    fields.update(changes)
    return ledger.record_run(InvestigationRun(**fields))


def mark_attempt(env, *, state="running", host=None, started_at=None, attempt_id="WA-crashed"):
    env.store.claim_work(env.item.id, ACTOR)
    env.store.update_metadata(env.item.id, {
        handoff.ATTEMPT_ID: attempt_id, handoff.ATTEMPT_STATE: state, handoff.ATTEMPT_STARTED: started_at or now(),
        handoff.ATTEMPT_ACTOR: ACTOR, handoff.ATTEMPT_HOST: host or handoff.hostname(), handoff.ATTEMPT_PID: 1,
    })


class HeldElsewhere:
    """Hold an item lock in a separate process, as a running attempt does."""

    def __init__(self, locks, item_id):
        code = textwrap.dedent(f"""
            import sys, time
            from pathlib import Path
            from aptrace_agent.work.ownership import ItemLock
            lock = ItemLock(Path({str(locks)!r}), {item_id!r}).acquire()
            print("held", flush=True)
            time.sleep(120)
        """)
        self.proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
        assert self.proc.stdout.readline().strip() == "held"

    def kill(self):
        self.proc.kill()
        self.proc.wait()


# -- 1-3: InvestigationRun work-item reference ----------------------------------


def _legacy_run_json(run_id="R-legacy"):
    """A run record as written before work_item_id existed."""

    return {
        "schema_version": 1, "run_id": run_id, "kind": "investigation", "case": "performing-rigs", "firmware_key": "k",
        "firmware_sha256": "s", "context_id": "X-1", "objective": "o", "model": None, "execution_config": {},
        "planner_version": None, "budgets": {}, "started_at": "2026-10-12T00:00:00+00:00", "ended_at": "2026-10-12T00:01:00+00:00",
        "termination_reason": "planner_finished", "parent_run_id": None,
        "source": {"git_commit": None, "git_branch": None, "dirty": None, "dirty_fingerprint": None},
        "invocation_ids": [], "evidence_ids": [], "claim_versions": [], "planner_requests": [], "trajectory": [],
    }


def test_runs_recorded_before_the_reference_existed_still_load(tmp_path):
    ledger = ResearchLedger(tmp_path / "ledger")
    (tmp_path / "ledger" / "runs").mkdir(parents=True)
    (tmp_path / "ledger" / "runs" / "R-legacy.json").write_text(json.dumps(_legacy_run_json(), indent=2, sort_keys=True) + "\n")

    run = ledger.run("R-legacy")

    assert run.work_item_id is None
    # Re-recording the same legacy record is still an idempotent no-op.
    assert ledger.record_run(run) == run


def test_persisted_case_ledger_runs_still_load():
    from aptrace_agent.ledger_wiring import DEFAULT_LEDGER_DIR

    if not (DEFAULT_LEDGER_DIR / "runs").is_dir():
        pytest.skip("no case ledger in this checkout")

    runs = ResearchLedger(DEFAULT_LEDGER_DIR).runs()
    assert runs and all(run.work_item_id is None for run in runs)


def test_standalone_runs_serialize_without_a_work_item_field(env):
    run = env.ledger.run(env.investigate(OBJECTIVE))

    assert run.work_item_id is None
    assert "work_item_id" not in (env.ledger.root / "runs" / f"{run.run_id}.json").read_text()


def test_linked_run_persists_reference_immutably_and_runs_stay_unique(env):
    first = env.ledger.run(env.investigate(OBJECTIVE, "apt-x"))
    second = env.ledger.run(env.investigate(OBJECTIVE, "apt-x"))

    assert first.run_id != second.run_id
    assert (first.work_item_id, second.work_item_id) == ("apt-x", "apt-x")
    assert json.loads((env.ledger.root / "runs" / f"{first.run_id}.json").read_text())["work_item_id"] == "apt-x"
    assert [r.run_id for r in handoff.runs_for_item(env.ledger, "apt-x")] == sorted([first.run_id, second.run_id], key=lambda r: env.ledger.run(r).started_at)

    with pytest.raises(Exception):
        first.work_item_id = "apt-y"  # frozen record
    with pytest.raises(LedgerImmutableError):
        env.ledger.record_run(first.model_copy(update={"work_item_id": "apt-y"}))


# -- 6: validation -------------------------------------------------------------


@pytest.mark.parametrize(
    "metadata, message",
    [
        ({"aptrace_kind": "audit-followup"}, "not an APTrace investigation"),
        ({"aptrace_case": "other-case"}, "different case or firmware"),
        ({"aptrace_firmware_sha256": "0" * 64}, "different case or firmware"),
        ({"aptrace_firmware_key": "other"}, "different case or firmware"),
        ({"aptrace_objective": ""}, "lacks required metadata"),
    ],
)
def test_items_for_another_case_firmware_or_kind_are_rejected_before_claiming(env, metadata, message):
    env.store.update_metadata(env.item.id, metadata)
    before = env.store.snapshot()

    with pytest.raises(InvalidWorkItem, match=message):
        start(env)

    assert env.calls == [] and not env.ledger.runs()
    assert env.store.snapshot()[env.item.id]["status"] == OPEN == before[env.item.id]["status"]


def test_objective_on_command_line_must_match_the_item(env):
    with pytest.raises(InvalidWorkItem, match="differs"):
        start(env, objective="Something else entirely.")

    assert env.calls == []


def test_changed_input_artifacts_are_a_note_not_a_refusal(env):
    env.context.artifacts["census_db"] = "d" * 64
    outcome = start(env)
    assert any("input artifacts changed" in note for note in outcome.notes)


def test_blocked_item_is_not_started(env):
    blocker = env.store.create_work("prerequisite")
    env.store.add_dependency(env.item.id, blocker.id)

    with pytest.raises(WorkRefused, match="blocked by unfinished work"):
        start(env)

    assert env.calls == []


# -- Case A: claimed, no run ---------------------------------------------------


def test_case_a_ready_item_runs_once_and_is_left_for_explicit_completion(env):
    assert rec(env).state == READY

    outcome = start(env)

    run = env.ledger.run(outcome.run_id)
    item = env.store.get_work(env.item.id)
    assert env.calls == [(OBJECTIVE, env.item.id)]
    assert run.work_item_id == env.item.id and run.objective == OBJECTIVE
    assert outcome.owned and outcome.reconciliation.state == AWAITING_COMPLETION
    assert (item.status, item.assignee) == (IN_PROGRESS, ACTOR)  # never closed automatically
    assert item.metadata[handoff.RUN_IDS] == [run.run_id]
    assert item.metadata[handoff.RUN_LINKS] == {run.run_id: handoff.LINK_DIRECT}
    assert item.metadata[handoff.ATTEMPT_STATE] == handoff.RECORDED
    assert item.metadata[handoff.ATTEMPT_ID] == outcome.attempt_id
    assert all(env.ledger.state(k) == ClaimState.PROPOSED for k in run.claim_versions)


def test_case_a_item_claimed_by_this_actor_without_attempt_can_start(env):
    env.store.claim_work(env.item.id, ACTOR)

    assert rec(env).state == READY
    assert start(env).owned


def test_case_a_item_claimed_by_another_actor_is_refused(env):
    env.store.claim_work(env.item.id, "someone-else")

    assert rec(env).state == CLAIMED_BY_OTHER
    with pytest.raises(WorkRefused, match="claimed-by-other"):
        start(env)

    assert env.calls == []


# -- Case B: ledger write succeeded, Beads write-back failed ----------------------


def test_case_b_exact_run_is_linked_by_reconciliation_without_rerunning(env):
    env.store.fail_metadata_after = 1  # the attempt marker succeeds; the write-back fails

    with pytest.raises(WriteBackFailed, match="ledger is intact") as failure:
        start(env)

    (run,) = env.ledger.runs()
    assert failure.value.run_id == run.run_id and run.work_item_id == env.item.id
    env.store.fail_metadata_after = None
    ledger_before = snapshot(env.ledger.root)

    found = rec(env)
    assert found.state == LINK_RUNS and found.unlinked_runs == [run.run_id]

    for _ in range(3):
        final = apply(env)

    item = env.store.get_work(env.item.id)
    assert final.state == AWAITING_COMPLETION and final.linked_runs == [run.run_id]
    assert item.metadata[handoff.RUN_IDS] == [run.run_id]
    assert item.metadata[handoff.RUN_LINKS] == {run.run_id: handoff.LINK_RECONCILED}
    assert item.metadata[handoff.ATTEMPT_STATE] == handoff.RECORDED
    assert len(env.calls) == 1  # the investigation ran once
    assert snapshot(env.ledger.root) == ledger_before


def test_case_b_ignores_lookalike_runs_without_the_reference(env):
    env.store.fail_metadata_after = 1

    with pytest.raises(WriteBackFailed):
        start(env)

    env.store.fail_metadata_after = None
    lookalike = env.investigate(OBJECTIVE)  # same objective and firmware, no reference

    final = apply(env)
    assert lookalike not in final.linked_runs and final.linked_runs == [r.run_id for r in handoff.runs_for_item(env.ledger, env.item.id)]


def test_beads_unavailable_before_the_run_leaves_the_ledger_untouched(env):
    env.store.fail_metadata_after = 0  # cannot even write the attempt marker

    with pytest.raises(WorkStoreUnavailable):
        start(env)

    assert env.calls == [] and not env.ledger.root.exists()


# -- Case C: interrupted before recording ---------------------------------------


def test_case_c_investigation_error_is_recorded_and_needs_explicit_restart(env):
    def explode(objective, work_item_id):
        raise RuntimeError("model endpoint unreachable")

    with pytest.raises(RuntimeError, match="unreachable"):
        start(env, investigate=explode)

    found = rec(env)
    assert found.state == INTERRUPTED and "model endpoint unreachable" in found.detail
    assert found.attempt[handoff.ATTEMPT_STATE] == handoff.FAILED
    assert env.store.get_work(env.item.id).status == IN_PROGRESS  # claim kept, not silently released

    with pytest.raises(WorkRefused, match="--restart"):
        start(env)
    assert env.calls == []

    outcome = start(env, restart=True)
    assert outcome.reconciliation.state == AWAITING_COMPLETION
    assert any("may propose equivalent claims" in note for note in outcome.notes)


def test_case_c_crash_leaves_running_attempt_that_is_interrupted_once_no_process_holds_it(env):
    mark_attempt(env)  # process died after writing the marker; its lock died with it

    assert rec(env).state == INTERRUPTED
    with pytest.raises(WorkRefused, match="interrupted"):
        start(env)

    assert start(env, restart=True).owned


def test_case_c_attempt_still_running_locally_is_active_and_cannot_be_restarted(env):
    mark_attempt(env)
    holder = HeldElsewhere(env.locks, env.item.id)

    try:
        found = rec(env)
        assert found.state == ACTIVE and "another APTrace process" in found.detail

        with pytest.raises(WorkActive):
            start(env, restart=True)
        with pytest.raises(WorkActive):
            handoff.complete_investigation(env.store, env.ledger, env.item.id, actor=ACTOR, lock_dir=env.locks)
        assert apply(env).state == ACTIVE
    finally:
        holder.kill()  # the kernel releases the lock when the process dies

    assert rec(env).state == INTERRUPTED
    assert env.calls == []


def test_case_c_attempt_on_another_host_is_treated_as_possibly_active(env):
    mark_attempt(env, host="other-mac-mini")

    found = rec(env)
    assert found.state == ACTIVE and "cannot be checked" in found.detail

    with pytest.raises(WorkRefused, match="active"):
        start(env, restart=True)


def test_case_c_reports_claims_left_by_a_partial_recording(env):
    mark_attempt(env)
    claim = env.ledger.propose_claim(
        subject="s", assertion="partial", claim_type="OTHER", proposed_grade="PROBABLE", proposed_by="t", run_id="R-never-recorded",
    )

    found = rec(env)
    assert found.state == INTERRUPTED and found.partial_claims == [claim.key]
    assert any(claim.key in note for note in start(env, restart=True).notes)
    assert env.ledger.state(claim.key) == ClaimState.PROPOSED  # reported, not discarded


def test_unreferenced_lookalike_run_needs_operator_review_and_is_never_linked(env):
    mark_attempt(env)
    lookalike = env.investigate(OBJECTIVE)  # e.g. recorded by a pre-integration build

    found = rec(env)
    assert found.state == OPERATOR_REVIEW and found.heuristic_candidates == [lookalike]

    for _ in range(2):
        assert apply(env).state == OPERATOR_REVIEW
    with pytest.raises(WorkRefused, match="operator-review"):
        start(env, restart=True)

    assert handoff.RUN_IDS not in env.store.get_work(env.item.id).metadata


# -- Case D: repeated reconciliation -----------------------------------------------


def test_case_d_reconciliation_is_idempotent_in_every_state(env):
    for state in (READY, AWAITING_COMPLETION, COMPLETED):
        if state == AWAITING_COMPLETION:
            start(env)
        if state == COMPLETED:
            handoff.complete_investigation(env.store, env.ledger, env.item.id, actor=ACTOR, lock_dir=env.locks)

        store_before, ledger_before, items = env.store.snapshot(), snapshot(env.ledger.root), len(env.store.items)

        for _ in range(3):
            assert rec(env).state == state
            assert apply(env).state == state

        assert env.store.snapshot() == store_before and snapshot(env.ledger.root) == ledger_before
        assert len(env.store.items) == items

    assert len(env.ledger.runs()) == 1 and len(env.calls) == 1
    # Completing again is a no-op.
    again = handoff.complete_investigation(env.store, env.ledger, env.item.id, actor=ACTOR, lock_dir=env.locks)
    assert again.state == COMPLETED and env.store.snapshot() == store_before


# -- Case E: conflicting records -----------------------------------------------------


def test_case_e_item_pointing_to_a_missing_run_is_a_conflict(env):
    handoff.link_run(env.store, env.item.id, "R-20261013T000000-gone00")

    found = rec(env)
    assert found.state == CONFLICT and [p.code for p in found.problems] == ["missing-run"]
    with pytest.raises(WorkRefused, match="conflict"):
        start(env)
    assert apply(env).state == CONFLICT and env.calls == []


def test_case_e_run_with_other_firmware_identity_is_a_conflict_not_repaired(env):
    write_run(env.ledger, env.context, run_id="R-wrong-firmware", work_item_id=env.item.id, firmware_sha256="f" * 64)
    store_before = env.store.snapshot()

    found = rec(env)
    assert found.state == CONFLICT and found.problems[0].code == "identity-mismatch" and found.problems[0].run_id == "R-wrong-firmware"
    assert apply(env).state == CONFLICT
    assert env.store.snapshot() == store_before


def test_case_e_listed_run_for_another_item_or_without_reference_is_a_conflict(env):
    write_run(env.ledger, env.context, run_id="R-foreign", work_item_id="apt-other")
    write_run(env.ledger, env.context, run_id="R-unreferenced")
    handoff.link_run(env.store, env.item.id, "R-foreign")
    handoff.link_run(env.store, env.item.id, "R-unreferenced")

    assert sorted(p.code for p in rec(env).problems) == ["foreign-run", "unreferenced-linked-run"]


# -- 10: no automatic re-execution; explicit reruns ----------------------------------


def test_existing_linked_run_prevents_re_execution_unless_rerun(env):
    first = start(env)

    with pytest.raises(WorkRefused, match="--rerun"):
        start(env)
    assert len(env.calls) == 1

    second = start(env, rerun=True)

    assert first.run_id != second.run_id
    assert [r.run_id for r in handoff.runs_for_item(env.ledger, env.item.id)] == [first.run_id, second.run_id]
    assert any("Nothing is merged" in note for note in second.notes)
    first_claims, second_claims = (env.ledger.run(r).claim_versions for r in (first.run_id, second.run_id))
    assert second.reconciliation.duplicate_claims == [first_claims + second_claims]  # reported only
    assert all(env.ledger.state(k) == ClaimState.PROPOSED for k in first_claims + second_claims)


def test_completed_item_is_never_re_executed(env):
    start(env)
    handoff.complete_investigation(env.store, env.ledger, env.item.id, actor=ACTOR, lock_dir=env.locks)

    for flags in ({}, {"rerun": True}, {"restart": True}):
        with pytest.raises(WorkRefused, match="completed"):
            start(env, **flags)

    assert len(env.calls) == 1


# -- 12: lease expiry and concurrent invocations during a live run ----------------------


def test_second_invocation_cannot_start_while_the_first_is_running(env):
    seen = {}

    def investigate(objective, work_item_id):
        for actor in (ACTOR, "other-worker"):
            with pytest.raises(WorkActive):
                start(env, actor=actor, restart=True, rerun=True)

        seen["reconcile"] = rec(env).state
        return env.investigate(objective, work_item_id)

    start(env, investigate=investigate)

    assert seen["reconcile"] == ACTIVE and len(env.ledger.runs()) == 1


def test_lease_reclaimed_during_a_live_run_does_not_close_or_reassign_the_result(env):
    def investigate(objective, work_item_id):
        # The 5-minute lease expires; a supervisor runs `bd reclaim`, and another actor claims.
        env.store.reclaim(work_item_id)
        env.store.claim_work(work_item_id, "other-worker")
        return env.investigate(objective, work_item_id)

    outcome = start(env, investigate=investigate)

    item = env.store.get_work(env.item.id)
    assert not outcome.owned and any("ownership" in note for note in outcome.notes)
    assert (item.status, item.assignee) == (IN_PROGRESS, "other-worker")
    assert item.metadata[handoff.RUN_IDS] == [outcome.run_id]  # the exact fact is still recorded
    assert item.metadata[handoff.ATTEMPT_STATE] == handoff.RUNNING  # attempt marker left as found
    assert outcome.reconciliation.state == CLAIMED_BY_OTHER

    with pytest.raises(WorkRefused):
        handoff.complete_investigation(env.store, env.ledger, env.item.id, actor=ACTOR, lock_dir=env.locks)


# -- 14: completion never touches the ledger --------------------------------------------


def test_completion_requires_a_linked_run_and_never_changes_claim_state(env):
    with pytest.raises(WorkRefused, match="ready"):
        handoff.complete_investigation(env.store, env.ledger, env.item.id, actor=ACTOR, lock_dir=env.locks)

    outcome = start(env)
    keys = env.ledger.run(outcome.run_id).claim_versions
    states = {k: env.ledger.state(k) for k in keys}
    before = snapshot(env.ledger.root)

    done = handoff.complete_investigation(env.store, env.ledger, env.item.id, actor=ACTOR, lock_dir=env.locks, reason="operator reviewed")

    item = env.store.get_work(env.item.id)
    assert done.state == COMPLETED and item.status == CLOSED
    assert item.close_reason.startswith("operator reviewed.") and "owned by the APTrace ledger" in item.close_reason
    assert snapshot(env.ledger.root) == before
    assert {k: env.ledger.state(k) for k in keys} == states
    assert all(ClaimVerifier(env.ledger, runner=env.runner, replay=False).precheck(k).current == ClaimState.PROPOSED for k in keys)


def test_lock_ids_are_restricted(tmp_path):
    with pytest.raises(ValueError):
        ItemLock(tmp_path, "../escape")

