"""
`aptrace-agent research --work-item` and `aptrace-agent work ...`.

The executor, context, and work store are faked; the controller runs with a
scripted planner and the run is recorded with record_investigation, so the
CLI wiring is exercised without census data, Beads, or a model.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

import pytest

from aptrace_agent import cli, ledger_wiring, work_cli
from aptrace_agent import executor as executor_module
from aptrace_agent.investigator import AutonomousInvestigationRun
from aptrace_agent.ledger.models import SourceRevision
from aptrace_agent.ledger.recorder import RecordingExecutor, record_investigation
from aptrace_agent.ledger.store import ResearchLedger
from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchController, ResearchSession
from aptrace_agent.work import handoff

from ledger_support import FakeExecutor, MutableContext
from work_support import OBJECTIVE, FakeWorkStore, Planner


@pytest.fixture
def cli_env(monkeypatch, tmp_path):
    context = MutableContext()
    store = FakeWorkStore()
    ledger_dir = tmp_path / "ledger"
    calls = []

    def autonomous(objective, *, seed_function, max_steps, executor=None, claim_contract=False):
        calls.append(objective)
        registry = LeadRegistry()
        session = ResearchSession(objective=objective, registry=registry, follower=LeadFollower(registry=registry, executor=executor))
        session.state.add_lead(registry.register(kind="function", description="USB handler", tool="function_facts", arguments={"function": "FUN_0000cc14"}))
        result = ResearchController(planner_client=Planner(), planner_model="scripted", reconciler=object(), max_steps=1, claim_contract=claim_contract).run(session)
        return AutonomousInvestigationRun(objective=objective, seed_function=seed_function, result=result, state=session.state.model_copy(deep=True), evidence=tuple(session.ledger.all()))

    def record(run, *, executor, recorder, ledger_dir_override, started_at, ended_at, max_steps, controller_cls, work_item_id=None):
        return record_investigation(
            ResearchLedger(ledger_dir_override), run, context=context(), recorder=recorder, model="scripted", execution_config={},
            planner_version="test", budgets={"max_steps": max_steps}, started_at=started_at, ended_at=ended_at,
            source=SourceRevision(), work_item_id=work_item_id,
        ).run_id

    monkeypatch.setattr(executor_module, "EvidenceExecutor", FakeExecutor)
    monkeypatch.setattr(ledger_wiring, "context_provider", lambda _executor: context)
    monkeypatch.setattr(cli, "run_autonomous_investigation", autonomous)
    monkeypatch.setattr(cli, "record_research_run", record)
    monkeypatch.setattr(work_cli, "_open", lambda args, initialize=False: (store, tmp_path / "locks"))
    monkeypatch.setattr(work_cli, "_context", lambda: context())
    item = handoff.create_investigation(store, context=context(), objective=OBJECTIVE)

    def main(*argv):
        monkeypatch.setattr(sys, "argv", ["aptrace-agent", *argv])
        cli.main()

    return type("CliEnv", (), dict(store=store, item=item, ledger=ResearchLedger(ledger_dir), ledger_dir=str(ledger_dir), calls=calls, main=staticmethod(main), context=context))


def test_plain_research_never_loads_the_work_package_or_needs_beads(tmp_path):
    script = textwrap.dedent("""
        import json, sys
        from types import SimpleNamespace
        from aptrace_agent import cli
        from aptrace_agent.research import ResearchRunResult, ResearchState
        run = SimpleNamespace(objective="o", seed_function=None, result=ResearchRunResult(stop_reason="planner_finished", steps=(), reconciled=True),
                              state=ResearchState(objective="o"), evidence=())
        cli.run_autonomous_investigation = lambda objective, **kwargs: run
        sys.argv = ["aptrace-agent", "research", "--json", "o"]
        cli.main()
        print(json.dumps(sorted(m for m in sys.modules if m == "aptrace_agent.work" or m.startswith("aptrace_agent.work."))))
    """)
    env = {**os.environ, "APTRACE_BD": str(tmp_path / "no-bd"), "APTRACE_WORK_DIR": str(tmp_path / "no-work")}
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env, timeout=120)

    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout.strip().splitlines()[-1]) == []
    assert "work_item" not in done.stdout and not (tmp_path / "no-work").exists()


def test_plain_research_ledger_run_has_no_work_reference(cli_env, capsys):
    cli_env.main("research", "--ledger", "--ledger-dir", cli_env.ledger_dir, "--json", OBJECTIVE)

    payload = json.loads(capsys.readouterr().out)
    assert "work_item" not in payload
    assert cli_env.ledger.run(payload["ledger_run_id"]).work_item_id is None
    assert cli_env.store.get_work(cli_env.item.id).status == "open"  # untouched


def test_research_with_work_item_runs_records_and_links(cli_env, capsys):
    cli_env.main("research", "--ledger", "--ledger-dir", cli_env.ledger_dir, "--work-item", cli_env.item.id, "--json")

    payload = json.loads(capsys.readouterr().out)
    work = payload["work_item"]
    run = cli_env.ledger.run(payload["ledger_run_id"])
    assert cli_env.calls == [OBJECTIVE] and payload["objective"] == OBJECTIVE
    assert run.work_item_id == cli_env.item.id and work["run_id"] == run.run_id
    assert work["reconciliation"]["state"] == handoff.AWAITING_COMPLETION
    assert cli_env.store.get_work(cli_env.item.id).metadata[handoff.RUN_IDS] == [run.run_id]


def test_research_with_work_item_prints_work_summary(cli_env, capsys):
    cli_env.main("research", "--ledger", "--ledger-dir", cli_env.ledger_dir, "--work-item", cli_env.item.id)

    out = capsys.readouterr().out
    assert f"WORK ITEM {cli_env.item.id}" in out and "awaiting-completion" in out and "not closed automatically" in out


def test_work_item_requires_ledger(cli_env, capsys):
    with pytest.raises(SystemExit) as exit_:
        cli_env.main("research", "--work-item", cli_env.item.id)

    assert exit_.value.code == 2 and "--work-item requires --ledger" in capsys.readouterr().err


def test_objective_is_still_required_without_work_item(cli_env, capsys):
    with pytest.raises(SystemExit) as exit_:
        cli_env.main("research", "--ledger")

    assert exit_.value.code == 2 and cli_env.calls == []


def test_refusal_exits_before_running(cli_env):
    cli_env.main("research", "--ledger", "--ledger-dir", cli_env.ledger_dir, "--work-item", cli_env.item.id)

    with pytest.raises(SystemExit, match="--rerun"):
        cli_env.main("research", "--ledger", "--ledger-dir", cli_env.ledger_dir, "--work-item", cli_env.item.id)

    assert len(cli_env.calls) == 1


def test_mismatched_objective_is_rejected(cli_env):
    with pytest.raises(SystemExit, match="differs"):
        cli_env.main("research", "--ledger", "--ledger-dir", cli_env.ledger_dir, "--work-item", cli_env.item.id, "Another", "objective.")

    assert cli_env.calls == []


def test_write_back_failure_still_reports_the_recorded_run(cli_env, capsys):
    cli_env.store.fail_metadata_after = 1

    with pytest.raises(SystemExit, match="work reconcile .* --apply"):
        cli_env.main("research", "--ledger", "--ledger-dir", cli_env.ledger_dir, "--work-item", cli_env.item.id)

    out = capsys.readouterr().out
    (run,) = cli_env.ledger.runs()
    assert "Research complete" in out and f"run {run.run_id} recorded; write-back FAILED" in out
    cli_env.store.fail_metadata_after = None

    cli_env.main("work", "reconcile", cli_env.item.id, "--apply", "--ledger-dir", cli_env.ledger_dir, "--json")
    rec = json.loads(capsys.readouterr().out)
    assert rec["state"] == handoff.AWAITING_COMPLETION and rec["linked_runs"] == [run.run_id]


def test_work_create_reconcile_and_complete(cli_env, capsys):
    cli_env.main("work", "create", "--priority", "1", "Trace", "SERCOM2", "usage.")
    created = capsys.readouterr().out.split()[0]
    item = cli_env.store.get_work(created)
    assert item.priority == 1 and item.metadata[handoff.OBJECTIVE] == "Trace SERCOM2 usage."
    assert item.metadata[handoff.FIRMWARE_SHA256] == cli_env.context().firmware_sha256

    cli_env.main("work", "reconcile", created, "--ledger-dir", cli_env.ledger_dir)
    assert "state: ready" in capsys.readouterr().out

    with pytest.raises(SystemExit, match="refused \\[ready\\]"):
        cli_env.main("work", "complete", created, "--ledger-dir", cli_env.ledger_dir)

    cli_env.main("research", "--ledger", "--ledger-dir", cli_env.ledger_dir, "--work-item", created)
    capsys.readouterr()
    cli_env.main("work", "complete", created, "--ledger-dir", cli_env.ledger_dir, "--reason", "reviewed")
    assert "state: completed" in capsys.readouterr().out
    assert cli_env.store.get_work(created).status == "closed"


def test_reconcile_conflict_exits_nonzero(cli_env, capsys):
    handoff.link_run(cli_env.store, cli_env.item.id, "R-missing")

    with pytest.raises(SystemExit) as exit_:
        cli_env.main("work", "reconcile", cli_env.item.id, "--ledger-dir", cli_env.ledger_dir)

    assert exit_.value.code == 1 and "problem missing-run" in capsys.readouterr().out
