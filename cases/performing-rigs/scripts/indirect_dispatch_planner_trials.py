#!/usr/bin/env python3
"""Planner trials for the indirect_call_target operation, recorded in a
SCRATCH copy of the case ledger (the canonical ledger is never written).

  scripted  a scripted planner selects resolve_indirect_call on the site
            the seed's disassembly exposes, then finishes; the run is
            recorded through the real executor and the recorded invocation
            is replayed
  live      bounded runs of the local planner (APTRACE_MODEL at
            OMLX_BASE_URL) on the same seed and objective; whether the
            operation was offered, selected, with which site, and which
            claims were proposed and admitted

A scripted selection is not autonomous tool selection; only the live trials
say anything about that. Run with the agent venv from the repo root:

    agent/.venv/bin/python cases/performing-rigs/scripts/indirect_dispatch_planner_trials.py \\
        --ledger-dir "$TMPDIR/indirect-dispatch-ledger" [--live N] [--out FILE]
"""
import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
CASE = HERE.parent
REPO_ROOT = CASE.parents[1]
CANONICAL_LEDGER = CASE / "research" / "ledger"
DEFAULT_OUT = CASE / "research" / "runs" / "indirect-dispatch-v1" / "planner-trials.json"
SEED = "FUN_0000c5cc"
OBJECTIVE = ("Determine which code the register-indirect call near the end of FUN_0000c5cc can transfer control to, "
             "and whether that call could dispatch through slot 7 or slot 8 of the vtable at 0x14900.")
MAX_STEPS = 6


class ScriptedPlanner:
    """OpenAI-shaped client returning scripted tool calls (then 'finish')."""

    def __init__(self, decisions):
        self.decisions = list(decisions)
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **_kwargs):
        name, arguments = self.decisions.pop(0) if self.decisions else ("finish", {"reason": "scripted trial done"})
        call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=json.dumps(arguments)))
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[call]))],
                               usage=SimpleNamespace(prompt_tokens=0, completion_tokens=0))


def _record(run, recorder, ledger_dir, started):
    from aptrace_agent.ledger_cli import record_research_run
    from aptrace_agent.research import ResearchController

    return record_research_run(run, executor=recorder.inner, recorder=recorder, ledger_dir_override=str(ledger_dir),
                               started_at=started, ended_at=datetime.now(timezone.utc).isoformat(),
                               max_steps=MAX_STEPS, controller_cls=ResearchController)


def _trial_record(run, run_id):
    result = run.result
    offered = [("resolve_indirect_call" in r.get("tools", [])) for r in result.planner_requests if r["phase"] == "decision"]
    return {
        "ledger_run_id": run_id,
        "stop_reason": result.stop_reason,
        "steps": [{"n": s.number, "action": s.action, "evidence": s.evidence_id} for s in result.steps],
        "decision_requests": len(offered),
        "resolve_offered_in": sum(offered),
        "resolved_sites": [o.arguments.get("site") for o in run.evidence if o.tool == "indirect_call_target"],
        "claim_admission": [{"decision": a.decision, "raw": a.raw, "grade": a.grade, "claim_type": a.claim_type,
                             "evidence_ids": list(a.evidence_ids),
                             "diagnostics": [getattr(d, "code", str(d)) for d in getattr(a, "diagnostics", []) or []]}
                            for a in result.claim_admission],
        "session_facts": [c.statement for c in run.state.claims if c.basis == "static-dataflow"],
    }


def scripted(ledger_dir):
    from aptrace_agent.executor import EvidenceExecutor
    from aptrace_agent.investigator import run_autonomous_investigation
    from aptrace_agent.ledger.operations import LedgerOperationRunner
    from aptrace_agent.ledger.recorder import RecordingExecutor
    from aptrace_agent.ledger.store import ResearchLedger
    from aptrace_agent.ledger_wiring import context_provider
    from aptrace_agent.research import ResearchController

    recorder = RecordingExecutor(EvidenceExecutor())
    inner = recorder.inner
    controller = ResearchController(
        planner_client=ScriptedPlanner([("resolve_indirect_call", {"site": "0x0000c6d8"})]),
        planner_model="scripted", reconciler=SimpleNamespace(run=lambda session: None), max_steps=MAX_STEPS,
        census_peripherals=inner.census.available_peripherals(),
        structural_tools=("usb_inventory", "common_paths", "function_effects", "observed_call_arguments",
                          "indirect_call_target"),
        indirect_sites=inner.indirect_targets.sites(), claim_contract=True)
    started = datetime.now(timezone.utc).isoformat()
    run = run_autonomous_investigation(OBJECTIVE, seed_function=SEED, max_steps=MAX_STEPS, controller=controller,
                                       executor=recorder, claim_contract=True)
    run_id = _record(run, recorder, ledger_dir, started)
    ledger = ResearchLedger(ledger_dir)
    invocations = [i for i in ledger.invocations() if i.run_id == run_id and i.tool == "indirect_call_target"]
    ops = LedgerOperationRunner(ledger, inner, context_provider(inner))
    replays = []
    for inv in invocations:
        replay = ops.replay(inv.invocation_id, run_id=f"{run_id}-replay")
        artifact = next(a for a in ledger.all_evidence() if a.invocation_id == inv.invocation_id)
        replays.append({"invocation": inv.invocation_id, "operation_key": inv.operation_key,
                        "arguments": inv.arguments, "input_artifacts": sorted(inv.input_artifacts),
                        "evidence_id": artifact.evidence_id, "grade": artifact.grade,
                        "limitation_codes": sorted(l.code for l in artifact.limitations),
                        "replay_matches": replay.matches})
    return {"mode": "scripted (not autonomous selection)", **_trial_record(run, run_id), "recorded": replays}


def live(ledger_dir, n):
    from aptrace_agent.executor import EvidenceExecutor
    from aptrace_agent.investigator import run_autonomous_investigation
    from aptrace_agent.ledger.recorder import RecordingExecutor

    trials = []
    for i in range(n):
        recorder = RecordingExecutor(EvidenceExecutor())
        started = datetime.now(timezone.utc).isoformat()
        try:
            run = run_autonomous_investigation(OBJECTIVE, seed_function=SEED, max_steps=MAX_STEPS, executor=recorder,
                                               claim_contract=True)
        except Exception as e:  # noqa: BLE001 -- a planner/runtime failure is a trial outcome, recorded as such
            trials.append({"trial": i + 1, "error": f"{type(e).__name__}: {e}"[:300]})
            continue
        trials.append({"trial": i + 1, **_trial_record(run, _record(run, recorder, ledger_dir, started))})
    return trials


def main(argv=None):
    import os

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ledger-dir", type=Path, required=True)
    p.add_argument("--live", type=int, default=0, help="number of live planner trials (needs the local runtime)")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = p.parse_args(argv)
    target = args.ledger_dir.resolve()
    if target == CANONICAL_LEDGER.resolve() or CANONICAL_LEDGER.resolve() in target.parents:
        raise SystemExit("refusing to write the canonical ledger")
    if target.exists():
        raise SystemExit(f"{target} exists; pass a new scratch directory")
    shutil.copytree(CANONICAL_LEDGER, target)
    sys.path.insert(0, str(REPO_ROOT / "agent" / "src"))
    doc = {"objective": OBJECTIVE, "seed": SEED, "max_steps": MAX_STEPS, "scratch_ledger": "copy of the canonical ledger",
           "model": os.environ.get("APTRACE_MODEL") if args.live else None, "scripted": scripted(target)}
    if args.live:
        doc["live"] = live(target, args.live)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=1, sort_keys=True, default=str) + "\n")
    print(json.dumps(doc["scripted"], indent=1, default=str)[:3000])


if __name__ == "__main__":
    sys.exit(main())
