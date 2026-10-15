#!/usr/bin/env python3
"""Planner trials for the value_forward_use operation, recorded in a SCRATCH
copy of the case ledger (the canonical ledger is never written).

  scripted  a scripted planner selects trace_value_use on the 0xea54 load
            the seed's disassembly exposes, then finishes; the run is
            recorded through the real executor and the invocation replayed
  live      bounded runs of the local planner (APTRACE_MODEL at
            OMLX_BASE_URL) on the same seed and objective: whether the
            operation was offered and selected, with which origin
            (selection), and which claims were proposed and admitted
            (interpretation)

A scripted selection is not autonomous tool selection; only the live trials
say anything about that. Run with the agent venv from the repo root:

    agent/.venv/bin/python cases/performing-rigs/scripts/value_forward_use_planner_trials.py \\
        --ledger-dir "$TMPDIR/value-forward-use-ledger" [--live N]
"""
import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
CASE = HERE.parent
sys.path.insert(0, str(HERE))
from callback_provenance_planner_trials import ScriptedPlanner, _record  # noqa: E402

CANONICAL_LEDGER = CASE / "research" / "ledger"
OUT = CASE / "research" / "runs" / "pcode-forward-use-v1" / "planner-trials.json"
SEED = "FUN_0000e8a8"
OBJECTIVE = ("FUN_0000e8a8 loads a pointer to FUN_0000ec48 from a flash literal. Determine where that loaded "
             "pointer value goes inside FUN_0000e8a8: is it called, passed, stored or returned, or only tested?")
MAX_STEPS = 5
ORIGIN = "0x0000ea54"


def _trial_record(run, run_id):
    result = run.result
    requests = [r for r in result.planner_requests if r["phase"] == "decision"]
    return {
        "ledger_run_id": run_id,
        "stop_reason": result.stop_reason,
        "steps": [{"n": s.number, "action": s.action, "evidence": s.evidence_id} for s in result.steps],
        "decision_requests": len(requests),
        "trace_offered_in": sum("trace_value_use" in r.get("tools", []) for r in requests),
        "traced_origins": [o.arguments.get("origin") for o in run.evidence if o.tool == "value_forward_use"],
        "verdicts": {o.arguments.get("origin"): o.result.get("verdict") for o in run.evidence if o.tool == "value_forward_use"},
        "first_trace_step": next((s.number for s in result.steps if s.action == "value_forward_use"), None),
        "claim_admission": [{"decision": a.decision, "raw": a.raw, "grade": a.grade, "claim_type": a.claim_type,
                             "evidence_ids": list(a.evidence_ids),
                             "diagnostics": [getattr(d, "code", str(d)) for d in getattr(a, "diagnostics", []) or []]}
                            for a in result.claim_admission],
        "session_facts": [c.statement for c in run.state.claims if c.basis == "static-dataflow"],
        "evidence_tools": {o.id: o.tool for o in run.evidence},
    }


def _controller(inner, planner_client=None, planner_model=None):
    from aptrace_agent.research import ResearchController
    from aptrace_agent.value_forward_use import census_code_pointer_loads

    kwargs = {"planner_client": planner_client, "planner_model": planner_model} if planner_client else {}
    return ResearchController(
        **kwargs, reconciler=SimpleNamespace(run=lambda session: None) if planner_client else None, max_steps=MAX_STEPS,
        census_peripherals=inner.census.available_peripherals(),
        structural_tools=("usb_inventory", "common_paths", "function_effects", "observed_call_arguments",
                          "indirect_call_target", "callback_argument_provenance", "value_forward_use"),
        indirect_sites=inner.indirect_targets.sites(),
        value_origins=census_code_pointer_loads(inner.census.db_path, inner.census.firmware_key),
        observation_scenarios=inner.observed_calls.supported_scenarios(),
        claim_contract=True)


def scripted(ledger_dir):
    from aptrace_agent.executor import EvidenceExecutor
    from aptrace_agent.investigator import run_autonomous_investigation
    from aptrace_agent.ledger.operations import LedgerOperationRunner
    from aptrace_agent.ledger.recorder import RecordingExecutor
    from aptrace_agent.ledger.store import ResearchLedger
    from aptrace_agent.ledger_wiring import context_provider

    recorder = RecordingExecutor(EvidenceExecutor())
    inner = recorder.inner
    controller = _controller(inner, ScriptedPlanner([("trace_value_use", {"origin": ORIGIN})]), "scripted")
    started = datetime.now(timezone.utc).isoformat()
    run = run_autonomous_investigation(OBJECTIVE, seed_function=SEED, max_steps=MAX_STEPS, controller=controller,
                                       executor=recorder, claim_contract=True)
    run_id = _record(run, recorder, ledger_dir, started)
    ledger = ResearchLedger(ledger_dir)
    ops = LedgerOperationRunner(ledger, inner, context_provider(inner))
    replays = []
    for inv in [i for i in ledger.invocations() if i.run_id == run_id and i.tool == "value_forward_use"]:
        replay = ops.replay(inv.invocation_id, run_id=f"{run_id}-replay")
        artifact = next(a for a in ledger.all_evidence() if a.invocation_id == inv.invocation_id)
        replays.append({"invocation": inv.invocation_id, "operation_key": inv.operation_key, "arguments": inv.arguments,
                        "input_artifacts": sorted(inv.input_artifacts), "evidence_id": artifact.evidence_id,
                        "grade": artifact.grade, "limitation_codes": sorted(l.code for l in artifact.limitations),
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
                                               controller=_controller(recorder.inner), claim_contract=True)
        except Exception as e:  # noqa: BLE001 -- a planner/runtime failure is a trial outcome, recorded as such
            trials.append({"trial": i + 1, "error": f"{type(e).__name__}: {e}"[:300]})
            continue
        trials.append({"trial": i + 1, **_trial_record(run, _record(run, recorder, ledger_dir, started))})
        print(json.dumps(trials[-1], indent=1, default=str)[:2500], flush=True)
    return trials


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ledger-dir", type=Path, required=True)
    p.add_argument("--live", type=int, default=0, help="number of live planner trials (needs the local runtime)")
    p.add_argument("--out", type=Path, default=OUT)
    args = p.parse_args(argv)
    target = args.ledger_dir.resolve()
    if target == CANONICAL_LEDGER.resolve() or CANONICAL_LEDGER.resolve() in target.parents:
        raise SystemExit("refusing to write the canonical ledger")
    if target.exists():
        raise SystemExit(f"{target} exists; pass a new scratch directory")
    shutil.copytree(CANONICAL_LEDGER, target)
    doc = {"objective": OBJECTIVE, "seed": SEED, "max_steps": MAX_STEPS, "scratch_ledger": "copy of the canonical ledger",
           "model": os.environ.get("APTRACE_MODEL") if args.live else None, "scripted": scripted(target)}
    print(json.dumps(doc["scripted"], indent=1, default=str)[:3000], flush=True)
    if args.live:
        doc["live"] = live(target, args.live)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=1, sort_keys=True, default=str) + "\n")


if __name__ == "__main__":
    sys.exit(main())
