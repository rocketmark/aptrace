#!/usr/bin/env python3
"""Performing Rigs: the 0xea54 function-pointer load through the production
value_forward_use operation, recorded and replayed in a SCRATCH ledger.

The operation runs through the normal APTrace execution path
(EvidenceExecutor -> LedgerOperationRunner) with the case's execution
context. The canonical ledger is never opened: the ledger lives in a
temporary directory (or --ledger DIR, which must not be the case ledger).
The invocation, evidence record and result are copied to
research/runs/pcode-forward-use-v1/ea54-ledger-record.json.

    agent/.venv/bin/python cases/performing-rigs/scripts/value_forward_use_ea54.py
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

CASE = Path(__file__).resolve().parents[1]
OUT = CASE / "research" / "runs" / "pcode-forward-use-v1"
ORIGIN = "0x0000ea54"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ledger", type=Path, help="scratch ledger directory (default: a temporary one)")
    args = p.parse_args(argv)

    from aptrace_agent.executor import EvidenceExecutor
    from aptrace_agent.ledger.operations import LedgerOperationRunner
    from aptrace_agent.ledger.store import ResearchLedger
    from aptrace_agent.ledger_wiring import DEFAULT_LEDGER_DIR, context_provider

    with tempfile.TemporaryDirectory(prefix="aptrace-scratch-ledger-") as tmp:
        root = args.ledger or Path(tmp) / "ledger"
        if root.resolve() == DEFAULT_LEDGER_DIR.resolve():
            sys.exit("refusing to write the canonical ledger")
        ledger = ResearchLedger(root)
        executor = EvidenceExecutor()
        ops = LedgerOperationRunner(ledger, executor, context_provider(executor))

        invocation, artifact = ops.run("R-pcode-ea54", "value_forward_use", {"origin": ORIGIN})
        if artifact is None:
            sys.exit(f"operation failed: {invocation.error}")
        result, intact = ledger.evidence_result(artifact.evidence_id)
        replays = [ops.replay(invocation.invocation_id, run_id=f"R-pcode-ea54-replay{i}") for i in (1, 2)]

        record = {
            "note": "scratch-ledger record of the production value_forward_use operation; canonical ledger untouched",
            "invocation": invocation.model_dump(mode="json"),
            "evidence": artifact.model_dump(mode="json"),
            "result_intact": intact,
            "result": result,
            "replays": [{"matches": r.matches, "replay_sha256": r.replay_sha256, "input_drift": r.input_drift,
                         "differences": r.differences, "runtime_ms": r.replay.runtime_ms} for r in replays],
        }
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / "ea54-ledger-record.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")

    print(result["planner_summary"])
    print(f"evidence {artifact.evidence_id} grade={artifact.grade} result_sha256={artifact.result_sha256[:16]}")
    print(f"runtime_ms={invocation.runtime_ms} replays match={[r.matches for r in replays]}")
    return 0 if all(r.matches for r in replays) else 1


if __name__ == "__main__":
    sys.exit(main())
