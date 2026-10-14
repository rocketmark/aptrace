#!/usr/bin/env python3
"""Targeted semantic investigation of FUN_0000b4b4 (SERCOM0 constant):
record mechanically supported evidence in a SCRATCH copy of the case ledger
and write a reproducible summary.

Evidence recorded, in order, through the agent's typed operations (the
same EvidenceExecutor/LedgerOperationRunner the investigator uses):

  1. function_disassembly FUN_0000b4b4          (decoded image)
  2. function_effects     FUN_0000b4b4          (RAW Crucible, parametric r0)
  3. function_effects     FUN_0000b4b4 r0=SERCOM0 base
                                                (HYPOTHETICAL: solver
                                                specialization chosen here,
                                                not a caller value)
  4. callsite_context at each static call site  (decoded r0 preparation)
  5. observed_call_arguments FUN_0000b4b4       (CALLER-GROUNDED: concrete
                                                boot replay, Unicorn)
  6. observed_call_arguments FUN_0000b5bc, FUN_0000b658, FUN_0000c8bc
                                                (one caller level up)
  7. replay of (5)                              (determinism check)

The canonical ledger is never written: --ledger-dir must not exist and is
created as a copy of it. Run with the agent venv from the repo root:

    agent/.venv/bin/python cases/performing-rigs/scripts/sercom0_semantic_investigation.py \\
        --ledger-dir /tmp/sercom0-ledger
"""
import argparse
import json
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE = HERE.parent
DEFAULT_OUT = CASE / "research" / "runs" / "sercom0-semantic-v1"
FUNCTION = "FUN_0000b4b4"
SERCOM0_BASE = 0x40003000
RUN_ID = "R-sercom0-semantic-v1"
# FUN_0000c8bc stores its r1 into this+0x10, the field FUN_0000c7c0 passes to
# FUN_0000b658 (the unobserved branch); it also installs the table holding c7c0.
UPSTREAM = ("FUN_0000b5bc", "FUN_0000b658", "FUN_0000c8bc")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ledger-dir", required=True, help="scratch ledger directory to create (must not exist)")
    p.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = p.parse_args(argv)

    from aptrace_agent.executor import EvidenceExecutor
    from aptrace_agent.ledger.operations import LedgerOperationRunner
    from aptrace_agent.ledger.store import ResearchLedger
    from aptrace_agent.ledger_wiring import DEFAULT_LEDGER_DIR, context_provider

    scratch = Path(args.ledger_dir).resolve()
    if scratch == DEFAULT_LEDGER_DIR.resolve() or scratch.exists():
        sys.exit(f"refusing to use {scratch}: pass a new scratch directory, never the canonical ledger")
    shutil.copytree(DEFAULT_LEDGER_DIR, scratch)

    executor = EvidenceExecutor()
    ledger = ResearchLedger(scratch)
    ops = LedgerOperationRunner(ledger, executor, context_provider(executor))
    steps = []

    def record(label, basis, tool, arguments):
        t0 = time.perf_counter()
        invocation, artifact = ops.run(RUN_ID, tool, arguments)
        seconds = round(time.perf_counter() - t0, 3)
        result = ledger.load_blob(invocation.result_sha256)[0] if invocation.result_sha256 else None
        steps.append({
            "label": label, "basis": basis, "tool": tool, "arguments": arguments,
            "invocation_id": invocation.invocation_id, "evidence_id": invocation.evidence_id,
            "status": invocation.status, "error": invocation.error,
            "grade": artifact.grade if artifact else None, "grade_basis": artifact.grade_basis if artifact else None,
            "limitations": [l.code for l in artifact.limitations] if artifact else [],
            "summary": (result or {}).get("planner_summary"), "wall_seconds": seconds,
        })
        print(f"[{label}] {tool} -> {invocation.status} {invocation.evidence_id} ({seconds}s)", flush=True)
        return invocation, result

    record("callee-disassembly", "STATIC_DECODE", "function_disassembly", {"function": FUNCTION})
    # Same canonical arguments as the historical evidence (EV-f9a9ae317433aceb), so the
    # identical operation is recognised; omitting the empty specialization changes the key.
    record("callee-effects", "SYMBOLIC_ALL_INPUTS", "function_effects", {"function": FUNCTION, "specialize": {}})
    record("callee-effects-hypothetical-sercom0", "HYPOTHETICAL_SOLVER_SPECIALIZATION", "function_effects",
           {"function": FUNCTION, "specialize": {"r0": SERCOM0_BASE}})

    static_sites = [(c.address, c.function) for c in executor.ghidra.function_facts(FUNCTION, max_edges=1000).callers]
    for address, caller in static_sites:
        record(f"callsite {address}", "STATIC_DECODE", "callsite_context",
               {"function": caller, "address": address, "before": 6, "after": 2})

    observed, observed_result = record("caller-arguments", "CALLER_GROUNDED_CONCRETE", "observed_call_arguments",
                                       {"function": FUNCTION})
    # One level up: which callers reach FUN_0000b5bc (the caller at 0xb5c2,
    # itself called from two static sites), and whether FUN_0000b658 runs.
    observations = {FUNCTION: observed_result}
    for upstream in UPSTREAM:
        _, observations[upstream] = record(f"caller-arguments {upstream}", "CALLER_GROUNDED_CONCRETE",
                                           "observed_call_arguments", {"function": upstream})

    t0 = time.perf_counter()
    replay = ops.replay(observed.invocation_id, run_id=RUN_ID + "-replay")
    replay_doc = {"original": observed.invocation_id, "replay": replay.replay.invocation_id,
                  "matches": replay.matches, "input_drift": replay.input_drift,
                  "differences": replay.differences, "wall_seconds": round(time.perf_counter() - t0, 3)}
    print(f"[replay] matches={replay.matches}", flush=True)

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, result in observations.items():
        (out / f"observed_call_arguments.{name}.json").write_text(json.dumps(result, indent=1, sort_keys=True))
    (out / "summary.json").write_text(json.dumps({
        "function": FUNCTION, "run_id": RUN_ID,
        "context_artifacts": ops.context().artifacts, "steps": steps, "replay": replay_doc,
    }, indent=1, sort_keys=True))
    print(f"wrote {out}/summary.json", flush=True)


if __name__ == "__main__":
    main()
