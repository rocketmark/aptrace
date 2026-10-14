#!/usr/bin/env python3
"""SERCOM0 investigation v2: run the registered scenario corpus against the
unresolved path FUN_0000c7c0 -> FUN_0000b658 -> FUN_0000b5bc -> FUN_0000b4b4
and the RAM fields that select the peripheral, recording every observation
in a SCRATCH copy of the case ledger, and write a reproducible summary.

Per registered scenario (config/observation_scenarios.json), through the
agent's typed operation observed_call_arguments (CALLER_GROUNDED_CONCRETE):

  FUN_0000b4b4  watching the first word of the six SERCOM wrapper objects
                (b4b4's only data-dependent access is a 4-byte read at r0;
                0x20004c54/0x20004c78 were observed as r0 in v1, the
                c8bc-stored 0x20004c48/60/6c are what the unobserved branch
                would pass, 0x20004c3c is the requested reproduction of the
                exploratory SERCOM0 word)
  FUN_0000c7c0  watching, on the three objects FUN_0000c8bc constructed in
                v1, the vtable word (this+0) and the SERCOM-object pointer
                (this+0x10) that c7c0 passes to b658
  FUN_0000b658, FUN_0000b5bc, FUN_0000c8bc   (path and prerequisite entries)

Static context: callsite_context at 0xc84a (c7c0's BL b658), and a slot
dispatch sweep (tools/census/slot_dispatch.py, pattern-matched, not ledger
evidence) for vtable slots 7/8 that lead to c7c0. Replays of two
observations check determinism. A boot run at 3,000,000 instructions (case
script budget override; not a ledger operation) checks whether the boot
main loop reaches anything new.

The canonical ledger is never written: --ledger-dir must not exist and is
created as a copy of it. Run with the agent venv from the repo root:

    agent/.venv/bin/python cases/performing-rigs/scripts/sercom0_scenario_investigation.py \\
        --ledger-dir "$TMPDIR/sercom0-v2-ledger"
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE = HERE.parent
REPO_ROOT = CASE.parents[1]
DEFAULT_OUT = CASE / "research" / "runs" / "sercom0-scenario-v2"
RUN_ID = "R-sercom0-scenario-v2"
FIRMWARE = CASE / "research" / "firmware" / "originals" / "firmware_autopilot868.bin"
SERCOM_WORDS = (0x20004C3C, 0x20004C48, 0x20004C54, 0x20004C60, 0x20004C6C, 0x20004C78)
OBJECTS = (0x20004348, 0x20004644, 0x20004940)  # FUN_0000c8bc `this` values observed in v1
WATCH_SERCOM = [{"address": f"0x{a:08x}", "size": 4} for a in SERCOM_WORDS]
WATCH_OBJECTS = [w for o in OBJECTS for w in ({"address": f"0x{o:08x}", "size": 4},
                                              {"address": f"0x{o + 0x10:08x}", "size": 4, "object_base": f"0x{o:08x}"})]
PATH = ("FUN_0000b658", "FUN_0000b5bc", "FUN_0000c8bc")
BUDGET_CHECK = 3_000_000


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _row(scenario, results):
    b4, c7, b6, b5, c8 = (results[f] for f in ("FUN_0000b4b4", "FUN_0000c7c0", "FUN_0000b658", "FUN_0000b5bc", "FUN_0000c8bc"))
    sites = {s["call_site"]: s for s in b5["call_sites"]}
    r0 = sorted({v["value"] for s in b4["call_sites"] for v in s["arguments"].get("r0", [])})
    regions = sorted({v["region"] or "?" for s in b4["call_sites"] for v in s["arguments"].get("r0", [])})

    def changes(result):
        fields = (result.get("watched_fields") or {}).get("fields", [])
        return {
            "initialized": [f["name"] for f in fields if f["initialization"]],
            "changed_after_initialization": [f["name"] for f in fields if f["changed_after_initialization"]],
            "never_written": [f["name"] for f in fields if not f["writes"]],
            "complete": (result.get("watched_fields") or {}).get("complete"),
        }

    run = b4.get("run") or {}
    return {
        "scenario": scenario,
        "kind": b4.get("scenario_config", {}).get("kind"),
        "status": b4["status"],
        "instructions": run.get("instructions_executed"),
        "termination": run.get("stop_reason") or (f"{run.get('legs')} legs, {run.get('budget_exhausted_legs')} at budget"
                                                  if "legs" in run else None),
        "c7c0_entries": c7["observed_entries"],
        "b658_entries": b6["observed_entries"],
        "b5bc_from_b658_0xb662": (sites.get("0x0000b662") or {}).get("status"),
        "b5bc_entries": b5["observed_entries"],
        "c8bc_entries": c8["observed_entries"],
        "b4b4_entries": b4["observed_entries"],
        "b4b4_r0_values": r0,
        "b4b4_r0_regions": regions,
        "b4b4_mmio_from_extent": (b4.get("mmio_in_function") or {}).get("access_count"),
        "sercom_words": changes(b4),
        "object_fields": changes(c7),
        "limitations": sorted({code for f in results.values() for code in f.get("_limitations", [])}),
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ledger-dir", required=True, help="scratch ledger directory to create (must not exist)")
    p.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = p.parse_args(argv)

    from aptrace_agent.executor import EvidenceExecutor
    from aptrace_agent.ledger.operations import LedgerOperationRunner
    from aptrace_agent.ledger.store import ResearchLedger
    from aptrace_agent.ledger_wiring import DEFAULT_LEDGER_DIR, context_provider
    from aptrace_agent.structural_wiring import UNICORN_PYTHON, OBSERVE_CALLS_SCRIPT

    scratch = Path(args.ledger_dir).resolve()
    if scratch == DEFAULT_LEDGER_DIR.resolve() or scratch.exists():
        sys.exit(f"refusing to use {scratch}: pass a new scratch directory, never the canonical ledger")
    shutil.copytree(DEFAULT_LEDGER_DIR, scratch)

    executor = EvidenceExecutor()
    ledger = ResearchLedger(scratch)
    ops = LedgerOperationRunner(ledger, executor, context_provider(executor))
    registered = executor.observed_calls.scenarios
    supported = set(executor.observed_calls.supported_scenarios())
    steps, observations, rows = [], {}, []

    def record(label, tool, arguments):
        t0 = time.perf_counter()
        invocation, artifact = ops.run(RUN_ID, tool, arguments)
        seconds = round(time.perf_counter() - t0, 3)
        result = ledger.load_blob(invocation.result_sha256)[0] if invocation.result_sha256 else None
        steps.append({
            "label": label, "tool": tool, "arguments": arguments,
            "invocation_id": invocation.invocation_id, "evidence_id": invocation.evidence_id,
            "status": invocation.status, "error": invocation.error,
            "grade": artifact.grade if artifact else None,
            "limitations": [l.code for l in artifact.limitations] if artifact else [],
            "summary": (result or {}).get("planner_summary"), "wall_seconds": seconds,
        })
        print(f"[{label}] {tool} -> {invocation.status} {invocation.evidence_id} "
              f"{(result or {}).get('status')} ({seconds}s)", flush=True)
        if result is not None:
            result = dict(result, _limitations=steps[-1]["limitations"], _evidence_id=invocation.evidence_id)
        return invocation, result

    record("static c7c0->b658 call", "callsite_context",
           {"function": "FUN_0000c7c0", "address": "0x0000c84a", "before": 4, "after": 1})

    categories = {"executed": [], "skipped_incompatible": [], "attempted_failed": [], "not_attempted": []}
    for scenario in sorted(registered):
        results = {}
        _, results["FUN_0000b4b4"] = record(f"{scenario} b4b4", "observed_call_arguments",
                                            {"function": "FUN_0000b4b4", "scenario": scenario, "watch": WATCH_SERCOM})
        _, results["FUN_0000c7c0"] = record(f"{scenario} c7c0", "observed_call_arguments",
                                            {"function": "FUN_0000c7c0", "scenario": scenario, "watch": WATCH_OBJECTS})
        for function in PATH:
            _, results[function] = record(f"{scenario} {function[-4:]}", "observed_call_arguments",
                                          {"function": function, "scenario": scenario})
        observations[scenario] = {f: r for f, r in results.items() if f in ("FUN_0000b4b4", "FUN_0000c7c0")}
        status = results["FUN_0000b4b4"]["status"]
        if scenario not in supported or status.startswith("unsupported"):
            categories["skipped_incompatible"].append({"scenario": scenario, "reason": status})
        elif status.startswith(("scenario_failed", "failed")):
            categories["attempted_failed"].append({"scenario": scenario, "reason": results["FUN_0000b4b4"].get("scenario_failure") or status})
        else:
            categories["executed"].append(scenario)
        rows.append(_row(scenario, results))

    replays = []
    for label in ("boot b4b4", "vl-plus b4b4"):
        original = next(s for s in steps if s["label"] == label)
        t0 = time.perf_counter()
        replay = ops.replay(original["invocation_id"], run_id=RUN_ID + "-replay")
        replays.append({"label": label, "original": original["invocation_id"], "replay": replay.replay.invocation_id,
                        "matches": replay.matches, "input_drift": replay.input_drift,
                        "differences": replay.differences, "wall_seconds": round(time.perf_counter() - t0, 3)})
        print(f"[replay {label}] matches={replay.matches}", flush=True)

    sweep_tool = REPO_ROOT / "tools" / "census" / "slot_dispatch.py"
    sweep = json.loads(subprocess.run(
        [sys.executable, str(sweep_tool), str(FIRMWARE), "--base", "0x4000", "--offset", "0x1c", "--offset", "0x20",
         "--target", "0xc744", "--target", "0xc7c0", "--target", "0xb658"],
        capture_output=True, text=True, check=True).stdout)
    sweep["tool_sha256"] = _sha(sweep_tool)
    sweep["firmware_sha256"] = _sha(FIRMWARE)

    budget = {}
    for entry in ("0xc7c0", "0xb4b4", "0xb658"):
        doc = json.loads(subprocess.run(
            [str(UNICORN_PYTHON), str(OBSERVE_CALLS_SCRIPT), "--firmware-key", "autopilot868", "--entry", entry,
             "--max-instructions", str(BUDGET_CHECK)], capture_output=True, text=True, check=True).stdout)
        budget[entry] = {"instructions": doc["run"]["instructions_executed"], "stop_reason": doc["run"]["stop_reason"],
                         "entries": doc["observation"]["observed_entries"]}
    print(f"[budget {BUDGET_CHECK}] {budget}", flush=True)

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "observations.json").write_text(json.dumps(observations, indent=1, sort_keys=True))
    (out / "coverage.json").write_text(json.dumps({"rows": rows, "categories": categories}, indent=1, sort_keys=True))
    (out / "summary.json").write_text(json.dumps({
        "run_id": RUN_ID,
        "context_artifacts": ops.context().artifacts,
        "watch": {"sercom_words": WATCH_SERCOM, "object_fields": WATCH_OBJECTS},
        "steps": steps, "replays": replays, "categories": categories,
        "slot_dispatch_sweep": sweep,
        "boot_budget_check": {"max_instructions": BUDGET_CHECK, "basis": "case script budget override, not a ledger operation",
                              "results": budget},
    }, indent=1, sort_keys=True))
    print(f"wrote {out}", flush=True)


if __name__ == "__main__":
    main()
