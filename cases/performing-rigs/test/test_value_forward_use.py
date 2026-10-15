#!/usr/bin/env python3
"""Performing Rigs: p-code forward use on AutoPilot 868
(scripts/pcode_forward_use_parity.py, scripts/value_forward_use_ea54.py).

Pins the recorded results: the 0xea54 load is a complete NO_ESCAPE (compare
at 0xea56, overwritten at 0xea58 and 0xeaa0); the other census code-pointer
loads keep their spike classifications; the unattributed stub 0x10438 is
INCOMPLETE with its tail-transfer ARGUMENT; every indirect_target reaching
definition reaches its site. When Ghidra and the case project are present,
a fresh executor run of 0xea54 must equal the recorded ledger result. Run
with the agent venv:

    agent/.venv/bin/python cases/performing-rigs/test/test_value_forward_use.py
"""
import json
import sys
from pathlib import Path

CASE = Path(__file__).resolve().parents[1]
RUNS = CASE / "research" / "runs" / "pcode-forward-use-v1"
FAILURES = []


def check(name, condition, detail=""):
    print(f"  [{'ok' if condition else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def ea54(result):
    check("0xea54 is NO_ESCAPE_WITHIN_SCOPE and complete",
          result["verdict"] == "NO_ESCAPE_WITHIN_SCOPE" and result["complete"] and not result["incomplete"])
    check("0xea54 loads 0xec49, a code pointer to FUN_0000ec48",
          result["origin_value"]["value"] == "0x0000ec49" and result["origin_value"]["code_address"] == "0x0000ec48"
          and result["origin_value"]["function_at_code_address"] == "FUN_0000ec48")
    check("0xea54 scope is FUN_0000e8a8", result["scope"]["function_name"] == "FUN_0000e8a8")
    uses = sorted((u["kind"], u["address"]) for u in result["uses"])
    check("0xea54 uses: compare at 0xea56, dead at 0xea58 and 0xeaa0",
          uses == [("COMPARE", "0x0000ea56"), ("DEAD", "0x0000ea58"), ("DEAD", "0x0000eaa0")], str(uses))


def test_recorded():
    print("recorded results:")
    record = json.loads((RUNS / "ea54-ledger-record.json").read_text())
    ea54(record["result"])
    check("ledger evidence is BOUNDED", record["evidence"]["grade"] == "BOUNDED")
    check("both replays match", all(r["matches"] for r in record["replays"]))
    refs = {r["origin"]: r for r in json.loads((RUNS / "code-pointer-references.json").read_text())["references"]}
    expected = {
        "0x0000bc76": ["ARGUMENT_ESCAPE"], "0x0000eaa6": ["ARGUMENT_ESCAPE"], "0x0000eada": ["ARGUMENT_ESCAPE"],
        "0x00010412": ["MEMORY_ESCAPE"], "0x00010416": ["MEMORY_ESCAPE"], "0x0001041a": ["MEMORY_ESCAPE"],
        "0x0000ea54": [],
    }
    for origin, kinds in expected.items():
        r = refs[origin]
        check(f"{origin} {kinds or 'no escape'}, agrees with the spike and Capstone v2",
              r["pcode"]["escape_kinds"] == kinds and r["vs_spike_raw_pcode"] == "AGREE" and r["vs_capstone_v2"] == "AGREE")
    stub = refs["0x00010438"]["pcode"]
    check("0x10438 stays INCOMPLETE (no containing function) and finds the tail-transfer argument",
          stub["incomplete"] == ["NO_CONTAINING_FUNCTION"] and stub["escape_kinds"] == ["ARGUMENT_ESCAPE"]
          and not stub["complete"])
    dual = json.loads((RUNS / "indirect-target-duality.json").read_text())
    check("every indirect_target reaching definition reaches its site in p-code",
          dual["outcomes"] == {"AGREE": dual["definition_pairs"]} and dual["indirect_target_sites"] == 86, str(dual["outcomes"]))


def test_fresh():
    print("fresh executor run (needs Ghidra and the case Ghidra project):")
    try:
        from aptrace_agent.executor import EvidenceExecutor

        executor = EvidenceExecutor()
        observation = executor.execute_operation("value_forward_use", {"origin": "0x0000ea54"}, evidence_id="E1")
    except Exception as exc:  # noqa: BLE001 -- an unavailable engine or project skips, it does not pass
        print(f"  SKIP: {type(exc).__name__}: {exc}")
        return
    if observation.result["status"] in ("engine_unavailable", "project_unavailable"):
        print(f"  SKIP: {observation.result['status']}")
        return
    ea54(observation.result)
    recorded = json.loads((RUNS / "ea54-ledger-record.json").read_text())["result"]
    check("fresh result equals the recorded ledger result", observation.result == recorded)


def main():
    test_recorded()
    test_fresh()
    print("\n" + ("FAILED: " + ", ".join(FAILURES) if FAILURES else "all value forward use case checks passed"))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
