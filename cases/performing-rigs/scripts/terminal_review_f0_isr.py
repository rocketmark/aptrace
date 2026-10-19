"""
Terminal Review v1 test package: the separately observed F0 motion-state
segment and the TC0 ISR STEP segment (acceptance test 5).

This is a review *fixture*, not an APTrace research run. It turns two
operator concrete artifacts named in the remote-to-motor causal graph into
the framework's terminal-assessment format:

- ``rx_state``: research/runs/remote-to-motor/f0-through-motor-state.json
  (RX entry 0x8a35, seeded F0 record, reaches FUN_00004d18 at instruction 71,
  2,537 instructions, motion target 5,000,000, busy gate 0x20001b14 still 0);
- ``isr``: research/runs/replacement-firmware-readiness/ch0-isr-positive.json
  (a direct AAPCS call of the TC0 handler 0x607c, 108 instructions, PB10
  OUTSET then OUTCLR, position 0 -> 1).

The two executions start from fresh, independently seeded states. Nothing
in either artifact connects them. The relations between them (busy gate,
rate machinery, TC0 IRQ delivery) carry only the causal graph's static or
unresolved evidence. Each source is checked against the SHA-256 the causal
graph records for it; a changed source is an error, never re-read silently.

Relation levels here are assigned by the fixture from the causal graph's
evidence modes (continuous concrete -> OBSERVED, static structural ->
STATIC). They are not APTrace tracker output and are not admitted evidence.

Prepare it for live review:

    agent/.venv/bin/python cases/performing-rigs/scripts/terminal_review_f0_isr.py --review-dir DIR
    agent/.venv/bin/aptrace-agent terminal-review retry TR-... --review-dir DIR
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from aptrace_agent.research.objective import ObjectiveSpec
from aptrace_agent.research.terminal import build_assessment
from aptrace_agent.schemas import EvidenceObservation

CASE = Path(__file__).resolve().parents[1]
ROOT = CASE.parents[1]
GRAPH = CASE / "research" / "generated" / "remote-to-motor-causal-graph.json"
ENGINE = "Unicorn concrete execution (tools/unicorn/concrete.py), operator-run"

QUESTION = (
    "Does the selected Manual Mode F0 jog command (channel 0, value 5000000) cause autopilot868 to drive the "
    "channel-0 STEP output? Keep separately executed segments, static paths and unknown scheduling distinct; "
    "do not infer end-to-end execution."
)

RELATIONS = [
    {"id": "R2", "source": "FUN_00005448", "target": "FUN_00004d18", "label": "jog handler reaches the motion target update"},
    {"id": "R3", "source": "FUN_00005448", "target": "0x20001b14", "label": "jog path writes the busy gate"},
    {"id": "R7", "source": "FUN_00004d18", "target": "FUN_00005ee8", "label": "motion state activates the rate machinery"},
    {"id": "R4", "source": "FUN_00005ee8", "target": "FUN_00005c00", "label": "rate machinery reaches timer period setup"},
    {"id": "R6", "source": "FUN_00005c00", "target": "FUN_0000607c", "label": "timer period setup leads to TC0 IRQ delivery"},
    {"id": "R5", "source": "FUN_0000607c", "target": "FUN_00005898", "label": "TC0 handler drives the STEP GPIO helper"},
]


def _source(graph: dict, key: str) -> tuple[dict, dict]:
    entry = graph["sources"][key]
    path = ROOT / entry["path"]
    actual = hashlib.sha256(path.read_bytes()).hexdigest()

    if actual != entry["sha256"]:
        raise ValueError(f"{entry['path']} changed: {actual} != causal graph {entry['sha256']}")

    return json.loads(path.read_text()), {"path": entry["path"], "sha256": actual, "mode": entry["mode"]}


def _edge(graph: dict, edge_id: str) -> dict:
    return next(e for e in graph["edges"] if e["id"] == edge_id)


def _seeds(run: dict) -> list[str]:
    return [f"seeded {s['len']} byte(s) at {s['addr']} (value is a harness input)" for s in run.get("applied_seeds", [])]


def _concrete(evidence_id: str, run: dict, source: dict, *, label: str, conditions: list[str], summary: str) -> EvidenceObservation:
    assumptions = [f"fresh machine state at entry {run['entry']}"] + _seeds(run) + conditions
    return EvidenceObservation(
        id=evidence_id,
        tool="concrete_segment",
        arguments={"artifact": source["path"], "entry": run["entry"]},
        result={
            "status": "ok" if run.get("completed") and run.get("error_free") else "failed: incomplete",
            "scenario": label,
            "harness_assumptions": [{"detail": a} for a in assumptions],
            "coverage": f"one concrete execution of {run['instructions_executed']} instructions from {run['entry']}, "
                        f"{run['stop_reason']}; MMIO is plain memory, no peripheral or interrupt model",
            "run": {"instructions_executed": run["instructions_executed"]},
            # Execution state in the registered-scenario result shape (one fresh leg and its seeds),
            # plus the artifact's final-memory snapshot. The artifacts log no RAM writes, so nothing
            # here is recorded as produced by execution.
            "legs": [{"leg": 0, "entry": run["entry"], "fresh": True, "seeds": list(run.get("applied_seeds", [])),
                      "reg_seed": [], "forced": {}, "stub_calls": []}],
            "final_memory": dict(run.get("memory", {})),
            "provenance": {"analysis": "operator_concrete_artifact", "engine": ENGINE, "artifact": source,
                           "firmware_sha256": None},
            "planner_summary": summary,
        },
    )


def f0_isr_assessment() -> dict:
    graph = json.loads(GRAPH.read_text())
    rx, rx_source = _source(graph, "rx_state")
    isr, isr_source = _source(graph, "isr")
    e09, e14, e10 = _edge(graph, "E09"), _edge(graph, "E14"), _edge(graph, "E10")
    e11, e12, e13 = _edge(graph, "E11"), _edge(graph, "E12"), _edge(graph, "E13")
    hits = {h["address"]: h["instruction"] for h in rx.get("watch_hits", [])}
    gpio = [m for m in isr.get("mmio_log", []) if m["direction"] == "write" and m["address"] in ("0x41008098", "0x41008094")]

    observations = [
        _concrete(
            "E1", rx, rx_source, label="rx-f0-direct-seed", conditions=list(e09["conditions"]),
            summary=(f"RX entry {rx['entry']} with the seeded F0 record reaches FUN_00005448 at instruction "
                     f"{hits.get('0x00005448')} and FUN_00004d18 at instruction {hits.get('0x00004d18')}; returns to "
                     f"{rx['requested_stop_at'][0]} after {rx['instructions_executed']} instructions. Final memory "
                     f"0x200024cc={rx['memory']['0x200024cc']} (target 5000000 LE), 0x20002524={rx['memory']['0x20002524']}, "
                     f"busy gate 0x20001b14={rx['memory']['0x20001b14']}; MMIO log {len(rx['mmio_log'])} entries. "
                     f"{e10['statement']}"),
        ),
        _concrete(
            "E2", isr, isr_source, label="tc0-isr-direct-call", conditions=list(e13["conditions"]) + list(e14["conditions"]),
            summary=(f"Direct call of the TC0 handler {isr['call']['function']} (not IRQ delivery) for "
                     f"{isr['instructions_executed']} instructions: GPIO writes "
                     + ", ".join(f"{m['address']}={m['value']}" for m in gpio)
                     + f" (PB10 OUTSET then OUTCLR); final 0x20002064={isr['memory']['0x20002064']} (position 0 -> 1)."),
        ),
        EvidenceObservation(
            id="E3", tool="function_facts", arguments={"function": "FUN_00005ee8"},
            result={"name": "FUN_00005ee8", "callers": [], "callees": [{"function": "FUN_00005c00", "address": "0x0"}],
                    "planner_summary": f"FUN_00005ee8 static call to FUN_00005c00 (Ghidra; {e12['statement']})"},
        ),
    ]
    blocker = lambda eid, detail: {"evidence_id": eid, "detail": detail}
    level = {"R2": "OBSERVED", "R3": "UNRESOLVED", "R7": "UNRESOLVED", "R4": "STATIC", "R6": "UNRESOLVED", "R5": "OBSERVED"}
    evidence = {
        "R2": [{"evidence_id": "E1", "level": "OBSERVED",
                "detail": "FUN_00005448 reaches FUN_00004d18 in the seeded RX execution (harness assumptions apply)"}],
        "R4": [{"evidence_id": "E3", "level": "STATIC", "detail": "static call edge FUN_00005ee8 -> FUN_00005c00 (Ghidra)"}],
        "R5": [{"evidence_id": "E2", "level": "OBSERVED",
                "detail": "direct handler call reaches FUN_00005898 and writes PB10 set then clear (harness assumptions apply)"}],
    }
    blockers = {
        "R3": [blocker("E1", "busy gate 0x20001b14 is still 0 at the RX segment exit; scoped to that segment, not absence of a writer")],
        "R7": [blocker("E1", e11["statement"])],
        "R6": [blocker("E2", e13["statement"])],
    }
    missing = {
        "R3": ["no completed function_effects of FUN_00005448 showing an access to 0x20001b14 (the effects analysis timed out)"],
        "R7": [f"no evidence relates FUN_00004d18 to FUN_00005ee8: {'; '.join(e11['unresolved'])}"],
        "R4": ["no concrete observation of FUN_00005ee8 calling FUN_00005c00 under the selected command"],
        "R6": [f"no timer expiry or IRQ delivery model: {'; '.join(e13['unresolved'])} (capability gap)"],
        "R5": [],
        "R2": [],
    }
    report = {
        "relations": [dict(r, level=level[r["id"]], evidence=evidence.get(r["id"], []), blockers=blockers.get(r["id"], []),
                           missing=missing[r["id"]]) for r in RELATIONS],
        "unresolved_relations": [r["id"] for r in RELATIONS if level[r["id"]] != "OBSERVED"],
        "explanation": "review fixture assembled from operator concrete artifacts; not an APTrace research run",
        "composition": "not attempted: per-edge levels are not an end-to-end causal result",
        "budget": {},
        "outcomes": [],
        "rejections": [],
    }
    spec = ObjectiveSpec.model_validate({
        "question": QUESTION, "firmware": "autopilot868", "relations": RELATIONS,
        "constraints": ["Keep static paths, concrete segments, symbolic evidence, unknown scheduling and physical effects distinct.",
                        "Do not infer full end-to-end execution."],
    })
    return build_assessment(spec=spec, report=report, observations=observations, stop_reason="review_fixture",
                            firmware_key="autopilot868")


LINKS = {"fixture": "cases/performing-rigs/scripts/terminal_review_f0_isr.py", "causal_graph": str(GRAPH.relative_to(ROOT)),
         "ledger_run_id": None, "artifact": None}


def main() -> None:
    from aptrace_agent.research.review import TerminalReviewer, TerminalReviewStore

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--review-dir", required=True)
    args = parser.parse_args()
    store = TerminalReviewStore(args.review_dir)
    print(TerminalReviewer(store, client=object()).prepare(f0_isr_assessment(), LINKS))


if __name__ == "__main__":
    main()
