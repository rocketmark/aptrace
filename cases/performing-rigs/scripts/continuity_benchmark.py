"""
Continuity benchmark: the SERCOM0 follow-up of C9:v1, before and after
ResearchController continuity (agent/src/aptrace_agent/research/history.py).

Question: does FUN_0000b4b4 read or write SERCOM0 registers, or only load
0x40003000 as a value? Source run R-20261013T190420-edcfa7; follow-up
candidate 34aa722266ae1091ee464ad0 (investigation-continuity spike).

Each trial copies the canonical case ledger to a fresh temporary directory,
re-derives the candidate, runs one follow-up investigation with the real
firmware tools, records it in the copy, and measures it. The canonical
ledger is only read. Modes:

  baseline  seed_session without history (the spike's follow-up behaviour)
  improved  seed_session with HistoricalOperations (continuity-v1 policy)

Planners:

  rules     deterministic stand-in that applies the prompt's rule order
            literally: analyze a peripheral the objective names when
            offered, then effects of a function the objective names, then
            the first offered lead
  qwen      the local planner (APTRACE_MODEL via OMLX_BASE_URL)

Usage (from the repository root):

  uv run --project agent python cases/performing-rigs/scripts/continuity_benchmark.py \
      --mode baseline improved --planner rules --repeat 1 --out <dir>
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from aptrace_agent.executor import EvidenceExecutor
from aptrace_agent.investigator import run_autonomous_investigation
from aptrace_agent.ledger.models import SourceRevision
from aptrace_agent.ledger.recorder import RecordingExecutor, record_investigation
from aptrace_agent.ledger.store import ResearchLedger
from aptrace_agent.ledger.verifier import ClaimVerifier
from aptrace_agent.ledger_wiring import DEFAULT_LEDGER_DIR, context_provider, lead_deriver_factory
from aptrace_agent.research import ResearchController
from aptrace_agent.research.followups import generate_followups
from aptrace_agent.research.history import HistoricalOperations


SOURCE_RUN = "R-20261013T190420-edcfa7"
CANDIDATE = "34aa722266ae1091ee464ad0"
TARGET = "FUN_0000b4b4"
# The four direct callers of FUN_0000b4b4 (call sites into it), from the
# source run's function_facts evidence.
DIRECT_CALLERS = {("FUN_0000a064", "0x0000a068"), ("FUN_0000a084", "0x0000a088"), ("FUN_0000a0a8", "0x0000a0ac"), ("FUN_0000b5bc", "0x0000b5c2")}
MAX_STEPS = 8
STRUCTURAL = ("usb_inventory", "common_paths", "function_effects")


class RulesPlanner:
    """Deterministic planner that follows the decision prompt's rules literally."""

    def __init__(self) -> None:
        self.asked: set[tuple[str, str]] = set()
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        tools = {t["function"]["name"]: t for t in kwargs["tools"]}
        prompt = "\n".join(str(m.get("content") or "") for m in kwargs["messages"])
        objective = prompt.split("OBJECTIVE:", 1)[-1].split("\n", 1)[0]

        if list(tools) == ["finish"]:
            return self._call("finish", {"reason": "budget", "claims": ""})

        if "analyze_peripheral" in tools:
            for peripheral in tools["analyze_peripheral"]["function"]["parameters"]["properties"]["peripheral"]["enum"]:
                if peripheral in objective and ("peripheral", peripheral) not in self.asked:
                    self.asked.add(("peripheral", peripheral))
                    return self._call("analyze_peripheral", {"peripheral": peripheral})

        if "analyze_function_effects" in tools:
            for function in re.findall(r"FUN_[0-9a-f]{8}", objective):
                if ("effects", function) not in self.asked:
                    self.asked.add(("effects", function))
                    return self._call("analyze_function_effects", {"function": function})

        if "follow_lead" in tools:
            lead = tools["follow_lead"]["function"]["parameters"]["properties"]["lead_id"]["enum"][0]
            return self._call("follow_lead", {"lead_id": lead})

        return self._call("finish", {"reason": "nothing offered", "claims": ""})

    @staticmethod
    def _call(name, arguments):
        call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=json.dumps(arguments)))
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[call]))], usage=None)


def trial(mode: str, planner: str, canonical: Path) -> dict:
    work = Path(tempfile.mkdtemp(prefix="continuity-bench-"))
    shutil.copytree(canonical, work / "ledger")
    ledger = ResearchLedger(work / "ledger")
    executor = EvidenceExecutor()
    context = context_provider(executor)()
    candidate = generate_followups(ledger, SOURCE_RUN, context=context, deriver_for=lead_deriver_factory(executor)).find(CANDIDATE)

    if candidate is None:
        raise SystemExit(f"candidate {CANDIDATE} does not derive from {canonical}")

    history = HistoricalOperations.for_followup(ledger, context, candidate) if mode == "improved" else None
    recorder = RecordingExecutor(executor)
    controller = None

    if planner == "rules":
        controller = ResearchController(
            planner_client=RulesPlanner(), planner_model="rules", reconciler=object(), max_steps=MAX_STEPS,
            census_peripherals=executor.census.available_peripherals(), structural_tools=STRUCTURAL, claim_contract=True,
        )

    started = datetime.now(timezone.utc).isoformat()
    clock = time.perf_counter()
    error = None

    try:
        run = run_autonomous_investigation(
            candidate.objective, max_steps=MAX_STEPS, executor=recorder, claim_contract=True,
            followup=candidate, history=history, controller=controller,
        )
    except Exception as exc:  # recorded as a trial outcome
        error = f"{type(exc).__name__}: {exc}"[:400]
        run = None

    elapsed = round(time.perf_counter() - clock, 1)

    if run is None:
        return {"mode": mode, "planner": planner, "error": error, "elapsed_s": elapsed}

    recorded = record_investigation(
        ledger, run, context=context, recorder=recorder, model=planner, execution_config={"temperature": 0.0, "max_tokens": 512},
        planner_version="benchmark", budgets={"max_steps": MAX_STEPS}, started_at=started,
        ended_at=datetime.now(timezone.utc).isoformat(), source=SourceRevision(), followup=candidate.provenance(),
    )
    metrics = measure(ledger, recorded, candidate, recorder)
    metrics.update(mode=mode, planner=planner, elapsed_s=elapsed, error=error)
    shutil.rmtree(work, ignore_errors=True)
    return metrics


def measure(ledger: ResearchLedger, run, candidate, recorder: RecordingExecutor) -> dict:
    source = ledger.run(SOURCE_RUN)
    source_ops = {ledger.invocation(i).operation_key for i in source.invocation_ids}
    invocations = [ledger.invocation(i) for i in run.invocation_ids]
    seeded = {json.dumps({"tool": lead.tool, "arguments": lead.arguments}, sort_keys=True) for lead in candidate.seeded_leads}
    done = {json.dumps({"tool": i.tool, "arguments": i.arguments}, sort_keys=True) for i in invocations if i.status == "ok"}
    continuity = run.continuity
    reused = continuity.reused if continuity else []
    reused_ops = {json.dumps({"tool": r.tool, "arguments": r.arguments}, sort_keys=True) for r in reused if r.trigger != "preload"}
    callers = {
        (i.arguments.get("function"), i.arguments.get("address"))
        for i in invocations
        if i.tool == "callsite_context" and i.status == "ok"
    } | {(r.arguments.get("function"), r.arguments.get("address")) for r in reused if r.tool == "callsite_context"}
    errors = [r for r in run.planner_requests if r.get("error") or r.get("decision") is None and r.get("phase") == "decision"]

    provenance = {
        "no_reused_operation_reexecuted": not ({i.operation_key for i in invocations} & {r.operation_key for r in reused}),
        "reused_evidence_not_run_evidence": not (set(run.evidence_ids) & {r.evidence_id for r in reused}),
        "reused_originals_exist": all(ledger.evidence(r.evidence_id).invocation_id and ledger.invocation(r.invocation_id) for r in reused),
        "inputs_are_durable": all(e.startswith("EV-") and ledger.has_evidence(e) for i in invocations for e in i.input_evidence_ids),
    }

    admission = run.claim_admission or []
    prechecks = {}

    for key in run.claim_versions:
        record = ClaimVerifier(ledger, context=context_provider(EvidenceExecutor())(), replay=False).precheck(key).record
        prechecks[key] = {"outcome": record.outcome.value, "failed": [c.name for c in record.checks if not c.passed]}

    claim_quality = {
        "proposals": len(admission),
        "admitted": sum(r.decision == "admitted" for r in admission),
        "rejected": sum(r.decision == "rejected" for r in admission),
        "unparseable": sum(r.decision == "unparseable" for r in admission),
        "correction_rounds": max((r.round for r in admission), default=0) - (1 if admission else 0),
        "reject_codes": sorted(d.code for r in admission for d in r.diagnostics if d.severity == "reject"),
        "note_codes": sorted(d.code for r in admission for d in r.diagnostics if d.severity == "note"),
        "records": [{"round": r.round, "decision": r.decision, "raw": r.raw, "claim_version": r.claim_version} for r in admission],
        "prechecks": prechecks,
    }

    return {
        "claim_quality": claim_quality,
        "run_id": run.run_id,
        "stop": run.termination_reason,
        "steps": len(run.trajectory),
        "steps_charged": continuity.budget["steps_charged"] if continuity else len([s for s in run.trajectory if s["action"] != "finish"]),
        "planner_requests": len(run.planner_requests),
        "max_prompt_chars": max((r.get("prompt_chars") or 0 for r in run.planner_requests), default=0),
        "max_prompt_tokens": max((r.get("prompt_tokens") or 0 for r in run.planner_requests), default=0),
        "rejected_requests": len(errors),
        "planner_runtime_errors": len([r for r in run.planner_requests if r.get("error")]),
        "tool_executions": len(recorder.traces) + len(recorder.failures),
        "tool_failures": len(recorder.failures),
        "seeded_leads": len(seeded),
        "seeded_attempted": len((done | reused_ops) & seeded),
        "seeded_completed": len((done | reused_ops) & seeded),
        "redundant_executions": sum(i.operation_key in source_ops for i in invocations),
        "redundant_operations": sorted({f"{i.tool}({json.dumps(i.arguments, sort_keys=True)})" for i in invocations if i.operation_key in source_ops}),
        "reused_preload": sum(r.trigger == "preload" for r in reused),
        "reused_on_request": sum(r.trigger != "preload" for r in reused),
        "reuse_refusals": [f"{r.tool}: {r.reason}" for r in (continuity.refused if continuity else [])],
        "new_operations": sum(i.operation_key not in source_ops for i in invocations if i.status == "ok"),
        "new_evidence": len([e for e in run.evidence_ids if e not in source.evidence_ids]),
        "direct_callers_inspected": len(callers & DIRECT_CALLERS),
        "claims_proposed": [
            {"key": key, "assertion": ledger.claim(key).assertion, "grade": ledger.claim(key).proposed_grade.value,
             "evidence": ledger.claim(key).supporting_evidence_ids, "state": ledger.state(key).value}
            for key in run.claim_versions
        ],
        "seeded_outcomes": [o.outcome for o in continuity.seeded_leads] if continuity else None,
        "fallbacks": continuity.budget["fallbacks"] if continuity else 0,
        "trajectory": [f"{s['action']}{'(reused)' if s.get('reused_from') else ''}" for s in run.trajectory],
        "provenance": provenance,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", nargs="+", default=["baseline", "improved"], choices=["baseline", "improved"])
    parser.add_argument("--planner", default="rules", choices=["rules", "qwen"])
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--ledger", default=str(DEFAULT_LEDGER_DIR), help="Ledger to copy (read only)")
    parser.add_argument("--out", required=True, help="Directory for per-trial JSON")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # Alternate modes so drift in the local runtime affects both equally.
    for n in range(1, args.repeat + 1):
        for mode in args.mode:
            result = trial(mode, args.planner, Path(args.ledger))
            result["repeat"] = n
            path = out / f"{args.planner}-{mode}-{n}.json"
            path.write_text(json.dumps(result, indent=2) + "\n")
            summary = {k: result.get(k) for k in ("stop", "steps_charged", "tool_executions", "redundant_executions", "seeded_attempted", "direct_callers_inspected", "new_evidence", "fallbacks")}
            quality = result.get("claim_quality") or {}
            summary.update({k: quality.get(k) for k in ("proposals", "admitted", "rejected", "unparseable", "correction_rounds", "reject_codes")})
            print(f"{args.planner} {mode} #{n}: {json.dumps(summary)}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
