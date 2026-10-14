#!/usr/bin/env python3
"""Summarize live planner trials for call-relation admission, and replay
each recorded claim proposal through an admission implementation.

Reads a SCRATCH trial ledger written by indirect_dispatch_planner_trials.py
(never the canonical one) and the runs it names. Per run: the proposals of
both admission rounds with their recorded decisions and diagnostics, whether
they assert call relations, whether they cite indirect_call_target evidence,
and planner requests and prompt tokens by phase. Each proposal is then
re-admitted, against the evidence it cites, by the agent source tree given
with --agent-src: the baseline checkout shows what the earlier admission
would have done with the same proposals. Run with the agent venv:

    agent/.venv/bin/python -I cases/performing-rigs/scripts/call_admission_benchmark.py \\
        --ledger-dir SCRATCH --trials TRIALS.json [--agent-src DIR --label NAME] [--out FILE]
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE = HERE.parent
REPO_ROOT = CASE.parents[1]
CANONICAL_LEDGER = CASE / "research" / "ledger"


def replay(ledger, run, record, admit, session_cls, registry_cls, follower_cls, observation_cls, controller_cls):
    """Re-admit one recorded proposal against the run's session evidence (E1..En in run order)."""
    proposals, unparseable = controller_cls._parse_claims([record.raw])
    if unparseable or not proposals:
        return {"decision": "unparseable", "codes": []}
    aliases = {f"E{n}": durable for n, durable in enumerate(run.evidence_ids, 1)}
    # The recorded citation map must agree with the run's evidence order.
    assert all(aliases.get(a) == d for a, d in zip(record.evidence_ids, record.durable_evidence_ids)), record.raw
    registry = registry_cls()
    session = session_cls(objective="replay", registry=registry, follower=follower_cls(registry=registry, executor=None))
    for alias, durable in aliases.items():
        artifact = ledger.evidence(durable)
        result, _ok = ledger.load_blob(artifact.result_sha256)
        session.record(observation_cls(id=alias, tool=artifact.tool, arguments=artifact.arguments, result=result))
    replayed = admit(proposals[0], session, round=record.round, function_exists=None)
    return {"decision": replayed.decision, "codes": sorted({d.code for d in replayed.diagnostics if d.severity == "reject"})}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ledger-dir", type=Path, required=True)
    p.add_argument("--trials", type=Path, required=True, help="planner trials JSON naming the live runs")
    p.add_argument("--agent-src", type=Path, default=REPO_ROOT / "agent" / "src", help="admission implementation to replay with")
    p.add_argument("--label", default="working tree", help="how the replayed implementation is recorded, e.g. 'baseline 3c74b5a'")
    p.add_argument("--out", type=Path)
    args = p.parse_args(argv)
    if args.ledger_dir.resolve() == CANONICAL_LEDGER.resolve():
        raise SystemExit("refusing to read the canonical ledger as a trial ledger")

    sys.path.insert(0, str(args.agent_src.resolve()))
    from aptrace_agent.ledger.store import ResearchLedger
    from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchController, ResearchSession
    from aptrace_agent.research.admission import admit
    from aptrace_agent.schemas import EvidenceObservation

    ledger = ResearchLedger(args.ledger_dir)
    trials = json.loads(args.trials.read_text())
    out = {"replayed_with": args.label, "trials": []}
    for trial in trials.get("live", []):
        if "ledger_run_id" not in trial:
            out["trials"].append({"trial": trial.get("trial"), "error": trial.get("error")})
            continue
        run = ledger.run(trial["ledger_run_id"])
        requests = {}
        for request in run.planner_requests:
            phase = requests.setdefault(request["phase"], {"requests": 0, "prompt_tokens": 0})
            phase["requests"] += 1
            phase["prompt_tokens"] += int(request.get("prompt_tokens") or 0)
        proposals = []
        for record in run.claim_admission:
            tools = sorted({ledger.evidence(d).tool for d in record.durable_evidence_ids})
            row = {
                "round": record.round, "raw": record.raw, "recorded_decision": record.decision,
                "recorded_codes": sorted({d.code for d in record.diagnostics if d.severity == "reject"}),
                "recorded_notes": sorted({d.code for d in record.diagnostics if d.severity == "note"}),
                "call_details": [f"{d.code}: {d.detail}" for d in record.diagnostics if d.code.startswith("CALL_")],
                "cited_tools": tools, "cites_indirect_call_target": "indirect_call_target" in tools,
                "claim_version": record.claim_version,
            }
            # Recorded by the hardened admission: a classified call assertion carries CALL_* codes.
            row["call_assertion"] = any(d.code.startswith("CALL_") and d.code != "CALL_RELATION_UNCHECKED" for d in record.diagnostics)
            if record.decision != "unparseable":
                row["replayed"] = replay(ledger, run, record, admit, ResearchSession, LeadRegistry, LeadFollower, EvidenceObservation, ResearchController)
            proposals.append(row)
        actions = [getattr(step, "action", None) or (step.get("action") if isinstance(step, dict) else None) for step in run.trajectory or []]
        out["trials"].append({
            "trial": trial["trial"], "run_id": run.run_id, "stop_reason": run.termination_reason, "steps": actions,
            "resolve_indirect_call_selected": "indirect_target" in actions,
            "requests_by_phase": requests, "proposals": proposals,
        })
    text = json.dumps(out, indent=1, sort_keys=True, default=str) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)
    print(text[:4000])


if __name__ == "__main__":
    sys.exit(main())
