from __future__ import annotations

import argparse
import json
import os

from datetime import datetime, timezone
from pathlib import Path

from aptrace_agent.investigator import (
    AutonomousInvestigationRun,
    run_autonomous_investigation,
    run_investigation,
)


def _research_payload(
    run: AutonomousInvestigationRun,
) -> dict:
    return {
        "schema_version": 1,
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "models": {
            "planner": os.environ.get(
                "APTRACE_MODEL"
            ),
            "reconciler": os.environ.get(
                "APTRACE_REVIEW_MODEL",
                "gemma-4-26b-a4b-it-4bit",
            ),
        },
        "objective": run.objective,
        "seed_function": run.seed_function,
        "stop_reason": (
            run.result.stop_reason
        ),
        "reconciled": (
            run.result.reconciled
        ),
        "trajectory": [
            {
                "number": step.number,
                "action": step.action,
                "lead_id": step.lead_id,
                "evidence_id": (
                    step.evidence_id
                ),
                "reason": step.reason,
            }
            for step in run.result.steps
        ],
        "evidence": [
            observation.model_dump()
            for observation in run.evidence
        ],
        "state": run.state.model_dump(),
    }


def _print_research_summary(
    run: AutonomousInvestigationRun,
) -> None:
    print()
    print("Research complete")
    print(
        f"  stop: {run.result.stop_reason}"
    )
    print(
        f"  reconciled: "
        f"{run.result.reconciled}"
    )
    print(
        f"  evidence: {len(run.evidence)}"
    )
    print(
        f"  steps: {len(run.result.steps)}"
    )

    proven = [
        claim
        for claim in run.state.claims
        if claim.grade.value == "PROVEN"
    ]

    supported = [
        claim
        for claim in run.state.claims
        if claim.grade.value == "SUPPORTED"
    ]

    open_questions = [
        question
        for question
        in run.state.open_questions
        if question.status.value == "OPEN"
    ]

    print()
    print("PROVEN")

    if not proven:
        print("  (none)")

    for claim in proven:
        print(
            f"  {claim.id}: "
            f"{claim.statement}"
        )
        print(
            "    evidence: "
            + ",".join(
                claim.evidence_ids
            )
        )

    print()
    print("SUPPORTED")

    if not supported:
        print("  (none)")

    for claim in supported:
        print(
            f"  {claim.id}: "
            f"{claim.statement}"
        )
        print(
            "    evidence: "
            + ",".join(
                claim.evidence_ids
            )
        )

    print()
    print("OPEN QUESTIONS")

    if not open_questions:
        print("  (none)")

    for question in open_questions:
        print(
            f"  {question.id}: "
            f"{question.question}"
        )
        print(
            "    evidence: "
            + ",".join(
                question.evidence_ids
            )
        )

    remaining = (
        run.state.open_leads()
    )

    print()
    print("REMAINING OPEN LEADS")

    if not remaining:
        print("  (none)")

    for lead in remaining:
        print(
            f"  {lead.id}: "
            f"[{lead.kind}] "
            f"{lead.description}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aptrace-agent",
        description=(
            "Evidence-driven APTrace "
            "firmware investigator"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    investigate = subparsers.add_parser(
        "investigate",
        help=(
            "Run one deterministic bounded "
            "firmware query"
        ),
    )

    investigate.add_argument(
        "question",
        nargs="+",
        help="Firmware-analysis question",
    )

    investigate.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help=(
            "Show routing, evidence execution, "
            "and usage"
        ),
    )

    investigate.add_argument(
        "--json",
        action="store_true",
        help="Emit the complete run as JSON",
    )

    research = subparsers.add_parser(
        "research",
        help=(
            "Run one autonomous bounded "
            "firmware investigation"
        ),
    )

    research.add_argument(
        "--function",
        required=True,
        dest="seed_function",
        help=(
            "Seed function, for example "
            "FUN_0000d3dc"
        ),
    )

    research.add_argument(
        "--max-steps",
        type=int,
        default=12,
        help=(
            "Maximum model-directed research "
            "steps (default: 12)"
        ),
    )

    research.add_argument(
        "--json",
        action="store_true",
        help=(
            "Emit the complete research run "
            "as JSON"
        ),
    )

    research.add_argument(
        "--output",
        help=(
            "Write the complete research run "
            "JSON artifact to this path"
        ),
    )

    research.add_argument(
        "objective",
        nargs="+",
        help="Research objective",
    )

    args = parser.parse_args()

    if args.command == "research":
        objective = " ".join(
            args.objective
        )

        run = (
            run_autonomous_investigation(
                objective,
                seed_function=(
                    args.seed_function
                ),
                max_steps=args.max_steps,
            )
        )

        payload = _research_payload(
            run
        )

        output_path = None

        if args.output:
            output_path = Path(
                args.output
            ).expanduser()

            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            output_path.write_text(
                json.dumps(
                    payload,
                    indent=2,
                )
                + "\n"
            )

        if args.json:
            print(
                json.dumps(
                    payload,
                    indent=2,
                )
            )
            return

        _print_research_summary(
            run
        )

        if output_path is not None:
            print()
            print(
                f"Artifact: {output_path}"
            )

        return

    if args.command != "investigate":
        raise SystemExit(2)

    question = " ".join(
        args.question
    )

    try:
        run = run_investigation(
            question,
            verbose=(
                args.verbose
                and not args.json
            ),
        )
    except ValueError as exc:
        raise SystemExit(
            f"aptrace-agent: {exc}"
        ) from exc

    if args.json:
        payload = {
            "question": run.question,
            "routing": run.routing,
            "plan": run.plan.model_dump(),
            "evidence": (
                run.evidence.model_dump()
            ),
            "answer": run.answer,
            "usage": {
                "synthesis": repr(
                    run.synthesis_usage
                ),
            },
        }

        print(
            json.dumps(
                payload,
                indent=2,
            )
        )
        return

    print()
    print(run.answer)

    if args.verbose:
        print()
        print("Plan:")
        print(
            run.plan.model_dump_json(
                indent=2
            )
        )

        print()
        print("Evidence:")
        print(
            run.evidence.model_dump_json(
                indent=2
            )
        )

        print()
        print("Routing:")
        print(
            f"  {run.routing}"
        )

        print()
        print("Usage:")
        print(
            f"  synthesis: "
            f"{run.synthesis_usage}"
        )


if __name__ == "__main__":
    main()
