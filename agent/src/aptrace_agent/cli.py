from __future__ import annotations

import argparse
import json
import os

from datetime import datetime, timezone
from pathlib import Path

from aptrace_agent.ledger_cli import (
    add_ledger_commands,
    handle_ledger_command,
    record_research_run,
)
from aptrace_agent.work_cli import (
    add_followup_command,
    add_research_work_options,
    add_work_commands,
    handle_followups_command,
    handle_work_command,
)
from aptrace_agent.research.projection import conclusion
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
        "planner_requests": list(
            run.result.planner_requests
        ),
        "conclusion": conclusion(
            run.state
        ),
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

    answer = conclusion(
        run.state
    )

    for heading, key in (
        ("PROVEN", "proven"),
        ("PROBABLE / HYPOTHESIS", "probable"),
        ("OPEN / UNRESOLVED", "open"),
    ):
        print()
        print(heading)

        if not answer[key]:
            print("  (none)")

        for line in answer[key]:
            print(f"  {line}")

    remaining = (
        run.state.open_leads()
    )

    print()
    print("REMAINING OPEN LEADS")

    if not remaining:
        print("  (none)")
    elif len(remaining) > 10:
        print(f"  ({len(remaining)} total; first 10 shown)")

    for lead in remaining[:10]:
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
        dest="seed_function",
        help=(
            "Optional expert seed function, for example "
            "FUN_0000d3dc. If omitted, APTrace performs "
            "bounded objective-driven discovery."
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
        "--ledger",
        action="store_true",
        help=(
            "Record the run, its invocations, evidence and the "
            "planner's structured claim proposals in the research "
            "ledger (enables the finish claim contract)"
        ),
    )

    research.add_argument(
        "--ledger-dir",
        help="Research ledger directory (default: the case ledger)",
    )

    research.add_argument(
        "objective",
        nargs="*",
        help=(
            "Research objective (required unless "
            "--work-item supplies it)"
        ),
    )

    add_research_work_options(research)
    add_ledger_commands(subparsers)
    add_work_commands(subparsers)
    add_followup_command(subparsers)

    args = parser.parse_args()

    if handle_ledger_command(args):
        return

    if handle_work_command(args):
        return

    if handle_followups_command(args):
        return

    if args.command == "research":
        objective = " ".join(
            args.objective
        )

        if args.work_item and not args.ledger:
            parser.error("--work-item requires --ledger")
        if not args.work_item and (args.restart or args.rerun):
            parser.error("--restart and --rerun require --work-item")
        if not args.work_item and not objective:
            parser.error("a research objective is required")

        recorder = None

        if args.ledger:
            from aptrace_agent.executor import EvidenceExecutor
            from aptrace_agent.ledger.recorder import RecordingExecutor

            recorder = RecordingExecutor(EvidenceExecutor())

        completed: dict = {}
        followup = None
        history = None

        if args.work_item:
            from aptrace_agent.ledger_wiring import context_provider
            from aptrace_agent.work_cli import followup_for_work_item

            followup = followup_for_work_item(args, executor=recorder.inner, context=context_provider(recorder.inner)())

            if followup is not None:
                from aptrace_agent.ledger.store import ResearchLedger
                from aptrace_agent.ledger_wiring import ledger_dir
                from aptrace_agent.research.history import HistoricalOperations

                history = HistoricalOperations.for_followup(
                    ResearchLedger(ledger_dir(args.ledger_dir)), context_provider(recorder.inner)(), followup
                )

        def investigate(
            objective: str,
            work_item_id: str | None = None,
        ) -> str | None:
            started_at = datetime.now(timezone.utc).isoformat()
            run = (
                run_autonomous_investigation(
                    objective,
                    seed_function=(
                        args.seed_function
                    ),
                    max_steps=args.max_steps,
                    **(
                        {"executor": recorder, "claim_contract": True}
                        if recorder is not None
                        else {}
                    ),
                    **({"followup": followup, "history": history} if followup is not None else {}),
                )
            )

            payload = _research_payload(
                run
            )
            completed.update(run=run, payload=payload)

            if recorder is None:
                return None

            from aptrace_agent.research import ResearchController

            payload["proposed_claims"] = list(run.result.proposed_claims)
            payload["ledger_run_id"] = record_research_run(
                run,
                executor=recorder.inner,
                recorder=recorder,
                ledger_dir_override=args.ledger_dir,
                started_at=started_at,
                ended_at=datetime.now(timezone.utc).isoformat(),
                max_steps=args.max_steps,
                controller_cls=ResearchController,
                work_item_id=work_item_id,
                **({"followup": followup.provenance()} if followup is not None else {}),
            )
            return payload["ledger_run_id"]

        work = work_error = None

        if args.work_item:
            from aptrace_agent.ledger_wiring import context_provider
            from aptrace_agent.work_cli import research_work_item

            work, work_error = research_work_item(
                args,
                objective,
                context_provider(recorder.inner)(),
                investigate,
            )
        else:
            investigate(objective)

        run = completed["run"]
        payload = completed["payload"]

        if work is not None:
            payload["work_item"] = work

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
        else:
            _print_research_summary(
                run
            )

            if work is not None:
                from aptrace_agent.work_cli import print_work_summary

                print_work_summary(work)

            if output_path is not None:
                print()
                print(
                    f"Artifact: {output_path}"
                )

        if work_error:
            raise SystemExit(work_error)

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
