from __future__ import annotations

import argparse
import json
import os
import sys

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
from aptrace_agent.research.candidates import DEFAULT_LIMIT as DEFAULT_CANDIDATE_LIMIT
from aptrace_agent.research.controller import EXPERIMENTAL_STRUCTURAL_TOOLS
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
    } | (
        {
            "objective_spec": run.objective_spec.model_dump(),
            "objective_report": run.result.objective_report,
            "terminal_assessment": getattr(run.result, "terminal_assessment", None),
        }
        if getattr(run, "objective_spec", None) is not None
        else {}
    )


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

    report = getattr(run.result, "objective_report", None)

    if report:
        from aptrace_agent.research.objective import render_report

        print()
        print("OBJECTIVE RELATIONS")

        for line in render_report(report):
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


def _review_store(args: argparse.Namespace, output_path: Path | None):
    """Where terminal reviews persist: --review-dir, else the ledger's, else beside --output."""

    from aptrace_agent.research.review import TerminalReviewStore

    if getattr(args, "review_dir", None):
        return TerminalReviewStore(args.review_dir)

    if getattr(args, "ledger", False) or args.command == "terminal-review":
        from aptrace_agent.ledger_wiring import ledger_dir

        return TerminalReviewStore(ledger_dir(getattr(args, "ledger_dir", None)) / "terminal-reviews")

    if output_path is not None:
        return TerminalReviewStore(output_path.with_name(output_path.name + ".terminal-review"))

    return None


def _residency():
    """oMLX residency manager (omlx.py), or None when no oMLX endpoint is configured."""

    if not os.environ.get("OMLX_BASE_URL"):
        return None

    from aptrace_agent.omlx import ModelResidency, OmlxRuntime

    return ModelResidency(OmlxRuntime())


def _reviewer(args: argparse.Namespace, store):
    from aptrace_agent.omlx import model_settings
    from aptrace_agent.research.review import TerminalReviewer

    return TerminalReviewer(store, model=getattr(args, "review_model", None), residency=_residency(), model_settings=model_settings)


def _print_final_report(store, inv: str) -> None:
    from aptrace_agent.research.review import render_final_report

    print()
    print("TERMINAL REVIEW REPORT")

    for line in render_final_report(store, inv):
        print(f"  {line}" if line else "")


def handle_terminal_review_command(args: argparse.Namespace) -> bool:
    if args.command != "terminal-review":
        return False

    from aptrace_agent.research.review import review_summary

    store = _review_store(args, None)

    if args.action == "list":
        for inv in store.ids():
            print(f"{inv}  {store.status(inv)}")
        return True

    if args.action == "prepare":
        # Package a saved run artifact for review; nothing is rerun.
        from aptrace_agent.research.objective import load_spec
        from aptrace_agent.research.terminal import assessment_from_artifact

        if not args.artifact:
            raise SystemExit("terminal-review prepare: --artifact is required")

        path = Path(args.artifact).expanduser()
        payload = json.loads(path.read_text())
        spec = load_spec(args.objective_file) if args.objective_file else None
        assessment = assessment_from_artifact(payload, spec=spec)
        links = {"ledger_run_id": payload.get("ledger_run_id"), "artifact": str(path),
                 "generated_at": payload.get("generated_at"), "objective_file": args.objective_file,
                 "planner_model": (payload.get("models") or {}).get("planner"), "prepared_from_artifact": True}
        args.investigation = _reviewer(args, store).prepare(assessment, links)
        print(args.investigation)

        if not args.json:
            return True

    if not args.investigation:
        raise SystemExit("terminal-review: an investigation id (TR-...) is required")

    if args.action == "retry":
        reviewer = _reviewer(args, store)
        restore = None if args.no_restore_planner else os.environ.get("APTRACE_MODEL")
        reviewer.retry(args.investigation, restore_model=restore)

    if args.json:
        print(json.dumps(review_summary(store, args.investigation), indent=2, default=str))
    else:
        _print_final_report(store, args.investigation)

    return True


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
        "--experimental-tool",
        dest="experimental_tools",
        action="append",
        default=[],
        choices=EXPERIMENTAL_STRUCTURAL_TOOLS,
        help=(
            "Offer this experimental structural tool to the planner "
            "(repeatable; default: none). Admission cannot yet check the "
            "claims drawn from its results"
        ),
    )

    research.add_argument(
        "--claim-candidates",
        type=int,
        default=DEFAULT_CANDIDATE_LIMIT,
        help=(
            "With --ledger: offer at most this many mechanically derived "
            "claim candidates for selection by id at the end of the run; "
            f"0 disables (default: {DEFAULT_CANDIDATE_LIMIT})"
        ),
    )

    research.add_argument(
        "--objective-file",
        help=(
            "JSON objective (research/objective.py ObjectiveSpec): question, "
            "constraints, relations, terms, scenarios. Declared relations make "
            "the run objective-bounded"
        ),
    )

    research.add_argument(
        "--relation",
        dest="relations",
        action="append",
        default=[],
        help="Relation to investigate, SRC->DST[:label] with FUN_ or 0x endpoints (repeatable)",
    )

    research.add_argument(
        "--constraint",
        dest="constraints",
        action="append",
        default=[],
        help="Objective constraint shown whole to the planner (repeatable)",
    )

    research.add_argument(
        "objective",
        nargs="*",
        help=(
            "Research objective (required unless "
            "--work-item supplies it)"
        ),
    )

    research.add_argument(
        "--review",
        choices=("auto", "skip"),
        default="auto",
        help=(
            "Terminal review of a focused run by the review model (APTRACE_REVIEW_MODEL): "
            "auto (default) or skip, recorded as skipped by explicit policy. The deterministic "
            "terminal assessment is always produced"
        ),
    )

    research.add_argument(
        "--review-dir",
        help=(
            "Terminal review store (default: <ledger>/terminal-reviews with --ledger, "
            "else <output>.terminal-review beside --output)"
        ),
    )

    research.add_argument(
        "--no-restore-planner",
        action="store_true",
        help="After terminal review, leave the planner model unloaded instead of restoring it",
    )

    terminal = subparsers.add_parser(
        "terminal-review",
        help="Show, list or retry persisted terminal reviews (never reruns the investigation)",
    )
    terminal.add_argument("action", choices=("show", "retry", "list", "prepare"))
    terminal.add_argument("investigation", nargs="?", help="Terminal review id, TR-...")
    terminal.add_argument("--review-dir", help="Terminal review store (default: <ledger>/terminal-reviews)")
    terminal.add_argument("--ledger-dir", help="Research ledger directory whose terminal-reviews store to use")
    terminal.add_argument("--review-model", help="Review model (default: APTRACE_REVIEW_MODEL or gemma-4-26b-a4b-it-4bit)")
    terminal.add_argument("--no-restore-planner", action="store_true", help="Leave the planner model unloaded after retry")
    terminal.add_argument("--json", action="store_true", help="Emit the review summary as JSON")
    terminal.add_argument("--artifact", help="prepare: a saved research --output artifact to assess and package")
    terminal.add_argument("--objective-file", help="prepare: the objective spec, for an artifact that does not record one")

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

    if handle_terminal_review_command(args):
        return

    if args.command == "research":
        objective = " ".join(
            args.objective
        )

        if args.work_item and not args.ledger:
            parser.error("--work-item requires --ledger")
        if not args.work_item and (args.restart or args.rerun):
            parser.error("--restart and --rerun require --work-item")
        objective_spec = None

        if args.objective_file or args.relations or args.constraints:
            from aptrace_agent.research.objective import load_spec

            try:
                objective_spec = load_spec(
                    args.objective_file or "", question=objective, relations=args.relations, constraints=args.constraints
                )
            except (OSError, ValueError) as exc:
                parser.error(f"invalid objective: {exc}")

            objective = objective or objective_spec.question

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
        planner_residency = None

        if objective_spec is not None and objective_spec.focused and args.review == "auto" and os.environ.get("APTRACE_MODEL"):
            # Lifecycle step 1: the planner is the only resident model. A
            # failure is reported; the run's own planner calls then decide.
            residency = _residency()

            if residency is not None:
                try:
                    planner_residency = residency.acquire(os.environ["APTRACE_MODEL"])
                except Exception as exc:  # noqa: BLE001
                    planner_residency = getattr(exc, "record", {"error": {"detail": str(exc)}})
                    print(f"aptrace-agent: planner residency not established: {exc}", file=sys.stderr)

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
                    **({"experimental_tools": tuple(args.experimental_tools)} if args.experimental_tools else {}),
                    **(
                        {"executor": recorder, "claim_contract": True, "claim_candidates": args.claim_candidates}
                        if recorder is not None
                        else {}
                    ),
                    **({"followup": followup, "history": history} if followup is not None else {}),
                    **({"objective_spec": objective_spec} if objective_spec is not None else {}),
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
                claim_candidates=args.claim_candidates,
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

        # Terminal assessment and review (focused runs). The assessment and
        # package persist before any model switch; the run artifact is
        # written next, so neither depends on the review.
        assessment = getattr(run.result, "terminal_assessment", None)
        review_store = inv = None

        if assessment is not None:
            if planner_residency is not None:
                payload["planner_residency"] = planner_residency

            review_store = _review_store(args, output_path)

            if review_store is None:
                payload["terminal_review"] = {"status": "unavailable", "error": {"kind": "no_review_store",
                                              "detail": "pass --review-dir, --output or --ledger to persist the review"}}
            else:
                links = {
                    "ledger_run_id": payload.get("ledger_run_id"),
                    "artifact": str(output_path) if output_path is not None else None,
                    "generated_at": payload["generated_at"],
                    "objective_file": args.objective_file,
                    "planner_model": os.environ.get("APTRACE_MODEL"),
                }
                reviewer = _reviewer(args, review_store)
                inv = reviewer.prepare(assessment, links)
                payload["terminal_review"] = {"investigation_id": inv, "store": str(review_store.root / inv), "status": "pending"}

        if output_path is not None:
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

        if inv is not None:
            from aptrace_agent.research.review import review_summary

            if args.review == "skip":
                reviewer.skip(inv, "research --review skip")
            else:
                reviewer.run(inv, restore_model=None if args.no_restore_planner else os.environ.get("APTRACE_MODEL"))

            summary = review_summary(review_store, inv)
            payload["terminal_review"] = {k: summary[k] for k in ("investigation_id", "store", "status", "attempts")}

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

            if inv is not None:
                _print_final_report(review_store, inv)
            elif "terminal_review" in payload:
                print()
                print(f"TERMINAL REVIEW: {payload['terminal_review']['status']} ({payload['terminal_review']['error']['detail']})")

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
