"""
Work-item commands for aptrace-agent: `work init|create|reconcile|complete`,
`followups` (preview / create follow-up work for a recorded run), and the
`research --ledger --work-item` hand-off.

Beads is reached only from here, and only when one of these is used: plain
`research` never imports the work package, initializes a store, or needs
`bd` installed.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable
from typing import Any

from aptrace_agent.ledger.store import ResearchLedger
from aptrace_agent.ledger_wiring import ledger_dir, work_dir


DEFAULT_ACTOR = "aptrace-agent"


def _store_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--work-dir", help="Work-store root holding .beads/ and item locks (default: APTRACE_WORK_DIR or ~/.aptrace/work/performing-rigs)")
    parser.add_argument("--actor", default=os.environ.get("APTRACE_WORK_ACTOR", DEFAULT_ACTOR), help=f"Beads actor that claims work (default: APTRACE_WORK_ACTOR or {DEFAULT_ACTOR})")


def add_research_work_options(research: argparse.ArgumentParser) -> None:
    research.add_argument("--work-item", help="Run the investigation for this Beads work item (requires --ledger); the objective comes from the item")
    research.add_argument("--restart", action="store_true", help="With --work-item: start a new attempt after an interrupted one that recorded no run")
    research.add_argument("--rerun", action="store_true", help="With --work-item: run another attempt although a linked run already exists")
    _store_options(research)


def add_work_commands(subparsers: Any) -> None:
    work = subparsers.add_parser("work", help="Long-horizon investigation work items (Beads)")
    commands = work.add_subparsers(dest="work_command", required=True)

    init = commands.add_parser("init", help="Create the Beads work store (outside any git work tree)")
    init.add_argument("--prefix", default="apt", help="Work item id prefix (default: apt)")
    _store_options(init)

    create = commands.add_parser("create", help="Create an investigation work item for the current case and firmware")
    create.add_argument("--priority", type=int, default=2, help="0 (highest) to 4 (default: 2)")
    create.add_argument("--depends-on", action="append", default=[], help="Work item that must be closed first (repeatable)")
    create.add_argument("--title", help="Title (default: derived from the objective)")
    create.add_argument("objective", nargs="+", help="Research objective")
    _store_options(create)

    reconcile = commands.add_parser("reconcile", help="Classify a work item against the ledger; --apply links exactly referenced runs")
    reconcile.add_argument("item", help="Work item id")
    reconcile.add_argument("--apply", action="store_true", help="Link runs whose work_item_id names this item (the only automatic repair)")
    reconcile.add_argument("--json", action="store_true", help="Emit the reconciliation as JSON")
    reconcile.add_argument("--ledger-dir", help="Research ledger directory (default: the case ledger)")
    _store_options(reconcile)

    complete = commands.add_parser("complete", help="Close investigation work with linked runs; never changes claim state")
    complete.add_argument("item", help="Work item id")
    complete.add_argument("--reason", default="", help="Operator note recorded in the close reason")
    complete.add_argument("--ledger-dir", help="Research ledger directory (default: the case ledger)")
    _store_options(complete)


def add_followup_command(subparsers: Any) -> None:
    followups = subparsers.add_parser(
        "followups",
        help="Rank follow-up investigations for a recorded run (preview; --create makes Beads work items)",
    )
    followups.add_argument("run_id", help="Recorded investigation run id (R-...)")
    followups.add_argument("--limit", type=int, default=3, help="Shortlist size (default: 3)")
    followups.add_argument("--create", action="store_true", help="Create work items for the selected shortlist candidates")
    followups.add_argument("--select", action="append", default=[], help="With --create: shortlist position (1-based) or key prefix (repeatable; default: none)")
    followups.add_argument("--json", action="store_true", help="Emit the report as JSON")
    followups.add_argument("--no-store", action="store_true", help="Preview without reading the work store")
    followups.add_argument("--ledger-dir", help="Research ledger directory (default: the case ledger)")
    followups.add_argument("--prefix", default="apt", help="Work item id prefix of the store (default: apt)")
    _store_options(followups)


def _open(args: argparse.Namespace, *, initialize: bool = False):
    from aptrace_agent.work.beads import BeadsWorkStore

    root = work_dir(args.work_dir)
    store = BeadsWorkStore(root / ".beads", actor=args.actor)
    return (store if initialize else store.open_checked()), root / "aptrace-locks"


def _context():
    from aptrace_agent.executor import EvidenceExecutor
    from aptrace_agent.ledger_wiring import context_provider

    return context_provider(EvidenceExecutor())()


def print_reconciliation(rec) -> None:
    item = rec.item
    print(f"{item.id} [{item.status}{', ' + item.assignee if item.assignee else ''}] {item.title}")
    print(f"  state: {rec.state}: {rec.detail}")
    print(f"  next: {rec.next_step}")

    if rec.linked_runs:
        print(f"  linked runs: {', '.join(rec.linked_runs)}")
    if rec.unlinked_runs:
        print(f"  unlinked runs (exact work_item_id): {', '.join(rec.unlinked_runs)}")
    if rec.attempt:
        print(f"  attempt: {json.dumps(rec.attempt, sort_keys=True)}")

    for problem in rec.problems:
        print(f"  problem {problem.code}: {problem.detail}")

    for key, state in rec.claim_states.items():
        print(f"  claim {key}: {state}")

    for group in rec.duplicate_claims:
        print(f"  possible duplicate proposals (same type and assertion text; not merged): {', '.join(group)}")
    if rec.heuristic_candidates:
        print(f"  heuristic candidates (no work-item reference; not linked): {', '.join(rec.heuristic_candidates)}")
    if rec.partial_claims:
        print(f"  claims whose run was never recorded (time-window diagnostic): {', '.join(rec.partial_claims)}")


def handle_work_command(args: argparse.Namespace) -> bool:
    if args.command != "work":
        return False

    from aptrace_agent.work import WorkStoreError
    from aptrace_agent.work import handoff

    try:
        if args.work_command == "init":
            store, _locks = _open(args, initialize=True)
            store.initialize(prefix=args.prefix)
            print(f"Beads work store ready at {store.beads_dir} (bd {store.check_version()})")
            return True

        store, locks = _open(args)

        if args.work_command == "create":
            item = handoff.create_investigation(
                store,
                context=_context(),
                objective=" ".join(args.objective),
                title=args.title,
                priority=args.priority,
                depends_on=tuple(args.depends_on),
            )
            print(f"{item.id} [{item.status}] {item.title}")
            print(f"  run: aptrace-agent research --ledger --work-item {item.id}")
            return True

        ledger = ResearchLedger(ledger_dir(args.ledger_dir))

        if args.work_command == "reconcile":
            if args.apply:
                rec = handoff.apply_reconciliation(store, ledger, args.item, actor=args.actor, lock_dir=locks)
            else:
                rec = handoff.reconcile(store, ledger, args.item, actor=args.actor, lock=handoff.ItemLock(locks, args.item))

            if args.json:
                print(json.dumps(rec.as_dict(), indent=2))
            else:
                print_reconciliation(rec)

            if rec.state == handoff.CONFLICT:
                raise SystemExit(1)

            return True

        if args.work_command == "complete":
            rec = handoff.complete_investigation(store, ledger, args.item, actor=args.actor, lock_dir=locks, reason=args.reason)
            print_reconciliation(rec)
            return True
    except (WorkStoreError, handoff.HandoffError, ValueError) as exc:
        raise SystemExit(f"aptrace-agent work: {exc}") from exc

    return False


def _followup_report(ledger: ResearchLedger, run_id: str, *, executor, context, limit: int = 3):
    from aptrace_agent.ledger_wiring import lead_deriver_factory
    from aptrace_agent.research.followups import generate_followups

    return generate_followups(ledger, run_id, context=context, deriver_for=lead_deriver_factory(executor), limit=limit)


def _select(report, selectors: list[str]) -> list:
    chosen = []

    for selector in selectors:
        if selector.isdigit() and 1 <= int(selector) <= len(report.shortlist):
            chosen.append(report.shortlist[int(selector) - 1])
            continue

        matches = [c for c in report.shortlist if c.key.startswith(selector)]

        if len(matches) != 1:
            raise SystemExit(f"aptrace-agent followups: --select {selector!r} matches {len(matches)} shortlist candidate(s)")

        chosen.append(matches[0])

    return list({c.key: c for c in chosen}.values())


def print_followup_report(report, annotations: dict[str, str]) -> None:
    print(f"FOLLOW-UPS for {report.run_id} ({report.case}/{report.firmware_key}, {report.generator_version})")
    print(f"  frontier: {report.frontier.status}: {report.frontier.detail}")

    for limitation in report.limitations:
        print(f"  limitation: {limitation}")

    sections = (("SHORTLIST", report.shortlist), ("DEFERRED (beyond --limit)", report.deferred), ("SUPPRESSED", report.suppressed))

    for title, candidates in sections:
        if not candidates:
            continue

        print()
        print(title)

        for position, c in enumerate(candidates, start=1):
            print(f"  {position}. [rank {c.rank} {c.category}] key {c.key}" + (f"  {c.status.upper()}: {c.status_detail}" if c.status != "proposed" else ""))
            print(f"     objective: {c.objective}")
            print(f"     why: {c.reason}")
            print(f"     gain: {c.information_gain}")

            for line in c.priority_basis:
                print(f"     basis: {line}")

            refs = c.claim_versions + c.audit_ids + c.verification_ids
            print(f"     refs: run {c.source_run_id}" + (f"; {', '.join(refs)}" if refs else "") + f"; evidence {', '.join(c.evidence_ids) or '-'}")
            print(f"     leads: {c.lead_count} consolidated, {len(c.seeded_leads)} seeded; context {c.context_chars()} chars")

            if c.key in annotations:
                print(f"     work: {annotations[c.key]}")


def handle_followups_command(args: argparse.Namespace) -> bool:
    if args.command != "followups":
        return False

    from aptrace_agent.executor import EvidenceExecutor
    from aptrace_agent.ledger_wiring import context_provider
    from aptrace_agent.work import WorkStoreError
    from aptrace_agent.work import followups as work_followups

    ledger = ResearchLedger(ledger_dir(args.ledger_dir))
    executor = EvidenceExecutor()
    context = context_provider(executor)()

    try:
        run = ledger.run(args.run_id)
    except KeyError:
        raise SystemExit(f"aptrace-agent followups: run {args.run_id} is not in the ledger") from None

    report = _followup_report(ledger, run.run_id, executor=executor, context=context, limit=args.limit)
    selected = _select(report, args.select) if args.create else []

    if args.create and not selected:
        raise SystemExit("aptrace-agent followups: --create needs at least one --select (shortlist position or key prefix)")

    store = None
    annotations: dict[str, str] = {}
    created: list[dict[str, Any]] = []

    try:
        if args.create or not args.no_store:
            try:
                store, _locks = _open(args)
            except WorkStoreError as exc:
                if args.create:
                    raise
                annotations = {c.key: f"work store unavailable ({exc}); not checked" for c in report.candidates()}

        if store is not None:
            for c in report.candidates():
                found = work_followups.existing_followups(store, c, prefix=args.prefix)
                exact, prior = found["exact"], found["prior"]
                text = f"{exact.id} [{exact.status}]" if exact else f"not created (would be {found['item_id']})"

                if prior:
                    text += f"; earlier items for the same question: {', '.join(f'{p.id} [{p.status}]' for p in prior)}"

                annotations[c.key] = text

        for c in selected:
            outcome = work_followups.materialize(store, c, context=context, prefix=args.prefix, source_item=run.work_item_id)
            created.append({"key": c.key, **outcome.as_dict()})
            annotations[c.key] = outcome.detail + "".join(f"; {note}" for note in outcome.notes)
    except (WorkStoreError, work_followups.FollowUpRefused) as exc:
        raise SystemExit(f"aptrace-agent followups: {exc}") from exc

    if args.json:
        print(json.dumps({"report": report.model_dump(mode="json"), "work": annotations, "created": created}, indent=2))
    else:
        print_followup_report(report, annotations)

        for row in created:
            print(f"\n{row['detail']}: run with `aptrace-agent research --ledger --work-item {row['item_id']}`")

    return True


def followup_for_work_item(args: argparse.Namespace, *, executor, context):
    """
    The follow-up candidate a work item was created from, re-assembled from
    the ledger, or None for an ordinary investigation item. Refuses when the
    candidate's evidence basis changed since the item was created.
    """

    from aptrace_agent.work import WorkStoreError
    from aptrace_agent.work.followups import followup_reference

    try:
        store, _locks = _open(args)
        reference = followup_reference(store.get_work(args.work_item))
    except WorkStoreError as exc:
        raise SystemExit(f"aptrace-agent research: {exc}") from exc

    if reference is None:
        return None

    run_id, key = reference
    ledger = ResearchLedger(ledger_dir(args.ledger_dir))
    candidate = _followup_report(ledger, run_id, executor=executor, context=context).find(key)

    if candidate is None:
        raise SystemExit(
            f"aptrace-agent research: {args.work_item} follows up candidate {key} of run {run_id}, which no longer derives from the ledger "
            f"(its evidence basis or inputs changed). Review `aptrace-agent followups {run_id}`; the item is left as is."
        )

    return candidate


def research_work_item(
    args: argparse.Namespace,
    objective: str,
    context,
    investigate: Callable[[str, str], str],
) -> tuple[dict[str, Any] | None, str | None]:
    """
    Run `research --ledger --work-item`. Returns (work summary, error). A
    refusal before the investigation starts exits immediately; an error after
    the run is recorded is returned so the caller still reports the run.
    """

    from aptrace_agent.work import WorkStoreError
    from aptrace_agent.work import handoff

    try:
        store, locks = _open(args)
        outcome = handoff.run_investigation(
            store,
            ResearchLedger(ledger_dir(args.ledger_dir)),
            args.work_item,
            actor=args.actor,
            context=context,
            investigate=investigate,
            lock_dir=locks,
            objective=objective or None,
            restart=args.restart,
            rerun=args.rerun,
        )
    except handoff.WriteBackFailed as exc:
        return {"item_id": exc.item_id, "run_id": exc.run_id, "write_back": "failed"}, f"aptrace-agent research: {exc}"
    except (WorkStoreError, handoff.HandoffError, ValueError) as exc:
        raise SystemExit(f"aptrace-agent research: {exc}") from exc

    return outcome.as_dict(), None


def print_work_summary(work: dict[str, Any]) -> None:
    print()
    print(f"WORK ITEM {work['item_id']}")

    if "reconciliation" not in work:
        print(f"  run {work['run_id']} recorded; write-back FAILED")
        return

    rec = work["reconciliation"]
    print(f"  attempt {work['attempt_id']} -> run {work['run_id']}")
    print(f"  state: {rec['state']}: {rec['detail']}")
    print(f"  next: {rec['next_step']}")
    print("  The work item is not closed automatically; closing never changes claim state.")

    for note in work["notes"]:
        print(f"  note: {note}")

    for group in rec["duplicate_claims"]:
        print(f"  possible duplicate proposals (not merged): {', '.join(group)}")


__all__ = [
    "add_followup_command",
    "add_research_work_options",
    "add_work_commands",
    "followup_for_work_item",
    "handle_followups_command",
    "handle_work_command",
    "print_work_summary",
    "research_work_item",
]
