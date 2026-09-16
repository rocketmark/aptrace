from __future__ import annotations

import argparse
import json

from aptrace_agent.investigator import run_investigation


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aptrace-agent",
        description="Evidence-driven APTrace firmware investigator",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    investigate = subparsers.add_parser(
        "investigate",
        help="Run one bounded firmware investigation",
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
        help="Show routing, evidence execution, and usage",
    )

    investigate.add_argument(
        "--json",
        action="store_true",
        help="Emit the complete run as JSON",
    )

    args = parser.parse_args()

    if args.command != "investigate":
        raise SystemExit(2)

    question = " ".join(args.question)

    try:
        run = run_investigation(
            question,
            verbose=args.verbose and not args.json,
        )
    except ValueError as exc:
        raise SystemExit(f"aptrace-agent: {exc}") from exc

    if args.json:
        payload = {
            "question": run.question,
            "routing": run.routing,
            "plan": run.plan.model_dump(),
            "evidence": run.evidence.model_dump(),
            "answer": run.answer,
            "usage": {
                "synthesis": repr(run.synthesis_usage),
            },
        }

        print(json.dumps(payload, indent=2))
        return

    print()
    print(run.answer)

    if args.verbose:
        print()
        print("Plan:")
        print(run.plan.model_dump_json(indent=2))

        print()
        print("Evidence:")
        print(run.evidence.model_dump_json(indent=2))

        print()
        print("Routing:")
        print(f"  {run.routing}")

        print()
        print("Usage:")
        print(f"  synthesis: {run.synthesis_usage}")


if __name__ == "__main__":
    main()
