"""
Ledger subcommands for aptrace-agent: claims, audit, verify, replay, check,
report, benchmark, and ledger recording for `research --ledger`.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aptrace_agent.ledger.models import ClaimState
from aptrace_agent.ledger.store import EVIDENCE_INVALIDATED, ResearchLedger, ensure_key
from aptrace_agent.ledger_wiring import (
    BENCHMARK_DIR,
    DEFAULT_REPORT_PATH,
    REPO_ROOT,
    context_provider,
    irq_handler_resolver,
    ledger_dir,
)


LEDGER_COMMANDS = ("claims", "propose", "supersede", "audit", "audit-repeat", "runtime-probe", "verify", "replay", "check", "report", "benchmark")


def add_ledger_commands(subparsers: Any) -> None:
    def ledger_parser(name: str, help_text: str) -> argparse.ArgumentParser:
        parser = subparsers.add_parser(name, help=help_text)
        parser.add_argument("--ledger-dir", help="Research ledger directory (default: the case ledger)")
        return parser

    ledger_parser("claims", "List claim versions with APTrace lifecycle state")

    propose = ledger_parser("propose", "Record a PROPOSED claim version from a JSON claim spec")
    propose.add_argument("spec", help="JSON file: subject, assertion, claim_type, proposed_grade, proposed_by, supporting_evidence_ids, ...")

    supersede = ledger_parser("supersede", "Write the next version of a claim from a JSON change spec (prior version is kept)")
    supersede.add_argument("claim", help="Latest claim version, e.g. C2:v1")
    supersede.add_argument("spec", help="JSON file: reason, proposed_by, and changed fields (semantics, supporting_evidence_ids, assertion, ...)")

    audit = ledger_parser("audit", "Adversarially audit one claim version with the audit model")
    audit.add_argument("claims", nargs="+", help="Claim id (latest version) or CLAIM:vN")
    audit.add_argument("--diagnostic", action="store_true", help="Audit even a claim that fails deterministic verification; recorded as diagnostic, never used by verification")
    _audit_options(audit)

    repeat = ledger_parser("audit-repeat", "Measure auditor stability: repeat identical audits of one claim version")
    repeat.add_argument("claim", help="Claim id (latest version) or CLAIM:vN")
    repeat.add_argument("--repeat", type=int, default=5, help="Number of identical audits (default 5)")
    repeat.add_argument("--output", help="Write per-run rows and the stability summary JSON to this path")
    _audit_options(repeat)

    probe = ledger_parser("runtime-probe", "Send byte-identical requests to the audit model runtime; compare responses")
    probe.add_argument("--audit-id", help="Also probe the exact first request of this recorded audit (system prompt + initial context)")
    probe.add_argument("--repeat", type=int, default=8)
    probe.add_argument("--configs", default="current,explicit_greedy", help="Comma-separated: current, explicit_greedy")
    probe.add_argument("--max-tokens", type=int, default=1200)
    probe.add_argument("--model", help="Model (default: APTRACE_REVIEW_MODEL or gemma-4-26b-a4b-it-4bit)")
    probe.add_argument("--output", help="Write probe results JSON to this path")

    verify = ledger_parser("verify", "Run APTrace deterministic verification of claim versions")
    verify.add_argument("claims", nargs="+", help="Claim id (latest version) or CLAIM:vN")
    verify.add_argument("--no-replay", action="store_true", help="Skip deterministic replay of supporting evidence")
    verify.add_argument("--precheck", action="store_true", help="Phases A-C only (no audit); never advances a claim")

    replay = ledger_parser("replay", "Replay a recorded deterministic invocation without any model")
    replay.add_argument("target", help="ToolInvocation id (TI-...) or evidence id (EV-...)")

    ledger_parser("check", "Re-hash stored evidence; invalidate changed evidence and stale its claims")

    report = ledger_parser("report", "Generate the Markdown research report from the ledger")
    report.add_argument("--output", help=f"Report path (default: {DEFAULT_REPORT_PATH})")
    report.add_argument("--check", action="store_true", help="Exit 1 if the existing report is stale")

    benchmark = ledger_parser("benchmark", "Run known-answer ledger benchmarks (setup, propose, audit, verify)")
    benchmark.add_argument("names", nargs="+", help="Fixture names under the case benchmark directory")
    benchmark.add_argument("--no-audit", action="store_true", help="Skip the audit model (deterministic checks only)")
    benchmark.add_argument("--output", help="Write benchmark results JSON to this path")
    _audit_options(benchmark)


def _audit_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--model", help="Audit model (default: APTRACE_REVIEW_MODEL or gemma-4-26b-a4b-it-4bit)")
    parser.add_argument("--max-decisions", type=int, default=5, help="Audit decisions including the verdict (default 5)")
    parser.add_argument("--case-search", action="store_true", help="Allow the auditor lexical case-document search (off by default: case prose contains prior conclusions)")


def _stack(args: argparse.Namespace):
    from aptrace_agent.executor import EvidenceExecutor
    from aptrace_agent.ledger.operations import LedgerOperationRunner

    executor = EvidenceExecutor()
    ledger = ResearchLedger(ledger_dir(args.ledger_dir))
    runner = LedgerOperationRunner(ledger, executor, context_provider(executor))
    return executor, ledger, runner


def _auditor(args: argparse.Namespace, executor, ledger, runner):
    from aptrace_agent.ledger.auditor import AuditBudget, ClaimAuditor

    return ClaimAuditor(
        ledger=ledger,
        runner=runner,
        model=args.model,
        budget=AuditBudget(max_decisions=args.max_decisions, max_tool_requests=max(1, args.max_decisions - 1)),
        peripherals=executor.census.available_peripherals(),
        irq_handlers=irq_handler_resolver(executor),
        case_search=args.case_search,
    )


def _runtime_snapshot(model: str) -> dict[str, Any]:
    """Serving-runtime configuration that can affect generation (oMLX), for
    diagnosing run-to-run variation. Secrets are never copied."""

    root = Path(os.environ.get("OMLX_HOME", "~/.omlx")).expanduser()
    snapshot: dict[str, Any] = {"endpoint": os.environ.get("OMLX_BASE_URL")}

    try:
        settings = json.loads((root / "settings.json").read_text())
        snapshot["server"] = {k: settings.get(k) for k in ("version", "scheduler", "cache", "sampling") if k in settings}
        snapshot["model_settings"] = json.loads((root / "model_settings.json").read_text()).get("models", {}).get(model)
    except (OSError, ValueError):
        snapshot["unavailable"] = True

    return snapshot


def _print_audit(audit) -> None:
    print(f"{audit.audit_id} {audit.claim_version}: {audit.verdict.value}" + (" (synthesized)" if audit.verdict_synthesized else ""))
    print(f"  model {audit.model} [{audit.template_version}] termination={audit.termination_reason}")

    for step in audit.steps:
        detail = step.tool or ""

        if step.arguments:
            detail += " " + json.dumps(step.arguments)[:140]

        status = step.rejection or step.error or (f"-> {step.evidence_id}" if step.evidence_id else "")
        print(f"  step {step.number}.{step.attempt} {step.action}: {detail} {status}".rstrip())

    if audit.scope_check:
        print(f"  scope_check: {audit.scope_check}")

    print(f"  reasoning: {audit.reasoning}")

    for item in audit.challenges:
        print(f"  challenge: {item}")

    for item in audit.limitations:
        print(f"  limitation: {item}")

    for item in audit.follow_up_requests:
        print(f"  follow-up: {item.question}")


def _print_verification(outcome) -> None:
    record = outcome.record
    print(
        f"{record.verification_id} {record.claim_version} [{record.mode}]: {outcome.previous.value} -> {outcome.current.value}"
        + (f"  phases {record.phases}" if record.phases else "")
    )

    for check in record.checks:
        print(f"  [{check.phase or '-'}:{'pass' if check.passed else 'FAIL'}:{check.severity}] {check.name}: {check.detail}")

    for item in record.semantic_checks:
        if not item.passed:
            print(
                f"  semantic {item.code.value}: {item.field}={item.claimed} claimed_role={item.claimed_role} "
                f"evidence_role={item.evidence_role} evidence={item.evidence_id} {item.detail}"
            )

    if outcome.staled:
        print(f"  staled dependents: {', '.join(outcome.staled)}")


def handle_ledger_command(args: argparse.Namespace) -> bool:
    if args.command not in LEDGER_COMMANDS:
        return False

    if args.command == "claims":
        ledger = ResearchLedger(ledger_dir(args.ledger_dir))

        for claim, state in ledger.iter_current():
            audit = ledger.latest_audit(claim.key)
            verdict = audit.verdict.value if audit else "-"
            print(f"{claim.key:<8} {state.value:<10} {claim.proposed_grade.value:<8} audit={verdict:<10} {claim.assertion[:100]}")

        return True

    if args.command == "propose":
        ledger = ResearchLedger(ledger_dir(args.ledger_dir))
        spec = json.loads(Path(args.spec).expanduser().read_text())
        spec.pop("note", None)
        claim = ledger.propose_claim(**spec)
        print(f"{claim.key} [{ledger.state(claim.key).value}] {claim.proposed_grade.value}: {claim.assertion}")
        return True

    if args.command == "supersede":
        ledger = ResearchLedger(ledger_dir(args.ledger_dir))
        spec = json.loads(Path(args.spec).expanduser().read_text())
        spec.pop("note", None)
        claim = ledger.supersede_claim(ensure_key(ledger, args.claim), proposed_by=spec.pop("proposed_by"), reason=spec.pop("reason"), **spec)
        print(f"{claim.key} [{ledger.state(claim.key).value}] supersedes {claim.supersedes}: {claim.assertion}")
        return True

    if args.command == "report":
        from aptrace_agent.ledger.report import report_is_stale, write_report

        ledger = ResearchLedger(ledger_dir(args.ledger_dir))
        path = Path(args.output).expanduser() if args.output else DEFAULT_REPORT_PATH

        if args.check:
            stale = report_is_stale(ledger, path)
            print(f"{path}: {'STALE (regenerate)' if stale else 'current'}")
            raise SystemExit(1 if stale else 0)

        print(write_report(ledger, path))
        return True

    if args.command == "runtime-probe":
        from aptrace_agent.ledger.auditor import DEFAULT_AUDIT_MODEL, SYSTEM_PROMPT
        from aptrace_agent.runtime_probe import build_request, post, run_probe

        ledger = ResearchLedger(ledger_dir(args.ledger_dir))
        model = args.model or os.environ.get("APTRACE_REVIEW_MODEL", DEFAULT_AUDIT_MODEL)
        prompts = {
            "short": [
                {"role": "system", "content": "Answer with one JSON object."},
                {"role": "user", "content": 'List the first five prime numbers as {"primes": [...]} and nothing else.'},
            ]
        }

        if args.audit_id:
            prompts[f"audit:{args.audit_id}"] = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": ledger.audit(args.audit_id).initial_context},
            ]

        base_url, api_key = os.environ["OMLX_BASE_URL"], os.environ["OMLX_API_KEY"]
        results = []

        for name, messages in prompts.items():
            for config in args.configs.split(","):
                payload = build_request(model, messages, config=config.strip(), max_tokens=args.max_tokens)
                result = run_probe(payload, repeat=args.repeat, send=lambda body: post(base_url, api_key, body))
                result.update(prompt=name, config=config.strip())
                results.append(result)
                print(
                    f"{name:<36} {config.strip():<16} request {result['request_sha256'][:12]} "
                    f"distinct_responses={result['distinct_responses']}/{args.repeat} "
                    f"errors={len(result['errors'])} tokens={[c['completion_tokens'] for c in result['calls']]} "
                    f"cached={[c['cached_tokens'] for c in result['calls']]} "
                    f"elapsed={[c['elapsed_s'] for c in result['calls']]}",
                    flush=True,
                )

        if args.output:
            path = Path(args.output).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {"generated_at": datetime.now(timezone.utc).isoformat(), "model": model, "runtime_config": _runtime_snapshot(model), "results": results},
                    indent=2,
                )
                + "\n"
            )
            print(f"results: {path}")

        return True

    if args.command == "check":
        ledger = ResearchLedger(ledger_dir(args.ledger_dir))
        changed = 0

        for artifact in ledger.all_evidence():
            if ledger.evidence_state(artifact.evidence_id) == EVIDENCE_INVALIDATED:
                continue

            try:
                _value, ok = ledger.load_blob(artifact.result_sha256)
            except KeyError:
                ok = False

            if not ok:
                changed += 1
                staled = ledger.invalidate_evidence(artifact.evidence_id, reason="stored result hash mismatch")
                print(f"{artifact.evidence_id}: INVALIDATED; stale claims: {', '.join(staled) or 'none'}")

        print(f"checked {len(ledger.all_evidence())} evidence artifact(s); {changed} invalidated")
        return True

    executor, ledger, runner = _stack(args)

    if args.command == "replay":
        from aptrace_agent.ledger.store import new_id

        target = args.target
        invocation_id = ledger.evidence(target).invocation_id if target.startswith("EV-") else target
        result = runner.replay(invocation_id, run_id=new_id("RP"))
        print(f"replay {invocation_id} ({result.original.tool}) -> {result.replay.invocation_id}: {'MATCH' if result.matches else 'MISMATCH'}")
        print(f"  original sha256 {result.original_sha256}")
        print(f"  replay   sha256 {result.replay_sha256}")

        for name, (old, new) in result.input_drift.items():
            print(f"  input drift {name}: {old} -> {new}")

        for line in result.differences:
            print(f"  diff {line}")

        if not result.matches:
            raise SystemExit(1)

        return True

    if args.command == "audit":
        from aptrace_agent.ledger.pipeline import audit_if_eligible
        from aptrace_agent.ledger.verifier import ClaimVerifier

        auditor = _auditor(args, executor, ledger, runner)
        verifier = ClaimVerifier(ledger, runner=runner)

        for key in args.claims:
            gated = audit_if_eligible(ensure_key(ledger, key), verifier=verifier, auditor=auditor, diagnostic=args.diagnostic)
            _print_verification(gated.precheck)

            if gated.skipped_reason:
                print(f"  audit {'recorded as DIAGNOSTIC' if gated.audit else 'SKIPPED'}: {gated.skipped_reason}")

            if gated.audit is not None:
                _print_audit(gated.audit)

            if gated.verification is not None:
                _print_verification(gated.verification)

        return True

    if args.command == "audit-repeat":
        from aptrace_agent.ledger.stability import stability_summary
        from aptrace_agent.ledger.store import new_id

        from aptrace_agent.ledger.pipeline import eligible
        from aptrace_agent.ledger.verifier import ClaimVerifier

        auditor = _auditor(args, executor, ledger, runner)
        key = ensure_key(ledger, args.claim)
        precheck = ClaimVerifier(ledger, runner=runner).precheck(key)

        if not eligible(precheck):
            _print_verification(precheck)
            print(f"{key} failed deterministic verification; repeated audits are not run")
            raise SystemExit(1)

        batch = new_id("B")
        audits = []

        for index in range(args.repeat):
            audit = auditor.audit(key, batch_id=batch)
            audits.append(audit)
            executed = [s.tool for s in audit.steps if (s.outcome or "").startswith("executed:")]
            print(
                f"[{index + 1}/{args.repeat}] {audit.audit_id} {key} fp={audit.input_fingerprint} "
                f"verdict={audit.verdict.value}{' (model ' + audit.model_verdict.value + ')' if audit.model_verdict else ''} "
                f"executed={executed} term={audit.termination_reason}",
                flush=True,
            )

        summary = stability_summary(audits)
        fingerprints = {a.input_fingerprint for a in audits}
        print(f"batch {batch}: {len(fingerprints)} distinct audit-input fingerprint(s)")

        for group in summary["groups"]:
            print("  " + json.dumps({k: group[k] for k in ("input_fingerprint", "runs", "verdicts", "verdict_agreement", "tool_sequence_agreement", "challenges_citing_coverage_gaps")}))

        if args.output:
            path = Path(args.output).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "batch_id": batch,
                        "claim_version": key,
                        "model": auditor.model,
                        "generation": auditor.generation(),
                        "runtime_config": _runtime_snapshot(auditor.model),
                        "repeat": args.repeat,
                        "distinct_fingerprints": sorted(f or "" for f in fingerprints),
                        **summary,
                    },
                    indent=2,
                )
                + "\n"
            )
            print(f"results: {path}")

        return True

    if args.command == "verify":
        from aptrace_agent.ledger.verifier import ClaimVerifier

        verifier = ClaimVerifier(ledger, runner=runner, replay=not args.no_replay)

        for key in args.claims:
            outcome = verifier.verify(ensure_key(ledger, key), mode="precheck" if args.precheck else "full")
            _print_verification(outcome)

        return True

    if args.command == "benchmark":
        from aptrace_agent.ledger.benchmark import run_benchmark

        auditor = None if args.no_audit else _auditor(args, executor, ledger, runner)
        results = []

        for name in args.names:
            result = run_benchmark(
                name,
                directory=BENCHMARK_DIR,
                ledger=ledger,
                runner=runner,
                auditor=auditor,
                irq_handlers=irq_handler_resolver(executor),
                repo=REPO_ROOT,
            )
            results.append(result.as_dict())
            print(f"benchmark {name}: setup {result.setup_run_id}")

            for outcome in result.claims:
                print(
                    f"  {outcome.label:<10} {outcome.key:<8} audit={outcome.audit_verdict or '-':<11} "
                    f"state={outcome.final_state:<9} pass={outcome.passed} failed={outcome.failed_checks}"
                )

                if outcome.audit_id:
                    _print_audit(ledger.audit(outcome.audit_id))

                print(f"    expectations: {json.dumps(outcome.expectations)}")

        if args.output:
            path = Path(args.output).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(), "results": results}, indent=2) + "\n")
            print(f"results: {path}")

        return True

    return False


def record_research_run(run, *, executor, recorder, ledger_dir_override, started_at, ended_at, max_steps, controller_cls, work_item_id=None) -> str:
    """Record a finished `research --ledger` run; returns the run id.

    work_item_id, when given, is stored on the run as an opaque reference to
    the work item the run was executed for (see `aptrace-agent work`).
    """

    from aptrace_agent.ledger.operations import source_revision
    from aptrace_agent.ledger.recorder import code_identity, record_investigation
    from aptrace_agent.research import projection

    ledger = ResearchLedger(ledger_dir(ledger_dir_override))
    recorded = record_investigation(
        ledger,
        run,
        context=context_provider(executor)(),
        recorder=recorder,
        model=os.environ.get("APTRACE_MODEL"),
        execution_config={"temperature": 0.0, "max_tokens": 512, "endpoint": "local-omlx", "claim_contract": True},
        planner_version=f"controller:{code_identity(controller_cls)} projection:{code_identity(projection)}",
        budgets={"max_steps": max_steps},
        started_at=started_at,
        ended_at=ended_at,
        source=source_revision(REPO_ROOT),
        work_item_id=work_item_id,
    )

    for key in recorded.claim_versions:
        claim = ledger.claim(key)
        print(f"  proposed {key} [{ledger.state(key).value}] {claim.proposed_grade.value}: {claim.assertion}")

    return recorded.run_id


__all__ = ["add_ledger_commands", "handle_ledger_command", "record_research_run", "ClaimState"]
