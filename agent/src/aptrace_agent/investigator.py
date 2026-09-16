from __future__ import annotations

from dataclasses import dataclass

from aptrace_agent.executor import EvidenceExecutor
from aptrace_agent.router import route_question
from aptrace_agent.schemas import EvidenceBundle, InvestigationPlan
from aptrace_agent.synthesizer import synthesize


@dataclass
class InvestigationRun:
    question: str
    plan: InvestigationPlan
    evidence: EvidenceBundle
    answer: str
    routing: str
    synthesis_usage: object


def run_investigation(
    question: str,
    *,
    verbose: bool = False,
) -> InvestigationRun:
    if verbose:
        print("[phase] ROUTE", flush=True)

    plan = route_question(question)

    if plan is None:
        raise ValueError(
            "This question requires an APTrace analysis capability "
            "that is not available yet."
        )

    if verbose:
        number = 1

        for args in plan.function_facts:
            print(
                f"[route {number}] "
                f"function_facts(function={args.function!r})",
                flush=True,
            )
            number += 1

        for args in plan.function_disassembly:
            print(
                f"[route {number}] "
                f"function_disassembly(function={args.function!r})",
                flush=True,
            )
            number += 1

        print("[phase] EXECUTE", flush=True)

    executor = EvidenceExecutor()

    evidence = executor.execute(
        question,
        plan,
        verbose=verbose,
    )

    if verbose:
        print(
            f"[executor] collected "
            f"{len(evidence.observations)} observation(s)",
            flush=True,
        )
        print("[phase] SYNTHESIZE", flush=True)

    answer, synthesis_usage = synthesize(evidence)

    return InvestigationRun(
        question=question,
        plan=plan,
        evidence=evidence,
        answer=answer,
        routing="deterministic",
        synthesis_usage=synthesis_usage,
    )
