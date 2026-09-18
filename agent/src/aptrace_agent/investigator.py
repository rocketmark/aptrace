from __future__ import annotations

from dataclasses import dataclass

from aptrace_agent.executor import EvidenceExecutor
from aptrace_agent.investigation_tools import (
    performing_rigs_callsite_context,
)
from aptrace_agent.research import (
    LeadDeriver,
    LeadFollower,
    LeadRegistry,
    ResearchController,
    ResearchRunResult,
    ResearchSession,
    ResearchState,
)
from aptrace_agent.router import route_question
from aptrace_agent.schemas import (
    EvidenceBundle,
    EvidenceObservation,
    InvestigationPlan,
)
from aptrace_agent.synthesizer import synthesize


@dataclass
class InvestigationRun:
    question: str
    plan: InvestigationPlan
    evidence: EvidenceBundle
    answer: str
    routing: str
    synthesis_usage: object


@dataclass
class AutonomousInvestigationRun:
    objective: str
    seed_function: str
    result: ResearchRunResult
    state: ResearchState
    evidence: tuple[EvidenceObservation, ...]


def run_investigation(
    question: str,
    *,
    verbose: bool = False,
) -> InvestigationRun:
    """
    Existing deterministic one-shot investigation path.
    """

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

    answer, synthesis_usage = synthesize(
        evidence
    )

    return InvestigationRun(
        question=question,
        plan=plan,
        evidence=evidence,
        answer=answer,
        routing="deterministic",
        synthesis_usage=synthesis_usage,
    )


def run_autonomous_investigation(
    objective: str,
    *,
    seed_function: str,
    max_steps: int = 12,
    planner_model: str | None = None,
    review_model: str | None = None,
    controller: ResearchController | None = None,
) -> AutonomousInvestigationRun:
    """
    Run one bounded autonomous firmware investigation.

    The seed establishes the initial firmware evidence. From that point
    onward the ResearchController chooses among APTrace-validated leads.
    """

    objective = objective.strip()

    if not objective:
        raise ValueError(
            "research objective must not be empty"
        )

    seed_function = seed_function.strip()

    if not seed_function:
        raise ValueError(
            "seed function must not be empty"
        )

    executor = EvidenceExecutor()
    registry = LeadRegistry()

    session = ResearchSession(
        objective=objective,
        registry=registry,
        follower=LeadFollower(
            registry=registry,
            executor=executor,
        ),
        deriver=LeadDeriver(
            registry=registry,
            callsite_reader=(
                performing_rigs_callsite_context()
            ),
        ),
    )

    session.record(
        executor.execute_operation(
            "function_facts",
            {
                "function": seed_function,
            },
            evidence_id=(
                session.ledger.next_id()
            ),
        )
    )

    session.record(
        executor.execute_operation(
            "function_disassembly",
            {
                "function": seed_function,
            },
            evidence_id=(
                session.ledger.next_id()
            ),
        )
    )

    research_controller = (
        controller
        or ResearchController(
            planner_model=planner_model,
            review_model=review_model,
            max_steps=max_steps,
        )
    )

    result = research_controller.run(
        session
    )

    return AutonomousInvestigationRun(
        objective=objective,
        seed_function=seed_function,
        result=result,
        state=session.state.model_copy(
            deep=True
        ),
        evidence=tuple(
            session.ledger.all()
        ),
    )
