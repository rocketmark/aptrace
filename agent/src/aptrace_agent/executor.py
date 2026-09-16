from __future__ import annotations

from aptrace_agent.ghidra_index import autopilot_ghidra_index
from aptrace_agent.schemas import (
    EvidenceBundle,
    EvidenceObservation,
    InvestigationPlan,
)


class EvidenceExecutor:
    """
    Deterministically execute an APTrace investigation plan.

    No model decisions occur here.
    """

    def __init__(self) -> None:
        self.ghidra = autopilot_ghidra_index()

    def execute(
        self,
        objective: str,
        plan: InvestigationPlan,
        *,
        verbose: bool = False,
    ) -> EvidenceBundle:
        observations: list[EvidenceObservation] = []
        seen: set[tuple[str, str]] = set()

        if not plan.function_facts:
            raise ValueError(
                "Investigation plan contains no evidence operations"
            )

        for args in plan.function_facts:
            function = args.function
            dedupe_key = ("function_facts", function)

            if dedupe_key in seen:
                if verbose:
                    print(
                        f"[executor] skip duplicate "
                        f"function_facts({function!r})",
                        flush=True,
                    )
                continue

            seen.add(dedupe_key)

            if verbose:
                print(
                    f"[executor] function_facts({function!r})",
                    flush=True,
                )

            facts = self.ghidra.function_facts(function)

            observations.append(
                EvidenceObservation(
                    id=f"E{len(observations) + 1}",
                    tool="function_facts",
                    arguments={"function": function},
                    result=facts.model_dump(),
                )
            )

        return EvidenceBundle(
            objective=objective,
            observations=observations,
        )
