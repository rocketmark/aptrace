from __future__ import annotations

from aptrace_agent.disassembly import autopilot_disassembler
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
        self.disassembler = autopilot_disassembler()

    def execute(
        self,
        objective: str,
        plan: InvestigationPlan,
        *,
        verbose: bool = False,
    ) -> EvidenceBundle:
        observations: list[EvidenceObservation] = []
        seen: set[tuple[str, str]] = set()

        if not plan.function_facts and not plan.function_disassembly:
            raise ValueError(
                "Investigation plan contains no evidence operations"
            )

        for args in plan.function_facts:
            function = args.function
            key = ("function_facts", function)

            if key in seen:
                continue

            seen.add(key)

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

        for args in plan.function_disassembly:
            function = args.function
            key = ("function_disassembly", function)

            if key in seen:
                continue

            seen.add(key)

            if verbose:
                print(
                    f"[executor] function_disassembly({function!r})",
                    flush=True,
                )

            disassembly = self.disassembler.function_disassembly(
                function
            )

            observations.append(
                EvidenceObservation(
                    id=f"E{len(observations) + 1}",
                    tool="function_disassembly",
                    arguments={"function": function},
                    result=disassembly.model_dump(),
                )
            )

        return EvidenceBundle(
            objective=objective,
            observations=observations,
        )
