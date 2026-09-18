from __future__ import annotations

from typing import Any

from aptrace_agent.case_evidence import performing_rigs_case_evidence

from aptrace_agent.disassembly import autopilot_disassembler
from aptrace_agent.ghidra_index import autopilot_ghidra_index
from aptrace_agent.investigation_tools import (
    performing_rigs_callsite_context,
    performing_rigs_pin_table,
)
from aptrace_agent.schemas import (
    EvidenceBundle,
    EvidenceObservation,
    InvestigationPlan,
)


class EvidenceExecutor:
    """
    Deterministically execute bounded APTrace evidence operations.

    No model decisions occur here.
    """

    def __init__(self) -> None:
        self.ghidra = autopilot_ghidra_index()
        self.disassembler = autopilot_disassembler()
        self.callsite_reader = (
            performing_rigs_callsite_context()
        )
        self.pin_table_reader = performing_rigs_pin_table()
        self.case_evidence = performing_rigs_case_evidence()

    def execute_operation(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        evidence_id: str,
    ) -> EvidenceObservation:
        if tool == "function_facts":
            function = str(arguments["function"])

            result = self.ghidra.function_facts(
                function
            ).model_dump()

        elif tool == "function_disassembly":
            function = str(arguments["function"])

            result = (
                self.disassembler
                .function_disassembly(function)
                .model_dump()
            )

        elif tool == "callsite_context":
            function = str(arguments["function"])
            address = arguments["address"]
            before = int(arguments.get("before", 8))
            after = int(arguments.get("after", 8))

            result = (
                self.callsite_reader.context(
                    function,
                    address,
                    before=before,
                    after=after,
                )
                .model_dump()
            )

        elif tool == "pin_table_entry":
            index = int(arguments["index"])

            result = (
                self.pin_table_reader.entry(index)
                .model_dump()
            )

        elif tool == "search_case_evidence":
            query = str(arguments["query"])
            max_results = int(
                arguments.get("max_results", 8)
            )

            result = (
                self.case_evidence.search(
                    query,
                    max_results=max_results,
                )
                .model_dump()
            )

        else:
            raise ValueError(
                f"unsupported evidence operation: {tool}"
            )

        return EvidenceObservation(
            id=evidence_id,
            tool=tool,
            arguments=dict(arguments),
            result=result,
        )

    def execute(
        self,
        objective: str,
        plan: InvestigationPlan,
        *,
        verbose: bool = False,
    ) -> EvidenceBundle:
        observations: list[EvidenceObservation] = []
        seen: set[tuple[str, str]] = set()

        if (
            not plan.function_facts
            and not plan.function_disassembly
        ):
            raise ValueError(
                "Investigation plan contains no evidence operations"
            )

        for args in plan.function_facts:
            function = args.function
            key = (
                "function_facts",
                function,
            )

            if key in seen:
                continue

            seen.add(key)

            if verbose:
                print(
                    f"[executor] function_facts({function!r})",
                    flush=True,
                )

            observations.append(
                self.execute_operation(
                    "function_facts",
                    {
                        "function": function,
                    },
                    evidence_id=(
                        f"E{len(observations) + 1}"
                    ),
                )
            )

        for args in plan.function_disassembly:
            function = args.function
            key = (
                "function_disassembly",
                function,
            )

            if key in seen:
                continue

            seen.add(key)

            if verbose:
                print(
                    f"[executor] "
                    f"function_disassembly({function!r})",
                    flush=True,
                )

            observations.append(
                self.execute_operation(
                    "function_disassembly",
                    {
                        "function": function,
                    },
                    evidence_id=(
                        f"E{len(observations) + 1}"
                    ),
                )
            )

        return EvidenceBundle(
            objective=objective,
            observations=observations,
        )
