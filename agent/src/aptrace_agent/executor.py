from __future__ import annotations

from typing import Any

from aptrace_agent.case_evidence import performing_rigs_case_evidence
from aptrace_agent.census import performing_rigs_census

from aptrace_agent.disassembly import autopilot_disassembler
from aptrace_agent.call_observation import planner_summary as observation_summary
from aptrace_agent.function_effects import planner_summary as effects_summary
from aptrace_agent.callback_provenance import planner_summary as callback_provenance_summary
from aptrace_agent.indirect_target import planner_summary as indirect_target_summary
from aptrace_agent.structural_wiring import (
    performing_rigs_function_effects,
    performing_rigs_callback_provenance,
    performing_rigs_indirect_targets,
    performing_rigs_observed_calls,
    performing_rigs_graph,
    performing_rigs_source_agreement,
    performing_rigs_usb_inventory,
    performing_rigs_value_forward_use,
)
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
        self.census = performing_rigs_census()
        self.graph = performing_rigs_graph(self.census)
        self.usb = performing_rigs_usb_inventory(self.census, self.graph)
        self.source_agreement = performing_rigs_source_agreement(self.census, self.usb)
        self._effects = None
        self._observed_calls = None
        self._indirect_targets = None
        self._callback_provenance = None
        self._value_forward_use = None

    @property
    def value_forward_use(self):
        if self._value_forward_use is None:
            self._value_forward_use = performing_rigs_value_forward_use(self.census)

        return self._value_forward_use

    @property
    def callback_provenance(self):
        if self._callback_provenance is None:
            self._callback_provenance = performing_rigs_callback_provenance(self.census)

        return self._callback_provenance

    @property
    def indirect_targets(self):
        if self._indirect_targets is None:
            self._indirect_targets = performing_rigs_indirect_targets(self.census)

        return self._indirect_targets

    @property
    def observed_calls(self):
        if self._observed_calls is None:
            self._observed_calls = performing_rigs_observed_calls(
                self.census,
                self.graph,
                self.usb,
                self.ghidra,
            )

        return self._observed_calls

    @property
    def effects(self):
        # Built lazily: it reads the firmware image's vector table.
        if self._effects is None:
            self._effects = performing_rigs_function_effects(
                self.census,
                self.graph,
                self.usb,
            )

        return self._effects

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

        elif tool == "census_peripheral_usage":
            # Firmware, database and bounds are bound by APTrace; only
            # the catalog-validated peripheral name varies.
            result = (
                self.census.peripheral_usage(
                    arguments["peripheral"],
                    limit=arguments.get("limit", 25),
                )
                .model_dump(mode="json")
            )

        elif tool == "census_common_paths":
            # Function sets are resolved by APTrace from its own evidence;
            # hop bounds and edge semantics are fixed by the graph reader.
            result = (
                self.graph.common_paths(
                    list(arguments["left"]),
                    list(arguments["right"]),
                    left_label=str(arguments.get("left_label", "left")),
                    right_label=str(arguments.get("right_label", "right")),
                )
                .model_dump(mode="json")
            )

        elif tool == "census_usb_inventory":
            result = (
                self.usb.inventory()
                .model_dump(mode="json")
            )

        elif tool == "structural_source_agreement":
            result = self.source_agreement(list(arguments["addresses"]))

        elif tool == "function_effects":
            effects = self.effects.analyze(
                arguments["function"],
                arguments.get("specialize") or {},
            )
            effects.planner_summary = effects_summary(effects)
            result = effects.model_dump(mode="json")

        elif tool == "observed_call_arguments":
            observed = self.observed_calls.observe(
                arguments["function"],
                arguments.get("scenario"),
                arguments.get("watch"),
            )
            observed.planner_summary = observation_summary(observed)
            result = observed.model_dump(mode="json")

        elif tool == "indirect_call_target":
            target = self.indirect_targets.resolve(arguments["site"])
            target.planner_summary = indirect_target_summary(target)
            result = target.model_dump(mode="json")

        elif tool == "callback_argument_provenance":
            provenance = self.callback_provenance.trace(arguments["site"])
            provenance.planner_summary = callback_provenance_summary(provenance)
            result = provenance.model_dump(mode="json")

        elif tool == "value_forward_use":
            result = (
                self.value_forward_use
                .trace(arguments["origin"], arguments.get("register"))
                .model_dump(mode="json")
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
