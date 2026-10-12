from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aptrace_agent.research.lead_generation import (
    CallsiteReader,
    FunctionFactsReader,
    LeadGenerationIssue,
    generate_case_search_leads_from_pin_table,
    generate_function_fact_leads,
    generate_function_leads_from_census,
    generate_function_leads_from_case_evidence,
    generate_pin_table_leads_from_callsite,
)
from aptrace_agent.research.leads import LeadRegistry
from aptrace_agent.research.state import Lead
from aptrace_agent.schemas import EvidenceObservation


@dataclass(frozen=True)
class DerivationResult:
    leads: tuple[Lead, ...]
    issues: tuple[LeadGenerationIssue, ...] = ()


class LeadDeriver:
    """
    Mechanically derive safe research directions from new evidence.

    This layer discovers available next steps. It does not decide which
    step is important; that remains a model decision.
    """

    def __init__(
        self,
        *,
        registry: LeadRegistry,
        callsite_reader: CallsiteReader,
        function_facts_reader: FunctionFactsReader | None = None,
    ) -> None:
        self.registry = registry
        self.callsite_reader = callsite_reader
        self.function_facts_reader = (
            function_facts_reader
        )

    def derive(
        self,
        observation: EvidenceObservation,
    ) -> DerivationResult:
        if observation.tool == "function_facts":
            generated = generate_function_fact_leads(
                observation.result,
                evidence_id=observation.id,
                registry=self.registry,
                callsite_reader=self.callsite_reader,
                function_facts_reader=(
                    self.function_facts_reader
                ),
            )

            return DerivationResult(
                leads=generated.leads,
                issues=generated.issues,
            )

        if observation.tool == "callsite_context":
            leads = generate_pin_table_leads_from_callsite(
                observation,
                evidence_id=observation.id,
                registry=self.registry,
            )

            return DerivationResult(
                leads=tuple(leads),
            )

        if (
            observation.tool
            == "search_case_evidence"
            and observation.arguments.get(
                "purpose"
            )
            == "discovery"
            and self.function_facts_reader
            is not None
        ):
            generated = (
                generate_function_leads_from_case_evidence(
                    observation,
                    evidence_id=observation.id,
                    registry=self.registry,
                    function_facts_reader=(
                        self.function_facts_reader
                    ),
                )
            )

            return DerivationResult(
                leads=generated.leads,
                issues=generated.issues,
            )

        if (
            observation.tool
            == "census_peripheral_usage"
            and self.function_facts_reader
            is not None
        ):
            generated = (
                generate_function_leads_from_census(
                    observation,
                    evidence_id=observation.id,
                    registry=self.registry,
                    function_facts_reader=(
                        self.function_facts_reader
                    ),
                )
            )

            return DerivationResult(
                leads=generated.leads,
                issues=generated.issues,
            )

        structural = _STRUCTURAL_TARGETS.get(observation.tool)

        if structural is not None and self.function_facts_reader is not None:
            return self._function_leads(
                observation,
                structural(observation.result),
            )

        if observation.tool == "pin_table_entry":
            leads = generate_case_search_leads_from_pin_table(
                observation,
                evidence_id=observation.id,
                registry=self.registry,
            )

            return DerivationResult(
                leads=tuple(leads),
            )

        return DerivationResult(
            leads=(),
        )

    def _function_leads(
        self,
        observation: EvidenceObservation,
        targets: list[tuple[str, str]],
    ) -> DerivationResult:
        """Validated function-facts leads for structurally surfaced targets."""

        leads: list[Lead] = []
        issues: list[LeadGenerationIssue] = []

        for function, why in targets:
            description = f"Inspect {function}, {why}"

            try:
                self.function_facts_reader.function_facts(function)
            except (KeyError, ValueError) as exc:
                issues.append(
                    LeadGenerationIssue(
                        kind="invalid-structural-function",
                        description=description,
                        reason=str(exc),
                        source_evidence_ids=(observation.id,),
                    )
                )
                continue

            leads.append(
                self.registry.register(
                    kind="function",
                    description=description,
                    tool="function_facts",
                    arguments={"function": function},
                    source_evidence_ids=[observation.id],
                )
            )

        return DerivationResult(
            leads=tuple(leads),
            issues=tuple(issues),
        )


def _common_path_targets(result: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (item["function"], "a known common descendant of both analyzed sets")
        for item in result.get("common", [])
        if not item.get("shared_utility")
    ][:2]


def _usb_targets(result: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (user["function"], "which accesses USB registers")
        for user in result.get("register_users", [])
    ][:3]


def _effects_targets(result: dict[str, Any]) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []

    for call in result.get("calls", []):
        target = call.get("target")

        if target:
            name = f"FUN_{int(target, 16) & ~1:08x}"
            targets.append((name, f"called by {result.get('function')}"))

    return list(dict.fromkeys(targets))[:3]


_STRUCTURAL_TARGETS = {
    "census_common_paths": _common_path_targets,
    "census_usb_inventory": _usb_targets,
    "function_effects": _effects_targets,
}
