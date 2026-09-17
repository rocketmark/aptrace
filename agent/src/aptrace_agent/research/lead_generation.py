from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from aptrace_agent.research.leads import LeadRegistry
from aptrace_agent.research.state import Lead


class CallsiteReader(Protocol):
    def context(
        self,
        function: str,
        address: int | str,
        before: int = 8,
        after: int = 8,
    ) -> Any:
        ...


@dataclass(frozen=True)
class LeadGenerationIssue:
    kind: str
    description: str
    reason: str
    source_evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class LeadGenerationResult:
    leads: tuple[Lead, ...]
    issues: tuple[LeadGenerationIssue, ...]


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)

    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump()
        if isinstance(dumped, Mapping):
            return dict(dumped)

    data = getattr(value, "__dict__", None)
    if isinstance(data, Mapping):
        return dict(data)

    return {}


def _first(
    data: Mapping[str, Any],
    *names: str,
) -> Any | None:
    for name in names:
        value = data.get(name)
        if value is not None and value != "":
            return value

    return None


def _address(value: Any) -> str:
    if isinstance(value, int):
        return f"0x{value:08x}"

    text = str(value).strip()

    if text.lower().startswith("0x"):
        try:
            return f"0x{int(text, 16):08x}"
        except ValueError:
            pass

    return text


def generate_function_fact_leads(
    facts: Any,
    *,
    evidence_id: str,
    registry: LeadRegistry,
    callsite_reader: CallsiteReader,
) -> LeadGenerationResult:
    """
    Generate validated incoming-call leads from FunctionFacts.

    Every structural lead is checked against the execution backend before
    registration. Metadata that cannot be executed becomes an issue instead
    of a model-visible lead.
    """

    data = _mapping(facts)

    target = _first(
        data,
        "name",
        "function",
        "function_name",
    ) or "the objective function"

    callers = data.get("callers") or []

    leads: list[Lead] = []
    issues: list[LeadGenerationIssue] = []
    seen: set[tuple[str, str]] = set()

    for entry in callers:
        caller_data = _mapping(entry)

        caller = _first(
            caller_data,
            "function",
            "caller",
            "caller_name",
            "name",
        )

        address = _first(
            caller_data,
            "address",
            "callsite",
            "callsite_address",
            "site",
        )

        if caller is None or address is None:
            continue

        caller_text = str(caller)
        address_text = _address(address)

        identity = (
            caller_text,
            address_text,
        )

        if identity in seen:
            continue

        seen.add(identity)

        description = (
            f"Inspect incoming call to {target} from "
            f"{caller_text} at {address_text}"
        )

        try:
            callsite_reader.context(
                caller_text,
                address_text,
                before=0,
                after=0,
            )
        except ValueError as exc:
            issues.append(
                LeadGenerationIssue(
                    kind="invalid-callsite",
                    description=description,
                    reason=str(exc),
                    source_evidence_ids=(evidence_id,),
                )
            )
            continue

        leads.append(
            registry.register(
                kind="callsite",
                description=description,
                tool="callsite_context",
                arguments={
                    "function": caller_text,
                    "address": address_text,
                    "before": 8,
                    "after": 8,
                },
                source_evidence_ids=[evidence_id],
            )
        )

    return LeadGenerationResult(
        leads=tuple(leads),
        issues=tuple(issues),
    )
