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


def _parse_immediate(text: str) -> int | None:
    text = text.strip()

    if text.startswith("#"):
        text = text[1:]

    try:
        return int(text, 0)
    except ValueError:
        return None


def _direct_r0_literal_before_callsite(
    observation: Any,
) -> int | None:
    data = _mapping(observation)

    if data.get("tool") != "callsite_context":
        return None

    result = _mapping(data.get("result"))

    callsite = result.get("address")
    instructions = result.get("instructions") or []

    call_index: int | None = None

    for i, raw in enumerate(instructions):
        ins = _mapping(raw)

        if ins.get("address") == callsite:
            call_index = i
            break

    if call_index is None:
        return None

    for raw in reversed(instructions[:call_index]):
        ins = _mapping(raw)

        mnemonic = str(
            ins.get("mnemonic", "")
        ).lower()

        operands = str(
            ins.get("operands", "")
        ).strip()

        if not operands:
            continue

        parts = [
            part.strip()
            for part in operands.split(",")
        ]

        if not parts:
            continue

        destination = parts[0].lower()

        if destination != "r0":
            continue

        if mnemonic not in {
            "mov",
            "movs",
            "mov.w",
            "movs.w",
        }:
            return None

        if len(parts) < 2:
            return None

        return _parse_immediate(parts[1])

    return None


def generate_pin_table_leads_from_callsite(
    observation: Any,
    *,
    evidence_id: str,
    registry: LeadRegistry,
) -> list[Lead]:
    """
    If a validated callsite directly loads a literal into r0 immediately
    before the call, expose a safe lead for resolving that literal through
    the Performing Rigs logical pin table.

    This producer does not decide whether the lead is important. The
    research model decides whether to follow it.
    """

    literal = _direct_r0_literal_before_callsite(
        observation
    )

    if literal is None:
        return []

    data = _mapping(observation)
    result = _mapping(data.get("result"))

    function = str(
        result.get("function", "unknown function")
    )

    address = str(
        result.get("address", "unknown address")
    )

    return [
        registry.register(
            kind="pin-table",
            description=(
                f"Resolve logical pin-table argument {literal} "
                f"observed at {function} callsite {address}"
            ),
            tool="pin_table_entry",
            arguments={
                "index": literal,
            },
            source_evidence_ids=[
                evidence_id,
            ],
        )
    ]


def generate_case_search_leads_from_pin_table(
    observation: Any,
    *,
    evidence_id: str,
    registry: LeadRegistry,
) -> list[Lead]:
    """
    Turn an observed GPIO identity from a pin-table result into a bounded
    case-evidence reconciliation lead.

    The search query is the observed entity itself. This producer does not
    add benchmark-specific semantic terms or decide that the search must be
    followed.
    """

    data = _mapping(observation)

    if data.get("tool") != "pin_table_entry":
        return []

    result = _mapping(data.get("result"))
    gpio = result.get("gpio")

    if not isinstance(gpio, str):
        return []

    gpio = gpio.strip()

    if not gpio:
        return []

    return [
        registry.register(
            kind="case-evidence",
            description=(
                f"Search existing case evidence for observed GPIO {gpio}"
            ),
            tool="search_case_evidence",
            arguments={
                "query": gpio,
                "max_results": 8,
            },
            source_evidence_ids=[
                evidence_id,
            ],
        )
    ]
