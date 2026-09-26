from __future__ import annotations

import re
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


class FunctionFactsReader(Protocol):
    def function_facts(
        self,
        function: str,
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
    function_facts_reader: FunctionFactsReader | None = None,
    max_incoming_calls: int = 8,
    max_outgoing_functions: int = 6,
) -> LeadGenerationResult:
    """
    Generate validated structural leads from FunctionFacts.

    Incoming and outgoing calls become validated callsite leads.
    Valid outgoing callees may additionally become bounded function-facts
    and disassembly leads so the research graph can move forward through
    the call graph.
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
    expanded_callees: set[str] = set()
    incoming_call_count = 0
    outgoing_function_count = 0

    for entry in callers:
        if (
            incoming_call_count
            >= max_incoming_calls
        ):
            break
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
                    source_evidence_ids=(
                        evidence_id,
                    ),
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
                source_evidence_ids=[
                    evidence_id,
                ],
            )
        )

        incoming_call_count += 1

    target_text = str(target)
    callees = data.get("callees") or []

    for entry in callees:
        callee_data = _mapping(entry)

        callee = _first(
            callee_data,
            "function",
            "callee",
            "callee_name",
            "name",
        )

        address = _first(
            callee_data,
            "address",
            "callsite",
            "callsite_address",
            "site",
        )

        if callee is None or address is None:
            continue

        callee_text = str(callee)
        address_text = _address(address)

        identity = (
            target_text,
            address_text,
        )

        if identity in seen:
            continue

        seen.add(identity)

        description = (
            f"Inspect outgoing call from {target_text} to "
            f"{callee_text} at {address_text}"
        )

        try:
            callsite_reader.context(
                target_text,
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
                    source_evidence_ids=(
                        evidence_id,
                    ),
                )
            )
            continue

        leads.append(
            registry.register(
                kind="callsite",
                description=description,
                tool="callsite_context",
                arguments={
                    "function": target_text,
                    "address": address_text,
                    "before": 8,
                    "after": 8,
                },
                source_evidence_ids=[
                    evidence_id,
                ],
            )
        )

        if (
            function_facts_reader is None
            or outgoing_function_count
            >= max_outgoing_functions
            or callee_text == target_text
            or callee_text in expanded_callees
        ):
            continue

        try:
            function_facts_reader.function_facts(
                callee_text
            )
        except (KeyError, ValueError) as exc:
            issues.append(
                LeadGenerationIssue(
                    kind="invalid-outgoing-function",
                    description=(
                        f"Inspect outgoing callee "
                        f"{callee_text} from "
                        f"{target_text}"
                    ),
                    reason=str(exc),
                    source_evidence_ids=(
                        evidence_id,
                    ),
                )
            )
            continue

        expanded_callees.add(
            callee_text
        )
        outgoing_function_count += 1

        leads.append(
            registry.register(
                kind="function",
                description=(
                    f"Inspect outgoing callee "
                    f"{callee_text} from "
                    f"{target_text}"
                ),
                tool="function_facts",
                arguments={
                    "function": callee_text,
                },
                source_evidence_ids=[
                    evidence_id,
                ],
            )
        )

        leads.append(
            registry.register(
                kind="function-disassembly",
                description=(
                    f"Inspect disassembly of outgoing "
                    f"callee {callee_text} from "
                    f"{target_text}"
                ),
                tool="function_disassembly",
                arguments={
                    "function": callee_text,
                },
                source_evidence_ids=[
                    evidence_id,
                ],
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



_DISCOVERED_FUNCTION_RE = re.compile(
    r"\bFUN_([0-9a-fA-F]{8})\b"
)

_DISCOVERED_ADDRESS_RE = re.compile(
    r"\b0x([0-9a-fA-F]{4,8})\b"
)


def generate_function_leads_from_case_evidence(
    observation: Any,
    *,
    evidence_id: str,
    registry: LeadRegistry,
    function_facts_reader: FunctionFactsReader,
    max_functions: int = 8,
) -> LeadGenerationResult:
    """
    Convert concrete firmware-function names found in an explicit
    discovery search into validated APTrace leads.

    The model chooses only the semantic search query. Function names
    come from retrieved evidence and are validated against the current
    firmware index before becoming leads.
    """

    data = _mapping(observation)

    if data.get("tool") != "search_case_evidence":
        return LeadGenerationResult(
            leads=(),
            issues=(),
        )

    arguments = _mapping(
        data.get("arguments")
    )

    if arguments.get("purpose") != "discovery":
        return LeadGenerationResult(
            leads=(),
            issues=(),
        )

    result = _mapping(
        data.get("result")
    )

    query = str(
        result.get("query", "")
    ).strip()

    explicit_functions: list[str] = []
    address_candidates: list[str] = []

    for raw_match in result.get(
        "matches",
        [],
    ):
        match = _mapping(raw_match)

        searchable = "\n".join(
            [
                str(
                    match.get(
                        "source",
                        "",
                    )
                ),
                str(
                    match.get(
                        "excerpt",
                        "",
                    )
                ),
            ]
        )

        for suffix in (
            _DISCOVERED_FUNCTION_RE.findall(
                searchable
            )
        ):
            function = (
                "FUN_" + suffix.lower()
            )

            if function not in explicit_functions:
                explicit_functions.append(
                    function
                )

        for suffix in (
            _DISCOVERED_ADDRESS_RE.findall(
                searchable
            )
        ):
            address = int(
                suffix,
                16,
            )

            function = (
                f"FUN_{address:08x}"
            )

            if (
                function
                not in address_candidates
            ):
                address_candidates.append(
                    function
                )

    leads: list[Lead] = []
    issues: list[LeadGenerationIssue] = []
    discovered: list[str] = []

    for function in explicit_functions:
        try:
            function_facts_reader.function_facts(
                function
            )
        except (KeyError, ValueError) as exc:
            issues.append(
                LeadGenerationIssue(
                    kind="invalid-discovered-function",
                    description=(
                        f"Inspect firmware function "
                        f"{function} mentioned by "
                        f"discovery query {query!r}"
                    ),
                    reason=str(exc),
                    source_evidence_ids=(
                        evidence_id,
                    ),
                )
            )
            continue

        discovered.append(
            function
        )

        if len(discovered) >= max_functions:
            break

    if len(discovered) < max_functions:
        for function in address_candidates:
            if function in discovered:
                continue

            try:
                function_facts_reader.function_facts(
                    function
                )
            except (KeyError, ValueError):
                # Naked documentary addresses are only promoted when
                # they exactly match a current firmware function entry.
                # Invalid addresses are expected and are not issues.
                continue

            discovered.append(
                function
            )

            if (
                len(discovered)
                >= max_functions
            ):
                break

    for function in discovered:

        description = (
            f"Inspect firmware function {function} "
            f"mentioned by discovery query {query!r}"
        )

        leads.append(
            registry.register(
                kind="function",
                description=description,
                tool="function_facts",
                arguments={
                    "function": function,
                },
                source_evidence_ids=[
                    evidence_id,
                ],
            )
        )

        leads.append(
            registry.register(
                kind="function-disassembly",
                description=(
                    f"Inspect disassembly of {function} "
                    f"mentioned by discovery query "
                    f"{query!r}"
                ),
                tool="function_disassembly",
                arguments={
                    "function": function,
                },
                source_evidence_ids=[
                    evidence_id,
                ],
            )
        )

    return LeadGenerationResult(
        leads=tuple(leads),
        issues=tuple(issues),
    )


def generate_function_leads_from_census(
    observation: Any,
    *,
    evidence_id: str,
    registry: LeadRegistry,
    function_facts_reader: FunctionFactsReader,
    max_functions: int = 4,
) -> LeadGenerationResult:
    """
    Promote the functions a census peripheral analysis narrowed to into
    validated function leads.

    Only functions the census attributes to the peripheral are promoted,
    in the census result's deterministic order. No caller/callee or
    callsite expansion happens here.
    """

    data = _mapping(observation)

    if data.get("tool") != "census_peripheral_usage":
        return LeadGenerationResult(
            leads=(),
            issues=(),
        )

    result = _mapping(
        data.get("result")
    )

    if result.get("status") != "ok":
        return LeadGenerationResult(
            leads=(),
            issues=(),
        )

    peripheral = str(
        result.get("peripheral", "")
    )

    leads: list[Lead] = []
    issues: list[LeadGenerationIssue] = []
    promoted = 0

    for raw in result.get(
        "functions",
        [],
    ):
        if promoted >= max_functions:
            break

        function = str(
            _mapping(raw).get("function", "")
        )

        description = (
            f"Inspect {function}, which the census "
            f"associates with {peripheral}"
        )

        try:
            function_facts_reader.function_facts(
                function
            )
        except (KeyError, ValueError) as exc:
            issues.append(
                LeadGenerationIssue(
                    kind="invalid-census-function",
                    description=description,
                    reason=str(exc),
                    source_evidence_ids=(
                        evidence_id,
                    ),
                )
            )
            continue

        promoted += 1

        leads.append(
            registry.register(
                kind="function",
                description=description,
                tool="function_facts",
                arguments={
                    "function": function,
                },
                source_evidence_ids=[
                    evidence_id,
                ],
            )
        )

        leads.append(
            registry.register(
                kind="function-disassembly",
                description=(
                    f"Inspect disassembly of {function}, "
                    f"which the census associates with "
                    f"{peripheral}"
                ),
                tool="function_disassembly",
                arguments={
                    "function": function,
                },
                source_evidence_ids=[
                    evidence_id,
                ],
            )
        )

    for raw in result.get(
        "unattributed_sites",
        [],
    ):
        site = _mapping(raw)

        issues.append(
            LeadGenerationIssue(
                kind="unattributed-census-site",
                description=(
                    f"{peripheral} reference at "
                    f"{site.get('site')} "
                    f"(block {site.get('basic_block')}): "
                    f"{site.get('detail')}"
                ),
                reason=(
                    "census attributes this site to no "
                    "known function"
                ),
                source_evidence_ids=(
                    evidence_id,
                ),
            )
        )

    return LeadGenerationResult(
        leads=tuple(leads),
        issues=tuple(issues),
    )
