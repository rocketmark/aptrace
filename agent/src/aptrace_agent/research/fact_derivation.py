from __future__ import annotations

from dataclasses import dataclass

from aptrace_agent.research.state import (
    Claim,
    ClaimGrade,
    ResearchState,
)
from aptrace_agent.research.state_updates import (
    ResearchStateUpdater,
)
from aptrace_agent.schemas import EvidenceObservation


@dataclass(frozen=True)
class FactDerivationResult:
    claims: tuple[Claim, ...]


def _direct_r0_literal(
    observation: EvidenceObservation,
) -> int | None:
    if observation.tool != "callsite_context":
        return None

    result = observation.result
    instructions = result.get(
        "instructions",
        [],
    )
    callsite = result.get("address")

    call_index = None

    for index, instruction in enumerate(
        instructions
    ):
        if (
            instruction.get("address")
            == callsite
        ):
            call_index = index
            break

    if call_index is None:
        return None

    for instruction in reversed(
        instructions[:call_index]
    ):
        operands = str(
            instruction.get(
                "operands",
                "",
            )
        ).strip()

        parts = [
            part.strip()
            for part in operands.split(",")
        ]

        if not parts:
            continue

        if parts[0].lower() != "r0":
            continue

        mnemonic = str(
            instruction.get(
                "mnemonic",
                "",
            )
        ).lower()

        if mnemonic not in {
            "mov",
            "movs",
            "mov.w",
            "movs.w",
        }:
            return None

        if len(parts) < 2:
            return None

        immediate = parts[1]

        if not immediate.startswith("#"):
            return None

        try:
            return int(
                immediate[1:],
                0,
            )
        except ValueError:
            return None

    return None


def _call_target(
    observation: EvidenceObservation,
) -> str | None:
    if observation.tool != "callsite_context":
        return None

    result = observation.result
    callsite = result.get("address")

    for instruction in result.get(
        "instructions",
        [],
    ):
        if (
            instruction.get("address")
            != callsite
        ):
            continue

        mnemonic = str(
            instruction.get(
                "mnemonic",
                "",
            )
        ).lower()

        if not mnemonic.startswith("bl"):
            return None

        target = str(
            instruction.get(
                "operands",
                "",
            )
        ).strip()

        return target or None

    return None


MAX_CENSUS_FUNCTION_CLAIMS = 4
MAX_CENSUS_UNATTRIBUTED_CLAIMS = 2


def _census_location(
    value: str | None,
    register: str | None,
    peripheral: str,
    base: str | None,
) -> str:
    """Short, unambiguous name for a peripheral address."""

    if value is None:
        return peripheral

    try:
        offset = int(value, 16) - int(str(base), 16)
    except (TypeError, ValueError):
        offset = None

    if offset == 0:
        return f"{value} ({peripheral} base)"

    if register and "/" not in register:
        return f"{value} ({register})"

    if offset is not None:
        return f"{value} ({peripheral}+0x{offset:x})"

    return value


def _census_claims(
    observation: EvidenceObservation,
) -> list[str]:
    """
    Atomic structural statements supported by one census peripheral
    analysis. Nothing here names the external device on the bus.
    """

    result = observation.result
    status = result.get("status")
    peripheral = str(result.get("peripheral", ""))
    base = result.get("peripheral_base")
    provenance = result.get("provenance") or {}
    reduction = provenance.get("reduction_status")

    if status == "no_matching_accesses":
        return [
            f"The census contains no constant-address MMIO site and no "
            f"aligned flash address constant for {peripheral} "
            f"(bounded static analysis; runtime-computed addresses "
            f"are not excluded)."
        ]

    if status == "no_code_references":
        return [
            f"{peripheral} addresses appear only in "
            f"{result.get('total_address_constants', 0)} aligned flash "
            f"data word(s) that no census instruction references; the "
            f"census has no constant-address MMIO site for {peripheral} "
            f"(bounded static analysis; indexed table access is not "
            f"excluded)."
        ]

    if status != "ok":
        return []

    statements = [
        f"Census structural usage of {peripheral}: "
        f"{result.get('total_mmio_sites', 0)} constant-address MMIO "
        f"site(s), {result.get('total_address_constants', 0)} flash "
        f"address constant(s) "
        f"({result.get('unreferenced_address_constants', 0)} with no "
        f"code reference), {result.get('total_functions', 0)} "
        f"attributed function(s), "
        f"{len(result.get('unattributed_sites') or [])} unattributed "
        f"reference site(s) (reduction {reduction})."
    ]

    for item in (result.get("functions") or [])[
        :MAX_CENSUS_FUNCTION_CLAIMS
    ]:
        parts: list[str] = []
        sites = item.get("mmio_sites") or []

        if sites:
            accesses = sorted(
                {
                    f"{site.get('register_name') or site.get('address')} "
                    f"{site.get('direction')}"
                    for site in sites
                }
            )

            parts.append(
                f"has {item.get('mmio_site_count')} statically "
                f"resolved {peripheral} MMIO site(s) "
                f"({', '.join(accesses[:4])}"
                f"{', ...' if len(accesses) > 4 else ''})"
            )

        loads = item.get("constant_loads") or []

        if loads:
            first = loads[0]
            parts.append(
                f"loads {peripheral} address constant "
                + _census_location(
                    first.get("value"),
                    first.get("register_name"),
                    peripheral,
                    base,
                )
                + f" at {first.get('site')}"
                + (
                    f" (+{len(loads) - 1} more load site(s))"
                    if len(loads) > 1
                    else ""
                )
            )

        reach = item.get("reachability")

        if reach:
            parts.append(
                f"census reachability {reach.get('status')}"
            )

        if parts:
            statements.append(
                f"{item.get('function')} " + "; ".join(parts) + "."
            )

    for site in (result.get("unattributed_sites") or [])[
        :MAX_CENSUS_UNATTRIBUTED_CLAIMS
    ]:
        statements.append(
            f"Code at {site.get('site')} (basic block "
            f"{site.get('basic_block')}, attributed to no census "
            f"function) references {peripheral}: {site.get('detail')}."
        )

    return statements


class StateFactDeriver:
    """
    Convert structurally explicit evidence into atomic PROVEN claims.

    No semantic role interpretation occurs here. Those judgments belong
    to the research reviewer.
    """

    def __init__(
        self,
        *,
        updater: ResearchStateUpdater | None = None,
    ) -> None:
        self.updater = (
            updater
            or ResearchStateUpdater()
        )

    def derive(
        self,
        observation: EvidenceObservation,
        state: ResearchState,
    ) -> FactDerivationResult:
        claims: list[Claim] = []

        if observation.tool == "pin_table_entry":
            result = observation.result

            index = result.get("index")
            gpio = result.get("gpio")
            group = result.get("group")
            bit = result.get("bit")

            if (
                index is not None
                and gpio
                and group is not None
                and bit is not None
            ):
                claim = (
                    self.updater.merge_claim(
                        state,
                        statement=(
                            "Logical pin-table index "
                            f"{index} maps to GPIO "
                            f"{gpio} "
                            f"(group {group}, bit {bit})."
                        ),
                        grade=ClaimGrade.PROVEN,
                        evidence_ids=[
                            observation.id,
                        ],
                    )
                )

                claims.append(claim)

        if observation.tool == "callsite_context":
            literal = _direct_r0_literal(
                observation
            )

            target = _call_target(
                observation
            )

            result = observation.result
            function = result.get(
                "function"
            )
            address = result.get(
                "address"
            )

            if (
                literal is not None
                and function
                and address
                and target
            ):
                claim = (
                    self.updater.merge_claim(
                        state,
                        statement=(
                            f"{function} calls "
                            f"{target} at "
                            f"{address} with "
                            f"r0 literal {literal} "
                            f"(0x{literal:x})."
                        ),
                        grade=ClaimGrade.PROVEN,
                        evidence_ids=[
                            observation.id,
                        ],
                    )
                )

                claims.append(claim)

        if observation.tool == "census_peripheral_usage":
            for statement in _census_claims(
                observation
            ):
                claims.append(
                    self.updater.merge_claim(
                        state,
                        statement=statement,
                        grade=ClaimGrade.PROVEN,
                        evidence_ids=[
                            observation.id,
                        ],
                    )
                )

        return FactDerivationResult(
            claims=tuple(claims)
        )
