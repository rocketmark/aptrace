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

        return FactDerivationResult(
            claims=tuple(claims)
        )
