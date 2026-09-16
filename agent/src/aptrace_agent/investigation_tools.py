from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel

from aptrace_agent.disassembly import autopilot_disassembler
from aptrace_agent.schemas import Instruction


class CallsiteContext(BaseModel):
    function: str
    address: str
    before: int
    after: int
    instructions: list[Instruction]


class CallsiteContextReader:
    """
    Bounded instruction context around one exact instruction address.

    The caller supplies:
      - a known function
      - one exact instruction address
      - small before/after windows

    No arbitrary address-range dumping is exposed.
    """

    MAX_CONTEXT = 16

    def __init__(self, disassembler: Any):
        self.disassembler = disassembler

    def context(
        self,
        function: str,
        address: int | str,
        before: int = 8,
        after: int = 8,
    ) -> CallsiteContext:
        if not 0 <= before <= self.MAX_CONTEXT:
            raise ValueError(
                f"before must be between 0 and "
                f"{self.MAX_CONTEXT}"
            )

        if not 0 <= after <= self.MAX_CONTEXT:
            raise ValueError(
                f"after must be between 0 and "
                f"{self.MAX_CONTEXT}"
            )

        target = self._parse_address(address)

        disassembly = (
            self.disassembler.function_disassembly(
                function
            )
        )

        instructions = disassembly.instructions

        index = None

        for i, instruction in enumerate(instructions):
            current = int(
                instruction.address,
                16,
            )

            if current == target:
                index = i
                break

        if index is None:
            raise ValueError(
                f"address 0x{target:08x} is not an "
                f"instruction boundary inside {function}"
            )

        start = max(
            0,
            index - before,
        )

        end = min(
            len(instructions),
            index + after + 1,
        )

        return CallsiteContext(
            function=function,
            address=f"0x{target:08x}",
            before=before,
            after=after,
            instructions=instructions[start:end],
        )

    @staticmethod
    def _parse_address(
        address: int | str,
    ) -> int:
        if isinstance(address, int):
            if address < 0:
                raise ValueError(
                    "address must not be negative"
                )

            return address

        text = address.strip()

        try:
            return int(text, 0)
        except ValueError as exc:
            raise ValueError(
                f"invalid address: {address!r}"
            ) from exc


class PinTableEntry(BaseModel):
    index: int
    table_address: str
    file_offset: str
    raw_hex: str
    group: int
    bit: int
    field_8: int
    gpio: str | None


class PinTableReader:
    """
    Read-only decoder for the Arduino-style pin-description table used
    by FUN_0000d3dc.

    Only the fields actually established by disassembly are named:
      +0  signed group index
      +4  bit number
      +8  signed field used by digitalRead validity handling

    We intentionally do not assign semantics to the remaining bytes.
    """

    MAX_INDEX = 127

    def __init__(
        self,
        firmware_path: Path,
        *,
        flash_base: int,
        table_base: int,
        stride: int,
    ):
        self.firmware_path = firmware_path
        self.flash_base = flash_base
        self.table_base = table_base
        self.stride = stride

    def entry(
        self,
        index: int,
    ) -> PinTableEntry:
        if not 0 <= index <= self.MAX_INDEX:
            raise ValueError(
                f"index must be between 0 and "
                f"{self.MAX_INDEX}"
            )

        image = self.firmware_path.read_bytes()

        address = (
            self.table_base
            + index * self.stride
        )

        offset = address - self.flash_base

        if offset < 0:
            raise ValueError(
                "pin-table address precedes firmware "
                "file mapping"
            )

        end = offset + self.stride

        if end > len(image):
            raise ValueError(
                f"pin-table entry {index} falls "
                "outside firmware image"
            )

        row = image[offset:end]

        group = int.from_bytes(
            row[0:1],
            "little",
            signed=True,
        )

        bit = int.from_bytes(
            row[4:8],
            "little",
            signed=False,
        )

        field_8 = int.from_bytes(
            row[8:9],
            "little",
            signed=True,
        )

        gpio = self._gpio_name(
            group,
            bit,
        )

        return PinTableEntry(
            index=index,
            table_address=f"0x{address:08x}",
            file_offset=f"0x{offset:08x}",
            raw_hex=row.hex(" "),
            group=group,
            bit=bit,
            field_8=field_8,
            gpio=gpio,
        )

    @staticmethod
    def _gpio_name(
        group: int,
        bit: int,
    ) -> str | None:
        if not 0 <= group <= 25:
            return None

        if not 0 <= bit <= 31:
            return None

        port = chr(
            ord("A") + group
        )

        return f"P{port}{bit:02d}"


def performing_rigs_callsite_context(
) -> CallsiteContextReader:
    return CallsiteContextReader(
        autopilot_disassembler()
    )


def performing_rigs_pin_table(
) -> PinTableReader:
    repo_root = (
        Path(__file__)
        .resolve()
        .parents[3]
    )

    firmware = (
        repo_root
        / "cases"
        / "performing-rigs"
        / "research"
        / "firmware"
        / "vendor-package"
        / "firmware_autopilot868.bin"
    )

    return PinTableReader(
        firmware,
        flash_base=0x4000,
        table_base=0x14284,
        stride=0x18,
    )
