from __future__ import annotations

from pathlib import Path

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_MCLASS,
    CS_MODE_THUMB,
)

from aptrace_agent.ghidra_index import GhidraIndex, autopilot_ghidra_index
from aptrace_agent.schemas import FunctionDisassembly, Instruction


class ThumbFunctionDisassembler:
    """
    Decode raw firmware bytes using Ghidra-derived function bounds.

    Function identity, entry, and size come from the Ghidra index.
    Instruction decoding is performed locally with Capstone in ARM M-class
    Thumb mode.
    """

    def __init__(
        self,
        firmware: Path,
        ghidra: GhidraIndex,
        *,
        flash_base: int = 0,
    ) -> None:
        self.firmware = firmware
        self.ghidra = ghidra
        self.flash_base = flash_base
        self._image = firmware.read_bytes()

        self._decoder = Cs(
            CS_ARCH_ARM,
            CS_MODE_THUMB | CS_MODE_MCLASS,
        )

    def function_disassembly(
        self,
        function: str,
    ) -> FunctionDisassembly:
        facts = self.ghidra.function_facts(function)

        if facts.size is None:
            raise ValueError(
                f"No function size available for {function}"
            )

        entry = int(facts.entry, 16)
        size = facts.size

        offset = entry - self.flash_base

        if offset < 0:
            raise ValueError(
                f"{function} entry is below flash base"
            )

        end = offset + size

        if end > len(self._image):
            raise ValueError(
                f"{function} extends beyond firmware image"
            )

        blob = self._image[offset:end]

        instructions: list[Instruction] = []
        bytes_decoded = 0

        for insn in self._decoder.disasm(blob, entry):
            instructions.append(
                Instruction(
                    address=f"0x{insn.address:08x}",
                    size=insn.size,
                    bytes_hex=insn.bytes.hex(" "),
                    mnemonic=insn.mnemonic,
                    operands=insn.op_str,
                )
            )

            bytes_decoded += insn.size

        return FunctionDisassembly(
            name=function,
            entry=facts.entry,
            size=size,
            architecture="ARM Cortex-M4F",
            mode="Thumb/Thumb-2 M-class",
            bounds_source="Ghidra function metadata",
            decoder="Capstone",
            bytes_requested=len(blob),
            bytes_decoded=bytes_decoded,
            complete=(bytes_decoded == len(blob)),
            instructions=instructions,
        )


def autopilot_disassembler() -> ThumbFunctionDisassembler:
    repo_root = Path(__file__).resolve().parents[3]

    firmware = (
        repo_root
        / "cases"
        / "performing-rigs"
        / "research"
        / "firmware"
        / "vendor-package"
        / "firmware_autopilot868.bin"
    )

    if not firmware.is_file():
        raise FileNotFoundError(firmware)

    return ThumbFunctionDisassembler(
        firmware=firmware,
        ghidra=autopilot_ghidra_index(),
        flash_base=0x4000,
    )
