from pathlib import Path
from types import SimpleNamespace

import pytest

from aptrace_agent.investigation_tools import (
    CallsiteContextReader,
    PinTableReader,
)
from aptrace_agent.schemas import Instruction


class FakeDisassembler:
    def function_disassembly(
        self,
        function: str,
    ):
        assert function == "FUN_00001000"

        return SimpleNamespace(
            instructions=[
                Instruction(
                    address="0x00001000",
                    size=2,
                    bytes_hex="01 20",
                    mnemonic="movs",
                    operands="r0, #1",
                ),
                Instruction(
                    address="0x00001002",
                    size=4,
                    bytes_hex="00 f0 7d f8",
                    mnemonic="bl",
                    operands="#0x1100",
                ),
                Instruction(
                    address="0x00001006",
                    size=2,
                    bytes_hex="00 28",
                    mnemonic="cmp",
                    operands="r0, #0",
                ),
            ]
        )


def test_callsite_context_exact_boundary():
    reader = CallsiteContextReader(
        FakeDisassembler()
    )

    result = reader.context(
        "FUN_00001000",
        "0x1002",
        before=1,
        after=1,
    )

    assert result.address == "0x00001002"

    assert [
        instruction.address
        for instruction in result.instructions
    ] == [
        "0x00001000",
        "0x00001002",
        "0x00001006",
    ]


def test_callsite_context_rejects_non_boundary():
    reader = CallsiteContextReader(
        FakeDisassembler()
    )

    with pytest.raises(ValueError):
        reader.context(
            "FUN_00001000",
            "0x1004",
        )


def test_pin_table_entry(tmp_path: Path):
    image = bytearray(0x200)

    flash_base = 0x4000
    table_base = 0x4040
    stride = 0x18

    # Entry 1 starts at file offset 0x58.
    offset = (
        table_base
        + stride
        - flash_base
    )

    row = bytearray(stride)

    # group 0 -> PORTA
    row[0] = 0

    # bit 22
    row[4:8] = (
        22
    ).to_bytes(
        4,
        "little",
    )

    # field +8 = 2
    row[8] = 2

    image[
        offset:
        offset + stride
    ] = row

    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(image)

    reader = PinTableReader(
        firmware,
        flash_base=flash_base,
        table_base=table_base,
        stride=stride,
    )

    result = reader.entry(1)

    assert result.index == 1
    assert result.group == 0
    assert result.bit == 22
    assert result.field_8 == 2
    assert result.gpio == "PA22"
    assert result.table_address == "0x00004058"
    assert result.file_offset == "0x00000058"


def test_pin_table_rejects_out_of_range(
    tmp_path: Path,
):
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"\x00" * 64)

    reader = PinTableReader(
        firmware,
        flash_base=0x4000,
        table_base=0x4040,
        stride=0x18,
    )

    with pytest.raises(ValueError):
        reader.entry(10)
