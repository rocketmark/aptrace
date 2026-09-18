from aptrace_agent.research import (
    ClaimGrade,
    ResearchState,
    StateFactDeriver,
)
from aptrace_agent.schemas import EvidenceObservation


def test_pin_mapping_becomes_proven_claim() -> None:
    state = ResearchState(
        objective="test"
    )

    observation = EvidenceObservation(
        id="E7",
        tool="pin_table_entry",
        arguments={
            "index": 1,
        },
        result={
            "index": 1,
            "gpio": "PA22",
            "group": 0,
            "bit": 22,
        },
    )

    result = StateFactDeriver().derive(
        observation,
        state,
    )

    assert len(result.claims) == 1

    claim = result.claims[0]

    assert claim.grade == ClaimGrade.PROVEN
    assert claim.statement == (
        "Logical pin-table index 1 maps "
        "to GPIO PA22 (group 0, bit 22)."
    )
    assert claim.evidence_ids == [
        "E7",
    ]


def test_callsite_literal_becomes_proven_claim() -> None:
    state = ResearchState(
        objective="test"
    )

    observation = EvidenceObservation(
        id="E5",
        tool="callsite_context",
        arguments={},
        result={
            "function": "FUN_00006968",
            "address": "0x000069a4",
            "instructions": [
                {
                    "address": "0x000069a2",
                    "mnemonic": "movs",
                    "operands": "r0, #1",
                },
                {
                    "address": "0x000069a4",
                    "mnemonic": "bl",
                    "operands": "#0xd3dc",
                },
                {
                    "address": "0x000069a8",
                    "mnemonic": "cbz",
                    "operands": "r0, #0x69ae",
                },
            ],
        },
    )

    result = StateFactDeriver().derive(
        observation,
        state,
    )

    assert len(result.claims) == 1

    claim = result.claims[0]

    assert claim.grade == ClaimGrade.PROVEN
    assert claim.statement == (
        "FUN_00006968 calls #0xd3dc at "
        "0x000069a4 with r0 literal 1 (0x1)."
    )
    assert claim.evidence_ids == [
        "E5",
    ]


def test_non_immediate_r0_is_not_promoted() -> None:
    state = ResearchState(
        objective="test"
    )

    observation = EvidenceObservation(
        id="E1",
        tool="callsite_context",
        arguments={},
        result={
            "function": "FUN_1",
            "address": "0x1004",
            "instructions": [
                {
                    "address": "0x1000",
                    "mnemonic": "ldr",
                    "operands": "r0, [r4]",
                },
                {
                    "address": "0x1004",
                    "mnemonic": "bl",
                    "operands": "#0x2000",
                },
            ],
        },
    )

    result = StateFactDeriver().derive(
        observation,
        state,
    )

    assert result.claims == ()
    assert state.claims == []
