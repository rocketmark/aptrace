from aptrace_agent.research import (
    LeadRegistry,
    generate_pin_table_leads_from_callsite,
)
from aptrace_agent.schemas import EvidenceObservation


def callsite_observation(
    *,
    evidence_id: str = "E4",
    immediate: str = "#1",
) -> EvidenceObservation:
    return EvidenceObservation(
        id=evidence_id,
        tool="callsite_context",
        arguments={
            "function": "FUN_00006968",
            "address": "0x000069a4",
        },
        result={
            "function": "FUN_00006968",
            "address": "0x000069a4",
            "before": 8,
            "after": 8,
            "instructions": [
                {
                    "address": "0x0000699e",
                    "size": 4,
                    "bytes_hex": "",
                    "mnemonic": "bl",
                    "operands": "#0xd300",
                },
                {
                    "address": "0x000069a2",
                    "size": 2,
                    "bytes_hex": "",
                    "mnemonic": "movs",
                    "operands": f"r0, {immediate}",
                },
                {
                    "address": "0x000069a4",
                    "size": 4,
                    "bytes_hex": "",
                    "mnemonic": "bl",
                    "operands": "#0xd3dc",
                },
            ],
        },
    )


def test_callsite_literal_creates_pin_table_lead() -> None:
    registry = LeadRegistry()

    leads = generate_pin_table_leads_from_callsite(
        callsite_observation(),
        evidence_id="E4",
        registry=registry,
    )

    assert len(leads) == 1

    lead = leads[0]

    assert lead.kind == "pin-table"
    assert "argument 1" in lead.description
    assert lead.source_evidence_ids == ["E4"]

    action = registry.resolve(lead.id)

    assert action.tool == "pin_table_entry"
    assert action.arguments == {
        "index": 1,
    }


def test_hex_literal_is_parsed() -> None:
    registry = LeadRegistry()

    leads = generate_pin_table_leads_from_callsite(
        callsite_observation(
            immediate="#0x25",
        ),
        evidence_id="E3",
        registry=registry,
    )

    action = registry.resolve(
        leads[0].id
    )

    assert action.arguments == {
        "index": 0x25,
    }


def test_non_immediate_r0_write_does_not_create_lead() -> None:
    observation = callsite_observation()

    observation.result["instructions"][-2][
        "mnemonic"
    ] = "ldr"

    observation.result["instructions"][-2][
        "operands"
    ] = "r0, [r4]"

    registry = LeadRegistry()

    leads = generate_pin_table_leads_from_callsite(
        observation,
        evidence_id="E4",
        registry=registry,
    )

    assert leads == []


def test_non_callsite_evidence_does_not_create_lead() -> None:
    observation = EvidenceObservation(
        id="E2",
        tool="function_disassembly",
        arguments={
            "function": "FUN_0000d3dc",
        },
        result={
            "instructions": [],
        },
    )

    registry = LeadRegistry()

    leads = generate_pin_table_leads_from_callsite(
        observation,
        evidence_id="E2",
        registry=registry,
    )

    assert leads == []
