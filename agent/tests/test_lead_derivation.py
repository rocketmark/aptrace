from aptrace_agent.research import (
    LeadDeriver,
    LeadRegistry,
)
from aptrace_agent.schemas import EvidenceObservation


class AcceptingCallsiteReader:
    def context(
        self,
        function: str,
        address: int | str,
        before: int = 8,
        after: int = 8,
    ) -> object:
        return object()


def test_deriver_turns_function_facts_into_callsite_lead() -> None:
    registry = LeadRegistry()

    deriver = LeadDeriver(
        registry=registry,
        callsite_reader=AcceptingCallsiteReader(),
    )

    observation = EvidenceObservation(
        id="E1",
        tool="function_facts",
        arguments={
            "function": "FUN_0000d3dc",
        },
        result={
            "name": "FUN_0000d3dc",
            "callers": [
                {
                    "function": "FUN_00006968",
                    "address": "0x000069a4",
                }
            ],
        },
    )

    result = deriver.derive(
        observation
    )

    assert len(result.leads) == 1

    action = registry.resolve(
        result.leads[0].id
    )

    assert action.tool == "callsite_context"
    assert action.arguments["address"] == (
        "0x000069a4"
    )


def test_deriver_turns_callsite_literal_into_pin_lead() -> None:
    registry = LeadRegistry()

    deriver = LeadDeriver(
        registry=registry,
        callsite_reader=AcceptingCallsiteReader(),
    )

    observation = EvidenceObservation(
        id="E3",
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
            ],
        },
    )

    result = deriver.derive(
        observation
    )

    assert len(result.leads) == 1

    action = registry.resolve(
        result.leads[0].id
    )

    assert action.tool == "pin_table_entry"
    assert action.arguments == {
        "index": 1,
    }


def test_deriver_turns_pin_result_into_case_search_lead() -> None:
    registry = LeadRegistry()

    deriver = LeadDeriver(
        registry=registry,
        callsite_reader=AcceptingCallsiteReader(),
    )

    observation = EvidenceObservation(
        id="E4",
        tool="pin_table_entry",
        arguments={
            "index": 1,
        },
        result={
            "index": 1,
            "gpio": "PA22",
        },
    )

    result = deriver.derive(
        observation
    )

    assert len(result.leads) == 1

    action = registry.resolve(
        result.leads[0].id
    )

    assert action.tool == "search_case_evidence"
    assert action.arguments["query"] == "PA22"


def test_registry_deduplicates_same_action_and_merges_provenance() -> None:
    registry = LeadRegistry()

    first = registry.register(
        kind="pin-table",
        description="Resolve argument 1",
        tool="pin_table_entry",
        arguments={
            "index": 1,
        },
        source_evidence_ids=[
            "E3",
        ],
    )

    second = registry.register(
        kind="pin-table",
        description="Resolve argument 1 again",
        tool="pin_table_entry",
        arguments={
            "index": 1,
        },
        source_evidence_ids=[
            "E5",
        ],
    )

    assert first.id == second.id
    assert first.source_evidence_ids == [
        "E3",
        "E5",
    ]
