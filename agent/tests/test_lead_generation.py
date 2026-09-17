from typing import Any

from aptrace_agent.research import (
    LeadRegistry,
    generate_function_fact_leads,
)


class AcceptingCallsiteReader:
    def context(
        self,
        function: str,
        address: int | str,
        before: int = 8,
        after: int = 8,
    ) -> object:
        return object()


class SelectiveCallsiteReader:
    def __init__(self, rejected: set[str]) -> None:
        self.rejected = rejected

    def context(
        self,
        function: str,
        address: int | str,
        before: int = 8,
        after: int = 8,
    ) -> object:
        address_text = str(address)

        if address_text in self.rejected:
            raise ValueError(
                f"{address_text} is not an instruction boundary "
                f"inside {function}"
            )

        return object()


def test_function_facts_generate_callsite_leads() -> None:
    facts = {
        "name": "FUN_0000d3dc",
        "callers": [
            {
                "function": "FUN_00006968",
                "address": "0x69a4",
            },
            {
                "function": "FUN_00008e18",
                "address": "0x91ca",
            },
        ],
    }

    registry = LeadRegistry()

    result = generate_function_fact_leads(
        facts,
        evidence_id="E2",
        registry=registry,
        callsite_reader=AcceptingCallsiteReader(),
    )

    assert [lead.id for lead in result.leads] == [
        "L1",
        "L2",
    ]

    assert (
        result.leads[0].description
        == "Inspect incoming call to FUN_0000d3dc from "
        "FUN_00006968 at 0x000069a4"
    )

    assert result.leads[0].source_evidence_ids == ["E2"]
    assert result.issues == ()


def test_callsite_lead_keeps_execution_payload_private() -> None:
    facts = {
        "name": "FUN_0000d3dc",
        "callers": [
            {
                "function": "FUN_00006968",
                "address": 0x69A4,
            }
        ],
    }

    registry = LeadRegistry()

    result = generate_function_fact_leads(
        facts,
        evidence_id="E2",
        registry=registry,
        callsite_reader=AcceptingCallsiteReader(),
    )

    lead = result.leads[0]
    visible = lead.model_dump()

    assert "FUN_00006968" in visible["description"]
    assert "0x000069a4" in visible["description"]
    assert "tool" not in visible
    assert "arguments" not in visible

    action = registry.resolve(lead.id)

    assert action.tool == "callsite_context"
    assert action.arguments == {
        "function": "FUN_00006968",
        "address": "0x000069a4",
        "before": 8,
        "after": 8,
    }


def test_duplicate_callsites_generate_one_lead() -> None:
    facts = {
        "name": "FUN_0000d3dc",
        "callers": [
            {
                "function": "FUN_00006968",
                "address": "0x69a4",
            },
            {
                "function": "FUN_00006968",
                "address": "0x000069a4",
            },
        ],
    }

    registry = LeadRegistry()

    result = generate_function_fact_leads(
        facts,
        evidence_id="E2",
        registry=registry,
        callsite_reader=AcceptingCallsiteReader(),
    )

    assert len(result.leads) == 1
    assert result.leads[0].id == "L1"


def test_invalid_callsite_becomes_issue_not_lead() -> None:
    facts = {
        "name": "FUN_0000d3dc",
        "callers": [
            {
                "function": "FUN_00006968",
                "address": "0x69a4",
            },
            {
                "function": "FUN_000093fc",
                "address": "0x78f2",
            },
        ],
    }

    registry = LeadRegistry()

    result = generate_function_fact_leads(
        facts,
        evidence_id="E2",
        registry=registry,
        callsite_reader=SelectiveCallsiteReader(
            {"0x000078f2"}
        ),
    )

    assert len(result.leads) == 1
    assert len(result.issues) == 1

    issue = result.issues[0]

    assert issue.kind == "invalid-callsite"
    assert "FUN_000093fc" in issue.description
    assert "0x000078f2" in issue.description
    assert "not an instruction boundary" in issue.reason
    assert issue.source_evidence_ids == ("E2",)

    assert registry.resolve("L1").arguments["address"] == (
        "0x000069a4"
    )
