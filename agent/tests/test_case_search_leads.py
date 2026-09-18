from aptrace_agent.research import (
    LeadRegistry,
    generate_case_search_leads_from_pin_table,
)
from aptrace_agent.schemas import EvidenceObservation


def pin_observation(
    gpio: str | None = "PA22",
) -> EvidenceObservation:
    return EvidenceObservation(
        id="E4",
        tool="pin_table_entry",
        arguments={
            "index": 1,
        },
        result={
            "index": 1,
            "group": 0,
            "bit": 22,
            "gpio": gpio,
        },
    )


def test_pin_table_gpio_creates_case_search_lead() -> None:
    registry = LeadRegistry()

    leads = generate_case_search_leads_from_pin_table(
        pin_observation(),
        evidence_id="E4",
        registry=registry,
    )

    assert len(leads) == 1

    lead = leads[0]

    assert lead.kind == "case-evidence"
    assert lead.description == (
        "Search existing case evidence for observed GPIO PA22"
    )
    assert lead.source_evidence_ids == ["E4"]

    action = registry.resolve(lead.id)

    assert action.tool == "search_case_evidence"
    assert action.arguments == {
        "query": "PA22",
        "max_results": 8,
    }


def test_case_search_lead_does_not_add_semantic_terms() -> None:
    registry = LeadRegistry()

    lead = generate_case_search_leads_from_pin_table(
        pin_observation(),
        evidence_id="E4",
        registry=registry,
    )[0]

    action = registry.resolve(lead.id)

    query = action.arguments["query"].lower()

    assert query == "pa22"
    assert "trigger" not in query
    assert "startup" not in query
    assert "reference" not in query


def test_missing_gpio_does_not_create_case_search_lead() -> None:
    registry = LeadRegistry()

    assert generate_case_search_leads_from_pin_table(
        pin_observation(None),
        evidence_id="E4",
        registry=registry,
    ) == []


def test_non_pin_evidence_does_not_create_case_search_lead() -> None:
    registry = LeadRegistry()

    observation = EvidenceObservation(
        id="E3",
        tool="callsite_context",
        arguments={},
        result={},
    )

    assert generate_case_search_leads_from_pin_table(
        observation,
        evidence_id="E3",
        registry=registry,
    ) == []
