import pytest

from aptrace_agent.research import (
    Claim,
    ClaimGrade,
    LeadRegistry,
    LeadStatus,
    ResearchState,
)


def test_lead_hides_execution_payload_from_model_visible_data() -> None:
    registry = LeadRegistry()

    lead = registry.register(
        kind="callsite",
        description="Inspect a caller of the objective function",
        tool="callsite_context",
        arguments={
            "function": "FUN_00006968",
            "address": "0x000069a4",
            "before": 8,
            "after": 8,
        },
        source_evidence_ids=["E2"],
    )

    visible = lead.model_dump()

    assert visible["id"] == "L1"
    assert visible["description"] == "Inspect a caller of the objective function"

    serialized = str(visible)

    assert "callsite_context" not in serialized
    assert "0x000069a4" not in serialized
    assert "FUN_00006968" not in serialized


def test_registry_resolves_private_execution_payload() -> None:
    registry = LeadRegistry()

    lead = registry.register(
        kind="pin-table",
        description="Resolve the logical pin argument observed in firmware",
        tool="pin_table_entry",
        arguments={"index": 1},
        source_evidence_ids=["E3"],
    )

    action = registry.resolve(lead.id)

    assert action.tool == "pin_table_entry"
    assert action.arguments == {"index": 1}


def test_followed_lead_cannot_be_resolved_again() -> None:
    registry = LeadRegistry()

    lead = registry.register(
        kind="function",
        description="Inspect related function",
        tool="function_facts",
        arguments={"function": "FUN_0000d3dc"},
    )

    registry.mark_followed(lead.id)

    assert lead.status == LeadStatus.FOLLOWED

    with pytest.raises(ValueError, match="not open"):
        registry.resolve(lead.id)


def test_research_state_tracks_evidence_claims_and_leads() -> None:
    state = ResearchState(
        objective="Determine the role of FUN_0000d3dc(1)."
    )

    state.add_evidence("E1")
    state.add_evidence("E1")
    state.add_evidence("E2")

    state.claims.append(
        Claim(
            id="C1",
            statement="The function performs a read-only GPIO state read.",
            grade=ClaimGrade.PROVEN,
            evidence_ids=["E2"],
        )
    )

    registry = LeadRegistry()

    lead = registry.register(
        kind="callsite",
        description="Inspect a runtime caller",
        tool="callsite_context",
        arguments={
            "function": "FUN_00006968",
            "address": "0x000069a4",
        },
        source_evidence_ids=["E2"],
    )

    state.add_lead(lead)

    assert state.evidence_ids == ["E1", "E2"]
    assert state.claims[0].grade == ClaimGrade.PROVEN
    assert state.open_leads() == [lead]


def test_research_state_rejects_duplicate_lead_ids() -> None:
    state = ResearchState(objective="test")
    registry = LeadRegistry()

    lead = registry.register(
        kind="function",
        description="Inspect function",
        tool="function_facts",
        arguments={"function": "FUN_0000d3dc"},
    )

    state.add_lead(lead)

    with pytest.raises(ValueError, match="duplicate lead id"):
        state.add_lead(lead)
