import pytest

from aptrace_agent.research import (
    EvidenceLedger,
    LeadFollower,
    LeadRegistry,
    LeadStatus,
    ResearchSession,
)
from aptrace_agent.schemas import EvidenceObservation


class RecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict, str]] = []

    def execute_operation(
        self,
        tool: str,
        arguments: dict,
        *,
        evidence_id: str,
    ) -> EvidenceObservation:
        self.calls.append(
            (
                tool,
                dict(arguments),
                evidence_id,
            )
        )

        return EvidenceObservation(
            id=evidence_id,
            tool=tool,
            arguments=dict(arguments),
            result={"ok": True},
        )


def test_ledger_allocates_authoritative_evidence_ids() -> None:
    ledger = EvidenceLedger()

    assert ledger.next_id() == "E1"

    ledger.add(
        EvidenceObservation(
            id="E1",
            tool="function_facts",
            arguments={
                "function": "FUN_0000d3dc",
            },
            result={"ok": True},
        )
    )

    assert ledger.next_id() == "E2"
    assert len(ledger) == 1
    assert ledger.get("E1").tool == "function_facts"


def test_ledger_rejects_out_of_sequence_ids() -> None:
    ledger = EvidenceLedger()

    with pytest.raises(
        ValueError,
        match="expected evidence id E1",
    ):
        ledger.add(
            EvidenceObservation(
                id="E7",
                tool="test",
                arguments={},
                result={},
            )
        )


def test_session_follow_lead_records_evidence_and_state() -> None:
    registry = LeadRegistry()

    lead = registry.register(
        kind="callsite",
        description="Inspect runtime caller",
        tool="callsite_context",
        arguments={
            "function": "FUN_00006968",
            "address": "0x000069a4",
            "before": 8,
            "after": 8,
        },
        source_evidence_ids=["E0"],
    )

    executor = RecordingExecutor()

    follower = LeadFollower(
        registry=registry,
        executor=executor,
    )

    session = ResearchSession(
        objective="Determine the role of the function.",
        registry=registry,
        follower=follower,
    )

    observation = session.follow_lead(
        lead.id
    )

    assert observation.id == "E1"
    assert session.state.evidence_ids == ["E1"]
    assert session.ledger.get("E1") == observation
    assert lead.status == LeadStatus.FOLLOWED

    assert executor.calls[0][2] == "E1"


def test_session_second_lead_gets_next_evidence_id() -> None:
    registry = LeadRegistry()

    first = registry.register(
        kind="callsite",
        description="First caller",
        tool="callsite_context",
        arguments={
            "function": "FUN_A",
            "address": "0x1000",
        },
    )

    second = registry.register(
        kind="callsite",
        description="Second caller",
        tool="callsite_context",
        arguments={
            "function": "FUN_B",
            "address": "0x2000",
        },
    )

    follower = LeadFollower(
        registry=registry,
        executor=RecordingExecutor(),
    )

    session = ResearchSession(
        objective="test",
        registry=registry,
        follower=follower,
    )

    assert session.follow_lead(first.id).id == "E1"
    assert session.follow_lead(second.id).id == "E2"

    assert session.state.evidence_ids == [
        "E1",
        "E2",
    ]
