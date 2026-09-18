import pytest

from aptrace_agent.research import (
    LeadFollower,
    LeadRegistry,
    LeadStatus,
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
            result={
                "observed": True,
            },
        )


class FailingExecutor:
    def execute_operation(
        self,
        tool: str,
        arguments: dict,
        *,
        evidence_id: str,
    ) -> EvidenceObservation:
        raise ValueError("execution failed")


def test_follow_lead_executes_private_action() -> None:
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
        source_evidence_ids=["E2"],
    )

    executor = RecordingExecutor()

    follower = LeadFollower(
        registry=registry,
        executor=executor,
    )

    observation = follower.follow(
        lead.id,
        evidence_id="E3",
    )

    assert observation.id == "E3"
    assert observation.tool == "callsite_context"

    assert executor.calls == [
        (
            "callsite_context",
            {
                "function": "FUN_00006968",
                "address": "0x000069a4",
                "before": 8,
                "after": 8,
            },
            "E3",
        )
    ]

    assert lead.status == LeadStatus.FOLLOWED


def test_followed_lead_cannot_execute_twice() -> None:
    registry = LeadRegistry()

    lead = registry.register(
        kind="callsite",
        description="Inspect runtime caller",
        tool="callsite_context",
        arguments={
            "function": "FUN_00006968",
            "address": "0x000069a4",
        },
    )

    executor = RecordingExecutor()

    follower = LeadFollower(
        registry=registry,
        executor=executor,
    )

    follower.follow(
        lead.id,
        evidence_id="E1",
    )

    with pytest.raises(
        ValueError,
        match="not open",
    ):
        follower.follow(
            lead.id,
            evidence_id="E2",
        )

    assert len(executor.calls) == 1


def test_failed_execution_leaves_lead_open() -> None:
    registry = LeadRegistry()

    lead = registry.register(
        kind="callsite",
        description="Inspect runtime caller",
        tool="callsite_context",
        arguments={
            "function": "FUN_00006968",
            "address": "0x000069a4",
        },
    )

    follower = LeadFollower(
        registry=registry,
        executor=FailingExecutor(),
    )

    with pytest.raises(
        ValueError,
        match="execution failed",
    ):
        follower.follow(
            lead.id,
            evidence_id="E1",
        )

    assert lead.status == LeadStatus.OPEN

    action = registry.resolve(lead.id)

    assert action.tool == "callsite_context"
