from types import SimpleNamespace

import pytest

from aptrace_agent.research import (
    CaseReconciler,
    LeadFollower,
    LeadRegistry,
    ResearchSession,
)
from aptrace_agent.schemas import EvidenceObservation


class NeverExecutor:
    def execute_operation(
        self,
        tool,
        arguments,
        evidence_id,
    ):
        raise AssertionError("not used")


class FakeCompletions:
    def __init__(self, content):
        self.content = content

    def create(self, **kwargs):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=self.content
                    )
                )
            ]
        )


class FakeClient:
    def __init__(self, content):
        self.chat = SimpleNamespace(
            completions=FakeCompletions(
                content
            )
        )


def make_session():
    registry = LeadRegistry()

    session = ResearchSession(
        objective="test",
        registry=registry,
        follower=LeadFollower(
            registry=registry,
            executor=NeverExecutor(),
        ),
    )

    session.record(
        EvidenceObservation(
            id="E1",
            tool="pin_table_entry",
            arguments={"index": 1},
            result={
                "index": 1,
                "gpio": "PA22",
                "group": 0,
                "bit": 22,
            },
        )
    )

    session.record(
        EvidenceObservation(
            id="E2",
            tool="search_case_evidence",
            arguments={
                "query": "PA22"
            },
            result={
                "query": "PA22",
                "matches": [],
                "files_scanned": 1,
                "truncated": False,
            },
        )
    )

    return session


def test_supported_reconciliation_ingests_claim():
    session = make_session()

    content = """
{
  "reconciliations": [
    {
      "query": "PA22",
      "status": "SUPPORTED",
      "role": "startup reference/input",
      "context": "It is later polled as a held-input check.",
      "proven_claim_ids": ["C1"],
      "case_evidence_ids": ["E2"],
      "unresolved": [
        "What physical component is connected to PA22?"
      ]
    }
  ]
}
"""

    reconciler = CaseReconciler(
        client=FakeClient(content),
        model="test",
    )

    reconciler.run(session)

    supported = [
        claim
        for claim in session.state.claims
        if claim.grade.value
        == "SUPPORTED"
    ]

    assert len(supported) == 1
    assert "startup reference/input" in (
        supported[0].statement
    )

    assert (
        session.state.open_questions[0]
        .question
        == "What physical component is connected to PA22?"
    )


def test_reconciliation_must_cover_every_query():
    session = make_session()

    content = """
{
  "reconciliations": []
}
"""

    reconciler = CaseReconciler(
        client=FakeClient(content),
        model="test",
    )

    with pytest.raises(
        RuntimeError,
        match="semantic validation twice",
    ):
        reconciler.run(session)


def test_supported_reconciliation_requires_proven_claim():
    session = make_session()

    content = """
{
  "reconciliations": [
    {
      "query": "PA22",
      "status": "SUPPORTED",
      "role": "startup input",
      "context": null,
      "proven_claim_ids": [],
      "case_evidence_ids": ["E2"],
      "unresolved": []
    }
  ]
}
"""

    reconciler = CaseReconciler(
        client=FakeClient(content),
        model="test",
    )

    with pytest.raises(
        RuntimeError,
        match="semantic validation twice",
    ):
        reconciler.run(session)
