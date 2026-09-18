from aptrace_agent.research import (
    ClaimGrade,
    ResearchState,
    ResearchStateUpdater,
)


def test_updater_allocates_claim_ids() -> None:
    state = ResearchState(
        objective="test"
    )

    updater = ResearchStateUpdater()

    first = updater.merge_claim(
        state,
        statement="First fact.",
        grade=ClaimGrade.PROVEN,
        evidence_ids=["E1"],
    )

    second = updater.merge_claim(
        state,
        statement="Second fact.",
        grade=ClaimGrade.SUPPORTED,
        evidence_ids=["E2"],
    )

    assert first.id == "C1"
    assert second.id == "C2"


def test_updater_merges_same_claim_and_provenance() -> None:
    state = ResearchState(
        objective="test"
    )

    updater = ResearchStateUpdater()

    first = updater.merge_claim(
        state,
        statement="The function reads one bit.",
        grade=ClaimGrade.SUPPORTED,
        evidence_ids=["E1"],
    )

    second = updater.merge_claim(
        state,
        statement="  The function reads one bit.  ",
        grade=ClaimGrade.PROVEN,
        evidence_ids=["E2"],
    )

    assert first is second
    assert len(state.claims) == 1
    assert state.claims[0].grade == (
        ClaimGrade.PROVEN
    )
    assert state.claims[0].evidence_ids == [
        "E1",
        "E2",
    ]


def test_updater_allocates_other_state_ids() -> None:
    state = ResearchState(
        objective="test"
    )

    updater = ResearchStateUpdater()

    hypothesis = (
        updater.merge_hypothesis(
            state,
            statement="Possible interpretation.",
            evidence_ids=["E1"],
        )
    )

    contradiction = (
        updater.merge_contradiction(
            state,
            description="Sources disagree.",
            evidence_ids=[
                "E1",
                "E2",
            ],
        )
    )

    question = (
        updater.merge_open_question(
            state,
            question="What is unresolved?",
            evidence_ids=["E2"],
        )
    )

    assert hypothesis.id == "H1"
    assert contradiction.id == "X1"
    assert question.id == "Q1"


def test_proven_claim_cannot_be_downgraded() -> None:
    state = ResearchState(
        objective="test"
    )

    updater = ResearchStateUpdater()

    claim = updater.merge_claim(
        state,
        statement="Authoritative fact.",
        grade=ClaimGrade.PROVEN,
        evidence_ids=["E1"],
    )

    updater.merge_claim(
        state,
        statement="Authoritative fact.",
        grade=ClaimGrade.SUPPORTED,
        evidence_ids=["E2"],
    )

    assert claim.grade == ClaimGrade.PROVEN
    assert claim.evidence_ids == [
        "E1",
        "E2",
    ]
