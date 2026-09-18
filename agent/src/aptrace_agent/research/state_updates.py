from __future__ import annotations

import re
from typing import Iterable

from aptrace_agent.research.state import (
    Claim,
    ClaimGrade,
    Contradiction,
    Hypothesis,
    OpenQuestion,
    ResearchState,
)


def _normalize(text: str) -> str:
    return " ".join(text.split()).strip().lower()


def _next_id(
    existing_ids: Iterable[str],
    prefix: str,
) -> str:
    maximum = 0

    for value in existing_ids:
        match = re.fullmatch(
            rf"{re.escape(prefix)}(\d+)",
            value,
        )

        if match:
            maximum = max(
                maximum,
                int(match.group(1)),
            )

    return f"{prefix}{maximum + 1}"


class ResearchStateUpdater:
    def merge_claim(
        self,
        state: ResearchState,
        *,
        statement: str,
        grade: ClaimGrade,
        evidence_ids: list[str],
    ) -> Claim:
        normalized = _normalize(statement)

        for claim in state.claims:
            if _normalize(claim.statement) == normalized:
                if (
                    claim.grade == ClaimGrade.PROVEN
                    or grade == ClaimGrade.PROVEN
                ):
                    claim.grade = ClaimGrade.PROVEN
                else:
                    claim.grade = ClaimGrade.SUPPORTED

                for evidence_id in evidence_ids:
                    if evidence_id not in claim.evidence_ids:
                        claim.evidence_ids.append(
                            evidence_id
                        )

                return claim

        claim = Claim(
            id=_next_id(
                (item.id for item in state.claims),
                "C",
            ),
            statement=statement.strip(),
            grade=grade,
            evidence_ids=list(
                dict.fromkeys(evidence_ids)
            ),
        )

        state.claims.append(claim)

        return claim

    def merge_hypothesis(
        self,
        state: ResearchState,
        *,
        statement: str,
        evidence_ids: list[str],
    ) -> Hypothesis:
        normalized = _normalize(statement)

        for hypothesis in state.hypotheses:
            if (
                _normalize(hypothesis.statement)
                == normalized
            ):
                for evidence_id in evidence_ids:
                    if (
                        evidence_id
                        not in hypothesis.evidence_ids
                    ):
                        hypothesis.evidence_ids.append(
                            evidence_id
                        )

                return hypothesis

        hypothesis = Hypothesis(
            id=_next_id(
                (item.id for item in state.hypotheses),
                "H",
            ),
            statement=statement.strip(),
            evidence_ids=list(
                dict.fromkeys(evidence_ids)
            ),
        )

        state.hypotheses.append(
            hypothesis
        )

        return hypothesis

    def merge_contradiction(
        self,
        state: ResearchState,
        *,
        description: str,
        evidence_ids: list[str],
    ) -> Contradiction:
        normalized = _normalize(description)

        for contradiction in state.contradictions:
            if (
                _normalize(contradiction.description)
                == normalized
            ):
                for evidence_id in evidence_ids:
                    if (
                        evidence_id
                        not in contradiction.evidence_ids
                    ):
                        contradiction.evidence_ids.append(
                            evidence_id
                        )

                return contradiction

        contradiction = Contradiction(
            id=_next_id(
                (
                    item.id
                    for item in state.contradictions
                ),
                "X",
            ),
            description=description.strip(),
            evidence_ids=list(
                dict.fromkeys(evidence_ids)
            ),
        )

        state.contradictions.append(
            contradiction
        )

        return contradiction

    def merge_open_question(
        self,
        state: ResearchState,
        *,
        question: str,
        evidence_ids: list[str],
    ) -> OpenQuestion:
        normalized = _normalize(question)

        for open_question in state.open_questions:
            if (
                _normalize(open_question.question)
                == normalized
            ):
                for evidence_id in evidence_ids:
                    if (
                        evidence_id
                        not in open_question.evidence_ids
                    ):
                        open_question.evidence_ids.append(
                            evidence_id
                        )

                return open_question

        open_question = OpenQuestion(
            id=_next_id(
                (
                    item.id
                    for item in state.open_questions
                ),
                "Q",
            ),
            question=question.strip(),
            evidence_ids=list(
                dict.fromkeys(evidence_ids)
            ),
        )

        state.open_questions.append(
            open_question
        )

        return open_question
