from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ClaimGrade(StrEnum):
    PROVEN = "PROVEN"
    SUPPORTED = "SUPPORTED"


class LeadStatus(StrEnum):
    OPEN = "OPEN"
    FOLLOWED = "FOLLOWED"
    DISMISSED = "DISMISSED"


class QuestionStatus(StrEnum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"


class Claim(BaseModel):
    id: str
    statement: str
    grade: ClaimGrade
    evidence_ids: list[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    id: str
    statement: str
    evidence_ids: list[str] = Field(default_factory=list)


class Contradiction(BaseModel):
    id: str
    description: str
    evidence_ids: list[str] = Field(default_factory=list)


class OpenQuestion(BaseModel):
    id: str
    question: str
    evidence_ids: list[str] = Field(default_factory=list)
    status: QuestionStatus = QuestionStatus.OPEN


class Lead(BaseModel):
    """
    Model-visible research lead.

    This intentionally contains no executable tool name, address argument,
    pin-table index, filesystem path, or other backend payload.
    """

    id: str
    kind: str
    description: str
    source_evidence_ids: list[str] = Field(default_factory=list)
    status: LeadStatus = LeadStatus.OPEN


class ResearchState(BaseModel):
    objective: str
    evidence_ids: list[str] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)
    open_questions: list[OpenQuestion] = Field(default_factory=list)
    leads: list[Lead] = Field(default_factory=list)

    def add_evidence(self, evidence_id: str) -> None:
        if evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)

    def add_lead(self, lead: Lead) -> None:
        if any(existing.id == lead.id for existing in self.leads):
            raise ValueError(f"duplicate lead id: {lead.id}")
        self.leads.append(lead)

    def lead(self, lead_id: str) -> Lead:
        for lead in self.leads:
            if lead.id == lead_id:
                return lead
        raise KeyError(f"unknown lead: {lead_id}")

    def open_leads(self) -> list[Lead]:
        return [lead for lead in self.leads if lead.status == LeadStatus.OPEN]
