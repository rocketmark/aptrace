from __future__ import annotations

import os
import re
from typing import Any, Literal

from openai import OpenAI
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aptrace_agent.research.session import ResearchSession
from aptrace_agent.research.state import ClaimGrade
from aptrace_agent.research.state_updates import ResearchStateUpdater


class EntityReconciliation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str
    status: Literal[
        "SUPPORTED",
        "NO_SUPPORTED_INTERPRETATION",
    ]

    role: str | None = None
    context: str | None = None

    proven_claim_ids: list[str] = Field(
        default_factory=list,
    )

    unresolved: list[str] = Field(
        default_factory=list,
    )


class ReconciliationProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reconciliations: list[
        EntityReconciliation
    ]


class CaseReconciler:
    """
    Reconcile collected documentary/case evidence with authoritative
    APTrace-derived facts.

    This component cannot create PROVEN claims.
    """

    def __init__(
        self,
        *,
        client: Any | None = None,
        model: str | None = None,
    ) -> None:
        self.client = client or OpenAI(
            base_url=os.environ["OMLX_BASE_URL"],
            api_key=os.environ["OMLX_API_KEY"],
            max_retries=0,
            timeout=120.0,
        )

        self.model = (
            model
            or os.environ["APTRACE_MODEL"]
        )

        self.updater = ResearchStateUpdater()

    def _format_case_evidence(
        self,
        observation,
    ) -> str:
        result = observation.result

        matches: list[str] = []

        for match in result.get("matches", [])[:6]:
            excerpt = " ".join(
                str(match.get("excerpt", "")).split()
            )

            if len(excerpt) > 650:
                excerpt = excerpt[:650] + "..."

            matches.append(
                f"  - {match.get('source')}:"
                f"{match.get('line')}: {excerpt}"
            )

        return (
            f"{observation.id} — CASE EVIDENCE\n"
            f"query: {result.get('query')}\n"
            + "\n".join(matches)
        )

    def _extract_json(
        self,
        content: str,
    ) -> str:
        text = content.strip()

        match = re.fullmatch(
            r"```(?:json)?\s*(.*?)\s*```",
            text,
            re.DOTALL | re.IGNORECASE,
        )

        return (
            match.group(1).strip()
            if match
            else text
        )

    def _request(
        self,
        messages: list[dict[str, str]],
    ) -> str:
        response = (
            self.client.chat.completions.create(
                model=self.model,
                temperature=0.0,
                messages=messages,
            )
        )

        content = (
            response.choices[0].message.content
        )

        if not content:
            raise RuntimeError(
                "reconciliation model returned no content"
            )

        return content

    def _resolve_claim_refs(
        self,
        session: ResearchSession,
        claim_ids: list[str],
    ) -> list[str]:
        claims = {
            claim.id: claim
            for claim in session.state.claims
            if claim.grade == ClaimGrade.PROVEN
        }

        resolved: list[str] = []

        for claim_id in claim_ids:
            claim = claims.get(claim_id)

            if claim is None:
                raise ValueError(
                    "reconciliation referenced unknown "
                    f"PROVEN claim: {claim_id}"
                )

            for evidence_id in claim.evidence_ids:
                if evidence_id not in resolved:
                    resolved.append(evidence_id)

        return resolved

    def _validate(
        self,
        session: ResearchSession,
        proposal: ReconciliationProposal,
        case_observations: list,
    ) -> None:
        expected = {
            observation.result["query"]:
            observation.id
            for observation in case_observations
        }

        actual_queries = [
            item.query
            for item in proposal.reconciliations
        ]

        if len(actual_queries) != len(
            set(actual_queries)
        ):
            raise ValueError(
                "duplicate reconciliation query"
            )

        if set(actual_queries) != set(expected):
            raise ValueError(
                "reconciliation must cover exactly the "
                "collected case-evidence queries"
            )

        valid_claim_ids = {
            claim.id
            for claim in session.state.claims
            if claim.grade == ClaimGrade.PROVEN
        }

        for item in proposal.reconciliations:
            unknown_claims = (
                set(item.proven_claim_ids)
                - valid_claim_ids
            )

            if unknown_claims:
                raise ValueError(
                    f"{item.query}: unknown PROVEN claims: "
                    + ", ".join(
                        sorted(unknown_claims)
                    )
                )

            if item.status == "SUPPORTED":
                if not item.role:
                    raise ValueError(
                        f"{item.query}: supported "
                        "reconciliation has no role"
                    )

                if not item.proven_claim_ids:
                    raise ValueError(
                        f"{item.query}: supported "
                        "reconciliation has no PROVEN "
                        "claim provenance"
                    )


    def run(
        self,
        session: ResearchSession,
    ) -> ReconciliationProposal:
        case_observations = [
            observation
            for observation in session.ledger.all()
            if observation.tool
            == "search_case_evidence"
        ]

        if not case_observations:
            return ReconciliationProposal(
                reconciliations=[]
            )

        proven_claims = [
            claim
            for claim in session.state.claims
            if claim.grade == ClaimGrade.PROVEN
        ]

        proven_text = "\n".join(
            f"{claim.id}: {claim.statement} "
            f"[{','.join(claim.evidence_ids)}]"
            for claim in proven_claims
        )

        queries_text = "\n".join(
            f"- {observation.result['query']}"
            for observation in case_observations
        )

        evidence_parts: list[str] = []

        for observation in case_observations:
            evidence_parts.append(
                self._format_case_evidence(
                    observation
                )
            )

        evidence_text = "\n\n".join(
            evidence_parts
        )

        prompt = f"""OBJECTIVE

{session.state.objective}

AUTHORITATIVE PROVEN FACTS

{proven_text}

ENTITIES THAT MUST EACH BE RECONCILED

{queries_text}

DOCUMENTARY / CASE EVIDENCE

{evidence_text}

TASK

Return exactly one reconciliation for every listed entity.

This is an entity-role reconciliation task, not a general firmware
analysis.

For every SUPPORTED entity provide:

role:
  What the supplied documentary/case evidence identifies this entity
  as doing. Keep this focused on the entity's semantic role.

context:
  Timing, mode, conditions, or additional usage details. If an entity
  is only configured, read, or active inside a particular operating
  mode, that belongs in context rather than being turned into the
  entity's role.

unresolved:
  Explicitly documented unknowns that remain important, especially
  physical identity, physical connectivity, or an unresolved semantic
  relationship. Use an empty list if none are actually supported.

Rules:

- Preserve distinctions among different entities.
- An operating mode is not itself an entity's role merely because the
  entity is used within that mode.
- Do not re-analyze FUN_0000d3dc.
- Do not describe a read as configuration or a write.
- Do not infer physical connectivity from firmware.
- Do not promote plausibility into fact.
- Do not ask questions already answered by authoritative PROVEN facts.
- A SUPPORTED entry must cite at least one relevant C# PROVEN claim and
  APTrace supplies each query's case-evidence provenance.
- In proven_claim_ids, cite only supplied C# identifiers.
- Do not emit E# provenance; APTrace attaches documentary evidence IDs.
- If no useful role is supported, use
  NO_SUPPORTED_INTERPRETATION.

Return ONLY JSON:

{{
  "reconciliations": [
    {{
      "query": "...",
      "status": "SUPPORTED",
      "role": "...",
      "context": "...",
      "proven_claim_ids": ["C1"],
      "unresolved": ["..."]
    }}
  ]
}}
"""

        messages = [
            {
                "role": "system",
                "content": (
                    "You reconcile documentary firmware "
                    "research with authoritative machine-derived "
                    "facts. Keep entity role, operating context, "
                    "and unresolved questions distinct. APTrace owns "
                    "documentary evidence identity and provenance; "
                    "you select relevant C# PROVEN claims."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ]

        content = self._request(
            messages
        )

        try:
            proposal = (
                ReconciliationProposal
                .model_validate_json(
                    self._extract_json(
                        content
                    )
                )
            )
        except ValidationError as error:
            corrected = self._request(
                messages
                + [
                    {
                        "role": "assistant",
                        "content": content,
                    },
                    {
                        "role": "user",
                        "content": (
                            "The previous response failed "
                            "schema validation:\n\n"
                            f"{error}\n\n"
                            "Return the same reconciliation "
                            "as one valid JSON object. "
                            "No markdown or commentary."
                        ),
                    },
                ]
            )

            proposal = (
                ReconciliationProposal
                .model_validate_json(
                    self._extract_json(
                        corrected
                    )
                )
            )

        # Validate the entire proposal before mutating state.
        #
        # A structurally valid response may still violate the semantic
        # reconciliation contract. Give the reviewer one bounded
        # correction attempt. Never ingest the invalid first proposal.
        try:
            self._validate(
                session,
                proposal,
                case_observations,
            )
        except ValueError as first_validation_error:
            correction = self._request(
                messages
                + [
                    {
                        "role": "assistant",
                        "content": proposal.model_dump_json(
                            indent=2
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            "Your reconciliation is valid JSON but "
                            "failed APTrace semantic validation.\n\n"
                            "VALIDATION ERROR\n\n"
                            f"{first_validation_error}\n\n"
                            "Correct only what is necessary to satisfy "
                            "the reconciliation contract. Preserve one "
                            "entry for every required query. A "
                            "SUPPORTED entry must cite at least one "
                            "relevant authoritative C# PROVEN claim "
                            "APTrace owns documentary evidence "
                            "identity and provenance. Return only one "
                            "JSON object "
                            "matching the requested schema."
                        ),
                    },
                ]
            )

            try:
                corrected_proposal = (
                    ReconciliationProposal
                    .model_validate_json(
                        self._extract_json(
                            correction
                        )
                    )
                )
            except ValidationError as error:
                raise RuntimeError(
                    "reconciliation correction returned "
                    "invalid JSON/schema"
                ) from error

            try:
                self._validate(
                    session,
                    corrected_proposal,
                    case_observations,
                )
            except ValueError as error:
                raise RuntimeError(
                    "reconciliation failed semantic "
                    "validation twice"
                ) from error

            proposal = corrected_proposal

        case_by_query = {
            observation.result["query"]:
            observation.id
            for observation in case_observations
        }

        for item in proposal.reconciliations:
            if (
                item.status
                != "SUPPORTED"
            ):
                continue

            evidence_ids = (
                self._resolve_claim_refs(
                    session,
                    item.proven_claim_ids,
                )
            )

            case_evidence_id = case_by_query[
                item.query
            ]

            if case_evidence_id not in evidence_ids:
                evidence_ids.append(
                    case_evidence_id
                )

            statement = (
                f"{item.query}: "
                f"{item.role.strip()}"
            )

            if item.context:
                statement += (
                    " "
                    + item.context.strip()
                )

            self.updater.merge_claim(
                session.state,
                statement=statement,
                grade=ClaimGrade.SUPPORTED,
                evidence_ids=evidence_ids,
            )

            own_case_id = (
                case_by_query[
                    item.query
                ]
            )

            for unresolved in (
                item.unresolved
            ):
                self.updater.merge_open_question(
                    session.state,
                    question=unresolved.strip(),
                    evidence_ids=[
                        own_case_id,
                    ],
                )

        return proposal
