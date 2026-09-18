from __future__ import annotations

import json

from dataclasses import dataclass
from typing import Any

from aptrace_agent.research.state import Lead, LeadStatus


@dataclass(frozen=True)
class LeadAction:
    """
    APTrace-private execution payload.

    This object is never part of the model-visible Lead.
    """

    tool: str
    arguments: dict[str, Any]


@dataclass
class _LeadRecord:
    lead: Lead
    action: LeadAction


class LeadRegistry:
    """
    Creates opaque model-visible lead IDs while keeping executable
    arguments private inside APTrace.
    """

    def __init__(self) -> None:
        self._records: dict[str, _LeadRecord] = {}
        self._action_index: dict[str, str] = {}
        self._next_id = 1

    def _action_key(
        self,
        tool: str,
        arguments: dict[str, Any],
    ) -> str:
        return json.dumps(
            {
                "tool": tool,
                "arguments": arguments,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

    def register(
        self,
        *,
        kind: str,
        description: str,
        tool: str,
        arguments: dict[str, Any],
        source_evidence_ids: list[str] | None = None,
    ) -> Lead:
        action_key = self._action_key(
            tool,
            arguments,
        )

        existing_id = self._action_index.get(
            action_key
        )

        if existing_id is not None:
            existing = self._records[
                existing_id
            ].lead

            for evidence_id in (
                source_evidence_ids or []
            ):
                if (
                    evidence_id
                    not in existing.source_evidence_ids
                ):
                    existing.source_evidence_ids.append(
                        evidence_id
                    )

            return existing

        lead_id = f"L{self._next_id}"
        self._next_id += 1

        lead = Lead(
            id=lead_id,
            kind=kind,
            description=description,
            source_evidence_ids=list(source_evidence_ids or []),
        )

        self._records[lead_id] = _LeadRecord(
            lead=lead,
            action=LeadAction(
                tool=tool,
                arguments=dict(arguments),
            ),
        )

        self._action_index[action_key] = lead_id

        return lead

    def resolve(self, lead_id: str) -> LeadAction:
        try:
            record = self._records[lead_id]
        except KeyError as exc:
            raise KeyError(f"unknown lead: {lead_id}") from exc

        if record.lead.status != LeadStatus.OPEN:
            raise ValueError(
                f"lead {lead_id} is not open: {record.lead.status}"
            )

        return record.action

    def mark_followed(self, lead_id: str) -> None:
        self._set_status(lead_id, LeadStatus.FOLLOWED)

    def dismiss(self, lead_id: str) -> None:
        self._set_status(lead_id, LeadStatus.DISMISSED)

    def _set_status(self, lead_id: str, status: LeadStatus) -> None:
        try:
            record = self._records[lead_id]
        except KeyError as exc:
            raise KeyError(f"unknown lead: {lead_id}") from exc

        record.lead.status = status
