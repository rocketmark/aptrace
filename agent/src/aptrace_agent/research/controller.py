from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from openai import OpenAI

from aptrace_agent.research.reconciliation import (
    CaseReconciler,
)
from aptrace_agent.research.session import (
    ResearchSession,
)


@dataclass(frozen=True)
class ResearchStep:
    number: int
    action: str
    lead_id: str | None = None
    evidence_id: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class ResearchRunResult:
    stop_reason: str
    steps: tuple[ResearchStep, ...]
    reconciled: bool


class ResearchController:
    """
    Model-directed bounded research loop.

    Qwen chooses among APTrace-validated leads. APTrace executes the
    selected lead and updates authoritative evidence/facts. Case
    reconciliation is sparse and occurs only at a terminal boundary in
    this initial production controller.
    """

    def __init__(
        self,
        *,
        planner_client: Any | None = None,
        planner_model: str | None = None,
        reconciler: Any | None = None,
        review_model: str | None = None,
        max_steps: int = 12,
        recent_evidence_limit: int = 6,
    ) -> None:
        if max_steps < 1:
            raise ValueError(
                "max_steps must be at least 1"
            )

        if recent_evidence_limit < 1:
            raise ValueError(
                "recent_evidence_limit must be at least 1"
            )

        self.planner_client = (
            planner_client
            or OpenAI(
                base_url=os.environ[
                    "OMLX_BASE_URL"
                ],
                api_key=os.environ[
                    "OMLX_API_KEY"
                ],
                max_retries=0,
                timeout=120.0,
            )
        )

        self.planner_model = (
            planner_model
            or os.environ["APTRACE_MODEL"]
        )

        self.reconciler = (
            reconciler
            or CaseReconciler(
                model=(
                    review_model
                    or os.environ.get(
                        "APTRACE_REVIEW_MODEL",
                        "gemma-4-26b-a4b-it-4bit",
                    )
                )
            )
        )

        self.max_steps = max_steps
        self.recent_evidence_limit = (
            recent_evidence_limit
        )

    def _format_observation(
        self,
        observation,
    ) -> str:
        result = observation.result

        if observation.tool == "function_facts":
            callers = result.get(
                "callers",
                [],
            )

            return (
                f"{observation.id} function_facts: "
                f"{result.get('name')} "
                f"entry={result.get('entry')} "
                f"size={result.get('size')} "
                f"validated_calls={len(callers)}"
            )

        if observation.tool == "function_disassembly":
            instructions = "\n".join(
                f"  {item.get('address')} "
                f"{item.get('mnemonic')} "
                f"{item.get('operands', '')}".rstrip()
                for item in result.get(
                    "instructions",
                    [],
                )
            )

            return (
                f"{observation.id} "
                f"function_disassembly:\n"
                f"{instructions}"
            )

        if observation.tool == "callsite_context":
            instructions = "\n".join(
                f"  {item.get('address')} "
                f"{item.get('mnemonic')} "
                f"{item.get('operands', '')}".rstrip()
                for item in result.get(
                    "instructions",
                    [],
                )
            )

            return (
                f"{observation.id} callsite_context "
                f"{result.get('function')} "
                f"@ {result.get('address')}:\n"
                f"{instructions}"
            )

        if observation.tool == "pin_table_entry":
            return (
                f"{observation.id} pin_table_entry: "
                f"index={result.get('index')} "
                f"gpio={result.get('gpio')} "
                f"group={result.get('group')} "
                f"bit={result.get('bit')}"
            )

        if observation.tool == "search_case_evidence":
            matches: list[str] = []

            for match in result.get(
                "matches",
                [],
            )[:3]:
                excerpt = " ".join(
                    str(
                        match.get(
                            "excerpt",
                            "",
                        )
                    ).split()
                )

                if len(excerpt) > 300:
                    excerpt = (
                        excerpt[:300]
                        + "..."
                    )

                matches.append(
                    f"  {match.get('source')}:"
                    f"{match.get('line')}: "
                    f"{excerpt}"
                )

            return (
                f"{observation.id} "
                f"search_case_evidence "
                f"query={result.get('query')}:\n"
                + "\n".join(matches)
            )

        return (
            f"{observation.id} "
            f"{observation.tool}: "
            f"{json.dumps(result, sort_keys=True)}"
        )

    def _state_digest(
        self,
        session: ResearchSession,
    ) -> str:
        state = session.state
        sections: list[str] = []

        proven = [
            claim
            for claim in state.claims
            if claim.grade.value == "PROVEN"
        ]

        supported = [
            claim
            for claim in state.claims
            if claim.grade.value == "SUPPORTED"
        ]

        if proven:
            sections.append(
                "AUTHORITATIVE PROVEN FACTS\n"
                + "\n".join(
                    f"{claim.id}: "
                    f"{claim.statement} "
                    f"[{','.join(claim.evidence_ids)}]"
                    for claim in proven
                )
            )

        if supported:
            sections.append(
                "SUPPORTED INTERPRETATION\n"
                + "\n".join(
                    f"{claim.id}: "
                    f"{claim.statement} "
                    f"[{','.join(claim.evidence_ids)}]"
                    for claim in supported
                )
            )

        if state.hypotheses:
            sections.append(
                "HYPOTHESES\n"
                + "\n".join(
                    f"{item.id}: "
                    f"{item.statement}"
                    for item in state.hypotheses
                )
            )

        if state.contradictions:
            sections.append(
                "CONTRADICTIONS\n"
                + "\n".join(
                    f"{item.id}: "
                    f"{item.description}"
                    for item in state.contradictions
                )
            )

        if state.open_questions:
            sections.append(
                "OPEN QUESTIONS\n"
                + "\n".join(
                    f"{item.id}: "
                    f"{item.question}"
                    for item in state.open_questions
                    if item.status.value == "OPEN"
                )
            )

        recent = session.ledger.all()[
            -self.recent_evidence_limit:
        ]

        if recent:
            sections.append(
                "RECENT EVIDENCE\n"
                + "\n\n".join(
                    self._format_observation(
                        observation
                    )
                    for observation in recent
                )
            )

        if not sections:
            return "(no research state yet)"

        return "\n\n".join(sections)

    def _prompt(
        self,
        session: ResearchSession,
    ) -> str:
        open_leads = (
            session.state.open_leads()
        )

        lead_text = "\n".join(
            f"{lead.id}: [{lead.kind}] "
            f"{lead.description}"
            + (
                " "
                f"[from "
                f"{','.join(lead.source_evidence_ids)}]"
                if lead.source_evidence_ids
                else ""
            )
            for lead in open_leads
        )

        return f"""OBJECTIVE

{session.state.objective}

RESEARCH STATE

{self._state_digest(session)}

OPEN APTRACE-VALIDATED LEADS

{lead_text}

TASK

Choose the single highest-value next research action.

APTrace has already validated the executable form of every lead. Choose
based on expected information value and the stated objective.

Prefer actions that:
- resolve important remaining uncertainty,
- follow a meaningful newly discovered relationship,
- independently verify a load-bearing interpretation, or
- reconcile evidence across domains.

Avoid redundant enumeration when existing evidence already answers the
same question.

Do not invent addresses, GPIOs, logical pin indexes, function identities,
or other structural arguments.

If the available evidence is sufficient for the objective, or the
remaining leads are unlikely to materially improve the result, use
finish.

Otherwise use follow_lead exactly once.
"""

    def _request_decision(
        self,
        session: ResearchSession,
    ) -> tuple[str, dict[str, Any]]:
        open_leads = (
            session.state.open_leads()
        )

        lead_ids = [
            lead.id
            for lead in open_leads
        ]

        tools = [
            {
                "type": "function",
                "function": {
                    "name": "follow_lead",
                    "description": (
                        "Follow one APTrace-validated "
                        "research lead."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "lead_id": {
                                "type": "string",
                                "enum": lead_ids,
                            }
                        },
                        "required": [
                            "lead_id",
                        ],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "finish",
                    "description": (
                        "End research because current "
                        "evidence is sufficient or the "
                        "remaining leads are low value."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "reason": {
                                "type": "string",
                            }
                        },
                        "required": [
                            "reason",
                        ],
                        "additionalProperties": False,
                    },
                },
            },
        ]

        messages = [
            {
                "role": "system",
                "content": (
                    "You direct a bounded firmware "
                    "research investigation. APTrace "
                    "owns evidence, structural facts, "
                    "tool arguments, and provenance. "
                    "You choose research direction. "
                    "Make exactly one tool call."
                ),
            },
            {
                "role": "user",
                "content": self._prompt(
                    session
                ),
            },
        ]

        first_problem: str | None = None

        for attempt in range(2):
            response = (
                self.planner_client
                .chat.completions.create(
                    model=self.planner_model,
                    temperature=0.0,
                    messages=messages,
                    tools=tools,
                    tool_choice="auto",
                )
            )

            message = (
                response.choices[0].message
            )

            tool_calls = (
                message.tool_calls or []
            )

            if len(tool_calls) == 1:
                call = tool_calls[0]

                try:
                    arguments = json.loads(
                        call.function.arguments
                    )
                except (
                    TypeError,
                    json.JSONDecodeError,
                ):
                    problem = (
                        "tool arguments were not "
                        "valid JSON"
                    )
                else:
                    name = (
                        call.function.name
                    )

                    if name == "follow_lead":
                        lead_id = arguments.get(
                            "lead_id"
                        )

                        if lead_id in lead_ids:
                            return (
                                name,
                                arguments,
                            )

                        problem = (
                            "follow_lead referenced "
                            "an unavailable lead"
                        )

                    elif name == "finish":
                        reason = arguments.get(
                            "reason"
                        )

                        if (
                            isinstance(reason, str)
                            and reason.strip()
                        ):
                            return (
                                name,
                                arguments,
                            )

                        problem = (
                            "finish requires a "
                            "non-empty reason"
                        )

                    else:
                        problem = (
                            "unexpected tool "
                            f"{name!r}"
                        )
            else:
                problem = (
                    "expected exactly one tool call, "
                    f"received {len(tool_calls)}"
                )

            if attempt == 0:
                first_problem = problem

                messages = (
                    messages
                    + [
                        {
                            "role": "assistant",
                            "content": (
                                message.content
                                or ""
                            ),
                        },
                        {
                            "role": "user",
                            "content": (
                                "Your previous response "
                                "did not satisfy the "
                                "controller contract: "
                                f"{problem}. "
                                "Make exactly one valid "
                                "follow_lead or finish "
                                "tool call now."
                            ),
                        },
                    ]
                )

                continue

            raise RuntimeError(
                "planner failed to produce a "
                "valid decision twice; "
                f"first error: {first_problem}; "
                f"second error: {problem}"
            )

        raise AssertionError(
            "unreachable"
        )

    def _has_case_evidence(
        self,
        session: ResearchSession,
    ) -> bool:
        return any(
            observation.tool
            == "search_case_evidence"
            for observation
            in session.ledger.all()
        )

    def _reconcile_terminal(
        self,
        session: ResearchSession,
    ) -> bool:
        if not self._has_case_evidence(
            session
        ):
            return False

        self.reconciler.run(
            session
        )

        return True

    def run(
        self,
        session: ResearchSession,
    ) -> ResearchRunResult:
        steps: list[ResearchStep] = []

        for step_number in range(
            1,
            self.max_steps + 1,
        ):
            open_leads = (
                session.state.open_leads()
            )

            if not open_leads:
                reconciled = (
                    self._reconcile_terminal(
                        session
                    )
                )

                return ResearchRunResult(
                    stop_reason=(
                        "research_graph_exhausted"
                    ),
                    steps=tuple(steps),
                    reconciled=reconciled,
                )

            action, arguments = (
                self._request_decision(
                    session
                )
            )

            if action == "finish":
                reason = str(
                    arguments["reason"]
                ).strip()

                steps.append(
                    ResearchStep(
                        number=step_number,
                        action="finish",
                        reason=reason,
                    )
                )

                reconciled = (
                    self._reconcile_terminal(
                        session
                    )
                )

                return ResearchRunResult(
                    stop_reason=(
                        "planner_finished"
                    ),
                    steps=tuple(steps),
                    reconciled=reconciled,
                )

            lead_id = str(
                arguments["lead_id"]
            )

            observation = (
                session.follow_lead(
                    lead_id
                )
            )

            steps.append(
                ResearchStep(
                    number=step_number,
                    action="follow_lead",
                    lead_id=lead_id,
                    evidence_id=(
                        observation.id
                    ),
                )
            )

        reconciled = (
            self._reconcile_terminal(
                session
            )
        )

        return ResearchRunResult(
            stop_reason="step_budget_exhausted",
            steps=tuple(steps),
            reconciled=reconciled,
        )
