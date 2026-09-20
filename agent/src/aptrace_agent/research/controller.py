from __future__ import annotations

import json
import os
import sys
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
        max_discovery_steps: int = 3,
        recent_evidence_limit: int = 6,
    ) -> None:
        if max_steps < 1:
            raise ValueError(
                "max_steps must be at least 1"
            )

        if max_discovery_steps < 0:
            raise ValueError(
                "max_discovery_steps must be at least 0"
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
        self.max_discovery_steps = (
            max_discovery_steps
        )
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
            instructions = result.get(
                "instructions",
                [],
            )

            first_address = (
                instructions[0].get("address")
                if instructions
                else None
            )

            last_address = (
                instructions[-1].get("address")
                if instructions
                else None
            )

            return (
                f"{observation.id} "
                f"function_disassembly: "
                f"{len(instructions)} instructions "
                f"from {first_address} to {last_address}; "
                "full disassembly retained by APTrace"
            )

        if observation.tool == "callsite_context":
            instructions = result.get(
                "instructions",
                [],
            )

            callsite = result.get(
                "address"
            )

            call_index = None

            for index, item in enumerate(
                instructions
            ):
                if item.get("address") == callsite:
                    call_index = index
                    break

            if call_index is None:
                selected = instructions[:6]
            else:
                selected = instructions[
                    max(0, call_index - 2):
                    min(
                        len(instructions),
                        call_index + 4,
                    )
                ]

            rendered = "\n".join(
                f"  {item.get('address')} "
                f"{item.get('mnemonic')} "
                f"{item.get('operands', '')}".rstrip()
                for item in selected
            )

            return (
                f"{observation.id} callsite_context "
                f"{result.get('function')} "
                f"@ {callsite}:\n"
                f"{rendered}"
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
            )[:2]:
                excerpt = " ".join(
                    str(
                        match.get(
                            "excerpt",
                            "",
                        )
                    ).split()
                )

                if len(excerpt) > 220:
                    excerpt = (
                        excerpt[:220]
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

    def _planner_open_leads(
        self,
        session: ResearchSession,
    ):
        """
        Return a bounded deterministic working set for the planner.

        APTrace retains the complete research graph. The planner sees
        a compact frontier so graph growth cannot make every decision
        prompt grow without bound.
        """

        open_leads = (
            session.state.open_leads()
        )

        limit = 24

        if len(open_leads) <= limit:
            return open_leads

        # Preserve some older unresolved breadth while emphasizing the
        # newest frontier produced by forward graph expansion.
        selected = (
            list(open_leads[:8])
            + list(open_leads[-16:])
        )

        result = []
        seen = set()

        for lead in selected:
            if lead.id in seen:
                continue

            seen.add(lead.id)
            result.append(lead)

        return result

    def _compact_lead(
        self,
        session: ResearchSession,
        lead,
    ) -> str:
        """
        Give the planner only the structural identity needed to choose
        a lead. APTrace retains descriptions, provenance and arguments.
        """

        try:
            action = session.registry.resolve(
                lead.id
            )
        except (KeyError, ValueError):
            return (
                f"{lead.id} [{lead.kind}]"
            )

        tool = action.tool
        args = action.arguments

        if tool in {
            "function_facts",
            "function_disassembly",
        }:
            target = args.get(
                "function",
                "?",
            )

            return (
                f"{lead.id} {tool} "
                f"{target}"
            )

        if tool == "callsite_context":
            function = args.get(
                "function",
                "?",
            )

            address = args.get(
                "address",
                "?",
            )

            return (
                f"{lead.id} callsite "
                f"{function}@{address}"
            )

        if tool == "pin_table_entry":
            return (
                f"{lead.id} pin_table_entry "
                f"index={args.get('index', '?')}"
            )

        if tool == "search_case_evidence":
            query = str(
                args.get(
                    "query",
                    "",
                )
            )

            if len(query) > 80:
                query = (
                    query[:77]
                    + "..."
                )

            return (
                f"{lead.id} case_search "
                f"{query!r}"
            )

        return (
            f"{lead.id} [{lead.kind}] "
            f"{tool}"
        )

    def _prompt(
        self,
        session: ResearchSession,
    ) -> str:
        all_open_leads = (
            session.state.open_leads()
        )

        open_leads = (
            self._planner_open_leads(
                session
            )
        )

        lead_text = "\n".join(
            self._compact_lead(
                session,
                lead,
            )
            for lead in open_leads
        )

        if (
            len(all_open_leads)
            > len(open_leads)
        ):
            lead_text += (
                "\n"
                f"[showing {len(open_leads)} "
                f"of {len(all_open_leads)} "
                "open leads; full graph retained "
                "by APTrace]"
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
            self._planner_open_leads(
                session
            )
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

        if (
            os.environ.get(
                "APTRACE_DEBUG_PLANNER_REQUEST"
            )
            == "1"
        ):
            prompt_text = str(
                messages[-1]["content"]
            )

            messages_json = json.dumps(
                messages,
                separators=(",", ":"),
                ensure_ascii=False,
            )

            tools_json = json.dumps(
                tools,
                separators=(",", ":"),
                ensure_ascii=False,
            )

            message_bytes = len(
                messages_json.encode("utf-8")
            )

            tool_bytes = len(
                tools_json.encode("utf-8")
            )

            print(
                "[planner-request] "
                f"open_total="
                f"{len(session.state.open_leads())} "
                f"open_visible={len(open_leads)} "
                f"recent_evidence="
                f"{min(len(session.ledger.all()), self.recent_evidence_limit)} "
                f"prompt_chars={len(prompt_text)} "
                f"message_bytes={message_bytes} "
                f"tool_bytes={tool_bytes} "
                f"total_bytes={message_bytes + tool_bytes}",
                file=sys.stderr,
            )

        first_problem: str | None = None

        for attempt in range(2):
            try:
                response = (
                    self.planner_client
                    .chat.completions.create(
                        model=self.planner_model,
                        temperature=0.0,
                        max_tokens=512,
                        messages=messages,
                        tools=tools,
                        tool_choice="auto",
                    )
                )
            except Exception as exc:
                error_text = str(
                    exc
                )

                if (
                    "prefill_memory_exceeded"
                    in error_text
                ):
                    return (
                        "planner_prefill_exhausted",
                        {
                            "reason": (
                                "Planner request exceeded "
                                "the local model prefill "
                                "memory guard. Research "
                                "stopped cleanly with all "
                                "accumulated evidence "
                                "retained."
                            )
                        },
                    )

                raise

            choices = getattr(
                response,
                "choices",
                None,
            )

            message = None

            if not choices:
                problem = (
                    "planner response contained "
                    "no choices"
                )

                tool_calls = []
            else:
                message = getattr(
                    choices[0],
                    "message",
                    None,
                )

                if message is None:
                    problem = (
                        "planner response choice "
                        "contained no message"
                    )

                    tool_calls = []
                else:
                    tool_calls = (
                        getattr(
                            message,
                            "tool_calls",
                            None,
                        )
                        or []
                    )

            if message is not None and len(tool_calls) == 1:
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
            elif message is not None:
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
                                (
                                    getattr(
                                        message,
                                        "content",
                                        None,
                                    )
                                    or ""
                                )
                                if message is not None
                                else ""
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

            return (
                "planner_contract_exhausted",
                {
                    "reason": (
                        "Planner could not produce a valid "
                        "research decision after one correction; "
                        f"first error: {first_problem}; "
                        f"second error: {problem}"
                    )
                },
            )

        raise AssertionError(
            "unreachable"
        )

    def _discovery_prompt(
        self,
        session: ResearchSession,
        attempted_queries: set[str],
    ) -> str:
        attempted = (
            "\n".join(
                f"- {query}"
                for query
                in sorted(attempted_queries)
            )
            or "(none)"
        )

        return f"""OBJECTIVE

{session.state.objective}

CURRENT DISCOVERY STATE

{self._state_digest(session)}

DISCOVERY SEARCHES ALREADY TRIED

{attempted}

TASK

Choose one bounded semantic search of the existing Performing Rigs case
evidence that is most likely to reveal concrete firmware functions or
other documented firmware anchors relevant to the objective.

The case-evidence search is primarily lexical. Prefer a short query
containing one to three discriminative engineering terms rather than a
sentence or a long collection of terms.

Each new search must explore a materially different investigative angle.
Do not merely append generic words such as "firmware", "function", or
"code" to a query that has already been tried. For example, different
angles might involve a device name, peripheral family, protocol,
chip-select terminology, motor-control terminology, or a documented
hardware signal.

Do not invent function names, addresses, GPIOs, or other structural
identifiers. APTrace will extract and validate any concrete firmware
identities found by the search.

Use search_case_evidence exactly once. If no additional documentary
search is likely to produce a useful firmware starting point, use finish.
"""

    def _request_discovery(
        self,
        session: ResearchSession,
        attempted_queries: set[str],
    ) -> tuple[str, dict[str, Any]]:
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "search_case_evidence",
                    "description": (
                        "Search bounded existing Performing "
                        "Rigs case evidence using semantic terms."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "minLength": 2,
                                "maxLength": 120,
                            }
                        },
                        "required": [
                            "query",
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
                        "End discovery because no further "
                        "bounded documentary search is useful."
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
                    "You choose semantic discovery direction "
                    "for a bounded firmware investigation. "
                    "APTrace owns structural identities and "
                    "validates anything discovered. Make "
                    "exactly one tool call."
                ),
            },
            {
                "role": "user",
                "content": self._discovery_prompt(
                    session,
                    attempted_queries,
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
                    max_tokens=512,
                    messages=messages,
                    tools=tools,
                    tool_choice="auto",
                )
            )

            choices = getattr(
                response,
                "choices",
                None,
            )

            message = None

            if not choices:
                problem = (
                    "planner response contained no choices"
                )
                tool_calls = []
            else:
                message = getattr(
                    choices[0],
                    "message",
                    None,
                )

                if message is None:
                    problem = (
                        "planner response choice contained "
                        "no message"
                    )
                    tool_calls = []
                else:
                    tool_calls = (
                        getattr(
                            message,
                            "tool_calls",
                            None,
                        )
                        or []
                    )

            if (
                message is not None
                and len(tool_calls) == 1
            ):
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
                        "tool arguments were not valid JSON"
                    )
                else:
                    name = call.function.name

                    if name == "search_case_evidence":
                        query = str(
                            arguments.get(
                                "query",
                                "",
                            )
                        ).strip()

                        normalized = (
                            query.casefold()
                        )

                        if not (
                            2 <= len(query) <= 120
                        ):
                            problem = (
                                "discovery query must be "
                                "2..120 characters"
                            )
                        elif (
                            normalized
                            in attempted_queries
                        ):
                            problem = (
                                "discovery query was already tried"
                            )
                        else:
                            return (
                                name,
                                {
                                    "query": query,
                                },
                            )

                    elif name == "finish":
                        reason = str(
                            arguments.get(
                                "reason",
                                "",
                            )
                        ).strip()

                        if reason:
                            return (
                                name,
                                {
                                    "reason": reason,
                                },
                            )

                        problem = (
                            "finish requires a non-empty reason"
                        )

                    else:
                        problem = (
                            f"unexpected discovery tool {name!r}"
                        )

            elif message is not None:
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
                                (
                                    getattr(
                                        message,
                                        "content",
                                        None,
                                    )
                                    or ""
                                )
                                if message
                                is not None
                                else ""
                            ),
                        },
                        {
                            "role": "user",
                            "content": (
                                "Your previous response "
                                "did not satisfy the "
                                "discovery contract: "
                                f"{problem}. Make exactly "
                                "one valid search_case_evidence "
                                "or finish tool call now."
                            ),
                        },
                    ]
                )

                continue

            return (
                "finish",
                {
                    "reason": (
                        "Discovery planner could not produce "
                        "a new valid search direction after "
                        "one correction; "
                        f"first error: {first_problem}; "
                        f"second error: {problem}"
                    )
                },
            )

        raise AssertionError(
            "unreachable"
        )

    def _follow_discovery_search(
        self,
        session: ResearchSession,
        query: str,
    ):
        lead = session.registry.register(
            kind="discovery",
            description=(
                f"Search existing case evidence "
                f"for discovery query {query!r}"
            ),
            tool="search_case_evidence",
            arguments={
                "query": query,
                "max_results": 8,
                "purpose": "discovery",
            },
            source_evidence_ids=[],
        )

        if all(
            existing.id != lead.id
            for existing
            in session.state.leads
        ):
            session.state.add_lead(
                lead
            )

        observation = (
            session.follow_lead(
                lead.id
            )
        )

        return lead, observation

    def _has_case_evidence(
        self,
        session: ResearchSession,
    ) -> bool:
        return any(
            (
                observation.tool
                == "search_case_evidence"
                and observation.arguments.get(
                    "purpose"
                )
                != "discovery"
            )
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

        objective_discovery = (
            not session.ledger.all()
            and not session.state.open_leads()
        )

        discovery_attempts = 0
        discovery_queries: set[str] = set()

        for step_number in range(
            1,
            self.max_steps + 1,
        ):
            open_leads = (
                session.state.open_leads()
            )

            if not open_leads:
                if (
                    objective_discovery
                    and discovery_attempts
                    < self.max_discovery_steps
                ):
                    action, arguments = (
                        self._request_discovery(
                            session,
                            discovery_queries,
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

                        return ResearchRunResult(
                            stop_reason=(
                                "discovery_finished"
                            ),
                            steps=tuple(steps),
                            reconciled=False,
                        )

                    query = str(
                        arguments["query"]
                    ).strip()

                    discovery_queries.add(
                        query.casefold()
                    )

                    lead, observation = (
                        self._follow_discovery_search(
                            session,
                            query,
                        )
                    )

                    discovery_attempts += 1

                    steps.append(
                        ResearchStep(
                            number=step_number,
                            action="discover",
                            lead_id=lead.id,
                            evidence_id=(
                                observation.id
                            ),
                        )
                    )

                    continue

                if (
                    objective_discovery
                    and self.max_discovery_steps > 0
                    and discovery_attempts
                    >= self.max_discovery_steps
                ):
                    return ResearchRunResult(
                        stop_reason=(
                            "discovery_exhausted"
                        ),
                        steps=tuple(steps),
                        reconciled=False,
                    )

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

            if action in {
                "planner_prefill_exhausted",
                "planner_contract_exhausted",
            }:
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
                    stop_reason=action,
                    steps=tuple(steps),
                    reconciled=reconciled,
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
