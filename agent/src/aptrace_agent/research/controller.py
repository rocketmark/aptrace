from __future__ import annotations

import json
import os
import sys
from collections.abc import Sequence
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
        census_peripherals: Sequence[str] = (),
        max_structural_analyses: int = 4,
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

        # APTrace-validated peripheral names with census evidence. The
        # planner may only choose among these; APTrace owns firmware,
        # database, limits and execution.
        self.census_peripherals = tuple(
            sorted(set(census_peripherals))
        )
        self.max_structural_analyses = (
            max_structural_analyses
        )

    def _census_observations(
        self,
        session: ResearchSession,
    ) -> list:
        return [
            observation
            for observation in session.ledger.all()
            if observation.tool
            == "census_peripheral_usage"
        ]

    def _analyzable_peripherals(
        self,
        session: ResearchSession,
    ) -> list[str]:
        done = self._census_observations(
            session
        )

        if len(done) >= self.max_structural_analyses:
            return []

        analyzed = {
            observation.arguments.get(
                "peripheral"
            )
            for observation in done
        }

        return [
            name
            for name in self.census_peripherals
            if name not in analyzed
        ]

    @staticmethod
    def _analysis_tool(
        peripherals: list[str],
    ) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "analyze_peripheral",
                "description": (
                    "Subsystem-level structural analysis "
                    "of one MCU peripheral from APTrace's "
                    "firmware census: which functions "
                    "access its registers or load its "
                    "address, and their reachability."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "peripheral": {
                            "type": "string",
                            "enum": peripherals,
                        }
                    },
                    "required": [
                        "peripheral",
                    ],
                    "additionalProperties": False,
                },
            },
        }

    def _analysis_guidance(
        self,
        session: ResearchSession,
        peripherals: list[str],
    ) -> str:
        if not peripherals:
            return ""

        analyzed = ", ".join(
            f"{observation.arguments.get('peripheral')} "
            f"({observation.id})"
            for observation in self._census_observations(
                session
            )
        ) or "(none)"

        return f"""
STRUCTURAL ANALYSIS

analyze_peripheral answers subsystem-level questions about one MCU
peripheral in a single step, from APTrace's precomputed firmware census.
Prefer this order:
1. existing case evidence
2. analyze_peripheral for a peripheral relevant to the objective
3. inspection of the functions it narrows to
4. caller/callee expansion only for a specific remaining question
Census facts are structural; they do not identify attached devices.
Already analyzed (do not repeat): {analyzed}
"""

    def _analysis_problem(
        self,
        session: ResearchSession,
        peripheral: Any,
    ) -> str:
        for observation in self._census_observations(
            session
        ):
            if observation.arguments.get(
                "peripheral"
            ) == peripheral:
                return (
                    f"{peripheral} was already analyzed "
                    f"in {observation.id}; choose a "
                    "different listed peripheral or "
                    "another action"
                )

        return (
            "analyze_peripheral requires "
            "one of the listed peripherals"
        )

    def _follow_peripheral_analysis(
        self,
        session: ResearchSession,
        peripheral: str,
    ):
        lead = session.registry.register(
            kind="census",
            description=(
                f"Census structural usage of "
                f"peripheral {peripheral}"
            ),
            tool="census_peripheral_usage",
            arguments={
                "peripheral": peripheral,
                "limit": 25,
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

        if observation.tool == "census_peripheral_usage":
            return self._format_census(
                observation
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

    @staticmethod
    def _format_census(
        observation,
    ) -> str:
        result = observation.result
        header = (
            f"{observation.id} census_peripheral_usage "
            f"{result.get('peripheral')}: "
            f"status={result.get('status')}"
        )

        if result.get("status") != "ok":
            return (
                f"{header} "
                f"({result.get('diagnostic')})"
            )

        functions = [
            item.get("function")
            for item in result.get(
                "functions",
                [],
            )[:6]
        ]

        unattributed = [
            str(item.get("site"))
            for item in result.get(
                "unattributed_sites",
                [],
            )[:4]
        ]

        return (
            f"{header} "
            f"mmio_sites={result.get('total_mmio_sites')} "
            f"address_constants="
            f"{result.get('total_address_constants')} "
            f"(unreferenced="
            f"{result.get('unreferenced_address_constants')}) "
            f"functions={result.get('total_functions')} "
            f"[{', '.join(functions)}]"
            + (
                f" unattributed_sites=[{', '.join(unattributed)}]"
                if unattributed
                else ""
            )
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

        if tool == "census_peripheral_usage":
            return (
                f"{lead.id} census peripheral "
                f"{args.get('peripheral', '?')}"
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
        analyzable: list[str],
    ) -> str:
        all_open_leads = (
            session.state.open_leads()
        )

        open_leads = (
            self._planner_open_leads(
                session
            )
        )

        actions = (
            "follow_lead or analyze_peripheral"
            if analyzable
            else "follow_lead"
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
{self._analysis_guidance(session, analyzable)}
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

Otherwise use {actions} exactly once.
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

        analyzable = (
            self._analyzable_peripherals(
                session
            )
        )

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

        if analyzable:
            tools.insert(
                1,
                self._analysis_tool(
                    analyzable
                ),
            )

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
                    session,
                    analyzable,
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

                    elif (
                        name == "analyze_peripheral"
                        and analyzable
                    ):
                        peripheral = arguments.get(
                            "peripheral"
                        )

                        if peripheral in analyzable:
                            return (
                                name,
                                {
                                    "peripheral": peripheral,
                                },
                            )

                        problem = self._analysis_problem(
                            session,
                            peripheral,
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

                if "already analyzed" in problem:
                    # Retry a repeated analysis request as a fresh,
                    # smaller request without the analysis tool, so the
                    # planner must choose a lead or finish.
                    analyzable = []
                    tools = [
                        tool
                        for tool in tools
                        if tool["function"]["name"]
                        != "analyze_peripheral"
                    ]
                    messages = [
                        messages[0],
                        {
                            "role": "user",
                            "content": self._prompt(
                                session,
                                analyzable,
                            ),
                        },
                    ]

                    continue

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
                                "follow_lead, "
                                + (
                                    "analyze_peripheral, "
                                    if analyzable
                                    else ""
                                )
                                + "or finish "
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
        analyzable: list[str],
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
{self._discovery_analysis_guidance(session, analyzable)}"""

    def _discovery_analysis_guidance(
        self,
        session: ResearchSession,
        analyzable: list[str],
    ) -> str:
        if not analyzable:
            return ""

        return (
            "\nIf the objective concerns an MCU peripheral or "
            "interface, analyze_peripheral may be used instead: it "
            "returns subsystem-level structural firmware evidence "
            "from APTrace's census in one step.\n"
            + self._analysis_guidance(
                session,
                analyzable,
            )
        )

    def _request_discovery(
        self,
        session: ResearchSession,
        attempted_queries: set[str],
    ) -> tuple[str, dict[str, Any]]:
        analyzable = (
            self._analyzable_peripherals(
                session
            )
        )

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

        if analyzable:
            tools.insert(
                1,
                self._analysis_tool(
                    analyzable
                ),
            )

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
                    analyzable,
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

                    elif (
                        name == "analyze_peripheral"
                        and analyzable
                    ):
                        peripheral = arguments.get(
                            "peripheral"
                        )

                        if peripheral in analyzable:
                            return (
                                name,
                                {
                                    "peripheral": peripheral,
                                },
                            )

                        problem = self._analysis_problem(
                            session,
                            peripheral,
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

                if "already analyzed" in problem:
                    analyzable = []
                    tools = [
                        tool
                        for tool in tools
                        if tool["function"]["name"]
                        != "analyze_peripheral"
                    ]
                    messages = [
                        messages[0],
                        {
                            "role": "user",
                            "content": self._discovery_prompt(
                                session,
                                attempted_queries,
                                analyzable,
                            ),
                        },
                    ]

                    continue

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
                                "one valid search_case_evidence, "
                                + (
                                    "analyze_peripheral, "
                                    if analyzable
                                    else ""
                                )
                                + "or finish tool call now."
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

                    if action == "analyze_peripheral":
                        lead, observation = (
                            self._follow_peripheral_analysis(
                                session,
                                arguments["peripheral"],
                            )
                        )

                        steps.append(
                            ResearchStep(
                                number=step_number,
                                action="analyze",
                                lead_id=lead.id,
                                evidence_id=(
                                    observation.id
                                ),
                            )
                        )

                        continue

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

            if action == "analyze_peripheral":
                lead, observation = (
                    self._follow_peripheral_analysis(
                        session,
                        arguments["peripheral"],
                    )
                )

                steps.append(
                    ResearchStep(
                        number=step_number,
                        action="analyze",
                        lead_id=lead.id,
                        evidence_id=(
                            observation.id
                        ),
                    )
                )

                continue

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
