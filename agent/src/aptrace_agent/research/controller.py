from __future__ import annotations

import json
import os
import re
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from openai import OpenAI

from aptrace_agent.research.projection import (
    COMPACT_BUDGET,
    PlannerProjection,
    ProjectionBudget,
    clip,
    known_functions,
)
from aptrace_agent.research.reconciliation import (
    CaseReconciler,
)
from aptrace_agent.research.session import (
    ResearchSession,
)
from aptrace_agent.research.state_updates import (
    ResearchStateUpdater,
)


# Structural tools beyond per-peripheral census analysis. Each is offered
# only when the application enables it.
STRUCTURAL_TOOLS = (
    "usb_inventory",
    "common_paths",
    "function_effects",
)

_FUNCTION_RE = re.compile(r"FUN_[0-9a-f]{8}")
_SET_NAME_RE = re.compile(r"[A-Z][A-Z0-9_]{0,23}")

# Optional structured claim-output contract on finish.
CLAIM_TYPES = ("RESOLUTION", "PATH_EXISTS", "NO_KNOWN_PATH", "UNREACHABLE", "BEHAVIOR", "STRUCTURE", "OTHER")
CLAIM_GRADES = ("EXACT", "STRONG", "PROBABLE")
MAX_PROPOSED_CLAIMS = 3
# Claims are one scalar string, one claim per line: the local planner's
# tool-call output degenerates on nested array-of-object arguments (and
# often on additional array arguments). "STRONG RESOLUTION E2,E4 text".
CLAIM_FORMAT = "GRADE [TYPE] E#,E# assertion"
# Optional trailing omission note on a claim line: "[omit E7,E8: reason]".
_OMIT_RE = re.compile(r"\s*\[omit\s+(?P<evidence>E\d+(?:\s*,\s*E\d+)*)\s*:\s*(?P<reason>[^\]]+)\]\s*$", re.IGNORECASE)
_CLAIM_LINE_RE = re.compile(
    r"\s*(?P<grade>EXACT|STRONG|PROBABLE)\s+(?:(?P<type>" + "|".join(CLAIM_TYPES) + r")\s+)?"
    r"(?P<evidence>E\d+(?:\s*,\s*E\d+)*)\s*[:\-]?\s+(?P<assertion>\S.*)",
    re.IGNORECASE | re.DOTALL,
)

# Sources whose function leads are structural narrowing rather than
# caller/callee crawling; their leads rank first for the planner.
_STRUCTURAL_SOURCES = {
    "census_peripheral_usage",
    "census_usb_inventory",
    "census_common_paths",
    "function_effects",
    "search_case_evidence",
}


@dataclass(frozen=True)
class ResearchStep:
    number: int
    action: str
    lead_id: str | None = None
    evidence_id: str | None = None
    reason: str | None = None
    # Durable evidence id when the step used a historical result by
    # reference instead of executing (follow-up sessions only).
    reused_from: str | None = None


@dataclass(frozen=True)
class ResearchRunResult:
    stop_reason: str
    steps: tuple[ResearchStep, ...]
    reconciled: bool
    planner_requests: tuple[dict[str, Any], ...] = ()
    # Structured claims the planner proposed at finish (claim contract only)
    # that passed admission (research/admission.py). Proposals, never facts:
    # APTrace records them as PROPOSED claim versions.
    proposed_claims: tuple[dict[str, Any], ...] = ()
    # Every admission decision (ClaimAdmission), admitted or not.
    claim_admission: tuple[Any, ...] = ()


@dataclass
class _Palette:
    """The tools offered for one planner request and what they accept."""

    tools: list[dict[str, Any]]
    lead_ids: list[str] = field(default_factory=list)
    analyzable: list[str] = field(default_factory=list)
    set_names: dict[str, list[str]] = field(default_factory=dict)
    known: set[str] = field(default_factory=set)
    # Tool whose request repeated an analysis already in evidence.
    duplicate: str | None = None

    def names(self) -> list[str]:
        return [tool["function"]["name"] for tool in self.tools]

    def drop(self, name: str) -> None:
        self.tools = [tool for tool in self.tools if tool["function"]["name"] != name]

        if name == "analyze_peripheral":
            self.analyzable = []


def _function_tool(name: str, description: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    }


def _prefill_rejected(value: Any) -> bool:
    """True for an oMLX prefill-memory rejection, raised or returned as a body."""

    if isinstance(value, Exception):
        text = str(value)
    else:
        if getattr(value, "choices", None):
            return False

        extra = getattr(value, "model_extra", None) or {}
        text = str(extra.get("error") or getattr(value, "error", "") or "")

    return "prefill_memory_exceeded" in text or "prefill memory guard" in text


class ResearchController:
    """
    Model-directed bounded research loop.

    Qwen chooses which uncertainty to pursue: a validated lead, a
    subsystem-level structural analysis, or finishing. APTrace validates
    every argument, executes the analysis, records evidence, and derives
    facts. The planner sees a bounded projection of the research state;
    the complete evidence ledger, claims and provenance stay in APTrace.
    Case reconciliation is sparse and occurs only at a terminal boundary.
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
        recent_evidence_limit: int = 2,
        census_peripherals: Sequence[str] = (),
        max_structural_analyses: int = 4,
        structural_tools: Sequence[str] = (),
        max_effects_analyses: int = 3,
        max_path_analyses: int = 3,
        max_visible_leads: int = 6,
        prefill_retry_delay: float = 3.0,
        projection_budget: ProjectionBudget | None = None,
        claim_contract: bool = False,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be at least 1")

        if max_discovery_steps < 0:
            raise ValueError("max_discovery_steps must be at least 0")

        if recent_evidence_limit < 1:
            raise ValueError("recent_evidence_limit must be at least 1")

        unknown = sorted(set(structural_tools) - set(STRUCTURAL_TOOLS))

        if unknown:
            raise ValueError(f"unknown structural tools: {', '.join(unknown)}")

        self.planner_client = planner_client or OpenAI(
            base_url=os.environ["OMLX_BASE_URL"],
            api_key=os.environ["OMLX_API_KEY"],
            max_retries=0,
            timeout=120.0,
        )

        self.planner_model = planner_model or os.environ["APTRACE_MODEL"]

        self.reconciler = reconciler or CaseReconciler(
            model=(
                review_model
                or os.environ.get(
                    "APTRACE_REVIEW_MODEL",
                    "gemma-4-26b-a4b-it-4bit",
                )
            )
        )

        self.max_steps = max_steps
        self.max_discovery_steps = max_discovery_steps

        # APTrace-validated peripheral names with census evidence. The
        # planner may only choose among these; APTrace owns firmware,
        # database, limits and execution.
        self.census_peripherals = tuple(sorted(set(census_peripherals)))
        self.max_structural_analyses = max_structural_analyses
        self.structural_tools = tuple(structural_tools)
        self.max_effects_analyses = max_effects_analyses
        self.max_path_analyses = max_path_analyses
        self.max_visible_leads = max_visible_leads
        self.prefill_retry_delay = prefill_retry_delay
        self.claim_contract = claim_contract
        self.proposed_claims: list[dict[str, Any]] = []
        self.claim_admission: list[Any] = []
        # Correction rounds the planner gets after a rejected claim proposal.
        self.max_claim_corrections = 1

        budget = projection_budget or ProjectionBudget(latest_count=recent_evidence_limit)
        self.normal_projection = PlannerProjection(budget)
        self.compact_projection = PlannerProjection(COMPACT_BUDGET)
        self.projection = self.normal_projection
        self.updater = ResearchStateUpdater()

        # Size of every planner request, for measurement and the run record.
        self.planner_requests: list[dict[str, Any]] = []

        # Decisions left to request with the compact projection after the
        # local server rejected a request at prefill.
        self._compact_decisions = 0

        # Tool -> decisions left during which it is withheld, after the
        # planner asked it to repeat an analysis already in evidence.
        self._cooldown: dict[str, int] = {}

    # -- what has already run ---------------------------------------------------

    @staticmethod
    def _observations(session: ResearchSession, tool: str) -> list:
        return [observation for observation in session.ledger.all() if observation.tool == tool]

    @classmethod
    def _executed(cls, session: ResearchSession, tool: str) -> list:
        """Observations of tool this session executed; reused historical results excluded."""

        return [observation for observation in cls._observations(session, tool) if observation.reused_from is None]

    @staticmethod
    def _seeded_open(session: ResearchSession) -> list:
        continuity = getattr(session, "continuity", None)
        return continuity.open_seeded(session.state) if continuity is not None else []

    def _census_observations(self, session: ResearchSession) -> list:
        return self._observations(session, "census_peripheral_usage")

    def _analyzable_peripherals(self, session: ResearchSession) -> list[str]:
        done = self._census_observations(session)

        if len(self._executed(session, "census_peripheral_usage")) >= self.max_structural_analyses:
            return []

        # Follow-up policy: no broad peripheral rediscovery while the leads
        # the follow-up exists for are still open.
        if self._seeded_open(session):
            return []

        analyzed = {observation.arguments.get("peripheral") for observation in done}

        # The USB inventory already includes the USB census usage.
        if self._observations(session, "census_usb_inventory"):
            analyzed.add("USB")

        return [name for name in self.census_peripherals if name not in analyzed]

    def _set_names(self, session: ResearchSession) -> dict[str, list[str]]:
        """Named function sets the planner may relate: analyzed peripherals."""

        sets: dict[str, list[str]] = {}

        for observation in self._census_observations(session):
            functions = [item.get("function") for item in observation.result.get("functions", [])]

            if functions:
                sets[str(observation.arguments.get("peripheral"))] = [f for f in functions if f]

        for observation in self._observations(session, "census_usb_inventory"):
            functions = observation.result.get("functions", [])

            if functions:
                sets["USB"] = list(dict.fromkeys(sets.get("USB", []) + functions))

        return sets

    # -- palette ----------------------------------------------------------------

    @staticmethod
    def _analysis_tool(peripherals: list[str]) -> dict[str, Any]:
        return _function_tool(
            "analyze_peripheral",
            "Census: functions using one peripheral, with reachability.",
            {"peripheral": {"type": "string", "enum": peripherals}},
            ["peripheral"],
        )

    def _structural_palette(self, session: ResearchSession, palette: _Palette) -> None:
        palette.analyzable = self._analyzable_peripherals(session)

        if palette.analyzable:
            palette.tools.append(self._analysis_tool(palette.analyzable))

        # Scoped to relevance: offered when the objective names USB or USB
        # census evidence already exists.
        usb_relevant = "usb" in session.state.objective.lower() or any(
            observation.arguments.get("peripheral") == "USB"
            for observation in self._census_observations(session)
        )

        if (
            "usb_inventory" in self.structural_tools
            and usb_relevant
            and not self._observations(session, "census_usb_inventory")
            and not self._seeded_open(session)
        ):
            palette.tools.append(
                _function_tool(
                    "analyze_usb_interface",
                    "USB questions only: USB register users, IRQ handlers, descriptors.",
                    {},
                    [],
                )
            )

        observations = session.ledger.all()
        palette.known = set(known_functions(observations))
        palette.set_names = self._set_names(session)

        if (
            "common_paths" in self.structural_tools
            and len(self._executed(session, "census_common_paths")) < self.max_path_analyses
            and len(palette.set_names) >= 2
        ):
            members = {"type": "array", "items": {"type": "string"}, "maxItems": 4}
            palette.tools.append(
                _function_tool(
                    "find_common_paths",
                    "Only to test whether two subsystems connect: do two function sets (analyzed peripherals or FUN_ names) converge in the call graph or shared RAM?",
                    {"left": members, "right": members},
                    ["left", "right"],
                )
            )

        if (
            "function_effects" in self.structural_tools
            and len(self._executed(session, "function_effects")) < self.max_effects_analyses
            and palette.known
        ):
            value = {"type": "integer"}
            palette.tools.append(
                _function_tool(
                    "analyze_function_effects",
                    "Only when one function's dataflow is the open question: symbolic MMIO/RAM/return effects of a known FUN_; r0/r1 optionally fix arguments.",
                    {"function": {"type": "string"}, "r0": value, "r1": value},
                    ["function"],
                )
            )

    def _apply_cooldown(self, palette: _Palette) -> None:
        for name, remaining in list(self._cooldown.items()):
            if remaining > 0 and len(palette.tools) > 1:
                palette.drop(name)

            if remaining <= 1:
                del self._cooldown[name]
            else:
                self._cooldown[name] = remaining - 1

    def _decision_palette(self, session: ResearchSession) -> _Palette:
        open_leads = self._planner_open_leads(session)
        palette = _Palette(tools=[], lead_ids=[lead.id for lead in open_leads])

        if palette.lead_ids:
            palette.tools.append(
                _function_tool(
                    "follow_lead",
                    "Follow one lead listed under LEADS.",
                    {"lead_id": {"type": "string", "enum": palette.lead_ids}},
                    ["lead_id"],
                )
            )

        self._structural_palette(session, palette)
        palette.tools.append(self._finish_tool())
        self._apply_cooldown(palette)

        continuity = getattr(session, "continuity", None)

        if continuity is not None and "follow_lead" in palette.names():
            continuity.offered.update(palette.lead_ids)

        return palette

    def _discovery_palette(self, session: ResearchSession) -> _Palette:
        palette = _Palette(
            tools=[
                _function_tool(
                    "search_case_evidence",
                    "Search case documents (lexical terms).",
                    {"query": {"type": "string"}},
                    ["query"],
                )
            ]
        )
        self._structural_palette(session, palette)
        palette.tools.append(
            _function_tool(
                "finish",
                "End discovery; no further search is useful.",
                {"reason": {"type": "string"}},
                ["reason"],
            )
        )
        return palette

    def _finish_tool(self) -> dict[str, Any]:
        notes = {"type": "array", "items": {"type": "string"}}
        properties: dict[str, Any] = {"reason": {"type": "string"}, "hypotheses": notes, "open_questions": notes}

        if not self.claim_contract:
            return _function_tool(
                "finish",
                "End research, optionally with hypotheses and open questions.",
                properties,
                ["reason"],
            )

        properties["claims"] = {"type": "string", "description": f"one claim per line: {CLAIM_FORMAT}"}
        return _function_tool(
            "finish",
            "End research, optionally with hypotheses, open questions, and evidence-backed claims, "
            f"each one string '{CLAIM_FORMAT}' (GRADE EXACT|STRONG|PROBABLE; TYPE optional: "
            + "|".join(CLAIM_TYPES)
            + ").",
            properties,
            ["reason"],
        )

    @classmethod
    def _sanitize_claims(cls, items: Any) -> list[dict[str, Any]]:
        """Well-formed claim proposals only; references are validated later by APTrace."""

        return cls._parse_claims(items)[0]

    @staticmethod
    def _parse_claims(items: Any) -> tuple[list[dict[str, Any]], list[str]]:
        """(well-formed proposals, raw text of items that are not claims)."""

        if isinstance(items, str):
            items = [line for line in items.splitlines() if line.strip()]

        if not isinstance(items, list):
            return [], ([str(items)[:600]] if items not in (None, "", []) else [])

        out: list[dict[str, Any]] = []
        unparseable: list[str] = []

        for item in items[: MAX_PROPOSED_CLAIMS * 3]:
            if len(out) == MAX_PROPOSED_CLAIMS:
                break

            raw = item if isinstance(item, str) else json.dumps(item, default=str)
            omissions: dict[str, str] = {}

            if isinstance(item, str):
                text = item.strip()
                omit = _OMIT_RE.search(text)

                if omit:
                    reason = omit["reason"].strip()
                    omissions = {e.strip().upper(): reason for e in omit["evidence"].split(",")}
                    text = text[: omit.start()].rstrip()

                match = _CLAIM_LINE_RE.fullmatch(text)

                if match is None:
                    unparseable.append(raw[:600])
                    continue

                item = {
                    "assertion": match["assertion"],
                    "grade": match["grade"],
                    "claim_type": match["type"] or "OTHER",
                    "evidence_ids": [e.strip().upper() for e in match["evidence"].split(",")],
                    "omissions": omissions,
                }

            if not isinstance(item, dict):
                unparseable.append(raw[:600])
                continue

            assertion = item.get("assertion")
            grade = str(item.get("grade", "")).upper()

            if not isinstance(assertion, str) or not assertion.strip() or grade not in CLAIM_GRADES:
                unparseable.append(raw[:600])
                continue

            claim_type = str(item.get("claim_type", "OTHER")).upper()
            evidence = item.get("evidence_ids") if isinstance(item.get("evidence_ids"), list) else []
            limitations = item.get("limitations") if isinstance(item.get("limitations"), list) else []
            out.append(
                {
                    "subject": clip(str(item.get("subject") or ""), 120),
                    "assertion": clip(assertion.strip(), 400),
                    "claim_type": claim_type if claim_type in CLAIM_TYPES else "OTHER",
                    "grade": grade,
                    "evidence_ids": [str(e).strip() for e in evidence if isinstance(e, (str, int))][:8],
                    "limitations": [clip(str(x), 240) for x in limitations if isinstance(x, str)][:4],
                    "semantics": item.get("semantics") if isinstance(item.get("semantics"), dict) else None,
                    "omissions": (
                        {str(k).upper(): str(v)[:240] for k, v in item["omissions"].items()}
                        if isinstance(item.get("omissions"), dict)
                        else {}
                    ),
                    "raw": raw[:600],
                }
            )

        return out, unparseable

    def _admit_round(self, session: ResearchSession, items: Any, round: int) -> list[Any]:
        from aptrace_agent.ledger.claim_checks import CLAIM_UNPARSEABLE, REJECT
        from aptrace_agent.ledger.models import ClaimAdmission, ClaimDiagnostic
        from aptrace_agent.research.admission import admit, function_resolver

        proposals, unparseable = self._parse_claims(items)
        records = [
            ClaimAdmission(
                round=round,
                raw=raw,
                decision="unparseable",
                diagnostics=[ClaimDiagnostic(code=CLAIM_UNPARSEABLE, severity=REJECT, detail=f"not a '{CLAIM_FORMAT}' line")],
            )
            for raw in unparseable
        ]
        resolver = function_resolver(session)
        peripherals = self.census_peripherals or None

        for proposal in proposals:
            record = admit(proposal, session, round=round, function_exists=resolver, peripherals=peripherals)
            records.append(record)

            if record.decision == "admitted":
                self.proposed_claims.append({**proposal, "admission": len(self.claim_admission) + len(records) - 1})

        return records

    def _accept_claims(self, session: ResearchSession, items: Any) -> None:
        """
        Admit the planner's claim proposals (research/admission.py). After a
        rejection, one bounded correction request shows the diagnostics; its
        proposals are admitted the same way. Nothing bypasses admission, and
        a run may end with no admitted claim.
        """

        self.proposed_claims = []
        self.claim_admission = []
        self.claim_admission = self._admit_round(session, items, 1)
        rejected = [r for r in self.claim_admission if r.decision != "admitted"]

        if rejected and self.max_claim_corrections > 0:
            action, arguments = self._request_claim_correction(session, rejected)

            if action == "finish":
                self.claim_admission += self._admit_round(session, arguments.get("claims"), 2)

    # -- validation -------------------------------------------------------------

    def _analysis_problem(self, session: ResearchSession, peripheral: Any, palette: _Palette | None = None) -> str:
        palette = palette or _Palette(tools=[])

        for observation in self._census_observations(session):
            if observation.arguments.get("peripheral") == peripheral:
                palette.duplicate = "analyze_peripheral"
                prior = f" (prior run evidence {observation.reused_from})" if observation.reused_from else ""
                return (
                    f"{peripheral} was already analyzed in {observation.id}{prior}; choose a "
                    "different listed peripheral or another action"
                )

        if self._seeded_open(session):
            return "peripheral discovery is withheld while follow-up leads are open; follow a [follow-up] lead"


        return "analyze_peripheral requires one of the listed peripherals"

    def _resolve_set(self, palette: _Palette, items: Any) -> tuple[list[str], str] | str:
        if not isinstance(items, list) or not 1 <= len(items) <= 4:
            return "find_common_paths sets need 1-4 names"

        functions: list[str] = []
        labels: list[str] = []

        for item in items:
            name = str(item).strip()
            upper = name.upper()

            if upper in palette.set_names:
                functions.extend(palette.set_names[upper])
                labels.append(upper)
            elif _FUNCTION_RE.fullmatch(name) and name in palette.known:
                functions.append(name)
                labels.append(name)
            else:
                usable = ", ".join(sorted(palette.set_names)) or "none yet"
                return (
                    f"unknown set member {name[:40]!r}; use analyzed peripheral names "
                    f"({usable}) or FUN_ names from evidence"
                )

        return list(dict.fromkeys(functions)), "+".join(labels)[:40]

    def _parse_structural(
        self,
        session: ResearchSession,
        palette: _Palette,
        name: str,
        arguments: dict[str, Any],
    ) -> tuple[str, dict[str, Any]] | str | None:
        """Validated (action, arguments), a problem, or None if not structural."""

        offered = palette.names()

        if name == "analyze_peripheral" and name in offered:
            peripheral = arguments.get("peripheral")

            if peripheral in palette.analyzable:
                return name, {"peripheral": peripheral}

            return self._analysis_problem(session, peripheral, palette)

        if name == "analyze_usb_interface" and name in offered:
            return name, {}

        if name == "find_common_paths" and name in offered:
            extra = sorted(set(arguments) - {"left", "right"})

            if extra:
                return f"find_common_paths accepts only left and right, not {', '.join(extra)}"

            left = self._resolve_set(palette, arguments.get("left"))
            right = self._resolve_set(palette, arguments.get("right"))

            for side in (left, right):
                if isinstance(side, str):
                    return side

            signature = (left[1], right[1])

            for observation in self._observations(session, "census_common_paths"):
                done = (observation.arguments.get("left_label"), observation.arguments.get("right_label"))

                if done in (signature, signature[::-1]):
                    palette.duplicate = name
                    return f"paths {left[1]}|{right[1]} were already analyzed in {observation.id}"

            return name, {"left": left[0], "right": right[0], "left_label": left[1], "right_label": right[1]}

        if name == "analyze_function_effects" and name in offered:
            extra = sorted(set(arguments) - {"function", "r0", "r1"})

            if extra:
                return (
                    "analyze_function_effects accepts only function and r0/r1 integers; "
                    f"rejected {', '.join(extra)}"
                )

            function = str(arguments.get("function", "")).strip()

            if not _FUNCTION_RE.fullmatch(function) or function not in palette.known:
                return "analyze_function_effects requires a FUN_ name already present in evidence"

            specialize: dict[str, int] = {}

            for register in ("r0", "r1"):
                value = arguments.get(register)

                if value is None:
                    continue

                if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
                    return f"{register} must be an integer in 0..4294967295"

                specialize[register] = value

            for observation in self._observations(session, "function_effects"):
                if (
                    observation.arguments.get("function") == function
                    and (observation.arguments.get("specialize") or {}) == specialize
                ):
                    palette.duplicate = name
                    return f"{function} effects were already analyzed in {observation.id}"

            return name, {"function": function, "specialize": specialize}

        return None

    # -- planner I/O ------------------------------------------------------------

    def _record_request(
        self,
        phase: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        state_chars: int,
        session: ResearchSession,
    ) -> dict[str, Any]:
        messages_json = json.dumps(messages, separators=(",", ":"), ensure_ascii=False)
        tools_json = json.dumps(tools, separators=(",", ":"), ensure_ascii=False)
        record = {
            "phase": phase,
            "evidence": len(session.ledger),
            "open_leads": len(session.state.open_leads()),
            "claims": len(session.state.claims),
            "prompt_chars": len(str(messages[-1]["content"])),
            "state_chars": state_chars,
            "message_bytes": len(messages_json.encode("utf-8")),
            "tool_bytes": len(tools_json.encode("utf-8")),
            "tools": [tool["function"]["name"] for tool in tools],
        }
        record["total_bytes"] = record["message_bytes"] + record["tool_bytes"]
        self.planner_requests.append(record)
        return record

    @staticmethod
    def _tool_call(response: Any) -> tuple[Any, str, dict[str, Any]] | tuple[Any, str]:
        """(message, name, arguments) for exactly one valid call, else (message, problem)."""

        choices = getattr(response, "choices", None)

        if not choices:
            return None, "planner response contained no choices"

        message = getattr(choices[0], "message", None)

        if message is None:
            return None, "planner response choice contained no message"

        tool_calls = getattr(message, "tool_calls", None) or []

        if not tool_calls:
            return message, "expected exactly one tool call, received 0"

        # Several parallel calls: take the first; APTrace validates it like
        # any other, and the rest are ignored.
        call = tool_calls[0]

        try:
            arguments = json.loads(call.function.arguments)
        except (TypeError, json.JSONDecodeError):
            return message, "tool arguments were not valid JSON"

        if not isinstance(arguments, dict):
            return message, "tool arguments were not a JSON object"

        return message, call.function.name, arguments

    def _begin_decision(self) -> None:
        """Choose this decision's projection before its palette is built."""

        compact = self._compact_decisions > 0
        self._compact_decisions = max(0, self._compact_decisions - 1)
        self.projection = self.compact_projection if compact else self.normal_projection

    def _create(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> tuple[Any, bool]:
        """One planner call; (response, rejected-at-prefill)."""

        try:
            response = self.planner_client.chat.completions.create(
                model=self.planner_model,
                temperature=0.0,
                max_tokens=512,
                messages=messages,
                tools=tools,
                tool_choice="auto",
            )
        except Exception as exc:
            if not _prefill_rejected(exc):
                raise

            return None, True

        return response, _prefill_rejected(response)

    def _ask(
        self,
        session: ResearchSession,
        *,
        phase: str,
        system: str,
        prompt_for: Any,
        palette: _Palette,
        parse: Any,
        contract: str,
        exhausted: str,
    ) -> tuple[str, dict[str, Any]]:
        """One planner decision with a single correction retry."""

        try:
            return self._ask_once(
                session,
                phase=phase,
                system=system,
                prompt_for=prompt_for,
                palette=palette,
                parse=parse,
                contract=contract,
                exhausted=exhausted,
            )
        finally:
            self.projection = self.normal_projection

    def _ask_once(
        self,
        session: ResearchSession,
        *,
        phase: str,
        system: str,
        prompt_for: Any,
        palette: _Palette,
        parse: Any,
        contract: str,
        exhausted: str,
    ) -> tuple[str, dict[str, Any]]:
        prompt, state_chars = prompt_for(palette)
        messages = [{"role": "system", "content": system}, {"role": "user", "content": prompt}]
        first_problem: str | None = None
        attempt = 0
        duplicates = 0

        while attempt < 2:
            record = self._record_request(phase, messages, palette.tools, state_chars, session)
            record["attempt"] = attempt

            if self.projection is self.compact_projection:
                record["compact"] = True

            response, rejected = self._create(messages, palette.tools)

            if rejected:
                record["error"] = "prefill_memory_exceeded"

                # The local server's prefill envelope moves with its memory
                # state. Pause, then retry with the compact projection (fewer
                # facts, one result, fewer leads), and stay compact for the
                # rest of this decision and the next three.
                for delay in (self.prefill_retry_delay, self.prefill_retry_delay * 3.3):
                    time.sleep(delay)
                    self.projection = self.compact_projection
                    self._compact_decisions = 3
                    prompt, state_chars = prompt_for(palette)
                    messages = [messages[0], {"role": "user", "content": prompt}]
                    record = self._record_request(phase, messages, palette.tools, state_chars, session)
                    record["attempt"] = attempt
                    record["compact"] = True
                    response, rejected = self._create(messages, palette.tools)

                    if not rejected:
                        break

                    record["error"] = "prefill_memory_exceeded"

                if rejected:
                    return (
                        "planner_prefill_exhausted",
                        {
                            "reason": (
                                "Planner request exceeded the local model prefill memory "
                                "guard, also with the compact projection. Research stopped "
                                "cleanly with all accumulated evidence retained."
                            )
                        },
                    )

            usage = getattr(response, "usage", None)
            record["prompt_tokens"] = getattr(usage, "prompt_tokens", None)

            if os.environ.get("APTRACE_DEBUG_PLANNER_REQUEST") == "1":
                print(f"[planner-request] {json.dumps(record, sort_keys=True)}", file=sys.stderr)

            log_path = os.environ.get("APTRACE_PLANNER_LOG")

            if log_path:
                with open(log_path, "a", encoding="utf-8") as log:
                    message = (getattr(response, "choices", None) or [SimpleNamespace(message=None)])[0].message
                    calls = getattr(message, "tool_calls", None) or []
                    log.write(
                        json.dumps(
                            {
                                "record": record,
                                "messages": messages,
                                "tools": palette.tools,
                                "content": getattr(message, "content", None),
                                "calls": [[c.function.name, c.function.arguments] for c in calls],
                            },
                            default=str,
                        )
                        + "\n"
                    )

            parsed = self._tool_call(response)
            message = parsed[0]

            if len(parsed) == 3:
                _message, name, arguments = parsed
                outcome = parse(palette, name, arguments)

                if isinstance(outcome, tuple):
                    record["decision"] = outcome[0]
                    return outcome

                problem = outcome
            else:
                problem = parsed[1]

            if palette.duplicate and duplicates < len(STRUCTURAL_TOOLS) + 1:
                # A repeated analysis is detected deterministically: retry
                # as a fresh, smaller request without that tool, keep it
                # withheld for the next two decisions, and do not spend the
                # single correction on it.
                duplicates += 1
                first_problem = first_problem or problem
                self._cooldown[palette.duplicate] = 2
                palette.drop(palette.duplicate)
                palette.duplicate = None
                prompt, state_chars = prompt_for(palette)
                messages = [messages[0], {"role": "user", "content": prompt}]
                continue

            if attempt == 0:
                first_problem = first_problem or problem
                attempt = 1
                content = (getattr(message, "content", None) or "") if message is not None else ""
                messages = messages + [
                    {"role": "assistant", "content": content},
                    {
                        "role": "user",
                        "content": (
                            f"Your previous response did not satisfy the {contract} contract: "
                            f"{problem}. Make exactly one valid "
                            + ", ".join(name for name in palette.names() if name != "finish")
                            + " or finish tool call now."
                        ),
                    },
                ]
                continue

            if exhausted == "finish":
                return (
                    "finish",
                    {
                        "reason": (
                            "Discovery planner could not produce a new valid search direction "
                            f"after one correction; first error: {first_problem}; second error: {problem}"
                        )
                    },
                )

            return (
                exhausted,
                {
                    "reason": (
                        "Planner could not produce a valid research decision after one "
                        f"correction; first error: {first_problem}; second error: {problem}"
                    )
                },
            )

        raise AssertionError("unreachable")

    # -- prompts ----------------------------------------------------------------

    def _state_digest(self, session: ResearchSession) -> str:
        return self.projection.render(session)

    def _analysis_guidance(self, session: ResearchSession, palette: _Palette | list[str]) -> str:
        if isinstance(palette, list):
            names = ["analyze_peripheral"] if palette else []
            set_names: dict[str, list[str]] = {}
        else:
            names = palette.names()
            set_names = palette.set_names

        structural = [
            name
            for name in ("analyze_peripheral", "analyze_usb_interface", "find_common_paths", "analyze_function_effects")
            if name in names
        ]

        if not structural:
            return ""

        order = ["case evidence"]

        if "analyze_peripheral" in structural:
            done = ", ".join(
                str(observation.arguments.get("peripheral"))
                for observation in self._census_observations(session)
            )
            order.append(
                "analyze_peripheral for a peripheral relevant to the objective"
                + (f" (already run: {done})" if done else "")
            )

        if "analyze_usb_interface" in structural:
            order.append("analyze_usb_interface")

        if "find_common_paths" in structural:
            order.append(
                "find_common_paths (sets: "
                + (", ".join(sorted(set_names)) or "FUN_ names")
                + ")"
            )

        if "analyze_function_effects" in structural:
            order.append("analyze_function_effects if dataflow matters")

        order += ["leads", "caller/callee expansion only for a specific question"]

        return (
            "\nSTRUCTURAL ANALYSIS (prefer earlier): "
            + "; ".join(order)
            + ". Census facts do not identify attached devices.\n"
        )

    def _planner_open_leads(self, session: ResearchSession):
        """
        Return a bounded, ranked working set for the planner.

        Structural narrowing (census, inventory, graph, effects, case
        discovery) ranks before per-function crawling; within a rank the
        newest lead comes first. APTrace retains the complete lead graph.
        """

        def rank(lead) -> tuple[int, int]:
            number = int(lead.id.lstrip("L") or 0)

            try:
                action = session.registry.resolve(lead.id)
            except (KeyError, ValueError):
                return 9, -number

            structural = False

            for evidence_id in lead.source_evidence_ids:
                try:
                    structural |= session.ledger.get(evidence_id).tool in _STRUCTURAL_SOURCES
                except KeyError:
                    pass

            if not lead.source_evidence_ids:
                structural = True

            base = {
                "function_facts": 0,
                "function_disassembly": 1,
                "pin_table_entry": 2,
                "search_case_evidence": 2,
                "census_peripheral_usage": 0,
                "callsite_context": 4,
            }.get(action.tool, 3)

            if not structural and action.tool in ("function_facts", "function_disassembly"):
                base += 2

            return base, -number

        # Follow-up leads first: they are why this run exists.
        ranked = sorted(session.state.open_leads(), key=lambda lead: (lead.origin is None, *rank(lead)))
        limit = 4 if self.projection is self.compact_projection else self.max_visible_leads
        return ranked[:limit]

    def _compact_lead(self, session: ResearchSession, lead) -> str:
        text = self._compact_lead_text(session, lead)
        return text + " [follow-up]" if lead.origin else text

    def _compact_lead_text(self, session: ResearchSession, lead) -> str:
        """
        Give the planner only the structural identity needed to choose a
        lead. APTrace retains descriptions, provenance and arguments.
        """

        try:
            action = session.registry.resolve(lead.id)
        except (KeyError, ValueError):
            return f"{lead.id} [{lead.kind}]"

        tool = action.tool
        args = action.arguments
        origin = ""

        if tool in {"function_facts", "function_disassembly"}:
            return f"{lead.id} {tool} {args.get('function', '?')}{origin}"

        if tool == "callsite_context":
            return f"{lead.id} callsite {args.get('function', '?')}@{args.get('address', '?')}{origin}"

        if tool == "census_peripheral_usage":
            return f"{lead.id} census peripheral {args.get('peripheral', '?')}"

        if tool == "pin_table_entry":
            return f"{lead.id} pin_table_entry index={args.get('index', '?')}{origin}"

        if tool == "search_case_evidence":
            return f"{lead.id} case_search {clip(str(args.get('query', '')), 80)!r}"

        return f"{lead.id} [{lead.kind}] {tool}"

    def _research_state(self, session: ResearchSession) -> tuple[str, int]:
        state = self._state_digest(session)
        reused = sum(o.reused_from is not None for o in session.ledger.all())
        count = f"{len(session.ledger)} evidence records retained" + (f", {reused} reused from prior runs" if reused else "")
        return f"STATE ({count})\n{state}", len(state)

    def _prompt(self, session: ResearchSession, palette: _Palette | list[str]) -> str:
        return self._decision_prompt(session, palette)[0]

    def _decision_prompt(self, session: ResearchSession, palette: _Palette | list[str]) -> tuple[str, int]:
        if isinstance(palette, list):
            # Compatibility path: a bare list of analyzable peripherals.
            built = self._decision_palette(session)

            if not palette:
                built.drop("analyze_peripheral")

            palette = built

        open_leads = [lead for lead in self._planner_open_leads(session) if lead.id in palette.lead_ids]
        all_open = session.state.open_leads()
        lead_text = "\n".join(self._compact_lead(session, lead) for lead in open_leads) or "(none)"

        if len(all_open) > len(open_leads):
            lead_text += f"\n[{len(open_leads)} of {len(all_open)} shown]"

        state, state_chars = self._research_state(session)

        return (
            f"""OBJECTIVE: {self.projection.objective(session)}

{state}

LEADS (APTrace-validated)
{lead_text}
{self._analysis_guidance(session, palette)}
TASK: make exactly one tool call, by the first rule that applies:
{self._followup_rule(session)}1) a subsystem the objective names is not under ALREADY RUN: analyze it;
2) the objective asks whether subsystems connect and their sets exist:
   find_common_paths (once per pair);
3) otherwise follow LEADS the analyses named (caller/callee leads only for
   a specific question);
4) evidence suffices: finish, listing hypotheses and open questions{self._claim_guidance()}.
Never repeat an ALREADY RUN analysis or invent identifiers.
""",
            state_chars,
        )

    def _followup_rule(self, session: ResearchSession) -> str:
        if not self._seeded_open(session):
            return ""

        return "0) [follow-up] leads are the open question this run exists for: follow one;\n"

    def _claim_guidance(self) -> str:
        if not self.claim_contract:
            return ""

        return f",\n   and claims (one '{CLAIM_FORMAT}' line each) for evidence-backed conclusions"

    def _discovery_prompt(
        self,
        session: ResearchSession,
        attempted_queries: set[str],
        palette: _Palette | list[str],
    ) -> str:
        return self._discovery_prompt_sized(session, attempted_queries, palette)[0]

    def _discovery_prompt_sized(
        self,
        session: ResearchSession,
        attempted_queries: set[str],
        palette: _Palette | list[str],
    ) -> tuple[str, int]:
        attempted = "; ".join(sorted(attempted_queries)) or "(none)"
        state, state_chars = self._research_state(session)

        return (
            f"""OBJECTIVE: {self.projection.objective(session)}

TASK: one lexical search (1-3 discriminative terms, a new angle each time:
device, peripheral, protocol, signal) of case documents for firmware anchors
or hardware facts. Never invent identifiers. Use search_case_evidence once,
or finish if no search would help.
{self._discovery_analysis_guidance(session, palette)}
{state}

SEARCHES TRIED: {attempted}
""",
            state_chars,
        )

    def _discovery_analysis_guidance(self, session: ResearchSession, palette: _Palette | list[str]) -> str:
        guidance = self._analysis_guidance(session, palette)

        if not guidance:
            return ""

        return (
            "For a peripheral or interface, a structural analysis (such as "
            "analyze_peripheral) may be used instead.\n" + guidance
        )

    # -- requests ---------------------------------------------------------------

    def _request_decision(self, session: ResearchSession) -> tuple[str, dict[str, Any]]:
        self._begin_decision()
        palette = self._decision_palette(session)

        def parse(palette: _Palette, name: str, arguments: dict[str, Any]):
            if name == "follow_lead" and "follow_lead" in palette.names():
                if arguments.get("lead_id") in palette.lead_ids:
                    return name, {"lead_id": arguments["lead_id"]}

                return "follow_lead referenced an unavailable lead"

            if name == "finish":
                reason = arguments.get("reason")

                if isinstance(reason, str) and reason.strip():
                    return name, arguments

                return "finish requires a non-empty reason"

            outcome = self._parse_structural(session, palette, name, arguments)
            return outcome if outcome is not None else f"unexpected tool {name!r}"

        return self._ask(
            session,
            phase="decision",
            system=(
                "You direct a bounded firmware research investigation. APTrace owns "
                "evidence, structural facts, tool arguments, and provenance. You choose "
                "research direction. Make exactly one tool call."
            ),
            prompt_for=lambda palette: self._decision_prompt(session, palette),
            palette=palette,
            parse=parse,
            contract="controller",
            exhausted="planner_contract_exhausted",
        )

    def _request_discovery(
        self,
        session: ResearchSession,
        attempted_queries: set[str],
    ) -> tuple[str, dict[str, Any]]:
        self._begin_decision()
        palette = self._discovery_palette(session)

        def parse(palette: _Palette, name: str, arguments: dict[str, Any]):
            if name == "search_case_evidence":
                query = str(arguments.get("query", "")).strip()

                if not 2 <= len(query) <= 120:
                    return "discovery query must be 2..120 characters"

                if query.casefold() in attempted_queries:
                    return "discovery query was already tried"

                return name, {"query": query}

            if name == "finish":
                reason = str(arguments.get("reason", "")).strip()
                return (name, {"reason": reason}) if reason else "finish requires a non-empty reason"

            outcome = self._parse_structural(session, palette, name, arguments)
            return outcome if outcome is not None else f"unexpected discovery tool {name!r}"

        return self._ask(
            session,
            phase="discovery",
            system=(
                "You choose semantic discovery direction for a bounded firmware "
                "investigation. APTrace owns structural identities and validates "
                "anything discovered. Make exactly one tool call."
            ),
            prompt_for=lambda palette: self._discovery_prompt_sized(session, attempted_queries, palette),
            palette=palette,
            parse=parse,
            contract="discovery",
            exhausted="finish",
        )

    def _request_final_claims(self, session: ResearchSession) -> tuple[str, dict[str, Any]]:
        """
        Claim contract only: after the step budget, one finish-only request
        so the planner can state its evidence-backed claims. No analysis
        tool is offered; research direction is unaffected.
        """

        self._begin_decision()
        palette = _Palette(tools=[self._finish_tool()])

        def prompt_for(palette: _Palette) -> tuple[str, int]:
            state, state_chars = self._research_state(session)
            return (
                f"""OBJECTIVE: {self.projection.objective(session)}

{state}

TASK: the step budget is exhausted; no further analysis is possible. Call
finish now with your reason and claims: one line per evidence-backed
conclusion, formatted '{CLAIM_FORMAT}', for example
'PROBABLE BEHAVIOR E2 <assertion>'. Name functions exactly as FUN_xxxxxxxx.
State only what the cited evidence shows; claims are graded PROBABLE.
""",
                state_chars,
            )

        def parse(palette: _Palette, name: str, arguments: dict[str, Any]):
            if name == "finish" and isinstance(arguments.get("reason"), str) and arguments["reason"].strip():
                return name, arguments

            return "call finish with a non-empty reason"

        return self._ask(
            session,
            phase="final-claims",
            system=(
                "You concluded a bounded firmware research investigation. APTrace owns "
                "evidence and verification. Make exactly one finish tool call."
            ),
            prompt_for=prompt_for,
            palette=palette,
            parse=parse,
            contract="final claims",
            exhausted="planner_contract_exhausted",
        )

    def _request_claim_correction(self, session: ResearchSession, rejected: list[Any]) -> tuple[str, dict[str, Any]]:
        """One finish-only request showing why proposals were not admitted."""

        from aptrace_agent.research.admission import feedback

        self._begin_decision()
        palette = _Palette(tools=[self._finish_tool()])
        diagnostics = feedback(rejected)

        def prompt_for(palette: _Palette) -> tuple[str, int]:
            state, state_chars = self._research_state(session)
            return (
                f"""OBJECTIVE: {self.projection.objective(session)}

{state}

APTrace did not admit these claims:
{diagnostics}

TASK: call finish once more with corrected claims, one per line, for
example 'PROBABLE BEHAVIOR E2,E5 FUN_0000a000 <assertion>', or with no
claims if the evidence does not support one. Claims without
typed semantics are PROPOSED hypotheses: grade them PROBABLE and state only
what the cited evidence shows. To leave out follow-up evidence, append
'[omit E#: reason]' to the line.
""",
                state_chars,
            )

        def parse(palette: _Palette, name: str, arguments: dict[str, Any]):
            if name == "finish" and isinstance(arguments.get("reason"), str) and arguments["reason"].strip():
                return name, arguments

            return "call finish with a non-empty reason"

        return self._ask(
            session,
            phase="claim-correction",
            system=(
                "You concluded a bounded firmware research investigation. APTrace owns "
                "evidence and verification. Make exactly one finish tool call."
            ),
            prompt_for=prompt_for,
            palette=palette,
            parse=parse,
            contract="claim correction",
            exhausted="planner_contract_exhausted",
        )

    # -- execution --------------------------------------------------------------

    def _follow_new_lead(self, session: ResearchSession, *, kind: str, description: str, tool: str, arguments: dict[str, Any], step: int | None = None):
        lead = session.registry.register(
            kind=kind,
            description=description,
            tool=tool,
            arguments=arguments,
            source_evidence_ids=[],
        )

        if all(existing.id != lead.id for existing in session.state.leads):
            session.state.add_lead(lead)

        return lead, session.follow_lead(lead.id, step=step)

    def _follow_peripheral_analysis(self, session: ResearchSession, peripheral: str, step: int | None = None):
        return self._follow_new_lead(
            session,
            step=step,
            kind="census",
            description=f"Census structural usage of peripheral {peripheral}",
            tool="census_peripheral_usage",
            arguments={"peripheral": peripheral, "limit": 25},
        )

    def _follow_discovery_search(self, session: ResearchSession, query: str):
        return self._follow_new_lead(
            session,
            kind="discovery",
            description=f"Search existing case evidence for discovery query {query!r}",
            tool="search_case_evidence",
            arguments={"query": query, "max_results": 8, "purpose": "discovery"},
        )

    def _execute_structural(self, session: ResearchSession, action: str, arguments: dict[str, Any], step: int | None = None):
        """Run one validated structural action; return (step action, lead, observation)."""

        if action == "analyze_peripheral":
            lead, observation = self._follow_peripheral_analysis(session, arguments["peripheral"], step)
            return "analyze", lead, observation

        if action == "analyze_usb_interface":
            lead, observation = self._follow_new_lead(
                session,
                step=step,
                kind="usb-inventory",
                description="USB structural inventory",
                tool="census_usb_inventory",
                arguments={},
            )
            return "usb_inventory", lead, observation

        if action == "find_common_paths":
            lead, observation = self._follow_new_lead(
                session,
                step=step,
                kind="graph",
                description=f"Common paths {arguments['left_label']} | {arguments['right_label']}",
                tool="census_common_paths",
                arguments=arguments,
            )
            return "common_paths", lead, observation

        if action == "analyze_function_effects":
            lead, observation = self._follow_new_lead(
                session,
                step=step,
                kind="effects",
                description=f"Function effects of {arguments['function']}",
                tool="function_effects",
                arguments=arguments,
            )
            return "effects", lead, observation

        raise ValueError(f"not a structural action: {action}")

    def _record_conclusions(self, session: ResearchSession, arguments: dict[str, Any]) -> None:
        """Planner-proposed hypotheses and open questions; never PROVEN."""

        for key, merge in (
            ("hypotheses", lambda text: self.updater.merge_hypothesis(session.state, statement=text, evidence_ids=[], source="planner")),
            ("open_questions", lambda text: self.updater.merge_open_question(session.state, question=text, evidence_ids=[], source="planner")),
        ):
            items = arguments.get(key)

            if not isinstance(items, list):
                continue

            for item in items[:3]:
                if isinstance(item, str) and item.strip():
                    merge(clip(item, 240))

    def _has_case_evidence(self, session: ResearchSession) -> bool:
        return any(
            observation.tool == "search_case_evidence"
            and observation.arguments.get("purpose") != "discovery"
            for observation in session.ledger.all()
        )

    def _reconcile_terminal(self, session: ResearchSession) -> bool:
        if not self._has_case_evidence(session):
            return False

        self.reconciler.run(session)
        return True

    def _structural_available(self, session: ResearchSession) -> bool:
        palette = _Palette(tools=[])
        self._structural_palette(session, palette)
        return bool(palette.tools)

    def _result(self, stop_reason: str, steps: list[ResearchStep], reconciled: bool) -> ResearchRunResult:
        return ResearchRunResult(
            stop_reason=stop_reason,
            steps=tuple(steps),
            reconciled=reconciled,
            planner_requests=tuple(self.planner_requests),
            proposed_claims=tuple(self.proposed_claims),
            claim_admission=tuple(self.claim_admission),
        )

    def _fallback_lead(self, session: ResearchSession):
        """Top open follow-up lead APTrace may follow when the planner fails, or None."""

        continuity = getattr(session, "continuity", None)

        if continuity is None or continuity.fallbacks >= continuity.max_fallbacks:
            return None

        seeded = [lead for lead in self._planner_open_leads(session) if lead.origin]
        return seeded[0] if seeded else None

    def run(self, session: ResearchSession) -> ResearchRunResult:
        """
        Budget: each executed action charges one step (max_steps). In a
        follow-up session (session.continuity) an action satisfied by a
        historical result charges nothing for the first max_free_reuses
        reuses and one step after that, so decisions never exceed
        max_steps + max_free_reuses. Without continuity every decision is
        one step, exactly as before.
        """

        steps: list[ResearchStep] = []
        objective_discovery = not session.ledger.all() and not session.state.open_leads()
        discovery_attempts = 0
        discovery_queries: set[str] = set()
        continuity = getattr(session, "continuity", None)
        charged = 0
        decision = 0

        def charge(observation) -> None:
            nonlocal charged
            charged += continuity.charge(observation.reused_from is not None) if continuity is not None else 1

            if continuity is not None:
                continuity.steps_charged = charged

        while charged < self.max_steps:
            decision += 1
            step_number = decision

            if continuity is not None:
                continuity.decisions = decision

            open_leads = session.state.open_leads()
            discovering = (
                not open_leads
                and objective_discovery
                and discovery_attempts < self.max_discovery_steps
            )

            # With no lead left, research continues only through an enabled
            # structural analysis that has not yet run.
            if (
                not open_leads
                and not discovering
                and not (self.structural_tools and self._structural_available(session))
            ):
                if (
                    objective_discovery
                    and self.max_discovery_steps > 0
                    and discovery_attempts >= self.max_discovery_steps
                ):
                    return self._result("discovery_exhausted", steps, False)

                return self._result("research_graph_exhausted", steps, self._reconcile_terminal(session))

            if discovering:
                action, arguments = self._request_discovery(session, discovery_queries)
            else:
                action, arguments = self._request_decision(session)

            if action == "planner_contract_exhausted" and (lead := self._fallback_lead(session)) is not None:
                # The planner produced no valid decision; APTrace takes the
                # top open follow-up lead instead of ending the run.
                continuity.fallbacks += 1
                observation = session.follow_lead(lead.id, step=step_number, trigger="fallback")
                steps.append(
                    ResearchStep(
                        number=step_number,
                        action="fallback_lead",
                        lead_id=lead.id,
                        evidence_id=observation.id,
                        reason=str(arguments["reason"]).strip()[:300],
                        reused_from=observation.reused_from,
                    )
                )
                charge(observation)
                continue

            if action in {"planner_prefill_exhausted", "planner_contract_exhausted"}:
                steps.append(ResearchStep(number=step_number, action="finish", reason=str(arguments["reason"]).strip()))

                # A follow-up whose planner fails after doing work still gets
                # the bounded final-claims request, as at budget exhaustion.
                if continuity is not None and action == "planner_contract_exhausted" and self.claim_contract and charged:
                    final, final_arguments = self._request_final_claims(session)

                    if final == "finish":
                        self._record_conclusions(session, final_arguments)
                        self._accept_claims(session, final_arguments.get("claims"))

                return self._result(action, steps, self._reconcile_terminal(session))

            if action == "finish":
                steps.append(ResearchStep(number=step_number, action="finish", reason=str(arguments["reason"]).strip()))

                if discovering:
                    return self._result("discovery_finished", steps, False)

                self._record_conclusions(session, arguments)

                if self.claim_contract:
                    self._accept_claims(session, arguments.get("claims"))
                return self._result("planner_finished", steps, self._reconcile_terminal(session))

            if action == "search_case_evidence":
                query = str(arguments["query"]).strip()
                discovery_queries.add(query.casefold())
                lead, observation = self._follow_discovery_search(session, query)
                discovery_attempts += 1
                steps.append(ResearchStep(number=step_number, action="discover", lead_id=lead.id, evidence_id=observation.id, reused_from=observation.reused_from))
                charge(observation)
                continue

            if action == "follow_lead":
                lead_id = str(arguments["lead_id"])
                observation = session.follow_lead(lead_id, step=step_number)
                steps.append(ResearchStep(number=step_number, action="follow_lead", lead_id=lead_id, evidence_id=observation.id, reused_from=observation.reused_from))
                charge(observation)
                continue

            step_action, lead, observation = self._execute_structural(session, action, arguments, step=step_number)
            steps.append(ResearchStep(number=step_number, action=step_action, lead_id=lead.id, evidence_id=observation.id, reused_from=observation.reused_from))
            charge(observation)

        if self.claim_contract:
            action, arguments = self._request_final_claims(session)

            if action == "finish":
                self._record_conclusions(session, arguments)
                self._accept_claims(session, arguments.get("claims"))

        return self._result("step_budget_exhausted", steps, self._reconcile_terminal(session))
