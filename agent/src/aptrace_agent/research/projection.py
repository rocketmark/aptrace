from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from aptrace_agent.research.session import ResearchSession
from aptrace_agent.research.state import Claim
from aptrace_agent.schemas import EvidenceObservation


# Tools whose single invocation answers a subsystem-level question. The
# planner sees which of these have already run so it does not reissue them.
SUBSYSTEM_TOOLS = (
    "census_peripheral_usage",
    "census_usb_inventory",
    "census_common_paths",
    "function_effects",
    "observed_call_arguments",
    "indirect_call_target",
    "callback_argument_provenance",
    "value_forward_use",
)

# Per-function inspection tools, summarized as "already inspected".
INSPECTION_TOOLS = {
    "function_facts": "facts",
    "function_disassembly": "dis",
    "function_effects": "effects",
    "callsite_context": "callsite",
}

_FUNCTION_RE = re.compile(r"\bFUN_[0-9a-f]{8}\b")

_BASIS_TAGS = {
    "census": "census",
    "census-graph": "graph",
    "raw-symbolic": "RAW",
    "solver": "SOLVER",
    "case-document": "case",
    "disassembly": "dis",
    "static-table": "table",
    "concrete-observed": "OBS",
    "static-dataflow": "DF",
}


@dataclass(frozen=True)
class ProjectionBudget:
    """
    Character budgets for the dynamic planner state.

    Characters, not tokens: the planner prompt is mostly ASCII identifiers
    and prose, so ~3.5-4 characters per token is a stable enough proxy and
    needs no tokenizer dependency. ``total`` bounds the whole dynamic
    research state (objective excluded); the section budgets keep any one
    kind of history from crowding out the others.
    """

    objective: int = 640
    analyses: int = 300
    inspected: int = 170
    facts: int = 700
    fact_line: int = 160
    open_items: int = 260
    item_line: int = 130
    latest: int = 480
    latest_first: int = 330
    latest_count: int = 2
    total: int = 1700


# Used for one retry when the local model rejects a request at prefill.
COMPACT_BUDGET = ProjectionBudget(
    analyses=220,
    inspected=0,
    facts=330,
    open_items=130,
    latest=260,
    latest_first=260,
    latest_count=1,
    total=850,
)


def clip(text: str, limit: int) -> str:
    text = " ".join(str(text).split())

    if len(text) <= limit:
        return text

    return text[: max(0, limit - 3)].rstrip() + "..."


def _clip_lines(text: str, limit: int) -> str:
    """Clip multi-line text to ``limit`` characters on a line boundary."""

    if len(text) <= limit:
        return text

    kept: list[str] = []
    used = 0

    for line in text.splitlines():
        if used + len(line) + 1 > limit - 4:
            break

        kept.append(line)
        used += len(line) + 1

    if not kept:
        return clip(text, limit)

    return "\n".join(kept) + "\n ..."


def functions_in(value: Any) -> list[str]:
    """Function identities mentioned anywhere in a JSON-like value, in
    first-seen order."""

    text = json.dumps(value, sort_keys=False, default=str)
    return list(dict.fromkeys(_FUNCTION_RE.findall(text)))


def _evidence_number(evidence_id: str) -> int:
    try:
        return int(evidence_id.lstrip("E"))
    except ValueError:
        return 0


def summarize_observation(
    observation: EvidenceObservation,
    limit: int = 600,
) -> str:
    """
    Deterministic, bounded planner-facing rendering of one observation.

    The complete result stays in the evidence ledger. A tool that
    precomputes its own ``planner_summary`` owns its semantics; others are
    rendered here. Unknown tools are never dumped unbounded.
    """

    result = observation.result
    head = f"{observation.id} {observation.tool}"

    summary = result.get("planner_summary") if isinstance(result, dict) else None

    if summary:
        return _clip_lines(f"{observation.id} {summary}", limit)

    tool = observation.tool

    if tool == "function_facts":
        text = (
            f"{head}: {result.get('name')} entry={result.get('entry')} "
            f"size={result.get('size')} "
            f"callers={result.get('unique_caller_count', len(result.get('callers', [])))} "
            f"callees={result.get('unique_callee_count', len(result.get('callees', [])))}"
        )

    elif tool == "function_disassembly":
        instructions = result.get("instructions", [])
        first = instructions[0].get("address") if instructions else None
        last = instructions[-1].get("address") if instructions else None
        text = (
            f"{head}: {result.get('name')} {len(instructions)} instructions "
            f"{first}..{last}; full listing retained by APTrace"
        )

    elif tool == "callsite_context":
        instructions = result.get("instructions", [])
        callsite = result.get("address")
        index = next(
            (
                i
                for i, item in enumerate(instructions)
                if item.get("address") == callsite
            ),
            None,
        )
        selected = (
            instructions[:6]
            if index is None
            else instructions[max(0, index - 2): index + 4]
        )
        rendered = "\n".join(
            f"  {item.get('address')} {item.get('mnemonic')} "
            f"{item.get('operands', '')}".rstrip()
            for item in selected
        )
        text = f"{head} {result.get('function')} @ {callsite}:\n{rendered}"

    elif tool == "census_peripheral_usage":
        text = _summarize_census(observation)

    elif tool == "pin_table_entry":
        text = (
            f"{head}: index={result.get('index')} gpio={result.get('gpio')} "
            f"group={result.get('group')} bit={result.get('bit')}"
        )

    elif tool == "search_case_evidence":
        matches = result.get("matches", [])
        sources = ", ".join(
            f"{m.get('source')}:{m.get('line')}" for m in matches[:3]
        )
        excerpt = ""

        if matches:
            excerpt = clip(matches[0].get("excerpt", ""), 240)

        text = (
            f"{head} query={result.get('query')!r}: "
            f"{len(matches)} match(es) [{sources}]"
            + (f"\n  top: {excerpt}" if excerpt else "")
        )

    else:
        text = f"{head}: {json.dumps(result, sort_keys=True, default=str)}"

    return _clip_lines(text, limit)


def _summarize_census(observation: EvidenceObservation) -> str:
    result = observation.result
    header = (
        f"{observation.id} census_peripheral_usage "
        f"{result.get('peripheral')}: status={result.get('status')}"
    )

    if result.get("status") != "ok":
        return f"{header} ({result.get('diagnostic')})"

    functions = [
        item.get("function") for item in result.get("functions", [])[:6]
    ]
    unattributed = [
        str(item.get("site")) for item in result.get("unattributed_sites", [])[:4]
    ]

    return (
        f"{header} mmio_sites={result.get('total_mmio_sites')} "
        f"address_constants={result.get('total_address_constants')} "
        f"(unreferenced={result.get('unreferenced_address_constants')}) "
        f"functions={result.get('total_functions')} [{', '.join(functions)}]"
        + (
            f" unattributed_sites=[{', '.join(unattributed)}]"
            if unattributed
            else ""
        )
    )


def analysis_label(observation: EvidenceObservation) -> str | None:
    """Short identity of a subsystem-level analysis, or None."""

    args = observation.arguments

    if observation.tool == "census_peripheral_usage":
        return f"census {args.get('peripheral')}"

    if observation.tool == "census_usb_inventory":
        return "usb-inventory"

    if observation.tool == "census_common_paths":
        return (
            f"paths {args.get('left_label', '?')}|{args.get('right_label', '?')}"
        )

    if observation.tool == "function_effects":
        specs = args.get("specialize") or {}
        suffix = "".join(f",{k}={v}" for k, v in sorted(specs.items()))
        return f"effects {args.get('function')}{suffix}"

    if observation.tool == "observed_call_arguments":
        return f"observed {args.get('function')}@{args.get('scenario') or 'boot'}"

    if observation.tool == "indirect_call_target":
        return f"indirect {args.get('site')}"

    if observation.tool == "callback_argument_provenance":
        return f"callback {args.get('site')}"

    if observation.tool == "value_forward_use":
        return f"value use {args.get('origin')}"

    if (
        observation.tool == "search_case_evidence"
        and args.get("purpose") == "discovery"
    ):
        return f"case {clip(str(args.get('query')), 40)!r}"

    return None


class PlannerProjection:
    """
    Bounded planner-facing view of a research session.

    The ledger, claims, hypotheses, leads and provenance stay complete in
    APTrace. This class only decides what the planner sees for the next
    decision: the objective, which analyses already ran, which functions
    were inspected, the newest facts, open questions, and compact
    renderings of the latest results. Every section has its own budget and
    the whole is capped, so the projection reaches a stable bound no
    matter how long research runs.
    """

    def __init__(self, budget: ProjectionBudget | None = None) -> None:
        self.budget = budget or ProjectionBudget()

    # -- sections -----------------------------------------------------------

    def _analyses(self, observations: Sequence[EvidenceObservation]) -> str:
        # A reused historical result is marked: it is not a new observation.
        labels = [
            f"{label}({obs.id}{'=prior' if obs.reused_from else ''})"
            for obs in observations
            if (label := analysis_label(obs)) is not None
        ]

        if not labels:
            return ""

        return self._joined_tail("ALREADY RUN: ", labels, self.budget.analyses)

    def _inspected(self, observations: Sequence[EvidenceObservation]) -> str:
        if self.budget.inspected <= 0:
            return ""

        inspected: dict[str, list[str]] = {}

        for obs in observations:
            tag = INSPECTION_TOOLS.get(obs.tool)

            if tag is None:
                continue

            function = obs.arguments.get("function")

            if not function:
                continue

            tags = inspected.setdefault(str(function), [])

            if tag not in tags:
                tags.append(tag)

        if not inspected:
            return ""

        items = [f"{name}({'/'.join(tags)})" for name, tags in inspected.items()]
        return self._joined_tail("INSPECTED: ", items, self.budget.inspected)

    @staticmethod
    def _joined_tail(prefix: str, items: list[str], limit: int) -> str:
        """Join items, keeping the newest when they do not all fit."""

        kept: list[str] = []
        used = len(prefix)

        for item in reversed(items):
            if used + len(item) + 2 > limit - 24:
                break

            kept.append(item)
            used += len(item) + 2

        kept.reverse()
        omitted = len(items) - len(kept)
        text = prefix + ", ".join(kept)

        if omitted:
            text += f" [+{omitted} earlier]"

        return text

    def _facts(self, claims: Sequence[Claim]) -> str:
        if not claims:
            return ""

        def recency(claim: Claim) -> tuple[int, int]:
            newest = max(
                (_evidence_number(e) for e in claim.evidence_ids),
                default=0,
            )
            return newest, _evidence_number(claim.id.lstrip("C"))

        ranked = sorted(claims, key=recency, reverse=True)
        lines: list[str] = []
        used = 0

        for claim in ranked:
            tag = _BASIS_TAGS.get(claim.basis or "", claim.grade.value.lower())

            if claim.grade.value != "PROVEN":
                tag = f"{tag},supported"

            line = clip(f"{claim.id}[{tag}] {claim.statement}", self.budget.fact_line)

            if used + len(line) + 1 > self.budget.facts:
                break

            lines.append(line)
            used += len(line) + 1

        omitted = len(ranked) - len(lines)
        header = f"FACTS (newest; {len(lines)} of {len(ranked)}"
        header += f", {omitted} older retained by APTrace)" if omitted else ")"

        return header + "\n" + "\n".join(lines)

    def _open_items(self, session: ResearchSession) -> str:
        state = session.state
        items: list[str] = []

        for hypothesis in reversed(state.hypotheses):
            items.append(clip(f"{hypothesis.id}[hypothesis] {hypothesis.statement}", self.budget.item_line))

        for contradiction in reversed(state.contradictions):
            items.append(clip(f"{contradiction.id}[contradiction] {contradiction.description}", self.budget.item_line))

        for question in reversed(state.open_questions):
            if question.status.value == "OPEN":
                items.append(clip(f"{question.id}[open] {question.question}", self.budget.item_line))

        if not items or self.budget.open_items <= 0:
            return ""

        lines: list[str] = []
        used = 0

        for item in items:
            if used + len(item) + 1 > self.budget.open_items:
                break

            lines.append(item)
            used += len(item) + 1

        omitted = len(items) - len(lines)
        header = "OPEN"

        if omitted:
            header += f" ({omitted} more retained by APTrace)"

        return header + "\n" + "\n".join(lines)

    def _latest(self, observations: Sequence[EvidenceObservation]) -> str:
        recent = list(observations[-self.budget.latest_count:])

        if not recent:
            return ""

        rendered: list[str] = []
        remaining = self.budget.latest

        for position, obs in enumerate(reversed(recent)):
            limit = self.budget.latest_first if position == 0 else remaining

            limit = min(limit, remaining)

            if limit < 80:
                break

            text = summarize_observation(obs, limit)
            rendered.append(text)
            remaining -= len(text) + 2

        return "LATEST\n" + "\n".join(rendered)

    # -- assembly -----------------------------------------------------------

    def sections(self, session: ResearchSession) -> list[str]:
        observations = session.ledger.all()
        continuity = getattr(session, "continuity", None)
        # Preloaded prior results are context, not this run's newest results.
        preloaded = continuity.preloaded if continuity is not None else set()
        recent = [obs for obs in observations if obs.id not in preloaded]

        return [
            section
            for section in (
                self._analyses(observations),
                self._inspected(observations),
                self._facts(session.state.claims),
                self._open_items(session),
                self._latest(recent),
            )
            if section
        ]

    def render(self, session: ResearchSession) -> str:
        """Dynamic research state, bounded by ``budget.total``."""

        sections = self.sections(session)

        if not sections:
            return "(no research state yet)"

        text = "\n\n".join(sections)

        if len(text) <= self.budget.total:
            return text

        # Section budgets sum above the total so that sparse sections leave
        # room for dense ones; when all are dense, trim the longest.
        while len(text) > self.budget.total:
            longest = max(range(len(sections)), key=lambda i: len(sections[i]))
            excess = len(text) - self.budget.total
            target = max(120, len(sections[longest]) - excess)
            sections[longest] = _clip_lines(sections[longest], target)
            text = "\n\n".join(sections)

            if all(len(section) <= 124 for section in sections):
                break

        return text

    def objective(self, session: ResearchSession) -> str:
        text = " ".join(session.state.objective.split())

        if len(text) <= self.budget.objective:
            return text

        # Say that text was lost rather than letting a clipped objective
        # pass as complete. A focused run (research/objective.py) shows its
        # declared objective whole instead.
        kept = clip(text, self.budget.objective)
        return f"{kept} [objective clipped: {len(text) - len(kept) + 3} more characters not shown]"


def known_functions(observations: Iterable[EvidenceObservation]) -> list[str]:
    """Function identities APTrace evidence has surfaced, first-seen order."""

    seen: dict[str, None] = {}

    for obs in observations:
        for name in functions_in(obs.result):
            seen.setdefault(name, None)

        function = obs.arguments.get("function")

        if isinstance(function, str) and _FUNCTION_RE.fullmatch(function):
            seen.setdefault(function, None)

    return list(seen)


def conclusion(state: Any, *, limit: int = 8) -> dict[str, list[str]]:
    """
    Compact final answer separating evidence levels.

    PROVEN: APTrace-derived claims (newest first, tagged with basis).
    PROBABLE: supported interpretations and hypotheses (never proven).
    OPEN: unresolved questions, from APTrace frontiers and the planner.
    """

    def ranked(claims: list[Claim]) -> list[Claim]:
        return sorted(
            claims,
            key=lambda c: (max((_evidence_number(e) for e in c.evidence_ids), default=0), _evidence_number(c.id.lstrip("C"))),
            reverse=True,
        )

    proven = [c for c in state.claims if c.grade.value == "PROVEN"]
    supported = [c for c in state.claims if c.grade.value != "PROVEN"]

    def tag(claim: Claim) -> str:
        return _BASIS_TAGS.get(claim.basis or "", claim.basis or "fact")

    return {
        "proven": [
            f"{c.id}[{tag(c)}] {c.statement} ({','.join(c.evidence_ids)})"
            for c in ranked(proven)[:limit]
        ]
        + ([f"(+{len(proven) - limit} more proven facts in the run artifact)"] if len(proven) > limit else []),
        "probable": [f"{c.id}[supported] {c.statement}" for c in ranked(supported)[:limit]]
        + [f"{h.id}[{h.source or 'hypothesis'}] {h.statement}" for h in state.hypotheses[:limit]],
        "open": [
            f"{q.id}[{q.source or 'open'}] {q.question}"
            for q in state.open_questions
            if q.status.value == "OPEN"
        ][:limit],
    }
