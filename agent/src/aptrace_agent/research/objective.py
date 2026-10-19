"""
Objective-bounded investigation (objective-v1).

A focused research run declares the relationships it investigates. APTrace
holds that objective in a structure, not only in prose clipped for the
planner, and uses it for three mechanical jobs:

- **Objective.** The question, constraints and relations stay whole for
  every planner request. Each relation carries per-edge evidence derived
  deterministically from recorded evidence: static call edges, symbolic
  calls/accesses, concrete scenario observations, and blockers. Relations
  are never composed into an end-to-end path here.
- **Relevance.** Before an operation runs, APTrace checks that its target
  function, peripheral, scenario or site is connected to the objective by
  declared terms, relation endpoints, or evidence one call-graph hop from an
  endpoint. Clearly unrelated operations are withheld or rejected.
- **Progress.** After each operation APTrace classifies the outcome
  (strengthened, blocker, relevant_partial, no_progress, failed), keeps the
  remaining budget visible, asks for one replan after repeated low-value
  steps, and stops with an explicit unresolved-relation report when the
  stall limit is reached.

Nothing here is firmware specific. Endpoints are FUN_ names or addresses;
scenario relevance uses the scenario registry's own metadata. Relevance and
progress only govern what is executed: they create no claims and are not
evidence. See docs/objective-bounded-investigation.md.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field, field_validator


OBJECTIVE_VERSION = "objective-v1"

MAX_RELATIONS = 8
MAX_CONSTRAINTS = 8
MAX_TERMS = 24
MAX_QUESTION = 1200
MAX_CONSTRAINT = 240
MAX_LABEL = 120

# Step outcomes, strongest first.
STRENGTHENED = "strengthened"
BLOCKER = "blocker"
RELEVANT_PARTIAL = "relevant_partial"
NO_PROGRESS = "no_progress"
FAILED = "failed"
OUTCOMES = (STRENGTHENED, BLOCKER, RELEVANT_PARTIAL, NO_PROGRESS, FAILED)

# Withheld-candidate code: a claim candidate about no objective-relevant
# function (selection scope only; admission is unchanged).
CANDIDATE_OUTSIDE_OBJECTIVE = "CANDIDATE_OUTSIDE_OBJECTIVE"

# Per-relation evidence levels, weakest first. None of them is a composed
# or verified causal relationship.
UNRESOLVED = "UNRESOLVED"
STATIC = "STATIC"
SYMBOLIC = "SYMBOLIC"
OBSERVED = "OBSERVED"
_LEVEL_RANK = {UNRESOLVED: 0, STATIC: 1, SYMBOLIC: 2, OBSERVED: 3}

_FUNCTION_RE = re.compile(r"^FUN_([0-9a-fA-F]{8})$")
_ADDRESS_RE = re.compile(r"^0x([0-9a-fA-F]{1,8})$")
_TOKEN_RE = re.compile(r"[a-z0-9]+")
# Tokens that never discriminate between operations.
_STOP_TOKENS = frozenset(
    "a an and are as at be by do does for from how in into is it its not of on or the then this to via was what when "
    "where whether which with without run".split()
)
# Result statuses that mean the operation produced no analysis result.
_FAILED_STATUS_PREFIXES = ("failed", "error")
_FAILED_STATUS_SUFFIXES = ("_unavailable",)


def _tokens(text: str) -> set[str]:
    return {t for t in _TOKEN_RE.findall(str(text).lower()) if len(t) >= 2 and t not in _STOP_TOKENS}


def function_name(address: int) -> str:
    return f"FUN_{address:08x}"


# -- specification -----------------------------------------------------------------


class RelationSpec(BaseModel):
    """One relationship the investigation must establish or explain."""

    id: str
    source: str
    target: str
    label: str = ""
    # Image of each endpoint when it differs from the objective's firmware.
    source_firmware: str | None = None
    target_firmware: str | None = None

    @field_validator("source", "target")
    @classmethod
    def _endpoint(cls, value: str) -> str:
        value = str(value).strip()

        if not (_FUNCTION_RE.fullmatch(value) or _ADDRESS_RE.fullmatch(value)):
            raise ValueError(f"relation endpoint must be FUN_xxxxxxxx or 0x address, not {value[:40]!r}")

        return value

    @field_validator("label")
    @classmethod
    def _label(cls, value: str) -> str:
        return " ".join(str(value).split())[:MAX_LABEL]


class ObjectiveSpec(BaseModel):
    """
    Operator-declared objective. ``question`` is the full natural-language
    objective; relations, constraints and terms are its structured parts.
    """

    version: str = OBJECTIVE_VERSION
    question: str
    # Firmware image the relation endpoints belong to unless a relation says
    # otherwise. Endpoints of another image are never resolved against the
    # loaded one.
    firmware: str | None = None
    constraints: list[str] = Field(default_factory=list)
    relations: list[RelationSpec] = Field(default_factory=list)
    # Extra relevance vocabulary (subsystems, scenario words) beyond the question.
    terms: list[str] = Field(default_factory=list)
    # Registered scenarios the operator declares relevant (an operator
    # assertion recorded as such, not evidence).
    scenarios: list[str] = Field(default_factory=list)
    # Peripheral inventory / case discovery not named by the objective.
    allow_broad_discovery: bool = False
    # Stall policy: consecutive low-value steps before a replan notice, and
    # before the run stops with an unresolved report.
    replan_after: int = 2
    stall_limit: int = 3

    @field_validator("question")
    @classmethod
    def _question(cls, value: str) -> str:
        value = " ".join(str(value).split())

        if not value:
            raise ValueError("objective question must not be empty")
        if len(value) > MAX_QUESTION:
            raise ValueError(f"objective question exceeds {MAX_QUESTION} characters; move detail into constraints")

        return value

    @field_validator("constraints")
    @classmethod
    def _constraints(cls, value: list[str]) -> list[str]:
        items = [" ".join(str(item).split()) for item in value if str(item).strip()]

        if len(items) > MAX_CONSTRAINTS:
            raise ValueError(f"at most {MAX_CONSTRAINTS} constraints")
        if any(len(item) > MAX_CONSTRAINT for item in items):
            raise ValueError(f"each constraint must be at most {MAX_CONSTRAINT} characters")

        return items

    @field_validator("relations")
    @classmethod
    def _relations(cls, value: list[RelationSpec]) -> list[RelationSpec]:
        if len(value) > MAX_RELATIONS:
            raise ValueError(f"at most {MAX_RELATIONS} relations")
        if len({r.id for r in value}) != len(value):
            raise ValueError("relation ids must be unique")

        return value

    @field_validator("terms")
    @classmethod
    def _terms(cls, value: list[str]) -> list[str]:
        if len(value) > MAX_TERMS:
            raise ValueError(f"at most {MAX_TERMS} terms")

        return [str(t).strip() for t in value if str(t).strip()]

    def model_post_init(self, _context: Any) -> None:
        if not 1 <= self.replan_after <= self.stall_limit:
            raise ValueError("need 1 <= replan_after <= stall_limit")

    @property
    def focused(self) -> bool:
        return bool(self.relations)

    def vocabulary(self, *, labels: bool = True) -> set[str]:
        """Objective words. Relation labels describe edges; they count for
        scenario matching but do not by themselves request inventory."""

        words = _tokens(self.question) | {t for term in self.terms for t in _tokens(term)}

        if labels:
            for relation in self.relations:
                words |= _tokens(relation.label)

        return words


def parse_relation(text: str, index: int) -> RelationSpec:
    """'SRC->DST' or 'SRC->DST:label' (CLI form)."""

    head, _, label = str(text).partition(":")
    source, arrow, target = head.partition("->")

    if not arrow:
        raise ValueError(f"relation must be SRC->DST[:label], not {text[:60]!r}")

    return RelationSpec(id=f"R{index}", source=source.strip(), target=target.strip(), label=label.strip())


def load_spec(path: str, *, question: str = "", relations: Sequence[str] = (), constraints: Sequence[str] = ()) -> ObjectiveSpec:
    """Objective file (JSON), with CLI relations/constraints appended."""

    data: dict[str, Any] = {}

    if path:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)

    if question and not data.get("question"):
        data["question"] = question

    existing = list(data.get("relations") or [])
    data["relations"] = existing + [
        parse_relation(text, len(existing) + i + 1).model_dump() for i, text in enumerate(relations)
    ]
    data["constraints"] = list(data.get("constraints") or []) + list(constraints)
    return ObjectiveSpec.model_validate(data)


# -- endpoints ----------------------------------------------------------------------


@dataclass(frozen=True)
class Endpoint:
    text: str
    address: int
    # "function" (a known function entry), "address" (not a function entry
    # in this image: data or MMIO), "other-image" (declared for another
    # firmware image), or "unvalidated".
    kind: str
    firmware: str | None = None

    @property
    def function(self) -> str | None:
        return function_name(self.address) if self.kind == "function" else None

    def render(self) -> str:
        text = self.function or f"0x{self.address:08x}"
        return f"{self.firmware}:{text}" if self.kind == "other-image" else text


def resolve_endpoint(text: str, function_exists: Callable[[str], bool] | None, *, firmware: str | None = None,
                     loaded: str | None = None) -> Endpoint:
    match = _FUNCTION_RE.fullmatch(text) or _ADDRESS_RE.fullmatch(text)
    address = int(match.group(1), 16)

    if firmware and loaded and firmware != loaded:
        kind = "other-image"
    elif function_exists is None:
        kind = "function" if text.startswith("FUN_") else "unvalidated"
    else:
        kind = "function" if function_exists(function_name(address)) else "address"

    return Endpoint(text=text, address=address, kind=kind, firmware=firmware)


# -- scenario relevance -----------------------------------------------------------


def scenario_tokens(metadata: Mapping[str, Mapping[str, Any]]) -> dict[str, set[str]]:
    """
    Discriminative tokens per registered scenario, from its own id, runner and
    optional ``topics``. A token present in more than half the scenarios
    (e.g. a shared prefix or runner verb) discriminates nothing and is dropped.
    """

    raw: dict[str, set[str]] = {}

    for name, entry in metadata.items():
        words = _tokens(name.replace("-", " ")) | _tokens(str(entry.get("runner", "")).replace("_", " "))

        for topic in entry.get("topics") or []:
            words |= _tokens(topic)

        raw[name] = words

    if len(raw) < 3:
        return raw

    counts: dict[str, int] = {}

    for words in raw.values():
        for word in words:
            counts[word] = counts.get(word, 0) + 1

    common = {word for word, count in counts.items() if count * 2 > len(raw)}
    return {name: words - common for name, words in raw.items()}


@dataclass(frozen=True)
class ScenarioRelevance:
    relevant: tuple[str, ...]
    # scenario -> why (matched terms, operator declaration, or evidence).
    basis: dict[str, str]


# -- outcomes and report ----------------------------------------------------------


class StepOutcome(BaseModel):
    step: int
    action: str
    target: str
    outcome: str
    evidence_id: str | None = None
    relations: list[str] = Field(default_factory=list)
    note: str = ""


class RelationStatus(BaseModel):
    id: str
    source: str
    target: str
    label: str
    level: str = UNRESOLVED
    # [{"evidence_id", "level", "detail"}]
    evidence: list[dict[str, str]] = Field(default_factory=list)
    blockers: list[dict[str, str]] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)


@dataclass
class _Assessment:
    relevant: bool
    reason: str = ""


# -- tracker -----------------------------------------------------------------------


@dataclass
class ObjectiveTracker:
    """Run-scoped objective state held by the controller (APTrace, not the planner)."""

    spec: ObjectiveSpec
    function_exists: Callable[[str], bool] | None = None
    # Firmware key of the loaded image, when the application knows it.
    firmware_key: str | None = None
    scenario_metadata: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    outcomes: list[StepOutcome] = field(default_factory=list)
    # Rejected or withheld operation requests: {"action", "target", "reason"}.
    rejections: list[dict[str, str]] = field(default_factory=list)
    since_progress: int = 0
    replan_requested: bool = False
    _levels: dict[str, str] = field(default_factory=dict)
    _blocker_keys: set[str] = field(default_factory=set)
    _relevant_evidence: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        for relation in self.spec.relations:
            for text, image in ((relation.source, relation.source_firmware), (relation.target, relation.target_firmware)):
                firmware = image or self.spec.firmware
                key = self._key(text, firmware)

                if key not in self.endpoints:
                    self.endpoints[key] = resolve_endpoint(text, self.function_exists, firmware=firmware, loaded=self.firmware_key)

        self._levels = {r.id: UNRESOLVED for r in self.spec.relations}

    def _key(self, text: str, firmware: str | None) -> str:
        return f"{firmware}:{text}" if firmware else text

    def _endpoint(self, relation: RelationSpec, side: str) -> Endpoint:
        image = relation.source_firmware if side == "source" else relation.target_firmware
        return self.endpoints[self._key(getattr(relation, side), image or self.spec.firmware)]

    # -- relevance sets ------------------------------------------------------

    def anchors(self) -> list[str]:
        """Relation endpoints that are function entries in this image."""

        return list(dict.fromkeys(e.function for e in self.endpoints.values() if e.function))

    def unresolved_anchors(self) -> list[Endpoint]:
        return [e for e in self.endpoints.values() if e.kind != "function"]

    def relevant_functions(self, observations: Sequence[Any]) -> list[str]:
        """
        Anchors plus functions one static call hop from an anchor, as
        recorded in function_facts evidence. One hop is a fixed bound:
        relevance does not spread with every followed lead.
        """

        anchors = self.anchors()
        relevant: dict[str, None] = dict.fromkeys(anchors)

        for obs in observations:
            if obs.tool != "function_facts" or not isinstance(obs.result, dict):
                continue

            name = obs.result.get("name") or obs.arguments.get("function")
            neighbours = [
                edge.get("function")
                for key in ("callers", "callees")
                for edge in obs.result.get(key) or []
                if isinstance(edge, dict)
            ]

            if name in anchors:
                relevant.update(dict.fromkeys(n for n in neighbours if n))
            elif any(n in anchors for n in neighbours) and name:
                relevant.setdefault(name)

        return list(relevant)

    def scenario_relevance(self, scenarios: Sequence[str], observations: Sequence[Any]) -> ScenarioRelevance:
        """
        Relevant registered scenarios: operator-declared ones, the best
        lexical match between the objective vocabulary and scenario
        metadata, and any scenario evidence shows entering an anchor.
        """

        basis: dict[str, str] = {}

        for name in self.spec.scenarios:
            if name in scenarios:
                basis[name] = "declared by the objective"

        tokens = scenario_tokens({name: self.scenario_metadata.get(name, {}) for name in scenarios})
        vocabulary = self.spec.vocabulary()
        scores = {name: tokens.get(name, set()) & vocabulary for name in scenarios}
        best = max((len(words) for words in scores.values()), default=0)

        if best:
            for name, words in scores.items():
                if len(words) == best:
                    basis.setdefault(name, "objective terms match scenario metadata: " + ", ".join(sorted(words)))

        anchors = set(self.anchors())

        for obs in observations:
            if obs.tool != "observed_call_arguments" or not isinstance(obs.result, dict):
                continue

            scenario = obs.arguments.get("scenario")

            if scenario in scenarios and obs.arguments.get("function") in anchors and (obs.result.get("observed_entries") or 0) > 0:
                basis.setdefault(scenario, f"{obs.id} observed {obs.arguments.get('function')} entered under it")

        ordered = tuple(name for name in scenarios if name in basis)
        return ScenarioRelevance(relevant=ordered, basis=basis)

    def peripheral_relevant(self, peripheral: str) -> bool:
        if self.spec.allow_broad_discovery:
            return True

        return str(peripheral).lower() in self.spec.vocabulary(labels=False)

    def query_relevant(self, query: str) -> bool:
        if self.spec.allow_broad_discovery:
            return True

        anchors = {a.lower() for a in self.anchors()}
        words = _tokens(query)
        return bool(words & self.spec.vocabulary()) or bool(words & anchors)

    # -- assessment ----------------------------------------------------------

    def assess(self, tool: str, arguments: Mapping[str, Any], observations: Sequence[Any], scenarios: Sequence[str] = (),
               source_evidence: Sequence[str] = ()) -> _Assessment:
        """Whether one operation (by executor tool name) is relevant to the objective."""

        relevant_functions = set(self.relevant_functions(observations))

        if tool in ("census_peripheral_usage", "census_usb_inventory"):
            peripheral = arguments.get("peripheral", "USB")

            if self.peripheral_relevant(peripheral):
                return _Assessment(True)

            return _Assessment(False, f"peripheral {peripheral} is not named by the objective question or terms; "
                               "inventory is not progress on a relation")

        if tool == "search_case_evidence":
            if self.query_relevant(str(arguments.get("query", ""))):
                return _Assessment(True)

            return _Assessment(False, "the search shares no term with the objective")

        if tool == "census_common_paths":
            members = set(arguments.get("left") or []) | set(arguments.get("right") or [])

            if members & relevant_functions:
                return _Assessment(True)

            return _Assessment(False, "neither set contains a relation endpoint or one of its neighbours")

        if tool in ("indirect_call_target", "callback_argument_provenance", "value_forward_use"):
            site = str(arguments.get("site") or arguments.get("origin") or "").lower()

            for obs in observations:
                if obs.id in self._relevant_evidence and site and site in json.dumps(obs.result, default=str).lower():
                    return _Assessment(True)

            return _Assessment(False, f"{site} appears in no evidence produced for the objective")

        function = arguments.get("function")

        if function is not None:
            if function not in relevant_functions:
                return _Assessment(
                    False, f"{function} is neither a relation endpoint nor one call hop from one in recorded evidence"
                )

            if tool == "observed_call_arguments":
                scenario = arguments.get("scenario")
                relevance = self.scenario_relevance(scenarios, observations)

                if scenario not in relevance.relevant:
                    listed = ", ".join(relevance.relevant) or "none"
                    return _Assessment(
                        False,
                        f"scenario {scenario} has no established relevance to the objective (no matching objective "
                        f"term, declaration, or evidence of it entering an endpoint); relevant scenarios: {listed}",
                    )

            return _Assessment(True)

        # Leads without a function target (pin table, case search from a
        # result): relevant only when produced by relevant evidence.
        if any(e in self._relevant_evidence for e in source_evidence):
            return _Assessment(True)

        return _Assessment(False, f"{tool} was not derived from evidence produced for the objective")

    def mark_relevant(self, evidence_id: str) -> None:
        """Evidence produced for the objective (e.g. a seed recorded before the run)."""

        self._relevant_evidence.add(evidence_id)

    def reject(self, action: str, target: str, reason: str) -> None:
        self.rejections.append({"action": action, "target": target[:80], "reason": reason[:300]})

    # -- relation evidence -----------------------------------------------------

    def relation_status(self, observations: Sequence[Any]) -> list[RelationStatus]:
        return [self._relation(relation, observations) for relation in self.spec.relations]

    def _relation(self, relation: RelationSpec, observations: Sequence[Any]) -> RelationStatus:
        source = self._endpoint(relation, "source")
        target = self._endpoint(relation, "target")
        status = RelationStatus(id=relation.id, source=source.render(), target=target.render(), label=relation.label)

        def add(level: str, obs: Any, detail: str) -> None:
            status.evidence.append({"evidence_id": obs.id, "level": level, "detail": detail[:200]})

            if _LEVEL_RANK[level] > _LEVEL_RANK[status.level]:
                status.level = level

        def block(obs: Any, detail: str) -> None:
            status.blockers.append({"evidence_id": obs.id, "detail": detail[:200]})

        for obs in observations:
            result = obs.result if isinstance(obs.result, dict) else {}
            function = obs.arguments.get("function") or result.get("function") or result.get("name")

            if obs.tool == "function_facts" and source.function and target.function:
                callees = {e.get("function") for e in result.get("callees") or [] if isinstance(e, dict)}
                callers = {e.get("function") for e in result.get("callers") or [] if isinstance(e, dict)}

                if (function == source.function and target.function in callees) or (
                    function == target.function and source.function in callers
                ):
                    add(STATIC, obs, f"static call edge {source.function} -> {target.function} (Ghidra call graph; heuristic boundaries)")

            elif obs.tool == "function_effects" and function in (source.function, target.function):
                # The source's effects can show its call or access; the
                # target's effects matter only for a read of an address source.
                if function == target.function and source.function:
                    continue

                failure = failure_status(result)

                if failure:
                    block(obs, f"effects of {function} produced no result ({failure}); this is not absence of effects")
                    continue

                if function == source.function and target.function:
                    for call in result.get("calls") or []:
                        if _same_address(call.get("target"), target.address):
                            add(SYMBOLIC, obs, f"symbolic call {source.function} -> {target.function} at {call.get('pc')}")

                other = target if function == source.function else source

                if other.kind != "function":
                    for access in result.get("accesses") or []:
                        if isinstance(access, dict) and _same_address(access.get("address"), other.address):
                            add(SYMBOLIC, obs, f"symbolic {access.get('kind')} of 0x{other.address:08x} by {function} "
                                f"(guard {access.get('guard', 'always')})")

                coverage = str(result.get("coverage") or "")

                if coverage.startswith("bounded"):
                    block(obs, f"effects of {function} are {coverage}: absent accesses are not excluded")

            elif obs.tool == "observed_call_arguments" and function == target.function:
                scenario = obs.arguments.get("scenario") or result.get("scenario")
                failure = failure_status(result)

                if failure:
                    block(obs, f"observation of {function} under {scenario} produced no result ({failure})")
                    continue

                if not result.get("observed_entries"):
                    block(obs, f"{function} not entered under scenario {scenario} (not thereby unreachable)")
                    continue

                callers = {
                    site.get("caller")
                    for site in result.get("call_sites") or []
                    if isinstance(site, dict) and site.get("status") in ("OBSERVED", "DYNAMIC_ONLY")
                }

                if source.function and source.function in callers:
                    add(OBSERVED, obs, f"{source.function} observed calling {function} under scenario {scenario} "
                        "(harness assumptions apply)")
                elif source.function:
                    block(obs, f"{function} entered under {scenario}, but no observed call from {source.function}")

        inspected = {o.arguments.get("function") for o in observations if o.tool == "function_facts"}
        status.missing = self._missing(status, source, target, inspected)
        return status

    @staticmethod
    def _missing(status: RelationStatus, source: Endpoint, target: Endpoint, inspected: set[str] = frozenset()) -> list[str]:
        missing: list[str] = []

        for endpoint in (source, target):
            if endpoint.kind == "other-image":
                missing.append(f"{endpoint.render()} belongs to firmware {endpoint.firmware}, not the loaded image: "
                               "this controller investigates one image; a cross-image relation needs a multi-image "
                               "scenario or composition capability")
            elif endpoint.kind == "address":
                missing.append(f"{endpoint.text} is not a function entry in this image (data/MMIO address or another image); "
                               "only symbolic access evidence can relate it")
            elif endpoint.kind == "unvalidated":
                missing.append(f"{endpoint.text} could not be validated as a function entry")

        if status.level == OBSERVED:
            return missing

        if source.function and target.function:
            if status.level == UNRESOLVED and {source.function, target.function} & inspected:
                missing.append(f"recorded function_facts show no direct call {source.function} -> {target.function}: "
                               "if the relation spans several calls, it needs a path capability (not a single edge)")
            elif status.level == UNRESOLVED:
                missing.append(f"no static call edge in evidence: function_facts of {source.function} or {target.function}")
            unentered = [b["evidence_id"] for b in status.blockers if " not entered under scenario " in b["detail"]]

            if unentered:
                missing.append(f"no concrete observation of {source.function} calling {target.function}: the scenarios "
                               f"tried did not enter {target.function} ({', '.join(unentered)}); needs a scenario that "
                               "reaches it (scenario coverage gap)")
            else:
                missing.append(f"no concrete observation of {source.function} calling {target.function}: "
                               f"observe_call_arguments of {target.function} under a relevant scenario")
        elif "address" in (source.kind, target.kind) and not any(e["level"] == SYMBOLIC for e in status.evidence):
            function = source.function or target.function

            if function:
                failed = [b["evidence_id"] for b in status.blockers if "effects of" in b["detail"] and "no result" in b["detail"]]
                missing.append(
                    f"function_effects of {function} failed ({', '.join(failed)}); no other offered operation relates an "
                    "address endpoint (capability gap)"
                    if failed else
                    f"no completed function_effects of {function} showing an access to the address endpoint"
                )

        return missing

    # -- progress ------------------------------------------------------------

    def record(self, *, step: int, action: str, tool: str, arguments: Mapping[str, Any], observation: Any,
               observations: Sequence[Any], relevant: bool) -> StepOutcome:
        """Classify one executed operation and update the stall counter."""

        result = observation.result if isinstance(observation.result, dict) else {}
        before = dict(self._levels)
        statuses = self.relation_status(observations)
        self._levels = {s.id: s.level for s in statuses}
        strengthened = [s.id for s in statuses if _LEVEL_RANK[s.level] > _LEVEL_RANK[before.get(s.id, UNRESOLVED)]]
        new_blockers = []

        for s in statuses:
            for b in s.blockers:
                key = f"{s.id}:{b['evidence_id']}"

                if key not in self._blocker_keys and b["evidence_id"] == observation.id:
                    self._blocker_keys.add(key)
                    new_blockers.append(s.id)

        target = str(arguments.get("function") or arguments.get("peripheral") or arguments.get("site")
                     or arguments.get("origin") or arguments.get("query") or "")
        failure = failure_status(result)

        if relevant:
            self.mark_relevant(observation.id)

        if failure:
            outcome, note = FAILED, f"{tool} produced no result: {failure}"
        elif strengthened:
            outcome, note = STRENGTHENED, "relation evidence level raised"
        elif new_blockers:
            outcome, note = BLOCKER, "; ".join(
                b["detail"] for s in statuses for b in s.blockers if b["evidence_id"] == observation.id
            )[:300]
        elif relevant:
            outcome, note = RELEVANT_PARTIAL, "relevant evidence; no relation level changed"
        else:
            outcome, note = NO_PROGRESS, "operation not connected to the objective"

        record = StepOutcome(
            step=step, action=action, target=target[:80], outcome=outcome, evidence_id=observation.id,
            relations=list(dict.fromkeys(strengthened + new_blockers)), note=note,
        )
        self.outcomes.append(record)

        if outcome in (STRENGTHENED, BLOCKER):
            self.since_progress = 0
            self.replan_requested = False
        else:
            self.since_progress += 1

        return record

    def failed_operations(self) -> list[StepOutcome]:
        return [o for o in self.outcomes if o.outcome == FAILED]

    def needs_replan(self) -> bool:
        return self.since_progress >= self.spec.replan_after

    def stalled(self) -> bool:
        return self.since_progress >= self.spec.stall_limit

    # -- planner rendering ----------------------------------------------------

    def render(self, observations: Sequence[Any], *, scenarios: Sequence[str], steps_used: int, max_steps: int) -> str:
        """Planner-facing objective block. Bounded by the spec's own limits, never clipped."""

        lines = [f"OBJECTIVE (held by APTrace, complete): {self.spec.question}"]

        if self.spec.constraints:
            lines.append("CONSTRAINTS:")
            lines += [f"- {c}" for c in self.spec.constraints]

        lines.append("RELATIONS (per-edge evidence only; APTrace never composes them into a chain):")

        for s in self.relation_status(observations):
            evidence = ",".join(dict.fromkeys(e["evidence_id"] for e in s.evidence))
            text = f"{s.id} {s.source} -> {s.target}"
            text += f" '{s.label}'" if s.label else ""
            text += f": {s.level}" + (f" ({evidence})" if evidence else "")

            if s.blockers and s.level != OBSERVED:
                text += f"; blocked {s.blockers[-1]['evidence_id']}: {s.blockers[-1]['detail'][:110]}"

            if s.missing and s.level != OBSERVED:
                text += f"; needs: {s.missing[-1][:150]}"

            lines.append(text)

        unresolved = [e.render() for e in self.unresolved_anchors()]

        if unresolved:
            lines.append("NOT FUNCTIONS IN THIS IMAGE (no function operation applies): " + ", ".join(unresolved))

        relevant = self.relevant_functions(observations)
        lines.append("RELEVANT FUNCTIONS: " + (", ".join(relevant[:16]) or "(none validated)")
                     + (f" [+{len(relevant) - 16}]" if len(relevant) > 16 else ""))

        if scenarios:
            relevance = self.scenario_relevance(scenarios, observations)
            lines.append("RELEVANT SCENARIOS: " + ("; ".join(f"{n} ({relevance.basis[n][:80]})" for n in relevance.relevant) or "none"))

        failed = self.failed_operations()

        if failed:
            lines.append("FAILED (do not repeat): " + "; ".join(f"{o.evidence_id} {o.note[:90]}" for o in failed[-4:]))

        if self.rejections:
            lines.append("REJECTED AS UNRELATED: " + "; ".join(f"{r['action']} {r['target']}" for r in self.rejections[-3:]))

        remaining = max(0, max_steps - steps_used)
        lines.append(
            f"BUDGET: {steps_used} of {max_steps} steps used, {remaining} left; {self.since_progress} consecutive "
            f"step(s) without progress (replan at {self.spec.replan_after}, stop at {self.spec.stall_limit})"
        )
        lines.append(
            "PROGRESS means raising an UNRESOLVED/STATIC relation's evidence level, or a concrete blocker for one."
        )

        if self.needs_replan():
            lines.append(
                "REPLAN: recent steps made no progress. Choose an operation on a relation endpoint or a relevant "
                "scenario, or finish and name the unresolved relations and what is missing."
            )

        return "\n".join(lines)

    # -- terminal report -----------------------------------------------------

    def report(self, observations: Sequence[Any], *, stop_reason: str, steps_used: int, max_steps: int) -> dict[str, Any]:
        statuses = self.relation_status(observations)
        unresolved = [s for s in statuses if s.level != OBSERVED]
        explanation = {
            "objective_stalled": f"stopped after {self.since_progress} consecutive steps without progress",
            "objective_no_relevant_operation": "no relevant operation remained for any unresolved relation",
            "step_budget_exhausted": "step budget exhausted",
        }.get(stop_reason, stop_reason)

        return {
            "version": OBJECTIVE_VERSION,
            "question": self.spec.question,
            "constraints": list(self.spec.constraints),
            "stop_reason": stop_reason,
            "explanation": explanation,
            "budget": {"max_steps": max_steps, "steps_used": steps_used},
            "relations": [s.model_dump() for s in statuses],
            "unresolved_relations": [s.id for s in unresolved],
            "answered": not unresolved,
            "composition": "not attempted: per-edge levels are not an end-to-end causal result",
            "anchors": {key: e.kind for key, e in self.endpoints.items()},
            "outcomes": [o.model_dump() for o in self.outcomes],
            "rejections": list(self.rejections),
        }


def failure_status(result: Mapping[str, Any]) -> str | None:
    """The status text when an operation produced no analysis result, else None."""

    status = str(result.get("status") or "")
    lowered = status.lower()

    if lowered.startswith(_FAILED_STATUS_PREFIXES) or lowered.endswith(_FAILED_STATUS_SUFFIXES) or "timeout" in lowered:
        return status

    return None


def _same_address(value: Any, address: int) -> bool:
    if value is None:
        return False

    try:
        return (int(value, 16) if isinstance(value, str) else int(value)) == address
    except (TypeError, ValueError):
        return False


def render_report(report: Mapping[str, Any]) -> list[str]:
    """Human-readable lines for the CLI summary."""

    lines = [f"objective: {'answered per edge' if report['answered'] else 'UNRESOLVED'} ({report['explanation']})"]

    for relation in report["relations"]:
        lines.append(f"  {relation['id']} {relation['source']} -> {relation['target']}: {relation['level']}")

        for item in relation["blockers"][-2:]:
            lines.append(f"      blocker {item['evidence_id']}: {item['detail']}")

        for item in relation["missing"]:
            lines.append(f"      missing: {item}")

    lines.append(f"  {report['composition']}")
    return lines


__all__ = [
    "OBJECTIVE_VERSION", "ObjectiveSpec", "RelationSpec", "ObjectiveTracker", "StepOutcome", "RelationStatus",
    "load_spec", "parse_relation", "failure_status", "scenario_tokens", "render_report", "OUTCOMES",
    "STRENGTHENED", "BLOCKER", "RELEVANT_PARTIAL", "NO_PROGRESS", "FAILED", "UNRESOLVED", "STATIC", "SYMBOLIC", "OBSERVED",
]
