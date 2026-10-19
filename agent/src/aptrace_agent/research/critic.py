"""
Critic validation (critic-validation-v1): deterministic checks of the review
model's terminal-review findings against APTrace's own record.

A finding is a proposition about the *investigation*: that the assessment
lacks evidence for something, or that it concluded something it should not
have. Validation decides that proposition from the persisted assessment
(never the reduced package, and never another model). It does not decide
firmware behavior. A SUPPORTED criticism of a missing timer-to-ISR
connection says the record does not establish that connection; it says
nothing about whether the firmware makes it.

Classifications:

- SUPPORTED: APTrace's record establishes the criticism.
- CONTRADICTED: APTrace's record directly refutes it. Only a positive record
  refutes (a relation level, a blocker recorded as incompleteness, an
  explicit qualifier, a carried-forward link, a shared execution). Missing
  support is never a refutation.
- UNRESOLVED: grounded and plausible, but the record neither establishes nor
  refutes it (for example any claim about firmware behavior).
- UNGROUNDED: no valid target in the package, or no identifiable defect.
  Fabricated citations are rejected and never used.

A finding is routed by its defect type (the reviewer's ``defect`` field when
valid, otherwise derived from its category):

- ``missing_evidence``: the gap is checked (relation level, joins and
  segments, state continuity). A finding that also characterizes the
  investigation (composition, scope) has that characterization checked
  separately: a refuted characterization of a real gap is reported as a
  mischaracterization, and the gap is kept.
- ``incorrect_inference``: the characterization is the finding (a negative
  drawn from incompleteness, static evidence presented as execution,
  overstated confidence, composition, scope).
- ``unsupported_assumption``: the cited scope's harness assumptions and the
  relation's capability gaps.
- ``contradiction``: two cited evidence items and APTrace's own
  contradiction and tension records.
- ``firmware_hypothesis``: never decided here (UNRESOLVED when grounded).

SUPPORTED and UNRESOLVED findings, and APTrace's own continuity concerns,
become bounded follow-up question proposals. They are never executed here.

Authority: validation changes no evidence, relation level, claim, grade or
admission decision. It is not a review of firmware and not verification.
See docs/critic-validation.md.
"""

from __future__ import annotations

import json
import re
from collections import deque
from collections.abc import Mapping, Sequence
from typing import Any

from aptrace_agent.ledger.hashing import digest
from aptrace_agent.research import continuity
from aptrace_agent.research.objective import OBSERVED, STATIC, SYMBOLIC, UNRESOLVED


VALIDATION_VERSION = "critic-validation-v1"
SUPPORTED, CONTRADICTED, UNRESOLVED_FINDING, UNGROUNDED = "SUPPORTED", "CONTRADICTED", "UNRESOLVED", "UNGROUNDED"
CLASSIFICATIONS = (SUPPORTED, CONTRADICTED, UNRESOLVED_FINDING, UNGROUNDED)

MISSING_EVIDENCE = "missing_evidence"
INCORRECT_INFERENCE = "incorrect_inference"
UNSUPPORTED_ASSUMPTION = "unsupported_assumption"
CONTRADICTION = "contradiction"
FIRMWARE_HYPOTHESIS = "firmware_hypothesis"
DEFECTS = (MISSING_EVIDENCE, INCORRECT_INFERENCE, UNSUPPORTED_ASSUMPTION, CONTRADICTION, FIRMWARE_HYPOTHESIS)

# Category -> (defect type, characterization check or None).
CATEGORY_DEFECTS = {
    "unsupported_relationship": (MISSING_EVIDENCE, None),
    "static_as_execution": (INCORRECT_INFERENCE, "static_as_execution"),
    "missing_prerequisite_or_state_continuity": (MISSING_EVIDENCE, None),
    "unjustified_composition": (MISSING_EVIDENCE, "composition"),
    "peripheral_timer_interrupt_assumption": (UNSUPPORTED_ASSUMPTION, None),
    "contradictory_evidence": (CONTRADICTION, None),
    "scope_mismatch": (MISSING_EVIDENCE, "scope"),
    "unsupported_negative": (INCORRECT_INFERENCE, "negative"),
    "overstated_confidence": (INCORRECT_INFERENCE, "confidence"),
    "counterexample_or_falsification": (FIRMWARE_HYPOTHESIS, None),
    "omitted_question": (FIRMWARE_HYPOTHESIS, None),
}

AUTHORITY = ("critic validation classifies the reviewer's propositions about the investigation record; it changes no "
             "evidence, relation level, claim, grade or admission decision and does not verify firmware behavior")

# APTrace's own scope qualifiers on negative-looking statements (objective-v1
# blockers, observation summaries, framework limitations).
QUALIFIERS = ("not thereby", "not absence", "never evidence of absence", "not excluded", "is incompleteness",
              "not impossible")
_NEGATIVE = re.compile(r"\b(not|never|no|unreachable|absent|absence|impossible|cannot)\b", re.IGNORECASE)
_FUNCTION = re.compile(r"^FUN_[0-9a-fA-F]+$")
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]+$")
_ID_TOKEN = re.compile(r"\b(?:R\d+->R\d+|[RESC]\d+)\b")
_HEX = re.compile(r"0x[0-9a-fA-F]{4,8}")

MAX_FOLLOWUPS = 8
TEXT = 300


def _clip(text: Any, limit: int = TEXT) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _record(path: str, text: Any = None, evidence_id: str | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {"record": path}

    if evidence_id:
        item["evidence_id"] = evidence_id

    if text is not None:
        item["text"] = _clip(text, 240)

    return item


def _check(name: str, result: str, detail: str, records: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    return {"check": name, "result": result, "detail": detail, "records": list(records)}


# -- the record a finding can target ------------------------------------------------


def state_continuity(assessment: Mapping[str, Any]) -> dict[str, Any]:
    """The assessment's continuity analysis (v2), or the same analysis of a v1 record's scopes."""

    recorded = (assessment.get("composition") or {}).get("continuity")
    return recorded if recorded else continuity.analyze(assessment["relations"], assessment.get("scopes") or [])


def target_index(assessment: Mapping[str, Any]) -> dict[str, Any]:
    """Every id a finding may target: relations, evidence, joins, segments, continuity concerns."""

    composition = assessment["composition"]
    return {
        "relations": [r["id"] for r in assessment["relations"]],
        "evidence": [e["evidence_id"] for e in assessment["evidence"]],
        "joins": [f"{j['from_relation']}->{j['to_relation']}" for j in composition["joins"]],
        "segments": {f"S{i}": s["relations"] for i, s in enumerate(composition["segments"], 1)},
        "continuity": {c["id"]: c["segments"] for c in state_continuity(assessment)["concerns"]},
    }


class _Record:
    """Read-only view of one assessment for validation."""

    def __init__(self, assessment: Mapping[str, Any], package: Mapping[str, Any] | None) -> None:
        self.assessment = assessment
        self.relations = {r["id"]: r for r in assessment["relations"]}
        self.order = {r["id"]: i for i, r in enumerate(assessment["relations"])}
        self.evidence = {e["evidence_id"]: e for e in assessment["evidence"]}
        self.scopes = {s["evidence_id"]: s for s in assessment.get("scopes") or []}
        self.index = target_index(assessment)
        self.continuity = state_continuity(assessment)
        self.segment_states = {s["evidence_id"]: s for s in self.continuity["segments"]}
        self.concerns = {c["id"]: c for c in self.continuity["concerns"]}
        self.joins = {f"{j['from_relation']}->{j['to_relation']}": j for j in assessment["composition"]["joins"]}
        content = (package or {}).get("content") or {}
        # What the reviewer was shown; a citation outside it is not accepted.
        self.shown_relations = {r["id"] for r in content.get("relations") or assessment["relations"]}
        self.shown_evidence = {e["evidence_id"] for e in content.get("evidence") or assessment["evidence"]}
        self.package_text = _normalize(_dump(content)) if content else None

    def relations_citing(self, evidence_id: str) -> list[str]:
        return [r["id"] for r in self.assessment["relations"]
                if evidence_id in {e["evidence_id"] for e in r["evidence"] + r["blockers"]}]

    def relation_evidence(self, relation_id: str) -> set[str]:
        r = self.relations[relation_id]
        return {e["evidence_id"] for e in r["evidence"] + r["blockers"]}

    def established_by(self, relation_id: str) -> set[str]:
        r = self.relations[relation_id]
        return {e["evidence_id"] for e in r["evidence"] if e["level"] == r["level"]}

    def established_relations(self, evidence_ids: Sequence[str]) -> list[str]:
        return self.sort([r for r in self.relations for e in evidence_ids if e in self.established_by(r)])

    def sort(self, relation_ids: Sequence[str]) -> list[str]:
        return sorted(dict.fromkeys(relation_ids), key=lambda r: self.order[r])

    def path(self, first: str, last: str) -> list[str] | None:
        """Relations from `first` to `last` along recorded joins; None when they form no chain (e.g. siblings)."""

        if first == last:
            return [first]

        edges: dict[str, list[str]] = {}

        for join in self.assessment["composition"]["joins"]:
            edges.setdefault(join["from_relation"], []).append(join["to_relation"])

        queue, seen = deque([[first]]), {first}

        while queue:
            route = queue.popleft()

            for nxt in edges.get(route[-1], []):
                if nxt == last:
                    return route + [nxt]

                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(route + [nxt])

        return None

    def claims(self) -> list[tuple[str, str, list[str]]]:
        """(record path, text, evidence ids) of every statement the investigation made."""

        claims = self.assessment.get("claims") or {}
        items = [(f"claims.session_claims[{i}]", c.get("statement"), c.get("evidence_ids") or [])
                 for i, c in enumerate(claims.get("session_claims") or [])]
        items += [(f"claims.proposals[{i}]", p.get("assertion"), p.get("evidence_ids") or [])
                  for i, p in enumerate(claims.get("proposals") or []) if p.get("decision") in ("admitted", "duplicate")]
        items += [(f"hypotheses[{i}]", h.get("statement"), h.get("evidence_ids") or [])
                  for i, h in enumerate(self.assessment.get("hypotheses") or [])]
        return [(path, str(text or ""), list(ids)) for path, text, ids in items]


def _dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)


def _normalize(text: str) -> str:
    return " ".join(str(text).lower().replace('\\"', '"').split())


# -- grounding ----------------------------------------------------------------------


def _ground(finding: Mapping[str, Any], record: _Record) -> dict[str, Any]:
    relations, evidence, joins, segments, concerns, rejected = [], [], [], [], [], []

    for rid in finding.get("relations") or []:
        (relations if rid in record.relations and rid in record.shown_relations else rejected).append(rid)

    for eid in finding.get("evidence_ids") or []:
        (evidence if eid in record.evidence and eid in record.shown_evidence else rejected).append(eid)

    for target in finding.get("targets") or []:
        if target in record.relations:
            relations.append(target)
        elif target in record.evidence:
            evidence.append(target)
        elif target in record.joins:
            joins.append(target)
        elif target in record.index["segments"]:
            segments.append(target)
        elif target in record.concerns:
            concerns.append(target)
        else:
            rejected.append(target)

    derived = list(relations)

    for join in joins:
        derived += join.split("->")

    for segment in segments:
        derived += record.index["segments"][segment]

    for concern in concerns:
        derived += record.established_relations(record.concerns[concern]["segments"])

    if not derived:
        for eid in evidence:
            established = [r for r in record.relations if eid in record.established_by(r)]
            derived += established or record.relations_citing(eid)

    cited = set(relations)
    unrelated = [e for e in evidence if cited and not any(e in record.relation_evidence(r) for r in cited)]
    quote = finding.get("quote")
    quote_check = None

    if quote:
        found = record.package_text is not None and _normalize(quote) in record.package_text
        quote_check = {"text": _clip(quote, 240), "found": found}

        if not found:
            rejected.append("quote")

    return {
        "relations": record.sort(derived),
        "cited_relations": list(dict.fromkeys(relations)),
        "evidence": list(dict.fromkeys(evidence)),
        "joins": list(dict.fromkeys(joins)),
        "segments": list(dict.fromkeys(segments)),
        "concerns": list(dict.fromkeys(concerns)),
        "rejected_citations": list(dict.fromkeys(rejected)),
        "unrelated_evidence": unrelated,
        "quote": quote_check,
    }


# -- checks: characterizations of the investigation ------------------------------------


def _negative(target: Mapping[str, Any], record: _Record) -> dict[str, Any]:
    """Did the investigation draw a negative conclusion from incompleteness?"""

    cited = set(target["evidence"])
    refuting, asserting = [], []

    for rid in target["relations"]:
        relation = record.relations[rid]
        refuting.append(_record(f"relations.{rid}.level", f"{relation['level']}: {relation['level_meaning']}"))
        blockers = [(i, b) for i, b in enumerate(relation["blockers"]) if not cited or b["evidence_id"] in cited]

        for i, blocker in blockers:
            # objective-v1 records failures, timeouts, bounded coverage and unentered targets as blockers,
            # never as negative evidence (INV-CTRL-OBJ-004).
            refuting.append(_record(f"relations.{rid}.blockers[{i}]", blocker["detail"], blocker["evidence_id"]))

    scope_evidence = cited | {e for rid in target["relations"] for e in record.relation_evidence(rid)}

    for path, text, ids in record.claims():
        if not set(ids) & scope_evidence or not _NEGATIVE.search(text):
            continue

        lowered = text.lower()
        (refuting if any(q in lowered for q in QUALIFIERS) else asserting).append(_record(path, text, ",".join(ids)))

    limitation = next((i for i, item in enumerate(record.assessment["limitations"]) if "never evidence of absence" in item), None)

    if limitation is not None:
        refuting.append(_record(f"limitations[{limitation}]", record.assessment["limitations"][limitation]))

    if asserting:
        return _check("negative_conclusion", UNRESOLVED_FINDING,
                      "a statement citing this evidence uses negative wording without an APTrace scope qualifier; "
                      "free text is not decided mechanically", asserting)

    return _check("negative_conclusion", CONTRADICTED,
                  "the record draws no negative conclusion here: relation levels are positive or UNRESOLVED, blockers are "
                  "recorded as incompleteness, and every statement citing this evidence carries an explicit scope qualifier",
                  refuting)


def _static_as_execution(target: Mapping[str, Any], record: _Record) -> dict[str, Any]:
    refuting, supporting = [], []

    for rid in target["relations"]:
        relation = record.relations[rid]

        if relation["level"] == OBSERVED:
            static_only = [e for e in record.established_by(rid) if e not in record.scopes]

            if static_only:
                supporting.append(_record(f"relations.{rid}.evidence", f"OBSERVED level rests on {', '.join(static_only)}, "
                                          "which has no execution scope", ",".join(static_only)))
            else:
                refuting.append(_record(f"relations.{rid}.level", "OBSERVED from evidence with an execution scope"))
        else:
            refuting.append(_record(f"relations.{rid}.level", f"{relation['level']}: {relation['level_meaning']}"))

    executed = set(record.scopes)

    for path, text, ids in _relevant_claims(target, record):
        if ids and set(ids) <= (set(target["evidence"]) - executed) and re.search(r"\b(execut|observed|ran|runs)\w*", text, re.I):
            supporting.append(_record(path, text, ",".join(ids)))

    validated = [k for k, j in record.joins.items() if j["continuity"] != "not validated"]

    if validated:
        supporting.append(_record("composition.joins", f"validated joins: {', '.join(validated)}"))

    if supporting:
        return _check("static_presented_as_execution", SUPPORTED, "the record presents static evidence as execution", supporting)

    return _check("static_presented_as_execution", CONTRADICTED,
                  "every targeted relation is reported at its own level with its meaning, no join is validated, and no "
                  "statement presents static-only evidence as execution", refuting)


def _relevant_claims(target: Mapping[str, Any], record: _Record) -> list[tuple[str, str, list[str]]]:
    """Statements that cite the finding's evidence or its relations' evidence."""

    scope = set(target["evidence"]) | {e for rid in target["relations"] for e in record.relation_evidence(rid)}
    return [(path, text, ids) for path, text, ids in record.claims() if set(ids) & scope]


def _segments_of(evidence_ids: set[str], record: _Record) -> set[str]:
    segments = set()

    for number, members in record.index["segments"].items():
        if any(evidence_ids & record.established_by(m) for m in members):
            segments.add(number)

    return segments


def _composition(target: Mapping[str, Any], record: _Record) -> dict[str, Any]:
    composition = record.assessment["composition"]
    refuting = [_record("composition.attempted", f"{composition['attempted']}: {composition['statement']}")]
    refuting += [_record(f"composition.joins[{k}]", f"continuity {j['continuity']}: {j['reason']}")
                 for k, j in record.joins.items() if set(k.split("->")) & set(target["relations"])]
    supporting = []

    for path, text, ids in _relevant_claims(target, record):
        if len({record.scopes[e].get("scenario") for e in ids if e in record.scopes}) > 1 or len(_segments_of(set(ids), record)) > 1:
            supporting.append(_record(path, text, ",".join(ids)))

    if composition["attempted"] or supporting:
        return _check("composition_presented", SUPPORTED, "a statement relates separately established segments", supporting)

    return _check("composition_presented", CONTRADICTED,
                  "the assessment does not compose these relations: composition is not attempted, every join is "
                  "unvalidated, and no statement spans separately established segments", refuting)


def _scope_attribution(target: Mapping[str, Any], record: _Record) -> dict[str, Any]:
    refuting, supporting = [], []

    for rid in target["relations"]:
        for scope in record.relations[rid]["scopes"]:
            refuting.append(_record(f"relations.{rid}.scopes[{scope['evidence_id']}]",
                                    f"scenario {scope.get('scenario')}, {scope.get('harness_assumptions_total', 0)} "
                                    "harness assumption(s)", scope["evidence_id"]))

    for path, text, ids in _relevant_claims(target, record):
        if len({record.scopes[e].get("scenario") for e in ids if e in record.scopes}) > 1:
            supporting.append(_record(path, text, ",".join(ids)))

    if supporting:
        return _check("scope_applied_elsewhere", SUPPORTED, "a statement combines evidence from different scenarios", supporting)

    return _check("scope_applied_elsewhere", CONTRADICTED,
                  "each relation's evidence is reported with its own execution scope, and no statement applies one "
                  "scenario's evidence to another", refuting)


def _confidence(record: _Record) -> dict[str, Any]:
    termination, claims = record.assessment["termination"], record.assessment["claims"]
    records = [
        _record("composition.attempted", record.assessment["composition"]["statement"]),
        _record("termination.every_relation_observed", termination["every_relation_observed"]),
        _record("claims.admitted", claims["admitted"]),
    ]

    if claims["admitted"]:
        return _check("stated_confidence", UNRESOLVED_FINDING,
                      "admitted claim proposals exist; their grades are admission's decision, not re-judged here", records)

    return _check("stated_confidence", CONTRADICTED,
                  "the assessment states only per-edge levels with their meanings: no composition, no admitted claim, "
                  "no end-to-end conclusion", records)


_CHARACTERIZATIONS = {"negative": _negative, "static_as_execution": _static_as_execution, "composition": _composition,
                      "scope": _scope_attribution}


# -- checks: gaps -------------------------------------------------------------------------


def _relation_gap(rid: str, record: _Record, *, conditional: bool) -> dict[str, Any]:
    relation = record.relations[rid]

    if relation["level"] != OBSERVED:
        needed = relation["evidence_needed"] or ["no stronger evidence recorded"]
        return _check(f"relation_gap:{rid}", SUPPORTED, f"{rid} is {relation['level']}: {relation['level_meaning']}",
                      [_record(f"relations.{rid}.level", relation["level"])]
                      + [_record(f"relations.{rid}.evidence_needed[{i}]", item) for i, item in enumerate(needed)])

    scoped = [s for s in relation["scopes"] if s["evidence_id"] in record.established_by(rid)]
    supplied = [s for s in scoped if s.get("harness_assumptions_total") or s.get("entry_conditions")]

    if conditional and supplied:
        return _check(f"relation_gap:{rid}", SUPPORTED,
                      f"{rid} is OBSERVED only under its scenario's harness assumptions, so it does not establish "
                      "the relation outside them",
                      [_record(f"relations.{rid}.scopes[{s['evidence_id']}]",
                               f"{s.get('harness_assumptions_total', 0)} harness assumption(s): "
                               + "; ".join(s.get("harness_assumptions") or []), s["evidence_id"]) for s in supplied])

    return _check(f"relation_gap:{rid}", UNRESOLVED_FINDING,
                  f"{rid} is OBSERVED under a registered scenario; whether that suffices for the criticism is not "
                  "decided mechanically", [_record(f"relations.{rid}.level", OBSERVED)])


def _concerns_between(evidence_ids: set[str], record: _Record) -> list[dict[str, Any]]:
    return [c for c in record.concerns.values() if len(set(c["segments"]) & evidence_ids) == 2]


def _connection(target: Mapping[str, Any], record: _Record) -> dict[str, Any] | None:
    """Gap between two or more targeted relations (or two cited execution segments)."""

    relations = [r for r in target["relations"] if r in record.relations]
    segments = sorted(set(target["evidence"]) & set(record.segment_states))

    if len(relations) < 2 and len(segments) < 2:
        return None

    if len(relations) >= 2:
        established = [record.established_by(r) for r in relations if record.relations[r]["level"] != UNRESOLVED]
        shared = set.intersection(*established) if len(established) == len(relations) and established else set()
        observed = [e for e in shared if e in record.segment_states]

        if observed:
            return _check("connection", CONTRADICTED,
                          f"{', '.join(relations)} are all established by the same execution ({', '.join(sorted(observed))}); "
                          "they are not separately executed",
                          [_record(f"relations.{r}.evidence", None, ",".join(sorted(observed))) for r in relations])

        path = record.path(relations[0], relations[-1])
    else:
        ordered = record.established_relations(segments)
        path = record.path(ordered[0], ordered[-1]) if len(ordered) >= 2 else None

    if not path or len(path) < 2:
        return None  # parallel relations or segments: no chain to connect

    records = []

    if record.assessment["composition"].get("disconnected"):
        records.append(_record("composition.disconnected", record.assessment["composition"]["disconnected"]))

    for a, b in zip(path, path[1:]):
        join = record.joins.get(f"{a}->{b}")

        if join:
            records.append(_record(f"composition.joins[{a}->{b}]", f"continuity {join['continuity']}: {join['reason']}"))

    for rid in path:
        if record.relations[rid]["level"] != OBSERVED:
            records.append(_record(f"relations.{rid}.level", f"{record.relations[rid]['level']}"))

    evidence = segments or sorted({e for r in path for e in record.established_by(r) if e in record.segment_states})

    for concern in _concerns_between(set(evidence), record):
        records.append(_record(f"composition.continuity.{concern['id']}", concern["statement"]))

    return _check("connection", SUPPORTED,
                  f"nothing recorded connects {path[0]} to {path[-1]} in one execution: every join is unvalidated"
                  + (", and intermediate relations lack execution evidence" if any(
                      record.relations[r]["level"] != OBSERVED for r in path[1:-1]) else ""),
                  records)


def _continuity_check(target: Mapping[str, Any], record: _Record) -> dict[str, Any] | None:
    cited = set(target["evidence"]) | {e for c in target["concerns"] for e in record.concerns[c]["segments"]}
    segments = sorted(cited & set(record.segment_states))

    if len(segments) < 2:
        if cited - set(record.segment_states):
            return _check("state_continuity", UNGROUNDED,
                          f"cited evidence {', '.join(sorted(cited - set(record.segment_states)))} is not an execution "
                          "segment, so it carries no state; the continuity part of the finding has no target")
        return None

    concerns = _concerns_between(set(segments), record)
    pairs = [p for p in record.continuity["pairs"] if set(p["segments"]) <= set(segments)]

    if concerns:
        return _check("state_continuity", SUPPORTED, "the segments share state they never passed to each other",
                      [_record(f"composition.continuity.{c['id']}", c["statement"]) for c in concerns])

    if pairs and all(p["relation"] == continuity.CARRIED for p in pairs):
        return _check("state_continuity", CONTRADICTED, "the record carries state between these segments",
                      [_record("composition.continuity.pairs", f"{'/'.join(p['segments'])}: carried") for p in pairs])

    unknown = [u for u in record.continuity["unknown"] if u["evidence_id"] in segments]
    return _check("state_continuity", UNRESOLVED_FINDING,
                  "no shared or carried state is identified between these segments"
                  + ("; their state is incompletely recorded" if unknown else ""),
                  [_record("composition.continuity.unknown", f"{u['evidence_id']}: {u['detail']}") for u in unknown])


def _assumption(target: Mapping[str, Any], record: _Record) -> list[dict[str, Any]]:
    checks = []
    cited = [e for e in target["evidence"] if e in record.scopes]

    for eid in cited:
        scope = record.scopes[eid]

        if scope.get("harness_assumptions_total") or scope.get("entry_conditions"):
            checks.append(_check(f"scope_assumptions:{eid}", SUPPORTED,
                                 f"{eid} holds only under {scope.get('harness_assumptions_total', 0)} harness assumption(s); "
                                 "the assumed condition is supplied by the harness, not demonstrated",
                                 [_record(f"scopes[{eid}].harness_assumptions[{i}]", text, eid)
                                  for i, text in enumerate(scope.get("harness_assumptions") or [])]
                                 + ([_record(f"scopes[{eid}].coverage", scope["coverage"], eid)] if scope.get("coverage") else [])))

    for rid in target["relations"]:
        relation = record.relations[rid]
        gaps = [i for i, item in enumerate(relation["evidence_needed"]) if "capability" in item]

        if relation["level"] != OBSERVED:
            checks.append(_check(f"relation_gap:{rid}", SUPPORTED, f"{rid} is {relation['level']}",
                                 [_record(f"relations.{rid}.evidence_needed[{i}]", relation["evidence_needed"][i]) for i in gaps]
                                 or [_record(f"relations.{rid}.level", relation["level"])]))

    return checks or [_check("scope_assumptions", UNRESOLVED_FINDING,
                             "the cited evidence records no harness assumption for this condition")]


def _contradiction(target: Mapping[str, Any], record: _Record) -> dict[str, Any]:
    evidence = target["evidence"]

    if len(evidence) < 2:
        return _check("demonstrated_contradiction", UNGROUNDED, "a contradiction needs two cited package evidence items")

    recorded = [(i, c) for i, c in enumerate(record.assessment.get("contradictions") or [])
                if set(evidence) <= set(c.get("evidence_ids") or [])]

    if recorded:
        return _check("demonstrated_contradiction", SUPPORTED, "APTrace recorded this contradiction",
                      [_record(f"contradictions[{i}]", c["description"]) for i, c in recorded])

    scenarios = {record.scopes[e].get("scenario") for e in evidence if e in record.scopes}
    tensions = [t for t in record.assessment.get("tensions") or [] if set(evidence) & set(t["positive"] + t["blockers"])]
    records = [_record(f"tensions[{t['relation']}]", t["note"]) for t in tensions]
    detail = "APTrace records no contradiction between these items"

    if len(scenarios) > 1:
        detail += "; they were observed under different harness states, which alone is not a contradiction"

    return _check("demonstrated_contradiction", UNRESOLVED_FINDING, detail, records)


# -- one finding ----------------------------------------------------------------------------


def _combine(checks: Sequence[Mapping[str, Any]]) -> str:
    results = [c["result"] for c in checks if c["result"] != UNGROUNDED]

    if SUPPORTED in results:
        return SUPPORTED

    if results and all(r == CONTRADICTED for r in results):
        return CONTRADICTED

    return UNRESOLVED_FINDING


def validate_finding(index: int, finding: Mapping[str, Any], record: _Record) -> dict[str, Any]:
    category = str(finding.get("category") or "")
    target = _ground(finding, record)
    reviewer_defect = finding.get("defect") if finding.get("defect") in DEFECTS else None
    defect, characterization = CATEGORY_DEFECTS.get(category, (reviewer_defect, None))
    defect = reviewer_defect or defect
    checks: list[dict[str, Any]] = []
    character = None

    out = {
        "index": index,
        "source": finding.get("source", "finding"),
        "category": category,
        "kind": finding.get("kind"),
        "effective_kind": finding.get("effective_kind"),
        "statement": _clip(finding.get("statement"), 600),
        "test": _clip(finding.get("test"), 600) if finding.get("test") else None,
        "target": target,
        "defect": {"type": defect, "source": "reviewer" if reviewer_defect else "category"},
        "reviewer_checkable": finding.get("checkable"),
        "reviewer_resolving_evidence": _clip(finding.get("resolving_evidence"), 600) if finding.get("resolving_evidence") else None,
    }

    if not (target["relations"] or target["evidence"]):
        detail = ("every citation is absent from the package" if target["rejected_citations"]
                  else "the finding names no relation, evidence, join, segment or continuity concern")
        return dict(out, classification=UNGROUNDED, checks=[_check("target", UNGROUNDED, detail)],
                    characterization=None, mischaracterizes_investigation=False, already_recorded=False)

    if defect is None:
        return dict(out, classification=UNGROUNDED,
                    checks=[_check("defect", UNGROUNDED, f"category {category!r} and defect {finding.get('defect')!r} "
                                   "identify no checkable defect")],
                    characterization=None, mischaracterizes_investigation=False, already_recorded=False)

    if defect == INCORRECT_INFERENCE:
        if characterization == "confidence":
            checks.append(_confidence(record))
        elif characterization in _CHARACTERIZATIONS:
            checks.append(_CHARACTERIZATIONS[characterization](target, record))
        else:
            checks.append(_check("characterization", UNRESOLVED_FINDING,
                                 "no mechanical check exists for this inference in this category"))
    elif defect == MISSING_EVIDENCE:
        connection = _connection(target, record)
        segments = set(target["evidence"]) & set(record.segment_states)
        flow = (_continuity_check(target, record)
                if category == "missing_prerequisite_or_state_continuity" or len(segments) >= 2 else None)
        checks += [c for c in (connection, flow) if c is not None]

        if connection is None:
            conditional = category in ("scope_mismatch", "missing_prerequisite_or_state_continuity",
                                       "peripheral_timer_interrupt_assumption")
            checks += [_relation_gap(r, record, conditional=conditional) for r in target["relations"]]

        if characterization in _CHARACTERIZATIONS:
            character = _CHARACTERIZATIONS[characterization](target, record)
    elif defect == UNSUPPORTED_ASSUMPTION:
        checks += _assumption(target, record)
    elif defect == CONTRADICTION:
        checks.append(_contradiction(target, record))
    else:
        checks.append(_check("firmware_behavior", UNRESOLVED_FINDING,
                             "a proposition about firmware behavior; critic validation does not evaluate firmware"))

    classification = _combine(checks)

    if all(c["result"] == UNGROUNDED for c in checks):
        classification = UNGROUNDED

    gap = defect in (MISSING_EVIDENCE, UNSUPPORTED_ASSUMPTION) and classification == SUPPORTED
    recorded = gap and all(
        record.relations[r]["level"] != OBSERVED for r in target["relations"]
    ) or any(c["check"] == "connection" and c["result"] == SUPPORTED for c in checks)
    return dict(out, classification=classification, checks=checks, characterization=character,
                mischaracterizes_investigation=bool(character and character["result"] == CONTRADICTED and gap),
                already_recorded=bool(recorded))


# -- follow-up questions ------------------------------------------------------------------------


def _endpoint(text: str) -> str:
    if ":" in text:
        return "other-image"

    if _FUNCTION.match(text):
        return "function"

    return "address" if _ADDRESS.match(text) else "other"


def _operations(rid: str, record: _Record) -> list[dict[str, Any]]:
    """Existing APTrace operations that could raise this relation's level, with their prerequisites."""

    relation = record.relations[rid]
    source, target = relation["source"], relation["target"]
    kinds = (_endpoint(source), _endpoint(target))
    failed_effects = [b["evidence_id"] for b in relation["blockers"] if "effects of" in b["detail"] and "no result" in b["detail"]]
    tried = sorted({s.get("scenario") for s in relation["scopes"] if s.get("scenario")})
    ops = []

    for i, item in enumerate(relation["evidence_needed"]):
        if "capability" in item:
            ops.append({"operation": None, "availability": "capability_gap", "detail": _clip(item)})

    if kinds == ("function", "function") and relation["level"] != OBSERVED:
        ops.append({"operation": "observe_call_arguments", "arguments": {"function": target, "scenario": None},
                    "level_if_found": OBSERVED, "availability": "existing operation; needs a registered scenario that enters "
                    f"{source}" + (f" (tried: {', '.join(tried)})" if tried else "")})

        if relation["level"] in (UNRESOLVED, STATIC):
            ops.append({"operation": "analyze_function_effects", "arguments": {"function": source},
                        "level_if_found": SYMBOLIC,
                        "availability": f"attempted: {', '.join(failed_effects)} produced no result; a repeat needs a "
                                        "different bound or specialization" if failed_effects else "existing operation"})
    elif "address" in kinds:
        function = source if kinds[0] == "function" else target if kinds[1] == "function" else None

        if function:
            address = target if kinds[1] == "address" else source
            ops.append({"operation": "analyze_function_effects", "arguments": {"function": function},
                        "level_if_found": SYMBOLIC,
                        "availability": f"attempted: {', '.join(failed_effects)} produced no result; a repeat needs a "
                                        "different bound or specialization" if failed_effects else "existing operation"})
            ops.append({"operation": "observed_call_arguments", "arguments": {"function": function, "scenario": None,
                                                                              "watch": [address]},
                        "level_if_found": "concrete store observation (scenario-scoped)",
                        "availability": "executor operation with watched RAM fields; not offered in the planner palette, "
                                        "so it needs an operator request"})
    elif "other-image" in kinds:
        ops.append({"operation": None, "availability": "capability_gap",
                    "detail": "the endpoint belongs to another firmware image; needs a multi-image scenario"})

    return ops


def _limitations(path: Sequence[str], evidence: Sequence[str], record: _Record) -> list[str]:
    items = []

    for rid in path:
        items += [i for i in record.relations[rid]["evidence_needed"] if "capability" in i]

    for eid in evidence:
        coverage = (record.scopes.get(eid) or {}).get("coverage")

        if coverage:
            items.append(f"{eid} coverage: {coverage}")

    for unknown in record.continuity["unknown"]:
        if unknown["evidence_id"] in evidence:
            items.append(f"{unknown['evidence_id']} state: {unknown['detail']}")

    items.append("the continuity check compares supplied, produced and carried address ranges between segments; it "
                 "does not compare legs within one scenario or model register, peripheral or interrupt state")
    return [_clip(i) for i in dict.fromkeys(items)]


def _question(kind: str, path: Sequence[str], concerns: Sequence[Mapping[str, Any]], record: _Record,
              cited: Sequence[str] = ()) -> dict[str, Any]:
    first, last = record.relations[path[0]], record.relations[path[-1]]
    evidence = sorted({e for r in path for e in record.established_by(r) if e in record.segment_states}
                      | {e for c in concerns for e in c["segments"]} | {e for e in cited if e in record.scopes})
    addresses = sorted({a["addr"] for c in concerns for a in c.get("addresses", [])
                        if c["kind"] in (continuity.INDEPENDENTLY_SUPPLIED, continuity.SUPPLIED_OVER_PRIOR)})
    missing, operations, conditions, expected = [], [], [], []

    for rid in path:
        relation = record.relations[rid]

        if relation["level"] != OBSERVED:
            missing += [f"{rid} ({relation['level']}): {item}" for item in relation["evidence_needed"] or ["no stronger evidence recorded"]]
            operations += [dict(op, relation=rid) for op in _operations(rid, record)]

    for a, b in zip(path, path[1:]):
        if f"{a}->{b}" in record.joins:
            missing.append(f"join {a}->{b}: continuity {record.joins[f'{a}->{b}']['continuity']}")

    missing += [f"{c['id']}: {c['requirement']}" for c in concerns]

    if kind == "connection":
        question = (f"Does one execution carry {first['source']} through {last['target']} ({' -> '.join(path)}), "
                    "with the intermediate relations established in that same execution?")
        operations.append({"operation": None, "availability": "requires_registered_scenario",
                           "detail": f"a case scenario that runs from {first['source']}'s caller context through "
                                     f"{last['target']} in one execution"
                                     + (f" without seeding {', '.join(addresses)}" if addresses else "")
                                     + f"; then observe_call_arguments of {last['target']} under it"})
        conditions.append(f"one execution, or segments recorded as carried forward, covering {' -> '.join(path)}")

        if addresses:
            conditions.append(f"{', '.join(addresses)} must be produced by firmware execution or carried from a recorded "
                              "segment, not supplied as an initial condition")

        expected.append(f"each of {', '.join(path)} OBSERVED under one scope whose state records no seed for the shared "
                        "addresses (or records them as carried_from)")
    elif kind == "assumption":
        question = (f"Does {' -> '.join(path)} hold without the harness assumptions its evidence "
                    f"({', '.join(evidence) or 'none'}) supplies?")
        conditions.append("the assumed condition (for example an interrupt delivery or a seeded peripheral state) is "
                          "produced by the modeled system, or the relation is observed without it")
        expected.append(f"{', '.join(path)} observed under a scope that does not supply the challenged assumption")
    else:
        question = f"Is {path[0]} ({first['source']} -> {first['target']}) established beyond {first['level']}?"
        tried = sorted({s.get("scenario") for s in first["scopes"] if s.get("scenario")})
        conditions.append(f"a registered scenario that enters {first['source']}"
                          + (f"; already tried: {', '.join(tried)}" if tried else ""))
        expected.append(f"{path[0]} at SYMBOLIC (completed effects show the call or access) or OBSERVED (a scenario-scoped "
                        "observed call), with its scope recorded")

    for eid in evidence:
        scope = record.scopes.get(eid) or {}

        if scope.get("harness_assumptions_total"):
            conditions.append(f"{eid}'s {scope['harness_assumptions_total']} harness assumption(s) stay disclosed; any that "
                              "remain are conditions of the new evidence, not firmware state")

    return {
        "kind": kind,
        "question": question,
        "challenged": {"relations": list(path), "levels": {r: record.relations[r]["level"] for r in path},
                       "from": first["source"], "to": last["target"], "segments": evidence},
        "missing_evidence": [_clip(m) for m in dict.fromkeys(missing)],
        "candidate_operations": operations,
        "conditions": list(dict.fromkeys(conditions)),
        "expected_evidence": expected,
        "limitations": _limitations(path, evidence, record),
    }


def followup_questions(findings: Sequence[Mapping[str, Any]], record: _Record) -> list[dict[str, Any]]:
    """Bounded follow-up proposals from SUPPORTED/UNRESOLVED findings and APTrace's continuity concerns."""

    groups: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}

    def add(kind: str, path: list[str], source: dict[str, Any], tests: Sequence[str], concerns: Sequence[Mapping[str, Any]],
            cited: Sequence[str] = ()):
        key = (kind, tuple(path))
        group = groups.setdefault(key, {"sources": [], "reviewer_tests": [], "concerns": {}, "cited": []})
        group["sources"].append(source)
        group["cited"] += [e for e in cited if e not in group["cited"]]
        group["reviewer_tests"] += [t for t in tests if t and t not in group["reviewer_tests"]]
        group["concerns"].update({c["id"]: c for c in concerns})

    for finding in findings:
        if finding["classification"] not in (SUPPORTED, UNRESOLVED_FINDING):
            continue

        relations = finding["target"]["relations"]
        evidence = set(finding["target"]["evidence"]) | {e for c in finding["target"]["concerns"] for e in record.concerns[c]["segments"]}
        segments = sorted(evidence & set(record.segment_states))
        ordered = relations if len(relations) >= 2 else record.established_relations(segments) if len(segments) >= 2 else []
        chain = record.path(ordered[0], ordered[-1]) if len(ordered) >= 2 else None
        source = {"finding": finding["index"], "source": finding["source"], "category": finding["category"],
                  "classification": finding["classification"]}
        tests = [finding.get("test") or "", finding.get("reviewer_resolving_evidence") or ""]

        if chain and len(chain) >= 2:
            concerns = _concerns_between(set(segments) or {e for r in chain for e in record.established_by(r)}, record)
            add("connection", chain, source, tests, concerns, finding["target"]["evidence"])
            continue

        # Parallel relations (no chain) each get their own question; an OBSERVED one is questioned on its scope.
        for rid in relations:
            observed = record.relations[rid]["level"] == OBSERVED
            kind = "assumption" if finding["defect"]["type"] == UNSUPPORTED_ASSUMPTION or observed else "relation"
            add(kind, [rid], source, tests, [], finding["target"]["evidence"])

    for concern in record.concerns.values():
        related = record.established_relations(concern["segments"])

        chain = record.path(related[0], related[-1]) if len(related) >= 2 else None

        if chain and len(chain) >= 2:
            add("connection", chain, {"aptrace_continuity": concern["id"]}, [], [concern], concern["segments"])

    connections = [path for kind, path in groups if kind == "connection"]

    for kind, path in list(groups):
        if kind != "connection":
            continue

        container = next((longer for longer in connections if len(longer) > len(path) and any(
            longer[i:i + len(path)] == path for i in range(len(longer) - len(path) + 1))), None)

        if container is not None:
            folded = groups.pop((kind, path))
            target = groups[("connection", container)]
            target["sources"] += folded["sources"]
            target["reviewer_tests"] += [t for t in folded["reviewer_tests"] if t not in target["reviewer_tests"]]
            target["concerns"].update(folded["concerns"])
            target["cited"] += [e for e in folded["cited"] if e not in target["cited"]]

    questions = []

    for (kind, path), group in sorted(groups.items(), key=lambda item: (record.order[item[0][1][0]], item[0][0], item[0][1])):
        body = _question(kind, list(path), list(group["concerns"].values()), record, group["cited"])
        questions.append({
            "id": "FQ-" + digest({"kind": kind, "path": list(path)})[:12],
            **body,
            "sources": group["sources"],
            "reviewer_tests": [_clip(t, 400) for t in group["reviewer_tests"]][:4],
            "status": "proposal",
            "executable": False,
            "note": "a proposal for a future bounded investigation; nothing here runs it, and reviewer tests are not "
                    "APTrace requirements",
        })

    return questions[:MAX_FOLLOWUPS]


# -- the whole review -------------------------------------------------------------------------


def _omitted_findings(review: Mapping[str, Any], start: int, record: _Record) -> list[dict[str, Any]]:
    """Omitted questions as omitted_question findings. Their ids, and the relations whose endpoint
    (function name or address) the text names, are pattern-extracted from the text."""

    findings = []

    for offset, text in enumerate(review.get("omitted_questions") or []):
        tokens = _ID_TOKEN.findall(text)
        lowered = text.lower()
        def naming(kind: str) -> list[str]:
            return [r["id"] for r in record.assessment["relations"]
                    if any(_endpoint(end) == kind and end.lower() in lowered for end in (r["source"], r["target"]))]

        # An address endpoint is specific; a function name is often shared by several relations.
        named = naming("address") or naming("function")
        explicit = [t for t in tokens if t.startswith("R") and "->" not in t]
        findings.append({
            "source": "omitted_question", "category": "omitted_question", "kind": "hypothesis",
            "effective_kind": "hypothesis", "statement": text, "test": None,
            # An endpoint named in the text grounds only when no relation id is cited.
            "relations": explicit or (named if len(named) <= 2 else []),
            "evidence_ids": [t for t in tokens if t.startswith("E")],
            "targets": [t for t in tokens if t.startswith(("C", "S")) or "->" in t],
            "index": start + offset,
        })

    return findings


def validate_review(
    assessment: Mapping[str, Any],
    review: Mapping[str, Any],
    *,
    package: Mapping[str, Any] | None = None,
    attempt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Deterministic validation of one parsed review against the assessment it reviewed."""

    from aptrace_agent.research.terminal import assessment_sha256

    record = _Record(assessment, package)
    raw = list(review.get("findings") or [])
    findings = [validate_finding(i, f, record) for i, f in enumerate(raw)]
    findings += [validate_finding(f["index"], f, record) for f in _omitted_findings(review, len(raw), record)]
    confidence = None

    if review.get("confidence") == "overstated":
        confidence = dict(_confidence(record), reviewer="overstated")

    unraised = []

    for concern in record.concerns.values():
        addresses = {a["addr"].lower() for a in concern.get("addresses", [])}
        raising = [f["index"] for f in findings if f["classification"] != UNGROUNDED and (
            concern["id"] in f["target"]["concerns"]
            or {int(h, 16) for h in _HEX.findall(f"{f['statement']} {f.get('test') or ''}")}
            & {int(a, 16) for a in addresses})]
        related = [f["index"] for f in findings if set(concern["segments"]) <= set(f["target"]["evidence"])]

        if not raising:
            unraised.append({"concern": concern["id"], "kind": concern["kind"], "statement": concern["statement"],
                             "findings_citing_both_segments": related})

    counts = {c: sum(1 for f in findings if f["classification"] == c) for c in CLASSIFICATIONS}
    result = {
        "version": VALIDATION_VERSION,
        "investigation_id": (package or {}).get("investigation_id") or (attempt or {}).get("investigation_id"),
        "attempt_id": (attempt or {}).get("attempt_id"),
        "assessment_sha256": assessment_sha256(assessment),
        "assessment_version": assessment.get("version"),
        "package_sha256": (package or {}).get("package_sha256"),
        "continuity_source": "assessment" if (assessment.get("composition") or {}).get("continuity") else
                             "recomputed from v1 scopes (harness assumption text)",
        "findings": findings,
        "confidence": confidence,
        "continuity": {"concerns": list(record.concerns.values()), "unknown": record.continuity["unknown"],
                       "not_raised_by_reviewer": unraised},
        "followups": followup_questions(findings, record),
        "counts": counts,
        "authority": AUTHORITY,
    }
    result["validation_sha256"] = digest({k: v for k, v in result.items() if k != "validation_sha256"})
    return result


def render_validation(validation: Mapping[str, Any]) -> list[str]:
    lines = [f"counts: " + ", ".join(f"{k} {v}" for k, v in validation["counts"].items())]

    for finding in validation["findings"]:
        refs = ",".join(finding["target"]["relations"] + finding["target"]["evidence"]) or "-"
        lines.append(f"[{finding['classification']}] #{finding['index']} {finding['category']} {refs}: "
                     f"{_clip(finding['statement'], 160)}")

        for check in finding["checks"]:
            lines.append(f"    {check['check']}: {check['result']} ({_clip(check['detail'], 200)})")

        if finding["target"]["rejected_citations"]:
            lines.append(f"    rejected citations: {', '.join(finding['target']['rejected_citations'])}")

        if finding["mischaracterizes_investigation"]:
            lines.append(f"    characterization {finding['characterization']['check']}: CONTRADICTED "
                         f"({_clip(finding['characterization']['detail'], 200)}); the gap itself is kept")

        if finding["already_recorded"]:
            lines.append("    the gap is already an APTrace evidence requirement")

    if validation.get("confidence"):
        lines.append(f"reviewer confidence 'overstated': {validation['confidence']['result']} "
                     f"({_clip(validation['confidence']['detail'], 200)})")

    for item in validation["continuity"]["not_raised_by_reviewer"]:
        lines.append(f"APTrace continuity {item['concern']} not raised by the reviewer: {_clip(item['statement'], 220)}")

    return lines


def render_followups(validation: Mapping[str, Any]) -> list[str]:
    lines = []

    for q in validation["followups"]:
        sources = ", ".join(f"#{s['finding']} {s['classification']}" if "finding" in s else f"APTrace {s['aptrace_continuity']}"
                            for s in q["sources"])
        lines.append(f"{q['id']} [{q['kind']}] {q['question']} (from {sources})")
        lines += [f"    missing: {m}" for m in q["missing_evidence"][:6]]
        lines += [f"    operation: {op.get('operation') or '-'} [{op['availability']}]"
                  + (f" {op['detail']}" if op.get("detail") else "") for op in q["candidate_operations"][:5]]
        lines += [f"    condition: {c}" for c in q["conditions"][:4]]
        lines += [f"    expected: {e}" for e in q["expected_evidence"]]

    return lines


__all__ = [
    "VALIDATION_VERSION", "SUPPORTED", "CONTRADICTED", "UNRESOLVED_FINDING", "UNGROUNDED", "CLASSIFICATIONS", "DEFECTS",
    "CATEGORY_DEFECTS", "AUTHORITY", "target_index", "state_continuity", "validate_finding", "validate_review",
    "followup_questions", "render_validation", "render_followups",
]
