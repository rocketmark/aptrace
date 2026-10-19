"""
Terminal review (terminal-review-v1): adversarial criticism of a focused
run's deterministic terminal assessment by the review model (Gemma).

Lifecycle (docs/terminal-review.md):

1. ``prepare``: persist the assessment and a bounded review package,
   write-once. The review is then ``pending``. Nothing here needs a model.
2. ``run``: make the reviewer the only resident model (omlx.ModelResidency),
   send the package, parse and check the criticism, release the reviewer,
   and persist one attempt record. Optionally restore the planner.
3. ``retry``: the same as ``run``, from the persisted package only. It
   verifies the package and assessment hashes first and never rebuilds them.

Status is derived from the attempt records: ``pending`` (package, no
attempt), ``completed``, ``unavailable`` (the model could not be made
resident or reached), ``failed`` (the model ran but produced no valid
review), ``skipped`` (explicit policy).

Authority: the review is advisory. It never changes evidence, relation
levels, claim state or admission. Its findings are kept apart from the
deterministic result in every report. A completed review does not mean the
conclusions are correct.

Critic validation (research/critic.py) classifies each finding of a completed
attempt against the full assessment and persists the result beside the
attempt (``validations/<attempt_id>.json``). It has no more authority than
the review.
"""

from __future__ import annotations

import copy
import json
import os
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aptrace_agent.ledger.hashing import digest
from aptrace_agent.ledger.store import LedgerImmutableError, new_id
from aptrace_agent.research import continuity
from aptrace_agent.research.critic import (
    DEFECTS,
    render_followups,
    render_validation,
    state_continuity,
    target_index,
    validate_review,
)
from aptrace_agent.research.terminal import assessment_sha256, render_assessment, unresolved_requirements


# v2 (Critic Validation v1): a targets index, compact execution state per
# scope, material-first reduction and recorded omissions. Template v2 asks
# for grounded findings. v1 packages and attempts stay valid.
PACKAGE_VERSION = "terminal-review-package-v2"
TEMPLATE_VERSION = "terminal-review-v2"
ATTEMPT_VERSION = "terminal-review-attempt-v1"
DEFAULT_REVIEW_MODEL = "gemma-4-26b-a4b-it-4bit"

# Package bound in rendered characters (well inside the review model's
# context; the oMLX setting for the default model is 40,000 tokens).
MAX_PACKAGE_CHARS = 24000

PENDING, COMPLETED, UNAVAILABLE, FAILED, SKIPPED = "pending", "completed", "unavailable", "failed", "skipped"
STATUSES = (PENDING, COMPLETED, UNAVAILABLE, FAILED, SKIPPED)

CATEGORIES = (
    "unsupported_relationship",
    "static_as_execution",
    "missing_prerequisite_or_state_continuity",
    "unjustified_composition",
    "peripheral_timer_interrupt_assumption",
    "contradictory_evidence",
    "scope_mismatch",
    "unsupported_negative",
    "overstated_confidence",
    "counterexample_or_falsification",
    "omitted_question",
)
KINDS = ("demonstrated_contradiction", "hypothesis", "suggested_test")
CONFIDENCE = ("overstated", "appropriate", "understated", "cannot_judge")

AUTHORITY = ("advisory: the review never changes evidence, relation levels, claim state or admission; "
             "APTrace deterministic verification remains the only authority")


SYSTEM_PROMPT = """You are an independent adversarial reviewer of a firmware reverse-engineering investigation.
APTrace, a deterministic evidence system, gives you its terminal assessment: the objective, the relations
it investigated with per-edge evidence levels, the execution scopes and harness assumptions of every
concrete result, the failed and rejected operations, and the open questions.

Your job is to challenge the investigation, not to summarize it favorably. Assume conclusions are wrong
until the evidence in the package forces them. You cannot run tools; you may only recommend analyses.
You have no authority to verify, promote or grade anything: APTrace's deterministic rules decide that.

Look for:
1. Relationships stated or implied without supporting evidence.
2. Static reachability (a call-graph edge) presented or treated as execution.
3. Missing execution prerequisites or missing state continuity between steps.
4. Separately executed traces or scenarios joined as if they were one execution.
5. Assumptions about peripheral, timer or interrupt behavior that no evidence demonstrates.
6. Evidence that contradicts other evidence.
7. Scope mismatches: evidence about one scenario, bound or set used for another.
8. Negative conclusions drawn from failed, bounded or missing analysis.
9. Confidence stronger than the evidence level.
10. Concrete counterexamples or falsification tests that could refute a relationship.
11. Important unresolved questions the conclusion omits.

Classify every finding:
- "demonstrated_contradiction": two cited evidence items in the package establish incompatible facts.
  Cite their evidence ids. Without cited evidence it is not demonstrated.
- "hypothesis": a plausible problem the package does not demonstrate.
- "suggested_test": a specific analysis, execution or measurement that would confirm or refute something.

Ground every finding. Name its target with ids from the package: relations (R..), evidence (E..), and the
"targets" index (joins R1->R2, segments S1, continuity concerns C1). State the defect:
- "missing_evidence": a relationship, prerequisite or state continuity the evidence does not establish;
- "incorrect_inference": APTrace concluded or implied something the evidence does not support. Quote the exact
  package text you challenge in "quote". Do not attribute a conclusion the package does not state;
- "unsupported_assumption": a harness, peripheral, timer or interrupt condition supplied rather than shown;
- "contradiction": two cited evidence items conflict;
- "firmware_hypothesis": a claim about firmware behavior to be tested.
APTrace checks every finding mechanically against its full record. Citations that are not in the package are
rejected, and a finding without a valid target is ungrounded.

Respond with exactly one JSON object and nothing else."""


RESPONSE_FORMAT = """RESPONSE FORMAT (one JSON object, no markdown):
{"findings": [{"category": "<one of: %s>",
               "kind": "demonstrated_contradiction" | "hypothesis" | "suggested_test",
               "defect": "<one of: %s>",
               "relations": ["R1", ...], "evidence_ids": ["E3", ...], "targets": ["R1->R2", "S1", "C1", ...],
               "quote": "<exact package text challenged; only for incorrect_inference>",
               "statement": "<the specific problem or test>",
               "checkable": true | false,
               "resolving_evidence": "<the evidence that would establish or refute the finding>",
               "test": "<the falsification test or evidence that would decide it>"}],
 "omitted_questions": ["<important unresolved question the conclusion omits>"],
 "confidence": "overstated" | "appropriate" | "understated" | "cannot_judge",
 "summary": "<two sentences at most>"}""" % (", ".join(CATEGORIES), ", ".join(DEFECTS))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _clip(text: Any, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


# -- package -----------------------------------------------------------------------


def investigation_id(assessment: Mapping[str, Any], links: Mapping[str, Any]) -> str:
    return "TR-" + digest({"assessment_sha256": assessment_sha256(assessment), "links": dict(links)})[:16]


def _compact_state(scope: Mapping[str, Any]) -> dict[str, Any] | None:
    state = continuity.segment_state(scope)

    if state is None:
        return None

    return {"initial": state["initial"], "supplied": state["supplied"], "supplied_unidentified": state["supplied_unidentified"],
            "carried_from": state["carried_from"], "produced": state["produced"][:8],
            "produced_recorded": state["produced_recorded"], "end_state": state["end_state"][:8]}


def _material(text: str, addresses: set[int]) -> bool:
    """A harness assumption a reviewer needs to challenge continuity or scope: one naming a shared
    address, or a qualifier (what the harness did not model)."""

    lowered = f" {text.lower()} "
    named = {int(h, 16) for h in re.findall(r"0x[0-9a-f]{1,8}", lowered)}
    return bool(named & addresses) or any(q in lowered for q in (" not ", " no ", "without", "direct call", "fresh"))


def build_package(assessment: Mapping[str, Any], *, links: Mapping[str, Any], max_chars: int = MAX_PACKAGE_CHARS) -> dict[str, Any]:
    """Bounded, deterministic review input built only from the assessment."""

    inv, assessment_hash = investigation_id(assessment, links), assessment_sha256(assessment)
    assessment = copy.deepcopy(dict(assessment))  # the reductions below must never touch the caller's assessment
    flow = state_continuity(assessment)
    shared = {int(a["addr"], 16) for c in flow["concerns"] for a in c.get("addresses", [])}

    # Scopes can be shared between relations (and with assessment["scopes"]): compact each once.
    compact = {s["evidence_id"]: _compact_state(s) for r in assessment["relations"] for s in r["scopes"]}

    for relation in assessment["relations"]:
        for scope in relation["scopes"]:
            scope["state"] = compact[scope["evidence_id"]]

    content: dict[str, Any] = {
        "objective": {k: assessment["objective"][k] for k in ("question", "constraints", "firmware")},
        "termination": assessment["termination"],
        "planner": assessment.get("planner"),
        "relations": [
            {k: r[k] for k in ("id", "source", "target", "label", "level", "level_meaning", "status", "evidence",
                               "blockers", "evidence_needed", "scopes")}
            for r in assessment["relations"]
        ],
        "composition": dict(assessment["composition"], continuity={
            "concerns": flow["concerns"], "unknown": flow["unknown"], "note": flow["note"]}),
        "targets": target_index(assessment),
        "tensions": assessment["tensions"],
        "evidence": [
            {k: e[k] for k in ("evidence_id", "tool", "arguments", "status", "summary", "result_sha256") if k in e}
            for e in assessment["evidence"]
        ],
        "failed_operations": assessment["failed_operations"],
        "rejected_operations": assessment["rejected_operations"][:8],
        "limitations": assessment["limitations"],
        "unresolved_questions": [q["question"] for q in assessment["unresolved_questions"]][:12],
        "hypotheses": [h["statement"] for h in assessment["hypotheses"]][:6],
        "contradictions": assessment["contradictions"],
        "claims": assessment["claims"],
        "operations": [
            {k: o[k] for k in ("step", "action", "tool", "arguments", "evidence_id", "status", "outcome")}
            for o in assessment["operations"]
        ],
    }
    truncated: list[str] = []
    omitted: list[dict[str, Any]] = []

    def cap(label: str, total: int, kept: int) -> None:
        if total > kept:
            omitted.append({"item": label, "dropped": total - kept, "kept": kept})

    # Fixed caps, recorded (they apply whatever the size).
    cap("rejected_operations", len(assessment["rejected_operations"]), 8)
    cap("hypotheses", len(assessment["hypotheses"]), 6)
    cap("unresolved_questions", len(assessment["unresolved_questions"]), 12)

    for relation in assessment["relations"]:
        for scope in relation["scopes"]:
            cap(f"assessment harness_assumptions {relation['id']}/{scope['evidence_id']} (beyond terminal.MAX_ASSUMPTIONS)",
                scope.get("harness_assumptions_total", 0), len(scope.get("harness_assumptions") or []))

    def size() -> int:
        return len(json.dumps(content, sort_keys=True))

    def keep_material_assumptions() -> None:
        for relation in content["relations"]:
            for scope in relation["scopes"]:
                items = scope["harness_assumptions"]
                kept = [a for i, a in enumerate(items) if i < 3 or _material(a, shared)]
                cap(f"harness_assumptions {relation['id']}/{scope['evidence_id']}", len(items), len(kept))
                scope["harness_assumptions"] = kept

    def drop(label: str, key: str, limit: int | None = None) -> Callable[[], None]:
        def reduce() -> None:
            items = content[key]
            kept = items[:limit] if limit is not None else []
            cap(label, len(items), len(kept))
            content[key] = kept
        return reduce

    def clip_summaries(limit: int | None) -> Callable[[], None]:
        def reduce() -> None:
            touched = [e["evidence_id"] for e in content["evidence"] if e.get("summary") and (limit is None or len(e["summary"]) > limit)]

            for e in content["evidence"]:
                if limit is None:
                    e.pop("summary", None)
                elif e.get("summary"):
                    e["summary"] = _clip(e["summary"], limit)

            if touched:
                omitted.append({"item": "evidence.summary" + (f">{limit} chars" if limit else ""), "evidence": touched})
        return reduce

    # Lowest value first: the trajectory, then evidence prose, then lists. Material state (scope state,
    # continuity concerns, segment boundaries, blockers, qualifiers, contradictions) is never reduced.
    reducers: list[tuple[str, Callable[[], None]]] = [
        ("operations", drop("operations (trajectory)", "operations")),
        ("evidence.summary<=300", clip_summaries(300)),
        ("evidence.arguments", lambda: (omitted.append({"item": "evidence.arguments"}),
                                        [e.pop("arguments", None) for e in content["evidence"]])),
        ("unresolved_questions<=6", drop("unresolved_questions (reduction)", "unresolved_questions", 6)),
        ("scopes.harness_assumptions<=3+material", keep_material_assumptions),
        ("evidence.summary<=120", clip_summaries(120)),
        # Last: ids, tool, status and result hash remain for every item.
        ("evidence.summary", clip_summaries(None)),
    ]

    for label, reduce in reducers:
        if size() <= max_chars:
            break

        reduce()
        truncated.append(label)

    package = {
        "version": PACKAGE_VERSION,
        "template_version": TEMPLATE_VERSION,
        "investigation_id": inv,
        "assessment_sha256": assessment_hash,
        "links": dict(links),
        "bounds": {"max_chars": max_chars, "chars": size(), "truncated": truncated, "within_bound": size() <= max_chars,
                   "omitted": omitted},
        "content": content,
    }
    package["package_sha256"] = package_sha256(package)
    return package


def package_integrity(assessment: Mapping[str, Any], package: Mapping[str, Any]) -> dict[str, Any]:
    """Whether a package kept the material a reviewer needs to challenge causal relationships.

    Material: every relation's level, blockers and evidence needed; every execution scope with its
    assumption total; the harness assumptions that name a shared address or a qualifier; continuity
    concerns; segment boundaries and joins; contradictions and tensions; every evidence id. Anything
    else the package dropped is listed as low-value omission. Works for v1 and v2 packages.
    """

    content = package["content"]
    flow = state_continuity(assessment)
    shared = {int(a["addr"], 16) for c in flow["concerns"] for a in c.get("addresses", [])}
    shown = {r["id"]: r for r in content["relations"]}
    missing: list[str] = []

    for relation in assessment["relations"]:
        mine = shown.get(relation["id"])

        if mine is None:
            missing.append(f"relation {relation['id']}")
            continue

        for key in ("level", "blockers", "evidence_needed"):
            if mine.get(key) != relation[key]:
                missing.append(f"{relation['id']}.{key}")

        scopes = {s["evidence_id"]: s for s in mine.get("scopes") or []}

        for scope in relation["scopes"]:
            kept = scopes.get(scope["evidence_id"])

            if kept is None:
                missing.append(f"{relation['id']} scope {scope['evidence_id']}")
                continue

            for text in scope.get("harness_assumptions") or []:
                if _material(text, shared) and text not in (kept.get("harness_assumptions") or []):
                    missing.append(f"{relation['id']}/{scope['evidence_id']} harness assumption: {text}")

    composition = content.get("composition") or {}

    for key in ("joins", "segments", "disconnected"):
        if composition.get(key) != assessment["composition"].get(key):
            missing.append(f"composition.{key}")

    shown_concerns = {c["id"] for c in (composition.get("continuity") or {}).get("concerns") or []}

    for concern in flow["concerns"]:
        if concern["id"] not in shown_concerns:
            missing.append(f"continuity {concern['id']} ({concern['kind']}) is not stated in the package")

    for key in ("contradictions", "tensions"):
        if content.get(key) != assessment.get(key):
            missing.append(key)

    absent = {e["evidence_id"] for e in assessment["evidence"]} - {e["evidence_id"] for e in content["evidence"]}
    missing += [f"evidence {e}" for e in sorted(absent)]
    return {"package_version": package.get("version"), "material_complete": not missing, "missing_material": missing,
            "truncated": package["bounds"].get("truncated", []), "omitted_recorded": package["bounds"].get("omitted")}


def package_sha256(package: Mapping[str, Any]) -> str:
    return digest({k: v for k, v in package.items() if k != "package_sha256"})


def review_messages(package: Mapping[str, Any]) -> list[dict[str, str]]:
    """The exact review request: fixed template plus the package content."""

    prompt = (
        "TERMINAL ASSESSMENT (JSON, produced deterministically by APTrace)\n\n"
        + json.dumps(package["content"], indent=1, sort_keys=True)
        + "\n\nTASK\n\nChallenge this investigation. Report the most important problems first, at most 12 findings. "
        "Every finding must name the relations and evidence ids it concerns. Prefer specific falsification tests "
        "over general advice. Do not restate the assessment.\n\n"
        + RESPONSE_FORMAT
    )
    return [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]


# -- parsing and APTrace checks ----------------------------------------------------


class MalformedReview(ValueError):
    pass


def _extract_json(content: str) -> Any:
    text = content.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE)
    text = fenced.group(1) if fenced else text

    try:
        return json.loads(text)
    except ValueError:
        start, end = text.find("{"), text.rfind("}")

        if start < 0 or end <= start:
            raise MalformedReview("response is not a JSON object") from None

        try:
            return json.loads(text[start : end + 1])
        except ValueError as exc:
            raise MalformedReview(f"response JSON does not parse: {exc}") from None


def parse_review(content: str, package: Mapping[str, Any]) -> dict[str, Any]:
    """Structured criticism with APTrace's mechanical reference checks. Raises MalformedReview."""

    data = _extract_json(content)

    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise MalformedReview("expected an object with a findings list")

    relation_ids = {r["id"] for r in package["content"]["relations"]}
    evidence_ids = {e["evidence_id"] for e in package["content"]["evidence"]}
    index = package["content"].get("targets") or {}
    target_ids = relation_ids | evidence_ids | set(index.get("joins") or []) | set(index.get("segments") or {}) \
        | set(index.get("continuity") or {})
    findings = []

    for index, item in enumerate(data["findings"][:16]):
        if not isinstance(item, dict) or not str(item.get("statement") or "").strip():
            raise MalformedReview(f"finding {index} has no statement")

        kind = str(item.get("kind") or "").strip()

        if kind not in KINDS:
            raise MalformedReview(f"finding {index} kind {kind!r} is not one of {', '.join(KINDS)}")

        category = str(item.get("category") or "").strip()
        relations = [str(r) for r in item.get("relations") or [] if isinstance(r, (str, int))]
        cited = [str(e) for e in item.get("evidence_ids") or [] if isinstance(e, (str, int))]
        checks = []

        if category not in CATEGORIES:
            checks.append(f"unknown category {category!r}")

        unknown_relations = [r for r in relations if r not in relation_ids]
        unknown_evidence = [e for e in cited if e not in evidence_ids]

        if unknown_relations:
            checks.append(f"relations not in the package: {', '.join(unknown_relations)}")

        if unknown_evidence:
            checks.append(f"evidence not in the package: {', '.join(unknown_evidence)}")

        targets = [str(t) for t in item.get("targets") or [] if isinstance(t, (str, int))]
        unknown_targets = [t for t in targets if t not in target_ids]
        defect = str(item.get("defect") or "").strip() or None

        if unknown_targets:
            checks.append(f"targets not in the package: {', '.join(unknown_targets)}")

        if defect is not None and defect not in DEFECTS:
            checks.append(f"unknown defect {defect!r}")

        effective = kind

        # A contradiction is demonstrated only by evidence in the package.
        if kind == "demonstrated_contradiction" and not [e for e in cited if e in evidence_ids]:
            effective = "hypothesis"
            checks.append("contradiction cites no package evidence; reported as a hypothesis")

        findings.append({
            "category": category,
            "kind": kind,
            "effective_kind": effective,
            "relations": relations,
            "evidence_ids": cited,
            "statement": _clip(item.get("statement"), 600),
            "test": _clip(item.get("test"), 600) if item.get("test") else None,
            # Grounding fields (template v2); absent from v1 responses.
            "targets": targets,
            "defect": defect,
            "quote": _clip(item.get("quote"), 400) if item.get("quote") else None,
            "checkable": item.get("checkable") if isinstance(item.get("checkable"), bool) else None,
            "resolving_evidence": _clip(item.get("resolving_evidence"), 600) if item.get("resolving_evidence") else None,
            "aptrace_checks": checks,
        })

    confidence = str(data.get("confidence") or "cannot_judge")
    known = {"findings", "omitted_questions", "confidence", "summary"}
    return {
        "findings": findings,
        "omitted_questions": [_clip(q, 300) for q in data.get("omitted_questions") or [] if isinstance(q, str)][:8],
        "confidence": confidence if confidence in CONFIDENCE else "cannot_judge",
        "summary": _clip(data.get("summary"), 500),
        "ignored_fields": sorted(set(data) - known),
        "authority": AUTHORITY,
    }


# -- store -------------------------------------------------------------------------


class TerminalReviewStore:
    """
    Write-once records per investigation:

        <root>/<investigation_id>/assessment.json
        <root>/<investigation_id>/package.json
        <root>/<investigation_id>/attempts/<attempt_id>.json
        <root>/<investigation_id>/residency/<record_id>.json
        <root>/<investigation_id>/validations/<attempt_id>.json   critic validation of a completed attempt
    """

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root).expanduser()

    def _dir(self, inv: str) -> Path:
        if not re.fullmatch(r"TR-[0-9a-f]{16}", inv):
            raise ValueError(f"not a terminal review id: {inv}")

        return self.root / inv

    @staticmethod
    def _write_once(path: Path, payload: Mapping[str, Any]) -> None:
        text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n"

        if path.exists():
            if json.loads(path.read_text()) == json.loads(text):
                return

            raise LedgerImmutableError(f"refusing to rewrite immutable terminal review record {path}")

        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("x", encoding="utf-8") as f:
            f.write(text)

    def put_assessment(self, assessment: Mapping[str, Any], links: Mapping[str, Any]) -> str:
        inv = investigation_id(assessment, links)
        self._write_once(self._dir(inv) / "assessment.json", {
            "investigation_id": inv, "assessment_sha256": assessment_sha256(assessment), "links": dict(links),
            "assessment": dict(assessment),
        })
        return inv

    def put_package(self, package: Mapping[str, Any]) -> None:
        self._write_once(self._dir(package["investigation_id"]) / "package.json", package)

    def put_attempt(self, attempt: Mapping[str, Any]) -> None:
        self._write_once(self._dir(attempt["investigation_id"]) / "attempts" / f"{attempt['attempt_id']}.json", attempt)

    def put_residency(self, inv: str, record_id: str, record: Mapping[str, Any]) -> None:
        self._write_once(self._dir(inv) / "residency" / f"{record_id}.json", record)

    def put_validation(self, inv: str, attempt_id: str, record: Mapping[str, Any]) -> None:
        self._write_once(self._dir(inv) / "validations" / f"{attempt_id}.json", record)

    def validation(self, inv: str, attempt_id: str) -> dict[str, Any] | None:
        path = self._dir(inv) / "validations" / f"{attempt_id}.json"
        return json.loads(path.read_text()) if path.is_file() else None

    def assessment(self, inv: str) -> dict[str, Any]:
        return json.loads((self._dir(inv) / "assessment.json").read_text())

    def package(self, inv: str) -> dict[str, Any]:
        return json.loads((self._dir(inv) / "package.json").read_text())

    def attempts(self, inv: str) -> list[dict[str, Any]]:
        base = self._dir(inv) / "attempts"
        records = [json.loads(p.read_text()) for p in base.glob("*.json")] if base.is_dir() else []
        return sorted(records, key=lambda a: (a.get("sequence", 0), a.get("started_at") or "", a["attempt_id"]))

    def ids(self) -> list[str]:
        return sorted(p.name for p in self.root.glob("TR-*") if p.is_dir()) if self.root.is_dir() else []

    def status(self, inv: str) -> str:
        attempts = self.attempts(inv)
        return attempts[-1]["status"] if attempts else PENDING

    def validate(self, inv: str, attempt_id: str | None = None) -> dict[str, Any] | None:
        """Critic validation of a completed attempt (the latest by default), computed from the persisted
        assessment and package. Deterministic; it writes nothing."""

        completed = [a for a in self.attempts(inv) if a["status"] == COMPLETED and a.get("review")]
        attempt = next((a for a in completed if a["attempt_id"] == attempt_id), None) if attempt_id else (
            completed[-1] if completed else None)

        if attempt is None:
            return None

        return validate_review(self.assessment(inv)["assessment"], attempt["review"], package=self.package(inv),
                               attempt=attempt)

    def verified_package(self, inv: str) -> dict[str, Any]:
        """The persisted package, after checking it still matches its own hash and the assessment."""

        package = self.package(inv)
        record = self.assessment(inv)

        if package_sha256(package) != package.get("package_sha256"):
            raise ValueError(f"{inv}: package content does not match its recorded hash")

        if assessment_sha256(record["assessment"]) != record["assessment_sha256"]:
            raise ValueError(f"{inv}: assessment content does not match its recorded hash")

        if package["assessment_sha256"] != record["assessment_sha256"]:
            raise ValueError(f"{inv}: package was built from a different assessment")

        return package


# -- review run ---------------------------------------------------------------------


def _error_kind(exc: Exception) -> tuple[str, str]:
    """(status, kind) for a review-request exception."""

    name = type(exc).__name__
    status_code = getattr(exc, "status_code", None)
    text = str(exc)

    if "prefill_memory_exceeded" in text or "prefill memory guard" in text:
        return FAILED, "prefill_rejected"

    if name in ("APITimeoutError", "TimeoutError", "ReadTimeout"):
        return FAILED, "timeout"

    if name == "APIConnectionError":
        return UNAVAILABLE, "endpoint_unavailable"

    if status_code == 507:
        return UNAVAILABLE, "insufficient_memory"

    if status_code == 404:
        return UNAVAILABLE, "model_not_served"

    if status_code is not None:
        return FAILED, f"http_{status_code}"

    return FAILED, f"error:{name}"


class TerminalReviewer:
    """Prepares, runs and retries terminal reviews against one store."""

    def __init__(
        self,
        store: TerminalReviewStore,
        *,
        model: str | None = None,
        client: Any | None = None,
        residency: Any | None = None,
        max_tokens: int = 2000,
        timeout: float = 900.0,
        model_settings: Callable[[str], Any] | None = None,
    ) -> None:
        self.store = store
        self.model = model or os.environ.get("APTRACE_REVIEW_MODEL", DEFAULT_REVIEW_MODEL)
        self.model_source = "argument" if model else ("APTRACE_REVIEW_MODEL" if os.environ.get("APTRACE_REVIEW_MODEL") else "default")
        self._client = client
        self.residency = residency
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.model_settings = model_settings

    @property
    def client(self) -> Any:
        if self._client is None:
            from openai import OpenAI

            self._client = OpenAI(base_url=os.environ["OMLX_BASE_URL"], api_key=os.environ["OMLX_API_KEY"],
                                  max_retries=0, timeout=self.timeout)
        return self._client

    def generation(self) -> dict[str, Any]:
        return {"temperature": 0.0, "max_tokens": self.max_tokens}

    # -- lifecycle --------------------------------------------------------

    def prepare(self, assessment: Mapping[str, Any], links: Mapping[str, Any]) -> str:
        """Persist assessment and package (status pending). Needs no model."""

        inv = self.store.put_assessment(assessment, links)
        self.store.put_package(build_package(assessment, links=links))
        return inv

    def skip(self, inv: str, reason: str) -> dict[str, Any]:
        package = self.store.verified_package(inv)
        attempt = self._attempt(inv, package, retry_of=None)
        attempt.update(status=SKIPPED, ended_at=attempt["started_at"], error=None, policy=reason)
        self.store.put_attempt(attempt)
        return attempt

    def retry(self, inv: str, *, restore_model: str | None = None) -> dict[str, Any]:
        previous = self.store.attempts(inv)
        return self.run(inv, restore_model=restore_model, retry_of=previous[-1]["attempt_id"] if previous else None)

    def _attempt(self, inv: str, package: Mapping[str, Any], retry_of: str | None) -> dict[str, Any]:
        return {
            "version": ATTEMPT_VERSION,
            "attempt_id": new_id("RA"),
            # Order of attempts for this investigation; the latest decides the status.
            "sequence": len(self.store.attempts(inv)) + 1,
            "investigation_id": inv,
            "package_sha256": package["package_sha256"],
            "assessment_sha256": package["assessment_sha256"],
            "template_version": TEMPLATE_VERSION,
            "links": package["links"],
            "retry_of": retry_of,
            "started_at": _now(),
            "ended_at": None,
            "status": PENDING,
            "model": {
                "id": self.model,
                "source": self.model_source,
                "generation": self.generation(),
                "client_timeout_s": self.timeout,
                "omlx_settings": self.model_settings(self.model) if self.model_settings else None,
            },
            "residency": [],
            "requests": [],
            "raw_responses": [],
            "review": None,
            "error": None,
            "authority": AUTHORITY,
        }

    def _request(self, attempt: dict[str, Any], messages: list[dict[str, str]]) -> str:
        attempt["requests"].append({"messages_sha256": digest(messages), "prompt_chars": sum(len(m["content"]) for m in messages)})
        response = self.client.chat.completions.create(model=self.model, messages=messages, **self.generation())
        choices = getattr(response, "choices", None)

        if not choices:
            extra = getattr(response, "model_extra", None) or {}
            raise RuntimeError(f"review model returned no choices: {str(extra.get('error') or response)[:300]}")

        content = choices[0].message.content or ""
        usage = getattr(response, "usage", None)
        attempt["raw_responses"].append({
            "content": content,
            "served_model": getattr(response, "model", None),
            "finish_reason": getattr(choices[0], "finish_reason", None),
            "usage": usage.model_dump() if hasattr(usage, "model_dump") else None,
        })
        return content

    def run(self, inv: str, *, restore_model: str | None = None, retry_of: str | None = None) -> dict[str, Any]:
        """One review attempt from the persisted package; always persists an attempt record."""

        package = self.store.verified_package(inv)
        attempt = self._attempt(inv, package, retry_of)

        try:
            self._review(attempt, package)
        finally:
            attempt["ended_at"] = _now()

            if attempt["status"] == PENDING:  # an unexpected exception
                attempt["status"] = FAILED

            self.store.put_attempt(attempt)

        if attempt["status"] == COMPLETED:
            # Derived, deterministic and advisory; a validation error never changes the review status.
            try:
                validation = self.store.validate(inv, attempt["attempt_id"])
            except Exception as exc:  # noqa: BLE001
                validation = {"error": {"kind": type(exc).__name__, "detail": str(exc)[:800]}}

            self.store.put_validation(inv, attempt["attempt_id"], validation)

        if restore_model and self.residency is not None:
            record_id = f"{attempt['attempt_id']}-restore"

            try:
                record = self.residency.acquire(restore_model)
            except Exception as exc:  # noqa: BLE001 - recorded, never changes the review status
                record = getattr(exc, "record", {"error": {"kind": getattr(exc, "kind", type(exc).__name__), "detail": str(exc)}})

            self.store.put_residency(inv, record_id, record)
            attempt = dict(attempt, restore=record)

        return attempt

    def _review(self, attempt: dict[str, Any], package: Mapping[str, Any]) -> None:
        if self.residency is not None:
            try:
                attempt["residency"].append(self.residency.acquire(self.model))
            except Exception as exc:  # noqa: BLE001
                attempt["residency"].append(getattr(exc, "record", None))
                attempt.update(status=UNAVAILABLE, error={"stage": "residency", "kind": getattr(exc, "kind", type(exc).__name__),
                                                          "detail": str(exc)[:800]})
                return

            # Context window as served, for provenance.
            after = (attempt["residency"][-1] or {}).get("after") or {}
            attempt["model"]["served"] = (after.get("models") or {}).get(self.model)
            attempt["model"]["server_version"] = after.get("server_version")
        else:
            attempt["residency"].append({"managed": False, "note": "no residency manager configured"})

        try:
            messages = review_messages(package)

            try:
                content = self._request(attempt, messages)
                attempt["review"] = parse_review(content, package)
                attempt["status"] = COMPLETED
            except MalformedReview as first:
                # One bounded correction round; the invalid first response is kept, never ingested.
                attempt["corrections"] = [str(first)]
                corrected = self._request(attempt, messages + [
                    {"role": "assistant", "content": content},
                    {"role": "user", "content": f"Your response failed APTrace validation: {first}. Return the same "
                                                "review as one valid JSON object in the required format, nothing else."},
                ])

                try:
                    attempt["review"] = parse_review(corrected, package)
                    attempt["status"] = COMPLETED
                except MalformedReview as second:
                    attempt.update(status=FAILED, error={"stage": "parse", "kind": "malformed_response",
                                                         "detail": f"{first}; after correction: {second}"})
        except Exception as exc:  # noqa: BLE001 - every request failure becomes an explicit status
            status, kind = _error_kind(exc)
            attempt.update(status=status, error={"stage": "request", "kind": kind, "detail": str(exc)[:800]})
        finally:
            if self.residency is not None:
                try:
                    attempt["residency"].append(self.residency.release(self.model))
                except Exception as exc:  # noqa: BLE001 - recorded; does not change the review result
                    attempt["residency"].append(getattr(exc, "record", {"error": {"detail": str(exc)}}))
                    attempt["release_error"] = {"kind": getattr(exc, "kind", type(exc).__name__), "detail": str(exc)[:400]}


# -- reporting ----------------------------------------------------------------------


def review_summary(store: TerminalReviewStore, inv: str) -> dict[str, Any]:
    attempts = store.attempts(inv)
    latest = attempts[-1] if attempts else None
    return {
        "investigation_id": inv,
        "store": str(store.root / inv),
        "status": latest["status"] if latest else PENDING,
        "attempts": [{"attempt_id": a["attempt_id"], "status": a["status"], "error": a.get("error"),
                      "model": a["model"]["id"], "retry_of": a.get("retry_of")} for a in attempts],
        "latest": latest,
    }


def render_final_report(store: TerminalReviewStore, inv: str) -> list[str]:
    """The four-part final report; Gemma's criticism is never merged into the result."""

    record = store.assessment(inv)
    assessment = record["assessment"]
    summary = review_summary(store, inv)
    latest = summary["latest"]
    lines = ["DETERMINISTIC INVESTIGATION RESULT (APTrace evidence rules; no model)"]
    lines += [f"  {line}" for line in render_assessment(assessment)]
    lines += ["", "ADVERSARIAL CRITICISM (review model; advisory, not verification)"]
    review = latest.get("review") if latest else None

    if review is None:
        lines.append(f"  (none: review {summary['status']})")
    else:
        for kind, heading in (("demonstrated_contradiction", "demonstrated contradictions (cite package evidence)"),
                              ("hypothesis", "hypotheses (not demonstrated)"),
                              ("suggested_test", "suggested tests")):
            items = [f for f in review["findings"] if f["effective_kind"] == kind]
            lines.append(f"  {heading}: {len(items)}")

            for item in items:
                refs = ",".join(item["relations"] + item["evidence_ids"])
                lines.append(f"    [{item['category']}] {refs}: {item['statement']}")

                if item["test"]:
                    lines.append(f"        test: {item['test']}")

                for check in item["aptrace_checks"]:
                    lines.append(f"        aptrace check: {check}")

        for question in review["omitted_questions"]:
            lines.append(f"  omitted question: {question}")

        lines.append(f"  reviewer's view of stated confidence: {review['confidence']}")

    validation = store.validate(inv, latest["attempt_id"]) if review is not None else None
    lines += ["", "CRITIC VALIDATION (APTrace's deterministic checks of the criticism; not firmware verification)"]

    if validation is None:
        lines.append("  (none: no completed review)")
    else:
        lines += [f"  {line}" for line in render_validation(validation)]

    lines += ["", "UNRESOLVED EVIDENCE REQUIREMENTS"]
    lines += [f"  {line}" for line in unresolved_requirements(assessment)] or ["  (none recorded)"]

    if validation is not None and validation["followups"]:
        lines.append("  follow-up question proposals (from supported/unresolved criticism and continuity; not executed):")
        lines += [f"    {line}" for line in render_followups(validation)]

    lines += ["", "REVIEW AVAILABILITY"]
    lines.append(f"  status: {summary['status']} ({len(summary['attempts'])} attempt(s)); investigation {inv}")

    if latest:
        lines.append(f"  model: {latest['model']['id']} ({latest['model']['source']}); template {latest['template_version']}")

        if latest.get("error"):
            lines.append(f"  error: {latest['error']['stage']} {latest['error']['kind']}: {_clip(latest['error']['detail'], 300)}")

        if latest.get("policy"):
            lines.append(f"  skipped by policy: {latest['policy']}")

    if summary["status"] != COMPLETED:
        lines.append("  the review step is missing; the deterministic result above stands on its own evidence")

    lines.append(f"  {AUTHORITY}")
    return lines


__all__ = [
    "PACKAGE_VERSION", "TEMPLATE_VERSION", "ATTEMPT_VERSION", "DEFAULT_REVIEW_MODEL", "STATUSES", "CATEGORIES", "KINDS",
    "PENDING", "COMPLETED", "UNAVAILABLE", "FAILED", "SKIPPED", "AUTHORITY",
    "build_package", "package_sha256", "package_integrity", "investigation_id", "review_messages", "parse_review",
    "MalformedReview",
    "TerminalReviewStore", "TerminalReviewer", "review_summary", "render_final_report",
]
