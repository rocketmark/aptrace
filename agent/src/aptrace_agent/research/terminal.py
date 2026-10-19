"""
Deterministic terminal assessment (terminal-assessment-v1).

Every focused (objective-bounded) research run ends with one assessment,
however it terminates: planner finish, step budget, stall, no relevant
operation, planner contract failure, or an exception in the loop. The
assessment is built from APTrace state only (the objective spec, the
objective-v1 report, recorded evidence, the trajectory, admission
decisions and session state). No model response is needed, and the same
inputs produce the same assessment and the same hash.

It reuses objective-v1's relation levels and blockers unchanged. It adds no
evidence grade, verdict or claim. In particular:

- **Joins.** Adjacent relations (one's target is the next one's source) are
  listed with the executions that established each side. A join is never
  validated here: separately established edges are reported as separately
  established, with the continuity question stated. This is the input a
  composition capability would need, not a composition.
- **Tensions.** A relation with both positive evidence and blockers is
  listed as a tension, never as a contradiction verdict. Scenario-scoped
  observations under different harness states are not contradictory.
- **Continuity (v2).** Each execution scope carries its normalized state
  (supplied, produced, carried, unknown), and the composition section
  reports where separately executed segments share state they never passed
  to each other (research/continuity.py). A concern never establishes
  continuity.

See docs/terminal-review.md.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from aptrace_agent.ledger.hashing import digest
from aptrace_agent.research import continuity
from aptrace_agent.research.objective import (
    OBSERVED,
    STATIC,
    SYMBOLIC,
    UNRESOLVED,
    ObjectiveSpec,
    failure_status,
)
from aptrace_agent.research.projection import summarize_observation


# v2 (Critic Validation v1): scopes carry normalized execution state and the
# composition section carries state continuity. v1 records stay valid.
ASSESSMENT_VERSION = "terminal-assessment-v2"

# Bounds that keep the assessment a reviewable size. The complete evidence
# stays in the run artifact and the ledger; the assessment carries hashes.
SUMMARY_CHARS = 700
MAX_ASSUMPTIONS = 12
ASSUMPTION_CHARS = 200

# stop_reason -> termination category.
TERMINATION_CATEGORIES = {
    "planner_finished": "completed",
    "step_budget_exhausted": "budget_exhausted",
    "objective_stalled": "stalled",
    "objective_no_relevant_operation": "no_relevant_operation",
    "planner_prefill_exhausted": "planner_failure",
    "planner_contract_exhausted": "planner_failure",
    "investigation_error": "error",
    "research_graph_exhausted": "exhausted",
    "discovery_exhausted": "exhausted",
    "discovery_finished": "completed",
}

# What each objective-v1 level means, restated so a reader (or reviewer)
# does not have to infer it. These are objective-v1's definitions.
LEVEL_MEANING = {
    UNRESOLVED: "no supporting evidence recorded",
    STATIC: "a Ghidra call-graph edge (heuristic function boundaries); static possibility, not execution",
    SYMBOLIC: "completed symbolic function effects show the call or access, under the recorded guard",
    OBSERVED: "concrete observation under one registered scenario and its harness assumptions; not natural execution",
}

FRAMEWORK_LIMITATIONS = (
    "Relation levels are per edge. APTrace did not compose relations into a path, and no composition was verified.",
    "A blocker (failure, timeout, bounded coverage, target not entered) is incompleteness, never evidence of absence.",
    "OBSERVED evidence is scoped to its scenario's harness assumptions; separately executed scenarios do not share state unless the evidence says so.",
    "STATIC evidence uses Ghidra's heuristic function boundaries and is not evidence of execution.",
    "Admitted claim proposals are PROPOSED; only APTrace deterministic verification changes claim state.",
)


def _clip(text: Any, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _observation_status(observation: Any) -> str:
    result = observation.result if isinstance(observation.result, dict) else {}
    failure = failure_status(result)

    if failure:
        return failure

    return str(result.get("status") or "ok")


def _scope(observation: Any) -> dict[str, Any] | None:
    """Execution scope of one concrete or symbolic result, or None for static facts."""

    result = observation.result if isinstance(observation.result, dict) else {}
    assumptions = result.get("harness_assumptions") or []
    coverage = result.get("coverage")
    scenario = observation.arguments.get("scenario") or result.get("scenario")

    if not (assumptions or coverage or scenario):
        return None

    config = result.get("scenario_config") if isinstance(result.get("scenario_config"), dict) else {}
    provenance = result.get("provenance") if isinstance(result.get("provenance"), dict) else {}
    run = result.get("run") if isinstance(result.get("run"), dict) else {}
    return {
        "evidence_id": observation.id,
        "tool": observation.tool,
        "scenario": scenario,
        "engine": provenance.get("engine"),
        "firmware_sha256": provenance.get("firmware_sha256"),
        "scenario_registry_sha256": provenance.get("scenario_registry_sha256") or config.get("registry_sha256"),
        "entry_conditions": config.get("entry_conditions"),
        "termination": config.get("termination"),
        "instructions_executed": run.get("instructions_executed"),
        "coverage": _clip(coverage, 400) if coverage else None,
        "harness_assumptions": [
            _clip(item.get("detail") if isinstance(item, dict) else item, ASSUMPTION_CHARS)
            for item in assumptions[:MAX_ASSUMPTIONS]
        ],
        "harness_assumptions_total": len(assumptions),
        "state": continuity.state_from_result(result),
    }


def _evidence_entry(observation: Any) -> dict[str, Any]:
    result = observation.result if isinstance(observation.result, dict) else {}
    provenance = result.get("provenance") if isinstance(result.get("provenance"), dict) else {}
    entry = {
        "evidence_id": observation.id,
        "tool": observation.tool,
        "arguments": dict(observation.arguments),
        "status": _observation_status(observation),
        "summary": _clip(summarize_observation(observation, limit=SUMMARY_CHARS), SUMMARY_CHARS),
        "result_sha256": digest(result),
        "analysis": provenance.get("analysis"),
        "analysis_version": provenance.get("analysis_version"),
    }

    if getattr(observation, "reused_from", None):
        entry["reused_from"] = observation.reused_from

    return entry


def _relation_status(level: str, blockers: Sequence[Any]) -> str:
    if level == OBSERVED:
        return "observed_within_scope"

    if level in (STATIC, SYMBOLIC):
        return "partial"

    return "blocked" if blockers else "unresolved"


def _joins(relations: Sequence[Mapping[str, Any]], scopes: Mapping[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Adjacent relation pairs; never validated, only described."""

    joins: list[dict[str, Any]] = []

    for first in relations:
        for second in relations:
            if first["id"] == second["id"] or first["target"] != second["source"]:
                continue

            def established(relation: Mapping[str, Any]) -> list[dict[str, Any]]:
                ids = list(dict.fromkeys(e["evidence_id"] for e in relation["evidence"] if e["level"] == relation["level"]))
                return [
                    {"evidence_id": i, "scenario": (scopes.get(i) or {}).get("scenario"),
                     "harness_assumptions_total": (scopes.get(i) or {}).get("harness_assumptions_total", 0)}
                    for i in ids
                ]

            left, right = established(first), established(second)
            shared = sorted({e["evidence_id"] for e in left} & {e["evidence_id"] for e in right})

            if first["level"] == UNRESOLVED or second["level"] == UNRESOLVED:
                reason = "at least one side has no supporting evidence"
            elif shared:
                reason = (f"both sides cite {', '.join(shared)}, but APTrace has not checked that the same execution "
                          "carried state across the join")
            else:
                reason = "the two sides were established by separate evidence; state continuity across the join is not established"

            joins.append({
                "from_relation": first["id"],
                "to_relation": second["id"],
                "shared_endpoint": first["target"],
                "from_level": first["level"],
                "to_level": second["level"],
                "from_evidence": left,
                "to_evidence": right,
                "continuity": "not validated",
                "reason": reason,
            })

    return joins


def _segments(relations: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Connected groups of relations that have any evidence, by shared endpoint.

    More than one segment means some established edges are connected to the
    rest by no recorded relation at all.
    """

    established = [r for r in relations if r["level"] != UNRESOLVED]
    groups: list[list[Mapping[str, Any]]] = []

    for relation in established:
        touching = [g for g in groups if any({relation["source"], relation["target"]} & {m["source"], m["target"]} for m in g)]
        merged = [relation] + [m for g in touching for m in g]
        groups = [g for g in groups if g not in touching] + [merged]

    order = {r["id"]: i for i, r in enumerate(relations)}
    segments = []

    for group in sorted(groups, key=lambda g: min(order[m["id"]] for m in g)):
        members = sorted(group, key=lambda m: order[m["id"]])
        segments.append({
            "relations": [m["id"] for m in members],
            "levels": {m["id"]: m["level"] for m in members},
            "evidence": sorted({e["evidence_id"] for m in members for e in m["evidence"] if e["level"] == m["level"]}),
            "scenarios": sorted({s["scenario"] for m in members for s in m["scopes"] if s.get("scenario")}),
        })

    return segments


def build_assessment(
    *,
    spec: ObjectiveSpec,
    report: Mapping[str, Any],
    observations: Sequence[Any],
    steps: Sequence[Any] = (),
    state: Any = None,
    claim_admission: Sequence[Any] = (),
    stop_reason: str,
    error: Mapping[str, str] | None = None,
    planner_model: str | None = None,
    firmware_key: str | None = None,
) -> dict[str, Any]:
    """The deterministic terminal assessment of one focused run."""

    by_id = {o.id: o for o in observations}
    scopes = {o.id: s for o in observations if (s := _scope(o)) is not None}
    relations = []

    for relation in report["relations"]:
        cited = list(dict.fromkeys([e["evidence_id"] for e in relation["evidence"]] + [b["evidence_id"] for b in relation["blockers"]]))
        relations.append({
            "id": relation["id"],
            "source": relation["source"],
            "target": relation["target"],
            "label": relation["label"],
            "level": relation["level"],
            "level_meaning": LEVEL_MEANING[relation["level"]],
            "status": _relation_status(relation["level"], relation["blockers"]),
            "evidence": list(relation["evidence"]),
            "blockers": list(relation["blockers"]),
            "evidence_needed": list(relation["missing"]),
            "scopes": [scopes[i] for i in cited if i in scopes],
        })

    tensions = [
        {"relation": r["id"], "level": r["level"],
         "positive": sorted({e["evidence_id"] for e in r["evidence"]}),
         "blockers": sorted({b["evidence_id"] for b in r["blockers"]}),
         "note": "positive evidence and blockers coexist; APTrace does not decide between them (not a contradiction verdict)"}
        for r in relations if r["evidence"] and r["blockers"]
    ]

    outcomes = {o["evidence_id"]: o for o in report.get("outcomes", []) if o.get("evidence_id")}
    operations = []

    for step in steps:
        number = getattr(step, "number", None)
        evidence_id = getattr(step, "evidence_id", None)
        observation = by_id.get(evidence_id) if evidence_id else None
        outcome = outcomes.get(evidence_id) if evidence_id else None
        operations.append({
            "step": number,
            "action": getattr(step, "action", None),
            "tool": observation.tool if observation is not None else None,
            "arguments": dict(observation.arguments) if observation is not None else {},
            "evidence_id": evidence_id,
            "status": _observation_status(observation) if observation is not None else None,
            "outcome": outcome["outcome"] if outcome else None,
            "note": _clip(outcome["note"], 300) if outcome else _clip(getattr(step, "reason", "") or "", 300),
            "reused_from": getattr(step, "reused_from", None),
        })

    failed = [
        {"evidence_id": o.id, "tool": o.tool, "arguments": dict(o.arguments), "status": failure_status(o.result)}
        for o in observations if isinstance(o.result, dict) and failure_status(o.result)
    ]

    blockers = [
        {"relation": r["id"], "evidence_id": b["evidence_id"], "detail": b["detail"]}
        for r in relations for b in r["blockers"]
    ]

    limitations = list(FRAMEWORK_LIMITATIONS)

    for r in relations:
        for item in r["evidence_needed"]:
            if "capability" in item and item not in limitations:
                limitations.append(item)

    questions, hypotheses, contradictions, session_claims = [], [], [], []

    if state is not None:
        questions = [
            {"question": q.question, "source": q.source, "evidence_ids": list(q.evidence_ids)}
            for q in state.open_questions if q.status == "OPEN"
        ]
        hypotheses = [
            {"statement": h.statement, "source": h.source, "evidence_ids": list(h.evidence_ids),
             "status": "hypothesis (untyped, at most PROBABLE)"}
            for h in state.hypotheses
        ]
        contradictions = [{"description": c.description, "evidence_ids": list(c.evidence_ids)} for c in state.contradictions]
        session_claims = [
            {"statement": c.statement, "grade": str(c.grade),
             "basis": c.basis, "evidence_ids": list(c.evidence_ids)}
            for c in state.claims
        ]

    proposals = []

    for decision in claim_admission:
        data = decision.model_dump(mode="json") if hasattr(decision, "model_dump") else dict(decision)
        proposals.append({
            "decision": data.get("decision"),
            "assertion": _clip(data.get("assertion") or data.get("raw"), 300),
            "grade": data.get("grade"),
            "claim_type": data.get("claim_type"),
            "evidence_ids": data.get("evidence_ids", []),
            "diagnostics": [_clip(d.get("detail") or d.get("code") or d, 200) for d in data.get("diagnostics", [])][:4],
        })

    category = TERMINATION_CATEGORIES.get(stop_reason, "other")
    answered = all(r["level"] == OBSERVED for r in relations)
    segments = _segments(relations)
    state_continuity = continuity.analyze(relations, list(scopes.values()))
    disconnected = (
        f"{len(segments)} separately established segments; no recorded relation connects them, so nothing "
        "here relates one segment's execution to another's"
        if len(segments) > 1 else None
    )

    return {
        "version": ASSESSMENT_VERSION,
        "objective": {
            "question": spec.question,
            "constraints": list(spec.constraints),
            "firmware": spec.firmware,
            "relations": [r.model_dump() for r in spec.relations],
            "terms": list(spec.terms),
            "declared_scenarios": list(spec.scenarios),
            "allow_broad_discovery": spec.allow_broad_discovery,
        },
        "termination": {
            "stop_reason": stop_reason,
            "category": category,
            "explanation": report.get("explanation", stop_reason),
            "error": dict(error) if error else None,
            "budget": dict(report.get("budget", {})),
            "every_relation_observed": answered,
            "analysis_failures": len(failed),
        },
        "planner": {"model": planner_model},
        "firmware_key": firmware_key,
        "relations": relations,
        "composition": {
            "attempted": False,
            "statement": report.get("composition", "not attempted"),
            "joins": _joins(relations, scopes),
            "segments": segments,
            "disconnected": disconnected,
            "continuity": state_continuity,
        },
        "tensions": tensions,
        "scopes": list(scopes.values()),
        "operations": operations,
        "evidence": [_evidence_entry(o) for o in observations],
        "failed_operations": failed,
        "rejected_operations": list(report.get("rejections", [])),
        "blockers": blockers,
        "limitations": limitations,
        "unresolved_relations": list(report.get("unresolved_relations", [])),
        "unresolved_questions": questions,
        "hypotheses": hypotheses,
        "contradictions": contradictions,
        "claims": {
            "session_claims": session_claims,
            "proposals": proposals,
            "admitted": sum(1 for p in proposals if p["decision"] in ("admitted", "duplicate")),
            "note": "APTrace admission decided these; admitted proposals are PROPOSED claim versions, not verified",
        },
    }


def assessment_from_artifact(
    payload: Mapping[str, Any],
    *,
    spec: ObjectiveSpec | None = None,
    function_exists: Any = None,
    firmware_key: str | None = None,
) -> dict[str, Any]:
    """Assessment of a saved `research --output` artifact, with no rerun.

    A focused artifact's own objective report is used as recorded. An older
    artifact without one needs `spec`; its report is then recomputed from the
    saved evidence by the objective-v1 tracker (deterministic). The saved
    trajectory and state are used as recorded.
    """

    from types import SimpleNamespace

    from aptrace_agent.research.objective import ObjectiveTracker
    from aptrace_agent.research.state import ResearchState
    from aptrace_agent.schemas import EvidenceObservation

    observations = [EvidenceObservation.model_validate(item) for item in payload.get("evidence", [])]
    stop_reason = str(payload.get("stop_reason") or "unknown")
    spec = spec or (ObjectiveSpec.model_validate(payload["objective_spec"]) if payload.get("objective_spec") else None)

    if spec is None:
        raise ValueError("artifact has no objective_spec: pass the objective spec it was run with")

    report = payload.get("objective_report")

    if not report:
        tracker = ObjectiveTracker(spec=spec, function_exists=function_exists, firmware_key=firmware_key or spec.firmware)
        steps_used = len([s for s in payload.get("trajectory", []) if s.get("evidence_id")])
        report = tracker.report(observations, stop_reason=stop_reason, steps_used=steps_used, max_steps=steps_used)

    steps = [SimpleNamespace(**{k: s.get(k) for k in ("number", "action", "lead_id", "evidence_id", "reason", "reused_from")})
             for s in payload.get("trajectory", [])]
    state = ResearchState.model_validate(payload["state"]) if payload.get("state") else None
    return build_assessment(
        spec=spec, report=report, observations=observations, steps=steps, state=state,
        claim_admission=payload.get("claim_admission", ()), stop_reason=stop_reason,
        planner_model=(payload.get("models") or {}).get("planner"), firmware_key=firmware_key or spec.firmware,
    )


def assessment_sha256(assessment: Mapping[str, Any]) -> str:
    return digest(dict(assessment))


def render_assessment(assessment: Mapping[str, Any]) -> list[str]:
    """Human-readable deterministic result (CLI and final report)."""

    termination = assessment["termination"]
    lines = [
        f"termination: {termination['category']} ({termination['stop_reason']}: {termination['explanation']})",
    ]

    if termination.get("error"):
        lines.append(f"  error: {termination['error'].get('type')}: {termination['error'].get('message')}")

    for relation in assessment["relations"]:
        lines.append(f"{relation['id']} {relation['source']} -> {relation['target']}: {relation['level']} [{relation['status']}]")
        cited = ",".join(dict.fromkeys(e["evidence_id"] for e in relation["evidence"]))

        if cited:
            lines.append(f"    evidence {cited}: {relation['level_meaning']}")

        for scope in relation["scopes"]:
            if scope.get("scenario"):
                lines.append(f"    scope {scope['evidence_id']}: scenario {scope['scenario']}, "
                             f"{scope['harness_assumptions_total']} harness assumption(s)")

        for blocker in relation["blockers"][-2:]:
            lines.append(f"    blocker {blocker['evidence_id']}: {blocker['detail']}")

    for join in assessment["composition"]["joins"]:
        lines.append(f"join {join['from_relation']}->{join['to_relation']} at {join['shared_endpoint']}: "
                     f"continuity {join['continuity']} ({join['reason']})")

    if assessment["composition"].get("disconnected"):
        lines.append(f"segments: {assessment['composition']['disconnected']}: "
                     + "; ".join("+".join(s["relations"]) for s in assessment["composition"]["segments"]))

    for concern in (assessment["composition"].get("continuity") or {}).get("concerns", []):
        lines.append(f"continuity {concern['id']} {concern['kind']}: {concern['statement']}")

    for item in assessment["failed_operations"]:
        lines.append(f"failed {item['evidence_id']} {item['tool']}: {item['status']}")

    for item in assessment["rejected_operations"]:
        lines.append(f"rejected {item['action']} {item['target']}: {_clip(item['reason'], 140)}")

    claims = assessment["claims"]
    lines.append(f"claim proposals: {len(claims['proposals'])}, admitted {claims['admitted']} (PROPOSED, not verified)")
    lines.append(f"composition: {assessment['composition']['statement']}")
    return lines


def unresolved_requirements(assessment: Mapping[str, Any]) -> list[str]:
    """What must be established before stronger conclusions: deterministic, from the assessment."""

    lines = []

    for relation in assessment["relations"]:
        if relation["level"] == OBSERVED:
            continue

        for item in relation["evidence_needed"] or ["no stronger evidence recorded"]:
            lines.append(f"{relation['id']} ({relation['level']}): {item}")

    for join in assessment["composition"]["joins"]:
        lines.append(f"join {join['from_relation']}->{join['to_relation']}: {join['reason']}; needs an execution or "
                     "composition capability that carries state across it")

    if assessment["composition"].get("disconnected"):
        lines.append(f"segments {' | '.join('+'.join(s['relations']) for s in assessment['composition']['segments'])}: "
                     "no recorded relation connects them; the intermediate relations need evidence")

    for concern in (assessment["composition"].get("continuity") or {}).get("concerns", []):
        lines.append(f"continuity {concern['id']} ({'/'.join(concern['segments'])}): {concern['requirement']}")

    return lines


__all__ = [
    "ASSESSMENT_VERSION", "TERMINATION_CATEGORIES", "LEVEL_MEANING", "build_assessment", "assessment_from_artifact",
    "assessment_sha256",
    "render_assessment", "unresolved_requirements",
]
