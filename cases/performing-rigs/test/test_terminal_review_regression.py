"""
Performing Rigs: Terminal Review v1 against the remote-to-motor runs.

Regression material (read-only; hashes checked below):

    research/runs/agent/remote-to-motor-2026-10-17.json            original drift run
    research/runs/agent/remote-to-motor-focused-2026-10-19.json    original focused run (timeout, vl-ampersand)
    research/runs/agent/objective-bounded-v1/live-*-2026-10-19.json objective-v1 live runs
    research/ledger/audits/A-20261019T133615-906232.json           the HTTP 507 diagnostic audit

Nothing here calls a model. Review responses are scripted; the saved live
review (research/runs/terminal-review-v1/) is checked mechanically, never
for wording.

Run with the agent environment (the replay needs the gitignored Ghidra cache):

    agent/.venv/bin/python -m pytest cases/performing-rigs/test/test_terminal_review_regression.py
"""

import hashlib
import json
import sys
from pathlib import Path

import pytest

from aptrace_agent.research.objective import OBSERVED, STATIC, UNRESOLVED, ObjectiveSpec
from aptrace_agent.research.review import COMPLETED, TerminalReviewer, TerminalReviewStore, build_package
from aptrace_agent.research.terminal import assessment_from_artifact, assessment_sha256

from test_objective_bounded_regression import DRIFT_RUN, FOCUSED_RUN, OBJECTIVES, RUNS, build, lead_to

CASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CASE / "scripts"))

from terminal_review_f0_isr import LINKS as F0_ISR_LINKS, f0_isr_assessment  # noqa: E402

LIVE_FOCUSED = RUNS / "objective-bounded-v1" / "live-focused-2026-10-19.json"
LIVE_DRIFT = RUNS / "objective-bounded-v1" / "live-drift-2026-10-19.json"
AUDIT_507 = CASE / "research" / "ledger" / "audits" / "A-20261019T133615-906232.json"
LIVE_REVIEWS = CASE / "research" / "runs" / "terminal-review-v1" / "reviews"
# SHA-256 as recorded by the causal graph (originals, audit) and at commit b9b0f5a (live runs).
DIGESTS = {
    DRIFT_RUN: "c1b35f96ed177d595b3cce82125977e0059a6dad58cfec64931dd0f058ab815d",
    FOCUSED_RUN: "9ddc76e2f61d0fcb40c34aab17a6e064d8f87bb1e60c407b4138bd4fec2da0f1",
    LIVE_FOCUSED: "f819040c00f6545124c4cf2738f33324b7df60b82973bb7da80e7aea13ccf954",
    LIVE_DRIFT: "684a12b952982c35b82ac9847e7538e8e0e62a56f388debf7b6248f258d3babf",
    AUDIT_507: "ac8ff6aeee851050ae427ab2f9db775ef62d108b0b1133b96972216d04d4f3ff",
}

REVIEW = {"findings": [{"category": "unjustified_composition", "kind": "suggested_test", "relations": ["R1", "R2"],
                        "evidence_ids": [], "statement": "scripted", "test": "scripted"}],
          "omitted_questions": [], "confidence": "cannot_judge", "summary": "scripted"}


class Client:
    def __init__(self):
        from types import SimpleNamespace

        self.chat = SimpleNamespace(completions=self)
        self.ns = SimpleNamespace

    def create(self, **kwargs):
        message = self.ns(content=json.dumps(REVIEW))
        return self.ns(choices=[self.ns(message=message, finish_reason="stop")], model=kwargs["model"], usage=None)


@pytest.fixture(scope="module")
def ghidra():
    from aptrace_agent.ghidra_index import GhidraCacheStale, autopilot_ghidra_index

    try:
        return autopilot_ghidra_index()
    except (GhidraCacheStale, FileNotFoundError, SystemExit) as exc:
        pytest.skip(f"AutoPilot Ghidra cache unavailable: {exc}")


def spec(name):
    return ObjectiveSpec.model_validate_json((OBJECTIVES / name).read_text())


# -- 1./2./3. the original focused run's choices, replayed ----------------------------------------


def test_replayed_focused_run_assesses_and_is_review_eligible_without_case_evidence(ghidra, tmp_path):
    holder = {}
    decisions = [
        ("analyze_function_effects", {"function": "FUN_00005448"}),
        ("analyze_function_effects", {"function": "FUN_00005448"}),
        ("observe_call_arguments", {"function": "FUN_00005448", "scenario": "vl-ampersand"}),
        ("observe_call_arguments", {"function": "FUN_00005448", "scenario": "vl-manual-f0e0"}),
        lambda tools: lead_to(holder["session"], "FUN_00004d18")(tools),
    ]
    _, controller, session, _, _ = build(ghidra, "remote-to-motor-focused-2026-10-19.objective.json", decisions,
                                         max_steps=4, seed="FUN_00005448")
    holder["session"] = session
    result = controller.run(session)
    assessment = result.terminal_assessment

    # The original run never reached Gemma: no non-discovery case search.
    assert not any(o.tool == "search_case_evidence" for o in session.ledger.all()) and result.reconciled is False
    assert assessment["termination"]["category"] == "stalled"
    assert {r["id"]: r["level"] for r in assessment["relations"]} == {"R1": STATIC, "R2": STATIC, "R3": UNRESOLVED}
    timeout = next(f for f in assessment["failed_operations"] if f["tool"] == "function_effects")
    assert timeout["status"] == "bounded: timeout 300s"
    assert any(r["action"] == "observe_call_arguments" and "vl-ampersand" in r["target"] for r in assessment["rejected_operations"])
    assert assessment["claims"]["proposals"] == []  # no admissible claims, still reviewable

    rv = TerminalReviewer(TerminalReviewStore(tmp_path), model="review-model", client=Client())
    inv = rv.prepare(assessment, {"artifact": None})
    assert rv.run(inv)["status"] == COMPLETED


def test_replayed_drift_run_assessment_keeps_cross_image_and_path_gaps(ghidra):
    decisions = [("search_case_evidence", {"query": "mando868 firmware firmware pin function map"}),
                 ("analyze_peripheral", {"peripheral": "PORT"})]
    _, controller, session, _, _ = build(ghidra, "remote-to-motor-2026-10-17.objective.json", decisions, max_steps=8)
    assessment = controller.run(session).terminal_assessment
    r0 = next(r for r in assessment["relations"] if r["id"] == "R0")
    assert r0["source"] == "mando868:0x0000be94" and any("multi-image" in m for m in r0["evidence_needed"])
    assert any("multi-image" in item for item in assessment["limitations"])
    assert {r["action"] for r in assessment["rejected_operations"]} >= {"search_case_evidence", "analyze_peripheral"}


# -- saved runs, assessed without rerunning anything ----------------------------------------------------


def test_saved_live_runs_assess_from_the_artifact_alone():
    for path in (LIVE_FOCUSED, LIVE_DRIFT):
        payload = json.loads(path.read_text())
        assessment = assessment_from_artifact(payload)
        assert [r["level"] for r in assessment["relations"]] == [r["level"] for r in payload["objective_report"]["relations"]]
        assert assessment_sha256(assessment) == assessment_sha256(assessment_from_artifact(payload))

    focused = assessment_from_artifact(json.loads(LIVE_FOCUSED.read_text()))
    r1 = next(r for r in focused["relations"] if r["id"] == "R1")
    assert r1["level"] == OBSERVED and r1["scopes"][0]["scenario"] == "vl-manual-f0e0"
    assert r1["scopes"][0]["harness_assumptions_total"] == 5
    join = next(j for j in focused["composition"]["joins"] if (j["from_relation"], j["to_relation"]) == ("R1", "R2"))
    assert join["continuity"] == "not validated"


def test_original_artifacts_assess_with_the_recomputed_objective_report(ghidra):
    exists = lambda name: _is_function(ghidra, name)
    drift = assessment_from_artifact(json.loads(DRIFT_RUN.read_text()), spec=spec("remote-to-motor-2026-10-17.objective.json"),
                                     function_exists=exists)
    assert all(r["level"] == UNRESOLVED for r in drift["relations"])  # as the objective-v1 comparison recorded

    focused = assessment_from_artifact(json.loads(FOCUSED_RUN.read_text()),
                                       spec=spec("remote-to-motor-focused-2026-10-19.objective.json"), function_exists=exists)
    assert {r["id"]: r["level"] for r in focused["relations"]} == {"R1": STATIC, "R2": STATIC, "R3": UNRESOLVED}
    assert {f["status"] for f in focused["failed_operations"]} >= {"bounded: timeout 300s"}


def _is_function(ghidra, name):
    try:
        ghidra.function_facts(name)
        return True
    except (KeyError, ValueError):
        return False


# -- 5. the F0 motion-state and ISR STEP package ----------------------------------------------------


def test_f0_isr_package_shows_two_unconnected_concrete_segments():
    assessment = f0_isr_assessment()
    package = build_package(assessment, links=F0_ISR_LINKS)
    content = package["content"]
    relations = {r["id"]: r for r in content["relations"]}

    assert relations["R2"]["level"] == OBSERVED and relations["R5"]["level"] == OBSERVED
    f0, isr = relations["R2"]["scopes"][0], relations["R5"]["scopes"][0]
    assert (f0["scenario"], isr["scenario"]) == ("rx-f0-direct-seed", "tc0-isr-direct-call")
    # Both executions seed the same word independently: a continuity question a reviewer must see.
    assert any("0x20000094" in a for a in f0["harness_assumptions"]) and any("0x20000094" in a for a in isr["harness_assumptions"])
    assert any("not IRQ delivery" in a or "Direct AAPCS handler call" in a for a in isr["harness_assumptions"])

    segments = [s["relations"] for s in content["composition"]["segments"]]
    assert ["R2"] in segments and ["R5"] in segments
    assert "separately established segments" in content["composition"]["disconnected"]
    assert {relations[r]["level"] for r in ("R3", "R7", "R6")} == {UNRESOLVED}
    assert package["bounds"]["within_bound"]
    assert assessment_sha256(assessment) == assessment_sha256(f0_isr_assessment())


def requests_connection_validation(review) -> bool:
    """Mechanical check of acceptance test 5, independent of wording: some finding cites both sides of
    the gap (the F0 motion segment R2/E1 and the ISR STEP segment R5/E2, or the IRQ-delivery relation R6
    between them) and proposes a test."""

    f0, isr = {"R2", "E1"}, {"R5", "E2", "R6"}

    for finding in review["findings"]:
        cited = set(finding["relations"]) | set(finding["evidence_ids"])

        if cited & f0 and cited & isr and finding.get("test"):
            return True

    return False


def test_saved_live_f0_isr_review_requests_validation_of_the_connection():
    store = TerminalReviewStore(LIVE_REVIEWS)
    inv = next((i for i in store.ids() if store.assessment(i)["links"].get("fixture")), None)

    if inv is None:
        pytest.skip("no saved live F0/ISR review")

    attempt = next(a for a in reversed(store.attempts(inv)) if a["status"] == COMPLETED)
    store.verified_package(inv)
    assert attempt["package_sha256"] == store.package(inv)["package_sha256"]
    assert requests_connection_validation(attempt["review"])


# -- immutability ----------------------------------------------------------------------------------


def test_regression_references_are_unchanged():
    assert {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in DIGESTS} == DIGESTS
    audit = json.loads(AUDIT_507.read_text())
    assert "507" in audit["steps"][0]["error"] and audit["verdict"] == "UNRESOLVED"
