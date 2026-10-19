"""
Performing Rigs: Critic Validation v1 against the saved Terminal Review v1
reviews of the remote-to-motor investigation.

Regression material (read-only; the store's file hashes are checked before
and after every validation here):

    research/runs/terminal-review-v1/reviews/TR-78cf8cd5aece72d3   focused run 1, Gemma review (false "unreachable" finding)
    research/runs/terminal-review-v1/reviews/TR-995b2d4e91725afe   F0 motion state + ISR STEP fixture, Gemma review
    research/runs/critic-validation-v1/                            the validation records generated from them

Both saved assessments are terminal-assessment-v1: their execution state is
recovered from APTrace's harness-assumption strings (disclosed fallback).
The fixture rebuilt today is v2 and carries structured state.

Nothing here calls a model, and nothing depends on Gemma's wording: findings
are selected by category and cited ids.

    agent/.venv/bin/python -m pytest cases/performing-rigs/test/test_critic_validation_regression.py
"""

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

from aptrace_agent.research import continuity
from aptrace_agent.research.critic import CONTRADICTED, SUPPORTED, UNGROUNDED, UNRESOLVED_FINDING, validate_review
from aptrace_agent.research.review import TerminalReviewStore, build_package, package_integrity, parse_review

CASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CASE / "scripts"))

from terminal_review_f0_isr import LINKS as F0_ISR_LINKS, f0_isr_assessment  # noqa: E402

STORE = CASE / "research" / "runs" / "terminal-review-v1" / "reviews"
SAVED = CASE / "research" / "runs" / "critic-validation-v1"
FOCUSED, F0_ISR = "TR-78cf8cd5aece72d3", "TR-995b2d4e91725afe"
SEED = "0x20000094"


def _store_digest():
    return {p.relative_to(STORE).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(STORE.rglob("*.json"))}


@pytest.fixture(scope="module")
def validations():
    if not (STORE / FOCUSED).is_dir() or not (STORE / F0_ISR).is_dir():
        pytest.skip("saved Terminal Review v1 store not present")

    before = _store_digest()
    store = TerminalReviewStore(STORE)
    result = {inv: store.validate(inv) for inv in (FOCUSED, F0_ISR)}
    assert _store_digest() == before  # validation reads the historical store and never writes it
    return result


def by(validation, category, *ids):
    """The finding of `category` citing all of `ids` (relations or evidence)."""

    return next(f for f in validation["findings"]
                if f["category"] == category and set(ids) <= set(f["target"]["relations"] + f["target"]["evidence"]))


# -- 1./2. grounding -----------------------------------------------------------------------------


def test_every_saved_finding_targets_package_relations_and_evidence(validations):
    for inv, validation in validations.items():
        package = TerminalReviewStore(STORE).package(inv)
        relations = {r["id"] for r in package["content"]["relations"]}
        evidence = {e["evidence_id"] for e in package["content"]["evidence"]}

        for item in validation["findings"]:
            assert item["classification"] != UNGROUNDED, (inv, item["index"])
            assert set(item["target"]["relations"]) <= relations and set(item["target"]["evidence"]) <= evidence
            assert item["target"]["rejected_citations"] == []


def test_a_fabricated_citation_in_the_f0_isr_package_is_not_accepted(validations):
    store = TerminalReviewStore(STORE)
    assessment, package = store.assessment(F0_ISR)["assessment"], store.package(F0_ISR)
    review = parse_review(json.dumps({"findings": [
        {"category": "unjustified_composition", "kind": "demonstrated_contradiction", "relations": ["R8"],
         "evidence_ids": ["E9"], "statement": "E9 shows the timer fired"},
        {"category": "unsupported_negative", "kind": "hypothesis", "relations": ["R6"], "evidence_ids": ["E2"],
         "quote": "APTrace states the TC0 IRQ is never delivered", "statement": "a negative from a direct call"},
    ]}), package)
    fabricated, quoted = validate_review(assessment, review, package=package)["findings"][:2]
    assert fabricated["classification"] == UNGROUNDED and fabricated["target"]["rejected_citations"] == ["R8", "E9"]
    assert quoted["target"]["quote"]["found"] is False and "quote" in quoted["target"]["rejected_citations"]
    # The record states R6 as UNRESOLVED with an incompleteness blocker: no negative was drawn.
    assert quoted["classification"] == CONTRADICTED


# -- 3. the false "not entered means unreachable" criticism ------------------------------------------------


def test_false_unreachable_criticism_is_contradicted_by_the_record(validations):
    finding = by(validations[FOCUSED], "unsupported_negative", "R2", "E4")
    assert finding["classification"] == CONTRADICTED
    records = finding["checks"][0]["records"]
    blocker = next(r for r in records if r["record"].startswith("relations.R2.blockers") and r["evidence_id"] == "E4")
    assert "not thereby unreachable" in blocker["text"]
    claim = next(r for r in records if r["record"].startswith("claims.session_claims"))
    assert "not thereby unreachable" in claim["text"] and claim["evidence_id"] == "E4"
    assert {"record": "relations.R2.level", "text": next(r["text"] for r in records if r["record"] == "relations.R2.level")} in records
    # Its suggested test (the inputs that take the branch toward FUN_00004d18) is not turned into a follow-up.
    assert not any(s.get("finding") == finding["index"] for q in validations[FOCUSED]["followups"] for s in q["sources"])


# -- 4. the missing timer-to-ISR connection stays a valid challenge -----------------------------------------


def test_missing_timer_to_isr_connection_is_retained(validations):
    validation = validations[F0_ISR]
    finding = by(validation, "scope_mismatch", "R2", "R5", "E1", "E2")
    assert finding["classification"] == SUPPORTED
    checks = {c["check"]: c for c in finding["checks"]}
    assert checks["connection"]["result"] == SUPPORTED
    cited = {r["record"] for r in checks["connection"]["records"]}
    assert {"relations.R7.level", "relations.R6.level", "composition.joins[R6->R5]"} <= cited
    assert checks["state_continuity"]["result"] == SUPPORTED
    # The finding also says APTrace joined the segments, which the record refutes; the gap is kept.
    assert finding["mischaracterizes_investigation"] is True

    interrupt = by(validation, "peripheral_timer_interrupt_assumption", "R6", "E2")
    assert interrupt["classification"] == SUPPORTED
    assert any("not IRQ delivery" in r.get("text", "") for c in interrupt["checks"] for r in c["records"])

    # The underlying firmware question is not decided: the relations keep their levels.
    assert {r["id"]: r["level"] for r in TerminalReviewStore(STORE).assessment(F0_ISR)["assessment"]["relations"]} == {
        "R2": "OBSERVED", "R3": "UNRESOLVED", "R7": "UNRESOLVED", "R4": "STATIC", "R6": "UNRESOLVED", "R5": "OBSERVED"}


def test_static_as_execution_and_overstated_confidence_are_contradicted(validations):
    validation = validations[F0_ISR]
    assert by(validation, "static_as_execution", "R4", "R6")["classification"] == CONTRADICTED
    assert validation["confidence"]["result"] == CONTRADICTED


# -- 5. independent seeding of 0x20000094 -------------------------------------------------------------------


def test_independent_seeding_is_a_continuity_concern_in_v1_and_v2(validations):
    saved = validations[F0_ISR]["continuity"]
    concern = next(c for c in saved["concerns"] if c["kind"] == continuity.INDEPENDENTLY_SUPPLIED)
    assert concern["segments"] == ["E1", "E2"] and concern["addresses"] == [{"addr": SEED, "len": 4}]
    assert concern["state"] == {"E1": "supplied", "E2": "supplied"} and concern["establishes_continuity"] is False
    assert validations[F0_ISR]["continuity_source"].startswith("recomputed from v1 scopes")
    # Gemma never raised it; APTrace reports it as its own.
    assert concern["id"] in {u["concern"] for u in saved["not_raised_by_reviewer"]}

    rebuilt = f0_isr_assessment()["composition"]["continuity"]
    kinds = {c["kind"]: c for c in rebuilt["concerns"]}
    assert kinds[continuity.INDEPENDENTLY_SUPPLIED]["addresses"] == [{"addr": SEED, "len": 4}]
    segments = {s["evidence_id"]: s for s in rebuilt["segments"]}
    assert segments["E1"]["source"] == "result.legs" and segments["E1"]["produced"] == []  # no write log
    assert {"0x200024cc", "0x20001b14"} <= set(segments["E1"]["end_state"]) and SEED not in segments["E1"]["end_state"]
    assert kinds[continuity.PRIOR_NOT_CARRIED]["state"] == {"E1": ["end_state"], "E2": "fresh"}


def test_focused_run_segments_are_one_scenario_with_unlocated_seeds(validations):
    flow = validations[FOCUSED]["continuity"]
    assert flow["concerns"] == []  # E3 and E4 replay vl-manual-f0e0 under one registry hash
    unknown = {u["evidence_id"]: u["detail"] for u in flow["unknown"]}
    assert "not located" in unknown["E3"] and "not located" in unknown["E4"]  # v1 text counts ranges only


# -- 6. missing evidence is not a contradiction ---------------------------------------------------------------


def test_every_contradiction_rests_on_a_positive_record(validations):
    for validation in validations.values():
        for item in validation["findings"]:
            if item["classification"] == CONTRADICTED:
                assert all(c["records"] for c in item["checks"] if c["result"] == CONTRADICTED)

        omitted = [f for f in validation["findings"] if f["source"] == "omitted_question"]
        assert omitted and all(f["classification"] == UNRESOLVED_FINDING for f in omitted)


# -- 7. bounded follow-up questions -----------------------------------------------------------------------------


def test_supported_and_unresolved_criticism_become_bounded_questions(validations):
    questions = {"->".join(q["challenged"]["relations"]): q for q in validations[F0_ISR]["followups"]}
    chain = questions["R2->R7->R4->R6->R5"]
    assert chain["kind"] == "connection" and chain["challenged"]["segments"] == ["E1", "E2"]
    assert {"aptrace_continuity": "C1"} in chain["sources"]
    assert any(SEED in c for c in chain["conditions"])
    assert any(op["availability"] == "capability_gap" and "IRQ delivery" in op["detail"] for op in chain["candidate_operations"])
    assert any("no peripheral or interrupt model" in item for item in chain["limitations"])
    assert {"R3", "R7", "R6"} <= set(questions)
    assert all(q["executable"] is False and q["status"] == "proposal" for q in validations[F0_ISR]["followups"])

    focused = {"->".join(q["challenged"]["relations"]): q for q in validations[FOCUSED]["followups"]}
    assert set(focused) == {"R2", "R3"}
    watch = next(op for op in focused["R3"]["candidate_operations"] if op["operation"] == "observed_call_arguments")
    assert watch["arguments"]["watch"] == ["0x20001b14"]
    effects = next(op for op in focused["R3"]["candidate_operations"] if op["operation"] == "analyze_function_effects")
    assert effects["availability"].startswith("attempted: E5")


# -- 8. no authority ----------------------------------------------------------------------------------------------


def test_saved_validation_records_reproduce_and_carry_no_authority(validations):
    for inv, validation in validations.items():
        saved = json.loads((SAVED / f"{inv}.validation.json").read_text())

        if saved["version"] != validation["version"]:
            pytest.skip("saved records are from another critic-validation version")

        assert saved == validation
        assert "changes no evidence" in validation["authority"]
        assert '"VERIFIED"' not in json.dumps(validation)


# -- Task 5: package integrity ------------------------------------------------------------------------------------


def test_saved_packages_kept_material_and_v1_reduction_would_have_dropped_the_seed(validations):
    store = TerminalReviewStore(STORE)

    for inv in (FOCUSED, F0_ISR):
        report = package_integrity(store.assessment(inv)["assessment"], store.package(inv))
        assert report["truncated"] == [] and report["missing_material"] == [f"continuity C1 (independently_supplied_state) "
                                                                            "is not stated in the package"] * (inv == F0_ISR)

    # The v1 rule "first 3 harness assumptions" drops E1's seed of 0x20000094 (its 4th assumption).
    assessment = store.assessment(F0_ISR)["assessment"]
    cut = copy.deepcopy(store.package(F0_ISR))
    cut["content"]["relations"][0]["scopes"][0]["harness_assumptions"] = \
        cut["content"]["relations"][0]["scopes"][0]["harness_assumptions"][:3]
    assert any(SEED in m for m in package_integrity(assessment, cut)["missing_material"])

    # The v2 package of the rebuilt fixture keeps it under every reduction.
    rebuilt = f0_isr_assessment()
    tight = build_package(rebuilt, links=F0_ISR_LINKS, max_chars=4000)
    assert tight["bounds"]["truncated"][-1] == "evidence.summary"
    assert package_integrity(rebuilt, tight)["material_complete"]
    scope = tight["content"]["relations"][0]["scopes"][0]
    assert any(SEED in a for a in scope["harness_assumptions"]) and {"addr": SEED, "len": 4} in scope["state"]["supplied"]


# -- the bounded live Gemma review under template v2 -------------------------------------------------------


LIVE = SAVED / "reviews"


def test_live_v2_review_is_grounded_and_its_validation_reproduces():
    store = TerminalReviewStore(LIVE)
    inv = next(iter(store.ids()), None)

    if inv is None:
        pytest.skip("no saved live critic-validation review")

    attempt = store.attempts(inv)[-1]
    assert attempt["template_version"] == "terminal-review-v2" and attempt["status"] == "completed"
    assert store.package(inv)["version"] == "terminal-review-package-v2"
    assert store.assessment(inv)["assessment"]["version"] == "terminal-assessment-v2"
    persisted = store.validation(inv, attempt["attempt_id"])

    if persisted["version"] != "critic-validation-v1":
        pytest.skip("saved validation is from another critic-validation version")

    assert persisted == store.validate(inv)
    reviewer_findings = [f for f in persisted["findings"] if f["source"] == "finding"]
    assert reviewer_findings and all(f["defect"]["source"] == "reviewer" for f in reviewer_findings)
    assert all(f["classification"] != UNGROUNDED and not f["target"]["rejected_citations"] for f in reviewer_findings)
    assert all(f["target"]["quote"]["found"] for f in reviewer_findings if f["target"]["quote"])
    # The reviewer was shown APTrace's continuity concerns; citing C1 repeats APTrace, it is not independent detection.
    assert "C1" in {c["id"] for c in store.package(inv)["content"]["composition"]["continuity"]["concerns"]}
