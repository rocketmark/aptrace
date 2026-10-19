"""
Critic Validation v1 (research/critic.py, research/continuity.py and the
review package/template v2 in research/review.py) with synthetic firmware
identities and scripted reviews. No live model and no case data; the
Performing Rigs regression is
cases/performing-rigs/test/test_critic_validation_regression.py.

Assertions are about classifications, grounding, the records cited, the
continuity concerns and the follow-up structure, never about model wording.
"""

import copy
import json
import sys

import pytest

from aptrace_agent import cli
from aptrace_agent.research import continuity
from aptrace_agent.research.critic import (
    CONTRADICTED,
    SUPPORTED,
    UNGROUNDED,
    UNRESOLVED_FINDING,
    validate_review,
)
from aptrace_agent.research.objective import OBSERVED, STATIC, UNRESOLVED
from aptrace_agent.research.review import (
    COMPLETED,
    PACKAGE_VERSION,
    TEMPLATE_VERSION,
    TerminalReviewer,
    TerminalReviewStore,
    build_package,
    package_integrity,
    parse_review,
    review_messages,
)
from aptrace_agent.research.terminal import ASSESSMENT_VERSION, assessment_sha256
from aptrace_agent.schemas import EvidenceObservation

from test_objective_bounded import facts, spec
from test_terminal_review import TIMEOUT, LINKS, FakeOmlx, ReviewClient, assessment_for, focused_run, reviewer

RELATIONS = [
    {"id": "R1", "source": "FUN_00001000", "target": "FUN_00002000", "label": "dispatch reaches handler"},
    {"id": "R2", "source": "FUN_00002000", "target": "FUN_00004000", "label": "handler reaches rate setup"},
    {"id": "R4", "source": "FUN_00004000", "target": "FUN_00005000", "label": "rate setup reaches output"},
    {"id": "R3", "source": "FUN_00002000", "target": "0x20000100", "label": "handler sets busy flag"},
]
SHARED = "0x20000200"


def segment(eid, function, caller, scenario, *, seeds=(), entered=True, final=None, carried=None, registry="reg-1",
            assumptions=("fresh state",)):
    result = {
        "status": "ok", "observed_entries": 1 if entered else 0,
        "call_sites": [{"caller": caller, "status": "OBSERVED"}] if entered else [],
        "harness_assumptions": [{"detail": a} for a in assumptions],
        "coverage": f"observed contexts only: scenario {scenario}",
        "scenario_config": {"registry_sha256": registry},
        "run": {"instructions_executed": 100},
        "legs": [{"leg": 0, "entry": "0x00001000", "fresh": carried is None,
                  "seeds": [{"addr": a, "len": n, "tag": "seed"} for a, n in seeds], "reg_seed": [["r0", "0x1"]],
                  "forced": {}, "stub_calls": []}],
        "provenance": {"analysis": "observed_call_arguments", "analysis_version": 2, "engine": "concrete"},
    }

    if final is not None:
        result["final_memory"] = final

    if carried is not None:
        result["carried_from"] = carried

    return EvidenceObservation(id=eid, tool="observed_call_arguments", arguments={"function": function, "scenario": scenario},
                               result=result)


def chain(**overrides):
    """R1 OBSERVED (E1, seg-a), R2 STATIC (E0) with an unentered blocker (E3), R4 OBSERVED (E2, seg-b), R3 UNRESOLVED (E5)."""

    observations = [
        EvidenceObservation(id="E0", tool="function_facts", arguments={"function": "FUN_00002000"},
                            result={"name": "FUN_00002000", "callers": [{"function": "FUN_00001000", "address": "0x0"}],
                                    "callees": [{"function": "FUN_00004000", "address": "0x0"}]}),
        overrides.get("E1") or segment("E1", "FUN_00002000", "FUN_00001000", "seg-a", seeds=[(SHARED, 4), ("0x20000400", 8)],
                                       final={"0x20000300": "01", SHARED: "02000000"}),
        overrides.get("E2") or segment("E2", "FUN_00005000", "FUN_00004000", "seg-b", seeds=[(SHARED, 4)]),
        segment("E3", "FUN_00004000", "FUN_00002000", "seg-a", entered=False, seeds=[(SHARED, 4)]),
        EvidenceObservation(id="E5", tool="function_effects", arguments={"function": "FUN_00002000"}, result=dict(TIMEOUT)),
    ]
    return assessment_for(spec(relations=RELATIONS), observations)


def finding(category, relations=(), evidence=(), **extra):
    return {"category": category, "kind": "hypothesis", "relations": list(relations), "evidence_ids": list(evidence),
            "statement": f"scripted {category}", "test": "scripted test", **extra}


def validate(assessment, *findings, confidence="cannot_judge", omitted=()):
    package = build_package(assessment, links=LINKS)
    content = json.dumps({"findings": list(findings), "omitted_questions": list(omitted), "confidence": confidence,
                          "summary": "s"})
    review = parse_review(content, package)
    return validate_review(assessment, review, package=package), package


def check(result, name):
    return next(c for c in result["checks"] if c["check"].startswith(name))


# -- the assessment v2 record --------------------------------------------------------------


def test_assessment_records_execution_state_and_continuity():
    assessment = chain()
    assert assessment["version"] == ASSESSMENT_VERSION == "terminal-assessment-v2"
    assert {r["id"]: r["level"] for r in assessment["relations"]} == {"R1": OBSERVED, "R2": STATIC, "R4": OBSERVED, "R3": UNRESOLVED}

    states = {s["evidence_id"]: s["state"] for s in assessment["scopes"]}
    assert states["E1"]["initial"] == "fresh" and states["E1"]["legs"][0]["supplied"][0] == {"addr": SHARED, "len": 4}
    assert states["E1"]["produced"] == [] and states["E1"]["produced_recorded"] is False  # a snapshot is not a write
    assert states["E5"] is None if "E5" in states else True

    flow = assessment["composition"]["continuity"]
    segments = {s["evidence_id"]: s for s in flow["segments"]}
    assert set(segments) == {"E1", "E2", "E3"}  # E0 (static) and E5 (symbolic) carry no execution state
    assert segments["E1"]["end_state"] == ["0x20000300"]  # the seeded word is supplied, not end state
    kinds = {(c["kind"], tuple(c["segments"])) for c in flow["concerns"]}
    assert (continuity.INDEPENDENTLY_SUPPLIED, ("E1", "E2")) in kinds
    assert (continuity.PRIOR_NOT_CARRIED, ("E1", "E2")) in kinds
    assert all(c["establishes_continuity"] is False for c in flow["concerns"])
    # E1 and E3 replay one registered scenario: not a continuity concern.
    assert {"segments": ["E1", "E3"], "relation": continuity.SAME_SCENARIO} in flow["pairs"]
    assert not any(set(c["segments"]) == {"E1", "E3"} for c in flow["concerns"])
    assert assessment_sha256(assessment) == assessment_sha256(chain())


def test_continuity_classifies_supplied_produced_carried_and_unknown():
    produced = segment("E1", "FUN_00002000", "FUN_00001000", "seg-a", seeds=[("0x20000400", 4)])
    produced.result["ram_log"] = [{"direction": "write", "address": SHARED, "value": "0x2"}]
    over = chain(E1=produced)["composition"]["continuity"]
    concern = next(c for c in over["concerns"] if c["kind"] == continuity.SUPPLIED_OVER_PRIOR)
    assert concern["state"] == {"E1": ["produced"], "E2": "supplied"} and concern["addresses"][0]["addr"] == SHARED
    # E1 no longer seeds the word, so only E3 (which does) shares it with E2.
    assert {tuple(c["segments"]) for c in over["concerns"] if c["kind"] == continuity.INDEPENDENTLY_SUPPLIED} == {("E3", "E2")}

    carried = segment("E2", "FUN_00005000", "FUN_00004000", "seg-b", seeds=[(SHARED, 4)], carried=["E1"])
    flow = chain(E2=carried)["composition"]["continuity"]
    assert {"segments": ["E1", "E2"], "relation": continuity.CARRIED} in flow["pairs"]
    assert not any(set(c["segments"]) == {"E1", "E2"} for c in flow["concerns"])

    # A terminal-assessment-v1 scope keeps only text: located seeds are parsed, counted ones are unknown.
    v1 = {"evidence_id": "E9", "scenario": "s", "instructions_executed": 10, "harness_assumptions_total": 3,
          "harness_assumptions": ["fresh machine state at entry 0x1", f"seeded 4 byte(s) at {SHARED} (value is a harness input)",
                                  "entry 0x1 (fresh state); 2 seeded range(s), 1 register seed(s), 0 stub(s)"]}
    state = continuity.segment_state(v1)
    assert state["source"] == "harness_assumption_text" and state["supplied"] == [{"addr": SHARED, "len": 4}]
    assert state["supplied_unidentified"] == 1 and state["initial"] == "fresh"


# -- grounding -------------------------------------------------------------------------------


def test_fabricated_citations_are_rejected_and_targetless_findings_are_ungrounded():
    validation, _ = validate(
        chain(),
        finding("unsupported_relationship", ["R9"], ["E77"]),
        finding("unsupported_relationship", ["R3", "R9"], ["E5", "E77"]),
        finding("unsupported_relationship"),
        finding("not_a_category", ["R3"]),
        finding("unsupported_negative", ["R2"], ["E3"], quote="APTrace concluded FUN_00004000 is unreachable"),
    )
    fabricated, mixed, empty, unknown, quoted = validation["findings"][:5]

    assert fabricated["classification"] == UNGROUNDED and fabricated["target"]["rejected_citations"] == ["R9", "E77"]
    assert mixed["target"]["relations"] == ["R3"] and mixed["target"]["evidence"] == ["E5"]
    assert mixed["target"]["rejected_citations"] == ["R9", "E77"]
    assert not any("E77" in json.dumps(c["records"]) for c in mixed["checks"])  # never used as support
    assert empty["classification"] == UNGROUNDED and unknown["classification"] == UNGROUNDED
    # A quote absent from the package is a rejected citation; the finding is still checked on the record.
    assert quoted["target"]["quote"]["found"] is False and "quote" in quoted["target"]["rejected_citations"]
    assert quoted["classification"] == CONTRADICTED


def test_parse_review_keeps_grounding_fields_and_flags_unknown_targets():
    package = build_package(chain(), links=LINKS)
    item = finding("unjustified_composition", ["R1"], ["E1"], targets=["R1->R2", "S9", "C1"], defect="nonsense",
                   checkable=True, resolving_evidence="one execution", quote="continuity not validated")
    parsed = parse_review(json.dumps({"findings": [item]}), package)["findings"][0]
    assert parsed["targets"] == ["R1->R2", "S9", "C1"] and parsed["checkable"] is True
    assert parsed["resolving_evidence"] == "one execution" and parsed["quote"] == "continuity not validated"
    assert any("targets not in the package: S9" in c for c in parsed["aptrace_checks"])
    assert any("unknown defect 'nonsense'" in c for c in parsed["aptrace_checks"])


# -- classifications -----------------------------------------------------------------------------


def test_negative_from_an_unentered_target_is_contradicted_by_the_blocker_record():
    validation, _ = validate(chain(), finding("unsupported_negative", ["R2"], ["E3"]))
    result = validation["findings"][0]
    assert result["classification"] == CONTRADICTED
    records = check(result, "negative_conclusion")["records"]
    blocker = next(r for r in records if r["record"].startswith("relations.R2.blockers"))
    assert blocker["evidence_id"] == "E3" and "not thereby unreachable" in blocker["text"]
    assert any(r["record"] == "relations.R2.level" for r in records)


def test_an_unqualified_negative_statement_leaves_the_criticism_unresolved():
    assessment = chain()
    assessment["hypotheses"] = [{"statement": "FUN_00004000 is unreachable from the handler", "evidence_ids": ["E3"],
                                 "source": "planner", "status": "hypothesis"}]
    result = validate(assessment, finding("unsupported_negative", ["R2"], ["E3"]))[0]["findings"][0]
    assert result["classification"] == UNRESOLVED_FINDING
    assert check(result, "negative_conclusion")["records"][0]["record"] == "hypotheses[0]"


def test_static_presented_as_execution_is_contradicted_only_by_a_positive_record():
    result = validate(chain(), finding("static_as_execution", ["R2", "R3"], ["E0"]))[0]["findings"][0]
    assert result["classification"] == CONTRADICTED

    tampered = chain()
    tampered["relations"][1].update(level=OBSERVED, evidence=[{"evidence_id": "E0", "level": OBSERVED, "detail": "x"}])
    result = validate(tampered, finding("static_as_execution", ["R2"], ["E0"]))[0]["findings"][0]
    assert result["classification"] == SUPPORTED  # OBSERVED resting on evidence with no execution scope


def test_missing_evidence_is_never_a_contradiction():
    validation, _ = validate(
        chain(),
        finding("unsupported_relationship", ["R3"], ["E5"]),
        finding("unsupported_relationship", ["R4"], ["E2"]),
        finding("contradictory_evidence", ["R1", "R4"], ["E1", "E2"]),
        finding("counterexample_or_falsification", ["R1"], ["E1"]),
    )
    unresolved_relation, observed_relation, contradiction, firmware = validation["findings"]
    assert unresolved_relation["classification"] == SUPPORTED  # R3 is UNRESOLVED: the gap is in the record
    assert observed_relation["classification"] == UNRESOLVED_FINDING  # R4 OBSERVED: neither established nor refuted
    assert contradiction["classification"] == UNRESOLVED_FINDING  # no contradiction recorded; absence refutes nothing
    assert firmware["classification"] == UNRESOLVED_FINDING
    assert CONTRADICTED not in {f["classification"] for f in validation["findings"]}


def test_a_gap_between_segments_is_supported_and_its_mischaracterization_is_reported():
    result = validate(chain(), finding("scope_mismatch", ["R1", "R4"], ["E1", "E2"]))[0]["findings"][0]
    assert result["classification"] == SUPPORTED
    connection = check(result, "connection")
    assert connection["result"] == SUPPORTED
    assert any(r["record"] == "composition.joins[R1->R2]" for r in connection["records"])
    assert any(r["record"] == "relations.R2.level" for r in connection["records"])
    assert check(result, "state_continuity")["result"] == SUPPORTED
    # The finding says APTrace joined the segments; the record says it did not. The gap is kept.
    assert result["characterization"]["result"] == CONTRADICTED and result["mischaracterizes_investigation"]


def test_only_statements_citing_the_target_can_support_a_characterization():
    assessment = chain()
    assessment["claims"]["session_claims"] = [{"statement": "E1 and E2 together show the output", "grade": "PROVEN",
                                               "basis": "x", "evidence_ids": ["E1", "E2"]}]
    spanning = validate(assessment, finding("unjustified_composition", ["R1"], ["E1"]))[0]["findings"][0]
    assert spanning["characterization"]["result"] == SUPPORTED  # the statement cites R1's evidence and spans segments

    unrelated = validate(assessment, finding("unjustified_composition", ["R3"], ["E5"]))[0]["findings"][0]
    assert unrelated["characterization"]["result"] == CONTRADICTED


def test_relations_established_by_one_execution_are_not_separate_executions():
    assessment = chain()
    for relation in assessment["relations"][:2]:
        relation.update(level=OBSERVED, evidence=[{"evidence_id": "E1", "level": OBSERVED, "detail": "same run"}])
    result = validate(assessment, finding("unjustified_composition", ["R1", "R2"], ["E1"]))[0]["findings"][0]
    assert check(result, "connection")["result"] == CONTRADICTED


def test_continuity_finding_without_two_execution_segments_has_no_continuity_target():
    result = validate(chain(), finding("missing_prerequisite_or_state_continuity", ["R3"], ["E1", "E5"]))[0]["findings"][0]
    assert check(result, "state_continuity")["result"] == UNGROUNDED
    assert result["classification"] == SUPPORTED  # R3 itself is UNRESOLVED


def test_unraised_continuity_concerns_and_overstated_confidence_are_reported():
    validation, _ = validate(chain(), finding("unsupported_relationship", ["R3"], ["E5"]), confidence="overstated")
    unraised = {item["concern"] for item in validation["continuity"]["not_raised_by_reviewer"]}
    assert unraised == {c["id"] for c in validation["continuity"]["concerns"]}
    assert validation["confidence"]["result"] == CONTRADICTED  # no composition, no admitted claim

    raised, _ = validate(chain(), finding("missing_prerequisite_or_state_continuity", ["R1", "R4"], ["E1", "E2"],
                                          statement=f"both seed {SHARED}"))
    assert "C1" not in {item["concern"] for item in raised["continuity"]["not_raised_by_reviewer"]}


# -- follow-up questions ----------------------------------------------------------------------------


def test_followups_come_from_supported_and_unresolved_criticism_and_are_never_executable():
    validation, _ = validate(
        chain(),
        finding("scope_mismatch", ["R1", "R4"], ["E1", "E2"], test="run both segments in one execution"),
        finding("unsupported_relationship", ["R3"], ["E5"]),
        finding("unsupported_negative", ["R2"], ["E3"]),
        finding("unsupported_relationship", ["R9"]),
        omitted=["Does FUN_00002000 write 0x20000100 when E5 is bounded differently?"],
    )
    questions = {q["kind"] + ":" + "->".join(q["challenged"]["relations"]): q for q in validation["followups"]}
    connection = questions["connection:R1->R2->R4"]
    sources = [s.get("finding", s.get("aptrace_continuity")) for s in connection["sources"]]
    assert 0 in sources and "C1" in sources  # the reviewer's gap and APTrace's own concern, merged
    assert connection["challenged"]["levels"] == {"R1": OBSERVED, "R2": STATIC, "R4": OBSERVED}
    assert any(SHARED in c for c in connection["conditions"])
    assert any(op["availability"] == "requires_registered_scenario" for op in connection["candidate_operations"])
    assert connection["reviewer_tests"] == ["run both segments in one execution"]

    busy = questions["relation:R3"]
    assert not any(s.get("finding") == 4 for s in questions.get("relation:R2", {"sources": []})["sources"])
    assert {s["finding"] for s in busy["sources"]} == {1, 4}  # the finding and the omitted question naming 0x20000100
    effects = next(op for op in busy["candidate_operations"] if op["operation"] == "analyze_function_effects")
    assert effects["availability"].startswith("attempted: E5")
    assert any(op["operation"] == "observed_call_arguments" and op["arguments"]["watch"] == ["0x20000100"]
               for op in busy["candidate_operations"])

    # Contradicted and ungrounded findings produce nothing.
    all_sources = {s.get("finding") for q in validation["followups"] for s in q["sources"]}
    assert not all_sources & {2, 3}
    assert all(q["status"] == "proposal" and q["executable"] is False for q in validation["followups"])
    assert validation["followups"] == validate(chain(), *[finding("scope_mismatch", ["R1", "R4"], ["E1", "E2"],
                                                                  test="run both segments in one execution"),
                                                          finding("unsupported_relationship", ["R3"], ["E5"]),
                                                          finding("unsupported_negative", ["R2"], ["E3"]),
                                                          finding("unsupported_relationship", ["R9"])],
                                               omitted=["Does FUN_00002000 write 0x20000100 when E5 is bounded differently?"])[0]["followups"]


# -- package v2 and integrity -------------------------------------------------------------------------


def test_package_keeps_material_state_under_reduction_and_records_omissions():
    assumptions = [f"filler assumption {i}" for i in range(3)] + [f"seeded 4 byte(s) at {SHARED} (value is a harness input)",
                                                                  "direct call is not IRQ delivery", "delta=1"]
    first = segment("E1", "FUN_00002000", "FUN_00001000", "seg-a", seeds=[(SHARED, 4)], assumptions=assumptions)
    first.result["planner_summary"] = "x" * 700
    assessment = chain(E1=first)
    package = build_package(assessment, links=LINKS, max_chars=4000)

    assert package["version"] == PACKAGE_VERSION and package["template_version"] == TEMPLATE_VERSION
    assert "scopes.harness_assumptions<=3+material" in package["bounds"]["truncated"]
    kept = package["content"]["relations"][0]["scopes"][0]["harness_assumptions"]
    assert kept[3:] == [assumptions[3], assumptions[4]]  # the shared seed and the qualifier, not "delta=1"
    assert any(o["item"] == "harness_assumptions R1/E1" and o["dropped"] == 1 for o in package["bounds"]["omitted"])
    assert {c["id"] for c in package["content"]["composition"]["continuity"]["concerns"]} >= {"C1"}
    assert package["content"]["relations"][0]["scopes"][0]["state"]["supplied"] == [{"addr": SHARED, "len": 4}]
    assert package["content"]["targets"]["joins"] == ["R1->R2", "R1->R3", "R2->R4"]
    assert package_integrity(assessment, package)["material_complete"]

    # The v1 rule (first 3 assumptions) would have dropped the shared seed: the integrity check names it.
    v1_style = copy.deepcopy(package)
    v1_style["content"]["relations"][0]["scopes"][0]["harness_assumptions"] = assumptions[:3]
    missing = package_integrity(assessment, v1_style)["missing_material"]
    assert any(SHARED in m for m in missing)


def test_review_template_v2_asks_for_grounded_findings():
    messages = review_messages(build_package(chain(), links=LINKS))
    system, user = messages[0]["content"], messages[1]["content"]
    assert '"targets"' in user and '"quote"' in user and '"defect"' in user and '"resolving_evidence"' in user
    assert "incorrect_inference" in system and "rejected" in system


# -- authority, persistence, determinism -------------------------------------------------------------


def test_validation_is_persisted_beside_the_attempt_and_changes_nothing_else(tmp_path):
    result, controller, session = focused_run([("follow_lead", {"lead_id": "L2"}), ("finish", {"reason": "done"})])
    state_before = session.state.model_dump_json()
    evidence_before = [o.model_dump_json() for o in session.ledger.all()]
    review = {"findings": [finding("unsupported_relationship", ["R3"], [])], "omitted_questions": [],
              "confidence": "overstated", "summary": "s", "verdict": "VERIFIED", "grade": "EXACT"}
    rv, store = reviewer(tmp_path, ReviewClient(review), FakeOmlx())
    inv = rv.prepare(result.terminal_assessment, LINKS)
    attempt = rv.run(inv)
    assert attempt["status"] == COMPLETED

    persisted = store.validation(inv, attempt["attempt_id"])
    assert persisted == store.validate(inv) and persisted["validation_sha256"]
    assert persisted["findings"][0]["classification"] == SUPPORTED
    assert "changes no evidence" in persisted["authority"]
    # Nothing in the validation can promote or grade: no claim state, grade or verdict fields.
    text = json.dumps(persisted)
    assert '"VERIFIED"' not in text and '"grade"' not in text
    assert session.state.model_dump_json() == state_before
    assert [o.model_dump_json() for o in session.ledger.all()] == evidence_before
    assert store.assessment(inv)["assessment_sha256"] == assessment_sha256(result.terminal_assessment)

    # Recomputing writes nothing.
    files = {p: p.read_bytes() for p in (tmp_path / "reviews").rglob("*.json")}
    store.validate(inv)
    assert {p: p.read_bytes() for p in (tmp_path / "reviews").rglob("*.json")} == files

    report = "\n".join(__import__("aptrace_agent.research.review", fromlist=["render_final_report"]).render_final_report(store, inv))
    assert report.index("ADVERSARIAL CRITICISM") < report.index("CRITIC VALIDATION") < report.index("UNRESOLVED EVIDENCE")
    assert "follow-up question proposals" in report


def test_a_validation_failure_never_changes_the_review_status(tmp_path, monkeypatch):
    rv, store = reviewer(tmp_path, ReviewClient({"findings": [], "confidence": "cannot_judge"}), FakeOmlx())
    inv = rv.prepare(chain(), LINKS)
    monkeypatch.setattr(TerminalReviewStore, "validate", lambda self, *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    attempt = rv.run(inv)
    assert attempt["status"] == COMPLETED and store.status(inv) == COMPLETED
    assert store.validation(inv, attempt["attempt_id"])["error"]["kind"] == "RuntimeError"


def test_cli_validate_reads_the_store_and_never_writes_it(tmp_path, monkeypatch, capsys):
    review = {"findings": [finding("scope_mismatch", ["R1", "R4"], ["E1", "E2"])], "confidence": "cannot_judge"}
    rv, store = reviewer(tmp_path, ReviewClient(review), FakeOmlx())
    inv = rv.prepare(chain(), LINKS)
    rv.run(inv)
    files = {p: p.read_bytes() for p in (tmp_path / "reviews").rglob("*.json")}
    output = tmp_path / "validation.json"

    monkeypatch.setattr(sys, "argv", ["aptrace-agent", "terminal-review", "validate", inv, "--review-dir",
                                      str(tmp_path / "reviews"), "--json", "--output", str(output)])
    cli.main()
    printed = json.loads(capsys.readouterr().out)
    assert printed == json.loads(output.read_text()) == store.validate(inv)
    assert {p: p.read_bytes() for p in (tmp_path / "reviews").rglob("*.json")} == files

    monkeypatch.setattr(sys, "argv", ["aptrace-agent", "terminal-review", "validate", inv, "--review-dir",
                                      str(tmp_path / "reviews"), "--attempt", "RA-none"])
    with pytest.raises(SystemExit, match="no completed review attempt RA-none"):
        cli.main()
