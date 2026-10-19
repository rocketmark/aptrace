"""
Terminal Review v1 (research/terminal.py, research/review.py, omlx.py) with
synthetic firmware identities, a simulated oMLX server and a scripted
review model. No live model and no case data; the Performing Rigs replay is
cases/performing-rigs/test/test_terminal_review_regression.py.

Nothing here depends on review-model wording: review responses are
scripted, and assertions are about lifecycle, persistence, status and
APTrace's own checks.
"""

import json
import sys
from types import SimpleNamespace

import pytest

from aptrace_agent import cli
from aptrace_agent.ledger.store import LedgerImmutableError
from aptrace_agent.omlx import (
    ENDPOINT_UNAVAILABLE,
    INSUFFICIENT_MEMORY,
    MODEL_NOT_SERVED,
    PINNED_MODEL_RESIDENT,
    SERVER_BUSY,
    UNEXPECTED_RESIDENCY,
    UNLOAD_UNVERIFIED,
    ModelResidency,
    OmlxError,
    OmlxRuntime,
    ResidencyError,
    ResidencyPolicy,
)
from aptrace_agent.research.objective import OBSERVED, STATIC, ObjectiveTracker
from aptrace_agent.research.review import (
    AUTHORITY,
    COMPLETED,
    FAILED,
    PENDING,
    SKIPPED,
    UNAVAILABLE,
    MalformedReview,
    TerminalReviewer,
    TerminalReviewStore,
    build_package,
    parse_review,
    render_final_report,
)
from aptrace_agent.research.terminal import ASSESSMENT_VERSION, assessment_sha256, build_assessment
from aptrace_agent.schemas import EvidenceObservation

from test_objective_bounded import GRAPH, facts, make, spec

PLANNER, REVIEWER = "planner-model", "review-model"
GB = 1 << 30


# -- simulated oMLX -------------------------------------------------------------------


class FakeOmlx:
    """oMLX lifecycle endpoints over an in-memory pool; records every call."""

    def __init__(self, loaded=(PLANNER,), *, ceiling=20 * GB, sizes=None, pinned=(), busy_polls=0,
                 ignore_unload=False, load_error=None, extra_after_load=None, down=False):
        self.sizes = sizes or {PLANNER: 17 * GB, REVIEWER: 16 * GB, "other-model": 9 * GB}
        self.loaded = set(loaded)
        self.ceiling = ceiling
        self.pinned = set(pinned)
        self.busy_polls = busy_polls
        self.ignore_unload = ignore_unload
        self.load_error = load_error
        self.extra_after_load = extra_after_load
        self.down = down
        self.calls = []

    def __call__(self, method, path, timeout):
        self.calls.append((method, path))

        if self.down:
            raise OmlxError(ENDPOINT_UNAVAILABLE, "connection refused")

        if path == "/api/status":
            active = 1 if self.busy_polls > 0 else 0
            self.busy_polls = max(0, self.busy_polls - 1)
            return {"version": "test", "active_requests": active, "waiting_requests": 0,
                    "loaded_models": sorted(self.loaded)}

        if path == "/v1/models/status":
            return {
                "final_ceiling": self.ceiling,
                "current_model_memory": sum(self.sizes[m] for m in self.loaded),
                "models": [{"id": m, "loaded": m in self.loaded, "is_loading": False, "pinned": m in self.pinned,
                            "estimated_size": s, "max_context_window": 40000} for m, s in self.sizes.items()],
            }

        model = path.split("/")[3]

        if path.endswith("/unload"):
            if model not in self.loaded:
                raise OmlxError("http_error", f"Model not loaded: {model}", 400)
            if not self.ignore_unload:
                self.loaded.discard(model)
            return {"status": "ok"}

        if path.endswith("/load"):
            if self.load_error:
                raise self.load_error
            if sum(self.sizes[m] for m in self.loaded) + self.sizes[model] > self.ceiling:
                raise OmlxError(INSUFFICIENT_MEMORY, f"Cannot load {model}: projected memory exceeds ceiling", 507)
            self.loaded.add(model)
            if self.extra_after_load:
                self.loaded.add(self.extra_after_load)
            return {"status": "ok"}

        raise AssertionError(path)

    def actions(self):
        return [(m, p) for m, p in self.calls if m == "POST"]


def residency(server, **policy):
    clock = SimpleNamespace(t=0.0)

    def sleep(seconds):
        clock.t += seconds

    return ModelResidency(
        OmlxRuntime("http://127.0.0.1:8000/v1", "key", request=server),
        ResidencyPolicy(**({"idle_wait_s": 10, "poll_s": 1, "settle_wait_s": 3, "unload_attempts": 2, "load_attempts": 2} | policy)),
        sleep=sleep,
        clock=lambda: clock.t,
    )


# -- scripted review model ------------------------------------------------------------


GOOD_REVIEW = {
    "findings": [
        {"category": "unjustified_composition", "kind": "suggested_test", "relations": ["R1", "R2"],
         "evidence_ids": ["E1"], "statement": "R1 and R2 come from separate executions.",
         "test": "Run one scenario that enters both edges with carried state."},
        {"category": "contradictory_evidence", "kind": "demonstrated_contradiction", "relations": ["R2"],
         "evidence_ids": [], "statement": "Uncited contradiction."},
        {"category": "static_as_execution", "kind": "hypothesis", "relations": ["R9"], "evidence_ids": ["E77"],
         "statement": "References that are not in the package."},
    ],
    "omitted_questions": ["Is the busy flag ever set?"],
    "confidence": "overstated",
    "summary": "Challenged.",
    "verdict": "VERIFIED",
}


class ReviewClient:
    """OpenAI-shaped client returning scripted contents or raising scripted errors."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kwargs):
        self.requests.append(kwargs)
        item = self.responses.pop(0)

        if isinstance(item, Exception):
            raise item

        content = item if isinstance(item, str) else json.dumps(item)
        message = SimpleNamespace(content=content)
        return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="stop")], model=kwargs["model"], usage=None)


class Raises:
    def __init__(self):
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kwargs):
        raise AssertionError("the planner must not run during terminal review")


# -- helpers ----------------------------------------------------------------------------


def focused_run(decisions, **kwargs):
    kwargs.setdefault("objective", spec())
    controller, session, planner, executor = make(decisions, **kwargs)
    return controller.run(session), controller, session


def reviewer(tmp_path, client, server=None, **kwargs):
    store = TerminalReviewStore(tmp_path / "reviews")
    return TerminalReviewer(store, model=REVIEWER, client=client,
                            residency=residency(server) if server is not None else None, **kwargs), store


LINKS = {"artifact": "run.json", "ledger_run_id": None, "generated_at": "2026-10-19T00:00:00+00:00"}


# -- 1. deterministic terminal assessment -------------------------------------------------


class Exploding:
    def __init__(self):
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kwargs):
        raise ConnectionError("planner endpoint went away")


TIMEOUT = {"status": "bounded: timeout 300s", "coverage": "bounded: timeout 300s", "calls": [], "accesses": []}


@pytest.mark.parametrize("case, stop, category", [
    ("finish", "planner_finished", "completed"),
    ("budget", "step_budget_exhausted", "budget_exhausted"),
    ("stall", "objective_stalled", "stalled"),
    ("no_operation", "objective_no_relevant_operation", "no_relevant_operation"),
    ("contract", "planner_contract_exhausted", "planner_failure"),
    ("timeout", "planner_finished", "completed"),
    ("error", "investigation_error", "error"),
])
def test_every_focused_termination_produces_a_deterministic_assessment(case, stop, category):
    kwargs = {}
    decisions = [("follow_lead", {"lead_id": "L2"}), ("finish", {"reason": "done"})]

    if case == "budget":
        decisions, kwargs = [("follow_lead", {"lead_id": "L2"}), ("follow_lead", {"lead_id": "L1"})], {"max_steps": 2}
    elif case == "stall":
        decisions = [("follow_lead", {"lead_id": "L2"}), ("follow_lead", {"lead_id": "L1"}), ("follow_lead", {"lead_id": "L3"})]
        kwargs = {"objective": spec(replan_after=1, stall_limit=2), "max_steps": 10}
    elif case == "no_operation":
        decisions, kwargs = [], {"objective": spec(relations=[{"id": "R1", "source": "0x20000100", "target": "0x20000200"}])}
    elif case == "contract":
        decisions = [("no_such_tool", {}), ("no_such_tool", {})]
    elif case == "timeout":
        decisions = [("follow_lead", {"lead_id": "L2"}), ("analyze_function_effects", {"function": "FUN_00002000"}),
                     ("finish", {"reason": "done"})]
        kwargs = {"overrides": {("function_effects", "FUN_00002000"): TIMEOUT}}

    if case == "error":
        controller, session, _, _ = make(decisions, objective=spec())
        controller.planner_client = Exploding()
        result = controller.run(session)
    else:
        result, controller, session = focused_run(decisions, **kwargs)

    assessment = result.terminal_assessment
    assert result.stop_reason == stop
    assert assessment["version"] == ASSESSMENT_VERSION
    assert assessment["termination"]["stop_reason"] == stop and assessment["termination"]["category"] == category
    assert assessment["objective"]["question"] == spec().question or case == "no_operation"
    assert assessment["objective"]["constraints"]
    assert {r["id"] for r in assessment["relations"]} == {r["id"] for r in result.objective_report["relations"]}

    for relation in assessment["relations"]:
        assert relation["level_meaning"] and "evidence_needed" in relation and "scopes" in relation

    assert assessment["composition"]["attempted"] is False
    assert "Admitted claim proposals are PROPOSED" in " ".join(assessment["limitations"])
    # The same relation levels as objective-v1: no competing grade.
    assert [r["level"] for r in assessment["relations"]] == [r["level"] for r in result.objective_report["relations"]]
    # Persistable and hashable with no model response.
    json.dumps(assessment)
    assert len(assessment_sha256(assessment)) == 64

    if case == "error":
        assert assessment["termination"]["error"] == {"type": "ConnectionError", "message": "planner endpoint went away"}
    if case == "timeout":
        assert assessment["failed_operations"][0]["status"] == "bounded: timeout 300s"
        assert assessment["termination"]["analysis_failures"] == 1
        assert any("not absence of effects" in b["detail"] for b in assessment["blockers"])


def test_assessment_is_reproducible_for_identical_runs():
    decisions = [("follow_lead", {"lead_id": "L2"}), ("finish", {"reason": "done"})]
    first, _, _ = focused_run(list(decisions))
    second, _, _ = focused_run(list(decisions))
    assert assessment_sha256(first.terminal_assessment) == assessment_sha256(second.terminal_assessment)


def test_unfocused_runs_are_unchanged():
    controller, session, _, _ = make([("follow_lead", {"lead_id": "L1"}), ("finish", {"reason": "done"})])
    session.state.add_lead(session.registry.register(kind="x", description="d", tool="function_facts",
                                                     arguments={"function": "FUN_00002000"}))
    result = controller.run(session)
    assert result.terminal_assessment is None and result.objective_report is None

    controller, session, _, _ = make([])
    session.state.add_lead(session.registry.register(kind="x", description="d", tool="function_facts",
                                                     arguments={"function": "FUN_00002000"}))
    controller.planner_client = Exploding()

    with pytest.raises(ConnectionError):
        controller.run(session)


def _observed(eid, function, caller, scenario, assumptions):
    return EvidenceObservation(
        id=eid, tool="observed_call_arguments", arguments={"function": function, "scenario": scenario},
        result={"status": "ok", "observed_entries": 1, "call_sites": [{"caller": caller, "status": "OBSERVED"}],
                "harness_assumptions": [{"detail": a} for a in assumptions],
                "coverage": f"observed contexts only: scenario {scenario}",
                "provenance": {"analysis": "observed_call_arguments", "analysis_version": 2, "engine": "concrete"}},
    )


def assessment_for(objective, observations, **kwargs):
    tracker = ObjectiveTracker(spec=objective, function_exists=lambda n: n in GRAPH)
    report = tracker.report(observations, stop_reason="step_budget_exhausted", steps_used=2, max_steps=2)
    return build_assessment(spec=objective, report=report, observations=observations,
                            stop_reason="step_budget_exhausted", **kwargs)


def test_separately_observed_edges_are_reported_as_unvalidated_joins_and_segments():
    objective = spec(relations=[
        {"id": "R1", "source": "FUN_00001000", "target": "FUN_00002000"},
        {"id": "R2", "source": "FUN_00002000", "target": "FUN_00003000"},
        {"id": "R5", "source": "FUN_00004000", "target": "FUN_00005000"},
    ])
    observations = [
        _observed("E1", "FUN_00002000", "FUN_00001000", "vl-alpha", ["fresh state", "seeded record"]),
        _observed("E2", "FUN_00003000", "FUN_00002000", "vl-beta", ["fresh state"]),
        _observed("E3", "FUN_00005000", "FUN_00004000", "boot", ["direct handler call"]),
    ]
    assessment = assessment_for(objective, observations)
    levels = {r["id"]: r["level"] for r in assessment["relations"]}
    assert levels == {"R1": OBSERVED, "R2": OBSERVED, "R5": OBSERVED}

    join = assessment["composition"]["joins"][0]
    assert (join["from_relation"], join["to_relation"], join["continuity"]) == ("R1", "R2", "not validated")
    assert "separate evidence" in join["reason"]
    assert [e["scenario"] for e in join["from_evidence"] + join["to_evidence"]] == ["vl-alpha", "vl-beta"]

    segments = assessment["composition"]["segments"]
    assert [s["relations"] for s in segments] == [["R1", "R2"], ["R5"]]
    assert "2 separately established segments" in assessment["composition"]["disconnected"]
    scope = assessment["relations"][0]["scopes"][0]
    assert scope["scenario"] == "vl-alpha" and scope["harness_assumptions"] == ["fresh state", "seeded record"]


# -- 2./3. eligibility for every focused run, including failures --------------------------


def test_review_is_eligible_without_case_evidence_and_for_failed_runs(tmp_path):
    # The make() Reconciler raises if case reconciliation runs: none of these has case evidence.
    controller, session, _, _ = make([], objective=spec())
    controller.planner_client = Exploding()
    errored = controller.run(session)
    stalled, _, _ = focused_run(
        [("follow_lead", {"lead_id": "L2"}), ("follow_lead", {"lead_id": "L1"}), ("follow_lead", {"lead_id": "L3"})],
        objective=spec(replan_after=1, stall_limit=2), max_steps=10,
    )
    no_claims, _, _ = focused_run([("follow_lead", {"lead_id": "L2"}), ("analyze_function_effects", {"function": "FUN_00002000"}),
                                   ("finish", {"reason": "x"})],
                                  overrides={("function_effects", "FUN_00002000"): TIMEOUT})

    assert (errored.stop_reason, stalled.stop_reason) == ("investigation_error", "objective_stalled")
    assert no_claims.terminal_assessment["failed_operations"]

    for result in (errored, stalled, no_claims):
        assert result.reconciled is False and result.proposed_claims == ()
        rv, store = reviewer(tmp_path / result.stop_reason, ReviewClient(GOOD_REVIEW), FakeOmlx())
        inv = rv.prepare(result.terminal_assessment, LINKS)
        assert store.status(inv) == PENDING
        attempt = rv.run(inv)
        assert attempt["status"] == COMPLETED, attempt["error"]


# -- 4. the package carries what a reviewer needs --------------------------------------------


def test_package_carries_provenance_scopes_assumptions_and_status():
    objective = spec(relations=[
        {"id": "R1", "source": "FUN_00001000", "target": "FUN_00002000"},
        {"id": "R2", "source": "FUN_00002000", "target": "FUN_00003000"},
    ])
    observations = [
        EvidenceObservation(id="E0", tool="function_facts", arguments={"function": "FUN_00002000"}, result=facts("FUN_00002000")),
        _observed("E1", "FUN_00002000", "FUN_00001000", "vl-alpha", ["fresh state", "seeded record"]),
    ]
    assessment = assessment_for(objective, observations, planner_model="planner-model")
    package = build_package(assessment, links=LINKS)
    content = package["content"]

    r1, r2 = content["relations"]
    assert r1["level"] == OBSERVED and "harness assumptions" in r1["level_meaning"]
    assert r2["level"] == STATIC and "not execution" in r2["level_meaning"] and r2["evidence_needed"]
    assert r1["scopes"][0]["harness_assumptions"] == ["fresh state", "seeded record"]
    assert content["composition"]["joins"][0]["continuity"] == "not validated"
    assert {e["evidence_id"]: e["result_sha256"] for e in content["evidence"]}.keys() == {"E0", "E1"}
    assert package["assessment_sha256"] == assessment_sha256(assessment)
    assert package["links"] == LINKS and package["bounds"]["within_bound"]


def test_package_is_bounded_and_never_alters_the_assessment():
    objective = spec()
    big = {"status": "ok", "planner_summary": "x" * 5000, "harness_assumptions": [{"detail": "a" * 500}] * 20,
           "coverage": "c"}
    observations = [EvidenceObservation(id=f"E{i}", tool="function_effects", arguments={"function": "FUN_00002000"}, result=big)
                    for i in range(60)]
    assessment = assessment_for(objective, observations)
    before = assessment_sha256(assessment)
    package = build_package(assessment, links=LINKS, max_chars=20000)
    assert package["bounds"]["truncated"] and package["bounds"]["chars"] <= 20000
    assert assessment_sha256(assessment) == before == package["assessment_sha256"]


# -- 6./8. sequential residency -----------------------------------------------------------------


def test_planner_is_unloaded_and_verified_before_the_reviewer_loads():
    server = FakeOmlx(loaded=(PLANNER,))
    record = residency(server).acquire(REVIEWER)

    assert record["ok"] and record["before"]["loaded"] == [PLANNER] and record["after"]["loaded"] == [REVIEWER]
    assert server.actions() == [("POST", f"/v1/models/{PLANNER}/unload"), ("POST", f"/v1/models/{REVIEWER}/load")]
    # The unload was re-read from the server before the load.
    unload_at = server.calls.index(("POST", f"/v1/models/{PLANNER}/unload"))
    load_at = server.calls.index(("POST", f"/v1/models/{REVIEWER}/load"))
    assert ("GET", "/v1/models/status") in server.calls[unload_at + 1 : load_at]
    assert any(a["action"] == f"wait:unloaded:{PLANNER}" and a["satisfied"] for a in record["actions"])


def test_reviewer_is_released_and_planner_restored():
    server = FakeOmlx(loaded=(REVIEWER,))
    manager = residency(server)
    released = manager.release(REVIEWER)
    restored = manager.acquire(PLANNER)
    assert released["ok"] and released["after"]["loaded"] == []
    assert restored["ok"] and server.loaded == {PLANNER}


def test_unload_waits_for_in_flight_requests_and_gives_up_bounded():
    server = FakeOmlx(busy_polls=3)
    record = residency(server).acquire(REVIEWER)
    assert record["ok"]
    assert next(a for a in record["actions"] if a["action"] == "wait:idle")["polls"] == 3

    busy = FakeOmlx(busy_polls=10_000)

    with pytest.raises(ResidencyError) as caught:
        residency(busy).acquire(REVIEWER)

    assert caught.value.kind == SERVER_BUSY and busy.actions() == []  # never aborts another request


@pytest.mark.parametrize("server, kind", [
    (FakeOmlx(ignore_unload=True), UNLOAD_UNVERIFIED),
    (FakeOmlx(loaded=(), ceiling=10 * GB), INSUFFICIENT_MEMORY),
    (FakeOmlx(loaded=(), load_error=OmlxError(INSUFFICIENT_MEMORY, "Cannot load: projected memory", 507)), INSUFFICIENT_MEMORY),
    (FakeOmlx(down=True), ENDPOINT_UNAVAILABLE),
    (FakeOmlx(pinned=(PLANNER,)), PINNED_MODEL_RESIDENT),
    (FakeOmlx(extra_after_load="other-model"), UNEXPECTED_RESIDENCY),
])
def test_residency_failures_are_explicit(server, kind):
    with pytest.raises(ResidencyError) as caught:
        residency(server).acquire(REVIEWER)

    assert caught.value.kind == kind
    assert caught.value.record["ok"] is False and caught.value.record["error"]["kind"] == kind


def test_unserved_model_is_never_replaced():
    server = FakeOmlx()

    with pytest.raises(ResidencyError) as caught:
        residency(server).acquire("missing-model")

    assert caught.value.kind == MODEL_NOT_SERVED and server.actions() == [] and server.loaded == {PLANNER}


def test_non_local_endpoints_are_refused():
    with pytest.raises(ValueError):
        OmlxRuntime("http://example.com:8000/v1", "key", request=FakeOmlx())


# -- review lifecycle, 9. failures -------------------------------------------------------------------


def assessment_fixture():
    result, _, _ = focused_run([("follow_lead", {"lead_id": "L2"}), ("finish", {"reason": "done"})])
    return result.terminal_assessment


def test_completed_review_is_persisted_with_identity_raw_response_and_checks(tmp_path):
    server = FakeOmlx()
    client = ReviewClient(GOOD_REVIEW)
    rv, store = reviewer(tmp_path, client, server, model_settings=lambda m: {"max_context_window": 40000})
    inv = rv.prepare(assessment_fixture(), LINKS)
    attempt = rv.run(inv, restore_model=PLANNER)
    stored = store.attempts(inv)[0]

    assert stored["status"] == COMPLETED and stored["investigation_id"] == inv
    assert stored["package_sha256"] == store.package(inv)["package_sha256"]
    assert stored["model"]["id"] == REVIEWER and stored["model"]["generation"]["temperature"] == 0.0
    assert stored["model"]["omlx_settings"] == {"max_context_window": 40000}
    assert stored["model"]["served"]["max_context_window"] == 40000
    assert stored["raw_responses"][0]["content"] == json.dumps(GOOD_REVIEW)
    assert stored["links"] == LINKS and stored["authority"] == AUTHORITY

    findings = stored["review"]["findings"]
    assert findings[0]["effective_kind"] == "suggested_test" and findings[0]["test"]
    assert findings[1]["kind"] == "demonstrated_contradiction" and findings[1]["effective_kind"] == "hypothesis"
    assert any("not in the package" in c for c in findings[2]["aptrace_checks"])
    assert stored["review"]["ignored_fields"] == ["verdict"]  # no verification authority

    # Lifecycle: reviewer acquired (planner unloaded), released, then planner restored.
    acquire, release = stored["residency"]
    assert acquire["operation"] == "acquire" and acquire["after"]["loaded"] == [REVIEWER]
    assert release["operation"] == "release" and release["after"]["loaded"] == []
    assert attempt["restore"]["ok"] and server.loaded == {PLANNER}
    assert (tmp_path / "reviews" / inv / "residency" / f"{stored['attempt_id']}-restore.json").is_file()
    # The prompt is the persisted package, unchanged.
    assert json.dumps(store.package(inv)["content"], indent=1, sort_keys=True) in client.requests[0]["messages"][1]["content"]


def test_507_timeout_and_malformed_responses_preserve_the_result(tmp_path):
    from openai import APIStatusError, APITimeoutError

    httpx = pytest.importorskip("httpx2")  # the HTTP library of the pinned openai client

    request = httpx.Request("POST", "http://127.0.0.1:8000/v1/chat/completions")
    status_507 = APIStatusError("Error code: 507", response=httpx.Response(507, request=request), body=None)
    cases = {
        "residency_507": (FakeOmlx(load_error=OmlxError(INSUFFICIENT_MEMORY, "projected memory", 507)), ReviewClient(),
                          UNAVAILABLE, INSUFFICIENT_MEMORY),
        "generation_507": (FakeOmlx(), ReviewClient(status_507), UNAVAILABLE, "insufficient_memory"),
        "timeout": (FakeOmlx(), ReviewClient(APITimeoutError(request=request)), FAILED, "timeout"),
        "malformed": (FakeOmlx(), ReviewClient("not json", '{"findings": "nope"}'), FAILED, "malformed_response"),
        "endpoint_down": (FakeOmlx(down=True), ReviewClient(), UNAVAILABLE, ENDPOINT_UNAVAILABLE),
    }

    for name, (server, client, status, kind) in cases.items():
        assessment = assessment_fixture()
        before = assessment_sha256(assessment)
        rv, store = reviewer(tmp_path / name, client, server)
        inv = rv.prepare(assessment, LINKS)
        attempt = rv.run(inv)

        assert attempt["status"] == status and attempt["error"]["kind"] == kind, (name, attempt["error"])
        assert attempt["review"] is None
        assert store.status(inv) == status
        assert store.assessment(inv)["assessment_sha256"] == before == assessment_sha256(assessment)
        report = "\n".join(render_final_report(store, inv))
        assert f"status: {status}" in report and "the review step is missing" in report
        assert "DETERMINISTIC INVESTIGATION RESULT" in report and "R1" in report

        if name != "residency_507" and name != "endpoint_down":
            # The reviewer is released even when the review failed.
            assert attempt["residency"][-1]["operation"] == "release"


def test_malformed_first_response_gets_one_correction(tmp_path):
    client = ReviewClient("```json\n{broken", GOOD_REVIEW)
    rv, store = reviewer(tmp_path, client, FakeOmlx())
    inv = rv.prepare(assessment_fixture(), LINKS)
    attempt = rv.run(inv)
    assert attempt["status"] == COMPLETED and len(attempt["raw_responses"]) == 2 and attempt["corrections"]


def test_skip_is_explicit_policy_and_pending_is_visible(tmp_path):
    rv, store = reviewer(tmp_path, ReviewClient(), FakeOmlx())
    inv = rv.prepare(assessment_fixture(), LINKS)
    assert store.status(inv) == PENDING
    rv.skip(inv, "research --review skip")
    assert store.status(inv) == SKIPPED and store.attempts(inv)[0]["policy"] == "research --review skip"
    assert "skipped by policy" in "\n".join(render_final_report(store, inv))


# -- 10. retry from the persisted package -----------------------------------------------------------


def test_retry_uses_the_persisted_package_and_never_reruns_the_planner(tmp_path):
    server = FakeOmlx()
    rv, store = reviewer(tmp_path, ReviewClient(OSError("boom")), server)
    inv = rv.prepare(assessment_fixture(), LINKS)
    first = rv.run(inv)
    assert first["status"] == FAILED

    files = {p: p.read_bytes() for p in (tmp_path / "reviews" / inv).glob("*.json")}
    retry = TerminalReviewer(store, model=REVIEWER, client=ReviewClient(GOOD_REVIEW), residency=residency(server))
    second = retry.retry(inv)

    assert second["status"] == COMPLETED and second["retry_of"] == first["attempt_id"]
    assert second["package_sha256"] == first["package_sha256"]
    assert [a["status"] for a in store.attempts(inv)] == [FAILED, COMPLETED]
    assert {p: p.read_bytes() for p in files} == files  # assessment and package unchanged

    # A tampered package is refused, not silently rebuilt.
    path = tmp_path / "reviews" / inv / "package.json"
    data = json.loads(path.read_text())
    data["content"]["relations"][0]["level"] = "OBSERVED"
    path.write_text(json.dumps(data))

    with pytest.raises(ValueError, match="does not match its recorded hash"):
        retry.retry(inv)


def test_records_are_write_once(tmp_path):
    store = TerminalReviewStore(tmp_path)
    assessment = assessment_fixture()
    inv = store.put_assessment(assessment, LINKS)
    store.put_assessment(assessment, LINKS)  # identical: no-op
    path = tmp_path / inv / "assessment.json"
    record = json.loads(path.read_text())

    with pytest.raises(LedgerImmutableError):
        store._write_once(path, dict(record, links={"artifact": "other"}))


def test_review_findings_never_touch_claims_or_evidence(tmp_path):
    result, controller, session = focused_run([("follow_lead", {"lead_id": "L2"}), ("finish", {"reason": "done"})])
    state_before = session.state.model_dump_json()
    evidence_before = [o.model_dump_json() for o in session.ledger.all()]
    rv, store = reviewer(tmp_path, ReviewClient(GOOD_REVIEW), FakeOmlx())
    rv.run(rv.prepare(result.terminal_assessment, LINKS))
    assert session.state.model_dump_json() == state_before
    assert [o.model_dump_json() for o in session.ledger.all()] == evidence_before

    report = render_final_report(store, store.ids()[0])
    criticism = report.index("ADVERSARIAL CRITICISM (review model; advisory, not verification)")
    deterministic = report[: criticism]
    assert not any("separate executions" in line for line in deterministic)


def test_parse_review_rejects_responses_without_findings():
    package = build_package(assessment_fixture(), links=LINKS)

    for content in ("[]", '{"findings": [{"kind": "hypothesis"}]}', '{"findings": [{"statement": "x", "kind": "maybe"}]}'):
        with pytest.raises(MalformedReview):
            parse_review(content, package)


# -- CLI ---------------------------------------------------------------------------------------------


def test_research_cli_persists_assessment_before_review_and_retry_reuses_it(monkeypatch, tmp_path, capsys):
    result, controller, session = focused_run([("follow_lead", {"lead_id": "L2"}), ("finish", {"reason": "done"})])
    run = SimpleNamespace(objective=spec().question, seed_function=None, result=result, state=session.state,
                          evidence=tuple(session.ledger.all()), objective_spec=spec())
    objective_file = tmp_path / "objective.json"
    objective_file.write_text(spec().model_dump_json())
    server = FakeOmlx()
    order = []

    monkeypatch.setattr(cli, "run_autonomous_investigation", lambda *a, **k: run)
    monkeypatch.setattr(cli, "_residency", lambda: residency(server))

    def make_reviewer(args, store):
        def model_settings(model):
            order.append(("review", (tmp_path / "run.json").exists()))
            return None
        return TerminalReviewer(store, model=REVIEWER, client=ReviewClient(GOOD_REVIEW), residency=residency(server),
                                model_settings=model_settings)

    monkeypatch.setattr(cli, "_reviewer", make_reviewer)
    monkeypatch.setenv("APTRACE_MODEL", PLANNER)
    monkeypatch.setattr(sys, "argv", ["aptrace-agent", "research", "--objective-file", str(objective_file),
                                      "--output", str(tmp_path / "run.json")])
    cli.main()
    out = capsys.readouterr().out

    artifact = json.loads((tmp_path / "run.json").read_text())
    assert artifact["terminal_assessment"]["version"] == ASSESSMENT_VERSION
    assert artifact["terminal_review"]["status"] == PENDING  # written before the review ran
    inv = artifact["terminal_review"]["investigation_id"]
    store = TerminalReviewStore(tmp_path / "run.json.terminal-review")
    assert store.status(inv) == COMPLETED and order == [("review", True)]
    assert server.loaded == {PLANNER}  # restored
    for heading in ("DETERMINISTIC INVESTIGATION RESULT", "ADVERSARIAL CRITICISM", "UNRESOLVED EVIDENCE REQUIREMENTS",
                    "REVIEW AVAILABILITY"):
        assert heading in out

    # Retry from the store: no investigation, no planner.
    monkeypatch.setattr(cli, "run_autonomous_investigation", lambda *a, **k: pytest.fail("investigation reran"))
    monkeypatch.setattr(sys, "argv", ["aptrace-agent", "terminal-review", "retry", inv, "--review-dir",
                                      str(tmp_path / "run.json.terminal-review"), "--json"])
    cli.main()
    summary = json.loads(capsys.readouterr().out)
    assert [a["status"] for a in summary["attempts"]] == [COMPLETED, COMPLETED]
    assert summary["attempts"][1]["retry_of"] == summary["attempts"][0]["attempt_id"]
