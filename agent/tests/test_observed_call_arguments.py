"""Caller-grounded argument observation (observed_call_arguments): result
interpretation, evidence grading and limitations, failure handling, and
ledger recording/replay/reuse identity. No Unicorn, census or model needed:
the harness subprocess is replaced by a recorded document."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess

import pytest

from aptrace_agent.call_observation import (
    CALLER_GROUNDED,
    ObservationInputError,
    ObservedCallArgumentsRunner,
    planner_summary,
)
from aptrace_agent.function_effects import FunctionEffectsRunner
from aptrace_agent.ledger.models import EvidenceGrade
from aptrace_agent.ledger.operations import TOOL_INPUTS
from aptrace_agent.ledger.semantics import (
    HARNESS_ASSUMPTIONS,
    HYPOTHETICAL_SPECIALIZATION,
    OBSERVATION_TRUNCATED,
    OBSERVED_CONTEXTS_ONLY,
    UNOBSERVED_CALL_SITES,
    evidence_grade,
    evidence_limitations,
)
from aptrace_agent.ledger.store import ResearchLedger
from aptrace_agent.research.history import HistoricalOperations

from ledger_support import FIRMWARE, stack


IMAGE = b"firmware-bytes"
IMAGE_SHA = hashlib.sha256(IMAGE).hexdigest()


def value(v, region, word=None, word_region=None, count=1):
    return {"value": v, "region": region, "count": count, "pointee_bytes": None if word is None else "00",
            "pointee_word": word, "pointee_word_region": word_region}


def harness_doc(**overrides):
    doc = {
        "status": "ok",
        "scenario": "boot",
        "firmware_key": "autopilot868",
        "firmware_sha256": IMAGE_SHA,
        "recipe": {"reference_key": "autopilot868", "gaps": [], "assumptions": [
            {"kind": "force_reg", "addr": "0x00009dd4", "detail": "radio id"},
            {"kind": "fake_tick", "addr": "0x200052ec", "detail": "tick"},
        ]},
        "run": {"stop_reason": "instruction limit reached", "instructions_executed": 450000,
                "init_status": "complete", "milestones_reached": ["0x00008960"]},
        "observation": {"analysis": "call_observation", "analysis_version": 1, "entry": "0x0000b4b4",
                        "observed_entries": 3, "call_sites": [
            {"call_site": "0x0000a068", "call_kind": "BL", "decoded_target": "0x0000b4b4", "return_address": "0x0000a06c",
             "hits": 2, "first_instruction": 10,
             "arguments": {"r0": [value("0x20004c54", "RAM", "0x41012000", "MMIO")], "r1": [value("0x00000000", None)]}},
            {"call_site": "0x0000c000", "call_kind": "BLX_REG", "decoded_target": None, "return_address": "0x0000c002",
             "hits": 1, "first_instruction": 20,
             "arguments": {"r0": [value("0x40003000", "MMIO", "0x00000000", None)]}},
        ]},
        "mmio_in_extent": {"extent": ["0x0000b4b4", "0x0000b500"], "log_entries": 10, "log_truncated": False,
                           "accesses": [], "access_count": 0},
    }
    doc.update(overrides)
    return doc


class FakeHarness:
    def __init__(self, doc=None, *, returncode=0, stderr="", raises=None):
        self.doc, self.returncode, self.stderr, self.raises = doc, returncode, stderr, raises
        self.argv = []

    def __call__(self, argv):
        self.argv.append(argv)
        if self.raises:
            raise self.raises
        stdout = json.dumps(self.doc) if isinstance(self.doc, dict) else (self.doc or "")
        return subprocess.CompletedProcess(argv, self.returncode, stdout=stdout, stderr=self.stderr)


def runner(tmp_path, harness, *, sha=IMAGE_SHA, python=True, extent=(0xB4B4, 0xB500)):
    image = tmp_path / "fw.bin"
    image.write_bytes(IMAGE)
    interp = tmp_path / "python3"
    if python:
        interp.write_text("")
    return ObservedCallArgumentsRunner(
        python=interp,
        script=tmp_path / "observe.py",
        firmware_key="autopilot868",
        firmware_image=image,
        expected_sha256=sha,
        entry_allowed=lambda entry: entry != 0xDEAD,
        static_call_sites=lambda name: [("0x0000a068", "FUN_0000a064"), ("0x0000b662", "FUN_0000b658")],
        function_extent=lambda name: extent,
        resolve_register=lambda v: "SERCOM0.CTRLA (0x40003000)" if v == 0x40003000 else None,
        run=harness,
    )


def test_observed_unobserved_and_dynamic_only_sites_are_distinguished(tmp_path):
    harness = FakeHarness(harness_doc())
    result = runner(tmp_path, harness).observe("FUN_0000b4b4")

    assert result.status == "ok" and result.basis == CALLER_GROUNDED and result.observed_entries == 3
    by_site = {s.call_site: s for s in result.call_sites}
    assert by_site["0x0000a068"].status == "OBSERVED" and by_site["0x0000a068"].caller == "FUN_0000a064"
    assert by_site["0x0000a068"].call_kind == "BL" and by_site["0x0000a068"].static_target_match is True
    # Never reached in the scenario: reported, with no values, and not as unreachable.
    assert by_site["0x0000b662"].status == "UNOBSERVED" and by_site["0x0000b662"].arguments == {}
    assert by_site["0x0000c000"].status == "DYNAMIC_ONLY" and by_site["0x0000c000"].static_target_match is False
    r0 = by_site["0x0000a068"].arguments["r0"][0]
    assert (r0.value, r0.region, r0.pointee_word, r0.pointee_word_region) == ("0x20004c54", "RAM", "0x41012000", "MMIO")
    assert by_site["0x0000c000"].arguments["r0"][0].register_name == "SERCOM0.CTRLA"
    assert "never reached: 0x0000b662" in result.coverage and "not thereby impossible" in result.coverage
    assert result.mmio_in_function["access_count"] == 0
    assert "heuristic" in result.mmio_in_function["extent_source"]
    assert [a["kind"] for a in result.harness_assumptions] == ["force_reg", "fake_tick"]
    # The request carried only the entry and APTrace-derived extent.
    assert harness.argv[0][-4:] == ["--entry", "0xb4b4", "--extent", "0xb4b4:0xb500"]
    text = planner_summary(result)
    assert "UNOBSERVED (not reached; not unreachable)" in text and "0x20004c54(RAM)->*=0x41012000" in text


def test_caller_grounded_and_hypothetical_evidence_stay_distinct():
    observed = {"status": "ok", "observed_entries": 2, "call_sites": [], "harness_assumptions": [{}]}
    grade, basis = evidence_grade("observed_call_arguments", observed)
    assert grade == EvidenceGrade.STRONG and "concrete execution" in basis

    # A specialized function_effects result is solver-derived under a chosen
    # input; it never acquires the caller-grounded basis.
    effects = {"status": "complete", "specialize": {"r0": "0x40003000"}}
    effects_grade, effects_basis = evidence_grade("function_effects", effects)
    assert effects_grade == EvidenceGrade.STRONG and "symbolic" in effects_basis
    assert "concrete" not in effects_basis
    assert CALLER_GROUNDED not in json.dumps(effects)
    codes = dict(evidence_limitations("function_effects", {"function": "FUN_0000b4b4", "specialize": {"r0": 0x40003000}}, effects))
    assert "r0=0x40003000" in codes[HYPOTHETICAL_SPECIALIZATION] and "not caller-grounded" in codes[HYPOTHETICAL_SPECIALIZATION]
    plain = dict(evidence_limitations("function_effects", {"function": "FUN_0000b4b4", "specialize": {}}, {"status": "complete"}))
    assert HYPOTHETICAL_SPECIALIZATION not in plain


def test_grades_and_limitations():
    ok = harness_doc()
    result = {"status": "ok", "observed_entries": 3, "harness_assumptions": ok["recipe"]["assumptions"],
              "call_sites": [{"call_site": "0x0000b662", "status": "UNOBSERVED"}], "mmio_in_function": {"access_count": 0}}
    codes = dict(evidence_limitations("observed_call_arguments", {}, result))
    assert {HARNESS_ASSUMPTIONS, OBSERVED_CONTEXTS_ONLY, UNOBSERVED_CALL_SITES} <= set(codes)
    assert "2 disclosed" in codes[HARNESS_ASSUMPTIONS] and "0x0000b662" in codes[UNOBSERVED_CALL_SITES]

    assert evidence_grade("observed_call_arguments", {"status": "ok", "observed_entries": 0})[0] == EvidenceGrade.BOUNDED
    assert evidence_grade("observed_call_arguments", {"status": "failed"})[0] == EvidenceGrade.UNKNOWN
    truncated = {"status": "bounded: entry watch cap reached", "observed_entries": 5, "call_sites": []}
    assert evidence_grade("observed_call_arguments", truncated)[0] == EvidenceGrade.STRONG
    assert OBSERVATION_TRUNCATED in dict(evidence_limitations("observed_call_arguments", {}, truncated))


@pytest.mark.parametrize(
    "harness, kwargs, status",
    [
        (FakeHarness(raises=subprocess.TimeoutExpired("x", 300)), {}, "bounded: timeout 300s"),
        (FakeHarness(returncode=1, stderr="Traceback\nUcError: unsupported instruction"), {}, "failed"),
        (FakeHarness("not json"), {}, "failed"),
        (FakeHarness(harness_doc()), {"sha": "0" * 64}, "firmware_unavailable"),
        (FakeHarness(harness_doc()), {"python": False}, "harness_unavailable"),
    ],
)
def test_failures_are_recorded_not_concluded(tmp_path, harness, kwargs, status):
    result = runner(tmp_path, harness, **kwargs).observe("FUN_0000b4b4")
    assert result.status == status
    assert result.call_sites == [] and result.observed_entries == 0
    assert evidence_grade("observed_call_arguments", result.model_dump(mode="json"))[0] == EvidenceGrade.UNKNOWN
    if status == "failed" and harness.stderr:
        assert "unsupported instruction" in result.planner_summary


def test_foreign_firmware_document_is_rejected(tmp_path):
    with pytest.raises(RuntimeError):
        runner(tmp_path, FakeHarness(harness_doc(firmware_sha256="f" * 64))).observe("FUN_0000b4b4")


def test_request_validation(tmp_path):
    r = runner(tmp_path, FakeHarness(harness_doc()))
    with pytest.raises(ObservationInputError):
        r.observe("E0000b4b4")
    with pytest.raises(ObservationInputError):
        r.observe("FUN_0000dead")


def test_ledger_records_replays_and_keys_on_harness_inputs(tmp_path):
    ledger, executor, context, ops = stack(tmp_path)
    context.artifacts.update({"boot_recipe": "d" * 64, "unicorn_harness": "e" * 64, "call_observation": "f" * 64})
    doc = runner(tmp_path, FakeHarness(harness_doc())).observe("FUN_0000b4b4").model_dump(mode="json")
    executor.drift["observed_call_arguments"] = doc

    invocation, artifact = ops.run("R-test", "observed_call_arguments", {"function": "FUN_0000b4b4"})
    assert invocation.status == "ok" and invocation.replayable
    assert set(invocation.input_artifacts) == set(TOOL_INPUTS["observed_call_arguments"])
    assert artifact.grade == EvidenceGrade.STRONG
    assert {l.code for l in artifact.limitations} >= {HARNESS_ASSUMPTIONS, OBSERVED_CONTEXTS_ONLY, UNOBSERVED_CALL_SITES}

    replay = ops.replay(invocation.invocation_id, run_id="R-replay")
    assert replay.matches and not replay.input_drift

    # A changed boot recipe is a different operation; an unrelated tool's identity is untouched.
    effects_key = ResearchLedger.operation_key("function_effects", {"function": "FUN_0000b4b4"},
                                               {k: context.artifacts[k] for k in TOOL_INPUTS["function_effects"]}, FIRMWARE)
    context.artifacts["boot_recipe"] = "0" * 64
    again, _ = ops.run("R-test2", "observed_call_arguments", {"function": "FUN_0000b4b4"})
    assert again.operation_key != invocation.operation_key
    assert ResearchLedger.operation_key("function_effects", {"function": "FUN_0000b4b4"},
                                        {k: context.artifacts[k] for k in TOOL_INPUTS["function_effects"]}, FIRMWARE) == effects_key


def test_historical_reuse_requires_the_current_analysis_version(tmp_path):
    ledger, executor, context, ops = stack(tmp_path)
    context.artifacts.update({"boot_recipe": "d" * 64, "unicorn_harness": "e" * 64, "call_observation": "f" * 64})
    doc = runner(tmp_path, FakeHarness(harness_doc())).observe("FUN_0000b4b4").model_dump(mode="json")
    executor.drift["observed_call_arguments"] = doc
    _, artifact = ops.run("R-test", "observed_call_arguments", {"function": "FUN_0000b4b4"})

    current = HistoricalOperations(ledger, context(), run_ids=[], evidence_ids=[artifact.evidence_id])
    decision = current.lookup("observed_call_arguments", {"function": "FUN_0000b4b4"})
    assert decision is not None and decision.reusable

    newer = HistoricalOperations(ledger, context(), run_ids=[], evidence_ids=[artifact.evidence_id],
                                 analysis_versions={"observed_call_arguments": 2})
    refused = newer.lookup("observed_call_arguments", {"function": "FUN_0000b4b4"})
    assert refused is not None and not refused.reusable and "analysis version" in refused.reason


def test_existing_tool_grades_are_unchanged():
    assert evidence_grade("function_effects", {"status": "complete"}) == (EvidenceGrade.STRONG, "symbolic extraction, not solver-confirmed")
    assert evidence_grade("census_peripheral_usage", {"status": "ok"})[0] == EvidenceGrade.STRONG
    assert FunctionEffectsRunner  # the hypothetical path is the existing analysis, untouched
