"""Structural source agreement and the seeded Ghidra cache the agent reads."""

import json
from pathlib import Path

import pytest

from aptrace_agent.ledger.semantics import evidence_grade, evidence_limitations
from aptrace_agent.source_agreement import (
    AgreementStatus,
    EvidenceRelation,
    GhidraExportSource,
    MacawCensusSource,
    SourceObservation,
    StructuralSourceAgreement,
    classify,
    source_agreement,
)

from ledger_support import CODE, FakeCodeSource


def _obs(source, start=None, end=None, *, blocks=None, available=True, recognizes=True, non_code=False):
    if not available:
        return SourceObservation(source=source, available=False)

    if not recognizes:
        return SourceObservation(source=source, available=True, recognizes_code=False, non_code=non_code)

    return SourceObservation(
        source=source,
        available=True,
        recognizes_code=True,
        function=f"FUN_{start:08x}",
        start=f"0x{start:08x}",
        end=f"0x{end:08x}",
        blocks=[(f"0x{s:08x}", f"0x{e:08x}") for s, e in (blocks or [(start, end)])],
    )


# 3
def test_source_agreement_entity_serialization_round_trips():
    result = source_agreement([FakeCodeSource(n, f) for n, f in CODE.items()], ["0x0000c724", 0xCC14])
    entry = StructuralSourceAgreement.model_validate(result["agreements"][0])

    assert entry.address == "0x0000c724"
    assert entry.observation("census").function == "FUN_0000c724"
    assert StructuralSourceAgreement.model_validate_json(entry.model_dump_json()) == entry
    assert json.loads(json.dumps(result))["status_counts"] == result["status_counts"]
    assert "0x0000c724 PARTIAL_AGREEMENT" in result["planner_summary"]


# 4
def test_exact_agreement():
    entry = classify(0xCCC6, [_obs("census", 0xCCC4, 0xCCCA), _obs("ghidra", 0xCCC4, 0xCCCA), _obs("macaw", 0xCCC4, 0xCCCA)])

    assert entry.status == AgreementStatus.AGREE
    assert entry.relation == EvidenceRelation.CONSISTENT
    assert (entry.function_start_agreement, entry.function_range_agreement, entry.block_agreement) == ("AGREE", "AGREE", "AGREE")
    assert entry.coverage_gaps == []


# 5
def test_partial_block_coverage_is_not_a_contradiction():
    # Macaw's blocks for the handler stop before the indirect branch: a subset.
    entry = classify(0xCC14, [_obs("census", 0xCC14, 0xCC1E), _obs("ghidra", 0xCC14, 0xCC1E), _obs("macaw", 0xCC14, 0xCC1A)])

    assert entry.status == AgreementStatus.PARTIAL_AGREEMENT
    assert entry.relation == EvidenceRelation.CONSISTENT
    assert entry.function_range_agreement == "DIFFER"
    assert entry.block_agreement == "SUBSET"


# 6
def test_function_boundary_disagreement():
    entry = classify(0x5010, [_obs("census", 0x5000, 0x5040), _obs("ghidra", 0x5008, 0x5040)])

    assert entry.status == AgreementStatus.BOUNDARY_DISAGREEMENT
    assert entry.relation == EvidenceRelation.STRUCTURAL_DISAGREEMENT
    assert entry.function_start_agreement == "DISAGREE"

    # Same start, different extents, overlapping-but-unnested blocks.
    overlap = classify(
        0x5004,
        [
            _obs("census", 0x5000, 0x5040, blocks=[(0x5000, 0x5010), (0x5020, 0x5040)]),
            _obs("ghidra", 0x5000, 0x5030, blocks=[(0x5000, 0x5018)]),
        ],
    )
    assert overlap.status == AgreementStatus.BOUNDARY_DISAGREEMENT


# 7
def test_missing_source_is_a_coverage_gap_not_a_contradiction():
    entry = classify(0xC5CC, [_obs("census", 0xC5CC, 0xC706), _obs("ghidra", 0, 0, recognizes=False), _obs("macaw", available=False)])

    assert entry.status == AgreementStatus.SOURCE_MISSING
    assert entry.relation == EvidenceRelation.COVERAGE_GAP
    assert entry.coverage_gaps == ["GHIDRA_COVERAGE_GAP", "MACAW_UNAVAILABLE"]

    # Two sources agree, the third lacks the code: still consistent, with a gap.
    partial = classify(0xC5CC, [_obs("census", 0xC5CC, 0xC706), _obs("ghidra", 0xC5CC, 0xC706), _obs("macaw", 0, 0, recognizes=False)])
    assert partial.status == AgreementStatus.PARTIAL_AGREEMENT
    assert partial.relation == EvidenceRelation.CONSISTENT
    assert partial.coverage_gaps == ["MACAW_COVERAGE_GAP"]


# 8
def test_conflicting_structural_facts_are_classified_distinctly():
    entry = classify(0x6000, [_obs("census", 0x6000, 0x6010), _obs("ghidra", 0x6000, 0x6010), _obs("other", recognizes=False, non_code=True)])

    assert entry.status == AgreementStatus.CONFLICT
    assert entry.relation == EvidenceRelation.CONTRADICTORY_EVIDENCE
    assert "non-code" in entry.disagreement
    assert "OTHER_COVERAGE_GAP" not in entry.coverage_gaps


def test_agreement_grade_and_limitations_are_structural():
    result = source_agreement([FakeCodeSource(n, f) for n, f in CODE.items()], ["0x0000c724"])
    grade, _basis = evidence_grade("structural_source_agreement", result)
    codes = [code for code, _text in evidence_limitations("structural_source_agreement", {}, result)]

    assert grade.value == "STRONG"
    assert "SOURCE_AGREEMENT_IS_STRUCTURAL" in codes
    assert "AGREEMENT_SOURCES_NOT_INDEPENDENT" in codes

    conflict = dict(result, status_counts={"CONFLICT": 1})
    assert evidence_grade("structural_source_agreement", conflict)[0].value == "UNKNOWN"


def test_ghidra_and_macaw_file_sources(tmp_path):
    static = tmp_path / "static.json"
    static.write_text(json.dumps({"functions": [{"name": "usb_label", "entry": "0x0000cc14", "size": 10, "thunk": False}]}))
    blocks = tmp_path / "census_export.json"
    blocks.write_text(json.dumps({"basicBlocks": [{"start": "0x0000cc14", "end": "0x0000cc1d", "functionEntry": "0x0000cc14"}]}))
    macaw = tmp_path / "macaw.json"
    macaw.write_text(json.dumps({"firmware": {"size_bytes": 100}, "basic_blocks": [{"block_start": "0xcc14", "function_entry": "0xcc14", "size": 6}]}))

    ghidra = GhidraExportSource(static, census_export=blocks, version="g").observe(0xCC1A)
    seen = MacawCensusSource(macaw, version="m", expected_size=100)

    assert (ghidra.function, ghidra.start, ghidra.end, ghidra.blocks) == ("usb_label", "0x0000cc14", "0x0000cc1e", [("0x0000cc14", "0x0000cc1e")])
    assert seen.observe(0xCC14).end == "0x0000cc1a"
    assert seen.observe(0xCC1A).recognizes_code is False
    assert MacawCensusSource(macaw, version="m", expected_size=99).observe(0xCC14).available is False
    assert MacawCensusSource(tmp_path / "absent.json", version=None).observe(0xCC14).available is False


def test_ghidra_index_names_labeled_functions_by_entry(tmp_path):
    from aptrace_agent.ghidra_index import GhidraIndex

    export = tmp_path / "export.json"
    export.write_text(
        json.dumps(
            {
                "functions": [
                    {"name": "main__CORE", "entry": "0x0000cd00", "size": 64, "thunk": False, "external": False},
                    {"name": "FUN_0000bc44", "entry": "0x0000bc44", "size": 254, "thunk": False, "external": False},
                ],
                "calls": [{"from": "0x0000cd10", "fromFunction": "main__CORE", "to": "0x0000bc44", "toFunction": "FUN_0000bc44"}],
            }
        )
    )
    index = GhidraIndex(export)

    assert index.function_facts("FUN_0000bc44").callers[0].function == "FUN_0000cd00"
    assert index.function_facts("FUN_0000cd00").callees[0].function == "FUN_0000bc44"


# -- the real seeded Ghidra cache (skipped when not built locally) -------------

REPO = Path(__file__).resolve().parents[2]
CACHE = REPO / "cases" / "performing-rigs" / "research" / "runs" / "ghidra_cache" / "autopilot868"
SEEDS = REPO / "cases" / "performing-rigs" / "research" / "runs" / "ghidra_seeds" / "autopilot868.json"
needs_cache = pytest.mark.skipif(not (CACHE / "meta.json").is_file() or not SEEDS.is_file(), reason="Ghidra cache not built")


def _aptrace_ghidra():
    from aptrace_agent.ghidra_index import _aptrace_ghidra

    return _aptrace_ghidra()


# 1
@needs_cache
def test_generated_seeds_are_part_of_ghidra_cache_identity(tmp_path, monkeypatch):
    from aptrace_agent.ghidra_index import GhidraCacheStale, ghidra_cache_identity

    ag = _aptrace_ghidra()
    current = ghidra_cache_identity("autopilot868")

    assert current["derived_seeds_sha256"] == ag.sha256_of(SEEDS)

    changed = json.loads(SEEDS.read_text())
    changed["seeds"].append({"addr": "0x0000d000", "role": "test-only"})
    (tmp_path / "autopilot868.json").write_text(json.dumps(changed))
    monkeypatch.setattr(ag, "SEEDS_ROOT", tmp_path)

    state, _meta, expected = ag.cache_status("autopilot868")
    assert state == "stale"
    assert expected["derived_seeds_sha256"] != current["derived_seeds_sha256"]

    with pytest.raises(GhidraCacheStale, match="derived_seeds_sha256"):
        ghidra_cache_identity("autopilot868")


# 2
@needs_cache
def test_refreshed_ghidra_export_recognizes_seeded_usb_targets():
    from aptrace_agent.ghidra_index import autopilot_ghidra_index

    index = autopilot_ghidra_index()
    seeded = {int(seed["addr"], 16) for seed in json.loads(SEEDS.read_text())["seeds"]}

    assert index.artifact == CACHE / "static_export.json"
    assert {f"FUN_{a:08x}" for a in seeded} == {"FUN_0000c724", "FUN_0000c5cc"}

    facts = {name: index.function_facts(name) for name in ("FUN_0000cc14", "FUN_0000c724", "FUN_0000c5cc")}
    assert {name: (f.entry, f.size) for name, f in facts.items()} == {
        "FUN_0000cc14": ("0x0000cc14", 10),
        "FUN_0000c724": ("0x0000c724", 6),
        "FUN_0000c5cc": ("0x0000c5cc", 314),
    }
    # c724 forwards to c5cc; the registration call 0xbcda in bc44 reaches the writer.
    assert [(c.function, c.address) for c in facts["FUN_0000c724"].callees] == [("FUN_0000c5cc", "0x0000c726")]
    assert ("FUN_0000bc44", "0x0000bcda") in {(c.function, c.address) for c in index.function_facts("FUN_0000ccc4").callers}
