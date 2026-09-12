#!/usr/bin/env python3
"""Regression coverage for tools/census/macaw_compare.py's handling of
`normalized_terminators` (APTrace.MacawExpand's macaw-normalized
resolutions, fed back into Macaw's own discovery via
`addDiscoveredFunctionBlockTargets` -- see src/APTrace/MacawExpand.hs).
Same convention as tools/census/test_reduce.py -- plain assertions, not
pytest:

    tools/unicorn/.venv/bin/python3 tools/census/test_macaw_compare.py

Covers, against small synthetic Macaw JSON documents and (where a DB is
needed) a scratch sqlite3 database built from the real schema -- never the
real census.sqlite3:

  * normalized_terminators are exposed as their own CFG edge source,
    never merged into or mistaken for ordinary `edges` (base Macaw
    evidence stays base Macaw evidence).
  * a `classify_failure` block that also has a `normalized_terminators`
    resolution is excluded from the "Macaw unresolved" classify_failure
    analysis (it is proven CFG evidence, not an open failure) -- while an
    ordinary, un-normalized classify_failure is still analyzed exactly as
    before.
"""
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import db as census_db  # noqa: E402
import macaw_compare as mc  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def _scratch_db():
    d = tempfile.TemporaryDirectory()
    conn = census_db.connect(Path(d.name) / "scratch.sqlite3")
    return d, conn


def _make_firmware(conn, key="scratch"):
    conn.execute(
        "INSERT INTO firmware (key, path, sha256, flash_base, size_bytes, ram_base, ram_size, "
        "mmio_base, mmio_size, built_at) VALUES (?,'x','y',0x4000,1000,0x20000000,0x1000,0x40000000,0x1000,'now')",
        (key,))
    conn.commit()
    return census_db.get_firmware_id(conn, key)


def _synthetic_macaw(normalized_terminators, incomplete_or_unresolved_terminators):
    """The minimal subset of a real `aptrace macaw-census`(-expand) JSON
    document the functions under test actually read."""
    return {
        "firmware": {"flash_base": "0x00004000", "ram_base": "0x20000000", "ram_size": "0x1000"},
        "roots": [],
        "functions": [{"entry": "0x00001000", "is_root": True, "block_count": 1}],
        "basic_blocks": [{"function_entry": "0x00001000", "block_start": "0x00001000", "size": 10,
                           "terminator_kind": "classify_failure"}],
        "edges": [],
        "calls": [],
        "incomplete_or_unresolved_terminators": incomplete_or_unresolved_terminators,
        "normalized_terminators": normalized_terminators,
    }


# ---------------------------------------------------------------------
# normalized_terminators are separate CFG evidence, never base edges
# ---------------------------------------------------------------------

def test_normalized_edges_kept_separate_from_base_edges():
    print("test_normalized_edges_kept_separate_from_base_edges")
    macaw = _synthetic_macaw(
        normalized_terminators=[
            {"function_entry": "0x00001000", "block_start": "0x00001000",
             "targets": ["0x00001010", "0x00001020"], "provenance": "macaw-normalized"},
        ],
        incomplete_or_unresolved_terminators=[
            {"function_entry": "0x00001000", "block_start": "0x00001000",
             "kind": "classify_failure", "detail": ["IP is not a mux"]},
        ],
    )

    # The block has NO ordinary `edges` entries at all (Macaw keeps it as
    # ClassifyFailure -- see APTrace.MacawExpand's module docstring) --
    # confirm the existing base-edge reader sees nothing here.
    base_jump_edges = mc.macaw_edges_by_function(macaw, mc._MACAW_JUMP_KINDS)
    base_targets = {t for edges in base_jump_edges.values() for (_s, _e, t, _k) in edges}
    check("base (ordinary) edges do not contain the normalized targets",
          0x1010 not in base_targets and 0x1020 not in base_targets,
          f"base_targets={base_targets!r}")

    # The dedicated normalized-edge reader DOES see them, tagged with a
    # kind that is clearly not one of Macaw's own terminator-classifier
    # kinds (never relabeled as e.g. "branch_true"/"jump").
    norm_edges = mc.macaw_normalized_edges_by_function(macaw)
    norm_targets = {t for edges in norm_edges.values() for (_s, _e, t, _k) in edges}
    norm_kinds = {k for edges in norm_edges.values() for (_s, _e, _t, k) in edges}
    check("normalized-edge reader recovers both supplied targets",
          norm_targets == {0x1010, 0x1020}, f"norm_targets={norm_targets!r}")
    check("normalized edges are tagged with a distinct, non-base kind",
          norm_kinds == {"macaw-normalized"}, f"norm_kinds={norm_kinds!r}")


# ---------------------------------------------------------------------
# classify_failure analysis excludes already-normalized blocks
# ---------------------------------------------------------------------

def test_classify_failure_analysis_excludes_normalized():
    print("test_classify_failure_analysis_excludes_normalized")
    d, conn = _scratch_db()
    try:
        fw = _make_firmware(conn)
        # One Ghidra basic block covering both synthetic classify_failure
        # addresses below, with a resolved outgoing edge -- so an
        # un-normalized failure at this address would be reported
        # "ghidra_resolved".
        conn.execute(
            "INSERT INTO basic_blocks (firmware_id, start_addr, end_addr, function_id, source) "
            "VALUES (?, 0x1000, 0x100f, NULL, 'ghidra-basicblockmodel')", (fw,))
        conn.execute(
            "INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, source) "
            "VALUES (?, 0x1000, 0x1010, 'cbranch', 1, 'ghidra-basicblockmodel')", (fw,))
        conn.commit()

        macaw = _synthetic_macaw(
            normalized_terminators=[
                {"function_entry": "0x00001000", "block_start": "0x00001000",
                 "targets": ["0x00001010", "0x00001020"], "provenance": "macaw-normalized"},
            ],
            incomplete_or_unresolved_terminators=[
                {"function_entry": "0x00001000", "block_start": "0x00001000",
                 "kind": "classify_failure", "detail": ["IP is not a mux"]},
            ],
        )
        result = mc.analyze_macaw_classify_failures(conn, fw, macaw)
        check("an already-normalized classify_failure is excluded from the analysis",
              len(result["blocks"]) == 0, f"blocks={result['blocks']!r}")

        # Sanity check the exclusion is targeted, not a blanket skip: an
        # ordinary, un-normalized classify_failure at a different address
        # is still analyzed exactly as before.
        macaw_unnormalized = _synthetic_macaw(
            normalized_terminators=[],
            incomplete_or_unresolved_terminators=[
                {"function_entry": "0x00001000", "block_start": "0x00001000",
                 "kind": "classify_failure", "detail": ["IP is not a mux"]},
            ],
        )
        result2 = mc.analyze_macaw_classify_failures(conn, fw, macaw_unnormalized)
        check("an ordinary (non-normalized) classify_failure is still analyzed",
              len(result2["blocks"]) == 1 and result2["blocks"][0]["status"] == "ghidra_resolved",
              f"blocks={result2['blocks']!r}")
    finally:
        conn.close()
        d.cleanup()


# ---------------------------------------------------------------------
# normalized-vs-Ghidra comparison must include fallthrough: a two-way
# conditional branch's Ghidra evidence is commonly split cbranch+fallthrough
# (see the 0x4b64/0x4ba2 false-disagreement investigation)
# ---------------------------------------------------------------------

def test_normalized_two_way_branch_agrees_with_cbranch_plus_fallthrough():
    print("test_normalized_two_way_branch_agrees_with_cbranch_plus_fallthrough")
    # Macaw normalized targets = {A, B}; Ghidra's real evidence for the
    # very same conditional branch is split across two edge kinds:
    # cbranch -> B (taken) and fallthrough -> A (not taken).
    a, b = 0x2000, 0x2010
    macaw = _synthetic_macaw(
        normalized_terminators=[
            {"function_entry": "0x00001000", "block_start": "0x00001000",
             "targets": [hex(a), hex(b)], "provenance": "macaw-normalized"},
        ],
        incomplete_or_unresolved_terminators=[
            {"function_entry": "0x00001000", "block_start": "0x00001000",
             "kind": "classify_failure", "detail": ["IP is not a mux"]},
        ],
    )
    ghidra_rows = [
        {"from_addr": 0x1000, "to_addr": b, "kind": "cbranch", "resolved": 1, "fn_entry": 0x1000},
        {"from_addr": 0x1000, "to_addr": a, "kind": "fallthrough", "resolved": 1, "fn_entry": 0x1000},
    ]
    macaw_norm_edges = mc.macaw_normalized_edges_by_function(macaw)

    # Reproduce the bug first: excluding fallthrough (the old behavior)
    # loses Ghidra's evidence for `a` entirely, so it wrongly falls out as
    # "macaw_only" even though Ghidra does resolve it -- just via a
    # fallthrough edge, which was being discarded before comparison. (In
    # the real 0x4b64/0x4ba2 case, an unrelated third Ghidra edge in the
    # same coarse block additionally supplied a `ghidra_only` entry at the
    # same site, turning this into a reported "genuine disagreement"; the
    # essential defect reproduced here -- losing `a` -- is the same one
    # `genuine_disagreements` was flagging downstream.)
    buggy_cmp = mc.compare_cfg_edges(
        [r for r in ghidra_rows if r["kind"] != "fallthrough"], macaw_norm_edges)
    buggy_macaw_only_targets = {row["target"] for row in buggy_cmp["macaw_only"]}
    check("reproduction: excluding fallthrough loses Ghidra's real evidence for `a`",
          buggy_macaw_only_targets == {a}, f"macaw_only_targets={buggy_macaw_only_targets!r}")

    # The fix (now the actual behavior of build_report's normalized_cmp):
    # include fallthrough -- full agreement, no disagreement.
    fixed_cmp = mc.compare_cfg_edges(ghidra_rows, macaw_norm_edges)
    fixed_disagreements = mc.genuine_disagreements(fixed_cmp)
    check("fix: cbranch+fallthrough together report full agreement",
          {row["target"] for row in fixed_cmp["shared"]} == {a, b}
          and not fixed_cmp["macaw_only"] and not fixed_cmp["ghidra_only"],
          f"shared={fixed_cmp['shared']!r} macaw_only={fixed_cmp['macaw_only']!r} "
          f"ghidra_only={fixed_cmp['ghidra_only']!r}")
    check("fix: zero genuine disagreements",
          len(fixed_disagreements) == 0, f"disagreements={fixed_disagreements!r}")


if __name__ == "__main__":
    test_normalized_edges_kept_separate_from_base_edges()
    test_classify_failure_analysis_excludes_normalized()
    test_normalized_two_way_branch_agrees_with_cbranch_plus_fallthrough()

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
        sys.exit(1)
    print("All checks passed.")
    sys.exit(0)
