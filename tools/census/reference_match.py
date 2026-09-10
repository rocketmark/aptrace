"""APTrace census: match every function in a firmware image against the
mechanically-built reference corpus (tools/census/reference_corpus.py),
in strictly decreasing order of defensibility:

  EXACT_BYTES             -- identical compiled code bytes (literal
                              pool excluded on both sides).
  EXACT_INSTRUCTIONS        -- identical decoded (mnemonic, op_str)
                              instruction sequence, raw bytes differ.
  RELOCATION_NORMALIZED       -- identical after masking only
                              relocation-derived operands (real ELF
                              relocations on the reference side; a
                              shape-based heuristic -- direct branch/
                              call targets, bare address-shaped
                              literals -- on the already-linked
                              firmware side).
  PC_RELATIVE_NORMALIZED         -- RELOCATION_NORMALIZED plus PC-
                              relative literal-load offsets masked.
  STRONG_STRUCTURAL                 -- same instruction count, same
                              branch count, byte size within 10% --
                              NEVER sets reference_source_confirmed
                              (see the evidence rule below).
  NO_MATCH                            -- none of the above.

Exact matches are always preferred: this checks tiers in order and
stops at the FIRST tier with any hit, never a looser tier that happens
to also match. See reference_normalize.py for exactly what each tier's
masking does and does not touch.

**Evidence rule**: `reference_matches.reference_source_confirmed=1`
ONLY for a NON-AMBIGUOUS match (exactly one distinct reference symbol,
by (source_file, symbol), at the best tier) at EXACT_BYTES/
EXACT_INSTRUCTIONS/RELOCATION_NORMALIZED/PC_RELATIVE_NORMALIZED.
STRONG_STRUCTURAL and an ambiguous match at ANY tier NEVER set it --
`is_ambiguous=1` and `reference_symbol_id=NULL` disclose the tie rather
than silently picking one candidate (see docs/tooling/census.md).

Self-contained: reads `functions`/firmware bytes directly (does not
depend on `census reduce` having already run `fingerprint.py`) -- so
`reference-match <firmware>` can run on a fresh `census build`, per
this project's own recipe (fetch -> build corpus -> reference-match ->
`census reduce`).
"""
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import reference_normalize as rn  # noqa: E402

TIER_ORDER = ["EXACT_BYTES", "EXACT_INSTRUCTIONS", "RELOCATION_NORMALIZED",
              "PC_RELATIVE_NORMALIZED", "STRONG_STRUCTURAL", "NO_MATCH"]
CONFIRMABLE_TIERS = {"EXACT_BYTES", "EXACT_INSTRUCTIONS", "RELOCATION_NORMALIZED",
                     "PC_RELATIVE_NORMALIZED"}
STRUCTURAL_SIZE_TOLERANCE = 0.10
MAX_CANDIDATES_PER_FUNCTION = 50  # defensive cap on STRONG_STRUCTURAL's bulk-collision case


def function_fingerprint(firmware_bytes, flash_base, entry, size):
    """Same shape as reference_corpus.py's per-symbol fingerprint, but
    for an ALREADY-LINKED firmware function -- no ELF relocation
    records exist, so masking falls back to reference_normalize.py's
    shape-based heuristic (relocated_offsets left empty). Returns None
    if nothing at `entry` decodes (never guesses)."""
    off = entry - flash_base
    chunk = firmware_bytes[off:off + max(size, 0)]
    if not chunk:
        return None
    instructions = rn.trim_trailing_padding(rn.decode_code_bytes(chunk, entry))
    if not instructions:
        return None
    last_off, last_size, _m, _o = instructions[-1]
    consumed = last_off + last_size
    code_bytes = chunk[:consumed]
    fp = rn.fingerprint_instructions(instructions)
    fp["exact_hash"] = hashlib.sha256(code_bytes).hexdigest()
    fp["byte_size"] = len(code_bytes)
    return fp


def compute(conn, firmware_id, firmware_bytes, flash_base, verbose=True):
    from db import replace_firmware_rows

    functions = conn.execute(
        "SELECT id, entry, size, name FROM functions WHERE firmware_id=?", (firmware_id,)).fetchall()
    ref_symbols = conn.execute(
        "SELECT rs.*, rp.pkg_key, rp.name AS pkg_name, rp.version AS pkg_version "
        "FROM reference_symbols rs JOIN reference_packages rp ON rp.id = rs.package_id").fetchall()
    if not ref_symbols:
        if verbose:
            print("  no reference corpus built yet -- run 'reference-corpus build' first")
        return [], []

    by_exact, by_instr, by_reloc, by_pcrel = {}, {}, {}, {}
    for rs in ref_symbols:
        by_exact.setdefault(rs["exact_hash"], []).append(rs)
        by_instr.setdefault(rs["exact_instr_hash"], []).append(rs)
        by_reloc.setdefault(rs["reloc_norm_hash"], []).append(rs)
        by_pcrel.setdefault(rs["pcrel_norm_hash"], []).append(rs)

    match_rows, candidate_rows = [], []
    for f in functions:
        fp = function_fingerprint(firmware_bytes, flash_base, f["entry"], f["size"])
        if fp is None:
            match_rows.append({
                "firmware_id": firmware_id, "function_id": f["id"], "tier": "NO_MATCH",
                "is_ambiguous": 0, "reference_symbol_id": None, "reference_source_confirmed": 0,
                "detail": "no decodable instructions", "source": "reference_match",
            })
            continue

        tier, hits = None, []
        for tier_name, index, key in (
                ("EXACT_BYTES", by_exact, fp["exact_hash"]),
                ("EXACT_INSTRUCTIONS", by_instr, fp["exact_instr_hash"]),
                ("RELOCATION_NORMALIZED", by_reloc, fp["reloc_norm_hash"]),
                ("PC_RELATIVE_NORMALIZED", by_pcrel, fp["pcrel_norm_hash"])):
            found = index.get(key)
            if found:
                tier, hits = tier_name, found
                break

        if tier is None and fp["byte_size"] > 0:
            candidates = [
                rs for rs in ref_symbols
                if rs["n_instructions"] == fp["n_instructions"] and rs["n_branches"] == fp["n_branches"]
                and abs(rs["byte_size"] - fp["byte_size"]) <= max(2, fp["byte_size"] * STRUCTURAL_SIZE_TOLERANCE)
            ]
            if candidates:
                tier, hits = "STRONG_STRUCTURAL", candidates

        if tier is None:
            match_rows.append({
                "firmware_id": firmware_id, "function_id": f["id"], "tier": "NO_MATCH",
                "is_ambiguous": 0, "reference_symbol_id": None, "reference_source_confirmed": 0,
                "detail": None, "source": "reference_match",
            })
            continue

        distinct_symbols = sorted({(h["source_file"], h["symbol"]) for h in hits})
        for h in hits[:MAX_CANDIDATES_PER_FUNCTION]:
            candidate_rows.append({
                "firmware_id": firmware_id, "function_id": f["id"], "reference_symbol_id": h["id"],
                "tier": tier, "detail": f"{h['pkg_name']} {h['pkg_version']} {h['source_file']}:{h['symbol']}",
                "source": "reference_match",
            })
        is_ambiguous = len(distinct_symbols) > 1
        confirmed = (tier in CONFIRMABLE_TIERS) and not is_ambiguous
        best = hits[0] if not is_ambiguous else None
        detail = (f"{best['pkg_name']} {best['pkg_version']} {best['source_file']}:{best['symbol']}" if best else
                  f"{len(distinct_symbols)} distinct reference symbol(s) tied at {tier}: " +
                  ", ".join(f"{sf}:{sy}" for sf, sy in distinct_symbols[:10]) +
                  (f" (+{len(distinct_symbols) - 10} more)" if len(distinct_symbols) > 10 else ""))
        match_rows.append({
            "firmware_id": firmware_id, "function_id": f["id"], "tier": tier,
            "is_ambiguous": int(is_ambiguous), "reference_symbol_id": best["id"] if best else None,
            "reference_source_confirmed": int(confirmed), "detail": detail, "source": "reference_match",
        })

    replace_firmware_rows(conn, firmware_id, "reference_match_candidates", candidate_rows)
    replace_firmware_rows(conn, firmware_id, "reference_matches", match_rows)
    conn.commit()

    if verbose:
        counts = {}
        for m in match_rows:
            counts[m["tier"]] = counts.get(m["tier"], 0) + 1
        n_confirmed = sum(1 for m in match_rows if m["reference_source_confirmed"])
        n_ambiguous = sum(1 for m in match_rows if m["is_ambiguous"])
        print(f"  reference-match: {counts}")
        print(f"  reference_source_confirmed={n_confirmed}  ambiguous={n_ambiguous}")
    return match_rows, candidate_rows


def apply_to_library_matches(conn, firmware_id, verbose=True):
    """Feed `reference_matches.reference_source_confirmed=1` rows (from
    a PRIOR `reference-match <firmware>` run -- this function never
    computes matches itself) into `library_matches.reference_source_
    confirmed` -- the SAME column `reference_library.py`'s curated
    confirmations already set, so every downstream consumer (residual
    exclusion, `census residual`, residual_priority, components) treats
    a mechanically-confirmed reference-source match exactly like a
    curated one, with no separate code path. Called from `census
    reduce`'s own pipeline, AFTER `reference_library.py`'s step, so a
    curated confirmation is never overwritten by a mechanical one (both
    ADD to the same set; neither ever removes the other's row) -- see
    reduce.py. Returns the number of NEWLY-confirmed functions (rows
    that were not already reference_source_confirmed=1)."""
    rows = conn.execute(
        "SELECT rm.function_id, rm.tier, rm.detail, rs.source_file, rs.symbol, rp.name AS pkg_name, "
        "rp.version AS pkg_version, rbv.variant_key, rbv.toolchain_version, rbv.optimize "
        "FROM reference_matches rm "
        "JOIN reference_symbols rs ON rs.id = rm.reference_symbol_id "
        "JOIN reference_packages rp ON rp.id = rs.package_id "
        "JOIN reference_build_variants rbv ON rbv.id = rs.build_variant_id "
        "WHERE rm.firmware_id=? AND rm.reference_source_confirmed=1", (firmware_id,)).fetchall()

    n_new = 0
    for r in rows:
        citation = (
            f"tools/census/reference_match.py mechanical match, tier={r['tier']} -- "
            f"{r['pkg_name']} {r['pkg_version']}, {r['source_file']}:{r['symbol']}, built with "
            f"{r['variant_key']} (arm-none-eabi-gcc {r['toolchain_version']}, {r['optimize']})"
        )
        cur = conn.execute("SELECT id, reference_source_confirmed FROM library_matches WHERE "
                           "firmware_id=? AND function_id=?", (firmware_id, r["function_id"])).fetchone()
        if cur is None:
            conn.execute(
                "INSERT INTO library_matches (firmware_id, function_id, confidence, method, "
                "matched_firmware_key, matched_function_id, matched_function_name, "
                "reference_source_confirmed, reference_source_citation, source) "
                "VALUES (?,?,?,?,?,?,?,1,?,?)",
                (firmware_id, r["function_id"], "EXACT", "reference-source-confirmed", None, None, None,
                 citation, "reference_match"))
            n_new += 1
        elif not cur["reference_source_confirmed"]:
            conn.execute(
                "UPDATE library_matches SET reference_source_confirmed=1, reference_source_citation=? "
                "WHERE id=?", (citation, cur["id"]))
            n_new += 1
        # else: already confirmed (curated or a prior mechanical run) -- leave its existing citation.
    conn.commit()
    if verbose:
        print(f"  {n_new} function(s) newly reference_source_confirmed via mechanical reference-match "
              f"(of {len(rows)} confirmable match(es))")
    return n_new
