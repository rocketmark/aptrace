"""APTrace census reduce: deterministic library/platform fingerprinting.

No external reference library is vendored in this repo, so the
strongest available ground truth is the OTHER firmware images already
in this same census database: `autopilot868`/`autopilot915` (near-
identical products, different RF frequency) and `mando868`/`mando915`
share a compiler, a C/C++ runtime, and very likely a common Arduino-
core/CMSIS/driver layer with the AutoPilot images, even though their
application logic differs. A function that is byte-identical (or
instruction-shape-identical) across two of these images is strong,
mechanical evidence it's shared platform/library code, not
application-specific logic -- no naming/intuition involved.

Four confidence tiers, in order of how the check was made:

  EXACT            -- byte-identical to a function in a DIFFERENT
                       firmware image (`exact_hash` match), OR Ghidra
                       itself marked the function a thunk (`thunk=1`,
                       already a mechanical fact this project's own
                       Ghidra export captures -- see
                       tools/ghidra/scripts/APTraceExportStaticAnalysis.java).
  STRONG_MATCH      -- identical (mnemonic, normalized-operand) token
                       sequence to a function in a different image
                       (`normalized_hash` match) -- same code shape,
                       differing only in embedded immediates/addresses
                       (e.g. a relocated literal-pool constant).
  POSSIBLE_MATCH    -- no hash match, but same basic-block count, same
                       (Ghidra-sourced) edge count, same callee count,
                       and byte size within 10%, against a function in
                       a different image -- a real structural
                       similarity, weaker than a hash match.
  NO_MATCH          -- none of the above.

Every row names its `method` and, where applicable, exactly which
function in which OTHER firmware image it matched -- so a later human/
LLM phase can always verify the claim directly rather than trust a
label.
"""
import re
import hashlib

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

_IMM_RE = re.compile(r"#-?0x[0-9a-fA-F]+|#-?\d+")
_ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{4,8}\b")


def _normalize_op_str(op_str):
    s = _IMM_RE.sub("#IMM", op_str)
    s = _ADDR_RE.sub("ADDR", s)
    return s


def _md():
    m = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    return m


def compute_fingerprints(conn, firmware_id, firmware_bytes, flash_base):
    md = _md()
    rows = conn.execute(
        "SELECT f.id AS function_id, f.entry, f.size, "
        "(SELECT COUNT(*) FROM basic_blocks b WHERE b.function_id=f.id) AS block_count, "
        "(SELECT COUNT(*) FROM edges e WHERE e.from_function_id=f.id AND e.resolved=1 "
        " AND e.source LIKE 'ghidra%') AS edge_count, "
        "(SELECT COUNT(DISTINCT e2.to_function_id) FROM edges e2 WHERE e2.from_function_id=f.id "
        " AND e2.kind LIKE '%call%' AND e2.to_function_id IS NOT NULL) AS callee_count "
        "FROM functions f WHERE f.firmware_id=?", (firmware_id,)).fetchall()

    out = []
    for r in rows:
        off = r["entry"] - flash_base
        size = max(r["size"], 0)
        chunk = firmware_bytes[off:off + size]
        exact_hash = hashlib.sha256(chunk).hexdigest()
        tokens = []
        for insn in md.disasm(chunk, r["entry"]):
            tokens.append(f"{insn.mnemonic} {_normalize_op_str(insn.op_str)}")
        normalized_hash = hashlib.sha256("\n".join(tokens).encode()).hexdigest() if tokens else None
        out.append({
            "firmware_id": firmware_id, "function_id": r["function_id"], "exact_hash": exact_hash,
            "normalized_hash": normalized_hash, "byte_size": size, "block_count": r["block_count"],
            "edge_count": r["edge_count"], "callee_count": r["callee_count"], "source": "fingerprint",
        })

    from db import replace_firmware_rows
    replace_firmware_rows(conn, firmware_id, "function_fingerprints", out)
    conn.commit()
    return out


def _family(firmware_key):
    """Strip a trailing digit run: 'autopilot868'/'autopilot915' ->
    'autopilot', 'mando868'/'mando915' -> 'mando'. A same-family match
    (a frequency-variant sibling of the SAME product) proves the
    matched function's bytes/shape are frequency-invariant -- real
    evidence, but NOT evidence of "platform/library plumbing vs
    application logic": this firmware's own motor-control or protocol-
    dispatch logic is just as likely to be byte-identical to its own
    915 sibling as any CMSIS/Arduino-core helper is. Only a
    CROSS-family match (autopilot vs mando -- a genuinely different
    product) is treated as real platform/library evidence -- see
    `method`'s '-same-product' suffix below and
    docs/tooling/census.md."""
    i = len(firmware_key)
    while i > 0 and firmware_key[i - 1].isdigit():
        i -= 1
    return firmware_key[:i]


def compute_matches(conn, firmware_id, firmware_key):
    """Cross-reference this firmware's fingerprints against every OTHER
    firmware image already present in the same database. Prefers a
    cross-product-family match over a same-family (frequency-variant
    sibling) match at the same confidence tier -- see `_family`."""
    my_family = _family(firmware_key)

    mine = conn.execute(
        "SELECT fp.*, fn.thunk, fn.name FROM function_fingerprints fp "
        "JOIN functions fn ON fn.id = fp.function_id WHERE fp.firmware_id=?",
        (firmware_id,)).fetchall()

    other_by_exact = {}
    other_by_norm = {}
    other_structural = []  # (firmware_key, function_id, name, block_count, edge_count, callee_count, byte_size)
    for row in conn.execute(
            "SELECT fp.*, fw.key AS firmware_key, fn.name AS fname FROM function_fingerprints fp "
            "JOIN firmware fw ON fw.id = fp.firmware_id "
            "JOIN functions fn ON fn.id = fp.function_id "
            "WHERE fp.firmware_id != ? ORDER BY fw.key, fp.function_id", (firmware_id,)):
        other_by_exact.setdefault(row["exact_hash"], []).append(row)
        if row["normalized_hash"]:
            other_by_norm.setdefault(row["normalized_hash"], []).append(row)
        other_structural.append(row)

    def sort_key(r):
        # Cross-family first (False sorts before True), then deterministic tie-break.
        return (_family(r["firmware_key"]) == my_family, r["firmware_key"], r["function_id"])

    def method_name(base, matched_key):
        return base if _family(matched_key) != my_family else f"{base}-same-product"

    out = []
    for m in mine:
        if m["thunk"]:
            out.append({
                "firmware_id": firmware_id, "function_id": m["function_id"], "confidence": "EXACT",
                "method": "ghidra-thunk", "matched_firmware_key": None, "matched_function_id": None,
                "matched_function_name": None, "source": "fingerprint",
            })
            continue

        exact_hits = sorted(other_by_exact.get(m["exact_hash"], []), key=sort_key)
        if exact_hits:
            best = exact_hits[0]
            out.append({
                "firmware_id": firmware_id, "function_id": m["function_id"], "confidence": "EXACT",
                "method": method_name("exact-byte-hash", best["firmware_key"]), "matched_firmware_key": best["firmware_key"],
                "matched_function_id": best["function_id"], "matched_function_name": best["fname"],
                "source": "fingerprint",
            })
            continue

        norm_hits = sorted(other_by_norm.get(m["normalized_hash"], []), key=sort_key) \
            if m["normalized_hash"] else []
        if norm_hits:
            best = norm_hits[0]
            out.append({
                "firmware_id": firmware_id, "function_id": m["function_id"], "confidence": "STRONG_MATCH",
                "method": method_name("normalized-instruction-hash", best["firmware_key"]),
                "matched_firmware_key": best["firmware_key"],
                "matched_function_id": best["function_id"], "matched_function_name": best["fname"],
                "source": "fingerprint",
            })
            continue

        candidates = [
            r for r in other_structural
            if r["block_count"] == m["block_count"] and r["edge_count"] == m["edge_count"]
            and r["callee_count"] == m["callee_count"] and m["byte_size"] > 0
            and abs(r["byte_size"] - m["byte_size"]) <= max(1, m["byte_size"] * 0.10)
        ]
        if candidates:
            candidates.sort(key=lambda r: (_family(r["firmware_key"]) == my_family,
                                             abs(r["byte_size"] - m["byte_size"]), r["firmware_key"], r["function_id"]))
            best = candidates[0]
            out.append({
                "firmware_id": firmware_id, "function_id": m["function_id"], "confidence": "POSSIBLE_MATCH",
                "method": method_name("structural-similarity", best["firmware_key"]),
                "matched_firmware_key": best["firmware_key"],
                "matched_function_id": best["function_id"], "matched_function_name": best["fname"],
                "source": "fingerprint",
            })
            continue

        out.append({
            "firmware_id": firmware_id, "function_id": m["function_id"], "confidence": "NO_MATCH",
            "method": "none", "matched_firmware_key": None, "matched_function_id": None,
            "matched_function_name": None, "source": "fingerprint",
        })

    # reference_source_confirmed/reference_source_citation are set by a
    # DIFFERENT authority (reference_library.py, run after this in
    # reduce.py's own pipeline) -- this function rebuilds library_matches
    # from scratch every time it runs (including via recompute_all_matches,
    # triggered by fingerprinting ANY other firmware), so an existing
    # confirmation must be carried forward here or a later firmware's
    # reduce would silently wipe an earlier firmware's own confirmations.
    existing_confirmed = {
        row["function_id"]: (row["reference_source_confirmed"], row["reference_source_citation"])
        for row in conn.execute(
            "SELECT function_id, reference_source_confirmed, reference_source_citation "
            "FROM library_matches WHERE firmware_id=? AND reference_source_confirmed=1", (firmware_id,))
    }
    for row in out:
        confirmed, citation = existing_confirmed.get(row["function_id"], (0, None))
        row["reference_source_confirmed"] = confirmed
        row["reference_source_citation"] = citation

    from db import replace_firmware_rows
    replace_firmware_rows(conn, firmware_id, "library_matches", out)
    conn.commit()
    return out


def recompute_all_matches(conn):
    """Cross-image matching is order-dependent (a firmware reduced
    before its siblings has nothing to match against yet) -- call this
    after fingerprinting ANY firmware so every already-fingerprinted
    image's matches reflect the CURRENT full set, not just what existed
    when it was first reduced. Cheap (no re-disassembly, just dict
    lookups) even across all four known images."""
    firmwares = conn.execute(
        "SELECT DISTINCT fw.id, fw.key FROM firmware fw "
        "JOIN function_fingerprints fp ON fp.firmware_id = fw.id ORDER BY fw.key").fetchall()
    for row in firmwares:
        compute_matches(conn, row["id"], row["key"])
