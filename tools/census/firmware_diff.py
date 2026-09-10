"""APTrace census: structured, deterministic 868-vs-915 diffs (or any
two firmware images already `census reduce`d in the same database).

Every diff here is a MECHANICAL FACT comparison -- raw hardware_snapshot
register bytes, static mmio_accesses (peripheral, register) site sets,
decoded pin_snapshot fields, residual_priority scores for functions
paired across images by an EXACT function-fingerprint match (byte-
identical code -- the same pairing mechanism boot_recipes.py's sibling
remap already relies on), and flash string/constant literal sets. NO
semantic interpretation of WHY something differs (e.g. "this is the
RF-band-specific part") is attempted here -- see docs/tooling/census.md
's "868 vs 915 diff" section and this module's own callers.

Requires both images to already have `census reduce` run (fingerprints,
hardware_snapshot, pin_snapshot, residual_priority, function_features
all read directly, never recomputed).
"""
import db as census_db


def _fw_pair(conn, key_a, key_b):
    return census_db.get_firmware_id(conn, key_a), census_db.get_firmware_id(conn, key_b)


def _hw_register_diff(conn, fa, fb):
    def regs(fw):
        return {(r["peripheral"], r["register_name"], r["addr"]): r["raw_value"]
                for r in conn.execute("SELECT * FROM hardware_snapshot WHERE firmware_id=?", (fw,))}
    ra, rb = regs(fa), regs(fb)
    diffs = []
    for key in sorted(set(ra) | set(rb)):
        va, vb = ra.get(key), rb.get(key)
        if va != vb:
            diffs.append({"peripheral": key[0], "register": key[1], "addr": f"0x{key[2]:08x}",
                           "value_a": va, "value_b": vb})
    return diffs


def _mmio_site_diff(conn, fa, fb):
    def sites(fw):
        return {(r["peripheral"], r["register_name"]) for r in conn.execute(
            "SELECT DISTINCT peripheral, register_name FROM mmio_accesses WHERE firmware_id=? "
            "AND peripheral IS NOT NULL", (fw,))}
    sa, sb = sites(fa), sites(fb)
    return {
        "only_in_a": [{"peripheral": p, "register": r} for p, r in sorted(sa - sb)],
        "only_in_b": [{"peripheral": p, "register": r} for p, r in sorted(sb - sa)],
    }


def _pin_config_diff(conn, fa, fb):
    def pins(fw):
        return {r["pin_name"]: r for r in conn.execute("SELECT * FROM pin_snapshot WHERE firmware_id=?", (fw,))}
    pa, pb = pins(fa), pins(fb)
    fields = ("direction", "output_value", "input_value", "pincfg_raw", "pmuxen", "pmux_nibble")
    diffs = []
    for name in sorted(set(pa) | set(pb)):
        a, b = pa.get(name), pb.get(name)
        if a is None or b is None:
            diffs.append({"pin_name": name, "only_in": "a" if b is None else "b"})
            continue
        changed = {f: [a[f], b[f]] for f in fields if a[f] != b[f]}
        if changed:
            diffs.append({"pin_name": name, "changed_fields": changed})
    return diffs


def _fingerprint_pairing(conn, fw):
    """exact_hash -> {function_id, entry, name} for one firmware --
    byte-identical code is the pairing key across the two images (the
    SAME EXACT-match mechanism boot_recipes.py's sibling remap uses)."""
    out = {}
    for r in conn.execute(
            "SELECT fp.exact_hash, f.id AS function_id, f.entry, f.name FROM function_fingerprints fp "
            "JOIN functions f ON f.id = fp.function_id WHERE fp.firmware_id=?", (fw,)):
        out[r["exact_hash"]] = {"function_id": r["function_id"], "entry": r["entry"], "name": r["name"]}
    return out


def _residual_diff(conn, fa, fb):
    ha, hb = _fingerprint_pairing(conn, fa), _fingerprint_pairing(conn, fb)
    common = sorted(set(ha) & set(hb))

    def priority(fw, fid):
        row = conn.execute("SELECT score, tier FROM residual_priority WHERE firmware_id=? AND function_id=?",
                            (fw, fid)).fetchone()
        return [row["score"], row["tier"]] if row else None

    tier_diffs = []
    for h in common:
        fida, fidb = ha[h]["function_id"], hb[h]["function_id"]
        pa_, pb_ = priority(fa, fida), priority(fb, fidb)
        if pa_ != pb_:
            tier_diffs.append({
                "exact_hash": h, "entry_a": f"0x{ha[h]['entry']:08x}", "entry_b": f"0x{hb[h]['entry']:08x}",
                "name_a": ha[h]["name"], "name_b": hb[h]["name"], "priority_a": pa_, "priority_b": pb_,
            })

    return {
        "byte_identical_function_count": len(common),
        "only_in_a": [{"entry": f"0x{ha[h]['entry']:08x}", "name": ha[h]["name"]} for h in sorted(set(ha) - set(hb))],
        "only_in_b": [{"entry": f"0x{hb[h]['entry']:08x}", "name": hb[h]["name"]} for h in sorted(set(hb) - set(ha))],
        "residual_priority_diffs": tier_diffs,
    }


def _string_diff(conn, fa, fb):
    def strs(fw):
        return {r["value"] for r in conn.execute("SELECT DISTINCT value FROM strings WHERE firmware_id=?", (fw,))}
    sa, sb = strs(fa), strs(fb)
    return {"only_in_a": sorted(sa - sb), "only_in_b": sorted(sb - sa)}


def _hardware_relevant_constant_diff(conn, fa, fb):
    """For byte-identical (EXACT-fingerprint-paired) functions that ALSO
    touch MMIO, flag pairs whose literal/flash-constant reference COUNT
    (function_features.n_literal_refs -- flash constants + string refs
    combined, already computed) differs -- a real, mechanical, if coarse,
    signal that image-specific data (e.g. a per-band constant table) is
    reached from otherwise-identical hardware-touching code. Deliberately
    NOT a claim about WHICH constant differs or why -- see module
    docstring."""
    ha, hb = _fingerprint_pairing(conn, fa), _fingerprint_pairing(conn, fb)
    common = sorted(set(ha) & set(hb))

    def feat(fw, fid):
        return conn.execute("SELECT n_literal_refs, n_mmio_reads, n_mmio_writes FROM function_features "
                             "WHERE firmware_id=? AND function_id=?", (fw, fid)).fetchone()

    diffs = []
    for h in common:
        fida, fidb = ha[h]["function_id"], hb[h]["function_id"]
        fta, ftb = feat(fa, fida), feat(fb, fidb)
        if fta is None or ftb is None:
            continue
        touches_mmio = (fta["n_mmio_reads"] + fta["n_mmio_writes"] > 0) or \
            (ftb["n_mmio_reads"] + ftb["n_mmio_writes"] > 0)
        if touches_mmio and fta["n_literal_refs"] != ftb["n_literal_refs"]:
            diffs.append({
                "exact_hash": h, "entry_a": f"0x{ha[h]['entry']:08x}", "entry_b": f"0x{hb[h]['entry']:08x}",
                "name_a": ha[h]["name"], "name_b": hb[h]["name"],
                "n_literal_refs_a": fta["n_literal_refs"], "n_literal_refs_b": ftb["n_literal_refs"],
            })
    return diffs


def diff_firmwares(conn, key_a, key_b):
    fa, fb = _fw_pair(conn, key_a, key_b)
    hw_diffs = _hw_register_diff(conn, fa, fb)
    mmio_diffs = _mmio_site_diff(conn, fa, fb)
    pin_diffs = _pin_config_diff(conn, fa, fb)
    residual_diffs = _residual_diff(conn, fa, fb)
    string_diffs = _string_diff(conn, fa, fb)
    constant_diffs = _hardware_relevant_constant_diff(conn, fa, fb)
    return {
        "firmware_a": key_a, "firmware_b": key_b,
        "hardware_register_diffs": hw_diffs,
        "mmio_site_diffs": mmio_diffs,
        "pin_config_diffs": pin_diffs,
        "residual_diffs": residual_diffs,
        "string_constant_diffs": string_diffs,
        "hardware_relevant_constant_diffs": constant_diffs,
        "counts": {
            "hardware_register_diffs": len(hw_diffs),
            "mmio_sites_only_in_a": len(mmio_diffs["only_in_a"]),
            "mmio_sites_only_in_b": len(mmio_diffs["only_in_b"]),
            "pin_config_diffs": len(pin_diffs),
            "functions_only_in_a": len(residual_diffs["only_in_a"]),
            "functions_only_in_b": len(residual_diffs["only_in_b"]),
            "residual_priority_diffs": len(residual_diffs["residual_priority_diffs"]),
            "strings_only_in_a": len(string_diffs["only_in_a"]),
            "strings_only_in_b": len(string_diffs["only_in_b"]),
            "hardware_relevant_constant_diffs": len(constant_diffs),
        },
        "note": "Every diff here is a mechanical fact comparison (raw register bytes, static MMIO site sets, "
                "decoded pin fields, EXACT-fingerprint-paired residual priority/literal-ref counts, string "
                "literal sets) -- no semantic interpretation (e.g. 'this is the RF-band-specific part') is "
                "attempted; see docs/tooling/census.md.",
    }
