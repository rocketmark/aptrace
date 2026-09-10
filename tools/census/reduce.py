"""APTrace census reduce: the closure-reduction layer on top of `census
build`'s base evidence (tools/census/build.py). Orchestrates, in order:

  1. Indirect-edge resolution (indirect_resolve.py) -- classify every
     indirect call/jump instruction (STATICALLY_RESOLVED /
     DYNAMICALLY_OBSERVED / FINITE_CANDIDATE_SET / UNRESOLVED),
     producing extra resolved-target edges reachability can use.
  2. Reachability (reachability.py) -- DEFINITELY_REACHABLE /
     POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT / NO_KNOWN_PATH, from
     mechanically-justified roots only.
  3. Library/platform fingerprinting (fingerprint.py) -- cross-image
     EXACT/STRONG_MATCH/POSSIBLE_MATCH/NO_MATCH against every other
     firmware image already in this database.
  4. Function feature records (features.py) -- one materialized,
     purely-structural row per function.
  5. Component grouping (components.py) -- deterministic connected
     components over reachable functions.
  6. Hardware-init snapshot (hardware_snapshot.py) -- MCU peripheral/
     pin register state at a well-defined (and honestly-labeled) point.

Requires `census build <firmware>` to have already run (this module
reads, never recomputes, the base evidence tables) -- see
docs/tooling/census.md.
"""
import datetime
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO_ROOT / "tools" / "ghidra"))

import db as census_db  # noqa: E402
import indirect_resolve  # noqa: E402
import reachability  # noqa: E402
import fingerprint  # noqa: E402
import features  # noqa: E402
import components  # noqa: E402
import hardware_snapshot  # noqa: E402
import pins as pins_mod  # noqa: E402
import aptrace_ghidra as ghidra  # noqa: E402
from build import FunctionRanges  # noqa: E402


def _hx(s):
    return int(s, 16)


def resolve_indirect_edges(conn, firmware_id, firmware_key, firmware_bytes, flash_base, func_ranges, verbose):
    rows = conn.execute(
        "SELECT DISTINCT from_addr FROM edges WHERE firmware_id=? AND kind LIKE 'computed%'",
        (firmware_id,)).fetchall()
    from_addrs = [r["from_addr"] for r in rows]
    if verbose:
        print(f"  [indirect-resolve] {len(from_addrs)} unique indirect-flow instruction(s)")

    resolutions = {}
    candidates = []
    reg_indirect_pending = {}

    for from_addr in from_addrs:
        already_resolved = conn.execute(
            "SELECT to_addr, source FROM edges WHERE firmware_id=? AND from_addr=? AND resolved=1",
            (firmware_id, from_addr)).fetchall()
        mnem, shape, reg = indirect_resolve.decode_instruction(firmware_bytes, flash_base, from_addr)
        from_fid = func_ranges.containing(from_addr)

        if already_resolved:
            classification = "STATICALLY_RESOLVED"
            for e in already_resolved:
                fid = func_ranges.containing(e["to_addr"])
                candidates.append({
                    "firmware_id": firmware_id, "from_addr": from_addr, "candidate_addr": e["to_addr"],
                    "candidate_function_id": fid, "confidence": "EXACT", "source": e["source"],
                })
            note = None
        else:
            table_candidates = []
            if shape == "table-branch":
                entry_width = 1 if mnem.startswith("tbb") else 2
                base_for_offset = from_addr + 4  # TBB/TBH are 32-bit (4-byte) Thumb-2 instructions
                table_candidates = indirect_resolve.scan_halfword_table(
                    firmware_bytes, flash_base, base_for_offset, entry_width, base_for_offset)
                note = f"TBB/TBH inline table at 0x{base_for_offset:08x}, {len(table_candidates)} entr{'y' if len(table_candidates)==1 else 'ies'}"
            elif shape == "mem-indirect":
                table_base = indirect_resolve.nearby_literal_table_base(conn, firmware_id, from_addr)
                if table_base is not None:
                    table_candidates = indirect_resolve.scan_pointer_table(firmware_bytes, flash_base, table_base)
                    note = f"candidate table at 0x{table_base:08x} (nearest preceding literal ref in the same block), {len(table_candidates)} entr{'y' if len(table_candidates)==1 else 'ies'}"
                else:
                    note = "mem-indirect (LDR into PC) with no nearby resolved literal-pool table base"
            elif shape == "reg-indirect":
                note = f"register-indirect via {reg} -- target is runtime state (e.g. a vtable/object pointer), no static table to scan"
            else:
                note = f"unrecognized indirect-flow shape (mnemonic={mnem!r})"

            if table_candidates:
                classification = "FINITE_CANDIDATE_SET"
                for idx, target in table_candidates:
                    fid = func_ranges.containing(target)
                    candidates.append({
                        "firmware_id": firmware_id, "from_addr": from_addr, "candidate_addr": target,
                        "candidate_function_id": fid, "confidence": "STRONG" if fid is not None else "WEAK",
                        "source": "flash-table-scan",
                    })
            else:
                classification = "UNRESOLVED"

            if shape == "reg-indirect" and reg:
                reg_indirect_pending[from_addr] = reg

        resolutions[from_addr] = {
            "firmware_id": firmware_id, "from_addr": from_addr, "from_function_id": from_fid,
            "instr_mnemonic": mnem, "instr_shape": shape, "classification": classification,
            "note": note, "source": "indirect-resolve",
        }

    if reg_indirect_pending:
        if verbose:
            print(f"  [indirect-resolve] replaying the Unicorn scenario corpus to watch "
                  f"{len(reg_indirect_pending)} register-indirect site(s)...")
        dynamic_hits = indirect_resolve.dynamic_candidates(firmware_key, reg_indirect_pending, verbose=verbose)
        end = flash_base + len(firmware_bytes)
        for from_addr, hits in dynamic_hits.items():
            seen = set()
            any_valid = False
            for val, scenario in hits:
                if val & 1 == 0 or not (flash_base <= (val & ~1) < end):
                    continue
                target = val & ~1
                key = (target, scenario)
                if key in seen:
                    continue
                seen.add(key)
                any_valid = True
                fid = func_ranges.containing(target)
                candidates.append({
                    "firmware_id": firmware_id, "from_addr": from_addr, "candidate_addr": target,
                    "candidate_function_id": fid, "confidence": "EXACT", "source": f"dynamic-observed:{scenario}",
                })
            if any_valid:
                resolutions[from_addr]["classification"] = "DYNAMICALLY_OBSERVED"
                resolutions[from_addr]["note"] = (resolutions[from_addr]["note"] or "") + \
                    f" -- {len(seen)} distinct target(s) actually observed at runtime"

    census_db.replace_firmware_rows(conn, firmware_id, "indirect_edge_resolutions", list(resolutions.values()))
    census_db.replace_firmware_rows(conn, firmware_id, "indirect_edge_candidates", candidates)
    conn.commit()

    counts = {}
    for r in resolutions.values():
        counts[r["classification"]] = counts.get(r["classification"], 0) + 1
    if verbose:
        print(f"  [indirect-resolve] classification: {counts}")
    return resolutions, candidates


def reduce_firmware(key, db_path=None, verbose=True):
    def log(msg):
        if verbose:
            print(msg)

    conn = census_db.connect(db_path, create=False)
    firmware_id = census_db.get_firmware_id(conn, key)
    census_db.clear_reduction_data(conn, firmware_id)

    fw_row = conn.execute("SELECT * FROM firmware WHERE id=?", (firmware_id,)).fetchone()
    fw_path, _flash_base_s, _labels = ghidra.firmware_info(key)
    firmware_bytes = fw_path.read_bytes()
    flash_base = fw_row["flash_base"]

    func_ranges = FunctionRanges(conn.execute(
        "SELECT id, entry, size FROM functions WHERE firmware_id=?", (firmware_id,)).fetchall())

    log(f"=== census reduce: {key} ===")
    log("[1/6] Resolving indirect control flow...")
    resolve_indirect_edges(conn, firmware_id, key, firmware_bytes, flash_base, func_ranges, verbose)

    log("[2/6] Computing reachability...")
    reach_rows = reachability.compute(conn, firmware_id, func_ranges)
    reach_counts = {}
    for r in reach_rows:
        reach_counts[r["status"]] = reach_counts.get(r["status"], 0) + 1
    log(f"  reachability: {reach_counts}")

    log("[3/6] Fingerprinting functions...")
    fingerprint.compute_fingerprints(conn, firmware_id, firmware_bytes, flash_base)
    fingerprint.recompute_all_matches(conn)
    lib_counts = {}
    for row in conn.execute(
            "SELECT confidence, COUNT(*) c FROM library_matches WHERE firmware_id=? GROUP BY confidence",
            (firmware_id,)):
        lib_counts[row["confidence"]] = row["c"]
    log(f"  library matches: {lib_counts}")

    log("[4/6] Building function feature records...")
    features.compute(conn, firmware_id)

    log("[5/6] Grouping into components...")
    comp_rows = components.compute(conn, firmware_id)
    log(f"  {len(comp_rows)} component(s)")

    log("[6/6] Taking hardware-init snapshot...")
    svd_map = pins_mod._samd51_map()
    hardware_snapshot.compute(
        conn, firmware_id, key, fw_path, flash_base, fw_row["ram_base"], fw_row["ram_size"],
        fw_row["mmio_base"], fw_row["mmio_size"], svd_map, verbose=verbose)

    log(f"Census reduce for '{key}' complete.")
    return firmware_id


def main(argv):
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("firmware")
    p.add_argument("--db", default=None)
    args = p.parse_args(argv)
    reduce_firmware(args.firmware, db_path=args.db)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
