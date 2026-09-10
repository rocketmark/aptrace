"""APTrace census reduce: the closure-reduction layer on top of `census
build`'s base evidence (tools/census/build.py). Orchestrates, in order:

  1. Fingerprinting (fingerprint.py) -- cross-image EXACT/STRONG_MATCH/
     POSSIBLE_MATCH/NO_MATCH against every other firmware image already
     in this database. Runs FIRST because boot-recipe sibling remapping
     (step 2) and reference-source propagation (step 3) both need it.
  2. Boot capture (boot_recipes.py) -- run this firmware's boot recipe
     (the cited AutoPilot recipe verbatim, a fingerprint-remapped
     sibling copy, or the incrementally-built Mando recipe), reusing
     dynamic_export.py/dynamic_ingest.py's own JSON format (scenario
     'boot') for dynamic_coverage/memory/mmio -- never a parallel
     ingestion path.
  3. Reference-source confirmation (reference_library.py +
     reference_match.py) -- tag `reference_source_confirmed` functions
     from TWO sources, both writing the SAME library_matches column:
     the curated, human-confirmed-against-real-upstream-source set from
     docs/investigations/boot-and-hardware-bringup.md
     (reference_library.py), and the mechanical reference-corpus match
     results from a PRIOR, separate `reference-match <firmware>` run
     (reference_match.py's `apply_to_library_matches` -- reads only,
     never recomputes matches itself; a no-op if `reference-match`
     hasn't been run for this firmware yet). A plain cross-image
     fingerprint match is NEVER enough by itself -- see
     docs/tooling/census.md's evidence rule.
  4. Indirect-edge resolution (indirect_resolve.py + boot_recipes.py) --
     classify every indirect call/jump instruction (STATICALLY_RESOLVED
     / DYNAMICALLY_OBSERVED / FINITE_CANDIDATE_SET / UNRESOLVED),
     merging targets observed during the scenario corpus AND during
     boot.
  5. Reachability (reachability.py) -- DEFINITELY_REACHABLE /
     POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT / NO_KNOWN_PATH, from
     mechanically-justified roots only.
  6. Function feature records (features.py) -- one materialized,
     purely-structural row per function.
  7. Component grouping (components.py) -- deterministic connected
     components over reachable functions.
  8. Hardware-init snapshot (hardware_snapshot.py) -- reuses the SAME
     machine/result step 2 already produced; never a second boot run.
  9. Residual priority scoring (residual_priority.py) -- a deterministic,
     disclosed-reasons priority score for every function in the
     residual queue, on top of steps 5-7's evidence.
 10. Hardware contract (hardware_contract.py) -- a machine-readable JSON
     document assembled from step 8's snapshot plus static MMIO/vector/
     pin evidence, persisted for direct reuse by `census diff`.

Requires `census build <firmware>` to have already run (this module
reads, never recomputes, the base evidence tables) -- see
docs/tooling/census.md.
"""
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
import boot_recipes  # noqa: E402
import reference_library  # noqa: E402
import dynamic_ingest  # noqa: E402
import pins as pins_mod  # noqa: E402
import residual_priority  # noqa: E402
import hardware_contract  # noqa: E402
import reference_match  # noqa: E402
import aptrace_ghidra as ghidra  # noqa: E402
from build import FunctionRanges  # noqa: E402


def _hx(s):
    return int(s, 16)


def resolve_indirect_edges(conn, firmware_id, firmware_key, firmware_bytes, flash_base, func_ranges,
                             boot_result, verbose):
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

    # Merge targets observed during the boot capture (already run by
    # the caller, see reduce_firmware) with a fresh scenario-corpus
    # replay -- same shape, same merge logic, two sources.
    all_dynamic_hits = {}
    if reg_indirect_pending:
        if boot_result is not None:
            boot_hits = boot_recipes.extract_indirect_hits(boot_result, reg_indirect_pending)
            for addr, hits in boot_hits.items():
                all_dynamic_hits.setdefault(addr, []).extend(hits)
        if verbose:
            print(f"  [indirect-resolve] replaying the Unicorn scenario corpus to watch "
                  f"{len(reg_indirect_pending)} register-indirect site(s)...")
        scenario_hits = indirect_resolve.dynamic_candidates(firmware_key, reg_indirect_pending, verbose=verbose)
        for addr, hits in scenario_hits.items():
            all_dynamic_hits.setdefault(addr, []).extend(hits)

        end = flash_base + len(firmware_bytes)
        for from_addr, hits in all_dynamic_hits.items():
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

    fw_row = conn.execute("SELECT * FROM firmware WHERE id=?", (firmware_id,))
    fw_row = fw_row.fetchone()
    fw_path, _flash_base_s, _labels = ghidra.firmware_info(key)
    firmware_bytes = fw_path.read_bytes()
    flash_base = fw_row["flash_base"]

    func_ranges = FunctionRanges(conn.execute(
        "SELECT id, entry, size FROM functions WHERE firmware_id=?", (firmware_id,)).fetchall())

    log(f"=== census reduce: {key} ===")

    log("[1/10] Fingerprinting functions...")
    fingerprint.compute_fingerprints(conn, firmware_id, firmware_bytes, flash_base)
    fingerprint.recompute_all_matches(conn)
    lib_counts = {}
    for row in conn.execute(
            "SELECT confidence, COUNT(*) c FROM library_matches WHERE firmware_id=? GROUP BY confidence",
            (firmware_id,)):
        lib_counts[row["confidence"]] = row["c"]
    log(f"  cross-image matches (NOT library truth by themselves): {lib_counts}")

    log("[2/10] Running boot capture...")
    # Every currently-unresolved register-indirect site is watched
    # DURING boot too, not just during the scenario corpus (step 4
    # reuses this same result).
    unresolved_reg_indirect = {}
    for r in conn.execute(
            "SELECT DISTINCT from_addr FROM edges WHERE firmware_id=? AND kind LIKE 'computed%' AND resolved=0",
            (firmware_id,)):
        mnem, shape, reg = indirect_resolve.decode_instruction(firmware_bytes, flash_base, r["from_addr"])
        if shape == "reg-indirect" and reg:
            unresolved_reg_indirect[r["from_addr"]] = reg

    boot_out_path, boot_machine, boot_result, boot_recipe, boot_gaps, init_status, boot_deliveries = \
        boot_recipes.capture_boot(
            conn, key, fw_path, flash_base, fw_row["ram_base"], fw_row["ram_size"],
            fw_row["mmio_base"], fw_row["mmio_size"], extra_watch=unresolved_reg_indirect, verbose=verbose)
    if boot_out_path is not None:
        n_runs = dynamic_ingest.ingest_file(conn, boot_out_path, firmware_key_filter=key)
        log(f"  ingested {n_runs} boot dynamic run(s) into dynamic_coverage/memory/mmio")
    if boot_deliveries:
        log(f"  delivered {len(boot_deliveries)} real interrupt(s) during boot: {boot_deliveries}")

    log("[3/10] Applying reference-source confirmations...")
    n_ref = reference_library.apply_reference_confirmations(conn, firmware_id, key)
    log(f"  {n_ref} function(s) reference-source-confirmed (curated, real 'library truth')")
    n_ref_mech = reference_match.apply_to_library_matches(conn, firmware_id, verbose=verbose)
    log(f"  {n_ref_mech} function(s) newly reference-source-confirmed via mechanical reference-match "
        f"(run 'reference-match {key}' first if this is 0 and you expect matches)")

    log("[4/10] Resolving indirect control flow...")
    resolve_indirect_edges(conn, firmware_id, key, firmware_bytes, flash_base, func_ranges, boot_result, verbose)

    log("[5/10] Computing reachability...")
    reach_rows = reachability.compute(conn, firmware_id, func_ranges)
    reach_counts = {}
    for r in reach_rows:
        reach_counts[r["status"]] = reach_counts.get(r["status"], 0) + 1
    log(f"  reachability: {reach_counts}")

    log("[6/10] Building function feature records...")
    features.compute(conn, firmware_id)

    log("[7/10] Grouping into components...")
    comp_rows = components.compute(conn, firmware_id)
    log(f"  {len(comp_rows)} component(s)")

    log("[8/10] Recording hardware-init snapshot...")
    svd_map = pins_mod._samd51_map()
    hardware_snapshot.compute(conn, firmware_id, key, boot_machine, boot_result, boot_recipe, init_status,
                                svd_map, verbose=verbose, delivery_log=boot_deliveries)

    log("[9/10] Scoring the residual queue...")
    priority_rows = residual_priority.compute(conn, firmware_id)
    tier_counts = {}
    for r in priority_rows:
        tier_counts[r["tier"]] = tier_counts.get(r["tier"], 0) + 1
    log(f"  {len(priority_rows)} residual function(s) scored: {tier_counts}")

    log("[10/10] Building hardware contract...")
    hardware_contract.compute(conn, firmware_id, key)
    log("  hardware contract persisted (hardware_contract_runs)")

    log(f"Census reduce for '{key}' complete (init_status={init_status}).")
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
