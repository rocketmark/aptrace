"""APTrace census: build (or rebuild) the mechanical evidence database for
one firmware image.

Orchestrates, in order:
  1. Ghidra (tools/ghidra/aptrace_ghidra.py) -- build/reuse the persistent
     project, load its static_export.json (functions/calls/dataRefs/
     strings) and census_export.json (basic blocks/CFG edges/RAM+MMIO
     accesses, APTraceExportCensus.java).
  2. A raw vector-table read + function-pointer-candidate scan directly
     against the firmware's own bytes (tools/census/raw_scan.py).
  3. An independent Capstone Thumb branch-target sweep, cross-checked
     against Ghidra's own basic-block coverage (tools/census/capstone_sweep.py).
  4. SVD-based MMIO/pin resolution (tools/census/pins.py, on top of
     tools/svd/resolve_mmio.py).
  5. Disagreement/anomaly detection (tools/census/scan_warnings).

No LLM, no semantic judgment anywhere in this file -- every table
populated here is either a direct transcription of a tool's own output,
or a small deterministic derivation (interval math, address-range
membership, a fixed regex) documented inline. See docs/tooling/census.md.

Every `census build` run REPLACES this firmware's own rows (see
db.replace_firmware_rows) -- it reflects the current state of the
Ghidra cache/firmware/scripts exactly, not a union across rebuilds.
"""
import bisect
import datetime
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO_ROOT / "tools" / "ghidra"))

import db as census_db  # noqa: E402
import raw_scan  # noqa: E402
import capstone_sweep  # noqa: E402
import pins as pins_mod  # noqa: E402
import aptrace_ghidra as ghidra  # noqa: E402


class FunctionRanges:
    """Sorted (entry, size, id) lookup for 'which known function contains
    this address', shared by every step below that needs to attribute an
    address to a Ghidra function (capstone-sweep edges, pin evidence)."""

    def __init__(self, rows):
        self._entries = sorted((r["entry"], r["size"], r["id"]) for r in rows)
        self._starts = [e[0] for e in self._entries]

    def containing(self, addr):
        i = bisect.bisect_right(self._starts, addr) - 1
        if i < 0:
            return None
        entry, size, fid = self._entries[i]
        if entry <= addr < entry + max(size, 1):
            return fid
        return None


def _hx(s):
    return int(s, 16)


def build(key, db_path=None, verbose=True, ghidra_build=True):
    def log(msg):
        if verbose:
            print(msg)

    if ghidra_build:
        log(f"[1/6] Ensuring Ghidra static analysis is fresh for '{key}'...")
        ghidra.build(key)  # no-ops if already fresh
    ghidra.ensure_fresh(key)

    fw_path, flash_base_s, _labels = ghidra.firmware_info(key)
    flash_base = _hx(flash_base_s)
    static = ghidra._load_static_export(key)
    census = ghidra._load_census_export(key)
    meta = ghidra.read_meta(key)

    ram_base, ram_size = _hx(ghidra.CENSUS_RAM_BASE), _hx(ghidra.CENSUS_RAM_SIZE)
    mmio_base, mmio_size = _hx(ghidra.CENSUS_MMIO_BASE), _hx(ghidra.CENSUS_MMIO_SIZE)

    conn = census_db.connect(db_path)

    # --- firmware row --------------------------------------------------
    row = conn.execute("SELECT id FROM firmware WHERE key = ?", (key,)).fetchone()
    fw_fields = (
        key, str(fw_path.relative_to(REPO_ROOT)), meta["firmware_sha256"], flash_base,
        len(fw_path.read_bytes()), ram_base, ram_size, mmio_base, mmio_size,
        meta.get("ghidra_version"), datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
    if row is None:
        conn.execute(
            "INSERT INTO firmware (key, path, sha256, flash_base, size_bytes, ram_base, ram_size, "
            "mmio_base, mmio_size, ghidra_version, built_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)", fw_fields)
        firmware_id = conn.execute("SELECT id FROM firmware WHERE key = ?", (key,)).fetchone()["id"]
    else:
        firmware_id = row["id"]
        conn.execute(
            "UPDATE firmware SET path=?, sha256=?, flash_base=?, size_bytes=?, ram_base=?, ram_size=?, "
            "mmio_base=?, mmio_size=?, ghidra_version=?, built_at=? WHERE key=?",
            fw_fields[1:] + (key,))
    conn.commit()
    census_db.clear_firmware_data(conn, firmware_id)

    # --- functions -------------------------------------------------------
    log("[2/6] Ingesting functions...")
    func_rows = [{
        "firmware_id": firmware_id, "entry": _hx(f["entry"]), "name": f["name"], "size": f["size"],
        "thunk": int(bool(f["thunk"])), "external": int(bool(f["external"])), "source": "ghidra",
    } for f in static["functions"]]
    census_db.replace_firmware_rows(conn, firmware_id, "functions", func_rows)
    conn.commit()
    entry_to_id = {r["entry"]: r["id"] for r in conn.execute(
        "SELECT id, entry FROM functions WHERE firmware_id = ?", (firmware_id,))}
    func_ranges = FunctionRanges(conn.execute(
        "SELECT id, entry, size FROM functions WHERE firmware_id = ?", (firmware_id,)).fetchall())
    known_entries = set(entry_to_id)

    # --- basic blocks ------------------------------------------------
    log("[3/6] Ingesting basic blocks, CFG edges, RAM/MMIO accesses...")
    block_rows = [{
        "firmware_id": firmware_id, "start_addr": _hx(b["start"]), "end_addr": _hx(b["end"]),
        "function_id": entry_to_id.get(_hx(b["functionEntry"])) if b.get("functionEntry") else None,
        "source": "ghidra-basicblockmodel",
    } for b in census["basicBlocks"]]
    census_db.replace_firmware_rows(conn, firmware_id, "basic_blocks", block_rows)
    conn.commit()
    block_starts_ends = [(r["start_addr"], r["end_addr"]) for r in conn.execute(
        "SELECT start_addr, end_addr FROM basic_blocks WHERE firmware_id = ? ORDER BY start_addr",
        (firmware_id,))]

    # --- Ghidra-sourced CFG edges --------------------------------------
    edge_rows = [{
        "firmware_id": firmware_id, "from_addr": _hx(e["from"]),
        "to_addr": _hx(e["to"]) if e["to"] else None, "kind": e["kind"],
        "resolved": int(bool(e["resolved"])),
        "from_function_id": entry_to_id.get(_hx(e["fromFunctionEntry"])) if e.get("fromFunctionEntry") else None,
        "to_function_id": entry_to_id.get(_hx(e["toFunctionEntry"])) if e.get("toFunctionEntry") else None,
        "source": e["source"],
    } for e in census["edges"]]

    # --- RAM/MMIO accesses (static, Ghidra reference manager) ----------
    mem_rows = [{
        "firmware_id": firmware_id, "from_addr": _hx(m["from"]),
        "from_function_id": entry_to_id.get(_hx(m["fromFunctionEntry"])) if m.get("fromFunctionEntry") else None,
        "to_addr": _hx(m["to"]), "width": m["width"], "direction": m["direction"], "source": m["source"],
    } for m in census["memoryAccesses"]]
    census_db.replace_firmware_rows(conn, firmware_id, "memory_accesses", mem_rows)

    mmio_rows = []
    for m in census["mmioAccesses"]:
        to_addr = _hx(m["to"])
        peripheral, register, note = pins_mod.resolve_mmio_addr(to_addr)
        mmio_rows.append({
            "firmware_id": firmware_id, "from_addr": _hx(m["from"]),
            "from_function_id": entry_to_id.get(_hx(m["fromFunctionEntry"])) if m.get("fromFunctionEntry") else None,
            "to_addr": to_addr, "width": m["width"], "direction": m["direction"],
            "peripheral": peripheral, "register_name": register, "resolution_note": note,
            "source": m["source"],
        })
    census_db.replace_firmware_rows(conn, firmware_id, "mmio_accesses", mmio_rows)
    conn.commit()

    # --- literal refs + strings (straight from Ghidra's existing export) ---
    log("[4/6] Ingesting literal refs and strings...")
    # static_export's "fromFunction" is a NAME, not an entry address --
    # resolve via the function name->entry map from the same export.
    # A handful of "to" values are Ghidra's own symbolic STACK-space
    # representation (e.g. "0xStack[-0x48]", a local-variable reference,
    # not a real flash/RAM/MMIO address) -- not representable as this
    # table's plain integer to_addr, so skipped here (the underlying
    # stack access is not lost: it's just not a "memory location" this
    # census's address-keyed tables can meaningfully index).
    name_to_entry = {f["name"]: _hx(f["entry"]) for f in static["functions"]}
    literal_rows = []
    for r in static["dataReferences"]:
        try:
            to_addr = _hx(r["to"])
        except ValueError:
            continue
        literal_rows.append({
            "firmware_id": firmware_id, "from_addr": _hx(r["from"]),
            "from_function_id": (entry_to_id.get(name_to_entry.get(r["fromFunction"]))
                                  if r.get("fromFunction") else None),
            "to_addr": to_addr, "to_label": r.get("toLabel"), "ref_type": r.get("refType"),
            "source": "ghidra-refmgr",
        })
    census_db.replace_firmware_rows(conn, firmware_id, "literal_refs", literal_rows)

    string_rows = [{
        "firmware_id": firmware_id, "addr": _hx(s["address"]), "length": s["length"],
        "data_type": s.get("dataType"), "value": s["value"], "source": "ghidra",
    } for s in static["strings"]]
    census_db.replace_firmware_rows(conn, firmware_id, "strings", string_rows)
    conn.commit()

    # --- vectors + function-pointer candidates (raw byte scan) ---------
    log("[5/6] Raw vector-table read, function-pointer scan, Capstone cross-check...")
    vectors = raw_scan.read_vectors(fw_path, flash_base, known_function_entries=known_entries)
    vector_rows = [{
        "firmware_id": firmware_id, "vector_index": v["vector_index"], "raw_value": v["raw_value"],
        "target_addr": v["target_addr"], "name": v["name"], "is_irq": v["is_irq"],
        "landed_in_known_function": v["landed_in_known_function"], "source": "raw-vector-scan",
    } for v in vectors]
    census_db.replace_firmware_rows(conn, firmware_id, "vectors", vector_rows)

    func_ranges_list = [(f["entry"], f["size"]) for f in func_rows]
    fp_candidates = raw_scan.scan_function_pointer_candidates(
        fw_path, flash_base, func_ranges_list, known_entries)
    fp_rows = [{
        "firmware_id": firmware_id, "location_addr": c["location_addr"], "raw_value": c["raw_value"],
        "target_addr": c["target_addr"], "matches_known_function": c["matches_known_function"],
        "source": "raw-flashword-scan",
    } for c in fp_candidates]
    census_db.replace_firmware_rows(conn, firmware_id, "function_pointers", fp_rows)
    conn.commit()

    # --- independent Capstone Thumb sweep (cross-check, not authority) --
    fw_bytes = fw_path.read_bytes()
    seeds = set(known_entries) | {v["target_addr"] for v in vectors if v["target_addr"] is not None}
    cs_edges, cs_discovered = capstone_sweep.sweep(fw_bytes, flash_base, seeds)
    # Overlapping linear walks from different seeds can legitimately
    # rediscover the same instruction/edge more than once -- dedup
    # before insertion so query results aren't cluttered with identical
    # repeats of the same fact.
    for from_addr, to_addr, kind in sorted(set(cs_edges)):
        edge_rows.append({
            "firmware_id": firmware_id, "from_addr": from_addr, "to_addr": to_addr, "kind": kind,
            "resolved": 1, "from_function_id": func_ranges.containing(from_addr),
            "to_function_id": func_ranges.containing(to_addr), "source": "capstone-sweep",
        })
    census_db.replace_firmware_rows(conn, firmware_id, "edges", edge_rows)
    conn.commit()

    # --- peripherals (rollup of resolved mmio_accesses) -----------------
    log("[6/6] Peripherals, pin evidence, scan_warnings...")
    peripheral_counts = {}
    for m in mmio_rows:
        if m["peripheral"]:
            peripheral_counts[m["peripheral"]] = peripheral_counts.get(m["peripheral"], 0) + 1
    svd_map = pins_mod._samd51_map()
    svd_by_name = {name: (base, size) for base, size, name, _regs in svd_map.peripherals}
    peripheral_rows = [{
        "firmware_id": firmware_id, "name": name, "base_addr": svd_by_name[name][0],
        "size": svd_by_name[name][1], "access_count": count, "source": "svd",
    } for name, count in peripheral_counts.items() if name in svd_by_name]
    census_db.replace_firmware_rows(conn, firmware_id, "peripherals", peripheral_rows)

    # --- pin evidence (PORT PINCFG/PMUX accesses only -- see pins.py) --
    pin_rows = []
    for m in mmio_rows:
        if m["peripheral"] != "PORT":
            continue
        for ev in pins_mod.port_pin_evidence(m["peripheral"], m["register_name"], m["from_addr"], m["to_addr"]):
            pin_rows.append({
                "firmware_id": firmware_id, "pin_name": ev["pin_name"], "group_index": ev["group_index"],
                "pin_index": ev["pin_index"], "evidence_kind": ev["evidence_kind"],
                "from_addr": m["from_addr"], "from_function_id": m["from_function_id"],
                "mmio_addr": m["to_addr"], "register_name": m["register_name"],
                "confidence": ev["confidence"], "source": "svd+ghidra-refmgr",
            })
    census_db.replace_firmware_rows(conn, firmware_id, "pins", pin_rows)
    conn.commit()

    # --- scan_warnings: disagreements, not hidden -----------------------
    warnings = _compute_warnings(
        firmware_id, static, block_starts_ends, cs_discovered, edge_rows, vectors, mmio_rows)
    census_db.replace_firmware_rows(conn, firmware_id, "scan_warnings", warnings)
    conn.commit()

    log(f"Census build for '{key}' complete: {len(func_rows)} functions, {len(block_rows)} blocks, "
        f"{len(edge_rows)} edges, {len(mem_rows)} RAM accesses, {len(mmio_rows)} MMIO accesses, "
        f"{len(vector_rows)} vectors, {len(fp_rows)} function-pointer candidates, "
        f"{len(pin_rows)} pin-evidence rows, {len(warnings)} warnings.")
    return firmware_id


def _compute_warnings(firmware_id, static, block_starts_ends, cs_discovered, edge_rows, vectors, mmio_rows):
    warnings = []

    # 1. Capstone-discovered branch/call targets that fall in an
    #    executable region but outside every Ghidra basic block --
    #    a real static-discovery disagreement worth flagging (Ghidra
    #    remains the authority; this is not a claim Capstone is right).
    starts = [s for s, _e in block_starts_ends]

    def covered(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i < 0:
            return False
        s, e = block_starts_ends[i]
        return s <= addr <= e

    cs_targets = {to for _f, to, _k in ((e["from_addr"], e["to_addr"], e["kind"]) for e in edge_rows
                                          if e["source"] == "capstone-sweep")}
    for addr in sorted(cs_targets):
        if not covered(addr):
            warnings.append({
                "firmware_id": firmware_id, "category": "capstone-target-not-in-ghidra-coverage",
                "addr": addr, "detail": f"Capstone sweep found a branch/call target at 0x{addr:08x} "
                                          "not covered by any Ghidra basic block.",
                "source": "capstone-sweep",
            })

    # 2. Vectors whose target isn't a known Ghidra function entry.
    for v in vectors:
        if v["target_addr"] is not None and not v["landed_in_known_function"]:
            warnings.append({
                "firmware_id": firmware_id, "category": "vector-outside-known-function",
                "addr": v["target_addr"],
                "detail": f"vector[{v['vector_index']}] ({v['name'] or 'IRQ'}) targets 0x{v['target_addr']:08x}, "
                           "which is not a known Ghidra function entry.",
                "source": "raw-vector-scan",
            })

    # 3. MMIO accesses the SVD couldn't resolve at all.
    unresolved_mmio = sorted({m["to_addr"] for m in mmio_rows if m["peripheral"] is None})
    for addr in unresolved_mmio:
        warnings.append({
            "firmware_id": firmware_id, "category": "mmio-unresolved", "addr": addr,
            "detail": f"0x{addr:08x} is accessed but not covered by any SAMD51 peripheral in the SVD.",
            "source": "svd",
        })

    # 4. Executable-region bytes not owned by any discovered basic block
    #    (gaps -- may legitimately include literal pools/padding, not
    #    necessarily a bug, but real residual evidence per
    #    docs/tooling/census.md).
    exec_blocks = [(_hx(b["start"]), _hx(b["end"])) for b in static["program"]["memoryBlocks"] if b["execute"]]
    for region_start, region_end in exec_blocks:
        pos = region_start
        for s, e in block_starts_ends:
            if e < region_start or s > region_end:
                continue
            if s > pos:
                warnings.append({
                    "firmware_id": firmware_id, "category": "exec-bytes-unowned", "addr": pos,
                    "detail": f"0x{pos:08x}-0x{s - 1:08x} ({s - pos} bytes) is in an executable region "
                               "but not covered by any discovered basic block.",
                    "source": "ghidra-basicblockmodel",
                })
            pos = max(pos, e + 1)
        if pos <= region_end:
            warnings.append({
                "firmware_id": firmware_id, "category": "exec-bytes-unowned", "addr": pos,
                "detail": f"0x{pos:08x}-0x{region_end:08x} ({region_end - pos + 1} bytes) is in an executable "
                           "region but not covered by any discovered basic block.",
                "source": "ghidra-basicblockmodel",
            })

    return warnings


def main(argv):
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("firmware", help="firmware key, e.g. autopilot868 (see tools/ghidra/aptrace_ghidra.py FIRMWARE_REGISTRY)")
    p.add_argument("--db", default=None, help="census database path (default: research/runs/census/census.sqlite3)")
    p.add_argument("--no-ghidra-build", action="store_true", help="skip the Ghidra build/freshness step (assume the cache is already fresh)")
    args = p.parse_args(argv)
    build(args.firmware, db_path=args.db, ghidra_build=not args.no_ghidra_build)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
