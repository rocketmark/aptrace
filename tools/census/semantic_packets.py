"""APTrace census: compact per-residual-function evidence packets for a
semantic classification pass.

This is a pure re-slice of evidence ALREADY in the census database (plus
two cheap, mechanical file lookups -- see below) -- no new static
analysis, no disassembly, no decompilation. One JSONL record per
residual function (the SAME residual definition `aptrace_census.py
residual`/`residual_priority.py` already use), capped and deduplicated
so the file stays small and auditable, never a raw table dump.

Two file-based lookups, both exact-string matches against files already
in the repo, never a new inference:
  - `research/provenance/function_classification.csv` -- this project's
    own existing structural-provenance table (platform/library role
    matches, mostly boot/runtime plumbing).
  - `docs/**/*.md` -- a plain substring search for this function's own
    hex address (e.g. "0x8774"), so a packet can say "this address is
    already mentioned in docs/investigations/X.md" without re-deriving
    anything from those docs.
"""
import csv
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import db as census_db  # noqa: E402
import residual_priority  # noqa: E402

MAX_LIST = 10  # cap on callers/callees/ram addrs/strings kept per packet -- compact, not exhaustive
PROVENANCE_CSV = REPO_ROOT / "research" / "provenance" / "function_classification.csv"
DOCS_DIR = REPO_ROOT / "docs"


def _hx(addr):
    return f"0x{addr:x}"


def _capped(items, cap=MAX_LIST):
    items = sorted(items)
    return {"values": items[:cap], "total": len(items), "truncated": len(items) > cap}


def _load_provenance_csv(firmware_bin_name):
    """address(int) -> compact row dict, for THIS firmware's rows only."""
    out = {}
    if not PROVENANCE_CSV.exists():
        return out
    with open(PROVENANCE_CSV, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("firmware") != firmware_bin_name:
                continue
            try:
                addr = int(row["address"], 16)
            except (KeyError, ValueError):
                continue
            out[addr] = {
                "role": row.get("role"), "classification": row.get("classification"),
                "source_reference": row.get("source_reference"),
            }
    return out


def _build_docs_index():
    """hex-address-string ("0x8774") -> sorted list of docs/**/*.md paths
    (repo-relative) that mention it -- one pass over the docs tree,
    reused for every function instead of re-scanning per function."""
    index = {}
    pattern = re.compile(r"0x0*([0-9a-fA-F]{3,8})\b")
    if not DOCS_DIR.exists():
        return index
    for path in DOCS_DIR.rglob("*.md"):
        text = path.read_text(errors="ignore")
        rel = str(path.relative_to(REPO_ROOT))
        for m in set(pattern.findall(text)):
            key = f"0x{m.lower()}"
            index.setdefault(key, set()).add(rel)
    return {k: sorted(v) for k, v in index.items()}


def _function_name(conn, fw, function_id):
    row = conn.execute("SELECT entry, name FROM functions WHERE id=?", (function_id,)).fetchone()
    return row


def build_packets(conn, firmware_key):
    fw = census_db.get_firmware_id(conn, firmware_key)
    fw_row = conn.execute("SELECT path FROM firmware WHERE id=?", (fw,)).fetchone()
    firmware_bin_name = Path(fw_row["path"]).name

    residual_ids = residual_priority.residual_function_ids(conn, fw)
    if not residual_ids:
        return []

    provenance = _load_provenance_csv(firmware_bin_name)
    docs_index = _build_docs_index()

    priority_by_fid = {r["function_id"]: r for r in conn.execute(
        "SELECT function_id, score, tier FROM residual_priority WHERE firmware_id=?", (fw,))}
    component_by_fid = {}
    for r in conn.execute(
        "SELECT cm.function_id, c.component_index FROM component_members cm "
        "JOIN components c ON c.id = cm.component_id WHERE cm.firmware_id=?", (fw,)
    ):
        component_by_fid[r["function_id"]] = r["component_index"]
    library_by_fid = {r["function_id"]: r for r in conn.execute(
        "SELECT function_id, confidence, matched_function_name, matched_firmware_key "
        "FROM library_matches WHERE firmware_id=?", (fw,))}
    reach_by_fid = {r["function_id"]: r["status"] for r in conn.execute(
        "SELECT function_id, status FROM function_reachability WHERE firmware_id=?", (fw,))}

    # dynamic_tx_rx-confirmed protocol RAM addresses -- same mechanical
    # fact residual_priority.py's own protocol_data_path signal uses.
    protocol_runs = [r["dynamic_run_id"] for r in conn.execute(
        "SELECT DISTINCT dynamic_run_id FROM dynamic_tx_rx WHERE firmware_id=?", (fw,))]
    protocol_ram_addrs = set()
    if protocol_runs:
        placeholders = ",".join("?" for _ in protocol_runs)
        for r in conn.execute(
                f"SELECT DISTINCT addr FROM dynamic_memory WHERE firmware_id=? "
                f"AND dynamic_run_id IN ({placeholders})", (fw, *protocol_runs)):
            protocol_ram_addrs.add(r["addr"])

    packets = []
    for fid in sorted(residual_ids):
        func = _function_name(conn, fw, fid)
        if func is None:
            continue
        addr = func["entry"]
        addr_hex = _hx(addr)

        n_blocks = conn.execute(
            "SELECT COUNT(*) FROM basic_blocks WHERE firmware_id=? AND function_id=?", (fw, fid)).fetchone()[0]
        size_row = conn.execute("SELECT size FROM functions WHERE id=?", (fid,)).fetchone()

        callers = {r["from_addr"] for r in conn.execute(
            "SELECT DISTINCT from_addr FROM edges WHERE firmware_id=? AND to_function_id=? "
            "AND kind LIKE '%call%'", (fw, fid))}
        callees = {r["to_addr"] for r in conn.execute(
            "SELECT DISTINCT to_addr FROM edges WHERE firmware_id=? AND from_function_id=? "
            "AND kind LIKE '%call%' AND to_addr IS NOT NULL", (fw, fid))}
        ram_writes = {r["to_addr"] for r in conn.execute(
            "SELECT DISTINCT to_addr FROM memory_accesses WHERE firmware_id=? AND from_function_id=? "
            "AND direction='WRITE'", (fw, fid))}
        ram_reads = {r["to_addr"] for r in conn.execute(
            "SELECT DISTINCT to_addr FROM memory_accesses WHERE firmware_id=? AND from_function_id=? "
            "AND direction='READ'", (fw, fid))}
        peripherals = sorted({r["peripheral"] for r in conn.execute(
            "SELECT DISTINCT peripheral FROM mmio_accesses WHERE firmware_id=? AND from_function_id=? "
            "AND peripheral IS NOT NULL", (fw, fid))})
        pins = sorted({r["pin_name"] for r in conn.execute(
            "SELECT DISTINCT pin_name FROM pins WHERE firmware_id=? AND from_function_id=?", (fw, fid))})
        strings = sorted({r["value"] for r in conn.execute(
            "SELECT DISTINCT s.value FROM literal_refs l JOIN strings s "
            "ON s.firmware_id=l.firmware_id AND s.addr=l.to_addr "
            "WHERE l.firmware_id=? AND l.from_function_id=?", (fw, fid))})

        priority = priority_by_fid.get(fid)
        lib = library_by_fid.get(fid)

        packets.append({
            "function_id": fid, "address": addr_hex, "name": func["name"],
            "component": component_by_fid.get(fid),
            "priority_tier": priority["tier"] if priority else None,
            "priority_score": priority["score"] if priority else None,
            "reachability": reach_by_fid.get(fid),
            "size": size_row["size"] if size_row else None,
            "n_basic_blocks": n_blocks,
            "callers": _capped(_hx(a) for a in callers),
            "callees": _capped(_hx(a) for a in callees),
            "ram_writes": _capped(_hx(a) for a in ram_writes),
            "ram_reads": _capped(_hx(a) for a in ram_reads),
            "peripherals": peripherals,
            "pins": pins,
            "strings": strings[:MAX_LIST],
            "strings_truncated": len(strings) > MAX_LIST,
            "protocol_ram_overlap": bool((ram_writes | ram_reads) & protocol_ram_addrs),
            "cross_image_library_match": {
                "confidence": lib["confidence"], "matched_function_name": lib["matched_function_name"],
                "matched_firmware": lib["matched_firmware_key"],
            } if lib else None,
            "provenance_csv": provenance.get(addr),
            "docs_mentions": docs_index.get(addr_hex, []),
        })
    return packets


def export_packets(conn, firmware_key, out_path):
    packets = build_packets(conn, firmware_key)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        for p in packets:
            f.write(json.dumps(p, sort_keys=True) + "\n")
    return len(packets)
