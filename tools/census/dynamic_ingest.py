"""APTrace census: ingest tools/census/dynamic_export.py's coverage-export
JSON files into the census database's dynamic_* tables.

Kept separate from dynamic_export.py (capture) so each step has one job:
capture never touches the database, ingest never touches Unicorn.
Re-running ingest for a scenario replaces that scenario's own prior rows
(idempotent, like every other `census build` step -- see db.py's
replace_firmware_rows), keyed on (firmware_id, scenario).
"""
import datetime
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import db as census_db  # noqa: E402
import pins  # noqa: E402


def _function_id_for_pc(conn, firmware_id, pc, function_cache):
    if pc in function_cache:
        return function_cache[pc]
    row = conn.execute(
        "SELECT id FROM functions WHERE firmware_id = ? AND entry <= ? "
        "ORDER BY entry DESC LIMIT 1", (firmware_id, pc)).fetchone()
    fid = None
    if row is not None:
        frow = conn.execute("SELECT entry, size FROM functions WHERE id = ?", (row["id"],)).fetchone()
        if frow["entry"] <= pc < frow["entry"] + max(frow["size"], 1):
            fid = row["id"]
    function_cache[pc] = fid
    return fid


def _basic_block_id_for_pc(conn, firmware_id, pc, block_cache):
    if pc in block_cache:
        return block_cache[pc]
    row = conn.execute(
        "SELECT id FROM basic_blocks WHERE firmware_id = ? AND start_addr <= ? AND end_addr >= ? "
        "LIMIT 1", (firmware_id, pc, pc)).fetchone()
    bid = row["id"] if row is not None else None
    block_cache[pc] = bid
    return bid


def ingest_file(conn, path, firmware_key_filter=None):
    """Ingest one scenario's dynamic_export.py JSON file. Returns the
    number of dynamic_runs rows written. `firmware_key_filter`, if given,
    only ingests legs for that firmware key (a capture file can span
    multiple firmware images, e.g. AutoPilot<->Remote scenarios)."""
    data = json.loads(Path(path).read_text())
    scenario = data["scenario"]
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    source_file = str(path)

    legs_by_firmware = {}
    for leg in data["legs"]:
        stem = Path(leg["firmware"]).stem
        key = next((k for k in ("autopilot868", "autopilot915", "mando868", "mando915")
                    if k in stem), stem)
        if firmware_key_filter and key != firmware_key_filter:
            continue
        legs_by_firmware.setdefault(key, []).append(leg)

    total_runs = 0
    for firmware_key, legs in legs_by_firmware.items():
        try:
            firmware_id = census_db.get_firmware_id(conn, firmware_key)
        except ValueError:
            continue  # this firmware hasn't had a static census built yet -- nothing to join against

        # Idempotent re-ingest: drop this (firmware, scenario)'s prior rows.
        run_ids = [r["id"] for r in conn.execute(
            "SELECT id FROM dynamic_runs WHERE firmware_id = ? AND scenario = ?",
            (firmware_id, scenario)).fetchall()]
        for rid in run_ids:
            conn.execute("DELETE FROM dynamic_coverage WHERE dynamic_run_id = ?", (rid,))
            conn.execute("DELETE FROM dynamic_memory WHERE dynamic_run_id = ?", (rid,))
            conn.execute("DELETE FROM dynamic_mmio WHERE dynamic_run_id = ?", (rid,))
            conn.execute("DELETE FROM dynamic_tx_rx WHERE dynamic_run_id = ?", (rid,))
            conn.execute("DELETE FROM dynamic_runs WHERE id = ?", (rid,))

        function_cache, block_cache = {}, {}
        for leg_index, leg in enumerate(legs):
            snap = leg["snapshot"]
            cur = conn.execute(
                "INSERT INTO dynamic_runs (firmware_id, scenario, leg_label, leg_index, entry, "
                "stop_reason, error, instructions_executed, ran_at, source_file) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (firmware_id, scenario, leg.get("label"), leg_index,
                 int(snap["entry"], 16) if snap.get("entry") else None,
                 snap.get("stop_reason"), snap.get("error"),
                 snap.get("instructions_executed"), now, source_file))
            run_id = cur.lastrowid
            total_runs += 1

            for pc_hex in (snap.get("visited_pcs") or []):
                pc = int(pc_hex, 16)
                fid = _function_id_for_pc(conn, firmware_id, pc, function_cache)
                bid = _basic_block_id_for_pc(conn, firmware_id, pc, block_cache)
                conn.execute(
                    "INSERT INTO dynamic_coverage (dynamic_run_id, firmware_id, pc, function_id, basic_block_id) "
                    "VALUES (?, ?, ?, ?, ?)", (run_id, firmware_id, pc, fid, bid))

            for entry in snap.get("ram_log", []):
                conn.execute(
                    "INSERT INTO dynamic_memory (dynamic_run_id, firmware_id, addr, width, direction, pc, value) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (run_id, firmware_id, int(entry["address"], 16), entry.get("size"),
                     entry["direction"], int(entry["pc"], 16) if entry.get("pc") else None,
                     entry.get("value")))

            for entry in snap.get("mmio_log", []):
                addr = int(entry["address"], 16)
                peripheral, register, _note = pins.resolve_mmio_addr(addr)
                conn.execute(
                    "INSERT INTO dynamic_mmio (dynamic_run_id, firmware_id, addr, width, direction, pc, value, "
                    "peripheral, register_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (run_id, firmware_id, addr, entry.get("size"), entry["direction"],
                     int(entry["pc"], 16) if entry.get("pc") else None, entry.get("value"),
                     peripheral, register))

            for tx in leg.get("tx_rx", []):
                conn.execute(
                    "INSERT INTO dynamic_tx_rx (dynamic_run_id, firmware_id, direction, data_hex, note) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (run_id, firmware_id, tx["direction"], tx["data_hex"], tx.get("note")))

    conn.commit()
    return total_runs


def ingest_dir(conn, dir_path, firmware_key_filter=None):
    dir_path = Path(dir_path)
    total = 0
    files = sorted(dir_path.glob("*.json"))
    for f in files:
        total += ingest_file(conn, f, firmware_key_filter=firmware_key_filter)
    return len(files), total


def main(argv):
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path", help="a dynamic_export.py JSON file, or a directory of them")
    p.add_argument("--firmware", default=None, help="only ingest legs for this firmware key")
    p.add_argument("--db", default=None, help="census database path (default: research/runs/census/census.sqlite3)")
    args = p.parse_args(argv)

    conn = census_db.connect(args.db)
    path = Path(args.path)
    if path.is_dir():
        nfiles, nruns = ingest_dir(conn, path, firmware_key_filter=args.firmware)
        print(f"Ingested {nfiles} file(s), {nruns} dynamic run(s).")
    else:
        nruns = ingest_file(conn, path, firmware_key_filter=args.firmware)
        print(f"Ingested {nruns} dynamic run(s) from {path}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
