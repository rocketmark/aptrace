"""APTrace census: generic indexed state/event array mapper.

Mechanically enumerates every slot of an arbitrary base/count/width RAM
array (e.g. AutoPilot's pending[] event-scheduling array, base=
0x200025bc, count=18, width=1) using ONLY facts already in the census
database:

  - memory_accesses     -- statically-resolved writers/readers
  - function_reachability -- is each writer/reader function itself
                              reachable from a justified root?
  - dynamic_memory        -- writes/reads already OBSERVED by a real
                              Unicorn scenario run (dynamic_ingest.py),
                              including the captured value where a write
                              was logged
  - indirect_edge_resolutions -- disclosed as a caveat on a writer/
                                   reader's OWN function ("this function
                                   also contains an unresolved indirect
                                   edge"), never claimed to explain the
                                   write itself

This module collects NO new static fact of its own and makes NO semantic
judgment about what any slot "means" (is it a real/dormant/motor/etc.
event) -- purely a mechanical re-slice of existing evidence, per slot,
stored in SQLite (state_map_runs / state_map_slots) exactly like every
other census layer. Reusable for any other indexed array in any firmware
census already covers -- nothing below is specific to AutoPilot or to
"events".

An OPTIONAL, equally generic dispatcher probe (`probe_dispatcher`) uses
real Unicorn concrete execution to observe what a real, unmodified
dispatcher function does when slot N is marked active, for every N in
range -- one reusable probe, never a per-slot hand-authored test. If a
slot's real output depends on some OTHER, unresolved RAM source (e.g. a
value the dispatcher reads but this probe never seeded), that dependency
is recorded as `output_depends_on_unresolved_source`, not invented.
"""
import datetime
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import db as census_db  # noqa: E402


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _function_row(conn, fw, function_id):
    if function_id is None:
        return None
    return conn.execute("SELECT entry, name FROM functions WHERE id=?", (function_id,)).fetchone()


def _reachability_status(conn, fw, function_id):
    if function_id is None:
        return None
    row = conn.execute(
        "SELECT status FROM function_reachability WHERE firmware_id=? AND function_id=?",
        (fw, function_id)).fetchone()
    return row["status"] if row else None


def _unresolved_indirect_in_function(conn, fw, function_id):
    if function_id is None:
        return []
    rows = conn.execute(
        "SELECT from_addr FROM indirect_edge_resolutions "
        "WHERE firmware_id=? AND from_function_id=? AND classification='UNRESOLVED'",
        (fw, function_id)).fetchall()
    return [r["from_addr"] for r in rows]


def _static_access_rows(conn, fw, addr, direction):
    """One row per static memory_accesses hit at exactly `addr`, enriched
    with the accessing function's name and reachability status, and any
    UNRESOLVED indirect edges inside that SAME function (a disclosed
    caveat, not a causal claim)."""
    out = []
    for r in conn.execute(
        "SELECT m.from_addr, m.from_function_id, m.width, m.source "
        "FROM memory_accesses m WHERE m.firmware_id=? AND m.to_addr=? AND m.direction=? "
        "ORDER BY m.from_addr", (fw, addr, direction)
    ):
        func = _function_row(conn, fw, r["from_function_id"])
        entry = {
            "from_addr": r["from_addr"],
            "from_function": func["name"] if func else None,
            "from_function_entry": func["entry"] if func else None,
            "width": r["width"],
            "reachability": _reachability_status(conn, fw, r["from_function_id"]),
            "source": r["source"],
        }
        unresolved = _unresolved_indirect_in_function(conn, fw, r["from_function_id"])
        if unresolved:
            entry["unresolved_indirect_in_same_function"] = unresolved
        out.append(entry)
    return out


def _dynamic_access_rows(conn, fw, addr, direction):
    out = []
    for r in conn.execute(
        "SELECT dm.pc, dm.value, dm.width, dr.scenario, dr.leg_label "
        "FROM dynamic_memory dm JOIN dynamic_runs dr ON dr.id = dm.dynamic_run_id "
        "WHERE dm.firmware_id=? AND dm.addr=? AND dm.direction=? "
        "ORDER BY dr.scenario, dr.leg_index", (fw, addr, direction)
    ):
        out.append({
            "scenario": r["scenario"], "leg_label": r["leg_label"],
            "pc": r["pc"], "width": r["width"],
            "value_hex": r["value"],
        })
    return out


def build_state_map(conn, firmware_key, base, count, width, label=None, dispatcher_entry=None,
                     source="state_map.py"):
    """Compute and persist one state_map_runs row plus `count` state_map_slots
    rows for the array [base, base + count*width), re-slicing existing
    census evidence only. Returns the new run_id."""
    fw = census_db.get_firmware_id(conn, firmware_key)
    cur = conn.execute(
        "INSERT INTO state_map_runs (firmware_id, base, count, width, label, dispatcher_entry, ran_at, source) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (fw, base, count, width, label, dispatcher_entry, _now(), source))
    run_id = cur.lastrowid

    rows = []
    for i in range(count):
        addr = base + i * width
        static_writers = _static_access_rows(conn, fw, addr, "WRITE")
        static_readers = _static_access_rows(conn, fw, addr, "READ")
        dynamic_writers = _dynamic_access_rows(conn, fw, addr, "write")
        dynamic_readers = _dynamic_access_rows(conn, fw, addr, "read")
        has_static_writer = bool(static_writers)
        has_dynamic_writer = bool(dynamic_writers)
        rows.append({
            "run_id": run_id, "firmware_id": fw, "slot_index": i, "addr": addr,
            "static_writers_json": json.dumps(static_writers),
            "static_readers_json": json.dumps(static_readers),
            "dynamic_writers_json": json.dumps(dynamic_writers),
            "dynamic_readers_json": json.dumps(dynamic_readers),
            "unresolved_indirect_json": json.dumps(sorted({
                addr2 for entry in static_writers + static_readers
                for addr2 in entry.get("unresolved_indirect_in_same_function", [])
            })),
            "has_static_writer": int(has_static_writer),
            "has_dynamic_writer": int(has_dynamic_writer),
            "unresolved_producer": int(not has_static_writer and not has_dynamic_writer),
            "source": source,
        })
    cols = list(rows[0].keys())
    conn.executemany(
        f"INSERT INTO state_map_slots ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
        [tuple(r[c] for c in cols) for r in rows])
    conn.commit()
    return run_id


def _parse_extra_seed(items):
    """['0x200000d9=01', ...] -> [(0x200000d9, b'\\x01'), ...]."""
    out = []
    for item in items or ():
        addr_s, hex_s = item.split("=", 1)
        out.append((int(addr_s, 16), bytes.fromhex(hex_s)))
    return out


def probe_dispatcher(conn, run_id, firmware_key, base, width, count, dispatcher_entry,
                      tx_wrappers=(), extra_seed=(), index_addr=None, index_width=1,
                      max_instructions=5000, source="state_map.py"):
    """One reusable, fully generic probe: for every slot N in range(count),
    mark slot N "active" (write a single 0xFF-filled `width`-byte value
    at base + N*width -- the array being mapped, nothing else invented),
    optionally also write N itself to `index_addr` (for a dispatcher that
    reads slot activity through a separate index/queue -- e.g. a scan
    table, supplied by the CALLER as a mechanical wiring parameter, not a
    semantic guess), apply any caller-supplied FIXED `extra_seed` writes
    identically for every slot (e.g. a rate-limit-gate bypass timestamp
    or a queue-length constant -- again mechanical wiring, not per-slot
    meaning), then run the real, unmodified firmware from
    `dispatcher_entry` and record where it stops: a real TX-wrapper call
    (`tx_wrappers`, tried as concrete stop addresses) with whatever bytes
    it was about to hand that wrapper, a clean return with NO TX wrapper
    ever reached, or something else (recorded as-is).

    Never invents a semantic "interesting" value for what the dispatched
    code goes on to read -- if the captured output is empty/all-zero
    while a real TX call WAS reached, that is recorded as
    `output_depends_on_unresolved_source=1` rather than silently retried
    with a made-up seed."""
    sys.path.insert(0, str(HERE.parent / "unicorn"))
    sys.path.insert(0, str(HERE.parent / "ghidra"))
    from concrete import ConcreteMachine  # noqa: E402
    import aptrace_ghidra as ghidra  # noqa: E402

    fw = census_db.get_firmware_id(conn, firmware_key)
    fw_path, flash_base_s, _load = ghidra.firmware_info(firmware_key)
    machine = ConcreteMachine(fw_path, flash_base=int(flash_base_s, 16),
                               mmio_base=0x40000000, mmio_size=0x4000000)

    fixed_extra_seed = _parse_extra_seed(extra_seed)
    rows = []
    for i in range(count):
        addr = base + i * width
        seed = list(fixed_extra_seed)
        seed.append((addr, b"\x01" + b"\x00" * (width - 1)))
        if index_addr is not None:
            seed.append((index_addr, i.to_bytes(index_width, "little")))

        stop_candidates = [machine.trampoline_addr] + list(tx_wrappers)
        result = machine.run(
            dispatcher_entry, seed_mem=seed,
            reg_seed=[("lr", machine.trampoline_addr | 1)],
            stop_at=stop_candidates,
            dump_reg_pointee=[("r0", 16)],
            max_instructions=max_instructions, label=f"state-map-probe-slot-{i}",
        )

        outcome = "other"
        tx_wrapper_hit = None
        output_hex = None
        depends_on_unresolved = 0
        if result.stopped_at(machine.trampoline_addr):
            outcome = "clean_return"
        else:
            for w in tx_wrappers:
                if result.stopped_at(w):
                    tx_wrapper_hit = w
                    _ptr, raw = result.reg_pointee("r0")
                    if raw is not None:
                        outcome = "string_tx"
                        output_hex = raw.hex()
                        if raw.strip(b"\x00") == b"":
                            depends_on_unresolved = 1
                    else:
                        outcome = "byte_tx"
                        output_hex = f"{result.registers['r0'] & 0xFF:02x}"
                    break
            if tx_wrapper_hit is None and result.error:
                outcome = "error"

        rows.append({
            "run_id": run_id, "firmware_id": fw, "slot_index": i,
            "outcome": outcome, "stop_reason": result.stop_reason,
            "tx_wrapper_addr": tx_wrapper_hit, "output_hex": output_hex,
            "output_depends_on_unresolved_source": depends_on_unresolved,
            "instructions_executed": result.instructions_executed,
            "source": source,
        })

    cols = list(rows[0].keys())
    conn.executemany(
        f"INSERT INTO state_map_dispatcher_probes ({', '.join(cols)}) "
        f"VALUES ({', '.join('?' for _ in cols)})",
        [tuple(r[c] for c in cols) for r in rows])
    conn.commit()
    return rows


def summary_rows(conn, run_id):
    """The deterministic per-slot summary table this module's CLI prints
    -- one row per slot, joining state_map_slots with
    state_map_dispatcher_probes (if any probe was run for this run_id)."""
    slots = conn.execute(
        "SELECT * FROM state_map_slots WHERE run_id=? ORDER BY slot_index", (run_id,)).fetchall()
    probes = {r["slot_index"]: r for r in conn.execute(
        "SELECT * FROM state_map_dispatcher_probes WHERE run_id=? ORDER BY slot_index", (run_id,))}
    out = []
    for s in slots:
        out.append({"slot": s, "probe": probes.get(s["slot_index"])})
    return out
