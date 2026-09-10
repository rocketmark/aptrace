"""APTrace census reduce: a deterministic MCU hardware-configuration
snapshot, decoded from the SAME boot-recipe execution
tools/census/boot_recipes.py already ran for dynamic coverage/indirect-
edge observation (tools/census/reduce.py runs the boot once and reuses
its final machine state here -- never a second, separate boot run) --
using the existing SVD resolver (tools/svd/resolve_mmio.py), no new
peripheral model.

`compute()` takes the already-run `machine` and `result`
(ConcreteMachine / RunResult from `boot_recipes.capture_boot`) plus the
`init_status` ('complete' / 'partial-justified' / 'blocked') and the
recipe's own `assumptions` list, and:

  1. Records one `hardware_snapshot_runs` row -- boot method, stop
     point, the three-way init_status, and the FULL disclosed-
     assumption list as `assumptions_json` (never hidden).
  2. Dumps every in-scope peripheral's raw register bytes
     (`hardware_snapshot`) -- PORT, ADC*, TC*/TCC*, SERCOM*, EIC, DMAC,
     NVMCTRL, USB, WDT, and the clock tree.
  3. Mechanically decodes PORT state into `pin_snapshot` -- direction,
     output/input level, PINCFG raw byte + PMUXEN bit, PMUX raw nibble.
     See pins.py's own docstring for why PMUX's raw nibble is NOT
     further resolved to a named peripheral function here (a per-pin
     datasheet table, not something the SVD's register definitions
     alone encode) -- MCU pin/mux facts only, no physical-connector
     identity anywhere in this table.

Whatever the machine's registers hold at the stop point is reported
as-is; `init_status`/`completed_init` tell a reader how much weight to
give it -- a 'blocked' or 'partial-justified' snapshot is still real
emulator state, just not necessarily post-full-init state.
"""
import datetime
import json

# Peripheral-name prefixes in scope, per the task's list (PORT, ADC,
# TC/TCC, SERCOM, EIC, DMAC, NVMCTRL, USB, watchdog, clocks).
PERIPHERAL_PREFIXES = ("PORT", "ADC", "TC", "TCC", "SERCOM", "EIC", "DMAC", "NVMCTRL",
                        "USB", "WDT", "GCLK", "OSCCTRL", "OSC32KCTRL", "MCLK")


def dump_registers(conn, firmware_id, machine, svd_map, verbose=True):
    rows = []
    scoped = [(base, size, name, regs) for base, size, name, regs in svd_map.peripherals
              if any(name.startswith(p) for p in PERIPHERAL_PREFIXES)]
    for base, size, name, regs in scoped:
        try:
            raw = machine.uc.mem_read(base, size)
        except Exception:  # noqa: BLE001 -- an unmapped/oversized region must not abort the whole dump
            continue
        by_offset = {}
        for regname, off, sz in regs:
            by_offset.setdefault(off, []).append((regname, sz))
        offsets = sorted(by_offset)
        for off in offsets:
            regnames, sz = by_offset[off][0][0], max(s for _n, s in by_offset[off])
            sz = max(sz, 1)
            if off + sz > size:
                continue
            value_bytes = bytes(raw[off:off + sz])
            rows.append({
                "firmware_id": firmware_id, "addr": base + off, "peripheral": name,
                "register_name": "/".join(sorted({n for n, _s in by_offset[off]})),
                "width": sz, "raw_value": value_bytes.hex(), "source": "hardware-snapshot",
            })
    if verbose:
        print(f"  [hardware-snapshot] dumped {len(rows)} register(s) across {len(scoped)} peripheral(s)")
    from db import replace_firmware_rows
    replace_firmware_rows(conn, firmware_id, "hardware_snapshot", rows)
    conn.commit()
    return rows


def decode_pins(conn, firmware_id, machine, svd_map):
    """Mechanical, register-arithmetic-only decode of PORT state into a
    per-pin table -- DIR/OUT/IN bitmask bits, PINCFG raw byte, PMUX
    enable bit + raw nibble. See pins.py's module docstring for why
    PMUX's raw nibble is NOT further resolved to a named peripheral
    function here (that mapping is a per-pin datasheet table, not
    something the SVD's register definitions alone encode)."""
    port = next(((base, size, regs) for base, size, name, regs in svd_map.peripherals if name == "PORT"), None)
    if port is None:
        return []
    base, size, regs = port
    by_name = {}
    for regname, off, sz in regs:
        by_name.setdefault(regname, (off, sz))

    groups = sorted({int(n.split(".")[0][5:]) for n in by_name if n.startswith("GROUP")})
    rows = []
    for g in groups:
        def reg32(suffix):
            key = f"GROUP{g}.{suffix}"
            if key not in by_name:
                return None
            off, _sz = by_name[key]
            try:
                return int.from_bytes(machine.uc.mem_read(base + off, 4), "little")
            except Exception:  # noqa: BLE001
                return None

        dir_val, out_val, in_val = reg32("DIR"), reg32("OUT"), reg32("IN")
        for pin_index in range(32):
            pincfg_key = f"GROUP{g}.PINCFG{pin_index}"
            pmux_key = f"GROUP{g}.PMUX{pin_index // 2}"
            pincfg_raw = None
            if pincfg_key in by_name:
                off, _sz = by_name[pincfg_key]
                try:
                    pincfg_raw = machine.uc.mem_read(base + off, 1)[0]
                except Exception:  # noqa: BLE001
                    pincfg_raw = None
            pmux_raw = None
            if pmux_key in by_name:
                off, _sz = by_name[pmux_key]
                try:
                    pmux_byte = machine.uc.mem_read(base + off, 1)[0]
                except Exception:  # noqa: BLE001
                    pmux_byte = None
                if pmux_byte is not None:
                    pmux_raw = (pmux_byte >> 4 & 0xF) if pin_index % 2 else (pmux_byte & 0xF)
            direction = None
            if dir_val is not None:
                direction = "OUT" if (dir_val >> pin_index) & 1 else "IN"
            rows.append({
                "firmware_id": firmware_id, "pin_name": f"P{chr(ord('A') + g)}{pin_index:02d}",
                "group_index": g, "pin_index": pin_index, "direction": direction,
                "output_value": ((out_val >> pin_index) & 1) if out_val is not None else None,
                "input_value": ((in_val >> pin_index) & 1) if in_val is not None else None,
                "pincfg_raw": pincfg_raw,
                "pmuxen": ((pincfg_raw >> 1) & 1) if pincfg_raw is not None else None,
                "pmux_nibble": pmux_raw, "source": "hardware-snapshot",
            })

    from db import replace_firmware_rows
    replace_firmware_rows(conn, firmware_id, "pin_snapshot", rows)
    conn.commit()
    return rows


def compute(conn, firmware_id, firmware_key, machine, result, recipe, init_status, svd_map, verbose=True):
    """Persist the hardware snapshot from an ALREADY-RUN boot capture
    (see boot_recipes.capture_boot) -- does not run Unicorn itself."""
    boot_method = recipe["reference_key"] if recipe else None
    assumptions = recipe.get("assumptions", []) if recipe else []
    notes = (f"reference recipe: {recipe['reference_key']}" if recipe else "no boot recipe available") + \
        f"; init_status={init_status}"

    conn.execute("DELETE FROM hardware_snapshot_runs WHERE firmware_id=?", (firmware_id,))
    conn.execute(
        "INSERT INTO hardware_snapshot_runs (firmware_id, boot_method, init_status, stop_addr, "
        "instructions_executed, stop_reason, completed_init, notes, assumptions_json, ran_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (firmware_id, boot_method, init_status, None,
         result.instructions_executed if result else None,
         result.stop_reason if result else None,
         int(init_status == "complete"), notes, json.dumps(assumptions),
         datetime.datetime.now(datetime.timezone.utc).isoformat()))
    conn.commit()

    if verbose:
        print(f"  [hardware-snapshot] {firmware_key}: init_status={init_status} "
              f"({len(assumptions)} disclosed assumption(s))")

    if machine is None:
        return None

    dump_registers(conn, firmware_id, machine, svd_map, verbose=verbose)
    decode_pins(conn, firmware_id, machine, svd_map)
    return {"init_status": init_status, "boot_method": boot_method}
