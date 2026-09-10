"""APTrace census reduce: a deterministic MCU hardware-configuration
snapshot, using the existing Unicorn ConcreteMachine and the existing
SVD resolver (tools/svd/resolve_mmio.py) -- no new peripheral model.

Two boot methods, honestly distinguished (never conflated):

  established-recipe-partial -- for `autopilot868` (and `autopilot915`,
    which the base census already found to be structurally identical
    to `autopilot868` -- same function/block/edge counts). Re-applies,
    VERBATIM, exactly the disclosed clock/oscillator/PLL/SERCOM/NVMCTRL
    MMIO-completion-bit assumptions already published and human-
    confirmed in docs/investigations/boot-and-hardware-bringup.md (the
    fake `RAM tick` counter, the four clock/PLL ready-bit forces, the
    two SERCOM reset-complete/DRE-ready pairs, the NVMCTRL DONE bit) --
    nothing here is a new hardware claim. That investigation's FULL
    recipe also seeds a GPIO-input boundary condition (PA22 held high)
    and stubs a DWT->CYCCNT-based delay whose exact addresses were
    never committed to a reproducible script/doc (only narrated) -- this
    module does NOT invent those (that would be new, uncommitted
    investigative work, out of scope for a mechanical reducer), so this
    run is a real, verbatim SUBSET of the established recipe and is
    named "-partial" specifically because it is not expected to reach
    the full documented steady-state main loop. Reported honestly via
    `completed_init` and `notes`, not silently treated as full boot.

  cold-run-bounded -- for every other image (currently `mando868`/
    `mando915`, which have no published boot recipe at all): entry at
    Reset_Handler, NO disclosed hardware assumptions, bounded by a plain
    instruction cap. Expected, honest result: it stalls at the first
    real hardware-completion-bit wait loop (MMIO is zero-modeled, so a
    "ready" bit the real chip would eventually set never does) -- this
    is not a bug in this module, it is the correct mechanical answer
    for an image nobody has done the (separate, human) bring-up
    investigation for yet.

Either way, the MMIO/PORT/pin state visible in the snapshot is whatever
the machine's registers actually hold at the stop point -- reported
as-is, with `completed_init` telling a reader how much weight to give
it.
"""
import datetime
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Verbatim from docs/investigations/boot-and-hardware-bringup.md's
# "clock/PLL completion bits" table and SERCOM5/SERCOM2/NVMCTRL section
# -- see that doc for the human-confirmed justification of each.
AUTOPILOT_CLOCK_MMIO_FORCE_BITS = [
    (0x4000140c, 0x1),    # OSC32KCTRL.STATUS.XOSC32KRDY
    (0x40001010, 0x100),  # OSCCTRL.STATUS.DFLLRDY
    (0x40001040, 0x3),    # OSCCTRL.DPLL0.DPLLSTATUS.{LOCK,CLKRDY}
    (0x40001054, 0x3),    # OSCCTRL.DPLL1.DPLLSTATUS.{LOCK,CLKRDY}
]
AUTOPILOT_SERCOM_CLEAR_BITS = [
    (0x43000400, 0x1),  # SERCOM5.CTRLA/SYNCBUSY bit0 (SWRST)
    (0x41012000, 0x1),  # SERCOM2.CTRLA/SYNCBUSY bit0 (SWRST)
]
AUTOPILOT_SERCOM_FORCE_BITS = [
    (0x43000418, 0x4),  # SERCOM5.INTFLAG.DRE
    (0x41012018, 0x4),  # SERCOM2.INTFLAG.DRE
]
AUTOPILOT_NVMCTRL_FORCE_BITS = [
    (0x41004010, 0x1),  # NVMCTRL.INTFLAG.DONE
]
AUTOPILOT_FAKE_TICK = [(0x200052ec, 20)]
AUTOPILOT_FORCE_REG = [(0x9dd4, "r0", 0x12)]  # disclosed "no radio module attached" stand-in
# Real milestones named in boot-and-hardware-bringup.md, watched (never
# stopped-at) so the snapshot's notes can honestly report exactly how
# far a real, cited investigation's own checkpoints were reached.
AUTOPILOT_MILESTONES = {
    0x9464: "boot/init entry", 0x69d8: "startup reference/input routine timeout exit",
    0x9dd4: "disclosed radio-ID assumption fires", 0x6190: "post-probe init resumes (1/5)",
    0x4c20: "post-probe init resumes (2/5)", 0x4328: "post-probe init resumes (3/5)",
    0x5d44: "post-probe init resumes (4/5)", 0x7770: "post-probe init resumes (5/5)",
    0x8960: "real main loop receive call",
}

ESTABLISHED_RECIPE_KEYS = {"autopilot868", "autopilot915"}
COLD_RUN_MAX_INSTRUCTIONS = 500_000
ESTABLISHED_RUN_MAX_INSTRUCTIONS = 500_000

# Peripheral-name prefixes in scope, per the task's list (PORT, ADC,
# TC/TCC, SERCOM, EIC, DMAC, NVMCTRL, USB, watchdog, clocks).
PERIPHERAL_PREFIXES = ("PORT", "ADC", "TC", "TCC", "SERCOM", "EIC", "DMAC", "NVMCTRL",
                        "USB", "WDT", "GCLK", "OSCCTRL", "OSC32KCTRL", "MCLK")


def _reset_handler_addr(conn, firmware_id):
    row = conn.execute(
        "SELECT target_addr FROM vectors WHERE firmware_id=? AND vector_index=1", (firmware_id,)).fetchone()
    return row["target_addr"] if row else None


def take_snapshot(firmware_key, firmware_path, flash_base, ram_base, ram_size, mmio_base, mmio_size,
                    reset_addr, verbose=True):
    unicorn_dir = HERE.parent / "unicorn"
    sys.path.insert(0, str(unicorn_dir))
    from concrete import ConcreteMachine  # noqa: E402

    # The SAMD51's real, factory-programmed NVM Software Calibration Row
    # (0x00800080) -- a fixed chip-architecture fact (not firmware- or
    # investigation-specific), already used the same way by
    # tools/unicorn/run_concrete.py's own --map-page option. Mapped as a
    # disclosed zero-filled placeholder for per-die analog trim data
    # (real startup code reads it during clock/ADC calibration); without
    # this, a cold run faults on the very first read of it.
    machine = ConcreteMachine(firmware_path, flash_base=flash_base, ram_base=ram_base, ram_size=ram_size,
                                mmio_base=mmio_base, mmio_size=mmio_size, track_dirty=False,
                                extra_maps=[(0x800080, 0x40)])

    if firmware_key in ESTABLISHED_RECIPE_KEYS:
        boot_method = "established-recipe-partial"
        milestones = list(AUTOPILOT_MILESTONES)
        result = machine.run(
            reset_addr, fake_tick=AUTOPILOT_FAKE_TICK,
            mmio_force_bits=AUTOPILOT_CLOCK_MMIO_FORCE_BITS + AUTOPILOT_SERCOM_FORCE_BITS + AUTOPILOT_NVMCTRL_FORCE_BITS,
            mmio_clear_bits=AUTOPILOT_SERCOM_CLEAR_BITS, force_reg=AUTOPILOT_FORCE_REG,
            watch=milestones, max_watch_hits=10, max_instructions=ESTABLISHED_RUN_MAX_INSTRUCTIONS,
            label="hardware-snapshot",
        )
        hit_addrs = {int(h["address"], 16) for h in result.watch_hits}
        completed_init = 0x8960 in hit_addrs
        last_milestone = max((a for a in hit_addrs), key=lambda a: list(AUTOPILOT_MILESTONES).index(a)) \
            if hit_addrs else None
        notes = (f"applied the established (cited) clock/PLL/SERCOM/NVMCTRL disclosed-assumption subset "
                 f"from docs/investigations/boot-and-hardware-bringup.md verbatim; did NOT seed PA22 or "
                 f"stub the DWT delay (their exact addresses were never committed to a reproducible "
                 f"script) -- milestones reached: "
                 f"{[AUTOPILOT_MILESTONES[a] for a in sorted(hit_addrs, key=lambda a: list(AUTOPILOT_MILESTONES).index(a))]}"
                 + ("" if completed_init else f"; stalled after {AUTOPILOT_MILESTONES.get(last_milestone, 'no milestone')}"))
    else:
        boot_method = "cold-run-bounded"
        result = machine.run(reset_addr, max_instructions=COLD_RUN_MAX_INSTRUCTIONS,
                              label="hardware-snapshot")
        completed_init = False
        notes = ("no published boot recipe exists for this image; ran from Reset_Handler with NO "
                 "disclosed hardware assumptions, bounded by a plain instruction cap -- expected to "
                 "stall at the first real hardware-completion-bit wait loop (MMIO is zero-modeled).")

    if verbose:
        print(f"  [hardware-snapshot] {firmware_key}: boot_method={boot_method} "
              f"instructions={result.instructions_executed} stop_reason={result.stop_reason} "
              f"completed_init={completed_init}")

    run_row = {
        "firmware_id": None, "boot_method": boot_method, "stop_addr": None,
        "instructions_executed": result.instructions_executed, "stop_reason": result.stop_reason,
        "completed_init": int(completed_init), "notes": notes,
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    return machine, run_row


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


def compute(conn, firmware_id, firmware_key, firmware_path, flash_base, ram_base, ram_size,
             mmio_base, mmio_size, svd_map, verbose=True):
    reset_addr = _reset_handler_addr(conn, firmware_id)
    if reset_addr is None:
        if verbose:
            print(f"  [hardware-snapshot] no Reset vector found for '{firmware_key}' -- skipping")
        return None

    machine, run_row = take_snapshot(firmware_key, firmware_path, flash_base, ram_base, ram_size,
                                       mmio_base, mmio_size, reset_addr, verbose=verbose)
    run_row["firmware_id"] = firmware_id
    run_row["stop_addr"] = None

    conn.execute("DELETE FROM hardware_snapshot_runs WHERE firmware_id=?", (firmware_id,))
    conn.execute(
        "INSERT INTO hardware_snapshot_runs (firmware_id, boot_method, stop_addr, instructions_executed, "
        "stop_reason, completed_init, notes, ran_at) VALUES (?,?,?,?,?,?,?,?)",
        (run_row["firmware_id"], run_row["boot_method"], run_row["stop_addr"],
         run_row["instructions_executed"], run_row["stop_reason"], run_row["completed_init"],
         run_row["notes"], run_row["ran_at"]))
    conn.commit()

    dump_registers(conn, firmware_id, machine, svd_map, verbose=verbose)
    decode_pins(conn, firmware_id, machine, svd_map)
    return run_row
