#!/usr/bin/env python3
"""APTrace Performing Rigs case: regression coverage for
config/boot_recipes.py's FEATHER_M4_PROFILE and config/feather_m4.py --
see docs/investigations/feather-m4-feasibility.md for the full
investigation these assertions support.

Deliberately not pytest-based, matching cases/performing-rigs/test/
test_concrete.py's own convention -- plain assertions, run as a script.
Exit code 0 means everything passed.

Opens the canonical census DB read-only (mode=ro); never writes to it.
"""
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
sys.path.insert(0, str(REPO_ROOT / "cases" / "performing-rigs" / "config"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "census"))

import boot_recipes as br  # noqa: E402
import feather_m4  # noqa: E402
import db as census_db  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def test_feather_profile_derivation():
    print("test_feather_profile_derivation (AUTOPILOT_RECIPE untouched, FEATHER_M4_PROFILE correctly derived)")
    check("AUTOPILOT_RECIPE still has its force_reg stand-in",
          br.AUTOPILOT_RECIPE["force_reg"] == [(0x9dd4, "r0", 0x12)])
    check("AUTOPILOT_RECIPE still has its PA22 seed",
          br.AUTOPILOT_RECIPE["seed_mem"] == [(0x41008020, (0x400000).to_bytes(4, "little"))])
    check("FEATHER_M4_PROFILE drops force_reg", br.FEATHER_M4_PROFILE["force_reg"] == [])
    check("FEATHER_M4_PROFILE drops seed_mem", br.FEATHER_M4_PROFILE["seed_mem"] == [])
    check("FEATHER_M4_PROFILE keeps the clock/PLL mmio_force_bits",
          br.FEATHER_M4_PROFILE["mmio_force_bits"] == br.AUTOPILOT_RECIPE["mmio_force_bits"])
    check("FEATHER_M4_PROFILE keeps the SERCOM mmio_clear_bits",
          br.FEATHER_M4_PROFILE["mmio_clear_bits"] == br.AUTOPILOT_RECIPE["mmio_clear_bits"])
    check("FEATHER_M4_PROFILE keeps the fake_tick mechanism",
          br.FEATHER_M4_PROFILE["fake_tick"] == br.AUTOPILOT_RECIPE["fake_tick"])
    check("FEATHER_M4_PROFILE keeps the DWT stub_call",
          br.FEATHER_M4_PROFILE["stub_calls"] == br.AUTOPILOT_RECIPE["stub_calls"])
    check("FEATHER_M4_PROFILE keeps the NVM calibration-row map_page",
          br.FEATHER_M4_PROFILE["map_pages"] == br.AUTOPILOT_RECIPE["map_pages"])
    check("FEATHER_M4_PROFILE is tagged with its base reference",
          br.FEATHER_M4_PROFILE["base_reference_key"] == "autopilot868")
    check("Same entry point as AUTOPILOT_RECIPE (same firmware, unmodified)",
          br.FEATHER_M4_PROFILE["entry"] == br.AUTOPILOT_RECIPE["entry"])


def test_feather_m4_pin_table():
    print("test_feather_m4_pin_table (QSPI collision pins exactly as documented)")
    check("QSPI_FLASH_PINS is exactly the 6 documented pins",
          set(feather_m4.QSPI_FLASH_PINS) == {"PB10", "PB11", "PA08", "PA09", "PA10", "PA11"})
    for pin in feather_m4.QSPI_FLASH_PINS:
        check(f"{pin} is marked an onboard-component collision in FEATHER_M4_PINS",
              feather_m4.FEATHER_M4_PINS[pin]["exposure"] == "onboard-component")
    check("PA24 (USB D-) is fixed-function", feather_m4.FEATHER_M4_PINS["PA24"]["exposure"] == "fixed-function")
    check("PA25 (USB D+) is fixed-function", feather_m4.FEATHER_M4_PINS["PA25"]["exposure"] == "fixed-function")
    check("PA23 (onboard LED) is an onboard component",
          feather_m4.FEATHER_M4_PINS["PA23"]["exposure"] == "onboard-component")
    check("PB30/PB31 (AutoPilot's shared reload pulses) are NOT in Feather's pin table",
          "PB30" not in feather_m4.FEATHER_M4_PINS and "PB31" not in feather_m4.FEATHER_M4_PINS)


def test_autopilot_profile_still_reaches_steady_state():
    print("test_autopilot_profile_still_reaches_steady_state (regression, both images)")
    conn = sqlite3.connect(f"file:{census_db.DEFAULT_DB_PATH.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    for fw_key in ("autopilot868", "autopilot915"):
        fw_row = conn.execute("SELECT * FROM firmware WHERE key=?", (fw_key,)).fetchone()
        if fw_row is None:
            check(f"{fw_key}: census row exists", False, "no census row -- run census build first")
            continue
        fw_path = REPO_ROOT / f"cases/performing-rigs/research/firmware/originals/firmware_{fw_key}.bin"
        recipe, gaps = br.resolve_for_firmware(conn, fw_key)
        check(f"{fw_key}: autopilot recipe resolves with no gaps", recipe is not None and gaps == [], gaps)
        if recipe is None:
            continue
        machine = br.build_machine(recipe, str(fw_path), fw_row["flash_base"], fw_row["ram_base"],
                                     fw_row["ram_size"], fw_row["mmio_base"], fw_row["mmio_size"])
        result = br.apply_recipe(machine, recipe)
        status = br.init_status_for(recipe, result)
        check(f"{fw_key}: autopilot profile reaches init_status=complete", status == "complete", status)
        check(f"{fw_key}: autopilot profile error_free", result.error is None, result.error)


def test_feather_profile_blocked_before_main_loop():
    print("test_feather_profile_blocked_before_main_loop (both images, bounded)")
    conn = sqlite3.connect(f"file:{census_db.DEFAULT_DB_PATH.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    BUDGET = 500_000  # well past the AutoPilot profile's own 403199-instruction steady-state run
    for fw_key in ("autopilot868", "autopilot915"):
        fw_row = conn.execute("SELECT * FROM firmware WHERE key=?", (fw_key,)).fetchone()
        if fw_row is None:
            continue
        fw_path = REPO_ROOT / f"cases/performing-rigs/research/firmware/originals/firmware_{fw_key}.bin"
        autopilot_recipe, gaps = br.resolve_for_firmware(conn, fw_key)
        if autopilot_recipe is None:
            check(f"{fw_key}: autopilot recipe resolves", False, gaps)
            continue
        feather_recipe = br.feather_m4_profile_for(autopilot_recipe)
        machine = br.build_machine(feather_recipe, str(fw_path), fw_row["flash_base"], fw_row["ram_base"],
                                     fw_row["ram_size"], fw_row["mmio_base"], fw_row["mmio_size"])
        result = br.apply_recipe(machine, feather_recipe, max_instructions=BUDGET)
        check(f"{fw_key}: feather profile error_free", result.error is None, result.error)
        check(f"{fw_key}: feather profile never reaches the real main loop (0x8960) in {BUDGET} instructions",
              not any(h["address"] == "0x00008960" for h in result.watch_hits))
        check(f"{fw_key}: feather profile never reaches the radio-ID probe (0x9dd4)",
              not any(h["address"] == "0x00009dd4" for h in result.watch_hits))
        check(f"{fw_key}: feather profile does reach boot/init entry (0x9464)",
              any(h["address"] == "0x00009464" for h in result.watch_hits))


def test_pa22_jumper_variant_clears_homing_loop_then_stalls_at_radio_probe():
    """Cheap, no-hardware-needed check behind roadmap.md's item 10 and
    feather-m4-feasibility.md's section 7a: re-adding ONLY the PA22
    seed to the Feather profile (radio stand-in still dropped) models
    "a Feather D12 jumpered to 3V3, no radio chip wired to PA15/16/17".
    """
    print("test_pa22_jumper_variant_clears_homing_loop_then_stalls_at_radio_probe")
    conn = sqlite3.connect(f"file:{census_db.DEFAULT_DB_PATH.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    fw_row = conn.execute("SELECT * FROM firmware WHERE key='autopilot868'").fetchone()
    autopilot_recipe, gaps = br.resolve_for_firmware(conn, "autopilot868")
    feather_recipe = br.feather_m4_profile_for(autopilot_recipe)
    variant = dict(feather_recipe)
    variant["seed_mem"] = [(0x41008020, (0x400000).to_bytes(4, "little"))]
    fw_path = REPO_ROOT / "cases/performing-rigs/research/firmware/originals/firmware_autopilot868.bin"
    machine = br.build_machine(variant, str(fw_path), fw_row["flash_base"], fw_row["ram_base"],
                                 fw_row["ram_size"], fw_row["mmio_base"], fw_row["mmio_size"])
    result = br.apply_recipe(machine, variant, max_instructions=200_000)
    hit_addrs = {h["address"] for h in result.watch_hits}
    check("error_free", result.error is None, result.error)
    check("reaches the homing-loop timeout exit (0x69d8) with PA22 jumpered high",
          "0x000069d8" in hit_addrs)
    check("reaches the radio-ID probe (0x9dd4) right after",
          "0x00009dd4" in hit_addrs)
    check("still never reaches the real main loop (no radio chip on a bare Feather either)",
          "0x00008960" not in hit_addrs)


def main():
    test_feather_profile_derivation()
    test_feather_m4_pin_table()
    test_autopilot_profile_still_reaches_steady_state()
    test_feather_profile_blocked_before_main_loop()
    test_pa22_jumper_variant_clears_homing_loop_then_stalls_at_radio_probe()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s): {FAILURES}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
