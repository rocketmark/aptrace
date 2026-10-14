#!/usr/bin/env python3
"""Observe the arguments that actually reach one function during this
case's canonical boot replay.

Runs the firmware's boot recipe (cases/performing-rigs/config/
boot_recipes.py, the same recipe and geometry the census boot capture
uses) with one extra passive watch at the function entry, capturing r0-r3,
LR and the bytes each argument register points at on every entry. The
framework summarizer (tools/unicorn/call_observation.py) attributes each
entry to its call instruction and classifies every value against the
census geometry.

Optionally (--extent LO:HI) also reports every MMIO access the concrete run
logged with a PC inside [LO, HI): an independent concrete observation of
which peripheral registers code in that range touched.

Prints one JSON document to stdout. It contains no timestamps or runtimes,
so identical inputs give an identical document. Run with the Unicorn venv:

    tools/unicorn/.venv/bin/python3 cases/performing-rigs/scripts/observe_call_arguments.py \\
        --firmware-key autopilot868 --entry 0xb4b4 [--extent 0xb4b4:0xb500]
"""
import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
CASE = REPO_ROOT / "cases" / "performing-rigs"
sys.path.insert(0, str(CASE / "config"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "unicorn"))

import boot_recipes  # noqa: E402
import call_observation  # noqa: E402

DEFAULT_DB = CASE / "research" / "runs" / "census" / "census.sqlite3"
SCENARIO = "boot"
POINTEE_BYTES = 4
MAX_ENTRY_HITS = 20_000
MAX_MMIO_LOG = 400_000


def _hex(v):
    return f"0x{v:08x}"


def observe(firmware_key, entry, extent=None, db_path=DEFAULT_DB):
    conn = sqlite3.connect(f"{Path(db_path).resolve().as_uri()}?mode=ro", uri=True)
    row = conn.execute(
        "SELECT path, sha256, flash_base, size_bytes, ram_base, ram_size, mmio_base, mmio_size "
        "FROM firmware WHERE key = ?", (firmware_key,)).fetchone()
    if row is None:
        raise SystemExit(f"unknown firmware key {firmware_key!r}")
    path, sha, flash_base, flash_size, ram_base, ram_size, mmio_base, mmio_size = row
    fw_path = REPO_ROOT / path
    image = fw_path.read_bytes()
    if hashlib.sha256(image).hexdigest() != sha:
        raise SystemExit("firmware image hash mismatch")

    recipe, gaps = boot_recipes.resolve_for_firmware(conn, firmware_key)
    if recipe is None:
        return {"status": "no_recipe", "recipe_gaps": gaps}

    machine = boot_recipes.build_machine(recipe, str(fw_path), flash_base, ram_base, ram_size, mmio_base, mmio_size)
    milestone_count = len(recipe.get("milestones", {})) + (recipe.get("steady_state_hits") or 0)
    result = boot_recipes.apply_recipe(
        machine, recipe, extra_watch=[entry], collect_coverage=False, log_mmio=extent is not None,
        max_watch_hits=milestone_count + MAX_ENTRY_HITS,
        watch_reg_pointee=[(r, POINTEE_BYTES) for r in call_observation.ARGUMENT_REGISTERS],
        max_mmio_log=MAX_MMIO_LOG,
    )

    def read_halfword(addr):
        off = addr - flash_base
        if 0 <= off <= len(image) - 2:
            return int.from_bytes(image[off:off + 2], "little")
        return None

    regions = [("FLASH", flash_base, flash_size), ("RAM", ram_base, ram_size), ("MMIO", mmio_base, mmio_size)]
    summary = call_observation.summarize_entry_observations(
        result.watch_hits, entry=entry, regions=regions, read_halfword=read_halfword)

    stop = result.stop_reason or ""
    truncated = stop.startswith("max watch hits")
    milestones = sorted({h["address"] for h in result.watch_hits
                         if int(h["address"], 16) in recipe.get("milestones", {})})
    doc = {
        "status": "bounded: entry watch cap reached" if truncated else "ok",
        "scenario": SCENARIO,
        "firmware_key": firmware_key,
        "firmware_sha256": sha,
        "recipe": {
            "reference_key": recipe["reference_key"],
            "entry": _hex(recipe["entry"]),
            "max_instructions": recipe.get("max_instructions"),
            "gaps": gaps,
            "assumptions": [
                {"kind": a["kind"], "addr": _hex(a["addr"]), "detail": a["detail"]}
                for a in recipe.get("assumptions", [])
            ],
        },
        "run": {
            "stop_reason": stop,
            "instructions_executed": result.instructions_executed,
            "init_status": boot_recipes.init_status_for(recipe, result),
            "milestones_reached": milestones,
        },
        "geometry": [{"region": n, "base": _hex(b), "size": _hex(s)} for n, b, s in regions],
        "observation": summary,
    }

    if extent is not None:
        lo, hi = extent
        log = result.to_dict().get("mmio_log") or []
        inside = [e for e in log if lo <= int(e["pc"], 16) < hi]
        doc["mmio_in_extent"] = {
            "extent": [_hex(lo), _hex(hi)],
            "log_entries": len(log),
            "log_truncated": len(log) >= MAX_MMIO_LOG,
            "accesses": inside[:200],
            "access_count": len(inside),
        }
    return doc


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--firmware-key", required=True)
    p.add_argument("--entry", required=True, type=lambda s: int(s, 0))
    p.add_argument("--extent", default=None, help="LO:HI code range for the MMIO cross-check")
    p.add_argument("--db", default=str(DEFAULT_DB))
    args = p.parse_args(argv)
    extent = tuple(int(x, 0) for x in args.extent.split(":")) if args.extent else None
    print(json.dumps(observe(args.firmware_key, args.entry & ~1, extent, args.db), indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
