#!/usr/bin/env python3
"""APTrace Performing Rigs case: run the real, unmodified AutoPilot868/
AutoPilot915 firmware images under BOTH the AutoPilot hardware profile
(AUTOPILOT_RECIPE, already-proven to reach main-loop steady state -- see
docs/investigations/boot-and-hardware-bringup.md) and the Feather M4
hardware profile (FEATHER_M4_PROFILE, cases/performing-rigs/config/boot_recipes.py)
and record a structured snapshot of each run for
docs/investigations/feather-m4-feasibility.md.

Reuses boot_recipes.py's OWN `build_machine`/`apply_recipe`/
`init_status_for` helpers -- the exact same path tools/census/reduce.py
uses for a real boot capture -- rather than re-deriving ConcreteMachine
construction/run parameters by hand. No change to concrete.py or
boot_recipes.py's existing functions; FEATHER_M4_PROFILE is additive.

Opens the canonical census DB read-only (mode=ro), per CLAUDE.md's
"run experiments against... read-only" discipline; never writes to it.
Writes ONLY to this script's own --out-dir (not the shared scenario
corpus / dynamic_export path capture_boot normally uses), since this is
a one-off investigation comparison, not a census-pipeline capture.

Usage:
    tools/unicorn/.venv/bin/python3 \\
        cases/performing-rigs/scripts/feather_m4_compare.py \\
        --out-dir cases/performing-rigs/research/generated/feather-m4
"""
import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "cases" / "performing-rigs" / "config"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "census"))

import boot_recipes as br  # noqa: E402
import db as census_db  # noqa: E402

FIRMWARE_PATHS = {
    "autopilot868": REPO_ROOT / "cases/performing-rigs/research/firmware/originals/firmware_autopilot868.bin",
    "autopilot915": REPO_ROOT / "cases/performing-rigs/research/firmware/originals/firmware_autopilot915.bin",
}


def sha256_of(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_recipe(fw_row, fw_path, recipe, max_instructions):
    machine = br.build_machine(recipe, str(fw_path), fw_row["flash_base"], fw_row["ram_base"],
                                 fw_row["ram_size"], fw_row["mmio_base"], fw_row["mmio_size"])
    return br.apply_recipe(machine, recipe, max_instructions=max_instructions)


def milestone_summary(result_dict, recipe):
    """result_dict is RunResult.to_dict() -- watch_hits there already
    carry hex-string addresses/instruction counts in the project's own
    established JSON shape; reused as-is, not re-derived."""
    by_addr = {}
    for hit in result_dict["watch_hits"]:
        by_addr.setdefault(hit["address"], []).append(hit)
    out = []
    for addr, label in recipe.get("milestones", {}).items():
        key = f"0x{addr:08x}"
        hits = by_addr.get(key, [])
        out.append({
            "addr": key, "label": label, "hit_count": len(hits),
            "first_instruction": hits[0]["instruction"] if hits else None,
            "last_instruction": hits[-1]["instruction"] if hits else None,
        })
    return out


def summarize(fw_key, profile_name, recipe, result, max_instructions, init_status):
    d = result.to_dict()
    return {
        "firmware_key": fw_key,
        "firmware_sha256": sha256_of(FIRMWARE_PATHS[fw_key]),
        "hardware_profile": profile_name,
        "reference_key": recipe["reference_key"],
        "entry": f"0x{recipe['entry']:08x}",
        "max_instructions_requested": max_instructions,
        "instructions_executed": d["instructions_executed"],
        "stop_reason": d["stop_reason"],
        "error": d["error"],
        "error_free": d["error_free"],
        "completed": d["completed"],
        "init_status": init_status,
        "final_registers": d["registers"],
        "milestones": milestone_summary(d, recipe),
        "watch_hit_count": len(d["watch_hits"]),
        "watch_hits_sample": d["watch_hits"][:30],
        "mmio_log_sample": d["mmio_log"][:200],
        "mmio_log_count": len(d["mmio_log"]),
        "visited_pc_count": len(d["visited_pcs"]) if d["visited_pcs"] is not None else None,
        "assumptions_applied": recipe["assumptions"],
        "recent_pcs": d["recent_pcs"],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--autopilot-max-instructions", type=int, default=450_000)
    ap.add_argument("--feather-max-instructions", type=int, default=4_000_000,
                     help="larger budget to confirm a DETERMINISTIC repeating pattern, not just one observation")
    args = ap.parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(f"file:{census_db.DEFAULT_DB_PATH.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    all_summaries = []
    for fw_key in ("autopilot868", "autopilot915"):
        fw_row = conn.execute("SELECT * FROM firmware WHERE key=?", (fw_key,)).fetchone()
        if fw_row is None:
            print(f"SKIP {fw_key}: no census row", file=sys.stderr)
            continue

        autopilot_recipe, gaps = br.resolve_for_firmware(conn, fw_key)
        if autopilot_recipe is None:
            print(f"SKIP {fw_key}: {gaps}", file=sys.stderr)
            continue
        feather_recipe = br.feather_m4_profile_for(autopilot_recipe)

        print(f"=== {fw_key} / autopilot profile ===", file=sys.stderr)
        r_autopilot = run_recipe(fw_row, FIRMWARE_PATHS[fw_key], autopilot_recipe, args.autopilot_max_instructions)
        status_autopilot = br.init_status_for(autopilot_recipe, r_autopilot)
        s_autopilot = summarize(fw_key, "autopilot", autopilot_recipe, r_autopilot,
                                  args.autopilot_max_instructions, status_autopilot)
        s_autopilot["remap_gaps"] = gaps
        all_summaries.append(s_autopilot)
        print(f"  init_status={status_autopilot} stop_reason={r_autopilot.stop_reason} "
              f"instructions={r_autopilot.instructions_executed}", file=sys.stderr)

        print(f"=== {fw_key} / feather_m4 profile ===", file=sys.stderr)
        r_feather = run_recipe(fw_row, FIRMWARE_PATHS[fw_key], feather_recipe, args.feather_max_instructions)
        status_feather = br.init_status_for(feather_recipe, r_feather)
        s_feather = summarize(fw_key, "feather_m4", feather_recipe, r_feather,
                                args.feather_max_instructions, status_feather)
        s_feather["remap_gaps"] = gaps
        all_summaries.append(s_feather)
        print(f"  init_status={status_feather} stop_reason={r_feather.stop_reason} "
              f"instructions={r_feather.instructions_executed}", file=sys.stderr)

        (out_dir / f"{fw_key}_autopilot_profile.json").write_text(json.dumps(s_autopilot, indent=2, default=str))
        (out_dir / f"{fw_key}_feather_m4_profile.json").write_text(json.dumps(s_feather, indent=2, default=str))

    (out_dir / "summary.json").write_text(json.dumps(all_summaries, indent=2, default=str))
    print(f"Wrote {len(all_summaries)} run summaries to {out_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()
