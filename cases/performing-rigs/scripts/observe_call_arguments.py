#!/usr/bin/env python3
"""Observe the arguments that actually reach one function during one of
this case's registered concrete scenarios (config/observation_scenarios.json).

Two scenario kinds:

  boot-recipe   the canonical boot recipe (cases/performing-rigs/config/
                boot_recipes.py, the same recipe and geometry the census
                boot capture uses), run once from Reset_Handler.
  virtual-link  one existing scenario of scripts/virtual_link.py, run
                unmodified. ConcreteMachine.run is wrapped for the duration
                of that one scenario (the dynamic_export.py technique); on
                legs that execute the target firmware the wrapper adds the
                passive observation below and removes it from the result
                before the scenario's own code sees it.

On every entry to the function the run captures r0-r3, LR and the 4 bytes
each argument register points at. The framework summarizer
(tools/unicorn/call_observation.py) attributes each entry to its call
instruction and classifies every value against the run's geometry.

Optionally:

  --extent LO:HI          every MMIO access the run logged with a PC inside
                          [LO, HI): an independent concrete observation of
                          which peripheral registers code there touched.
  --watch ADDR:LEN[@OBJ]  a small RAM field (at most 8 fields of at most 16
                          bytes) whose CPU stores are recorded with the
                          bytes they overwrote; OBJ names the object base
                          the field belongs to, so a store through that
                          object pointer is distinguished from a computed
                          one. Each argument value pointing into a watched
                          field is correlated with that field's history.

Prints one JSON document to stdout. It contains no timestamps or runtimes,
so identical inputs give an identical document. Run with the Unicorn venv:

    tools/unicorn/.venv/bin/python3 cases/performing-rigs/scripts/observe_call_arguments.py \\
        --firmware-key autopilot868 --entry 0xb4b4 [--scenario boot] \\
        [--extent 0xb4b4:0xb500] [--watch 0x20004c54:4]
"""
import argparse
import contextlib
import hashlib
import inspect
import json
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
CASE = REPO_ROOT / "cases" / "performing-rigs"
sys.path.insert(0, str(CASE / "config"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "unicorn"))
sys.path.insert(0, str(HERE))

import boot_recipes  # noqa: E402
import call_observation  # noqa: E402

DEFAULT_DB = CASE / "research" / "runs" / "census" / "census.sqlite3"
SCENARIOS_PATH = CASE / "config" / "observation_scenarios.json"
POINTEE_BYTES = 4
MAX_ENTRY_HITS = 20_000
MAX_MMIO_LOG = 400_000
MAX_WATCH_FIELDS = 8
MAX_WATCH_BYTES = 16
MAX_WRITE_EVENTS = 4_000


def _hex(v):
    return f"0x{v:08x}"


def load_scenarios(path=SCENARIOS_PATH):
    return json.loads(Path(path).read_text())["scenarios"]


def parse_watch(spec):
    """'ADDR:LEN' or 'ADDR:LEN@OBJECT_BASE' -> field dict (unvalidated)."""
    field, _, obj = spec.partition("@")
    addr, _, length = field.partition(":")
    return {"name": f"{int(addr, 0):#010x}+{int(length, 0)}", "address": int(addr, 0), "size": int(length, 0),
            "object_base": int(obj, 0) if obj else None}


def validate_watch(fields, ram_base, ram_size):
    if len(fields) > MAX_WATCH_FIELDS:
        raise SystemExit(f"at most {MAX_WATCH_FIELDS} watched fields")
    spans = sorted((f["address"], f["address"] + f["size"]) for f in fields)
    for f in fields:
        if not 1 <= f["size"] <= MAX_WATCH_BYTES:
            raise SystemExit(f"watched field {f['name']}: size must be 1..{MAX_WATCH_BYTES}")
        if not (ram_base <= f["address"] and f["address"] + f["size"] <= ram_base + ram_size):
            raise SystemExit(f"watched field {f['name']} is not inside RAM")
    if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
        raise SystemExit("watched fields overlap")


class _Census:
    """Firmware row and heuristic function boundaries from the census DB."""

    def __init__(self, db_path, firmware_key):
        self.conn = sqlite3.connect(f"{Path(db_path).resolve().as_uri()}?mode=ro", uri=True)
        self.conn.row_factory = sqlite3.Row
        row = self.conn.execute(
            "SELECT id, path, sha256, flash_base, size_bytes, ram_base, ram_size, mmio_base, mmio_size "
            "FROM firmware WHERE key = ?", (firmware_key,)).fetchone()
        if row is None:
            raise SystemExit(f"unknown firmware key {firmware_key!r}")
        self.row = row
        self.path = REPO_ROOT / row["path"]
        self.image = self.path.read_bytes()
        if hashlib.sha256(self.image).hexdigest() != row["sha256"]:
            raise SystemExit("firmware image hash mismatch")

    def function_of(self, pc):
        hit = self.conn.execute(
            "SELECT entry FROM functions WHERE firmware_id = ? AND entry <= ? AND ? < entry + size "
            "ORDER BY entry DESC LIMIT 1", (self.row["id"], pc, pc)).fetchone()
        return f"FUN_{hit['entry']:08x}" if hit else None

    def read_halfword(self, addr):
        off = addr - self.row["flash_base"]
        if 0 <= off <= len(self.image) - 2:
            return int.from_bytes(self.image[off:off + 2], "little")
        return None

    def read_code(self, addr):
        off = addr - self.row["flash_base"]
        return self.image[off:off + 4] if 0 <= off <= len(self.image) - 2 else None


def _mmio_in_extent(log, extent):
    lo, hi = extent
    inside = [e for e in log if lo <= int(e["pc"], 16) < hi]
    return {
        "extent": [_hex(lo), _hex(hi)],
        "log_entries": len(log),
        "log_truncated": len(log) >= MAX_MMIO_LOG,
        "accesses": inside[:200],
        "access_count": len(inside),
    }


def _watched(census, fields, writes, final, dropped):
    return call_observation.summarize_watched_writes(
        writes, fields=fields, read_code=census.read_code, function_of=census.function_of,
        final_bytes=final, dropped=dropped)


def _correlation(census, hits, entry, watched, regions):
    out = []
    for reg in call_observation.ARGUMENT_REGISTERS:
        out += [g for g in call_observation.correlate_calls_with_fields(
            hits, entry=entry, register=reg, watched=watched, regions=regions,
            read_halfword=census.read_halfword) if g["field"] is not None]
    return out


# -- boot recipe ------------------------------------------------------------

def _observe_boot(census, firmware_key, entry, extent, fields, max_instructions):
    row = census.row
    recipe, gaps = boot_recipes.resolve_for_firmware(census.conn, firmware_key)
    if recipe is None:
        return {"status": "no_recipe", "recipe_gaps": gaps}

    machine = boot_recipes.build_machine(recipe, str(census.path), row["flash_base"], row["ram_base"],
                                         row["ram_size"], row["mmio_base"], row["mmio_size"])
    milestone_count = len(recipe.get("milestones", {})) + (recipe.get("steady_state_hits") or 0)
    result = boot_recipes.apply_recipe(
        machine, recipe, extra_watch=[entry], collect_coverage=False, log_mmio=extent is not None,
        max_watch_hits=milestone_count + MAX_ENTRY_HITS,
        watch_reg_pointee=[(r, POINTEE_BYTES) for r in call_observation.ARGUMENT_REGISTERS],
        max_mmio_log=MAX_MMIO_LOG,
        watch_mem_write=[(f["address"], f["size"]) for f in fields], max_mem_write_log=MAX_WRITE_EVENTS,
        dump_mem=[(f["address"], f["size"]) for f in fields], max_instructions=max_instructions,
    )

    regions = [("FLASH", row["flash_base"], row["size_bytes"]), ("RAM", row["ram_base"], row["ram_size"]),
               ("MMIO", row["mmio_base"], row["mmio_size"])]
    summary = call_observation.summarize_entry_observations(
        result.watch_hits, entry=entry, regions=regions, read_halfword=census.read_halfword)

    stop = result.stop_reason or ""
    truncated = stop.startswith("max watch hits")
    milestones = sorted({h["address"] for h in result.watch_hits
                         if int(h["address"], 16) in recipe.get("milestones", {})})
    budget = max_instructions or recipe.get("max_instructions")
    doc = {
        "status": "bounded: entry watch cap reached" if truncated else "ok",
        "scenario": "boot",
        "firmware_key": firmware_key,
        "firmware_sha256": row["sha256"],
        "recipe": {
            "reference_key": recipe["reference_key"],
            "entry": _hex(recipe["entry"]),
            "max_instructions": budget,
            "gaps": gaps,
            "assumptions": [
                {"kind": a["kind"], "addr": _hex(a["addr"]), "detail": a["detail"]}
                for a in recipe.get("assumptions", [])
            ],
        },
        "run": {
            "stop_reason": stop,
            "instructions_executed": result.instructions_executed,
            "budget_exhausted": stop == "instruction limit reached",
            "init_status": boot_recipes.init_status_for(recipe, result),
            "milestones_reached": milestones,
        },
        "geometry": [{"region": n, "base": _hex(b), "size": _hex(s)} for n, b, s in regions],
        "observation": summary,
    }

    if extent is not None:
        doc["mmio_in_extent"] = _mmio_in_extent(result.to_dict().get("mmio_log") or [], extent)

    if fields:
        final = {f["name"]: result.mem(f["address"], f["size"]).hex() for f in fields}
        watched = _watched(census, fields, result.mem_write_hits, final, result.mem_write_dropped)
        doc["watched_fields"] = watched
        doc["correlation"] = _correlation(census, result.watch_hits, entry, watched, regions)
    return doc


# -- virtual-link scenarios ---------------------------------------------------

def _observe_virtual_link(census, firmware_key, scenario, spec, entry, extent, fields):
    import concrete
    import virtual_link

    target = census.path.resolve()
    original = concrete.ConcreteMachine.run
    signature = inspect.signature(original)
    own_ranges = {f"0x{f['address']:08x}:{f['size']}" for f in fields}
    legs, hits, writes, mmio = [], [], [], []
    state = {"dropped": 0, "final": {}, "geometry": None, "truncated": False}

    def observed_run(self, *args, **kwargs):
        bound = signature.bind(self, *args, **kwargs)
        bound.apply_defaults()
        a = bound.arguments
        on_target = Path(self.firmware_path).resolve() == target
        index = len(legs)

        if on_target:
            scenario_watch = {w & ~1 for w in a["watch"]}
            a["watch"] = sorted(scenario_watch | {entry})
            a["max_watch_hits"] = a["max_watch_hits"] + MAX_ENTRY_HITS
            have = {r for r, _n in a["watch_reg_pointee"]}
            a["watch_reg_pointee"] = list(a["watch_reg_pointee"]) + [
                (r, POINTEE_BYTES) for r in call_observation.ARGUMENT_REGISTERS if r not in have]
            scenario_ranges = {f"0x{x:08x}:{n}" for x, n in a["watch_mem_write"]}
            a["watch_mem_write"] = list(a["watch_mem_write"]) + [(f["address"], f["size"]) for f in fields]
            a["max_mem_write_log"] = a["max_mem_write_log"] + MAX_WRITE_EVENTS
            scenario_dumps = set(a["dump_mem"])
            a["dump_mem"] = list(a["dump_mem"]) + [(f["address"], f["size"]) for f in fields
                                                   if (f["address"], f["size"]) not in scenario_dumps]
            scenario_mmio = a["log_mmio"]
            if extent is not None:
                a["log_mmio"], a["max_mmio_log"] = True, max(a["max_mmio_log"], MAX_MMIO_LOG)

        result = original(*bound.args, **bound.kwargs)
        leg = {
            "leg": index,
            "firmware": Path(self.firmware_path).name,
            "observed": on_target,
            "label": a.get("label"),
            "entry": _hex(a["entry"] & ~1),
            "fresh": a["fresh"],
            "instructions_executed": result.instructions_executed,
            "stop_reason": result.stop_reason,
            "error": result.error,
            # Harness inputs of this leg, as the scenario supplied them.
            "sp": None if a["sp"] is None else _hex(a["sp"]),
            "reg_seed": [[n, _hex(v & 0xFFFFFFFF)] for n, v in a["reg_seed"]],
            "seeds": result.applied_seeds,
            "stub_calls": [_hex(x) for x in a["stub_calls"]],
            "forced": {k: len(a[k]) for k in ("force_reg", "force_mem", "fake_tick", "mmio_force_bits", "mmio_clear_bits")
                       if a[k]},
        }
        legs.append(leg)

        if not on_target:
            return result

        state["geometry"] = state["geometry"] or [
            ("FLASH", self.flash_base, len(self.firmware)), ("RAM", self.ram_base, self.ram_size),
            ("MMIO", self.mmio_base, self.mmio_size)]
        if (result.stop_reason or "").startswith("max watch hits"):
            state["truncated"] = True

        mine = [dict(h, leg=index) for h in result.watch_hits if int(h["address"], 16) == entry]
        hits.extend(mine)
        leg["entries"] = len(mine)
        if entry not in scenario_watch:
            result.watch_hits = [h for h in result.watch_hits if int(h["address"], 16) != entry]

        writes.extend(dict(w, leg=index) for w in result.mem_write_hits if w["range"] in own_ranges)
        result.mem_write_hits = [w for w in result.mem_write_hits
                                 if w["range"] not in own_ranges or w["range"] in scenario_ranges]
        state["dropped"] += result.mem_write_dropped
        for f in fields:
            key = (f["address"], f["size"])
            state["final"][f["name"]] = result.memory[key].hex()
            if key not in scenario_dumps:
                del result.memory[key]

        if extent is not None:
            mmio.extend(dict(e, leg=index) for e in result.mmio_log)
            if not scenario_mmio:
                result.mmio_log = []
        return result

    runner = getattr(virtual_link, spec["runner"])
    status, failure = "ok", None
    concrete.ConcreteMachine.run = observed_run
    try:
        with contextlib.redirect_stdout(sys.stderr):
            outcome = runner(verbose=False)
        if not outcome:
            status, failure = "scenario_failed: runner reported failure", None
    except Exception as exc:  # the scenario's own assertion or harness error: recorded
        status, failure = "scenario_failed", f"{type(exc).__name__}: {str(exc)[:300]}"
    finally:
        concrete.ConcreteMachine.run = original
        virtual_link._machines.clear()

    observed = [leg for leg in legs if leg["observed"]]
    if not observed:
        status = f"unsupported: scenario executed no {firmware_key} code"
    elif status == "ok" and state["truncated"]:
        status = "bounded: entry watch cap reached"

    regions = state["geometry"] or []
    doc = {
        "status": status,
        "scenario": scenario,
        "firmware_key": firmware_key,
        "firmware_sha256": census.row["sha256"],
        "scenario_failure": failure,
        "run": {
            "legs": len(legs),
            "observed_legs": len(observed),
            "instructions_executed": sum(leg["instructions_executed"] for leg in observed),
            "budget_exhausted_legs": sum(1 for leg in observed if leg["stop_reason"] == "instruction limit reached"),
            "errored_legs": sum(1 for leg in observed if leg["error"]),
        },
        "legs": legs,
        "geometry": [{"region": n, "base": _hex(b), "size": _hex(s)} for n, b, s in regions],
        "observation": call_observation.summarize_entry_observations(
            hits, entry=entry, regions=regions, read_halfword=census.read_halfword),
    }

    if extent is not None:
        doc["mmio_in_extent"] = _mmio_in_extent(mmio, extent)

    if fields:
        watched = _watched(census, fields, writes, state["final"], state["dropped"])
        doc["watched_fields"] = watched
        doc["correlation"] = _correlation(census, hits, entry, watched, regions)
    return doc


def observe(firmware_key, entry, extent=None, db_path=DEFAULT_DB, scenario="boot", watch=(),
            max_instructions=None, scenarios_path=SCENARIOS_PATH):
    scenarios = load_scenarios(scenarios_path)
    if scenario not in scenarios:
        raise SystemExit(f"unknown scenario {scenario!r}; registered: {', '.join(sorted(scenarios))}")
    spec = scenarios[scenario]
    census = _Census(db_path, firmware_key)
    fields = [parse_watch(w) for w in watch]
    validate_watch(fields, census.row["ram_base"], census.row["ram_size"])
    if max_instructions is not None and spec["kind"] != "boot-recipe":
        raise SystemExit("--max-instructions applies only to the boot recipe")

    config = {"id": scenario, **spec,
              "registry_sha256": hashlib.sha256(Path(scenarios_path).read_bytes()).hexdigest()}

    if firmware_key not in spec["firmware_keys"]:
        doc = {"status": f"unsupported: scenario {scenario!r} does not execute {firmware_key}",
               "scenario": scenario, "firmware_key": firmware_key, "firmware_sha256": census.row["sha256"],
               "run": {"instructions_executed": 0},
               "observation": call_observation.summarize_entry_observations(
                   [], entry=entry, regions=[], read_halfword=census.read_halfword)}
    elif spec["kind"] == "boot-recipe":
        doc = _observe_boot(census, firmware_key, entry, extent, fields, max_instructions)
    elif spec["kind"] == "virtual-link":
        doc = _observe_virtual_link(census, firmware_key, scenario, spec, entry, extent, fields)
    else:
        raise SystemExit(f"scenario {scenario!r} has unsupported kind {spec['kind']!r}")

    doc["scenario_config"] = config
    return doc


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--firmware-key", required=True)
    p.add_argument("--entry", required=True, type=lambda s: int(s, 0))
    p.add_argument("--scenario", default="boot")
    p.add_argument("--extent", default=None, help="LO:HI code range for the MMIO cross-check")
    p.add_argument("--watch", action="append", default=[], help="ADDR:LEN[@OBJECT_BASE] RAM field to watch")
    p.add_argument("--max-instructions", type=int, default=None, help="boot recipe budget override")
    p.add_argument("--db", default=str(DEFAULT_DB))
    args = p.parse_args(argv)
    extent = tuple(int(x, 0) for x in args.extent.split(":")) if args.extent else None
    doc = observe(args.firmware_key, args.entry & ~1, extent, args.db, args.scenario, args.watch,
                  args.max_instructions)
    print(json.dumps(doc, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
