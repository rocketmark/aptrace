#!/usr/bin/env python3
"""Indirect-dispatch resolution v1: can any register-indirect call dispatch
through vtable 0x14900 slot 7 (+0x1c) or slot 8 (+0x20) and so reach the
unexecuted path FUN_0000c7c0 -> FUN_0000b658 -> FUN_0000b5bc -> FUN_0000b4b4?

Evidence, each kept at its own level:

  static      census inventory of indirect sites; firmware bytes (vtable
              layout, constructor stores, every flash materialization of an
              address inside the table, direct BL/B.W/B<c>.W into the slot
              targets); per-site target derivation (tools/census/
              indirect_target.py, intraprocedural reaching definitions over
              census blocks); census reachability of each containing function
  cross-check Macaw's independent root-seeded census (does it discover the
              site, and does it leave it unresolved?) and Ghidra's decompiler
              (the vtable offsets each containing function dispatches through;
              shares Ghidra's CFG, not this tool's dataflow)
  concrete    one canonical boot (case boot recipe, its disclosed assumptions)
              watching every register-indirect site: receiver r0 and target
              register at each execution, and end-of-boot RAM scanned for any
              pointer into the table or copy of its slot-7/8 entries

Nothing here writes the census database or any research ledger. Output is
deterministic JSON (no timestamps) under research/runs/indirect-dispatch-v1/.
Run with the Unicorn venv from the repo root:

    tools/unicorn/.venv/bin/python3 cases/performing-rigs/scripts/indirect_dispatch_investigation.py \\
        [--out DIR] [--no-ghidra]
"""
import argparse
import collections
import hashlib
import json
import re
import sqlite3
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE = HERE.parent
REPO_ROOT = CASE.parents[1]
sys.path[:0] = [str(REPO_ROOT / "tools" / "census"), str(REPO_ROOT / "tools" / "unicorn"), str(CASE / "config")]

import capstone  # noqa: E402

import indexed_writes as iw  # noqa: E402
import indirect_target as it  # noqa: E402
import slot_dispatch  # noqa: E402

FIRMWARE_KEY = "autopilot868"
DEFAULT_OUT = CASE / "research" / "runs" / "indirect-dispatch-v1"
CENSUS_DB = CASE / "research" / "runs" / "census" / "census.sqlite3"
MACAW_JSON = CASE / "research" / "runs" / "macaw" / f"{FIRMWARE_KEY}.macaw-census.json"
GHIDRA_CLI = REPO_ROOT / "tools" / "ghidra" / "aptrace_ghidra.py"

# The question's parameters: the table and the two slots under investigation.
VTABLE = 0x14900
SLOTS = {7: 0x1C, 8: 0x20}
PATH = (0xC7C0, 0xB658, 0xB5BC, 0xB4B4)
PATH_CALLS = ((0xC7C0, 0xC84A, 0xB658), (0xB658, 0xB662, 0xB5BC), (0xB5BC, 0xB5C2, 0xB4B4))
MATERIALIZE_WINDOW = 0x40          # addresses within this distance of the table count as "into the table"
MAX_LOAD_OFFSET = 0xFFF            # largest immediate offset of a Thumb-2 word load (LDR.W imm12)
MOVW_MOVT_WINDOW = 8               # instructions between a movw and its movt

TOOL_SOURCES = {
    "indirect_target": REPO_ROOT / "tools" / "census" / "indirect_target.py",
    "slot_dispatch": REPO_ROOT / "tools" / "census" / "slot_dispatch.py",
    "fnptr_resolve": REPO_ROOT / "tools" / "census" / "fnptr_resolve.py",
    "indexed_writes": REPO_ROOT / "tools" / "census" / "indexed_writes.py",
    "indirect_resolve": REPO_ROOT / "tools" / "census" / "indirect_resolve.py",
    "unicorn_harness": REPO_ROOT / "tools" / "unicorn" / "concrete.py",
    "boot_recipe": CASE / "config" / "boot_recipes.py",
    "investigation_script": Path(__file__).resolve(),
}


def _hex(v):
    return None if v is None else f"0x{v:08x}"


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _md():
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
    md.detail = True
    return md


def _disasm(image, base, start, end):
    return [{"addr": _hex(x.address), "text": f"{x.mnemonic} {x.op_str}".strip()}
            for x in _md().disasm(image[start - base:end - base], start)]


# -- pure classification (unit-tested in test/test_indirect_dispatch.py) ------

def slot_relevance(result, entries, table_bases, slot_code):
    """Can the site's target be a slot-7/8 entry of the table?

    `entries`: table entry address -> label (e.g. 0x1491c -> 'slot 7');
    `slot_code`: the code those entries hold -> label; `table_bases`: the
    flash-materialized constants pointing into the table region, the only
    base values a load can use under assumption A1 (no pointer arithmetic
    forms a table pointer, no copy of the table or its entries elsewhere).
    Returns {'status', 'slots', 'reasons'}."""
    if result.get("instruction_shape") != "reg-indirect":
        return {"status": "NOT_APPLICABLE", "slots": [], "reasons": ["not a register-indirect transfer"]}
    reasons, hits, unresolved = [], set(), False
    for p in result.get("patterns") or []:
        pat = p["pattern"]
        if pat == "constant-target":
            v = int(p["value"], 16) & ~1
            if v in slot_code:
                hits.add(slot_code[v])
            reasons.append(f"constant target 0x{v:08x}")
        elif pat == "constant-slot":
            slot = int(p["slot_addr"], 16)
            stored = {int(c["target"], 16) for c in result.get("candidate_targets", []) if c.get("is_code_pointer")}
            if slot in entries or stored & set(slot_code):
                hits.update([entries[slot]] if slot in entries else [slot_code[t] for t in stored & set(slot_code)])
                reasons.append(f"slot 0x{slot:08x} holds a slot-7/8 entry")
            elif p.get("slot_region") == "flash":
                reasons.append(f"loads immutable flash word 0x{slot:08x}, not a slot-7/8 entry")
            elif p.get("slot_writers_unresolved") or not p.get("slot_writers"):
                unresolved = True
                reasons.append(f"RAM slot 0x{slot:08x}: writers unresolved or unknown")
            else:
                reasons.append(f"RAM slot 0x{slot:08x}: every census writer stores a constant that is not a "
                               "slot-7/8 entry")
        elif pat in ("vtable-slot", "object-table-slot", "object-field"):
            d = p.get("slot_offset", p.get("field_offset"))
            via = [(b, e) for b in table_bases for e in entries if b + d == e]
            if via:
                hits.update(entries[e] for _b, e in via)
                reasons.append(f"[base + 0x{d:x}] reaches {', '.join(entries[e] for _b, e in via)} "
                               f"iff base = {', '.join(f'0x{b:08x}' for b, _e in via)}")
            else:
                reasons.append(f"[base + 0x{d:x}]: no materialized table base b has b + 0x{d:x} at a slot-7/8 entry")
        else:
            unresolved = True
            reasons.append({
                "argument": f"callback passed in r{p.get('arg')}: its value is supplied by callers (not followed)",
                "call-result": "target is a call's return value (not followed)",
                "indexed-table": "indexed load from a runtime table: entry content not derived",
                "pointer-iteration": "walks a pointer array: entry content not derived",
            }.get(pat, f"target derivation unknown ({p.get('reason', pat)})"))
    if not result.get("patterns"):
        unresolved = True
        reasons.append("no reaching definition recovered")
    status = ("CONDITIONALLY_POSSIBLE" if hits else "UNRESOLVED" if unresolved else "EXCLUDED_WITHIN_ANALYSIS_SCOPE")
    return {"status": status, "slots": sorted(hits), "reasons": reasons}


def containing_reachability(observed_hits, census_status):
    """Reachability of a site's containing code, never a global negative."""
    if observed_hits:
        return "OBSERVED"
    if census_status == "DEFINITELY_REACHABLE":
        return "STATICALLY_ESTABLISHED"
    if census_status == "POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT":
        return "CONDITIONALLY_POSSIBLE"
    return "UNRESOLVED"


def straight_line_call(image, base, entry, call_site, callee):
    """Is the BL at `call_site` reached on every path from `entry` (no
    return, register jump or branch leaving [entry, call_site]), and what is
    the last definition of r0 before it? Calls before it are listed: a
    callee that does not return would break the path."""
    calls, exits, r0_defs, bl = [], [], [], None
    for x in _md().disasm(image[entry - base:call_site + 4 - base], entry):
        if x.address == call_site:
            bl = x
            break
        text = f"0x{x.address:x} {x.mnemonic} {x.op_str}".strip()
        written = {x.reg_name(r) for r in x.regs_access()[1]}
        last = x.operands[-1] if x.operands else None
        if x.group(capstone.CS_GRP_CALL):
            calls.append(text)
        elif x.group(capstone.CS_GRP_JUMP) or x.group(capstone.CS_GRP_RET) or "pc" in written:
            target = last.imm if last is not None and last.type == capstone.arm.ARM_OP_IMM else None
            if target is None or not entry <= target <= call_site:
                exits.append(text)
        if "r0" in written:
            r0_defs.append(text)
    direct = bl is not None and bl.mnemonic.startswith("bl") and bl.operands[0].imm == callee
    return {"caller": _hex(entry), "call_site": _hex(call_site), "callee": _hex(callee), "direct_bl": direct,
            "on_every_path_from_entry": direct and not exits, "exits_before": exits, "calls_before": calls,
            "last_r0_definition": r0_defs[-1] if r0_defs else "none (r0 is the caller's incoming r0)"}


# -- static ---------------------------------------------------------------------

def connect_ro():
    conn = sqlite3.connect(f"file:{CENSUS_DB}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def census_counts(conn, fw):
    rows = conn.execute("SELECT classification, instr_shape, COUNT(*) n FROM indirect_edge_resolutions "
                        "WHERE firmware_id=? GROUP BY 1,2 ORDER BY 1,2", (fw,)).fetchall()
    return [{"classification": r["classification"], "shape": r["instr_shape"], "count": r["n"]} for r in rows]


def function_rows(conn, fw):
    return {r["entry"]: dict(r) for r in conn.execute(
        "SELECT f.id, f.entry, f.name, f.size, r.status AS reach, r.hops FROM functions f "
        "LEFT JOIN function_reachability r ON r.function_id=f.id WHERE f.firmware_id=?", (fw,))}


def vtable_layout(conn, fw, image, base, census_fns, macaw_fns):
    def word(a):
        return struct.unpack_from("<I", image, a - base)[0]
    slots = []
    for n, target in it.scan_pointer_table(image, base, VTABLE, 64):
        raw = word(VTABLE + 4 * n)
        fn = census_fns.get(target)
        owner = conn.execute("SELECT f.name FROM basic_blocks b LEFT JOIN functions f ON f.id=b.function_id WHERE "
                             "b.firmware_id=? AND b.start_addr<=? AND b.end_addr>=?", (fw, target, target)).fetchone()
        slots.append({"ghidra_block_owner": (owner["name"] or "(unattributed block)") if owner else "(no block)","slot": n, "offset": f"0x{4 * n:x}", "entry_addr": _hex(VTABLE + 4 * n), "raw_word": _hex(raw),
                      "target": _hex(target), "thumb_bit": raw & 1,
                      "census_function": fn["name"] if fn else None,
                      "census_function_size": fn["size"] if fn else None,
                      "census_reachability": fn["reach"] if fn else None,
                      "macaw_discovered": target in macaw_fns})
    end = VTABLE + 4 * len(slots)
    return {"address_point": _hex(VTABLE),
            "header": [{"addr": _hex(VTABLE - 8), "word": _hex(word(VTABLE - 8)),
                        "pattern_matched_role": "offset-to-top (Itanium C++ ABI shape; zero)"},
                       {"addr": _hex(VTABLE - 4), "word": _hex(word(VTABLE - 4)),
                        "pattern_matched_role": "typeinfo pointer (zero: no RTTI)"}],
            "slots": slots,
            "terminator": {"addr": _hex(end), "word": _hex(word(end)),
                           "ascii": image[end - base:end - base + 16].split(b"\0")[0].decode("ascii", "replace"),
                           "why_stop": "not a Thumb code pointer into the image"},
            "slot_count": len(slots)}


def materializations(image, base, lo, hi, values):
    """Every way the flash image can name an address in [lo, hi) or one of
    `values`: aligned words, movw/movt pairs, adr / add rd, pc, #imm."""
    md = _md()
    words, pairs, adrs = [], [], []
    for off in range(0, len(image) - 3, 4):
        (w,) = struct.unpack_from("<I", image, off)
        if lo <= w < hi or w in values:
            words.append({"location": _hex(base + off), "value": _hex(w)})
    for off in range(0, len(image) - 4, 2):
        insns = list(md.disasm(image[off:off + 4 * (MOVW_MOVT_WINDOW + 1)], base + off, count=MOVW_MOVT_WINDOW + 1))
        if not insns:
            continue
        x = insns[0]
        m = x.mnemonic.lower()
        if m == "movw" and len(x.operands) == 2:
            rd, low = x.reg_name(x.operands[0].reg), x.operands[1].imm & 0xFFFF
            for y in insns[1:]:
                if y.mnemonic.lower() == "movt" and y.reg_name(y.operands[0].reg) == rd:
                    v = ((y.operands[1].imm & 0xFFFF) << 16) | low
                    if lo <= v < hi or v in values:
                        pairs.append({"movw": _hex(x.address), "movt": _hex(y.address), "value": _hex(v)})
                    break
        elif m in ("adr", "adr.w", "add", "addw") and len(x.operands) >= 2 and "pc" in x.op_str:
            imm = x.operands[-1].imm if x.operands[-1].type == capstone.arm.ARM_OP_IMM else None
            if imm is not None:
                v = ((x.address + 4) & ~3) + imm
                if lo <= v < hi or v in values:
                    adrs.append({"location": _hex(x.address), "instruction": f"{m} {x.op_str}", "value": _hex(v)})
    return {"range": [_hex(lo), _hex(hi)], "values": sorted(_hex(v) for v in values),
            "aligned_words": words, "movw_movt_pairs": pairs, "pc_relative_address": adrs,
            "basis": "exhaustive sweep of the image (aligned words; movw/movt and adr at every halfword offset)"}


def object_provenance(conn, fw, image, base, installs, slot_targets):
    """Calls into each vptr-installing function for VTABLE, with their
    `this` (r0) and remaining constant arguments, and every flash literal
    naming one of those objects with the direct call that follows it."""
    ctor_entries = sorted({int(i["function"], 16) for i in installs if i["vtable"] == _hex(VTABLE) and i["function"]})
    objects, calls = {}, []
    for entry in ctor_entries:
        seen = set()
        for e in conn.execute("SELECT DISTINCT from_addr, from_function_id FROM edges WHERE firmware_id=? AND "
                              "kind='call' AND to_addr=? AND resolved=1 ORDER BY from_addr", (fw, entry)):
            blk = conn.execute("SELECT * FROM basic_blocks WHERE firmware_id=? AND start_addr<=? AND end_addr>=?",
                               (fw, e["from_addr"], e["from_addr"])).fetchone()
            insns = iw._decode_block(image, base, blk["start_addr"], blk["end_addr"])
            for i, x in enumerate(insns):
                if not (x.mnemonic.startswith("bl") and x.operands and x.operands[0].imm == entry) or x.address in seen:
                    continue
                seen.add(x.address)
                args = {}
                for reg in ("r0", "r1", "r2", "r3"):
                    res = iw._resolve_reg_value(insns, blk["start_addr"], reg, i, image, base)
                    args[reg] = _hex(res["value"] & 0xFFFFFFFF) if res["kind"] in ("imm", "literal") else res["kind"]
                calls.append({"call_site": _hex(x.address), "constructor": _hex(entry), "arguments": args,
                              "basis": "same-block constant resolution (indexed_writes resolver)"})
                if args["r0"].startswith("0x"):
                    objects.setdefault(args["r0"], {"object": args["r0"], "constructed_at": [], "sercom_object_arg": []})
                    objects[args["r0"]]["constructed_at"].append(_hex(x.address))
                    objects[args["r0"]]["sercom_object_arg"].append(args["r1"])
    refs = []
    md = _md()
    for obj in sorted(objects):
        o = int(obj, 16)
        for off in range(0, len(image) - 3, 4):
            if struct.unpack_from("<I", image, off)[0] != o:
                continue
            lit = base + off
            for r in conn.execute("SELECT l.from_addr, f.name FROM literal_refs l LEFT JOIN functions f ON "
                                  "f.id=l.from_function_id WHERE l.firmware_id=? AND l.to_addr=? ORDER BY 1",
                                  (fw, lit)):
                follow = list(md.disasm(image[r["from_addr"] - base:r["from_addr"] - base + 12], r["from_addr"], count=4))
                nxt = next((y for y in follow[1:] if y.mnemonic.lower().split(".")[0] in ("bl", "b")
                            and y.operands and y.operands[0].type == capstone.arm.ARM_OP_IMM), None)
                target = nxt.operands[0].imm if nxt is not None else None
                refs.append({"object": obj, "literal": _hex(lit), "load_site": _hex(r["from_addr"]),
                             "function": r["name"],
                             "next_direct_transfer": (f"{nxt.mnemonic} 0x{target:x}" if nxt is not None else None),
                             "transfer_site": _hex(nxt.address) if nxt is not None else None,
                             "target_is_vtable_slot": slot_targets.get(target)})
    return {"constructors": [_hex(e) for e in ctor_entries], "constructor_calls": calls,
            "objects": [objects[k] for k in sorted(objects)], "object_literal_uses": refs}


def macaw_crosscheck(macaw, site):
    blocks = macaw["_blocks"]
    hit = next(((s, n) for s, n in blocks if s <= site < s + n), None)
    if hit is None:
        return {"discovered": False}
    start = hit[0]
    indirect = any(int(c["call_site"], 16) == start and c["kind"] == "indirect" for c in macaw["calls"])
    unresolved = any(int(t["block_start"], 16) == start for t in macaw["incomplete_or_unresolved_terminators"])
    resolved = [c["callee"] for c in macaw["calls"] if int(c["call_site"], 16) == start and c["callee"]]
    return {"discovered": True, "block": _hex(start), "indirect_call": indirect, "unresolved_terminator": unresolved,
            "callees": sorted(resolved)}


_DEC_VTABLE = re.compile(r"\*\(code \*\*\)\(\*(\w+) \+ (0x[0-9a-f]+|\d+)\)")
_DEC_VTABLE0 = re.compile(r"\*\(code \*\*\)\*(\w+)")


def ghidra_decompile_offsets(entries):
    """Vtable-shaped dispatch offsets Ghidra's decompiler shows per function
    (`*(code **)(*p + off)` and `(**(code **)*p)`)."""
    if not entries:
        return {}, None
    proc = subprocess.run([sys.executable, str(GHIDRA_CLI), "decompile", FIRMWARE_KEY, *[f"0x{e:x}" for e in entries]],
                          capture_output=True, text=True, timeout=900)
    text = proc.stdout
    out = {}
    for chunk in re.split(r"(?m)^Function: ", text)[1:]:
        head = re.match(r"(\w+) @ ([0-9a-f]+)", chunk)
        if not head:
            continue
        offs = {int(m.group(2), 0) for m in _DEC_VTABLE.finditer(chunk)} | ({0} if _DEC_VTABLE0.search(chunk) else set())
        out[int(head.group(2), 16)] = sorted(offs)
    return out, {"returncode": proc.returncode, "stdout_sha256": hashlib.sha256(text.encode()).hexdigest()}


# -- concrete ---------------------------------------------------------------------

def boot_observation(conn, row, sites):
    import boot_recipes
    recipe, gaps = boot_recipes.resolve_for_firmware(conn, FIRMWARE_KEY)
    machine = boot_recipes.build_machine(recipe, str(REPO_ROOT / row["path"]), row["flash_base"], row["ram_base"],
                                         row["ram_size"], row["mmio_base"], row["mmio_size"])
    max_hits = 400_000
    result = boot_recipes.apply_recipe(machine, recipe, extra_watch=sorted(sites), collect_coverage=False,
                                       log_mmio=False, max_watch_hits=max_hits,
                                       dump_mem=[(row["ram_base"], row["ram_size"])])
    per = collections.defaultdict(lambda: {"hits": 0, "receivers": collections.Counter(), "targets": collections.Counter()})
    for h in result.watch_hits:
        a = int(h["address"], 16)
        if a in sites:
            regs = h["registers"]
            per[a]["hits"] += 1
            per[a]["receivers"][regs["r0"]] += 1
            per[a]["targets"][regs[sites[a]]] += 1
    ram = result.mem(row["ram_base"], row["ram_size"])
    return result, ram, per, recipe, gaps, max_hits


def ram_scan(ram, ram_base, lo, hi, values):
    out = []
    for i in range(0, len(ram) - 3, 4):
        (w,) = struct.unpack_from("<I", ram, i)
        if lo <= w < hi or w in values:
            out.append({"addr": _hex(ram_base + i), "word": _hex(w)})
    return out


# -- driver -----------------------------------------------------------------------

def run(out_dir, use_ghidra=True):
    conn = connect_ro()
    row = conn.execute("SELECT * FROM firmware WHERE key=?", (FIRMWARE_KEY,)).fetchone()
    fw, base = row["id"], row["flash_base"]
    image = (REPO_ROOT / row["path"]).read_bytes()
    assert hashlib.sha256(image).hexdigest() == row["sha256"], "firmware digest mismatch"
    census_fns = function_rows(conn, fw)
    macaw = json.loads(MACAW_JSON.read_text())
    macaw["_blocks"] = sorted((int(b["block_start"], 16), b["size"]) for b in macaw["basic_blocks"])
    macaw_fns = {int(f["entry"], 16) for f in macaw["functions"]}

    # vtable, installations, materialization, objects
    layout = vtable_layout(conn, fw, image, base, census_fns, macaw_fns)
    slot_targets = {int(s["target"], 16): f"slot {s['slot']}" for s in layout["slots"]}
    entries = {VTABLE + off: f"slot {n}" for n, off in SLOTS.items()}
    slot_code = {int(layout["slots"][n]["target"], 16): n for n in SLOTS}
    installs = it.vptr_installations(conn, FIRMWARE_KEY, image)
    table_end = VTABLE + 4 * layout["slot_count"]
    # Any constant b with b + d at a slot-7/8 entry, for a load offset d the
    # ISA can encode, is a base some load could use to read that entry.
    base_lo, base_hi = min(entries) - MAX_LOAD_OFFSET, max(entries) + 1
    mat = materializations(image, base, base_lo, table_end + MATERIALIZE_WINDOW,
                           {t | 1 for t in slot_code} | set(slot_code))
    table_bases = sorted({int(w["value"], 16) for w in mat["aligned_words"] + mat["movw_movt_pairs"]
                          + mat["pc_relative_address"] if base_lo <= int(w["value"], 16) < base_hi})
    objects = object_provenance(conn, fw, image, base, installs, slot_targets)
    sweep = slot_dispatch.sweep(image, base, list(SLOTS.values()), list(slot_code))

    # every register-indirect site
    resolutions = conn.execute(
        "SELECT r.from_addr, r.classification, r.instr_mnemonic, r.from_function_id, f.entry AS census_fn "
        "FROM indirect_edge_resolutions r LEFT JOIN functions f ON f.id=r.from_function_id "
        "WHERE r.firmware_id=? ORDER BY r.from_addr", (fw,)).fetchall()
    vtables = sorted({int(i["vtable"], 16) for i in installs})
    results = {}
    for r in resolutions:
        results[r["from_addr"]] = it.resolve_indirect_call(conn, FIRMWARE_KEY, image, r["from_addr"], vtables)
    reg_sites = {a: res["target_reg"] for a, res in results.items() if res["instruction_shape"] == "reg-indirect"}

    # concrete boot
    boot, ram, per, recipe, gaps, max_hits = boot_observation(conn, row, reg_sites)
    obj_fields = []
    for o in objects["objects"]:
        a = int(o["object"], 16) - row["ram_base"]
        vptr, sercom = struct.unpack_from("<I", ram, a)[0], struct.unpack_from("<I", ram, a + 0x10)[0]
        regs = struct.unpack_from("<I", ram, sercom - row["ram_base"])[0] if row["ram_base"] <= sercom < \
            row["ram_base"] + row["ram_size"] else None
        obj_fields.append({"object": o["object"], "vptr_at_end": _hex(vptr), "this_0x10_at_end": _hex(sercom),
                           "word_at_this_0x10_at_end": _hex(regs)})
    ram_copies = ram_scan(ram, row["ram_base"], VTABLE - 8, table_end, {t | 1 for t in slot_code} | set(slot_code))
    offsets = sorted({p.get("slot_offset", p.get("field_offset")) for res in results.values()
                      for p in res.get("patterns", []) if p["pattern"] in ("vtable-slot", "object-table-slot",
                                                                          "object-field")})
    ram_bases = [w for w in ram_scan(ram, row["ram_base"], base_lo, base_hi, set())
                 if any(int(w["word"], 16) + d in entries for d in offsets)]
    object_set = {o["object"] for o in objects["objects"]}

    # cross-checks
    decompiled, ghidra_run = ({}, None)
    if use_ghidra:
        fn_entries = sorted({int(res["containing_function"], 16) for res in results.values()
                             if res.get("containing_function") and res["instruction_shape"] == "reg-indirect"})
        decompiled, ghidra_run = ghidra_decompile_offsets(fn_entries)

    inventory, groups = [], collections.Counter()
    by_fn = collections.defaultdict(set)
    for r in resolutions:
        a = r["from_addr"]
        res = results[a]
        if res["instruction_shape"] == "reg-indirect":
            for p in res["patterns"]:
                if p["pattern"] in ("vtable-slot", "object-table-slot") and res.get("containing_function"):
                    by_fn[int(res["containing_function"], 16)].add(p["slot_offset"])
    for r in resolutions:
        a = r["from_addr"]
        res = results[a]
        obs = per.get(a)
        census_fn = census_fns.get(r["census_fn"]) if r["census_fn"] is not None else None
        ghidra_fn = int(res["containing_function"], 16) if res.get("containing_function") else None
        reach_fn = census_fn or (census_fns.get(ghidra_fn) if ghidra_fn is not None else None)
        rel = slot_relevance(res, entries, table_bases, {c: f"slot {n}" for c, n in slot_code.items()})
        group = res.get("pattern") or res.get("derivation_status")
        groups[(r["classification"], group)] += 1
        dec = None
        if ghidra_fn is not None and ghidra_fn in decompiled:
            mine = sorted(by_fn.get(ghidra_fn, set()))
            dec = {"function": _hex(ghidra_fn), "decompiler_vtable_offsets": [f"0x{o:x}" for o in decompiled[ghidra_fn]],
                   "resolver_vtable_offsets": [f"0x{o:x}" for o in mine],
                   "agree": sorted(decompiled[ghidra_fn]) == mine}
        receivers = sorted(obs["receivers"]) if obs else []
        inventory.append({
            "site": _hex(a),
            "census_classification": r["classification"],
            "in_reported_56": r["classification"] == "UNRESOLVED" and res["instruction_shape"] == "reg-indirect",
            "instruction": f"{res['mnemonic']} {res.get('target_reg') or ''}".strip(),
            "instruction_shape": res["instruction_shape"],
            "target_register": res.get("target_reg"),
            "census_function": census_fn["name"] if census_fn else None,
            "ghidra_block_function": res.get("containing_function"),
            "attribution_disagrees": (res["instruction_shape"] == "reg-indirect"
                                      and (census_fn["entry"] if census_fn else None) != ghidra_fn),
            "pattern": res.get("pattern"),
            "derivation_status": res["derivation_status"],
            "target_resolution_status": res["resolution_status"],
            "patterns": res.get("patterns", []),
            "register_loaded_from_memory": any(p["pattern"] not in ("constant-target", "argument", "call-result",
                                                                    "unresolved") for p in res.get("patterns", [])),
            "vtable_like": any(p["pattern"] in ("vtable-slot", "object-table-slot") for p in res.get("patterns", [])),
            "slot_offsets": sorted({p["slot_offset"] for p in res.get("patterns", []) if "slot_offset" in p}),
            "candidate_targets_0x14900": sorted({c["target"] for c in res.get("candidate_targets", [])
                                                 if c.get("vtable") == _hex(VTABLE) and c["is_code_pointer"]}),
            "slot_7_8_relevance": rel,
            "containing_function_census_reachability": reach_fn["reach"] if reach_fn else None,
            "containing_reachability": containing_reachability(obs["hits"] if obs else 0,
                                                               reach_fn["reach"] if reach_fn else None),
            "boot": ({"executions": obs["hits"], "r0_values": receivers,
                      "targets": sorted(obs["targets"]),
                      "r0_is_a_0x14900_object": any(x in object_set for x in receivers),
                      # r0 is the receiver only where the target is loaded through it
                      "receiver_is_a_0x14900_object": any(x in object_set for x in receivers) and any(
                          p["pattern"] in ("vtable-slot", "object-table-slot") for p in res.get("patterns", []))}
                     if obs else {"executions": 0}),
            "macaw": macaw_crosscheck(macaw, a),
            "ghidra_decompiler": dec,
        })

    reported = [s for s in inventory if s["in_reported_56"]]
    path_calls = [straight_line_call(image, base, e, s, c) for e, s, c in PATH_CALLS]
    slot7_entry, slot8_entry = layout["slots"][7], layout["slots"][8]
    possible = [s["site"] for s in inventory if s["slot_7_8_relevance"]["status"] == "CONDITIONALLY_POSSIBLE"]
    unresolved_sites = [s["site"] for s in inventory if s["slot_7_8_relevance"]["status"] == "UNRESOLVED"]
    excluded_sites = [s["site"] for s in inventory if s["slot_7_8_relevance"]["status"] == "EXCLUDED_WITHIN_ANALYSIS_SCOPE"]

    vtable_doc = {
        "layout": layout, "slot_7": slot7_entry, "slot_8": slot8_entry,
        "slot_7_body": _disasm(image, base, int(slot7_entry["target"], 16), int(slot7_entry["target"], 16) + 0xa),
        "vptr_installations": installs, "table_bases_in_flash": [_hex(b) for b in table_bases],
        "materializations": mat, "objects": objects, "object_fields_end_of_boot": obj_fields,
        "path_functions": {
            _hex(e): {"census_function": (census_fns.get(e) or {}).get("name"),
                      "census_size": (census_fns.get(e) or {}).get("size"),
                      "census_reachability": (census_fns.get(e) or {}).get("reach"),
                      "macaw_discovered": e in macaw_fns}
            for e in (int(slot7_entry["target"], 16), *PATH)},
        "path_calls": path_calls,
    }
    boot_doc = {
        "scenario": "boot", "recipe_reference": recipe["reference_key"], "recipe_gaps": gaps,
        "assumptions": [{"kind": x["kind"], "addr": _hex(x["addr"]), "detail": x["detail"]}
                        for x in recipe.get("assumptions", [])],
        "stop_reason": boot.stop_reason, "instructions_executed": boot.instructions_executed,
        "watch_hit_cap": max_hits, "watch_hits": len(boot.watch_hits),
        "sites_watched": len(reg_sites), "sites_executed": len(per),
        "sites_executed_in_reported_56": sum(1 for s in reported if s["boot"]["executions"]),
        "vtable_sites_with_a_0x14900_receiver": sum(1 for s in inventory if s["boot"].get("receiver_is_a_0x14900_object")),
        "sites_whose_r0_was_a_0x14900_object": [s["site"] for s in inventory if s["boot"].get("r0_is_a_0x14900_object")],
        "per_site": [{"site": _hex(a), "executions": per[a]["hits"],
                      "r0_values": dict(sorted(per[a]["receivers"].items())),
                      "targets": dict(sorted(per[a]["targets"].items()))} for a in sorted(per)],
        "end_of_boot_ram_table_pointers_or_slot_7_8_copies": ram_copies,
        "end_of_boot_ram_bases_reaching_slot_7_8_at_a_site_offset": ram_bases,
        "site_offsets_checked": [f"0x{d:x}" for d in offsets],
        "object_fields_end_of_boot": obj_fields,
        "limits": ["one scenario (boot), budget-bound", "end-of-boot RAM only; a transient copy is not excluded",
                   "harness assumptions are listed; values are firmware-produced only within that harness"],
    }
    summary = {
        "question": "Can any register-indirect call dispatch through vtable 0x14900 slot 7 (+0x1c) or slot 8 (+0x20)?",
        "firmware": {"key": FIRMWARE_KEY, "sha256": row["sha256"], "flash_base": _hex(base)},
        "inputs": {"census_db_sha256": _sha(CENSUS_DB), "macaw_census_sha256": _sha(MACAW_JSON),
                   "ghidra_decompile": ghidra_run,
                   "tool_sources": {k: _sha(v) for k, v in sorted(TOOL_SOURCES.items())},
                   "indirect_target_analysis": [it.ANALYSIS, it.ANALYSIS_VERSION],
                   "slot_dispatch_version": sweep["analysis_version"]},
        "census_counts": census_counts(conn, fw),
        "reported_56": {"definition": "indirect_edge_resolutions with classification UNRESOLVED and instr_shape "
                                      "reg-indirect",
                        "count": len(reported),
                        "also_unresolved_not_register_indirect": [s["site"] for s in inventory
                                                                  if s["census_classification"] == "UNRESOLVED"
                                                                  and not s["in_reported_56"]]},
        "groups": [{"census_classification": c, "pattern": g, "count": n} for (c, g), n in sorted(groups.items(),
                                                                                                 key=lambda kv: (kv[0][0], str(kv[0][1])))],
        "slot_sweep": sweep,
        "slot_7_8": {"conditionally_possible": possible, "unresolved": unresolved_sites,
                     "excluded_within_analysis_scope": len(excluded_sites),
                     "assumptions": [
                         "A1: a load reaches a table entry only through a base value that the image materializes as a "
                         "constant (aligned word, movw/movt, adr); no pointer arithmetic forms a table pointer and "
                         "no copy of the table or of its slot-7/8 words exists elsewhere",
                         "A2: the census inventory of indirect sites plus the halfword sweep cover the code that can "
                         "transfer control (code decodable only from another alignment is not covered)",
                         "A3: each site's reaching definitions are the census blocks and resolved edges (bounded; "
                         "incomplete results stay UNRESOLVED)"]},
        "resolver_limitations": list(it.LIMITATIONS),
        "decompiler_disagreements": [s["site"] for s in inventory if s["ghidra_decompiler"]
                                     and not s["ghidra_decompiler"]["agree"]],
        "attribution_disagreements": [s["site"] for s in inventory if s["attribution_disagrees"]],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    docs = {"inventory.json": {"sites": inventory}, "vtable.json": vtable_doc, "boot-dispatch.json": boot_doc,
            "summary.json": summary}
    for name, doc in docs.items():
        (out_dir / name).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    return docs


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--no-ghidra", action="store_true", help="skip the Ghidra decompiler cross-check")
    args = p.parse_args(argv)
    docs = run(args.out, use_ghidra=not args.no_ghidra)
    s = docs["summary.json"]
    print(json.dumps({"reported_56": s["reported_56"]["count"], "slot_7_8": {k: v for k, v in s["slot_7_8"].items()
                                                                            if k != "assumptions"},
                      "resolver_limitations": list(it.LIMITATIONS),
        "decompiler_disagreements": s["decompiler_disagreements"]}, indent=1))


if __name__ == "__main__":
    sys.exit(main())
