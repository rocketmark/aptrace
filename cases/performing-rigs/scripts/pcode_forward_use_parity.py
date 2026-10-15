#!/usr/bin/env python3
"""Performing Rigs: p-code forward-use (tools/ghidra/pcode_forward_use.py)
on AutoPilot 868, compared with the existing Python analyses.

Read-only. The case Ghidra project is copied into a scratch workspace by
the framework driver; the census database is opened read-only; nothing in
the ledger, claims or census changes. Outputs go to
research/runs/pcode-forward-use-v1/.

Three comparisons:

1. real-image code-pointer references: every census literal_refs row that
   references a function_pointers flash word with a known target (READ =
   loads, DATA = other references), against the architecture spike's saved
   raw-p-code probe and Capstone-v2 walker results, and a fresh Capstone-v2
   run given Ghidra's function body.
2. backward/forward duality against indirect_target v2: for each of the
   census's register-indirect sites, every top-level reaching definition
   with an instruction is a forward-use origin for the branch register;
   p-code should find a CONTROL_TRANSFER at the site.
3. fixtures: the production results against the spike's saved Capstone v1
   and v2 results.

    tools/unicorn/.venv/bin/python3 cases/performing-rigs/scripts/pcode_forward_use_parity.py
"""
import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

CASE = Path(__file__).resolve().parents[1]
REPO = CASE.parents[1]
sys.path.insert(0, str(REPO / "tools" / "ghidra"))
import pcode_forward_use as pfu  # noqa: E402

FIRMWARE_KEY = "autopilot868"
FIRMWARE = CASE / "research" / "firmware" / "originals" / "firmware_autopilot868.bin"
PROJECT = CASE / "research" / "runs" / "ghidra_cache" / FIRMWARE_KEY
CENSUS = CASE / "research" / "runs" / "census" / "census.sqlite3"
SPIKE_CASE = CASE / "research" / "runs" / "architecture-eval-v1"
SPIKE = REPO / "docs" / "spikes" / "architecture-evaluation" / "experiments"
OUT = CASE / "research" / "runs" / "pcode-forward-use-v1"
UNICORN_PY = REPO / "tools" / "unicorn" / ".venv" / "bin" / "python3"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def target():
    meta = json.loads((PROJECT / "meta.json").read_text())
    return pfu.Target(
        image=FIRMWARE, image_sha256=meta["firmware_sha256"], language_id=meta["processor"],
        compiler_spec_id=meta["cspec"], base=int(meta["load_base"], 0),
        project=pfu.GhidraProject(PROJECT, "aptrace", FIRMWARE.name, identity=sha256(PROJECT / "meta.json")),
    )


def census():
    return sqlite3.connect(f"file:{CENSUS}?mode=ro", uri=True)


def summary(r):
    return {
        "verdict": r["verdict"], "complete": r["complete"], "escape_kinds": r["escape_kinds"],
        "incomplete": [i["code"] for i in r.get("incomplete") or []],
        "unsupported": (r.get("unsupported") or {}).get("code"),
        "tracked": (r.get("tracked") or {}).get("storage"),
        "function": (r.get("scope") or {}).get("function_name"),
        "uses": [[u["kind"], u["address"], u["instruction"]] for u in r.get("uses") or []],
    }


# The unattributed stub's range, as the architecture-eval-v1 case note gave
# it to the Capstone walker (ldr r1 / b.w; the literal follows).
STUB_RANGES = {0x10438: (0x10438, 0x1043d)}


def capstone_v2(address, body):
    """The spike's Capstone-v2 forward walker, given Ghidra's (single-range) body or the recorded stub range."""

    if address in STUB_RANGES:
        lo, hi = STUB_RANGES[address]
    elif body and len(body) == 1:
        lo, hi = (int(x, 16) for x in body[0])
    else:
        return {"status": "not_run", "reason": "no single-range Ghidra body to give it"}
    proc = subprocess.run(
        [str(UNICORN_PY), str(SPIKE / "python" / "capstone_forward_use.py"), str(FIRMWARE), "4000", f"0x{address:x}",
         "--fn", f"{lo:x}:{hi + 1:x}"], capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        return {"status": "failed", "reason": proc.stderr.strip()[-200:]}
    r = json.loads(proc.stdout)[0]
    return {"status": "ok", "use_kinds": r["use_kinds"], "complete": r["complete"], "incomplete": r["incomplete"],
            "uses": r["uses"]}


ESCAPE_OF = {"CONTROL_TRANSFER": "CONTROL_FLOW_ESCAPE", "ARGUMENT": "ARGUMENT_ESCAPE", "STORE": "MEMORY_ESCAPE",
             "RETURN_VALUE": "RETURN_ESCAPE"}


def compare_kinds(pcode, other_kinds, other_complete):
    escapes = sorted({ESCAPE_OF[k] for k in other_kinds if k in ESCAPE_OF})
    if pcode["verdict"] == pfu.UNSUPPORTED:
        return "P-CODE UNSUPPORTED"
    if escapes == pcode["escape_kinds"] and other_complete == pcode["complete"]:
        return "AGREE"
    if escapes == pcode["escape_kinds"]:
        return "AGREE ON ESCAPES; COMPLETENESS DIFFERS"
    if not escapes and not other_complete and not pcode["complete"]:
        return "BOTH INCOMPLETE; P-CODE ALSO FINDS " + ",".join(pcode["escape_kinds"])
    return "DISAGREE"


def real_loads(t):
    with census() as conn:
        rows = conn.execute(
            "SELECT DISTINCT l.from_addr, l.ref_type, l.to_addr, f.raw_value, f.target_addr FROM function_pointers f "
            "JOIN literal_refs l ON l.to_addr=f.location_addr AND l.firmware_id=f.firmware_id "
            "JOIN firmware w ON w.id=f.firmware_id WHERE f.matches_known_function=1 AND w.key=? ORDER BY l.from_addr",
            (FIRMWARE_KEY,)).fetchall()
    doc, m = pfu.run_forward_use(t, [pfu.Origin(r[0]) for r in rows])
    spike_raw = {int(p["def_addr"], 16): p["raw"] for p in
                 json.loads((SPIKE_CASE / "ghidra_all_code_pointer_loads.json").read_text())["probes"]}
    out = []
    for (addr, ref, word, raw, tgt), r in zip(rows, doc["results"]):
        p = summary(r)
        row = {"origin": f"0x{addr:08x}", "census_ref_type": ref, "pointer_word": f"0x{word:08x}",
               "census_value": f"0x{raw:08x}", "census_target": f"0x{tgt:08x}",
               "pcode_origin_value": (r.get("origin_value") or {}).get("value"),
               "pcode_code_address": (r.get("origin_value") or {}).get("code_address"),
               "instruction": r.get("origin_instruction"), "pcode": p}
        if addr in spike_raw:
            s = spike_raw[addr]
            row["spike_raw_pcode"] = {"use_kinds": s["use_kinds"], "complete": s["complete"], "incomplete": s["incomplete"]}
            row["vs_spike_raw_pcode"] = compare_kinds(p, s["use_kinds"], s["complete"])
        if ref == "READ":
            c = capstone_v2(addr, (r.get("scope") or {}).get("body"))
            row["capstone_v2"] = c
            if c["status"] == "ok":
                row["vs_capstone_v2"] = compare_kinds(p, c["use_kinds"], c["complete"])
        out.append(row)
    return {"engine": doc["engine"], "program": doc["program"], "walker_sha256": doc["walker_sha256"],
            "driver_sha256": doc["driver_sha256"], "measurement": m.__dict__, "references": out}


def duality(t):
    proc = subprocess.run(
        [str(UNICORN_PY), str(REPO / "tools" / "census" / "indirect_target.py"), FIRMWARE_KEY, "--db", str(CENSUS),
         "--all-register-indirect"], capture_output=True, text=True, cwd=REPO / "tools" / "census", timeout=600, check=True)
    sites = json.loads(proc.stdout)["sites"]
    pairs = []
    for s in sites:
        for d in s["reaching_definitions"]["defs"]:
            if d.get("def_addr"):
                pairs.append((s, d))
    origins = sorted({(int(d["def_addr"], 16), s["target_reg"]) for s, d in pairs})
    doc, m = pfu.run_forward_use(t, [pfu.Origin(a, reg) for a, reg in origins])
    by_origin = {(int(r["origin_address"], 16), reg): r for (_, reg), r in zip(origins, doc["results"])}
    rows = []
    for s, d in pairs:
        r = by_origin[(int(d["def_addr"], 16), s["target_reg"])]
        transfers = [u for u in r.get("uses") or [] if u["kind"] == "CONTROL_TRANSFER"]
        at_site = [u for u in transfers if int(u["address"], 16) == int(s["site"], 16)]
        if r["verdict"] == pfu.UNSUPPORTED:
            outcome = "P-CODE UNSUPPORTED"
        elif at_site:
            outcome = "AGREE"
        elif not r["complete"]:
            outcome = "P-CODE INCOMPLETE, NO TRANSFER FOUND"
        else:
            outcome = "DISAGREE: complete p-code walk does not reach the site"
        rows.append({
            "site": s["site"], "target_reg": s["target_reg"], "mnemonic": s["mnemonic"],
            "indirect_target": {"pattern": s["pattern"], "derivation_status": s["derivation_status"],
                                "reaching_complete": s["reaching_definitions"]["complete"],
                                "function_attributed": s["function_attributed"]},
            "definition": {"def_addr": d["def_addr"], "kind": d["kind"], "instruction": d["instruction"]},
            "pcode": {"verdict": r["verdict"], "complete": r["complete"],
                      "incomplete": [i["code"] for i in r.get("incomplete") or []],
                      "function": (r.get("scope") or {}).get("function_name"),
                      "transfers": [[u["address"], u["instruction"]] for u in transfers]},
            "outcome": outcome,
        })
    counts = {}
    for row in rows:
        counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
    return {"indirect_target_sites": len(sites), "definition_pairs": len(rows), "distinct_origins": len(origins),
            "outcomes": counts, "measurement": m.__dict__, "pairs": rows}


def fixtures():
    controls = json.loads((REPO / "tools" / "ghidra" / "fixtures" / "pcode_forward_use" / "controls.json").read_text())
    thumb = controls["suites"][0]
    v1 = {}
    for line in (SPIKE / "results" / "python_v1_thumb_controls.txt").read_text().splitlines():
        addr, kinds = line.split(" ", 1)
        v1[int(addr, 16)] = json.loads(kinds.replace("'", '"'))
    v2 = {int(x["def_addr"], 16): x for x in json.loads((SPIKE / "results" / "python_v2_thumb_controls.json").read_text())}
    rows = []
    for o in thumb["origins"]:
        a = int(o["origin"], 16)
        k1 = sorted({ESCAPE_OF[k] for k in v1[a] if k in ESCAPE_OF})
        k2 = sorted({ESCAPE_OF[k] for k in v2[a]["use_kinds"] if k in ESCAPE_OF})
        rows.append({"case": o["case"], "pcode": o["escape_kinds"], "capstone_v1": k1, "capstone_v2": k2,
                     "spike_ground_truth": o["spike_escapes"], "assessment": o["assessment"]})
    return rows


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    t = target()
    meta_before = sha256(PROJECT / "meta.json")
    census_before = sha256(CENSUS)
    loads = real_loads(t)
    (OUT / "code-pointer-references.json").write_text(json.dumps(loads, indent=1, sort_keys=True) + "\n")
    dual = duality(t)
    (OUT / "indirect-target-duality.json").write_text(json.dumps(dual, indent=1, sort_keys=True) + "\n")
    fx = fixtures()
    (OUT / "fixture-parity.json").write_text(json.dumps(fx, indent=1, sort_keys=True) + "\n")
    print("code-pointer references:")
    for r in loads["references"]:
        print(f"  {r['origin']} {r['census_ref_type']:4} {r['pcode']['verdict']:22} {','.join(r['pcode']['escape_kinds']):32}"
              f" spike={r.get('vs_spike_raw_pcode', '-')} | capstone_v2={r.get('vs_capstone_v2', '-')}")
    print("duality vs indirect_target:", dual["outcomes"], dual["measurement"])
    print("fixture parity:")
    for r in fx:
        print(f"  {r['case']:26} pcode={r['pcode']} v1={r['capstone_v1']} v2={r['capstone_v2']}")
    assert sha256(PROJECT / "meta.json") == meta_before and sha256(CENSUS) == census_before, "an input changed"
    return 0


if __name__ == "__main__":
    sys.exit(main())
