#!/usr/bin/env python3
"""Callback-argument provenance v1 for autopilot868: one-hop caller
provenance for every register-indirect site whose target is an incoming
argument, the before/after inventory of the previously unresolved sites,
and what it implies for an entry into the slot-7 thunk 0xc744.

Static: tools/census/indirect_target.py (v2) and
tools/census/callback_provenance.py over the census DB (read-only).
Concrete cross-check: observed_call_arguments in every EXISTING registered
scenario (no new scenario) for the argument-origin functions and the
recovered targets. Writes research/runs/callback-provenance-v1/. Run with
the agent venv from the repo root:

    agent/.venv/bin/python cases/performing-rigs/scripts/callback_provenance_investigation.py
"""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE = HERE.parent
REPO_ROOT = CASE.parents[1]
CENSUS = REPO_ROOT / "tools" / "census"
sys.path.insert(0, str(CENSUS))
sys.path.insert(0, str(REPO_ROOT / "agent" / "src"))

import callback_provenance as cp  # noqa: E402
import db as census_db  # noqa: E402
import indirect_target as it  # noqa: E402

FIRMWARE = "autopilot868"
OUT = CASE / "research" / "runs" / "callback-provenance-v1"
V1_INVENTORY = CASE / "research" / "runs" / "indirect-dispatch-v1" / "inventory.json"
THUNK, SLOT8 = 0xC744, 0xC7C0
PROBES = {"0x0000c744": "slot-7 thunk", "0x0000c7c0": "slot-8 begin-like"}
TOOLS = ("indirect_target.py", "callback_provenance.py", "slot_dispatch.py", "fnptr_resolve.py", "indexed_writes.py",
         "indirect_resolve.py")


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write(name, doc):
    (OUT / name).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")


def _completeness(r):
    if r["provenance_status"] == "NOT_APPLICABLE":
        return "not applicable"
    if r["incomplete_reasons"]:
        return "partial (bound hit)"
    return "full within scope" if r["target_set"] == "CLOSED" else "partial: target set open"


def _probe(r):
    """Is the thunk (or slot 8) a candidate, excluded within scope, or not excludable?"""
    targets = {t["target"] for t in r["candidate_targets"]}
    out = {}
    for addr, label in PROBES.items():
        if addr in targets:
            status = "CANDIDATE"
        elif r["provenance_status"] == "NOT_APPLICABLE":
            status = "NOT_APPLICABLE"
        elif r["target_set"] == "CLOSED":
            status = "EXCLUDED_WITHIN_SCOPE"
        else:
            status = "NOT_EXCLUDED"
        out[addr] = {"label": label, "status": status}
    return out


def _missing(r):
    """The precise upstream value or condition an OPEN site still needs."""
    out = []
    for o in r["argument_origins"]:
        for a in o["address_taken"]:
            if a["kind"] == "flash-word":
                uses = "; ".join(f"loaded at {x['addr']}, next use {x['next_use']['instruction'] if x['next_use'] else '?'}"
                                 for x in a["loaded_by"]) or "no recorded literal load"
                out.append(f"indirect entries into {o['function_entry']}: its address {a['value']} is the flash word "
                           f"{a['location']} ({uses})")
            else:
                out.append(f"indirect entries into {o['function_entry']}: {a['kind']} at {a.get('location') or a.get('site')}")
        for c in o["callers"]:
            for h in c.get("next_hop") or []:
                out.append(f"what callers of {h['function_entry']} pass in {h['argument']} (forwarded at {c['site']})")
            if c["value_status"] in ("UNKNOWN", "MEMORY_DEPENDENT"):
                out.append(f"caller {c['site']} value {c['value_status']}")
    return sorted(dict.fromkeys(out))


def _row(r):
    callers = [{"site": c["site"], "transfer": c["transfer"], "caller_function": c["caller_function"],
                "value_status": c["value_status"],
                "values": [x.get("raw_value") or x.get("argument") or x.get("shape") or x.get("reason")
                           for x in c["components"]],
                "caller_reachability": c["caller_reachability"]["status"]}
               for o in r["argument_origins"] for c in o["callers"]]
    coverage = {pc: v for pc, v in r.get("recorded_coverage", {}).items()}
    return {
        "site": r["site"], "instruction": r["instruction"], "containing_function": r["containing_function"],
        "argument_source": [f"incoming {o['argument']} of {o['function_entry']}" for o in r["argument_origins"]],
        "direct_callers": callers,
        "recovered_values": r["caller_value_statuses"],
        "candidate_targets": [{"target": t["target"], "raw_values": t["raw_values"],
                               "via": [v["caller_site"] for v in t["via"]],
                               "conditions": sorted({c for v in t["via"] for c in v["conditions"]})}
                              for t in r["candidate_targets"]],
        "provenance_status": r["provenance_status"], "target_set": r["target_set"],
        "root_reachability": sorted({c["caller_reachability"] for c in callers}) or ["n/a"],
        "recorded_census_coverage": {pc: v["executed_in"] for pc, v in coverage.items()},
        "completeness": _completeness(r), "open_reasons": r["open_reasons"],
        "incomplete_reasons": r["incomplete_reasons"], "missing_upstream": _missing(r), "probes": _probe(r),
    }


def static_part(conn, image):
    fw = conn.execute("SELECT id FROM firmware WHERE key=?", (FIRMWARE,)).fetchone()["id"]
    sites = [r[0] for r in conn.execute(
        "SELECT from_addr FROM indirect_edge_resolutions WHERE firmware_id=? AND instr_shape='reg-indirect' "
        "ORDER BY from_addr", (fw,))]
    v1 = {s["site"]: s for s in json.loads(V1_INVENTORY.read_text())["sites"]}
    derivations = {}
    for s in sites:
        r = it.resolve_indirect_call(conn, FIRMWARE, image, s, max_blocks=cp.MAX_BLOCKS)
        derivations[r["site"]] = r
    # v1 -> v2 at the v1 default bound (the bound the earlier inventory used).
    changed = []
    for s in sites:
        name = f"0x{s:08x}"
        r64 = it.resolve_indirect_call(conn, FIRMWARE, image, s)
        before = v1[name]
        if (before.get("pattern"), before["derivation_status"]) != (r64.get("pattern"), r64["derivation_status"]):
            changed.append({"site": name, "v1": [before.get("pattern"), before["derivation_status"]],
                            "v2": [r64.get("pattern"), r64["derivation_status"]],
                            "v1_targets_0x14900": sorted(before.get("candidate_targets_0x14900") or []),
                            "patterns_v2": r64["patterns"]})
    arg_sites = [s for s in sites if any(p["pattern"] == "argument" for p in derivations[f"0x{s:08x}"]["patterns"])]
    results = [cp.trace_callback_argument(conn, FIRMWARE, image, s) for s in arg_sites]

    callback_v1 = sorted(k for k, s in v1.items() if s.get("pattern") == "argument" and s["in_reported_56"])
    unresolved_v1 = sorted(k for k, s in v1.items() if s["slot_7_8_relevance"]["status"] == "UNRESOLVED")
    by_site = {r["site"]: r for r in results}
    inventory = []
    for name in sorted(set(callback_v1) | set(unresolved_v1)):
        s, r = v1[name], by_site.get(name)
        inventory.append({
            "site": name, "instruction": s["instruction"], "in_v1_callback_16": name in callback_v1,
            "in_v1_unresolved_27": name in unresolved_v1,
            "before": {"pattern": s.get("pattern"), "derivation_status": s["derivation_status"],
                       "slot_7_8_relevance": s["slot_7_8_relevance"]["status"],
                       "reason": s["slot_7_8_relevance"]["reasons"][:1]},
            "after": ({"site_pattern": r["site_pattern"], "site_derivation_status": r["site_derivation_status"],
                       "provenance_status": r["provenance_status"], "target_set": r["target_set"],
                       "candidate_targets": [t["target"] for t in r["candidate_targets"]],
                       "c744": _probe(r)["0x0000c744"]["status"], "completeness": _completeness(r)}
                      if r else {"site_pattern": derivations[name].get("pattern"),
                                 "site_derivation_status": derivations[name]["derivation_status"],
                                 "provenance_status": "NOT_APPLICABLE", "c744": "NOT_EXCLUDED",
                                 "completeness": "unchanged: target is not an incoming argument"}),
        })
    return derivations, changed, results, inventory


def dynamic_part(functions):
    """observed_call_arguments in every existing registered scenario."""
    from aptrace_agent.executor import EvidenceExecutor

    runner = EvidenceExecutor().observed_calls
    out = []
    for function in functions:
        for scenario in runner.supported_scenarios():
            r = runner.observe(function, scenario).model_dump(mode="json")
            out.append({"function": function, "scenario": scenario, "status": r["status"],
                        "observed_entries": r.get("observed_entries"),
                        "call_sites": [{"call_site": c.get("call_site"), "status": c.get("status"), "hits": c.get("hits"),
                                        "r3": (c.get("arguments") or {}).get("r3"),
                                        "r1": (c.get("arguments") or {}).get("r1")}
                                       for c in r.get("call_sites") or []],
                        "instructions_executed": (r.get("run") or {}).get("instructions_executed"),
                        "stop_reason": (r.get("run") or {}).get("stop_reason"),
                        "harness_assumptions": len(r.get("harness_assumptions") or [])})
    return out


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    db_path = census_db.DEFAULT_DB_PATH
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM firmware WHERE key=?", (FIRMWARE,)).fetchone()
    image = (REPO_ROOT / row["path"]).read_bytes()

    derivations, changed, results, inventory = static_part(conn, image)
    _write("provenance.json", {"sites": results})
    _write("site-derivations-v2.json", {"bound_max_blocks": cp.MAX_BLOCKS, "changed_vs_v1_at_64_blocks": changed,
                                        "sites": list(derivations.values())})
    rows = [_row(r) for r in results]
    _write("callback-sites.json", {"sites": rows})
    _write("inventory.json", {"sites": inventory})

    functions = sorted({o["function_name"] for r in results for o in r["argument_origins"] if o["function_name"]}
                       | {t["target_function"] for r in results for t in r["candidate_targets"] if t["target_function"]})
    dynamic = dynamic_part(functions)
    _write("dynamic.json", {"functions": functions, "observations": dynamic})

    probes = {r["site"]: _probe(r) for r in results}
    count = lambda pred: sum(1 for x in inventory if pred(x))  # noqa: E731
    summary = {
        "firmware": {"key": FIRMWARE, "sha256": row["sha256"]},
        "census_db_sha256": _sha(db_path),
        "tools": {name: _sha(CENSUS / name) for name in TOOLS},
        "analyses": {"indirect_target": it.ANALYSIS_VERSION, "callback_provenance": cp.ANALYSIS_VERSION},
        "bounds": results[0]["bounds"] if results else None,
        "argument_sites": len(results),
        "provenance_status": {s: sum(1 for r in results if r["provenance_status"] == s) for s in
                              sorted({r["provenance_status"] for r in results})},
        "target_set": {s: sum(1 for r in results if r["target_set"] == s) for s in ("CLOSED", "OPEN")},
        "candidate_targets": sorted({t["target"] for r in results for t in r["candidate_targets"]}),
        "non_callable_values": sorted({v for r in results for v in r["non_callable_values"]}),
        "next_hops": sorted({json.dumps(h, sort_keys=True) for r in results for h in r["next_hops"]}),
        "v1_callback_16": {"count": count(lambda x: x["in_v1_callback_16"]),
                           "gained_caller_constraint": count(lambda x: x["in_v1_callback_16"]
                                                             and x["after"]["provenance_status"] in
                                                             ("CONCRETE", "FINITE_TARGET_SET", "FORWARDED_ARGUMENT")),
                           "closed": count(lambda x: x["in_v1_callback_16"] and x["after"].get("target_set") == "CLOSED")},
        "v1_unresolved_27": {
            "count": count(lambda x: x["in_v1_unresolved_27"]),
            "after": {k: count(lambda x, k=k: x["in_v1_unresolved_27"] and x["after"]["c744"] == k)
                      for k in ("CANDIDATE", "EXCLUDED_WITHIN_SCOPE", "NOT_EXCLUDED")},
        },
        "c744": {"candidate_at": sorted(s for s, p in probes.items() if p["0x0000c744"]["status"] == "CANDIDATE"),
                 "excluded_within_scope_at": sorted(s for s, p in probes.items()
                                                    if p["0x0000c744"]["status"] == "EXCLUDED_WITHIN_SCOPE"),
                 "not_excluded_at": sorted(s for s, p in probes.items() if p["0x0000c744"]["status"] == "NOT_EXCLUDED")},
        "dynamic": {"runs": len(dynamic), "entries_observed": sorted({(d["function"], d["scenario"]) for d in dynamic
                                                                      if d["observed_entries"]})},
        "v1_v2_derivation_changes": [c["site"] for c in changed],
    }
    _write("summary.json", summary)
    print(json.dumps(summary, indent=1, default=str))


if __name__ == "__main__":
    sys.exit(main())
