"""Spike-only: one REA MCP session over the raw firmware; dump every procedure dossier.
usage: python3 -I rea_full_pass.py OUT_PREFIX"""
import sys, json, time, os, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_client import Rea, S
out = sys.argv[1]
FW = f"{S}/fw/firmware_autopilot868.bin"  # hash-verified read-only copy
r = Rea(f"{out}.calls.jsonl")
t0 = time.perf_counter()
r.call("open_binary", {"path": FW, "format": "raw-binary", "architecture": "arm", "entry_point": "0x4000", "provider_id": "ghidra"})
dt_cold, _, procs = r.call("list_procedures", {})
procs = procs["raw_result"]
plist = procs if isinstance(procs, list) else procs["value"]
addrs = [p["address"] for p in plist]
lat = []
with open(f"{out}.dossiers.jsonl", "w") as f:
    for a in addrs:
        dt, res, sc = r.call("analyze_function", {"procedure": a})
        lat.append(dt)
        v = sc.get("raw_result", {}).get("value") if isinstance(sc, dict) else None
        f.write(json.dumps({"address": a, "seconds": round(dt, 4), "is_error": res.get("isError"),
                            "evidence_id": sc.get("evidence_id") if isinstance(sc, dict) else None,
                            "value": v, "error": None if v else sc}, sort_keys=True) + "\n")
total = time.perf_counter() - t0
rc = r.close()
lat.sort()
summary = {"procedures": len(addrs), "cold_first_query_s": round(dt_cold, 3), "total_session_s": round(total, 3),
           "analyze_function_median_s": round(lat[len(lat)//2], 4), "p95_s": round(lat[int(len(lat)*.95)], 4),
           "max_s": round(lat[-1], 4), "sum_s": round(sum(lat), 3), "server_exit": rc}
json.dump(summary, open(f"{out}.summary.json", "w"), indent=1)
print(json.dumps(summary))
