"""Spike-only bounded TMC5160 query set against REA (one MCP session).

Query set is fixed and derived only from external grounding:
  - ATSAMD51 datasheet / case SVD peripheral addresses (vendor documentation)
  - user-supplied hardware observations (SERCOM5-capable SPI pins PB03/PB02/PB01,
    CS pins PB08/PA18/PB09/PA19)
No Macaw output is used as input.
"""
import sys, json, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_client import Rea, S

FW = f"{S}/fw/firmware_autopilot868.bin"  # hash-verified read-only copy
fwb = open(FW, "rb").read()
r = Rea(f"{S}/out/tmc.calls.jsonl")
r.call("open_binary", {"path": FW, "format": "raw-binary", "architecture": "arm", "entry_point": "0x4000", "provider_id": "ghidra"})

def val(sc):
    if isinstance(sc, dict) and "raw_result" in sc:
        rr = sc["raw_result"]
        return rr["value"] if isinstance(rr, dict) and "value" in rr else rr
    return sc

def le(x):
    return x.to_bytes(4, "little").hex()

CONSTS = {  # name -> 32-bit constant (SVD: SERCOM5 @0x43000400, PORT @0x41008000, group stride 0x80)
    "SERCOM5_base": 0x43000400, "SERCOM5_INTFLAG": 0x43000418, "SERCOM5_DATA": 0x43000428,
    "PORT_base(GROUP0)": 0x41008000, "PORT_GROUP1(PB)": 0x41008080,
    "PORT_PA_OUTCLR": 0x41008014, "PORT_PA_OUTSET": 0x41008018,
    "PORT_PB_OUTCLR": 0x41008094, "PORT_PB_OUTSET": 0x41008098,
    "PORT_PB_PMUX0": 0x410080B0, "PORT_PB_PINCFG0": 0x410080C0,
}
# Arduino-variant style {port, pin} adjacent uint32 pairs (PORTA=0, PORTB=1)
PINPAIRS = {"PB03": (1, 3), "PB02": (1, 2), "PB01": (1, 1), "PB08": (1, 8), "PA18": (0, 18), "PB09": (1, 9), "PA19": (0, 19)}

out = {"constants": {}, "pin_pairs": {}, "strings": None, "byte_fidelity": [], "latency": {}}
first = True
for name, c in CONSTS.items():
    dt, res, sc = r.call("search_bytes", {"pattern": le(c)})
    if first:
        out["latency"]["first_query_cold_s"] = round(dt, 3); first = False
    v = val(sc)
    hits = [m["address"] for m in (v.get("matches") or [])] if isinstance(v, dict) else []
    entry = {"constant": hex(c), "pattern": le(c), "hits": []}
    for h in hits:
        dtx, _, x = r.call("xrefs", {"address": h})
        out["latency"].setdefault("xrefs_s", []).append(round(dtx, 4))
        xv = val(x)
        refs = []
        for ref in (xv if isinstance(xv, list) else xv.get("references", []) if isinstance(xv, dict) else []):
            if isinstance(ref, str):
                ref = {"source_address": ref}
            src = ref.get("source_address") or ref.get("from") or ref.get("address")
            _, _, cp = r.call("resolve_containing_procedure", {"address": src})
            cpv = val(cp)
            refs.append({"source": src, "kind": ref.get("kind", {}).get("type") if isinstance(ref.get("kind"), dict) else ref.get("type"),
                         "containing": cpv})
        entry["hits"].append({"literal_at": h, "xrefs": refs})
    out["constants"][name] = entry

for name, (port, pin) in PINPAIRS.items():
    pat = le(port) + le(pin)
    _, _, sc = r.call("search_bytes", {"pattern": pat})
    v = val(sc)
    out["pin_pairs"][name] = {"pattern": pat, "hits": [m["address"] for m in (v.get("matches") or [])] if isinstance(v, dict) else v}

_, _, sc = r.call("search_strings", {"pattern": "SPI|SERCOM|TMC|Trinamic|motor", "mode": "regex", "case_sensitive": False})
out["strings"] = sc.get("raw_result", sc) if isinstance(sc, dict) else sc

# byte fidelity: provider bytes vs immutable firmware file bytes
for a in [0x4000, 0x99c2, 0xa000, 0xcc24, 0x15400]:
    _, _, sc = r.call("read_bytes", {"address": hex(a), "length": 16})
    v = val(sc)
    hexv = v.get("hex") or v.get("bytes") if isinstance(v, dict) else None
    out["byte_fidelity"].append({"address": hex(a), "provider": hexv, "file": fwb[a - 0x4000:a - 0x4000 + 16].hex(),
                                 "equal": (hexv or "").lower() == fwb[a - 0x4000:a - 0x4000 + 16].hex()})

# latency: decompile + repeated identical query
for p in ["0x9f60", "0xa000", "0x9f60"]:
    dt, res, sc = r.call("procedure_pseudo_code", {"procedure": p})
    out["latency"].setdefault("decompile_s", []).append([p, round(dt, 4), bool(res.get("isError"))])
for _ in range(3):
    dt, _, _ = r.call("xrefs", {"address": "0x99c2"})
    out["latency"].setdefault("xrefs_repeat_s", []).append(round(dt, 4))
for p in ["0x9f60", "0xa000"]:
    dt, _, sc = r.call("get_call_graph", {"address": p, "direction": "backward"})
    out.setdefault("callers_graph", {})[p] = sc.get("raw_result", sc) if isinstance(sc, dict) else sc
    out["latency"].setdefault("call_graph_s", []).append(round(dt, 4))

r.close()
json.dump(out, open(f"{S}/out/tmc.json", "w"), indent=1, sort_keys=True)
print(json.dumps({k: out[k] for k in ["latency", "byte_fidelity", "pin_pairs"]}, indent=1))
for k, e in out["constants"].items():
    print(k, e["constant"], [(h["literal_at"], [(x["source"], (x["containing"] or {}).get("address") if isinstance(x["containing"], dict) else x["containing"]) for x in h["xrefs"]]) for h in e["hits"]])
