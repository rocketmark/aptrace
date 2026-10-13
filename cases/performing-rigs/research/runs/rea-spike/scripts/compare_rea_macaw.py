"""Disposable spike comparator: REA (Ghidra raw-binary lane) vs Macaw census.

Not a framework comparator. Deterministic: sorted inputs, no timestamps.
usage: python3 -I compare_rea_macaw.py REA_DOSSIERS.jsonl MACAW_CENSUS.json FIRMWARE.bin APTRACE_GHIDRA_EXPORT.json OUT.json

Declared normalizations (all mechanical):
  N1 Thumb bit: Macaw canonical addresses are already even; REA addresses are even.
  N2 Decode mode of an REA procedure: THUMB if any listed instruction is 2 bytes
     (consecutive-address delta 2) or starts at addr % 4 == 2, or uses a
     Thumb-only mnemonic form ('.w'/'.n' suffix, cbz/cbnz/it*), or (single-instruction
     bodies) the body is 2 bytes, or the 32-bit LE word's A32 condition nibble is not
     0xE while the listed mnemonic carries no condition suffix (i.e. it cannot be the
     A32 decode of those bytes); else A32_OR_UNPROVEN.
  N3 Call-site containment: an REA call reference at instruction address i
     matches a Macaw call whose block [block_start, block_start+size) contains i.
  N4 Block starts: Macaw ends blocks at calls (call_return edges); Ghidra's
     BasicBlockModel does not. Macaw starts that are call-return addresses are
     dropped before comparing block starts.
  N5 CFG edges compared as per-function intra-function branch-target sets
     (REA basic_blocks successors vs Macaw non-call_return edge targets,
     both restricted to the function's own blocks).
Scope: Macaw is vector-root-seeded; REA/Ghidra is whole-image heuristic.
  Function-level gaps are split by whether the function is reachable from the
  vector-table roots through the *other side's own* direct call edges.
"""
import json, sys, struct, re

rea_path, macaw_path, fw_path, ghidra_path, out_path = sys.argv[1:6]
H = lambda s: int(s, 16)
fw = open(fw_path, "rb").read()
BASE = 0x4000
END = BASE + len(fw)

# ---------- REA ----------
rea = {}
for line in open(rea_path):
    d = json.loads(line)
    if d["value"]:
        rea[H(d["address"])] = d["value"]

INS = re.compile(r"^0x([0-9a-f]+): (\S+)")
THUMB_ONLY = re.compile(r"(\.w|\.n)$|^(cbz|cbnz|it|ite|itt|itte|ittt|itet|iteet|ittee|itee|tbb|tbh)$")

COND = ("eq","ne","cs","cc","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","hs","lo")

def rea_mode(v):
    addrs, mnems = [], []
    for s in v["assembly"]:
        m = INS.match(s)
        if m:
            addrs.append(int(m.group(1), 16)); mnems.append(m.group(2))
    a = sorted(addrs)
    if any(x % 4 == 2 for x in a) or any(b - x == 2 for x, b in zip(a, a[1:])) or any(THUMB_ONLY.search(m) for m in mnems):
        return "THUMB", a
    body = v["procedure"]["body"]
    if len(a) == 1:
        if body["total_bytes"] == 2:
            return "THUMB", a
        w = struct.unpack_from("<I", fw, a[0] - BASE)[0]
        if (w >> 28) != 0xE and not any(mnems[0].endswith(c) for c in COND):
            return "THUMB", a
    return "A32_OR_UNPROVEN", a

rea_fn = {}
for e, v in sorted(rea.items()):
    mode, ins = rea_mode(v)
    ranges = [(H(r["start"]), H(r["end"])) for r in v["procedure"]["body"]["ranges"]]
    blocks = {H(b["start"]): (H(b["end"]), sorted(H(s) for s in b.get("successors", []))) for b in v["basic_blocks"]}
    calls = sorted({(H(r["source_address"]), H(r["target_address"]))
                    for r in v["outgoing_references"] if r["kind"].get("call") and not r["kind"].get("indirect")})
    rea_fn[e] = {"mode": mode, "ins": ins, "ranges": ranges, "blocks": blocks, "calls": calls}

def bytes_of_ranges(rs):
    s = set()
    for a, b in rs:
        s.update(range(a, b + 1))
    return s

# ---------- Macaw ----------
mc = json.load(open(macaw_path))
mfn = {H(f["entry"]): f for f in mc["functions"]}
mblocks = {}
for b in mc["basic_blocks"]:
    mblocks.setdefault(H(b["function_entry"]), []).append((H(b["block_start"]), b["size"]))
m_retaddrs = {H(e["target"]) for e in mc["edges"] if e["kind"] == "call_return"}
medges = {}
for e in mc["edges"]:
    if e["kind"] != "call_return":
        medges.setdefault(H(e["function_entry"]), set()).add(H(e["target"]))
mcalls = {}
for c in mc["calls"]:
    if c["kind"] == "direct" and c["callee"]:
        mcalls.setdefault(H(c["caller"]), set()).add((H(c["call_site"]), H(c["callee"])))
m_bytes = set()
for fe, bl in mblocks.items():
    for s, n in bl:
        m_bytes.update(range(s, s + n))

# ---------- vector roots (architecture fact: Cortex-M vector table layout) ----------
nwords = 16 + 136
roots = set()
for i in range(1, nwords):
    w = struct.unpack_from("<I", fw, 4 * i)[0]
    if w & 1 and BASE <= (w & ~1) < END:
        roots.add(w & ~1)

def reach(callmap, start):
    seen, todo = set(), [r for r in start if r in callmap]
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        todo += [t for t in callmap.get(f, ()) if t not in seen and t in callmap]
    return seen

rea_cg = {e: {t for _, t in f["calls"]} for e, f in rea_fn.items()}
mac_cg = {e: {t for _, t in mcalls.get(e, set())} for e in mfn}
rea_reach = reach(rea_cg, roots)
mac_reach = reach(mac_cg, roots)

# ---------- existing APTrace Ghidra (same engine family; reference only) ----------
gx = json.load(open(ghidra_path))
g_entries = {H(f["entry"]) for f in gx["functions"] if not f.get("external")}

# ---------- comparisons ----------
rea_thumb = {e for e, f in rea_fn.items() if f["mode"] == "THUMB"}
rea_a32 = {e for e, f in rea_fn.items() if f["mode"] != "THUMB"}
R, M = set(rea_fn), set(mfn)

def hx(s):
    return [hex(x) for x in sorted(s)]

func = {
    "AGREE_entry": hx(R & M),
    "REA_only": {
        "thumb_reachable_from_vector_roots_via_rea_calls": hx((R - M) & rea_thumb & rea_reach),
        "thumb_not_root_reachable(INCOMPARABLE_scope)": hx((R - M) & rea_thumb - rea_reach),
        "a32_or_unproven": hx((R - M) & rea_a32),
    },
    "MACAW_only": {
        "root_reachable_via_macaw_calls(REA_COVERAGE_GAP)": hx((M - R) & mac_reach),
        "other": hx((M - R) - mac_reach),
    },
}

# decode conflict: REA A32 procedure bodies overlapping Macaw Thumb code bytes
conflicts = []
for e in sorted(rea_a32):
    ov = bytes_of_ranges(rea_fn[e]["ranges"]) & m_bytes
    if ov:
        conflicts.append({"rea_entry": hex(e), "overlap_bytes": len(ov), "first": hex(min(ov))})

# coverage (bytes)
rea_bytes_thumb = set().union(*[bytes_of_ranges(rea_fn[e]["ranges"]) for e in rea_thumb]) if rea_thumb else set()
rea_bytes_a32 = set().union(*[bytes_of_ranges(rea_fn[e]["ranges"]) for e in rea_a32]) if rea_a32 else set()
coverage = {
    "macaw_code_bytes": len(m_bytes),
    "rea_thumb_function_bytes": len(rea_bytes_thumb),
    "rea_a32_function_bytes": len(rea_bytes_a32),
    "both(thumb)": len(m_bytes & rea_bytes_thumb),
    "macaw_only": len(m_bytes - rea_bytes_thumb - rea_bytes_a32),
    "rea_thumb_only": len(rea_bytes_thumb - m_bytes),
    "rea_a32_over_macaw_thumb(DISAGREE_decode_mode)": len(rea_bytes_a32 & m_bytes),
}

# instruction-boundary agreement inside common Thumb functions: every Macaw block start
# should be an REA instruction address
common = sorted(R & M & rea_thumb)
ALL_REA_INS = set().union(*[set(rea_fn[x]["ins"]) for x in rea_thumb])
REA_THUMB_BYTES = set().union(*[bytes_of_ranges(rea_fn[x]["ranges"]) for x in rea_thumb])
inst_ok = inst_bad = 0
bad_samples = []
blocks_res = {"AGREE": 0, "DISAGREE": 0}
block_disagree = []
edges_res = {"AGREE": 0, "DISAGREE": 0}
edge_disagree = []
extent_res = {"AGREE": 0, "DISAGREE": 0}
extent_disagree = []
call_res = {"AGREE": 0, "REA_extra": 0, "MACAW_extra": 0}
call_diffs = []
for e in common:
    f = rea_fn[e]
    insset = ALL_REA_INS
    rbytes = bytes_of_ranges(f["ranges"])
    mb = sorted(mblocks.get(e, []))
    mbytes = set()
    for s, n in mb:
        mbytes.update(range(s, s + n))
        if s not in REA_THUMB_BYTES:
            continue  # boundary only checkable where REA decoded those bytes
        if s in insset:
            inst_ok += 1
        else:
            inst_bad += 1
            if len(bad_samples) < 10:
                bad_samples.append(hex(s))
    # extent (block-byte set)
    if rbytes == mbytes:
        extent_res["AGREE"] += 1
    else:
        extent_res["DISAGREE"] += 1
        extent_disagree.append({"entry": hex(e), "rea_only_bytes": len(rbytes - mbytes), "macaw_only_bytes": len(mbytes - rbytes)})
    # block starts (N4)
    ms = {s for s, _ in mb if s not in m_retaddrs or s == e}
    rs = set(f["blocks"])
    if ms == rs:
        blocks_res["AGREE"] += 1
    else:
        blocks_res["DISAGREE"] += 1
        block_disagree.append({"entry": hex(e), "rea_only": hx(rs - ms)[:8], "macaw_only": hx(ms - rs)[:8]})
    # CFG targets (N5)
    rt = {t for _, (_, succ) in f["blocks"].items() for t in succ if t in rbytes}
    mt = {t for t in medges.get(e, set()) if t in mbytes}
    if rt == mt:
        edges_res["AGREE"] += 1
    else:
        edges_res["DISAGREE"] += 1
        edge_disagree.append({"entry": hex(e), "rea_only": hx(rt - mt)[:8], "macaw_only": hx(mt - rt)[:8]})
    # calls (N3)
    mc_ = mcalls.get(e, set())
    mbl = {s: n for s, n in mb}
    def mblock_of(i):
        for s, n in mbl.items():
            if s <= i < s + n:
                return s
        return None
    rset = {(mblock_of(i), t) for i, t in f["calls"]}
    mset = set(mc_)
    call_res["AGREE"] += len(rset & mset)
    call_res["REA_extra"] += len(rset - mset)
    call_res["MACAW_extra"] += len(mset - rset)
    if rset != mset:
        call_diffs.append({"entry": hex(e),
                           "rea_only": [[hex(a) if a is not None else None, hex(b)] for a, b in sorted(rset - mset, key=lambda x: (x[0] or 0, x[1]))][:6],
                           "macaw_only": [[hex(a), hex(b)] for a, b in sorted(mset - rset)][:6]})

result = {
    "inputs": {"rea_dossiers": rea_path, "macaw_census": macaw_path, "firmware_bytes": len(fw)},
    "vector_roots": len(roots),
    "counts": {"rea_procedures": len(R), "rea_thumb": len(rea_thumb), "rea_a32_or_unproven": len(rea_a32),
               "macaw_functions": len(M), "aptrace_ghidra_cortex_functions": len(g_entries),
               "rea_root_reachable": len(rea_reach), "macaw_root_reachable": len(mac_reach)},
    "function_entries": func,
    "function_entries_counts": {"AGREE": len(R & M),
                                "REA_only_thumb_root_reachable": len((R - M) & rea_thumb & rea_reach),
                                "REA_only_thumb_not_root_reachable": len((R - M) & rea_thumb - rea_reach),
                                "REA_only_a32_or_unproven": len((R - M) & rea_a32),
                                "MACAW_only_root_reachable": len((M - R) & mac_reach),
                                "MACAW_only_other": len((M - R) - mac_reach)},
    "decode_mode_conflicts": conflicts,
    "coverage_bytes": coverage,
    "common_thumb_functions": len(common),
    "instruction_boundary": {"macaw_block_starts_on_rea_instruction": inst_ok, "not_on_rea_instruction": inst_bad, "samples": bad_samples},
    "function_extent": extent_res, "function_extent_disagreements": extent_disagree,
    "block_starts_N4": blocks_res, "block_start_disagreements": block_disagree,
    "cfg_targets_N5": edges_res, "cfg_disagreements": edge_disagree,
    "direct_calls_N3": call_res, "call_disagreements": call_diffs,
    "memory_accesses": "UNAVAILABLE: Macaw census emits no memory/MMIO access relation",
    "vs_existing_aptrace_ghidra(same engine family, NOT corroboration)": {
        "rea_entries_not_in_aptrace_ghidra": hx(R - g_entries),
        "aptrace_ghidra_entries_not_in_rea": len(g_entries - R),
    },
}
json.dump(result, open(out_path, "w"), indent=1, sort_keys=True)
print(json.dumps({k: result[k] for k in ["counts", "function_entries_counts", "coverage_bytes", "common_thumb_functions",
                                          "instruction_boundary", "function_extent", "block_starts_N4", "cfg_targets_N5", "direct_calls_N3"]}, indent=1))
print("decode_mode_conflicts:", len(conflicts), conflicts[:5])
print("rea_entries_not_in_aptrace_ghidra:", result["vs_existing_aptrace_ghidra(same engine family, NOT corroboration)"]["rea_entries_not_in_aptrace_ghidra"])
