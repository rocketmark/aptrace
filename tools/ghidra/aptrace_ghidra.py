#!/usr/bin/env python3
"""APTrace: a persistent-project Ghidra query interface.

Problem this replaces: every prior investigation in this project invoked
`analyzeHeadless` with `-import ... -deleteProject`, which re-imports the
raw firmware and re-runs full auto-analysis (seconds) for a *single*
decompile/disassemble/xref query, then throws the analyzed database away.
Ten queries against the same firmware meant ten full re-analyses.

This module keeps one Ghidra project per firmware image on disk (under
`research/runs/ghidra_cache/<key>/`), built once (import + vector-table
seeding + auto-analysis + provenance labels, if any), and answers later
queries by *reopening* that project with `-process -noanalysis` (skips
auto-analysis entirely) or, for queries the project's own cached JSON
export can already answer (callers/xrefs/containing-function/symbol),
without invoking Ghidra at all.

Cache identity: a query only reuses a cached project if the firmware's
own SHA-256, the load base, the processor/language, the installed Ghidra
version, ANALYSIS_VERSION (an explicit manual override, for a semantic
change this identity can't otherwise see), AND the actual content hashes
of every script/data input `build()` feeds to analyzeHeadless --
APTraceSeedVectorTable.java, APTraceApplyProvenance.java,
APTraceExportStaticAnalysis.java, and the firmware's own provenance
labels TSV if it has one -- all still match what's recorded in the
cache's own `meta.json`. This means an ordinary edit to a provenance
label or one of those scripts invalidates the cache on its own, with no
human needing to remember to bump ANALYSIS_VERSION. Any mismatch is
treated as stale -- this module refuses to silently reuse a stale cache;
it reports the mismatch and asks for `rebuild`.

Usage:
    tools/ghidra/aptrace_ghidra.py build       autopilot868
    tools/ghidra/aptrace_ghidra.py rebuild     autopilot868
    tools/ghidra/aptrace_ghidra.py decompile   mando868 0x49c4 [0x8258 ...]
    tools/ghidra/aptrace_ghidra.py disasm      autopilot868 0x83b0 0x83ec
    tools/ghidra/aptrace_ghidra.py callers     mando868 0x58a8
    tools/ghidra/aptrace_ghidra.py xrefs       autopilot868 0x20001b40
    tools/ghidra/aptrace_ghidra.py containing  autopilot868 0xb228
    tools/ghidra/aptrace_ghidra.py symbol      autopilot868 FUN_00006fd8
    tools/ghidra/aptrace_ghidra.py literal     autopilot868 0x8528       # raw firmware read, no Ghidra
    tools/ghidra/aptrace_ghidra.py status      [firmware-key]

Firmware keys and their (path, load base) are in FIRMWARE_REGISTRY below.
Add new images there, not by hand-rolling a new analyzeHeadless call.

See docs/tooling/ghidra-backend.md for the full design writeup and
docs/investigations/toolchain-cleanup.md for why this replaced the old
per-query analyzeHeadless pattern.
"""
import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"
CACHE_ROOT = REPO_ROOT / "research" / "runs" / "ghidra_cache"

# An explicit, manual override for a semantic change that content-hashing
# below can't see on its own (e.g. a change to how Ghidra itself is
# invoked, or an intentional "treat every cache as stale" reset). Ordinary
# edits to APTraceSeedVectorTable.java, APTraceApplyProvenance.java,
# APTraceExportStaticAnalysis.java, or a firmware's provenance TSV already
# invalidate the cache automatically via their own content hashes in
# expected_identity() -- bumping this is not required for those.
ANALYSIS_VERSION = 1

PROCESSOR = "ARM:LE:32:Cortex"
CSPEC = "default"

# Address-range defaults for APTraceExportCensus.java's RAM/MMIO
# classification -- matches tools/unicorn/concrete.py's ram_base/ram_size
# and tools/unicorn/virtual_link.py's (wider) MMIO window, so a static
# memory/MMIO access and a dynamic (Unicorn) one are classified against
# the same address ranges.
CENSUS_RAM_BASE = "0x20000000"
CENSUS_RAM_SIZE = "0x30000"
CENSUS_MMIO_BASE = "0x40000000"
CENSUS_MMIO_SIZE = "0x4000000"

# firmware key -> (path relative to repo root, load base, provenance TSV or None)
FIRMWARE_REGISTRY = {
    "autopilot868": ("research/firmware/originals/firmware_autopilot868.bin", "0x4000",
                      "research/provenance/ghidra_labels.tsv"),
    "autopilot915": ("research/firmware/originals/firmware_autopilot915.bin", "0x4000", None),
    "mando868": ("research/firmware/originals/firmware_mando868.bin", "0x4000", None),
    "mando915": ("research/firmware/originals/firmware_mando915.bin", "0x4000", None),
}


def resolve_headless():
    import os
    import shutil as _shutil
    found = _shutil.which("analyzeHeadless")
    if found:
        return found
    env_home = os.environ.get("GHIDRA_HOME")
    if env_home and (Path(env_home) / "support" / "analyzeHeadless").exists():
        return str(Path(env_home) / "support" / "analyzeHeadless")
    try:
        prefix = subprocess.run(["brew", "--prefix", "ghidra"], capture_output=True, text=True, check=True).stdout.strip()
        candidate = Path(prefix) / "libexec" / "support" / "analyzeHeadless"
        if candidate.exists():
            return str(candidate)
    except Exception:
        pass
    sys.exit("error: could not find Ghidra's analyzeHeadless (install with `brew install ghidra`"
              " or set GHIDRA_HOME).")


def ghidra_version(headless_path):
    """Best-effort version extraction from the resolved analyzeHeadless path
    (e.g. .../Cellar/ghidra/12.1.3/libexec/support/analyzeHeadless). Homebrew
    exposes this via a version-less symlink (`opt/ghidra` -> `Cellar/ghidra/
    X.Y.Z`), so the real path must be resolved first. Falls back to
    'unknown' -- staleness detection still works via the other identity
    fields, just without a Ghidra-version-bump trigger."""
    real = str(Path(headless_path).resolve())
    m = re.search(r"ghidra/([0-9][0-9A-Za-z.\-_]*)/", real)
    return m.group(1) if m else "unknown"


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def firmware_info(key):
    if key not in FIRMWARE_REGISTRY:
        sys.exit(f"error: unknown firmware key '{key}'. Known: {', '.join(sorted(FIRMWARE_REGISTRY))}")
    rel_path, base, labels = FIRMWARE_REGISTRY[key]
    path = REPO_ROOT / rel_path
    if not path.exists():
        sys.exit(f"error: firmware file not found: {path}")
    return path, base, (REPO_ROOT / labels) if labels else None


def cache_dir(key):
    return CACHE_ROOT / key


# Every script/data input `build()` actually feeds to analyzeHeadless (see
# its -preScript/-postScript args below) -- hashed into cache identity so
# an edit to any of them invalidates the cache automatically, without
# relying on a human remembering to bump ANALYSIS_VERSION. Scripts that
# only ever run against an already-built, read-only project (decompile/
# disasm) are deliberately excluded: they don't change what's persisted,
# so hashing them would invalidate caches for no reason.
BUILD_SCRIPTS = ("APTraceSeedVectorTable.java", "APTraceApplyProvenance.java",
                  "APTraceExportStaticAnalysis.java", "APTraceExportCensus.java")


def _file_identity_hash(path):
    """sha256 of a real file, or a stable sentinel if it's missing --
    "missing" must still differ from any real content hash, so a script
    or TSV that's deleted (or that only starts existing later) also
    invalidates the cache rather than silently comparing equal."""
    return sha256_of(path) if path.exists() else "missing"


def expected_identity(key):
    path, base, labels_tsv = firmware_info(key)
    headless = resolve_headless()
    identity = {
        "firmware_key": key,
        "firmware_path": str(path.relative_to(REPO_ROOT)),
        "firmware_sha256": sha256_of(path),
        "load_base": base,
        "processor": PROCESSOR,
        "cspec": CSPEC,
        "ghidra_version": ghidra_version(headless),
        "analysis_version": ANALYSIS_VERSION,
    }
    for script in BUILD_SCRIPTS:
        identity[f"script_sha256:{script}"] = _file_identity_hash(SCRIPTS_DIR / script)
    identity["provenance_tsv_sha256"] = (
        _file_identity_hash(labels_tsv) if labels_tsv is not None else None)
    return identity


def read_meta(key):
    meta_path = cache_dir(key) / "meta.json"
    if not meta_path.exists():
        return None
    with open(meta_path) as f:
        return json.load(f)


def cache_status(key):
    """Returns (state, meta, expected) where state is one of:
    'missing' (never built), 'stale' (identity mismatch), 'fresh'."""
    meta = read_meta(key)
    expected = expected_identity(key)
    if meta is None:
        return "missing", None, expected
    if meta != expected:
        return "stale", meta, expected
    return "fresh", meta, expected


def _run_headless(key, extra_args, description, readonly_process=False):
    headless = resolve_headless()
    cdir = cache_dir(key)
    project_name = "aptrace"
    cmd = [headless, str(cdir), project_name] + extra_args
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"error: {description} failed (exit {result.returncode}):\n"
                  f"{result.stdout[-4000:]}\n{result.stderr[-4000:]}")
    return result


def build(key, force=False):
    """First query/build: import -> seed vector table -> auto-analysis ->
    apply provenance labels (if this firmware has any) -> export the full
    static-analysis JSON -> persist the project. Refuses to silently
    clobber a project whose cache identity doesn't match unless
    force=True (i.e. an explicit `rebuild`)."""
    state, meta, expected = cache_status(key)
    cdir = cache_dir(key)
    if state == "fresh" and not force:
        print(f"'{key}' is already built and up to date at {cdir} (use 'rebuild' to force).")
        return
    if cdir.exists():
        if state == "fresh":
            print(f"Rebuilding '{key}' (forced) -- removing {cdir}")
        elif state == "stale":
            print(f"Cache for '{key}' is STALE (identity changed):")
            for k in expected:
                if meta is None or meta.get(k) != expected[k]:
                    print(f"  {k}: cached={meta.get(k) if meta else None!r} -> expected={expected[k]!r}")
            print(f"Rebuilding at {cdir}")
        shutil.rmtree(cdir)
    cdir.mkdir(parents=True, exist_ok=True)

    path, base, labels_tsv = firmware_info(key)
    static_export = cdir / "static_export.json"
    census_export = cdir / "census_export.json"
    args = [
        "-import", str(path),
        "-processor", PROCESSOR,
        "-cspec", CSPEC,
        "-loader", "BinaryLoader",
        "-loader-baseAddr", base,
        "-scriptPath", str(SCRIPTS_DIR),
        "-preScript", "APTraceSeedVectorTable.java", "56", "",
        "-analysisTimeoutPerFile", "300",
    ]
    # Apply provenance labels BEFORE exporting, so the cached JSON (and
    # every callers/xrefs/symbol query answered from it) reflects the
    # renamed, human-readable symbols rather than raw FUN_xxxx addresses.
    if labels_tsv is not None and labels_tsv.exists():
        args += ["-postScript", "APTraceApplyProvenance.java", str(labels_tsv)]
    args += ["-postScript", "APTraceExportStaticAnalysis.java", str(static_export)]
    # Basic-block/CFG-edge/RAM-MMIO-access export for `aptrace census`
    # (tools/census/) -- see APTraceExportCensus.java's own docstring for
    # why this is a separate script from APTraceExportStaticAnalysis.java.
    args += ["-postScript", "APTraceExportCensus.java", str(census_export),
              CENSUS_RAM_BASE, CENSUS_RAM_SIZE, CENSUS_MMIO_BASE, CENSUS_MMIO_SIZE]
    print(f"Building '{key}' ({path.name}) -- this runs full auto-analysis once...")
    _run_headless(key, args, f"build '{key}'")

    meta = expected_identity(key)
    with open(cdir / "meta.json", "w") as f:
        json.dump(meta, f, indent=2)
    n_funcs = len(json.load(open(static_export))["functions"])
    n_blocks = len(json.load(open(census_export))["basicBlocks"])
    print(f"Built '{key}': {n_funcs} functions, {n_blocks} basic blocks, cached at {cdir}")
    print(f"  (provenance labels {'applied' if labels_tsv and labels_tsv.exists() else 'not available for this image'})")


def ensure_fresh(key):
    state, meta, expected = cache_status(key)
    if state == "missing":
        sys.exit(f"error: '{key}' has not been built yet. Run: "
                  f"tools/ghidra/aptrace_ghidra.py build {key}")
    if state == "stale":
        sys.exit(f"error: cached project for '{key}' is STALE (firmware/toolchain/analysis-version "
                  f"changed since it was built). Run: tools/ghidra/aptrace_ghidra.py rebuild {key}")


def _query_via_process(key, post_script, script_args, description):
    """Reopen the persistent project (-process -noanalysis -readOnly) and
    run one postScript against it -- no re-import, no re-analysis."""
    ensure_fresh(key)
    path, _, _ = firmware_info(key)
    program_name = path.name
    args = [
        "-process", program_name,
        "-noanalysis", "-readOnly",
        "-scriptPath", str(SCRIPTS_DIR),
        "-postScript", post_script,
    ] + script_args
    _run_headless(key, args, description)


def decompile(key, addrs):
    cdir = cache_dir(key)
    out = cdir / "_last_decompile.txt"
    _query_via_process(key, "APTraceDecompileFunctions.java",
                        [str(out), ",".join(addrs)], f"decompile {addrs} in '{key}'")
    print(out.read_text())


def disasm(key, start, end):
    cdir = cache_dir(key)
    out = cdir / "_last_disasm.txt"
    _query_via_process(key, "APTraceDisassembleRange.java",
                        [str(out), start, end], f"disasm {start}-{end} in '{key}'")
    print(out.read_text())


def _load_static_export(key):
    ensure_fresh(key)
    with open(cache_dir(key) / "static_export.json") as f:
        return json.load(f)


def _load_census_export(key):
    """The basic-block/CFG-edge/RAM-MMIO-access export from
    APTraceExportCensus.java, for tools/census/ to build on -- same
    cache-freshness contract as _load_static_export."""
    ensure_fresh(key)
    with open(cache_dir(key) / "census_export.json") as f:
        return json.load(f)


def _norm_addr(a):
    return f"0x{int(a, 0):08x}"


def callers(key, addr):
    """Answered entirely from the cached static export -- no Ghidra
    invocation needed, since the full call graph was already captured at
    build time."""
    data = _load_static_export(key)
    target = _norm_addr(addr)
    hits = [c for c in data["calls"] if c.get("to", "").lower() == target.lower()]
    if not hits:
        print(f"No callers of {target} found in the cached static export for '{key}'.")
        return
    for c in hits:
        print(f"{c['from']}  {c.get('fromFunction') or '(unattributed -- possibly a tail-jump target)'}"
              f"  -> {c['to']}  {c.get('toFunction', '')}")


def xrefs(key, addr):
    """Data references TO or FROM the given address, from the cached
    export's dataReferences table."""
    data = _load_static_export(key)
    target = _norm_addr(addr)
    to_hits = [r for r in data["dataReferences"] if r.get("to", "").lower() == target.lower()]
    from_hits = [r for r in data["dataReferences"] if r.get("from", "").lower() == target.lower()]
    if to_hits:
        print(f"References TO {target}:")
        for r in to_hits:
            print(f"  {r['from']} ({r.get('fromFunction','?')})  [{r.get('refType','')}]"
                  + (f"  label={r['toLabel']}" if r.get("toLabel") else ""))
    if from_hits:
        print(f"References FROM {target}:")
        for r in from_hits:
            print(f"  -> {r['to']}  [{r.get('refType','')}]"
                  + (f"  label={r['toLabel']}" if r.get("toLabel") else ""))
    if not to_hits and not from_hits:
        print(f"No data references to/from {target} found in the cached static export for '{key}'.")


def containing(key, addr):
    """Which function's [entry, entry+size) range contains this address --
    answered from the cached function table. Flags the common
    'tail-jump/unattributed region' case this project has hit repeatedly
    (see e.g. persistent-record-motor-target-mapping.md)."""
    data = _load_static_export(key)
    target = int(addr, 0)
    funcs = sorted((int(f["entry"], 16), f) for f in data["functions"])
    best = None
    for entry, f in funcs:
        if entry <= target:
            best = f
        else:
            break
    if best is None:
        print(f"No function found at or before 0x{target:08x}.")
        return
    entry = int(best["entry"], 16)
    size = best.get("size", 0)
    in_range = entry <= target < entry + size
    print(f"{best['name']} @ {best['entry']} size={size}"
          + ("" if in_range else f"  (0x{target:08x} is PAST this function's own recorded size --"
                                   " likely a tail-jumped/unattributed region; verify with disasm)"))


def symbol(key, name_or_addr):
    """Look up a function by name (substring, case-insensitive) or by
    address, from the cached function table."""
    data = _load_static_export(key)
    try:
        target = _norm_addr(name_or_addr)
        hits = [f for f in data["functions"] if f["entry"].lower() == target.lower()]
    except ValueError:
        needle = name_or_addr.lower()
        hits = [f for f in data["functions"] if needle in f["name"].lower()]
    if not hits:
        print(f"No symbol matching '{name_or_addr}' found in '{key}'.")
        return
    for f in hits:
        print(f"{f['entry']}  {f['name']}  size={f.get('size',0)}  thunk={f.get('thunk', False)}")


def literal(key, addr, width=4, count=1):
    """Raw firmware read at a flash address -- no Ghidra needed at all.
    addr is a flash (load-base-relative) address; converted to a file
    offset using the firmware's own registered load base."""
    path, base_s, _ = firmware_info(key)
    base = int(base_s, 0)
    a = int(addr, 0)
    data = path.read_bytes()
    off = a - base
    if off < 0 or off + width * count > len(data):
        sys.exit(f"error: 0x{a:08x} (file offset 0x{off:x}) is outside {path.name} "
                  f"(size 0x{len(data):x}, load base {base_s})")
    fmt = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}[width]
    for i in range(count):
        chunk = data[off + i * width: off + (i + 1) * width]
        (val,) = struct.unpack(fmt, chunk)
        print(f"0x{a + i*width:08x}: 0x{val:0{width*2}x}  ({val})")


def dump(key, addr, length=64):
    """Raw hex dump of `length` bytes starting at a flash address -- no
    Ghidra needed, same file-offset conversion as `literal`."""
    path, base_s, _ = firmware_info(key)
    base = int(base_s, 0)
    a = int(addr, 0)
    data = path.read_bytes()
    off = a - base
    if off < 0 or off + length > len(data):
        sys.exit(f"error: range [0x{a:08x}, 0x{a+length:08x}) is outside {path.name} "
                  f"(size 0x{len(data):x}, load base {base_s})")
    chunk = data[off:off + length]
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        print(f"0x{a+i:08x}  {hex_part:<47}  {ascii_part}")


def status(key=None):
    keys = [key] if key else sorted(FIRMWARE_REGISTRY)
    for k in keys:
        state, meta, expected = cache_status(k)
        print(f"{k}: {state}")
        if meta:
            for field in ("firmware_sha256", "ghidra_version", "analysis_version"):
                mark = "" if meta.get(field) == expected.get(field) else "  <- MISMATCH"
                print(f"    {field}: {meta.get(field)}{mark}")


def main(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="build (or reuse, if already fresh) the persistent project")
    b.add_argument("firmware")

    rb = sub.add_parser("rebuild", help="force a full rebuild, even if the cache looks fresh")
    rb.add_argument("firmware")

    dc = sub.add_parser("decompile", help="decompile one or more functions (comma/space-separated addresses)")
    dc.add_argument("firmware")
    dc.add_argument("addrs", nargs="+")

    da = sub.add_parser("disasm", help="disassemble an address range")
    da.add_argument("firmware")
    da.add_argument("start")
    da.add_argument("end")

    cl = sub.add_parser("callers", help="every real caller of a function (from the cached call graph)")
    cl.add_argument("firmware")
    cl.add_argument("addr")

    xr = sub.add_parser("xrefs", help="data references to/from an address (from the cached export)")
    xr.add_argument("firmware")
    xr.add_argument("addr")

    co = sub.add_parser("containing", help="which function's range contains this address")
    co.add_argument("firmware")
    co.add_argument("addr")

    sy = sub.add_parser("symbol", help="look up a function by name substring or address")
    sy.add_argument("firmware")
    sy.add_argument("name_or_addr")

    li = sub.add_parser("literal", help="raw little-endian read at a flash address (no Ghidra)")
    li.add_argument("firmware")
    li.add_argument("addr")
    li.add_argument("--width", type=int, default=4, choices=(1, 2, 4, 8))
    li.add_argument("--count", type=int, default=1)

    du = sub.add_parser("dump", help="raw hex dump of a byte range (no Ghidra)")
    du.add_argument("firmware")
    du.add_argument("addr")
    du.add_argument("--length", type=int, default=64)

    st = sub.add_parser("status", help="show cache freshness for one or all known firmware keys")
    st.add_argument("firmware", nargs="?")

    args = p.parse_args(argv)

    if args.command == "build":
        build(args.firmware)
    elif args.command == "rebuild":
        build(args.firmware, force=True)
    elif args.command == "decompile":
        decompile(args.firmware, args.addrs)
    elif args.command == "disasm":
        disasm(args.firmware, args.start, args.end)
    elif args.command == "callers":
        callers(args.firmware, args.addr)
    elif args.command == "xrefs":
        xrefs(args.firmware, args.addr)
    elif args.command == "containing":
        containing(args.firmware, args.addr)
    elif args.command == "symbol":
        symbol(args.firmware, args.name_or_addr)
    elif args.command == "literal":
        literal(args.firmware, args.addr, args.width, args.count)
    elif args.command == "dump":
        dump(args.firmware, args.addr, args.length)
    elif args.command == "status":
        status(args.firmware)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
