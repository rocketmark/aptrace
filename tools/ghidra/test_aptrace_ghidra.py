#!/usr/bin/env python3
"""APTrace: regression coverage for tools/ghidra/aptrace_ghidra.py's
persistent-project cache. Not pytest-based, same convention as
tools/unicorn/test_concrete.py. Builds (or reuses) the mando868 cache,
so the first run pays the one-time ~13s analysis cost; later runs are
fast. Exit code 0 means everything passed.
"""
import io
import sys
import time
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import aptrace_ghidra as ag  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def captured(fn, *a, **kw):
    buf = io.StringIO()
    with redirect_stdout(buf):
        fn(*a, **kw)
    return buf.getvalue()


def main():
    key = "mando868"

    print("build/status: cache identity and freshness")
    ag.build(key)  # builds if missing/stale, else says "already built"
    state, meta, expected = ag.cache_status(key)
    check("status is 'fresh' immediately after build", state == "fresh", state)
    check("meta.json identity matches expected", meta == expected)

    print("query cost: a decompile query after build must not re-run auto-analysis")
    t0 = time.time()
    out = captured(ag.decompile, key, ["0x000049c4"])
    elapsed = time.time() - t0
    check("decompile succeeds and finds the real function", "FUN_000049c4" in out)
    # A full import+analyze is ~10-15s on this project's own firmware
    # images (see docs/tooling/ghidra-backend.md); a reopened, -noanalysis
    # query should be well under that -- generous bound to avoid flakes on
    # a loaded CI box, but still catches "silently re-analyzing every time".
    check(f"reopened query is well under a full re-analysis (took {elapsed:.1f}s)", elapsed < 8.0)

    print("callers/xrefs/containing/symbol: answered from cache, no Ghidra invocation")
    t0 = time.time()
    out = captured(ag.callers, key, "0x58a8")
    elapsed = time.time() - t0
    check("callers finds real call sites into the TX wrapper", "0x000058a8" in out)
    check(f"cached-JSON query is near-instant (took {elapsed:.2f}s)", elapsed < 1.0)

    out = captured(ag.symbol, key, "0x49c4")
    check("symbol finds FUN_000049c4 by address", "FUN_000049c4" in out)

    out = captured(ag.containing, key, "0x49d0")
    check("containing attributes an address inside the function to it",
          "FUN_000049c4" in out and "PAST" not in out)

    print("literal: raw firmware read, no Ghidra needed")
    out = captured(ag.literal, key, "0x49c0")
    check("literal reads the real struct-base pointer (0x20000b20)", "0x20000b20" in out, out)

    print("staleness detection: a tampered meta.json must be refused, not silently reused")
    meta_path = ag.cache_dir(key) / "meta.json"
    import json
    real_meta = json.load(open(meta_path))
    tampered = dict(real_meta, firmware_sha256="0" * 64)
    with open(meta_path, "w") as f:
        json.dump(tampered, f)
    state, _, _ = ag.cache_status(key)
    check("tampered identity is detected as 'stale', not 'fresh'", state == "stale", state)
    raised = False
    try:
        ag.ensure_fresh(key)
    except SystemExit:
        raised = True
    check("a stale cache refuses to answer a Ghidra-backed query", raised)
    # restore
    with open(meta_path, "w") as f:
        json.dump(real_meta, f, indent=2)

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s): {FAILURES}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
