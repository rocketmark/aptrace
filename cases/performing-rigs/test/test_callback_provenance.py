#!/usr/bin/env python3
"""Performing Rigs: callback-argument provenance v1
(scripts/callback_provenance_investigation.py).

Synthetic results check that the 0xc744 probe never turns an OPEN set into
an exclusion and that missing upstream values are named. Real-image checks
(gitignored census DB) pin the e8a8 -> ec48 callback, the forwarded f0b4
stack argument, the closed f190/1059c sites, and that a fresh run matches
the recorded provenance.json. Run with the agent venv:

    agent/.venv/bin/python cases/performing-rigs/test/test_callback_provenance.py
"""
import json
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE = HERE.parent
sys.path.insert(0, str(CASE / "scripts"))

import callback_provenance_investigation as cpi  # noqa: E402

FAILURES = []
RUNS = CASE / "research" / "runs" / "callback-provenance-v1"


def check(name, condition, detail=""):
    print(f"  [{'ok' if condition else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def result(target_set="OPEN", targets=(), status="CONCRETE", **kw):
    return {"provenance_status": status, "target_set": target_set,
            "candidate_targets": [{"target": t} for t in targets], "incomplete_reasons": [], "argument_origins": [],
            **kw}


def test_probe():
    check("an OPEN set never excludes the thunk",
          cpi._probe(result())["0x0000c744"]["status"] == "NOT_EXCLUDED")
    check("a CLOSED set without the thunk excludes it within scope",
          cpi._probe(result("CLOSED", ["0x0000e882"]))["0x0000c744"]["status"] == "EXCLUDED_WITHIN_SCOPE")
    check("a recovered thunk target is a candidate, whatever the set",
          cpi._probe(result("OPEN", ["0x0000c744"]))["0x0000c744"]["status"] == "CANDIDATE")
    check("no argument origin: not applicable",
          cpi._probe(result(status="NOT_APPLICABLE"))["0x0000c744"]["status"] == "NOT_APPLICABLE")
    r = result(argument_origins=[{"function_entry": "0x0000f0b4", "address_taken": [], "callers": [
        {"site": "0x0000ed00", "value_status": "FORWARDED_ARGUMENT",
         "next_hop": [{"function_entry": "0x0000ec48", "argument": "r3"}]}]}])
    check("a forwarded value names its next hop as the missing upstream value",
          cpi._missing(r) == ["what callers of 0x0000ec48 pass in r3 (forwarded at 0x0000ed00)"], cpi._missing(r))


def test_real():
    import callback_provenance as cp
    import db as census_db

    if not Path(census_db.DEFAULT_DB_PATH).is_file() or not (RUNS / "provenance.json").is_file():
        print("  [skip] census database or recorded run not present")
        return
    conn = sqlite3.connect(f"file:{census_db.DEFAULT_DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM firmware WHERE key=?", (cpi.FIRMWARE,)).fetchone()
    image = (cpi.REPO_ROOT / row["path"]).read_bytes()
    recorded = {r["site"]: r for r in json.loads((RUNS / "provenance.json").read_text())["sites"]}

    r = cp.trace_callback_argument(conn, cpi.FIRMWARE, image, 0xEE60)
    (c,) = r["argument_origins"][0]["callers"]
    check("e8a8 -> ec48: bl at 0xeaac passes the literal 0xe883 in r3 (a constant, not a forwarded argument)",
          (c["site"], c["caller_function"], c["value_status"], c["components"][0]["raw_value"],
           c["components"][0]["basis"]) ==
          ("0x0000eaac", "0x0000e8a8", "CONCRETE", "0x0000e883", "literal at 0x0000eb00"), c["components"])
    check("its target is the Thumb code pointer 0xe882; the set is open (ec48 is address-taken at 0xeafc)",
          [t["target"] for t in r["candidate_targets"]] == ["0x0000e882"] and r["target_set"] == "OPEN"
          and r["argument_origins"][0]["address_taken"][0]["location"] == "0x0000eafc", r["open_reasons"])
    r = cp.trace_callback_argument(conn, cpi.FIRMWARE, image, 0xF114)
    o = r["argument_origins"][0]
    check("f0b4's 'spill' is stack argument 4; both callers forward their own r3",
          (o["argument"], r["provenance_status"], r["next_hops"]) ==
          ("stack argument 4", "FORWARDED_ARGUMENT", [{"argument": "r3", "function_entry": "0x0000ec48"},
                                                      {"argument": "r3", "function_entry": "0x0000f190"}]), r["next_hops"])
    for site, target in ((0xF396, "0x0000e882"), (0x105D2, "0x00010378")):
        r = cp.trace_callback_argument(conn, cpi.FIRMWARE, image, site)
        check(f"0x{site:x}: closed set {{{target}}}; 0xc744 excluded within scope",
              r["target_set"] == "CLOSED" and [t["target"] for t in r["candidate_targets"]] == [target]
              and cpi._probe(r)["0x0000c744"]["status"] == "EXCLUDED_WITHIN_SCOPE", r["open_reasons"])
    fresh = {f"0x{s:08x}": cp.trace_callback_argument(conn, cpi.FIRMWARE, image, s)
             for s in (int(k, 16) for k in recorded)}
    check("a fresh run reproduces the recorded provenance.json", fresh == recorded,
          [k for k in recorded if fresh[k] != recorded[k]])
    summary = json.loads((RUNS / "summary.json").read_text())
    check("no recorded site has 0xc744 as a candidate", summary["c744"]["candidate_at"] == [], summary["c744"])


def main():
    print("test_callback_provenance (case)")
    test_probe()
    test_real()
    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURE(S): {FAILURES}")
        sys.exit(1)
    print("\nall callback provenance case checks passed")


if __name__ == "__main__":
    main()
