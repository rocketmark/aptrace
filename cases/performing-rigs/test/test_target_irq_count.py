#!/usr/bin/env python3
"""Performing Rigs ATSAMD51 vector-table coverage: the target's external
IRQ count comes from the case SVD and reaches every vector consumer (census
raw scan, Ghidra seeding, Haskell numIrq), and the high-numbered IRQs the
old 40-IRQ assumption dropped (SERCOM, USB, TCC/TC) are recorded and
accepted as reachability roots. Same convention as test_reduce.py -- plain
assertions, not pytest:

    tools/unicorn/.venv/bin/python3 cases/performing-rigs/test/test_target_irq_count.py

The image checks need the hash-verified AutoPilot868 original; the
census-database checks need a census built with this IRQ count (each
skips, with a message, if its input is absent or stale).
"""
import re
import sqlite3
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE = HERE.parent
REPO_ROOT = HERE.parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools" / "census"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "ghidra"))
sys.path.insert(0, str(CASE / "config"))

import aptrace_ghidra as ghidra  # noqa: E402
import db as census_db  # noqa: E402
import performing_rigs  # noqa: E402
import raw_scan  # noqa: E402
import reachability  # noqa: E402

FAILURES = []

IMAGE = REPO_ROOT / performing_rigs.FIRMWARE_REGISTRY["autopilot868"][0]
FLASH_BASE = int(performing_rigs.FIRMWARE_REGISTRY["autopilot868"][1], 16)
CENSUS_DB = CASE / "research" / "runs" / "census" / "census.sqlite3"

# Handler targets read from the AutoPilot868 vector table (static,
# mechanically read 2026-10-12; raw words have the Thumb bit set).
USB_HANDLERS = {80: 0xCC14, 81: 0xCCB6, 82: 0xCCBA, 83: 0xCCBE}
SERCOM_HIGH = {50: 0xB114, 65: 0xB140}   # SERCOM1_0, SERCOM4_OTHER
TC_TCC_HIGH = {93: 0x60EC, 110: 0x60D0}  # TCC1_MC0, TC3
DEFAULT_HANDLER = 0xCC10


def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def test_irq_count_is_target_configuration():
    print("test_irq_count_is_target_configuration")
    svd_values = [int(e.findtext("value"), 0)
                  for e in ET.parse(performing_rigs.TARGET_SVD).iter("interrupt")]
    check("NUM_EXTERNAL_IRQ is the SVD's highest interrupt number + 1",
          performing_rigs.NUM_EXTERNAL_IRQ == max(svd_values) + 1, performing_rigs.NUM_EXTERNAL_IRQ)
    check("ATSAMD51J19A SVD defines IRQ0..135 (136 external IRQs), not the old 40",
          performing_rigs.NUM_EXTERNAL_IRQ == 136, performing_rigs.NUM_EXTERNAL_IRQ)

    hs = (CASE / "src" / "APTrace" / "Case" / "PerformingRigs.hs").read_text()
    m = re.search(r"^numIrq\s*=\s*(\d+)\s*$", hs, re.M)
    check("Haskell APTrace.Case.PerformingRigs.numIrq agrees with the SVD-derived count",
          m is not None and int(m.group(1)) == performing_rigs.NUM_EXTERNAL_IRQ,
          m.group(1) if m else "numIrq not found")

    check("Ghidra seeding covers 15 system + NUM_EXTERNAL_IRQ words after the initial SP",
          ghidra.SEED_VECTOR_WORDS == 15 + performing_rigs.NUM_EXTERNAL_IRQ, ghidra.SEED_VECTOR_WORDS)


def _image_vectors():
    if not IMAGE.is_file():
        print(f"  SKIP: {IMAGE} not present")
        return None
    return {v["vector_index"]: v for v in raw_scan.read_vectors(
        IMAGE, FLASH_BASE, num_irq=performing_rigs.NUM_EXTERNAL_IRQ)}


def test_high_irq_vectors_in_image_scan():
    print("test_high_irq_vectors_in_image_scan")
    vectors = _image_vectors()
    if vectors is None:
        return
    check("scan covers all 16 + 136 vector words (not capped at IRQ40)",
          len(vectors) == 152 and max(vectors) == 151, len(vectors))
    for label, table in (("USB", USB_HANDLERS), ("SERCOM", SERCOM_HIGH), ("TC/TCC", TC_TCC_HIGH)):
        for irq, target in table.items():
            v = vectors.get(16 + irq)
            check(f"{label} IRQ{irq} -> 0x{target:x} (canonical, Thumb bit cleared), is_irq",
                  v is not None and v["target_addr"] == target and v["raw_value"] == target | 1
                  and v["is_irq"] == 1,
                  v and hex(v["target_addr"] or 0))
    beyond_40 = [i - 16 for i, v in vectors.items()
                 if i >= 16 + 40 and v["target_addr"] not in (None, DEFAULT_HANDLER)]
    check("21 populated non-default IRQ handlers at IRQ40+ (beyond old coverage) are now scanned",
          len(beyond_40) == 21, beyond_40)


def test_reachability_accepts_high_irq_roots():
    print("test_reachability_accepts_high_irq_roots (synthetic database)")
    with tempfile.TemporaryDirectory() as d:
        conn = census_db.connect(Path(d) / "t.sqlite3")
        conn.execute("INSERT INTO firmware (key, path, sha256, flash_base, size_bytes, ram_base, ram_size, "
                     "mmio_base, mmio_size, built_at) VALUES ('t','t.bin','0',?,4096,0x20000000,0x30000,"
                     "0x40000000,0x4000000,'2026-10-12T00:00:00Z')", (FLASH_BASE,))
        fw = census_db.get_firmware_id(conn, "t")
        for irq, target in USB_HANDLERS.items():
            conn.execute("INSERT INTO functions (firmware_id, entry, name, size, thunk, external, source) "
                         "VALUES (?,?,?,?,0,0,'t')", (fw, target, f"FUN_{target:08x}", 4))
            conn.execute("INSERT INTO vectors (firmware_id, vector_index, raw_value, target_addr, name, "
                         "is_irq, landed_in_known_function, source) VALUES (?,?,?,?,NULL,1,1,'t')",
                         (fw, 16 + irq, target | 1, target))
        conn.commit()
        root_ids = reachability.compute_roots(conn, fw)
        rows = conn.execute("SELECT addr, root_kind, justification FROM reachability_roots "
                            "WHERE firmware_id=?", (fw,)).fetchall()
        check("USB IRQ80-83 handlers are irq-vector roots with function ids",
              {r["addr"] for r in rows if r["root_kind"] == "irq-vector"} == set(USB_HANDLERS.values())
              and len(root_ids) == 4, [tuple(r) for r in rows])
        check("root justification names the high IRQ number",
              any("IRQ83" in r["justification"] for r in rows))
        conn.close()


def test_built_census_has_high_irq_vectors():
    print("test_built_census_has_high_irq_vectors (real census database)")
    if not CENSUS_DB.is_file():
        print(f"  SKIP: {CENSUS_DB} not built")
        return
    conn = sqlite3.connect(f"{CENSUS_DB.resolve().as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    fw = conn.execute("SELECT id FROM firmware WHERE key='autopilot868'").fetchone()
    if fw is None:
        print("  SKIP: autopilot868 not in census")
        return
    fw = fw["id"]
    n = conn.execute("SELECT COUNT(*) FROM vectors WHERE firmware_id=?", (fw,)).fetchone()[0]
    if n != 16 + performing_rigs.NUM_EXTERNAL_IRQ:
        print(f"  SKIP: census has {n} vectors -- built before the IRQ-count fix; rebuild it")
        return
    roots = {r["addr"] for r in conn.execute(
        "SELECT addr FROM reachability_roots WHERE firmware_id=? AND root_kind='irq-vector'", (fw,))}
    for label, table in (("USB", USB_HANDLERS), ("SERCOM", SERCOM_HIGH), ("TC/TCC", TC_TCC_HIGH)):
        for irq, target in table.items():
            v = conn.execute("SELECT target_addr FROM vectors WHERE firmware_id=? AND vector_index=?",
                             (fw, 16 + irq)).fetchone()
            check(f"census {label} IRQ{irq} vector -> 0x{target:x} and is a reachability root",
                  v is not None and v["target_addr"] == target and target in roots)
    conn.close()


if __name__ == "__main__":
    test_irq_count_is_target_configuration()
    test_high_irq_vectors_in_image_scan()
    test_reachability_accepts_high_irq_roots()
    test_built_census_has_high_irq_vectors()

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
        sys.exit(1)
    print("All checks passed.")
    sys.exit(0)
