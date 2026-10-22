"""Performing Rigs AutoPilot/Remote case configuration: the known firmware
images and this target's RAM/MMIO memory geometry.

Moved out of tools/ghidra/aptrace_ghidra.py, which is a reusable Ghidra-
backend orchestrator (see docs/tooling/ghidra-backend.md) and should not
be the place product-specific firmware identities/addresses live. Other
tools import these names from aptrace_ghidra (e.g. build.py's
`ghidra.CENSUS_RAM_BASE`, test_aptrace_ghidra.py's `ag.FIRMWARE_REGISTRY`)
-- aptrace_ghidra.py re-exports them under the same names, so this move
changes nothing for existing callers.

Plain module-level data, not a configuration framework: there is exactly
one product (Performing Rigs AutoPilot/Remote) known to this codebase
today.
"""

import xml.etree.ElementTree as ET
from pathlib import Path

# Address-range defaults for APTraceExportCensus.java's RAM/MMIO
# classification -- matches tools/unicorn/concrete.py's ram_base/ram_size
# and cases/performing-rigs/scripts/virtual_link.py's (wider) MMIO window, so a static
# memory/MMIO access and a dynamic (Unicorn) one are classified against
# the same address ranges.
CENSUS_RAM_BASE = "0x20000000"
CENSUS_RAM_SIZE = "0x30000"
CENSUS_MMIO_BASE = "0x40000000"
CENSUS_MMIO_SIZE = "0x4000000"

# ATSAMD51J19A external (NVIC) interrupt count, derived from the case SVD
# rather than restated: the highest <interrupt><value> plus one (IRQ0..135
# -> 136). The vector table is therefore 16 Cortex-M system words
# (initial SP + 15 exceptions) followed by this many IRQ words. Consumed by
# the census raw vector scan (tools/census/build.py) and the Ghidra vector
# seeding (tools/ghidra/aptrace_ghidra.py); the Haskell side's
# APTrace.Case.PerformingRigs.numIrq must agree (checked by
# cases/performing-rigs/test/test_target_irq_count.py).
TARGET_SVD = Path(__file__).resolve().parent / "svd" / "ATSAMD51J19A.svd"


def _svd_num_external_irq(svd_path):
    values = [int(e.findtext("value"), 0) for e in ET.parse(svd_path).iter("interrupt")]
    return max(values) + 1


NUM_EXTERNAL_IRQ = _svd_num_external_irq(TARGET_SVD)

# firmware key -> (path relative to repo root, load base, provenance TSV or None)
FIRMWARE_REGISTRY = {
    # Research-only derived image. Never substitute for either original key.
    "autopilot915_freshness_research": ("cases/performing-rigs/research/generated/trigger-patch-2026-10-22/RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_freshness.bin", "0x4000", None),
    "autopilot868": ("cases/performing-rigs/research/firmware/originals/firmware_autopilot868.bin", "0x4000",
                      "cases/performing-rigs/research/provenance/ghidra_labels.tsv"),
    "autopilot915": ("cases/performing-rigs/research/firmware/originals/firmware_autopilot915.bin", "0x4000", None),
    "mando868": ("cases/performing-rigs/research/firmware/originals/firmware_mando868.bin", "0x4000", None),
    "mando915": ("cases/performing-rigs/research/firmware/originals/firmware_mando915.bin", "0x4000", None),
}

# Host executables use Ghidra's native format/language detection, never the
# raw Cortex-M loader. Target-specific provenance stays in this case.
EXECUTABLE_REGISTRY = {
    "vendor_bossac": {
        "path": "cases/performing-rigs/research/firmware/vendor-package/bossac.exe",
        "format": "pe32-x86",
        "sha256": "eaebd0b6ef980e464b1a6a5a50eee91f9d6202f51dae7d9f78779d18593121a9",
    },
}
