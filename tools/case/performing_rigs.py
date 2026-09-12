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
