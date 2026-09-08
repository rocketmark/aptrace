# Ghidra Backend

Static RE, decompilation, cross-references, structure/table recovery. See
[`tool-selection.md`](tool-selection.md) for when to reach for this instead
of Macaw or Crucible.

## Setup

Installed via Homebrew (bottled, pulls in `openjdk@21`):

```sh
brew install ghidra   # pinned at 12.1.3 as of this writing
```

`tools/ghidra/analyze_firmware.sh` locates `analyzeHeadless` automatically
(checks `PATH`, then `$GHIDRA_HOME/support/analyzeHeadless`, then
`brew --prefix ghidra`). No manual configuration needed after `brew install`.

## Usage

```sh
tools/ghidra/analyze_firmware.sh FIRMWARE.bin [LOAD_ADDR_HEX] [OUT_JSON] [EXTRA_SEED_ADDRS]

# e.g. the standard AutoPilot image:
tools/ghidra/analyze_firmware.sh Autopilot_firm/firmware_autopilot868.bin 0x4000

# with extra addresses seeded (for cross-checking a specific region):
tools/ghidra/analyze_firmware.sh Autopilot_firm/firmware_autopilot868.bin 0x4000 \
    research/runs/ghidra/firmware_autopilot868.json "0x8259,0x801c,0x8a35"
```

Output is JSON: program metadata (language, memory blocks), functions,
call edges (caller->callee), data references from code, and defined
strings. A reference run against `firmware_autopilot868.bin` is checked in
at `research/runs/ghidra/firmware_autopilot868.json`.

## Why `ARM:LE:32:Cortex`, specifically

The language is forced via `-processor "ARM:LE:32:Cortex" -cspec default`
rather than left to auto-detection (raw binaries have no format hint to
auto-detect from anyway). This specific language's processor spec
(`ARMCortex.pspec`) sets the `TMode` context register to `1` (Thumb) for
the entire address space **by construction** — meaning this configuration
is architecturally incapable of decoding A32/ARM-mode instructions,
matching real Cortex-M4F hardware exactly. That property is what makes it
a meaningful independent cross-check on Macaw's decode (see
[`tool-selection.md`](tool-selection.md)'s "Tool disagreements" section for
the concrete case this caught).

## Why vector-table seeding is necessary

A raw `BinaryLoader` import gives Ghidra **no entry points at all**. Its own
heuristic Function Start Search alone is not enough: an unseeded run of
`firmware_autopilot868.bin` found only 204 functions, none in the
`0x8000`-`0x9700` range where the protocol dispatcher lives. The wrapper
script runs `tools/ghidra/scripts/APTraceSeedVectorTable.java` as a
`-preScript`, which reads the same 56-entry (16 system + 40 IRQ) vector
table structure already validated by `tools/vector_scan.py` and
`APTrace.VectorTable` (see
[`../firmware/firmware-layout.md`](../firmware/firmware-layout.md)) and
disassembles/creates a function at each handler address before
auto-analysis runs. This alone took the function count from 204 to 414,
including the dispatcher region, by letting Ghidra's own flow-following
analysis reach code no longer cut off from every entry point.

The same script accepts a 4th argument to the wrapper (a comma-separated
list of additional addresses) for seeding specific addresses under
investigation that aren't reachable from the vector table alone — this is
how the `0x801c` cross-check in `tool-selection.md` was done.

## Scripts

- `tools/ghidra/scripts/APTraceSeedVectorTable.java` — `-preScript`, seeds
  function starts from the vector table (+ optional extra addresses).
- `tools/ghidra/scripts/APTraceExportStaticAnalysis.java` — `-postScript`,
  exports the JSON described above. Hand-rolled JSON serialization (no
  external library dependency — headless scripts only have Ghidra's own
  bundled classpath).

Both extend `ghidra.app.script.GhidraScript` and are compiled on the fly by
the headless analyzer; no separate build step.

## Known limitations

- The export script's call/data-reference extraction is a single linear
  pass over disassembled instructions — it reflects whatever Ghidra's
  auto-analysis actually reached and disassembled, not a claim that every
  real function has been found. Cross-check against Macaw's independent
  discovery rather than trusting either alone.
- No SVD-based MMIO/peripheral register naming yet — see
  [`tool-selection.md`](tool-selection.md)'s "SVD / MMIO labeling" section
  for the identified mechanism and why it isn't wired up yet.
- `analyzeHeadless` always creates a Ghidra project; the wrapper script uses
  a temp directory and `-deleteProject` so nothing persists beyond the
  exported JSON.
