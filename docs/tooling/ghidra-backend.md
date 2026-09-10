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

## Usage: `tools/ghidra/aptrace_ghidra.py` (preferred, persistent-project)

**Use this, not a raw `analyzeHeadless` invocation, for every recurring
decompile/disassemble/callers/xrefs/symbol question.** Every prior
investigation in this project imported and fully auto-analyzed the same
raw firmware image (a real, ~10-15s cost, not just process startup) for
a *single* query, then deleted the project — ten questions against one
firmware meant ten full re-analyses.

```sh
# First use of a firmware: import, seed the vector table, auto-analyze,
# apply provenance labels (if research/provenance/ghidra_labels.tsv
# exists for it), export the full static-analysis JSON, and persist the
# Ghidra project under research/runs/ghidra_cache/<key>/ (gitignored,
# fully regenerable). ~10-15s, same as before -- paid once.
tools/ghidra/aptrace_ghidra.py build autopilot868
tools/ghidra/aptrace_ghidra.py build mando868

# Every later query reopens the persisted project with -process
# -noanalysis (skips auto-analysis entirely -- typically ~3s, mostly
# JVM startup) or, where the cached export JSON already has the answer,
# doesn't invoke Ghidra at all (near-instant):
tools/ghidra/aptrace_ghidra.py decompile   mando868 0x49c4          # needs Ghidra (reopened, not re-analyzed)
tools/ghidra/aptrace_ghidra.py disasm      autopilot868 0x83b0 0x83ec  # needs Ghidra (reopened)
tools/ghidra/aptrace_ghidra.py callers     mando868 0x58a8          # from the cached export -- no Ghidra
tools/ghidra/aptrace_ghidra.py xrefs       autopilot868 0x20001b40  # from the cached export -- no Ghidra
tools/ghidra/aptrace_ghidra.py containing  autopilot868 0x8186      # from the cached export -- no Ghidra
tools/ghidra/aptrace_ghidra.py symbol      autopilot868 FUN_00006fd8  # from the cached export -- no Ghidra
tools/ghidra/aptrace_ghidra.py literal     autopilot868 0x8528      # raw firmware read -- no Ghidra at all
tools/ghidra/aptrace_ghidra.py dump        mando868 0x49c0 --length 32  # raw hex dump -- no Ghidra at all

# Cache freshness / explicit invalidation:
tools/ghidra/aptrace_ghidra.py status                # all known firmware keys
tools/ghidra/aptrace_ghidra.py status autopilot868   # one
tools/ghidra/aptrace_ghidra.py rebuild autopilot868  # force a full rebuild
```

Firmware keys (`autopilot868`, `autopilot915`, `mando868`, `mando915`)
and their (path, load base, provenance-labels-TSV-or-None) are in
`FIRMWARE_REGISTRY` at the top of `aptrace_ghidra.py` — add a new image
there, not by hand-rolling a new `analyzeHeadless` command.

### Cache identity and staleness

A cached project is only reused if **all** of these still match what's
recorded in the cache's own `research/runs/ghidra_cache/<key>/meta.json`:
the firmware's own SHA-256, the load base, the processor/language, the
installed Ghidra version, this module's own `ANALYSIS_VERSION` constant
(an explicit manual override for a semantic change identity can't
otherwise see), **and the actual content hashes of every script/data
input `build()` feeds to `analyzeHeadless`** — `APTraceSeedVectorTable
.java`, `APTraceApplyProvenance.java`, `APTraceExportStaticAnalysis
.java`, and the firmware's own provenance-labels TSV, if it has one
(`None` for a firmware with no TSV configured). A hardening pass added
these content hashes specifically so an ordinary edit to a provenance
label or one of those scripts invalidates the cache **automatically** —
no human needs to remember to bump `ANALYSIS_VERSION` for that class of
change; `ANALYSIS_VERSION` remains available for the rarer case identity
can't see on its own (e.g. how Ghidra itself is invoked). `decompile`/
`disasm`'s own scripts are deliberately excluded from identity: they run
read-only against an already-built project and never affect what's
persisted, so hashing them would invalidate caches for no reason. Any
mismatch is reported as `stale`, never silently reused — `build`/a
Ghidra-backed query both refuse and tell you to `rebuild`. `tools/ghidra/
test_aptrace_ghidra.py` regression-tests this (a deliberately tampered
`meta.json`, a modified build script, and a modified provenance TSV all
correctly detected as stale).

### Why callers/xrefs/containing/symbol don't need Ghidra at query time

`build` exports the *entire* analyzed program's structure (functions,
call edges, data references, strings) to `static_export.json` once,
right after applying provenance labels (so renamed, human-readable
symbols are what callers/xrefs/symbol queries see, not raw `FUN_xxxx`
addresses). Everything except `decompile`/`disasm` (which genuinely need
the decompiler/disassembly listing, not just the pre-extracted graph) is
answered by grepping that already-cached JSON in plain Python — no
subprocess, no JVM startup, effectively instant.

### One-off/manual use: `tools/ghidra/analyze_firmware.sh`

Still available for a genuinely one-shot query against a firmware image
that isn't in `FIRMWARE_REGISTRY` (a new/unregistered image, or a
throwaway cross-check you don't want persisted):

```sh
tools/ghidra/analyze_firmware.sh FIRMWARE.bin [LOAD_ADDR_HEX] [OUT_JSON] [EXTRA_SEED_ADDRS]

# e.g. the standard AutoPilot image:
tools/ghidra/analyze_firmware.sh Autopilot_firm/firmware_autopilot868.bin 0x4000

# with extra addresses seeded (for cross-checking a specific region):
tools/ghidra/analyze_firmware.sh Autopilot_firm/firmware_autopilot868.bin 0x4000 \
    research/runs/ghidra/firmware_autopilot868.json "0x8259,0x801c,0x8a35"
```

Output is JSON in the same shape `aptrace_ghidra.py build` produces
internally: program metadata (language, memory blocks), functions, call
edges (caller->callee), data references from code, and defined strings.
This always re-imports and re-analyzes (`-deleteProject`, nothing
persists) -- use `aptrace_ghidra.py` instead for any firmware you expect
to query more than once. A reference run against `firmware_autopilot868.bin`
from before the persistent-cache workflow existed is checked in at
`research/runs/ghidra/firmware_autopilot868.json`, kept for historical
investigations that cite it by that path.

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
  function starts from the vector table (+ optional extra addresses). Run
  once, at `build` time.
- `tools/ghidra/scripts/APTraceApplyProvenance.java` — `-postScript`, run
  (at `build` time, before export) when a firmware has a
  `research/provenance/*.tsv` labels file — renames functions and adds
  plate comments from the provenance classification work (see
  [`docs/investigations/boot-and-hardware-bringup.md`](../investigations/boot-and-hardware-bringup.md)).
- `tools/ghidra/scripts/APTraceExportStaticAnalysis.java` — `-postScript`,
  exports the JSON described above (post-provenance, so renamed symbols
  are what it captures). Hand-rolled JSON serialization (no external
  library dependency — headless scripts only have Ghidra's own bundled
  classpath). Run once, at `build` time; this is the file
  `aptrace_ghidra.py callers/xrefs/containing/symbol` query without
  invoking Ghidra again.
- `tools/ghidra/scripts/APTraceDecompileFunctions.java` — `-postScript`,
  dumps decompiler C output for a comma-separated list of addresses to a
  text file. Cheaper to read than raw p-code for "what does this function
  actually do" questions. Run per query, against the *reopened* project
  (`-process -noanalysis`, not a fresh `-import`) via `aptrace_ghidra.py
  decompile`.
- `tools/ghidra/scripts/APTraceDisassembleRange.java` — `-postScript`,
  dumps per-instruction (address, mnemonic, operands) for one address
  range. Decompiled C hides real instruction addresses; reach for this
  when a Unicorn scenario needs an exact call-site or loop-entry address
  (see
  [`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md)
  for a real use). Run per query via `aptrace_ghidra.py disasm`, same
  reopened-project mechanism as `decompile`.

All four extend `ghidra.app.script.GhidraScript` and are compiled on the
fly by the headless analyzer; no separate build step.

## Known limitations

- The export script's call/data-reference extraction is a single linear
  pass over disassembled instructions — it reflects whatever Ghidra's
  auto-analysis actually reached and disassembled, not a claim that every
  real function has been found. Cross-check against Macaw's independent
  discovery rather than trusting either alone.
- No SVD-based MMIO/peripheral register naming yet — see
  [`tool-selection.md`](tool-selection.md)'s "SVD / MMIO labeling" section
  for the identified mechanism and why it isn't wired up yet.
- `aptrace_ghidra.py`'s cache is keyed on firmware SHA-256 + load base +
  language + Ghidra version + `ANALYSIS_VERSION` + the content hashes of
  `APTraceSeedVectorTable.java`/`APTraceApplyProvenance.java`/
  `APTraceExportStaticAnalysis.java`/the provenance TSV, checked against
  `meta.json` on every use — a mismatch is reported as `stale` and
  refused, never silently reused. Editing any of those four files
  already invalidates the cache automatically via its own hash;
  `ANALYSIS_VERSION` only needs a manual bump for a change identity
  can't see on its own (e.g. how Ghidra itself is invoked).
- The persistent cache lives under `research/runs/ghidra_cache/` (in
  `.gitignore` — not distributed, fully regenerable via `build`).
  `analyze_firmware.sh` (the one-shot path) still always creates a
  temp-directory project and deletes it (`-deleteProject`), for the
  cases that genuinely want no persistence.
