# `aptrace census` — mechanical firmware evidence database

A fully mechanical firmware census/closure system: deterministic static
analysis (Ghidra, an independent Capstone cross-check, a raw
vector-table/function-pointer scan, SVD resolution) plus existing
Unicorn dynamic coverage go in; a queryable SQLite evidence database and
a mechanical closure report come out. **No LLM interpretation anywhere
in the pipeline or its output** — every row is either a direct
transcription of a tool's own result or a small, explicitly-documented
deterministic derivation (interval math, a regex, address-range
membership). Semantic classification ("this function is a motor
handler") is a later, separate phase this system does not attempt — see
"Limitations" below.

This complements, and does not replace, the rest of `docs/tooling/`:
`tool-selection.md` still governs which specialist tool to reach for on
a *targeted* question; this document governs the one-command *bulk
inventory* pass that gives later targeted work something to start from.

## What it collects

Per firmware image, in one `census build` run:

- **Static, from Ghidra** (`tools/ghidra/scripts/APTraceExportCensus.java`,
  run as an additional headless postScript alongside the existing
  `APTraceExportStaticAnalysis.java`, cached the same content-hash-gated
  way — see `tools/ghidra/aptrace_ghidra.py`): functions, Ghidra's own
  basic-block model, block-level CFG edges (fallthrough/branch/cbranch/
  call/computed), RAM and MMIO reads/writes with an access width derived
  from the Thumb mnemonic, and (reused directly from the existing
  static export) call edges, flash/literal data references, and
  strings.
- **Unresolved indirect control flow**: a computed branch/call
  instruction with no reference Ghidra's own analysis resolved is
  recorded as an edge with `to_addr = NULL`, `resolved = 0` — never
  silently dropped.
- **Static, independent of Ghidra** (`tools/census/raw_scan.py`): the
  ARMv7-M vector table, read directly from the firmware's own flash
  bytes (mirroring `APTraceSeedVectorTable.java`'s own parsing, kept as
  a separate queryable record); function-pointer *candidates* — 4-byte-
  aligned flash words outside any known function body whose value (Thumb
  bit stripped) equals a known function's entry point.
- **Static, independent cross-check** (`tools/census/capstone_sweep.py`):
  a from-scratch Capstone Thumb disassembly walk from the same roots
  (vectors ∪ Ghidra function entries), recording every direct branch/
  call target it finds. Per `docs/tooling/tool-selection.md`'s
  tool-disagreement discipline, **this is a cross-check, never treated
  as superior to Ghidra** — its only job is to flag a target Ghidra's
  own basic-block coverage didn't end up including (`scan_warnings`
  category `capstone-target-not-in-ghidra-coverage`).
- **MMIO/pin resolution** (`tools/census/pins.py`, on top of the
  existing `tools/svd/resolve_mmio.py` — no independent SVD parsing):
  every MMIO access resolved to a peripheral/register name where
  possible; `PORT.GROUPn.PINCFGxx` (exact) and `PORT.GROUPn.PMUXxx`
  (heuristic — one byte covers two pins) accesses further resolved to a
  specific pin (`PA08`, etc).
- **Dynamic, from the existing Unicorn scenario corpus**
  (`tools/census/dynamic_export.py` + `dynamic_ingest.py`, see "Dynamic
  coverage ingestion" below): every unique PC executed, every RAM/MMIO
  access, stop reason, and any TX/RX bytes a scenario already captured —
  for each leg of every scenario in `tools/unicorn/virtual_link.py`
  (`run_ampersand_roundtrip`, `run_g_ack_roundtrip`, `run_s_roundtrip`,
  `run_plus_target_distance_roundtrip`, `run_pb05_reload_motion_check`,
  `run_t_status_feedback_check`), without modifying any of that
  scenario logic.

Deliberately **not** collected: Crucible/What4/Z3 symbolic evidence
(bulk symbolic execution is explicitly out of scope for census
generation — see `tool-selection.md`; symbolic execution stays reserved
for later targeted questions) and any semantic label.

## Evidence sources (provenance)

Every row carries a `source` column naming exactly where it came from,
so no fact is ever presented without a way to trace it back:

| `source` value | Meaning |
|---|---|
| `ghidra` | Direct from Ghidra's function/string tables |
| `ghidra-basicblockmodel` | Ghidra's `BasicBlockModel`-derived blocks/edges |
| `ghidra-instrscan` | A per-instruction Ghidra scan (unresolved indirect flow) |
| `ghidra-refmgr` | Ghidra's `ReferenceManager` (memory/MMIO/literal accesses) |
| `capstone-sweep` | The independent Capstone cross-check |
| `raw-vector-scan` | A direct read of the firmware's own flash bytes |
| `raw-flashword-scan` | The function-pointer-candidate scan |
| `svd`, `svd+ghidra-refmgr` | SVD-resolved peripheral/register/pin facts |
| `unicorn-<scenario>` (via `dynamic_runs.source_file`) | One ingested Unicorn scenario capture |

## Database / output location

- Database: `research/runs/census/census.sqlite3` (override with `--db`).
  One database covers every firmware image ever built into it — rows are
  scoped by `firmware_id`, tables are not duplicated per image.
- Dynamic-coverage capture files (intermediate, one per scenario):
  `research/runs/census/dynamic/<scenario>.json`.
- Schema: `tools/census/schema.sql` (also the authoritative table/column
  reference — read it directly rather than this doc for exact types).
  Sixteen tables: `firmware`, `functions`, `basic_blocks`, `edges`,
  `vectors`, `function_pointers`, `memory_accesses`, `mmio_accesses`,
  `literal_refs`, `strings`, `peripherals`, `pins`, `dynamic_runs`,
  `dynamic_coverage`, `dynamic_memory`, `dynamic_mmio`, `dynamic_tx_rx`,
  `scan_warnings`.
- A `census build` run **replaces** that firmware's own rows in every
  table (see `tools/census/db.py`'s `clear_firmware_data`/
  `replace_firmware_rows`) — it reflects the current Ghidra
  cache/firmware/scripts exactly, not an accumulation across rebuilds.
  This also clears previously-ingested dynamic coverage (its
  `function_id`/`basic_block_id` attributions would otherwise point at
  rows a static rebuild just replaced) — re-run `ingest-dynamic` after
  any `build`.

## CLI usage

All commands take a firmware key from `tools/ghidra/aptrace_ghidra.py`'s
`FIRMWARE_REGISTRY` (`autopilot868`, `autopilot915`, `mando868`,
`mando915`). Run with the Unicorn venv, the only Python environment in
this repo with both `sqlite3` and `capstone` available:

```
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py build autopilot868
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py summary autopilot868
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py function autopilot868 0x8258
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py callers autopilot868 0x8258
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py callees autopilot868 0x8258
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py readers autopilot868 0x20001b40
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py writers autopilot868 0x20001b40
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py peripheral autopilot868 PORT
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py pin autopilot868 PB05
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py uncovered autopilot868
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py indirect-edges autopilot868
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py warnings autopilot868 [--category CATEGORY]
```

Addresses are hex (`0x` prefix optional), matching every other address
convention in this project.

`build` runs the Ghidra static pipeline (building/reusing the
persistent project cache), the raw scans, and the Capstone cross-check,
but does **not** run Unicorn scenarios itself (that's a separate,
explicit step, so a plain `census build` stays fast and side-effect-free
against the emulator):

```
tools/unicorn/.venv/bin/python3 -c "
import sys; sys.path.insert(0, 'tools/census')
import dynamic_export
dynamic_export.capture(['all'])   # or e.g. ['g', 's']
"
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py ingest-dynamic research/runs/census/dynamic
```

## What the closure metrics mean

`aptrace_census.py summary <firmware>` reports mechanical counts only —
**no "percent understood" figure is computed or implied**; semantic
classification is a separate, later phase this system deliberately does
not attempt (see the top-level task this tooling was built for). The
counts answer:

- How many functions/basic blocks did Ghidra discover, and how many
  blocks aren't attributed to any known function (a residual queue
  item, not necessarily a bug — see `scan_warnings`).
- How many CFG edges are resolved (Ghidra) vs. unresolved indirect, and
  how many the independent Capstone sweep found (its own count, not
  folded into Ghidra's).
- How many RAM locations, MMIO sites, and peripherals are referenced at
  all.
- How many functions have at least one ingested dynamic run passing
  through them ("dynamically exercised") vs. not ("uncovered" — see
  `uncovered`, the direct residual-queue answer to "statically
  reachable but never dynamically exercised", modulo the caveat in
  Limitations below about what "reachable" means here).
- How many `scan_warnings` rows exist, broken down by category — the
  disagreement/anomaly residual queue (see next section).

## Residual queues (`scan_warnings` categories)

- `capstone-target-not-in-ghidra-coverage` — a branch/call target the
  independent Capstone sweep found that Ghidra's own basic-block model
  doesn't cover. A static-discovery disagreement, not an assumed bug in
  either tool.
- `vector-outside-known-function` — a populated vector-table entry whose
  target isn't a known Ghidra function entry.
- `mmio-unresolved` — an MMIO address accessed by the firmware that the
  vendored SVD has no peripheral covering.
- `exec-bytes-unowned` — a byte range inside an executable memory block
  that no discovered basic block covers (may legitimately be a literal
  pool or alignment padding, not necessarily a bug — reported as raw
  evidence either way).

Also directly queryable without a dedicated warning category:
unresolved indirect edges (`indirect-edges`), functions never
dynamically exercised (`uncovered`), and any pin/peripheral referenced
only through evidence weaker than PINCFG/PMUX (queryable via
`peripheral PORT`, which lists every raw PORT access including ones
`pin` can't attribute to a single pin — see Limitations).

## Limitations

- **"Reachable" in `uncovered` means "discovered by Ghidra as a
  function", not "provably reachable from a vector root".** A full
  static reachability closure (transitive closure of resolved call/jump
  edges from the vector table) is not computed by this pass — every
  Ghidra-discovered function is treated as the reachability universe.
  This is a reasonable approximation (Ghidra's own discovery is already
  seeded from the vector table and driven by real code discovery) but
  is not the same claim as "a solver-confirmed reachable path exists."
- **PORT bitmask registers are not attributed to a single pin.**
  `DIR`/`DIRSET`/`DIRCLR`/`OUT`/`OUTSET`/`OUTCLR`/`IN`/`CTRL`/
  `WRCONFIG` are 32-bit, one-bit-per-pin registers; which pin(s) a given
  access touches depends on an immediate bitmask value that would need
  real dataflow analysis to recover, not just a register-name pattern
  match. Only `PINCFG` (exact, one pin) and `PMUX` (heuristic, one byte
  shared by two pins — real SAMD5x/E5x hardware packing, not a guess)
  accesses appear in the `pins` table. Every PORT access is still fully
  captured in `mmio_accesses`/queryable via `peripheral PORT`.
- **No physical-connector identity.** `pins` never claims "PA08 = Motor
  connector X" — that is a different evidence class (a curated
  annotation, not a mechanical scan result) and this tooling does not
  attempt it. See `docs/hardware/hardware-reference.md` if such curated
  mappings exist.
- **The Capstone sweep is a bounded, best-effort linear walk** (per-seed
  and total instruction caps in `capstone_sweep.py`), not a guaranteed-
  exhaustive disassembly — it exists only to surface a disagreement
  worth investigating, not to replace Ghidra.
- **Function-pointer candidates can include false positives.** Any odd
  ("Thumb-bit-set") flash word outside a known function body whose value
  happens to equal a real function's entry point is reported — a
  coincidental match is possible, especially for a small firmware image
  with many short functions; `matches_known_function` records the fact,
  not a claim of certainty.
- **Dynamic coverage only reflects the currently-ingested scenario
  corpus.** `uncovered`/`function ... dynamically exercised` are exactly
  as complete as the scenarios captured via `dynamic_export.py` — a
  function genuinely reachable at runtime but not exercised by any of
  the six scenarios in `tools/unicorn/virtual_link.py` will show as
  uncovered.
- **No semantic classification.** Nothing in this database says what a
  function or peripheral access *means* — that is intentionally a
  separate, later phase (see the "Semantic classification" note at the
  top).

## How to rerun it

```
# Full pipeline, one firmware image:
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py build <firmware-key>

# All four known images:
for fw in autopilot868 autopilot915 mando868 mando915; do
  tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py build "$fw"
done

# Dynamic coverage (once, covers whichever firmware images the scenario
# corpus touches -- currently autopilot868 and mando868):
tools/unicorn/.venv/bin/python3 -c "
import sys; sys.path.insert(0, 'tools/census')
import dynamic_export; dynamic_export.capture(['all'])
"
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py ingest-dynamic research/runs/census/dynamic

# Regression tests:
tools/unicorn/.venv/bin/python3 tools/census/test_census.py
```

`census build` is deterministic given the same firmware bytes, Ghidra
version, and script contents (the same content-hash cache-freshness
contract `tools/ghidra/aptrace_ghidra.py` already uses — see
`ANALYSIS_VERSION`/`BUILD_SCRIPTS` there); `census ingest-dynamic` is
deterministic given the same dynamic-export JSON files, which are
themselves deterministic given the same firmware and
`tools/unicorn/virtual_link.py` scenario code (Unicorn concrete
execution has no randomness in this harness).
