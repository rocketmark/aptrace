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

`census build` produces the raw inventory (below). `census reduce`
(see "Closure reduction" below) runs on top of it and mechanically
narrows "all discovered functions" down through reachability, indirect-
edge resolution, cross-image library/platform fingerprinting, and
dynamic coverage to a small residual set — the actual input a later
semantic-classification phase should look at.

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
  Eighteen base-evidence tables (`census build`): `firmware`,
  `functions`, `basic_blocks`, `edges`, `vectors`, `function_pointers`,
  `memory_accesses`, `mmio_accesses`, `literal_refs`, `strings`,
  `peripherals`, `pins`, `dynamic_runs`, `dynamic_coverage`,
  `dynamic_memory`, `dynamic_mmio`, `dynamic_tx_rx`, `scan_warnings`.
  Twelve closure-reduction tables (`census reduce`, built ON TOP of the
  above — see "Closure reduction" below): `reachability_roots`,
  `function_reachability`, `indirect_edge_resolutions`,
  `indirect_edge_candidates`, `function_fingerprints`,
  `library_matches`, `function_features`, `components`,
  `component_members`, `hardware_snapshot_runs`, `hardware_snapshot`,
  `pin_snapshot`.
- A `census build` run **replaces** that firmware's own rows in every
  base-evidence table (see `tools/census/db.py`'s `clear_firmware_data`/
  `replace_firmware_rows`) — it reflects the current Ghidra
  cache/firmware/scripts exactly, not an accumulation across rebuilds.
  This also clears previously-ingested dynamic coverage AND any
  closure-reduction data (both reference `functions`/`basic_blocks` ids
  a rebuild just replaced) — re-run `ingest-dynamic` and `census reduce`
  after any `build`. A `census reduce` run replaces only its own twelve
  tables (`clear_reduction_data`), so it can be rerun on its own without
  forcing a static rebuild.

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
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py indirect-edges autopilot868 [--classification C]
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py warnings autopilot868 [--category CATEGORY]

tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py reduce autopilot868
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py reachable autopilot868 [--status S]
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py residual autopilot868
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py components autopilot868 [--id N]
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py library-matches autopilot868 [--confidence C]
tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py hardware-snapshot autopilot868 [--peripheral P]
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

If `census reduce` has run, the summary also prints a "Closure
reduction" section — still mechanical counts only, no invented
"understood %":

- Reachability: `DEFINITELY_REACHABLE` / `POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT`
  / `NO_KNOWN_PATH` function counts.
- Indirect edges: `STATICALLY_RESOLVED` / `DYNAMICALLY_OBSERVED` /
  `FINITE_CANDIDATE_SET` / `UNRESOLVED` counts.
- Library/platform matches: `EXACT` / `STRONG_MATCH` / `POSSIBLE_MATCH`
  / `NO_MATCH` counts (cross-product-family only — see "Closure
  reduction" below for why a same-family sibling match doesn't count
  here).
- **The headline number**: reachable functions, minus cross-product
  library/platform matches, minus dynamically-exercised functions =
  the residual reachable application-function count (also `aptrace
  census residual`) — the actual deliverable this reduction layer
  exists to produce: a SMALL set for later semantic analysis, not
  "hundreds of merely-uncovered functions."
- Component count (`aptrace census components`).
- Hardware-snapshot summary: boot method, whether it completed real
  init, register/peripheral counts, and configured-pin counts (`aptrace
  census hardware-snapshot`).

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

## Closure reduction (`census reduce`)

`census reduce <firmware>` runs a second pass, ON TOP OF an existing
`census build` (it reads, never recomputes, the base evidence tables),
that mechanically narrows "all discovered functions" down to a small
residual set worth a later human/LLM's attention. Still no LLM
interpretation anywhere: every stage below is deterministic static
analysis, bounded byte-pattern scans, cross-image byte/structural
comparison, or a real (unmodified) replay of the existing Unicorn
scenario corpus. Run order (`reduce.py`): indirect-edge resolution →
reachability → fingerprinting → feature records → components →
hardware snapshot — each stage after the first can use the previous
stage's output (e.g. reachability treats a newly-resolved indirect
target as a real edge).

**1. Indirect-edge resolution** (`indirect_resolve.py`) — every
indirect call/jump instruction (Ghidra-resolved or not) is classified
into exactly one of:

- `STATICALLY_RESOLVED` — Ghidra's own basic-block model already
  resolved it (e.g. a compiler-generated `TBB`/`TBH` jump table Ghidra
  itself recovered).
- `DYNAMICALLY_OBSERVED` — no static resolution, but a dedicated replay
  of the Unicorn scenario corpus (`dynamic_candidates`, a `watch` list
  added to every scenario leg via the same non-invasive
  `ConcreteMachine.run` monkeypatch `dynamic_export.py` uses — no
  scenario code changes) actually executed the instruction with a
  concrete register value.
- `FINITE_CANDIDATE_SET` — neither of the above, but a bounded flash
  scan found a plausible candidate table: an inline `TBB`/`TBH` table
  (scanned per the ARMv7-M architecture's own offset encoding, stopping
  at the first entry that doesn't land in the flash image), or a table
  based at the nearest Ghidra-resolved literal-pool constant preceding
  a `LDR`-into-PC instruction in the same basic block.
- `UNRESOLVED` — none of the above found anything. Left exactly as
  unresolved as it was.

Every candidate any method found is kept in `indirect_edge_candidates`
(never deduplicated away — two methods disagreeing stays visible);
`indirect_edge_resolutions` holds the single summary classification
(strongest tier with evidence) plus the decoded instruction shape
(`reg-indirect` / `mem-indirect` / `table-branch` / `unknown`) and a
human-readable note.

**2. Reachability** (`reachability.py`) — transitive closure from
mechanically-justified roots ONLY:

- `Reset_Handler` (the CPU's own boot entry, vector[1]'s target).
- Every populated system/IRQ vector (the ARMv7-M vector table itself —
  hardware fact, not a heuristic).
- Any address that RESOLVED control flow (static or dynamic — an
  `indirect_edge_candidates` row with confidence `EXACT`/`STRONG`)
  actually treats as an indirect call/jump target.

Deliberately **not** a root: a `function_pointers` row (the raw
flash-word scan) by itself — see `reachability_roots`' own module
docstring and `test_reachability_does_not_trust_raw_function_pointer_candidates`
in `test_reduce.py`. Two BFS passes over the same roots produce three
statuses: `DEFINITELY_REACHABLE` (resolved direct/indirect edges only),
`POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT` (only reachable by also
following a `FINITE_CANDIDATE_SET` edge), `NO_KNOWN_PATH` (neither —
NOT a claim of unreachability, just "no path this evidence can
currently construct").

**3. Library/platform fingerprinting** (`fingerprint.py`) — since no
external reference library is vendored in this repo, the strongest
available ground truth is the OTHER firmware images already in the
same census database. Four tiers: `EXACT` (byte-identical to a function
in a different image, or Ghidra's own `thunk=1` fact), `STRONG_MATCH`
(identical normalized (mnemonic, operand-shape) token sequence — same
code, differing only in embedded immediates/addresses), `POSSIBLE_MATCH`
(same block/edge/callee count and byte size within 10%, no hash match),
`NO_MATCH`. **Same-product-family matches are distinguished from
cross-product matches** (`fingerprint._family`, e.g. `autopilot868`/
`autopilot915` are the same family, `mando868` is a different one): a
function byte-identical to its own frequency-variant sibling proves
nothing about "library vs. application" (this firmware's own
application logic is just as likely to be frequency-invariant as a
CMSIS helper is), so only a CROSS-family `EXACT`/`STRONG_MATCH` counts
toward "library/platform" in the residual computation below — a
same-family-only match is still recorded (useful evidence on its own)
but tagged with a `-same-product` method suffix and excluded from that
count. `library_matches` is recomputed for every already-fingerprinted
image every time ANY image is fingerprinted (`recompute_all_matches`),
so cross-image matching is eventually consistent regardless of which
firmware you `reduce` first.

**4. Function feature records** (`features.py`) — one materialized
`function_features` row per function: structural counts only (callers,
callees, basic blocks, RAM/MMIO reads/writes, literal refs, strings,
pins, indirect edges, IRQ-handler flag, dynamic-run/scenario counts)
plus small JSON evidence lists (peripherals/pins/scenarios touched) and
this function's own reachability status/library confidence. No
semantic field — every count is independently re-derivable from the
base tables by direct SQL; this table only saves re-joining them for a
single-function lookup.

**5. Component grouping** (`components.py`) — deterministic connected
components over REACHABLE functions only, via a union-find with FIVE
mechanical union rules (never "any shared call edge" — that collapses
the whole binary through common utility functions like a driver's own
"write register" helper): (1) strongly-connected call-graph components
(Tarjan's algorithm — mutual recursion), (2) a direct call to a
LOW-fan-in callee (`CALL_UNION_MAX_CALLERS`, default 3 — a "private-ish"
helper relationship, not a shared-hub call), (3) sharing a resolved
MMIO peripheral, (4) sharing an exact RAM address, (5) sharing a pin,
(6) co-occurring in the same dynamic scenario run. Stable small-integer
`component_index` per firmware (sorted by each component's minimum
member's entry address) — stable for a GIVEN evidence state, not
across a rebuild that changes the evidence. No naming — every
component's evidence (member functions, peripherals, pins, RAM
addresses, scenarios) is reported for a later human/LLM to name.

**6. Hardware-init snapshot** (`hardware_snapshot.py`) — a real Unicorn
run from `Reset_Handler`, dumping every in-scope peripheral's raw
register bytes (`PORT`, `ADC*`, `TC*`/`TCC*`, `SERCOM*`, `EIC`, `DMAC`,
`NVMCTRL`, `USB`, `WDT`, and the clock tree `GCLK`/`OSCCTRL`/
`OSC32KCTRL`/`MCLK` — every SVD peripheral whose name starts with one
of those prefixes) resolved through the same SVD used everywhere else,
plus a mechanically-decoded per-pin table (`pin_snapshot`: direction
from `DIR`, output/input level from `OUT`/`IN`, `PINCFG` raw byte +
`PMUXEN` bit, `PMUX` raw nibble — pure register-bit arithmetic, no SVD
field-enumeration lookup attempted, see Limitations). **Two honestly-
distinguished boot methods**, recorded in `hardware_snapshot_runs`:

- `established-recipe-partial` (`autopilot868`/`autopilot915`) —
  re-applies, VERBATIM, the disclosed clock/PLL/SERCOM/NVMCTRL
  completion-bit assumptions already published and human-confirmed in
  `docs/investigations/boot-and-hardware-bringup.md`. Named "-partial"
  because that investigation's FULL recipe also seeds a GPIO-input
  boundary condition (PA22) and stubs a DWT-based delay whose exact
  addresses were only narrated, never committed to a reproducible
  script — this module does NOT invent those (new investigative work is
  out of scope for a mechanical reducer). `completed_init` (did it
  reach the real main-loop milestone, `0x8960`) and `notes` (exactly
  which of the doc's own named milestones were reached) report the
  honest result plainly — it is NOT expected to complete.
- `cold-run-bounded` (`mando868`/`mando915`, or any future image with
  no published boot recipe) — `Reset_Handler`, zero disclosed
  assumptions, a plain instruction cap. Expected, honest result:
  stalls at the first real hardware-completion-bit wait loop (MMIO is
  zero-modeled) — not a bug, the correct mechanical answer for an image
  nobody has done the separate, human bring-up investigation for yet.

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
- **`DYNAMICALLY_OBSERVED`/`FINITE_CANDIDATE_SET` yield is low for
  register-indirect (`BX`/`BLX reg`) sites specifically.** In this
  firmware, the vast majority of unresolved indirect calls are a
  C++/HAL-style virtual-dispatch pattern (load an object pointer from
  RAM, load a function pointer from a vtable at a fixed offset, `BLX`)
  — there is no static flash table to scan for this (the "table" is a
  RAM-resident vtable), and none of the six current scenarios perform a
  cold boot through the driver-init code that would exercise it, so
  most of these end up honestly `UNRESOLVED`. This is a real property
  of the firmware/scenario corpus, not a bug in the resolver — see
  `indirect_edge_resolutions.note` for the per-site reasoning.
- **Cross-image library/platform matching is only as strong as having
  another image in the database.** With only `autopilot868`/
  `autopilot915`/`mando868`/`mando915` available, "library/platform
  code" in practice means "code shared between the AutoPilot and
  Remote products" — real compiler/Arduino-core/CMSIS/driver code, but
  not the full set a genuine vendored reference library (none exists in
  this repo) might additionally confirm as library.
- **Component grouping's thresholds are a documented, not a uniquely
  correct, choice.** `CALL_UNION_MAX_CALLERS` (default 3) trades off
  under-grouping (a genuinely tight helper relationship above the
  threshold stays split) against over-grouping (a shared low-fan-in
  callee incorrectly implies two callers belong together) — see
  `components.py`'s module docstring for the exact rules and rationale.
- **The hardware-init snapshot is honestly partial for every current
  image.** No image in this census reaches `completed_init=True` yet
  (see `hardware_snapshot_runs.notes` for exactly where each one
  stalls) — `autopilot868`/`915` stall past "boot/init entry" for want
  of an uncommitted PA22-seed/DWT-stub recipe, `mando868`/`915` stall at
  the very first hardware-completion-bit wait loop (no disclosed
  assumptions applied at all). The register/pin state captured is real
  emulator state at that stopping point, not a claim about steady-state
  configuration.
- **`pin_snapshot`'s `pmux_nibble` is a raw register field, not a named
  peripheral function.** SAMD5x/E5x's PMUX-to-peripheral-function
  letter mapping (A-H) is fixed silicon-wide, but WHICH peripheral
  occupies which letter is a per-pin datasheet table this module does
  not have machine-readable access to — only the raw 0-15 nibble value
  is reported.
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

# Closure reduction -- run AFTER build + ingest-dynamic, for each image:
for fw in autopilot868 autopilot915 mando868 mando915; do
  tools/unicorn/.venv/bin/python3 tools/census/aptrace_census.py reduce "$fw"
done

# Regression tests:
tools/unicorn/.venv/bin/python3 tools/census/test_census.py
tools/unicorn/.venv/bin/python3 tools/census/test_reduce.py
```

`census build` is deterministic given the same firmware bytes, Ghidra
version, and script contents (the same content-hash cache-freshness
contract `tools/ghidra/aptrace_ghidra.py` already uses — see
`ANALYSIS_VERSION`/`BUILD_SCRIPTS` there); `census ingest-dynamic` is
deterministic given the same dynamic-export JSON files, which are
themselves deterministic given the same firmware and
`tools/unicorn/virtual_link.py` scenario code (Unicorn concrete
execution has no randomness in this harness). `census reduce` is
deterministic given the same base-evidence tables (i.e. rerun it after
any `build`/`ingest-dynamic`, in that order — indirect-edge resolution
feeds reachability, and reachability feeds components) and the same set
of OTHER firmware images already reduced in the same database (cross-
image library matching depends on what else is present — reducing all
four images, in any order, converges to the same final matches since
`recompute_all_matches` refreshes every already-fingerprinted image
every time).
