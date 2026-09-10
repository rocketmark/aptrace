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
  `pin_snapshot`. `hardware_snapshot_runs` additionally carries
  `init_status` (`complete`/`partial-justified`/`blocked`) and
  `assumptions_json` (the complete disclosed-assumption list for that
  run); `library_matches` additionally carries
  `reference_source_confirmed`/`reference_source_citation` (see
  "Closure reduction" below) — both added via `db.py`'s column
  migration (`ALTER TABLE ... ADD COLUMN`, applied automatically on
  connect to an older database, same as new tables).
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
- Cross-image fingerprint matches: `EXACT` / `STRONG_MATCH` /
  `POSSIBLE_MATCH` / `NO_MATCH` counts — shared/platform-code EVIDENCE
  only, never converted into "library truth" by itself (see "Closure
  reduction" below's evidence rule).
- Reference-source-confirmed count — functions matched against REAL,
  FETCHED upstream source (currently `adafruit/ArduinoCore-samd`
  v1.7.11's CONFIRMED tier) — the ONLY thing subtracted from the
  residual below.
- **The headline number**: reachable functions, minus reference-
  source-confirmed TRUE library functions, minus dynamically-exercised
  functions = the residual reachable, non-library, dynamically-
  unexercised function count (also `aptrace census residual`) — the
  actual deliverable this reduction layer exists to produce: a SMALL,
  evidence-backed set for later semantic analysis, not "hundreds of
  merely-uncovered functions." Cross-image shared-code evidence is
  reported but NOT subtracted here — inspect it separately via
  `aptrace census library-matches`.
- Component count (`aptrace census components`).
- Hardware-snapshot summary: `init_status` (`complete` /
  `partial-justified` / `blocked`), boot method (which reference
  recipe), register/peripheral counts, and configured-pin counts
  (`aptrace census hardware-snapshot`).

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
comparison, or a real (unmodified/non-invasively-instrumented) replay
of Unicorn execution — either the existing scenario corpus or a cited
boot recipe. Run order (`reduce.py`): fingerprinting → boot capture →
reference-source confirmation → indirect-edge resolution → reachability
→ feature records → components → hardware snapshot — each stage after
the first can use the previous stage's output (fingerprinting has to
come first because both boot-recipe sibling remapping and reference-
source propagation need it; reachability treats a newly-resolved
indirect target, static OR dynamic, as a real edge).

**1. Fingerprinting** (`fingerprint.py`) — see "3. Library/platform
fingerprinting vs. reference-source confirmation" below; runs first
because later stages depend on it.

**2. Boot capture** (`boot_recipes.py`) — runs this firmware's boot
recipe once (see "Boot recipes" below), capturing dynamic coverage the
same way `dynamic_export.py`'s scenario corpus does (reusing its own
JSON export/ingest format unchanged, scenario name `'boot'` — never a
parallel ingestion path) and, in the SAME execution, watching every
currently-unresolved register-indirect call site for a real observed
target (feeding stage 4). The SAME final machine/result is reused for
the hardware snapshot (stage 8) — boot only ever runs once per
`census reduce` call, never twice.

**3. Reference-source confirmation** (`reference_library.py`) — see
below; must run after fingerprinting (needs cross-image matches to
propagate through) and is safe to run before or after boot capture.

**4. Indirect-edge resolution** (`indirect_resolve.py` +
`boot_recipes.py`) — every indirect call/jump instruction (Ghidra-
resolved or not) is classified into exactly one of:

- `STATICALLY_RESOLVED` — Ghidra's own basic-block model already
  resolved it (e.g. a compiler-generated `TBB`/`TBH` jump table Ghidra
  itself recovered).
- `DYNAMICALLY_OBSERVED` — no static resolution, but a real Unicorn
  execution actually executed the instruction with a concrete register
  value, observed by a `watch` list added to every leg via a non-
  invasive `ConcreteMachine.run` monkeypatch (no scenario/recipe code
  changes) -- from TWO sources, merged: the existing six-scenario
  corpus (`indirect_resolve.dynamic_candidates`) AND the stage-2 boot
  capture (`boot_recipes.extract_indirect_hits`). Boot is often the
  BETTER source for this specific category: most of this firmware's
  unresolved indirect sites are C++/HAL-style virtual dispatch
  (SERCOM/USB/display-driver object vtables) exercised during driver
  bring-up, which none of the six mid-execution-entry scenarios ever
  reach, but a real boot does.
- `FINITE_CANDIDATE_SET` — neither of the above, but a bounded flash
  scan found a plausible candidate table: an inline `TBB`/`TBH` table
  (scanned per the ARMv7-M architecture's own offset encoding, stopping
  at the first entry that doesn't land in the flash image), or a table
  based at the nearest Ghidra-resolved literal-pool constant preceding
  a `LDR`-into-PC instruction in the same basic block.
- `UNRESOLVED` — none of the above found anything. Left exactly as
  unresolved as it was.

Register-indirect decoding (`indirect_resolve.decode_instruction`)
normalizes Capstone's ARM EABI register-alias mnemonics (`sb`/`sl`/
`fp`/`ip` for `r9`/`r10`/`r11`/`r12`) back to the canonical `rN` names
`concrete.py`'s register table uses — `mando868` has a real `bx sl`
indirect-call site that otherwise raised a `KeyError` during boot-
capture indirect-hit extraction (regression-tested in
`test_reduce.py`).

Every candidate any method found is kept in `indirect_edge_candidates`
(never deduplicated away — two methods disagreeing stays visible);
`indirect_edge_resolutions` holds the single summary classification
(strongest tier with evidence) plus the decoded instruction shape
(`reg-indirect` / `mem-indirect` / `table-branch` / `unknown`) and a
human-readable note.

**5. Reachability** (`reachability.py`) — transitive closure from
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

**Stages 1 & 3 in detail — library/platform fingerprinting vs.
reference-source confirmation** (`fingerprint.py` / `reference_library.py`)
— **IMPORTANT EVIDENCE RULE,
tightened this pass: a cross-image fingerprint match is NEVER, by
itself, converted into "library truth."** `library_matches.confidence`
(`EXACT`/`STRONG_MATCH`/`POSSIBLE_MATCH`/`NO_MATCH`) records ONLY that
this firmware's code is shared with another image already in this same
census database — real, useful evidence (see `fingerprint.py`'s own
docstring for the four tiers' exact definitions and
`fingerprint._family`'s same-product-vs-cross-product distinction,
tagged via a `-same-product` method suffix), but not proof of
"platform/library plumbing vs. application logic": application code
(motor control, protocol dispatch) is just as likely to be byte-
identical across a frequency-variant sibling, or even shared between
the two products, as a CMSIS helper is. `library_matches` is recomputed
for every already-fingerprinted image every time ANY image is
fingerprinted (`recompute_all_matches`, which now also PRESERVES any
existing `reference_source_confirmed` flag across that rebuild — see
below), so cross-image matching is eventually consistent regardless of
which firmware you `reduce` first.

The ONLY thing this reducer treats as confirmed "library truth" is a
separate boolean, `library_matches.reference_source_confirmed`
(+ `reference_source_citation`), set exclusively by
`reference_library.py` from `docs/investigations/boot-and-hardware-
bringup.md`'s own CONFIRMED tier — functions already structurally
matched, byte-for-byte, against REAL, FETCHED upstream source
(`adafruit/ArduinoCore-samd` v1.7.11): `Reset_Handler`, `Dummy_Handler`,
`SysTick_Handler`, `millis()`, `main()`, the sketch's `setup()`/
`loop()`. No new matching work happens in that module — it tags
`autopilot868`'s own already-cited functions directly, and mechanically
propagates the SAME confirmation to any OTHER image's EXACT fingerprint
match (a real, deterministic consequence of byte-identical code, not a
new judgment call). Every other tier (`EXACT`/`STRONG_MATCH`/
`POSSIBLE_MATCH`, cross-product or not) remains fully queryable
(`library-matches`) as shared-code evidence but does NOT exclude a
function from the residual count.

**6. Function feature records** (`features.py`) — one materialized
`function_features` row per function: structural counts only (callers,
callees, basic blocks, RAM/MMIO reads/writes, literal refs, strings,
pins, indirect edges, IRQ-handler flag, dynamic-run/scenario counts)
plus small JSON evidence lists (peripherals/pins/scenarios touched) and
this function's own reachability status/library confidence. No
semantic field — every count is independently re-derivable from the
base tables by direct SQL; this table only saves re-joining them for a
single-function lookup.

**7. Component grouping** (`components.py`) — deterministic connected
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

**8. Hardware-init snapshot** (`hardware_snapshot.py`) — reuses the SAME
machine/result stage 2's boot capture already produced (never a second
boot run) to dump every in-scope peripheral's raw register bytes
(`PORT`, `ADC*`, `TC*`/`TCC*`, `SERCOM*`, `EIC`, `DMAC`, `NVMCTRL`,
`USB`, `WDT`, and the clock tree `GCLK`/`OSCCTRL`/`OSC32KCTRL`/`MCLK` —
every SVD peripheral whose name starts with one of those prefixes)
resolved through the same SVD used everywhere else, plus a
mechanically-decoded per-pin table (`pin_snapshot`: direction from
`DIR`, output/input level from `OUT`/`IN`, `PINCFG` raw byte + `PMUXEN`
bit, `PMUX` raw nibble — pure register-bit arithmetic, no SVD
field-enumeration lookup attempted, see Limitations).

### Boot recipes (`boot_recipes.py`)

Two REFERENCE recipes, each keyed by the firmware image the underlying
investigation actually used, packaging EXISTING, cited evidence
mechanically — no new semantic RE work performed by this module:

- **`AUTOPILOT_RECIPE`** (reference `autopilot868`) — packages,
  VERBATIM, every disclosed assumption from `docs/investigations/
  boot-and-hardware-bringup.md`: the four clock/PLL completion bits,
  the two SERCOM SWRST/DRE pairs, the NVMCTRL DONE bit, the RAM tick
  counter (`0x200052ec`), the PA22 GPIO-input boundary condition
  (`PORT.GROUP0.IN` bit 22, resolved via the SVD — that doc named the
  bit but not the register's own address), the DWT-delay stub
  (identified THIS pass by querying `literal_refs` for `0xe0001004`/
  `0xe0001000`, DWT->CYCCNT/CTRL, landing in the tiny leaf function
  `FUN_0000cd34` the doc's own text already named as "the DWT delay"),
  the radio-ID `--force-reg` stand-in, and the NVM Software Calibration
  Row mapping. Reproduces the cited document's own milestones
  EXACTLY (instruction-for-instruction, see `test_reduce.py` and the
  worked reproduction below) and reaches real main-loop steady state
  (5 confirmed `0x8960` iterations, matching that document's own
  success criterion) — `init_status` **`complete`**.
- **`MANDO_RECIPE`** (reference `mando868`) — Reset_Handler (from the
  `vectors` table, cross-checked against an EXACT fingerprint match to
  `autopilot868`'s own Reset_Handler — both agree), the SAME clock/PLL
  completion bits (confirmed touched by `mando868`'s own clock-init
  function, itself an EXACT byte match to `autopilot868`'s
  `FUN_0000cdd8`, at the identical peripheral addresses — direct static
  evidence, not assumed), and the DWT-delay stub (EXACT match to
  `autopilot868`'s own). Two further stalls were diagnosed by watching
  the exact register state at each wait loop (never by skipping PCs or
  forcing an exit) and modeled the same documented way once the
  evidence matched: a `SERCOM2` `SWRST` self-clear and `INTFLAG.DRE`
  wait (register state at the stall showed `r3=0x41012000`, the same
  peripheral/pattern `autopilot868`'s own driver constructor uses). A
  fourth stall, a plain RAM-flag wait at `0x20003b30`, was then closed
  by modeling the REAL interrupt delivery that releases it — see
  "Interrupt delivery (`interrupt_bridges`)" below — after which the
  recipe runs on to a confirmed steady-state main loop (`FUN_00007abc`,
  10 watch hits at an exact 33-instruction period). `init_status`
  **`complete`**.

**Sibling remapping.** For `autopilot915`/`mando915` (not themselves a
reference recipe's own image), every CODE address in the family's
reference recipe is remapped via an EXACT function-fingerprint match:
`sibling_addr = sibling_function.entry + (ref_addr - ref_function.entry)`
— exact because byte-identical functions have identical internal
offsets by construction. A RAM DATA address (the tick counter) is
remapped differently — via the SIBLING's OWN `memory_accesses` target
for the EXACT-matched function, not offset arithmetic (a RAM address is
never "inside" a function's code range, and cross-build RAM layout can
differ even when the code is byte-identical — confirmed empirically:
`mando915`'s own tick counter is a DIFFERENT RAM address than
`mando868`'s, `autopilot915`'s is IDENTICAL to `autopilot868`'s).
Peripheral/MMIO addresses are reused unchanged (chip-fixed, not
firmware-specific). Any address that fails to remap (no EXACT match
found) is DROPPED from the sibling's recipe and reported as a gap —
never guessed; `boot_recipes.capture_boot` prints and the caller can
inspect every such gap.

### Interrupt delivery (`interrupt_bridges`)

The `0x20003b30` RAM-flag wait that previously blocked `mando868`/
`mando915` at `init_status='partial-justified'` was closed mechanically,
by tracing the REAL interrupt chain that releases it rather than
force-writing the flag:

- The flag's only writer (`ldr r3,[...]; movs r2,#0; strb r2,[r3]; bx
  lr`, at `0x13764`/`0x13765`) has no resolved static call/jump edge and
  no vector-table entry directly to it — but it IS reachable, as a data
  value: `FUN_00013874` (real DMAC/TC2/EVSYS driver setup on the boot
  path) registers it via a generic callback-registration helper,
  `FUN_00011fd8(object, callback, slot)`, which writes
  `*(object + (slot+2)*4) = callback` — placing this release routine at
  `object+0xC` (slot 1, "transfer complete") for a driver object at
  `0x200026f8`.
- That object pointer is itself written into a DMA channel→object
  lookup table (base `0x20003a60`, recovered from a literal pool at
  `FUN_00011d20`+0x28) at index 2 — confirmed by watching the actual
  memory write during boot replay (`instruction 67257`, `PC=0x11e2c`,
  `LR=0x11d8f`).
- IRQ vectors 47–51 (`DMAC_0`..`DMAC_OTHER`, IRQ31-35 per the SVD's own
  `<interrupt>` elements) all target one real handler, `FUN_00011d20`:
  it reads `DMAC.INTPEND` (`0x4100a020`) `& 0x1f` for the pending
  channel, looks up `channel_table[channel]`, and — if non-null — calls
  `FUN_00011cb8(object, channel)`, which reads
  `DMAC.CHANNELn.CHINTFLAG` (`0x4100a000 + ch*0x10 + 0x4e`, SVD-
  confirmed) and, for the `TCMPL` bit (bit 1), invokes the callback at
  `object+0xC` — exactly the flag-release routine.

This chain is executed for real, not stubbed, via a new, deliberately
narrow `ConcreteMachine.deliver_interrupt(handler_entry, ...)` primitive
(`tools/unicorn/concrete.py`): it runs the REAL compiled ISR body as a
nested AAPCS subroutine call on the CURRENT stack at the CURRENT
machine state, preserving `r0-r3`/`r12` around the call and relying on
the ISR's own AAPCS callee-saved discipline for `r4-r11` — no
`EXC_RETURN`, no NVIC priority/masking model, no vector-table dispatch
simulation. It is NOT a general Cortex-M exception simulator, only
enough to run one already-identified real handler and return.

A recipe opts into this by declaring an `interrupt_bridges` list (see
`MANDO_RECIPE`) — one entry per `{wait_check_addr, flag_addr,
flag_released_value, handler_addr, release_callback_addr,
callback_slot_offset, dmac_base, intpend_offset,
channel_table_literal_offset, channel_table_count,
chintflag_channel_stride, chintflag_offset, chintflag_tcmpl_bit,
max_deliveries, citation}`. `boot_recipes.run_with_interrupt_bridges`
drives it: on hitting a bridge's `wait_check_addr`, it identifies the
channel whose table entry's own callback (at `object+
callback_slot_offset`) matches `release_callback_addr` (a uniquely-
identifying match — `mando868`'s channel table has multiple
simultaneously-registered channels at this point, so "first non-null
entry" is NOT a valid heuristic and was rejected after an early run
picked the wrong channel), seeds `INTPEND`/`CHINTFLAG.TCMPL` for that
channel, calls `deliver_interrupt`, then explicitly clears
`CHINTFLAG`/`INTPEND` afterward (write-1-to-clear is the real hardware
convention used consistently elsewhere in this SVD, e.g.
`SERCOM.INTFLAG` — this MMIO model has no automatic W1C behavior of its
own, so the bridge must do it, or the flags stay permanently "pending"
and cause runaway spurious re-delivery). `max_deliveries` bounds this
per bridge so an unexpected non-terminating loop stops honestly instead
of running forever. Every real delivery is recorded (channel, table
address, instruction count, whether the handler returned cleanly) and
folded into `hardware_snapshot_runs.assumptions_json` as an
`interrupt_delivered` entry — never a hidden side effect.

One resume-correctness bug was found and fixed while building this:
`machine.run(entry=X, stop_at=[..., X, ...])` immediately re-triggers
on the very first about-to-execute instruction when resuming exactly AT
a `stop_at` address, reporting `instructions_executed=1` with ZERO real
forward progress. `run_with_interrupt_bridges` now always performs an
unconditional `max_instructions=1` step (no `stop_at`) past a bridge's
`wait_check_addr` before resuming the guarded run, both when the wait
was already released and right after a delivery.

For `mando868`, four real deliveries (all channel 2) release the flag
and the recipe proceeds all the way to a confirmed steady-state main
loop. `mando915`'s sibling-remapped recipe delivers the identical four
interrupts at the identical instruction counts, confirming a faithful
remap.

**Beyond AutoPilot's and Mando's own steady-state milestones, nothing
further is modeled.** `AUTOPILOT_RECIPE` reproduces the cited
document's FULL recipe and reaches real main-loop steady state; what
remains unmodeled there is explicitly out of scope, unchanged from that
document's own "Open items": a second, deeper NVM-erase-loop dependency
that does not visibly advance over millions of instructions, and the TX
path's still-unnamed real transport peripheral (gated behind a runtime
driver-object pointer). `MANDO_RECIPE` now also reaches real steady
state; no further blocker is currently open for either family.

**A real Unicorn correctness bug was found and fixed along the way**:
`ConcreteMachine.run(..., log_ram=True)` corrupted later emulation on a
long (~400K-instruction), RAM/stack-heavy run — a cross-hook
reentrancy hazard (`hook_code`'s own direct `--fake-tick`/`--force-mem`
writes landing inside the `log_ram` hook's range triggered Unicorn's
hook dispatch reentrantly). Fixed for that specific mechanism (the
hooked range now excludes any such address, `concrete.py`'s
`_ranges_excluding`) and regression-tested
(`tools/unicorn/test_concrete.py`); NOT fully root-caused beyond that
narrow case for an arbitrarily long/RAM-heavy run, so `boot_recipes.py`
defaults `log_ram=False` for its own (long) capture — `log_mmio` and
`collect_coverage` were both verified safe and remain default-on. See
`concrete.py`'s `run()` docstring and `boot_recipes.py`'s
`apply_recipe` docstring.

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
- **`DYNAMICALLY_OBSERVED`/`FINITE_CANDIDATE_SET` yield for register-
  indirect (`BX`/`BLX reg`) sites still leaves most `UNRESOLVED`.**
  Most unresolved indirect calls are a C++/HAL-style virtual-dispatch
  pattern (load an object pointer from RAM, load a function pointer
  from a vtable at a fixed offset, `BLX`) — there is no static flash
  table to scan for this (the "table" is a RAM-resident vtable), and
  the six scenario-corpus legs never perform a cold boot through
  driver-init code. Adding the boot-recipe replay (see "Closure
  reduction" above) closed a real share of this gap by actually
  executing driver bring-up for the first time — `autopilot868` went
  from 0 to 29 `DYNAMICALLY_OBSERVED` indirect sites, `mando868` from 0
  to 6 (smaller because `mando868`'s own boot recipe stops earlier, at
  its own documented blocker) — but most register-indirect sites still
  end up honestly `UNRESOLVED`: many are on driver code paths beyond
  even the boot recipe's own reach (e.g. `autopilot868`'s radio-probe
  retry loop, gated behind the disclosed radio-ID stand-in) or are
  genuinely runtime-object-dependent in a way no bounded run can
  exhaustively enumerate. See `indirect_edge_resolutions.note` for the
  per-site reasoning.
- **Cross-image library/platform matching is only as strong as having
  another image in the database, and is deliberately NOT treated as
  "library truth" on its own** (see the evidence rule in "Closure
  reduction" above). With only `autopilot868`/`autopilot915`/
  `mando868`/`mando915` available, a cross-image match in practice
  means "code shared between the AutoPilot and Remote products" —
  real evidence, but the only functions this reducer actually excludes
  from the residual as confirmed library code are the small, curated
  `reference_source_confirmed` set (currently 7 for the AutoPilot
  family, 3 for Mando — see `reference_library.py`), matched against
  real, fetched `ArduinoCore-samd` source. A genuine vendored reference
  library (none exists in this repo) could grow that set; a plain
  cross-image match, however strong, should not be read as more than
  "shared code" evidence.
- **Component grouping's thresholds are a documented, not a uniquely
  correct, choice.** `CALL_UNION_MAX_CALLERS` (default 3) trades off
  under-grouping (a genuinely tight helper relationship above the
  threshold stays split) against over-grouping (a shared low-fan-in
  callee incorrectly implies two callers belong together) — see
  `components.py`'s module docstring for the exact rules and rationale.
- **The hardware-init snapshot is `complete` for all four known
  images.** `autopilot868`/`915` and `mando868`/`915` all now reach
  real main-loop steady state (`init_status='complete'`) and their
  snapshots reflect genuinely post-init MCU state, including the DMAC
  channel-2 registers as left by a REAL interrupt handler execution
  (see "Interrupt delivery (`interrupt_bridges`)" above) for the Mando
  pair. See `hardware_snapshot_runs.assumptions_json` for the complete,
  per-run disclosed-assumption list, including every real interrupt
  delivered during that run.
- **Sibling remap for a code address just past its reference function's
  own declared size falls back to a bounded, best-effort offset match.**
  `_remap_code_addr` normally requires the reference address to fall
  STRICTLY inside a matched function's own declared size; a handful of
  real addresses used by `MANDO_RECIPE` (e.g. `0x13765`, the interrupt
  bridge's release-callback address) land a small number of bytes past
  their containing function's own end — inside a Ghidra-unattributed
  ("exec-bytes-unowned") code gap, not a different function. Within a
  bounded window (`NEARBY_GAP_WINDOW`, 0x400 bytes past the reference
  function's declared end) the remap still proceeds via that function's
  own EXACT-match offset and is flagged in the reported gaps as
  best-effort, not guaranteed-exact; an address further away than that
  is still rejected and dropped, never guessed.
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
