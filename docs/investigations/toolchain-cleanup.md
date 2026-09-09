# Toolchain cleanup: turning recurring RE mechanics into stable APTrace operations

**This slice is not about new firmware behavior.** Every prior M6 slice
kept re-paying the same set of mechanical costs — re-importing/
re-analyzing the same firmware in Ghidra for one query, running a
concrete scenario twice just to dereference a pointer, hand-computing a
stack frame to call a function directly, discarding a failed Unicorn
run's own useful state, re-deriving a register-value bug from a full
`--trace --trace-every 1` rerun, manually round-tripping hex between
runs. None of that is firmware evidence; all of it is harness friction
this project's own investigation docs kept documenting *as if it were a
finding* (see `plus-target-distance-roundtrip.md`'s own "concrete
techniques this slice needed" section, which is really a list of tooling
papercuts). This slice fixes the mechanics without touching any
firmware-behavior conclusion.

## What changed, and why

### 1-2. A persistent Ghidra project cache and query interface

**Before**: every decompile/disassemble/callers/xrefs question ran
`analyzeHeadless -import ... -deleteProject` — a full re-import and
~10-15s auto-analysis pass, thrown away afterward, for one address.

**After**: `tools/ghidra/aptrace_ghidra.py`.

```sh
tools/ghidra/aptrace_ghidra.py build autopilot868      # once: import, seed, analyze,
                                                         # apply provenance labels, export,
                                                         # persist the project (~10-15s)
tools/ghidra/aptrace_ghidra.py decompile autopilot868 0x6fd8   # reopened, -noanalysis (~3s)
tools/ghidra/aptrace_ghidra.py callers   autopilot868 0x8258   # from the cached export (~instant)
tools/ghidra/aptrace_ghidra.py containing autopilot868 0x8186  # from the cached export, flags
                                                                 # the tail-jump case this
                                                                 # project has hit repeatedly
tools/ghidra/aptrace_ghidra.py literal   autopilot868 0x8528   # raw firmware read, no Ghidra
tools/ghidra/aptrace_ghidra.py status                          # cache freshness, all firmwares
```

`decompile`/`disasm` genuinely need Ghidra's own decompiler/disassembly
listing, so they reopen the persisted project (`-process -noanalysis
-readOnly`) rather than re-importing — auto-analysis, the expensive
part, never reruns. `callers`/`xrefs`/`containing`/`symbol` are answered
entirely from `static_export.json` (the full function/call-graph/
data-reference/string export `build` produces once, *after* applying
provenance labels so renamed symbols are what these queries see) — no
Ghidra invocation at all. `literal`/`dump` read the raw `.bin` directly
and never touch Ghidra.

**Cache identity**: `research/runs/ghidra_cache/<key>/meta.json` records
the firmware's SHA-256, load base, processor/language, installed Ghidra
version, and this module's own `ANALYSIS_VERSION`. Any mismatch is
reported `stale` and refused — `build`/a query both say so and ask for
`rebuild`, never silently reusing a wrong cache. Regression-tested in
`tools/ghidra/test_aptrace_ghidra.py`, including a deliberately tampered
`meta.json`. The cache directory is gitignored and fully regenerable.

`tools/ghidra/analyze_firmware.sh` (the old one-shot path) still exists,
for a genuinely throwaway query against a firmware not worth persisting.

### 3-4, 6-9. `concrete.py`: a reusable Unicorn library

**Before**: `run_concrete.py` was a single `main()` function; every
caller (including `virtual_link.py`) spawned it as a subprocess, once
per concrete run, parsing its own hex-strings-only CLI arguments and its
JSON output back into Python.

**After**: `tools/unicorn/concrete.py` holds a `ConcreteMachine` class —
the actual Unicorn setup/hook/snapshot logic, now a reusable Python
object. `run_concrete.py` is a thin CLI wrapper over it (unchanged flag
set, plus the additions below); `virtual_link.py` imports `concrete.py`
directly, building one machine per firmware image and reusing it across
every leg of every scenario.

Concretely, this fixed or added:

- **Reused mapped memory (priority 7)**: `ConcreteMachine.__init__` loads
  the firmware and builds the flash/RAM/MMIO map once; `run()`/`call()`
  default to `fresh=True` (reset RAM+registers before every call — the
  same isolation a fresh subprocess gave for free) but skip rebuilding
  the map and re-reading the firmware file. Measured effect: all four
  `virtual_link.py` scenarios together (`ampersand`, `g`, `s`, `plus` —
  16 concrete legs total) run in **~0.1s**, down from several seconds of
  subprocess-spawn-per-leg overhead. `reset(mmio=True)` is available
  when a scenario genuinely needs MMIO state not to leak between runs;
  the default leaves it alone, "explicit, not assumed," per the same
  discipline this project already applies to every MMIO-modeling flag.
- **Single-run TX capture (priority 3)**: `dump_reg_pointee` reads a
  register's value and dereferences it in the *same* run that reaches
  the stop point. `capture_tx_bytes` in `virtual_link.py` used to run
  twice (once to learn R0, once to dump `*R0`); it now runs once. The
  pointer is still always whatever the real firmware computed — this
  removes a redundant execution, not the evidence property.
- **A proper direct-function-call helper (priority 4)**:
  `ConcreteMachine.call(entry, args=[...])` handles r0-r3, stack
  arguments beyond r3 (placed at the exact AAPCS offsets a real caller's
  own `str` sequence would use), an 8-byte-aligned stack allocation
  carved out of a reserved region below RAM's top (so a callee's own
  stack usage can't collide with anything), Thumb entry, and — the part
  that used to mean "invent an LR and accept a crash" — a real,
  decodable trampoline instruction (`b .`, Thumb encoding `0xE7FE`) as
  the return address, installed once in a small reserved page. A clean
  return is now a *fact* (`CallResult.returned`), not an inference from
  where a crash happened to land. Regression-tested against a known,
  previously-hand-called Remote function
  (`FUN_000049c4`, 5 AAPCS arguments, the 5th on the stack) in
  `tools/unicorn/test_concrete.py`, including confirming a second call
  on the same machine doesn't leak the first call's state.
- **Structured failure snapshots (priority 5)**: `run()`/`call()` never
  raise on a Unicorn error or unexpected stop unless a caller opts in
  (`raise_on_error=True`); the full `RunResult` (`stop_reason`, `error`,
  `registers`, `recent_pcs`, any requested dumps, watch/mmio/stub/
  mem-write logs) is populated identically whether the run succeeded or
  not. `ConcreteExecutionError` (raised only when asked) still carries
  the complete result via `.result`.
- **Numeric CLI semantics (priority 6)**: `--reg`/`--arg`/length-and-count
  fields now use `int(value, 0)` (`28` decimal, `0x28` hex) instead of
  always-hex. This is the direct fix for the exact bug that produced a
  real false investigative path in `plus-target-distance-roundtrip.md`
  (`--reg r0=28` meaning decimal 28, silently read as hex 40, corrupting
  a real dedup guard). `--force-reg`'s value and `--mmio-force-bits`/
  `--mmio-clear-bits`'s mask stay hex-only (a bitmask is conventionally
  always hex; there's no ambiguity to fix there). Address-shaped values
  are unchanged (always hex, matching every address already written in
  this project's docs). Migration note: a *bare* hex digit string
  without `0x` for a register value (never used by this project's own
  scripts, which always emit an explicit `0x` prefix for Python-int
  register values) now parses as decimal and will raise if it isn't
  valid decimal — add `0x`. Regression-tested end-to-end through the
  actual CLI (not just the parsing function) in `test_concrete.py`.
- **Explicit state carry-forward (priority 8)**: `RunResult.carry(addr,
  length, label=...)` packages bytes a run's own `dump_mem` actually
  captured, tagged `carried:<label>` in the next run's `applied_seeds`
  log — visibly distinct from a disclosed harness seed. The `'+'` -> `G`
  scenario in `virtual_link.py` uses this for both of its cross-leg
  transfers (the channel-0 config struct `'+'` writes, and the resolved-
  target staging value one `FUN_00007e2c` call produces for the next),
  replacing manual `bytes.fromhex(snap["memory"][...])` round-tripping.
- **Bounded failure tracing (priority 9)**: `recent_pcs` (default last 64
  PCs, `--trace-last N`) is populated on every run, success or failure,
  cheaply enough to leave on always — `--trace --trace-every 1` (which
  prints every single instruction) stays available for the rare case
  that genuinely needs it, no longer the only way to see what a run was
  doing right before it died.

### 10. Small binary-analysis helpers

`aptrace_ghidra.py literal`/`dump` (little-endian N-byte reads, raw hex
dumps, flash-address-to-file-offset conversion) and `containing` (which
function's range contains an address, from the cached export) replace
the recurring one-off Python snippets prior slices wrote for exactly
these questions — kept intentionally small, no new module beyond what
`aptrace_ghidra.py` already needed.

## What did NOT change

No firmware-behavior conclusion from any prior M6 slice is revisited or
altered by this one. The one genuine harness bug this cleanup both
*caused the discovery of* and *fixed* — the `--reg` hex/decimal
ambiguity — was already found and worked around correctly within
`plus-target-distance-roundtrip.md` itself (by using an explicit `0x`
prefix); this slice's numeric-semantics fix makes that workaround
unnecessary going forward, it does not change what that slice concluded
about `'+'`/`G`/`FUN_00006fd8`.

## Acceptance

All demonstrated as part of this slice, and re-runnable at any time:

```sh
tools/doctor.sh                                          # environment health, unchanged
tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py all   # all 4 scenarios, ~0.1s
tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py plus  # the '+' -> distance=500 chain, byte-identical result
tools/unicorn/.venv/bin/python3 tools/unicorn/test_concrete.py      # concrete.py/run_concrete.py regressions
python3 tools/ghidra/test_aptrace_ghidra.py                          # aptrace_ghidra.py regressions
```

## Hardening pass

The cleanup above reused a single `ConcreteMachine`/persistent Ghidra
project across many calls for speed — reuse the old fresh-subprocess/
fresh-import model never had to justify. A follow-up hardening pass
checked that reuse against the exact guarantee it replaced (a fresh
process/fresh Ghidra import per call) and fixed two real isolation gaps
plus two smaller ambiguities, all in `concrete.py`/`aptrace_ghidra.py`;
no firmware-behavior conclusion from this slice or any prior one changed.

**1. `fresh=True` now restores every mapped mutable region, not just
RAM/registers.** The initial cleanup's `run()`/`call()` reset RAM and
registers before each call but left flash, the MMIO window, and the PPB
(SysTick/NVIC/SCB/MPU) however a prior call on the same reused machine
had left them — not equivalent to the old subprocess model, which got a
genuinely fresh address space every time. Fixed with page-granularity
dirty-page tracking rather than a blind re-zero (which would be
prohibitively slow against a multi-megabyte MMIO window): a single
`UC_HOOK_MEM_WRITE` hook records every 4KB page any CPU-executed store
touches, and `reset()` restores only those pages from a pristine
snapshot taken once at construction. One non-obvious follow-up gap:
**`UC_HOOK_MEM_WRITE` never fires for this class's own direct
`uc.mem_write()` calls** — only for the CPU's own instruction-driven
stores during `emu_start()`. Every harness-side injection this class
does directly (`seed_mem`, `--fake-tick`, `--force-mem`,
`--mmio-force-bits`/`--mmio-clear-bits`) bypasses the hook entirely and
had to be marked dirty explicitly at each call site — found by testing
dirty-tracking with an actual `seed_mem`-bearing `run()` rather than
trusting the mechanism from a synthetic `uc.mem_write()` probe alone.
Regression-tested in `test_concrete.py`
(`test_fresh_isolation_across_mutable_state`): a single run mutates RAM,
flash, MMIO, and PPB via every one of those injection paths, and a
subsequent `fresh=True` run observes the same bytes a brand-new
`ConcreteMachine` would; `fresh=False` is confirmed to still carry state
forward intentionally.

**2. Ordinary `run()` now starts from the real device SP again; `call()`'s
return trampoline moved outside real RAM.** The cleanup's `call()` helper
carved its return trampoline out of the *top of real, mapped RAM*, which
had two side effects nothing had caught: an ordinary `run()`'s default SP
was no longer the real SAMD51 RAM top (`0x20030000`), and real device RAM
permanently carried harness-only trampoline bytes no real boot would ever
produce. Fixed by moving the trampoline to a dedicated harness-only page
(`HARNESS_BASE = 0x2FFF0000`) entirely outside any real SAM D5x/E5x
variant's RAM footprint, restoring `run()`'s default SP to the real RAM
top. The first placement tried for this page was `0xFFFF0000` (the
ARMv7-M "vendor-specific"/reserved region) — that failed outright:
Device-type memory is implicitly Execute-Never under the architecture,
and Unicorn's Cortex-M4 model enforces it, faulting every `call()` with
`UC_ERR_EXCEPTION` the instant execution reached the trampoline (not a
decode error — a modeled CPU exception). `0x2FFF0000` sits inside the
architected "SRAM" memory-type region (Normal/executable by the default
Cortex-M memory map) but still far past real silicon, which is what
makes it usable. Regression-tested in `test_concrete.py`
(`test_real_default_sp_and_no_trampoline_in_ram`).

**3. Ghidra cache identity now hashes the actual build-time scripts and
provenance TSV, not just a manually-bumped version constant.** The
cleanup's cache identity already caught firmware/Ghidra-version drift but
relied on a human remembering to bump `ANALYSIS_VERSION` for an ordinary
edit to `APTraceSeedVectorTable.java`, `APTraceApplyProvenance.java`,
`APTraceExportStaticAnalysis.java`, or a firmware's own provenance-labels
TSV — exactly the kind of manual discipline this project's own "don't
rely on a human remembering" principle (already applied to firmware
evidence) had not yet been applied to the tooling itself. Fixed by
hashing each of those four inputs directly into `meta.json`'s recorded
identity, so any edit invalidates the cache automatically.
`ANALYSIS_VERSION` remains as an explicit manual override for a semantic
change the content hashes can't see (e.g. a change to how Ghidra itself
is invoked). Regression-tested in `test_aptrace_ghidra.py`: a modified
build script and a modified provenance TSV are both independently
confirmed to flip a fresh cache to `stale`, without ever touching the
real, committed script/TSV files (both tests monkeypatch `SCRIPTS_DIR`/
`FIRMWARE_REGISTRY` to point at a temporary modified copy instead).

**4. `RunResult.success` was ambiguous; replaced by `error_free` and
`completed`.** A single `success` property meant "no Unicorn exception,"
which made an instruction-limit result (ran out of budget, reached
nothing in particular) look indistinguishable from a properly reached
stop. Split into two explicit properties: `error_free` (no Unicorn
exception — says nothing about *why* execution stopped) and `completed`
(the run's actual execution objective was reached — every requested
`stop_at`, or, if none was requested, simply not having exhausted the
instruction budget). Regression-tested in `test_concrete.py`
(`test_error_free_vs_completed_semantics`) across all four combinations:
an expected stop reached, an instruction limit hit with no exception, a
genuine Unicorn error, and a clean `call()` return.

**5. `virtual_link.py`'s failure paths now carry the full structured
snapshot, not just a message string.** `_expect_stop`'s bare `RuntimeError`
and three `call()`-based "did not return cleanly" raises all discarded
the `RunResult`/snapshot they had in hand at the point of failure. Fixed
with a small `UnexpectedStopError(RuntimeError)` carrying `.snapshot` (the
full `to_dict()` snapshot, or the real `RunResult` for a `call()`-based
leg) — the same information a caller could already read from a
successful run (`stop_reason`, `error`, `registers`, `recent_pcs`,
requested memory, watch/mmio/stub hits) stays inspectable on a failed one
too, without rerunning the scenario by hand. No scenario function itself
needed rewriting — this is purely in the shared failure path.

**6. Reused-machine scenario order is now regression-tested.** The
cleanup's biggest behavioral change — one `ConcreteMachine`/one
`virtual_link._machines` cache reused across every leg of every scenario,
in one process — is exactly the class of change a subprocess-per-call
model could never have gotten wrong, and so had never needed a test for.
`test_concrete.py`'s `test_virtual_link_scenario_order_independence` runs
all four scenarios (`plus`, `g`, `s`, `ampersand`) in two different
orders, in the same process, against the same reused machine cache, and
confirms every one still produces its own already-known-good result
regardless of what ran before it. Building this test surfaced one minor
test-writing bug of its own (not a harness bug): `run_s_roundtrip()`
deliberately returns a descriptive `dict`, not `True` — an earlier draft
of the order-independence test used `ok is True`, which failed for the
's' scenario in every order tried, and looked at first like a real
leakage regression before the return-type mismatch was found. Comparing
truthiness instead resolved it once the actual cause was identified.

## New workflow

```
researcher asks a firmware question
  -> aptrace_ghidra.py build (once) / query (every time after, cheap)
  -> ConcreteMachine.run() or .call() (proper ABI/state capture, one execution)
  -> a RunResult/CallResult, inspectable whether it succeeded or not
  -> RunResult.carry(...) if a later leg needs this run's real output
  -> next question
```

replacing:

```
re-import + re-analyze in Ghidra for one query
  -> hand-construct a raw analyzeHeadless command
  -> write scratch Python to compute SP/LR/stack-arg offsets
  -> crash on an invented return address, infer success from where it died
  -> rerun with --trace --trace-every 1 to see the last few PCs
  -> manually bytes.fromhex() a JSON memory dump into the next run's --seed-mem
  -> repeat
```
