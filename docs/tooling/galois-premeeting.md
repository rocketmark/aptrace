# Pre-Galois-Meeting Tooling Notes

A tooling-only detour (2026-09-08), not a new APTrace slice: two clean,
deterministic repros to show Galois, a first (experimental) integration of
`crucible-debug`/`crucible-macaw-debug`, an optional GREASE experiment
against our raw Cortex-M firmware, a small MMIO-diagnostics addition, and
the questions this raised. Nothing here changes APTrace's conclusions or
its tool hierarchy — see "What did *not* change" at the end.

## Environment

| Component | Version / commit | Source |
|---|---|---|
| Ghidra | via `brew install ghidra` | `tools/ghidra/analyze_firmware.sh` |
| Unicorn | 2.1.4 (pinned venv) | `tools/unicorn/run_concrete.py` |
| GHC / cabal | 9.6.7 / 3.16.1.0 | `docs/toolchain.md` |
| Z3 | 4.15.3 | `brew install z3` |
| macaw (`external/macaw`) | `593a918d` (2026-07-21) | this repo's pinned checkout |
| crucible (macaw's submodule) | `a9831089` (2026-05-15) | `external/macaw/deps/crucible` |
| what4 | `4ce24dc4` (2026-05-20) | `external/macaw/deps/what4` |
| dismantle | `4711a9e1` (2026-05-05) | `external/macaw/deps/dismantle` |
| semmc | `75c6d376` (2026-05-06) | `external/macaw/deps/semmc` |
| `crucible-debug` | 0.1.2.0.99 | `external/macaw/deps/crucible/crucible-debug` (already vendored, unused until now) |
| `crucible-macaw-debug` | 0.1.0 | `external/macaw/crucible-macaw-debug` (already vendored, unused until now) |
| GREASE | commit `5bfc4791` on `main`, cloned fresh to `/tmp/grease-eval/grease` (not vendored in this repo) | https://github.com/GaloisInc/grease |

**Note on `crucible-debug`/`crucible-macaw-debug`**: both were *already
present* in our pinned `external/macaw` checkout (as git submodules of
`crucible`, and as a sibling package of `macaw` respectively) before this
pass — nothing new was pulled down for the debugger experiment. GREASE, by
contrast, is not part of our tree at all; it vendors its *own* pinned
copies of macaw/crucible/what4/semmc/dismantle under its own `deps/`
(interestingly, its pinned `dismantle` commit is identical to ours —
`4711a9e1` — suggesting close lineage, but GREASE does not reuse our
checkout directly). It was cloned to a scratch directory for this
one-off experiment, not added to this repo.

## Repro 1: Macaw's A32-on-Cortex-M mode selection follows the entry address's low bit, not the target

**Background**: `docs/investigations/trigger-input.md` already documented
that Macaw lifts flash `0x801c` as ARM (A32) mode code
(`BL_i_A1`/`BX_A1`, `PSTATE_T => 0`) — architecturally impossible on this
Thumb-only Cortex-M4F — while Ghidra's Thumb-only `ARM:LE:32:Cortex`
language decodes the identical bytes as ordinary, real, 8-times-called
Thumb code. That investigation left open *why* Macaw chose A32 mode for
this address.

**New, sharper repro this pass**: re-running `aptrace explore` at the
*same bytes* with only the entry address's low (Thumb) bit changed
reproduces both outcomes on demand, isolating the trigger to that one bit:

```sh
EXE=external/macaw/dist-newstyle/build/*/ghc-9.6.7/aptrace-0.1.0.0/x/aptrace/build/aptrace/aptrace
$EXE explore research/firmware/originals/firmware_autopilot868.bin 0x4000 0x801c   # low bit clear
$EXE explore research/firmware/originals/firmware_autopilot868.bin 0x4000 0x801d   # low bit set
```

`0x801c` (even, Thumb bit clear):

```
# 0x801c 0x801c: BL_i_A1(xxxxxxxx.xxxxxxxx.xxxxxxxx.xxxx1011) cond 4, imm24 898312
  ...
  { PSTATE_T = 0x0 :: [1], ... }
  call_if r14 pc=0x375444 :: [32] lr=0x8020, return to 0x8020
0x8020:
  # 0x8020 0x8020: BX_A1(0001xxxx.IIIIIIII.0010IIII.xxxx0001) Rm 11, cond 11, ...
```

`0x801d` (odd, Thumb bit set) — the exact same underlying bytes:

```
# 0x801d 0x801c: PUSH_T1(xxxxxxxx.1011010x) M 1, register_list 8
# 0x801f 0x801e: LDR_l_T1(xxxxxxxx.01001xxx) Rt 3, imm8 13
# 0x8021 0x8020: LDRB_i_T1(xxxxxxxx.01111xxx) Rn 3, Rt 3, imm5 0
# 0x8023 0x8022: CBZ_T1(xxxxxxxx.101100x1) Rn 3, i 0, imm5 4, op 0
  classify failure   -- (an ordinary, separate limitation: an unresolved indirect branch target, not an A32/mode issue)
```

The odd-address decode matches Ghidra's independent Thumb-only decode
exactly (`push {r3,lr}` / `ldr r3,[...]` / `ldrb r3,[r3,#0]` / `cbz`).
**This means the A32 lift is not a property of the bytes at `0x801c` in
isolation — it's a direct consequence of Macaw treating the *caller-
supplied* entry/call-target address's LSB as the mode selector, exactly
per real ARM `BX`/`BLX` semantics, and *something upstream of this call
site computed or propagated that target without the Thumb bit set*.**
This project's own `CLAUDE.md`/`unicorn-backend.md` already independently
learned this exact convention the hard way for Unicorn (`docs/tooling/
unicorn-backend.md`: "the Thumb bit belongs on the address, not just the
mode flag") — this repro shows Macaw's AArch32 backend follows the
identical rule, and on a target that is *architecturally Thumb-only*, an
A32 result is *never* a legitimate answer, only ever a sign the address
handed to discovery lost its low bit somewhere.

**Not changed**: no Macaw/dismantle fix attempted, per the task. The
open question ("what upstream computation produced this call target
without the Thumb bit") remains open; see "Questions for Galois" below.

## Repro 2: readonly-flash values are assumption-backed, not folded, during plain Crucible execution

**Background**: `docs/investigations/whole-function-trace-divergence.md`
already fully explained this (root cause: `Data.Macaw.Symbolic.Memory.
populateSegmentChunk` always populates `readonly` memory via solver
assumptions, never folded literals, so a branch condition built from a
literal-pool read never becomes a concrete `Pred` during *plain* Crucible
stepping — Crucible picks a side, not necessarily the real one). This
pass re-ran the existing repro fresh (not just re-quoting the historical
doc) to confirm it still reproduces identically today, and to capture one
clean before/after table.

```sh
EXE=external/macaw/dist-newstyle/build/*/ghc-9.6.7/aptrace-0.1.0.0/x/aptrace/build/aptrace/aptrace
$EXE protocol research/firmware/originals/firmware_autopilot868.bin
```

| Question | Real firmware value | Unicorn (concrete) | Plain Crucible execution (whole-function) | Solver-aware Crucible (isolated block) |
|---|---|---|---|---|
| `buffer[0]` for a real `&` packet | `0x26` | Confirms `0x8266`'s branch takes the **skip-the-loop** path (`0x82c6`) in 3 instructions ([`docs/tooling/unicorn-backend.md`](unicorn-backend.md)) | Takes the **wrong** side (`0x8268`, enter-the-loop) at the very first hit of this branch — confirmed live this pass at rich-trace hit #6, `r3` printed as an unresolved `let`-expression built from `select cglobalMemoryBytes ... 0x8528/0x8529/0x852a/0x852b`, never a literal `0x26` | `checkBranchModel` (Test G1/G2, seeding `buffer[0]=0x26` and `SP`=top of RAM directly): `0x82c6` **SAT** (`R3=0x26`), `0x8268` **UNSAT** — the correct answer |
| Consequence | — | Dispatcher reaches the real `&` handler, `pending[5]=1`, in 46 instructions | Never reaches the handler: cycles `0x827e`-`0x82c4` for the full 300000-step cap, `R6` climbing linearly (`5699 -> 5799 -> ... -> 7599`, confirmed this pass), then aborts | (isolated-block query has no such loop — it terminates immediately either way) |

This is a genuinely clean repro for a Galois conversation: **the same
concrete input, run three ways, gives three different-looking outcomes,
and the difference is entirely explained by whether a solver is in the
loop when a readonly-memory-derived value needs to become concrete** —
not a bug in Macaw's decode (repro 1) or in `mkFunCFG`'s CFG wiring (both
independently exonerated in
[`docs/investigations/gate-block-crucible-isolation.md`](../investigations/gate-block-crucible-isolation.md)).

**Not changed**: no memory-model redesign attempted, per the task and
per this project's own already-recorded decision
(`docs/project-status.md`'s "Tooling gaps": the narrow fix, if ever
needed, is baking the *specific* literal-pool words a target reads as
concrete values — the same pattern already proven for the packet buffer
via `bqMemoryBytes`).

## `crucible-debug` + `crucible-macaw-debug`: a small, working prototype

**New**: `APTrace.DebugHarness.runDebug` (`src/APTrace/DebugHarness.hs`),
wired up as `aptrace debug FIRMWARE.bin ENTRY_ADDR_HEX`. Compiles and runs
against our exact pinned macaw/crucible checkout with **no version
conflicts** — `crucible-syntax`, `crucible-debug`, and `crucible-macaw-debug`
all built cleanly on the first real attempt (after the one expected
missing-dependency fix, see below).

**Why a new, separate module instead of extending `ProtocolHarness`/
`SymbolicRunner`**: `Dbg.debugger` (the debugger's `ExecutionFeature`)
requires the simulator's personality type `p` to satisfy `Dbg.HasContext p
cExt sym ext t` — a lens onto a `Lang.Crucible.Debug.Context` value
(breakpoints, I/O streams, instruction-trace history). APTrace's existing
harnesses fix `p ~ Data.Macaw.Symbolic.MacawSimulatorState` (a package-
provided placeholder macaw-symbolic doesn't actually use for anything —
confirmed by reading its own source comment: "the default memory model
doesn't require anything extra from the simulator... a distinct type for
forward-compatibility"). Retrofitting `HasContext` onto that would mean
threading a new personality type through both existing harness modules.
GREASE's own reference integration (`grease-exe/src/Grease/Main.hs`) does
exactly this with a large custom `GreaseSimulatorState` wrapper type — real
precedent that this is the standard way to do it *and* that it's non-trivial
enough to warrant its own type. This prototype takes the smaller-footprint
option instead: `crucible-debug` also ships the trivial base case
`instance HasContext (Context cExt sym ext t) cExt sym ext t where context
= id` — so a simulation whose personality *is* a bare `Context` value
satisfies `HasContext` for free, no wrapper needed. That's sufficient for
a standalone prototype block-CFG run; it would not be sufficient if
APTrace later wants the debugger attached to the *same* run as the
existing whole-function harness's other features (`debugFeature`,
`richTraceFeature`) — those would need to move onto a shared, real
personality type at that point (a real, if modest, restructuring —
deliberately not done here).

**What it does**: attaches `Dbg.debugger` to the already-proven AutoPilot
`&`-check block (`0x888c`, `r3=0x26`, level-2 concretely and level-3
solver-confirmed elsewhere in this project), feeds it a small canned
command script via `Dbg.prepend` (so the run is a deterministic,
reproducible transcript, not a live terminal session), and prints
`crucible-macaw-debug`'s output.

```sh
EXE=external/macaw/dist-newstyle/build/*/ghc-9.6.7/aptrace-0.1.0.0/x/aptrace/build/aptrace/aptrace
$EXE debug research/firmware/originals/firmware_autopilot868.bin 0x888c < /dev/null
```

```
Couldn't find register struct
Ok
Ok

Ok

[aptrace debug] simulation aborted
```

(canned script: `mregister r3`, `step`, `step`, `mregister r3 _pc`,
`continue`, `quit`)

**Findings**:

1. **It builds and runs, cleanly, against our real pinned stack** — the
   headline positive result. `mregister`/`mtrace`/`mmemory`/`mglobals`
   (all of `crucible-macaw-debug`'s macaw-specific commands) are built on
   `Data.Macaw.Symbolic.Regs.execStateRegs` — the *same* API this
   project's own `richTraceFeature` already uses independently
   (`docs/investigations/whole-function-trace-divergence.md`) — real
   architectural alignment, not a coincidence.
2. **`mregister r3` failed with "Couldn't find register struct" at the
   very start of execution.** `crucible-macaw-debug`'s own README already
   flags this exact class of issue: "The values printed may be slightly
   out of date. See https://github.com/GaloisInc/macaw/issues/460 for a
   discussion." This pass didn't investigate further — a known upstream
   gap, not something to chase down here.
3. **`step` worked** (both steps acknowledged).
4. **Non-interactive/scripted use has a real rough edge**: running with
   `stdin` from `/dev/null` and *no* explicit trailing `quit` in the
   canned script does not exit gracefully on EOF — it loops printing "No
   command given" indefinitely (observed directly; killed after it had
   already written >400MB to a log file in well under a minute). Adding
   an explicit `quit` as the script's last command avoids this
   entirely and is what the transcript above uses. Worth asking Galois
   whether EOF-on-stdin is meant to end a session automatically for
   scripted/CI use, since right now the caller must know to always end
   their canned script with `quit`.
5. **The final `continue` after fully single-stepping this (tiny, 3-4
   real instruction) block reported "simulation aborted" rather than
   "finished."** Not investigated further this pass — flagged as a
   question rather than a conclusion (see below).
6. **Not attempted this pass**: wiring `Data.Macaw.Symbolic.Syntax.
   machineCodeParserHooks`/`Data.Macaw.AArch32.Symbolic.Syntax.
   aarch32ParserHooks` in place of the vacuous `ParserHooks empty empty`
   used here, which would let the REPL's `load`/`call` commands parse
   real macaw-syntax `.cbl` snippets interactively. Not needed to
   demonstrate the integration; a real prototype extension if wanted.

## GREASE: an optional experiment against raw Cortex-M firmware

GREASE (commit `5bfc4791`, `main`, cloned fresh — not vendored in this
repo) is "a command-line tool, Ghidra plug-in, and Haskell library that
checks properties about binaries using under-constrained symbolic
execution" (its own README). It has a dedicated `grease-aarch32` package
and an explicit raw-binary mode:

```sh
grease --solver z3 --raw-binary --load-base 0x4000 --address ADDR -- FIRMWARE.armv7l.elf
```

(`--raw-binary` requires a filename GREASE recognizes; a plain copy
renamed to `*.armv7l.elf` was used — no content changes, no ELF headers
added. Its own docs: "There are no symbols in a raw binary, so address
entrypoints are the only valid entrypoints.")

**GREASE's AArch32 backend is built for Linux userspace ARM, not
bare-metal Cortex-M** — confirmed by reading `grease-aarch32`'s own
source (`Grease.Macaw.Arch.AArch32`): it wires in
`Stubs.aarch32LinuxStmtExtensionOverride`, per-syscall argument/return
register mappings, and TLS-global initialization unconditionally, and
assumes AAPCS32 call-boundary conventions for its function-level
reasoning. None of that is applicable to firmware with no OS underneath
it, though (as the results below show) it doesn't *prevent* raw-binary
analysis — those Linux-specific hooks simply never fire for code that
never makes a syscall.

**Same class of gotcha as repro 1, independently reproduced in a second,
unrelated Galois tool**: `--address 0x888c` (no Thumb bit) fails outright:

```
Finished analyzing '0x888c'. Likely bug: unavoidable error (safety condition is unsatisfiable) at 0x888c
0x888c: error: in 0x888c
TranslationError {transErrorAddr = 0x888c, transErrorReason = DecodeError (ARMInvalidInstruction A32 0x888c ...)}
```

`--address 0x888d` (Thumb bit set) works, and produces a genuinely
interesting result:

```
Heuristic: grow and initialize memory referenced by: R4
...
Finished analyzing '0x888d'. Possible bug(s):

At 0x8894:
PointerWrite outside of static memory range (known BlockID 0): 0x20002329:[32]
Concretized arguments:
R0: 00000000
R1: 00000000
R2: 00000000
R3: 00000026
...
(4 more, at 0x88a6/0x88ee/0x892e/0x88ba, with R3 = 0x48/0x41/0x58/0x4a)
```

**This is a real, positive result**: with zero manual guidance about
what "the `&` command" even is, GREASE's under-constrained symbolic
execution independently rediscovered `R3 = 0x26` (`'&'`) as a value
reaching this exact block — the same fact this project already
solver-confirmed with its own harness
(`docs/harness/protocol-harness-results.md`) and concretely confirmed
with Unicorn. The other four `R3` values (`0x48`='H', `0x41`='A',
`0x58`='X', `0x4a`='J') are presumably other single-character command
checks GREASE's own path exploration reached nearby in the same
dispatcher chain — plausible, not independently verified this pass.

**The flagged "bug" is very likely a textbook uc-symex false positive,
not a real defect**: `0x20002329` is exactly 1 byte below the *real*,
already-known RX packet buffer address `0x2000232a`
(`docs/investigations/trigger-input.md`). GREASE is analyzing this block
*in isolation* (that's the whole point of under-constrained symex): `R4`
starts as a fully symbolic, heuristically-"grown" pointer, not knowing
it is *always* exactly `0x2000232a` in the real, whole-program firmware
(loaded from a literal pool by the real caller). GREASE's own
`doc/limitations.md` names this exact class of issue directly: "it makes
it difficult to say with certainty whether a behavior observed during
analysis is feasible in practice... heuristics... attempt to maximize
true positives and minimize false positives" — this looks like precisely
that tradeoff in action, not chased down further here (would require
telling GREASE what `R4` really is, e.g. via a startup override, which
is a real next step if this tool is adopted rather than a "premeeting"
task).

**Verdict for "where GREASE should sit relative to our custom Crucible
harnesses"**: it looks like a genuinely useful, cheap **first-pass sweep**
tool for raw Cortex-M firmware once the Thumb-bit convention is
respected — real signal (independently found the `&` byte with zero
guidance) at the cost of the expected uc-symex false-positive class. It
is not a replacement for this project's targeted, whole-firmware-aware
`checkBranchModel`/`ProtocolHarness` queries (which know the real caller
context, real buffer addresses, and real event semantics) — see
"Questions for Galois" for where exactly Galois would draw that line.

## Small MMIO-diagnostics improvement

`tools/svd/resolve_mmio.py --unicorn-log SNAPSHOT.json` (new): reads a
`run_concrete.py --log-mmio` snapshot directly and prints every logged
MMIO access resolved to a real ATSAMD51J19A peripheral/register name,
with its direction, value, PC, and instruction count — no new peripheral
modeling, purely a diagnostics convenience connecting two tools that
already existed separately. Example (real output, `FUN_0000bc44`'s USB
pin-mux setup from
[`docs/investigations/samd51-peripheral-mapping.md`](../investigations/samd51-peripheral-mapping.md)):

```
$ python3 tools/svd/resolve_mmio.py --unicorn-log snapshot.json
read  0x40000818  MCLK.APBBMASK (+0x18)  (pc=0x0000bc78, instr #119)
write 0x40000818 = 0x1  MCLK.APBBMASK (+0x18)  (pc=0x0000bc7e, instr #121)
read  0x41008058  PORT.GROUP0.PINCFG24 (+0x58)  (pc=0x0000bc8a, instr #126)
write 0x41008058 = 0x1  PORT.GROUP0.PINCFG24 (+0x58)  (pc=0x0000bc92, instr #128)
read  0x4100803c  PORT.GROUP0.PMUX12 (+0x3c)  (pc=0x0000bca2, instr #132)
write 0x4100803c = 0x7  PORT.GROUP0.PMUX12 (+0x3c)  (pc=0x0000bcaa, instr #134)
```

## Questions for Galois

1. **Cortex-M / Thumb-only execution**: is there an existing, supported
   way to tell macaw-aarch32 "this target has no ARM execution state at
   all, always decode as Thumb regardless of the LSB of a computed call
   target"? Repro 1 shows the LSB convention is followed literally even
   when the *architecture itself* makes the other mode impossible — is
   normalizing call-target addresses upstream (before they reach
   discovery) the intended fix on our side, or is there a mode-forcing
   flag/option we're missing?
2. **Raw-binary architecture handling in GREASE**: given `grease-aarch32`
   is built around Linux/AAPCS32 assumptions, is bare-metal Cortex-M a
   realistic target for GREASE today, or is `grease-aarch32` specifically
   not intended for that (with a different architecture module being the
   right starting point, or none existing yet)?
3. **Readonly flash and plain Crucible execution**: repro 2's root cause
   (`populateSegmentChunk` always uses solver assumptions for readonly
   segments) is deliberate, per its own source comment, to avoid solver
   crashes on large concrete arrays. Is there a recommended middle
   ground for a whole-firmware target (mostly flash, most of it never
   touched by any single query) — e.g. lazily folding only the
   specific literal-pool words actually read on a given path, rather
   than "all of flash" or "none of it"?
4. **MMIO modeling**: our own zero-behavior MMIO stub (Unicorn) and
   symbolic MMIO region (Crucible) both only go as far as "don't crash,
   don't claim real behavior." Is there a Galois-side pattern (e.g. a
   library of common peripheral models, or a principled way to express
   "this read always returns 0 except this one status bit is
   nondeterministic") we should be reusing instead of hand-rolling
   further special cases as we hit them?
5. **Debugger integration**: given the `HasContext`
   personality-type requirement, is there a lighter-weight recommended
   pattern for attaching `crucible-debug` to an *existing* harness with a
   fixed personality type (short of the full custom-wrapper approach
   GREASE itself uses)? Separately: is the EOF/non-interactive "No
   command given" loop (finding 4 above) expected, and what's the
   supported way to drive `crucible-debug` fully non-interactively (for
   CI, or for capturing a deterministic transcript) without a trailing
   `quit`-or-hang risk?
6. **Interrupts**: this project's harnesses (Unicorn and Crucible both)
   model straight-line/callable code only — no NVIC, no interrupt
   preemption at arbitrary points. Given ATSAMD51's peripherals routinely
   drive behavior via ISRs (confirmed concretely in
   `docs/investigations/samd51-peripheral-mapping.md` — a timer ISR
   toggling a GPIO pin), what's Galois's recommended approach for
   symbolically/concretely reasoning about interrupt-driven control flow
   without building a full interrupt controller model?
7. **Using Ghidra-derived discovery facts**: we already cross-check
   Macaw's discovery/decode against Ghidra's independent Thumb-only
   decoder (repro 1 is exactly this). Is there a supported way to feed
   Ghidra's own function-boundary/xref facts *into* Macaw's discovery
   (rather than only using them as an after-the-fact cross-check), to
   correct exactly the kind of call-target/mode issue in repro 1 before
   it ever reaches Crucible?
8. **Where GREASE should sit relative to our custom Crucible harnesses**:
   given this pass's result (real signal, expected uc-symex false
   positives, Linux-flavored AArch32 assumptions baked in), does Galois
   see GREASE as a complement to targeted harnesses like ours (a cheap
   first-pass sweep before hand-authoring specific queries) or as a
   longer-term replacement once its firmware/bare-metal support matures?
9. **The RF/SPI driver-object boundary**: both AutoPilot and Remote hide
   their real RF/SPI behavior behind runtime driver objects and function
   pointers populated by code we deliberately haven't modeled (see
   `docs/investigations/samd51-peripheral-mapping.md` and
   `docs/investigations/mando-first-execution.md`) — reaching into them
   either means running full real startup, or building real SPI/radio
   peripheral behavior, both explicitly out of scope for our current
   goals. **What abstraction boundary would Galois recommend when we
   care about protocol/application-level behavior but deliberately do
   not want to model the underlying hardware driver** — e.g. is there a
   supported "treat this call as returning a symbolic-but-plausible
   value and move on" pattern (an override, in GREASE's terms) that's
   better than our current ad hoc entry-point-selection and (new)
   `--stub-call` approach?

## What did *not* change

- No fix to Macaw's A32 decode or call-target handling.
- No redesign of Crucible's memory model or `populateSegmentChunk`.
- No peripheral emulation added anywhere (Unicorn's MMIO window and
  Crucible's MMIO region are exactly as permissive/zero-behavior as
  before; the new `--unicorn-log` diagnostic only *names* addresses
  already being read/written).
- GREASE is not wired into APTrace's pipeline and is not vendored in this
  repo — it stays an external, optional experiment until/unless a real
  use case and a decision to adopt it exist.
- `aptrace debug` is additive and experimental (new module, new
  subcommand); no existing module (`SymbolicRunner`, `ProtocolHarness`,
  `FirmwareLoader`, `VectorTable`) or existing CLI subcommand
  (`solve`/`explore`/`protocol`/bare) was changed, and `tools/doctor.sh`
  plus a fresh run of all four existing subcommands were re-verified
  working after every change in this pass.
- Tool hierarchy unchanged: Ghidra (static) -> Unicorn (concrete truth)
  -> Macaw/Crucible/What4 (symbolic, targeted) remains authoritative;
  GREASE and `crucible-debug` are additions at the experimental tier, not
  replacements for any existing tier.
