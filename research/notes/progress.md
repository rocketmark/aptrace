# APTrace Progress Log

## 2026-09-07

### Step 1 — Workspace inspection

- `~/github/aptrace` already contained `Autopilot_firm/` (four `.bin` firmware images, a
  `bossac.exe` flasher, `update_firmware.bat`, `desktop.ini`) and
  `PerformingRigs_UserManual_AutoPilot.pdf`.
- Searched `~/github` top level for other AutoPilot material; nothing else relevant found
  outside `aptrace/`.
- Created project skeleton: `external/`, `research/{firmware/{originals,extracted},notes}`,
  `src/APTrace/`, `app/`, `test/`, `tools/`.
- Copied the four `.bin` files (unmodified) into `research/firmware/originals/` and recorded
  SHA-256 hashes (`SHA256SUMS.txt`). Originals in `Autopilot_firm/` untouched.
- Full findings: [firmware-layout.md](firmware-layout.md).

**Key result: MCU identified as Microchip/Atmel ATSAMD51 (Cortex-M4F)**, built with
Arduino + Adafruit SAMD board package 1.7.11, flashed via bossac at app offset 0x4000
behind a 16KB Adafruit UF2-style bootloader. RAM top 0x20030000 (192KB) confirms M4F
(SAMD51x19/x20 die), not SAMD21 (M0+, max 32KB RAM).

### Step 4 — Vector table scanner

- Wrote `tools/vector_scan.py`, a standalone Python prototype (not the final Haskell CLI)
  that scores candidate offsets by: SP within a plausible RAM range, Reset vector Thumb-bit
  + in-range, reserved-vector zero-check, and count of Thumb-tagged handler pointers.
- Ran against all four images with `--flash-base 0x4000 --ram-size 0x30000`. All four
  produce a single high-confidence candidate at file offset 0, matching a textbook ARMv7-M
  layout (reserved slots exactly zero, shared default-handler stub across most exceptions).
- Recovered Reset_Handler, SysTick_Handler, and ~20 distinct real IRQ handler addresses per
  image vs. ~20 that alias to a shared default stub. Full tables in firmware-layout.md.

### Step 2 (in progress) — Cloning Galois repos

- Cloned (shallow default clone, no pinning yet) into `~/github/aptrace/external/`:
  - `macaw` (GaloisInc/macaw)
  - `crucible` (GaloisInc/crucible)
  - `what4` (GaloisInc/what4)
- Commit hashes and build investigation: TBD, next step.

- Recorded commit hashes:
  - macaw: `593a918dda8afc1c6b56fc8e264ebd8d7ad70868` (master)
  - crucible: `37b8dd21cdf91947d7f65e785cb1ebbbee15cc22` (master)
  - what4: `a8401c9f2221755ac94d3a456d028752c7188d7c` (master)
- Macaw's checkout is itself the umbrella repo for the whole ARM stack: `macaw-aarch32`,
  `macaw-aarch32-symbolic`, `macaw-aarch32-syntax`, `macaw-loader-aarch32` all live inside
  it, plus submodules `deps/semmc`, `deps/dismantle`, `deps/asl-translator`,
  `deps/arm-asl-parser`, `deps/crucible`, `deps/what4` (not yet `git submodule update`'d).

### Step 3 — Macaw/Cortex-M source assessment (no build yet, source reading only)

Read `macaw-aarch32/README.md`, `Data.Macaw.ARM{,.ARMReg,.Arch,.Disassemble,.Eval,.Identify}`,
and the relevant parts of `base/src/Data/Macaw/{Memory,Discovery}.hs`. Full findings with
file/line citations: [macaw-cortexm-assessment.md](macaw-cortexm-assessment.md).

Headline results:
- Macaw already supports both A32 and T32 (Thumb-2) decoding; a pure-Thumb Cortex-M image
  needs no A32 support at all (M-profile has no A32 mode to begin with).
- The only A/R-profile/Linux-specific parts are cleanly isolated in `arm_linux_info`
  (syscall ABI + PLT stub sizing) and are simply not used for a bare-metal
  `ArchitectureInfo`; ordinary Thumb-2 semantics are unaffected.
- Raw firmware → `Data.Macaw.Memory` is straightforward and ELF-free: `memSegment` takes a
  plain `ByteString` + link address + permissions; no need to route through `elf-edit`.
- `cfgFromAddrs` takes a bare list of entry-point addresses — vector-table-driven discovery
  needs no special support, and works with the odd (Thumb-bit-set) addresses directly,
  since `mkInitialAbsState` derives the Thumb mode from the entry address's low bit.
- Unsupported instructions fail per-block (`TranslateError`), not per-program — matches the
  plan's incremental posture for Step 6.
- Cortex-M4F VFP scalar float ops (`FPAdd`/`FPMul`/`FPDiv`/`FPSqrt`/etc.) are already
  modeled as macaw primitives — good news given AutoPilot firmware likely uses floats.
- Gap: Cortex-M-only state (MSP/PSP, CONTROL, PRIMASK, BASEPRI, FAULTMASK, IPSR, NVIC, SCB,
  EXC_RETURN) has no representation in the ASL-derived register set — expected, and per the
  plan's Step 10 classification this is CAN STUB / not needed for the POC (we're not
  modeling interrupts/exceptions yet, only registering handlers as independent roots).
- Preliminary recommendation leans **A** (continue with Macaw AArch32 + a thin Cortex-M
  environment layer), pending a successful build and real-instruction validation (Step 6).

### Step 2 (build) — SUCCESS

- Installed GHCup + GHC 9.6.7 + cabal 3.16.1.0 (no prior Haskell toolchain on this
  machine). Used macaw's documented `cabal.project.freeze.ghc-9.6.7`.
- `git submodule update --init` on `external/macaw` (non-recursive; the nested
  submodules inside `deps/asl-translator`, `deps/dismantle`, `deps/semmc`,
  `deps/arm-asl-parser` are each package's own standalone-build submodules and are
  **not** referenced by macaw's `cabal.project.dist`, which pins its own copies —
  confirmed by a clean build without touching them). Submodule pins differ from our
  separately-cloned top-level `external/crucible`/`external/what4` (e.g. macaw's
  `deps/crucible` = `a9831089...`, top-level clone = `37b8dd21...`); the build uses
  macaw's own pinned submodules, not the top-level clones (which remain useful only
  as easy-to-browse references at their own latest-master commit).
- `cabal build macaw-aarch32 macaw-aarch32-symbolic macaw-loader-aarch32` (targeted,
  not `cabal build all`, to skip x86/PPC/RISC-V) — **built clean**, ~13 minutes total
  on this machine. Only diagnostic of note: `Missing function definition for:
  USAT16_A1, USAT16_T1, USAT_A1_ASR, USAT_A1_LSL, USAT_T1_ASR, USAT_T1_LSL` — the
  saturating-arithmetic instruction family is the **only** gap surfaced across the
  entire ASL-derived AArch32/Thumb semantics set. No other opcode family reported
  missing.
- Verified `cabal build` correctness with `grep -in "error:"` — zero real errors.

### Step 5 — First working APTrace loader + discovery (SUCCESS, first try beyond typos)

Created local package `aptrace` (`~/github/aptrace/{aptrace.cabal,src/APTrace/*,app/Main.hs}`),
built against macaw's already-built dependency tree by making `external/macaw/cabal.project`
a small local file (`import: cabal.project.dist` + `packages: ../../.`) rather than a bare
symlink — reuses the cached build, adds zero upstream modifications.

- `src/APTrace/VectorTable.hs`: pure vector-table parser (Haskell port of
  `tools/vector_scan.py`'s core logic).
- `src/APTrace/FirmwareLoader.hs`: `buildMemory` constructs a `Data.Macaw.Memory.Memory
  32` directly from raw bytes via `MM.memSegment` + `MM.insertMemSegment` (flash segment
  RX at the given load address, RAM segment RW zero-filled at 0x20000000/0x30000) — no
  ELF anywhere, confirming the Step 3 assessment. `resolveEntry` intentionally does NOT
  clear the Thumb bit before calling `MM.resolveAbsoluteAddr`, per the assessment's
  finding that `Data.Macaw.ARM.Eval.mkInitialAbsState` derives decode mode from the
  entry address's own low bit.
- `app/Main.hs`: reads firmware, parses vector table, builds memory, resolves every
  non-zero vector entry to a `MemSegmentOff`, and calls `Data.Macaw.Discovery.cfgFromAddrs
  ARM.arm_linux_info mem addrSymMap entryAddrs []` directly (reusing `arm_linux_info`
  as-is, per the assessment's finding that its Linux-specific parts are inert for
  bare-metal code that never executes a PLT stub or syscall pattern).

**Ran against real, unmodified `firmware_autopilot868.bin`** (flash base 0x4000):

- 50 non-empty vector table entries parsed correctly.
- Macaw discovery found **25 functions** total: every named vector-table handler that
  has a *distinct* address (IRQ10, IRQ12–27, IRQ35, Reset_Handler, SysTick_Handler, one
  representative of the shared default-handler group) plus **4 more discovered
  transitively** (e.g. `0xa2ac`, `0xcd8a`, `0xcd90`, `0xcdd8` — functions called *from*
  the vector-table entry points, found automatically by Macaw's own call-graph
  exploration, not seeded by us). This is real control-flow recovery, not just entry
  point enumeration.
- **Zero `TranslateError`/unsupported-instruction failures** across all 25 functions,
  including `Reset_Handler` itself (~1231 lines of Macaw IR / a genuinely large,
  non-trivial function) and roughly **1500 real instructions total**. Confirmed via
  `grep -c "TranslateError"` (0 hits) and manual review of a sample function
  (`IRQ10_Handler @ 0x952d`): real Thumb-2 instructions (`LDR_l_T1`, `LDRB_i_T1`,
  `BFC_T1`, `STRB_i_T1`, `LDR_i_T1`, `CMP_i_T1`) lifted with plausible IR, including a
  full NZCV flag computation for `CMP`.
- Full output saved at `research/notes/runs/discovery-autopilot868-flash0x4000.log`.

This is a first-try, essentially clean result (only two trivial type-inference/Word32-
vs-Word64 fixes needed to get `FirmwareLoader.hs` compiling) — strong, concrete evidence
for the "Continue with Macaw AArch32" recommendation in the assessment doc, upgraded
from "preliminary" to reasonably confident. Primary-goal milestones 1–6 are now met on
real firmware.

### Steps 7-9 — SUCCESS: full symbolic-execution demonstration on real firmware

Full writeup: [symbolic-execution-results.md](symbolic-execution-results.md).

Found that `IRQ10_Handler`'s entry block loads a literal-pool pointer (`0x40002000`,
read directly from the firmware bytes) into R3 — a genuine Cortex-M peripheral MMIO
base, not a RAM global — then a later block (`0x9536`) polls a 32-bit status word 8
bytes past that base in a `while (status != 0) {}`-shaped loop.

Added `APTrace.SymbolicRunner` (`src/APTrace/SymbolicRunner.hs`) and
`FirmwareLoader.buildMemoryWithMMIO` (a third, RW, initially-zero memory segment).
Key design decision: symbolically execute *only* the loop-body block in isolation via
`Data.Macaw.Symbolic.mkParsedBlockCFG`, not the whole function — Crucible's default
`executeCrucible` has no loop-invariant inference, so a whole-function run risks not
terminating on a loop with a fully symbolic exit condition; a single block always
finishes, since its terminator becomes a Crucible `return`. Memory is backed by
`Data.Macaw.Symbolic.Memory.newGlobalMemory ... SymbolicMutable`, which makes all
*mutable* (RW) memory fully symbolic — RAM and our new MMIO segment alike — with no
per-region override hook needed; this is a general mechanism that happens to give
"unknown peripheral read → fresh symbolic value" as a side effect of the correct
general assumption ("we don't know RAM/register contents up front"). A Z3 online
solver process (`What4.Protocol.Online`) is queried directly for each of the block's
two branch targets, with a model of R2 (the loaded status word) on success.

One dependency detour: initially tried reusing `Data.Macaw.Refinement.Solver`
(`macaw-refinement`) for Z3 backend setup, since it's a real, working example of this
exact plumbing — but (a) it's an `other-modules`-only (private) module, not
`exposed-modules`, so it isn't importable, and (b) depending on `macaw-refinement`
pulls in macaw-x86/ppc/riscv transitively (its cabal file has no per-architecture
flags), which we'd specifically avoided building. Inlined the ~15-line Z3-backend
setup directly into `SymbolicRunner.hs` instead (mirroring the same code, MIT/BSD
upstream, not copied verbatim beyond the obvious `WE.newExprBuilder`/
`CBS.newSimpleBackend`/`WC.extendConfig` incantation).

**Result, on real, unmodified `firmware_autopilot868.bin`:**

```
Query 1: is exit block 0x953c reachable?
  SAT: reachable when R2 (status word @ 0x40002008) = 0x0
Query 2: is loop-continuation 0x9536 reachable?
  SAT: reachable when R2 (status word @ 0x40002008) = 0x1010101
```

Both branch directions confirmed reachable with concrete Z3 models, exactly matching
the hand-derived semantics of the block's `CMP`+conditional-branch (Z flag set, i.e.
status == 0, exits the loop; any nonzero status continues polling — a real
SYNCBUSY-style hardware wait idiom). **This is the project's key milestone: every
Primary Goal item (1-9) is now demonstrated on real firmware, using only unmodified
upstream Macaw/Crucible/What4/Z3** plus ~350 lines of new APTrace code total
(`VectorTable.hs`, `FirmwareLoader.hs`, `SymbolicRunner.hs`, `Main.hs`).

### Protocol-level RF inventory found in the repo, and how it connects

A separate, concurrent research pass populated `research/autopilot_static_inventory/`
(v0.3) with a detailed static reverse-engineering of the bidirectional AutoPilot<->Remote
RF command protocol (parser dispatch tree at AutoPilot `0x8258`, outbound event
dispatcher at `0x9268`, several proven request/response transactions, and a list of
open questions — dormant pending events, an 11-vs-10 field mismatch, several
Remote-transmitted packets not explained by the visible dispatch tree).

Several of those open questions are reachability/symbolic-execution questions that
APTrace's already-proven pipeline (discovery + `SymbolicMutable` memory + Crucible +
What4/Z3, per `symbolic-execution-results.md`) is a direct fit for — notably "are
events 8/9/11/12/14 truly unreachable" and "which Remote-transmitted commands does
the parser actually accept," both currently answered by static inference rather than
proof. Wrote up the mapping and a concrete milestone order (M1-M6) in
[protocol-harness-roadmap.md](protocol-harness-roadmap.md). Key gap: APTrace has only
been run against the AutoPilot image so far, not the Remote/mando images where most
of that inventory's addresses live (M1 in the roadmap).

## Next experiment

1. Cross-validate the decoded Thumb-2 instructions against an independent
   disassembler (arm-none-eabi-objdump / Capstone — neither installed yet) to close
   out Step 6 with full confidence, though zero decode/lift failures across ~1500
   instructions plus a semantically-correct symbolic-execution result is already
   strong signal.
2. Step 10 (Cortex-M state gap inventory: MSP/PSP, CONTROL, PRIMASK, NVIC, SysTick,
   EXC_RETURN, etc., classified REQUIRED NOW / REQUIRED FOR FEATURE / CAN STUB /
   IRRELEVANT) — not yet written up as its own document.
3. Extend the `solve` subcommand beyond one hardcoded function/block pair into
   something more general (still deliberately minimal per the "don't over-design the
   CLI" guidance) — e.g. accept function/block/pointer-register/MMIO-address as CLI
   arguments instead of literals in `runSolve`.
4. Try a whole-function symbolic run (not just one block) on a function with no
   internal loops, to validate the `mkFunCFG` path end-to-end too.
5. **Protocol harness roadmap M1**: point APTrace's loader/discovery at
   `firmware_mando868.bin` (the Remote image) — see
   [protocol-harness-roadmap.md](protocol-harness-roadmap.md). and its dependency chain** (`semmc`, `dismantle`,
   `asl-translator`, `arm-asl-parser`, `crucible`, `what4`) — this is the biggest remaining
   unknown. Need to: init the relevant submodules, read each repo's build docs (README,
   `cabal.project*`, any Nix flake) to find the officially supported build path, and
   determine GHC version compatibility (macaw ships `cabal.project.freeze.ghc-9.10.2/9.8.4/9.6.7`).
   This is expected to be resource- and time-intensive (ASL-to-Haskell semantics generation
   via Template Haskell is a known slow step in this codebase) — flagged to the user before
   kicking off rather than launched silently in the background.
2. Once built: confirm real Thumb-2 instructions from `firmware_autopilot868.bin` decode
   (Step 6), starting with `SysTick_Handler` (0xcca4) as a small, near-leaf candidate.
3. Cross-check discovered decode against `arm-none-eabi-objdump` or Capstone as a second
   opinion (need to install/locate one first — not yet checked for on this machine).
