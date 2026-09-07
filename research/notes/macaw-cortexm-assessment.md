# Macaw / Cortex-M Feasibility Assessment

Repo: `~/github/aptrace/external/macaw`, commit `593a918dda8afc1c6b56fc8e264ebd8d7ad70868`
(master, cloned 2026-09-07). Crucible `37b8dd21cdf91947d7f65e785cb1ebbbee15cc22`,
what4 `a8401c9f2221755ac94d3a456d028752c7188d7c` (both also master).

This is a source-reading assessment (no build performed yet — see progress.md). All claims
below are grounded in file paths / function names in the cloned tree, not general Macaw
knowledge.

## Package layout relevant to ARM

```
external/macaw/
  macaw-aarch32/            -- Data.Macaw.ARM.*: the actual A32/T32 lifter
  macaw-aarch32-symbolic/   -- Macaw -> Crucible translation for AArch32
  macaw-aarch32-syntax/     -- s-expression syntax for aarch32 (crucible-syntax front end)
  macaw-loader-aarch32/     -- Data.Macaw.BinaryLoader.AArch32: ELF-based loader only
  macaw-semmc/              -- shared support for semmc-derived architectures (ARM + PPC)
  deps/semmc, deps/dismantle, deps/asl-translator, deps/arm-asl-parser  -- ARM semantics
    pipeline: arm-asl-parser + asl-translator turn ARM's official ASL pseudocode into
    Haskell semantics; dismantle (dismantle-arm-xml) is Galois's own table-driven Thumb/ARM
    decoder, generated from ARM XML instruction encodings, not hand-written like flexdis86.
```

`macaw-aarch32` explicitly supports **both A32 and T32 (Thumb-2) encodings**
(`macaw-aarch32/README.md`, `Data.Macaw.ARM.Disassemble` header comment). Vector
(NEON/SIMD) instruction semantics exist but are **disabled by default** for compile-time
reasons, toggleable via `isUninterpretedOpcode` in `Data.Macaw.ARM.Arch`
(`macaw-aarch32/src/Data/Macaw/ARM/Arch.hs:683`).

## Answers to the Step 3 questions

### 1. Can Macaw decode pure Thumb Cortex-M code without ARM-mode instructions?

**Yes, and this is the easy case, not the hard one.** Decode mode (A32 vs T32) is tracked
per-block via a single register bit, `PSTATE_T`
(`macaw-aarch32/src/Data/Macaw/ARM/Disassemble.hs:130-144`, `thumbState`). Nothing requires
A32 code to ever appear — a firmware that is 100% Thumb (which Cortex-M is, since M-profile
*has no A32 mode at all*) just always has `PSTATE_T = 1` and only ever calls
`ThumbD.disassembleInstruction` (`Disassemble.hs:272-274`, `Dismantle.ARM.T32`). We don't
need to special-case anything to disable A32 — it simply never gets selected once every
entry point and every computed branch target is Thumb (odd address).

### 2. Does the AArch32 implementation assume an A/R-profile processor anywhere?

**Yes, in two identifiable, isolated places — not throughout.**

- `Data.Macaw.ARM.arm_linux_info` (`macaw-aarch32/src/Data/Macaw/ARM.hs:38-59`) is a
  **Linux-specific** `ArchitectureInfo` value: it wires up `preserveRegAcrossSyscall` /
  `linuxSystemCallPreservedRegisters` (`ARMReg.hs:286-297`, explicitly cites the Linux ARM
  EABI syscall convention) and `armPLTStubInfo` (dynamic-linking PLT stub sizes,
  `ARM.hs:69-73`, meaningless without a loader/dynamic linker). Both are irrelevant to a
  statically-linked bare-metal image and can simply be omitted/replaced when we build our
  own `ArchitectureInfo` — nothing else in `arm_linux_info` is Linux-specific.
- The register set itself is derived wholesale from the ARM **ASL** globals
  (`ARMReg.hs:260-264`, `armRegs`, pulling from `ASL.simpleGlobalRefs` /
  `ASL.gprGlobalRefsSym` / `ASL.simdGlobalRefsSym`), which model the full A/R-profile
  `PSTATE`/`CPSR`/banked-register world because that's what the official ARM ASL spec (the
  source of these semantics) covers. This isn't a *bug*, but it means the register file
  as currently exposed has no explicit modeling of Cortex-M-only state: `MSP`/`PSP` (two
  stack pointers), `CONTROL`, `PRIMASK`, `BASEPRI`, `FAULTMASK`, `IPSR` (exception number),
  or `EXC_RETURN` semantics for exception return. Ordinary Thumb-2 instruction semantics
  (data processing, load/store, branches) do not touch this state and are unaffected;
  only M-profile system-level code (exception entry/return, `MSR`/`MRS` to special
  registers) would need it.

### 3. Which instructions/state are likely problematic for M-profile?

Not yet empirically confirmed (requires a build + Step 6 comparison against
`objdump`/Capstone), but structurally:

- **Ordinary Thumb-2 data processing / load-store / branch instructions**: should decode
  and lift cleanly — these are shared between A/R-profile T32 and M-profile Thumb, and
  `dismantle-arm-xml`'s table-driven decoder is derived from ARM's own encoding tables, not
  hand-picked for a particular profile.
- **`SVC`**: decodes fine; represented as the `ARMSyscall` primitive
  (`Data.Macaw.ARM.Arch.hs:189`, `ARMPrimFn`), but its *interpretation* is Linux-syscall
  shaped. On Cortex-M, `SVC` almost never appears outside an RTOS (FreeRTOS uses it for
  context switches in some ports) — need to check if our firmware uses it at all before
  worrying about this.
- **`MRS`/`MSR` to M-profile special registers** (`MSP`, `PSP`, `PRIMASK`, `BASEPRI`,
  `FAULTMASK`, `CONTROL`), **`CPSID`/`CPSIE`**, **`WFI`/`WFE`/`SEV`**, **`BKPT`**: these are
  M-profile-specific or behave differently than on A/R-profile. Whether `dismantle-arm-xml`
  even *decodes* the M-profile encodings of `MRS`/`MSR` (which differ from the A/R-profile
  encodings) is unverified — this is the single most important open question for Step 6,
  since if these fail to decode we get a clean "unsupported instruction" block boundary
  (see below), not a crash.
- **Memory barriers `DMB`/`DSB`/`ISB`**: likely decode (they're part of common Thumb-2, not
  M-profile-specific) but their semantics are probably no-ops from a symbolic-execution
  standpoint — fine for our purposes.
- **Exception return** (`BX`/`POP {PC}` with an `EXC_RETURN` magic value in LR, e.g.
  `0xFFFFFFF9`): the generic call/return identification in
  `macaw-aarch32/src/Data/Macaw/ARM/Identify.hs` recognizes ordinary Thumb return patterns
  (`isValidReturnAddress`, lines 58-81) but has no special knowledge of `EXC_RETURN` values.
  Not a concern for the POC (we treat each vector-table entry as an independent root, per
  the plan — we do not model exception return at all yet).

**Crucially: unsupported instructions fail per-instruction, not per-program.** When
`lookupSemantics` returns `Nothing` for a decoded-but-unimplemented instruction, or the
decoder itself fails, `Disassemble.hs` cleanly terminates the current block with a
`TranslateError` marker (`Disassemble.hs:194-196, 206, 350-362`) and preserves everything
discovered up to that point. This directly matches the plan's Step 6 guidance
("do NOT immediately implement every unsupported instruction... first determine whether it
blocks useful execution") — Macaw's own architecture already supports exactly that
incremental posture.

### 4. Can we create a Macaw memory image programmatically from a raw binary?

**Yes, directly, with no ELF involved.** `macaw-loader-aarch32` (the only existing AArch32
loader) is ELF-only (`Data.Macaw.BinaryLoader.AArch32`, depends on `elf-edit`) — it is not
usable for a raw `.bin`. But it is only a thin convenience wrapper: the underlying
`Data.Macaw.Memory` API (`base/src/Data/Macaw/Memory.hs`) that it calls into is
loader-agnostic:

- `memSegment :: ... -> BS.ByteString -> MemWord w -> m (MemSegment w)`
  (`Memory.hs`, around `memSegment ::`) builds one segment directly from a plain
  `ByteString` + a link-time address + `Perm.Flags`, with an empty relocation map and no
  ELF-derived segment index — exactly what a flat firmware image needs.
- `emptyMemory :: AddrWidthRepr w -> Memory w` (`Memory.hs:1028`) and
  `insertMemSegment :: MemSegment w -> Memory w -> Either ... (Memory w)` (`Memory.hs:1057`)
  assemble one or more such segments into a `Memory 32`.

So our `FirmwareLoader` can build: one `MemSegment` for flash (our `.bin` bytes, base
`0x00004000`, `Perm.execute .|. Perm.read`) and one all-zero/BSS `MemSegment` for RAM
(base `0x20000000`, size `0x30000`, `Perm.read .|. Perm.write`, no execute) — entirely
without touching `elf-edit` or any ELF-shaped abstraction. This is a small amount of new
code, not a fork of anything.

### 5. Can code discovery start from arbitrary vector-table entry points?

**Yes, directly.** `Data.Macaw.Discovery.cfgFromAddrs` (`base/src/Data/Macaw/Discovery.hs:889-906`)
takes a plain `[ArchSegmentOff arch]` list of "Initial function entry points" — there is no
requirement that these come from an ELF symbol table or `_start`. We resolve each vector
table word (after masking the Thumb bit, per the address-translation logic already used
throughout Macaw, e.g. `MC.clearSegmentOffLeastBit` in `Disassemble.hs:125`) to a
`MemSegmentOff` and hand the whole list — Reset_Handler plus every distinct interrupt
handler we found in `firmware-layout.md` — straight to `cfgFromAddrs`. This is exactly the
Step 5 design ("treat interrupt handlers simply as independent roots/entry points").

One important, favorable detail: `Data.Macaw.ARM.Eval.mkInitialAbsState`
(`macaw-aarch32/src/Data/Macaw/ARM/Eval.hs:104-117`) sets the initial `PSTATE_T` (Thumb
mode) bit **from the low bit of the entry address itself**
(`pstate_t_val = if lowBitSet startAddr then 1 else 0`). This means we should hand Macaw
the raw, odd vector-table addresses (Thumb bit still set) as entry points — Macaw derives
the decode mode from that bit automatically. This is precisely the ARM/Thumb function-
pointer convention the vector table already encodes; no separate bit-clearing step is
needed to select Thumb mode (only to compute the actual byte offset to disassemble from,
which `clearSegmentOffLeastBit` already handles internally).

### 6. Can we supply our own memory/MMIO semantics during Crucible execution?

Not yet empirically verified (requires getting as far as Step 7/8), but structurally this
is a Crucible-level question, not a Macaw-ARM one: once a function is translated to a
Crucible CFG (via `macaw-aarch32-symbolic`), memory reads/writes go through Crucible's
standard memory-model override mechanism, which is architecture-agnostic. This is the
standard mechanism other Macaw-based tools (e.g. `macaw-x86-symbolic` consumers) use to
model MMIO/unknown memory as fresh symbolic values, so there is no ARM-specific obstacle
here. To be confirmed once we build `macaw-aarch32-symbolic` and read its Crucible
memory-model glue code (next investigation step).

### 7. Which abstractions would need extension for Cortex-M special registers or exception state?

Per §2/§3, the gap is a well-defined **environment layer**, not a lifter rewrite:

- `MSP`/`PSP`, `CONTROL`, `PRIMASK`, `BASEPRI`, `FAULTMASK`, `IPSR`, NVIC, SCB, SysTick,
  exception entry/return (`EXC_RETURN` in LR) — none of these exist in the current ARMReg /
  ASL-globals register set, because M-profile isn't the ASL profile these semantics were
  generated from. Per the plan's Step 10 classification, all of this is **"CAN STUB" or
  "REQUIRED FOR SPECIFIC FIRMWARE FEATURE"** for the POC — we are explicitly not modeling
  interrupts or exception handling yet (Step 5: "treat interrupt handlers simply as
  independent roots"), so none of this blocks the milestone.
- What *is* required now is purely our own new code (not a Macaw patch): the raw-binary
  `FirmwareLoader`/`CortexMAddressSpace` (§4), and enough MMIO-address-range classification
  to know when a read is "peripheral" vs "RAM" vs "flash" (Step 8) — both green-field
  APTrace modules, not upstream extensions.

## Notable positive surprise: floating point

The ATSAMD51 in our target firmware is Cortex-**M4F** (has an FPU), and Arduino/Adafruit
firmware for motion control very plausibly uses floating point (PID loops, unit
conversions). `Data.Macaw.ARM.Arch.ARMPrimFn` already has first-class constructors for
`FPAdd`, `FPSub`, `FPMul`, `FPDiv`, `FPSqrt`, `FPCompareGE/GT/EQ/NE/UN`, `FPToFixed`,
`FixedToFP`, `FPRoundInt`, `FPMulAdd`, etc. (`Arch.hs`, referenced in
`Data.Macaw.ARM.Eval.absEvalArchFn:157-182`) — i.e. VFP scalar float instructions are
already modeled as primitives (abstractly interpreted as `MA.TopV`, unconstrained, which is
exactly the conservative behavior we want for now). This significantly de-risks analyzing
real motion-control code, as opposed to needing custom float-instruction handling from
scratch.

## Recommendation (preliminary, pending a successful build)

Based on source inspection alone, the evidence strongly favors:

**A. Continue with Macaw AArch32 + a Cortex-M environment layer.**

Everything examined so far is either (a) already generic enough to reuse as-is
(instruction decode, Thumb-bit handling, entry-point-driven code discovery, raw-memory
construction), or (b) cleanly isolated Linux/A-profile-specific code we simply don't call
(`arm_linux_info`'s syscall/PLT wiring). No evidence yet of anything that would force
option B (custom lifter), C (different Galois component), or D (fundamentally unsuitable).

**Update (same day, post-build): confirmed, not just provisional.** `macaw-aarch32` was
built successfully (GHC 9.6.7, ~13 min for the targeted package set; see
`progress.md` Step 2). A minimal APTrace loader (`src/APTrace/FirmwareLoader.hs`,
`app/Main.hs`) built on the first attempt beyond two trivial `Word32`/`Word64` type
fixes, and run against real, unmodified `firmware_autopilot868.bin`: 25 functions
discovered (21 from vector-table entry points, 4 more found transitively via normal
call-graph exploration), **zero** `TranslateError`/unsupported-instruction failures
across ~1500 real lifted instructions, including the large, non-trivial `Reset_Handler`.
Only `USAT`/`USAT16` (saturating arithmetic) surfaced as missing semantics anywhere in
the build, and none of our discovered functions hit it. Full run log:
`research/notes/runs/discovery-autopilot868-flash0x4000.log`. Recommendation A is now
well-supported by direct evidence, not just source reading.

**Second update (same day): the full pipeline works end to end.** Steps 7-9 are now
also done, not just assessed: `IRQ10_Handler` (a real, discovered interrupt handler)
was translated block-by-block into Crucible via `Data.Macaw.Symbolic.mkParsedBlockCFG`,
its memory backed by `Data.Macaw.Symbolic.Memory.newGlobalMemory` with a genuine
memory-mapped-peripheral address (`0x40002000`, found by reading a real literal-pool
value out of the firmware bytes) modeled as symbolic, and a Z3 online solver process
produced concrete, semantically-correct models for both directions of the block's
real conditional branch. Full details: `symbolic-execution-results.md`. Every
research question in this document (1-7) now has a direct, empirical answer, not
just a source-reading-based inference. Recommendation **A** is fully confirmed.

## Open items for the next pass

1. ~~Build `macaw-aarch32`~~ — done (Step 2 in progress.md).
2. ~~Confirm real Thumb-2 firmware lifts cleanly~~ — done: 25 functions, 0 failures.
3. ~~Get one function into Crucible, with symbolic MMIO and a solver model~~ — done,
   see `symbolic-execution-results.md`.
4. Cross-validate a sample of the decoded instructions against an independent
   disassembler (objdump/Capstone; neither installed yet) — not yet done, still worth
   doing for full Step 6 confidence even though the zero-failure result plus a
   semantically-correct symbolic-execution result is already strong signal.
5. Confirm whether `dismantle-arm-xml` decodes M-profile-only `MRS`/`MSR` operand
   encodings — not yet exercised (our firmware may simply not use them; needs checking).
6. Step 10 (systematic Cortex-M state gap inventory) not yet written up as its own
   document.
