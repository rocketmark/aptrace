# Symbolic Execution Demonstration (Steps 7-9)

This is the key feasibility milestone: a real branch in real, unmodified AutoPilot
firmware, symbolically executed through Macaw -> Crucible -> What4 -> Z3, with a
memory-mapped peripheral register as symbolic input and a solver-produced model for
both directions of the branch.

## Target

- Firmware: `research/firmware/originals/firmware_autopilot868.bin`
  (SHA-256 `6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3`)
- Function: `IRQ10_Handler`, entry `0x952d` (Thumb bit set), one of the ~20 real,
  distinct interrupt handlers found by the vector-table scan (see
  `firmware-layout.md`).
- Target basic block: `0x9536` -- the body of a polling loop within that handler.

## How the addresses were found

`tools/vector_scan.py` found `IRQ10_Handler` pointing at flash address `0x952d`
(see the vector table dump in `firmware-layout.md`). Running
`aptrace`'s discovery mode (`aptrace firmware_autopilot868.bin 0x4000`) lifted its
Macaw IR; the entry block loads a 32-bit literal from a PC-relative literal pool at
flash address `0x9548`. Reading that literal directly from the firmware bytes
(file offset `0x9548 - 0x4000 = 0x5548`) gives the value `0x40002000` -- squarely
in the Cortex-M peripheral region (`0x40000000+`), i.e. a genuine MMIO base pointer,
not a RAM global.

The lifted IR for the following block (`0x9536`) is:

```
0x9536:
  r1197 := (bv_add _R3_0 (0x8 :: [32]))     ; R3 = 0x40002000 (peripheral base)
  r1198 := read_mem r1197 (bvle4)           ; load 32-bit status @ 0x40002008
  ... CMP_i_T1 r1198, #0 (computes PSTATE_Z) ...
  r1249 := (eq r1248 (0x1 :: [1]))          ; r1248 = PSTATE_Z
  r1259 := (mux r1249 (0x953c) (0x9536))    ; Z=1 (status==0) -> exit; else -> loop
  branch r1249 0x953c 0x9536
```

This is a real `while (status != 0) { }` busy-wait on a hardware status register --
a classic "wait for SYNCBUSY/ready bit" pattern on this MCU family.

## How it was run

`aptrace solve firmware_autopilot868.bin` (see `app/Main.hs`, `runSolve`):

1. Build a Macaw `Memory` with three segments: flash (concrete, RX, real firmware
   bytes), RAM (RW, 0x20000000/192KB), and a small MMIO segment at
   `0x40002000`/1KB (RW) -- see `APTrace.FirmwareLoader.buildMemoryWithMMIO`.
2. Run the same vector-table-driven discovery as the plain `discover` mode to
   locate `IRQ10_Handler`, then look up its `ParsedBlock` at `0x9536`.
3. Translate *only that one block* to a Crucible CFG via
   `Data.Macaw.Symbolic.mkParsedBlockCFG` -- not the whole function -- because
   the block is a loop body with a symbolic exit condition, and Crucible's
   default `executeCrucible` has no loop-invariant inference; simulating the
   whole function risks not terminating. A single block ending in a conditional
   branch always finishes (its terminator becomes a Crucible `return`).
4. Back the memory with Crucible-LLVM's memory model via
   `Data.Macaw.Symbolic.Memory.newGlobalMemory ... SymbolicMutable`, which makes
   all *mutable* (writable) memory -- our RAM and our MMIO segment alike --
   fully symbolic, while flash stays concrete. This is a general mechanism, not
   an MMIO-specific hack: it happens to give us exactly "unknown peripheral read
   returns a fresh symbolic value" as a side effect of "we don't know RAM/register
   contents at an arbitrary point in time," which is the correct modeling
   assumption for both.
5. Seed R3 (the peripheral-base register, invariant across loop iterations) to
   the concrete value `0x40002000`; leave every other register (and all of
   RAM/MMIO) fully symbolic.
6. Run the block to completion (`CS.executeCrucible`), then ask an online Z3
   process (`What4.Protocol.Online`) whether each of the block's two branch
   targets is a satisfiable value of the ending PC, and if so, request a model
   for R2 (the register holding the loaded status word).

See `src/APTrace/SymbolicRunner.hs` for the full implementation.

## Result

```
$ aptrace solve firmware_autopilot868.bin
Function @ 0x952d, loop block @ 0x9536
MMIO region: 0x40002000 - 0x40002400 (fully symbolic)
Seeding R3 = 0x40002000 (peripheral base pointer)

Query 1: is exit block 0x953c reachable?
  SAT: reachable when R2 (status word @ 0x40002008) = 0x0

Query 2: is loop-continuation 0x9536 reachable?
  SAT: reachable when R2 (status word @ 0x40002008) = 0x1010101
```

Both directions are confirmed reachable, with concrete Z3-produced models
consistent with the hand-derived semantics above (Z flag set, i.e. status == 0,
exits; any nonzero status continues the loop). This is a real path condition
over a real memory-mapped peripheral in real, unmodified firmware, discharged by
an unmodified upstream SMT solver via unmodified Crucible/What4 plumbing.

## What this demonstrates

All of the "Primary goal" milestones (README-level Step 1-9) are met on real
AutoPilot firmware:

1. Raw firmware image loaded (no ELF, no format wrapper). ✅
2. Vector table parsed, Reset_Handler and interrupt handlers identified. ✅
3. Reset_Handler and other handler addresses determined. ✅
4. Thumb/Thumb-2 decoding via Macaw's existing AArch32 support -- unmodified
   upstream Macaw, zero decode failures across ~1500 real instructions. ✅
5. Control flow / basic blocks recovered (25 functions, including transitively
   discovered ones). ✅
6. A real function lifted into Macaw IR and (for this block) Crucible. ✅
7. Symbolic execution of a real piece of firmware. ✅
8. A real memory-mapped peripheral read treated as symbolic input. ✅
9. Solver-produced models for both directions of a real, reachable branch. ✅

No custom symbolic execution engine, SMT interface, or ARM decoder was written --
only a firmware loader (~90 lines), a vector-table parser (~50 lines), and a
block-level Crucible/What4 driver (~200 lines), all calling directly into
unmodified upstream Macaw/Crucible/What4 APIs.
