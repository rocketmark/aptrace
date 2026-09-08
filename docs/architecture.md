# APTrace Architecture

## What is APTrace?

APTrace is a bare-metal Cortex-M firmware analysis tool. Its initial target
is firmware for the Performing Rigs AutoPilot motion-control system
(Microchip ATSAMD51, Cortex-M4F), but the design is meant to generalize to
other Cortex-M firmware.

## What problem is it solving?

Given a raw, headerless Cortex-M firmware image (no ELF, no debug symbols,
often no public documentation of the wire protocol it speaks), recover
enough structure and behavior to answer concrete questions like "what byte
sequence makes this firmware take this branch?" or "what string does this
firmware transmit in response to this input?" — with *proof* (a solver-
checked model), not just plausible static inference.

## Original hypothesis vs. current direction

The project started as a feasibility spike for a narrower question: **can
the Galois Macaw/Crucible/What4 stack alone do this, without writing a
custom symbolic execution engine?** That question has a qualified yes —
see [`docs/firmware/cortexm-assessment.md`](firmware/cortexm-assessment.md)
and [`docs/harness/symbolic-execution-results.md`](harness/symbolic-execution-results.md)
for the demonstrations. Macaw's AArch32/Thumb backend decodes real Cortex-M4F
firmware cleanly, and Crucible/What4/Z3 can solve real reachability and
input-value questions against it.

But pushing further — into a real, moderately complex dispatcher function
with several called subroutines, loops, and per-channel state — surfaced a
harder problem: **faithfully modeling the effects of code you haven't
lifted yet** (see [`docs/project-status.md`](project-status.md)'s "Current
blockers"). Macaw/Crucible/What4 remain the right tool for *symbolic
reachability once you know what you're asking*, but they are not, by
themselves, a full reverse-engineering workflow. Structure recovery (what is
this table? what does this function actually do? what are these addresses
named?) and cheap concrete execution (just run this code path and see what
happens, without paying the cost of full symbolic evaluation) are separate
needs, well served by separate, mature tools.

**APTrace's direction going forward is to be a workbench that orchestrates
these tools, rather than a monolith that reimplements what they already do
well.**

## Planned tool roles

| Tool | Role | Status |
|---|---|---|
| **Ghidra** | Static RE / decompiler / cross-references / data structure and table recovery / naming MMIO registers and globals | Not yet integrated |
| **Macaw** | Independent CFG recovery and machine-code lifting (ground truth, doesn't depend on a decompiler's heuristics) | In use, proven (see `docs/firmware/cortexm-assessment.md`) |
| **Unicorn** | Fast concrete Thumb execution and state snapshotting — run firmware to a checkpoint cheaply, then hand a concrete state to the symbolic side | Not yet integrated |
| **Crucible + What4 + Z3** | Targeted symbolic reachability and input-value solving, once the question and the relevant code region are well understood | In use, proven |
| **APTrace** | Orchestration: evidence model, scenario definitions, trace capture, and (eventually) a UI/workbench tying the above together | This repo |

This is a planning statement, not an implementation status — none of
Ghidra, Unicorn, or the orchestration layer exist yet. Per
[`docs/project-status.md`](project-status.md)'s "explicit do-not-start-yet
items," that integration work is deliberately deferred until the current
AutoPilot-only symbolic-execution blocker is resolved or explicitly
deprioritized.

## Intended pipeline (Macaw/Crucible side)

```
raw Cortex-M firmware
        |
        v
      APTrace
        |
        +-- raw firmware loader        (APTrace.FirmwareLoader)
        +-- vector-table parser        (APTrace.VectorTable, tools/vector_scan.py)
        +-- Cortex-M memory map        (flash/RAM/MMIO segments)
        +-- MMIO abstraction           (symbolic-on-read, via SymbolicMutable memory)
        |
        v
Macaw AArch32 / Thumb lifting
        |
        v
     Macaw IR
        |
        v
    Crucible                          (APTrace.SymbolicRunner, APTrace.ProtocolHarness)
        |
        v
     What4
        |
        v
   Z3 / solver
```

## Repository layout

```
aptrace/
  README.md                 -- entry point; see docs/ for everything else
  aptrace.cabal              -- the APTrace library + CLI, as a local cabal package
  src/APTrace/
    VectorTable.hs           -- ARMv7-M vector table parser
    FirmwareLoader.hs        -- raw firmware -> Macaw Memory (no ELF)
    SymbolicRunner.hs        -- one Macaw block -> Crucible -> What4/Z3
    ProtocolHarness.hs       -- whole-function Crucible execution + diagnostics
  app/Main.hs                -- CLI entry point (see docs/toolchain.md for usage)
  tools/vector_scan.py       -- standalone Python vector-table scanner/validator
  external/macaw/            -- GaloisInc/macaw, vendored as described in docs/toolchain.md
  docs/                       -- current, authoritative documentation (this tree)
  research/
    firmware/originals/      -- copies of the AutoPilot/Mando firmware images + hashes
    autopilot_static_inventory/  -- raw static RE research artifacts (see docs/protocol/)
    runs/                    -- saved raw tool output from real runs
```
