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
and [`docs/investigations/symbolic-execution-results.md`](investigations/symbolic-execution-results.md)
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

## Tool roles

See [`docs/tooling/tool-selection.md`](tooling/tool-selection.md) for the
full decision guidance (when to use which, worked examples, evidence
levels, anti-patterns) — this table is a summary.

| Tool | Role | Status |
|---|---|---|
| **Ghidra** | Static RE / decompiler / cross-references / data structure and table recovery / naming MMIO registers and globals | Integrated — [`docs/tooling/ghidra-backend.md`](tooling/ghidra-backend.md) |
| **Macaw** | Independent machine-code control-flow recovery and Thumb-2 lifting | In use, proven (see `docs/firmware/cortexm-assessment.md`) |
| **Unicorn** | Fast concrete Thumb execution and state snapshotting — run firmware to a checkpoint cheaply, then hand a concrete state to the symbolic side | Integrated — [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md) |
| **Crucible + What4 + Z3** | Targeted symbolic reachability and input-value solving, once the question and the relevant code region are well understood | In use, proven |
| **APTrace** | Orchestration: evidence model, scenario definitions, trace capture, and (eventually) a UI/workbench tying the above together | This repo |

The orchestration/evidence-model/UI layer beyond what's described in
`docs/tooling/` is still just this table — not yet built.

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
  CLAUDE.md                  -- mandatory operating rules for Claude Code sessions
  aptrace.cabal              -- the APTrace library + CLI, as a local cabal package
  src/APTrace/
    VectorTable.hs           -- ARMv7-M vector table parser
    FirmwareLoader.hs        -- raw firmware -> Macaw Memory (no ELF)
    SymbolicRunner.hs        -- one Macaw block -> Crucible -> What4/Z3
    ProtocolHarness.hs       -- whole-function Crucible execution + diagnostics
    MacawCensus.hs, MacawExpand.hs, MacawIsaClassify.hs, MacawNormalize.hs
                             -- Macaw static-discovery pipeline (docs/tooling/macaw-analysis.md)
    DebugHarness.hs          -- experimental crucible-debug prototype
    Case/                    -- Performing Rigs case code (below)
  app/Main.hs                -- CLI entry point (see docs/toolchain.md for usage)
  tools/
    vector_scan.py           -- standalone Python vector-table scanner/validator
    doctor.sh                -- verifies Ghidra/Unicorn/Macaw-Crucible-What4-Z3 are usable
    ghidra/                  -- headless Ghidra integration (see docs/tooling/ghidra-backend.md)
    unicorn/                 -- concrete-execution backend (see docs/tooling/unicorn-backend.md)
    census/                  -- aptrace census evidence database (docs/tooling/census.md)
    case/                    -- Performing Rigs case config (below)
  external/macaw/            -- GaloisInc/macaw, vendored as described in docs/toolchain.md
  docs/                       -- current, authoritative documentation (this tree)
    tooling/                 -- tool-selection.md and per-backend usage docs
    investigations/          -- Performing Rigs case/research dossiers
  research/
    firmware/originals/      -- copies of the AutoPilot/Mando firmware images + hashes
    autopilot_static_inventory/  -- raw static RE research artifacts (see docs/protocol/)
    runs/                    -- saved raw tool output from real runs (incl. runs/ghidra/)
```

## Framework / case split

Reusable framework/tooling code carries no Performing Rigs-specific
knowledge and must not import case code; Performing Rigs case code may
depend on framework code, never the reverse:

- `src/APTrace/Case/PerformingRigs.hs` -- the single authoritative
  definition of the AutoPilot/Remote target's RAM base/size, IRQ vector
  count, and default flash base. Framework modules that need this
  geometry (`APTrace.MacawCensus`, `APTrace.MacawExpand`,
  `APTrace.DebugHarness`) take it as parameters instead of hardcoding it.
- `src/APTrace/Case/PerformingRigsScenarios.hs` -- Performing Rigs
  AutoPilot-specific investigation scenarios (`aptrace solve`/`protocol`/
  `trigger`/`trigger-crosscheck`), hardcoding real, discovered flash/RAM
  addresses. `app/Main.hs` is the only place both framework and case
  modules are wired together, which is expected for a CLI entry point.
- `tools/case/performing_rigs.py` -- the known firmware image registry
  (`FIRMWARE_REGISTRY`) and this target's RAM/MMIO geometry, imported by
  `tools/ghidra/aptrace_ghidra.py` and `tools/census/build.py` rather than
  hardcoded inside them.
- `docs/investigations/` holds Performing Rigs case/research dossiers;
  `docs/tooling/` and `docs/harness/execution-model.md` hold framework/
  tooling documentation describing reusable mechanisms, not one
  firmware's results.

**Known remaining coupling, not yet cleaned up**: this target's RAM
geometry (`0x20000000`/`0x30000`) is still independently duplicated as
inline CLI-argument defaults in several `tools/unicorn/*.py` scripts
(`concrete.py`, `run_concrete.py`, `virtual_link.py`,
`trigger_mitigation_prototype.py`, `trigger_transient_propagation.py`)
and `tools/census/state_map.py`, rather than importing it from
`tools/case/performing_rigs.py`. `tools/census/hardware_contract.py`
also decodes ATSAMD51-specific peripheral register fields in code that
borders on census/schema semantics. Both are real, bounded follow-ups,
not attempted in the pass that established the `Case`/`case` boundary
above.
