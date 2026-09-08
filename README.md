# APTrace

## What is APTrace?

A bare-metal Cortex-M firmware analysis tool built around the GaloisInc
[Macaw](https://github.com/GaloisInc/macaw) /
[Crucible](https://github.com/GaloisInc/crucible) /
[What4](https://github.com/GaloisInc/what4) stack: raw firmware in, a
Macaw-recovered control-flow graph, and targeted symbolic-execution queries
("what input reaches this address / sets this memory location?") answered
by Z3. It reuses that existing open-source RE/symbolic-execution stack
rather than writing a new one.

The project is moving toward being a **workbench** — orchestrating several
purpose-built tools rather than reimplementing what they already do well:

| Tool | Role |
|---|---|
| Ghidra | Static RE: decompiler, cross-references, structure/table recovery, MMIO naming |
| Macaw | Independent control-flow recovery and Thumb-2 lifting |
| Unicorn | Cheap concrete execution and memory-state snapshotting |
| Crucible + What4 + Z3 | Targeted symbolic reachability and input-solving |
| APTrace | Orchestration, evidence model, scenarios, traces, UI |

See [`docs/architecture.md`](docs/architecture.md) for the full picture and
[`docs/project-status.md`](docs/project-status.md)'s "explicit
do-not-start-yet items" for why Ghidra/Unicorn integration hasn't started
yet.

## What problem is it solving?

Reverse-engineering the bidirectional RF command protocol between a
Performing Rigs **AutoPilot** motion-control unit and its **Remote**
control, from firmware images alone — with claims backed by solver
evidence ("this exact byte value is required to reach this code") rather
than only by reading disassembly and reasoning by inspection.

## What firmware are we analyzing?

Performing Rigs **AutoPilot** and **Remote** firmware images. See
[`docs/firmware/firmware-inventory.md`](docs/firmware/firmware-inventory.md)
for the exact files and hashes.

## What MCU/platform is confirmed?

**ATSAMD51 / Cortex-M4F** (Microchip), Arduino + Adafruit SAMD bootloader
lineage. The application image is flashed behind a 16KB bootloader and
loaded starting at flash offset **`0x4000`**. Details, vector table, and
memory map: [`docs/firmware/firmware-layout.md`](docs/firmware/firmware-layout.md).

## What tools are currently in use?

Macaw (discovery/lifting), Crucible (symbolic execution), What4/Z3
(solving) — all via git submodules pinned to known-good versions, built
with GHC 9.6.7. Full build/usage instructions:
[`docs/toolchain.md`](docs/toolchain.md).

## What has been proven so far?

- Raw firmware loading, vector-table parsing, Thumb-2 lifting, Macaw CFG
  recovery, Crucible execution, and What4/Z3 solving against a real
  memory-mapped peripheral — all demonstrated on real, unmodified AutoPilot
  firmware ([`docs/harness/symbolic-execution-results.md`](docs/harness/symbolic-execution-results.md)).
- Four single-character protocol commands solver-confirmed against the real
  compiled dispatcher: `&` → `0x26`, `G` → `0x47`, `!` → `0x21`, `S` →
  `0x53`, each required to reach its real handler block
  ([`docs/harness/protocol-harness-results.md`](docs/harness/protocol-harness-results.md)).
- `&` additionally confirmed (by inspection of the reached handler) to write
  `pending[5]=1`, which is the AutoPilot's firmware-version-response event.

Full current-state detail: [`docs/project-status.md`](docs/project-status.md).

## What is the current blocker?

Replaying the **whole** dispatcher function (not just one isolated block)
against a real in-memory `&` packet does not terminate. The cause has been
narrowed to a memory-side-effect modeling gap: two called functions
(`0x5274`/`0x5448`) are currently stubbed with no memory writes, and the
loop they're called from likely depends on a write one of them makes to
know when to stop. Full diagnosis:
[`docs/harness/protocol-harness-results.md`](docs/harness/protocol-harness-results.md);
the fix under consideration: [`docs/harness/execution-model.md`](docs/harness/execution-model.md).

## What is the next milestone?

**M1**: complete the AutoPilot-only transaction end to end — a real `&`
packet, run through the unmodified dispatcher, sets `pending[5]`, and the
outbound hook at `0x8c10`/`0x7f84` emits `V01R39`. **Do not move to the
Remote firmware before this works.** Full roadmap:
[`docs/harness/roadmap.md`](docs/harness/roadmap.md).

## Where should a new developer read next?

1. [`docs/project-status.md`](docs/project-status.md) — current state,
   blockers, next steps. Start here.
2. [`docs/architecture.md`](docs/architecture.md) — what APTrace is and the
   workbench direction.
3. [`docs/toolchain.md`](docs/toolchain.md) — build and run it.
4. [`docs/firmware/`](docs/firmware/) — the target firmware itself.
5. [`docs/protocol/`](docs/protocol/) — the protocol being reverse-engineered.
6. [`docs/harness/`](docs/harness/) — how the symbolic-execution harness
   works and what it's found.
7. [`docs/investigations/`](docs/investigations/) — deep dives on specific
   open questions.
8. [`docs/history/`](docs/history/) — superseded material, kept for
   provenance only.

## Repository layout

```
aptrace/
  README.md                 -- this file
  docs/                      -- current, authoritative documentation (see above)
  aptrace.cabal              -- the APTrace library + CLI, as a local cabal package
  src/APTrace/
    VectorTable.hs           -- ARMv7-M vector table parser
    FirmwareLoader.hs        -- raw firmware -> Macaw Memory (no ELF)
    SymbolicRunner.hs        -- single-block Macaw -> Crucible -> What4/Z3
    ProtocolHarness.hs       -- whole-function execution against the protocol dispatcher
  app/Main.hs                -- CLI entry point
  tools/vector_scan.py       -- standalone Python vector-table scanner/validator
  external/macaw/            -- GaloisInc/macaw, with crucible/what4/semmc/dismantle/
                                 asl-translator/arm-asl-parser as git submodules
  research/
    firmware/originals/           -- copies of the AutoPilot/Remote firmware images + SHA256SUMS.txt
    autopilot_static_inventory/   -- raw/derived static RE artifacts (see docs/protocol/ for curated view)
    runs/                          -- saved tool output from real runs
```

Original firmware images live untouched in `Autopilot_firm/` at the repo
root (not under `research/`); `research/firmware/originals/` holds working
copies plus recorded hashes. Proprietary firmware binaries are not intended
to be published outside this local checkout.
