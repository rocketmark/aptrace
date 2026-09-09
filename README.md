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

| Tool | Role | Status |
|---|---|---|
| Ghidra | Static RE: decompiler, cross-references, structure/table recovery, MMIO naming | Integrated |
| Macaw | Independent control-flow recovery and Thumb-2 lifting | In use |
| Unicorn | Cheap concrete execution and memory-state snapshotting | Integrated |
| Crucible + What4 + Z3 | Targeted symbolic reachability and input-solving | In use |
| APTrace | Orchestration, evidence model, scenarios, traces, UI | This repo |

**Read [`docs/tooling/tool-selection.md`](docs/tooling/tool-selection.md)
before doing firmware-analysis work** — it covers which tool to reach for
and why (short version in [`CLAUDE.md`](CLAUDE.md)). See
[`docs/architecture.md`](docs/architecture.md) for the full picture.

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

**ATSAMD51J19A / Cortex-M4F** (Microchip; exact part confirmed by physical
board inspection — see [`docs/hardware/`](docs/hardware/)), Arduino +
Adafruit SAMD bootloader lineage. The application image is flashed behind
a 16KB bootloader and loaded starting at flash offset **`0x4000`**.
Details, vector table, and memory map:
[`docs/firmware/firmware-layout.md`](docs/firmware/firmware-layout.md).
Real peripheral/register naming for raw MMIO addresses (via the
ATSAMD51J19A SVD) and a first hardware-grounded peripheral survey:
[`docs/investigations/samd51-peripheral-mapping.md`](docs/investigations/samd51-peripheral-mapping.md).

## What tools are currently in use?

Ghidra (static RE, via Homebrew), Unicorn (concrete execution, via a
pinned Python venv), Macaw (discovery/lifting), Crucible (symbolic
execution), What4/Z3 (solving) — the latter three via git submodules
pinned to known-good versions, built with GHC 9.6.7. Run
[`tools/doctor.sh`](tools/doctor.sh) to verify all four are usable. Full
build/usage instructions: [`docs/toolchain.md`](docs/toolchain.md).

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
- The `&` branch above independently reproduced two more ways: concretely
  (Unicorn) and via static cross-reference (Ghidra), agreeing with the
  solver result. See
  [`docs/tooling/tool-selection.md`](docs/tooling/tool-selection.md).
- **The full AutoPilot-only milestone (M1) is complete** at the concrete
  (Unicorn) evidence tier: a real `&|` packet, through the unmodified
  dispatcher, sets `pending[5]`, and the real outbound TX hook emits
  exactly `V01R39`. See
  [`docs/investigations/tx-hook-verification.md`](docs/investigations/tx-hook-verification.md).
- **The same transaction is now also confirmed from the Remote's own
  side**: real TX construction (`"&|"`) and real RX capture (`"V01R39"`
  copied into the Remote's own capture buffer), the first concrete
  execution of the Remote (`mando`) firmware. See
  [`docs/investigations/mando-first-execution.md`](docs/investigations/mando-first-execution.md).
- **The two firmwares are now connected through a harness-driven virtual
  RF link** (`tools/unicorn/virtual_link.py`, no LoRa/SPI hardware
  modeled): Remote sends `"&|"`, the harness transfers the exact bytes,
  AutoPilot parses it and produces `"V01R39"`, the harness transfers the
  exact bytes back, Remote captures exactly `"V01R39\0"` — one script, one
  round trip, both real firmwares. This closes roadmap M3. See
  [`docs/investigations/virtual-rf-link.md`](docs/investigations/virtual-rf-link.md).
- **A second transaction, `G -> #`, confirms the virtual link generalizes**
  (roadmap M4): Remote's real `G<d><d><seq>|` request, AutoPilot
  concretely scheduling event 17 (not just solver-confirmed
  reachability), AutoPilot's real `"#"` response, and Remote's real
  retry/ack path accepting it — `tools/unicorn/virtual_link.py g`. See
  [`docs/investigations/g-ack-roundtrip.md`](docs/investigations/g-ack-roundtrip.md).
- **A third transaction, `S -> P...`, closes both response forms**
  (roadmap M4): Remote's real `"S|"` query, AutoPilot concretely
  scheduling event 6 and computing the response's first field in the same
  handler pass, and both the short (`"P1,"`) and extended (`"P11,0,0,"`)
  forms exercised concretely — `tools/unicorn/virtual_link.py s`. Found a
  real "don't downgrade" guard in the Remote's own parser by running it.
  See [`docs/investigations/s-p-roundtrip.md`](docs/investigations/s-p-roundtrip.md).

Full current-state detail: [`docs/project-status.md`](docs/project-status.md).

## What is the next milestone?

**M6 (in progress)**: a deliberate pivot from protocol mapping to
hardware provenance — `command/state -> internal variable/function ->
timer/MMIO -> ISR/GPIO -> MCU pin -> physical hardware behavior`. The
motor-timer survey is done: TC0-TC3 (IRQ107-110) each clear their own
interrupt flags and reach a shared, table-indexed GPIO-pulse mechanism,
structurally distinct from the already-proven TCC1 -> PB22 case — see
[`docs/investigations/motor-timer-survey.md`](docs/investigations/motor-timer-survey.md).
The per-channel pin index is now also resolved (TC0->PB10, TC1->PA08,
TC2->PB12, TC3->PA10 — a compile-time `.data`-segment fact, not
application-written) — see
[`docs/investigations/pin-index-provenance.md`](docs/investigations/pin-index-provenance.md).
`I<channel><mode>|` is now traced into that chain, meet-in-the-middle:
the command handler's own per-channel rate-update gate both conditionally
triggers a direct `step_delta` direction-sign write and independently
gates whether the ramp logic ever reaches the real timer/GPIO chain — see
[`docs/investigations/i-command-motor-chain.md`](docs/investigations/i-command-motor-chain.md).
What sets that gate nonzero was searched for exhaustively and not found
by any static method — see
[`docs/investigations/channel-busy-gate-search.md`](docs/investigations/channel-busy-gate-search.md).
Two concrete follow-ups diagnosed and resolved the suspected timing gaps
(new `--fake-tick`/`--mmio-force-bits`/`--mmio-clear-bits` Unicorn
capabilities) and got a real, unmodified concrete run all the way from
`Reset_Handler` through real clock init, a real SERCOM/DMA driver
constructor, and real homing — see
[`docs/investigations/systick-tick-injection.md`](docs/investigations/systick-tick-injection.md)
and
[`docs/investigations/reset-handler-clock-init.md`](docs/investigations/reset-handler-clock-init.md).
That "extra tick-time" past homing turned out not to be a timing gap at
all: tracing the real post-homing call graph found a real SPI
chip-ID probe (matching the well-known SX127x LoRa `RegVersion` check)
that genuinely fails with no chip attached, sending the firmware into
its own real, infinite retry loop — correctly identified and left
unfaked, a real hardware boundary rather than something to model past.
See
[`docs/investigations/post-homing-radio-probe.md`](docs/investigations/post-homing-radio-probe.md).
Confirmed no software bypass exists, then got past that boundary
honestly with the narrowest possible disclosed assumption (a new
`--force-reg` capability, fabricating one register value at one exact
instruction, explicitly labeled every time as harness-supplied
external-device state, not observed) — **a real concrete run now reaches
the real, stable main loop**, with `0x20001b14` still unwritten by idle
execution alone and the real inbound-command injection point identified
for a follow-on slice. See
[`docs/investigations/post-probe-main-loop.md`](docs/investigations/post-probe-main-loop.md).
That injection point is now used: a real `G<d><d><seq>|` was delivered
end to end through the real RX ring, real parser, and real dispatcher
(a new `--force-mem` capability, plus a `--fake-tick` recalibration after
diagnosing a real per-byte radio-poll-vs-inter-byte-timeout collision) —
and it uncovered the real reason `0x20001b14` never moves: the whole
motor-phase/ramp/monitor subsystem is not reachable from a cold boot at
all. The real, currently-running main loop lives entirely inside a
different function that never returns; the one real unlock traces,
via an exhaustive literal-pool scan, to exactly one command —
`MC4<...>|` (motor configuration, all four channels). See
[`docs/investigations/g-command-motor-subsystem-unlock.md`](docs/investigations/g-command-motor-subsystem-unlock.md).
That unlock is now confirmed concretely: a real `MC4` frame delivered
through the same real RX path hands control to the real operational main
loop, and — sequenced with a real `G` — the real motor "commit a move"
function (`FUN_00006fd8`) fires for the first time in this project.
`0x20001b14` still doesn't move; this run's own register-captured
`distance=0` explains why, via `FUN_00006fd8`'s own documented no-op
branch, not a missing mechanism. See
[`docs/investigations/mc4-transition.md`](docs/investigations/mc4-transition.md).
Tracing that `distance=0` further found the real reason it can never
currently be otherwise: the motor target/position config is bulk-loaded
from a compiled-in default-configuration blob at a specific flash
address, and that blob is genuinely blank in this firmware image
(confirmed by reading the raw `.bin` directly) — a real external-data
provisioning boundary, the same evidence class as the unmodeled radio-ID
chip, not a missing mechanism. Exhaustively trying every legal value of
the command's own "type" digit confirms `distance` is always `0` or
`-1`, never enough to cross the real move threshold. See
[`docs/investigations/target-config-provenance.md`](docs/investigations/target-config-provenance.md).
`!`/`I`'s own protocol transactions remain queued for whenever M4
resumes. Full roadmap:
[`docs/harness/roadmap.md`](docs/harness/roadmap.md).

## Where should a new developer read next?

1. [`docs/project-status.md`](docs/project-status.md) — current state,
   blockers, next steps. Start here.
2. [`docs/tooling/tool-selection.md`](docs/tooling/tool-selection.md) —
   which analysis tool to reach for and why. Read before doing any
   firmware-analysis work (see [`CLAUDE.md`](CLAUDE.md)).
3. [`docs/architecture.md`](docs/architecture.md) — what APTrace is and the
   workbench direction.
4. [`docs/toolchain.md`](docs/toolchain.md) — build and run it.
5. [`docs/firmware/`](docs/firmware/) — the target firmware itself.
6. [`docs/hardware/`](docs/hardware/) — the physical boards/MCUs the
   firmware runs on (board photos, part numbers, pinout/wiring notes from
   the user manual) — external, hardware-side research, not derived from
   the firmware binaries themselves.
7. [`docs/protocol/`](docs/protocol/) — the protocol being reverse-engineered.
8. [`docs/harness/`](docs/harness/) — how the symbolic-execution harness
   works and what it's found.
9. [`docs/investigations/`](docs/investigations/) — deep dives on specific
   open questions.
10. [`docs/history/`](docs/history/) — superseded material, kept for
    provenance only.

## Repository layout

```
aptrace/
  README.md                 -- this file
  CLAUDE.md                  -- mandatory operating rules for Claude Code sessions
  docs/                      -- current, authoritative documentation (see above)
    tooling/                 -- tool-selection.md and per-backend usage docs
    hardware/                -- physical board/MCU research (photos, manual, pinouts)
  aptrace.cabal              -- the APTrace library + CLI, as a local cabal package
  src/APTrace/
    VectorTable.hs           -- ARMv7-M vector table parser
    FirmwareLoader.hs        -- raw firmware -> Macaw Memory (no ELF)
    SymbolicRunner.hs        -- single-block Macaw -> Crucible -> What4/Z3
    ProtocolHarness.hs       -- whole-function execution against the protocol dispatcher
  app/Main.hs                -- CLI entry point
  tools/
    vector_scan.py           -- standalone Python vector-table scanner/validator
    doctor.sh                -- verifies Ghidra/Unicorn/Macaw-Crucible-What4-Z3 are usable
    ghidra/                  -- headless Ghidra integration
    unicorn/                 -- concrete-execution backend (pinned venv);
                                 virtual_link.py orchestrates it into the
                                 cross-firmware virtual RF link
    svd/                     -- ATSAMD51J19A SVD file + MMIO address resolver
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
