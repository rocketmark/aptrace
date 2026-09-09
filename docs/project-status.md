# APTrace — Project Status

**This is the single authoritative source for current project state.** If
anything elsewhere in the repo conflicts with this document, this document
wins — and if you find such a conflict, it's a bug in the docs; fix it here.
Historical detail lives in linked docs, not here — this file stays short by
design.

Last updated: 2026-09-08 (traced the motor target/position config to a compiled-in default-configuration blob that is genuinely blank in this firmware image — a real external-data boundary, not a missing mechanism).

**Before doing firmware-analysis work, read
[`docs/tooling/tool-selection.md`](tooling/tool-selection.md)** (short
version: [`CLAUDE.md`](../CLAUDE.md)) for which of Ghidra/Unicorn/Macaw/
Crucible to reach for.

## Current milestone

**Goal**: one complete AutoPilot-only transaction, verified through
APTrace's own pipeline:

```
wire command "&|"
    -> real receive/parser path (unmodified compiled firmware)
    -> event 5 scheduled
    -> outbound TX hook (0x8c10 / 0x7f84)
    -> observed string == "V01R39"
```

**Status: COMPLETE at the concrete (Unicorn) evidence tier, end to end.**
As of 2026-09-07, every stage of the chain above has been independently,
concretely demonstrated against real, unmodified firmware, entering at
real call sites with the firmware establishing its own state (not
hand-picked to make the answer come out right):

1. `&|` → `pending[5]=1`: entering at the real caller (`0x8a34`) with a
   real `&|` packet, `pending[5]` becomes `1` in 46 instructions. See
   [`docs/investigations/dispatcher-loop-concrete-trace.md`](investigations/dispatcher-loop-concrete-trace.md).
2. `pending[5]=1` → TX hook → `"V01R39"`: the real, unmodified outbound
   dispatcher (`0x9268`) consumes event 5 and calls the real TX hook
   (`0x8c10`) with a pointer to a buffer holding exactly `"V01R39\0"` —
   independently confirmed to be what a real, unconditional startup
   routine (`FUN_00004328`) writes there before the main loop ever runs.
   See [`docs/investigations/tx-hook-verification.md`](investigations/tx-hook-verification.md).

Per [`docs/tooling/tool-selection.md`](tooling/tool-selection.md)'s
evidence levels, this is **level 2** (concretely executed) across the
whole chain. A **level 3** (solver-confirmed, Crucible/What4/Z3) proof of
the *whole* chain in one run remains blocked by a known, deliberately
unfixed tooling gap — see "Tooling gaps," not a firmware blocker. Individual
pieces of the chain (e.g. the `&` character check itself) already have
independent level-3 confirmation.

**Note on the command itself**: `&|` is the wire-level frame the Remote
transmits (`|` is the frame terminator). The dispatcher's first-byte check
requires exactly `0x26` ('&') at flash `0x888c` — solver-confirmed
(level 3) — and the full `&|` frame reaching that check, and the full
onward path to `"V01R39"`, has now also been demonstrated concretely
(level 2, above).

**Remote (`mando`) firmware**: first concrete execution (2026-09-08), then
a full harness-driven virtual RF link (2026-09-08) closing roadmap M3
entirely at the concrete evidence tier. Ghidra's existing pipeline loads/
discovers Mando cleanly with zero platform-specific changes (563
functions; every previously-named Remote function of interest resolves
at its documented address). The complete `&|` -> `V01R39` round trip now
runs as **one harness-driven script** (`tools/unicorn/virtual_link.py`),
not two hand-run scenarios: Remote's real `0xba98` computes `"&|"` and
calls its real TX wrapper; the harness transfers those exact bytes (no
radio modeled) into AutoPilot's real RX buffer; AutoPilot's real
dispatcher schedules event 5 and its real outbound dispatcher builds
`"V01R39"`; the harness transfers those exact bytes into Remote's real RX
ring buffer; Remote's real collection loop captures exactly `"V01R39\0"`.
See [`docs/investigations/mando-first-execution.md`](investigations/mando-first-execution.md)
for the per-firmware proofs and the honest boundary found (both firmwares
gate real RF I/O behind an unmodeled driver layer — reaching past it
needed the `--stub-call` Unicorn capability, not full radio emulation),
and [`docs/investigations/virtual-rf-link.md`](investigations/virtual-rf-link.md)
for the round trip itself and the two reusable primitives
(`capture_tx_bytes`/`deliver_and_observe`) it's built from. A second
transaction, `G -> #` (roadmap M4), closed the same way immediately
afterward (2026-09-08), confirming the primitives generalize — see
[`docs/investigations/g-ack-roundtrip.md`](investigations/g-ack-roundtrip.md).
A third, `S -> P...`, closed the same day (2026-09-08) at *both* its
response forms — see
[`docs/investigations/s-p-roundtrip.md`](investigations/s-p-roundtrip.md)
— after which the project deliberately paused protocol-transaction work
to pivot toward hardware provenance (see "Next steps").

## Proven capabilities & findings

Demonstrated on real, unmodified firmware; safe to build on without
re-proving:

- **Target/platform**: Performing Rigs AutoPilot/Remote firmware on
  Microchip/Atmel **ATSAMD51J19A** (Cortex-M4F, 512KB flash, 192KB SRAM —
  exact part confirmed by physical board inspection, not inferred),
  Arduino/Adafruit SAMD lineage, app image loaded at flash `0x4000`.
  Hashes: [`docs/firmware/firmware-inventory.md`](firmware/firmware-inventory.md).
  Layout/vector table: [`docs/firmware/firmware-layout.md`](firmware/firmware-layout.md).
  Hardware/board-level research:
  [`docs/hardware/autopilot-research-handoff.md`](hardware/autopilot-research-handoff.md).
- **Macaw pipeline**: raw `.bin` loading (no ELF), vector-table parsing,
  Thumb-2 lifting (zero decode failures across ~1500 real instructions),
  and CFG discovery from arbitrary seeded entry points — used to seed the
  protocol dispatcher directly.
- **Crucible execution infrastructure works** at both granularities:
  single-block (`APTrace.SymbolicRunner.checkBranchModel`) and
  whole-function (`APTrace.ProtocolHarness.runPacketTransaction`) — i.e.
  the lift-to-Crucible-to-What4/Z3 machinery runs correctly in general.
  **A whole-function solver-confirmed replay of the full `&`-command
  dispatcher specifically is still blocked by a known, documented, and
  deliberately unfixed tooling gap — see "Tooling gaps," not a claim
  about the firmware.**
- **Solver-confirmed single-block protocol checks** (not hand-derived): a
  register holding the packet's first byte, checked against each command's
  real comparison instruction, reaches the correct handler exactly at that
  command's ASCII value:

  | Command | Solver-confirmed value | Check block |
  |---|---|---|
  | `&` | `0x26` | `0x888c` -> `0x8890` |
  | `G` | `0x47` | `0x83b2` -> `0x83b6` |
  | `!` | `0x21` | `0x87b2` -> `0x87b6` |
  | `S` | `0x53` | `0x87be` -> `0x87c2` |

  See [`docs/harness/protocol-harness-results.md`](harness/protocol-harness-results.md).
- **The real caller into the protocol dispatch region**: `0x8a34 -> 0x8259`
  (Macaw-call-classified `BL`, not a tail-jump). See
  [`docs/investigations/trigger-input.md`](investigations/trigger-input.md).
- **A real calling-convention bug, fixed**: the opaque function-call
  override used to clobber *every* register (including AAPCS callee-saved
  R4-R11), corrupting a loop's own counter/table-pointer state and
  producing a hang that looked like firmware complexity. Fixed to only
  substitute the genuinely caller-saved registers (R0-R3, R12). See
  [`docs/harness/execution-model.md`](harness/execution-model.md).
- **A reusable diagnostic**: `APTrace.ProtocolHarness.debugFeature`, a
  Crucible `ExecutionFeature` that logs the visited program location every
  N steps — turns an opaque hang into "stuck cycling through X, Y, Z."
  Reuse it whenever a whole-function run doesn't terminate as expected.
- **Ghidra headless static analysis** integrated
  (`tools/ghidra/analyze_firmware.sh`, Thumb-only `ARM:LE:32:Cortex`,
  vector-table entry seeding): 414 functions discovered on real firmware
  (vs. 204 unseeded), including the dispatcher region. See
  [`docs/tooling/ghidra-backend.md`](tooling/ghidra-backend.md).
- **Unicorn concrete execution** integrated (`tools/unicorn/run_concrete.py`,
  Cortex-M4 model): concretely running from `0x888c` with `r3=0x26`
  reproduces the solver-confirmed `&` -> `0x8890` branch exactly. See
  [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **`--watch`/`--watch-mem`** added to the Unicorn backend: records full
  register/memory state at multiple addresses across one run without
  halting (unlike `--stop-at`) — needed for a per-iteration loop trace. See
  [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **`--watch-mem-write`** added to the Unicorn backend: a true memory
  watchpoint (fires on any write landing in an address range, regardless
  of which instruction performs it) rather than `--watch`'s code-address
  trigger — for exactly the case where a static xref search finds no
  writer and the question is whether a computed/indirect store reaches a
  RAM address at all. First used in
  [`docs/investigations/channel-busy-gate-search.md`](investigations/channel-busy-gate-search.md).
  See [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **`--fake-tick` added to the Unicorn backend**: a narrow,
  instruction-count-paced increment of a *firmware-maintained tick
  variable* (identified first, not assumed) — deliberately not a
  SysTick/timer peripheral model. Used to get a real concrete run past
  `FUN_00006968`'s homing-timeout wait; results obtained this way are
  documented as "firmware behavior observed after time was advanced by
  the harness," not "real hardware timing modeled." See
  [`docs/investigations/systick-tick-injection.md`](investigations/systick-tick-injection.md)
  and [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **`--mmio-force-bits`/`--mmio-clear-bits`/`--map-page` added to the
  Unicorn backend**: explicit, address-scoped hooks that force a named
  MMIO register's bits set or clear on every read (never on a write,
  never on a timer), for a real, SVD-identified completion/self-clearing
  bit the zero-behavior model otherwise leaves permanently wrong —
  plus a minimal facility to map one extra fixed page (e.g. the SAMD51
  NVM calibration row) outside flash/RAM/MMIO. Not a peripheral model —
  each address is named and justified individually. Used to run
  `Reset_Handler`'s real clock-init chain and a real SERCOM/DMA driver
  constructor to completion for the first time. See
  [`docs/investigations/reset-handler-clock-init.md`](investigations/reset-handler-clock-init.md)
  and [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **`--force-reg` added to the Unicorn backend**: fabricates one
  register's value at one exact instruction — deliberately a different,
  stricter-disclosure mechanism than `--mmio-force-bits`/
  `--mmio-clear-bits` (which model documented MCU-internal silicon
  behavior; this stands in for something genuinely external, like an
  attached device's response, that the harness has no way to know).
  Scoped to a single program point (the instruction after one specific
  call site returns), not a callee's every invocation. First and only
  use so far: one SPI chip-ID read result, disclosed as harness-supplied
  external-device state every time it's mentioned. See
  [`docs/investigations/post-probe-main-loop.md`](investigations/post-probe-main-loop.md)
  and [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **The real `&|` -> `pending[5]=1` transaction, concretely demonstrated**:
  entering at the real caller (`0x8a34`), letting the firmware establish
  its own entry state (not manually seeded), with a real `&|` packet in the
  buffer — `pending[5]` becomes `1` in 46 instructions. See
  [`docs/investigations/dispatcher-loop-concrete-trace.md`](investigations/dispatcher-loop-concrete-trace.md).
- **`tools/doctor.sh`** verifies Ghidra, Unicorn, and Macaw/Crucible/What4/Z3
  are all usable, including functional smoke tests.
- **`APTrace.ProtocolHarness.RichTraceConfig`/`runPacketTransactionTraced`**:
  a reusable, fine-grained (every-step, not sampled) execution trace for a
  bounded address range within a whole-function run, using the existing
  `Data.Macaw.Symbolic.Regs.simStateRegs` API to recover live register
  state. What found the readonly-flash root cause — see "Tooling gaps."
  See [`docs/investigations/whole-function-trace-divergence.md`](investigations/whole-function-trace-divergence.md).
- **The real `pending[5]=1` -> TX hook -> `"V01R39"` transaction, concretely
  demonstrated**: the real, unmodified outbound dispatcher (`0x9268`)
  consumes event 5 (`pending[5]` observed going `1` -> `0`) and calls the
  real TX hook (`0x8c10`) with a pointer to a buffer independently
  confirmed to hold exactly `"V01R39\0"` — written there unconditionally
  by a real startup routine (`FUN_00004328`), not seeded to force the
  answer. Combined with the `&|` -> `pending[5]=1` result above, this
  closes the full AutoPilot milestone at the concrete evidence tier. See
  [`docs/investigations/tx-hook-verification.md`](investigations/tx-hook-verification.md).
- **Real ATSAMD51J19A peripheral/register naming for raw MMIO addresses**:
  [`tools/svd/resolve_mmio.py`](../tools/svd/resolve_mmio.py), backed by
  the real vendor SVD file, plus `run_concrete.py --log-mmio` to capture
  what a concrete run actually touches. Used to confirm the full
  `Reset_Handler` startup peripheral-init chain (clock tree, analog block,
  WDT, PORT, TC0-TC3, TCC1, USB), and one fully-resolved pin-level fact:
  **PB22 is toggled from a real timer interrupt handler (IRQ93/TCC1)** —
  a named GPIO tied to already-understood firmware behavior, matching the
  hardware doc's "4 motor-output channels." Also produced an honest
  negative result: the outbound TX path (`0x9268`→`0x8c10`) touches no
  MMIO directly — its real transport peripheral is gated behind a runtime
  driver-object pointer, not a literal address, and naming it is the next
  slice, not done here. See
  [`docs/investigations/samd51-peripheral-mapping.md`](investigations/samd51-peripheral-mapping.md).
- **First concrete Mando (Remote) execution**: Ghidra discovery clean with
  no platform-specific changes; both halves of the `&|` -> `V01R39`
  round trip confirmed from the Remote's own side via Unicorn (real TX
  construction and real RX capture, in two separate runs mirroring the
  AutoPilot milestone's own two-step structure). Required a new
  `run_concrete.py --stub-call` capability (the Unicorn-side equivalent of
  Crucible's existing opaque function-call override) to get past a real,
  not-yet-modeled radio/SPI driver dependency — the same class of boundary
  already found on the AutoPilot's TX path. See
  [`docs/investigations/mando-first-execution.md`](investigations/mando-first-execution.md).
- **A full, harness-driven virtual RF link, both firmwares, one round
  trip**: `tools/unicorn/virtual_link.py` runs the complete `&|` ->
  `V01R39` transaction end to end — Remote's real TX call, a harness-
  mediated byte transfer (no radio modeled), AutoPilot's real dispatch
  and response, a second harness-mediated transfer, Remote's real
  capture — asserting the exact bytes at every step. Built from two
  reusable primitives (`capture_tx_bytes`, `deliver_and_observe`) that
  don't hardcode transaction content, only the already-proven RF-boundary
  addresses, so the same script structure applies to future transactions
  (`G -> #`, `S -> P...`). This closes roadmap M3. See
  [`docs/investigations/virtual-rf-link.md`](investigations/virtual-rf-link.md).
- **`G -> #` through the same virtual link (roadmap M4)**: confirms the
  M3 primitives genuinely generalize — `tools/unicorn/virtual_link.py g`
  runs Remote's real `G<d><d><seq>|` request (register-seeded call
  arguments, not just RAM), AutoPilot's real handler concretely
  scheduling event 17 (not just solver-confirmed *reachability* — a real
  first for this project), AutoPilot's real single-byte TX wrapper
  (`0x7f84`, a new `capture_tx_byte` primitive alongside the
  pointer-based `capture_tx_bytes`), and Remote's real retry/ack loop
  (`0xb59c`) accepting the real `"#"` byte (`R4` becomes `1`, its own
  genuine `int` return value). Needed two new `--stub-call` targets on
  the AutoPilot side for real-but-irrelevant helpers (one hits the same
  "driver object needs real startup" boundary already known from RF; one
  spins on what's plausibly persistent motor-config data, not yet
  investigated further). See
  [`docs/investigations/g-ack-roundtrip.md`](investigations/g-ack-roundtrip.md).
- **`S -> P...` through the same virtual link (roadmap M4), both response
  forms**: `tools/unicorn/virtual_link.py s` runs Remote's real `"S|"`
  query, AutoPilot's real handler concretely scheduling event 6 *and*
  computing the response's first field in the same pass (from a
  literal-pool-confirmed device-state variable, `0x20002524`), and
  Remote's real parser consuming and storing the result — at **both** the
  short (`"P1,"`) and extended (`"P11,0,0,"`) response forms, exercised
  concretely by seeding two different real device-state values rather
  than asserting one and trusting the decompile for the other. No new
  harness capability needed (first time since M3 that a transaction
  didn't need one). Found, by running it rather than by reading the
  decompile: a real "don't downgrade" guard in the Remote's parser (a
  fresh device receiving `"P1,"` does **not** update its stored state at
  all), and that the AutoPilot- and Remote-side conditions for the
  extended form (`docs/protocol/`'s existing description already named
  both) are the *same* variable by construction, not independently
  aligned. See
  [`docs/investigations/s-p-roundtrip.md`](investigations/s-p-roundtrip.md).
- **Motor-timer survey completed (roadmap M6)**: TC0/TC1/TC2/TC3 are
  IRQ107-110 (`0x607c`/`0x6098`/`0x60b4`/`0x60d0`), each clearing its own
  MC0+OVF interrupt flags then reaching a shared, table-indexed
  GPIO-pulse helper (`FUN_00005898`/`FUN_0000d388`) — a real, confirmed
  mechanism, structurally different from the already-proven TCC1 -> PB22
  case (inline toggle, no shared helper), and concretely exercised on all
  four channels via `run_concrete.py --log-mmio`. The rate-control
  mechanism fell out naturally: `FUN_00005c00`/`FUN_00006260` write/read
  each TC's `CC0` (period) with correct SYNCBUSY/RETRIGGER sequencing.
  **Honestly limited, not forced, at the time**: the real per-channel pin
  assignment depended on a RAM index byte per channel that pass found no
  static producer for — cold-RAM concrete execution gave the same pin
  (PA23) for all four channels, an artifact of uninitialized state, not a
  hardware fact, and was documented as exactly that rather than reported
  as a result. A genuine protocol-to-hardware link was found in passing:
  the event-15/`I`-command result value
  (`i32[0x20002064[channel]]`) is the *same* address as this mechanism's
  own step-position counter. See
  [`docs/investigations/motor-timer-survey.md`](investigations/motor-timer-survey.md).
- **Pin-index provenance resolved (roadmap M6)**: the per-channel
  pin-index bytes above (`0x20000164`-`0x20000167`) are not written by any
  application instruction — they are `.data`-segment initializers,
  compiled into flash and copied into RAM by `Reset_Handler`'s own
  startup copy loop (`0xcc24`-`0xcc70`), before any peripheral init runs.
  Read directly from the unmodified firmware image: **TC0 -> PB10, TC1 ->
  PA08, TC2 -> PB12, TC3 -> PA10** — a static (level-1), compiled-image
  fact, not a concrete-execution artifact, cross-validated against the
  already-proven PB22/TCC1 fact (table index 40 independently decodes to
  PB22 under the same group/pin scheme). Also ruled out, with evidence,
  as *not* the source: NVM/EEPROM-persisted config (real NVM flash-write
  helpers exist in this firmware but none reads config into this array)
  and board/runtime detection (nothing runs before the `.data` copy). See
  [`docs/investigations/pin-index-provenance.md`](investigations/pin-index-provenance.md).
- **`I<channel><mode>|` traced into the motor/timer chain, meet-in-the-
  middle (roadmap M6)**: the command handler's own `0x20001b14[channel]`
  gate conditionally calls `FUN_00005274`->`FUN_00004d18`, which writes
  `step_delta[channel]`'s direction sign — concretely validated with
  Unicorn (both branches of the gate exercised, matching the
  disassembly exactly). Independently, `FUN_00006338` (ramp/velocity
  logic) only forwards a rate update to the already-proven
  `FUN_00005ee8`->`FUN_00005c00`->`FUN_00005898` chain when that same
  gate is nonzero — the two directions of the meet-in-the-middle search
  converge on the identical byte. Also corrected the record: the
  handler's "`=5`" write is to `0x20002524[channel]`, not
  `0x20001b14[channel]` as an older static-inventory pass had it. See
  [`docs/investigations/i-command-motor-chain.md`](investigations/i-command-motor-chain.md).
- **`0x20001b14[channel]`'s producer searched exhaustively — a genuine
  negative result (roadmap M6)**: a dedicated follow-up
  ([`docs/investigations/channel-busy-gate-search.md`](investigations/channel-busy-gate-search.md))
  checked all 12 direct-reference functions, 7 one-hop candidates
  (including the two originally suspected, `FUN_00006fd8` and
  `FUN_00008e18`), the complete one-time-init boot chain, and every
  literal-referenced global packed around the byte (ruling out a
  computed-offset alias) — no setter found by any static method. Also
  confirmed the byte is `.bss` (cold value `0`, not a fixed nonzero
  startup constant, unlike the pin-index bytes) and resolved a
  decompiler artifact by disassembly along the way. Added a genuine
  Unicorn memory watchpoint (`--watch-mem-write`, new in
  `tools/unicorn/run_concrete.py`) and used it for a partial concrete
  confirmation.
- **A concrete follow-up ran past the homing timeout, then hit a
  different real dependency (roadmap M6)**: the elapsed-time source was
  diagnosed precisely (a firmware-maintained tick RAM variable, not a
  SysTick register) and resolved with a new, narrow `--fake-tick`
  capability, plus one disclosed real-GPIO-input boundary condition
  (`PORT.GROUP0.IN` bit 22 read high) and one disclosed stub (a
  `DWT->CYCCNT`-based pulse-width delay, unrelated to control flow). The
  run escaped `FUN_00006968`'s homing-timeout loop at almost exactly the
  predicted tick count, with `--watch-mem-write 0x20001b14:4` live
  throughout — then crashed on a null-pointer dereference into an
  uninitialized DMA/SERCOM-shaped peripheral driver object, touched from
  more than one call site. Root-caused, not just described: a separate
  true-`Reset_Handler` run confirms this object would have been
  constructed by `FUN_0000cdd8`'s own clock/peripheral bring-up chain,
  which is blocked by the already-documented `SYNCBUSY`-style stall in
  "Tooling gaps" below — this is a downstream symptom of that same known
  gap, not an independent new one. No write to `0x20001b14` beyond the
  already-known `.bss` clear was observed. See
  [`docs/investigations/systick-tick-injection.md`](investigations/systick-tick-injection.md).
- **The `FUN_0000cdd8` stall resolved; the null-driver-object crash
  avoided for real (roadmap M6)**: identified all 4 of `FUN_0000cdd8`'s
  16 status polls that don't already pass under zero-behavior MMIO
  (each a real, SVD-named ready/lock bit — see "Tooling gaps"), modeled
  them with a new, explicit `--mmio-force-bits`/`--mmio-clear-bits`
  mechanism, and reran from the true `Reset_Handler`. The run now
  completes clock init, constructs the real SERCOM/DMA driver object
  (two SERCOM instances, `SERCOM5` then `SERCOM2`, each needing its own
  SWRST-clear and DRE-ready treatment) without the previous crash, and
  reaches and exits `FUN_00006968`'s real homing timeout — the primary
  acceptance target for this slice. Still no write to `0x20001b14`
  observed; reaching a directly observable main-loop state needs more
  simulated tick-time than expected, a new characterization gap (not a
  hardware-modeling one) named precisely rather than patched around. See
  [`docs/investigations/reset-handler-clock-init.md`](investigations/reset-handler-clock-init.md).
- **The "excessive tick cost" explained: a real radio-chip-ID probe
  fails, not a timing gap (roadmap M6)**: tracing `FUN_00009464`'s real
  post-homing call graph (not assuming `FUN_00007770`/`FUN_00005d44`
  were the whole story — they turn out to be unreached) found
  `FUN_0000610c` runs *second*, right after homing: a real device
  bring-up (`FUN_00009d88`) that resets a peripheral, performs a real
  SPI transaction through the already-confirmed SERCOM/DMA driver, and
  requires register `0x42` to read back `0x12` — concretely confirmed
  (`--watch 0x9dd4`) to instead read `0` under this harness, since no
  real chip answers. On failure the firmware takes its own real,
  intentional **infinite** retry loop (print + `delay(1000ms)`,
  forever) — fully explaining the large, ever-climbing tick counts
  `reset-handler-clock-init.md` found, which are that same loop's
  per-iteration countdown, not a stuck one-time boot delay. Register
  `0x42`=`0x12` matches the well-known SX127x LoRa "RegVersion" check —
  a strong pattern match, not independently verified against this
  board's actual silicon — plausibly the same unmodeled transport
  peripheral already on record in `samd51-peripheral-mapping.md`/
  `virtual-rf-link.md`. Correctly **not faked**: a real external-device
  response is a different evidence class from the MCU's own
  self-completing status bits modeled in the prior slice. No new
  tooling needed. See
  [`docs/investigations/post-homing-radio-probe.md`](investigations/post-homing-radio-probe.md).
- **A real concrete run now reaches the real main loop, past the
  radio-ID boundary (roadmap M6)**: confirmed no software bypass exists
  for the radio-ID probe (both call sites and the probe body checked).
  Introduced the narrowest possible disclosed assumption — a new,
  explicit `run_concrete.py --force-reg ADDR:REG:HEX` flag, used exactly
  once (`--force-reg 0x9dd4:r0:0x12`, the single instruction right after
  the SPI read returns) — deliberately a different, stricter-disclosure
  mechanism than `--mmio-force-bits` (that models documented MCU
  silicon; this fabricates one external value at one program point,
  disclosed every time as harness-supplied, not observed). With it, a
  real run goes `Reset_Handler` -> real clock/peripheral init -> the
  real startup reference/input routine (the neutral term for what was
  called "homing") -> the disclosed radio-ID assumption -> real
  post-probe init -> the **real main loop, confirmed stable and
  repeating** (`FUN_00008960` hit five times, ~400,000 instructions
  total, confirming the earlier tick-cost puzzle really was entirely the
  now-resolved infinite retry loop). `0x20001b14` remains unwritten
  across genuine steady-state idle execution — confirmed concretely,
  not inferred. A second, deeper dependency (a real bulk NVM erase loop
  that doesn't visibly advance over millions of instructions, likely
  gated on a zero-valued config field rather than a documented status
  bit) was found and precisely reported, not chased, since it doesn't
  block the above. The real RX injection point for a follow-on "inject
  I/M" slice was identified concretely (a 100-byte RAM ring buffer at
  `0x2000245c`) but not used. See
  [`docs/investigations/post-probe-main-loop.md`](investigations/post-probe-main-loop.md).
- **A real `G<d><d><seq>|` command delivered end to end through the real
  RX ring, real parser, and real dispatcher (roadmap M6) — and the
  reason `0x20001b14` still doesn't move**: a new, disclosed
  `run_concrete.py --force-mem TRIGGER:MEMADDR:HEXBYTES` flag (the
  memory-range counterpart to `--force-reg`) injected a real `"G000|"`
  packet into the live RX ring right after boot reaches the main loop.
  Delivery first required diagnosing and fixing a genuine harness-timing
  artifact: the real per-byte "is data available" check re-runs a real
  SX127x-style radio IRQ-flags poll on *every* byte, costing far more
  real instructions than the existing `--fake-tick` period accounted
  for, which spuriously tripped the firmware's own real inter-byte
  assembly timeout and prevented the terminator from ever being
  recognized — fixed by raising the tick period (20 -> 300), not by
  adding a new model. Once fixed, the real dispatcher ran to completion
  and this slice found `G`'s handler also writes a previously
  undocumented `0x200025e1 = 2` arm byte a second function
  (`FUN_00007e2c`) gates on — but `0x20001b14` still didn't move.
  Tracing why found the real reason: `FUN_00007e2c` (and
  `FUN_00008e18`/`FUN_00006338`/`FUN_00008a80` — everything this project
  has ever described as "runs every main-loop iteration") is **not
  reachable from a cold boot at all**, because it lives inside
  `FUN_000093fc`, which is only called after `FUN_00009464` returns — and
  `FUN_00009464` contains its own internal loop (the *real*,
  currently-permanent main loop, confirmed concretely to never exit in
  any run this slice performed) with exactly one real exit, gated on a
  byte (`0x20000060`) this slice traced, via an exhaustive whole-firmware
  literal-pool scan, to exactly one writer: **`MC4<...>|`** (motor
  configuration, all four channels — never the per-channel `MC<0-3>`
  form). Concretely confirming the `MC4` unlock hit a second, distinct
  per-byte timing dependency (not yet characterized) and was not chased
  further, per the task's explicit anti-fuzzing scope. See
  [`docs/investigations/g-command-motor-subsystem-unlock.md`](investigations/g-command-motor-subsystem-unlock.md).
- **`MC4` concretely confirmed as the real cold-boot-to-motor-subsystem
  transition; `FUN_00006fd8` (real "commit a move") fires for the first
  time in this project (roadmap M6)**: static characterization first —
  `MC4`'s handler (`FUN_00008258` at `0x86f0`, calling `FUN_00007a98` x4)
  writes four per-channel fields, of which only the 4th is genuinely
  consumed by the locked subsystem (`FUN_00007e2c`/`FUN_00008e18`, via
  exhaustive literal-pool xref), then writes `0x20000060=0` — the sole
  unlock, confirmed by a from-scratch exhaustive scan. Delivering a real
  36-byte `MC4` frame hit a second, now precisely diagnosed, per-byte
  timing dependency: `FUN_00008960`'s inter-byte timeout is measured
  *cumulatively from packet start*, not per byte, so a longer frame needs
  a proportionally larger `--fake-tick` period (300 -> 2000, sized from a
  direct ~5,696-instruction-per-byte measurement, not guessed). With that
  fix, `MC4` alone concretely unlocks `FUN_000093fc` (confirmed: `0x8714`
  -> `FUN_00009464` returns -> `FUN_000093fc`/`FUN_00007e2c`/`FUN_00008e18`
  all reached repeatedly). Sending `G` and `MC4` in the same buffer found
  a real "flush stale bytes while busy" firmware behavior that silently
  drops the second command — fixed by sequencing a second `--force-mem`
  injection at `FUN_00009464`'s own one-time return instruction. With
  `MC4` then `G` properly sequenced, `G`'s `0x200025e1=2` arm — confirmed
  independent of `MC4` by both xref and control flow — lets
  `FUN_00007e2c` reach **`FUN_00006fd8`, the real motor move-commit
  function, for the first time ever observed in this project**
  (register-captured: `channel=0, distance=0, rate=0x121fa`). Still no
  write to `0x20001b14`: with `distance=0`, `FUN_00006fd8`'s own code
  takes its documented "8 units or fewer, no real move" branch — a
  concrete, register-level explanation, not an open question. See
  [`docs/investigations/mc4-transition.md`](investigations/mc4-transition.md).
- **Traced the motor target/position config to a real, blank compiled-in
  default-configuration blob — a genuine external-data boundary, not a
  missing mechanism (roadmap M6)**: `FUN_00004b64` bulk-loads the
  `0x20001b40` per-channel struct from a lazily-initialized RAM buffer
  (`FUN_00009724`), itself sourced from a plain flash-address read (no
  driver/peripheral indirection — confirmed by register capture,
  `src=0x00012000`) — and that exact flash address is, in this firmware
  image, **entirely `0x00`** (confirmed by reading the raw `.bin` file
  directly, the strongest possible evidence tier). The loader's own real
  fallback (fully disassembled, including a genuine ARM void-return
  subtlety the decompiled pseudo-C got wrong) then fills the struct with
  `0xFF`; a separate, one-shot, `.data`-driven resync
  (`FUN_00004b24`) immediately overwrites each channel's mode-0 target
  with that channel's own live position (`0x20002064[channel]`, cold-
  zero) — a real "no move commanded yet" default. Exhaustively trying
  every `G` "type" digit (`0`-`9`) after a real `MC4` gives exactly two
  concrete, register-captured outcomes — `distance=0` (mode 0) or
  `distance=-1` (modes 1-9) — neither of which crosses `FUN_00006fd8`'s
  `8`-unit real-move threshold. This is the same evidence class as the
  unanswered radio-ID chip in `post-homing-radio-probe.md`: a real
  external-data/provisioning gap, not something this harness can close
  without fabricating motor-position data. See
  [`docs/investigations/target-config-provenance.md`](investigations/target-config-provenance.md).

## Corrected assumptions

- **The `I` handler's "`=5`" write targets `0x20002524[channel]`, not
  `0x20001b14[channel]`.** `research/autopilot_static_inventory/synchronous-responses.md`'s
  original static-inventory pass conflated two distinct, adjacent-in-role
  per-channel byte arrays. Disassembly of the real handler
  (`0x872e`-`0x877c`) shows `0x20001b14[channel]` is only ever *read*
  there (as a gate on calling `FUN_00005274`); the literal `5` is stored
  to `0x20002524[channel]`, a separate flag also written by
  `FUN_00006fd8` (`=1`, on committing a real move) and an unnamed
  periodic poller (`=2`). See
  [`docs/investigations/i-command-motor-chain.md`](investigations/i-command-motor-chain.md).
- **The `0x827e`-`0x82c4` loop is not on the ASCII-command path at all —
  it's gated on `buffer[0]==0xF0`.** Two earlier passes (Ghidra-based
  decompilation, then a first symbolic-execution pass) both examined this
  loop under the assumption that it runs first for *every* packet,
  including `&`. Concrete execution found the dispatcher's actual first
  decision, at `0x8258`-`0x8266`, is `cmp buffer[0],#0xF0; bne <skip the
  loop>` — the loop is v0.1's own "binary motor/control frame" path
  (`0xF0`/`0xE0`), and ASCII commands branch straight past it into the
  character-comparison chain instead. **The loop is never entered for the
  `&` command the current milestone is about.** This supersedes the
  "flat parser chain" correction below it and the memory-side-effect
  blocker hypothesis that followed from it. See
  [`docs/investigations/dispatcher-loop-concrete-trace.md`](investigations/dispatcher-loop-concrete-trace.md)
  and [`docs/investigations/parser-dispatch.md`](investigations/parser-dispatch.md).
- **The "flat parser chain" model of `0x8258` is not fully trusted** (background,
  now refined by the point above). The original static pass modeled the
  dispatcher as a simple if/else-if scan over the packet's leading byte;
  the real shape is a `buffer[0]` gate into either the binary-frame loop or
  the ASCII chain. See
  [`docs/investigations/parser-dispatch.md`](investigations/parser-dispatch.md).
- **Macaw vs. Ghidra disagreement at `0x801c`, resolved.** Macaw lifted this
  address (on the path that sets up the dispatcher's R0 argument) as
  ARM/A32-mode code — architecturally impossible on Cortex-M4F. Ghidra's
  Thumb-only Cortex-M language (incapable of decoding A32 at all) instead
  decoded it as an ordinary, well-formed, 8-times-called Thumb function.
  **Conclusion: the A32 lift was a Macaw/dismantle decode limitation, not
  dead code.** R0's exact value at the dispatcher call site was
  subsequently pinned down directly via Unicorn: **R0 = 0**, traced to
  `*(byte*)0x20001fd4` at the real call site, a byte never written before
  that point from cold RAM. See
  [`docs/tooling/tool-selection.md`](tooling/tool-selection.md#tool-disagreements-investigate-dont-default),
  [`docs/investigations/trigger-input.md`](investigations/trigger-input.md),
  and [`docs/investigations/dispatcher-loop-concrete-trace.md`](investigations/dispatcher-loop-concrete-trace.md).
- **`FUN_000093fc` (and the motor-phase/ramp/monitor code it calls) is not
  reachable from a cold boot at all, without a prior `MC4` command.**
  `i-command-motor-chain.md`, `channel-busy-gate-search.md`, and
  `post-probe-main-loop.md` all describe `FUN_00006338`/`FUN_00007e2c`/
  `FUN_00008e18`/`FUN_00008a80` as running "every main-loop iteration" —
  an accurate reading of `FUN_000093fc`'s static structure, but this was
  never concretely confirmed as *reachable* until this slice tried and
  found the real, currently-running main loop is actually
  `FUN_00009464`'s own internal loop, which calls only
  `FUN_00008960`/`FUN_00005dd0` and does not return under any condition
  exercised so far. Those docs are not rewritten retroactively (their own
  static findings still stand); this is the corrected, concretely-checked
  reachability picture. See
  [`docs/investigations/g-command-motor-subsystem-unlock.md`](investigations/g-command-motor-subsystem-unlock.md).

## Tooling gaps

**Resolved: `FUN_0000cdd8`'s clock/peripheral-init chain now runs to
completion under Unicorn.** Previously stalled indefinitely (confirmed
in
[`docs/investigations/systick-tick-injection.md`](investigations/systick-tick-injection.md)
at `pc=0xcde8`), root-caused and fixed in
[`docs/investigations/reset-handler-clock-init.md`](investigations/reset-handler-clock-init.md):
of 16 status-register polls in the function, exactly 4 don't already
pass under the zero-behavior MMIO model (`OSC32KCTRL.STATUS.XOSC32KRDY`,
`OSCCTRL.STATUS.DFLLRDY`, `OSCCTRL.DPLL0/DPLL1.DPLLSTATUS.{LOCK,CLKRDY}`
— all real, SVD-identified, predictably-completing bits on hardware
already confirmed to boot), now satisfied via a new, explicit
`run_concrete.py --mmio-force-bits`/`--mmio-clear-bits` mechanism (never
a general peripheral model — each address is named and justified
individually). A real, unmodified concrete run now goes
`Reset_Handler` -> `FUN_0000cdd8` (complete) -> the real SERCOM/DMA
driver constructor (also completes, resolving the downstream
null-pointer crash `systick-tick-injection.md` found) -> real homing,
confirmed via `--watch` hits at the same exit point found from the
routed-around entry point. **Not fully resolved**: continuing past
homing to a directly observable main-loop state (`FUN_00008960`) needs
far more simulated tick-time than initially expected — a newly
identified characterization gap (not a missing-MMIO-behavior one), see
that doc's "next step."

**Not a firmware blocker — a known, documented, and deliberately unfixed
harness limitation.** A whole-function Crucible replay of the `&`-command
dispatcher gets stuck in the `0x827e` loop, taking the wrong branch at
`0x8266` despite `buffer[0]` being concretely `0x26`. This was fully
investigated and explained (not left as an open mystery):

- The `0x8266` branch itself, Macaw's lift of it, and `mkFunCFG`'s entry/
  branch-CFG wiring are all confirmed correct — isolating the exact block
  in Crucible (existing single-block machinery, extended with a small
  `bqMemoryBytes` addition to seed the buffer content) reproduces the
  correct, deterministic result for both `buffer[0]=0x26` and the `0xF0`
  control case. See
  [`docs/investigations/gate-block-crucible-isolation.md`](investigations/gate-block-crucible-isolation.md).
- **Root cause**: the dispatcher's buffer pointer is loaded from a literal
  pool in flash, and flash is `readonly` — `populateSegmentChunk` always
  populates readonly memory via solver assumptions, never as folded array
  literals, regardless of `ConcreteMutable`/`SymbolicMutable`. That's fine
  for a solver query, but plain Crucible execution has no solver in the
  loop for an ordinary `Br`, so the branch condition never folds to a
  concrete `Pred` and Crucible picks the wrong side. See
  [`docs/investigations/whole-function-trace-divergence.md`](investigations/whole-function-trace-divergence.md)
  and [`docs/tooling/tool-selection.md`](tooling/tool-selection.md#known-limitation-readonly-flash-and-plain-crucible-execution).

**Deliberately not fixed in this pass, and not planned unless needed**: no
general fix (baking all of flash into literals, redesigning
`populateSegmentChunk`) — that's a real execution-model change with no
current symbolic use case requiring it, now that the milestone below is
closed at the concrete evidence tier. Revisit only if a future
Crucible/What4/Z3 use case genuinely needs a whole-function proof through
a literal-pool-derived branch; the narrow fix (baking the *specific*
literal-pool words that target reads, the same store pattern already
proven for the packet buffer) would be the smallest starting point.

## Next steps

**Note**: a tooling-only detour (2026-09-08, ahead of a Galois meeting)
happened between the milestone above and this section — two clean repros
(Macaw's A32-on-Cortex-M mode selection, readonly-flash/plain-Crucible
divergence), an experimental `aptrace debug` (`crucible-debug`/
`crucible-macaw-debug`), an optional GREASE experiment, and a small MMIO-
diagnostics addition. See
[`docs/tooling/galois-premeeting.md`](tooling/galois-premeeting.md). It did
not touch the milestone/roadmap; roadmap M3 (the virtual RF link) closed
separately and immediately afterward, also on 2026-09-08.

1. **Deliberate pivot: behavior-to-hardware provenance (in progress).**
   `&|`, `G -> #`, and `S -> P...` are all done — a deliberate stop before
   `!`/`I`, pivoting toward `command/state -> internal variable/function
   -> timer/MMIO -> ISR/GPIO -> MCU pin -> physical hardware behavior`.
   The motor-timer survey (TC0-TC3's ISR/GPIO mechanism, matched against
   the already-proven TCC1 -> PB22 case) is now done — see
   [`docs/investigations/motor-timer-survey.md`](investigations/motor-timer-survey.md).
   The per-channel pin-index gap that survey left open is now also
   closed: TC0->PB10, TC1->PA08, TC2->PB12, TC3->PA10, a `.data`-segment
   startup-initialization fact, not application-written — see
   [`docs/investigations/pin-index-provenance.md`](investigations/pin-index-provenance.md).
   `I<channel><mode>|`'s state machine is now traced forward and meets
   the timer chain from (12)/(13) in the middle: the handler's own
   `0x20001b14[channel]!=0` gate conditionally calls `FUN_00005274` ->
   `FUN_00004d18`, which writes `step_delta[channel]`'s *sign* (a
   confirmed, concretely-validated edge — also corrected the record:
   the handler's `=5` write is `0x20002524[channel]`, not
   `0x20001b14[channel]` as previously catalogued); separately,
   `FUN_00006338`'s ramp logic only propagates a rate update to the
   real `FUN_00005c00`/`FUN_00005898` chain when that same
   `0x20001b14[channel]` gate is nonzero. See
   [`docs/investigations/i-command-motor-chain.md`](investigations/i-command-motor-chain.md).
   **One link remains**: what sets `0x20001b14[channel]` nonzero in the
   first place — exhaustively searched (12 direct-reference functions, 7
   one-hop candidates, the full boot chain, a neighbor-offset sweep) and
   not found by any static method; a concrete watchpoint (new
   `run_concrete.py --watch-mem-write`) confirmed one branch writes
   nothing. See
   [`docs/investigations/channel-busy-gate-search.md`](investigations/channel-busy-gate-search.md).
   Two concrete follow-ups: first
   ([`docs/investigations/systick-tick-injection.md`](investigations/systick-tick-injection.md))
   resolved the homing-timeout tick gap with a new `--fake-tick`
   capability and got past it with the watchpoint live, but hit an
   uninitialized DMA/SERCOM-shaped peripheral object, root-caused to the
   `FUN_0000cdd8` clock-init stall; second
   ([`docs/investigations/reset-handler-clock-init.md`](investigations/reset-handler-clock-init.md))
   resolved *that* stall too (4 real, SVD-named completion bits, a new
   `--mmio-force-bits`/`--mmio-clear-bits` mechanism) and reran from the
   true `Reset_Handler` — clock init now completes, the driver object
   constructs without crashing, and real homing runs and exits, all
   confirmed. A third follow-up
   ([`docs/investigations/post-homing-radio-probe.md`](investigations/post-homing-radio-probe.md))
   traced *why*: `FUN_0000610c`, reached second after homing (before
   either `FUN_00007770` or `FUN_00005d44`), performs a real SPI
   device-ID probe (register `0x42` expected `0x12`, matching the
   well-known SX127x LoRa `RegVersion` check) through the already-real
   SERCOM/DMA driver — concretely confirmed to read `0`, not `0x12`,
   with no chip attached, so the firmware takes its own real,
   **infinite** retry loop. Not a timing gap; not faked (a different,
   external-device evidence class from the MCU-internal bits already
   modeled) — correctly identified and left as an open, real hardware
   boundary. A fourth follow-up
   ([`docs/investigations/post-probe-main-loop.md`](investigations/post-probe-main-loop.md))
   confirmed no software bypass exists, then introduced the narrowest
   possible disclosed assumption (a new `--force-reg` mechanism,
   fabricating exactly one register value at one instruction) to get
   past it. The real main loop is now reached and confirmed stable
   (`FUN_00008960`, 5 iterations, ~400,000 instructions total from
   `Reset_Handler`) — resolving the earlier "excessive tick cost" as
   entirely attributable to the now-bypassed infinite retry loop.
   `0x20001b14` remains unwritten through genuine idle main-loop
   execution, concretely confirmed. **The real RX injection point is
   now identified** (a 100-byte RAM ring buffer at `0x2000245c`,
   index `0x200024c0`) for a follow-on slice that injects a real `I`/`M`
   command — not attempted this pass. A second, deeper dependency (a
   real bulk NVM erase loop that doesn't advance over millions of
   instructions, likely gated on a zero-valued config field rather than
   a status bit) was found and reported precisely; it does not block
   the above and was not chased further.
   A fifth follow-up
   ([`docs/investigations/g-command-motor-subsystem-unlock.md`](investigations/g-command-motor-subsystem-unlock.md))
   delivered a real `G000|` through the real RX ring for the first time
   (a new `--force-mem` mechanism, plus a `--fake-tick` recalibration
   after diagnosing a real per-byte radio-poll-vs-inter-byte-timeout
   collision), confirmed `G`'s handler arms a previously undocumented
   `0x200025e1=2` byte, and — the real answer to why `0x20001b14` never
   moves — found that `FUN_00007e2c`/`FUN_00008e18`/`FUN_00006338`/
   `FUN_00008a80` (the whole motor-phase/ramp/monitor subsystem) are not
   reachable from a cold boot at all: the real, currently-running main
   loop lives entirely inside `FUN_00009464` and never returns, so
   `FUN_000093fc` (which calls all four) is never called. The one real
   unlock — clearing `0x20000060` — traces to exactly one command,
   `MC4<...>|` (never per-channel `MC<0-3>`), found by the same
   exhaustive literal-pool-scan method already used for `0x20001b14`
   itself. A concrete `MC4` delivery attempt hit a second, distinct
   per-byte timing dependency and was not chased further this pass.
   A sixth follow-up
   ([`docs/investigations/mc4-transition.md`](investigations/mc4-transition.md))
   characterized `MC4` fully (frame schema, per-channel field storage —
   only the 4th field feeds the locked subsystem — and the exact
   `0x20000060=0` unlock instruction), diagnosed the second timing
   dependency precisely (a *cumulative*, not per-byte, inter-byte
   timeout — fixed by sizing `--fake-tick`'s period from a direct
   per-byte-cost measurement), and delivered `MC4` alone concretely:
   `FUN_000093fc` reached for real, with `FUN_00007e2c`/`FUN_00008e18`
   now running every iteration. Sequencing a real `G` after `MC4` (a
   second `--force-mem` at `FUN_00009464`'s own one-time return
   instruction, after finding same-buffer back-to-back delivery gets the
   second command silently flushed by a real firmware behavior) reached
   **`FUN_00006fd8`, the real move-commit function, for the first time in
   this project** — still no `0x20001b14` write, explained concretely by
   a register-captured `distance=0` taking `FUN_00006fd8`'s own
   documented no-op branch. `0x200025e1` (`G`'s arm) and `0x20000060`
   (`MC4`'s unlock) are confirmed independent by both xref and control
   flow — no function touches both.
   A seventh follow-up
   ([`docs/investigations/target-config-provenance.md`](investigations/target-config-provenance.md))
   traced `distance=0`'s producer: `FUN_00006fd8`'s config struct
   (`0x20001b40`, confirmed base — a same-session decompiler-vs-
   disassembly correction after `FUN_00007e2c`'s tail-jump initially
   mis-attributed it) is bulk-loaded from a lazily-initialized buffer
   sourced from a plain flash-address read (`0x00012000`, register-
   captured, no driver indirection) — and that exact flash address is,
   in this firmware image, entirely `0x00` (confirmed by reading the raw
   `.bin`). The real loader fallback fills the struct with `0xFF`; a
   one-shot, `.data`-driven resync then overwrites each channel's mode-0
   target with its own live position (cold-zero). Exhaustively trying
   every `G` "type" digit (`0`-`9`) gives only `distance=0` or `-1`,
   never `>8` in magnitude — a real, external-data provisioning boundary
   (the same evidence class as the unmodeled radio-ID chip), not a
   missing mechanism.
2. **Exercise `!`/`I` through the virtual link** (roadmap M4, deferred
   per (1)): `!0|`/`!1|` (`0xc440`, event 7 — already has a known
   11-vs-10 field mismatch to preserve, not normalize away) and
   `I<channel><mode>|` (`0xb958`/`0xb834`, dynamic per-channel state) —
   same two primitives, not started.
3. `G`/`S`'s handler-side event-scheduling writes are now concretely
   verified; `!` still only has solver-confirmed entry *reachability* —
   a smaller, parallel task, not a prerequisite for (1) or (2).
4. If a real symbolic use case for the readonly-flash gap above ever
   arises, apply the narrow fix described in "Tooling gaps" — not before.
5. Name the TX path's real transport peripheral by tracing what
   populates the driver-object pointer `0x8c10` dispatches through;
   install `GhidraSVD` only if the standalone resolver stops being
   convenient enough for routine use. **Possibly related**: the radio-ID
   probe object `post-homing-radio-probe.md` found (`0x20004160`) is a
   real, constructed SERCOM/DMA driver object of the same general shape
   — worth checking whether it's the *same* object `0x8c10` dispatches
   through, not assumed to be.

The `0x827e` loop's own internal structure and its callees `0x5274`/`0x5448`
([`docs/investigations/dispatcher-loop-callees.md`](investigations/dispatcher-loop-callees.md))
remain correctly documented and are relevant to future `0xF0`/`0xE0`
binary-frame work. Fuller backlogs (protocol open questions, remaining
tooling gaps like the still-not-installed `GhidraSVD` extension) are
tracked in [`docs/protocol/open-questions.md`](protocol/open-questions.md)
and [`docs/tooling/tool-selection.md`](tooling/tool-selection.md), not
duplicated here.

## Tool architecture

APTrace orchestrates specialist tools rather than reimplementing them:

| Tool | Role | Status |
|---|---|---|
| Ghidra | static RE / decompiler / xrefs / tables / MMIO naming | Integrated — [`docs/tooling/ghidra-backend.md`](tooling/ghidra-backend.md) |
| Unicorn | concrete Thumb execution / state snapshots | Integrated — [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md) |
| Macaw | independent CFG discovery / machine-code lifting | In use, proven |
| Crucible + What4 + Z3 | targeted symbolic reachability / input solving | In use, proven |
| APTrace | orchestration, evidence model, scenarios, traces, UI | This repo |

See [`docs/tooling/tool-selection.md`](tooling/tool-selection.md) for when
to use which, and [`docs/architecture.md`](architecture.md) for rationale.
