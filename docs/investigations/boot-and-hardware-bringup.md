# Boot Sequence and Hardware Bring-Up — Current Model

This dossier consolidates eight slice-by-slice investigations that
together took a concrete Unicorn run from `Reset_Handler` all the way
to a stable, repeating real main loop in the AutoPilot firmware
(`firmware_autopilot868.bin`, ATSAMD51J19A). Along the way they
resolved the tick source, four real clock/peripheral completion-bit
polls, a real radio chip-ID probe and its infinite-retry failure mode,
the RX injection point, the TC0-TC3/TCC1 motor-timer-to-GPIO
mechanism and its real per-channel pin assignments, and the exact
Adafruit ArduinoCore-samd toolchain the firmware was built from. The
individual slices (`boot-and-hardware-bringup.md`,
`boot-and-hardware-bringup.md`, `boot-and-hardware-bringup.md`,
`boot-and-hardware-bringup.md`, `boot-and-hardware-bringup.md`,
`boot-and-hardware-bringup.md`, `boot-and-hardware-bringup.md`,
`boot-and-hardware-bringup.md`) are superseded by this document and
removed; their process is preserved in git history.

## Current model

**The real boot order, `Reset_Handler` to steady state**, all
concretely reproduced in one run:

1. `Reset_Handler` (`FUN_0000cc24`, flash `0xcc24`) — the textbook
   CMSIS Cortex-M startup: a `.data` copy loop (flash `__etext` ->
   RAM `[__data_start__, __data_end__)`), a `.bss` zero loop, then
   `SCB->CPACR |= (0xF << 20)` followed by `DSB`/`ISB` — the standard
   ARM FPU-enable sequence, verbatim, for a Cortex-M4F.
2. `FUN_0000cdd8()` — clock tree + full analog block bring-up
   (`MCLK`, `GCLK`, `OSCCTRL`, `OSC32KCTRL`, `SUPC`, `NVMCTRL`, `CMCC`,
   `AC`, `ADC0`, `ADC1`, `DAC`, `USB`), unconditionally, before
   anything application-specific runs.
3. `FUN_0000cd90()` — this is **`main()`** (see toolchain section
   below): its own call order matches ArduinoCore-samd's
   `main.cpp` exactly (`init(); __libc_init_array(); initVariant();
   delay(1); [USB init]; setup(); for(;;){loop();yield();
   serialEventRun();}`). It transitively reaches `WDT`, `NVMCTRL`,
   `EIC`, `DMAC`, `GCLK`, `MCLK`, `PORT`, `TC0`-`TC3`, `TCC1`, and
   `USB` — every general-purpose timer, DMA, and USB brought up
   unconditionally at startup, a signature of Arduino-core-generated
   `init()`, not a hand-tuned minimal firmware.
4. `FUN_00009464` is the sketch's real **`setup()`**. It runs the
   startup reference/input routine (`FUN_00006968` — earlier docs
   called this "homing"; that is an analyst label, not a
   vendor-confirmed name, kept here as a neutral term), then the SPI
   SERCOM/DMA driver construction, then the radio chip-ID probe
   (`FUN_0000610c`). Unusually for Arduino idiom, this `setup()`
   contains its own permanent internal loop and does not return under
   normal conditions — it only returns if `0x20000060` is cleared
   (an `MC4`-transition condition), at which point `main()`'s own
   `for(;;){loop();...}` runs for the first time.
5. `FUN_000093fc` is the sketch's real **`loop()`** — only reached if
   `setup()` returns.
6. The real, stable, repeating main loop's own receive call is
   `FUN_00008960`, confirmed via multiple `--watch` hits with
   consistent ~2900-2940-instruction spacing between iterations —
   genuine steady-state operation, not a stall.

**The radio chip-ID probe and its real failure mode.** `FUN_0000610c`
calls `FUN_00009d88`, a real device bring-up routine (CS pin config,
an optional reset pulse, SERCOM/DMA driver init, then a real SPI
transaction reading register `0x42` and requiring the response equal
`0x12`). With no physical chip attached, the read returns `0`, the
check fails, and the firmware takes its own real, intentional
infinite retry branch (print status; delay 1000ms; repeat) — this is
a genuine external-hardware dependency, not a timing/tooling gap, and
it single-handedly explained tens of millions of instructions of
apparent "excessive tick cost" seen before this was traced.

**The motor-timer mechanism**, for all five timer channels: TCC1's
handler (IRQ93, `0x60ec`) does its GPIO write **inline** —
`PORT.GROUP1.OUTTGL = 0x400000` (toggles `PB22`) — with the pin baked
directly into the instruction stream, no runtime indirection. TC0-TC3
(IRQ107-110) are structurally different: each clears the same two
flags (`MC0`, `OVF`) it was configured to raise at startup, then
tail-branches into a **shared, table-indexed pulse helper**,
`FUN_00005898(channel)` — TC1/TC2/TC3 directly, TC0 via a much larger
velocity-ramp function (`FUN_00005be8`) that reaches the same helper
on its fast path. `FUN_00005898` advances a per-channel position
accumulator and, on a periodic-boundary condition, looks up a
per-channel RAM index byte into a flash-resident pin-descriptor table
and pulses that pin high then low via `FUN_0000d388` (a generic,
table-driven GPIO setter — the `digitalWrite()`-shaped access
pattern). The real per-channel pin assignments (below) come from that
table lookup, not from a fixed instruction.

**Toolchain and Arduino-idiom naming.** The exact board package —
Adafruit `samd` v1.7.11, named directly by embedded build-path strings
in the firmware image — was fetched from `adafruit/ArduinoCore-samd`
at git tag `1.7.11` and compared structurally (not by guessed naming)
against `cortex_handlers.c`, `main.cpp`, `delay.c`, `wiring_digital.c`,
and `SERCOM.cpp`. This confirmed `Reset_Handler`, `Dummy_Handler`,
`SysTick_Handler`, `millis()`, and `main()` byte-for-byte in
structure, and supplied the correct Arduino-idiom names for
`setup()`/`loop()` above (independently corroborated by this
project's own call-graph tracing in other docs).

## Evidence

**The four real SVD-named completion bits** that do not already pass
under zero-behavior MMIO (all documented ready/lock bits that real
hardware sets automatically once its own preceding configuration
write takes effect — the MCU's own guaranteed behavior, not an
external dependency):

| # | Address:bit | SVD register.field | Preceding write |
|---|---|---|---|
| 1 | `0x4000140c` bit 0 | `OSC32KCTRL.STATUS.XOSC32KRDY` | `OSC32KCTRL.XOSC32K = 0x200e` |
| 2 | `0x40001010` bit 8 | `OSCCTRL.STATUS.DFLLRDY` | `OSCCTRL.DFLLCTRLB = 0x98` |
| 3 | `0x40001040` bits 0-1 | `OSCCTRL.DPLL0.DPLLSTATUS.{LOCK,CLKRDY}` | `DPLL0CTRLB=0x800; DPLL0CTRLA|=2` |
| 4 | `0x40001054` bits 0-1 | `OSCCTRL.DPLL1.DPLLSTATUS.{LOCK,CLKRDY}` | `DPLL1CTRLB=0x800; DPLL1CTRLA|=2` |

(Twelve other polls in the same function already pass under
zero-behavior MMIO — each is a `SYNCBUSY`/`DFLLSYNC`-style "busy" bit
whose exit condition, reading `0`, cold MMIO already satisfies.)

One level down, the real SERCOM/DMA driver constructor needed the
same treatment for two SERCOM instances, `SERCOM5` (`0x43000400`) and
`SERCOM2` (`0x41012000`): `CTRLA`/`SYNCBUSY` bit 0 (`SWRST`, real
hardware self-clears within a few cycles — `--mmio-clear-bits`) and
`INTFLAG.DRE` (bit 2, `0x43000418`/`0x41012018` — set the moment the
peripheral is enabled with nothing queued, still category (a) since
no data transfer had yet been attempted — `--mmio-force-bits`).
Later, the bulk-NVM erase loop (see Open Items) needed
`NVMCTRL.INTFLAG.DONE` (bit 0, `0x41004010`), the same category,
modeled the same way.

**The radio-ID probe.** Register `0x42`, expected value `0x12`,
reached via `FUN_00009d88` -> `FUN_000099c2` -> `FUN_00009984` ->
the SERCOM driver's transceive primitives. This matches the textbook
"RegVersion" chip-identification check used by the Semtech SX127x
LoRa transceiver family — **a strong pattern match, not an
independently hardware-verified fact about this board's actual
silicon**. Concretely confirmed failing under zero-behavior MMIO via
`--watch 0x9dd4` (the `cmp r0,#0x12` immediately after the read):
`r0=0x00000000` at instruction 74157. No software bypass exists —
both call sites into the check (`FUN_00009464`'s boot path and the
ASCII command dispatcher's `0x8914`) reach the same unconditional
check; the probe body itself has no debug flag or alternate branch.

**The RX injection point**, dumped (not assumed) at the moment
`0x8960` is first reached: two selector bytes, `*0x20000018 = 0x00`
and `*0x2000006a = 0x01`, together select the plain **100-byte RAM
ring buffer** at `0x2000245c` (head/tail indices at `0x200024c0`/
`0x200024c4`) over the deeper radio-SPI-FIFO branch
(`FUN_0000c93e`/`FUN_0000cb18`). `0x20000018` is the same byte
`FUN_0000610c` clears to `0` on a successful probe — a traced
connection, not a coincidence.

**TC0-TC3 IRQs, addresses, and the shared pulse helper.** Vector-table
entries (literal-pool base address resolved for each):

| IRQ | Handler | Literal-pool base | Peripheral |
|---:|---|---|---|
| 93 | `0x60ec` | `0x41018000` | TCC1 (inline `PORT.GROUP1.OUTTGL`) |
| 107 | `0x607c` | `0x40003800` | TC0 |
| 108 | `0x6098` | `0x40003c00` | TC1 |
| 109 | `0x60b4` | `0x4101a000` | TC2 |
| 110 | `0x60d0` | `0x4101c000` | TC3 |

**The real per-channel pin table** and its provenance. The flash
pin-descriptor table at `0x14284` (24 bytes/entry, group/pin fields,
an Arduino-style `g_APinDescription[]`-shaped array) is indexed by a
per-channel RAM byte at `0x20000164`-`0x20000167`. Two independent
exhaustive searches (Ghidra `dataReferences` xrefs, twice, plus a raw
byte-pattern scan for the literal `0x20000164`) found **no
application instruction** that writes those bytes — because there
isn't one: they are `.data`-segment initializers, baked into flash at
`0x14da4` (`29 2b 07 2d`) and copied into RAM by `Reset_Handler`'s own
generic `.data` copy loop (`0xcc24`-`0xcc70`), which runs *before*
`FUN_0000cdd8`'s clock init and before any peripheral is even
clocked. This rules out NVM/EEPROM (the firmware's real NVM helpers
are flash-write primitives, not called anywhere near this array) and
board/runtime detection (nothing between `Reset_Handler` and the
`.data` copy reads any pin/strap/ID register) as alternative sources.
Decoding the table (offset `0x00` = PORT group, offset `0x04` = pin
number, cross-validated against the independently-known `PB22` =
table index 40, an exact match):

| Channel | RAM byte | Index | Pin |
|---|---|---:|---|
| TC0 | `0x20000164` | 41 (`0x29`) | **PB10** |
| TC1 | `0x20000165` | 43 (`0x2b`) | **PA08** |
| TC2 | `0x20000166` | 7 (`0x07`)  | **PB12** |
| TC3 | `0x20000167` | 45 (`0x2d`) | **PA10** |
| TCC1 | *(none — inline)* | 40 (baked into instruction) | **PB22** |

**Toolchain identification and confidence tiers.** Adafruit
`ArduinoCore-samd` v1.7.11, confirmed via embedded build-path strings
and verified by fetching and structurally comparing the real tagged
source:

- **CONFIRMED** (byte-for-byte structural match against fetched
  source): `Reset_Handler` (`FUN_0000cc24`), `Dummy_Handler`
  (`FUN_0000cc10`), `SysTick_Handler` (`FUN_0000cca4`), `millis()`
  (`FUN_0000ccd0`), `main()` (`FUN_0000cd90`), the sketch's `setup()`
  (`FUN_00009464`) and `loop()` (`FUN_000093fc`) by call-order match,
  and SERCOM SPI reset (`SERCOM::resetSPI()`, the `SWRST`
  set/self-clear pattern already disassembly-confirmed for both
  SERCOM5/SERCOM2).
- **LIKELY_STANDARD_LIBRARY** (role/structural match, not
  byte-verified against a built binary): `delay()` (`FUN_0000cd50`),
  SPI single-byte transceive (`FUN_000099c2`, completion-bit polarity
  not disassembly-confirmed), the GPIO pulse helper's `OUTSET`/
  `OUTCLR` access pattern (`FUN_00005898`/`FUN_0000d388`, matching
  `wiring_digital.c`'s `digitalWrite()` — note the pin-index *table
  itself* is board-specific/custom even though the access pattern is
  standard), and the `FUN_0000e648`/`FUN_0000e664` memcpy/memset
  fingerprint (newlib-nano/libgcc shape, not matched against a built
  binary).
- **LIKELY_THIRD_PARTY_LIBRARY** (circumstantial register-map/shape
  evidence, no source fetched): the radio probe/IRQ-poll cluster
  (`FUN_0000610c`, `FUN_00009d88`, `FUN_00009eac`, `FUN_00009984`,
  `FUN_00007fdc`) — an SX127x/RFM9x-style driver family, not
  distinguished further; and the LCD status-line refresh
  (`FUN_00007514`), which dispatches through a vtable-shaped
  indirect call, evidence of *some* OO display-driver library
  (plausibly Adafruit_GFX-derived), kept at LOW-MEDIUM confidence.
- **UNKNOWN, honestly**: the NVMCTRL bulk-erase sequence's origin
  (ArduinoCore-samd 1.7.11 ships no NVM/EEPROM helper file at all,
  ruling out the Adafruit core specifically, but neither confirming
  nor ruling out a third-party flash library or hand-written code);
  CMSIS `SystemInit()`'s exact upstream source (a separate,
  unfetched Microchip CMSIS-Atmel package — the clock-init sequence
  itself is independently fully documented from the SVD and
  disassembly regardless).

## Test / repro

This cluster added, to `tools/unicorn/run_concrete.py`:

- **`--fake-tick ADDR:PERIOD`** — advances the firmware's own
  RAM-resident millis/tick counter (`0x200052ec`, read by both the
  homing-timeout loop and the generic delay helper) on an
  instruction-count cadence, rather than modeling `SysTick`
  MMIO registers at all. Diagnosed as necessary by disassembling the
  real tick-reading functions directly (not assumed): the value comes
  from a firmware-maintained RAM counter incremented by the real
  `SysTick_Handler`, not a raw register read.
- **`--mmio-force-bits ADDR:MASK`** / **`--mmio-clear-bits
  ADDR:MASK`** — narrow, address-scoped hooks that OR (or AND-NOT) a
  mask onto every read of one named register, used exclusively for
  documented MCU completion/self-clear bits that real silicon
  guarantees once its own preceding write takes effect (the four
  clock/PLL bits and the SERCOM SWRST/DRE bits above, later the
  NVMCTRL `DONE` bit). Each hook's snapshot records how many times it
  actually changed a value, so a hook that never fires is visible as
  `count: 0`.
- **`--force-reg ADDR:REG:HEX`** — sets one register to one value
  immediately before the instruction at `ADDR` executes. Used exactly
  once, `--force-reg 0x9dd4:r0:0x12`, to stand in for "a radio module
  is present and answers this read with the value real firmware
  requires." This is a **materially different, stricter-disclosure**
  mechanism than `--mmio-force-bits`: the MMIO hooks model what the
  MCU's *own* documented silicon guarantees, while `--force-reg`
  fabricates a value the harness has no way to know — standing in for
  an external device's behavior, not internal chip state — and it is
  scoped to one instruction rather than one register generally, so it
  cannot leak into any other call to the same read helper.
- **`--log-mmio`** — a purely observational read/write hook recording
  every MMIO access (address, size, direction, value, PC, instruction
  count) into the snapshot's `mmio_log`, capped by `--max-mmio-log`
  (default 5000). Added no peripheral behavior; used to cross-check
  static xref-based peripheral claims against real execution (e.g.
  confirming the TCC1/TC0-3 INTFLAG-clear and GPIO-pulse sequences
  live, and confirming the TX path touches zero MMIO before its
  driver-object dispatch boundary).
- Supporting, narrower hooks used along the way: `--seed-mem`
  (`PORT.GROUP0.IN` bit 22 / PA22 held high — a disclosed GPIO-input
  boundary assumption for the homing wait loop, no physical function
  claimed), `--stub-call` (skipping `DWT->CYCCNT`-based pulse-width
  delays, a hardware cycle-counter dependency structurally unrelated
  to the tick mechanism), `--watch` / `--watch-mem-write` (read-only
  confirmation instrumentation), and `--map-page` (mapping the NVM
  Software Calibration Row as a disclosed zero-filled placeholder for
  per-die analog trim data, irrelevant to any digital motor-state
  target).

**The concrete run that reaches the stable main loop**: entry at the
true `Reset_Handler`, with `--fake-tick 0x200052ec:20`, the four
clock/PLL `--mmio-force-bits`, the two SERCOM `--mmio-clear-bits`
(SWRST) plus `--mmio-force-bits` (DRE), PA22 seeded high, the DWT
delay stubbed, and `--force-reg 0x9dd4:r0:0x12`. Milestones confirmed
via `--watch`: boot/init entry (`0x9464`) at instruction 27740; the
startup reference/input routine's real timeout exit (`0x69d8`) at
64134; the disclosed radio-ID assumption firing (`0x9dd4`) at 74157;
real post-probe init resuming (`0x6190`, `0x4c20`, `0x4328`, `0x5d44`,
`0x7770`) through instruction 271845; and the real main loop's receive
call (`0x8960`) hit five times, at instructions 378402, 381341,
384252, 387163, and 390074 — a consistent ~2900-2940-instruction
cadence confirming genuine steady-state operation. Total cost from
`Reset_Handler` to first stable main-loop entry: ~390,000
instructions, ~19,500 fake ticks — in the same order as a normal
embedded boot. Across this whole run (through the fifth `0x8960`
iteration), `0x20001b14`-`0x20001b17` (a channel-busy-gate target
tracked by other investigations) recorded no write beyond the
already-known `.bss` zero-clear at startup.

## Open items

- **The TX path's real transport peripheral, still unnamed.** The
  dispatch at `0x8c10` is gated behind a runtime driver-object
  pointer, not a literal address — the same C++/HAL-style indirection
  pattern seen in the confirmed USB bring-up function
  (`FUN_0000bc44`). Static tracing found the TX path's descendants
  bracket a disable/re-enable of `EIC.INTENCLR`/`INTENSET` (a critical
  section around an interrupt-driven line — plausibly a radio
  IRQ/DIO pin or UART flow control), and `--log-mmio` confirmed zero
  MMIO accesses before the `0x8c10` boundary; continuing past it
  diverges into an unmapped read at address `0x4` within ~50
  instructions. Naming the exact peripheral needs either statically
  resolving what init function populates the driver-object pointer
  `0x8c10` reads, or concretely seeding that mode byte and object
  pointer — neither done.
- **A second, deeper NVM-erase-loop dependency**, found but not
  chased. Pushing the main-loop run tens of millions of instructions
  further reaches a real bulk-erase operation (`FUN_000098d8`/
  `FUN_000098f0`, NVMCTRL command `0xa501`), gated on
  `NVMCTRL.INTFLAG.DONE` (bit 0, `0x41004010` — modeled the same way
  as the other completion bits, and it did fire once), but the outer
  erase loop still does not visibly advance over millions of
  instructions. The likely explanation, from the loop's own
  structure, is that its per-iteration step size (read once from a
  config-structure field) is itself `0` — a firmware-configuration
  question, not a missing-completion-bit one, and not resolved here.
- **The cold-RAM pin-index artifact.** The first concrete run through
  all four TC handlers (cold RAM, no seeding) showed every channel
  resolving to the same table entry, `PA23` (index 0) — because the
  per-channel RAM index bytes were all zero before the `.data` copy
  had been observed in that particular run. This is now resolved at
  the static evidence tier (the real values, `PB10`/`PA08`/`PB12`/
  `PA10`, are compiler-baked `.data` initializers, confirmed by direct
  flash reads and disassembly of the copy loop — a stronger form of
  evidence than a concrete replay would add). One caveat carries
  forward, though: the ISR -> `FUN_00005898` -> `FUN_0000d388`
  pulse-helper *mechanism* itself was only concretely (Unicorn)
  exercised on the artifact pin (`PA23`, index 0, cold RAM) for all
  four channels — it was not independently re-run with each channel's
  real index byte seeded to confirm the mechanism against the real
  pins (`PB10`/`PA08`/`PB12`/`PA10`) individually. The static evidence
  for the real pin identities is solid; a concrete re-confirmation on
  the real pins specifically has not been done.
- **A previously unexamined NVM write path.** While classifying the
  standard-library/application boundary, a real write path to flash
  address `0x12000` was found: `FUN_0000449c` (a channel-0 move-
  complete handler) -> `FUN_000097a4` (checks a "dirty" byte at
  `+0x1002`, marks the buffer written) -> the same NVM erase/write
  primitives (`FUN_000098f0`/`FUN_0000984c`) the read side uses,
  sharing driver-object base `0x20004148`. This was found here, not
  chased further — what actually sets the `+0x1002` dirty byte, and
  whether the handler's apparent channel-0-only scope is real or an
  artifact of tracing only one of its two call sites, remain open.
  Characterizing this fully is left to whichever consolidated
  persistence dossier covers the `0x12000` config-read/write chain;
  this document only reports that the write path was found here and
  makes no claim about its resolution status elsewhere.
