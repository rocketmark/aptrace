# Boot Sequence and Hardware Bring-Up — Current Model

This dossier consolidates a series of slice-by-slice investigations that
together took a concrete Unicorn run from `Reset_Handler` all the way
to a stable, repeating real main loop in the AutoPilot firmware
(`firmware_autopilot868.bin`, ATSAMD51J19A). Along the way they
resolved the tick source, four real clock/peripheral completion-bit
polls, a real radio chip-ID probe and its infinite-retry failure mode,
the RX injection point, the TC0-TC3/TCC1 motor-timer-to-GPIO
mechanism and its real per-channel pin assignments, the exact
Adafruit ArduinoCore-samd toolchain the firmware was built from, and
the EIC/EXTINT interrupt-callback dispatch mechanism. The individual
investigation slices are superseded by this document and removed;
their process is preserved in git history.

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

**The TX path's real transport, `0x8c10` — CONFIRMED.** `0x8c10`
(`FUN_00008c10`, called from `phase_ramp_state_machine__CUSTOM`,
`sketch_setup__CUSTOM`, and several unnamed static-flow ancestors)
reads the SAME mode-selector byte as the RX injection point above
(`*0x2000006a`) and, for the real runtime value `1`, dispatches to a
real, initialized driver object at `0x20004160`:

- **Object initialization**: constructed by `FUN_00009934` (a generic
  driver-object constructor: `object+0x00` = vtable pointer,
  `object+0x10` = a numeric parameter, `object+0x18` = an embedded
  sub-object pointer, `object+0x1c`/`+0x20`/`+0x24` = three PORT
  pin-table indices, plus a call to the reference-confirmed
  `Stream::setTimeout()` at `0xb6fa` — this driver class derives from
  `Stream`). Reached via a tiny thunk at `0x9f3c`
  (`ldr r0,[pc,#4]; b.w 0x9934`, itself vtable[0] of the SAME class),
  called from inside `radio_irq_flags_poll__THIRD_PARTY`'s own extended
  body, in turn called from `radio_rx_drain__THIRD_PARTY` — i.e. this
  object is constructed as part of the SAME boot-time radio-driver
  bring-up as the already-documented chip-ID probe, confirmed to
  execute exactly once during real boot, before main-loop steady state
  (`census reduce`'s own `dynamic_coverage` for the `boot` scenario:
  `0x9934`/`0x9f3c`/`0x9e70`/`0x7fdc` each hit exactly once).
- **Real object contents** (dumped from a completed `AUTOPILOT_RECIPE`
  boot run, at main-loop steady state — not assumed): vtable pointer
  `0x00014050` (flash, 7 real entries, `vtable[7]` already string data);
  `+0x10 = 0x007a1200` (8,000,000 — a plausible SPI clock rate);
  `+0x18 = 0x20004198` (`= self+0x38`, an embedded sub-object, not a
  separate heap allocation); pin-table indices `+0x1c = 0x30 (48)`,
  `+0x20 = 0x23 (35)`, `+0x24 = 0x22 (34)`, resolved via the SAME
  `g_APinDescription`-shaped flash table already used for the TC-channel
  pins (`0x14284`, 24 bytes/entry) to **PA15, PA16, PA17**.
- **Resolved indirect target**: `vtable[1] = 0x00009a96`
  (`FUN_0000b216`: `r3 = *object; r3 = *(r3+4); bx r3` — a real
  vtable dispatch, reached via wrapper `FUN_0000b23a`). This exact
  edge (`0xb234`'s `bx r3` → `0x9a96`) was ALREADY present in
  `indirect_edge_resolutions` as `DYNAMICALLY_OBSERVED` from the
  existing `boot` scenario capture (the real boot itself already calls
  `0x8c10` once during setup) — this investigation independently
  re-confirmed it via a fresh, unstubbed `ConcreteMachine.call(0x8c10,
  ...)` from the completed boot snapshot (see "Test / repro" below), it
  does not add a new row. A SECOND vtable slot used elsewhere in this
  driver class, `vtable[0]` via a different wrapper (`FUN_0000b242`,
  `bx r3` at `0xb246`), remains `UNRESOLVED` — it is called only from
  two unrelated functions (`0x7f8e`, `0xb2c8`), never from the `0x8c10`
  chain, and was not chased further (out of this investigation's scope).
- **HAL functions actually reached** (real, unstubbed execution):
  `0x9a96` (vtable[1], FIFO-write) writes the caller's buffer bytes
  one-by-one via `radio_reg_readwrite__THIRD_PARTY` (`0x9984`) /
  `SERCOM_transferDataSPI__STANDARD_LIBRARY` (`0x99c2`) at register
  `0x22`, matching the SAME driver primitives already confirmed for the
  boot-time radio chip-ID probe; `radio_reg_readwrite` itself calls
  `digitalWrite_pulse_shared__STANDARD_LIBRARY` (`0xd388`, CS
  low/high), `FUN_0000a000`/`FUN_0000a03c` (begin/end transaction —
  SERCOM SWRST + baud config on enter, `cpsie i`/conditional
  `EIC.INTENCLR`/`INTENSET` on exit), and `FUN_0000a05c` (a one-level
  dereference into the embedded sub-object, tail-calling the real
  ArduinoCore-samd SERCOM SPI transceive primitive at `0xb468`).
- **Exact peripheral/registers touched** (real `--log-mmio`, unstubbed):
  `SERCOM2` in **SPI Master mode** — `CTRLA` (`0x41012000`, SWRST +
  ENABLE), `CTRLB` (`0x41012004`), `BAUD` (`0x4101200c`), `INTFLAG.DRE`
  (`0x41012018`), `SYNCBUSY` (`0x4101201c`), `DATA` (`0x41012028`,
  written once per real payload byte); `PORT.GROUP0` (`PA15`) `DIRSET`/
  `OUTSET`/`OUTCLR`/`PINCFG15` (chip-select, toggled low then high
  around the transaction, via the same `digitalWrite`-shaped helper
  already confirmed for the TC-channel pins); `GCLK.PCHCTRL3`/
  `PCHCTRL23` (peripheral clock gating around the transaction).
  **Zero DMAC addresses touched** — this transfer is CPU-driven/
  polled (`INTFLAG.DRE`-waited), not DMA. The `EIC.INTENCLR`/
  `INTENSET` critical section (`0x4000280c`/`0x40002810`, previously
  flagged as "plausibly a radio IRQ/DIO pin or UART flow control") is
  REAL CODE reachable from `0xa000`/`0xa03c`, but its trigger condition
  (a flag byte in the embedded sub-object, `0x200041a2` at steady
  state) reads `0` for the real, confirmed driver instance — it did NOT
  fire during a real, traced transmit. **PA16**/**PA17** (the other two
  pin-table indices in the object, plausibly RESET/DIO0 for an SX127x-
  style module) are never touched by a transmit call itself — consistent
  with being boot-time-only (reset) or RX-side (DIO/IRQ) pins, neither
  independently confirmed by this investigation.
- **Transport identity: CONFIRMED at the MCU-peripheral level** — SPI
  via `SERCOM2` (Master mode), chip-select `PA15`, no DMA, EIC not
  active for TX. The specific EXTERNAL device on the other end of that
  SPI bus is, at most, **PROBABLE**: the register-address pattern
  (`0x81`/`0x83` for mode, `0x22` for FIFO base, `0x42`↔`0x12` for the
  boot-time chip-ID check) matches the textbook SX127x/RFM9x LoRa
  register map already noted for the chip-ID probe, and this TX path
  demonstrably reuses the SAME driver object/functions — but no
  external, hardware-independent confirmation of the exact chip model
  or of a physical connector/antenna identity exists, and none is
  claimed. See "Test / repro" below for the exact reproduction.

**The EIC/EXTINT interrupt-callback dispatch mechanism — vectors
identified, registration path exhaustively absent.** Vector-table
indices 28-43 correspond exactly, in order, to the ATSAMD51 datasheet's
`EIC_0_IRQn`…`EIC_15_IRQn` (confirmed against the vendored
`samd51g19a.h`, not inferred from code shape). Each of the 16
corresponding stub functions (flash `0xcbb0`-`0xcc0a`) loads `R0` with
its own line number (0-15, one per stub, confirmed by decoding each
`MOVS R0,#N` immediate directly) and then unconditionally branches
(not calls) into one shared dispatcher at `0xcb6c`. **The dispatcher
does not use `R0` as its dispatch index** — `R4` is a separate,
loop-carried scan counter the dispatcher itself initializes to `0` and
increments every iteration, independent of which physical EIC line
woke it; `R0` is loaded and never referenced again. The dispatcher's
own literal-pool loads (read directly from the firmware image, not
assumed) give the concrete RAM/peripheral layout:

| Register | Value | Role |
|---|---|---|
| `R6` | `0x40002800` | EIC peripheral base (matches the ATSAMD51 SVD/header exactly) |
| — | `0x14` (20) | `EIC.INTFLAG` offset the dispatcher reads (`R6+0x14`) — matches the header exactly |
| `R8` | `0x2000525c` | callback-table base (RAM) |
| `R5` | `0x200052a0` | mask/ISR-list base (RAM) |
| `R7` | `0x200052e4` | `nints`-style registered-interrupt count address (RAM) |

The spacing between these RAM addresses is regular: `0x200052a0 -
0x2000525c = 0x44` (68 bytes / 17 words), and `0x200052e4 - 0x200052a0
= 0x44` (68 bytes / 17 words) — consistent with two fixed-size,
back-to-back 17-word regions followed immediately by the count, but
this is an **inference from spacing alone**; no array-bounds
declaration was found to confirm 17 as the real entry count. Callback
stride is 4 bytes; the dispatch call itself is a real, non-fabricated
register-indirect `BLX_r_T1` at `0xcb92` (`callback_table[R4]`,
Macaw's own `ParsedCall` terminator, correctly classified
`true_indirect_call` — see
[`docs/tooling/macaw-analysis.md`](../tooling/macaw-analysis.md)).
Callback entries live in RAM, not flash — nothing in the compiled
image statically initializes them.

**No registration routine was found.** Two independent, whole-firmware
structural searches — a literal-pool byte scan for all three RAM
addresses, and a full-binary Thumb2 MOVW/MOVT disassembly sweep (to
catch constant materialization that doesn't use a literal pool) — each
find these three addresses embedded exactly **once** anywhere in the
~200 KB image: in the dispatcher's own prologue. Ghidra's independent
static cross-reference table agrees: the only recorded access to any
of the three addresses, from any function, is the dispatcher's own
read of the count. One promising lead — the same EIC base-address
literal also appears near flash `0xa038`/`0xa058` — was chased and
resolves against THIS SAME document's own finding above: those
addresses belong to `0xa000`/`0xa03c`, the already-documented SPI
begin/end-transaction helpers (SERCOM SWRST + conditional
`EIC.INTENCLR`/`INTENSET` — see "The TX path's real transport" above),
which is unrelated to the callback/mask/count structure. This is an
**exhaustive static negative result, not proof that runtime
registration is impossible** — no dynamic (Unicorn) check was run for
this specific question. The best current interpretation: this is
linked Arduino-SAMD-core interrupt-attach platform infrastructure
(present because the vector table references it) whose application use
is **not established** by any evidence gathered so far.

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

**The real, unstubbed TX call**: from that SAME completed boot
snapshot (`ConcreteMachine` reused via `fresh=False`, current SP), a
direct `ConcreteMachine.call(0x8c10, args=[buf_addr], stub_calls=[])`
with a real (non-empty) buffer runs the ENTIRE dispatch chain for
real — mode-byte read, `radio_irq_flags_poll`'s pre-transmit IRQ-flag
pokes, the `0xb23a`→`0xb216`→`0x9a96` vtable[1] dispatch, the real
per-byte `SERCOM2` SPI write loop, and the final `RegOpMode`-style
write — with only `mmio_clear_bits=[(0x41012000, 0x1)]` (SERCOM2
CTRLA/SYNCBUSY SWRST self-clear — the SAME real-hardware fact
`AUTOPILOT_RECIPE` already discloses for this exact address/bit at
boot time, needed again because this driver issues its own SWRST at
the start of each transaction) and the SAME already-cited DWT delay
stub (`stub_calls=[0xcd34]`, needed only for the post-write guard-time
wait to terminate in Unicorn's zero-behavior MMIO model). With both
applied, `CallResult.returned = True` after 6,465 real instructions —
no other assumption, force, or stub was required; the TX function's
own real body ran unmodified throughout.

## Open items

- **RESOLVED this pass — the TX path's real transport peripheral.**
  Previously: "gated behind a runtime driver-object pointer... naming
  the exact peripheral needs either statically resolving what init
  function populates the driver-object pointer, or concretely seeding
  that mode byte and object pointer — neither done." Both are now done
  — see "The TX path's real transport, `0x8c10` — CONFIRMED" above:
  the object is constructed at boot by `FUN_00009934`, its real
  contents were dumped from a completed boot snapshot, its vtable[1]
  indirect dispatch (`0x9a96`) was independently reconfirmed, and a
  real, unstubbed `0x8c10` call was traced end-to-end to SERCOM2 SPI
  Master + PORT.GROUP0 (PA15 chip-select) with zero DMAC involvement.
  The earlier note about "diverges into an unmapped read at address
  `0x4`" described what happens continuing PAST `0x8c10` with a
  synthetic/uninitialized object — using the REAL object, it does not
  diverge; it completes cleanly (`CallResult.returned = True`).
  Remaining, disclosed uncertainty: the external device's exact chip
  model/physical connector identity (PROBABLE, not CONFIRMED — see
  above), and a second, unrelated vtable slot on the same driver class
  (`vtable[0]`, `0xb246`) that stays `UNRESOLVED` (never called from
  the `0x8c10` chain).
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
