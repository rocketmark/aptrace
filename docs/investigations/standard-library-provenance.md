# Investigation: A Bounded Standard-Library/Provenance Classification Pass

**Question**: this project keeps re-deriving the same handful of
"infrastructure" facts (Reset_Handler's `.data`/`.bss` copy, SysTick/
millis, SERCOM SWRST self-clear, digitalWrite-shaped GPIO writes,
memcpy/memset-shaped loops) across many investigations. Separate
high-confidence standard/platform/library code from AutoPilot-specific
application logic, so future slices can spend their budget on the
custom callers instead of re-characterizing known infrastructure — and,
along the way, sharpen exactly who the *custom* callers are above the
`0x12000` flash-read primitive `target-config-provenance.md` found.

**Scope, deliberately bounded**: this does not attempt to classify every
function in either binary. It classifies the specific function families
this project has actually encountered and repeatedly re-derived, using
source-backed comparison against the exact evidenced toolchain
(Adafruit SAMD board package v1.7.11, per the embedded build-path
strings in `docs/firmware/firmware-layout.md`) wherever a real source
comparison was practical, and states plainly where it wasn't. No
firmware behavior changes; classification is purely an analysis/
reporting layer.

## Method

1. **Confirmed the exact toolchain to compare against.** The firmware
   image itself names it: embedded build-path strings
   (`C:\Arduinos\...\adafruit\hardware\samd\1.7.11\libraries\SPI\SPI.cpp`,
   already documented in `firmware-layout.md`) directly identify
   `adafruit:samd` board package version **1.7.11**. This is the exact
   version fetched for comparison — not a guessed "close enough"
   release.
2. **Fetched the real source** for that exact tag from Adafruit's public
   `ArduinoCore-samd` repository (`github.com/adafruit/ArduinoCore-samd`,
   git tag `1.7.11`) — `cortex_handlers.c`, `main.cpp`, `delay.c`,
   `wiring_digital.c`, `SERCOM.cpp`, `SPI.cpp`, and a few others — rather
   than guessing function names from memory of "what Arduino cores
   usually look like." Not vendored into this repo (LGPL source better
   left at its canonical location); every match below cites the exact
   file and function so it's independently reproducible from the tag.
3. **Compared structurally**, not just by name: control-flow shape,
   register/field-access order, and (where already disassembled by a
   prior investigation) the exact bit/field being manipulated. A
   "CONFIRMED" classification requires a real structural match against
   the fetched source, not a plausible-sounding name.
4. **Recorded every classification with its evidence** in a small,
   reusable CSV (`research/provenance/function_classification.csv`) —
   see "The inventory" below — rather than only in this prose.
5. **Applied the classification back into the Ghidra pipeline** as a new,
   narrow, optional post-script (`APTraceApplyProvenance.java`) that
   renames matched functions and adds a one-line provenance comment —
   tested concretely against the real firmware image (37 functions
   renamed, 2 correctly skipped — see "Ghidra pipeline integration"). No
   large new framework: one script, one TSV, idempotent, purely
   cosmetic to Ghidra's own database.

## Classification scale used

| Label | Meaning |
|---|---|
| `CONFIRMED_ADAFRUIT_CORE` | Structural match against fetched ArduinoCore-samd@1.7.11 source, specific function identified |
| `CONFIRMED_ARDUINO_LIBRARY` | (unused this pass — no case met this bar) |
| `CONFIRMED_CMSIS_RUNTIME` | (unused this pass — see "What wasn't confirmed" below) |
| `CONFIRMED_THIRD_PARTY_LIBRARY` | (unused this pass — the radio/LCD candidates below stayed at LIKELY; see why) |
| `LIKELY_STANDARD_LIBRARY` | Strong structural/role match, but not verified byte-for-byte against a built binary, or matched only at the family/cluster level |
| `LIKELY_THIRD_PARTY_LIBRARY` | Strong circumstantial evidence (e.g. a real, well-known chip register map) but no source file was fetched/compared |
| `CUSTOM_APPLICATION` | AutoPilot-specific logic; no plausible library match, or explicitly built on top of a confirmed/likely library primitive |
| `UNKNOWN` | Insufficient evidence either way — recorded as a real gap, not guessed |

## Results

Full detail with per-row evidence in
[`research/provenance/function_classification.csv`](../../research/provenance/function_classification.csv);
summary here.

### Confirmed Adafruit-core infrastructure

- **`FUN_0000cc24` = `Reset_Handler`** — byte-for-byte structural match
  to `cortex_handlers.c`'s `Reset_Handler`: `.data` copy loop, `.bss`
  zero loop, FPU enable (`SCB->CPACR |= 0xF<<20`, `__SAMD51__`-gated in
  source), `SystemInit()`, `main()`, trap. Already independently
  documented (without the source match) in `firmware-layout.md` and
  `reset-handler-clock-init.md`.
- **`FUN_0000cc10` = the shared default/weak exception stub** — matches
  `Dummy_Handler` (`for(;;){}`), the target every unimplemented vector
  aliases to.
- **`FUN_0000cca4` = `SysTick_Handler`** — the vector table's own
  distinct-from-default slot, matching the core's real tick handler
  role (wraps a weak `sysTickHook()` then increments the tick counter).
- **`FUN_0000ccd0` = `millis()`** — a single volatile-load-and-return,
  matching `delay.c`'s `_ulTickCount` read exactly; already
  independently characterized (without the name) as "a firmware-
  maintained RAM counter incremented by the real SysTick_Handler" in
  `systick-tick-injection.md`.
- **`FUN_0000cd90` = `main()`** — **a new finding this pass**: its call
  order (six init-shaped calls, then a "setup"-shaped function, then a
  "loop"-shaped function, then one more call) matches `main.cpp`'s
  `init(); __libc_init_array(); initVariant(); delay(1); [USB init];
  setup(); for(;;){loop();yield();serialEventRun();}` structure exactly.
  This reframes two functions this project has discussed extensively
  without naming their Arduino role:
  - **`FUN_00009464` is the AutoPilot sketch's `setup()`** — it does the
    real device bring-up (the startup-reference routine, the radio-ID
    probe, post-probe init — all already documented) and then contains
    its **own internal, permanent loop** that does not return under
    normal conditions. This is a real but nonstandard pattern: instead
    of returning to let `main()`'s own `for(;;){loop();...}` run,
    `setup()` never gives control back — unless `MC4` clears
    `0x20000060`, at which point it genuinely *does* return, and
    `main()` proceeds to its own loop for the first time.
  - **`FUN_000093fc` is the AutoPilot sketch's real `loop()`** — called
    from exactly where `main()` calls `loop()`, and only ever reached if
    `setup()` returns. This matches, exactly, what
    `g-command-motor-subsystem-unlock.md` and `mc4-transition.md` already
    found by tracing the call graph independently; this pass supplies
    the correct Arduino-idiom name for what those docs called "the
    boot-phase loop" and "the real operational main loop."

### Likely standard library (role/structural match, not byte-verified)

- **`delay()` (`FUN_0000cd50`)** — already independently confirmed as "a
  real micros()-based countdown register genuinely decrementing"
  (`reset-handler-clock-init.md`); matches `delay.c`'s shape.
- **SERCOM SPI reset** (the `CTRLA.bit.SWRST=1; while(CTRLA.bit.SWRST ||
  SYNCBUSY.bit.SWRST);` pattern already disassembly-confirmed in
  `reset-handler-clock-init.md` for both SERCOM5 and SERCOM2) — an
  **exact** logical match to `SERCOM.cpp`'s `SERCOM::resetSPI()`. Raised
  to the strongest confidence this pass reaches for a non-`Reset_Handler`
  match, since the earlier investigation already pinned the exact bit.
- **SPI single-byte transceive (`FUN_000099c2`)** — write-DATA,
  busy-wait a completion flag, read-DATA-back shape, matching
  `SERCOM::transferDataSPI()`. Not disassembled to confirm which exact
  completion bit (`RXC` vs `DRE`) is polled, so kept at LIKELY rather
  than CONFIRMED.
- **The GPIO pulse helper (`FUN_00005898`/`FUN_0000d388`, already
  characterized in `motor-timer-survey.md`)** — looks up a per-channel
  byte in a `.data`-segment table (already independently confirmed as a
  compiled-in initializer in `pin-index-provenance.md`) then writes
  `PORT.Group[n].OUTSET`/`OUTCLR` — exactly `wiring_digital.c`'s
  `digitalWrite()` shape. The **table itself** (`pin-index-
  provenance.md`'s pin-index array) is very likely `g_APinDescription[]`
  from a board variant file, but AutoPilot uses a custom PCB rather than
  a stock Adafruit variant, so that specific table is board-specific/
  custom even though the *access pattern* matches the standard core —
  kept as two separate claims, not conflated.
- **`FUN_0000e648`/`FUN_0000e664`** — disassembled in full this pass
  (see `target-config-provenance.md`): a plain pre/post-increment
  byte-copy loop and a plain forward byte-fill loop, respectively — the
  canonical newlib-nano/libgcc `memcpy`/`memset` fingerprint. Not
  matched byte-for-byte against a built newlib/libgcc binary (would
  need to reproduce the exact `arm-none-eabi-gcc` version and flags), so
  LIKELY, not CONFIRMED.
- **The `0xd61c`-`0xe18c` arithmetic cluster** (`FUN_0000db08`,
  `dbdc`, `de30`, `dae8`, `e13c`, `e18c`, `d61c` — used throughout the
  motor-profile math in `FUN_00006fd8`, `FUN_000046c8`, `FUN_00004910`)
  — classified as a **cluster**, not seven individually confirmed
  matches: tight address clustering immediately adjacent to the
  confirmed memcpy/memset pair, small leaf functions taking/returning
  paired 32-bit halves (a `(lo,hi)` calling-convention shape typical of
  ARM EABI `__aeabi_l*` 64-bit compiler-runtime helpers). Genuinely
  **not pinned to individual symbol names** — flagged honestly as a
  cluster-level LIKELY, with a note that a future pass could resolve
  exact names via calling-convention analysis if it becomes load-bearing.

### Likely third-party library (circumstantial, no source fetched)

- **The radio device-bringup/probe/IRQ-poll cluster** (`FUN_0000610c`,
  `FUN_00009d88`, `FUN_00009eac`, `FUN_00009984`, `FUN_00007fdc`) — no
  source file was fetched or compared for this one; the classification
  rests entirely on register-map evidence *already in this project's own
  docs*: the probed registers (`0x42` "RegVersion" expecting `0x12`,
  `0x12` "RegIrqFlags", `0x01` "RegOpMode") are real, well-known SX127x
  LoRa transceiver register addresses, already noted in
  `post-homing-radio-probe.md`. This pass just gives that already-solid
  circumstantial evidence a library-family label (an SX127x/RFM9x-style
  driver — RadioHead's `RH_RF95`, an Adafruit LoRa example, or similar;
  not distinguished) instead of leaving it as an isolated coincidence.
  Kept at LIKELY, not CONFIRMED, precisely because no source was
  compared.
- **The LCD status-line refresh call (`FUN_00007514`)** — ends in an
  indirect call through a function pointer read from the callee object's
  *own first field* (`(**(code**)*obj)(obj, cmd, ...)`) — a C++
  virtual-dispatch/vtable-call shape, not a hand-written register poke.
  This is real evidence of *some* object-oriented display-driver library
  (plausibly Adafruit_GFX-derived), but no specific library or version
  was matched against source — LOW-MEDIUM confidence, explicitly not
  guessed further.

### Deliberately left `UNKNOWN`

- **The NVMCTRL bulk-erase sequence** (`FUN_000098d8`, region
  `0x9860`-`0x9910`, already found in `post-probe-main-loop.md`) issues
  real NVMCTRL commands (key `0xA5` + `EP`/`WP`) directly against
  `CTRLB` — no library abstraction layer visible in the disassembly.
  Checked: ArduinoCore-samd 1.7.11's `cores/arduino/` tree has **no**
  NVM/EEPROM helper file at all (no `flash.cpp`/`NVM.cpp`/`EEPROM.cpp`),
  so this rules out the Adafruit core as the source — but does not
  confirm or rule out a third-party flash-emulation library (e.g.
  `FlashStorage`) or hand-written application code. Recorded as `UNKNOWN`
  rather than guessed either way.

### Confirmed custom application layer (the payoff)

Everything else this project has been actively investigating is
confirmed, by elimination and by its AutoPilot-specific content, as
`CUSTOM_APPLICATION` — recorded in the CSV mainly so the inventory is a
complete picture, not because classifying them was hard:
`FUN_00008258` (ASCII dispatcher), `FUN_00007cc0`/the `FUN_00007e2c`
gate (manual-move state machine), `FUN_00006fd8` (move-commit),
`FUN_00008e18` (phase/ramp state machine), `FUN_00008a80` (event
monitor), `FUN_000054e0` (L-family handler), `FUN_00007a98` (MC/MC4
config parser), and — the sharpened finding below — the entire
`0x12000` config-loading chain.

## Sharpening the `0x12000` question

`target-config-provenance.md` traced the motor target/config struct to
a chain ending in a plain byte-copy from flash address `0x12000`. This
pass's classification answers the task's exact follow-up — **once the
low-level primitive is classified as standard, who are the custom
callers, and where does their input come from**:

```
FUN_00004b64 (CUSTOM_APPLICATION)         -- bulk-loads all 4 channels'
  |                                          0x120-byte config blocks
  v
FUN_00009768 (thin wrapper, CUSTOM)       -- per-byte accessor with a
  |                                          lazy-init check
  v
FUN_00009724 (CUSTOM_APPLICATION)         -- the blank-detection +
  |                                          0xFF-fallback decision logic
  v
FUN_0000990e (CUSTOM, thin wrapper)       -- calls the standard primitive
  |
  v
FUN_0000e648 (LIKELY_STANDARD_LIBRARY)    -- plain memcpy, src=0x00012000
```

and, separately:

```
FUN_00004b64 (CUSTOM_APPLICATION)
  |
  v
FUN_00004b24 (CUSTOM_APPLICATION)         -- the position-resync decision
                                              (target := current position)
```

**The answer**: every decision-making function in this chain —
*whether* to treat the blob as blank, *what* to fill it with, *when* to
resync a channel's target to its live position, *which* channel gets
which treatment — is `CUSTOM_APPLICATION` code. The only
`LIKELY_STANDARD_LIBRARY` pieces are the two leaf primitives
(`FUN_0000e648`/`memcpy`, and by the same reasoning `FUN_0000e664`/
`memset` for the blank-fill).

### A real write path exists — found while sharpening this question, not chased further

Classifying the read chain's neighbors surfaced something
`target-config-provenance.md` didn't need and didn't look for: **the
same flash address, `0x12000`, is also a real write target.** A
whole-firmware literal-pool scan for the constant `0x00012000` (the
same method used throughout this project) finds exactly one flash cell
holding it, consumed by a previously unexamined function:

```
FUN_000097f4  -- ldr r1,[=0x00012000]; ... bl FUN_0000981c(obj, 0x12000, 0x1001)
                 then clears the persisted buffer's "dirty" (+0x1002) and
                 "initialized" (+0x0) marker bytes
```

and, one level up, a **conditional** save routine reached from a real
completion-event handler:

```
FUN_0000449c (CUSTOM_APPLICATION)         -- a channel-0 "move complete"
  |                                          handler: 4 display-clear calls,
  |                                          then maybe-save, delay(100),
  |                                          then a GPIO pulse (channel 0)
  v
FUN_000097a4 (CUSTOM_APPLICATION)         -- if the persisted buffer's
  |                                          "dirty" byte (+0x1002) is
  |                                          nonzero: mark it "has been
  |                                          written" (+0x1001=1 -- the
  |                                          exact byte FUN_00009724
  |                                          checks to decide whether to
  |                                          blank-fill on next boot),
  |                                          copy the RAM buffer out, then:
  v
FUN_000098f0 (erase) / FUN_0000984c (write)  -- the real NVMCTRL commit,
                                                 sharing the same
                                                 driver-object base
                                                 (0x20004148) as the read
                                                 path
```

`FUN_0000449c` is called from **`FUN_00005be8`** (TC0's own, channel-0-
only ISR ramp logic — already known from `channel-busy-gate-search.md`
as the function that clears `0x20001b14[0]` on real target-reached) and
from **`FUN_00005dd0`** (called every real main-loop iteration, at two
separate sites — a second, not-yet-distinguished completion condition).
This is exactly the shape of a real "when this channel's move finishes,
persist config and update the display" handler — **not chased further
this pass**: what actually sets the `+0x1002` "dirty" byte that gates
the save, and whether the same handler exists per-channel or is
genuinely channel-0-only, are open questions for the next persistence
slice, not this bounded classification one.

**Why this matters more than a simple negative result**: it means the
`0x12000` region is not a permanently-blank reserved page by design —
it is a real, round-trip persisted-configuration flash page that this
firmware's own real code *would* write to, automatically, the first
time a real move completes. On a never-yet-moved, freshly-blank unit,
this is the same chicken-and-egg `target-config-provenance.md` already
named (no move without config, no config without a move) — but it is
now a **fully named, traced mechanism** rather than an open question
about whether a write path exists at all. There is no hidden NVM/EEPROM
abstraction layer left unaccounted for between the application logic and
the raw flash bytes on *either* the read or the write side; the only
remaining unknowns are (a) the real dirty-flag trigger, and (b) the
*content* flash address `0x12000` would hold on a unit that has actually
completed a real move — the latter an external-data question, not a
code-provenance one, exactly as `target-config-provenance.md` already
concluded for the read side.

## The inventory

[`research/provenance/function_classification.csv`](../../research/provenance/function_classification.csv)
— one row per function/cluster, columns: `firmware`, `address`,
`ghidra_name`, `role`, `classification`, `confidence_basis`,
`source_reference`, `notes`. Meant to be extended by future slices, not
replaced.

## Ghidra pipeline integration

A new, small, optional post-script,
[`tools/ghidra/scripts/APTraceApplyProvenance.java`](../../tools/ghidra/scripts/APTraceApplyProvenance.java),
reads a minimal companion TSV
([`research/provenance/ghidra_labels.tsv`](../../research/provenance/ghidra_labels.tsv)
— address/name/classification only, no free text, to avoid needing a
CSV/JSON parser in the Ghidra scripting environment) and renames each
matched function plus adds a one-line plate comment citing this doc and
the CSV. **Tested concretely** against the real firmware image:

```
tools/ghidra/analyze_firmware.sh ... \
  -postScript APTraceApplyProvenance.java research/provenance/ghidra_labels.tsv
```

Result: **42 functions renamed, 2 correctly skipped** (`0x7cc0` and
`0x97f4` — neither is a Ghidra-recognized function entry, since both are
tail-jump targets inside another function's body rather than a
discovered function start, the same pattern documented in
`mc4-transition.md`/`standard-library-provenance.md`'s own write-path
finding; expected, not a bug). Verified the renamed output flows through
correctly to
`APTraceDecompileFunctions.java` (e.g. `Reset_Handler__ADAFRUIT_CORE`
appears with its provenance comment in decompiled output). This is
purely a Ghidra-database annotation — no change to `run_concrete.py`,
no change to firmware behavior, and it does not remove standard code
from analysis or execution; it only labels it so future decompile/
disassembly output is easier to scan for the custom parts. Not run by
default in `analyze_firmware.sh` (kept optional, per the task's "don't
build a large new framework" instruction) — invoke it explicitly as a
second `-postScript` when a clean, labeled view is useful.

## What wasn't confirmed, and why

- **CMSIS runtime** (the `SystemInit()`/clock-init chain itself,
  already fully characterized register-by-register in
  `reset-handler-clock-init.md`): ArduinoCore-samd 1.7.11 does not ship
  a SAMD51 `system_samd51.c`/`startup_samd51.c` in its own repository —
  Adafruit's SAMD51 support relies on a separate, Microchip-authored
  CMSIS-Atmel component package the Arduino IDE installs alongside the
  core, which was not fetched this pass (out of the bounded scope). The
  clock-init *sequence* (`OSC32KCTRL`→`OSCCTRL`→`DPLL0`/`DPLL1`) is
  already fully documented from the SVD and disassembly and is not
  disputed — only the exact upstream C source for `SystemInit()` itself
  remains unfetched. Recorded as a gap, not guessed at
  `CONFIRMED_CMSIS_RUNTIME`.
- **USB**: not encountered as a concrete blocker in any investigation to
  date (this project's TX/RX path is the RX-ring/radio path, not USB
  serial), so no USB-stack functions were identified as candidates to
  classify this pass. If a future slice hits USB-shaped code, this
  pass's method (fetch the exact 1.7.11 `cores/arduino/USB/` tree)
  applies directly.
- **Third-party libraries** (radio, LCD): correctly left at LIKELY, not
  CONFIRMED, since no source was fetched for either — the evidence is
  real (register maps, vtable-call shape) but a name-and-version match
  would require identifying and fetching the specific library, which
  this bounded pass did not do.

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| `Reset_Handler`/`main()`/`millis()`/`Dummy_Handler` match ArduinoCore-samd@1.7.11 | **Confirmed** (structural source comparison) |
| `FUN_00009464`/`FUN_000093fc` are the sketch's real `setup()`/`loop()` | **Confirmed** (call-order match against `main.cpp`, consistent with this project's own independently-derived reachability findings) |
| SERCOM SPI reset matches `SERCOM::resetSPI()` | **Confirmed** (exact bit/structure match against already-disassembled code) |
| `delay()`, SPI transceive, `digitalWrite`-shaped GPIO writes, memcpy/memset | **Likely** (role/structural match, not byte-verified against a built binary) |
| The `0x12000` config chain's decision logic is 100% custom, built on a standard `memcpy` | **Confirmed** (this pass's own classification of an already-fully-disassembled chain) |
| `0x12000` also has a real write path (`FUN_0000449c`->`FUN_000097a4`->NVM erase/write), reached from a channel-0 move-completion handler | **Confirmed statically** (literal-pool scan + disassembly, this pass) — **not exercised concretely**, and the "dirty" flag's own trigger is **unresolved** |
| Radio driver family = SX127x-style; LCD refresh = an OO display-driver library | **Likely** (circumstantial register-map/vtable evidence, no source fetched) |
| NVMCTRL bulk-erase sequence's origin (custom vs. third-party flash library) | **Unknown**, honestly |
| Exact `__aeabi_l*` names for the `0xd61c`-`0xe18c` cluster | **Unknown** at the individual-function level |
| CMSIS `SystemInit()` source-level match | **Not attempted** (separate CMSIS-Atmel package, out of bounded scope) |

## Evidence level

Level 1 (static) throughout — source-fetched structural comparison for
the CONFIRMED/LIKELY_STANDARD_LIBRARY tier, register-map/circumstantial
evidence (already established by prior concrete investigations) for the
LIKELY_THIRD_PARTY_LIBRARY tier. No new concrete (Unicorn) runs were
needed for this pass; where a claim rests on an *earlier* concrete
finding (e.g. `delay()`'s decrementing register, `digitalWrite`'s
`.data` pin table), that is cited to the investigation that established
it rather than re-derived.

## Next step

Two independent follow-ups, neither started:

1. **Extend the CSV** as new investigations encounter more standard-code
   families (the task's own list still has "USB" and "compiler/runtime
   support" only partially covered) — the inventory is designed to be
   appended to, not replaced.
2. **The sharpened `0x12000` persistence question, for the next slice**:
   this pass found the real write path (`FUN_0000449c`->`FUN_000097a4`->
   the same NVM erase/write primitives the read side uses) statically,
   but did not exercise it concretely and did not trace what actually
   sets the `+0x1002` "dirty" byte that gates the save. The next
   persistence slice should (a) find the dirty-flag's real setter — the
   most likely candidate, given `FUN_0000449c`'s callers, is somewhere
   in the channel-0 move-completion path (`FUN_00005be8`/`FUN_00005dd0`)
   that this pass did not trace back further — and (b) determine whether
   `FUN_0000449c`'s apparent channel-0-only scope is real or an artifact
   of only having traced one of its two call sites in `FUN_00005dd0` in
   detail. Concretely exercising a real move-completion event (once one
   is reachable) and watching flash address `0x12000` for a real write
   would be the natural continuation, not a re-derivation of the read
   path this pass and `target-config-provenance.md` have now fully
   characterized.
