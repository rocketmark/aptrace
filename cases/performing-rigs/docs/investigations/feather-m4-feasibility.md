# Feather M4 Express Feasibility — Running Original AutoPilot Firmware

> **2026-10-19 safety and evidence update:**
> [Minimum startup / READY investigation](feather-minimum-ready.md) supersedes
> §8's proposed physical power-up/jumper trial and its assurances about brief
> contention and recovery. Do not run the original image on an intact Feather
> to test whether its QSPI flash survives. Electrical isolation must first be
> validated. Historical receive-loop success does not establish READY or USB
> command responsiveness. Fresh replay is currently blocked by a host Unicorn
> SIGILL before target execution; see the new report for artifacts and next
> experiment.

**Question.** Before a physical Adafruit Feather M4 Express exists in
this investigation, how far does the real, unmodified AutoPilot
firmware (868/915) run against a Feather M4's actual hardware
characteristics instead of AutoPilot's own board, and is flashing the
unmodified image onto a real Feather electrically safe to attempt?

**This is not a new emulator-building effort.** It reuses, unmodified,
the Unicorn-based concrete-execution harness
(`tools/unicorn/concrete.py`) and the boot-recipe mechanism
(`config/boot_recipes.py`) that already, before this investigation,
boots AutoPilot868/915 from the real `Reset_Handler` to real main-loop
steady state — see
[`boot-and-hardware-bringup.md`](boot-and-hardware-bringup.md). The new
work is a second, Feather-grounded set of environmental assumptions for
the SAME firmware image (`FEATHER_M4_PROFILE`), a Feather M4 pin/
hardware-component model (`config/feather_m4.py`), and the GPIO safety
comparison between them.

## 1. Engine choice: Renode evaluated, not adopted

Renode's only pre-built ATSAMD51 platform (`atsamd51g19a`) models CPU
(Cortex-M), NVIC, one SAMD5-family UART, and DWT — nothing for SERCOM,
PORT/GPIO, the GCLK/MCLK/OSCCTRL clock tree, ADC/DAC, or NVMCTRL, all of
which this firmware's own `Reset_Handler`→`main()` path exercises
unconditionally at boot (see §4 below). That is strictly less capable
than this project's existing Unicorn harness, which has already reached
real main-loop steady state for this exact firmware family. Per
`CLAUDE.md`'s "do not replace existing infrastructure without evidence
it would improve this task," Renode was not adopted; building the
missing SERCOM/PORT/clock-tree peripheral models in Renode's
platform-description language would be strictly more work than reusing
what already exists here, for no demonstrated benefit. Classification:
`CONFIRMED` (Renode's own shipped platform file is this limited —
verified against its public supported-boards documentation, not
assumed).

## 2. Cortex-M feature ledger

What `ConcreteMachine` (`tools/unicorn/concrete.py`) actually emulates,
for this investigation's purposes — unchanged by this investigation,
recorded here because the task requires disclosing it, not because
anything was modified:

| Feature | Status | Evidence |
|---|---|---|
| Thumb/Thumb-2 instruction decode and execution | **Emulated** (Unicorn's real `UC_CPU_ARM_CORTEX_M4` CPU model, `UC_MODE_THUMB \| UC_MODE_MCLASS`) | `concrete.py:432-433` |
| Core registers (R0-R12, SP, LR, PC, CPSR) | **Emulated**, real | `concrete.py:63-69` |
| Cortex-M Private Peripheral Bus (SysTick, NVIC, SCB, MPU, DWT MMIO) | **Mapped, not functionally modeled** — zero-behavior RAM (reads return last-written value), present only so ordinary startup/delay code touching this address range doesn't fault | `concrete.py:83-87` |
| NVIC asynchronous interrupt delivery / EXC_RETURN / priority masking | **Not modeled.** A narrow, evidence-bounded `ConcreteMachine.deliver_interrupt` primitive exists (real handler execution, real peripheral-pending state seeded at one disclosed synchronization point) but is used only by `MANDO_RECIPE`; neither `AUTOPILOT_RECIPE` nor `FEATHER_M4_PROFILE` uses it, since this investigation never reached a point requiring it | `concrete.py:967-985`, `boot_recipes.py`'s `interrupt_bridges` |
| FPU (VFP) instructions | **Not stress-tested.** `Reset_Handler`'s own `SCB->CPACR \|= (0xF<<20)` (FPU enable) executes and was observed in every run; no VFP instruction execution was specifically checked for in this pass's traced boot path. `UC_CPU_ARM_CORTEX_M4` is Unicorn's own M4F-capable model, but this investigation makes no independent claim about VFP correctness | `boot-and-hardware-bringup.md` §1 |
| General MMIO peripheral registers (SERCOM, PORT, GCLK, etc.) | **Zero-behavior by default** (reads return last-written value; no real peripheral semantics) — real behavior is modeled only via disclosed, cited, address-scoped hooks (`--mmio-force-bits`/`--mmio-clear-bits`/`--force-reg`/`--fake-tick`), never a blanket "always succeed" | `run_concrete.py`'s module docstring, `boot_recipes.py`'s `assumptions` lists |
| Unmapped-memory faults | **Real** — an access outside the mapped flash/RAM/MMIO/extra-maps regions raises `UC_ERR_*` and the run's `error`/`stop_reason` record it; never silently skipped | `concrete.py`'s `hook_mem_unmapped` |

No unsupported instruction or silently-skipped fault occurred in any
run this investigation performed (`error_free: true` in every captured
snapshot — see `cases/performing-rigs/research/generated/feather-m4/*.json`).

## 3. The two hardware profiles

Both profiles run the identical firmware image from the identical
`Reset_Handler` entry point (`0xcc24` for `autopilot868`, remapped via
this project's existing EXACT-fingerprint sibling mechanism for
`autopilot915`), with identical flash/RAM/MMIO geometry (flash base
`0x4000`, RAM base `0x20000000`/192 KB, MMIO window `0x40000000`/64 MB —
read from this case's own census DB firmware rows, not hand-picked).
Only the *environmental assumptions* differ.

### AutoPilot profile (`AUTOPILOT_RECIPE`, unchanged by this investigation)

The pre-existing, already-proven recipe — see
[`boot-and-hardware-bringup.md`](boot-and-hardware-bringup.md) for its
full evidence chain. Included here only as the baseline to compare
against.

### Feather M4 profile (`FEATHER_M4_PROFILE`, new, `config/boot_recipes.py`)

Derived from `AUTOPILOT_RECIPE` by reclassifying every one of its
disclosed assumptions:

| Assumption | Classification | Carried to Feather profile? |
|---|---|---|
| `--fake-tick` (RAM tick counter mechanism) | Generic SAMD51/firmware mechanism | **Kept** |
| 4× clock/PLL `mmio_force_bits` (XOSC32KRDY, DFLLRDY, DPLL0/1 LOCK+CLKRDY) | Generic SAMD51 chip behavior (real silicon self-sets these after its own preceding write, on any board) | **Kept** |
| SERCOM5/SERCOM2 SWRST self-clear (`mmio_clear_bits`) + DRE-on-enable (`mmio_force_bits`) | Generic SAMD51 peripheral-enable-time self-reporting, independent of what (if anything) is wired downstream of the SERCOM's pins | **Kept** |
| NVMCTRL `INTFLAG.DONE` (`mmio_force_bits`) | Generic SAMD51 chip behavior | **Kept** |
| DWT delay `stub_call` | Generic (Unicorn's zero-behavior MMIO never advances `DWT->CYCCNT`; structurally unrelated to any board) | **Kept** |
| NVM Software Calibration Row `map_page` | Generic SAMD51 chip-architecture fact (a real, factory-programmed per-die area on every SAM D5x/E5x) | **Kept** |
| `--force-reg 0x9dd4:r0:0x12` (radio chip-ID stand-in) | **AutoPilot-board-specific**: stands in for "a radio module is present and answers correctly." A bare Feather M4 has no device wired to PA15/PA16/PA17 at all — those pads don't even appear in `feather_m4.FEATHER_M4_PINS` | **Dropped** |
| `--seed-mem 0x41008020` (PA22/`PORT.GROUP0.IN` bit 22 held high) | **AutoPilot-board-specific**: `boot-and-hardware-bringup.md` itself discloses "no physical function claimed" for this seed. PA22 is a plain, otherwise-unconnected Feather header pin (Arduino D12) | **Dropped** |

No new peripheral behavior was added for the Feather profile — it is
strictly AutoPilot's own recipe with the two board-specific stand-ins
removed, run on the exact same engine.

## 4. Startup traces

Both profiles were run for both firmware images via
`cases/performing-rigs/scripts/feather_m4_compare.py` (new, this
investigation), which reuses `boot_recipes.py`'s own `build_machine`/
`apply_recipe`/`init_status_for` — the identical path
`tools/census/reduce.py` uses for a real boot capture, not a
hand-rolled invocation. Raw snapshots:
`cases/performing-rigs/research/generated/feather-m4/*.json`.

**Firmware image hashes** (from `cases/performing-rigs/research/firmware/originals/SHA256SUMS.txt`):

| Image | SHA-256 |
|---|---|
| `firmware_autopilot868.bin` | `6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3` |
| `firmware_autopilot915.bin` | `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |

### AutoPilot profile — both images (regression check)

`init_status=complete`, `stop_reason="max watch hits (14) reached at
0x00008960"`, `instructions_executed=403199`, `error_free=true` — for
**both** `autopilot868` and `autopilot915` (the sibling remap via this
project's existing exact-fingerprint mechanism reproduced identical
instruction counts, as `boot-and-hardware-bringup.md`'s own prior
finding that 868/915 differ only in an RF-band string predicts).
Exactly reproduces the already-documented milestone sequence
(`0x9464`→`0x69d8`→`0x9dd4`→ five post-probe resumes →`0x8960`). This is
a **regression confirmation**, not new research — included to establish
that the comparison's baseline is real before trusting the Feather
side's divergence.

### Feather M4 profile — both images

`init_status=partial-justified`, `stop_reason="instruction limit
reached"`, `instructions_executed=4,000,000` (the full requested
budget), `error_free=true` — for **both** images, identical results.
**The firmware never reaches the main loop, the radio-ID probe, or even
the "post-probe init resumes" milestones** — `0x9464` ("boot/init
entry") is hit exactly once (instruction 27740, identical to the
AutoPilot profile), and every milestone after it has `hit_count: 0`.

**The real first obstacle, mechanically confirmed (not predicted):**
`FUN_00006968` (the "startup reference/input" routine) contains an
inner wait loop at `0x69ae-0x69ca` that calls `millis()` twice per
iteration and compares the elapsed tick count against a `0x708`
(1800-tick) threshold — but only advances toward that threshold while a
`digitalRead()` call (same loop body) reads nonzero; whenever that read
is zero, the loop **resets its own elapsed-tick accumulator to zero**
instead of advancing. Disassembling the literal pool at `0xd408` and
reading the firmware's own pin-descriptor table at `0x14284` (the SAME
24-byte-per-entry, `group`/`pin`/`sentinel`-shaped table this project
already used to resolve other pins, e.g. the radio driver's PA15/16/17
— not a new table, not a new mechanism) shows table index 1 resolves to
`group=0, pin=22` — **PA22**, the exact pin `AUTOPILOT_RECIPE`'s
dropped `seed_mem` assumption holds high. Under the Feather profile's
zero-behavior MMIO (nothing drives Feather's D12/PA22 high), this read
is always 0, so the elapsed-tick accumulator never survives 1800
consecutive ticks and `0x69d8` (the documented timeout exit) is never
reached — confirmed up to a 4,000,000-instruction budget (≈2200×
the real AutoPilot run's own tick requirement), not a 1-shot
observation. This is a real, bounded-per-iteration, deterministic
dependency on AutoPilot's own PA22 wiring — not a Unicorn fault, not an
unsupported instruction, and not the previously-expected radio-ID
probe (which is never even reached). Classification: `CONFIRMED`
(direct disassembly + the project's own already-established pin table,
cross-checked against `autopilot915`'s identical literal-pool value).

**What this does not establish:** what AutoPilot's own board actually
wires to PA22 (`boot-and-hardware-bringup.md` already discloses "no
physical function claimed" — this investigation does not change that),
or whether a manually-wired jumper from a Feather's D12 to 3V3 would let
this specific firmware image continue past this point on real
hardware. The latter is a plausible (`INFERRED`), not run, mitigation —
see §7.

## 5. Peripheral-access inventory (Feather profile)

From the Feather-profile run's `--log-mmio` capture (5000-entry cap,
same observational limit this harness already documents elsewhere),
resolved via this case's own SVD resolver
(`config/pins.py`/`config/svd/resolve_mmio.py` — no new resolution
mechanism):

- **Clock tree, fully exercised**: `OSC32KCTRL`, `OSCCTRL` (DFLL +
  both DPLLs), `GCLK` (multiple `GENCTRL`/`PCHCTRL` channels), `MCLK`
  (`APBAMASK`/`APBBMASK`/`APBCMASK`/`APBDMASK`/`AHBMASK`/`CPUDIV`).
- **`SUPC.VREG`**, **`NVMCTRL`** (`CTRLA`, `PARAM`), **`CMCC.CTRL`**.
- **`ADC0`/`ADC1`** (`CTRLA`/`CTRLB`/`REFCTRL`/`SAMPCTRL`/`INPUTCTRL`/
  `AVGCTRL`/`CALIB`/`SYNCBUSY`) and **`DAC`** (`CTRLA`/`CTRLB`/
  `DACCTRL0`/`DACCTRL1`/`SYNCBUSY`) — all brought up unconditionally,
  consistent with `boot-and-hardware-bringup.md`'s own characterization
  of this firmware's `init()` as full, un-pruned Arduino-core bring-up.
- **`USB.DEVICE`/`HOST`** (`CTRLA`, `CTRLB`, `PADCAL`, `INTENSET`,
  `SYNCBUSY`, `DESCADD`) — confirms USB peripheral bring-up is reached
  under the Feather profile too (same chip-level USB pads, see §6.6).
- **`PORT`**: `GROUP0.IN` (30 hits in a 200-entry sample window alone —
  this *is* the PA22 polling loop from §4), `GROUP0`/`GROUP1`
  `DIRSET`/`DIRCLR`/`OUTSET`/`OUTCLR`/`PINCFGxx`/`PMUX12`.

No DMAC, SERCOM data-transfer, or motor-timer (`TCC1`/`TC0`-`TC3`)
register access was observed — expected, since none of those are
reached before the PA22 blocker (§4).

## 6. Hardware-profile comparison

Answering the task's own numbered questions:

1. **Does the firmware reach normal application initialization?**
   AutoPilot profile: yes (`init_status=complete`, confirmed). Feather
   profile: **no** — it never leaves `FUN_00006968`'s own
   board-dependent wait loop.
2. **Which peripherals does it attempt to configure?** Identical up to
   the blocker: full clock tree, SUPC, NVMCTRL, CMCC, AC, both ADCs,
   DAC, USB, and PORT pin configuration for the pins `FUN_00006968`
   itself touches (§4-§5). Neither profile reaches SERCOM data
   transfer, DMAC, or the motor timers within this comparison (Feather:
   blocked before; AutoPilot: those are reached later in its own
   already-documented run, outside what this investigation re-verifies).
3. **Which GPIO pins does it drive, direction and initial level?** See
   §7's full table — sourced from `firmware-pin-function-map.json`
   (already `FIRMWARE_PROVEN`/`PROBABLE` graded by this case) crossed
   against `config/feather_m4.py`.
4. **Could any configured output conflict with Feather onboard
   circuitry?** **Yes — CONFIRMED.** AutoPilot's `STEP_CH0/CH1/CH3` and
   `DIR_CH0/CH1/CH3` (`PB10/PA08/PA10/PB11/PA09/PA11`) are driven as
   GPIO `OUTPUT`s by the firmware and are **exactly** Feather M4's
   onboard QSPI flash chip's SCK/IO0/IO2/CS/IO1/IO3 — a real, powered,
   actively-driven device with no header exposure at all. See §7.
5. **Do missing AutoPilot peripherals prevent progress?** **Yes** — the
   absence of AutoPilot's board-specific PA22 drive is what blocks
   progress (§4), reached before the also-absent radio chip would have
   mattered.
6. **Is USB initialization reached?** Yes, under **both** profiles —
   USB bring-up happens unconditionally in `main()`'s own `init()`
   sequence, before `setup()`'s board-dependent code runs (§5's log
   shows `USB.DEVICE/HOST` register accesses in the Feather run). USB
   D-/D+ are the same dedicated `PA24`/`PA25` pads on both boards
   (`feather-m4-reference.md`'s resolved-ambiguity note) — no
   collision.
7. **Does the firmware enter a main loop?** AutoPilot profile: yes
   (confirmed, 5× `0x8960` hits). Feather profile: **no**, within a
   4,000,000-instruction bound.
8. **Which differences are observed vs. only predicted from wiring?**
   The PA22-blocker mechanism (§4) is **observed** (a real executed
   trace, disassembly-confirmed). The GPIO/QSPI conflict (§7) is
   **predicted from wiring** — no physical hardware exists to observe
   an actual electrical contention on.
9. **Is executing the original image on physical Feather hardware
   reasonable?** See §7's recommendation — not as the unmodified image
   drives its STEP0/1/3 and DIR0/1/3 pins today.

## 7. GPIO safety analysis

Every firmware-driven pin from `firmware-pin-function-map.json`,
crossed against `config/feather_m4.py`:

| Signal | Pin | Direction | Feather M4 reality | Risk |
|---|---|---|---|---|
| STEP_CH0 | PB10 | OUTPUT | Onboard QSPI flash **SCK** | **CONFIRMED collision** — drives the onboard flash clock line |
| STEP_CH1 | PA08 | OUTPUT | Onboard QSPI flash **IO0** | **CONFIRMED collision** |
| STEP_CH3 | PA10 | OUTPUT | Onboard QSPI flash **IO2** | **CONFIRMED collision** |
| DIR_CH0 | PB11 | OUTPUT | Onboard QSPI flash **CS** | **CONFIRMED collision**, highest severity (chip-select contention can corrupt in-progress flash transactions) |
| DIR_CH1 | PA09 | OUTPUT | Onboard QSPI flash **IO1** | **CONFIRMED collision** |
| DIR_CH3 | PA11 | OUTPUT | Onboard QSPI flash **IO3** | **CONFIRMED collision** |
| STEP_CH2 | PB12 | OUTPUT | Not in Feather's pin table | `INFERRED` inert (no onboard contention; not independently measured) |
| DIR_CH2 | PB13 | OUTPUT | Not in Feather's pin table | `INFERRED` inert |
| DRIVER_RESET_STROBE_A | PB06 | OUTPUT | Not in Feather's pin table | `INFERRED` inert |
| DRIVER_RESET_STROBE_B | PB07 | OUTPUT | Not in Feather's pin table | `INFERRED` inert |
| TRIGGER_DIGITAL | PB05 | INPUT/analog | Not in Feather's pin table | `INFERRED` inert |
| RADIO_SPI_CS | PA15 | OUTPUT | Not in Feather's pin table | `INFERRED` inert |
| SHARED_RELOAD_PULSE_A | PB30 | OUTPUT | Not in Feather's pin table; **confirmed not SWD** (`PA30`/`PA31`, different port) | `INFERRED` inert |
| SHARED_RELOAD_PULSE_B | PB31 | OUTPUT | Not in Feather's pin table; confirmed not SWD | `INFERRED` inert |
| DRIVER_ENABLE_A | PB17 | OUTPUT | Feather header D0 / Serial1 RX | Benign on a bare board; would contend with Serial1 if that UART is in use |
| DRIVER_ENABLE_B | PB16 | OUTPUT | Feather header D1 / Serial1 TX | Same caveat |
| TCC1_AUX_PULSE | PB22 | OUTPUT | Feather hardware SPI **MISO** (header) | Benign on a bare board; relevant only if an SPI peripheral is attached |
| RADIO_CANDIDATE_B | PA17 | UNKNOWN | Feather hardware SPI **SCK** (header) | Same caveat |
| TRIGGER_BOOT_ARM_SELECT | PA02 | INPUT_PULLUP | Feather header A0/D14 | Benign ordinary header pin |
| STARTUP_REF_INPUT | PA22 | input, polled | Feather header D12 | Benign electrically; **behaviorally** this is §4's actual blocker |
| RADIO_CANDIDATE_A | PA16 | UNKNOWN | Feather header D5 | Benign ordinary header pin |
| STARTUP_COMPLETION_LATCH | PA23 | OUTPUT | Feather's **onboard red LED** (`LED_BUILTIN`) | Benign — lights the onboard LED, a designed-to-be-driven load, not hazardous |
| USB_DM / USB_DP | PA24 / PA25 | fixed-function | Feather's own USB D-/D+ (identical role) | None — same electrical function on both boards |

### 7a. The PA22 blocker, re-tested with a jumper-equivalent seed

Cheap to check without hardware, so checked this pass rather than left
as a pure prediction: re-adding *only* the PA22 seed to the Feather
profile (radio stand-in still dropped — i.e. "what if a Feather D12 is
jumpered to 3V3, but no radio chip is wired to PA15/16/17") does clear
`FUN_00006968`'s wait loop — `0x69d8` (the documented timeout exit) is
reached, immediately followed by `0x9dd4` (the radio-ID probe) — and
then stalls there instead, within a 200,000-instruction budget, exactly
matching `boot-and-hardware-bringup.md`'s own already-documented real
failure mode for that probe under zero-behavior MMIO. Classification:
`CONFIRMED` (executed, superseding §8/roadmap's earlier `INFERRED`
framing) **in simulation only** — a real physical D12→3V3 jumper test
on hardware has not been run.

**Headline finding**: AutoPilot's unmodified firmware drives **all
six** of Feather M4's onboard QSPI flash pins as digital outputs
(STEP/DIR for motor channels 0, 1, and 3) within its normal boot/setup
sequence — reached well before the PA22 blocker, since GPIO
configuration for the motor-timer pins happens during `main()`'s own
early bring-up, independent of `setup()`'s later board-dependent code.
This was not re-verified by a fresh trace in this pass (out of scope —
it is `firmware-pin-function-map.json`'s own already-`FIRMWARE_PROVEN`
finding, cited, not re-derived); it is reported here as a wiring-level
prediction (§6 item 8's "predicted from wiring" category), not a
measured electrical event, since no physical board exists to measure.

## 8. Recommendation for the first physical test

**Do not flash the unmodified image and power up a bare Feather M4 as
a first test.** Driving a live chip-select and clock/data lines into an
active onboard QSPI flash chip risks corrupting the Feather's own
bootloader/flash contents, and — depending on drive strength and
whatever state the flash chip's own outputs are in — a brief bus
contention on `IO0`-`IO3`. Neither outcome is "likely catastrophic
chip damage" (SAMD51 GPIO drivers and typical QSPI NOR flash I/O pins
both tolerate push-pull contention briefly), but it is also not a risk
worth taking for a first test when it is this cheaply avoidable.

**Recommended first physical test, in order:**

1. Before powering anything: verify with a multimeter (power off) that
   the Feather's QSPI flash pins are where `feather-m4-reference.md`
   says — confirm this investigation's identification, not Adafruit's
   schematic alone, matches the specific unit in hand.
2. Run the unmodified firmware in this harness one more time with
   `--stop-at` set to the very first instruction that configures
   `PB10`/`PB11`/`PA08`/`PA09`/`PA10`/`PA11` as GPIO (a bounded,
   reusable follow-up this investigation did not need to run, since
   the PA22 blocker already prevents reaching main-loop steady state
   either way) — confirms exactly which instruction first touches the
   QSPI pins and whether it happens before or after any
   recoverable/observable point.
3. For a first physical bring-up: wire a jumper from the Feather's
   D12 to 3V3 (§7a's simulation-`CONFIRMED` mitigation for §4's PA22
   blocker — not yet tried on real hardware) and power the board
   **without** anything connected to the
   STEP/DIR-conflicting pins reachable from headers — which, per §7,
   is none of them (all six are QSPI-internal, not header pins) — so
   the actual electrical risk is to the Feather's own onboard flash
   chip, not to external wiring. Watch (oscilloscope or logic analyzer
   on the QSPI pins is not possible without desoldering — these are
   not header-accessible) whether the board still boots its own
   bootloader/CircuitPython afterward; if it does not, the flash was
   corrupted and the board needs a bootloader re-flash via its own UF2
   recovery procedure before any further use.
4. Do not treat a successful boot of the *AutoPilot application* on a
   physical Feather as the measure of success for this first test —
   given §4's confirmed blocker, the unmodified image will not reach
   its own main loop on a bare Feather without a hardware or firmware
   change. The first test's actual goal is narrower: confirm the QSPI
   pins survive being driven, and confirm (or refute) that a D12→3V3
   jumper gets the firmware past the PA22 wait loop in physical
   execution.

## 9. Reproducible tests

See `cases/performing-rigs/test/test_feather_m4_profile.py` (new):
asserts the AutoPilot profile still reaches `init_status=complete` for
both images (regression), the Feather profile reaches
`init_status=partial-justified` and never hits any milestone past
`0x9464` within a bounded instruction budget for both images, and that
`config/feather_m4.py`'s QSPI-collision pins are exactly
`{PB10,PB11,PA08,PA09,PA10,PA11}`.

## Evidence/assumption summary

Every assumption applied in every run above is recorded, per-run, in
`cases/performing-rigs/research/generated/feather-m4/*.json`'s
`assumptions_applied` field — the same `A(kind, addr, detail,
citation)` records `config/boot_recipes.py` already uses, nothing
informal or undisclosed.

| Claim | Grade |
|---|---|
| AutoPilot profile reaches main-loop steady state (regression) | `CONFIRMED` (re-executed this pass) |
| Feather profile never reaches `0x69d8` within 4,000,000 instructions | `CONFIRMED` (executed, not predicted) |
| The blocking condition is PA22 via pin-table index 1 | `CONFIRMED` (direct disassembly + existing pin table) |
| QSPI flash pins = `PB10/PB11/PA08/PA09/PA10/PA11` | `CONFIRMED` (vendor source, `variant.h`/`variant.cpp`) |
| Those pins collide with AutoPilot's STEP0/1/3, DIR0/1/3 | `CONFIRMED` (both sides independently sourced, cross-referenced) |
| A D12→3V3 jumper would let the firmware clear the PA22 blocker, then stall at the (also unmet, on a bare Feather) radio-ID probe instead | `CONFIRMED` in simulation (§7a, executed this pass); not yet tried on real hardware |
| Driving unexposed-on-Feather pins (PB12/13, PB06/07, PB05, PA15, PB30/31) is electrically inert | `INFERRED` (absence from the vendor pin table; not independently measured) |
| Executing the unmodified image's early GPIO/motor init on a bare physical Feather is safe | `UNKNOWN` — not established either way by simulation alone; §8's recommendation is to avoid it rather than assume safety |
