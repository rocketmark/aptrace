# Hardware Reference — AutoPilot / Remote

Physical hardware and user-manual facts for the Performing Rigs **AutoPilot**
(motion-control unit) and **Remote** (handheld wireless controller). Firmware
reverse-engineering findings live under [`docs/investigations/`](../investigations/);
this file covers only what is true about the physical hardware and what the
user manual documents.

## MCU / Silicon

Both units use the same MCU family in different package/temperature grades,
confirmed by physical board inspection:

| Unit | Part | Package | Core | Flash | SRAM |
|---|---|---|---|---|---|
| AutoPilot | ATSAMD51J19A-AU | TQFP-64 (10×10 mm), standard temp | Cortex-M4F, up to 120 MHz | 512 KB | 192 KB |
| Remote | ATSAMD51J19A-AF | TQFP-64, extended-temp/automotive grade | Cortex-M4F, up to 120 MHz | 512 KB | 192 KB |

The `-AU`/`-AF` suffix is package/temperature grade only — same die, same
peripheral set, same pinout for analysis purposes.

## AutoPilot Unit — Board-Level Facts

Input/output panel:

- power button
- trigger input, 3.5 mm TRS
- four RJ45 "motor signal input" jacks (STEP/DIR, not Ethernet)
- USB-C port, used for firmware updates
- 48 V DC power input
- status LED
- four XLR-4 motor-output connectors

Visible board features: four repeated motor-output driver channels, large
electrolytic capacitors, low-value power resistors (~0R22 markings)
consistent with current sensing, USB-C.

**Motor driver IC identity — CONFIRMED by PCB photo.** A QFP package in one
of the four repeated motor-driver channels is legibly marked (Trinamic
triangle logo) `TMC5160A-TA / 2512 A19TA / GERMANY` —
`research/AutoPilot Board Photos/REV 1/20260530_PerformingRigs_DatabaseImages_AutoPilot0101.jpg`,
reconfirmed from a wider angle in `..._0103.jpg`. This is the first
independent, in-repo confirmation of the TMC5160A-TA part (previously an
external/asserted fact only). **Not established by this evidence**: which
of the four repeated channels/XLR jacks this specific chip belongs to, the
identity of the other three (assumed identical by board repetition, not
individually confirmed), and any SPI/UART bus wiring between this chip and
the ATSAMD51 — no legible net label or traceable copper run to the MCU was
found in any available photo.

**Adjacent SOIC-8 parts — CONFIRMED by manufacturer marking match.** Small
SOIC-8 parts visible in the same board region (both REV 1 and REV 2
photos), marked:

```text
88537N
26Z
N9x4G4
```

are Texas Instruments **CSD88537ND** — a dual 60 V N-channel NexFET power
MOSFET, SOIC-8. TI's own documentation gives `88537N` as this exact
part's package/device marking. Classification:
`PROVEN — PCB PHOTO + MANUFACTURER MARKING MATCH`. `26Z`/`N9x4G4` are
recorded only as secondary package/lot/trace markings, not independently
decoded.

**Architectural implication**: the CSD88537ND is consistent with the
external N-channel MOSFET power stage the TMC5160A requires — it is a
power-stage component, not a second motor-control IC. The exact number of
CSD88537ND packages per motor channel and the complete bridge topology are
**not** inferred from this one photo; that would need either an
independent per-channel photo count or PCB continuity evidence.

**Adjacent 16-pin SSOP mux/demux — CONFIRMED by manufacturer marking
match.** A 16-pin SSOP part in the same cluster (`0103.jpg`), marked:

```text
CL257
27M
AFRN64
```

is Texas Instruments **`SN74CBTLV3257`** — a low-voltage, 4-bit 1-of-2
FET multiplexer/demultiplexer, DBQ/SSOP-16 package. `CL257` is TI's own
documented top-side device marking for this exact part (`SCDS040N`);
`27M`/`AFRN64` are secondary lot/trace codes, not independently decoded.
Classification: `PROVEN — PCB PHOTO + MANUFACTURER MARKING MATCH`. TI's
own datasheet lists "Motor drives" as a named application for this part.
Pinout (DBQ/16-pin): `S`(1), `1B1`(2), `1B2`(3), `1A`(4), `2B1`(5),
`2B2`(6), `2A`(7), `GND`(8), `3A`(9), `3B2`(10), `3B1`(11), `4A`(12),
`4B2`(13), `4B1`(14), `OE‾`(15), `VCC`(16) — four independent channels,
each switching its `A` pin to either `B1` or `B2`, sharing one select
line (`S`) and one active-low output-enable (`OE‾`).

**Device count — `PROBABLE`, not `PROVEN`**: the board's motor-driver
region is an established 4-repeated-channel layout, and the signal-count
math (4 motors × STEP+DIR = 8 signals = 2 × this part's 4 switched
channels) is consistent with **two** `SN74CBTLV3257` devices — but this
pass did not locate a second legible (or identifiably-blurry) photo of a
second device; only one is independently confirmed. Do not round this up
to `PROVEN` until a second photo or continuity check confirms it.

**Architectural implication — leading hypothesis, `HIGH-CONFIDENCE
INFERENCE`, not proven**: the current leading theory is that two
`SN74CBTLV3257` devices select, per motor pair, between MCU-generated
STEP/DIR and externally-supplied (RJ45) STEP/DIR, with their outputs
feeding the four TMC5160 STEP/DIR inputs — not a shared SPI/UART config
bus as earlier speculated. This would also explain why no firmware path
consuming external RJ45 STEP/DIR pulses has been found: the external
pulses may bypass the ATSAMD51 entirely, switched in electrically. **Not
established** — no board signal has been traced to this chip's
`A`/`B1`/`B2`/`S`/`OE‾` pins. See
[`firmware-pin-function-map.md`](firmware-pin-function-map.md)'s "Motor
bus architecture — mux hypothesis" for the full reasoning, the
continuity-test plan, and the evidence-status summary.

**Photo folder note**: the `REV 1` subfolder is not exclusively Remote-board
photos as previously recorded — it contains the original Remote/Mando set
(`...0042`-`...0074`) plus a later-added set of real AutoPilot board
close-ups (`...0095` onward, silkscreen `52_PO_V01R04`, the same board
identity as the `REV 2` folder). Treat REV 1 as mixed; check each file's
own board identity rather than trusting the folder name.

### XLR-4 motor output pinout

```
1 = A+
2 = A-
3 = B+
4 = B-
```

Direct bipolar stepper-winding drive — the AutoPilot itself contains the
stepper power stages.

### RJ45 motor signal input pinout

MRMC / other third-party controllers:

```
1 = GND
2 = unused
3 = 5V
4 = unused
5 = STEP
6 = DIR
7 = unused
8 = unused
```

Dragonframe DMC-32 uses a different assignment (STEP+, DIR+, 5V, GND, several
unused pins) — see manual page 25 for exact pin numbers.

### Trigger input (3.5 mm TRS)

Tip and sleeve used, ring unused. Accepts relay closure or an external
electrical signal up to 48 V, either polarity.

## Remote Unit — Board-Level Facts

- Ai-Thinker **Ra-01H** radio module
- rotary encoder ("jog wheel") with integrated push switch
- separate display/front-panel board, connected via flex/ribbon cable
- USB connector
- LiPo battery, 3.7 V / 1250 mAh
- buzzer/sounder component
- several unpopulated test headers

## Bootloader / Flashing

- Flasher: `bossac` (BOSSA), the standard tool for Atmel/Microchip SAM-D/E
  parts with a UART/USB bootloader.
- Device enumerates under USB VID `0x239A` (Adafruit Industries); board
  enters the bootloader via the standard 1200-baud touch-reset.
- Bootloader occupies the first 16 KB of flash (`0x0000`–`0x3FFF`);
  application images are flashed starting at offset **`0x4000`**.
- Vendor updater tool: **NOXON Firmware Uploader**, Windows-only.
- After programming, the updater issues a Cortex-M software reset via the
  AIRCR register (`0xE000ED0C`).

## Firmware File Inventory

| File | Size (bytes) | Unit | Radio region |
|---|---|---|---|
| `firmware_autopilot868.bin` | 70768 | AutoPilot | EU / 868 MHz |
| `firmware_autopilot915.bin` | 70768 | AutoPilot | US/other / 915 MHz |
| `firmware_mando868.bin` | 138304 | Remote | EU / 868 MHz |
| `firmware_mando915.bin` | 138304 | Remote | US/other / 915 MHz |

`mando` is the Remote/controller image; `autopilot` is the motion-control
unit image. The 868/915 pair for each unit differs only in radio
configuration. See [`docs/firmware/firmware-inventory.md`](../firmware/firmware-inventory.md)
for hashes and [`docs/firmware/firmware-layout.md`](../firmware/firmware-layout.md)
for flash-layout detail.

## User Manual — Condensed Feature Summary

Source: `PerformingRigs_UserManual_AutoPilot.pdf`. The full command-by-command
and UI-string cross-referenced version of these workflows lives in
[`docs/ui/user-guide-workflows.md`](../ui/user-guide-workflows.md) and
[`docs/ui/action-command-map.md`](../ui/action-command-map.md) — this section
is a short pointer plus manual-only facts not covered there.

- **Manual Mode**: jog wheel rotation drives the selected motor continuously,
  speed centered around zero; click stops immediately; double-click cycles
  through connected channels; direction can be inverted (A/B orientation).
- **Auto Mode**: four channels (M1–M4), each with programmed points A/B/C/D
  and movement segments A→B, B→C, C→D. Direction of rotation is recorded per
  segment. Segment parameters: duration (ms) or max speed, ramp
  (accel/decel proportion, e.g. `50` ≈ 25% accel + 25% decel), delay (ms),
  and loop (yes/no).
- **Motor configuration constants** (as documented in the manual): current
  set in mA (built-in rig types auto-select it; "Other" allows manual entry);
  default max speed 10,000 steps/second; microstepping selectable among
  1/2/4/8/16/32/64/128/256; return speed default 25, user range up to 99.
- **Persistence**: programmed moves and motor configuration remain stored
  across power-off (nonvolatile storage).
- **External STEP/DIR input**: when an external controller (MRMC, DMC-32) is
  connected via RJ45, Auto Mode is disabled/grayed out while Manual Mode
  remains available; the Remote UI shows a source label ("MRMC inputs" /
  "DMC32 inputs").
- **Motor presence**: AutoPilot auto-detects which of the four ports have a
  motor connected and Manual Mode only cycles through connected channels.
- **Trigger sensitivity**: connecting the trigger cable before power-up lets
  the unit establish a noise baseline (less sensitive/more noise-immune);
  connecting after power-up is more sensitive but more prone to false
  triggers.
- **Firmware update**: Windows-only NOXON Firmware Uploader; separate images
  per unit and radio region (see inventory above).

Manual page references: p.5 (AutoPilot input panel), p.6 (motor output
panel), p.7 (Remote controls), p.10 (Manual Mode), p.11–14 (Auto Mode),
p.15–16 (external STEP/DIR), p.17–19 (settings/motor config/microstepping),
p.20–24 (firmware updater), p.25 (wiring diagrams).

## See Also

- [`docs/ui/user-guide-workflows.md`](../ui/user-guide-workflows.md) — full
  UI/command cross-reference for the workflows summarized above.
- [`docs/ui/action-command-map.md`](../ui/action-command-map.md) — action ↔
  protocol command mapping.
- [`docs/firmware/firmware-inventory.md`](../firmware/firmware-inventory.md),
  [`docs/firmware/firmware-layout.md`](../firmware/firmware-layout.md) —
  firmware hashes and flash layout.
- [`docs/investigations/boot-and-hardware-bringup.md`](../investigations/boot-and-hardware-bringup.md) —
  pin/peripheral mapping derived from firmware analysis.
