# Hardware Reference — Adafruit Feather M4 Express

Physical hardware facts about the **Adafruit Feather M4 Express**
development board, collected to evaluate whether unmodified AutoPilot
firmware is safe and useful to run on one (see
[`docs/investigations/feather-m4-feasibility.md`](../investigations/feather-m4-feasibility.md)
for the full investigation). This board is not part of the Performing
Rigs product — it is candidate test hardware for AutoPilot firmware
analysis.

## MCU

**ATSAMD51J19A**, Cortex-M4F, 512 KB flash, 192 KB SRAM — the identical
part number already confirmed for the real AutoPilot unit
(`hardware-reference.md`). Adafruit's own marketing/datasheet naming for
this exact part on this exact board is the basis for this case's
reference-corpus build already using the `adafruit_feather_m4` board
target (`status.md`'s "fifth census layer").

## Pin table and onboard components — CONFIRMED, VENDOR SOURCE

Every fact below is read directly from Adafruit's own board-support
package (`ArduinoCore-samd` v1.7.11, git tag, already vendored in this
repo — see
[`config/feather_m4.py`](../../config/feather_m4.py)'s module docstring
for exact paths), not from a web pinout diagram, a datasheet re-render,
or memory. Classification: `CONFIRMED — VENDOR SOURCE`.

| Category | Pins | Detail |
|---|---|---|
| Onboard QSPI NOR flash | `PB10` (SCK), `PB11` (CS), `PA08` (IO0), `PA09` (IO1), `PA10` (IO2), `PA11` (IO3) | A real, powered, actively-driven 2 MB SPI flash chip storing the UF2 bootloader and any CircuitPython/compiled image. **Not broken out to any header pin** — these six MCU pads exist only to drive this chip. |
| Onboard NeoPixel | `PB03` | Single addressable RGB LED soldered to the board. |
| Onboard red LED | `PA23` | `LED_BUILTIN` / Arduino D13, driven through a series resistor. |
| USB D-/D+ | `PA24`/`PA25` | Dedicated, fixed-function SAMD51 silicon pads (not PORT-mux'd), identical electrical role on every SAM D5x/E5x board including AutoPilot's. |
| Feather hardware SPI bus (header) | `PB22` (MISO), `PB23` (MOSI), `PA17` (SCK) | Exposed on the Feather header; no onboard device on a bare board. |
| Hardware UART (header, Serial1) | `PB17` (RX), `PB16` (TX) | Exposed on the Feather header (D0/D1). |
| I2C (header) | `PA12` (SDA), `PA13` (SCL) | Exposed on the Feather header (D21/D22). |
| Remaining digital/analog header pins | `PA14,PA16,PA18,PA19,PA20,PA21,PA22,PA02,PA05,PB08,PB09,PA04,PA06,PB01,PA27,PA03` | Ordinary Feather header pins, no onboard function. |

A PORT pin **not** listed above does not appear anywhere in Feather
M4's own pin-description table at all — Adafruit's board design leaves
that package pad unrouted to any header pin or onboard component. See
`config/feather_m4.py`'s `NOT_EXPOSED_NOTE` for the exact evidence-grade
caveat (inferred from the vendor source's silence, not independently
confirmed by continuity/photo evidence on a physical unit — no physical
Feather exists in this investigation yet).

## Resolved ambiguities

- **USB D+ is PA25, not PA27**, on every SAM D5x/E5x including Feather
  M4, despite Adafruit's own `variant.cpp` commenting its Arduino
  "digital pin 30" table slot (`PORTA, 27`) `// USB/DP`. USB D-/D+ are
  dedicated analog pads outside the ordinary PORT-mux pin table on this
  silicon family (already an established fact in this case — see
  `firmware-pin-function-map.json`'s `USB_DM`/`USB_DP` entries); the
  vendor comment is a board-package housekeeping artifact, not a
  competing electrical claim. See `config/feather_m4.py`'s module
  docstring for the full reasoning.
- **No SWD/debug-pin collision risk.** ATSAMD51's Serial Wire Debug
  pins are `PA30` (SWCLK) and `PA31` (SWDIO) — Microchip SAM D5x/E5x
  Family Data Sheet DS60001507, cross-checked against Adafruit's own
  SAMD51 Thing Plus graphical pinout (same silicon family, same
  SWDIO/SWDCLK labeling). AutoPilot's "shared reload pulse" signals use
  `PB30`/`PB31` — a different PORT group entirely — so there is no
  debug-pin collision to evaluate further.

## What this document does not establish

- No physical Feather M4 Express unit has been inspected, measured, or
  photographed for this investigation — every "onboard component"
  claim above is a vendor-board-support-package fact, not a
  continuity-bench or photo finding (contrast with `hardware-reference.md`'s
  AutoPilot facts, several of which ARE photo/continuity-confirmed).
- Silicon revision / exact flash chip part number are not established
  (Adafruit has shipped more than one QSPI flash part across production
  runs of this board family; this does not change which MCU pins drive
  it).
