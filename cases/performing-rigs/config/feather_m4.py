"""APTrace Performing Rigs case: Adafruit Feather M4 Express hardware
profile -- Feather-specific pin table and onboard-component map, used
ONLY to answer the AutoPilot-firmware-on-Feather feasibility question
(cases/performing-rigs/docs/investigations/feather-m4-feasibility.md).
Not a framework/general-purpose SAMD51 board model.

Every fact here is transcribed VERBATIM from Adafruit's own board-
support package, already fetched (for an unrelated reference-source-
fingerprinting pass, see status.md's "fifth census layer") at EXACT
pinned version 1.7.11 and sitting in this repo at:

    cases/performing-rigs/research/runs/census/reference_corpus/sources/
    adafruit-ArduinoCore-samd-1.7.11/variants/feather_m4/{variant.h,variant.cpp}

No new download, no web lookup, no guessed pinout -- this module only
re-expresses that already-vendored, already-verified source as
case-local Python data; see each entry's `citation` for the exact
file+line.

**USB D+/D- note (resolved, not carried forward as a discrepancy):**
`variant.cpp` labels its Arduino "digital pin 30" entry `{ PORTA, 27,
...} // USB/DP`. This is NOT read as "Feather M4's USB D+ pad is
PA27." USB D+/D- are dedicated, fixed-function SAMD51 silicon pads
(PA24/PA25 on every SAM D5x/E5x package, outside the ordinary
PORT-mux pin table) -- already an established, chip-level fact in this
case (see cases/performing-rigs/research/generated/firmware-pin-function-map.json's
USB_DM/USB_DP entries: "a standard, fixed silicon-level fact for this
MCU family, not firmware-configurable"). Adafruit's own Arduino pin
table entry for "D30" is a board-package housekeeping artifact (some
boards use that slot as a sense/identification pin with a stale
comment), not a competing claim about the real USB pads. Both boards'
real USB D-/D+ are PA24/PA25, so USB is NOT a GPIO-collision candidate
on either profile.

**SWD note (resolved, not carried forward as an open risk):**
ATSAMD51's Serial Wire Debug pins are PA30 (SWCLK) and PA31 (SWDIO) --
Microchip SAM D5x/E5x Family Data Sheet DS60001507, cross-checked
against Adafruit's own SAMD51 Thing Plus graphical pinout (same
silicon family) which labels the same two pins SWDIO/SWDCLK. AutoPilot's
"shared reload pulse" signals use PB30/PB31 -- a different PORT group
entirely -- so there is no debug-pin collision risk to evaluate further.
"""

_VARIANT_H = "cases/performing-rigs/research/runs/census/reference_corpus/sources/adafruit-ArduinoCore-samd-1.7.11/variants/feather_m4/variant.h"
_VARIANT_CPP = "cases/performing-rigs/research/runs/census/reference_corpus/sources/adafruit-ArduinoCore-samd-1.7.11/variants/feather_m4/variant.cpp"


def P(pin_name, role, exposure, citation, note=""):
    return {"pin": pin_name, "role": role, "exposure": exposure, "citation": citation, "note": note}


# Every PORT pin that appears ANYWHERE in Feather M4's own
# g_APinDescription table (variant.cpp), i.e. every pin this board
# actually wires to something -- a header, an onboard component, or a
# fixed-function pad. A PORT pin NOT in this dict does not appear in
# Feather's own pin table at all: its package pad exists (same die as
# AutoPilot) but Adafruit's board design leaves it unrouted to any
# header or onboard component (see `NOT_EXPOSED_NOTE` below for what
# that does and does not imply).
FEATHER_M4_PINS = {
    "PB17": P("PB17", "Arduino D0 / Serial1 RX (SERCOM5 PAD1)", "header",
              _VARIANT_CPP + ":37"),
    "PB16": P("PB16", "Arduino D1 / Serial1 TX (SERCOM5 PAD0)", "header",
              _VARIANT_CPP + ":38"),
    "PA14": P("PA14", "Arduino D4", "header", _VARIANT_CPP + ":44"),
    "PA16": P("PA16", "Arduino D5 (TCC1_CH0 PWM-capable)", "header", _VARIANT_CPP + ":45"),
    "PA18": P("PA18", "Arduino D6 (TCC1_CH2 PWM-capable)", "header", _VARIANT_CPP + ":46"),
    "PB03": P("PB03", "Onboard NeoPixel data line", "onboard-component",
              _VARIANT_CPP + ":50", note="Single addressable RGB LED soldered to the board (PIN_NEOPIXEL, variant.h:91)."),
    "PA19": P("PA19", "Arduino D9", "header", _VARIANT_CPP + ":51"),
    "PA20": P("PA20", "Arduino D10", "header", _VARIANT_CPP + ":52"),
    "PA21": P("PA21", "Arduino D11", "header", _VARIANT_CPP + ":53"),
    "PA22": P("PA22", "Arduino D12", "header", _VARIANT_CPP + ":54"),
    "PA23": P("PA23", "Arduino D13 / onboard red LED (LED_BUILTIN)", "onboard-component",
              _VARIANT_CPP + ":57", note="Driving this pin lights the onboard indicator LED -- a real, visible, but non-hazardous side effect (the LED+series-resistor are designed to be driven)."),
    "PA02": P("PA02", "Arduino A0/D14, also DAC0/VOUT0", "header", _VARIANT_CPP + ":61"),
    "PA05": P("PA05", "Arduino A1/D15, also DAC1/VOUT1", "header", _VARIANT_CPP + ":62"),
    "PB08": P("PB08", "Arduino A2/D16", "header", _VARIANT_CPP + ":63"),
    "PB09": P("PB09", "Arduino A3/D17", "header", _VARIANT_CPP + ":64"),
    "PA04": P("PA04", "Arduino A4/D18", "header", _VARIANT_CPP + ":65"),
    "PA06": P("PA06", "Arduino A5/D19", "header", _VARIANT_CPP + ":66"),
    "PB01": P("PB01", "Arduino A6/D20", "header", _VARIANT_CPP + ":69"),
    "PA12": P("PA12", "Arduino D21/SDA (SERCOM2 PAD0)", "header", _VARIANT_CPP + ":74"),
    "PA13": P("PA13", "Arduino D22/SCL (SERCOM2 PAD1)", "header", _VARIANT_CPP + ":75"),
    "PB22": P("PB22", "Arduino D23/MISO (SERCOM1 PAD2) -- Feather's hardware SPI bus", "header-bus",
              _VARIANT_CPP + ":79", note="Shared SPI header pin; no onboard device on a bare board, but relevant if a shield/peripheral is attached."),
    "PB23": P("PB23", "Arduino D24/MOSI (SERCOM1 PAD3) -- Feather's hardware SPI bus", "header-bus",
              _VARIANT_CPP + ":80", note="Same caveat as PB22."),
    "PA17": P("PA17", "Arduino D25/SCK (SERCOM1 PAD1) -- Feather's hardware SPI bus", "header-bus",
              _VARIANT_CPP + ":81", note="Same caveat as PB22."),
    "PA24": P("PA24", "USB D- (dedicated fixed-function pad, every SAM D5x/E5x)", "fixed-function",
              _VARIANT_CPP + ":91", note="Identical electrical role on AutoPilot and Feather -- see module docstring."),
    "PA27": P("PA27", "Arduino digital-pin-30 table slot, commented 'USB/DP' in Adafruit's source", "header",
              _VARIANT_CPP + ":92", note="NOT the real USB D+ pad -- see module docstring's USB note. Listed here only for completeness/transparency about the vendor source's own comment."),
    "PA03": P("PA03", "Arduino AREF/D31 (DAC/VREFP)", "header", _VARIANT_CPP + ":95"),
    "PB10": P("PB10", "Onboard QSPI flash SCK", "onboard-component",
              _VARIANT_CPP + ":104 (pin index 34, PIN_QSPI_SCK, " + _VARIANT_H + ":194)",
              note="Dedicated to the onboard 2MB SPI flash chip; not broken out to any header."),
    "PB11": P("PB11", "Onboard QSPI flash CS", "onboard-component",
              _VARIANT_CPP + ":105 (pin index 35, PIN_QSPI_CS, " + _VARIANT_H + ":195)",
              note="Chip-select line to the onboard flash chip; not broken out to any header."),
    "PA08": P("PA08", "Onboard QSPI flash IO0", "onboard-component",
              _VARIANT_CPP + ":106 (pin index 36, PIN_QSPI_IO0, " + _VARIANT_H + ":196)",
              note="Not broken out to any header."),
    "PA09": P("PA09", "Onboard QSPI flash IO1", "onboard-component",
              _VARIANT_CPP + ":107 (pin index 37, PIN_QSPI_IO1, " + _VARIANT_H + ":197)",
              note="Not broken out to any header."),
    "PA10": P("PA10", "Onboard QSPI flash IO2", "onboard-component",
              _VARIANT_CPP + ":108 (pin index 38, PIN_QSPI_IO2, " + _VARIANT_H + ":198)",
              note="Not broken out to any header."),
    "PA11": P("PA11", "Onboard QSPI flash IO3", "onboard-component",
              _VARIANT_CPP + ":109 (pin index 39, PIN_QSPI_IO3, " + _VARIANT_H + ":199)",
              note="Not broken out to any header."),
    "PA25": P("PA25", "USB D+ (dedicated fixed-function pad, every SAM D5x/E5x)", "fixed-function",
              "chip-level fact, not board-specific -- see module docstring's USB note",
              note="Identical electrical role on AutoPilot and Feather."),
}

# The onboard QSPI NOR flash chip -- stores the UF2 bootloader and any
# CircuitPython/compiled-sketch image. This is a REAL, powered,
# actively-driven device on every Feather M4, not a passive header.
QSPI_FLASH_PINS = ("PB10", "PB11", "PA08", "PA09", "PA10", "PA11")

NOT_EXPOSED_NOTE = (
    "A PORT pin absent from FEATHER_M4_PINS does not appear anywhere in "
    "Feather M4's own g_APinDescription table (variant.cpp). Adafruit's "
    "board design leaves its package pad unrouted to any header pin or "
    "onboard component. This is inferred from the board-support package's "
    "silence, not independently confirmed by continuity/photo evidence on "
    "a physical unit (no physical Feather exists in this investigation "
    "yet) -- graded INFERRED, not CONFIRMED, in the feasibility doc. "
    "Practically: driving such a pin as a GPIO output is expected to be "
    "electrically inert (no onboard contention), but this has not been "
    "measured."
)

SOURCE_CITATION = _VARIANT_CPP + " and " + _VARIANT_H + " (Adafruit ArduinoCore-samd v1.7.11, already vendored in this repo)"
