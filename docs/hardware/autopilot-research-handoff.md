# AutoPilot / Noxon Reverse-Engineering Research Notes

_Last updated: 2026-09-08_

## Purpose

This file is a handoff document for future reverse-engineering work on the Performing Rigs **AutoPilot** system. It summarizes what has been learned so far from:

- the AutoPilot user manual,
- board photographs of the Wireless Remote / controller,
- board photographs of the AutoPilot motor-control unit,
- firmware-update screenshots in the manual,
- prior discussion about using Ghidra, Macaw, Crucible, What4, and GREASE-style under-constrained symbolic execution.

The main goal is to turn raw firmware and hardware observations into a human-readable functional model:

```text
physical control / external input
    ->
MCU peripheral / firmware routine
    ->
protocol or internal state
    ->
motion behavior
    ->
physical motor output
```

A secondary goal is to make the system testable enough to produce reproducible vendor-quality bug reports and, potentially, to support an independent controller/software stack.

---

# 1. System Architecture

There are **two distinct embedded targets**. They use the same SAMD51J19A MCU family, but they are different boards, have different peripherals, and run different firmware images.

## 1.1 Wireless Remote / Controller

Role:

- human interface,
- jog wheel input,
- menu/display UI,
- wireless link to AutoPilot,
- battery-powered handheld.

Observed / identified hardware:

- **Microchip / Atmel ATSAMD51J19A-AF**,
- 32-bit ARM Cortex-M4F, up to 120 MHz,
- 512 KB flash,
- 192 KB SRAM,
- 64-pin TQFP package,
- Ai-Thinker **Ra-01H** radio module,
- rotary encoder / jog wheel with push action,
- display/front-panel daughterboard connected by flex/ribbon,
- USB connector,
- LiPo battery,
- buzzer/sounder-like component,
- several unpopulated/test headers.

Confidence on the Remote MCU identity: **HIGH / treated as confirmed for current research**.

The `-AF` orderable variant is the extended-temperature / automotive-grade TQFP-64 version of the same ATSAMD51J19A device family.

Important: the Remote is a separate firmware target from the AutoPilot unit even though both use the SAMD51J19A family.

## 1.2 AutoPilot Unit

Role:

- receives wireless commands,
- accepts external STEP/DIR signals,
- stores and executes programmed moves,
- provides stepper-motor power and drive,
- exposes four motor channels.

Observed / identified hardware:

- **Microchip / Atmel ATSAMD51J19A-AU** main MCU,
- 32-bit ARM Cortex-M4F, up to 120 MHz,
- 512 KB flash,
- 192 KB SRAM,
- 64-pin TQFP package,
- large power section and repeated driver circuitry,
- four large motor-output connectors,
- USB-C used for firmware updates,
- multiple large electrolytic capacitors,
- low-value power resistors (e.g. ~0R22 markings),
- repeated channel circuitry consistent with stepper motor drive/current control.

Confidence on the AutoPilot MCU identity: **HIGH / treated as confirmed for current research**.

The `-AU` orderable variant is the standard-temperature TQFP-64 version of the ATSAMD51J19A.

## 1.3 Important consequence: one MCU platform, two board models

Because both targets use ATSAMD51J19A, most low-level analysis infrastructure can be shared:

```text
ATSAMD51J19A platform model
├── Cortex-M4F CPU semantics
├── flash / SRAM layout
├── interrupt / vector model
├── PORT / GPIO
├── EIC
├── SERCOM
├── TC / TCC
├── ADC / DAC
├── USB
├── DMAC
├── EVSYS
├── NVMCTRL
└── system-control / Cortex-M registers
```

Then keep the physical board mappings separate:

```text
AutoPilot / ATSAMD51J19A-AU
├── STEP/DIR inputs
├── trigger input
├── motor driver interfaces
├── current / load / presence sensing
├── wireless/radio interface
├── status LED
├── power control
└── USB-C updater path

Remote / ATSAMD51J19A-AF
├── jog encoder
├── encoder push button
├── display
├── radio
├── battery monitoring
├── buzzer
└── USB
```

This means Ghidra processor setup, SAMD51 peripheral definitions/SVD data, Unicorn setup, and the Macaw/Crucible platform layer should be reusable between the two binaries. **Pin assignments, enabled peripherals, external devices, and firmware semantics must still be modeled per board.**

Firmware mapping:

```text
firmware_autopilot*.bin
    -> AutoPilot main unit
    -> ATSAMD51J19A-AU

firmware_mando*.bin
    -> Wireless Remote
    -> ATSAMD51J19A-AF
```

The earlier SAM4-family hypothesis for the AutoPilot should be considered **superseded**.

---

# 2. User Manual: Highest-Value Reverse-Engineering Findings

Source: `PerformingRigs_UserManual_AutoPilot(1).pdf`, revised Oct. 8, 2025.

## 2.1 AutoPilot inputs

The input panel contains:

1. power button,
2. trigger input on 3.5 mm TRS,
3. four RJ45 "motor signal inputs",
4. USB-C firmware-update port,
5. 48 V DC power input,
6. status LED.

### Critical clarification: the RJ45 ports are not Ethernet

The manual explicitly describes them as accepting **motor STEP and DIRECTION signals** from external motion-control systems.

Supported examples listed in the manual:

- Dragonframe DMC-32,
- Mark Roberts Motion Control Ulti-Box / Quad Box / Octo Box,
- Camerabotics Action Server (listed as in development in the manual).

Therefore the architecture for this path is:

```text
Dragonframe / MRMC / other controller
    ->
STEP + DIR electrical signals
    ->
RJ45 connector
    ->
AutoPilot
    ->
motor driver / power stage
    ->
stepper motor
```

There is no reason to assume a packet protocol on these RJ45 inputs.

---

# 3. Wiring Information from the Manual

## 3.1 4-pin XLR motor output

The manual gives the AutoPilot XLR motor pinout as:

```text
1 = A+
2 = A-
3 = B+
4 = B-
```

This is direct bipolar stepper motor winding drive.

That strongly confirms that the AutoPilot contains the actual stepper power stages.

## 3.2 RJ45 motor signal input

The manual provides separate pin mappings for MRMC/other devices and DMC-32.

### MRMC / OTHER

```text
Pin 1 = GND
Pin 2 = unused
Pin 3 = 5 V
Pin 4 = unused
Pin 5 = STEP
Pin 6 = DIR
Pin 7 = unused
Pin 8 = unused
```

### DMC-32

The manual indicates a different RJ45 assignment, including:

```text
STEP+
DIR+
5 V
GND
```

with several unused pins.

For exact pin numbering, refer to page 25 of the manual rather than relying on memory alone.

---

# 4. Wireless Remote: Human-Readable Control Semantics

The manual gives the primary semantics of the jog wheel directly.

## 4.1 Multifunction jog wheel

The jog wheel supports:

- **Rotate**  
  - move cursor in menus,
  - position motors / set speed depending on mode.

- **Click**
  - enter/select,
  - set a programmed point,
  - instant stop in Manual Mode.

- **Long press**
  - go back in menus,
  - power down when the power icon is shown.

- **Double click**
  - cycle through connected motor channels in Manual Mode.

This is extremely useful for reverse engineering the Remote firmware because these are known UI behaviors that can be used to rename anonymous routines.

Example naming progression:

```text
sub_xxxx
    ->
encoder_delta_handler
    ->
jog_wheel_rotate
```

and:

```text
sub_yyyy
    ->
encoder_button_handler
    ->
jog_click / long_press / double_click dispatcher
```

---

# 5. Manual Mode Semantics

Manual Mode provides real-time control of a stepper motor.

Important behaviors:

- turning the jog wheel one way moves the motor continuously in one direction,
- turning it the other way moves in the other direction,
- speed is centered around zero,
- clicking the jog wheel can stop the motor immediately,
- double-click cycles connected motor channels,
- direction can be inverted between A/B orientation,
- motor ports are auto-detected.

Potential firmware targets:

```text
selected_motor_channel
manual_speed
manual_direction
manual_stop
connected_motor_mask
direction_invert
```

---

# 6. Auto Mode Data Model

Auto Mode provides repeatable programmed motion.

The user-facing model strongly suggests an internal move structure.

## 6.1 Channels

Four motor channels:

```text
M1
M2
M3
M4
```

## 6.2 Programmed points

Each motor can have:

```text
A
B
C
D
```

Programmed movement segments are:

```text
A -> B
B -> C
C -> D
```

The manual explicitly says the **direction of rotation is recorded**.

## 6.3 Segment parameters

Parameters include:

- duration OR maximum speed,
- ramp,
- delay,
- loop.

Manual meanings:

### Duration

Time to complete movement, displayed in milliseconds.

Example:

```text
1000 = 1 second
```

### Speed

Maximum movement speed, user scale 1-99.

### Ramp

Acceleration/deceleration proportion.

Manual examples:

- `50` = approximately 25% accelerating + 25% decelerating,
- low number = faster arrival at full speed,
- high number = more gradual ramp.

### Delay

Pause before executing the movement, in milliseconds.

### Loop

YES / NO; causes motion to loop back and forth.

## 6.4 Likely internal representation

Not confirmed, but useful as a search model:

```c
struct MoveSegment {
    position_or_distance;
    direction;
    duration_or_speed;
    ramp;
    delay;
    loop;
};
```

Do not assume exact field widths or layout until found in firmware.

---

# 7. Persistent Storage

The manual states that programmed moves remain stored after the AutoPilot is powered off.

Therefore there is a nonvolatile storage subsystem for at least some of:

- programmed A/B/C/D movement data,
- per-motor configuration,
- possibly RF channel,
- possibly other settings.

Reverse-engineering target:

```text
record move
    ->
serialize data
    ->
NVM / flash write
```

Useful functions to locate:

```text
save_move
load_move
clear_move
save_motor_config
load_motor_config
save_settings
```

This persistent format may be one of the fastest ways to recover meaningful internal data structures.

---

# 8. Motor Configuration Constants

The manual exposes several constants that are useful for static analysis.

## 8.1 Current

Configured in milliamps.

Built-in rig types can auto-select current.

Custom motor type:

```text
Other
```

allows manual current configuration.

## 8.2 Maximum speed

Manual default:

```text
10,000 steps/second
```

Search candidate:

```text
10000
0x2710
```

in regions associated with motor configuration.

## 8.3 Microstepping

Supported values:

```text
1
2
4
8
16
32
64
128
256
```

This sequence is an excellent signature for locating a microstep configuration table.

## 8.4 Return speed

Default:

```text
25
```

User range appears to run up to:

```text
99
```

---

# 9. Stepper-Motor Assumptions from the Manual

The manual describes common 1.8-degree, 200-step motors.

Examples given:

- Pour standard motor: 50:1 gearbox -> 10,000 full steps/rev,
- Pour high-speed motor: 5:1 gearbox -> 1,000 full steps/rev,
- Spin: no gearbox -> 200 full steps/rev.

These are user-facing examples, not necessarily firmware constants, but they may appear in predefined motor configuration tables.

---

# 10. External Input Behavior

The AutoPilot can detect external motor-signal inputs.

When an external controller is connected:

- Manual Mode remains available,
- Auto Mode is disabled / grayed out.

The Remote can display source labels such as:

```text
MRMC inputs
DMC32 inputs
```

Therefore the firmware appears to contain logic for:

```text
external_input_present
external_input_type
auto_mode_enabled = false
```

This is a good target for identifying the RJ45 input GPIO/peripheral paths.

---

# 11. Motor Presence Detection

The manual states that AutoPilot auto-detects which motor ports have motors connected and only cycles through connected channels.

This implies some form of per-channel presence/load sensing.

Possible mechanisms include:

- current sensing,
- winding continuity/load detection,
- driver fault/status feedback,
- another electrical probe.

The exact mechanism is not yet known.

Firmware target:

```text
motor1_connected
motor2_connected
motor3_connected
motor4_connected
```

Hardware target:

trace each channel's driver/status/current-sense circuitry back to the MCU.

---

# 12. Trigger Input

The trigger input is on a 3.5 mm TRS connector.

The manual says it can be activated by:

- relay closure,
- little/no voltage,
- external electrical signal,
- up to 48 V,
- either polarity.

The wiring diagram indicates tip and sleeve are used; ring is not used.

## 12.1 Sensitivity behavior

The manual documents two sensitivity modes:

### Less sensitive

Connect trigger cable **before power-up**.

AutoPilot establishes a noise baseline and becomes less susceptible to false triggering.

### More sensitive

Connect trigger cable **after power-up**.

Input becomes more sensitive but more susceptible to inadvertent triggering.

This strongly suggests firmware logic more complex than a simple digital GPIO read.

Likely pattern:

```text
boot
    ->
sample trigger input / baseline
    ->
establish threshold
    ->
detect trigger event
```

This is a useful firmware and PCB tracing target.

---

# 13. Firmware Update Process

The manual documents a Windows-only updater workflow.

Updater identity shown in screenshots:

```text
NOXON Firmware Uploader
```

This is strong evidence that Noxon supplied at least part of the platform / updater tooling.

## 13.1 Separate images

The manual screenshots show separate firmware images for:

- Remote EU / 868 MHz,
- Remote North/South America / 915 MHz,
- AutoPilot EU / 868 MHz,
- AutoPilot North/South America / 915 MHz.

Visible filenames include forms resembling:

```text
firmware_mando868.bin
firmware_mando915.bin
firmware_autopilot868.bin
firmware_autopilot915.bin
```

`mando` is very likely the Remote/controller image.

The AutoPilot and Remote must therefore be treated as independent firmware targets.

## 13.2 Approximate sizes visible in updater package screenshot

The manual screenshot appears to show approximately:

```text
Remote / mando image:     ~128 KB
AutoPilot image:          ~70 KB
```

Treat these as screenshot-derived approximate values until checked against the actual files.

## 13.3 Updater serial/reset clues

The updater screenshots show COM-port status including approximately:

```text
1200 baud
7 data bits
even parity
1 stop bit
RTS enabled
```

Do not assume this is the actual firmware transfer protocol.

It may only be part of bootloader-entry/reset behavior.

The updater output also visibly performs memory read/verify operations in chunks and eventually writes to:

```text
0xE000ED0C
```

with a value consistent with a Cortex-M software reset request.

That address is the Cortex-M Application Interrupt and Reset Control Register (AIRCR).

This is useful evidence that the updater is directly manipulating a Cortex-M target after programming.

---

# 14. Controller / Remote Hardware Observations

## 14.1 MCU

Identified device:

```text
Microchip / Atmel ATSAMD51J19A-AF
```

Working confidence: **HIGH / confirmed for current research**.

Core properties relevant to reverse engineering:

```text
CPU:       ARM Cortex-M4F
Clock:     up to 120 MHz
Flash:     512 KB
SRAM:      192 KB
Package:   TQFP-64
```

The `-AF` part is the extended-temperature / automotive-grade TQFP variant. It remains the same ATSAMD51J19A architecture and pin-compatible TQFP-64 package family as the AutoPilot's `-AU` part for purposes of firmware analysis.

## 14.2 Radio

Module marking:

```text
Ai-Thinker Ra-01H
```

This provides a strong hardware anchor for radio-driver identification.

The firmware likely talks to the radio through an SPI-capable SERCOM plus GPIOs for chip select / reset / interrupt lines.

## 14.3 Jog wheel

The component is a rotary encoder assembly, likely with a push switch.

Likely firmware path:

```text
encoder A/B
    ->
GPIO / EIC / event / timer
    ->
quadrature decode
    ->
signed jog delta
```

and separately:

```text
push switch
    ->
GPIO / EIC
    ->
click / long-press / double-click timing logic
```

## 14.4 Display

The front/display board is separate and connected through a flex/ribbon.

Therefore UI rendering and control inputs may traverse that interconnect.

## 14.5 Battery

Visible battery:

```text
3.7 V
1250 mAh
```

This is useful for separating power-management/ADC behavior from user input behavior.

---

# 15. AutoPilot Hardware Observations

## 15.1 Main MCU

Identified device:

```text
Microchip / Atmel ATSAMD51J19A-AU
```

Working confidence: **HIGH / confirmed for current research**.

Core properties relevant to reverse engineering:

```text
CPU:       ARM Cortex-M4F
Clock:     up to 120 MHz
Flash:     512 KB
SRAM:      192 KB
Package:   TQFP-64 (10 x 10 mm)
```

This identification replaces the earlier speculative SAM4E/SAM4S direction. The AutoPilot analysis should now be grounded in the **SAM D51** peripheral map, interrupt layout, pin muxing, NVM controller, USB device controller, timers, SERCOM blocks, event system, and GPIO architecture.

## 15.2 Visible board-level features

The AutoPilot board contains:

- ATSAMD51J19A-AU main MCU,
- four repeated motor-output channels,
- large power capacitors,
- low-value power resistors,
- power semiconductor / driver circuitry,
- four large external motor connectors,
- USB-C,
- separate power input/control region,
- various smaller driver/interface ICs.

The board photographs should now be mapped against the **64-pin SAMD51J19A TQFP pinout**. This makes visual trace-following much more actionable: a trace that reaches a known package pin can be translated into `PAxx` / `PBxx`, then into the possible peripheral mux functions for that pin.

## 15.3 High-value implication: AutoPilot and Remote share the same silicon family

The AutoPilot (`-AU`) and Remote (`-AF`) are not two unrelated MCU platforms. They are two orderable variants of **ATSAMD51J19A**, both in 64-pin TQFP.

For reverse engineering, this means:

- same ARM instruction set / Cortex-M4F behavior,
- same flash and SRAM capacity,
- same peripheral register architecture,
- same interrupt numbering model,
- same basic pin names and multiplexing scheme,
- same SAMD51 device support packs / CMSIS headers are applicable,
- same Unicorn memory/peripheral skeleton can be reused,
- same Macaw/Crucible SAMD51 MMIO model can be reused.

What must remain board-specific:

- which PA/PB pins are actually routed,
- SERCOM instance and pad selections,
- timer/channel assignments,
- ADC inputs,
- radio wiring,
- motor-driver wiring,
- trigger/input conditioning,
- display/encoder wiring,
- NVM data layout and application semantics.

This should reduce duplicated harness work substantially.

## 15.4 Adafruit M4 lineage hypothesis

An earlier first-pass firmware inspection reportedly found **Adafruit M4-related notes/artifacts** in the firmware. Combined with the confirmed ATSAMD51J19A, this deserves deliberate investigation rather than being treated as an incidental string.

Known external context:

- Adafruit M4-class boards use SAMD51-family Cortex-M4F MCUs.
- Adafruit documents M4 application flashing with BOSSA / `bossac`.
- In the Adafruit M4 bootloader layout, a 16 KB bootloader reservation means applications are flashed at offset **`0x4000`**.
- The open UF2 SAMD bootloader lineage is derived from Atmel SAM-BA and exposes a CDC interface compatible with BOSSA.

This does **not** yet prove the AutoPilot application was written with Adafruit libraries. Several possibilities remain:

```text
A. Noxon application built on Adafruit / Arduino SAMD core
B. custom application using an Adafruit-derived bootloader only
C. selected Adafruit / TinyUSB / SAMD support components reused
D. development began on an Adafruit M4 board and remnants remained
E. coincidental / third-party library strings with no architectural significance
```

Treat this as a **high-value hypothesis**, not a confirmed ancestry.

### Tests that would strengthen or falsify the hypothesis

1. **Application base / vector table**
   - Check whether the application is linked at `0x4000`.
   - A `0x4000` base is consistent with Adafruit's 16 KB M4 bootloader convention, but is not proof by itself.

2. **BOSSA / SAM-BA behavior**
   - Determine whether the Noxon updater's transfer stage is actually BOSSA/SAM-BA compatible.
   - The existing presence of `bossac.exe` is important evidence.

3. **1200-baud reset/touch behavior**
   - The updater screenshots show a 1200-baud serial setup.
   - Test whether this is only a bootloader-entry/reset touch before re-enumeration rather than the payload transfer rate.

4. **Bootloader fingerprints**
   - Compare USB descriptors, bootloader behavior, flash offsets, reset behavior, and protocol responses with known SAMD51 UF2/SAM-BA/BOSSA implementations.

5. **Library/source matching**
   - Compare binary functions against builds/source from:
     - Adafruit Arduino SAMD support,
     - ArduinoCore-samd,
     - UF2 SAMDx1 bootloader,
     - TinyUSB,
     - CMSIS,
     - Microchip/Atmel SAMD51 startup and peripheral support.
   - Goal: identify and subtract standard runtime/library code so analysis can focus on Noxon/Performing Rigs-specific logic.

6. **String and metadata inventory**
   - Record the exact Adafruit/M4 strings, addresses, and cross-references rather than only noting that they exist.
   - Determine whether strings are application-facing, build metadata, USB descriptors, library error text, or dead/unreferenced data.

7. **Linker/startup signature**
   - Compare Reset_Handler, vector table, C runtime initialization, clock setup, and USB startup with known Adafruit/Arduino SAMD51 builds.

If multiple independent fingerprints line up, open-source source trees may become a practical "Rosetta Stone" for naming standard functions in Ghidra.

## 15.5 Pin-mapping opportunity

Because the exact MCU/package is known, build a pin map with the TQFP-64 package as the physical bridge:

```text
board trace
    ->
package pin number
    ->
PAxx / PBxx
    ->
mux function
    ->
SERCOM / TCC / TC / ADC / EIC / GPIO
    ->
firmware MMIO references
    ->
human function
```

For each mapped pin, record:

```text
package_pin
port_pin
mux_function
board_net/component
firmware_refs
human_semantic
confidence
```

---

# 16. How Hardware Photos Help Firmware Analysis

The objective is to build a provenance graph from physical hardware to software.

Example:

```text
rotary encoder phase A
    ->
MCU pin
    ->
GPIO peripheral
    ->
interrupt / polling routine
    ->
jog delta
    ->
radio packet field
```

or:

```text
RJ45 STEP input
    ->
input conditioning
    ->
MCU pin
    ->
timer/counter/GPIO
    ->
axis motion state
```

or:

```text
MCU timer/PWM
    ->
driver IC
    ->
XLR A+/A-/B+/B-
    ->
stepper motor
```

Each discovered mapping should carry a confidence level:

```text
CONFIRMED
STRONG INFERENCE
TENTATIVE
UNKNOWN
```

---

# 17. Turning Raw Hex into Human-Readable Meaning

Hex values do not inherently mean "jog +" or "jog -".

The translation comes from combining:

1. controlled physical actions,
2. packet or memory diffs,
3. static firmware analysis,
4. symbolic execution,
5. hardware tracing.

Example workflow:

```text
perform exactly one known action
    ->
capture bytes
    ->
repeat
    ->
identify changing field
    ->
trace field in firmware
    ->
trace resulting state / output
    ->
assign human-readable label
```

For a rotary encoder, a common pattern may be:

```text
0x01 = +1
0xFF = -1
```

if interpreted as signed 8-bit two's complement.

But this must be proven by correlation and firmware behavior.

Use cautious naming progression:

```text
positive value
    ->
positive jog
    ->
clockwise
    ->
increase position
```

Do not jump directly to the final semantic label without evidence.

---

# 18. GREASE-Style Under-Constrained Analysis

The planned firmware-analysis stack is:

```text
raw firmware
    ->
Cortex-M loader
    ->
Macaw lifting / CFG
    ->
Crucible symbolic execution
    ->
What4 / SMT solver
    ->
GREASE-style under-constrained analysis
```

## 18.1 Core idea

Analyze interesting functions directly rather than symbolically booting the entire device.

Start a function with:

```text
PC = target function
SP = synthetic valid stack
LR = return sentinel
R0-R3 = symbolic
other relevant state = symbolic / constrained as needed
```

Then execute.

When execution fails because a symbolic register is used as a pointer, refine the precondition.

Example:

```text
LDR R2, [R0, #0x14]
```

Initial state:

```text
R0 = unconstrained 32-bit
```

Refinement:

```text
R0 must point to at least 0x18 bytes
```

Restart and continue.

This can infer pointer shapes and object layout without source code.

## 18.2 Firmware-specific memory classification

The refinement engine must distinguish:

```text
flash
SRAM
MMIO/peripherals
system control space
symbolic pointer/object memory
```

Do not "invent heap objects" for known MMIO addresses.

## 18.3 Useful questions

Once a packet/parser/motor routine is found, ask:

```text
What input reaches this behavior?
```

Examples:

```text
What packet bytes reach motor_increment_position()?
What input causes a write to this timer register?
What state causes current limit to be exceeded?
Can this parser reach an invalid memory access?
Can a command cause a divide-by-zero?
```

## 18.4 Discovery vs validation

Under-constrained execution can produce impossible states.

Therefore classify findings:

```text
CONFIRMED
reachable from realistic caller/input

POTENTIAL
function-local counterexample; caller feasibility unknown

INFEASIBLE
caller constraints rule it out
```

A second caller-feasibility pass should validate high-value findings.

---

# 19. Suggested Analysis Priorities

## Priority 1: Confirm binary layout and bootloader relationship

The exact AutoPilot MCU is no longer an open question; use **ATSAMD51J19A-AU** as the target device.

Now establish:

- actual application/vector-table base,
- whether the image is linked at `0x0000`, `0x4000`, or another offset,
- whether the updater preserves a resident bootloader,
- whether the bootloader is BOSSA/SAM-BA/UF2-derived or custom,
- whether the 1200-baud step is a bootloader-entry/reset mechanism,
- USB VID/PID/descriptors in application and bootloader modes.

A `0x4000` application base would be especially interesting because it matches the common 16 KB Adafruit M4 bootloader layout, but this must be verified rather than assumed.

## Priority 2: Load authoritative SAMD51 device definitions

Use ATSAMD51J19A-specific:

- memory map,
- interrupt table,
- PORT/EIC definitions,
- SERCOM register maps,
- TC/TCC,
- ADC/DAC,
- USB,
- NVMCTRL,
- DMAC,
- EVSYS,
- pin multiplexing tables.

Use the same low-level platform definitions for AutoPilot and Remote, with separate board routing maps.

## Priority 3: Recover peripheral initialization and pin usage

Find initialization of:

- PORT / GPIO,
- EIC,
- timers/counters,
- ADC,
- SERCOM SPI/UART/I2C,
- USB,
- watchdog,
- nonvolatile memory,
- DMAC / EVSYS,
- any driver-control peripherals.

For each configured pin, convert firmware setup into a candidate physical net.

## Priority 4: Fingerprint Adafruit / Arduino / UF2 lineage

Because Adafruit M4 artifacts were seen during early firmware inspection, systematically test:

- application offset,
- startup code,
- bootloader behavior,
- USB descriptors,
- BOSSA compatibility,
- known library function matches,
- exact Adafruit-related strings and xrefs.

Do not label the application "Adafruit-based" until evidence goes beyond generic SAMD51 code.

## Priority 5: Locate motor-control path

Trace:

```text
Manual Mode or STEP/DIR input
    ->
axis selection
    ->
speed/direction
    ->
step generation
    ->
driver configuration
    ->
physical motor output
```

Now that the exact pinout is known, tie timer/GPIO writes back to physical driver nets where possible.

## Priority 6: Locate persistent move/config storage

Search for:

- flash/NVM writes,
- tables containing motor parameters,
- A/B/C/D move structures,
- RF channel setting,
- microstep tables.

## Priority 7: Locate radio protocol

On the Remote:

```text
jog/button
    ->
command structure
    ->
radio TX
```

On AutoPilot:

```text
radio RX
    ->
packet parser
    ->
command dispatch
    ->
motion behavior
```

## Priority 8: Build protocol/function/pin dictionaries

Maintain linked dictionaries:

```text
raw byte / register / function
    ->
meaning
    ->
evidence
    ->
confidence
```

and:

```text
MCU pin
    ->
peripheral function
    ->
physical board net
    ->
firmware references
    ->
human meaning
```

---

# 20. Useful Static-Analysis Signatures

Search for constants / patterns such as:

```text
10000 / 0x2710
1,2,4,8,16,32,64,128,256
25
99
1000
```

Potentially associated with:

- max steps/sec,
- microstepping,
- return speed,
- duration in milliseconds.

Also search for:

- tables containing four repeated channel structures,
- three move segments per motor,
- persistent storage functions,
- radio-region differences between 868 MHz and 915 MHz binaries.

---

# 21. Important Open Questions

1. Is the AutoPilot application linked at `0x4000`, and what exactly occupies/preserves the lower flash region?
2. What exact bootloader/protocol does the NOXON updater use?
3. Is BOSSAC/SAM-BA directly involved, wrapped, or only protocol-compatible?
4. Does the 1200-baud updater step trigger reset/bootloader entry?
5. Are the Adafruit M4 artifacts evidence of:
   - an Adafruit/Arduino SAMD application framework,
   - an Adafruit/UF2-derived bootloader,
   - reused libraries only,
   - or development-history remnants?
6. What are the exact Adafruit/M4 strings/artifacts, addresses, and cross-references in each firmware image?
7. Which ATSAMD51J19A pins map to:
   - each RJ45 STEP/DIR input,
   - each motor channel/driver control,
   - trigger input,
   - USB,
   - radio,
   - current sensing,
   - motor-presence sensing,
   - status LED,
   - power button?
8. Which SERCOM instance/pads connect to the radio on each board?
9. How is motor presence detected?
10. How are MRMC vs DMC-32 inputs distinguished?
11. What is the persistent move/config format?
12. What is the Remote <-> AutoPilot radio packet format?
13. Which radio settings differ between 868 and 915 MHz images?
14. Are there any secondary programmable controllers on the AutoPilot board, or is the ATSAMD51J19A the only application MCU?
15. Can standard/open-source SAMD51 library code be source-matched and removed from the reverse-engineering problem?
16. Can the firmware be safely patched and reflashed?
17. Can a clean independent firmware be built for the AutoPilot hardware?

Resolved question:

```text
AutoPilot main MCU = ATSAMD51J19A-AU
Remote MCU         = ATSAMD51J19A-AF
```

---

# 22. Research Discipline

When adding findings, keep facts separate from inference.

Use this format:

```text
Finding:
Evidence:
Source:
Confidence:
Notes:
```

Example:

```text
Finding:
RJ45 inputs carry STEP/DIR, not Ethernet.

Evidence:
User manual explicitly calls them motor signal inputs and provides STEP/DIR pinouts.

Source:
PerformingRigs_UserManual_AutoPilot(1).pdf, pages 15-16 and 25.

Confidence:
CONFIRMED.
```

Avoid silently upgrading an inference into a fact.

---

# 23. Recommended Output Artifacts

Maintain these files as the project evolves:

```text
research/
  autopilot_research.md
  hardware/
    remote_board.md
    autopilot_board.md
    pin_map.csv
  firmware/
    binary_inventory.md
    function_map.csv
    mmio_map.csv
    strings.md
  protocol/
    radio_protocol.md
    external_step_dir.md
  analysis/
    symbolic_targets.md
    findings.md
    open_questions.md
```

Useful tables:

### `function_map.csv`

```text
address,name,role,evidence,confidence
```

### `mmio_map.csv`

```text
address,peripheral,register,firmware_refs,physical_component,confidence
```

### `pin_map.csv`

```text
mcu_pin,peripheral,board_trace,component,function,confidence
```

### `radio_protocol.md`

For each observed message:

```text
offset
raw value
decoded meaning
physical action
firmware function
confidence
```

---

# 23.1 External MCU / bootloader reference notes

These references are useful for verifying the MCU/platform implications above:

- Microchip ATSAMD51J19A product page:  
  https://www.microchip.com/en-us/product/atsamd51j19a
- Microchip SAM D5x/E5x family data sheet / TQFP-64 pinout.
- ATSAMD51J19A-AU: TQFP-64, 120 MHz Cortex-M4F, 512 KB flash, 192 KB SRAM, standard-temperature variant.
- ATSAMD51J19A-AF: TQFP-64, same MCU resources, extended-temperature / automotive-grade variant.
- Adafruit M4 UF2 bootloader notes: M4 applications using the Adafruit 16 KB bootloader are flashed at `0x4000` with BOSSA.
- UF2 SAMDx1 source lineage: derived from Atmel SAM-BA and compatible with BOSSA over USB CDC.

Useful URLs:

```text
https://learn.adafruit.com/adafruit-feather-m4-express-atsamd51/uf2-bootloader-details
https://github.com/microsoft/uf2-samdx1
```

These are **external context**. They should be used to test hypotheses against the actual AutoPilot/Remote binaries, not substituted for binary evidence.

---

# 24. Primary Source

`PerformingRigs_UserManual_AutoPilot(1).pdf`

Especially valuable pages:

- page 5: AutoPilot input panel,
- page 6: motor output panel,
- page 7: Wireless Remote controls,
- page 10: Manual Mode,
- pages 11-14: Auto Mode behavior,
- pages 15-16: external STEP/DIR pass-through,
- pages 17-19: settings / motor configuration / microstepping,
- pages 20-24: firmware updater,
- page 25: wiring diagrams.

---

# 25. Immediate Next Step for Claude / Future Analysis

Treat the AutoPilot MCU as **ATSAMD51J19A-AU** and the Remote MCU as **ATSAMD51J19A-AF**.

For the AutoPilot binary:

1. verify the application/vector-table base and flash layout,
2. explicitly test the `0x4000` / 16 KB bootloader hypothesis,
3. load ATSAMD51J19A symbols/peripheral definitions,
4. recover PORT pin mux and peripheral initialization,
5. build a first physical pin map from firmware + board photos,
6. inventory every Adafruit/M4-related string/artifact with address and xrefs,
7. compare startup/USB/bootloader-adjacent code against known SAMD51 Arduino/Adafruit/UF2 implementations,
8. identify which code is generic platform/library code versus Noxon/Performing Rigs application code,
9. continue mapping motor channels, STEP/DIR inputs, trigger sensing, NVM move storage, and radio,
10. keep concrete execution evidence authoritative for behavior, and use symbolic execution for genuinely symbolic questions.

For the Remote binary:

1. reuse the same ATSAMD51J19A low-level model,
2. create a separate AF-board pin/peripheral map,
3. trace jog encoder -> firmware state -> radio TX,
4. trace AutoPilot response -> radio RX -> parser/UI,
5. compare common library/startup code with the AutoPilot binary to identify shared code automatically.

The key architectural simplification is:

```text
one SAMD51J19A analysis platform
    +
two board-specific hardware maps
    +
two application firmware images
```

The Adafruit M4 evidence should be investigated as a potential source-code fingerprinting shortcut, but kept explicitly labeled as a hypothesis until matched against concrete binary evidence.

