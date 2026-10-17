# AutoPilot Continuity Bench Sheet

Use the annotated photos to identify each device and probe location.

## Setup

Board must be completely powered **OFF** and disconnected from:

- 48 V power
- USB
- RJ45 cables
- all other external connections

Before using continuity/resistance mode, verify with DC-voltage mode that the board is discharged.

For each check, record:

- clean continuity / beep
- approximate resistance
- no continuity

If the reading is not near 0 Ω, record the resistance value.

## 1. SN74CBTLV3257 pin orientation

Viewed from the top with the text upright:

```text
             16 15 14 13 12 11 10 9
               o  o  o  o  o  o  o  o
             ┌─────────────────────────┐
             │          CL257          │
             └─────────────────────────┘
               o  o  o  o  o  o  o  o
               1  2  3  4  5  6  7  8
               ↑
             PIN 1
```

Use the package pin-1 indicator as the primary orientation reference.

Relevant mux pins:

- Pin 1 = S
- Pin 15 = /OE

Channel map:

| Channel | A pin | B1 pin | B2 pin |
|---:|---:|---:|---:|
| 1 | 4 | 2 | 3 |
| 2 | 7 | 5 | 6 |
| 3 | 9 | 11 | 10 |
| 4 | 12 | 14 | 13 |

## 2. Mux control lines to ATSAMD51

### Mux 1 — SELECT

Probe: **SN74CBTLV3257 Mux 1 pin 1 (S)** against:

| ATSAMD51J19A pin | Reading |
|---|---:|
| Pin 39 (PB16) | 334.5K |
| Pin 40 (PB17) | 334.5K |

### Mux 1 — OUTPUT ENABLE

Probe: **SN74CBTLV3257 Mux 1 pin 15 (/OE)** against:

| ATSAMD51J19A pin | Reading |
|---|---:|
| Pin 9 (PB06) | 325.4K |
| Pin 10 (PB07) | 325.6K |

### Mux 2 — SELECT

Probe: **SN74CBTLV3257 Mux 2 pin 1 (S)** against:

| ATSAMD51J19A pin | Reading |
|---|---:|
| Pin 39 (PB16) | 334.5K |
| Pin 40 (PB17) | 334.5K |

### Mux 2 — OUTPUT ENABLE

Probe: **SN74CBTLV3257 Mux 2 pin 15 (/OE)** against:

| ATSAMD51J19A pin | Reading |
|---|---:|
| Pin 9 (PB06) | 324.9K |
| Pin 10 (PB07) | 325.2K |

## 3. Mux outputs to TMC5160 STEP/DIR

Relevant TMC5160A-TA pins:

- Pin 17 = REF_STEP
- Pin 18 = REF_DIR

For each mux, test these A/common pins:

- SN74CBTLV3257 pin 4 (1A)
- SN74CBTLV3257 pin 7 (2A)
- SN74CBTLV3257 pin 9 (3A)
- SN74CBTLV3257 pin 12 (4A)

against **TMC5160A-TA pin 17 and pin 18** on each TMC identified in the photos.

### Mux 1

| Mux pin | Target | TMC1 | TMC2 | TMC3 | TMC4 |
|---|---|---:|---:|---:|---:|
| 4 (1A) | Pin 17 (REF_STEP) | 0 | 497.5K | 568K | 568K |
| 4 (1A) | Pin 18 (REF_DIR) | 562K | 497.4K | 568K | 568K |
| 7 (2A) | Pin 17 (REF_STEP) | 566K | 494K | 565K | 565K |
| 7 (2A) | Pin 18 (REF_DIR) | 0 | 494.3K | 565K | 565K |
| 9 (3A) | Pin 17 (REF_STEP) | 559K | 488.7K | 558K | 558K |
| 9 (3A) | Pin 18 (REF_DIR) | 559K | 488.7K | 0 | 558K |
| 12 (4A) | Pin 17 (REF_STEP) | 558K | 487K | 0 | 558K |
| 12 (4A) | Pin 18 (REF_DIR) | 558K | 487K | 557K | 558K |

### Mux 2

| Mux pin | Target | TMC1 | TMC2 | TMC3 | TMC4 |
|---|---|---:|---:|---:|---:|
| 4 (1A) | Pin 17 (REF_STEP) | 548K | 0 | 549K | 549K |
| 4 (1A) | Pin 18 (REF_DIR) | 548K | 479K | 549K | 549K |
| 7 (2A) | Pin 17 (REF_STEP) | 549K | 478K | 549K | 549K |
| 7 (2A) | Pin 18 (REF_DIR) | 549K | 0 | 549K | 549K |
| 9 (3A) | Pin 17 (REF_STEP) | 560K | 478K | 558K | 558K |
| 9 (3A) | Pin 18 (REF_DIR) | 560K | 478K | 558K | 0 |
| 12 (4A) | Pin 17 (REF_STEP) | 560K | 490K | 560K | 0 |
| 12 (4A) | Pin 18 (REF_DIR) | 560K | 490K | 560K | 560K |

## 4. Trace both sides of each used mux channel

For every A pin that connects to a TMC5160 STEP or DIR input, test its corresponding B1 and B2 pins.

- A pin 4 → B1 pin 2 / B2 pin 3
- A pin 7 → B1 pin 5 / B2 pin 6
- A pin 9 → B1 pin 11 / B2 pin 10
- A pin 12 → B1 pin 14 / B2 pin 13

Check each B1/B2 against the ATSAMD51-side and RJ45-side probe points marked in the photos. Repeat for each STEP/DIR channel found.

RJ45s viewed from the exterior of the board:

```text
┌─────┐  ┌─────┐
│  1  │  │  2  │
└─────┘  └─────┘

┌─────┐  ┌─────┐
│  3  │  │  4  │
└─────┘  └─────┘
```

### Record — Mux 1

| Field | 1A | 2A | 3A | 4A |
|---|---|---|---|---|
| Mux # | 1 | 1 | 1 | 1 |
| Channel # | 1A | 2A | 3A | 4A |
| A pin | 4 | 7 | 9 | 12 |
| Connected TMC | 1 | 1 | 3 | 3 |
| TMC # | 17 | 18 | 18 | 17 |
| TMC pin | 2 | 5 | 11 | 14 |
| Signal | STEP / DIR | STEP / DIR | STEP / DIR | STEP / DIR |
| B1 pin | 2 | 5 | 11 | 14 |
| B1 continuity to | Thru diodes to VCC I/O & RJ45 #2 thru a resistor | Thru diodes to VCC I/O & RJ45 #2 thru a resistor | Thru diodes to VCC I/O & RJ45 #4 thru a resistor | Thru diodes to VCC I/O & RJ45 #4 thru a resistor |
| B1 resistance | 471 ohms | 468 ohms | 468 ohms | 468 ohms |
| B2 pin | 3 | 6 | 10 | 13 |
| B2 continuity to | Thru diodes to VCC I/O & RJ45 #2 thru a resistor | Thru diodes to VCC I/O & RJ45 #2 thru a resistor | Thru diodes to VCC I/O & RJ45 #4 thru a resistor | Thru diodes to VCC I/O & RJ45 #4 thru a resistor |
| B2 resistance | 468 ohms | 488 ohms | 468 ohms | 468 ohms |

### Record — Mux 2

| Field | 1A | 2A | 3A | 4A |
|---|---|---|---|---|
| Mux # | 2 | 2 | 2 | 2 |
| Channel # | 1A | 2A | 3A | 4A |
| A pin | 4 | 7 | 9 | 12 |
| Connected TMC | 2 | 2 | 4 | 4 |
| TMC # | 17 | 18 | 18 | 17 |
| TMC pin | 2 | 5 | 11 | 14 |
| Signal | STEP / DIR | STEP / DIR | STEP / DIR | STEP / DIR |
| B1 pin | 2 | 5 | 11 | 14 |
| B1 continuity to | Thru diodes to VCC I/O & RJ45 #1 thru a resistor | Thru diodes to VCC I/O & RJ45 #1 thru a resistor | Thru diodes to VCC I/O & RJ45 #3 thru a resistor | Thru diodes to VCC I/O & RJ45 #3 thru a resistor |
| B1 resistance | 470 ohms | 470 ohms | 470 ohms | 470 ohms |
| B2 pin | 3 | 6 | 10 | 13 |
| B2 continuity to | Thru diodes to VCC I/O & RJ45 #1 thru a resistor | Thru diodes to VCC I/O & RJ45 #1 thru a resistor | Thru diodes to VCC I/O & RJ45 #3 thru a resistor | Thru diodes to VCC I/O & RJ45 #3 thru a resistor |
| B2 resistance | 470 ohms | 470 ohms | 470 ohms | 470 ohms |

## 5. TMC5160 mode pins

Start with **TMC 1**.

Probe:

- TMC5160A-TA pin 21 (SD_MODE)
- TMC5160A-TA pin 22 (SPI_MODE)

Check where each goes using the probe points marked in the photos.

### Record

**TMC 1 pin 21 (SD_MODE)**

- connection: TMC VCC I/O pin 20; also 51J19 pins 8, 21, 34, 48 & 56
- resistance: 0

**TMC 1 pin 22 (SPI_MODE)**

- connection: TMC VCC I/O pin 20; also 51J19 pins 8, 21, 34, 48 & 56
- resistance: 0

Check specifically for connection to:

- GND
- VCC_IO
- resistor network
- ATSAMD51
- another logic IC
- shared net with another TMC5160

## 6. TMC5160 serial/configuration pins

On TMC 1, trace:

| TMC pin | Signal | TMC1 | TMC2 | TMC3 | TMC4 |
|---:|---|---|---|---|---|
| 13 | CSN_CFG3 | Pin 11 of 51J19 | Pin 37 of 51J19 | Pin 12 of 51J19 | Pin 38 of 51J19 |
| 14 | SCK_CFG2 | Pin 64 of 51J19 | Pin 64 of 51J19 | Pin 64 of 51J19 | Pin 64 of 51J19 — shared |
| 15 | SDI_CFG1 | Pin 63 of 51J19 | Pin 63 of 51J19 | Pin 63 of 51J19 | Pin 63 of 51J19 — shared |
| 16 | SDO_CFG0 | Pin 62 of 51J19 | Pin 62 of 51J19 | Pin 62 of 51J19 | Pin 62 of 51J19 — shared |

### Record

| TMC 1 pin | Signal | Connection | Resistance |
|---:|---|---|---:|
| 13 | CSN_CFG3 | ________________________ | 0 |
| 14 | SCK_CFG2 | ________________________ | 0 |
| 15 | SDI_CFG1 | ________________________ | 0 |
| 16 | SDO_CFG0 | ________________________ | 0 |

For each pin, also check whether the same net is shared with the other TMC5160s.

Example:

- TMC 1 pin 14 → TMC 2 pin 14: __________
- TMC 1 pin 14 → TMC 3 pin 14: __________
- TMC 1 pin 14 → TMC 4 pin 14: __________

Repeat that cross-driver check for pins 13, 15, and 16.

## 7. Remaining TMC5160 configuration pins

On TMC 1, trace:

- Pin 23 = ENCB_DCN_CFG4
- Pin 24 = ENCA_DCN_CFG5
- Pin 25 = ENCN_DCO_CFG6

### Record

| TMC 1 pin | Signal | Connection | Resistance |
|---:|---|---|---:|
| 23 | CFG4 | GNDANA 51J19 Pin 7 | 0 |
| 24 | CFG5 | GNDANA 51J19 Pin 7 | 0 |
| 25 | CFG6 | GNDANA 51J19 Pin 7 | 0 |

## 8. Lower-priority TMC5160 pins

If the measurements above are complete, trace:

- TMC5160A-TA pin 28 = DRV_ENN
- TMC5160A-TA pin 26 = DIAG0
- TMC5160A-TA pin 27 = DIAG1

### Record

| TMC 1 pin | Signal | Connection |
|---:|---|---|
| 28 | DRV_ENN | GNDANA 51J19 Pin 7 |
| 26 | DIAG0 | ________________________ |
| 27 | DIAG1 | ________________________ |

Also note whether any are shared across multiple TMC5160s.

## Priority order

Work in this order:

1. **Mux 1 + Mux 2 pin 1 (S)** to:
   - ATSAMD51J19A pin 39 (PB16)
   - ATSAMD51J19A pin 40 (PB17)
2. **Mux 1 + Mux 2 pin 15 (/OE)** to:
   - ATSAMD51J19A pin 9 (PB06)
   - ATSAMD51J19A pin 10 (PB07)
3. **Mux pins 4, 7, 9, 12** to:
   - TMC5160A-TA pin 17 (REF_STEP)
   - TMC5160A-TA pin 18 (REF_DIR)
4. **Corresponding mux B1/B2 pins:**
   - 2/3, 5/6, 11/10, 14/13
5. **TMC 1:**
   - pin 21 SD_MODE
   - pin 22 SPI_MODE
6. **TMC 1:**
   - pin 13 CSN_CFG3
   - pin 14 SCK_CFG2
   - pin 15 SDI_CFG1
   - pin 16 SDO_CFG0
7. **TMC 1:**
   - pin 23 CFG4
   - pin 24 CFG5
   - pin 25 CFG6
8. **If time:**
   - pin 28 DRV_ENN
   - pin 26 DIAG0
   - pin 27 DIAG1

## Important

All measurements are performed with the board **powered OFF**.

Do not use continuity or resistance mode on a powered board.

A via, resistor pad, or exposed point on the same trace may be used instead of probing an IC leg directly. Record which alternate point was used.

---

*Source: Mark Stalzer — Google Doc “Pin Testing” (screenshots 2026-09-21). Twin PDF: `AutoPilot_Continuity_Bench_Sheet.pdf`.*
