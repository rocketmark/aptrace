# TMC5160 contract for apfw2 POC 0.1

This is implementation guidance, not a powered-test authorization. Source: AutoPilot868 SHA-256 `6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3`, load0x4000; [reconstruction and citations](tmc5160-datasheet-reconciliation.md), [124 recorded datagrams](../../research/generated/tmc5160-startup-transactions.json), [eight software reference vectors](../../research/generated/tmc5160-configuration-vectors.json). Confidence is high for the bounded software behavior; no hardware verification or VERIFIED claim is implied. No apfw2 files were changed.

## READY — implement and test on the host

| Interface / concern | Contract | Evidence / reference |
|---|---|---|
| Pin constants | SERCOM5: MOSI PB02/package63/PAD0, SCK PB03/package64/PAD1, MISO PB01/package62/PAD3; mux D, DOPO0,DIPO3 | M DS60001507N Fig4-2 p22, Table6-1 pp30/33/34, Table6-15 p37, §35.8.1 p920; constructor0x9f60 at0xa28c |
| Device selection | logical0/TMC1 PB08;1/TMC2 PA18;2/TMC3 PB09;3/TMC4 PA19. CS active LOW, inactive HIGH; exactly one selected per datagram | Existing bench §6; M package table; recorded0xacd8/0xac28 intervals. Driver→motor/XLR mapping remains conditional |
| Transport | Mode3, eight-bit MSB-first characters, software CS, receiver enabled; exclusive bus ownership across each full read pair; timeout/error propagation | CTRLA transaction3030000e, CTRLB20000, BAUD0b; T rev1.18 §4 pp23–25 |
| Clock setup | Enable MCLK.APBDMASK.SERCOM5 bit1 and a valid GCLK_SERCOM5_CORE at PCHCTRL35; synchronize reset/config/enable. Original GEN1 and shared PCHCTRL3 have41; derive replacement BAUD from actual GCLK | M §35.5.3 p905, Table14-9 p155, §15.8.10 p179; SPI5-INIT vector. Legacy2MHz is a request, not required first bench speed |
| Write register | `write_register(driver, address, uint32_payload)` emits `(address&0x7f)|0x80`, then payload bytes31:24,23:16,15:8,7:0 in one CS-low interval; return SPI_STATUS separately from transport success | T §4.1 pp23–24;0xacd8; T001/T002 |
| Read register | `read_register(driver,address)` performs two five-byte datagrams with CS HIGH between; second MISO data answers first request. Preserve status separately, report validity/error, never treat dummy MOSI as response | T §4.1;0xac28 and T101/T102. No recorded RX word is an oracle |
| Register representation | Explicit bitfields and reserved-bit masks; raw encoded values distinct from engineering units and active/readback-confirmed state | T §6 pp31–56; generated JSON fields |
| Microsteps | `configure_microsteps(driver,16,interpolate=true)` targets CHOPCONF.MRES4,INTPOL1,DEDGE0, preserving approved remaining fields. Legacy full word14408155 is a comparison vector, not a mandatory default |0xb070; T019; T §6.5.2 p51. Track sixteen commanded microsteps/fullstep separately from interpolation256 |
| Current representation | Separate requested engineering current, verified board calibration/R_SENSE, encoded GLOBALSCALER/IRUN/IHOLD and measured/confirmed current. If reproducing legacy conversion on host, input400 with recorded coefficients must yield G133,IRUN5,IHOLD4 |0xae60; CURRENT-400 vector; T §9 p74. No board R_SENSE or safe target is supplied |
| Diagnostics | Decode DRV_STATUS by named masks; bits29/30 are OLA/OLB and have validity conditions. Distinguish driver fault, reset flag and invalid/missing response from connector presence | T §4.1.2 p24; §6.5.5 p56;0xa944/0xa970/0xa982 |

Minimum software boundaries: bus initialization/timeout; exclusive device selection; raw read/write with status and response-validity reporting; explicit approved configuration object; apply configuration under an established inhibit; reset detection/reinitialization; named fault reporting; separate motion commands. No API should report “safe,” “motor connected,” or measured milliamps solely from a successful transport request. Keep unconfirmed desired settings separate from active settings. A reset or transport failure invalidates assumed device state.

Eight bounded regression references cover SERCOM setup, CS/write framing, CHOPCONF write, pipelined read request, current400 conversion, microstep16 conversion, four-select isolation requests and all124 startup datagrams. They can check host serialization and intended legacy behavior. They do not constitute passing apfw2 tests (none were run), an RX oracle, physical isolation proof, or approval to replay startup on a board. Current-input boundary cases and unobserved microstep mappings require separate software requirements/tests before relying on them.

## CONDITIONAL — electrical gates determine use

| Behavior | Required condition |
|---|---|
| Driving these pins on the board | Confirm board/package identity and valid compatible rails; all CS preload HIGH before output enable; scope reset/initialization. Legacy GPIO direction-before-HIGH ordering need not be reproduced |
| SPI plus external STEP/DIR | TMC1 measured straps must reach valid HIGH/HIGH at power/reset. Verify other powered bus devices individually; no inheritance of TMC1 measurements |
| First read | Resolve power-domain, enable and all-channel containment; line voltage/CS independence/MISO release; then use documented IOIN0x04 read pair with VERSION/pin-state checks from bench delta |
| Nominal16 microsteps | Actual SD_MODE1, successful register application, valid reset history and identified STEP route; physical motion/count confirmation still needed |
| Current calculation | Measured R_SENSE/topology, applicable V_FS, power-stage/driver settings, active current regulation and motor/current budget supplied by responsible engineering work |
| Reinitialization | Establish reset/inhibit behavior before writes; MCU reset does not guarantee TMC reset. Reapply all approved software-used registers rather than trusting previous RAM state |

## BLOCKED — powered operation

Powering an SPI test remains blocked until an engineering-defined, documented non-energizing setup exists. TMC1 DRV_ENN is reported grounded; T rev1.18 §2.2 p13 defines HIGH as bridge disable, so this is not an available inhibit. CFG6 is DCO output in the inferred mode yet is reported grounded; review this specific condition. VCC_IO alone does not supply internal logic; VCC, VSA/5VOUT, VS and gate-domain topology/back-power paths are unresolved. A read-only command or absence of STEP pulses does not close these gates.

First motor energization also needs measured sense network and allowable current, selected-driver→motor connector mapping, deliberate chopper/microstep/current choices, all other channels contained, and reset/STOP/fault waveform/current evidence. Legacy TOFF becomes nonzero before current setup; do not use the observed startup ordering as a safe order. StealthChop enable/tuning must meet the manufacturer prerequisites, including standstill and IHOLD at nominal IRUN on the off→on transition (T §6.1 p32); the legacy final IHOLD4/IRUN5 is not a compliance demonstration. Original IRUN5 falls below the datasheet's16–31 recommendation for best microstep performance (T p38); historical compatibility is not a requirement to retain it.

Recommended implementation ordering, conditional on an independently established inhibit: set all selects inactive; initialize bus; validate one driver's read response; establish/reset known state; request TOFF0 and apply approved configuration while hardware containment remains in effect; validate only readable registers and documented status; retain shadows for write-only fields (GLOBALSCALER and IHOLD_IRUN are marked W in T); enable only after the physical motion gate. SPI writes have no general per-write acknowledgement. Status alone cannot prove every write-only field or current took effect.

## OPTIONAL — defer beyond first single-axis movement

Reproducing every legacy chopper word, temporary current400 substitution, internal-ramp position clears, all-channel configuration, StealthChop transitions, stallGuard tuning, DIAG integration, DcStep and reconnect automation is not required for POC0.1. Nonselected-channel containment on shared power/bus is required. Preserve APTrace/apfw2 independence: use these reports/vectors as external evidence; do not import APTrace runtime machinery into the replacement firmware.
