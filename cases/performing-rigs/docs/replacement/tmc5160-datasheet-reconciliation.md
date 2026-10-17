# Datasheet-grounded TMC5160 configuration reconstruction

## Investigation result and scope

**Partial hardware readiness; complete reconstruction of the selected startup's recorded transmit requests.** The seven reported serial connections agree with the ATSAMD51J19A package, supported mux D, and observed SERCOM5 configuration. TMC1's reported straps support SPI configuration plus external STEP/DIR **if the identified pins reach valid powered HIGH levels**. This does not establish the other three drivers' mode. All 620 recorded SERCOM5 DATA writes group into 124 complete, attributable five-byte logical datagrams: 108 writes and 16 read requests from eight read-method calls. No physical transfer or register response is validated.

CURRENT=400 reaches GLOBALSCALER=133, IRUN=5 and IHOLD=4. MICROSTEPPING=16 reaches CHOPCONF.MRES=4, INTPOL=1, DEDGE=0: a request for sixteen external microsteps per full step, interpolated internally to 256. Actual current, power-stage containment, powered mode and connector mapping still require board evidence. Powered SPI testing and motor energization remain blocked by the unresolved engineering prerequisites below.

Baseline: `main`, HEAD `6b331521d2c20e24fdf16cfd9f975fa67dd3d607`, matching local origin/main (no fetch); initial tracked tree clean. Prior interface records were committed in `b299e68`; these new documents supersede their missing-document qualifications without changing historical evidence. AutoPilot868 image: `research/firmware/originals/firmware_autopilot868.bin`, 70768 bytes, load 0x4000, SHA-256 `6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3`. All firmware-specific findings and vectors in this report concern this image, not AutoPilot915, a bootloader, or apfw2.

Paths below are relative to the Performing Rigs case. Confidence is high for documentary decoding and the scoped software requests, conditional for the physical join, and unknown for electrical effect. These exports have no admitted claim ID, verification state is null, APTrace grade is UNKNOWN, and **no VERIFIED ledger claim is created**. Documentary interpretation does not satisfy a missing verification envelope.

## Manufacturer references

Page citations use printed pages, matching one-based PDF pages in these supplied editions.

| ID | Exact repository-relative file | Identity / revision / date | SHA-256 |
|---|---|---|---|
| M | `cases/performing-rigs/research/SAM-D5x-E5x-Family-Data-Sheet-DS60001507.pdf` | Microchip Technology Inc., *SAM D5x/E5x Family Data Sheet*, ATSAMD51 family including J19A; DS60001507N, 03/2026 (revision history Table64-1 p1985). PDF creation 2026-03-25 is metadata, not an independently specified publication day. 2002 pages | `9a911a0ec57f0a0db0f2056eefcfb47ffa6703e9de2e6b78f66cb24152a8a5ae` |
| T | `cases/performing-rigs/research/tmc5160a_datasheet_rev1.18.pdf` | TRINAMIC Motion Control, Analog Devices supplied reference; *TMC5160/TMC5160A Datasheet*, rev1.18, 2023-MAR-01, TQFP48/QFN56. 134 pages | `3c3edc4fbd694f3afd95ff8f5922a777fdc56d91660c3c0fbdccc016f1bd0be1` |

Both PDFs were read locally through PDFKit text extraction. Package diagram, mux tables, CHOPCONF fields, current equation and electrical table were also visually inspected; supporting text and page images reside in `research/runs/tmc5160-datasheet-reconstruction/`. M §4.2 Fig4-2 p22; §6.1 Table6-1 pp30–34; §6.2.8.1 Table6-15 p37; §14.8 PCHCTRL Table14-9 p155; §15.8.10 pp179–180; §35.5.1–3 pp904–905; §35.8.1 pp919–921. T §2.2 pp12–13; §4 pp23–25; §6 register tables pp31–56; §9 pp74–75; §25 p119; §28.2 p123 are the principal references.

## Pin-level reconciliation

Physical basis: populated upper table in `docs/hardware/AutoPilot_Continuity_Bench_Sheet.md` §6. Firmware basis: previous `research/runs/tmc5160-interface-reconciliation/` pin dumps, constructor/disassembly and boot MMIO, cross-referenced below. Classification **P+D+C/S** means reported physical route + manufacturer documentation + concrete/static firmware evidence; it does not mean powered continuity has been remeasured. Device labels and package orientation remain conditional on the bench record's identity. No conflicting package assignment was found; older reports left this conversion unknown.

| MCU package pin | GPIO | Available serial mux / chosen function | Firmware request | Reported destination | M reference | Classification / remaining conflict |
|---|---|---|---|---|---|---|
| 11 | PB08 | D SERCOM4/PAD0 available; PORT GPIO chosen | index18, object0x200020a0, GROUP1 bit8; OUTCLR/SET mask0x100 | TMC1 CSN_CFG3 pin13 | Fig4-2 p22; Table6-1 p30 | P+D+C/S; physical independent select untested |
| 37 | PA18 | C SERCOM1/PAD2, D SERCOM3/PAD2 available; GPIO chosen | index10, object0x200021d8, GROUP0 bit18 mask0x40000 | TMC2 CSN_CFG3 pin13 | p22; Table6-1 p32 | P+D+C/S; same limit |
| 12 | PB09 | D SERCOM4/PAD1 available; GPIO chosen | index19, object0x2000213c, GROUP1 bit9 mask0x200 | TMC3 CSN_CFG3 pin13 | p22; Table6-1 p30 | P+D+C/S; same limit |
| 38 | PA19 | C SERCOM1/PAD3, D SERCOM3/PAD3 available; GPIO chosen | index11, object0x20002274, GROUP0 bit19 mask0x80000 | TMC4 CSN_CFG3 pin13 | p22; Table6-1 p32 | P+D+C/S; same limit |
| 64 | PB03 | D SERCOM5/PAD1 | index23; PMUX1.O=3; PINCFG3=0x41; DOPO=0 | shared SCK_CFG2 pin14; MCU SCK output | p22; Table6-1 p30; Table6-15 p37 | P+D+C/S; waveforms unknown |
| 63 | PB02 | D SERCOM5/PAD0 | index22; PMUX1.E=3; PINCFG2=0x41; DOPO=0 | shared SDI_CFG1 pin15; MCU MOSI output | p22; Table6-1 p34; Table6-15 p37 | P+D+C/S; levels unknown |
| 62 | PB01 | D SERCOM5/PAD3 | index52; PMUX0.O=3; PINCFG1=0x41; DIPO=3 | shared SDO_CFG0 pin16; MCU MISO input | p22; Table6-1 p33; Table6-15 p37 | P+D+C/S; release/contention unknown |

These three serial pads belong to SERCOM5 IOSET6. M §35.8.1 p920 defines DOPO=0 as DO/PAD0 and SCK/PAD1, DIPO=3 as DI/PAD3. T §2.2 p12 defines SDI as driver input and SDO as tristate driver output: SDI connects to **MCU MOSI**, SDO to **MCU MISO**. Four GPIO selects do not imply SERCOM4 traffic or automatic SS. This resolves the logical-channel→TMC join as 0→1, 1→2, 2→3, 3→4; it does not resolve driver→XLR/STEP-DIR routing.

Constructor0x9f60 at callsite0xa28c creates SPI object0x200041e4 → SERCOM object0x20004c78 → base0x43000400. The separate radio uses SERCOM2. MMIO instructions70647/70686/70724 select mux D at0x410080b0=0x30 and0x410080b1=0x30→0x33; PINCFG writes70650/70689/70727 enable mux. Initial CTRLA0x0030000c requests SPI host, DIPO3, DOPO0; CTRLB0x00020000 enables receiver, MSSEN=0, eight-bit characters. Initial BAUD=5; later transaction CTRLA0x3030000e sets ENABLE, CPOL=1, CPHA=1, DORD=0 (MSB first), BAUD=11. API0xa000 requests 2MHz and mode3. This agrees with T §4.3 p25 mode3; it does not measure 2MHz.

Clock dependencies: M §35.5.3 p905 requires APB and GCLK_CORE. Recorded MCLK.APBDMASK at0x40000820=0x3ff sets SERCOM5 bit1 (M §15.8.10 p179). GCLK PCHCTRL35 at0x40001d0c goes0→0x41, selecting GEN1 and CHEN; PCHCTRL3 at0x40001c8c likewise supplies shared SERCOM_SLOW (M Table14-9 p155). A replacement must derive BAUD from its actual core clock and respect synchronization; it need not copy the original global clock tree. Formula fSCK=fGCLK_CORE/[2(BAUD+1)] gives 2MHz for BAUD11 **if** core clock is48MHz. Hardware frequency is unmeasured.

GPIO configuration requests PINCFG=0x42, DIRSET for each select at instructions65096–65178, then OUTSET HIGH at65212/65239/65274/65302. Per-device startup reapplies DIRSET before HIGH. These request GPIO outputs with input buffers enabled (PINCFG.PMUXEN=0), followed by inactive HIGH; later digitalWrite also toggles pull settings. Direction is requested before the recorded HIGH, so this does **not** prove a glitch-free inactive waveform from reset (M §32.8.3 p832). Plain-memory MMIO does not implement complete PORT alias/pad electrical semantics. apfw2 should preload inactive HIGH and deliberately establish a suitable output mode after electrical gates; do not copy a reset glitch or infer physical drive from OUTSET alone. None of the complete datagrams overlaps another recorded select assertion.

## Operating mode and supply interpretation

Manufacturer mode decision (T §2.2 pp12–13):

| SPI_MODE | SD_MODE | Configuration interface | Motion input / mode |
|---|---|---|---|
| HIGH | HIGH | SPI on CSN/SCK/SDI/SDO | External STEP/DIR; CFG4 is DCEN, CFG5 DCIN, CFG6 DCO |
| HIGH | LOW | SPI | Internal ramp generator; reference and encoder pin roles |
| LOW | HIGH | Standalone CFG pins; SPI unavailable | External STEP/DIR |
| LOW | LOW | UART/single-wire interface | Internal ramp generator |

Raw bench §5 records **TMC1 only**, SD_MODE21 and SPI_MODE22 each0Ω to VCC_IO20. This is unpowered continuity, not powered HIGH. If pin identification, rail validity and powered levels hold, the first row applies and agrees with MCU-generated STEP/DIR plus observed SPI writes. The prior HIGH/HIGH→standalone inference is contradicted by T. No powered strap measurement exists; other devices' mode straps remain unknown.

TMC1 CFG4/5/6→GNDANA0Ω (§7) must be interpreted in that mode: CFG4 LOW requests no DcStep; CFG5 is a gating input; CFG6 is **DCO output**, not a standalone microstep/current selector. The reported grounding of an output warrants targeted electrical review of pin identity, output behavior and loading before power; it does not establish a microstep strap. T §2.2 says leave CFG4 open or ground for normal HIGH/HIGH operation.

TMC1 DRV_ENN28→GNDANA (§8; no resistance column) is not a disable strap. T §2.2 p13: **HIGH disables the power stage and floats motor outputs**. LOW removes that inhibition; effective switching still depends on TOFF, power and other configuration. No independent MCU control of DRV_ENN is established. Other devices' enable states are unknown.

T pp12–13 distinguishes VCC_IO (3.3–5V digital I/O supply, does not power core), VCC (5V internal digital supply from5VOUT), VSA (regulator/analog supply), VS (motor bridge supply) and gate/charge-pump domains. VCC_IO alone is not a documented complete communication-power setup. M §7.1 p43 specifies1.71–3.63V MCU I/O supply; T's5V allowance does not authorize5V on MCU nets. T §28.2 p123 defines input LOW≤0.3VCC_IO and HIGH≥0.7VCC_IO; actual MCU/driver rails, level compatibility and unpowered input/back-power conditions require circuit evidence.

T §25 p119 states power-up defaults reload on undervoltage of VSA,5VOUT orVCC_IO; **VCC is not monitored and must not be lost**. A MCU reboot is not necessarily a driver reset. Its recommendation is TOFF=0 then reinitialize software-used registers and stop ongoing ramp motion. Hardware-reset-by-VCC_IO cycling requires all digital inputs LOW to avoid protection-diode back-power; it is not an approved board procedure here. Defaults include explicit/OTP exceptions; do not assume every register is zero or retained after reset.

## Chronological serial reconstruction

The full [124-row chronological table](../../research/runs/tmc5160-datasheet-reconstruction/startup-transaction-table.md) is part of this report. [Machine-readable transactions](../../research/generated/tmc5160-startup-transactions.json) preserve raw bytes separately from register fields, all DATA write MMIO indexes/instructions/PCs, bounding CS writes, device objects, method entries, LR caller references and source hashes.

Method: use only recorded OUTCLR/OUTSET bits for the four documented selects; collect SERCOM5.DATA low bytes strictly inside each matching LOW→HIGH interval; require one selected device and exactly five bytes. All framing derives from one MMIO log. Method/caller metadata joins the separate configuration-watch run by deterministic instruction ordinal and object, checked against register and payload arguments. This join is an explicit assumption, not same-run watch provenance. There are no orphan bytes, incomplete nonempty intervals, overlapping select requests or active intervals left at checkpoint. No unobserved template is counted. The trace cannot determine real failed transfers.

| Recorded span | Requests |
|---|---|
| T001–T023; T024–T046; T047–T069; T070–T092 | 23 initial writes each to TMC1,2,3,4 in logical order0,1,2,3 |
| T093–T100 | GCONF=0 and PWMCONF=c408001e in order TMC1,3,2,4 |
| T101–T116 | Two DRV_STATUS read-method calls per driver, two five-byte CS intervals per method, in order TMC1,2,3,4 |
| T117–T124 | GCONF=4 and PWMCONF=c40c001e in order TMC1,3,2,4 |

T §4.1–4.3 pp23–25: one active-low CS interval contains40bits, MSB first; first byte bit7=1 writes, bit7=0 reads, bits6:0 select register. Four payload bytes are big endian. Read payload arrives for the previous datagram's request, alongside an SPI_STATUS byte. Legacy0xacd8 writes and0xac28 reads agree;0xb468 writes DATA through an indirect peripheral object, explaining why literal-address xrefs are insufficient. Examples: T001 `80 00 00 00 00`; T002 `ec 10 41 01 50`; T101/T102 each `6f 00 00 00 00` separated by CS HIGH. In the read pair, the second physical MISO payload would answer the first request. No synthetic receive value is a register oracle.

The native run stops0x8960 at378402 instructions, completed/error-free under its harness, not a successful hardware session. MMIO is memory; SERCOM completion bits are forced and receive data is not supplied by a TMC model. Forced tick/radio ID, seeded PA22, stubbed DWT delay and calibration-row placeholder remain material assumptions (exact command in previous execution-manifest). No physical SCK edges, CS setup/hold, sampling, status, motor presence or current are observed.

## Register meanings and initialization

Each observed word's relevant fields are in JSON. Distinct payloads and documentary meanings:

| Register | Observed values | Meaning / T reference |
|---|---|---|
| GCONF0x00 | 00000000; 00000004 | en_pwm_mode bit2:0 SpreadCycle,1 StealthChop; other set flags absent. §6.1 pp32–33 |
| CHOPCONF0x6c | 10410150→10410158→10408158→10408155; repeated10408155;14408155 | TOFF0→8→8→5; TBL2→2→1→1 (36→24clocks); then MRES0→4 (256→16). CHM0, INTPOL1, HSTRT5 (=6), HEND2 (=-1), TPFD4 (=512clocks), DEDGE0, both short protections not disabled. §6.5.2 pp51–52 |
| COOLCONF0x6d | 0;00050000;01050000 | SEMIN0 disables CoolStep; SGT0→5, then SFILT1. No automatic current scaling inferred merely from register name. §6.5.3 p53 |
| PWMCONF0x70 | c40c001e; c408001e | PWM_OFS30, PWM_GRAD0, freq0, autograd1, freewheel0, REG4,LIM12; autoscale1 versus0. Applies with StealthChop; autoscale0 does not regulate IRUN/IHOLD as current targets. §6.5.4 pp54–55 |
| GLOBALSCALER0x0b |00000085 | G=133/256;0 would mean256, not off.1–31 forbidden;>128 recommended. §6.1 p36 |
| IHOLD_IRUN0x10 |0;00000500;00000504;000f0504 | IHOLD0→4, IRUN0→5, IHOLDDELAY0→15. Zero CS represents1/32, not off. §6.2 p38 |
| TPOWERDOWN0x11 |00000040 |64×2^18 tCLK after standstill; IHOLDDELAY15 adds15×2^18 clocks per reduction step. Not a measured wall time. §6.2 p38 |
| XTARGET0x2d / XACTUAL0x21 |0 /0 | Target/actual position cleared in library initialization; does not establish internal-ramp motion in SD_MODE1. §6.3.1 pp40–41 |
| DRV_STATUS0x6f |reads only | Payload on MOSI is dummy0; no observed device value. §6.5.5 p56 |

All drivers receive the same current/chopper/resolution sequence. Initial writes20/21 differ: TMC1/2 request GCONF0 and autoscale0, TMC3/4 request GCONF4 and autoscale1. Later writes temporarily request0/0 for all, then4/1 for all. Final **requested** common state is CHOPCONF14408155, GLOBALSCALER85, IHOLD_IRUN000f0504, TPOWERDOWN40, COOLCONF01050000, GCONF4, PWMCONFc40c001e, positions0. No readback confirms it. TOFF becomes nonzero before current/resolution setters finish; copying the legacy order is not an approved safe startup sequence. T §6.1 p32 also says to switch en_pwm_mode from off to on only at standstill with IHOLD at nominal IRUN. The recorded final IHOLD4/IRUN5 does not establish that prerequisite; no physical tuning/standstill condition is validated.

The configuration runs before the captured DRV_STATUS reads, so those reads do not gate the initial writes on this path.0xa944 selects0x6f;0xa970/0xa982 extract bits29/30, which T p56 identifies as **OLA/OLB open-load flags**, not connector-present bits. Open-load diagnostics can be false at standstill/high velocity; a zero or set flag is not a connector-presence oracle. No reset/reconnect replay was observed, and this bounded run does not establish universal fault recovery or absence of other initialization paths.

## Current and microstepping paths

`0x9464→0x7770→0x7514` temporarily replaces each CURRENT halfword rooted at0x2000006c with400, calls0xae60 and restores the prior software value2000. The display-oriented historical label on0x7514 is misleading: it executes configuration. Microstep halfwords rooted at0x200000f0 are16. Separate watch records show0xae60(400) and0xb070(16) for all four objects, with caller returns0x7545/0x75d5/0x765d/0x76e5 and0x757d/0x760d/0x7695/0x7717 respectively.

0xae60 uses object+0x0c float0.0560000017 and+0x10 hold coefficient≈0.9. Existing Ghidra decompilation plus supported raw dump0xaee8–0xaeef establishes constants65535.0 and83198. For request q, the integer path takes Rcode=truncate(object_float×65535), starts CS=31, computes G=floor((((Rcode×0x2d41)>>8)×q)/((CS+1)×83198)), decrements CS for low G until the loop's threshold is passed; values≥256 select encoded G=0. This is a description of the observed branch for400, not a validated full input-domain algorithm. Here Rcode=3670, CS=5, G=133; IRUN=5 then IHOLD=truncate(5×0.9)=4. Later callers set hold delay15 and powerdown64. Do not implement untested overflow/low-input cases from decompiler output.

T §9 p74 gives:

`I_RMS = (G/256) × ((CS+1)/32) × (V_FS/R_SENSE) / sqrt(2)`

G=256 for encoded0, otherwise GLOBALSCALER; CS is applicable IRUN/IHOLD/CS_ACTUAL; R_SENSE is the **actual circuit resistor**, V_FS the applicable sense full-scale voltage. T §28.2 p123 gives325mV typical under its stated full-scale conditions, not an exact guaranteed board value. With **hypothetical** R_SENSE=0.056Ω and V_FS=0.325V, the recorded G/CS imply about0.39975A RMS run and0.33313A hold. This numerical agreement supports an intended milliamp interpretation of400 and an assumed0.056Ω coefficient; neither unit metadata nor a measured0.056Ω resistor is established by code alone. The defensible contract is input400→these register words, not400mA delivered. Actual resistor values/topology, MOSFETs, supply, calibration/tolerance, thermal/motor ratings and active mode/current regulation remain required. IHOLD=4 vs IRUN=5 yields5/6 current scaling, not exactly90%, because the hardware equation usesCS+1. Firmware writes no observed explicit DRV_CONF0x0a in these124datagrams; this is a scoped observation, not proof of universal absence or safe OTP/reset power-stage settings.

0xb070 maps16→MRES4 through the vtable setter (+0x24), and T019/T042/T065/T088 actually write14408155. The request means sixteen microsteps/fullstep with interpolation to256 and one STEP edge per input pulse under documented SD_MODE1. It is no longer merely a UI value. Other statically present mappings (0→8/fullstep;2→7;4→6;8→5;32→3;64→2;128→1;256→0) were not dynamically tested here. Interpolation does not multiply the external commanded position count. Effective motor angle still needs a functioning driver, known STEP path and motor characteristics.

## Execution, gaps and recommended next work

Reused APTrace evidence: existing native Unicorn boot MMIO/configuration-watch/state records, Ghidra reviews/disassembly/dumps and case SVD/pin map. New APTrace operation: `python3 tools/ghidra/aptrace_ghidra.py dump autopilot868 0xaee8 --length 8` for the precise current constants. No new emulation, broad census or symbolic query was needed; no Macaw/Z3 test was run. The requested deterministic offline interpretation is saved as `research/runs/tmc5160-datasheet-reconstruction/interpret-recorded-transactions.py`; it interprets existing bytes and GPIO requests only, and is not a new APTrace engine/decoder interface. PDFKit extraction/rendering is document handling. No internet, package installation, firmware implementation, apfw2 edit, framework test, ledger edit, commit or push occurred.

| Gap / priority | Impact and observed evidence | Cause assessment / needed capability or evidence |
|---|---|---|
| Physical peripheral responses / HIGH | DATA reads have no external driver model; no validated status/readback or electrical effect | Plain-memory MMIO is intentionally insufficient. Obtain engineering-approved captured SPI responses; no new simulator proposed |
| PORT electrical semantics and timing / HIGH | OUTCLR/SET plus direction/pull requests cannot certify actual CS waveform, reset idle, independent drive or timing | Emulator limitations plus missing waveforms. Capture CS/SCK/MOSI/MISO/rails with actual output configuration |
| Board evidence / HIGH | TMC1-only unpowered straps; grounded DRV_ENN and CFG6/DCO need review; R_SENSE and supply topology unknown | Missing physical/circuit evidence, not a demonstrated APTrace defect. Resolve engineering gates in bench delta |
| Claim admission / MEDIUM | Documentary fields have no implemented verification envelope/ledger proof | Existing LID/verification-policy limitation. Keep null status and scoped evidence; any new validator is a separate development task |
| Cross-run attribution / LOW | Method/caller watches and raw framing recorded separately | Deterministic alignment is checked but conditional. If stronger provenance is needed, existing native CLI can capture both watch sets with MMIO in one bounded run |

Documentation dependencies G0 and mode/protocol/register parts of G1/G4/G6/G9 are now resolved for the supplied parts. Electrical parts remain. Existing-capability next work: a narrowly scoped same-run observation or named runtime input/reconnect path only when needed by POC requirements. APTrace development recommendations: stronger physical-event semantics and reproducible verification envelopes belong to separate work. New-evidence next work: establish circuit/power/enable containment, verify straps/logic levels/CS release, then one documented read; identify sense network and selected connector before energization. See [implementation contract](tmc5160-apfw2-contract.md), [bench delta](tmc5160-bench-delta.md) and [reference vectors](../../research/generated/tmc5160-configuration-vectors.json).
