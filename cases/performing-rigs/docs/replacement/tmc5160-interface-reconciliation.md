# TMC5160 interface reconciliation

## Result

**Partial: a substantive candidate configuration/diagnostic interface is supported; electrical functionality is not demonstrated.** Original firmware concretely requests SERCOM5 SPI-master transfers, four software chip selects, five-byte writes and two-transaction reads. The recorded physical serial routing is consistent with investigating this interface, but the exact MCU **package-pin → GPIO → supported pinmux** bridge cannot be certified from the manufacturer references available locally. No valid TMC response or safe test-power configuration has been established.

Do not adopt “no serial interface,” “SERCOM5 only initializes,” “CURRENT/MICROSTEPPING only affect display,” or “standalone/no SPI established” as implementation facts. The first three conflict with the bounded evidence below; the last lacks its authoritative mode-table justification locally. This does not reopen the established MCU STEP/DIR motion architecture.

Baseline: clean `main`, HEAD `66f2cf9f2c6206b20cf8e4b22addbc0bf952f301`, matching local origin/main, no network fetch. Firmware: AutoPilot868, 70768 bytes, SHA-256 `6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3`, load base 0x4000. No bootloader or apfw2 files were analyzed. These conclusions are not transferred to the 915 image without evidence.

The companion `research/generated/tmc5160-interface-contract.json` (paths relative to case root) uses stable finding IDs, evidence references/hashes, null verification state for unadmitted findings, and UNKNOWN where no APTrace grade was assigned. Documentary, static and concrete bases stay separate. No new VERIFIED claim was created. Current LID semantics proposals remain proposals.

## Physical evidence and original records — TMC-PHYS-SERIAL

The most specific available record is `docs/hardware/AutoPilot_Continuity_Bench_Sheet.md`, especially §§2–8. Its attribution is Mark Stalzer, Google Doc “Pin Testing,” screenshots dated 2026-09-21. Hardware reconciliation narratives are dated 2026-10-17. Actual measurement date, instrument/setup uncertainty and measured board revision are not independently recorded. Photo dossiers describe AutoPilot silkscreen 52_PO_V01R04; that is not proof the measurements used that exact revision. The bench sheet's referenced twin PDF/annotated measurement originals were not located locally; no external document was accessed.

Raw §6 upper table:

| Device / terminal | Reported MCU package pin | Confirmed GPIO identity from local package reference |
|---|---:|---|
| TMC1 CSN_CFG3 / 13 | 11 | unknown |
| TMC2 CSN_CFG3 / 13 | 37 | unknown |
| TMC3 CSN_CFG3 / 13 | 12 | unknown |
| TMC4 CSN_CFG3 / 13 | 38 | unknown |
| Shared SCK_CFG2 / 14 | 64 | unknown |
| Shared SDI_CFG1 / 15 | 63 | unknown |
| Shared SDO_CFG0 / 16 | 62 | unknown |

These are **reported continuity routes**. Lower §6 connection cells are blank beside resistance entries of 0; do not assign those zeros to every upper-table route without an unambiguous paired endpoint. The upper table is populated and cannot be dismissed as a blank template. It does not document powered signal levels, loading, isolation, intervening components or MISO release behavior. Terminal numbers are explicit, but independent package orientation/device-to-photo identification and point-to-point probe records are unavailable. Reconcile this metadata rather than repeating all continuity measurements.

Raw §3 establishes two distinct muxes and direct A-side paths to TMC1/TMC3 versus TMC2/TMC4. Raw §4's RJ45 resistance/diode paths concern that mux/STEP-DIR network, **not automatically the serial bus**. Do not insert either mux into the SPI schematic without evidence. Raw §2 tests only S→PB16/PB17 and /OE→PB06/PB07 on each mux, about 324.9–334.5 kΩ. It does not establish direct control continuity or exclude buffered relationships. These results and TMC1's grounded DRV_ENN do not define a safe enable state.

## MCU and peripheral reconciliation — TMC-LEGACY-PINS / TMC-SPI5-CONFIG

Available primary device material: `config/svd/ATSAMD51J19A.svd` and the existing SVD resolver. It supplies register definitions and SERCOM DOPO/DIPO encodings, **not physical package pinout or the complete GPIO multiplexing matrix**. The previously fetched reference corpus/CMSIS-Atmel headers are not present in this checkout. No local ATSAMD51 data sheet/package table, package-specific I/O header/ATDF, saved KiCad symbol for these seven pins, or TMC5160A data sheet was located in the repository or the bounded local reference locations checked. The older pin map's attributed KiCad transcription covers other named pins, not these seven package relationships. Missing references are evidence dependencies; no guessed pinout is substituted.

The following is a **separate firmware-requested configuration**, not a certified conversion of the physical table:

| Legacy role | Firmware GPIO / pin-table index | Evidence |
|---|---|---|
| SPIClass input field (MISO interpretation) | PB01 / 52 (0x34) | constructor arguments, object +4 and pin-table entry 0x14764 |
| SPIClass output field (MOSI interpretation) | PB02 / 22 (0x16) | constructor stack argument, object +5 and pin-table entry 0x14494 |
| SPIClass clock field (SCK interpretation) | PB03 / 23 (0x17) | constructor r3, object +6 and pin-table entry 0x144ac |
| logical channel 0 software select | PB08 / 18; device object 0x200020a0 | object +0x34, table 0x14434; GPIO request mask 0x100 |
| logical channel 1 software select | PA18 / 10; object 0x200021d8 | object +0x34, table 0x14374; mask 0x40000 |
| logical channel 2 software select | PB09 / 19; object 0x2000213c | object +0x34, table 0x1444c; mask 0x200 |
| logical channel 3 software select | PA19 / 11; object 0x20002274 | object +0x34, table 0x1438c; mask 0x80000 |

Signal-role interpretation uses the SPIClass layout and access code, not a physical waveform. MCU pad indices in this table are not MCU package-pin numbers. In particular, the four legacy logical channels are not automatically TMC1–4 in bench numbering. **That join remains unknown** until the primary package mapping is available.

Fresh boot records SPIClass construction at 0x9f60 with object 0x200041e4 → SERCOM object 0x20004c78 → base 0x43000400 (SERCOM5). Constructor at 0xa28c passes indices 52/23/22, DOPO=0 and DIPO=3. A separate object 0x20004198 → 0x20004c54 belongs to the radio's SERCOM2 path. Do not conflate their common library transfer routine.

Concrete PORT requests select mux function **D** on PB01/PB03/PB02 (GROUP1.PMUX0=0x30 at 0x410080b0, GROUP1.PMUX1=0x30 then 0x33 at 0x410080b1; PINCFG PMUXEN set). SVD decodes SERCOM5 CTRLA=0x0030000c as SPI master, DOPO=0, DIPO=3; transaction CTRLA=0x3030000e additionally sets ENABLE and CPOL/CPHA. DOPO=0 defines DO PAD0 and SCK PAD1; DIPO=3 defines DI PAD3. This is internally coherent **as a firmware request**. That does not establish manufacturer support for function D on these exact pads; the pinmux table is missing.

Legacy beginTransaction supplies 2000000 and mode argument 3, with BAUD=0x0b in the captured accesses. These are software requests, not an independently measured bus rate or a recommended setting. The four software selects are manipulated through digitalWrite/PORT, rather than automatic SERCOM SS; they are candidate independent outputs, but physical independent device selection remains untested.

No overlap exists between these firmware-requested pads and the established STEP/DIR pairs, PB06/PB07/PB16/PB17 controls, radio PA15/16/17, or USB PA24/25. This compares the named existing mappings only; it is not an exhaustive ownership proof across all paths, bootloader activity or board revisions. Other connected circuitry and pulls remain unknown.

## Original firmware: observed configuration and reads

**TMC-SERIAL-WRITE.** Previous `replacement-firmware-readiness/application-boot.json` already contains 640 writes to SERCOM5.DATA in its 450000-instruction bounded run. A new repeat using the same boot assumptions stops at first receive call 0x8960 after 378402 instructions and captures **620 SERCOM5 transfers**, plus 70 SERCOM2 transfers. Counts differ because the bounds differ. Both logs are below their configured MMIO caps; no universal absence follows.

At 0xb468 the routine loads the peripheral base through its caller's object, writes DATA at +0x28, polls INTFLAG and reads DATA. Passive watches identify 620 entries with SERCOM object 0x20004c78. First observed select interval: PB08 OUTCLR at instruction272271, bytes `80 00 00 00 00` at272283–272356, OUTSET at272405. Next interval contains `ec 10 41 01 50`. These are raw modeled requests, not captured electrical MOSI or validated TMC register meanings.

Device objects share vtable0x14250. Entry0 is Thumb pointer0xacd9 → function0xacd8: begin transaction, select LOW, send selector OR0x80, send a 32-bit value most-significant byte first, end, select HIGH. Disassembly confirms this five-byte format. Object +0x38 is zero in captured state, selecting the hardware SPI branch rather than the alternate software-bitbang branch in 0xabf8. The result is substantially stronger than merely finding SPI code: transfer and select requests actually executed under the disclosed model.

**TMC-SERIAL-READ.** Entry1 →0xac28 implements a request transaction and a second transaction collecting four bytes, storing an initial return byte in object +0x14. Wrapper0xa944 supplies selector0x6f; helpers0xa970/0xa982 extract bits29/30 from its returned word. Fresh boot reaches0xac28 eight times (twice for each of the four objects) at instructions368987–373770. These are demonstrated read attempts. They are **not valid status responses**: Unicorn MMIO is memory, read values are not a modeled external TMC, and the earlier “motor presence” interpretation cannot establish actual connector detection from this model. No device identity or named fault bit is assigned without its data sheet.

**TMC-CONFIG-CONSUMERS.** The function at0x7514 is historically labeled `lcd_status_refresh__THIRD_PARTY`, but its observed behavior includes serial device configuration. In setup0x9464 →0x7770, the firmware calls0x7514 for all four logical channels. The instruction at0x753e loads a halfword through the pointer at0x7758 (=0x2000006c) and0x7540 calls0xae60. That helper eventually invokes the write method with selector0x10. Fresh caller-grounded watches show argument400 (0x190) for each device while0x7770 temporarily substitutes that channel's RAM value; this is not a claimed400mA current. The code uses object coefficients and other helpers, so actual current scaling remains unresolved.

The same startup helper calls0xb070 using values from0x200000f0 (pointer0x775c). Fresh watches show argument16 for each object. Static code maps selected power-of-two inputs to a vtable setter; its physical microstep interpretation and actual driver setting require documentation/readback. Both fields feed **serial-setting code**, contradicting the earlier display-only inference. This proves neither that every runtime MC command reaches hardware nor a precise safe motor-current/microstep value. No full MC replay was needed or performed.

These facts follow one named startup path, not a new whole-image interface census. Earlier TMC r7's recorded peripheral query was **SERCOM4**, not SERCOM5; it reported no constant-address sites, explicitly excluding computed-base accesses. The run ended `planner_prefill_exhausted`, `reconciled=false`. Other inspected TMC transcripts also ended unreconciled. None proves no SPI use. The fresh transfer routine demonstrates why constant-address xrefs to0x43000400/28 can be empty: its address is loaded indirectly through an object.

## Mode decision table — TMC-MODE-STRAPS

| Evidence / condition | What is observed | Data-sheet-defined behavior established locally | Decision |
|---|---|---|---|
| Raw §5, TMC1 only | SD_MODE21 and SPI_MODE22, each0Ω to VCC I/O20 | No authoritative local mode truth table located | Fixed reported wiring; powered HIGH/threshold/reset sampling and interface consequence remain conditional |
| Raw §7, TMC1 | CFG4/5/6 pins23/24/25, each0Ω to GNDANA | Device mode-dependent CFG interpretation unavailable | Do not infer microstep/current settings |
| Raw §8, TMC1 | DRV_ENN28 connected to GNDANA; no resistance column | Powered enable/current-path behavior not established | No GPIO-disable or non-energizing state inferred |
| Raw §6 | Serial/config routes recorded | Serial framing/readable register/default requirements unavailable | Candidate interface, not working communication |
| Other three devices | Serial routes recorded, mode/CFG/DRV_ENN measurements not independently specified | No transfer of TMC1 mode facts | Mode remains unknown per device |
| Legacy SERCOM5 transfers | Runtime software writes and read attempts observed | No electrical target response or register validation | Does not establish device mode or reset defaults |

The summaries' “HIGH/HIGH means standalone/no SPI” conclusion is not justified by the local evidence supplied. Conversely, this report does not invent a replacement truth table. Obtain the correct local TMC5160A-TA mode table, power-domain requirements and SPI chapter. Even a fixed physical strap requires valid powered rail levels and appropriate startup/reset conditions. External STEP/DIR motion and serial configuration are separate questions; a restriction against their coexistence is not established here.

## Configuration and implementation implications

| Property | Supported classification | POC consequence |
|---|---|---|
| Reported serial nets | Physical evidence, bounded to source table | Preserve device/package assignments; do not equate to certified GPIOs |
| SERCOM5 access and logical selects | Concrete modeled behavior plus static/SVD evidence | Candidate software transport and regression observations available |
| Mode/CFG/enable wiring | Physical evidence for TMC1; mode semantics conditional/missing | Resolve reference/power-state questions before SPI testing |
| Current and microstep input consumers | Original-firmware behavior: serial-setting paths observed | Display-only premise rejected; electrical values remain unknown |
| Effective current/sense resistors | Unknown pending physical characterization | Blocks first energization; no legacy coefficient is a substitute |
| Chopper, hold/run current, actual microstep state, startup defaults | Firmware raw selectors/words available, meanings/defaults unvalidated | Must remain unspecified in an actionable hardware configuration |
| Diagnostic/status access | Original read attempts observed; candidate interface | Software diagnostic boundary can be designed; valid faults/identity reads unproven |
| Motor-safe enable/reset/fault state | Unknown pending electrical verification | Blocks power/access until an approved test configuration exists |

READY: software-level bus/device-selection abstraction, explicit error/timeout/readback result handling and separation of motion versus configuration. CONDITIONAL: SERCOM5 instance, observed D/DOPO/DIPO recipe and logical select GPIOs, subject to manufacturer pad/package tables and physical validation. BLOCKED: a deployable TMC register protocol/configuration, guaranteed non-energizing access, current settings and actual mode/diagnostic interpretation while essential local device references and hardware gates remain missing. OPTIONAL for POC: multi-driver bring-up and broad diagnostic enumeration after shared-bus isolation has been established. No apfw2 driver code was written.

## Execution, limitations and next work

APTrace operations: existing Ghidra xrefs/callers/containing/dump/decompile/disasm on named SPI/startup methods, existing SVD address lookup, and three repeats of the established native Unicorn boot recipe with passive observations or RAM dumps. Exact reproduction commands, file hashes and native results are in `research/runs/tmc5160-interface-reconciliation/`. All three new runs reach the requested0x8960 checkpoint at378402 instructions, error-free and completed at that checkpoint. No physical communication or interrupt/time behavior is implied. No software implementation changed, so framework test suites were not rerun; artifact syntax/reference/hash checks are recorded separately.

There was no unresolved sandbox blocker. Already approved execution patterns were reused. Ghidra had no function object at0xb468 or0xa944; supported range disassembly supplied the needed instructions without creating functions or changing analysis policies. This is an attribution/boundary limitation, not proof of absent code. Empty constant-address xrefs were not used as absence evidence. No symbolic run was needed for these concrete input/state questions.

| Gap | Impact / observed evidence | Cause assessment | Needed evidence/capability / priority |
|---|---|---|---|
| Package/pinmux references absent | Cannot certify seven package→GPIO assignments or supported SERCOM5 pad routing; local SVD lacks those tables | Missing local device material, not demonstrated engine defect | Obtain local ATSAMD51J19A package/I/O mux tables; HIGH |
| TMC mode/SPI/register reference absent | No authoritative mode decision, register identity/readback oracle or electrical test parameters | Missing local device reference | Obtain correct TMC5160A documentation; HIGH |
| No physical external-device model or measurement | Native reads do not establish communication/status/current | Intentional plain-memory MMIO; board evidence incomplete | Execute engineering-approved bench plan; HIGH; no new simulator recommended |
| Prior labels and summaries overstate semantics | SERCOM5 transactions and field consumers were missed despite existing evidence | Documentary interpretation and bounded census limitations | Use these exact trace/method references; MEDIUM; no new analysis feature required |
| Production verification envelopes/semantics incomplete | New export cannot claim VERIFIED | Existing readiness report X15 and unresolved LID proposals | Preserve unadmitted/scoped export; existing development recommendations remain separate; no remediation in this task |

Next existing-capability work: reuse these traces and inspect only a named unresolved setting once its device reference supplies a concrete question. New evidence: first acquire local authoritative references, then approve a non-energizing electrical setup, verify powered straps/line levels/CS isolation and one documented read-only transaction; characterize current and reset containment before any motor test. No broad SPI discovery, new engine/model, package installation, external access, historical ledger rewrite, commit or push was performed.
