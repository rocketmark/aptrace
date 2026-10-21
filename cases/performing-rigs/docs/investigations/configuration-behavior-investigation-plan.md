# Configuration, internal state and apfw2: assessment and investigation plan

2026-10-20; repository `50aece37a6661b455a4a1628faa290b86104a26b`.
**Assessment complete; behavioral recovery remains partial.** This pass reviews
existing evidence and performs seven small read-only Ghidra queries. It does
not initiate a broad reversing campaign, execute new motion scenarios, change
APTrace/apfw2, or access hardware. The release matrix remains A/B/C/D PARTIAL,
E/F BLOCKED, production NO-GO.

First-package outcome: [motor-state ownership/reference findings](motor-state-ownership-and-reference.md)
now provide the semantic/lifetime matrix and bounded witnesses. Use that result
before starting another motor-state investigation. The [X/trigger package](x-trigger-acceptance.md)
now closes the bounded selector/reset/acceptance contract and qualifies the
older repeated-accept/no-motion claims. The [A/radio package](a-radio-reconfiguration.md)
now establishes the band/channel mapping, Remote retune sequence and invalid-value
differences. Packet defaults, natural recovery and checkpoint timing remain
bounded follow-ups. The [D package](d-serial-number-and-compatibility.md) identifies
field9 as the Remote's displayed serial number; it is unscaled. Original
provisioning remains unresolved, but no operating-feature persistence requirement
is established. Package6's selected software defaults/checkpoint/reset questions
are now integrated into [bring-up Pass1](autopilot-bring-up-pass1.md), including
revalidation of affected witnesses. Its physical durability/recovery exit is
not met. Pass1 also qualifies the old permanent-zero analog coefficient claim
and the order of stored-A loading versus initial radio settings.
The priorities below retain the original planning rationale.

The highest-value next work is a **field-to-behavior contract**, starting with
motor targets/reference frames and runtime motor setup. The existence of NVM
and the ability to reload D after reset are already established; repeating them
would add little. X has a concrete trigger consumer and A has a radio-init
consumer, with their bounded results linked above. D's now-demonstrated product
role is the displayed SN identity; it is not established as a control parameter
or immutable silicon identity.

Preserving old bytes, reproducing useful behavior, and reproducing legacy bugs
are separate requirements. Intentional settings reset removes a mandatory blob
migration requirement; it does not make the state irrelevant to replacement
firmware behavior. Conversely, no evidence justifies copying the entire Noxon
layout or its persistence scheduling into apfw2.

## Evidence basis and how to read this assessment

“Established” means the specifically cited static relationship or bounded
execution result. It is not a new admitted/VERIFIED claim or a physical-device
result. “Hypothesis” is an interpretation to test. “Unknown” is an unresolved
join, unit, ownership or behavior. Existing traces keep their original seeds,
stop reasons and confidence; this review does not promote them.

| Reference | Existing work and scope |
|---|---|
| E1 | [Persistent-state release assessment](persistent-state-release-assessment.md), [observations](../../research/generated/persistent-state-2026-10-19/observations.json) and [execution/carry commands](../../research/generated/persistent-state-2026-10-19/execution-manifest.json): both default startups; 868 D/save/fresh-reset readback; factory data separated from app settings. |
| E2 | [Motor persistence dossier](motor-config-persistence.md), [loader/consumer output](../../research/generated/persistent-state-2026-10-19/consumers-static.txt), [native loader instructions](../../research/generated/persistent-state-2026-10-19/loader-disasm.txt): payload/struct staging, normalization, resync, dirty/save paths. Use its corrected constructor/caller interpretation, not the older statements preserved in historical artifacts. |
| E3 | [Auto mode and plus](auto-mode-and-plus-command.md), [virtual-link operator scenario](../../scripts/virtual_link.py): captured Remote frame, delta/target/dirty and G move-commit witness with disclosed prior-record and arm-state seeds. It is not a demonstrated cold-boot-to-physical-move chain or, by itself, a flash-save witness. |
| E4 | [Trigger investigation](trigger-input.md): mode selection, thresholds, gate consumers, bounded replay and symbolic guards. Its exhaustive/negative language is search- and model-relative, not a universal hardware proof. |
| E5 | [Configured startup](feather-ready-resumed.md) and E1: setup gate, MC4, operational loop and 868 version reply under tick/radio/RX assumptions. Distinguish configured application operation from vendor READY and USB responsiveness. |
| E6 | [Motor setup/unlock](motor-subsystem-unlock.md), [UI/command map](../ui/action-command-map.md), [protocol pipeline](protocol-pipeline.md): producers, runtime arrays and packets. Some motor-consumer descriptions are superseded by E7. |
| E7 | [TMC interface reconciliation](../replacement/tmc5160-interface-reconciliation.md), current [apfw2 interface contract](../replacement/tmc5160-apfw2-contract.md) and [reference artifacts](../../research/generated/tmc5160-interface-contract.json): current/microstep fields have serial-driver consumers. Legacy “display-only” and “no serial interface” conclusions are not a planning baseline. Electrical validity and safe current remain distinct. |
| E8 | [Remote-to-motor causal trace](remote-to-motor-causal-trace.md) and [APTrace assessment](remote-to-motor-aptrace-assessment.md): separate command-state and ISR/STEP segments, unresolved natural activation and STOP/RF-loss joins. |
| E9 | [This pass's targeted outputs](../../research/generated/configuration-planning-2026-10-20/) and [manifest](../../research/generated/configuration-planning-2026-10-20/manifest.json): exact boot pointer destinations, A/X/D references, radio consumer and trigger-selector instructions. AutoPilot868 only. |

E1 pins original hashes: AutoPilot868
`6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3`,
AutoPilot915 `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920`.
Most detailed behavioral dossiers concern 868. Equal save/helper and MC handler
ranges plus matching default startups do not establish complete 915 equivalence.

## What is established, and what it does not establish

| State / relationship | Established findings | Meaningful remaining gap / apfw2 relevance |
|---|---|---|
| Persistent container | Internal flash `[0x12000,0x13001)`: 4096 payload bytes plus provisioning byte; staging at `0x20003145`. Zero provisioning triggers FF fallback. Differing writes mark dirty; a later save programs flash. E1/E2 demonstrate the distinction between staging and durability. | Not a complete validated/versioned schema. FF validity bytes can look truthy. apfw2 needs an explicit validity/default policy if it stores equivalent concepts, not necessarily this format. |
| Startup/readiness | Original packaged zeros work with the modeled PA22/radio baseline and a normal-format MC4; both variants enter actual loop `0x93fc`. Stored D is not necessary for these tested starts. | Which nondefault/invalid records alter normalization, reference state or later acceptance? No vendor READY oracle, physical start or USB enumeration is thereby established. MC4 is external session input, not recovered motor setup from the blob. |
| Four motor channel structures | RAM `0x20001b40 + channel*0x120`, payload logical offsets 500..1651. Record stride `0x48`; delta `+0`, computed target `+0xc`, start/target `+0x10`, validity `+0x44` appear in known paths. Loader, resync and writeback are real. | Bounds, all field meanings, mode-zero special treatment, signed/scaled units, stale-reference handling and which fields are authoritative versus derived. These affect programmed moves, not merely storage compatibility. Do not assume every field is a tunable motor parameter or a saved absolute physical position. |
| Stored targets → motion request | E3's mode-98 plus witness computes delta/target 500, marks dirty, then G reaches a move-commit argument of 500. Interactive plus modes 0/20 and bulk mode 98 have different consequences. | Modeled commit is not timed STEP/DIR or motor rotation. Dirty is not proof that this plus record reached flash. Safe STOP/activation, reference validity and realistic Remote resync remain unresolved joins. |
| Runtime motor setup | MC4 parses four fields per channel into arrays `0x2000006c`, `0x200000dc`, `0x200000f0`, `0x20000138`, and clears setup flag `0x20000060`. Tested handlers cause no additional config-setter calls or flash writes. | Desired values, serialized driver requests and electrically active state are different. E7 already shows current/microstep consumers: do not infer hardware irrelevance from “display refresh” names. When changed MC values take effect still warrants a focused check if legacy updates are required. |
| Trigger state | PA02 chooses analog/digital mode at startup; PB05 is the trigger input. X's stored offset `0x33` loads `0x20000194`, consumed at `0x8e7e`; known preset bands are [200,580] and [250,750] in raw sample units. E4 also identifies filter/latch and reporting/acceptance gates. | X is a preset selector, not evidence of analog/digital mode selection. Stored offset 400 loads `0x20001b38`, which participates in trigger acceptance (`0x7b`). Reconcile these gates with program validity/arming before choosing replacement semantics. Do not inherit the first-sample-latch anomaly as a requirement. |
| A | Offset `0x1a`, boot-valid range20..25 with fallback20, maps to `0x20000069`. The [completed A package](a-radio-reconfiguration.md) establishes displayed channels1–6, `base+(A−19)*300000` Hz, common modem requests and Remote staging→five sends→local retune. | Packet defaults, interrupted/lost retune and paired durability remain open. Remote915's setup override is resolved; its stored19 lower-bound mismatch is demonstrated. Requested RF settings are not physical communication or device calibration. |
| X | Handler changes runtime selector and stages offset `0x33`; boot defaults invalid selector to 1. E9 confirms shared boot/command destination and trigger read; E4 supplies preset interpretation. | End-to-end command → chosen band → accept/status → reset outcome has not been established by the D round trip. Physical threshold voltage and sensible debounce are separate product/hardware questions. |
| D | u32 at logical `0x15..0x18`, DE marker at `0x19`; runtime `0x200029d4`. Proven modeled save/reload. The [D result](d-serial-number-and-compatibility.md) traces unchanged field9→Remote0x20001078→six-digit SN display. **The earlier D÷10 inference was wrong:** field1 divides a different value at0x200000ec. | No control consumer or necessary operational persistence established in the bounded chain. Keep the report slot; optional stable/provisioned serial support is a product choice. Specific native UI/provisioning writer, serial allocation and external-client requirements remain open. |
| Factory/identity | Separate calibration words and silicon identity are read outside the app blob. E1 distinguishes them from command-controlled fields. | Real values and physical necessity were not measured. Preserve invariants; there is no justification to emulate or clone per-unit factory rows in a Noxon-style settings store. |

State ownership also crosses the radio boundary. E3 identifies Remote-local
program records, boot/reconnect bulk-push and a distinct periodic push. Bulk
plus requires a separate “has programmed data” flag; a fresh Remote boot is
not proof that every saved program will be resent. MC4 following the successful
S/P handshake does not imply that all target records were transferred. Treat
“Remote is authoritative and AutoPilot is only a reconstructible cache” as a
hypothesis until the selected workflow's producers, gates and reset behavior
are joined. Replacing the AutoPilot's storage need not require duplicating
Remote storage, but that decision cannot follow from MC4 startup alone.

The boot PA22 input/save-housekeeping path is separate from PA02 mode selection
and PB05 trigger sampling. Holding PA22 indefinitely can save/halt; that is a
startup-fixture hazard, not evidence that X controls power-down or that a
trigger event necessarily persists state.

## Priority order and bounded investigation packages

Priority is conditional on the replacement feature: retaining the existing
Remote, automatic recorded moves and the trigger raises compatibility work;
a deliberately different host protocol or manual-only first milestone can defer
much of it. This is a proposed sequence, not a new product-scope commitment.
Each item should be a separate APTrace question with its own bounds and report.

### 1. Motor state ownership and reference-frame semantics — highest value

**Question:** what is the minimal semantic record needed for a programmed move,
and which values must be re-derived after reset or reconnection?

Reuse E2/E3's known producer/loader/resync/G paths rather than rediscover plus.
For the selected workflow, identify whether the Remote, AutoPilot, or an
external host owns the durable program and what actually causes it to resend.
Start with one channel and two distinguishable records: trace payload → live
record → mode selection → resync → computed target → move-commit arguments.
Cover mode zero versus one selected nonzero mode, a negative delta, invalid
validity data and a second channel only to check stride/isolation. Record
range/units as unknown until the Remote producer/conversion and consumer agree.
Stop at original move-commit entry or state preparation; do not demand a timed
motor trace to answer record semantics.

**Deliverable / exit:** a field table with source, legal index, signedness,
transform, validation, consumer and lifetime; a transition table for cold start,
G/config reload, plus and resync; explicit unresolved fields. Distinguish saved
relative program content from live position and derived absolute targets.
No need to name every byte of all four channels before this first result.

**Why apfw2:** wrong reference ownership can make correctly parsed stored data
request the wrong movement. Reproducing the full legacy blob is less valuable
than deciding what counts as a valid position/program after reset.

### 2. Session configuration versus driver-applied state — high value

Use E6's MC4 frame/arrays and E7's current/microstep traces as the baseline.
Trace one changed MC parameter through its caller to the existing serial setter
or rate/table consumer; distinguish setup entry from a later MC update and
any timestamp/display-refresh gate. Use captured native datagrams as software
observations, not physical readback. Include desired-versus-active state after
MCU/driver reset. Do not repeat the bus/pin/register discovery already in E7.

**Exit:** four-field ownership/unit/application table and the minimal MC4/setup
session state needed by the retained Remote workflow, with validation and
reset/update rules. Identify which settings are reapplied versus stored.
**Why apfw2:** a “display” path may apply current/microsteps. Conversely,
legacy nominal current and temporary override values are not safe defaults;
physical current, sense network and containment remain outside this analysis.

### 3. X, trigger program-validity and acceptance — high if trigger is retained

Close the shortest stored-to-behavior chain first: source command → selector
`+0x33` → `0x20000194` → threshold-band branch. Then connect offset 400's
`0x7b` gate and per-record validity to accept/reload behavior. Keep PA02 input
mode, X preset, TR reporting and motion-arm state in separate columns.

Propose differential replays using two valid selectors and raw samples just
inside/outside each known band, then one invalid selector on fresh startup.
Control the first-sample latch explicitly and compare reporting-on versus
acceptance-enabled conditions; otherwise a constant ADC result could be
misread as an X effect. Observe selected branch, status and reload/arm writes;
there is no need to energize a motor. Reuse the existing guard proofs.

**Exit:** command/reset/threshold/acceptance table and explicit intended
replacement requirements for sampling, debounce and arming. E4's no-motion
observations must not be generalized into a safe physical trigger guarantee.

### 4. A and communications reconfiguration — high for legacy RF compatibility

**Bounded result available:** [A radio reconfiguration](a-radio-reconfiguration.md).
Reuse its selector/frequency table and native Remote915 base override. Do not
repeat discovery or assume an acknowledged transition; prioritize only missing
packet defaults and a selected loss/reset recovery sequence if legacy RF is retained.

Follow the already identified init argument into the radio routine and the
Remote A producer/peer receiver. Compare the lowest/highest valid selector and
invalid input under a disclosed radio fixture; inspect code-level frequency/
register requests, return/failure paths, and reinitialization of session state.
Verify save/reload separately from immediate radio changes. Compare 915 only
at variant-sensitive base-frequency/callee boundaries after the 868 meaning
is clear; do not assume all radio behavior matches because MC/save code does.

**Exit:** selector-to-requested-radio-configuration table, units/provenance,
peer coordination and reset/error behavior. RF emission, usable link and
regulatory/physical suitability require separate evidence. If apfw2 will use a
new transport, retain the discovered contract as a compatibility note and defer
legacy A emulation.

### 5. D meaning and reporting — medium, deliberately time-boxed

**Bounded result available:** [D serial-number/compatibility contract](d-serial-number-and-compatibility.md).
The product label and unscaled field9 mapping are established; the normal Remote
UI writer is not. No new control-setting requirement or automatic durability
investigation follows. The first-field hypothesis below is corrected accordingly.

The save/restart proof is already enough. Inspect the exact Remote sender/UI
origin and the ninth field parsed from the `0x8c70` response. Correlate two
representative values with unchanged decimal reporting; keep wire
numbers, user units and storage units separate. Search additional consumer
paths only when a concrete use or ambiguity warrants it.

**Exit:** either a named, evidence-linked parameter and compatibility need,
or “round-tripped/reporting value with unresolved product meaning.” Escalate
only if a consumer affects movement, trigger, link or a retained user workflow.
Do not build a D-specific replacement setting merely because its persistence
has the strongest demonstration.

### 6. Durability/default contracts for the selected features — medium

The [bring-up Pass1](autopilot-bring-up-pass1.md) now revalidates selected
checkpoint/fresh-restart witnesses with the corrected memory-hook backend,
and integrates default staging, a later default checkpoint, unchanged dirty,
selected invalid fields and marker validation into the timeline. Reuse those
artifacts rather than starting another broad configuration investigation.
Other historical hooked paths are not thereby recertified. Remaining questions
are selected recovery cut points and physical durability boundaries below.

After selecting meaningful fields, make a write → dirty → checkpoint → durable
state → reset matrix for those fields, not the whole blob. E2's save sites
include PA22 housekeeping and channel-0 completion; distinguish them from
ordinary staging. Check repeated save/dirty behavior and invalid provisioning
only where it changes the intended state contract. Reuse exact-byte carry
rather than changing an on-disk firmware image.

**Exit:** intentional reset/reconfigure behavior and which retained feature,
if any, needs persistence in apfw2. Do not reproduce unchanged dirty flags,
repeated flash wear, undocumented markers or channel asymmetry without a
behavioral requirement. Atomicity/retention/power-loss safety are not established
by flat-memory flash writes and require other evidence.

## Work to defer, and boundaries that remain important

Low return for replacement firmware: exhaustive naming of unused blob bytes;
byte-compatible migration after intentional reset was accepted; replaying the
settled D round trip; redesigning SPI discovery; proving every historical
“dead” UI command; cloning factory identity; matching every legacy chopper
word, packet quirk or sample-latch bug. Revisit only when a retained workflow
or a concrete counterexample depends on them.

Do **not** defer explicit STOP/RF-loss/reset behavior merely because it is not
persistent configuration. E8's causal joins remain open. A replacement can
have independently specified behavior without inheriting an unproven legacy
silence-to-stop assumption. The present plan is not a substitute for existing
motor/physical/recovery gates, and adds no motor-operation authorization.

## What current APTrace can establish

| Method / current capability | Realistic use here | Evidence limit / response to a gap |
|---|---|---|
| Persistent Ghidra project, native disassembly/xrefs and census | Field addresses, direct consumers, branch structure, producer/consumer hypotheses and comparison of bounded variant regions. | Heuristic function boundaries, thunks/computed addresses and aliasing can hide consumers. Failed searches do not prove unused fields. Use disassembly plus a concrete witness at the disputed join. |
| Ghidra p-code forward use | Trace a selected instruction-defined register value within its function and identify escape into a call/store. | It is not whole-program memory/struct taint or backward memory provenance. Planner exposure is experimental because value-flow claim admission is incomplete; use explicit opt-in/scratch evidence only if needed. See [capability documentation](../../../../docs/tooling/pcode-forward-use.md). No new dataflow implementation is proposed. |
| Direct Unicorn CLI and existing virtual-link scenarios | Original parser/state transitions, selected inputs, function arguments, program requests, memory writes and exact-byte flash-state carry across fresh startup. | Tick/ID/RX/MMIO seeds are assumptions; a field seed tests a consumer, not its natural producer. Some scenarios bypass setup/arm gates. Preserve error/completion/watch-cap distinctions and exact command bytes. |
| Existing call/field observation | Capture values at an appropriate registered scenario's function entry and join them to watched fields. | Scenario applicability is not automatic; unrelated protocol fixtures have previously failed without useful diagnostics. Prefer a relevant existing scenario or the supported raw CLI, not a new hidden harness. |
| Macaw/Crucible bounded analysis | A small, already isolated validation or branch question after static/concrete evidence identifies the bound. | Opaque calls, discovery gaps, readonly flash and timeouts restrict effects. No all-path schema proof or absence from empty timed-out summaries. Do not start with symbolic execution of the whole dispatcher. |
| Existing controller and ledger | Bounded discovery, structured findings and provenance. | Prior runs stopped at budgets or drifted to peripheral inventories; the controller is not an autonomous multi-image causal proof engine. New semantic claims require valid admission; a documentary table is not a VERIFIED result. |
| Hardware-faithful movement/retention | No current result here certifies naturally timed STEP/DIR, actual flash erasure, power loss, RF/USB delivery or electrical safety. | These are model/evidence boundaries, not missing setting names. Follow existing hardware/recovery plans; develop a new capability only in a separately authorized task if a specific software question requires it. |

## Execution and next handoff

This pass reviewed E1–E8, including the prior native snapshots, corrected
persistence interpretation and newer driver contract. It used E9's seven
read-only public Ghidra queries to resolve priorities; no new research-controller
run, solver run, concrete replay, ledger mutation or framework test was needed.
Ghidra reused the fresh AutoPilot868 project; Java configuration is recorded in
the manifest. X references connect the boot/command destination to the trigger
reader; A references connect its boot/command value to nontrivial radio-init
arithmetic; D references identify the reporting lead. These are structural
relationships, not fresh end-to-end command demonstrations.

The first follow-up should take package 1, paired with package 2's existing
parameter/driver contract review, and return a small semantic field/lifetime
matrix before further expansion. Packages 3–5 can then proceed independently
when their product feature is retained. Each handoff should retain input hash,
field/index, original producer, transformation/consumer, tested initial state,
expected discriminating output, actual output, bounds and remaining unknowns.
Stop a package when its exit artifact is sufficient for an explicit apfw2
requirement decision; do not expand merely to eliminate every unknown offset.

No gate grade changes, configuration behavior or apfw2 implementation are
proposed as accomplished by this assessment.
