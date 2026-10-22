# Motor programs, references and applied configuration

2026-10-20; inspected repository `618dc2bba63e7b17237327fb453e7ebdcd1194d2`.
**Result: a bounded semantic model is established; whole-product ownership,
physical references and driver state remain partially unresolved.**

Noxon's state is distributed. The Remote authors/encodes programmed segments;
the AutoPilot maintains a local flash-backed execution copy and its own live
software reference. Targets are derived in that reference frame. MC4 supplies
a separate set of session motor parameters; acceptance does not guarantee they
have reached the driver. Neither a saved target nor a software counter proves
the motor's physical position.

This closes the first package in the [investigation plan](configuration-behavior-investigation-plan.md)
with relevant existing MC4/driver evidence. It does not implement apfw2, analyze
X/A/D, demonstrate physical movement, or change release grades. A/B/C/D remain
PARTIAL; E/F BLOCKED; production NO-GO.

## Evidence and confidence

Continuation: [bring-up Pass2](autopilot-bring-up-pass2.md) closes a selected
continuous original AutoPilot reset→Remote-built program→MC4→nonduplicate-G→
request chain, with no AP program/reference/validity/target/arm seeds. Original
G dispatch supplies arm2; the main loop requests `(0,30,500,8119)` at0x6fd8.
No-G and duplicate-sequence controls do not request; trigger-HIGH G does.
TC0 READSYNC completion is an explicit MMIO assumption. Full Remote UI/RF/ACK,
physical reference, trajectory validity and actual driver/motor state remain
outside that witness. The older composed helper runs retain their own scope.

“Demonstrated” below means the stated original-code execution in a disclosed
model, or the specifically identified native instruction relationship. It is
not a new admitted/VERIFIED claim. Interpretations and missing joins are named
explicitly. No new claim-state changes were made.

| ID | Evidence |
|---|---|
| N1 | [New native snapshots, source review and replay commands](../../research/generated/motor-state-semantics-2026-10-20/), [observations/checks](../../research/generated/motor-state-semantics-2026-10-20/observations.json), [provenance](../../research/generated/motor-state-semantics-2026-10-20/manifest.json). Twenty direct CLI runs: isolated helpers, selection/request phases, three startup/MC4 runs, and Remote builder/count controls. |
| R1 | [Persistence release assessment](persistent-state-release-assessment.md), [motor persistence](motor-config-persistence.md): actual 868 command/save/fresh-reset readback, staged versus durable state, corrected loader/resync/save interpretation; both packaged variants start under the prior modeled baseline. |
| R2 | [Auto mode/plus](auto-mode-and-plus-command.md), [existing virtual-link scenario](../../scripts/virtual_link.py): Remote UI/transfer paths, one-record plus→target→G commit witness with explicit seeds. These do not establish an unconditional fresh-boot download or RF execution. |
| R3 | [Motor unlock/MC4](motor-subsystem-unlock.md), [UI/command map](../ui/action-command-map.md): packet fields, runtime arrays, setup gate and Remote producers. Historical “display-only/pure unlock” wording is superseded by R4 and N1. |
| R4 | [TMC interface reconciliation](../replacement/tmc5160-interface-reconciliation.md), [current replacement contract](../replacement/tmc5160-apfw2-contract.md), [native boot/config traces](../../research/runs/tmc5160-interface-reconciliation/): serial setters, temporary current input400, microstep conversion and initialization. Raw requests are not electrical confirmation. |
| R5 | [Remote-to-motor causal trace](remote-to-motor-causal-trace.md): separate receiver/state and timer/ISR/STEP segments, unresolved natural activation, physical position and STOP/RF-loss edges. |

New runs use only original 868 images: AutoPilot SHA-256
`6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3`,
Remote SHA-256 `cf74cf03b375eaed1f48ff2ab0852a2cbbca4ece1ea8eb0989ec938af5e431bc`.
No new 915 semantic equivalence is asserted.

## Ownership: what is authoritative for which decision?

| Decision/state | Owner supported by evidence | Transfer/reconstruction and limits |
|---|---|---|
| Editing and encoding a programmed segment | Remote UI/program RAM, with Remote-local persistent records described in R2. Its real `0x49c4` builder reads local deltas/parameters. | N1 captures a two-record frame containing +500 and −200. The fixture represents prior recorded RAM data; it does not freshly demonstrate UI editing or Remote flash retention. |
| Local execution copy | AutoPilot staged payload and flash blob at `[0x12000,0x13001)`. | R1 establishes local save/readback. N1 full reset reads a provisioned motor-record fixture without receiving a new plus packet. Only MC4 is delivered. AutoPilot is therefore not merely a stateless Remote cache. |
| Coordinate reference and resolved target | AutoPilot software live-position array and resync/chain helpers. | Remote-authored deltas can be reused, while AutoPilot re-derives starts/endpoints. Saving derived target bytes does not make those bytes absolute physical truth across reset. |
| Desired motor setup | Remote MC/MC4 input, with AutoPilot runtime arrays/defaults. | MC4 is not a motor-program download or evidence that earlier plus transfers completed. No persistence of MC4 values is demonstrated by the examined paths. |
| Settings actually requested from a driver | AutoPilot serial configuration path, conditional on initialization/update flow. | Timestamp-gated calls and temporary boot substitution can differ from current desired arrays. Actual active electrical state needs validated readback/reset evidence. |

There is **no demonstrated global authority or reconciliation protocol** for
these copies. The examined transfer paths do not establish program versioning,
conflict arbitration, atomic multi-channel replacement or checksum-based
agreement after reset. Accepted packets change local state, subject to their
mode/sequence/confirmation guards; it is not an unrestricted “last packet wins”
contract. Exclusive ownership of every field remains unknown.

R2 identifies two different transfers: `0xc440`'s boot/reconnect exchange can
send mode98 bulk plus for channels with nonzero local data, then MC4; the
`0xb6f0` periodic sibling has different gates and does not send MC4. The former
requires a separate programmed-data/session flag. Record presence alone does
not imply that a cold Remote boot sends the program. The sibling's scheduling
conditions must not be substituted for the former's gates.

Fresh `remote-ownership.txt` also narrows an older statement that any clean P
response alone guarantees the transfer tail. In `0xc440`, the invocation mode
matters: the normal mode-zero path includes another configuration-response
parse/validation that can clear the success flag before the tail; a nonzero
invocation can skip that section. The final tail tests that flag and the
program-data gate. This is a **static qualification**, not a new end-to-end
handshake execution. The successful exchange must be specified by path and
validated responses, not just a P prefix. Decoding those unrelated response
settings is outside this package.

## Concise semantic field/lifetime matrix

Offsets are within a channel record unless stated otherwise. A channel has
`0x120` bytes; helper record stride is `0x48`. This does not prove that all four
stride slots are legal user records: the examined wire writer loops over three
entries, and the Remote count helper tests three contiguous delta slots.

| Field/state | Demonstrated role and lifetime | apfw2-oriented assessment |
|---|---|---|
| `+0x00`, signed 32-bit delta | Program displacement input. N1 preserves +500/−200 through chain and resync. Bulk Remote builder serializes both signed values. | Maintain an explicitly typed displacement and declared unit/conversion. Physical units and all wire-unit conversions are not resolved here. |
| `+0x10`, start/reference | Record0 start is an existing base for `0x4ca8`; `0x4b24` replaces it with current software position. Following record starts receive preceding endpoints. | Derived execution reference, not independent per-record physical calibration. Persisting it must not imply reference validity after reset. |
| `+0x0c`, computed endpoint | `endpoint = start + delta`; subsequent records chain from that endpoint. G's nonzero mode selects this field. | Reconstructible from validated program and a valid reference. Retaining bytes is optional; retaining correct semantics is necessary for recorded moves. Overflow behavior is not qualified. |
| `+0x3c`, helper loop-bound byte | In these helpers it acts as an inclusive last index: fixture1 makes two records participate. Loader contains a range-normalization check. | Origin/complete legal bounds remain unresolved. Do not equate it to wire record count or copy its permissive bounds as validation. |
| `+0x44`, validity | G selection tests nonzero. Zero in the selected second record falls back to current position, producing distance0 in N1. | Need explicit validity/schema checks; a truthy byte is not data-integrity or position-validity proof. R1's blank FF fallback warns against treating every nonzero value as provisioned. |
| Other record fields | Wire writers derive timing/profile data and clear unused entries. Native output is retained, but field units/bounds are not fully decoded. | Do not port raw coefficients or invent units. Resolve only fields required by the selected trajectory interface. |
| Live position `0x20002064[ch]` | Volatile software position; N1 reset run ends at zero, helper tests use disclosed current positions. R5 separately traces ISR updates. | Maintain software position and an independent reference-valid flag. No encoder, homing success or physical zero is demonstrated by a zero counter. |
| Resync request/latch `0x20000134[ch]` | When set and the loader's other guard permits it, loader resyncs, clears the flag and writes records back to staging. With flag0 it reloads without rebasing. Runtime paths can request resync again. | This is not just a power-on flag. Represent explicit invalidation/re-reference events; do not silently rebase on every read. |
| Staged payload / dirty / flash | `0x43f0` copies records to staging and differing bytes dirty it. Separate `0x97a4` checkpoint erases/programs. | Distinguish edited, staged, durable and reconstructible state. N1 does not newly prove these representative records were physically or emulated-flash saved; R1 proves the mechanism with another field. |
| G target `0x2000201c[ch]`, phase/arm `0x200025e0/e1` | Mode-selected target is staged, then the next state-machine phase passes target−current to `0x6fd8`. Request arming is separate from record validity. | Separate program validity, reference validity, request acceptance and execution state; do not compress them into one READY/valid bit. |
| MC desired arrays | `0x2000006c`: field1×80; `0x200000dc`: field2 raw; `0x200000f0`: field3 with1→0; `0x20000138`: field4 raw/profile-table selection. Runtime session configuration. | Validate typed desired settings and their dependencies. These are not the flash-backed target structures. |
| Driver configuration/shadows | Setters consume desired current/microstep inputs, but only when called. Boot also temporarily substitutes current input400. | Track desired, last-requested and confirmed/unknown active configuration separately. Reset/failure invalidates active-state assumptions. |

N1 Remote count controls return2 for `[500,−200,0]`, 0 for a zero first delta
even with a later nonzero delta, and1 for `[500,0,−200]`. That is a contiguous
nonzero-prefix convention in this helper, **not** proof that a zero-length
record is universally invalid in the product. Do not adopt zero delta as a
replacement schema terminator without an explicit requirement.

## Demonstrated transitions and discriminating experiments

All arithmetic below is in the firmware's internal integer units. Fixtures
have two representative records; other profile fields are zero and are not
claimed to describe a safe or complete physical trajectory.

| Transition / native artifact | Input and observed result | What it distinguishes |
|---|---|---|
| `chain.json`, `0x4ca8` | Existing first start1000; deltas +500/−200; current10000. Results: starts1000/1500, endpoints1500/1300. | Chaining alone does not use current position to replace the first start. |
| `resync.json`, `0x4b24` | Same records/current. Results: starts10000/10500, endpoints10500/10300. | Resync re-anchors the program then chains; it does not change the deltas. |
| `resync-channel1.json` | Same vector on logical channel1. Four writes stay inside that channel; channel0 untouched. | A bounded stride/isolation check, not a physical connector/channel mapping. |
| `saved-record-reset-startup.json` | A synthetic provisioned flash blob embeds the prior native resync output at payload offset500, including starts10000/10500 and endpoints10500/10300. Full original reset + MC4 reaches `0x93fc`; current0, starts0/500, endpoints500/300. | Saved deltas survive the read; prior derived coordinates are replaced under startup resync. This is fresh startup from simulated data, not measured power-cycle retention or a physical reference. |
| `reload-established-reference.json` | Load the reset-result records from an already-loaded staging fixture; current600, resync flag0. Starts0/500 and endpoints500/300 remain. | Later reload need not follow the current position. |
| `reload-resync-enabled.json` | Same fixture/current, flag1. Calls resync and writeback, clears flag, results starts600/1100, endpoints1100/900. | Explicit resync changes the frame and stages the result; not automatic on every reload. |

The plus tail's native instructions show that accepted mode98 invokes resync
on all four channels, then the `mode > 50` branch chains and stages all four.
Interactive modes0/20 do not take that compute/stage branch. R2 already
provides their producer/receiver context; these are not interchangeable modes.
A transfer for one channel can therefore have wider resync consequences at the
finalization boundary. Multi-channel transaction/ack completeness is not proven
by the channel0 examples here.

### G selection through the original move-request boundary

The G tests carry the exact records from `resync.json`. Current software
position is10200. First call executes original `0x7e2c` selection to its real
return; a second fresh run carries its produced target/phase/arm and stops at
`0x6fd8` **before the commit routine executes**. Remaining RAM is a disclosed
zero/idle fixture; display-string helpers are stubbed and the rate table is
zero. No natural scheduler, IRQ delivery or full producer-to-commit continuity
is asserted for this composed pair.

| Selector | Selected target | Captured `(channel, const, distance, rate)` at commit entry |
|---|---:|---|
| Mode0 | First start10000 | `(0,30,−200,0)` |
| Mode1 | Record0 endpoint10500 | `(0,30,300,0)` |
| Mode2 | Record1 endpoint10300 | `(0,30,100,0)` |
| Mode2, selected validity0 | Current10200 | `(0,30,0,0)` |

This overturns “a negative segment delta is necessarily the next negative
motor request”: record1 delta−200 can produce a +100 request from current10200.
The request is target−current, and mode0 returns to the start reference rather
than selecting another stored displacement. The zero-validity path prepares
a zero-distance call; this test does not execute or certify the callee's
physical no-motion behavior. R2's older witness separately exercises the
callee's >8 threshold under its own fixture.

## MC4, application timing and reset

N1 reuses the exact established startup/RX baseline, changing only channel0's
first MC field to30 and third to16. Four fields per channel are still delivered
as normal MC4; other channels retain the original example parameters. Watches
capture original entry arguments at `0xae60` and `0xb070`, not invented SPI
responses. R4 supplies the existing link from these setters to serialized
requests and register interpretations.

| Phase | Demonstrated software observation |
|---|---|
| Reset/initialization, before MC4 | All four current-setter calls receive400; all four microstep calls receive16. R4's `0x7770` temporarily substitutes current400 then restores desired RAM. Startup also makes GPIO/pulse requests; it is not a physically inert reset recipe. |
| MC4 with an old application timestamp (`mc4-driver-update.json`) | Desired channel0 current becomes2400 (=30×80), microstep value16. Setter entries receive2400/16 for its driver object; other channels receive1600/0. Setup flag clears and loop entry is reached. Input1 is remapped to microstep value0; this is not a claim that 0 means “unset.” R4's helper maps it to its full-step encoding. |
| Same MC4 with recent-config timestamps (`mc4-recent-config.json`) | Desired arrays have the same2400/16 values, setup flag still clears, but only the four boot setter calls400/16 occur. No post-MC setters are observed before loop entry. The timestamp condition is a disclosed seeded recent-application fixture. |

Native `0x7b4e..0x7b62` compares elapsed ticks against300 and skips `0x7514`
when elapsed≤300. This function's name “LCD refresh” does not describe all its
side effects. MC4 acceptance is therefore **not an apply acknowledgement**.
The recent-timestamp test does not prove permanent mismatch: another later
configuration path or repeated packet may apply settings. No such eventual
application was established in that bounded run.

The second MC field is read by initialization helper `0x6190`; its one resolved
direct caller is setup. The fourth feeds profile/table selection in motion
consumers. Complete dynamic late-update dependencies for these two fields are
not resolved here; do not assert that they are unused or already reapplied.
The desired first-field transformation and setter inputs are demonstrated;
measured current, resistor calibration and electrical safety are not.

A driver/MCU reset can invalidate applied settings independently of program
storage or desired arrays. The required replacement policy is to initialize
and, under a validated inhibit/configuration process, reapply or validate all
settings needed for operation: current/hold behavior, microstep/scaling,
required chopper/mode/direction and fault/reset state per R4. This is an
engineering recommendation, not proof of Noxon's complete reset recovery or
an instruction to replay its boot writes/pulses. Software position/reference
and program/MC4 state require their own reset decisions.

## Implications for apfw2

| Maintain / establish | Reconstruct when appropriate | Do not carry forward without a requirement |
|---|---|---|
| Typed program deltas and required trajectory parameters, explicit record counts/bounds/validity, and declared wire/internal units. Decide whether the retained Remote or another host owns editing and durable program versions. | Endpoints from validated deltas plus an explicitly established reference; selected target and target−current request. | Whole Noxon blob, raw derived coefficients, zero-delta count sentinels or truthy FF validity. |
| Software position, reference validity and the event that establishes/re-establishes the frame. Distinguish estimated/measured state and intended reference. | Rebase on an explicit authorized state transition, not merely on every read or reconnect. | Treating reset-to-zero as demonstrated physical homing, or restoring old absolute targets blindly. |
| Session setup completeness, program transfer completion and arming/STOP/reset state as separate concepts. | Reconfigure session parameters from the chosen host/default contract; restore programs only through a defined transfer/reset policy. | Assuming MC4 means programs arrived, records imply a resend, or a successful handshake implies every channel was replaced atomically. |
| Desired/last-requested/confirmed-or-unknown driver state and dirty/dependency tracking. | Reapply/validate required configuration after reset/failure before relying on it. | The300-tick display-coupled apply gate, temporary400 input, raw current numbers as measured mA, or every legacy initialization word/pulse. |
| A durability requirement only for features that actually need retained local state. | Defaults plus normal external configuration under the accepted intentional-reset contract. | Mandatory Noxon-byte-compatible migration, persistence of every RAM cache, repeated-save quirks or channel asymmetry without a product need. |

These are requirements/options for an apfw2 design decision, not an implemented
configuration model. A manual-only initial milestone need not reproduce the
entire Auto Mode program machinery. Existing Remote compatibility would need
the relevant mode, resend and parameter-application contract or a deliberate
incompatibility decision. Stop/RF-loss and physical protection/recovery remain
independent requirements; this report does not close them.

## Unresolved questions and smallest next work

1. **Program identity and synchronization.** Choose the retained workflow's
   editing/durability authority, then observe one real UI-authored program
   through the actual successful transfer/ack path, including interruption and
   reconnect. Existing tooling can inspect/capture bounded producer/receiver
   state, but RF continuity and whole multi-channel commit remain unproven.
2. **Units and legal records.** Trace the selected Remote conversion branch,
   bound indices/count and required timing denominators; use two signed
   records, not a whole blob census. Test a range boundary only when it changes
   the proposed interface. Current math is internal integer arithmetic, not
   certified physical distance/speed/acceleration.
3. **Reference establishment.** Map a specific real input/request that raises
   the resync flag and determine when the product considers the physical frame
   valid. Existing static/concrete tools can follow that chosen software path;
   actual homing/reference correctness needs independent hardware/product
   evidence. Do not promote the zero reset counter into that answer.
4. **Late MC dependencies and apply completion.** Resolve the second/fourth
   field's changed-value consumers only if required by the retained setup
   workflow, and specify an explicit apply/validation policy. Noxon's timestamp
   behavior is a useful counterexample, not a recommended design.

The first package is complete to its stated bounded exit: semantic/lifetime
matrix, representative signed records, reset/reload/resync differences, mode
and invalidity effects, ownership qualification and apfw2 consequences. X/A/D,
exhaustive trajectory coefficients, full-motion simulation and physical work
are deliberately not started.

## APTrace execution and limitations

Existing public persistent Ghidra queries provided disassembly, function output
and caller anchors. Original native instructions anchor the resync/mode/apply
conditions; C output is heuristic interpretation, not an independent lifter.
The verified direct `tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py`
path supplied all new executions. Full-startup runs reuse the prior clocks,
SERCOM completion, tick, DWT stub, zero calibration placeholder, forced radio ID
and RX-ring injection; each command records these assumptions. Helpers and G
phase fixtures are explicitly not full startup. Original firmware files and
historical evidence remain unchanged.

No new harness, script-based instruction semantics, firmware patch, backend,
solver run, controller/ledger mutation or APTrace/apfw2 implementation was
introduced. Case artifact generation packs declared input fixtures and checks
recorded outputs; it does not replace an analysis engine. A metadata patch
attempt failed without changing its target and was corrected; no firmware run
failed or had an assertion suppressed.

APTrace currently supports these bounded value/state observations and explicit
carry. It does not establish interprocess continuity merely by copying selected
RAM, complete whole-program struct aliasing, natural timed motion, physical
NVM retention/atomicity, valid TMC response or end-to-end RF delivery. Existing
p-code forward use is intraprocedural, not a general memory/ownership proof;
experimental claim admission restrictions remain in force. No new VERIFIED
claim or global no-effect/absence conclusion is derived here. A specific gap
should lead to an explicit boundary or a separately authorized development
task, not a replacement analyzer.
