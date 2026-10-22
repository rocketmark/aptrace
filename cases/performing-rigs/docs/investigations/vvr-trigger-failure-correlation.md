# Physical trigger failures: VVR correlation and bounded firmware tests

2026-10-22. **Partial causal assessment.** The preserved reports establish physical
failures; APTrace establishes matching software mechanisms under disclosed MCU
inputs. Neither establishes the measured MCU waveform during a reported failure.
An acquired digital LOW can cause original profile initiation after the modeled
input returns HIGH. A Rev1-like analog fault band can cause initiation under X1
and remain inactive under X2. A held active level can initiate again after native
completion plus a supplied Remote W command, subject to the zero-position return
limitation below. Exact release correspondence remains unproven.

Primary evidence: [five original reports and provenance](../../research/validation/nathan-vvr/README.md).
New [execution packet](../../research/generated/vvr-trigger-correlation-2026-10-22/README.md)
preserves commands, native results and checks. This report does not close any
physical validation failure or change a release gate.

## Sources and firmware correspondence

| Report / primary PDF pages | Hardware and software actually identified | Observation relevant here |
|---|---|---|
| VVR-001 pp1–2,4–5 | Rev1; `Autopilot_firm29-06.rar`, build group2026-06-29; 915MHz bin flashed | Trigger selector and diagnostics introduced; field fault not reproduced on bench; Quick Configuration missing. |
| VVR-002 pp1–4 | “Current Production Hardware”; July2026 mitigation beta, no hash | Initial trigger misses recover after reconnection; stored moves approximately every30s after early reset, fade after approximately10min; absent after full power cycle. Do not silently upgrade its hardware description to a measured board identity. |
| VVR-003 pp1–5 | Rev1; `firm05-08`,915MHz; displayed AP V01R39 / Remote V01R42 | Inactive-supply fault in Relay Contact mode; X/mode dependence; no spontaneous30s pattern during this session. |
| VVR-004 pp1–5,8–9 | Rev2 silk52_P0_V01R04, two units; same reported release; Rev1 cross-check | ChainB repeated moves, M3; INFO0 on Rev2 Spark+ output; INFO-exit/UI-dependent eligibility; approximately74mV flickers every21–27s with **no motion** during quiet watch. Appendix summarizes Iker's September2 reply and polarity retests. |
| VVR-005 pp1–6 | Rev2, same silk/release; Rev1 compatibility cross-check | Swapped adapter fixes Spark+ output idle; supply connection still causes one move; settled3300mV quiet; dry-contact10/10; resistor deferred. |

APTrace possesses one four-image vendor package and its working copies, not a
hash-identified sequence of June/July/August releases. Image SHA-256 identities
are in [the inventory](../firmware/firmware-inventory.md) and new packet manifest.
The studied868 AutoPilot reports `V01R39` through native startup/version TX;
the915 image is separately identified, and new915 positive/control tests below
execute its own original instructions. Prior Target1 found byte-identical
filter/baseline/classifier/selection ranges across the two packaged variants.
**A common filename or displayed R39 is insufficient to identify `firm05-08`.**
No archive/hash chain links these files to Nathan's flash session; Remote R42
identity is not established by this investigation. Obtain the actual three
release archives or vendor SHA-256s before asserting release-specific fixes,
regressions or cross-release behavioral equivalence. The old inventory's
“Remote not yet analyzed” language is stale; extensive later Remote evidence
exists, but does not supply that missing release provenance.

The five reports are primary evidence. Separate recent correspondence, the
referenced `Iker-Trigger-Thresholds-2026-08.md`, capacitor explanation and500ms
pulse record are not included in the supplied PDFs. The September2 reply is
available as a **report author's summary** in VVR-004 p8, not the original email.
The user confirmed the separate correspondence is unavailable. The request's
500ms/capacitor descriptions remain user-supplied context. No
instructions inside historical reports authorize hardware operations or email.

## Reconciled firmware model and electrical boundary

Use the top-level corrections in [trigger failures](trigger-misfire-failure-modes.md),
[bring-up Pass1](autopilot-bring-up-pass1.md)/[Pass2](autopilot-bring-up-pass2.md),
[startup learning](startup-voltage-learning.md), [Target2](trigger-symbolic-reachability-target2.md)
and [Target3](motion-initiation-route-coverage.md). Historical zero-alpha/frozen
first-sample and “reload cannot initiate motion without G” conclusions do not
describe normal full-reset behavior. Alpha is0.05; a natural nonzero Remote-built
profile can start via the scheduled evaluator without G or phase arm.

Firmware samples PA02 once for analog1/digital2; PB05 is the recovered sense
input. Rev1's intermediate INFO values are consistent with analog acquisition;
Rev2's endpoint-only values/menu are consistent with the digital path. Reports
and software together support these interpretations, but do not measure PA02 or
PB05 on either physical revision. Do not identify mode solely from board name.

The recovered Remote display renders the T sample as `sample*3300/1023`
(`trigger-input.md`, T-status consumer0xfa10). Digital T substitutes0 or1023;
thus3300/0 can be **encoded GPIO observations**, not analog pin measurements.
Analog T carries filtered/cached integers. Conditional inverse conversions locate
VVR-003 standby1664–1670 around516–518 counts and fault1909–1958 around592–607;
contact1922–1990 around596–617. Those overlap above X1's upper580. They are
constraints on the displayed sample under this software contract, not a jack
transfer function or a recording of every acquisition. X2's inactive250–750
contains this range. X1 inactive200–580 and X2 inactive250–750 are inclusive;
either extreme outside is active. A mode selector is not evidence of electrical
source-type rejection.

VVR-003 p2 quotes Iker's approximately1850mV relay trip/1950 clean contact and
polarity-dependent voltage thresholds; these are vendor statements, not an exact
equation for our binary's integer580 boundary (approximately1871mV in INFO
units). VVR-004 also reports Rev1 fault values in **12/24 mode**, whereas VVR-003
reported that condition quiet in12/24 mode. Preserve that difference: wiring,
mode, transient history and exact software need reconciliation; do not force both
sessions into a single X1 explanation.

## Connection transient: observed original-firmware causality

New `digital-acquired-transient` replays the preserved powered-connection
witness byte-for-byte. A second run substitutes only the original915 image.
Both execute12,327,153 instructions with no native error, stopping at0x5fa6.
The RX ring receives the existing native Remote-built nonzero program
`+2,1,1,0,98,1,0,50,1000,500,0,0|`, followed by MC4. No AutoPilot record,
reference, arm, filter or eligibility cell is supplied artificially.

| Original boundary | Instruction index, both images | Observation |
|---|---:|---|
| `0x9228→digitalRead(0x39)` | before12,098,771 | Mode2, modeled PB05 LOW at acquisition. |
| `0x922c` |12,098,771 | Saved r0=0; modeled GPIO already HIGH (`0x410080a0=0x20`). |
| `0x8f98` |12,098,773 | Acceptance/reload reached with marker7b, channels0, idle9, TR0. |
| `0x5f8c` |12,327,006 | Channel0 rate initiation, after original reload/profile construction and scheduling. |
| `0x5810` |12,327,140 | Original timer-enable helper entered. |
| `0x5fa4` / stop`0x5fa6` |12,327,152 /153 | Original live1 store; TC0 CTRLA0x602; modeled GPIO remains HIGH. |

The acquisition-to-start gap is228,235 executed instructions, **not a measured
physical delay**. The command deliberately puts release between digitalRead and
its compare, at original PCs. It models a possible observation history, not a
measured capacitor discharge, pulse width or interrupt timing.

Existing paired controls remain consequential: `digital-idle`,
`digital-unsampled-transient`, `digital-setup-only-transient` do not start within
14M; `same-history-contact-control` is byte-identical to the positive. LOW is
not sufficient while shared eligibility is absent. Target2's actual-instruction
SMT provides feasible digital-gate anchors and excludes each bad guard in its
bounded pre-read region; it does not model GPIO acquisition symbolically or
prove guards remain true under every interrupt. The saved LOW is not re-read or
withdrawn because the physical/model input later releases.

Target3 follows timer initialization/period/enable and independently executes
STEP helper/IRQ/catch-up fragments. This continuous witness establishes timer
initiation, **not continuous timer counting, IRQ delivery, STEP edges or physical
movement**. A local STEP fragment is not substituted for a naturally delivered
interrupt here. The physical VVR move is observed by Nathan; APTrace has not
reproduced the physical device.

Analog history provides a separate conditional mechanism: existing normal-reset
`analog-startup-transient-tail` starts with raw225 already inactive while retained
filter11 accepts, then filter148 at initiation. Target1's paired interventions
attribute such behavior to filter history rather than separately stored startup
average/flag. This cannot be assigned to VVR-005's likely digital acquisition
without confirming physical mode. A brief raw event after analog baseline can
instead be attenuated: the existing one-acquisition225→900→225 control peaks259
and never initiates within14M. Filtering is neither uniformly harmful nor a
guarantee against connection events.

## Rev1-like fault-band comparison

New full-reset **915** executions change only X via the real `X2|` parser in the
negative control. Both acquire517 at startup then600 at setup return, retain the
same nonzero program/MC4, and preserve normal alpha0.05. These correspond to
approximately1668 and1935 INFO mV **if the recovered display contract applies**.
No source voltage or board waveform is generated by that calculation.

X1 accepts at12,360,987 with filtered581, starts0x5f8c at12,587,610 with593,
enables TC0 and reaches live1 at12,587,756. X2 has filtered600 and selector2,
but no acceptance/rate-start/live-store through14M. This reproduces a
configuration-sensitive **first initiation** consistent with VVR-003's fault
band; it does not yet reproduce successive physical moves or settle VVR-004's
different mode observation. The held history is hypothetical despite its
diagnostic values being constrained by the report.

## Completion and re-arm

The prior22M held run ended before natural time-based profile completion. New
65M `held-completion` continues unchanged input/profile/clock assumptions,
reducing code watchpoints only. At0x5fac the original stage table at0x200025e8
contains2,500,000;5,000,000;2,500,000;0. The function compares elapsed0xccdc
clock with each duration, advances stage0x200025e2, and resets timestamp
0x200030cc between stages. The10,000,000 duration sum is in the recovered
clock's units; instruction-paced fake ticks are not calibrated wall time.

Stage transitions occur at22,246,440;42,249,832;52,249,040 instructions. At
52,249,046 terminal0x6026 is reached;0x5958 at52,249,063 stops the channel;
0x6056 at52,249,088 follows the channel-clear store. No busy/position/idle cell
is forced. Final channel/live0, TC0 ENABLE clear, current stage3, input900.
The idle byte becomes2 (word0x1402), **not9**, phase arms remain0, and only one
acceptance/start occurs through65M. A held input plus this program and no later
Remote packet is therefore not sufficient for successive initiation.

Static instruction/decompile evidence identifies the next boundary: completion
sets idle1 and completed-channel flag0x20002014; phase service0x8e18 can advance
idle2. A separate phase3/all-live-and-duration-zero path writes idle9. Existing
native bare-W dispatch can arm the phase path; it is not interchangeable with
W1 (which can reload directly) or G. The phase service's phase2 return request
also depends on current software position. This position has not advanced in
the no-IRQ simulation, so zero-distance return behavior must not be mistaken for
a completed physical out-and-back move.

The packet also tests a real `W|` delivered at original completion0x6056 and
a matched input-release control. Both run60M instructions without error:

| Completion/session condition | Native transitions | Result |
|---|---|---|
| Active900 held; no later command (`held-completion`,65M) | Natural terminal stage, stop/live0, idle2 | One acceptance and timer initiation only; no complete re-arm. |
| Same active900 held; W after completion (`held-completion-w`,60M) | Complete52,249,088; W arm0x865a at52,264,274; return request0x6fd8 at52,279,609; idle9 store0x9088 at52,291,959; second acceptance0x8f98 at52,292,297 | Second rate start52,524,408; enable52,524,542; live store52,524,554. No input release/edge between starts. |
| Release raw to225 at first acceptance; same completion-timed W (`released-completion-w`,60M) | Natural completion52,246,833; W arm52,261,794; return request52,277,367; idle9 store52,289,719 | One acceptance/start only; final raw/filter225, idle9, channel/live0, phase3. Eligibility alone does not start with inactive input. |

These are natural original **AutoPilot** state transitions from reset and
parsed packets, with no forced busy/phase/idle values. The injected command is
`W|`, not W1 or G. Input release changes classification/work performed and
slightly shifts completion instruction indices; both controls reach the same
post-completion eligibility, so absence of a second request is not explained by
failure to complete or re-arm.

However, W is an explicit external session input, not proof of an automatically
transmitted Remote response. Current software position remains0 without STEP
progression, and both return requests have distance0. This makes native return
completion possible without claiming a physically completed out-and-back move.
The result establishes that **no repeated electrical transition is logically
required by the acceptance policy once this session re-arms**. It does not
establish that a held line alone repeats, the exact Remote exchange used by M3,
or completion of a nonzero physical return. Natural Remote-produced completion
exchange and timer/position progression remain separate evidence obligations.

## Failure-mode matrix

| Report / physical conditions | Conditional MCU history and reproduced boundary | Strength / limitation | Firmware opportunity and remaining uncertainty |
|---|---|---|---|
| VVR-005 F-002 pp2–4: swapped PIA,25ft XLR/wire lead, powered idle approximately0V supply; first mate one move, settled3300 quiet | Eligible digital LOW acquisition followed by HIGH before acceptance: both packaged images reach timer ENABLE/live1 after release | Demonstrated software mechanism; no measured insertion waveform or exact tested-build identity | Persistence qualification/freshness can reject short acquired events; cancellation policy can reject released pending events. Intentional equally short closure is indistinguishable. Capture PB05/PA02 during actual insertion. |
| VVR-004 F-001 pp3–4: original PIA, Spark+ output, Rev2 INFO0; contacts also0 | Held digitalLOW reaches first original initiation; analog-held completion+W demonstrates second initiation without new input edge | Strong conditional level/re-arm mechanism; repeated digital physical movement and actual Remote exchange not demonstrated; zero-distance simulated return | Require inactive qualification after readiness/completion. Steady source fault and held intentional contact cannot be separated by source intent without added information. Polarity intervention supports electrical direction dependence, not a proven leakage network. |
| VVR-003 F-001 pp2–3: Rev1 Relay Contact, idle supply,1909–1958mV, occasional16mV; reset does not clear | 517→600 filtered counts starts X1 and does not start X2; held900 plus native completion/W can initiate again without an edge | New915 fault-band first-initiation/control and868 re-arm evidence; exact MCU time series, M3 exchange, nonzero return and release package unresolved | Hysteresis/qualification/release-to-rearm can constrain repeated starts; merely raising threshold risks rejecting clean contacts in overlapping band. |
| VVR-004 F-002 p4: INFO/monitor exit, trigger re-enabled, movement without RUNNING UI; program reactivation restarts loop | TR reporting inhibits acceptance; active level can become accepted when eligibility returns | Recovered gating consistent with window; full Remote/UI sequence not reproduced | Explicit arm transition, post-arm inactive qualification, separate telemetry from authorization, coherent execution status. UI change alone is not measured electrical evidence. |
| VVR-002 F-002 p3: early reset, approximately30s repeats fade by10min, absent after power cycle | Filter history/initial eligibility can explain a first delayed or stale start; program timing/session re-arm could pace repeats | No reproduction of30s interval or10min recovery; July binary unavailable | Do not invent a periodic trigger timer. Obtain program duration/repeat settings, exact reset kind/device, connection state and captured acquisition history. |
| VVR-002 F-001 pp1–2: initial sources missed, work after reconnect | Inactive/missed sample, TR/marker/busy/idle gates, mode mismatch can each block initiation | Plausible alternatives; none identified as this session's cause | Record sample/classification/eligibility/rejection reason independently; external positive-control success does not establish AP pin stimulus. |
| VVR-004 p3: approximately74mV flickers every21–27s while quiet | Diagnostic artifact, transient or missed qualified sample could explain no movement | Reported **no motion**; no native correspondence established | Do not equate display flicker with accepted trigger, periodic callback or VVR-002's30s motor events. |

## Periodicity, mitigations and minimum additional evidence

No recovered evidence identifies a30s false-trigger oscillator or10min timeout.
The current repeated filter converges with acquisition count, not a demonstrated
ten-minute lifecycle. A stored move's duration, return-to-reference time, Remote
repeat behavior or recurring external disturbance could space moves. VVR-004's
M3/program-reactivation details strengthen the session-state question but do
not retroactively identify VVR-002's program. Its later power-cycle result and
VVR-003's negative idle watches are bounded observations, not closure of the
July fault. Reset could mean Remote/UI reset, application reset or complete
power loss; the report does not settle retained-state domains.

For apfw2, explicitly distinguish acquisition, filtered classification,
recognition, eligibility, consumed authorization and actual output service.
Require fresh inactive qualification after startup, program replacement and
completion before accepting a new active event; define active persistence and
freshness in real time; decide whether release cancels pending authorization;
discard stale pre-arm history; keep diagnostics independent of arming; prevent
Remote reload/direct commands from bypassing the chosen authorization policy.
These are policy recommendations, not an implementation or proof of electrical
reliability. The unchanged reference model already explores several of them;
Target3 shows why a trigger-only model cannot cover every producer/output.

A qualified intentional500ms pulse and an insertion event with an identical
acquired history cannot be distinguished by intent. Longer qualification trades
latency/missed short triggers against transient rejection. Require actual timing
measurements before choosing a threshold or claiming compatibility. Source
polarity, leakage/bias and invalid wiring can still need electrical correction.

Smallest useful bench capture: on the VVR-005 swapped-PIA B-2 setup, synchronize
PB05 sense, PA02/mode and first STEP/enable indication with XLR insertion; retain
source output state, X/TR and program/arming state. Compare one idle insertion
with one intentional pulse on the same wiring. Capture enough prehistory to
show whether the unit was inactive and armed, whether LOW was acquired, whether
it released before initiation, and whether the diagnostic3300 returned later.
For sustained faults, record at least two complete movements, completion/Remote
exchange and MCU input throughout, to distinguish held level from repeated
edges/session commands. Reuse the existing board/pin evidence and safe accessible
test points; this report neither performs nor authorizes hardware modifications.

## Execution, capability limits and next work

APTrace's existing direct Unicorn CLI and persistent Ghidra queries were used;
no analysis backend, original firmware, formal models, apfw2 or physical devices
were modified. Exact command files disclose fake tick, DWT delay stub, radio-ID,
MMIO-completion assumptions and RX-ring delivery. Write-watch uses the corrected
memory-hook-single-step path; the repeated868 positive is byte-identical to its
preserved original. Native timing is instruction-bounded, not measured RF or
electrical time. Existing Target2 SMT results are reused with their local scope;
no new solver theorem or admitted claim is asserted.

**Capability gap, high for physical trajectory/repeated-move claims:** the
documented direct CLI does not provide a validated autonomous TC/NVIC/STEP
schedule and position progression. New execution proves time-based profile
completion can occur without that facility; lack of IRQs was not sufficient to
explain the earlier unfinished22M run. Needed development is a supported,
validated continuous peripheral/interrupt scenario, not forced busy/idle values.

**Evidence gaps, high:** exact release archives/hashes, separate correspondence,
PA02/PB05 insertion waveform, natural Remote completion/re-arm exchange. Existing
APTrace can follow the latter when concrete packets/predecessors are available;
new physical measurements and release provenance cannot be derived from code.
The bounded W-control outcomes must retain their zero-position/no-IRQ and
externally supplied packet limitations. No formal model was edited to absorb
these uncertainties.
