# Natural Remote / AutoPilot retrigger lifecycle — Phase 2

2026-10-22. **The proposed autonomous completion → X → Remote W → held-input
retrigger loop is excluded in the exercised original-firmware histories, but
not excluded for every program, peripheral schedule or field release.**

Both original AutoPilot families complete the representative program without
queuing X, requesting an X send, restoring idle9 or initiating a second profile
when no W is delivered. Original868 held, released and reactivated histories all
finish at idle2 through65M instructions. Original915 held digital input gives
the same bounded result. The naturally generated `@` notifications occur near
initiation, not at completion; they enter the Remote's RUNNING screen but do not
set its exit flag. No natural X producer was recovered.

**An operator-driven sequence is supported:** a genuine captured AutoPilot @,
processed by original Remote instructions, enters RUNNING; an explicitly supplied
Remote button level causes six W send requests. Those bytes match the W packet
consumed in a fresh original AutoPilot completion/return replay, which restores
idle9 and initiates again with continuously active input. This is a staged,
button-conditioned software sequence, not an autonomous loop or physical RF
exchange. A separate bounded running-W experiment follows the stop/return path
and also reaches second initiation without trigger release.

The actual autonomous recurrence in Nathan's VVRs remains unexplained. This
negative fixture result does not contradict his observed movements. No original
image, experimental image, apfw2, model, framework source or hardware was changed;
Gates1–5 were not rerun or reclassified. No new admitted/VERIFIED claim or solver
theorem is asserted.

## Evidence and execution scope

The [Phase 2 packet](../../research/generated/remote-autopilot-lifecycle-phase2-2026-10-22/README.md)
contains exact commands, original snapshots, projected event/write histories,
message-transfer provenance, Ghidra outputs and hashes. This continues
[Phase 1](remote-autopilot-execution-lifecycle-phase1.md); its field inventory and
local variant-byte comparisons remain applicable.

New execution comprises original-image public Unicorn CLI runs and public Ghidra
queries. There are eight AutoPilot executions, including a short message capture
and a longer STOP diagnostic, and eight Remote executions, including three
capture-bound replays of initial protocol probes. Counts are not independent
verification votes. No new harness, peripheral model, script interpreting
instructions, framework, model checker, Macaw or SMT run was introduced. Artifact
projection records native fields; it does not implement firmware semantics.

Full AutoPilot runs start at pristine reset `0xcc24`. They reuse the existing
Remote-built nonzero program and MC4 bytes in the real RX ring, fake instruction-
paced tick, radio-ID response, MMIO-ready/read-clear responses, calibration map
and DWT delay stub. No idle, live, phase, completion, position or program-record
cell is forced. New queue write watches are passive and use the existing
memory-hook-single-step execution mode. All counts below are guest instruction
indices, not calibrated real time.

Remote runs execute actual ring/parser, screen guards and W-loop instructions.
The radio poll `0xb440` is stubbed because bytes are delivered at its RX-ring
boundary. Screen experiments also stub display operations, delay, TX transport
and the general UI service `0xc340`. Those runs do not continuously execute a
fully initialized Remote session, subsequent RF traffic or UI timeouts. Actual
`digitalRead(45)` executes against supplied GPIO state: the original915 pin-table
entry maps it to PA10, `0x41008020` bit10. This is a modeled button level, not an
observed human press.

## AutoPilot completion-to-message provenance

The exact monitored range is `0x200025bc..0x200025cd`, all18 pending counters.
In both held runs, the **only CPU write overlapping counter0** is reset BSS
clearing at `0xcc82`, instruction7573, writing a zero word. No nonzero write to
counter0 occurs. No observed `0x7f84` send request carries0x58 (X). Zero dropped
watched writes and watch counts below the cap support this bounded exclusion,
including computed writes actually executed in these runs.

| Original execution | First live store `0x5fa4` | Completion/channel-clear boundary `0x6056` | Outbound single-byte requests at `0x7f84` | End of65M |
|---|---:|---:|---|---|
| 868, analog225→900 held |12,451,170|52,249,088|# at12,103,265 and12,313,315; @ at12,520,776 /12,733,166 /12,941,135|One acceptance/start, channels/live0, phase0, idle2, queue empty|
| 915, digital LOW held |12,327,152|52,125,562|# at12,117,244 and12,330,272; @ at12,536,671 /12,750,795 /12,957,322|One acceptance/start, channels/live0, phase0, idle2, queue empty|

The queue writes identify why @ occurs: external-trigger acceptance at
`0x8f98` writes3 to counter1 at `0x8f9c`. Dispatcher `0x9268` consumes those
three counts at `0x929c`, then invokes single-byte sender `0x7f84` with0x40.
It does not originate from completion. The # requests are program/protocol ACK
activity, not completion or rearm events.

Native timed completion in `0x5fac` advances the stage, detects next duration0,
sets completion bookkeeping, conditionally writes idle1, invokes stop helper
`0x5958`, and clears the live byte. The phase-service suffix
`0x9090–0x9106` checks the completed/valid record, continuation byte and live
array, invokes `0x693c`, and writes idle2 at `0x9104`. `0x693c` writes two
GPIOs; it does not enqueue X or transmit a radio notification. The terminal
suffix has no queue-counter store. The selected mode/record takes this finished
branch rather than `0x4ae4→0x6e68` continuation. Static inspection of that
continuation prepares another profile; it does not establish a new X producer.
Multi-record execution itself is not newly validated here.

Thus the sequence is blocked at **completion → outbound X**, before any Remote
response would be relevant. This is a real negative result within the executed
program/environment/bound, not merely a failure to find X in a string search.

### X delivery and other notification mechanisms

| Mechanism | Producer/guard or consumer recovered | Evidence / limit |
|---|---|---|
| Pending X, counter0 | `0x9268` scans priority indices, requires a nonzero counter and elapsed dispatcher interval>=51 clock ticks; decrements the counter and calls `0x7f84(0x58)`. | Existing seeded positive control establishes dispatch, not natural enqueueing. No ordinary-completion, STOP or zero-return X producer is demonstrated. |
| Pending @, counters1/4 | Counter1=3 at trigger acceptance; counter4=1/2 for R0/R1. Same dispatcher/pacing path emits0x40. | Fresh native counter1 writes and three sends; R routes static. @ is not uniquely a completion notification. |
| `a0/a1/a2`, counter13 | `0x4440` builds a status digit and can queue13 when its guard permits; boot also queues13. | New original868 capture stops at `0x8c10` after13,155,568 instructions with r0=`0x20001fcc`, bytes `61 30 00` (`a0`). Periodic status queue writes continue before and after completion. No new completion-specific X or @ accompanies it. |
| `C`, counter10 | `0x8a80` channel-state4 timed branch. | Distinct state-monitor path, not the state1 profile terminal path exercised here. |
| Numeric result, counter15 | `0x8a80` state5 completion branch, selector updated to channel+1, builder `0x8ddc`. | I-family completion result, not proof of a normal trigger-profile notification or RUNNING exit. |
| `MS`, counter16 | `0x5dd0` connection/state transition logic. | Session-related mechanism, not identified as ordinary profile completion. |

Fresh xrefs plus the existing
[pending-event producer survey](../../research/autopilot_static_inventory/pending-events.md)
do not recover a direct counter0 enqueue site. The survey's old description of
`0x8f9c` as a position/bounds monitor is superseded by later trigger-acceptance
evidence. That inventory is corroborating search history, not a whole-program
alias-completeness certificate. The new native watches close executed computed
writes in the chosen histories; unexecuted aliases/interrupt contexts remain open.

Single-byte and string wrapper entry observations establish firmware send
requests/payloads. The wrappers contain native serial/radio paths, but no physical
RF send, receive, ACK or delivery timing is certified by these observations.

## Remote reception and W generation

The real Remote RX ring is at `0x20001773`, read/write bytes at
`0x200017d7/d8`. Both new X parser controls consume one supplied0x58 byte through
the original availability/read functions, return normally after92 instructions,
leave read==write==1 and set exit word `0x20000ff4=1`. No exit flag is seeded.
The915 parser entry is `0x10cf4`;868 is `0x10ce4`.

The X suffix at915 `0x10e22–0x10e58` drains remaining RX, reads signed accumulator
`0x200017f0`, and writes exit+1 for positive **or zero**, −1 for negative. It
updates the associated timestamp. It does not require a new local button press.
These X inputs are explicitly supplied positive controls; AutoPilot did not
naturally produce them in the completion experiment.

The first native AutoPilot @ byte is transferred, unchanged, into separate
Remote replays. Its provenance is recorded in `message-transfers.json`.
At `0x10cf4`, @ drains the ring, excludes page12, writes page9 and enters
RUNNING routine `0xcfc8`. In81 instructions it reaches that routine with exit
word0. The screen does not itself initialize that word; it consumes/clears it on
exit. A previously pending X can therefore affect entry, but no such pending X
was produced by the AutoPilot histories here.

| Remote experiment using captured @ | Native result | Classification |
|---|---|---|
| Parser to screen entry | Page9, exit word0, stops at `0xcfc8`. | Genuine firmware-produced byte, injected at modeled RX boundary; actual parser processing. |
| Screen, PA10 LOW, no exit flag | No `0x5930` W-send-loop hit through5,000 instructions. | Bounded screen control. General UI service/transport/display are stubbed, so not a complete Remote idle-session exclusion. |
| Same screen, PA10 HIGH supplied at `0xd028` | Six `0x5930` hits with r0=`0x1c598`, pointee `57 7c 00`; reaches `0xd078` in373 instructions. | Explicit button/peripheral event produces W requests through original code. No exit-word or button-return register override. |

`0x591c(0)` selects `W|`, loops6 times, with delay argument0x23. Transport
`0x58a8` is stubbed, so these are requests to send, not demonstrated RF packets.
RUNNING entry also requests J three times through `0x5a50` (statically recovered).
J is a separate ancillary command and is not silently interpreted as W or STOP.
The button and X-derived flag therefore converge on the same `0xd06e–0xd074`
exit suffix and `0x591c(0)` payload loop. Given a received X, that exit requires
no button press; the unresolved part is its natural AutoPilot producer, not a
different X-specific W command format. This convergence is supported by the
actual parser/guard controls and recovered instructions, rather than a complete
autonomous two-device X replay.

The known exit-word writers remain the X suffix and the screen's clear. @,
ordinary numeric reports and the lowercase-status branch do not directly set
that word in the recovered parser. The lowercase branch can invoke reconnection
and page routing through `0xc440/0xfd7c`; these are distinct session transitions.
A complete, continuously initialized Remote receiving every status message is
not executed here. Resolved xrefs do not exclude undiscovered computed writers.

Repeated or delayed X can set the word again; an existing pending word can
satisfy the next RUNNING entry. Repeated @ can affect screen/session routing but
does not itself fulfill the recovered exit guard. Whether delayed traffic can
cause several separate screen exits depends on RX draining, nested UI/service
execution and session state; six copies from one helper call must not be counted
as six separately caused exits.

## Combined timeline and provenance classification

F = firmware-produced under the stated execution environment; R = original
processing of captured peer bytes; P = explicitly supplied peripheral input;
I = injected protocol delivery/state boundary; S = static; U = unresolved.
F does not imply physical hardware or an autonomous two-device execution.

| Step | State/event | Classification |
|---|---|---|
|1|Reset → program/MC4 accepted through real AutoPilot parser; no application-state seeding|F plus I for program/config delivery and P for tick/MMIO/device responses|
|2|Active acquisition → `0x8f98`; queue1=3; profile/rate/TC0 enable/live|F, with P for GPIO/ADC input|
|3|Three @ send requests near initiation; later status `a0` captured|F; physical transport unverified|
|4|Captured @ → real Remote ring/parser → page9/RUNNING, exit word0|R+I; display/transport/service boundaries disclosed|
|5a|Natural AutoPilot timed completion → idle2; no X enqueue/send|F; observed negative through65M|
|5b|AutoPilot completion → X → Remote exit|U globally, excluded in the exercised histories; **not supplied as a natural event**|
|6|Remote PA10 button level supplied → six W requests|P→F; explicit operator/peripheral condition, not completion-generated|
|7|Captured W bytes equal the packet supplied to AutoPilot RX at first completion `0x6056`|R+I; packet placement/timing modeled; no live RF link|
|8|W phase1/2/3 → zero-distance return request → idle9|F, with existing peripheral assumptions and software position0|
|9|Held active input → second acceptance/rate/ENABLE/live|F, conditional on step7, not autonomous|

In the fresh original915 operator-W replay, first completion is52,125,562,
return request `0x6fd8` is52,155,465, idle9 boundary is52,167,621, second acceptance
is52,167,777 and second live store is52,400,358. Through60M, X counter0 again has
only its reset-zero write. The zero-distance return therefore does **not** fill
the missing X-producer link either. Three more @ requests follow second
acceptance; they must not be reassigned to first completion.

This staged construction exchanges the actual recovered payloads. It does not
run the Remote beside a preserved AutoPilot instance at real RF timing: the
AutoPilot prefix is deterministically replayed and W enters its original RX
ring at the declared completion PC. Essential button and delivery events remain
external. It is specifically not a no-command autonomous retrigger witness.
Only one of the six captured W request payloads is delivered in this staged
replay. Full-burst delivery, duplicates arriving in different phases, and delayed
messages causing additional screen exits are not dynamically closed. The
post-completion and running-STOP results do not depend on claiming all six RF
packets arrived.

## Held, released and fresh input comparison

The new original868 no-command comparison keeps the same program, configuration,
clock/peripheral assumptions and65M bound. “Fresh” here means reactivation **at
completion**, because no autonomous rearming occurs; there is no reachable
post-rearm input opportunity in these no-W runs.

| History | Input schedule | Outcome without W |
|---|---|---|
|Held|Baseline225 →900 at setup return, then held|One start; completion52,249,088; idle2, channel/live0 through65M; no X|
|Released|Same activation, raw225 supplied at first acceptance|One start; completion52,246,833; effective225, idle2 through65M; no X|
|Released/reactivated|Same release; raw900 supplied at first completion `0x6056`|One start; effective900 at end, but idle2 still blocks acceptance through65M; no X|

For comparison, [Phase 1's original868 W controls](remote-autopilot-execution-lifecycle-phase1.md)
establish held+W→second start, released+W→idle9 without second start, and
release/reactivation+W→second start after effective input rises to587. The latter
is a genuine original control, not the experimental patch. Original915 digital
held+W and release/reactivation+W also initiate twice. The new captured Remote W
payload has exactly the same bytes as these supplied-W controls; that establishes
the command interpretation, not the natural scheduling of those commands.

Together these distinguish the causes: an electrical edge alone does not restore
the idle2→9 state; W/return restores eligibility; active classification then
allows another initiation without checking for a prior qualified release. No
separate retained digital “pending trigger event” was discovered. Analog filter
history can remain active after raw release, as the existing original controls
show, so raw and effective input must remain separate.

## Running STOP versus ordinary completion

A fresh original915 run supplies the captured W bytes at the first live-store
boundary, rather than after normal completion. Actual W parsing sets phase1;
the service requests stop `0x5274(0,4)`, proceeds to phase2, the terminal service
stops the channel, phase2 prepares a zero-distance return and phase3 restores9.
The held input then initiates again.

| First STOP/return sequence | Instruction index |
|---|---:|
|First live boundary, W delivered in RX ring|12,327,152|
|W phase1 store `0x865a`|12,349,029|
|Stop-request helper `0x5274(0,4)`|12,359,510|
|Stop helper `0x5958`|12,367,117|
|Terminal/channel-clear boundary `0x6056`|12,367,142|
|Idle9 store `0x9088`|12,376,400|
|Held-input second acceptance `0x8f98`|12,376,556|
|Second rate start `0x5f8c`|12,603,309|
|Second TC0 ENABLE-containing store `0x571c`|12,603,394|
|Second enable-helper entry `0x5810`|12,603,443|

The final `operator-w-single-stop-prefix` stops at12,603,450, before the next
live-store visit can deliver another W. The longer14M diagnostic delivered W at
**every** live-store visit because `--force-mem` is PC-recurring. Its later
repetitions are harness-driven and are not an autonomous-loop finding. The
shorter prefix retains one W delivery and the second actual ENABLE request.

Thus the exercised STOP/W route differs from no-command completion: it activates
return phases and permits idle9, whereas ordinary completion leaves2. No fresh
trigger transition is required afterward. This closes a software stop/return
join left at helper entry in Phase1. It does not certify physical stopping,
deceleration distance, nonzero return, driver state or pending NVIC/STEP behavior.
No comprehensive STOP-safety investigation was undertaken.

## Relation to Nathan's reports

Primary sources remain the [preserved VVR PDFs and extraction provenance](../../research/validation/nathan-vvr/README.md),
not analyst descriptions alone.

- **VVR-003, p3 F-001:** connected inactive supplies caused continuous triggering
  in Relay Contact mode, with diagnostic1.91–1.96V overlapping intentional
  contact values; reset reactivated it. Prior original X1/X2 evidence supports
  active classification in that reported band, but this phase does not establish
  how the field unit repeatedly regained eligibility. A constant active sample
  plus the representative no-W program does not reproduce autonomous repetition.
- **VVR-004, p4 F-001/F-002:** repeated M3 movements and UI-dependent return-to-A,
  INFO-exit and program-reactivation observations remain physical findings. The
  operator-W/return mechanism is a plausible software correspondence for
  interaction-dependent reeligibility, especially a return-to-reference action.
  It does not show that each unintended field move was preceded by an operator
  action, nor explain the entire continuous loop. Actual M3 records, Remote
  session/traffic, input waveform and release identity remain needed. Diagnostic
  quiet-watch flickers with no motion remain negative observations.
- **VVR-002, p3 F-002:** approximately30s recurrence and gradual disappearance
  after about10min are not explained here. Instruction-paced profile timing and
  status dispatch do not establish a physical30s oscillator. Neither program
  duration nor a heartbeat should be relabeled as that field period without
  synchronized evidence.

Nathan observed physical motor movements. This work observes original CPU
initiation and modeled time-based completion, without STEP-counted position
progress. His inactive source is not proof of a constant MCU pin history.
The packaged originals are still not hash-linked to the field-tested release
archives; matching displayed revision labels do not repair that gap.

## Capability gaps and next APTrace work

| Gap / priority | Impact and observed evidence | Likely cause and needed capability/evidence |
|---|---|---|
|Whole-program X producer closure — high for universal lifecycle claims|Counter0 has no positive writer in the four65M no-command histories or60M zero-return replay. Direct survey finds no enqueue site, but cannot certify all aliases/interrupts.|Likely an unused endpoint in these paths, **not proved globally**. Existing APTrace should follow any newly identified writer/field-program path; an alias-aware complete writer analysis would require framework work. Exact frontier: positive store to `0x200025bc[0]`, consumed at `0x9268` case0.|
|Initialized coupled Remote session — high for field recurrence|Captured @ reaches RUNNING, but screen controls stub general service and transport; a0/session traffic is not processed continuously by a normal booted Remote.|Case scenario/initialization gap. Smallest useful next software experiment: preserve naturally established Remote session/RX-enable/page state, deliver the captured @ and status stream through original service/parser, leave button inactive, observe `0x20000ff4` writes and W calls. Do not seed a convenient exit flag.|
|TC/NVIC and nonzero return — high for physical lifecycle|Time-based profiles complete, but software position stays0; return is distance0. Running-W prefix proves software transitions only.|Missing validated continuous timer/interrupt/position behavior. Existing bounded helper/handler scenarios can study local conditions; continuous nonzero return needs a supported peripheral scenario or synchronized physical evidence. Do not force live/position clear.|
|Program/UI/release correspondence — high for VVR causation|Only the representative accepted program and selected modes were exercised; exact M3 contents and field hashes are unavailable.|Missing evidence, not a demonstrated APTrace defect. Obtain original records/release hashes and synchronized Remote/AutoPilot traffic/input history; then replay that bounded sequence.|
|Real time/electrical history — high for30s/physical claims|Fake ticks, supplied ADC/GPIO and radio/MMIO assumptions have no wall-time or measured waveform equivalence.|New measurements required. No software-only inference of source leakage, recurrence interval or physical intent.|

The smallest experiment that can refute the present bounded exclusion is a
supported original program/peripheral history that causes a nonzero counter0
write or another real exit-word producer, followed by original Remote W without
button input. Record the exact writer PC and state at that first divergence.
If X appears in an actual link capture, trace its producer rather than injecting
it as an unexplained oracle. If only W appears, recover the Remote caller and
screen/session predecessor. Existing tools suffice for these bounded replays once
their missing inputs/context are available; a general radio emulator is not
required or proposed.

Operational failures: two initial Remote screen invocations tried GPIO outside
the CLI's default MMIO window and failed before guest execution. The established
`--mmio-size 0x4000000` corrected the input geometry; no permission escalation,
dependency change or framework modification was needed. Two initial documentation
paths were stale; repository search located the current dossier. The recurring
W diagnostic is retained with its restriction above. Final native runs have no
guest errors or dropped watched writes; instruction-budget stops are not proof
of product readiness. No new symbolic all-path exclusion is claimed.

## Stateful-patch readiness

We now know enough to implement and test a **bounded stateful trigger-
qualification experiment**, if separately authorized: preserve a consumed
authorization across completion, W/STOP and idle9 restoration; require the
chosen fresh inactive/active qualification before another trigger-derived
profile; cover digital and analog history; keep an explicit manual return
operation distinct from granting another external-trigger start.

We do **not** yet know enough to claim that such a patch fixes Nathan's
autonomous repeated movements or covers every original program/session route.
The natural no-button W producer in the field remains unestablished, and nonzero
return/interrupt behavior and exact M3/release provenance remain open. These gaps
limit the eventual efficacy claim; they need not conceal the already demonstrated
held-input acceptance after command-driven reeligibility. No patch, RAM allocation,
product policy or model change is implemented in Phase2.
