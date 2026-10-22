# AutoPilot bring-up, Pass 2: retained channel, analog continuity and request authorization

2026-10-21. **The selected software transitions are established, with explicit
peripheral and input assumptions. Enough evidence exists to define a testable
application bring-up contract; a complete legacy-Remote or physical READY
contract is not established.** No apfw2, original firmware, APTrace implementation
or physical hardware was modified.

This extends [Pass1](autopilot-bring-up-pass1.md), not its flashing/recovery scope.
The principal results, in priority order, are:

1. Retained A25 is not automatically requested in either the tested setup wait
   or extended configured execution. Explicit A25 input causes the retune.
   Examined Remote reconnection paths do not supply a cross-channel recovery
   mechanism; a channel mismatch must not be assumed to repair itself.
2. Continuous analog-mode reset→baseline→runtime execution preserves alpha0.05
   and updates samples. With native program acceptance, a filtered active input
   reaches reload; TR1 can report that same active condition while preventing
   reload. Normal permanent first-sample freezing is contradicted by this path.
3. One continuous original AutoPilot reset→Remote-built program→MC4→G sequence
   reaches original request entry0x6fd8 with `(0,30,500,8119)`, without seeding
   AutoPilot program, position, validity, target or arm state. Two fresh runs are
   byte-identical. Execution stops before the commit routine runs.

“Continuous” describes AutoPilot instruction/state continuity within one native
run. It does not imply physical input continuity, a running Remote UI, actual
RF delivery, autonomous timer interrupts or motor operation.

## Evidence and execution

The [evidence packet](../../research/generated/bring-up-pass2-2026-10-21/README.md)
contains [24 exact native commands](../../research/generated/bring-up-pass2-2026-10-21/commands.json),
[execution outcomes](../../research/generated/bring-up-pass2-2026-10-21/execution-results.json),
70 scoped artifact checks, static queries, raw snapshots, sampling summaries
and the selected program-event sequence. Input/source hashes and commands bind
the results to unmodified original868 images and the corrected memory-hook
backend. No new VERIFIED/admitted claims or ledger grades are asserted.

Methods: existing public APTrace Ghidra callers/decompile/disassembly/literal
queries, existing SVD resolver, and documented direct Unicorn CLI execution.
Static control flow selected the input ablations; native execution tested them.
No independent instruction analyzer, new harness, new peripheral implementation,
solver proof or framework test was introduced. Exact bytes were compared across
the supported modeled RF boundary, not represented as an over-air exchange.

The documented venv uses Python3.9.6/Unicorn2.1.4. Full startups record
`memory-hook-single-step` using the already-corrected backend. Commands use the
direct CLI; no comparison wrapper, dependency change or security bypass was
introduced. Twenty-two commands exit0 without a native
execution error; two exploratory cold-Remote runs exit1 and retain
their structured unmapped-read snapshots. Exit0 includes instruction/watch-cap
observations with `completed=false`; it does not mean product READY.

## 1. Retained radio settings and reconnection

### Observed AutoPilot progression

The retained-A25 fixture is Pass1's provision1/A25 data-flash input. Initial
radio bring-up still reads compiled A20, requests864300000Hz, and stores that
requested frequency at radio-object0x20004160+0x28 =0x20004188. Boot reader0x4c20
later loads A25 into0x20000069; staged A at0x20003160 is25. That load does not
itself reinitialize the radio.

| Bounded run | Native observation | What it establishes |
|---|---|---|
| `radio-retained-a25-waiting-peer` | No peer packet supplied.30M instructions, tick7496; setup flag remains1, no0x93fc entry; one0x610c and one0x9b20 call. Runtime25, requested shadow864300000Hz. | The original setup polling path does not apply the retained channel within this >5s nominal post-initialization window. |
| `radio-retained-a25-silence-window` | MC4 supplied, then no more input.35M instructions, tick8746;4985 loop entries. Still one initialization/frequency call and the same mismatch. | MC4/setup exit and a nominal >5000ms since the supplied packet do not repair requested tuning in this model. Instruction-paced timing is not measured RF silence. |
| `radio-explicit-a25` | Real-format `A25,\|` supplied at setup return. Native0x610c executes again;0x9b20 receives865800000Hz at11,985,230. Requested shadow changes to865800000Hz. | Even with runtime already25, an explicit command requests the proper retained channel. Radio ID success remains modeled. |

Fresh caller queries resolve0x610c from setup0x948c and ASCII A dispatch0x8914;
0x9b20's resolved caller is probe0x9de2. These are search-relative direct-call
results, not a proof excluding every indirect call or all future firmware paths.
Combined with the runtime controls, they provide no support for an automatic
retained-channel apply, periodic scan or fallback on this path.

### Remote-side sequence and the recovery boundary

Existing and refreshed native analysis shows Remote0x7664→0x71d0 loading local
store index0x2d into its A selector. Setup0xfdf0 calls that loader before
0x7ba4 requests its radio configuration. Thus a Remote retaining25 can request
865800000Hz while this AutoPilot initially requests864300000Hz. The relevant
Remote initialization callers are startup, RF-channel UI confirmation and the
separate host/service `$SC…` path. Its silence/reconnect routine0x10ce4 clears
session latches after the nominal5000-tick condition and can invoke0xc440's
S/configuration exchange; that examined path does not retune or send A.

The UI channel change stages locally, sends A five times, then retunes the
Remote. An A25 frame sent while the Remote is already on25 cannot be presumed
to reach an AutoPilot still on20. Reconnection alone is not evidence of channel
negotiation. The software-supported correction requires an input delivered
over a currently reachable transport, or externally bringing the peers to a
common channel before another coordinated channel change. The inspected
service path is not a validated recovery recipe.

**Inference, not physical observation:** under normal frequency-selective RF,
the requested mismatch prevents assuming peer reception. Actual applied modem
state, matching packet defaults, receiver behavior and a successful recovered
link were not measured. RX-ring injection bypasses that mismatch and cannot
demonstrate cross-channel recovery. Stop this line here: no natural recovery
was demonstrated or found in the examined resolved paths; validating a real
link requires unavailable RF/device evidence. No universal all-path absence
claim or hardware operation is proposed.

The frequency arithmetic carries over conditionally to the915 base from prior
variant evidence. This pass does not assert a newly executed915 paired startup.

## 2. Continuous analog initialization, acquisition and acceptance

### Unbroken initialization and sampling

New runs start at original reset0xcc24 with PA02 HIGH, producing mode1 at
0x20001fc0. The baseline clock/SERCOM, calibration-placeholder, PA22 release,
radio-ID and tick assumptions are unchanged. ADC1.RESULT0x43002040 is supplied
as a declared external input:225 during setup,900 at setup return0x94e4.
Original ADC helper0xd1b4, result load0xd2a2, filter0x42a4 and normal scheduler
execute. There is no ADC-function stub, filter-return override, deadline reset,
forced initialization flag, coefficient seed or program/eligibility flag seed.
One preliminary stream used raw900→3600 and is retained separately.

| Stage/state | Original-code observation |
|---|---|
| Reset/init | Alpha bytes at0x20000014 are `cd cc 4c 3d` =0.05; cold filter flag0x20003118 is0. |
| Baseline0x5d44 | First due acquisition reads225, writes filtered float225 at0x2000311c and flag1.128 calls to the filter occur, but only3 reach ADC acquisition under this modeled clock; cached returns are not128 independent samples. |
| Subsequent runtime acquisition | Flag remains1 and alpha remains0.05. Actual filter returns259,291,321,350,… after the225→900 step, approaching900. This is the original blend `old+(new−old)×0.05` plus integer rounding. |
| Sampling versus polling | Deadline0x20003124 is tested using0xccdc's nominal microsecond-scale clock; due acquisition advances/rebases the deadline. Non-due calls reuse the cached value. Telemetry uses a separate nominal millisecond clock. None of the instruction spacing establishes a physical rate or pulse-width limit. |
| Native X1 comparison | Runtime bands become inclusive[200,580]. In `analog-band-transition`, the15th observed comparison sees587 and becomes active. |
| Native X2 command | A real X2 packet changes runtime/staged selector. The band becomes[250,750]; in this stream the30th comparison sees755 and becomes active. One X1 poll precedes packet dispatch. These are ordinal fixture observations, not fixed latency specifications. |

This closes Pass1's initialization-continuity question in the selected original
startup path. A set initialization flag means “filter has a previous value,”
not “ignore future samples.” Zero-alpha fixtures still freeze their value, but
they represent conditional seeded/abnormal state. Source review also shows
the older transient harness entered0x5d44 directly with mode seeded, rather
than executing full reset/data initialization. That construction cannot support
the former normally-zero coefficient attribution. Every old boot-chain variant
has not been reconstructed; no historical artifacts were overwritten.

### Natural program eligibility and diagnostic divergence

Two further continuous analog runs use native Remote-built program acceptance
and MC4, then the same225→900 stream, with **no G command**:

| Conditions | Observed result |
|---|---|
| Default packaged state, no accepted program | Effective sample becomes active, but marker is not7b; no reload acceptance. TR1 can still emit `T900,1,\|`. |
| Accepted program, X1, TR0 | At12,203,576, effective587 and marker7b pass original0x8f98. Native0x6e4c reload prepares channel0, clears idle to0 and leaves phase arms0. By14M instructions there is one acceptance and no0x6fd8 entry. |
| Same accepted program, native TR1 packet | At12,118,734 emits `T291,0,\|`; at14,122,227 emits `T900,1,\|`. Marker remains7b, but no0x8f98/reload or motion-request entry by15M. Idle remains9 and channel state0. |

The actual gate separates active input from reporting, program/session marker,
four channel states and idle state. TR1 is an execution guard as well as a
subscription. Reload prepares valid records but does not authorize a move by
itself. Individual record validity and physical reference truth are different
from the shared marker gate. No physical-reference-valid check was encountered
on this selected path.

**Plausible software consequences, not field-failure diagnoses:** short input
changes may be attenuated or not acquired before the next deadline; X changes
both band edges; reporting can suppress reload despite visibly active telemetry;
held input can become eligible after other state transitions because the gate
does not itself impose an edge/release contract. The tested reload changes its
own eligibility, so “one accept on every LOW poll” is not the continuous
behavior demonstrated here. Electrical noise, ADC accuracy, jack bias, bounce,
loop jitter and physical misfire causation remain unmeasured.

## 3. Continuous program-to-request sequence

### Producer/input provenance and modeling boundary

Original Remote0x49c4 builds
`+1,1,1,0,98,1,0,0,0,500,0,0|` from a representative prior record delta500.
UI editing, a full Remote boot and the successful0xc440 handshake are not newly
executed. The Remote's actual post-builder counter byte1 at0x20001820 is carried
to original G builder0xb680, which builds `G011|`. It temporarily stores0x63
while entering its ACK helper; that is not a new sequence digit. The corrected
capture stops at real0xb59c after construction, before unavailable cold driver
execution. This is not a demonstrated RF send/ACK.

The AutoPilot itself runs continuously from pristine original reset. Only the
captured program bytes are put into its real RX ring at setup polling0x94b8;
the existing MC4 packet is delivered at the program handler's native tail0x81ca;
captured G011 is delivered at setup return0x94e4. Inputs at these PCs are
disclosed delivery timing assumptions, not inferred physical packet arrival.
The original RX assembly, parser, program computations, state stores and main
loop run throughout. No AutoPilot RAM program, reference, position, validity,
setup flag, target or arm is seeded. No application routine is stubbed; the
existing DWT delay stub remains a peripheral-timing assumption.

The representative record is accepted by Noxon's examined checks; this does
not certify all trajectory fields, units, non-finite intermediate coefficients,
rate limits or physical safety. Its request's rate8119 is an internal argument,
not a measured speed or a recommended motion profile.

### Progression and precise execution dependency

The first run reaches a repeating0x627c..0x6280 wait after program/MC4/G
processing. Native0x6260 writes0x80 to TC0.CTRLBSET0x40003805, then waits for bit7
to clear. The local SVD names CMD at bits5..7, value4 READSYNC. Plain MMIO
retains the written command indefinitely. The existing read-clear facility,
`--mmio-clear-bits 40003804:8000`, supplies that command-completion assumption
in the aligned containing word. It fires3 times in the positive LOW-input run.
No timer counts, interrupts or motor steps are generated by this assumption.

With that one addition, the following original transitions occur:

| Instruction / routine | Actual state change or observation |
|---|---|
|11,494,826 /0x8258 | Program frame parsed through the actual RX caller. |
|11,496,143 /0x8146 | Mode98 takes native resync branch for four channels. |
|11,518,818 /0x817e | Chain/writeback has produced record0 delta500, start0, endpoint500. Staging is dirty. |
|11,518,931 /0x81ca | Runtime/session marker0x20001b38 is7b; MC4 packet is supplied. No flash checkpoint is asserted. |
|12,065,991 /0x8718 | MC4 clears setup flag; native desired current/microstep arrays reflect the packet. |
|12,074,771 /0x8f98;12,074,777 /0x6e4c | With modeled PB05 LOW, one natural trigger acceptance/reload occurs before G dispatch. It does not set G arm or the trigger phase arms. |
|12,128,630 /0x8258 | G011 is parsed. Sequence1 differs from prior program sequence0. |
|12,146,139 /0x83e0 | Original dispatcher writes2 to G arm0x200025e1;0x83e6 initializes G phase0. |
|12,152,359 /0x7d56 | Original0x7e2c selects endpoint500 into0x2000201c and advances phase1. |
|12,178,974 /0x6fd8 | Request entry arguments: channel0, constant30, target−current=500, rate8119. Stop occurs before its first instruction. |

The positive repeat is byte-identical, not just equal at the distance field.
Current0 is a software reset reference; no homing or physical position has been
established. Marker/record validation, resync and request arming are observable
software transitions, not substitutes for that missing physical truth.

### Discriminating controls

| Input change, otherwise same original reset path | Result |
|---|---|
| Remove G | Program and MC4 accepted; one trigger reload, G arm/phase remain0, no request entry within14M. |
| Reuse G sequence0 (`G010\|`) | Three parsed packets, but G's shared sequence guard suppresses arming; no request. This demonstrates why independently seeded G fragments can miss a real protocol condition. |
| Hold PB05 HIGH | No trigger acceptance/reload. G011 still reaches0x6fd8 at12,138,041 with the same arguments. G is independent of an active trigger. |
| Omit TC0 READSYNC completion | Accepted program/G state and selected target exist, but scheduler remains in the hardware-completion wait within20M. It is not evidence the firmware rejected the program. |

These controls close the selected natural G-arm producer and scheduler join
left open in Pass1. They do not close STOP/reset while moving, physical
reference validation, timer/IRQ delivery, every request family or a complete
Remote UI→RF→ACK→motion session.

### Driver configuration alongside this path

Native0xae60 current-helper arguments are400 for the four boot calls, then1600
for four post-MC4 calls. Native0xb070 microstep-helper arguments are16 at boot,
then0 after the packet's1→0 conversion. Desired arrays agree with those later
arguments in these runs. Earlier recent-timestamp controls still show that
MC4 acceptance can skip those later setters; they are not universally tied to
setup exit. No valid TMC readback confirms active settings. Initialization,
requested settings, register shadows and physical reset/fault recovery remain
different evidence levels.

## Consolidated conditions for a testable software contract

| Condition | Demonstrated software predicate/transition | Inference or remaining requirement |
|---|---|---|
| Communications availability | Radio init can return under the declared ID/bus assumptions; correct A command changes the requested frequency. | Applied modem state, packet defaults and peer delivery need independent evidence. A CPU ID override is not a working link. |
| Remote synchronization | Resolved Remote startup/reconnect producers, program and MC4 formats, and the actual sequence-counter relationship are recovered. | A full paired reboot/reconnect S/P/!/program/ACK/MC4 exchange is not continuously executed. No cross-channel scan/recovery established. |
| Retained configuration correctly applied | Stored A loads; A command requests it. Initial radio settings precede that load and can remain inconsistent. | A startup contract must test requested/applied state separately from stored/RAM equality. Do not infer peer agreement from any one field. |
| Trigger acquisition/recognition | Full analog reset initializes0.05; due ADC reads update the filter; X selects inclusive bands. | Physical sampling rate, pulse width, electrical integrity and debounce/release policy are not recovered as reliability guarantees. |
| Trigger acceptance | Native program marker, idle/channel guards and TR0 admit one filtered active reload; TR1 reports while rejecting it. | Preparation does not itself arm a move. Natural eligibility restoration across all workflows remains unproven. |
| Program/reference validity | Native program produces valid-byte1, marker7b, software start0/endpoint500; G selects target500. | This is Noxon's bounded acceptance, not full schema/trajectory integrity, reconciled durable program ownership or physical reference validity. |
| Driver configuration | Original startup and later MC4 setter arguments observed in the same request path. | Confirmed device configuration and behavior after driver/MCU reset require readback/reset evidence; timestamp-gated updates remain conditional. |
| Motion-request authorization | Nonduplicate G writes its own arm, main loop advances its phase, and target−current reaches the request boundary. No-G and duplicate controls do not. | No independently confirmed-driver or physical-reference predicate was encountered on this path. This is not a universal safety policy or permission to operate a motor. |

**Yes, a testable application software bring-up contract can now be written**
as staged predicates and input/output tests, including negative controls. These
vectors supply concrete oracles without choosing apfw2's implementation. Before
freezing a complete legacy-compatible readiness specification, resolve or
explicitly scope out the natural paired handshake/retained-channel policy,
required program units/profile validation and reference-establishment policy.
Physical readiness additionally needs radio/driver confirmation, electrical
input characterization and board/reset/bootloader evidence. Some of these are
engineering requirements to choose; they cannot be copied from a demonstrated
single vendor READY predicate, because none has been grounded.

USB endpoint responsiveness remains separate and untested. Startup already
requests outputs/pulses before the motion-commit boundary. QSPI conflicts still
prohibit recommending unmodified-image execution on an intact Feather. No
flashing/interruption, D provisioning or physical motor work was performed.

## APTrace limitations and next bounded work

| Gap / observed boundary | Impact and needed work | Priority |
|---|---|---|
| RF and device models absent | RAM-injected packets and register shadows cannot prove actual channel application, handshake or peer receipt. Use existing tools only for a selected missing software exchange; validated RF/device or physical evidence is a separate need. | High before physical/legacy-link READY claims |
| TC command completion is plain memory | Concrete wait0x6280 needs a disclosed READSYNC completion assumption. Existing read-clear facility suffices for the request boundary; no interrupt model was invented. Timer progression/STEP behavior remains outside this result. | High for deeper execution, not a remaining blocker for this request witness |
| Cold Remote transport is uninitialized | Two captures using `--call` continue into a cold driver and fault. CLI `--call` owns its return stop and does not forward `--stop-at`; corrected `--entry` capture stops at the real ACK boundary. Document this API boundary; do not mistake those failed sends for peer communication. No backend fix in this operator pass. | Low for the recovered bytes |
| Native Ghidra project locking | Two overlapping queries failed with LockException; serialized repeats succeeded. One positional dump-length invocation failed parsing and was corrected using the documented literal interface. Failures retained; no lock/security bypass. | Operational limitation, resolved for this pass |
| Position/profile/STOP evidence incomplete | Request500 and software0 do not certify trajectory units, physical reference, stop latency, fault containment or reset while moving. A selected software STOP/arming lifecycle and scoped profile validation are possible with current tools; physical guarantees need new evidence. | High before a motion-ready specification |

Stop here: the three priorities have bounded answers and their important
remaining joins are visible. Further work should select one contract gap,
not repeat broad subsystem discovery. A/B/C/D release gates remain PARTIAL,
E/F BLOCKED, production NO-GO. No stronger physical or vendor-specific READY
claim follows from the new software continuity.
