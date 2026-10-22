# AutoPilot trigger misfires: failure mechanisms and discriminating tests

2026-10-21. **Campaign correction:** the continuation below establishes a
second motion-initiation path: accepted reload → channel profile service
`0x6338` → rate start `0x5f8c` → timer enable `0x5810`. It does not require
`0x6fd8` or the separate phase arm. Historical “no motion request” language
in the initial pass means only no observed `0x6fd8` call and must not be read
as absence of software pulse-generation authorization. See the campaign matrix
for new request outcomes and remaining completion/re-arm limits.

**Initial pass — partial answer: several software mechanisms can suppress, delay,
or admit an input without a new edge. None establishes the cause of a physical
misfire or a V1/V2 reliability difference.** This investigation follows the
signal through sampled input, classification, reload acceptance and request
preparation. An accepted reload is not a demonstrated motor activation.

## Result and evidence ranking

The strongest explanations for *missed or unexpected apparent triggering* are:
normal analog attenuation and polling; TR diagnostics suppressing acceptance;
X reclassification of unchanged input; and level-based acceptance when an
already-active input becomes eligible. Program, reference and arm state explain
why recognized input need not produce the expected move. Electrical noise,
contact bounce, bias and startup mode selection could expose these mechanisms,
but their presence on a particular board has not been measured.

Priority here ranks evidence and diagnostic value, not incidence or probability.
The matrix separates observed software behavior from physical hypotheses.

| ID / rank | Conditions and path | Expected operator symptom | Evidence / reproduction boundary |
|---|---|---|---|
| F1 / demonstrated, high | Analog PB05 excursion acquired once; normal alpha0.05 in `0x42a4`, X1 | Short valid electrical pulse may be missed; no threshold crossing | New one-acquisition pulse:225→900→225 yields259 then257…225, no `0x8f98` by14M instructions. Held900 control crosses587 and accepts in Pass2. Whether a real pulse produces these acquisitions needs measurement. |
| F2 / demonstrated, high | TR1 at `0x20003120`; `0x8f7c` rejects even between report deadlines | Remote displays active trigger but no accepted reload | Pass2 native TR1 emits `T900,1,\|` with marker7b/idle9; no acceptance by15M. TR0 control accepts once. Diagnostics are behavior-changing. |
| F3 / demonstrated, high | Real X2 packet changes inactive band from[200,580] to[250,750] | Apparent trigger without input edge, or an input formerly active becomes inactive | New constant225 full-reset X1 control never accepts; X2 accepts225. X is not monotonically “more sensitive”: e.g.225 becomes active, whereas600 becomes inactive. Static boundary tests support inclusive endpoints. |
| F4 / demonstrated, high | Input active before native program/MC4 eligibility; normal level gate, no release/edge requirement | Effect at setup completion or re-arming rather than at the original event | New constant900 since boot accepts once after native program/MC4. No later ADC change required. Natural program state, not seeded acceptance guards. Subsequent repeated activation requires restoration of eligibility, not demonstrated here. |
| F5 / demonstrated, high | Analog low-side excursion; classifier is outside-band, not rising-only | Low-going noise/disconnection could look active, often sooner than the tested high excursion | New225→0 gives214,203,193; accepts193 on third observed runtime comparison. Positive225→900 takes15 comparisons in Pass2. These counts are input-dependent, not physical latency specifications. |
| F6 / demonstrated contract, high | Missing marker7b, any channel nonzero, idle byte not9, record invalid, or arms absent | Recognized input rejected, accepted reload with no prepared record, or reload without expected motion | X/guard controls and Pass2 natural program/no-program/TR comparisons. Reload `0x6e4c` changes eligibility and clears phase arms. Shared acceptance does not require individual record validity. No-G accepted case has no request by14M. |
| F7 / demonstrated constituents, medium | Software reference differs from physical position; resync rebases records; independent G/phase arm | Wrong destination/direction or apparent wrong-time move despite a legitimate input | Motor/reference analysis: endpoints=start+delta; resync uses software position. Pass2 G reaches request with trigger HIGH; earlier phase-arm fixture can request before input/TR checks. Physical reference error and natural trigger-phase arm production remain unproved. |
| F8 / supported software path, physical hypothesis | PB05 digital LOW sampled in `0x8e18`; bare input/no MCU pull or debounce; external bias unknown | Noise/bounce/floating signal may be interpreted as active; short pulse may fall between polls | Pin/trigger evidence establishes code behavior, not a physically floating net. Continuous LOW accepts once then reload blocks further acceptance. Multiple motor firings from bounce have not been reproduced. |
| F9 / supported software path, physical hypothesis | PA02 sampled once in startup `0x6968`; HIGH analog, LOW digital | Cable/startup conditions can select different interpretation for the whole boot | Existing pin/boot witnesses. X does not change mode. PA02-to-jack electrical connection is UNKNOWN. Cable insertion causing a mode change is not demonstrated. |
| F10 / supported, timing unmeasured | Due-only acquisition, cached filter return, main-loop scheduling, synchronous startup/configuration waits | Pulse missed, acceptance delayed, stale filtered activity persists after release | Native deadline controls and full-startup traces; no trigger ISR path established. Acquisition clock is microsecond-scale, reporting clock millisecond-scale. Fake ticks do not measure loop jitter or capture bandwidth. |
| F11 / supported, medium | Startup waits for MC4; radio probe/reinitialization blocks or peers use mismatched channels; commands rejected by sequence guard | System appears powered/connected but trigger service or program/arm delivery is unavailable | Pass2 setup/no-peer, retained-A and duplicate-G controls. No MC4 means no normal loop service. Matching RF requests are not confirmed communications. Do not reinterpret flat-MMIO READSYNC stalls as field faults. |
| F13 / demonstrated, high | Analog input900 held through initialization, TR1 before MC4; raw returns225 at first report; later real TR0 | Acceptance after the physical-input model is already inactive | Corrected paired run accepts at filtered866/raw225; TR1 control never accepts by14M. A repeated MC4 packet after TR0 is disclosed; this proves a stale filtered decision at acceptance, not a timing specification. |
| F12 / plausible downstream, medium | Driver reset, configuration not applied, disconnected/disabled driver, or physical step path fault | Motion request exists but no movement, wrong scale or weak motion | Existing MC4/TMC evidence separates desired arrays from timestamp-gated apply and temporary boot400/16 settings. No electrical driver state, step waveform or motor outcome reproduced here. This is not an input-recognition fault. |

The paired filter-tail experiment establishes acceptance after the modeled raw
input returned inactive. This is a sampling/acceptance result, not a physical
timing claim. All new cases remain short of a motion request.

## Evidence sources and reconciliation

Use these current reports in precedence order:

- [Bring-up Pass2](autopilot-bring-up-pass2.md), continuous reset/ADC/program
  witnesses and negative controls; [Pass1](autopilot-bring-up-pass1.md), startup
  and historical witness revalidation.
- [X/acceptance](x-trigger-acceptance.md), band boundaries, guards, TR, reload
  and conditional helper fixtures; [motor/reference](motor-state-ownership-and-reference.md),
  ownership, targets, reference and MC4/driver distinctions.
- [Trigger dossier](trigger-input.md), underlying pin, native control-flow,
  filter and baseline evidence. Its older narrative is historical and qualified
  by the bring-up findings, rather than a current normal-startup model.
- [Firmware pin map](../hardware/firmware-pin-function-map.md), PB05/PA02
  software identity and incomplete physical routing;
  [hardware reference](../hardware/hardware-reference.md), documentary manual
  claims; [TMC reconciliation](../replacement/tmc5160-interface-reconciliation.md).
- [Memory-hook correction](write-watch-instrumentation.md). Pass1 replays
  startup/save witnesses; the repaired-hook audit replays selected motor/X/MC
  evidence. New runs use the corrected backend. Historical observations not
  replayed are not silently promoted to full-reset continuity evidence.

Corrections important to a misfire diagnosis:

1. Normal reset copies alpha0.05 into `0x20000014`. Zero-alpha helper fixtures
   can freeze their first value but do not establish that normal firmware does.
   The initialized flag `0x20003118` selects first-sample initialization; it is
   not a normal permanent sample latch. New pulse/step tests preserve reset data.
2. ADC acquisitions recur. A non-due call can return a cached value, and an
   acquired raw change can be filtered away. These are separate losses.
3. Both deadlines use the number500 but different clocks: `0xccdc` acquisition
   versus `0xccd0` reporting. Do not claim a500ms input poll period or a proven
   physical2kHz service rate from this model.
4. Repeated LOW acceptance under manually restored guards is conditional.
   Natural reload clears idle/changes channel state; continuous LOW does not
   establish a repeated-fire oscillator.
5. T telemetry is the filtered/rounded analog value and classification, not
   necessarily the instantaneous jack signal, ADC.RESULT, or accepted event.
   Absence of T between deadlines proves nothing about input absence.
6. “Trigger never causes motion” is too broad. The examined accepted reload
   is not a motion authorization; an earlier armed branch can request before
   the input checks. The natural trigger-specific arm lifecycle remains open.
7. The manual's cable-before-power “noise baseline” narrative is not a proven
   adaptive threshold algorithm. Existing native references identify the
   startup128-helper average at `0x20003128` and low flag `0x200023c0` without an
   established decision consumer. X branches install fixed bands. The old
   baseline findings are search-relative, not a whole-image proof of no possible
   indirect consumer. Cable timing could instead change mode/electrical bias;
   that alternative also needs measurements.

## State and failure-boundary map

| Boundary | State/read and transition | What failure would mean |
|---|---|---|
| Electrical → MCU input | Physical front end and bias → PB05 (digital alias57/analog59); PA02 alias37 chooses mode once | No jack-to-MCU transfer function, safe voltage threshold or revision-specific noise margin has been established. Manual jack ratings are not MCU ratings. |
| MCU → sample | Digital `digitalRead` level; analog ADC1.RESULT `0x43002040` through `0xd1b4`, due filter `0x42a4` | Poll phase, analog acquisition conditions and front-end settling can lose events before classification. |
| Sample → classification | Rounded filter at `0x20000190`; X `0x20000194`; analog outside inclusive band; digital LOW | No demonstrated separate on/off hysteresis or input release history in this gate. Configuration itself can change classification. |
| Classification → reported | TR flag and millisecond report deadline; original TX wrapper `0x8c10` | Diagnostic display is decimated state, not an event count. Reporting also inhibits acceptance. |
| Classification → accepted reload | `0x8f98`: marker `0x20001b38=0x7b`, channel bytes `0x20002524[4]=0`, idle byte `0x200000d8=9`, TR0 | Input can be active while eligibility is absent; eligibility can later arrive without a new edge. No shared physical-reference predicate is established. |
| Reload → prepared/authorized | `0x6e4c`, valid records `+0x44`, resync flags `0x20000134[]`, phase arms `0x20002318[]`; separate G `0x200025e0/e1` | Loaded record, resolved reference and arm are independent. Reload can consume eligibility without authorizing motion. |
| Authorization → request | Original `0x6fd8`; target-current using software `0x20002064[]`; independent earlier phase branch/G path | A request can arise independently of a contemporaneous trigger. Timestamp coincidence does not prove trigger causation. |
| Request → physical movement | Timers, interrupts, STEP/DIR, enable, applied driver settings and mechanics | Outside these execution witnesses. A correct request cannot prove a movement or electrical safety. |

## New execution and falsification design

[New packet](../../research/generated/trigger-misfire-2026-10-21/README.md)
contains ten exact direct commands (all exit0), native snapshots,88/88 scoped
artifact checks and provenance. The independent X2 replay is byte-identical.
All new cases reuse Pass2 `analog-program-acceptance`: full original868 reset,
Remote-built representative channel0 delta500 program bytes through the RX ring,
then native MC4. No G is delivered. No AutoPilot program, reference, threshold,
eligibility, arm, filter or initialized flag is seeded. The only treatment
changes are modeled ADC.RESULT values and real-format X/TR input bytes.

Common assumptions are inherited explicitly: MMIO completion/read-clear flags,
PA22 startup handshake, PA02 HIGH at mode selection, radio-ID return0x12,
instruction-paced fake ticks every4000 instructions, and the existing DWT delay
stub `0xcd34`. Packet placement in the RX ring models delivery, not RF. MMIO
ADC completion is assumed; an injected count is not a voltage. Watch/address
observations and normal implicit dirty hooks use `memory-hook-single-step`.
All runs stop before any `0x6fd8` execution if reached, otherwise at14M
instructions. Exit0 with `completed=false` is a bounded observation, not READY.
No original image, APTrace implementation, dependency or hardware is modified.

The one-acquisition pulse is constructed with900 supplied at setup return and
225 restored at every `0x8e7a`, after the filter returns. The first result259
and subsequent decay establish that exactly the first runtime high acquisition
influenced this sequence. This is a PC-timed external waveform assumption, not
an assertion about which real-world pulse widths would do so. The inactive
control has the same input225 throughout. Startup-active900 has no runtime
input edge. The X2 treatment leaves225 unchanged but supplies `X2|` at setup
return, after the first runtime phase visit. An independent identical X2 replay
checks reproducibility.

### Filter-tail and startup-order challenge

The initial `released-tail-*` pair intentionally retained setup-return TR1
placement. Both accepted900 at instruction12,079,178 with TR still0, **before**
the first T report at12,137,779. That pair cannot test post-release acceptance:
reload already consumed eligibility. It is preserved as an unsuccessful test of
that hypothesis and a positive startup-order witness. A packet being available
at setup return is not the same as its dispatcher having run before input service.

The corrected pair delivers program→TR1→MC4 through the native RX path. Native
TR store `0x8510`/post-store `0x8512` is resolved by the saved APTrace disassembly;
TR1 is observed at11,548,793 before MC4/setup completion. Both runs start with
ADC900 and change it to225 at the first T send `0x8f44` at12,103,349. The treatment
also supplies `TR0|` there; native TR0 is observed at12,140,891. At12,499,329 it
accepts with raw225, effective866, idle9 and all channel states0. The paired TR1
control has no acceptance. Neither requests motion by14M instructions.

`--force-mem` at the common post-TR PC also delivers MC4 again after TR0 in the
treatment. This is retained explicitly rather than silently described as a pure
single-packet ablation. The acceptance snapshot itself establishes the crucial
counterexample: current raw input can be inactive while original firmware
accepts a still-active filtered history after communications/gate processing.
It does not measure decay duration or isolate a universal TR0-to-acceptance delay.

These tests try to falsify three attractive explanations: “any acquired pulse
is sufficient,” “an edge is required,” and “X only adjusts immunity to the same
active polarity.” All three fail under the new original-code witnesses.
They do not falsify every possible event/arming path.

## Physical relevance, V1/V2 and smallest useful tests

No revision-paired trigger circuit, waveform, firmware-hash comparison or field
failure capture is preserved in the reviewed case evidence. The request does
not specify which revision is worse. No direction or hardware cause is inferred.
The known board photograph/revision is not evidence of two compared trigger
front ends. PB05's firmware identity is strong; its jack route is neighborhood/
probable evidence, and PA02's electrical relationship remains UNKNOWN.

For cable/noise-dependent intermittent behavior, the most relevant *physical
hypotheses* are front-end bias/marginal levels, pulse shaping, and startup mode
selection. The software has demonstrated ways to amplify those differences:
LOW is active digitally; either analog extreme is active; no release contract
exists at the reload gate; pulse attenuation depends on history. TR/program/arm
state is a strong alternative for a displayed trigger without movement. Those
are conditional matches to symptom categories, not a diagnosis of either model.

Prioritized discriminating tests, for a separately authorized bench session:

1. On each already-identified revision, use the same known trigger source/cable,
   firmware identity and X/TR/program state. Observe jack waveform and, only at
   an already confirmed safe accessible node, PB05; record PA02 level at startup
   if its access/routing is confirmed. Compare cable-before/after-power and idle
   versus one pulse. This distinguishes bias/mode changes from identical input
   processed differently. Do not assume a bare MCU pin is the jack input or
   apply the manual's high-voltage rating to a probe point.
2. With a clean repeatable source, compare short and held pulses at fixed X,
   then a marginal constant input with X1/X2. Record acquisition/classification
   separately from accepted-event indication. Use TR1 only in a diagnostic run;
   repeat in TR0 because TR1 changes operation. Width sweeps around the actual
   observed acceptance boundary distinguish front-end pulse loss from software
   attenuation; no width limit is prescribed from fake ticks.
3. Keep input asserted across startup/MC4 or a known program re-arm transition,
   then release before the transition in a paired control. Capture the state
   transition and request/STEP indication without requiring motor operation.
   This separates level-at-eligibility effects from edge capture or bounce.

No extensive new board survey is required. If safe MCU-node access is unavailable,
start with the jack waveform plus existing firmware diagnostics in separate runs;
that leaves the analog front-end transfer question unresolved rather than
assuming it away. Do not use simulation to authorize intact-Feather operation;
its previously identified QSPI/motor-pin conflicts remain unresolved.

## apfw2 implications (requirements candidates, not implementation)

- Model input mode, sample validity/age, active classification, event identity,
  armed eligibility, program validity, reference validity, request commitment
  and applied driver state separately. Report rejection reasons and the stage
  reached, rather than a single trigger/READY bit.
- Choose an explicit edge/level and release-to-rearm contract, including input
  already active at boot, enable, program load, X/mode change and recovery.
  Prevent a configuration change or cached pre-arm sample from silently becoming
  a newly authorized event unless the product deliberately requests that policy.
- Specify minimum pulse capture and maximum latency under load; validate against
  the real front end. Select filtering, hysteresis and debounce from that
  contract. A blanket debounce delay can make valid short-pulse loss worse.
- Keep diagnostic subscriptions passive; show raw/filtered/classified/accepted
  states and counters distinctly. Preserve legacy TR compatibility only with an
  explicit decision about its suppressing semantics.
- Validate the selected program and physical reference before motion, and make
  arm/reset/reload/resync transitions explicit. Deduplicate motion authorization
  separately from transport sequencing; a previously valid record or marker is
  insufficient. Invalidate/reapply driver state after driver initialization/reset.
- Do not copy the cold-fixture zero-alpha artifact, fixed X bands as universal
  electrical thresholds, or Noxon's software-zero-as-physical-reference assumption.
  Final electrical polarity, bias and timing requirements need bench evidence.

## Capability gaps, scope limits and next work

APTrace's existing native Ghidra and direct concrete interfaces were sufficient
for these bounded counterexamples; no framework extension was required.
The CLI's PC-timed MMIO/packet injection is reproducible but does not model a
validated asynchronous electrical waveform, autonomous ADC/timer/IRQ timing,
or physical peripheral completion. **Gap:** no validated timing/front-end model
in these witnesses. **Impact:** cannot rank pulse widths, jitter or field failure
rates. **Observed evidence:** instruction-paced fake ticks and explicit ADC/MMIO
injections. **Cause:** deliberate model boundary, not an observed firmware defect.
**Needed:** measured timing/waveform fixtures and, only if required later, an
exposed validated timed-input workflow. Priority medium for simulation; bench
measurement is the immediate evidence need, not permission to build a new model.

The natural external-trigger phase-arm/re-arm sequence is a remaining *firmware
evidence gap*, not demonstrated missing APTrace machinery. Highest-value next
APTrace work is one natural Remote auto/arm→trigger→request sequence, then held
input/release and STOP/reload controls, using current interfaces. Stop at request
entry. Resolve whether an already armed branch can produce a request following
disarm before interpreting it as a spurious trigger. No broad reconstruction,
915 equivalence, physical movement or release-gate promotion follows from this
investigation. Physical noise/revision causation requires new evidence, not
further confidence language about the current software traces.

## Targeted request campaign: an overlooked motion-initiation path

**Result:** a continuous original Remote-built program → AutoPilot reset/program/
MC4 → external analog trigger → original pulse-generation request is now
established. It uses the profile/rate-start route, **not** the G/phase-command
route through `0x6fd8`. No downstream arm, eligibility, position, filter, channel
state or timer-start value was seeded. No W or G is supplied in the successful
trigger cases. This materially corrects the initial pass's interpretation.

The [campaign packet](../../research/generated/trigger-request-campaign-2026-10-21/README.md)
contains commands, snapshots, native static queries, event extraction, checks
and hashes. The firmware remains the original868 image. These are software
requests and modeled register writes, not actual motor movement or measured
V1/V2 waveforms.

### Natural path and the mistaken boundary

The previous negative reasoning followed `0x5fac` and `0x8e18`, and treated
`phase_arm=0` / no `0x6fd8` as the decisive absence of motion authorization.
It missed the other scheduled branch of `sketch_loop`:

| Stage | Original behavior and observable state |
|---|---|
| Remote program | Original builder `0x49c4` constructs `+2,1,1,0,98,1,0,50,1000,500,0,0\|` from representative Remote record0. Only Remote delta500, ramp field50, timing source10000 and time-mode flag1 are seeded. These represent prior recorded UI state, not a full Remote boot or a newly traced physical gesture. The original builder divides the timing source by10. Units and full trajectory validation are not newly certified. |
| Native AutoPilot load | Full original reset receives those exact bytes in the RX ring at `0x94b8`, then MC4 at the original plus tail `0x81ca`. Marker becomes7b, record valid, idle byte9, channel state0. Radio delivery/completion assumptions are inherited from Pass2. |
| Input recognition and acceptance | With ADC225→900 at setup return and X1/TR0, effective587 reaches `0x8f98` at12,227,578 instructions. This is the actual input path, not a replacement command. |
| Profile preparation / eligibility | Accepted reload `0x6e4c→0x4b64→0x6b50` prepares coefficients and writes channel state `0x20002524[0]=1` and profile mode `0x2000310c[0]=1`; phase arm `0x20002318[0]` remains0 and idle becomes0. Both state cells matter. |
| Scheduled motion evaluation | The timed branch of `sketch_loop` selects channel states1/2/5 and calls `0x6338`. Its own switch reads **profile mode `0x2000310c`**, not the phase-arm byte. Mode1 evaluates the stored profile against elapsed time, derives signed rate/period and can initiate the channel when live flag `0x20001b14[ch]` is0. |
| Request / start boundary | In `profile-held`, the eleventh observed profile-service call reaches `0x5f8c(0)` at12,451,024. It executes `0x5570`, `0x5ee8(0)` (rate/timer setup) and `0x5810(0)` (timer enable), then writes live flag1 at PC`0x5fa4`. Stop at`0x5fa6`, instruction12,451,171, is **after** these original operations. Phase arms remain0; no `0x6fd8` is called. |
| Requested peripheral state | Channel0 timer pointer resolves to TC0 `0x40003800`; `0x5810` clears its interrupt flags and ORs ENABLE mask0x2 into CTRLA. At the stop, aligned CTRLA is`0x602`, period-like RAM `0x2000007c=0x2c3bc6`, converted period `0x200030e8=0x5877`, and captured timer CC word at`0x4000381c=0x5877`. These are requested register values, not measured timer frequency, pulse count or speed. |

The separate G/phase route remains real: Pass2's `0x6fd8(0,30,500,8119)`
request is not invalidated. It is simply not the only motion-initiation route.
The initial campaign's requests below mean a channel-specific entry to
`0x5f8c`, followed through the actual timer-enable/live-state write; they do not
rename a trigger report or a prepared profile as a motor request.

**Superseded conclusions:** the initial report's F6/F7 and state-map rows must
not imply that a separate G/phase arm is necessary after accepted reload.
Likewise the old trigger dossier's closure over state1's `0x5fac` consumer was
incomplete: `sketch_loop` has another consumer, `0x6338`, selected in a different
timing branch. “No commit” in earlier no-G witnesses means no `0x6fd8` entry,
not no timer start. `0x20001b14` is a live motor/rate flag, not a dead baseline;
new write watches identify a nonzero writer at`0x5fa4`. Broad historical negative
claims are withdrawn; their raw snapshots are preserved unchanged.

### Failure-mode matrix through the request boundary

All rows have native program validity/marker7b unless specified. “One start”
means one `0x5f8c`/timer-enable sequence in the stated bounded run. A start is
not proof of displacement500, correct direction, physical reference, or actual
movement. ADC counts and PC-timed changes are hypothetical external inputs.

| Input scenario / command name | Classification / acceptance | Eligibility and resulting request | Timing / scope |
|---|---|---|---|
| `profile-held`: baseline225 then held900 | Filter crosses X1 at587; one acceptance | Native state1/profile1, phase arms0; **one timer-start request** | Natural baseline; first start after11 profile-service calls. Independent replay byte-identical. |
| `profile-inactive`: constant225 | Inactive; no acceptance | Marker7b/idle9/state0 retained; **no start** |14M instructions, same program/MMIO setup. |
| `profile-single-pulse`: one acquired900 then225 | Peak259, then decay; inactive | No acceptance, no state1, **no start** |14M; a sampled pulse can be lost before motion authorization. Not a physical minimum-pulse measurement. |
| `profile-startup-active`:900 throughout startup | Active on first runtime processing; no runtime edge | Acceptance then **one start**, without W/G | Demonstrates level-at-eligibility can initiate requested pulse generation. |
| `profile-x2`: unchanged225, native X2 |225 is inactive under X1, active under X2; one acceptance | **One start** without an input edge | Same nonzero timing/ramp program as baseline. Configuration-induced reclassification propagates beyond reload. |
| `profile-low-excursion`:225→0 |214,203,193; accepts193 | **One start** | Same nonzero timing/ramp program as baseline. The earlier delta-only `rate-low-excursion` also starts, but its period clamps to20; it is not the principal trajectory control. |
| `profile-tail`: raw900→225 at first T send; real TR0 later | Filter still866 when accepted, raw225 | **One start** after inactive raw input | TR1 is processed before MC4. Common post-TR injection queues another MC4 after TR0; preserved/disclosed as in the original tail test. |
| `profile-sample-aligned-pulses`:900 before filter call,225 after its return on every visit | Acquisitions see high samples and integrate like held900 | **One start**, same instruction boundary/register outcome as held control | Repeated short modeled excursions can accumulate. Exact sampling correlation is adversarial/hypothetical, not measured contact bounce or a waveform assigned to either board revision. |
| `profile-opposite-phase-pulses`:225 before filter call,900 after return on every visit | Acquisitions stay225 despite between-call highs | No acceptance, **no start** | Same two levels and program, different phase.14M. Poll-relative event placement, not equal-duration/equal-energy physical pulses. |
| `profile-held-continuation` | One accepted event; sustained active input | One start through14M, no repeated acceptance/start | Period updates are not counted as duplicate requests. State1/idle0 continue to block reload. |
| `profile-release-continuation`: input returns225 at acceptance | Filter later returns inactive | One start through14M, same requested timer-state outcome as held continuation | Release does not cancel an already accepted profile. No automatic physical-stop conclusion follows. |
| TR1 active control from prior pass | Active T reporting, no accepted reload | No prepared state1 on this path | Prior concrete evidence retained; not represented as a newly rerun nonzero-profile request control. |

The two-phase pulse experiment is a bounded surrogate for plausible narrow
pulses/chatter at the **sampled-input** boundary. It demonstrates phase sensitivity
and accumulation, not a quantified susceptibility to actual electrical bounce.
It does not justify assigning “aligned” to V1 or “opposite-phase” to V2.

### W controls, completion and re-arm boundary

The initial search for the missing arm used only original command processing:

- Original Remote `0x591c(0)` uses flash string `W|`; Remote `0xb79c` uses
  `W1|`. Native AP disassembly resolves bare-W dispatch to`0x8628..0x866a` and
  W1 to the shared reload at`0x8624`. Flash string extraction and builder paths
  are static evidence; a paired Remote send/ACK exchange was not simulated.
- `w-without-trigger`: bare W at idle9 does not arm or reach0x6fd8. Its
  idle guard takes a different branch; a W packet is not a universal arm.
- `w-after-trigger`: queued W after natural acceptance sets phase arm1 at
  `0x865a`, then phase2. Profile processing has meanwhile set live flag1 at
  `0x5fa4`; phase1 calls stop helper`0x5274(0,4)`, which writes stop-request1
  at`0x2000309d`, and phase2 waits at`0x8fae` because `0x20001b14[0]=1`.
  The final live/stop flags are1/1 and no `0x6fd8` occurs. This does **not**
  block the earlier profile-rate start; it blocks the separate phase request.
- `w1-then-w-without-trigger` reaches phase arm2 without an
  external trigger, because W1 itself invokes the profile preparation path.
  This prevents misattributing all later activity to an external event.

A later [VVR correlation](vvr-trigger-failure-correlation.md) now extends the
same profile past natural completion: stage transitions finish near52.25M,
channel/live clear, idle2. Supplying native W at completion reaches idle9 and a
second timer initiation under held active input; the matched released-input
control reaches idle9 with no second initiation. This closes time-based profile
completion and conditional command-driven re-arm for the simulated zero-position
case. A natural Remote exchange and nonzero physical return remain unproved.
No phase/busy/idle cells were forced. The22M outcome below was an insufficient
duration bound, not proof that completion required an unmodeled IRQ.

A complete release→completion→natural re-arm→second trigger sequence was not
established by the original runs below. Held/released continuations demonstrate no duplicate
start only within their observed eligibility state; an absence of duplicates
before re-arm is not a debounce proof. The22M held extension still has one
acceptance/start, channel/profile mode1, live flag1, idle0 and phase arms0;
7,823 watch hits remain below its8,000 cap. The exact missing transition is
profile/channel1→completed/idle9→new-event eligibility. Its cause is not yet
isolated: the actual profile-stage duration/deadline and completion predicates
must be checked before attributing the lack of completion to missing IRQs.
No automatic timer IRQ, actual counted
STEP pulse or motor-position progression is supplied by the direct CLI fixtures.
The backend has a documented narrow `deliver_interrupt()` facility, but the
CLI does not expose a validated autonomous timer schedule for this continuous
scenario. A separate cold ISR witness or clearing busy/idle by force would not
supply the missing continuous completion evidence. No such state seeding or
custom interrupt/waveform runner was introduced.

### Practical implications and remaining work

The campaign now promotes startup-active input, X reclassification, filtered
history after release, and sample-aligned repeated excursions from mere reload
hypotheses to **demonstrated software timer-start mechanisms**. A single acquired
short pulse and opposite-phase pulses do not reach that boundary under their
controls. No duplicate start or physical V1/V2 cause is established.

For apfw2, guard every pulse-generation route, not only an explicit distance
command. Apply the same event ownership, arm/program/reference checks and
cancellation policy to profile playback and direct moves. Diagnostics and X
changes must have an explicit relationship to already-filtered input and arming.
Specify whether release cancels, consumes, or merely rearms an event. Distinguish
rate updates of one move from duplicate authorizations. Never derive physical
reference validity from a software counter or timer-enable write. These are
requirements candidates; no implementation changes were made.

Execution comprised26 direct native commands, all exit0/error-free, with191/191
scoped artifact checks. The Remote builder is a hook-free continuous run;
observed AutoPilot runs use memory-hook-single-step. A first analysis check
incorrectly expected the Remote mode to match AP and was corrected against the
documented hook-selection behavior, without changing execution. Exact snapshots
and request-boundary outcomes are preserved; no new ledger admission or release
grade is asserted.

Highest-value remaining evidence is continuous profile completion and natural
eligibility restoration with original timer/stop processing, followed by a second
clean pulse, held input, and release-before-rearm controls. Existing APTrace
static queries can identify the exact busy-clear/idle-restoration path; an
existing supported scenario must also expose reproducible state-preserving
interrupt/time delivery before claiming repeat-event coverage. **Capability gap
(priority high for duplicate/re-arm conclusions):** the selected direct-CLI
workflow provides PC-timed external changes and register completion assumptions,
not a validated continuous motor timer/IRQ/completion environment. The reusable
backend's narrow interrupt API exists; this is a scenario/interface and validation
gap, not evidence Unicorn cannot execute the handler. New waveform scheduling or
peripheral implementation would require a separate APTrace development task.
Physical revision timing/bias still needs new measurements, but boards were not
needed to establish the first software request path and these input counterexamples.
