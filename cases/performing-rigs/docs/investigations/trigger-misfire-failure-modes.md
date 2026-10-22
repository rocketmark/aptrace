# AutoPilot trigger misfires: failure mechanisms and discriminating tests

2026-10-21. **Partial answer: several software mechanisms can suppress, delay,
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
