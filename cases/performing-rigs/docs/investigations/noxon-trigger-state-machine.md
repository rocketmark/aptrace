# Original Noxon trigger state machine and formal counterexamples

Target3 qualification: [motion route coverage](motion-initiation-route-coverage.md)
now demonstrates B1 before MC4, W1 without trigger acceptance, and G continuing
through the common evaluator to timer enable. Local catch-up and group-service
runs also emit STEP writes outside a new timer-start action. The model is a
selected trigger-history model, not a complete initiation graph. Recommended
producer/output and concurrency corrections are documented separately; no TLA+
source or proposed controller was silently changed.

Target2 qualification: [bounded binary reachability](trigger-symbolic-reachability-target2.md)
now supports digital pre-read guards and captured-R0 branching with feasible
SAT/UNSAT companions. The original gate precedes digitalRead, while this model's
classification/gate action is atomic. Existing projections assume no intervening
state writer; asynchronous correspondence would require a demonstrated producer
and finer gate/acquire/decide states. No new analog-history or profile-progress
symbolic theorem is claimed. The TLA+ sources and proposed controller are unchanged.

2026-10-22. **Result: a separate, bounded descriptive TLA+ package matches 20
original-firmware trigger histories and four direct-G endpoint controls.** It
exposes native-backed starts from preexisting active input, X reclassification,
retained analog history and a sampled digital LOW after GPIO release. Short
pulses can fail to initiate because of acquisition phase or filter attenuation.
These are counterexamples to **proposed** safety/progress requirements, not proof
that Noxon violates a published product specification or causes a particular
physical misfire. Completion, repeated-event re-arm and STOP/reset guarantees
remain unresolved.

[Package](../../specifications/noxon-trigger/README.md),
[model](../../specifications/noxon-trigger/NoxonTrigger.tla),
[trace correspondence](../../specifications/noxon-trigger/trace-correspondence.json),
[results](../../specifications/noxon-trigger/verification/results.json),
[counterexample logs](../../specifications/noxon-trigger/verification/).
The existing proposed controller is unchanged; source hashes are preserved and
checked. No apfw2, APTrace framework, original binary, ledger, release gate or
physical device was modified. No new firmware execution was necessary.

## Evidence selection and corrections

The current model uses [powered-connection evidence](powered-trigger-connection.md),
[the request campaign](trigger-misfire-failure-modes.md#targeted-request-campaign-an-overlooked-motion-initiation-path),
[X/acceptance](x-trigger-acceptance.md), [trigger-input](trigger-input.md),
[bring-up Pass1](autopilot-bring-up-pass1.md)/[Pass2](autopilot-bring-up-pass2.md),
and [motor/reference state](motor-state-ownership-and-reference.md).
The [prior formal verification](../../specifications/trigger-acceptance/VERIFICATION.md)
is a proposed controller, not a recovered original implementation. Its tiny
`NoxonWitness.tla` was only an illustrative three-case abstraction; this package
provides a separate, substantially more detailed replay-validated model.

Two superseded interpretations must not enter this model:

1. Normal reset initializes filter alpha **0.05**, not zero. A first due sample
   initializes history; subsequent due acquisitions update it. Historical cold
   zero-alpha helper runs do not establish normal permanent first-sample freeze.
2. No `0x6fd8` request or phase arm does **not** mean no motion initiation.
   Scheduled profile evaluation `0x6338` can call `0x5f8c` and enable the timer.

Native image: `firmware_autopilot868.bin`, SHA256
`6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3`.
Source packets:

- [trigger request campaign](../../research/generated/trigger-request-campaign-2026-10-21/README.md): full reset, original Remote-built nonzero profile,
  MC4, original analog path and profile initiation, including negative controls.
- [powered input campaign](../../research/generated/powered-trigger-connection-2026-10-21/README.md): digital sampled/unsampled/released inputs and normal analog startup tails.
- [Pass2](../../research/generated/bring-up-pass2-2026-10-21/): fresh/duplicate/no-G and trigger-HIGH direct request controls.
- [X packet](../../research/generated/trigger-x-semantics-2026-10-20/): native classifier/filter instructions, guard tests, invalid-record reload evidence. Older conditional helper tests remain conditional.

These continuous principal witnesses use the corrected memory-hook execution
path. PC/instruction schedules, fake clocks, plain-MMIO completion assumptions,
radio-ID return and DWT delay stub remain simulation assumptions. RX ring packet
injection is not proof of RF delivery. Input levels are hypothetical MCU-visible
histories, not measured V1/V2 waveforms or jack-voltage transfer functions.

## Recovered transition and lifetime map

| Stage | Original state/read/write and transition | Formal representation / boundary |
|---|---|---|
| Startup mode | `0x6968` reads PA02 once; HIGH→mode1, LOW→mode2 at `0x20001fc0`. PB05 serves analog59/digital57. X does not select this mode. | Mode constant per native fixture. Physical mode wiring and startup electrical classification remain unknown. |
| Setup/program | MC4 clears setup flag `0x20000060`; plus program produces marker `0x7b` at `0x20001b38`. Before setup exit, normal trigger polling is unavailable. | Native observed producer outputs enter as subsystem-boundary events; boot and Remote protocol are not independently regenerated in TLC. |
| Physical input changes | GPIO1.IN `0x410080a0` bit5; ADC1.RESULT `0x43002040`. | `raw` events independent of acquisition; explicit PC/instruction anchors. No electrical RC or physical-time model. |
| Analog acquisition/history | `0x42a4` deadline `0x20003124`, clock `0xccdc`, interval500. At `0x42d4`, r0 is native ADC acquisition. Float/flag `0x2000311c`/`0x20003118`; initialized alpha at `0x20000014`. | Actual ADC acquisition, serial and returned filtered integer tracked separately. Cached returns need not be new acquisitions. Native numeric returns are an oracle, not a new float implementation. |
| Analog interpretation | Return at `0x8e7a`, copied to `0x20000190`. X at `0x20000194`: X1 inactive inclusive200..580; X2 inclusive250..750. Either side outside is active. X changes preserve filter history. | Classifier computed independently from integer and X; current raw need not agree. Valid X1/X2 only. Invalid stored values default to1 per prior evidence, outside this replay scope. |
| Digital acquisition | `0x9228` calls `0xd3dc`; comparison at `0x922c` uses captured r0. LOW active; current GPIO may already be HIGH. | Captured digital result distinct from current raw GPIO. No invented debounce, release qualification or second-read cancellation. |
| Shared acceptance | `0x8f98`: setup exited, marker7b, all four channel bytes `0x20002524[]` zero, **byte** `0x200000d8` equal9, `0x20003120` TR flag0, input classified active. | Gate computed independently. Channel word is an aggregate “all zero” condition in these channel0 scenarios. No independent physical-reference/driver-ready guard is inserted. |
| Diagnostics | TR1 can report active T while inhibiting acceptance, even when reporting is not due; TR0 can expose existing filtered history. | TR gate included. The tail fixture has a second MC4 injection after TR0; it is not a clean isolation of TR0 alone. |
| Accepted reload | `0x6e4c→0x4b64→0x6b50` uses truthy record+0x44, prepares targets/profile data, channel state1/profile mode1 `0x2000310c[]`, idle0; clears phase arms `0x20002318[]`. | One valid nonzero record/channel0. Accepted reload changes profile eligibility. Individual invalid-record handling is documented separately; it is not represented as a universal trigger veto. |
| Profile initiation | Main loop `0x93fc` schedules `0x6338`; evaluator reads profile mode, time/profile and live state. `0x5f8c→0x5ee8→0x5810`, original TC0 ENABLE and live1 write at `0x5fa4`; stop `0x5fa6`. TC0 `0x40003800`, CC0 `0x4000381c`. | Rate-call opportunity is a native evaluator oracle. State/provenance, request, enable and live transitions modeled separately; final actual ENABLE bit checked. **TLC does not independently calculate the evaluator deadline/rate.** |
| Direct G | Fresh shared sequence G011 sets G arm2 at `0x200025e1`, phase0 then1 at `0x200025e0`; target-current yields `0x6fd8(0,30,500,8119)`. TC READSYNC completion required. | Separate `DirectG.tla`; fresh-sequence and target arithmetic checked for four native cases. Rate8119 is a native parameter oracle; endpoint is request entry, not timer activation. |
| Running/completion | Observed state1/live1/idle0 blocks another shared reload.22M held run still has one start and no recovered natural idle9 restoration. | Replay continues within this observed busy window. No invented Complete→Armed transition. |
| STOP/reset/re-arm | Cold reset/initialization known; continuous accepted/running STOP/reset and complete re-arm paths not established. W phase stop-request path does not prove physical stopping. | Deliberately outside transition relation. Their safety properties are unresolved, not vacuous passes. |

Software position0 and a truthy motor record are not physical homing. Desired MC4
settings, applied driver register requests and actual driver readiness are distinct.
The model does not invent reference-valid/driver-ready booleans for the original.

## Validation before safety interpretation

`project-fixtures.py` reads existing native artifacts, preserving source hashes.
It emits separate input events and expected output checkpoints. The model uses
input mode, physical input changes, acquired ADC/digital values, native filtered
returns, upper-layer producer boundaries and the evaluator/call schedule. It
**computes** active classification, shared acceptance count, pending reload,
profile eligibility, idle/channel state, request count, timer and live state.
Checkpoint expectations never assign these modeled outputs.

The 20 histories cover held/inactive/single pulse, two acquisition phases of
repeated pulses, startup-active, X2, TR/filter tail, release after acceptance,
extended busy hold, low-side excursion, digital idle/preexisting LOW,
sampled/unsampled/setup-only transients, a post-inactive digital LOW, analog
setup-only excursion/startup tail/marginal600. Every projected transition has
its original PC/instruction anchor in `trace-correspondence.json`. Intermediate
acceptance/profile/rate/enable state and endpoint channel/idle/live/ENABLE are
checked. `Correspondence.cfg` completes with10,046 distinct states, including
20 initial states and10,026 projected steps. No additional interleavings are
explored; counts are model states, not firmware trials.

Three mutation controls reject materially incorrect abstractions:

- Requiring current raw active at the digital acceptance gate contradicts the
  sampled-LOW/current-HIGH witness.
- Freezing the filter at its initial integer contradicts the held analog fixture.
- Requiring current raw active in the analog acceptance gate contradicts the
  retained-history tail fixture.

All fail `Correspondence`, as intended. A matched replay is stronger than an
unvalidated plausible misfire model, but remains a **partial trace correspondence**,
not instruction refinement. Numeric filter returns and evaluator deadlines/calls
are native oracles. In particular, native `0x5f8c` supplies the modeled due-rate
opportunity: the model checks its recovered state dependencies and later enable
outcome, but does not independently predict an arbitrary profile's start time.
Original execution is the evidence that these opportunities occur.

`DirectG.cfg` compares four additional native endpoints: fresh G with LOW,
fresh G with HIGH, absent G, duplicate G sequence0. Fresh cases yield exactly
`<<0,30,500,8119>>`; controls yield no request and no G arm. This bounded branch
is not a complete G parser, protocol automaton or timer/driver model.

## Failure matrix and shortest useful counterexamples

Full TLC states are retained in named logs. The following sequences collapse
repeated polls and unrelated native instructions; they are the shortest useful
**explanations**, not claims of minimum physical duration. BFS finds the first
violation in each selected finite history, not the shortest history of every
possible binary execution. Instruction counts are scheduling witnesses, not ms.
All positive rows below have corresponding original-code initiation evidence.

| Desired property / check | Shortest useful native-backed sequence | Result and endpoint |
|---|---|---|
| Fresh post-readiness qualifying event (`Startup`) | ADC900 already at boot → program/MC4 eligible → first active900 → accept → reload → rate/enable/live | **FAIL**, accept12,103,180; live12,337,024. No post-readiness inactive/new electrical episode. Also digital LOW held across eligibility starts. |
| Config cannot manufacture a new electrical event (`Reclassification`) | Constant225 under X1 → X2 → same225 now low-side active → accept → profile start | **FAIL**, accept12,136,945; live12,363,529. No electrical change. X is intentionally a classification setting; “must disarm” is a proposed policy. |
| Current raw must still be active (`FilterTail`) | TR1/history900 → raw225/TR0 (and second MC4) → filtered866 active → accept → filtered455 at start | **FAIL**, accept12,523,334; live12,757,495. Raw input has returned inactive; filter history opens the gate. Not proof TR0 alone causes this transition. |
| Current classification must remain active (`DecayedClassification`) | Same tail → accept866 → filter decays through inactive band before evaluator start → enable | **FAIL**, filtered455 at start. Original profile commitment survives loss of active classification. Cancellation-on-release is a proposed contract, not necessarily Noxon's intended behavior. |
| Startup history must not authorize after release (`StartupTail`) | ADC0 during startup → raw225 before runtime → filtered11 → accept → filtered148/start | **FAIL**, accept12,103,173; live12,337,017. Normal alpha0.05 does not eliminate retained startup history. |
| Current GPIO must be LOW at initiation (`SampledRelease`) | LOW during digitalRead → HIGH before comparison → captured r0=0 → accept → reload → enable/live | **FAIL**, sampled/compared12,098,771, accept12,098,773; live12,327,152. This is a captured sample consequence, not proof firmware can know the intervening physical release. |
| Release after acceptance cancels initiation (`AcceptedRelease`) | Analog step → filtered587 accepted → raw225 at accept → filter355 → evaluator starts | **FAIL**, live12,451,170; one start through14M. Again a proposed cancellation policy, not established product intent. |
| Every short pulse eventually initiates (`ShortPulse`) | One acquired900 amid225 → filtered259 then257…225 → never outside X1 → no accept/start | **FAIL temporal claim**, no start by14M. Completion of finite replay stutters; not proof no future input could ever start it. Pulse does not satisfy replacement's qualification contract. |
| Every electrical pulse is recognized (`UnsampledPulse`) | GPIO HIGH when read, LOW after comparison → no acquired LOW → no accept/start | **FAIL temporal claim**, no start by14M. Neither controller can promise detection of an event with no acquisition witness. |
| Repeated excursions cannot accumulate | ADC900 at each acquisition,225 between → native filter same259…587 as held → start | **Native/model reproduction** of initiation, same held start boundary. Opposite acquisition phase yields225/no start by14M. No physical pulse-energy equivalence or V1/V2 assignment. |
| No duplicate initiation for one episode | Hold input through observed state1/live1/idle0 window | **PASS only in replay window** through22M: one acceptance/rate/enable/live. No completion or natural re-arm; not a debounce or recurring-episode proof. |
| Program/session marker required | Shared gate marker==7b | **PASS on these traces**; supported by prior static/guard evidence. All natural principal fixtures have valid marker at runtime; this suite alone does not establish invalid-program rejection nonvacuously. |
| Initiation has prepared profile provenance | Accepted reload → state1/profile1 → due-rate oracle → enable/live | **PASS within fixture assumptions**, not a universal “all motion is trigger-authorized” property. Independent G intentionally bypasses trigger activity. |
| Invalid record/reference/driver prevents motion | Truthy record vs physical reference/driver state | **UNRESOLVED as a physical safety property.** Prior invalid-record helper can accept shared reload without preparing channel0; these natural profile fixtures use valid record. No physical reference or driver-failure oracle is available. Missing independent checks are not evidence of actual invalid physical state. |
| STOP/reset discard old accepted events | Requires continuous accepted/running STOP/reset trace and later scheduler behavior | **UNRESOLVED**, action excluded rather than fabricated. |
| Accepted event makes legitimate progress | `accepts>0 ~> starts>0` for selected original histories | **PASS conditional** on the recorded evaluator opportunities, MMIO completions and fair finite replay. It does not prove every accepted original program eventually starts. |

These counterexamples are invariant/temporal failures in TLC, with native witnesses.
No SMT query or UNSAT claim is involved. Native TC enable/live writes mean a
software pulse-generation initiation; no row proves STEP edges or movement.

## Comparison with the unchanged proposed controller

`ReferenceReplay.tla` imports the existing `TriggerAcceptance.tla`; it does not
edit that model. It uses the same sampled digital results and ADC acquisition /
filtered-return histories, valid X mapping and producer-boundary ordering.
Numeric ADC acquisitions at `0x42d4` carry serials; cached analog returns are not
fed as newly acquired observations. Physical GPIO changes not sampled by firmware
are **not silently supplied as new reference observations**.

For this comparison only, independent program/reference/driver validators are
assumed successful after native program/MC4 boundaries. This is an optimistic
readiness assumption, not proof MC4 establishes physical reference or driver
health. The adapter marks newly acquired observations current/history-valid,
uses K=N=1 and age0 delivery, no expiry ticks, and promptly processes/accepts/
starts a profile when permitted. It omits physical completion and does not model
the original evaluator latency. It therefore compares acceptance policy under
finite histories, not end-to-end timing or a coupled hardware implementation.

With those assumptions, the reference starts once for
`digital-connection-after-inactive-sample` (HIGH sample then LOW); all other
selected histories end without a reference start. The original starts in13 of
20 histories. The comparison checks expected endpoint counts, original reference
safety invariants/action properties and finite replay completion. It provides
these practical distinctions:

- Startup-active and X2 reclassification are rejected until new inactive
  qualification; filtered/raw disagreement does not create a reference event.
- The original digital sampled transient has no prior post-ready inactive sample,
  so the reference rejects it for lack of qualification. **This comparison does
  not prove the reference detects its unobserved physical HIGH.** Once armed,
  an otherwise identical intentional contact/connection sample can still be
  accepted; fresh HIGH acquisition before Start is needed for known-release
  cancellation. Positive connection-after-inactive illustrates this information
  limit, rather than a universal connection-transient cure.
- One acquired analog pulse and wholly unsampled digital excursions do not get
  a reference progress guarantee. Desired minimum duration, sampling deadlines,
  K/N and acceptable delay still need engineering decisions.
- Held analog/marginal600 inputs already active at eligibility are intentionally
  suppressed without a fresh inactive interval, even if Noxon users consider
  those legitimate starts. Reset/config barriers change that product contract.
- TR reporting is passive in the proposed controller. Noxon uses it as an inhibit;
  compatibility needs an explicit decision. These traces do not isolate every
  diagnostics-only history as a reference comparison.
- G is an independent manual command. The reference's shared **trigger** grant
  for profile/direct backends does not specify how to authorize manual G. Calling
  every G-with-HIGH request a trigger-safety violation would be incorrect.
- Duplicate-after-completion, physical STOP/reset execution, adapter timestamp /
  history honesty, reference validity and physical driver readiness remain
  unverified for the original; the reference has finite modeled policies with
  external implementation obligations, not physical guarantees.

## Execution, reproducibility and model review

Existing APTrace concrete/static evidence supplied all firmware facts; this pass
performed read-only artifact projection and case-owned TLA+/TLC execution under
the user's explicit formal-verification assignment. It introduced no substitute
firmware interpreter or analysis backend. The pinned existing TLC2 2.19 jar and
Java21, exact configurations, runner commands, exit/diagnostic checks, source
hashes and full logs are in the package. Jar hash is checked against the previous
package. Expected safety counterexamples exit12; temporal counterexamples exit13;
clean correspondence/comparison checks exit0. All15 final checker experiments
match their expected outcomes: three positive checks (10,046 descriptive states,
20 direct-G states,18,725 reference-replay states), seven safety counterexamples,
two progress counterexamples and three correspondence mutation counterexamples.
Sixteen artifact/provenance checks pass, including86 unchanged prior-reference
files, the pinned jar and post-MC4 acquisition provenance for each analog fixture.

Model-review failures are retained, not counted as firmware findings:
`initial/Reclassification-monitor-mismatch.log` passed an incorrect event monitor
that treated threshold reclassification as a fresh electrical event. The monitor
now records a physical inactive→active change separately. The descriptive gate
was unchanged. `initial/ReferenceReplay-unassigned.log` diagnosed incomplete
successor assignments caused by IF expression scope; parentheses corrected the
replay driver. `initial/DirectG-forward-reference.log` preserves a definition-order
error. Several initial shell commands used the wrong working directory and failed
before running a checker; commands were corrected. A process-list diagnostic was
denied by the sandbox; no bypass was attempted. An optional Python compile check
could not write the system-selected cache outside the workspace; an in-memory
syntax check passed instead. These do not affect native evidence.

## Capability gaps and next work

**High: continuous completion/re-arm evidence.** The direct execution fixtures do
not provide a validated autonomous timer/IRQ/completion schedule. Original native
22M still retains state1/live1/idle0. Existing APTrace static queries should first
identify exact profile duration/completion predicates and idle restoration. Then
use a supported continuous scenario to test completion→release/held→second event,
plus accepted-pending/running STOP/reset controls. Do not force-clear busy state
and call that natural completion. A validated CLI interrupt/peripheral scenario
may require subsequent framework work; this investigation does not implement it.

**Medium: formal refinement/orchestration.** APTrace exposes native/static evidence,
but no automatic admitted binary-to-TLA simulation relation or numerical filter /
profile proof workflow. User-authorized case models provide bounded comparison,
not a general new APTrace proof capability. Needed improvement: provenance-aware
trace projection/validation and supported profile-clock/ISR scenarios. This is
separate development, not silent operator replacement of missing analysis.

**New evidence: electrical transfer and intent.** Minimal synchronized jack/PB05 /
PA02 captures around connection and intentional triggers remain the right bench
discriminator. No waveform is assigned to V1 or V2. Identical MCU histories remain
indistinguishable in both models. Physical stopping and actual motor/driver health
also need independent evidence; no physical experiment was performed here.

The replacement-design implication is to make qualification, acquisition epochs,
configuration barriers, diagnostics policy, event ownership and cancellation
explicit across every trigger-driven backend. Choose release-before-start policy
and minimum pulse contract deliberately. Do not copy software-zero-as-reference,
confuse reporting with acceptance, assume phase-arm0 means no profile start, or
claim debounce/duplicate safety before continuous completion/re-arm is established.
This is a factual/formal assessment; no replacement controller was implemented.
