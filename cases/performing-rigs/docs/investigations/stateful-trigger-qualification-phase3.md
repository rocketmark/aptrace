# Phase 3 — Stateful external-trigger qualification

**Simulation research only. All generated firmware is NOT FOR HARDWARE DEPLOYMENT.**

## Investigation result

A second actual AutoPilot915 binary now enforces a common digital/analog,
single-use trigger policy. This is a working experimental subset, with bounded
native execution evidence; overall mitigation remains **PARTIAL**.

1. **Connection-like transients:** yes within the tested acquisition histories.
   The patch rejects a nominal 10-tick digital excursion, the historical
   saved-LOW/current-HIGH witness, and release at the final authorization entry.
   A fresh nominal 500-tick pulse still initiates. These histories do not cover
   every physical insertion waveform or interrupt schedule.
2. **Held input after W:** yes in the demonstrated lifecycle. One supplied W
   after completion, or during execution followed by STOP/return, restores
   eligibility without authorizing a second held-input start. A qualified release
   and fresh activation subsequently authorize a second start.
3. **Lifecycle and motion coexistence:** functionally demonstrated for the tested
   program/MC4, natural completion, W return and direct G/W1/B1 routes. Exact
   trigger-driven motor-output preservation is **not established**: initial
   timer period and full captured write streams differ. Continuous STEP output
   remains outside the supported continuation.

The patch does not distinguish a sustained electrical fault beginning after
arming from an identical legitimate activation. Release after its commit point
also remains accepted. Neither result is hidden by redefining acceptance.
No autonomous completion-to-W sequence or physical motor movement is claimed.

## Starting evidence and scope

The [Phase 1 state map](remote-autopilot-execution-lifecycle-phase1.md) and
[Phase 2 histories](remote-autopilot-execution-lifecycle-phase2.md) separate idle2
completion from W-driven restoration of idle9. Their four original no-W histories
remain the evidence against an autonomous loop in those particular runs.
The [VVR correlation](vvr-trigger-failure-correlation.md),
[motor-output baseline](vvr-trigger-motor-output.md),
[first-patch handoff](noxon-trigger-engineering-handoff.md) and completed
[Gate 1](trigger-patch-gate1.md), [Gate 2](trigger-patch-gate2.md),
[Gate 3](trigger-patch-gate3.md), [Gate 4](trigger-patch-gate4.md)
remain separate evidence. Their classifications have not changed. No gate was
reopened; Gate 5 was not run. No apfw2, original image, first patch, formal model,
APTrace implementation or framework test was modified.

The [evidence packet](../../research/generated/stateful-trigger-patch-2026-10-22/README.md)
contains source, generator, binary, native snapshots, independent Ghidra listings,
modification manifest and saved-artifact checks. The only executable registry
change adds the case-local `autopilot915_stateful_research` image key.

## Policy and recovered lifecycle

Qualification is separate from eligibility. Poll entry at `0x8e18` now acquires
input and updates a persistent state machine before the original function body.
Both original external trigger branches converge at `0x8f98`; a common gate
there can veto before the original queue1 store at `0x8f9c`. Entering `0x8f98`
is therefore **not** counted as acceptance in patched runs.

| State | Meaning | Transition |
|---|---|---|
| 0 | Need inactive | Inactive sample starts state1 |
| 1 | Qualifying inactive | 50 firmware ticks of sampled inactivity arms state2 |
| 2 | Armed | Fresh active classification while eligible starts state3 |
| 3 | Qualifying active | 50 firmware ticks of sampled activity produces state4 |
| 4 | Qualified, unconsumed | Final fresh acquisition and gate checks consume to0 |

Digital LOW is active, using the original `digitalRead(57)` helper at `0xd3dc`.
Analog classification uses the original filter `0x42a4` plus a fresh raw
`analogRead(59)` at `0xd1b4`. Both must classify inactive to arm and active to
qualify/commit. Inclusive inactive bands are X1 `[200,580]` and X2 `[250,750]`.
Raw-active/filter-inactive may wait armed for the filter; the opposite mismatch
invalidates the candidate. Unsupported modes/X values fail closed.

Context changes in mode, X, program marker or TR invalidate qualification;
TR nonzero disables it. The program-transfer tail at `0x81d0` explicitly clears
state and remembered mode before forwarding the original printf tail. A poll
gap greater than20 ticks invalidates state. Invalid state values above4 reset.
These are finite defenses, not general corruption detection.

Inactive qualification can occur while execution is ineligible. Active input
while ineligible resets qualification rather than queuing an event through busy.
Thus W and idle9 alone cannot mint an authorization, while release-to-rearm is
independent of Remote eligibility. Original setup, channels, marker, idle and TR
gates remain in effect. At grant, the patch rechecks setup-complete, channels0,
marker123, idle9 and TR0, mode/X context and acquisition age.

The final gate saves registers, reacquires input, checks age, saves PRIMASK,
masks interrupts, rechecks eligibility/context, consumes authorization and
increments a diagnostic consumption counter. The **commit store is `0x15696`**;
label `commit` at `0x15694` precedes it. PRIMASK is restored before returning to
original `0x8f9c`. ADC work is outside the masked region. This does not cancel
motion after commitment or introduce STOP on subsequent release. Physical input
can change after the last read; the critical region cannot make electrical
acquisition and later initiation physically atomic.

## Binary architecture, storage and verification

Exact source915 SHA-256:
`0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920`.
First patch SHA-256:
`ae9e6a749426fc3d800a0e26d016cc58f818ce8f84d5a7ba12c41d6d727bc616`.
New stateful image SHA-256:
`29d4bd68348bcfccef26098c4cf6cc85a1f2ef40a861d046b7c4c43e76f230db`.
No compatibility with another build, including868 or a field R39 label, follows.

The new image loads at `0x4000`, grows from70,768 to71,384 bytes, and appends
616 executable bytes at `[0x15470,0x156d8)`. The reproducible generator uses
installed clang's Thumb assembler; it rejects unresolved relocations and checks
source identity and displaced bytes. Independent APTrace/Ghidra disassembly
confirms the inserted instructions and detours.

| Original address | Change |
|---|---|
| `0x8e18` | Four-byte prologue replaced by B.W to poll hook `0x15470` |
| `0x8f98` | Displaced LDR/MOVS replaced by B.W to common grant hook `0x15650` |
| `0x81d0` | Original tail branch redirected through program hook `0x15484` |
| `0xcca0` | Reset BSS-end literal extended by64 bytes |
| `0x11050` | Allocator initial-break literal extended by64 bytes |

The manifest records byte offsets and before/after encodings. Restoring these
five four-byte ranges and removing the extension reproduces the original exactly;
configuration flash `[0x12000,0x13000)` and existing vectors remain unchanged.
Appended physical flash ownership, bootloader/update/checksum contracts and
possible persistent data beyond the distributed image are **unknown**. This is
simulation allocation, not evidence of a deployable code cave.

State uses explicitly reserved `[0x2000531c,0x2000535c)`. Original BSS ends at
`0x2000531c`, which is also the allocator's initial break. Both literals are
changed; this is not allocation inferred from missing cross-references. Existing
globals, SP and heap cursor `0x20005308` stay at their addresses. Heap allocations
start64 bytes later. Direct native allocator controls return original `0x2000531c`
and patched `0x2000535c` respectively. A reset probe prefilled all64 bytes with FF
and captured16 original reset-loop stores clearing the entire block at `0xcc82`.

Offsets: state0, qualification tick4, mode8, X12, marker16, TR20, raw24,
filtered28, last poll tick32, consumption count40. Remaining bytes are reserved.
The full-write-watch intentional smoke run attributes new-block writes only to
the extended reset loop or appended patch. Static source restricts intended
writers to these routines; arbitrary aliases, all indirect callers and all IRQ
writers are not universally excluded.

The poll trampoline replays the original48-byte prologue and saves volatile
registers with an additional24-byte aligned frame. Helpers preserve callee-saved
registers. The grant saves/restores `r0-r12,lr` and replays the displaced r2/r3
assignments; accepted native frame observations match `r0-r12,sp,lr` before/after
apart from those intended assignments. Program-tail temporary frame is24 bytes.
APSR flags are **not** fully preserved (the accepted observation differs in C);
register-frame correspondence does not prove arbitrary inline-hook equivalence.
No exhaustive stack bound, IRQ interleaving or NVIC delivery certification exists.

Direct G/W1/B1 and internal motion routes do not pass the common external gate;
they retain their original distinct initiation behavior. This is an external
trigger policy, not universal authorization of every motor producer.

## Differential execution and timing

`run-experiments.py` is a case-owned waveform/RX recipe on the existing public
APTrace ConcreteMachine interface, reusing the established CLI configuration and
intentional-program recipe. It supplies peripheral inputs and command arrivals;
it does not authorize movement or implement a shadow trigger gate. Qualification
executes from the generated binary. Only the explicit invalid-state probe writes
new policy state. `check-artifacts.py` analyzes saved artifacts, not firmware.

Each run starts a new machine at reset `0xcc24`, retaining the established radio-ID
stand-in, DWT/readiness assumptions and tick at `0x200052ec`: one increment per
4,000 guest instructions. Actual application program/MC4 and W/X command handlers
execute; RX delivery is modeled. Short cases run16M instructions; held-W and
release/repress run65M. PC-driven histories are labeled separately from timed
waveforms. Execution is original-firmware or patched-binary instruction execution
with modeled peripherals, not symbolic proof or physical behavior.

Intervals50/50 and maximum gap20 were selected against the observed cadence and
intentional pulse. Digital500 poll gaps are1–8 ticks in original/first and1–7 in
stateful (median2). Changes are applied at the first poll meeting the requested
tick, so nominal500 pulses actually span499–501 ticks across images. These are
**nominal firmware milliseconds**, not measured wall-clock500ms. The patch captures
its timestamp at poll entry before acquisition, so even a50-tick qualification
is not a strict50 physical milliseconds between completed ADC conversions under
preemption. Missed edges between polls remain possible; no continuous-level proof
is offered. Added ADC/filter calls alter acquisition cadence and overhead.

The core matched matrix below counts native live initiations at `0x5fa4`,
corroborated by true external acceptance `0x8f9c`, rate start `0x5f8c` and TC0
ENABLE-containing store `0x571c`. For rejected cases all watched initiation
boundaries, including `0x571c` and `0x5810`, are absent within the full bound.

| History | Original915 | First patch | Stateful |
|---|---:|---:|---:|
| Digital fresh nominal500 ticks | 1 | 1 | 1 |
| Digital nominal10 ticks | 1 | 1 | 0 |
| Digital active from startup | 1 | 1 | 0 |
| Historical saved LOW/current HIGH at `9228/922c` | 1 | 0 | 0 |
| Release at final read/gate entry | 1 | 0 | 0 |
| Analog fresh nominal500 ticks, X1 | 1 | 1 | 1 |
| Analog517 at startup, then600 before arming | 1 | 1 | 0 |
| Analog517 qualified inactive, then sustained600 | 1 | 1 | 1 |
| Held active, one W after natural completion | 2 | 2 | 1 |
| Held active, one W while running | 2 | 2 | 1 |
| W after completion, qualified release then repress | 2 | 2 | 2 |

The before-commit comparison releases at original `0x922c`, first patch `0x15478`,
and new gate entry `0x15650`. These are matched semantic read boundaries, not
identical elapsed timing. The historical transient repeats its explicit PC-driven
LOW/HIGH pair on attempts. Neither fixture is passed off as an oscilloscope trace.
W cases deliver exactly one supplied `W|`; native return `0x6fd8`, STOP/completion
and idle restoration remain observable. No recurring-PC W source or forced
idle/busy clear substitutes for that lifecycle. A200-tick inactive interval before
the next500-tick activation supports the release/repress positive control.

Digital500 elapsed acceptance is101/101/151 ticks (original/first/new), with
rate/live158/158/207. Recognition latency from actual active edge is0/0/51;
new rate/live latency is107 ticks. Analog500 acceptance is137/137/177, rate/live
194/194/236, with actual edges100/100/101: new recognition76 ticks and live135
versus original37 and94. X2 inactive517→900 accepts at181 and reaches live239
from an active edge100 (recognition81, live139). Both modes recognize the tested approximately500-tick
intentional input. This is one tested pulse/phase per mode, not a missed-trigger
probability or validation of Nathan's physical pulse distribution.

Final validation: **40/40 matrix executions**, **261/261 saved-artifact checks**,
zero pending cases, zero native execution errors and no recorded memory-write
truncation in the matrix. The packet also retains the initial timed control,
eight supporting CLI snapshots and the invalid-resting-level X2 witness. Generator
reproduction returns the same71384-byte image and SHA-256. Assertions establish
the stated finite results; they do not promote overall mitigation to complete.

## Downstream behavior and preservation limits

All three images retain the same first80-byte program record for accepted digital
and analog500 controls: positive direction, start0 and endpoint500. Each reaches
the original profile/rate/timer/live boundaries. The initial rate-to-live TC0
sequence has13 stores with the same address/size/PC structure. First patch equals
original. Stateful matches12 of13 values; CC0 at `0x4000381c`, store PC `0x5c44`,
differs: digital `0x5278`→`0x5563`; analog `0x5877`→`0x5278`.
The enable-containing store at `0x571c` remains CTRLA `0x602`.

The full fixed16M captures also differ. Digital TC0 writes are522/522/492 and
driver serial writes32,581/32,490/32,280; analog counts are499/499/477 and
31,800/31,800/30,565. These streams have not been sorted, normalized or presented
as equivalent. Changed qualification/acquisition work and instruction-paced time
change evaluator phase; that is an explanation supported by timing, not proof
that physical speed/distance accuracy would be preserved. Timer fidelity and
motion-profile preservation are unresolved engineering risks.

Separate full-reset B1 and direct G/W1 controls reach original live boundary
`0x5fa6` with final complete TC0/live bytes matching the historical original915
controls, and zero consumed external grants. Program loading, configuration,
startup and natural completion remain executable. Manual/jog, nonzero W return,
multiple program records, full six-W bursts and every internal producer are not
newly validated here. No physical direction/distance or continuous trigger-caused
STEP pulse train is demonstrated. The rejected forced-counter continuation from
the earlier motor-output investigation is not used.

## Counterexamples and untested boundaries

A sustained analog false-active condition beginning **after** successful arming
still initiates, as does an electrically identical legitimate contact. Initial
active suppression improves the pre-arm fault case, not fault identification.
A qualified digital release immediately after the consume store still initiates;
this is the declared commitment limit, not mid-motion cancellation. Qualification
cannot exclude an arbitrarily late physical transition after its last acquisition.

Additional saved witnesses characterize the boundaries below. These are new-image
probes, not three-image differential controls. See packet outcomes for input times.

| Stateful probe | Observed result |
|---|---|
| Nominal49 and51 digital pulses | Both actual51 ticks; no initiation |
| Release just after consume store | One initiation; no post-commit cancellation |
| Analog10 ticks | No initiation; filter latency also contributes |
| Fresh X2 analog500, inactive517 then900 | One initiation, corrected fixture |
| X1→X2 command at tick126 during active qualification | No initiation |
| Inject stateFFFFFFFF at tick125 during qualification | No initiation |

Both nominal49- and51-tick digital probes are rejected at the tested phases;
poll quantization produces the same actual51-tick history in both. They are one
observed input history, not two independent duration points. The51-tick
probe is phase-sensitive: elapsed input width does not equal the time between
first acquired active sample and final grant. Inactive rearming includes filtering latency. Mode/X changes invalidate
state, but there is no exhaustive configuration/eligibility/filter-history proof.
W during active qualification, arbitrary state corruption into a valid value,
clock rollover, adversarial long IRQ preemption and all mode-transition orders
remain untested. No universal writer or bypass exclusion follows from the sampled
call graph and finite runs.

## APTrace execution and capability gaps

APTrace Ghidra decompile/disassembly supplied the original boundaries, allocator,
reset and independent patch decode. Existing Unicorn CLI and ConcreteMachine
supplied native executions and register/memory/write observations. Saved commands
and fixture hashes preserve reproducibility. No independent instruction engine,
new framework, package installation, framework tests or symbolic solver was added.
The assembler and image generator are the explicitly requested patch deliverable.

The initial X2 positive fixture incorrectly used225 as its resting level, which
is active under X2. It correctly produced no grant. The fixture source and this
snapshot are preserved as `run-experiments-initial.py` and
`stateful-analog-x2-invalid-resting225.json.gz`; only that case was rerun with517
as the resting level. Earlier snapshots retain the initial fixture hash. This
was an input-recipe correction, not a firmware change or a suppressed defect.

The initial generator invocation used an incorrect repository-parent index and
failed before producing a candidate; it was corrected. A first sandboxed timed
native invocation terminated with host SIGILL132 before guest execution. The
reviewed execution context for the same simulation command then worked and was
reused for the campaign; no toolchain or security-setting change was made. This
is a host execution-context limitation, not a firmware rejection. There was no
significant candidate defect/correction requiring replacement of a tested image.

| Gap / evidence | Impact and assessment | Needed capability / priority |
|---|---|---|
| TC/NVIC continuation unresolved; initiation streams captured, continuous trigger STEP absent | No waveform equivalence or physical suppression claim; peripheral fidelity is the likely limitation | Validated state-preserving timer/IRQ service, high |
| Instruction-paced tick and modeled GPIO/ADC/RX | Cannot certify real500ms recognition, filter timing or IRQ freshness; actual physical clock/input missing | Measured timing plus validated peripheral scheduling, high |
| Sparse native frames and static CFG, not full writer/IRQ/alias closure | No universal hook equivalence or all-path state ownership proof | Caller-frame-aware whole-path verification and feasible IRQ schedules, high |
| Host native SIGILL in initial sandbox context | Default-context timed recipe failed; reviewed same operation succeeded | Stable native execution environment, medium |
| Case recipes orchestrate existing acquisition hooks; no general declarative waveform runner used | Reproduction depends on checked-in recipe and engine assumptions; no framework fix silently supplied | Supported time/phase waveform and event-aligned comparison workflow, medium |

Missing exact field-release identity, insertion/fault waveforms, physical flash
ownership and bootloader contract are **missing evidence**, not APTrace bugs.
Binary policy overhead and timer-period differences are **engineering limits**,
not findings repaired by changing the harness clock. No firmware release grade,
physical repair or safety certification is promoted.

## Engineering assessment and recommended next work

For Nathan and Noxon, this packet demonstrates that both recovered external paths
can share a native authorization mechanism and that W-driven eligibility need
not equal a new trigger. It supplies concrete counterexamples to the first
freshness-only patch and bounded working improvements. The defensible negotiation
claim is a feasible firmware mitigation policy deserving vendor engineering,
not a field-ready repair or complete resolution of VVR-003/004/005.

Existing APTrace operations can next examine W during qualification, selected
mode/filter-history transitions, manual/internal controls and several pulse
phases, preserving this image as a baseline. Vendor/source work should quantify
acquisition overhead and rate-evaluator timing before choosing an implementation.
APTrace development would be needed for validated continuous timer/IRQ service,
stronger writer/frame closure and a supported waveform campaign interface.
New evidence is required for exact field firmware, physical pulse/fault timing,
flash/update ownership and representative unit behavior. These are recommendations,
not authorization for hardware, framework development or another gate campaign.
