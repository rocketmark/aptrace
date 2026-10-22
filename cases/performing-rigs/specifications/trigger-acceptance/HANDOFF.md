# Claude Code implementation handoff

## Scope and authority

Implement this **proposed** controller after review, not Noxon's transition
quirks. This package does not implement it. TLA+ specifies a logical motion group
with at most one outstanding event/move. `profile` and `direct` are two downstream
routes for the same trigger-derived authorization. A coordinated multi-channel
start is one group transaction, not one new event per timer write. Independent
manual/jog commands and transport security are outside this model: they must
not bypass the gate and need a separately specified command-authorization
contract before being enabled. Do not silently treat a legacy G packet as a
trigger authorization.

`TriggerAcceptance.tla` and the decisions below define behavior. If deployment
requires a different policy, update/model-check the specification first. No
Noxon address is an implementation requirement. Numerical qualification/time
settings are required configuration inputs, not values to guess from the test
models. This is a complete parameterized state contract, not a completed
hardware/compatibility or production timing specification.

## Inputs, adapters and trust boundary

A new measurement frame contains `(bootGeneration, configGeneration, sequence,
capturedAt, rawActive, filteredActive, filterGeneration, quality)`.

1. Sampling assigns a strictly new sequence to an actual acquisition, not to
   each read of a cached filtered value. Reject duplicate/out-of-order frames
   and frames from older boot/config generations. These map to `Replay`, which
   does not refresh any age, qualification count or event. Sequence uniqueness
   and generation tagging are adapter obligations, abstracted rather than
   proved by the model's `fresh` bit.
2. Compute arrival age from **capture** time using a monotonic clock. In TLA+
   `Acquire(raw,filtered,history,arrivalAge)` permits arrival ages0..MaxAge+1;
   the last value represents any expired frame. Never timestamp old data as new.
   Elapsed `Tick` ages both the latest observation and the pending token.
3. `history=TRUE` means the filtered classification uses only the current
   input/config epoch and valid acquisitions. It is not a synonym for “filter
   initialized.” Wrong-generation or invalid history is not trusted, even if
   filteredActive is TRUE. On invalidation, completion and reset discard cached
   history; begin the next qualification window from fresh measurements.
4. `I` requires both raw and filtered inactive. `A` requires both raw and
   filtered active. Disagreement cannot recognize an event or qualify inactive.
   A fresh disagreement while Armed resets the active qualification count;
   while Recognized/Authorized, any loss of A cancels the pending event. Invalid
   history or expired data disarms and requires inactive qualification again.
5. A new frame occupies the model's one-entry mailbox until `Process`. The
   implementation must serialize the corresponding intake/process transitions;
   asynchronous queues/overwrites need a conformance argument, not new implicit
   behavior. Missed physical pulses before acquisition are outside the guarantee.
6. Readiness is three independent attestations: valid program, valid physical
   reference and ready/configured driver. The model does not validate a CRC,
   trajectory, physical zero or driver readback itself. A nonzero Noxon record
   byte, software position0 or requested register write is not such attestation.
   Providers must specify validators and explicitly invalidate on uncertainty.

Init represents a positively identified, quiescent cold power-on. A restart/MCU
reset must apply Reset immediately after Init, before any readiness or input
can be processed; it therefore enters the stopped latch and requires Resume.
If the platform cannot distinguish cold power-on from restart reliably, apply
Reset on every boot (including cold boot), accepting the explicit-Resume cost.
Readiness must stay false until unknown pre-reset hardware work is quiescent. Do not restore authorizations from persistence. The model Reset
action represents an observed reset/cancellation transaction and can retain an
opaque active identity solely for stop acknowledgement; it does not prove RAM
survives MCU reset. Hardware boot must establish a new generation and quiescence
without depending on that lost RAM.

Raw/filtered booleans abstract electrical thresholds, mode, hysteresis and
continuous filtering. No filter formula, voltage threshold or PA02 source-type
interpretation is mandated by this model. Adapter correctness and physical input
reliability are separate verification tasks.

## States, events, guards and outputs

| State | Allowed event / guard | Effect |
|---|---|---|
| Disabled | Readiness/config update makes all three attestations true, not stopped | Qualify; no inherited sample/counter/history/token. |
| Qualify | Fresh valid I frames, processed after readiness | Count consecutive I; at `ReleaseSamples`, Armed. Active, mixed or invalid frames never become events. Invalidity resets qualification. |
| Armed | Fresh valid A frames | Count consecutive A; at `ActiveSamples`, allocate a new event identity, emit Recognized, retain a pending token and its original lifetime. I/mixed frames reset active count. |
| Recognized | Still ready, not stopped, current A/history fresh, token unexpired | `Accept` emits Accepted and marks the token Authorized. Otherwise cancellation invalidates; no motion yet. |
| Authorized | Same guards, motion idle, token accepted/not canceled/not consumed | `Start(profile|direct)` atomically consumes token and emits one group Start. Record active event identity, enter Running. All timer/direct backends must use this transaction. |
| Running | Matching `CompleteEvent(activeEvent)` | Complete, idle, Qualify; erase qualification/filter history. A new post-completion I window is required. |
| Running | Release, repeat pulses, expired/invalid input observations | No second trigger is queued, no re-arm, no automatic stop of an already committed profile. STOP/readiness fault remains effective. |
| Any | STOP | Invalidate pending token/history/counts; latch stopped; invalidate reference. If a move exists, request stopping and keep its identity until matching acknowledgement. |
| Any | Reset | Same pending invalidation; also clear program/reference/driver readiness; latch stopped. Do not replay saved arm/event state. Physical stop/disable is an integration obligation. |
| Any | Configuration/program/reference/driver update, even same validity values | Invalidate pending history/qualification/token. Idle→Qualify or Disabled according to readiness. If moving, request stop and latch stopped. No implicit resume or event from reclassification. |
| Stopped | Matching stop acknowledgement | Motion becomes idle. Stopped latch remains. A stale/wrong-event acknowledgement is ignored. |
| Stopped | Explicit Resume, all attestations valid, motion idle | Qualify. No old event, filter history or inactive qualification is restored. |
| Any relevant idle/pending state | Observation or token deadline expires | Cancel/disarm; require fresh inactive qualification. New active frames do not extend the original token lifetime. |

`CompleteEvent(e)` and `AckStopEvent(e)` must match the current active identity.
Wrong/stale callbacks have no state effect (`StaleCompletion`). `Accept` is the
recognition-to-authorization transition; Start is the only irreversible event
consumption. Guard failure returns rejection/no change, not a hidden queue or
an implicit retry. `Complete`, STOP, reset and configuration invalidation share the model output
`Invalidate`; entering `motion="stopping"` is the stop/disable request.
The TLA `output` field is a last-transition label; diagnostic
publication must not itself create events or change state.

A state-machine operation is atomic at its linearization point. Once STOP,
reset or invalidation is processed, later Start cannot use the old token.
If Start linearizes first, a later STOP requests stopping; this is not a proof
of zero-distance physical stopping. Queued-but-unprocessed STOP latency and
ISR races are platform obligations; the model does not assert priority over an
input the controller has not yet received.

## Identity, authorization and backend contract

- Use boot/config generations and a non-reused event serial. The implementation
  must reject old queued grants/callbacks across reset/reconfiguration. Do not
  copy TLC's finite1/2 ID budget into the product. Never wrap IDs into a live
  namespace; fail closed/report exhaustion and establish a fresh verified
  generation after quiescence before reuse of a counter range.
- `recognized`, `accepted`, `canceled`, `starts`, `eventNo`/MaxEvents history
  limits and `startOK` are verification bookkeeping. They need not be unbounded
  runtime containers. The behavioral obligations are current token identity,
  validity, single consumption, current active identity and no stale replay.
- The three `Unsafe*` constants exist only for negative controls. Do not port
  them as runtime options. All reference configurations set them FALSE.
- Profile evaluation/rate changes inside an already authorized group are not
  new Starts. Every path that first enables a timer or issues a direct move
  must enter the shared gate; validating only a G/0x6fd8-style function is
  insufficient. Untrusted callbacks cannot initiate a second route.
- Reserve/consume authorization once for the group before initiating its
  configured channels. Partial backend failure must enter a stopped/fault state;
  no silent retry or auto-resume with the consumed event. The model checks logical
  authorization, not distributed atomicity or simultaneous multi-axis edges.
- Physical motor completion/stop acknowledgement must be genuine and tied to
  the active event. After STOP, reference must be revalidated (not necessarily
  rehomed) before Resume. A software counter alone is not automatically valid.
- Source release or input freshness loss **before Start** cancels pending work.
  After Start, release does not cancel the committed trajectory. Implement a
  separately specified dead-man mode if required; do not silently change this.

## Explicit policy choices and tradeoffs

| Decision | Proposed contract | Alternative / cost needing product review |
|---|---|---|
| D1 startup/eligibility | Automatic arm only after a new inactive window following readiness | Accepting already-asserted inputs preserves level-at-enable operation but reintroduces demonstrated startup starts. |
| D2 event interpretation | Qualified inactive→active episode, consumed once | Level-repeat/queued triggers would need a different event/re-arm model and could repeat connection disturbances. |
| D3 pre-start release | Cancel, including accepted but not committed events | Latching a short recognized pulse until later motion preserves short triggers but permits delayed starts after the condition ends. |
| D4 completion | Require fresh inactive qualification after completion; discard busy-period triggers/releases | Reusing release observed while moving improves throughput but needs separate event-boundary proof. |
| D5 STOP/reset | Latched stop, explicit Resume; STOP invalidates reference, reset invalidates all readiness | Retaining a proven reference after controlled STOP may be useful; change the model/provider contract before adopting it. |
| D6 configuration | Disarm; if moving, stop; never reclassify history into a new event | Seamless live changes trade continuity against provenance and race risks. |
| D7 diagnostics | Passive | Original TR behavior suppresses input acceptance and can expose stored activity when disabled; compatibility must be deliberately changed or versioned. |
| D8 routes | One trigger-derived group start, profile or direct | Independent manual/jog intent needs its own authorization specification; this package does not invent it. |

These are stated design proposals, not Noxon discoveries or already-approved
product compatibility changes. They are sufficiently explicit to implement the
reference controller. If any is rejected, obtain a revised formally checked
contract rather than improvising in code.

## Parameters that must be supplied, not guessed

| Parameter | Meaning / requirements | Checked examples, not deployment defaults |
|---|---|---|
| ReleaseSamples K | Consecutive fresh consistent inactive acquisitions after each boundary; K≥1 |1,2 |
| ActiveSamples N | Consecutive fresh consistent active acquisitions after arm; N≥1 |1,2 |
| MaxAge | Maximum capture age at recognition/commit; monotonic time unit defined by adapter |0,1,2 abstract ticks |
| TokenTTL | Maximum time from recognition to Start; never renewed by input refresh |0,1,2 abstract ticks |
| Input acquisition interval / filter / hysteresis | New-measurement cadence, history invalidation, raw/filtered classification, acceptable latency/minimum pulse width |Not numerically specified or physically verified |
| Program/reference/driver validators | Evidence sufficient to assert each readiness flag and causes of invalidation |Provider contracts required before hardware deployment |

At commitment, recompute capture/token age from the actual monotonic clock;
do not rely on a periodic tick handler having run. A clock discontinuity
invalidates the epoch and pending authorization. Tick in TLA+ abstracts elapsed
time, not proof that an interrupt runs on schedule.

Fresh samples are not necessarily uniformly spaced, and K/N alone do not imply
milliseconds. Set sampling, qualification and deadlines together. Firmware
cannot distinguish a powered-source insertion from an intentional closure with
identical observable history. N=1 permits a fresh one-sample active event after
arm; N>1 suppresses it **and its legitimate short equivalent**. No choice is
claimed universally reliable for V1/V2 without measurements.

## Implementation acceptance

1. Implement the parameterized transitions and adapter interfaces above; run
   the declarative behavioral suite with the specified parameters.
2. Add conformance traces mapping concrete operations to TLA actions, including
   both physical motion routes, wrong callbacks, STOP/start races and reset.
   This package does not establish refinement of future code.
3. Use `original-fixtures.json` for deliberate differential outcomes. Preserve
   original images and modeled-MMIO qualifications; do not infer motor motion
   from a timer-start witness. Old fixture setup may not include a fresh inactive
   window *after* readiness, so it is not automatically a legitimate reference
   trigger sequence.
4. Before production, select numerical timing/filter policy, validate the front
   end and readiness/stop providers, and review compatibility decisions D1–D8.
   No hardware operation, firmware flash or apfw2 implementation is authorized
   by this specification package itself.
