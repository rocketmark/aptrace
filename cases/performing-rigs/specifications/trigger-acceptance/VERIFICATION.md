# Verification report

Question: define a precise reference trigger contract, check its safety and
progress, and hand it off for later implementation. **Result: the parameterized
transition contract is specified and passes the finite TLC configurations below.**
No executable controller, original-firmware change or apfw2 change was made.
There is no implementation-refinement proof, unbounded theorem, physical input
reliability proof or release-gate promotion.

## What TLC checked

All final positive checks use the same `TriggerAcceptance.tla`, all unsafe
switches FALSE, breadth-first exhaustive search, one worker, no state constraints
or symmetry reduction. Deadlock checking is explicitly disabled: idle, stopped,
no-input and exploration-budget boundaries may legitimately quiesce. Progress
is checked by named temporal properties, not inferred from absence of deadlock.
`verification/results.json` and exact native logs/commands are authoritative.

| Configuration | K/N, age/TTL, history budget | Distinct states | Result |
|---|---|---:|---|
| Safety |1/1,1/1,1 event; hostile environment |19,305 |All named safety/action properties pass. |
| SafetyTwoEvents |2/2,2/2,2 events; hostile |119,312 |Same properties pass, including second-event/re-arm interleavings. |
| SafetyZeroAge |1/1,0/0,2 events; hostile |52,600 |Same properties pass at immediate expiry boundary. |
| Progress |1/1,1/1,1 event; hostile |19,305 |Safety plus recognized/authorization resolution and motion resolution pass under fairness. |
| Cooperative |2/2,1/1,2 events; cooperative |92 |Two legitimate events served, either route; completion eventually re-arms. |

State graphs for different checks overlap; these are not counts of independent
physical trials. TLC uses hashed fingerprints; logs retain its collision
estimates. This is finite model checking, not a deductive proof for every
parameter, event count, scheduler or adapter implementation.

Safety requirements checked:

- `TypeOK`: state domains/readiness separation and callback identity structure.
- `PendingQualified`: a pending event has an inactive-qualification witness.
- `StoppedInvalidates`: no pending token survives the stopped latch.
- `AuthorizedStarts`, `UniqueStarts`, `StartGuarded`: starts have accepted
  provenance, consume distinct event identities and satisfy current readiness,
  freshness, qualification and token-lifetime guards.
- `PendingValid`: recognized/authorized work cannot remain live with invalid
  readiness, stale/disagreeing evidence or expired lifetime.
- `RecognitionHasFreshQualifiedInput`: only processing a fresh, current-history,
  consistent active observation while Armed can increase event number. Startup,
  reconfiguration, completion, replay, STOP and reset do not manufacture events.
- `StartTransitionAuthorized`: every start-log extension comes from Authorized,
  with valid unconsumed token and idle motion, for either backend route.
- `CancellationInvalidates`: invalidation removes token, qualification and
  unprocessed history. `StaleCompletionIgnored`: wrong-event completions do
  not modify motion/authorization state.

The model's trusted-new-measurement and history flags are abstract interface
contracts, not proofs that a future sampling adapter assigns them correctly.
A physically changed but not yet observed input is not known to the controller.
No assertion says current voltage is still active throughout the MaxAge window.

## Progress assumptions and limits

Hostile configurations allow arbitrary raw/filtered disagreement, bad history,
expired arrivals, ticks, validity/configuration changes, STOP, reset, replay,
route choice and invalid completion notifications. Safety does not require
fairness. The temporal claims additionally assume weak fairness for processing,
acceptance, starting and matching completion/stop-acknowledgement actions:
a continuously enabled action eventually runs. Fairness definitions follow
[Lamport's specification treatment](https://lamport.org/tla/book-02-03-04.pdf).
No physical scheduler deadline or guaranteed motor completion follows from it.

`RecognizedResolves` permits acceptance **or explicit cancellation**.
`AuthorizationResolves` permits start **or cancellation**. They do not promise
motion after STOP or under continuously adversarial configuration/input changes.
`MotionResolves` assumes completion or stopping is eventually delivered; this
is a backend/environment obligation, not a demonstrated original-firmware
completion path.

The Cooperative specification adds stable readiness, valid fresh observations,
inactive input during qualification, active input while Armed/pending, no
expiry/cancellation disruptions and fair acquisition. Completion is fair.
`AllEventsServed` checks both budgeted event identities eventually start;
`CompletionRearms` checks return to Armed after a started move. Thus the model
has a checked, repeatable legitimate operating path and does not require a reset
between the two events. The assumption of timely handling before expiry is
represented by no Tick in this scenario; it does not prove a real-time WCET.

**Exploration budget:** MaxEvents1/2 bounds the model's identity/history sets.
After budget exhaustion no further recognition is modeled. It is not a runtime
limit to implement. The progress claims are conditional on identities remaining
available and are checked for the stated finite scopes, not unbounded recurring
triggers. General refinement/scaling to non-reused runtime serials remains an
implementation/proof obligation. Physical STOP/reset execution, callback
honesty, filter correctness and reference validity also remain assumptions.

## Counterexamples and refinement

Final raw counterexamples are preserved, including complete states and action
labels. Expected failing configurations are deliberate tests, never references
to implement. Native TLC exit12 denotes the checked safety violation; exit13
is a temporal violation. Parser errors do not satisfy either expected result.

| Check | Meaningful counterexample / response |
|---|---|
| StartupCounterexample | Readiness → fresh A → Recognized without inactive qualification; PendingQualified fails. Reference disables the unsafe startup branch. |
| DuplicateCounterexample | Qualify → recognize → accept → start → second backend start with same event; UniqueStarts fails. Reference has one consuming gate. |
| StopCounterexample | Qualify → recognize → STOP retains token; StoppedInvalidates fails. Reference discards token and requires Resume/revalidation. |
| UnconditionalProgressCounterexample | A recognized event is canceled by readiness/config invalidation, with no later start. The overly strong EveryRecognizedStarts property fails. The checked contract refines this to start/acceptance **or cancellation**, and checks legitimate-start progress separately under cooperative assumptions. |
| FairnessCounterexample | A recognized event stays pending under stuttering after input/tick/replay steps when fairness is removed. Weak fairness is necessary for the progress claim; safety alone cannot promise scheduling. |
| NoxonStartup / NoxonReclassification / NoxonFilterTail | The small evidence-linked Noxon abstraction exposes eligibility, X change or TR change without a fresh episode and reaches Start. NewEpisodeRequired fails in all three. |

`NoxonWitness.tla` intentionally abstracts only those three behaviors already
shown by original-code executions. It omits normal filtering math, program
loading, driver state and arbitrary original control flow. These are model
counterexamples consistent with concrete fixtures, **not** symbolic execution
or formal verification of Noxon's binary.

Model review also exposed two missing abstraction details: callback identities
and delayed arrival age. The final model includes matching active-event
completion/stop acknowledgement and expired-arrival handling; all final checks
were repeated. Initial snapshots/logs are retained under `verification/initial/`.
An initial temporal-action syntax error (`[]` applied directly to an action)
was corrected to stutter-closed action properties; its failed diagnostic log is
retained. No property was silently removed or failed run reclassified as a pass.

## Traceability: observation versus proposed behavior

| Requirement | Basis | Status / intended difference |
|---|---|---|
| R1 post-readiness inactive qualification | Original startup-active timer starts; powered-connection digital/preexisting input and analog startup tail |Proposed D1; deliberately rejects active-at-enable. |
| R2 freshness/history provenance and expiry | `profile-tail`, `analog-startup-transient-tail`; corrected normal alpha0.05 in bring-up |Proposed; do not carry stale filter history across epochs or retimestamp caches. |
| R3 config changes cannot create events | Native X2 accepts constant225 and starts timer |Proposed config barrier; numbers/physical voltage meanings not copied. |
| R4 single-use shared authorization | Profile route6338→5f8c/timer enable and separate G/phase6fd8 route |Observed multiple routes; proposed single gate covers both. |
| R5 program/reference/driver validity separated | Motor-state/reference and MC4/driver evidence: software zero, desired settings and truthy record byte do not prove physical state |Readiness providers are explicit assumptions/implementation obligations. |
| R6 STOP/reset invalidate, identity-bound callbacks | Original full completion/re-arm/STOP physical guarantees remain open |Proposed conservative semantics, not a recovered Noxon guarantee. |
| R7 one event per active episode; no busy queue | Original held starts once only within tested eligibility; post-completion behavior open |Proposed release-after-completion rule, checked in model. |
| R8 passive diagnostics | TR1 inhibits acceptance; turning it off can expose filtered active history |Proposed compatibility change. |
| R9 preserve qualified legitimate operation | Design requirement and cooperative TLC progress |Conditional on readiness, current input, adequate pulse duration, scheduling and completion. |
| R10 no impossible source-intent claim | Equal MCU histories for connection/contact replay; front end unknown |Neither TLA nor firmware can identify source intent without additional observables. |

Original evidence links/hashes and comparison expectations are in
`original-fixtures.json`. The [powered connection report](../../docs/investigations/powered-trigger-connection.md)
and [misfire/request campaign](../../docs/investigations/trigger-misfire-failure-modes.md)
retain electrical/model limitations. The [motor/reference report](../../docs/investigations/motor-state-ownership-and-reference.md)
separates physical references and driver state from Noxon's record contents.

## Handoff readiness and remaining work

The controller transitions, cancellation boundaries, event consumption,
completion/STOP/reset semantics, interfaces and declarative tests are specified
well enough for a parameterized implementation. Product decisions D1–D8 are
explicit proposals; numerical timing, electrical/filter behavior, validator
providers and compatibility approval are unresolved. Do not invent defaults or
claim production readiness. Claude Code's later implementation needs its own
conformance tests/refinement review, especially ISR/timer paths, callbacks and
reset races. That work has not been done here.

APTrace capability finding: existing concrete/static investigations supply the
firmware evidence; there was no exposed repository TLA+/TLC workflow and no local
TLC jar. The explicit user assignment authorized this case specification/checking
package and pinned upstream tool use. It does not add a general APTrace formal
verification capability or silently replace missing firmware analysis. Future
APTrace orchestration/proof admission is separate development work. Priority
medium; current reproducible TLC artifacts suffice for this specification task.
Highest-priority new physical evidence remains the minimal input-waveform/mode
capture identified by the powered-connection report. Formal safety does not
resolve the front-end information limit or assign behavior to V1/V2 hardware.
