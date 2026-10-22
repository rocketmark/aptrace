# Reference trigger-acceptance specification and TLC checks

2026-10-22. **Delivered a proposed parameterized TLA+ contract and implementation
handoff, with finite safety/progress model checks and preserved counterexamples.**
No executable controller, apfw2, original firmware, APTrace framework or hardware
was modified. This is not physical reliability verification or proof that future
code conforms to the specification.

The [package entry point](../../specifications/trigger-acceptance/README.md),
[Claude Code handoff](../../specifications/trigger-acceptance/HANDOFF.md),
[formal model](../../specifications/trigger-acceptance/TriggerAcceptance.tla),
[verification report](../../specifications/trigger-acceptance/VERIFICATION.md),
[declarative tests](../../specifications/trigger-acceptance/behavioral-tests.json)
and [original-firmware fixtures](../../specifications/trigger-acceptance/original-fixtures.json)
are the deliverables. The handoff states transitions, guards, cancellation,
callbacks, timing parameters, readiness-provider obligations and intentional
compatibility changes; Claude Code need not invent missing controller behavior.
Numerical timing/filter values and hardware integration remain unresolved inputs.

## Proposed behavior and relation to evidence

Fresh inactive qualification after readiness arms the controller; subsequent
fresh, consistent raw/filtered active observations recognize an event. Recognition,
acceptance and group motion start are separate. Each accepted authorization can
start either profile playback or a direct request once. All such paths must use
the same atomic consuming gate. Completion requires a new inactive window;
held/busy input is not queued. Configuration/history/freshness invalidation cancels
pending events. STOP and reset latch stopped, clear pending authorization and
require explicit resume/readiness checks. Wrong-event callbacks are ignored.

This deliberately changes Noxon's active-at-eligibility, X reclassification,
filter-tail and TR observer behavior. The model respects the discovered second
motion-initiation path: profile/channel state can reach6338→5f8c→timer enable
without6fd8 or the separate phase arm. It does not repeat the former inference
that absence of6fd8 means no motion authorization. Physical reference validity,
validated program and driver readiness are separate attestations, not old truthy
record markers or software-zero position.

A new qualified inactive→active episode can start; release after commitment does
not automatically stop the trajectory. Release before commitment cancels.
Preexisting asserted inputs, busy-period pulses and short pulses that fail the
chosen qualification/deadline contract are not guaranteed to start. Those costs
are explicit policy proposals with alternatives in the handoff, not hidden
compatibility assumptions. Identical observable contact/connection histories
remain indistinguishable; no software-only universal misfire cure is claimed.

## Evidence and verification

The specification reuses the [misfire/request campaign](trigger-misfire-failure-modes.md),
[powered-connection assessment](powered-trigger-connection.md),
[X contract](x-trigger-acceptance.md), both bring-up reports and motor/reference
analysis. No new broad reverse engineering or original-firmware experiment was
needed. Snapshot/command hashes bind the differential fixtures to existing
unmodified original868 execution; the small Noxon TLA model is an evidence-linked
abstraction, not binary verification.

Five final positive TLC configurations check19,305 /119,312 /52,600 /19,305 /92
distinct states respectively, exhausting their finite graphs. Safety covers
qualified/fresh recognition, provenance, one start per event, common route guards,
cancellation, stopped-token invalidation and stale completion handling. Progress
checks recognition/authorization resolution to acceptance/start **or cancellation**.
A cooperative environment checks two legitimate starts and completion/re-arm.

Five deliberate negative reference checks preserve startup qualification,
duplicate start, retained-STOP-token, unconditional-progress and fairness
counterexamples. Three separate Noxon abstractions expose startup, reclassification
and filter-tail policy violations. Counterexamples refine the claim: STOP or
invalidation may legitimately cancel a recognized event, and scheduling fairness
is required for progress. Model review added capture-age and callback-identity
coverage. Initial semantic/action-syntax diagnostics are preserved, not counted
as successful verification.

## Scope and capability findings

The explicit user assignment authorized case-owned TLA+/TLC work. APTrace had
no exposed TLA verification workflow or installed TLC; a pinned official jar was
used from temporary storage, without changing APTrace implementation/dependencies.
The package contains checker-only orchestration, exact commands/logs, tool hashes
and a replay runner that requires expected diagnostics as well as exit codes.
No executable reference state machine was implemented.

Model checks do not prove unbounded event counts/all parameter combinations,
real-time deadlines, sampling/filter adapter correctness, physical stopping,
reference/driver truth, or implementation refinement. MaxEvents1/2 is an
exploration budget, not a runtime capacity. Safety does not rely on fairness;
liveness assumes fair processing and genuine completion/acknowledgement. The
cooperative progress scenario also assumes stable valid inputs/readiness and
handling before expiry. Deadlock checks are disabled because legitimate idle/
stopped/budget endpoints can quiesce; named progress properties, not “no deadlock,”
carry the progress claim.

Recommended next work: Claude Code implements the stated parameterized contract
and adapter/test interfaces, then supplies trace conformance/refinement evidence
for both motion routes and reset/ISR races. Product review selects explicit
policy decisions and numerical timing; physical work establishes front-end input
behavior, validity providers and driver/stop integration. An APTrace orchestration/
proof-admission capability would be separate development work, not silently
assumed present. No release gate is promoted by these model results.
