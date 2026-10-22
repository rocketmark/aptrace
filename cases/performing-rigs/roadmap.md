## Persistent-state release work

Gate D is PARTIAL: both packaged variants reconstruct tested default startup;
meaningful local state exists but dedicated settings preservation/migration is
not mandatory for the agreed intentional reset. Obtain the actual apfw2
release/map/erase contract and validate a default-state downgrade across physical
reset/power cycle on a recovery-qualified engineering unit, with factory identity,
calibration, boot protection and unowned-region invariants intact. A/B/C remain
PARTIAL; E/F BLOCKED; production NO-GO. See the
[persistence assessment](docs/investigations/persistent-state-release-assessment.md).

# Harness Roadmap

## Reference trigger implementation handoff

Use the [formally checked contract](specifications/trigger-acceptance/README.md)
and declarative tests for a subsequent implementation task. Review the explicit
policy choices and provide timing/filter parameters and readiness-provider
contracts; do not copy model event-budget or unsafe switches into runtime code.
Require conformance/refinement evidence for profile and direct start paths,
callbacks, STOP/reset and ISR races. Model checking is finite/conditional and
has not established physical reliability or deployed behavior.

## Trigger reliability follow-up

The independent [Gate 1 assessment](docs/investigations/trigger-patch-gate1.md)
is INCONCLUSIVE, with no demonstrated local decode/branch defect. Before claiming
structural certification, obtain non-vacuous caller-frame-aware state/write
verification and address CFG coverage and PORT-read modeling limits.

The [Gate 2 assessment](docs/investigations/trigger-patch-gate2.md) is also
INCONCLUSIVE: targeted veto, ordered29,236-write intentional control and G/W1/B1
initiation reproduce, but cross-peripheral ordering changes and sparse side-effect
coverage prevent a behavioral PASS. Next verification work should establish
event-aligned comparison and complete boundary-state/write coverage; retain
fresh-input ordering and unacquired-polling differences explicitly.

The [Gate 3 assessment](docs/investigations/trigger-patch-gate3.md) is FAIL within
modeled scope: held/W repetition and post-read release reproduce. Preserve its
before-read rejection, after-comparison initiation and no-W completion controls.
Next define W authorization versus physical release-to-rearm, initial arming and
analog-history policy; investigate selected retained-filter histories and the
TC0-service idle writer's feasible interleavings using existing capabilities.
Validated IRQ/peripheral scenarios and framed/event-aligned verification remain
framework gaps, not permission to create replacement harnesses. Gate4 is
INCONCLUSIVE; Gate5 remains NOT RUN and hardware deployment NOT APPROVED.

The [Gate 4 catalog and assessment](docs/investigations/trigger-patch-gate4.md)
defines reusable proposed SAFE-001–010 properties, inferred firmware predicates
and unresolved policy parameters. Obtain product decisions on W authorization,
release-to-rearm, cancellation commitment/latency, startup readiness, sustained/
analog qualification and required output ordering before mandatory evaluation.
Preserve CE-1/CE-2 as confirmed behaviors with policy unresolved; retain Gate3's
FAIL within modeled scope and Gate1/2's INCONCLUSIVE verdicts. Existing-capability
follow-up can inspect specific ISR-writer prerequisites, retained-filter histories
or natural command lifecycles once a property question is selected. Development
priorities are first-class property/event definitions, native trace evaluation
and CE linkage, scoped behavioral admission, reachable framed proofs and route/
observer coverage. A separately authorized Gate5 must validate peripheral reads,
interrupt scheduling, instruction-count versus physical time, initialization,
cross-peripheral order and instrumentation noninterference. Gate4 did not execute
Gate5 or authorize implementation/hardware work; full safety is NOT ESTABLISHED.

The [experimental binary subset](docs/investigations/experimental-trigger-freshness-patch.md)
now proves one firmware-only stale-read mitigation without changing motor code.
Do not treat it as a deployable fix or the complete proposed policy. Further
stateful work must establish owned/reset-initialized storage, fresh acquisition
and inactive/active timing, session invalidation and release-to-rearm for both
paths. Retain the late-release and held/W counterexamples; preserve direct
producers. No permanent RAM reservation or full-policy binary implementation
has been established, and no larger-patch impossibility is asserted.

The [matched motor-output comparison](docs/investigations/vvr-trigger-motor-output.md)
now establishes equal observed original915 DIR/rate/TC0/driver requests for
transient and held inputs. Next work beyond that boundary needs validated
TC counting/CC/prescaler, pending/interrupt delivery and position progression.
Do not count shared startup STEP pulses as trigger consequences or reuse the
rejected repeated COUNT forces as a motor-fault reproduction. The first
ENABLE-containing store can precede0x5810; observe actual register stores rather
than treating that helper as the unique initiation sink.

Use the [VVR correlation](docs/investigations/vvr-trigger-failure-correlation.md)
as the physical-evidence starting point. The time-based profile-completion gap
is now closed for the bounded868 scenario: idle2 follows completion; supplied W
re-arms to idle9, and a held active input starts again without another edge.
Next isolate the natural Remote/M3 completion exchange and a nonzero return with
validated timer/STEP/position progression. Do not repeat the22M duration mistake
or force busy/idle to claim completion. Obtain hash-linked tested release archives
and a minimal insertion/PB05/mode/output capture; preserve VVR-003/004 differences
in reported Rev1 mode. Separate correspondence is unavailable. The July30s/10min
episode still needs exact reset, program duration/repeat and input history.

Targets1/2 and [Target3 route coverage](docs/investigations/motion-initiation-route-coverage.md)
are closed at their bounded exits. Preserve the filter-history/average distinction,
feasible digital SAT anchors and pre-read gate timing. Next valuable evidence is a
natural group/jog/W0/phase operation with exact arming, continuous timer/IRQ
service and completion/STOP quiescence. Do not repeat the missing-G/profile-start
search or assume timer ENABLE counts every STEP emission: B1, W1, catch-up and
group producers are now inventoried. Formal-model corrections need explicit
scope/authority decisions before implementation; neither controller was changed.


The [recovered Noxon formal package](specifications/noxon-trigger/README.md)
now supplies native-backed counterexamples and a same-acquisition-history
reference comparison. Preserve its oracle/boundary qualifications; do not treat
replay correspondence as exhaustive binary verification. Extend it with a
continuous completion/re-arm or accepted/running STOP/reset witness only after
that transition is established through supported APTrace execution. Resolve the
post-readiness qualification compatibility cost and sampling-adapter contract
before claiming the proposed controller fixes all connection transients.


The [request campaign](docs/investigations/trigger-misfire-failure-modes.md#targeted-request-campaign-an-overlooked-motion-initiation-path)
establishes natural program/MC4→external-trigger→profile service0x6338→rate start
0x5f8c/timer enable0x5810. Do not repeat the search for a required G/phase arm;
that is a separate path. Next resolve the current profile-stage duration and
completion predicates, then a continuous completion→eligibility restoration→
second-pulse sequence with held/released and duplicate-request controls. Use a
supported state-preserving timer/IRQ scenario where required; separate cold ISR
runs or forced busy/idle clears do not establish this lifecycle. Distinguish
one profile's rate updates from repeated event authorizations. No physical
V1/V2 waveform attribution is established. Boards were not required for the
first request boundary; revision-specific electrical timing still needs evidence.

The [powered-source connection assessment](docs/investigations/powered-trigger-connection.md)
adds MCU-level transient/startup controls and same-history source ambiguity.
Before assigning Noxon's reported bench-supply effect to capacitance or choosing
an electrical selector, obtain a minimal source/jack/confirmed-sense-node capture
with PA02/mode and firmware identity recorded for each compared revision. Test
nominally inactive insertion, already-asserted insertion and intentional closure.
Conceptual qualification/persistence policies have documented trigger-preservation
costs; do not treat them as implemented or timing-qualified fixes.

## Bring-up contract follow-up

Use the [integrated timeline](docs/investigations/autopilot-bring-up-pass1.md) and
[Pass2 condition matrix/vectors](docs/investigations/autopilot-bring-up-pass2.md)
to define staged application software predicates. The selected continuous
analog and program/MC4/G-request joins are established; do not repeat them.
Remaining decisions/evidence before a complete readiness specification:

1. Resolve or explicitly scope out the full paired Remote S/P/!/program/ACK/MC4
   handshake and retained-channel recovery policy. No automatic repair of the
   retained-A25/requested-A20 mismatch is established; RF confirmation is separate.
2. Resolve only required program units/profile bounds, reference-establishment
   policy and a selected STOP/reset/trigger-phase arming lifecycle. A demonstrated
   software0 reference and G request are not physical position or a safety policy.
3. Validate actual radio/driver configuration, ADC/input behavior and physical
   timing under a separately authorized plan. Continuous alpha0.05/filtering and
   diagnostic suppression are software facts, not physical trigger reliability.
4. Keep NVM interruption, retention, bootloader recovery, USB and product READY
   as separate gaps. Do not expand software bring-up into a broad interruption
   or D-provisioning investigation without a selected consequential question.

Package6 defaults/durability is integrated into this bring-up work rather than
a separate broad configuration survey. No replacement implementation, firmware
modification or hardware action is authorized by these planning entries.

## Configuration-to-behavior investigation

The [first motor-state/reference package](docs/investigations/motor-state-ownership-and-reference.md)
is complete at its bounded exit. Next, choose the retained workflow's durable
program authority and physical reference contract; resolve only necessary record
units/bounds and late MC dependency/application rules. Do not repeat the NVM
round trip or motor bus discovery. The [X/trigger package](docs/investigations/x-trigger-acceptance.md)
is complete at its bounded exit: separate bands, sample freshness, reporting,
eligibility and arming. If legacy triggers are retained, trace one natural
arm/eligibility-restoration sequence with STOP/reset controls; obtain physical
timing/pulse evidence before selecting debounce/re-arm behavior. The
[A/radio package](docs/investigations/a-radio-reconfiguration.md) now establishes
six channel requests, the Remote's five-send/local-retune sequence,915 setup
override and invalid-value mismatch. Before claiming legacy RF compatibility,
resolve remaining packet defaults and selected loss/reset/paired persistence
behavior. Its A25 write-watch discrepancy is isolated and worked around in the
backend; the selected deferred startup/persistence witnesses now match in Pass1.
Do not use the original instrumentation artifact as firmware behavior. The
[D package](docs/investigations/d-serial-number-and-compatibility.md) now resolves
unscaled field9 as the SN display. Decide whether stable displayed identity or
legacy service provisioning is required; only then investigate the missing
provisioning client or selected identity durability contract. No general
durability/defaults investigation was implied by completing the [plan's](docs/investigations/configuration-behavior-investigation-plan.md)
D package; selected package6 questions are now integrated into bring-up Pass1/2.
No configuration implementation or physical validation has been performed.

## Production upgrade/downgrade release gates

Production replacement is NO-GO: obtain actual bootloader/BOSSA provenance,
application-independent entry, live protection/erase bounds, unit-bound full
backups, apfw2 layout/state compatibility, verified SWD or equivalent recovery,
and a representative non-production round trip with interruption recovery.
These require separately authorized physical evidence; no board operations
were performed in the assessment. See
[six-gate plan](docs/investigations/reversible-firmware-update.md).

Gate B remaining work: host PE/x86 analysis now recovers the pinned vendor
client's relevant BOSSA 1.9-family behavior. Obtain exact-build provenance if
available, actual monitor capability/protection evidence, unit-bound backups,
and measured erase/recovery validation. Native host queries cannot establish
physical bootloader survival. Use the [hardware handoff](docs/investigations/vendor-bossac-hardware-handoff.md);
Gate B remains PARTIAL; current classifications are summarized above and
production remains NO-GO.

## Feather original-firmware READY follow-up (2026-10-19)

Configured application operation and version response are now reproducible
through the direct CLI, using PA22 high then release, the existing radio-ID
stand-in and an MC4 configuration exchange. Next: ground any stronger product
READY predicate, deliver transactions through a validated radio/absent-device
model, and assess USB enumeration and command replies separately. Replay the
new controls before extending to AutoPilot915. No intact-Feather execution
trial: validate electrical isolation of all six onboard QSPI conflicts first.
See [resumed report and regressions](docs/investigations/feather-ready-resumed.md).

Current, unfinished work only. For what's already proven and how the
system got here, see [`cases/performing-rigs/status.md`](status.md)
(authoritative) and the relevant `cases/performing-rigs/docs/investigations/*.md` dossier —
completed milestones are not re-narrated here.

## Done (summary only)

- **M1 — AutoPilot-only `&` transaction, end to end.** Closed at the
  concrete tier.
- **M3 — Remote (`mando`) firmware brought up, virtual RF link built.**
  Closed at the concrete tier; `capture_tx_bytes`/`deliver_and_observe`
  are the reusable primitives.
- **M4 — `G → #`, `S → P...`, `!0|/!1| → 11-field CSV`, and
  `I<channel><mode>|/I9|/I1| → signed number` transactions.** All closed
  at the concrete tier through the same virtual link; the event-7
  11-vs-10 field mismatch and the I9|/I1| distinction question are both
  resolved by execution — see
  [`cases/performing-rigs/docs/investigations/protocol-pipeline.md`](docs/investigations/protocol-pipeline.md).
- **M5 — Tool-workbench integration (Ghidra, Unicorn).** Done; see
  [`docs/tooling/tool-selection.md`](../../docs/tooling/tool-selection.md).
- **M6 — Behavior-to-hardware provenance.** The full pivot from protocol
  mapping to physical hardware is done: boot sequence, motor-subsystem
  unlock, motor-config persistence, `'+'`/Auto Mode, Manual Mode/limits,
  and the trigger-input investigation are all closed — see
  [`cases/performing-rigs/status.md`](status.md#major-established-system-facts)
  for the current-state summary and links to each dossier.
- **AutoPilot's TX transport (`0x8c10`)** — confirmed `SERCOM2` SPI
  Master, chip-select `PA15`, no DMA, via the same driver object
  constructed/probed during boot; see
  [`cases/performing-rigs/docs/investigations/boot-and-hardware-bringup.md`](docs/investigations/boot-and-hardware-bringup.md).
  Remote's own `0x58a8` transport remains open (see below).

See [`cases/performing-rigs/docs/investigations/protocol-harness-results.md`](docs/investigations/protocol-harness-results.md)
and [`docs/harness/execution-model.md`](../../docs/harness/execution-model.md) for the harness
mechanics (calling convention, tracing, memory model) established along
the way.

## Open — protocol pipeline

1. **Dormant-event reachability** (events 2, 3, 8, 9, 11, 12, 14) — per
   [`cases/performing-rigs/docs/protocol/open-questions.md`](docs/protocol/open-questions.md), a
   natural Crucible/What4 target now that whole-function execution habits
   are better understood (see the readonly-flash caveat in
   [`cases/performing-rigs/docs/investigations/protocol-pipeline.md`](docs/investigations/protocol-pipeline.md)
   before attempting a whole-function run).
2. **Remote-transmitted-packets-not-in-the-dispatch-tree question** — not
   revisited since the dispatch structure was corrected.
3. **Name the Remote's own TX path transport (`0x58a8`)** — AutoPilot's
   `0x8c10` is now resolved (see "Done" above); the Remote's own
   driver-object pointer, populated by its `0x200038fc` config struct /
   constructor `0x1129c`, has not been walked through the same way. See
   [`cases/performing-rigs/docs/investigations/protocol-pipeline.md`](docs/investigations/protocol-pipeline.md)'s
   open items.

## Open — trigger-input mitigation

A software mitigation (consecutive-sample debounce on the digital arm) is
designed and Unicorn-prototyped in
[`cases/performing-rigs/docs/investigations/trigger-input.md`](docs/investigations/trigger-input.md),
but nothing has been flashed to real hardware. Before any patch is real:

4. **Get physical measurements** at the trigger jack and at PB05:
   transient polarity/duration/bounce count, whether the line floats when
   disconnected, and whether the MCU-side waveform matches the jack-side
   waveform. Also measure the real main-loop period (to convert a
   poll-count debounce threshold into real time) and the minimum
   legitimate trigger pulse width.
5. **Find a verified, real flash code cave** for the mitigation trampoline
   — the current design uses a harness-only scratch page. The most
   promising unexplored option is flash beyond the current image's end,
   within the part's real 512KB; this needs either a real device flash
   dump or vendor/BOSSA documentation review, not assumed blank.
6. Once (4) and (5) are done: pick a real debounce threshold, build a real
   flashable patch, and validate it against a real device — none of this
   has been attempted yet.

## Open — hardware-bringup loose ends

7. **Full paired Remote-session continuity** remains unproven. Pass2 establishes
   the continuous AutoPilot reset/program/MC4/G→request segment with actual
   builder bytes and no application-state seeds. The remaining join is the
   Remote's natural UI/session/handshake/ACK and physical delivery, not the
   former boot/probe-budget issue. Do not substitute that request witness for
   STOP/reset, physical reference or confirmed driver behavior.

## Open — Feather M4 feasibility

9. **Physical feasibility remains unresolved:** isolate and validate all six
   onboard-QSPI conflicts before considering any original-image execution.
   Startup requests GPIO/pulses even without a motion command. The tested PA22
   stimulus is HIGH then LOW, not a permanent3V3 strap; radio readbacks/routing,
   device electrical responses and USB require independent evidence. No intact
   Feather execution trial or hardware operation follows from the simulation.

## Tooling gaps (not firmware blockers)

- **Readonly flash vs. plain Crucible execution**: a whole-function
  symbolic replay through a literal-pool-derived branch doesn't fold
  correctly. Root-caused, deliberately left unfixed — see
  [`cases/performing-rigs/docs/investigations/protocol-pipeline.md`](docs/investigations/protocol-pipeline.md).
  Revisit only if a real symbolic use case needs a whole-function proof
  through such a branch; the narrow fix (baking the specific literal-pool
  words that target reads) is the smallest starting point.
- **`GhidraSVD`** is still not installed as a proper extension; the
  standalone `cases/performing-rigs/config/svd/resolve_mmio.py` resolver remains good enough for
  routine use — install only if that changes.

## Adding new work here

When a numbered item above closes, delete it (or fold a one-line summary
into "Done") rather than leaving a struck-through record — git history is
the record of how it closed. Add new items only for work that is
genuinely not started or not finished; do not use this file to narrate
progress on an item that's already in flight (that belongs in the
relevant investigation's own working notes until it closes).
