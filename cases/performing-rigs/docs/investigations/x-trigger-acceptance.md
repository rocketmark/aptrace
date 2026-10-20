# X, trigger recognition and motion-request acceptance

2026-10-20; repository `fb29ce393c31c701a1711cac78e7076a0ebd090e`.
**Result: the bounded X-to-trigger contract is established for AutoPilot868;
physical misfire causation and a natural trigger-to-motion chain remain open.**

X selects an analog inactive band, independently of the boot-selected input
mode. A recognized input, a reported input, an accepted reload, a prepared
program and an armed motion request are different events. Noxon's reload gate
does not validate physical reference or even require an individually valid
motor record. It prepares valid records but clears the examined motion arm.
The first-sample behavior is reproduced; changing X can change the decision
without changing that stale sample.

This completes the X package from the [configuration plan](configuration-behavior-investigation-plan.md).
No A/D investigation, apfw2 or APTrace implementation change, code-image
modification, physical operation, motor execution or release-gate promotion
was performed. A/B/C/D remain PARTIAL; E/F BLOCKED; production NO-GO.

## Evidence and scope

“Demonstrated” means the cited native instruction relationship or original-code
execution under the listed fixture. It does not mean a newly admitted/VERIFIED
claim, exhaustive path proof or hardware confirmation. No ledger was changed.

| ID | Evidence |
|---|---|
| N1 | [New evidence directory](../../research/generated/trigger-x-semantics-2026-10-20/), [exact concrete commands and exit statuses](../../research/generated/trigger-x-semantics-2026-10-20/concrete-commands.json), [observations/checks](../../research/generated/trigger-x-semantics-2026-10-20/observations.json), [provenance/static commands](../../research/generated/trigger-x-semantics-2026-10-20/manifest.json). |
| R1 | [Trigger dossier](trigger-input.md): PA02/PB05 pin resolution, seven digital guards, existing independent bounded solver checks, boot-to-runtime analog latch witness, Remote T-display consumer and MC4 scheduler gate. Its broad negative and repeat-refire conclusions need the qualifications below. |
| R2 | [Motor state/reference](motor-state-ownership-and-reference.md): program records, software position, conditional loader resync and separate G request state; [motor persistence](motor-config-persistence.md) and [persistence assessment](persistent-state-release-assessment.md): staging, checkpoint and reset contract. |
| R3 | [Auto mode/plus](auto-mode-and-plus-command.md) and existing [virtual-link scenarios](../../scripts/virtual_link.py): actual bulk-plus frame, gate producer and independent arm control. No new RF transport or whole-session continuity is claimed here. |

All new runs use the unmodified AutoPilot868 image, SHA-256
`6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3`.
No new 915 equivalence is asserted. Static evidence comes from APTrace's
persistent Ghidra project; instruction ranges resolve material decompiler
ambiguities. Existing solver guards were reused rather than reproved.

## Configuration and lifetime contract

| State | Producer/lifetime | Observed consumer and meaning |
|---|---|---|
| Input mode `0x20001fc0` | R1: PA02 read once during startup; HIGH→1, LOW→2. Volatile. | `0x8e70`: exactly 2 takes digital path, otherwise analog. X does not choose mode. Normal boot supplies 1 or 2; other seeded values are not supported user modes. |
| X selector `0x20000194` | `X1\|` / `X2\|`; stored logical offset `0x33`, staged byte `0x20003179`, flash byte `0x12033`. | `0x8e7e`: 1 writes lower200/upper580; 2 writes lower250/upper750 each analog poll. Other runtime values leave existing thresholds unchanged, but X0/X3 are rejected and boot defaults invalid stored values to1. There is no demonstrated user X0/custom-band command. |
| Analog filtered value / initialized flag | Float `0x2000311c`, flag `0x20003118`, coefficient `0x20000014`; effective rounded integer copied to `0x20000190`. Volatile, separate from persisted X. | First acquisition initializes float/flag; later acquisitions blend `old+(new−old)*alpha`. Observed alpha0 preserves first sample. Neither the X branch nor the examined reload clears the filter flag. |
| Acquisition deadline `0x20003124` | `0x42a4` uses `0xccdc`, a SysTick-derived sub-millisecond clock. | When signed `now−deadline >= 0`, acquire and advance deadline by500, or rebase to now+500 when far behind. This is separate from telemetry timing. |
| Reporting `0x20003120` | TR command runtime state, not X. | Nonzero permits T telemetry when due, and prevents the examined normal reload acceptance gate, even when no telemetry is due. |
| Program/session marker `0x20001b38` | Persisted logical400, boot load; also produced by bulk-plus finalization. | Must equal `0x7b` at trigger reload gate. Not proof that any selected record is valid, references are physical, or transfers were reconciled. R2 qualifies the old unconditional Remote-reconnect claim. |
| Channel state `0x20002524[4]`, idle cell `0x200000d8` | Runtime processing; idle cell can become9 in the state machine and is cleared by reload. | All four channel bytes must be0 and idle cell9 for acceptance. These are execution-state guards, not input debounce or physical-reference checks. |
| Record `+0x44` | Local loaded program record; channel stride `0x120`, record stride `0x48`. | Tested truthy/zero controls profile preparation and the pre-trigger armed move branch. It is not tested by the shared input-to-reload gate. |
| Resync request `0x20000134[ch]` | R2: software request, consumed/cleared conditionally by loader. | Can rebase record start onto current software position during accepted reload. No homing/encoder-valid predicate is established. |
| Phase arm `0x20002318[ch]` | Independent command/state transitions (R1/R3), not X. | Reload clears it for valid channels. The earlier per-channel portion of `0x8e18` can commit an already armed, valid record before reaching the trigger/reporting logic. G uses a separate request state (R2). |

N1 `x-command-native.txt` (`0x8918..0x8934`) checks command X and the next
character '1'/'2', writes the runtime u32, then tail-calls the common dirty-byte
setter with index `0x33`. `x-dispatch-{1,2}.json` execute the real dispatcher
`0x8258`, returning cleanly with the expected runtime/staged byte and dirty1.
`x-dispatch-{0,3}.json` leave prior selector2 and staging/dirty unchanged.
These witnesses do not establish strict validation of every possible malformed
packet or delivery over a physical radio/USB link.

`fresh-reader-x{0,1,2,3}.json` call original boot reader `0x4c20` in fresh RAM
with provisioned flash data: stored1→1, 2→2, 0/3→1. Invalid X is defaulted in
RAM; this branch does not repair the stored byte. Other boot fields can dirty
the blob, so the fixture's dirty byte is not evidence of X repair. These are
fresh-reader fixtures, not four complete hardware resets. The X command stages
data; durability still requires the separate checkpoint demonstrated in R2.
No new X-specific save/power-loss experiment was needed or claimed.

## Input-to-outcome mapping

“Active” below is a software classification: analog outside the inclusive
inactive band, or digital LOW. It says nothing about voltage, contact quality
or motor activation. “Accept” means arrival at original `0x8f98`, before its
reload side effects, unless a row explicitly continues through reload.

| Condition | Recognition/report | Acceptance / motion consequence |
|---|---|---|
| Analog, X1 | Inactive `200 <= sample <= 580`; active outside. | With other guards satisfied and TR0, active reaches `0x8f98`. |
| Analog, X2 | Inactive `250 <= sample <= 750`; active outside. | Same acceptance rule. This is a different band, not uniformly “more sensitive.” |
| Digital, X1 or X2 | LOW active, HIGH inactive; no analog helper called. | Both tested LOW cases accept; HIGH rejects. X has no effect on this path. |
| TR1, active, telemetry due | Analog225: X1 sends `T225,0,\|`; X2 sends `T225,1,\|`. Digital LOW sends `T0,1,\|`. | Reporting is independent of program marker. It does not imply acceptance; continuation after a stubbed TX rejects at `0x9232`. |
| TR1, active, telemetry window spent | No T send. | Still no acceptance: reporting flag blocks it. Lack of telemetry is not an inactive-input observation. |
| TR0, active, telemetry window spent | No T send. | Acceptance still occurs; telemetry timing is not debounce or an acceptance rate limit. |
| TR0, analog225/X2, marker≠0x7b, one busy channel, or idle≠9 | Active classification unchanged. | Each tested changed guard rejects. Digital guard necessity also has R1's existing symbolic corroboration. |
| TR0, active, marker7b/idle9, all individual records invalid | Shared acceptance entry still reached. | Full reload returns status3, no prepared channel; no commit. Marker validity and record validity differ. |
| Same fixture, valid channel0 +500 record | Same acceptance entry. | Full reload returns status3, prepared channel0 flags1, phase arm0 and idle0; no commit. |
| Held LOW on carried valid post-reload state | Input still active. | Next bounded invocation does not reaccept or commit; channel state1/idle0 now block the gate. |
| Independently seeded phase arm2, valid channel0, current600, HIGH input/TR1 | Stops at commit **before** trigger processing. | Request `(channel0, mode0x32, distance−600, profile0)` uses saved start0 minus software current600. This is a separate arm control, not a trigger-induced request. Validity0 suppresses this control's commit. |

N1's sixteen `band-x*` runs cover 199,200,249,250,580,581,750,751 for
both selectors. All actual boundary values are inactive for their band.
The analog gates at `0x8f48..0x8f94` and digital gates at
`0x9202..0x922e` explicitly separate the idle/marker/reporting tests from
the input condition. T messages describe input state, not request eligibility.
They are emitted for inactive as well as active input when reporting is due.

## Sampling, latching and state transitions

1. **Startup** chooses PA02 mode and loads/defaults X. R1's boot baseline
   path reaches the filter; its first acquired sample initializes the float.
   Neither a known initial position nor a valid motor program follows from it.
2. **Poll** processes existing per-channel phase state first. In analog mode
   it calls the acquisition/filter helper, stores its rounded output, selects
   the X band, then handles logging/reporting and the reload gate. Digital mode
   bypasses that filter and band selection. The input read is conditional on
   its consumers; it is not necessarily acquired on every loop iteration.
3. **Recognized + report-enabled** can send a T frame if the roughly500ms
   reporting window is open, regardless of program eligibility. It then fails
   the normal acceptance guard. Reporting is not an additive diagnostics tap.
4. **Recognized + report-disabled + idle/marker guards** enters `0x8f98`,
   writes status3 and tail-jumps to `0x6e4c`: clears a control cell, reloads
   configuration, builds profiles, clears arms/idle, and requests the known
   PB30-high/PB31-low GPIO side effects. These are real output requests in the
   model; absence of move-commit is not proof that arbitrary hardware is safe.
5. **Reload reference handling** remains conditional. With the same native
   plus record and software current600, `reload-reference-preserved.json`
   retains start0/end500; `reload-reference-resync.json`, changing only the
   resync flag to1, reaches `0x4b24`, produces start600/end1100 and clears the
   flag. Both remain unarmed. A current counter and resync request are not a
   verified physical reference; no explicit reference-valid prerequisite was
   found on the examined trigger gate.
6. **Subsequent LOW** does not automatically restore the now-false guards.
   R1's LOW-count matrices restore idle conditions or stop before reload.
   They demonstrate a level gate without input history, not an uninterrupted
   held-input→repeated-reload/motion sequence. Reacceptance after other firmware
   transitions restore eligibility remains possible, with no edge/release
   qualification in this gate; its natural timing is not established here.

The filter tests distinguish **new acquisitions** from **new effective values**:

| Experiment | Observation |
|---|---|
| `filter-clock-before-deadline`, clock499/deadline500 | No ADC boundary reached; returns cached225. |
| `filter-clock-at-deadline`, clock500/deadline500 | Acquires injected900; advances deadline1000; alpha0 still returns225. |
| `filter-new-session` | Cold flag/float; injected900 becomes the effective first sample and returns900. |
| `filter-alpha-one-control` | Disclosed counterfactual alpha1; same prior225/new900 returns900. Not an original configuration or proposed fix. |
| `latched-x1` versus `latched-x2` | Both acquire900 but retain effective225. X1 rejects, X2 accepts, solely because the band changed around that stale225. |

The existing latch xrefs contain one read/one write-to1; coefficient xrefs
contain the read and no resolved writer. Together with the cold/boot witnesses
this supports first-sample freezing in the examined model, not universal proof
against every aliasing writer. X does not fix that behavior.

**Timing correction to R1:** `0xccdc` reads SysTick and the millisecond counter,
multiplies the latter by1000 and adds a fractional term (`micros-native.txt`).
The filter's500 therefore uses nominal microsecond-scale units. Telemetry uses
`0xccd0`, the millisecond-counter read, with500. Physical rates/jitter are not
measured. Calling both “500 ticks” hid a thousand-fold unit distinction.
The older statement that analog “never resamples” is also incorrect: it can
reacquire while preserving the effective value through alpha0.

## What changes our understanding of misfires

The first-sample anomaly remains a credible software defect: it makes later
analog acquisition ineffective under observed initialization. A changed X can
also reclassify a stale value, so an apparent response to configuration does
not prove that the sensor is being sampled effectively. The two preset bands
shift both boundaries; they do not form a simple sensitivity ordering.

Digital no-history qualification and conditional repeated eligibility remain
plausible nuisance-acceptance mechanisms. But “one accept per LOW poll” is not
the natural post-reload behavior demonstrated here. Reload's self-clearing
idle/channel state can explain a one-shot **software reload** in the fixture;
it does not explain the reported physical movement by itself.

Reporting active input can coexist with a missing program or blocked request;
silence can mean throttling rather than inactivity. Entering TR diagnostics
also changes acceptance behavior. Those are plausible sources of confusing
field diagnosis, not established explanations of a particular incident.

The deliberate selector validation, bands and eligibility branches are clear
code contracts. Their product intent is inferred. Zero-alpha initialization
and diagnostic/execution coupling look undesirable for a reliable replacement;
calling them intentional safety features is unsupported. Physical jack bias,
threshold voltage, transients, bounce, minimum pulse width, real loop timing,
natural arm/STOP/RF-loss transitions and actual driver activation remain open.
No universal “neither arm can cause uncommanded motion” conclusion follows.

## apfw2 requirements and behaviors to avoid

These are design recommendations grounded in the recovered failure modes,
not claims that the replacement must implement every Noxon feature.

| Explicit state/contract | Requirement for a retained programmed-trigger workflow |
|---|---|
| Input configuration | Separate electrical mode, polarity, analog inactive/active thresholds and sampling/filter parameters. Validate ranges and threshold ordering. Preserve X1/X2 wire compatibility only if required; do not label them monotonically sensitive settings. |
| Sample health | Track sample value, timestamp, freshness and initialization. Initialize filter coefficients deliberately and test that a new valid sample can change the effective value after startup. Stale/uninitialized samples must not silently authorize a move. |
| Qualification | Use an explicitly specified time-based debounce/hysteresis/release contract, informed by physical pulse/bounce measurements. Do not inherit a per-loop count as a known duration, the accidental first-sample freeze, or unconditional repeat-fire compatibility from restored-gate tests. |
| Program and reference | Validate program integrity, indices, units/ranges and derived targets separately from a transfer marker. Maintain physical/reference validity independently of the software position counter; reset/resync must have explicit invalidation/revalidation semantics. |
| Request arming | Separate input-recognized, candidate event, eligibility, armed, accepted/queued and running states. Reject/record a reason when program, reference, desired/applied driver setup, execution state or safety conditions are not qualified. Initialization, reset and reconnect must not implicitly arm. |
| Re-arming / configuration change | Specify release/dwell and held-active startup behavior. Invalidate/requalify a pending candidate when mode/band/program/reference changes. Decide explicitly whether held input can retrigger once execution becomes idle; do not inherit this by accident. |
| Diagnostics | Report raw/effective value, freshness, recognized state, eligibility/arm state and rejection reason independently. Diagnostic subscription should have a documented execution policy; avoid an undocumented TR-style flag that quietly disables requests. |
| Storage | Persist only intentional configuration/program content with validation/version/default rules. Treat edits, staged data and durable data separately; runtime filter latch and physical-reference validity should not be inferred from a persisted selector or target. |

Do not carry forward magic marker7b/idle9 as a substitute for these states,
truthy record bytes as full validation, stale absolute targets across reset,
or Noxon's undocumented GPIO pulse as an apfw2 trigger requirement. Actual
motor activation additionally requires the independent MC4/driver-applied and
safety contracts in R2 and the existing TMC work.

## APTrace execution and capability gaps

Used APTrace's documented Ghidra query interface for bounded native ranges,
pointers and xrefs, and the verified direct `run_concrete.py` CLI for59 runs.
All authoritative dispatcher/helper/phase witnesses return or reach their
declared boundary. Two initial RX-wrapper attempts exit1 after valid-X writes:
their trace passes the requested `0x8a38` boundary and then faults on the
wrapper's unseeded zero pointer. They are retained as failed attempts, not
successful packet executions. Directly calling the actual dispatcher with the
existing AAPCS helper gives cleanly bounded replacements; no backend fix or
security bypass was attempted. One “not due” probe actually was due because
it conflated the two clock units; the two explicit deadline probes supersede
that label. See the manifest for exact execution qualifications.

Analog experiments stub only the ADC helper `0xd1b4` and inject a declared
sample at its return `0x42d4`; original filter/comparisons still execute.
Clock-boundary probes disclose the clock-return override at `0x42aa`.
Digital probes use plain MMIO pin state. These are controlled software inputs,
not ADC conversion/electrical models. Native plus supplies channel0/staged
records/marker for reload tests; idle/mode state is disclosed fixture state.
The held-LOW follow-up carries the relevant post-state, not a whole machine
or naturally scheduled RF session. Profiles are not qualified trajectories.
The independent arm2/alpha1 controls are explicitly counterfactual fixtures.
All commit observations stop before commit executes.

| Gap / missing evidence | Impact, observation, needed work and priority |
|---|---|
| Electrical/ADC/timing model absent | Plain MMIO and injected ADC returns cannot establish voltage, noise immunity or reliability. This is an existing model limit, not a newly diagnosed defect. Obtain measured input/timing evidence and validated peripheral models if needed; high for physical reliability. |
| Natural trigger-to-motion and reference-valid join unresolved | Shared reload clears arms; independent arm can commit earlier in the function. Bounded evidence does not settle all command/interrupt interleavings or physical position. Existing tools can investigate a selected natural arm/restoration/STOP path; high if legacy trigger semantics are retained. |
| RX-wrapper boundary did not bound two valid-X runs | Original operations reported structured faults after intended boundary; direct dispatcher call answers this package but not natural RX continuity. Cause of boundary overshoot is not diagnosed; reproduce minimally in a separate tooling task if needed, without asserting a firmware failure. Low for this bounded result. |
| Indirect-writer completeness / product intent | Xrefs do not prove absence of every aliasing write; code behavior cannot prove intended UI semantics. Existing watchpoints/whole-startup traces can challenge specific counterexamples; product documents/device evidence are a separate dependency. Medium. |

## Recommended next work and exit

The package stops at its planned boundary: X selection/reset behavior,
inclusive bands, first-sample/filter controls, reporting divergence, marker
versus record validity, conditional resync and absence of a new arm in the
tested reload are reproducible. No broader trigger census or A/D work is needed
to use these results.

Using existing APTrace, the highest-value **trigger follow-up**, if retained,
is a single natural command/phase-arm→eligibility-restoration→trigger sequence,
with STOP/reset interruption controls and the driver-applied gate observed.
Do not infer that sequence from forced arm2. Exact X checkpoint timing can be
tested through the existing persistence workflow if compatibility requires it;
the shared mechanism alone does not settle power-loss durability. Framework
development is not required to interpret this package; any wrapper-boundary
repair or new peripheral model belongs to a separate development task.
Physical reliability and reference correctness require new physical evidence,
outside this session's authorization. The separate A/D packages remain unstarted.
