# Target 1 — startup voltage learning and trigger behavior

2026-10-22. **The startup routine does influence later triggering through the
analog filter history it initializes. Its separately stored average and
low-baseline flag have no demonstrated downstream effect in the analyzed
paths.** Changing those two stored results alone leaves the recorded execution
identical; changing only retained filter history changes acceptance and timer
initiation. No adaptive standby subtraction or learned trigger band was found.
This is a strong bounded causal result, **not a whole-program proof that the two
stored cells can never be read through an alias**.

[Evidence packet](../../research/generated/startup-baseline-2026-10-22/README.md),
[commands](../../research/generated/startup-baseline-2026-10-22/commands.json),
[outcomes](../../research/generated/startup-baseline-2026-10-22/outcomes.json),
[44/44 artifact checks](../../research/generated/startup-baseline-2026-10-22/checks.json).
Seven new full-reset original-firmware executions were made through APTrace's
direct Unicorn CLI. No original image, apfw2, framework implementation, hardware,
ledger admission or release gate was changed. Target2 and Target3 were not opened.

## Evidence and recovered computation

Start with [trigger-input](trigger-input.md), [bring-up Pass1](autopilot-bring-up-pass1.md),
[Pass2](autopilot-bring-up-pass2.md), [failure modes](trigger-misfire-failure-modes.md),
[powered connection](powered-trigger-connection.md), and the
[descriptive formal model](noxon-trigger-state-machine.md). Two corrections remain
essential: normal reset initializes alpha0.05, and the scheduled profile route
can start the timer without a separate G/phase arm. Neither a permanent frozen
first sample nor absence of0x6fd8 is a valid normal-startup conclusion.

Both packaged AutoPilot868 and AutoPilot915 execute `0x5d44` during the new normal
analog-mode reset paths. Each makes **128 filter calls**, observed at `0x5d8c`;
only **three actual ADC acquisitions** occur inside this loop under the disclosed
instruction-paced clock. “128 samples” therefore means128 returned filtered or
cached integers, not128 independent measurements at a demonstrated physical rate.
Normal hardware acquisition counts/timing are not established by this simulation.

The baseline/filter/classifier and selection ranges are byte-identical between
variants; exact ranges and hashes are in `variant-region-identity.json`. Ghidra's
915 project was built through the normal interface and its decompile/xrefs agree
with868. This is a targeted equivalence observation, not whole-image equivalence.

| Routine/state | Recovered operation and lifetime |
|---|---|
| `0x5d44..0x5db0` | Calls0x5d24/0x434c with200/100/200 delays. Writes constant1400 to0x20001fc8 and zero to0x20002098,0x2000313c,0x20001fc4. These stores precede acquisition and do not depend on measured voltage. |
| Mode `0x20001fc0` | At0x5d80..84, exactly2 skips the128-call loop and average/low-flag updates. Original boot0x6968 samples PA02 once: HIGH→1, LOW→2. X is independent. New runs use actual PA02 mode1 selection; mode2 skip is native instruction evidence plus existing digital boot witnesses. |
| Filter `0x42a4` | Clock/deadline0x20003124 selects due acquisition; ADC helper0xd1b4 returns at0x42d4. First due sample initializes float0x2000311c/flag0x20003118. Subsequent acquisitions blend with alpha0.05; other calls return cached history. The baseline loop calls this same stateful filter used later. |
| Sum in r4,128 iterations | `0x5d8e` adds each returned integer. Average is signed division by128, truncated toward zero (negative bias127 before arithmetic shift). Actual input examples are nonnegative. No conversion from ADC counts to jack volts is established. |
| Average `0x20003128` | `0x5da4` stores the divided sum. Constant225 produces225; constant900 produces900. It remains in RAM through the observed subsequent loop/start boundary. It is not evidence of durable NVM persistence. |
| Low-baseline flag `0x200023c0` | Compare **sum** to0xaf00 (44,800; equivalent to a350 boundary for a constant stream). If lower,0x5dae writes signed−100. Otherwise no store here; reset zero remains0 in900 runs. No measured-unit interpretation or downstream threshold adjustment is established. |
| Runtime analog `0x8e18` | Actual returned filter value is copied to0x20000190. X1 inactive inclusive200..580; X2 inclusive250..750. The examined comparison uses fixed bands, not average±offset. Neither X handling nor the examined reload resets this filter history. |
| Acceptance/initiation | Shared0x8f98 guard then reload0x6e4c/0x6b50 prepares channel/profile1, idle0. Scheduled0x6338→0x5f8c→0x5810 enables TC0; original live1 at0x5fa4, stop0x5fa6. This is software initiation, not physical movement. |

## Paired execution and causal controls

All cases consume the same original Remote-built nonzero profile and native MC4.
They start at original reset, with actual PA02 selecting analog mode1. Startup
ADC is225 or900. **At baseline return0x5db0, ADC becomes225 in every run** and
remains225 through later trigger processing. Existing94e4 input delivery also
writes225. Configuration and post-baseline waveform are otherwise identical.

Common hardware assumptions are inherited from the validated natural profile
fixtures: PA22 startup HIGH→LOW, radio-ID r0=0x12, explicit MMIO completion bits,
TC READSYNC completion, DWT delay stub0xcd34, fake tick every4000 instructions,
and PC-timed RX ring delivery. None proves actual peripheral readiness or RF
communication. The input change is a PC-boundary experiment, not calibrated time.

| Run | Startup ADC | Stored average/flag after return | Retained filter after return | Runtime returns / result |
|---|---:|---|---:|---|
| natural225 (868) |225|225 /−100|225|225 continuously; no acceptance/start by14M instructions. |
| natural900 (868) |900|900 /0|900|866,834,804,775…; accepts866, then initiates with filter455. |
| average-injected |225|**900 /0 injected**|225|Same no-start result as natural225. |
| average-reversed |900|**225 /−100 injected**|900|Same acceptance/start as natural900. |
| filter-control |900|900 /0 unchanged|**225 injected**|225 continuously; no acceptance/start by14M. |
| natural225-915 |225|225 /−100|225|Same negative outcome as868. |
| natural900-915 |900|900 /0|900|Same positive outcome as868. |

The interventions are deliberate **RAM causal probes**, not natural operating
scenarios, original-image changes or suggested patches. Both derived cells are
crossed over together at baseline return; this tests the joint result and any
normal readers of it, including indirect ones reached in these executions. It
does not assert that either alone has arbitrary-state noninterference.

For natural225 versus average-injected, and natural900 versus average-reversed,
**every recorded register/watch state, instruction index, final memory byte and
stop outcome is identical after excluding only the two intentionally changed
cells**. External force logs intentionally differ. The original CPU write-watch
also captures reset zeros and average/conditional-flag writes, with no subsequent
CPU writes to either result cell within the observation window. Harness injections
are separately recorded and are not misrepresented as original CPU writes.
No watch-cap exhaustion or memory-write-log drops occurred.

The natural900868/915 cases accept at instruction12,103,180 with filtered866;
rate start at12,336,878, timer-enable helper at12,337,012, live write12,337,024,
and stop12,337,025 after execution of that write. Consult `outcomes.json` for
exact native anchors. The raw ADC had been225 since baseline return near9.50M;
retained filter state, rather than a continuing active raw input, crosses into
normal acceptance. At initiation filtered455 is already inside X1's inactive
band. Subsequent input release/decay does not cancel the committed profile.

This establishes a concrete dependency chain:

`startup acquisition → shared filter float/flag → runtime filtered value → fixed-band classification → accepted reload → profile-rate/timer initiation`.

It does **not** establish:

`stored average/low flag → learned standby threshold → rejection of that standby`.

The earlier `profile-startup-active` fixture also starts with900 held throughout
startup/runtime. Thus these software paths do not demonstrate that measuring an
arbitrary active standby makes it safe/inactive. Successful averaging is not
successful compensation.

## Reader/writer, alias and symbolic assessment

Ghidra's recovered references in both variants identify average WRITE0x5da4 and
low-flag WRITE0x5dae, with no established subsequent READ consumer. Average also
has a `[DATA]` reference at0x5dae. That is **not a demonstrated read**: native
0x5dae is a predicated store, using the pointer loaded from0x5dcc under the same
LT condition. Do not count a conservative merged pointer reference as evidence
that runtime trigger code uses the average.

APTrace's exposed p-code `value_forward_use` was run on0x5d9e (average in r3) and
0x5daa (−100 in r2). Both report **MEMORY_ESCAPE**, not a dead-value proof.
The average reaches store0x5da4 and is killed/overwritten before function return.
The may-flow walker also reports a possible store-address use at0x5dae; predicated
instructions are over-approximated and it does not prove correlated conditions
exclude that path. Its documented absence of memory-alias/interprocedural flow
means it cannot follow the stored result into arbitrary later consumers. Full
result, assumptions, origin/function bounds and Ghidra identity are preserved.

The independent existing Macaw expansion has263 discovered functions,199
incomplete/unresolved terminators and48 residual classification failures. The
0x5d44 region is not recovered with the same boundaries as Ghidra: Macaw gives43
blocks and the effects run extends beyond native baseline return into following
code. Its result cannot close a whole-image alias/callback audit. The extracted
coverage record is in the packet; original full expansion is hash-bound.

Two existing `function-effects`/Crucible/What4/Z3 operations were attempted only
for Target1 dependency scope:

- **Baseline0x5d44:** raw status `partial (some paths aborted)`,22 Macaw blocks,
  36 reads/19 writes/141 opaque calls. It records average store0x5da4 but has
  symbolic stores and following-function effects inconsistent with a complete
  isolated baseline CFG. Assumptions: Thumb/AAPCS opaque calls clobber argument
  registers but have no memory effects; concrete readonly image, unconstrained
  RAM/MMIO, zero non-GPR bookkeeping registers,3,000-step bound. In particular,
  opaque0x42a4 cannot prove absence of the **actual** filter side effect.
- **Trigger0x8e18:** bounded at3,001 Crucible steps,90 Macaw blocks,1,243 reads,
  12 writes/244 opaque calls and490 non-stack symbolic access addresses. No direct
  concrete baseline-cell read is listed, but these symbolic addresses and opaque
  callees are unresolved dependencies, not excluded aliases. The per-channel
  phase path dominates this execution; later normal classifier coverage is not
  established by its termination status.

**No relational nondependence SMT query was available or proved.** These runs
produce built-in guard/region facts, not a two-execution equivalence theorem.
`symbolic-assessment.json` retains exact outcomes and relevant queries. Baseline
query11 asks whether access23 at0x5dae is in FLASH0x4000+0x11470, under the above
base assumptions; it returns **UNKNOWN**, not exclusion of a baseline consumer.
The successful SAT facts around the average store corroborate only reachability
inside that abstraction. Trigger guard queries include UNSAT for both a guard
and its refutation under asserted common assumptions. This cannot be interpreted
as a meaningful universal no-dependency result; its assumption/path feasibility
has not been validated. No solver outcome here establishes an absent hardware
mechanism or safe trigger behavior.

Classification of the conclusion:

| Evidence standard | Result |
|---|---|
| Confirmed dependency in original execution | **Yes:** startup filter history changes native classification, acceptance and timer initiation with identical subsequent ADC/configuration. Filter-only intervention removes that start. |
| Dependency/nondependency established by bounded symbolic analysis | **No accepted relational result.** P-code proves an escaping store within its may-flow scope; effects runs are partial/bounded, with opaque calls and unresolved symbolic addresses. |
| No dependency found within stated recovered/tested paths | **Stored average and low flag:** no subsequent concrete consumer recovered, crossed-over values have no recorded downstream effect in the normal868 profile scenarios.915 natural pair and byte-identical relevant code agree. |
| Unresolved whole-program dependency | Arbitrary aliases, indirect/callback/IRQ paths, other modes/programs and unmodeled peripherals are not exhaustively excluded. No claim that all possible readers have been found. |

This goes beyond ordinary xrefs by testing both derived globals together across
complete original startup→trigger→initiation runs, separately perturbing the
filter history, collecting address-based CPU write watches and attempting both
p-code flow and independent symbolic effects. It still cannot replace a complete
memory-alias proof with a failed search.

## Meaning for the reported product behavior

Nathan's account of Noxon's advice is a reported observation, not a firmware
specification independently recovered here. The shipped software does sample
startup input and retain filter history. Consequently connecting a chain before
power-on can change early behavior, and a transient during this window can affect
later recognition. A setup-only disturbance with **no ADC acquisition** need not
have the same effect, as the earlier powered-connection negative control showed.

There is no evidence here that the calculated average calibrates the later
trigger threshold, learns arbitrary standby voltage, identifies source intent,
or compensates for polarity. PA02 selects mode independently; mode2 bypasses
analog baseline averaging and polls PB05 active LOW. We cannot map PA02 to
Noxon's relay/12V/24V product labels without the circuit evidence. Analog fixed
bands can classify either low or high extremes as active, but ADC counts are not
jack voltages and do not establish the physical origin of polarity sensitivity.

Another undiscovered standby-learning mechanism is not logically excluded by
partial CFG recovery. Existing recovered mechanisms already explain a startup
history dependence without invoking one. Stronger claims that the entire routine
is dead, or that it implements adaptive standby compensation, should both be
avoided. Old “dead baseline” language is defensible only for the two derived
cells within the stated evidence scope, not the stateful sampling routine.

## Execution, gaps and next work

All seven concrete commands completed exit0/error-free through the verified
direct CLI and corrected memory-hook path.44/44 bounded artifact checks passed.
Both symbolic processes exited0, which signifies output production, not proof
completeness; raw/enriched results and solver logs retain the limitations above.
Static commands used normal Ghidra interfaces and the explicit-target public
p-code driver. Initial915 query needed a normal project build; a missing p-code
scratch directory and literal-address prefix error were corrected. An optional
process-list/interrupt diagnostic was unavailable in the sandbox; no security
bypass was used. The symbolic run completed normally with one UNKNOWN query.

**Capability gap (medium):** current public effects and p-code operations do not
provide an alias-complete, interprocedural two-execution noninterference check for
these stored RAM outputs. Impact: no universal dead-state theorem; observed
coverage/opaque calls/partial CFG and MEMORY_ESCAPE are the concrete evidence.
Needed capability is a validated bounded relational/alias workflow with explicit
callback/IRQ coverage, not a new framework installed for this task. No development
was undertaken.

**Existing-tools next experiment, only if stronger scope is required:** extend one
of the identical mean/flag crossover pairs with a selected suspected consumer /
callback or additional supported input mode, preserving downstream state and
watching that consumer's live operand. Native instruction inspection can resolve
any concrete reader candidate before another targeted effects query. A global
“find every consumer” theorem remains beyond the demonstrated interface; do not
make it a prerequisite for accepting the concrete filter-history dependency.

**Ready to review and move to Target2:** yes, with a corrected premise: separate
learned-result cells from shared filter history. Target2 must establish feasible
symbolic scope before interpreting guard UNSAT. This investigation does not solve
Target2 acceptance completeness or Target3 motion-route coverage. Physical causes
of Nathan's startup/polarity misfires still require a minimal synchronized source /
PB05/PA02 capture, not another broad hardware survey. No physical experiment is
performed or authorized by this result.
