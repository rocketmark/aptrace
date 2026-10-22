# Binary patch verification — Gate 3

2026-10-22. Research only. **NOT FOR HARDWARE DEPLOYMENT.** Repository baseline
`c703230ca4df40c69a238dfff53a7b9a5c92298d`. Existing APTrace operations only.

## A. Executive verdict

**FAIL within modeled scope.** Fresh execution reproduces two mandatory-policy
counterexamples: release after the new read does not cancel subsequent
acceptance/initiation (P2), and held LOW plus completion-time W produces another
initiation without an intervening release (P3). These are failures against the
requested candidate policies, not newly discovered regressions against the
original firmware's intended contract. Both were preserved historical findings.

The targeted saved-LOW/current-HIGH rejection remains supported within its
recorded bounds. A new before-read release control rejects; an after-comparison
release variation still accepts. The no-W control completes the first profile
and remains at one initiation through 60M instructions. Six historical replays
match their decompressed snapshots byte for byte. Three new scenario variations
also finish their requested bounded observations. P4–P6 retain material gaps.
No universal safety, physical activation or hardware suitability is established.

## B. Artifact identity and provenance

Case-relative paths unless stated otherwise:

| Artifact | SHA-256 |
|---|---|
| Original915: `research/firmware/originals/firmware_autopilot915.bin`, 70,768 bytes | `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |
| Patched915: `research/generated/trigger-patch-2026-10-22/RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_freshness.bin`, 70,796 bytes | `ae9e6a749426fc3d800a0e26d016cc58f818ce8f84d5a7ba12c41d6d727bc616` |
| Repository `tools/unicorn/concrete.py` | `fcf4529322de345b3f6dd7f4c373084b1957348ade2bb4c1d6acf285d6266f3b` |
| Repository `tools/unicorn/run_concrete.py` | `e91dce33ec855c883dd9ba8ca7c1976020c096552e3300649399b682c3256735` |

Fresh initialization hashes agree with Gates 1/2. Interpreter is Python 3.9.6;
fresh package query reports Unicorn 2.1.4. APTrace version is identified by
repository baseline and backend hashes, rather than an inferred release label.
Both images map at `0x4000`; application reset entry is `0xcc24`.

[Initialization](trigger-patch-gate3-initialization.md) records authority recovery.
[Fresh packet](../../research/generated/patch-gate3-2026-10-22/README.md) contains
commands, raw snapshots, extracted observations, diagnostics and hashes.
[Authoring packet](../../research/generated/trigger-patch-2026-10-22/README.md)
retains the original witnesses and manifests. None was overwritten. Exact
correspondence to the field-tested release and appended physical flash ownership
remain unestablished.

## C. Hypotheses and exploration strategy

Operationalize P2 as no later acceptance or TC0 initiation from the acquired
request after modeled PB05 becomes HIGH; P3 requires an intervening released
input before a second external-trigger authorization, even when W restores
software eligibility. W itself can be an intentional command: whether product
policy should exempt it is a specification decision. This investigation tests
the requested release-to-rearm policy explicitly, without inventing user intent.

Prioritize existing full-reset witnesses, then vary only a sampling boundary or
remove W. Reuse completed Gate 1 structural analysis, Gate 2 differential
controls and Target1/2/3 dependencies rather than repeat full-image discovery.
Nine firmware runs: six exact recipe replays plus before-read release,
after-comparison release and held/no-W controls. One separate doctor branch
run diagnoses execution context. All decisions were Codex selections; APTrace's
native planner was not invoked and did not select this campaign.

The scenarios reconstruct state through original reset/program/MC4 execution,
not snapshots transplanted from another run. Common assumptions include mapped
zero-initialized RAM/MMIO, PA22 startup handshake, radio-ID return, stubbed
`0xcd34`, explicit MMIO completion/clear behavior, supplied RX payloads and a
tick at `0x200052ec` every 4,000 executed instructions. ADC and GPIO rules are
explicit in each command. No application busy/idle/rearm cells are forced in
the new digital controls. W bytes enter the RX ring at `0x6056`; the firmware
parses and acts on them. This does not reproduce RF delivery or a Remote UI.

PC-indexed force rules fire on every hit. Instruction counts, fake timer
values and elapsed physical time are different quantities. There is no
calibrated electrical pulse-width sweep, synchronizer model, autonomous timer
counting or NVIC schedule. Position remains modeled; nonzero physical return
and motor travel are not established.

## D. Counterexample ledger

### G3-CE-01 — release after the new read

**Confirmed within modeled scope; P2 VIOLATED.** Initial state comes from the
authoritative `late-release-patched` full-reset recipe. At `0x9228`, the model
sets PB05 LOW. At `0x1547c`, after the new helper returns LOW, it sets PB05 HIGH.
The firmware then compares the already acquired r0, restores its frame and
branches through `0x15484` to acceptance `0x8f98`.

| Event | Guest instruction | Observation |
|---|---:|---|
| New-read return `0x1547c` | 12,098,793 | r0=0; current input bytes `20000000` (PB05 HIGH) |
| Acceptance `0x8f98` | 12,098,797 | First observed prohibited acceptance after release |
| Rate start `0x5f8c` | 12,327,030 | Pending accepted request progresses |
| Store at `0x571c` | 12,327,115 | CPU writes `0x602` to TC0 CTRLA `0x40003800`, previous `0x600` |
| Enable helper `0x5810` | 12,327,164 | Subsequent explicit helper; not the first ENABLE store |

Evidence: fresh `late-release-patched.json`, byte-identical historical snapshot,
and ordered CPU stores in `observations.json`. Reproduction: direct invocation
in `late-release-patched-command.txt`. New `release-after-new-compare` moves the
release to `0x1547e`, after CMP: it observes HIGH at 12,098,794 and follows the
same acceptance/store milestones. This independently exercises the retained
comparison/flags window, rather than merely relabeling the historical replay.

Independent corroboration: fresh public Ghidra patch disassembly plus Gate 1's
Macaw decode show no subsequent GPIO read on this local continuation. POP.W
preserves the comparison flags. This confirms the local mechanism; it does not
prove the absence of every downstream cancellation mechanism globally. The
observed executed ENABLE store establishes this particular continuation.

The modeled release is not a measured physical edge; physical latency/intent
remain unknown. The 14M run ends at its budget, after the violating prefix has
executed without guest error. Whole-application completion is not required to
observe that already executed store, and is not claimed.

### G3-CE-02 — held LOW, completion, W, second initiation

**Confirmed within modeled scope; P3 VIOLATED.** Initial state and input history
come from `held-w-{original,patched}`. PB05 is seeded LOW from reset and has no
release rule. Actual firmware completes the profile; W is supplied at the
recorded completion boundary without forcing completion or eligibility cells.

| Patched event | Guest instruction | State/path evidence |
|---|---:|---|
| First acceptance / rate start | 12,098,797 / 12,327,030 | Eligible initial LOW |
| Completion boundary `0x6056` | 52,125,562 | Channel/live zero, idle1 |
| Phase store boundary `0x9104` | 52,125,768 | Subsequent idle2, independently visible at W handler |
| W handling `0x865a` | 52,140,327 | Idle2, input still LOW |
| Return request `0x6fd8` | 52,155,465 | Software position/return model retained |
| Eligibility restoration boundary `0x9088` | 52,167,621 | Idle2 before store; idle9 at subsequent acquisition |
| Second acceptance `0x8f98` | 52,167,801 | Earliest observed repeated authorization without release |
| Second rate start / enable helper | 52,400,236 / 52,400,370 | Later live-store `0x5fa4` at 52,400,382 |

Fresh original and patched snapshots each match historical bytes. Original
second acceptance/start occur at 52,167,777 / 52,400,212. This is retained
behavior, not a new patch-induced repetition. Recipes record two live1 stores;
these selected watch ranges do not capture the ordered TC0 peripheral stores.
The completed suffix, helper checkpoint, live store and final enabled register
corroborate initiation; do not claim an independently logged first ENABLE store
for each held/W start.

Reproduction: `held-w-patched-command.txt` and original control. New
`held-no-w-patched` removes only the three W-delivery force arguments: completion
occurs at the same 52,125,562, final idle bytes are `02140000`, and only one
acceptance/start occurs through 60M. Thus held LOW alone is not sufficient for
the second initiation in this bound. Fresh `release-fresh-w-patched` reproduces
the eligible HIGH observation followed by LOW and second start at 52,403,731;
this has no minimum released-duration qualification.

The W/no-W comparison is a causal concrete control, not a proof for arbitrary
commands or repeated completion cycles. Required rearming here means physical
release; software eligibility does restore. If W is intended to authorize a
fresh operation independently of input release, the product specification must
explicitly distinguish that contract. The requested P3 policy does not.

### Preserved rejected and unresolved hypotheses

| ID | Classification | Evidence/reason |
|---|---|---|
| G3-H-01: release before new read still bypasses veto | **Rejected within bound** | `release-before-new-read`: release at `0x15478`, 230 fresh-HIGH returns, 230 rejection branches, no acceptance/start through 14M. |
| G3-H-02: held LOW alone repeats after completion | **Rejected within bound** | New no-W control: one start, natural completion, idle2 through 60M. |
| G3-H-03: active input from reset violates initial-release arming | **Candidate, policy-dependent** | Held runs start without a released observation. Violates a require-release-since-reset policy, but required startup qualification/readiness semantics are unspecified; P4 remains INCONCLUSIVE. |
| G3-H-04: analog/history safeguards can be bypassed | **Unresolved as a safety violation** | Fresh X1 starts at filtered581; X2 with the same supplied 517→600 history does not. No digital-extension entry. This demonstrates absent digital-patch protection, but does not define which analog histories must be rejected. |
| G3-H-05: interrupt changes eligibility after pre-read checks | **Unresolved** | Static ISR-linked idle writer identified; no feasible concurrent entry/interleaving or concrete bypass established. Arbitrary RAM mutation is not a reachable race witness. |

## E. Property verification matrix

| Property/category | Disposition | Evidence and exact bounds |
|---|---|---|
| P1 targeted transient rejection | **SUPPORTED WITHIN BOUNDS** | Gate 2 exact saved-LOW/current-HIGH replay reused; new release-before-read history has 230 r0=1 returns and rejection exits through 14M. Assumes fixed pin metadata, normal helper completion and scenario state/peripheral contracts. No quantified retained-state or interrupt proof. |
| P2 release cancellation | **VIOLATED** | G3-CE-01 and new after-CMP variation: released current GPIO followed by acceptance and executed ENABLE-containing store. CPU/model scope only. |
| P3 no repeated initiation | **VIOLATED** | G3-CE-02: one completion/W cycle, two starts without release through 60M. No-W and release/repress controls bound interpretation. |
| P4 startup and initial arming | **INCONCLUSIVE** | Reset-to-first-start with LOW from boot demonstrates no enforced initial release in this scenario. Required arming/readiness policy, physical reset/retention and already-active input intent remain unspecified. |
| P5 analog-history protection | **INCONCLUSIVE** | Fresh X1 positive reaches live boundary at 12,587,757; X2 negative through 14M, both exact historical replays. Retained-filter dependence reused from Target1; arbitrary histories and required analog safety qualification not established. |
| P6 execution-state robustness | **INCONCLUSIVE** | Actual reset/completion/rearm states and two comparison boundaries explored. No arbitrary-state reachability proof, asynchronous IRQ schedule, stack-margin proof or complete side-effect comparison. |
| Alternative initiation paths | **Partial** | Gate 2 patched915 G/W1/B1 witnesses reused; analog X1 freshly initiates without new guard. Target3's 868 catch-up/group/IRQ routes remain variant-qualified, not freshly proven patched915 paths. |
| Interrupt/timing sensitivity | **INCONCLUSIVE** | External-input update around read concretely consequential; fresh ISR-linked static idle write, instruction-paced scheduling and Gate 2 global ordering mismatch retained. No autonomous IRQ interleaving result. |
| Counterexample validation | **Two confirmed within model; one new timing variant** | Independent decoding, exact replay, original/patched repetition control and W/no-W comparison. Rejected/unresolved hypotheses retained above. |
| Model/evidence completeness | **Incomplete** | Finite CPU executions and selected stores; no universal physical activation, timing, graph or policy proof. |

## F. Analysis completeness and execution

Nine final firmware commands exit0, error=null, memory-hook-single-step, zero
dropped captured writes and no watch-cap termination. Analog X1 stops at the
requested `0x5fa6` live-state boundary; the other eight terminate at 14M or 60M
instruction budgets. These are completed finite observations, not completed
application lifetimes. Six replays have byte-identical decompressed historical
records. Three variations have no historical oracle. `observations.json` is
field extraction and digest comparison, not a new firmware model or verifier.
No artifact assertion count is promoted to a safety proof.

Three initial attempts sourced command files through the shell and exited132
without snapshots. The existing direct doctor CLI then reaches `0x8890` in
three instructions. Direct firmware CLI invocations succeed. Host diagnostic
inspection found SIGILL in `init_cache_info → uc_mem_map`, consistent with the
documented context-dependent native initialization failure; precise denial cause
was not established. No policy, interpreter, package or implementation was
changed. `ps` resource inspection was denied; resource measurements were not
invented. An unmatched optional ISR filename glob was corrected by repository
file discovery. No native guest run aborted after initialization.

Fresh Ghidra operations: patch disassembly, TC0/service decompilation, idle and
channel xrefs, and focused service-store disassembly. TC0 `0x607c` invokes
`0x5be8`; xrefs identify an idle-byte WRITE at `0x5b1a`. Native listing confirms
that store writes1. This identifies a relevant state writer, not a demonstrated
race: prerequisites in group service, pending IRQ feasibility and the full
call-chain effects remain unresolved. Static xrefs are not exhaustive alias
coverage or sufficient proof that an interrupt can arrive at the new read.

The existing library's `deliver_interrupt` is a narrow nested handler call with
manual pending-state setup/resumption, no EXC_RETURN or NVIC priority/masking.
The public one-shot CLI exposes no corresponding interleaving scenario here.
No new harness was created to bridge that gap. Concrete input forces model a
peripheral change, not an interrupt. Gate 2's 357 global fresh-control ordering
differences and unacquired polling differences remain unresolved potential
regressions; named-stream equality does not establish benign ordering.

No new symbolic operation was run: Gate 1's framed fragment abort and Target2's
original868 fixed-slice scope do not supply the missing patched full-state
workflow. Reused Target2 results: seven symbolic eligibility cells with fixed
r5/r6 pointers, stable state/no concurrent writer, pre-read target `0x9226`;
one SAT anchor and seven UNSAT exclusions. Original captured-R0 branch has
another SAT anchor and nonzero-R0 UNSAT. They do not execute the patched helper
or establish reset reachability for every symbolic assignment. Native controls
corroborate those historical fragments only. No new SAT/UNSAT or universal P1/P6
claim is made; all-path-aborted fragment UNSAT remains inadmissible.

## G. APTrace capability assessment

APTrace executed actual firmware, reconstructed application state, applied
explicit stimuli, collected checkpoints and CPU stores, decoded the patch and
exposed ISR data references. Codex selected/decomposed operations, prepared CLI
argument variations, inspected low-level fields and interpreted policy failures.
The native planner generated no scenarios or counterexamples in this run.
Hash/byte comparisons and JSON displays perform evidence inspection only.
No new tests, harnesses, controller, firmware or implementation were written.
No ledger claim admission or release gate was promoted.

| Gap / priority | Observed evidence and impact | Needed capability / likely boundary |
|---|---|---|
| Adversarial campaign and evidence reuse — high, reusable | Manual recovery of recipes, output-path edits, scenario naming and hypothesis ledger. No native P1–P6 plan selected. | Public policy-to-scenario workflow with fresh/historical provenance and coverage accounting. Present one-shot interface is lower-level than requested question. |
| Input-history/event alignment — high, reusable | PC rules repeat; fake instruction tick shifts housekeeping ordering. Before/after read variants require manual selection. | Sampling-event histories, bounded timing exploration and event-aligned comparison preserving global-order contradictions. Physical clock contracts remain case evidence. |
| Reachable state and symbolic replay — high, reusable | Reset/completion states concrete; no parameterized framed patched-state proof. Historical original slices cannot prove patched concurrency. | Reachability constraints, completed-path witnesses, explicit frame/callee contracts and supported symbolic-to-concrete replay. Avoid arbitrary RAM claims. |
| Interrupt/peripheral scenarios — high | Library helper lacks NVIC/exception semantics; no validated AutoPilot continuous timing/IRQ bridge. ISR-linked idle write is static only. | Supported bounded interleaving enumeration with masking/pending/timer contracts and state-preserving replay. AutoPilot clock/position modeling is a separate case limitation. |
| Route/sink completeness — high, reusable | Cached xrefs/CFG unresolved edges and variant-qualified group/catch-up witnesses. | Typed producer-to-output inventory with unresolved-edge obligations and variant identity; no negative conclusion from absent graph edges. |
| Evidence/claim and instrumentation semantics — high | Budget stop versus guest error versus pre-run host crash need manual separation; sparse stores omit direct-path peripheral ordering. | Integrated witness-prefix admission, observer-coverage accounting, complete boundary state and provenance-aware differential reports. Existing traces remain useful, not exhaustive. |
| Execution context diagnostics — medium | Shell-sourced native runs fail while direct CLI succeeds; resource inspection denied. | Clear initialization diagnostics and supported operation provenance without changing security policy. |

## H. Gate 4 readiness and recommended next work

**Gate 4 NOT RUN.** P1's local predicate and P2's sampled release/acceptance/CPU
ENABLE milestones have usable bounded semantics. P3 has a concrete one-cycle
counterexample requiring explicit treatment of W authorization versus physical
release. Preserve both confirmed witnesses in any later formal assessment.
P4 needs initial readiness/release rules; P5 needs analog history, hysteresis,
qualification and threshold policy; P6 needs reachable state, stack and
interrupt/peripheral assumptions. Physical release detection latency and
physical activation are not specified by CPU milestones alone.

Existing-capability next work: selected retained-filter reset histories on the
patched image, specific ISR-writer feasibility investigation and policy-aligned
command lifecycle controls. Development next work: native campaign orchestration,
framed differential verification, event alignment and validated interrupt/model
coverage. New evidence needed: exact field-release identity and peripheral/input
timing contracts. These recommendations do not authorize implementation or
physical operations. A known FAIL does not close the inconclusive properties.

## I. Cumulative verification state

| Item | State |
|---|---|
| Gate 1 | **INCONCLUSIVE** |
| Gate 2 | **INCONCLUSIVE** |
| Gate 3 | **FAIL within modeled scope** |
| Gate 4 | **NOT RUN** |
| Gate 5 | **NOT RUN** |
| Full safety policy | **NOT ESTABLISHED** |
| Hardware deployment | **NOT APPROVED** |
