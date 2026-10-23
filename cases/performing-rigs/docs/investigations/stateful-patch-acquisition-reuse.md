# Stateful patch acquisition-reuse experiment

**2026-10-23. Simulation only — NOT FOR HARDWARE DEPLOYMENT.**

## Result

The final R2 image implements acquisition reuse with the Phase3 qualification
policy and final fresh authorization gate. It is a **bounded analog-workload
improvement with a digital CPU-cost tradeoff**, not an across-the-board speedup
or a field-ready replacement.

Ordinary analog live polling uses one native filter/ADC entry per poll, versus
approximately two in Phase3. Median whole-function work falls501→409 guest
instructions (**18.4%**). Digital busy polling rises158→210 (**32.9%**) because
provenance and dispatch bookkeeping exceed the cheap read saving there. The
500-tick controls remain recognized; analog recognition is10 modeled ticks later.

Two return-boundary counterexamples were found and preserved. Initial reuse
accepted an input Phase3 excluded; a conservative first correction then missed a
legitimate500-tick input. R2 restores the original pre-phase observation only
where W/return processing can change eligibility, and reuses native results
elsewhere. It rejects the early input and accepts the fresh post-idle9 input.
It does not impose R1's extra eligibility predicate or change50/50/20 intervals.

At equivalent profile age/feedback, native evaluator and ordered timer results
match original/Phase3. Absolute/start-aligned streams still differ through sampled
profile age and scheduler phase. Physical timing, complete STEP output and
whole-movement preservation remain unproven.

Final validation: **3,979 checks pass, zero failures or pending cases** across73
comparison records (11 original,31 Phase3,31 fresh R2 histories). R2 also has32
fresh native support controls and one prefix-frame witness:64 native snapshots
in its packet. The generator rebuild reproduces the image hash below.

## Evidence and identity

The [final packet](../../research/generated/acquisition-reuse-r2-2026-10-23/README.md)
contains source, generator, actual image, modification manifest, commands, native
traces, static decoding and saved-artifact checks. The
[initial rejected packet](../../research/generated/acquisition-reuse-2026-10-23/README.md)
and [rejected R1 packet](../../research/generated/acquisition-reuse-r1-2026-10-23/README.md)
retain their images and failing witnesses. Starting evidence is
[Phase3](stateful-trigger-qualification-phase3.md),
[the timing investigation](stateful-patch-motor-timing-preservation.md),
[motor output](vvr-trigger-motor-output.md) and
[the lifecycle](remote-autopilot-execution-lifecycle-phase2.md).

| Image | SHA-256 |
|---|---|
| Original915 | `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |
| First freshness patch | `ae9e6a749426fc3d800a0e26d016cc58f818ce8f84d5a7ba12c41d6d727bc616` |
| Phase3 | `29d4bd68348bcfccef26098c4cf6cc85a1f2ef40a861d046b7c4c43e76f230db` |
| Initial reuse — rejected | `7a0824437f9620321632f141fdca6d755f13396da00a219e9b2d8f43c24f4e96` |
| R1 — rejected | `8ce441ec3f5d3315d41ff1360da26dcba8accf6543c8fbf67be0fae35682b77b` |
| Final R2 | `f20e2004830c1daad818bdfd6155917fe2ab05205fb7c688be1a5358c7ea128a` |

Original images, first patch, Phase3 source/generator/evidence, prior timing
packet, apfw2, formal models and completed Gates1–4 remain unchanged. No Gate5,
framework development, new framework, installation or hardware operation occurred.
Case registry additions identify the three separate research iterations.

## Reused observations and freshness

**Analog.** The original background call `0x8e76→0x42a4` occurs before external
eligibility checks, including during motion. The native filter calls
`analogRead(59)` at `0x42d0` only when its microsecond deadline is due. Its cached
return at `0x42ea` can otherwise contain no new raw conversion.

A six-byte detour at `0x42d4` captures actual returned R0, millis and X, replays the
original LDR/VMOV and continues at `0x42da`. The background wrapper calls the native
filter once, records its integer return and updates qualification. Per-poll type
is cleared first. A cached-only return therefore lacks valid raw provenance and
invalidates qualification; changing the retained float alone cannot authorize.
Native filter initialization, alpha and history are not reset or reimplemented.
Startup observations cannot arm the policy across the program/poll invalidations.

The paired raw and filtered result belong to the observed serialized native
acquisition epoch. Resolved original filter callers are learning at`0x5d88` and
background service at`0x8e76`; direct float writes resolve to the native filter.
These inventories do not exclude all indirect/IRQ writers. The protocol relies on
the original shared filter not being concurrently reentered or independently
modified. It is not a universal reentrancy proof.

**Digital.** The native acceptance read at`0x9228` feeds qualification without a
second poll-entry read on the ordinary eligible path. The original comparison at
`0x922c` receives the same R0. When busy, that native read is skipped; the reject
exit supplies one fallback sample unless the poll already observed input. This
retains inactive qualification while live and prevents active candidates from
being queued through ineligibility. Native TR-reporting reads are not silently
promoted to authorization samples. The rare final grant still reacquires input.

**W/return transition.** Ordinary reuse occurs after the original phase-processing
loop. R2 therefore checks the pending phase word at poll entry. If phases are
nonzero and entry is ineligible, it performs Phase3's fresh observation **before**
that loop and runs the same qualification logic there. A per-poll completion flag
prevents the native wrappers/exit from updating the policy again after eligibility
changes. This is an acquisition fallback at a lifecycle boundary, not a new
eligibility rule. Inactive arming remains independent of Remote eligibility.
It can cost Phase3-like acquisition work during W/return; ordinary motion retains
reuse. No shared scheduler stamp or motion evaluator instruction is modified.

**Storage and age.** The same explicitly reserved64 bytes at
`[0x2000531c,0x2000535c)` are used; reset BSS end and allocator start remain
`0x2000535c`. State/since/context occupy offsets0–20; raw/filtered24/28; last
observation32; provenance type36; consumed counter40; acquisition tick44; X48;
pre-phase-observed flag52; immediate fallback classification56 and mode60.
Types are0 invalid,1 native analog,2 digital,3 immediate fresh pre-phase fallback.

Native observations require matching mode/X and age≤20. Missing/stale/wrong-mode
records invalidate pending state. Native sample ticks drive elapsed qualification
and gap checks, rather than repeated cached-return time. Type3 is produced only
from the just-executed fresh fallback, consumed immediately, and cannot advance
again through the post-phase wrapper. Mode/X are captured before that fallback
and rechecked. Every poll clears validity/completion; program transfer clears
qualification and those validity fields. The retained policy requires50 ticks
inactive,50 active, consumes a grant, and invalidates gaps>20. Unsupported modes
and unsupported analog X values fail closed.

Stamps are firmware millis reads shortly after native acquisition/return, not
hardware ADC timestamps. Sub-tick conversion timing, preemption and continuous
physical input between samples remain unverified. The final gate is unchanged
in policy: fresh acquisition, eligibility/context recheck, bounded interrupt-masked
consume, then original queue store`0x8f9c`. Its R2 consume store is`0x1589e`
(label`commit` at`0x1589c`). Release after consume does not cancel motion.

## Discovered regressions and bounded corrections

The original matrix alone did not expose the temporal problem. Both companion
histories first qualify release while moving and deliver exactly one actual RX
`W|`; no idle/live state is forced.

| Return-boundary input | Phase3 starts | Initial reuse | R1 | Final R2 |
|---|---:|---:|---:|---:|
| LOW at poll entry while idle1, phase3, live0 and policy armed | 1 | **2** | 1 | 1 |
| Fresh500 LOW immediately after native idle9 store | 2 | — | **1** | 2 |

For the first witness, initial reuse records an armed state at idle1/channel0,
then samples after original phase processing restores idle9. It treats the held
LOW as newly eligible, qualifies it and starts again. Phase3 samples before the
restoration and invalidates the armed state. This is a new demonstrated regression,
not merely a different timer phase. The initial candidate is rejected despite
passing its original69-case matrix. Its checker retains the failing assertion.

R1 required active qualification to be eligible both at poll entry and sampling.
That blocks the first witness but rejects a genuine500-tick activation supplied
immediately after the idle9 store. Phase3 retains its earlier inactive arming and
accepts that input; R1 loses it. R1 is also rejected, with its failed positive
control retained. It is not described as an acceptable policy-preserving fix.

R2 instead performs a real fresh pre-phase observation during the ineligible
W/return transition, as Phase3 did, and prevents a second policy update in that
poll. The early LOW clears arming before idle9; the late LOW follows an observed
inactive sample, retains arming and qualifies on later eligible observations.
The positive and negative companions both pass without changing thresholds,
resetting the scheduler, blocking W or adding mid-motion cancellation.

## Regression execution and outcomes

All final candidate histories are freshly executed. Immutable original/Phase3
controls are reused from the complete initial experiment: original11 core runs,
Phase3's18 Phase3 histories, nine acquisition controls, two extra mode/fault cases
and the two return-edge companions. Sources, image hashes and input recipes are
identified per artifact; reuse is not represented as another fresh replay.

| Core history | Original | Phase3 | Final R2 |
|---|---:|---:|---:|
| Fresh digital500 | 1 | 1 | 1 |
| Digital10 | 1 | 0 | 0 |
| Startup active | 1 | 0 | 0 |
| Saved-LOW/current-HIGH PC history | 1 | 0 | 0 |
| Release at final authorization entry | 1 | 0 | 0 |
| Fresh analog500 X1 | 1 | 1 | 1 |
| Pre-arm analog fault | 1 | 0 | 0 |
| Sustained analog fault after arming | 1 | 1 | 1 |
| Held active, W after completion | 2 | 1 | 1 |
| Held active, W during execution | 2 | 1 | 1 |
| Qualified release/repress after W | 2 | 2 | 2 |

The rest of the Phase3 matrix covers nominal49/51 digital pulses, post-commit
release, analog10, intentional X2, real X1→X2 during qualification and invalid-state
injection. Actual quantized waveforms are retained: nominal widths are not equated
with exact physical or acquired durations. All formerly excluded histories have
no newly accepted start in the final bounded matrix.

Focused controls hold the ADC deadline in the future on every poll from tick165,
with/without repeatedly forcing the retained float900; both must reject without
new native conversion. Repeatedly aging an observation by21 ticks also rejects.
The Phase3 stale-cache counterpart is ordinary fresh acquisition, since Phase3
has no reused observation record to corrupt; this distinction is explicit.
Clock-gap and grant-age controls allow20 in the observed phase and reject21.
Mode perturbations test analog↔digital changes with the new input already active;
these are explicit memory perturbations, not claims about a normal mode command.
A real X2 command plus sustained600-count input is inactive in both patched images.

The release-during-motion control releases100 ticks after live, holds inactive
through completion/W, then applies fresh500 activity200 ticks after completion;
it starts twice. Native armed-label observations occur while live in both digital
and analog release histories. Held/W tests restore idle9 without repeating.
G/W1/B1 reach their original live boundary with matching final TC0/live bytes and
zero consumed external grants. No autonomous completion-to-W field loop is claimed.

Seeded native classifier/policy controls separately exercise age20/21, missing
provenance, mode/X mismatches, raw/filter disagreement, X2 fault classification,
49/50 qualification, ineligible active clearing and busy inactive arming. Additional
controls cover the fresh pre-phase record. These are local native executions
under disclosed seeds, not natural provenance or universal verification proofs.

## Workload and motor comparison

Measurements span`0x8e18→0x943e`, including deferred wrappers and native helpers,
partitioned at live1. Measuring only the prologue would conceal moved work. The native5ms scheduler
at`0x93fc` retains stamp`0x20002408` and period`0x20000130` (5,000µs);
the background budget at`0x2000293c` remains3,500µs. No scheduler reset is
introduced. Different helper/filter cadence and authorization times still shift
which evaluator ages occur within each instruction-paced scheduling window.

| Live control | Completed poll spans | Median guest instructions | Filter / ADC entries |
|---|---:|---:|---:|
| Digital original | 326 | 61 | — |
| Digital Phase3 | 307 | 158 | — |
| Digital R2 | 306 | 210 | — |
| Analog original | 312 | 254 | 312 /312 |
| Analog Phase3 | 296 | 501 | 592 /632 |
| Analog R2 | 292 | 409 | 292 /292 |

R2 removes92 median analog instructions (18.4% of Phase3's whole function,37.2%
of its excess over original). It uses one filter/ADC per poll, versus2 filter and
2.135 ADC entries per Phase3 poll in this window. Appended assembly alone does
more bookkeeping; its instruction count omits the native-helper saving and is
not the optimization measure. Counts over a fixed window also include different
start times and incomplete final loop phases.

Digital eligible polling removes a redundant pin57 read, but busy operation still
requires one. Provenance/wrapper/phase dispatch adds52 median instructions there
(32.9%). This remains a material limitation. W/return fallback can deliberately
restore Phase3-like work; no all-state workload reduction is claimed.

| Intentional input | Authorization tick | Rate/live tick | First enabled profile age / CC0 |
|---|---:|---:|---|
| Digital original | 101 | 158 | 53 /`0x5278` |
| Digital Phase3 | 151 | 207 | 52 /`0x5563` |
| Digital R2 | 151 | 208 | 52 /`0x5563` |
| Analog original | 137 | 194 | 51 /`0x5877` |
| Analog Phase3 | 177 | 236 | 53 /`0x5278` |
| Analog R2 | 187 | 244 | 52 /`0x5563` |

Times are relative to setup. Edges are digital101/100/100 and analog100/101/101,
respectively. Final recognition/live latency is51/108 digital and86/143 analog
nominal ticks. Analog recognition is10 ticks later than Phase3: reuse restores
one native filter update stream instead of additional update opportunities.
All tested approximately500-tick intentional inputs succeed; this is not a
physical missed-trigger bound or validation of Nathan's entire pulse distribution.

Each captured CC0 is paired with actual profile age, desired position, raw period
and scaling. Under the observed stage0/zero-feedback state:

`p = 0.0000132 × (profile_age_ms + 5)²`

`raw_period = trunc(120000 / p)`, initially scaled by`>>7`.

The differing initial values still correspond to ages51/52/53. Frozen native calls
at equivalent elapsed/feedback state reproduce original/Phase3 ordered TC0 writes
in R2. Program record, positive direction/endpoint500 and profile coefficients
match. Initial timer-store structure and observed driver data values (`0x00/0x6f`
at the native serial-store PC`0xb46a`) are preserved; differences remain explained
by actual sampled inputs rather than an unexplained trajectory parameter change.
No selected CC0 value or global stream normalization was used to tune the patch.

Analog's first enabled age is closer to original in this one control, digital's
is unchanged. Complete scheduler/output convergence does not follow: absolute
window size, phase and driver ordering can differ. Software position/COUNT remain0;
continuous STEP/TC/NVIC service, complete acceleration/cruise/deceleration and
physical speed/distance equivalence remain unvalidated. The rejected forced-counter
continuation is not used.

## Layout, integrity and provenance

R2 is71,904 bytes:1,136 appended bytes at`[0x15470,0x158e0)` and40 original bytes
changed in nine ranges. It is520 bytes larger than Phase3. Changes are at poll
entry`8e18`, ADC-return capture`42d4`, filter call`8e76`, digital call`9228`,
reject exit`9232`, common gate`8f98`, program transfer`81d0`, and the two explicit
reservation literals`cca0/11050`. Evaluator/scheduler/configuration/vectors remain
byte-identical outside the manifest's listed ranges. Restoring those ranges and
removing the extension reconstructs original915.

The generator pins exact source identity/displaced bytes, assembles installed
clang Thumb code, refuses unresolved relocations and records source/object/image
hashes. Ghidra independently decodes new instructions and detours. Native wrapper
observations preserve tested callee registers/SP, post-helper volatile outputs and
NZCVQ. Raw replay preserves framed registers and original LDR/VMOV effects. The
common gate preserves R0–R12/SP/LR except intended displaced R2/R3. A W/return
prefix-frame witness checks full entry registers and the original48-byte prologue
stack adjustment while the new fallback actually executes. These finite checks
are not exhaustive incoming-CFG, IRQ, APSR or stack-depth certification.

Reset clears all64 reserved bytes; the allocator starts above them. Full state
write watches confine observed writers to the extended reset loop or appended
code. Metadata is trusted software state, not protection against arbitrary
corruption into a valid type/state. Shared-filter serialization and all alias/IRQ
writers remain open. Physical flash ownership, bootloader/checksum/update contracts
and exact field-release correspondence remain unknown; do not flash these images.

## APTrace execution, gaps and next work

Existing Ghidra and native CLI/ConcreteMachine are the analysis/execution mechanisms.
Case recipes supply external inputs, explicit adversarial state/clock perturbations
and observations, not authorization decisions or a replacement emulator. The
artifact checker compares saved values/arithmetic only. Installed clang is used
for the expressly requested binary authoring. Two bounded corrections and both
rejected candidates are preserved; neither failed assertion was silently removed.
Support command construction initially required correcting relative paths/seed
selection before execution; no prior outputs were changed. The R2 assembler first
refused a global-symbol relocation and succeeded with a resolved local alias,
before producing an executable image. No framework/toolchain change was used.

| Gap / evidence | Effect and assessment | Needed capability / priority |
|---|---|---|
| Instruction-paced clock and modeled ADC/SysTick | Guest work is measurable; real CPU cost, sub-tick freshness and deadline slack are not | Measured acquisition/WCET plus independently validated time scheduling, high |
| Stalled COUNT/position; no validated autonomous TC/NVIC continuation | Cannot establish continuous STEP, physical speed/distance or full-trajectory preservation | State-preserving timer/IRQ service checked against measurements, high |
| Finite writer/caller/frame checks | No universal alias, reentrancy, ISR or stack bound guarantee; native shared filter must serialize | Feasible IRQ/caller and ownership/frame verification, high |
| PC-phase/mode/cache perturbations | Establish modeled boundaries, not field waveform occurrence or a normal mode-byte producer | Field build/traffic/waveform and vendor source correspondence, medium |

The result is meaningful for analog redundant work and the tested safeguards;
it does not justify promoting a generally faster or deployable replacement.
Sustained false-active after arming and post-consume release remain Phase3 policy
limits. Next consider reducing digital bookkeeping without losing busy release
observation, and test more W/acquisition phases and calibrated latency. Existing
APTrace can run those comparisons; independent time/IRQ modeling requires separate
development, and hardware timing/build/flash evidence requires new measurements.
These recommendations do not authorize another patch, framework development,
physical operation or certification campaign.
