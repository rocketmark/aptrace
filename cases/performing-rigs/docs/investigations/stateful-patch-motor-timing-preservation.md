# Stateful patch motor-timing preservation investigation

**2026-10-23. Simulation-only original/patched binary execution. No firmware changes.**

## Result and answers

The Phase3 CC0 differences are **explained within the execution model**. The
images calculate the same prepared profile at different elapsed profile ages.
The stateful patch changes both authorization time and recurring background
work; profile preparation and the shared evaluator scheduler have distinct time
origins. Aligning on authorization, live1, or instruction count does not align
those origins or subsequent evaluator sample times.

1. **Why different periods?** At the first actual timer start, digital original
   evaluates profile age53ms, stateful52ms; analog original51ms, stateful53ms.
   The evaluator adds its native5ms look-ahead. Identical coefficients and
   feedback then yield exactly the observed periods. The later output sequences
   also sample the profile on different schedules and span different amounts of
   modeled motion time in a fixed instruction window.
2. **Model versus firmware?** The extra instruction/acquisition work is real
   executed firmware work. Its conversion to time by one tick per4,000 guest
   instructions is a model assumption. Nine frozen-clock evaluator controls
   reproduce all disputed periods identically in all three images. Native
   state-preserving clock-cadence controls change the original's period too.
   Thus changed movement parameters are not needed to explain these witnesses.
   No quantitative physical CPU-time, speed or trajectory impact is established.
3. **Smallest next change?** First test acquisition reuse: keep the state policy
   and final common authorization gate, but feed recurring qualification from
   existing, timestamped native acquisitions instead of duplicating filter/raw
   ADC work at poll entry. Preserve a bounded digital release-observation path
   while busy. Place that work within the scheduler's background budget. Do not
   reset the shared scheduler or retune the profile to force particular CC0
   values. This is a bounded architectural recommendation, not an implemented
   third patch or proof it will meet timing.

The protections can plausibly preserve the same calculated profile law; the
unchanged evaluator already does so for equivalent inputs. **Whole-movement and
physical motor-behavior preservation remain unproven.** Requested step intervals
really differ in the observed streams; calling them harmless is not justified.

## Evidence and unchanged baselines

The [packet](../../research/generated/stateful-motor-timing-2026-10-23/README.md)
retains native snapshots, complete prepared RAM, commands, observation recipes,
Ghidra disassembly/decompilation, p-code results, arithmetic comparisons and hashes.
Starting evidence is [Phase3](stateful-trigger-qualification-phase3.md),
[matched motor output](vvr-trigger-motor-output.md),
[motion routes](motion-initiation-route-coverage.md) and
[motor/reference ownership](motor-state-ownership-and-reference.md).

| Binary | SHA-256 |
|---|---|
| Original915 | `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |
| First freshness patch | `ae9e6a749426fc3d800a0e26d016cc58f818ce8f84d5a7ba12c41d6d727bc616` |
| Phase3 stateful patch | `29d4bd68348bcfccef26098c4cf6cc85a1f2ef40a861d046b7c4c43e76f230db` |

No generator, assembly, existing image, apfw2, formal model, APTrace implementation
or completed gate evidence changed. No diagnostic binary variant was necessary;
Gate5 and physical hardware were not used. Exact correspondence to Nathan's field
releases remains unestablished.

## Matched absolute timeline

Six fresh reset executions repeat Phase3's digital/analog nominal500-tick inputs,
program and MC4. Timing is firmware counter time relative to native setup return,
not physical milliseconds. First-patch analog is identical to original here;
first-patch digital has112 extra instructions before acceptance but the same
listed ticks. Full instruction coordinates are in `analysis.json` and snapshots.

| Input / image | Active edge | Accept `8f9c` | Prepare entry `6b50` | First valid evaluator clock read | Rate / CC0 / live |
|---|---:|---:|---:|---:|---:|
| Digital original | 101 | 101 | 105 | 108 | 158 |
| Digital first | 101 | 101 | 105 | 108 | 158 |
| Digital stateful | 100 | 151 | 155 | 157 | 207 |
| Analog original | 100 | 137 | 141 | 143 | 194 |
| Analog first | 100 | 137 | 141 | 143 | 194 |
| Analog stateful | 101 | 177 | 182 | 185 | 236 |

Actual edges are first-poll quantized; nominal500 pulses span499–501 ticks. Digital
recognition/live latency is0/57 ticks original,51/107 stateful. Analog is37/94
original,76/135 stateful. These quantify intentional recognition delay separately
from post-preparation sampling. Matching motion start to the same absolute tick
would erase intended qualification latency and is not an equivalence criterion.

## Recovered calculation and first meaningful divergence

Instruction evidence is in `evaluator-listing.txt`, `evaluator-tail.txt`,
`rate-listing.txt` and the Ghidra calculation/preparation outputs. Local p-code
forward-use corroborates elapsed-value escape into a math-helper argument,
period-array addressing, and scaled-value storage. It does not establish an
interprocedural proof of the complete floating-point computation. Native register
and memory observations supply the concrete values across those boundaries.

The relevant dataflow is:

- `0x6b50` prepares coefficient/duration arrays and records profile origin in
  `0x200030cc[ch]`, using native microsecond clock `0xccdc`.
- `0x6338` dispatches by profile mode at `0x2000310c[ch]`. Mode1 reads that clock
  again at `0x635e`; `0x6368` subtracts the channel's origin.
- The mode1 calculation divides elapsed microseconds by1000, then adds native
  look-ahead `0x20002954` =5. At `0x639a`, the time-square has been calculated.
- Coefficients are at `0x20000850`, `0x20000e90`, `0x200014d0`, indexed by
  channel/stage; initial position is at `0x20002908`. The result is visible at
  `0x6420` before feedback subtraction.
- `0x6260` reads software position and synchronized TC count/previous CC. The
  evaluator subtracts software/fractional position from desired position, using
  direction state at `0x20000094`. In these witnesses position and COUNT stay0.
- Scalar `0x200025dc` =120,000 divided by the absolute residual produces a raw
  period, converted to integer and stored at `0x66ee` in `0x2000007c[ch]`.
- Start is allowed when this period is below the per-channel ceiling at
  `0x20000180` =3,000,000 and live is0. Earlier evaluations above that ceiling
  do **not** start TC0. The first computed period is not the first enabled one.
- `0x5f8c` initializes the timer, calls `0x5ee8` to clamp/scale the period and
  `0x5810` to enable. Above60,000, the observed path shifts the raw period by7;
  `0x5f28` stores the scaled value and tail-calls `0x5c00` with it in R1.
  `0x5c44` stores its low16 bits at TC0 CC0 `0x4000381c`.

Native prepared-state captures compare all four channels' coefficient and duration
arrays, initial-position state, the first80-byte program record, target and
position arrays, direction, profile mode, raw-period state, evaluator scalar,
period ceiling and scaling state. These motion regions match across all images.
They are finite region comparisons, not complete RAM equality: clocks, scheduler
phase, filter history, heap pointers and qualification state can differ.

The first relative motion-calculation divergence is already the **first valid
evaluator elapsed input**, before any CC0 write:

| Run | Profile origin µs | First evaluator µs | Elapsed ms | Look-ahead age ms | Calculated desired position |
|---|---:|---:|---:|---:|---:|
| Digital original / first | 3,124,999 | 3,127,999 | 3 | 8 | 0.0008448 |
| Digital stateful | 3,174,999 | 3,176,999 | 2 | 7 | 0.0006468 |
| Analog original / first | 3,162,999 | 3,163,999 | 1 | 6 | 0.0004752 |
| Analog stateful | 3,202,999 | 3,205,999 | 3 | 8 | 0.0008448 |

For this initial stage the prepared law is `p(t) = 0.0000132 × t²`, with t in
look-ahead milliseconds and zero initial/software position. The cubic coefficient
and stage0 linear coefficient are0. This is a position/residual-based control
calculation, not a direct measurement of physical acceleration. For these zero
COUNT/position witnesses:

`raw_period = trunc(120000 / p(elapsed_ms + 5))`

`CC0 = raw_period >> 7` on the observed initial scaling branch.

| Initial timer start | Elapsed ms | Look-ahead ms | Desired position | Raw period | CC0 |
|---|---:|---:|---:|---:|---:|
| Digital original / first | 53 | 58 | 0.0444048 | 2,702,410 | 21,112 (`5278`) |
| Digital stateful | 52 | 57 | 0.0428868 | 2,798,063 | 21,859 (`5563`) |
| Analog original / first | 51 | 56 | 0.0413952 | 2,898,886 | 22,647 (`5877`) |
| Analog stateful | 53 | 58 | 0.0444048 | 2,702,410 | 21,112 (`5278`) |

The binary arithmetic and integer scaling explain **every captured CC0 update**
in the six primary traces, including later scaling transitions, under their
observed zero-feedback stage0 conditions. This is a saved-value calculation
check, not an independently implemented controller or a full-trajectory proof.

## Scheduler and instruction-paced clock

Native `0xccdc` combines the millis counter `0x200052ec`, SysTick registers and a
pending-interrupt indication. In these modeled histories SysTick LOAD119999 and
VAL0 contribute a fixed999µs fraction; the harness increments the millis word
once per4,000 guest instructions. That is not a cycle-calibrated hardware clock.

The scheduler `0x93fc` stores its own origin at `0x20002408`. When elapsed reaches
`0x20000130` =5,000µs, it rebases this stamp and services eligible channels through
`0x6338`. Below that deadline it returns without background work once elapsed is
at least `0x2000293c` =3,500µs; earlier in the slot it runs `0x8e18`, output queue,
RX and other housekeeping. The patch inserts work into this background region.

Profile origin and scheduler origin differ. At the first valid digital evaluator,
the scheduler/profile origins are3,127,999/3,124,999 original and
3,176,999/3,174,999 stateful. A delayed authorization changes preparation's phase
within this shared schedule. Added recurring work further changes instruction
phase and deadline observations. Aligning on the queue store or live flag alone
cannot remove either effect. Even the unpatched original has no invariant that
identical program data always starts with one particular CC0 value independent
of trigger/scheduler phase.

## Controlled timing experiments

**Frozen equivalent-state controls.** The public native CLI calls the unchanged
`0x6338(0)` with the same captured original prepared global/TC0/SysTick state in
all three images. Only the diagnostic millis counter selects profile age51,52
or53; time then stays frozen. The real evaluator, timer initialization, scaling
and return execute; this deliberately bypasses trigger admission and does not
validate the qualifier. At each age all three images have identical instruction
counts, raw period, complete TC0 state and ordered TC0 writes. The outputs are
respectively `5877`, `5563`, `5278`. No changed profile coefficient is required.

**State-preserving continuation controls.** Each image first executes normally
from reset until `0x635e`, before the first valid profile time read. The public
`fresh=False` continuation keeps CPU/FPU, RAM, stack and MMIO on that same machine;
SP is explicitly retained. Only the disclosed clock counter is set to profile
origin+3ms, and fake-tick cadence is selected anew. Each continuation runs2M
instructions. Thus all first evaluator ages are3ms; subsequent qualification
work remains enabled. These controls are modeled clock interventions, not natural
physical histories or complete normalization of every scheduler/UI deadline.

| Image | Continuation instructions per tick | First start profile age ms | First CC0 | CC0 update count |
|---|---:|---:|---:|---:|
| Original | 4,000 | 53 | `5278` | 90 |
| Stateful | 4,000 | 52 | `5563` | 91 |
| Original | 2,000 | 57 | `482c` | 175 |
| Stateful | 2,000 | 52 | `5563` | 174 |

The first input age can match while later sampled ages diverge. The original
period changes solely by changing the clock schedule after preparation; the
stateful period is unchanged across these two particular schedules, not generally
clock-independent. Together with frozen controls, this localizes the initial
value difference to elapsed-state selection rather than changed arithmetic.

Two clock-from-reset2000 runs never reached the timed fixture's setup-return
boundary within16M instructions. They are retained as non-runtime controls and
excluded from motor comparisons. This fixture's startup/command sequence is also
timing-dependent; changing the clock from reset is not a clean motor experiment.

## Workload and motion-start-aligned comparison

The measured interval is poll entry `0x8e18` to original body `0x8e1c`. It includes
the displaced prologue in both images and all new helper work in the stateful
image. Original/first interval is1 guest instruction. Additional instructions
therefore equal the listed span minus1.

| Mode | Stateful span min / median / max | Post-live median extra | Post-live extra sum | Fraction of post-live instruction window |
|---|---|---:|---:|---:|
| Digital | 83 / 98 / 129 | 97 | 29,310 | 0.95% |
| Analog | 357 / 374 / 405 | 373 | 109,809 | 3.71% |

The overall minima/maxima include pre-live state transitions. Post-live spans
are94–103 digital and367–377 analog, across307 and296 completed polls respectively.
The grant interval `8f98→8f9c` is95 instructions digital and371 analog, versus2
original/first. That measures the rare common grant gate, not the first patch's
separate digital freshness detour. Poll register saving, timestamp/read-gap/context
checks and acquisitions recur even with a consumed grant while motion is live;
this is not just pre-start overhead. The brief PRIMASK section in the grant is
separate from recurring work; no ADC is executed with PRIMASK masked.

Analog live-phase original filter/ADC helper entries are312/312; stateful592/632.
The new code calls the filter plus a raw ADC acquisition, after which the original
body can call the filter again. Caching means helper entries are not all distinct
physical samples. Shared GPIO-helper counts also include nontrigger pins, so they
are not presented as digital-trigger acquisition counts. These are guest
instruction/entry measurements, not SAMD51 cycle costs or measured CPU utilization.

Motion-start alignment retains a real difference: digital original first CC0
updates are21,112,17,894,15,359; stateful21,859,18,476,15,821. They are not identical
streams after simply subtracting start timestamps. `analysis.json` pairs each
CC0 write with its actual profile age, calculated desired position and raw period.
For equivalent elapsed/feedback state the law agrees; different sampling times
produce different requests. Neither sorting outputs nor shifting sample indices
would prove equivalence.

Direction and endpoint remain positive/500; all observed software positions stay0.
The initial13-store timer sequence retains its PC/address/size structure and
CTRLA enable-containing value `0x602`, with the documented CC0 difference.
After rate start, the sets of driver-serial values by writer PC match across
original/stateful in both modes, as do observed GPIO masks by writer PC. Counts,
interleaving and time order differ. Set agreement excludes a new observed byte
value at those PCs, not changed transactions or physical driver equivalence.
No new continuous STEP observation or valid TC/NVIC feedback was obtained.

The captures cover initial stage0 acceleration-law sampling and a period-scaling
transition, not a validated full acceleration/cruise/deceleration trajectory.
Full prepared coefficient/duration arrays agree, but terminal motion and physical
position/distance cannot be inferred with COUNT/position stalled. The old
forced-counter continuation is not used.

## Engineering assessment and remedy priorities

The initial CC0 differences are different phases of the same calculated profile
under the modeled feedback, **not unexplained new movement parameters**. They
are actual different requested timer intervals. Their physical consequence is
unresolved: a real independent clock can absorb CPU-work changes while there is
slack, or expose deadline misses if work overruns. Neither outcome is established
by instruction-paced time. Perfect CC0 equality is too strong when qualification
intentionally changes start phase, yet correct coefficient equality alone is too
weak to establish motion preservation.

| Priority / proposed change | Demonstrated target and policy preservation | Risk / next experiment |
|---|---|---|
| 1. Reuse native acquisition results for recurring qualification; keep final fresh gate | Removes the largest observed analog duplication without changing coefficients, consumed grant, initial inactive qualification or release-to-rearm policy. Timestamp raw/filtered results; update once per genuine sample and retain stale-gap invalidation. | Native filter caching and startup callers require explicit ownership; raw and filtered evidence must correspond to actual acquisition times. Compare the complete Phase3 rejection/repress matrix, same pulse phases, measured helper workload and this report's age→period relation. |
| 2. Budget the remaining qualification service within scheduler background slack | Addresses recurring digital and analog work. Preserve release sampling while ineligible and avoid carrying active candidates through busy. | A blanket busy-state skip loses independent release observation. Budget deferral must not silently make state stale or miss legitimate pulses; test deadline-adjacent inputs, W during qualification, MAX_GAP and latency under load. Measure worst-case cycles on hardware before claiming slack suffices. |
| 3. Consider profile-origin/scheduling changes only if vendor requirements demand tighter start-phase control | Could define when the first profile sample should occur relative to a qualified event. | Resetting shared `0x20002408` can affect other channels and Remote paths; changing look-ahead5 or scalar120000 changes original control behavior. Requires a new explicit scheduling contract and multi-channel/direct-route comparisons. It is not the smallest first adjustment. |

No remedy is implemented or certified here. Preserve the real common grant gate;
replacing it with a harness veto, delaying all commands, disabling W or tuning
clock inputs until streams agree would not address the engineering question.

## APTrace execution, failures and validation

Existing Ghidra and p-code interfaces supply static evidence; existing Unicorn
CLI/ConcreteMachine supply instruction execution, watches, prepared-state capture
and native continuation. Checked-in case recipes change observations, external
waveforms or disclosed clock inputs, not firmware decisions or emulator semantics.
`analyze.py` compares saved evidence and arithmetic values only.

Three initial overbroad GPIO watches hit100,000 observations during startup and
stopped before the motor experiment. Their native snapshots/source are retained
under `watch-cap-attempts`; subsequent observations use sparse watches and lightweight
helper counts. One initial sandboxed frozen-CLI invocation failed with host SIGILL
before guest evidence; the established reviewed native context succeeded. The
initial p-code request tracked R0 at a store that does not define R0 and returned
UNSUPPORTED/REGISTER_NOT_WRITTEN; that result is retained, with the corrected
period-array-address origin in the final p-code batch. These are instrumentation,
execution-context and query failures, not firmware counterexamples.

The six primary bounds end at16M instructions, except two analog originals ending
at16M+3 as reported by the existing engine. This tiny observed bound overrun is
recorded, not silently rounded to exact equality. Every main witness and timer
calculation precedes the bound. Native watch and memory-write logs are untruncated.
The packet's **2,869/2,869 saved-artifact checks pass**, covering arithmetic, equivalent frozen outputs,
prepared motion regions, bounded runs and clock-normalized continuations. They
are finite regression assertions, not universal verification.

## Capability gaps and recommended next APTrace work

| Gap / observed evidence | Impact / likely cause | Needed capability and priority |
|---|---|---|
| Fake ticks tied to guest instruction count; fixed SysTick fraction | No real CPU cost, independent-clock jitter or physical-speed attribution; model construction, not a demonstrated firmware defect | Validated cycle/time scheduling and measured acquisition/WCET data, high |
| COUNT/position remain0; validated continuous TC/NVIC service absent | No full trajectory, STEP, physical speed/distance or deceleration equivalence | State-preserving timer/IRQ continuation validated against measured traces, high |
| Local p-code forward flow stops at calls; no global binary refinement | Native arithmetic covers these states, not every channel, stage, writer or IRQ interleaving | Bounded caller/callee correspondence and IRQ-aware frame verification, medium |
| Watch cap and host SIGILL/context sensitivity | Initial observations cannot support motor claims; corrected scope/context produced usable evidence | Robust native execution environment and targeted observability, medium |

Exact tested-release identity and real trigger/ADC/loop waveforms are missing
firmware/physical evidence, not emulator bugs. Existing APTrace can next test
more scheduler phases, selected full-program native calculations and eventual
candidate acquisition reuse with this unchanged evidence as baseline. Framework
improvements and physical timing measurements are separate future work. No new
framework, hardware operation, complete safety campaign or third patch follows
from these recommendations.
