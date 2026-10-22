# Experimental digital-trigger freshness binary patch

2026-10-22. **Working partial result; RESEARCH ONLY — NOT FOR HARDWARE
DEPLOYMENT.** A generated modified915 image rejects the reproduced
saved-LOW/current-HIGH connection history before acceptance and TC0 initiation,
while preserving the intentional control's29,236 captured output requests.
This meets the request's minimum experimental success criterion. It is **not**
the complete trigger-safety policy: initial qualification, timed debounce,
release-to-rearm and analog protection are not implemented. Their failing or
unchanged cases are explicitly retained below.

[Generator, image and evidence](../../research/generated/trigger-patch-2026-10-22/README.md),
[modification manifest](../../research/generated/trigger-patch-2026-10-22/modification-manifest.json),
[native outcomes](../../research/generated/trigger-patch-2026-10-22/outcomes.json),
[Noxon-facing summary](experimental-trigger-freshness-noxon-summary.md).

## Baseline and compatibility

Use [VVR correlation](vvr-trigger-failure-correlation.md),
[motor-output comparison](vvr-trigger-motor-output.md),
[Target2](trigger-symbolic-reachability-target2.md),
[Target3](motion-initiation-route-coverage.md) and
[startup filter history](startup-voltage-learning.md) with their existing limits.

| Image | SHA-256 / size |
|---|---|
| Original AutoPilot915 | `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920`,70768 bytes |
| Experimental freshness subset | `ae9e6a749426fc3d800a0e26d016cc58f818ce8f84d5a7ba12c41d6d727bc616`,70796 bytes |

The generator refuses any other input hash/size/opcode sequence. It never
writes the original path. Neither this image nor the original is established
as byte-identical to Nathan's `Autopilot_firm05-08` or the June/July releases.
Do not apply the recipe to868 or another release merely because offsets or R39
appear similar. No physical bootloader, image-integrity/checksum or flash
ownership/deployment contract is qualified.

## Actual modification and storage

Digital eligibility remains the original9202–9224 sequence: four channel bytes0,
marker7b, idle byte9, TR0. Original0x9228 calls digitalRead(57). Originally,
0x922c compared its saved result and0x922e branched to shared acceptance0x8f98.

| Flash address / binary offset | Original | Derived image |
|---|---|---|
|0x922c /0x522c | `00283ff4b3ae`: CMP r0,0; BEQ.W0x8f98 | `B.W0x15470; NOP`, replacing exactly those six bytes |
|0x15470 /0x11470 | End of original file |28-byte appended executable routine; end0x1548c |

All original-region bytes outside922c..9231 are identical, including vectors,
configuration storage `[0x12000,0x13001)`, constants and other executable/data
regions. Original return0x9232, nearby telemetry code0x9238 and analog path are
not overwritten. Both branches are within Thumb-2 range; no original literal,
function or vector is relocated. Ghidra independently decodes the emitted branch,
BL and PUSH/POP instructions through the normal new case target
`autopilot915_freshness_research`; existing target keys are unchanged.

```
15470 cmp r0,#0
15472 bne15488                 ; original inactive result still rejects
15474 push {r0-r4,lr}          ;24 bytes,8-byte stack alignment preserved
15476 movs r0,#57
15478 bl original0xd3dc        ; actual second digitalRead
1547c cmp r0,#0
1547e pop.w {r0-r4,lr}         ; preserve comparison flags
15482 bne15488                 ; fresh HIGH invalidates saved LOW
15484 b.w0x8f98                ; original acceptance, registers restored
15488 b.w0x9232                ; original epilogue
```

No persistent state variable or fixed RAM slot is introduced. The original
digitalRead leaf uses r0–r3 and does not alter r12 or callee-saved registers;
the inserted save/restore covers its clobbers and LR. At accepted entries, the
tests verify r0–r12, SP and LR against the original controls. The patch does not
mask interrupts or modify exception code, but increases stack use by24 bytes and
adds an interruptible execution window. Peak-stack/real-preemption safety is not
proved by the non-interrupting simulation.

This is **an explicit simulation image extension, not a claimed free code cave**.
The loader provisions the additional28 bytes beyond the original file end.
No original code/data address is reclaimed. It is inside the identified MCU's
nominal flash address range, but that does not certify ownership of physical
flash after the original image. This distinction prohibits hardware deployment.

### Why no stateful policy is claimed

The reset literals delimit initialized data at20000000..20000430 and BSS at
20000830..2000531c. For example,200052f0 has no direct cached xref but is
**inside original BSS**, so absence of references does not make it available.
Neither the intervening data/BSS gap nor heap/stack space was certified as a
new permanent state reservation. A real stateful insertion needs an explicit
allocation contract and appropriate reset/default integration, not an arbitrary
apparently unused word. The patch avoids that unverified reuse entirely.

This is a limit of the delivered subset and established ownership evidence,
**not a proof that the binary cannot support a larger patch or that SRAM is
exhausted**. No complete-layout impossibility was demonstrated. A source-level
state allocation is straightforward for Noxon; a further binary reservation/
relocation experiment remains unfinished. The complete requested safety policy
must not be represented as implemented by this report.

## Original-versus-patched experiments

Twenty actual native runs use the existing direct CLI, corrected memory-hook
mode, original reset, same nonzero Remote-built program and same MC4. No patch
decision is supplied by the harness. Inputs and RX packets are environmental
assumptions; the inserted bytes make the decision. The rejected forced-counter
experiment is not reused. Timing, radio-ID, DWT-stub and MMIO-completion
assumptions are identical to the baseline and recorded per command.

The programmed channel0 descriptor remains delta+500, start0, endpoint500,
profile mode1. Current/microstep requests remain boot400/16 then MC41600/0.
These are software requests/coordinates, not measured current, homing or travel.

| Test / native history | Original | Patched | Requirement assessment |
|---|---|---|---|
| A: LOW at first read, HIGH at0x922c before original compare | Accept12,098,773; rate start12,327,006; early ENABLE store0x571c reached | No acceptance,0x5f8c,0x571c,0x5810, known STEP-emitter or TC0-handler entry through14M | **Specific stale-read history mitigated.**230 actual second reads returnHIGH and reject. |
| A negative: HIGH at acquisition, LOW after return | No acceptance/initiation through14M | Same negative outcome | Original inactive result cannot be turned into an accepted event merely by a later LOW. |
| B baseline: acquired LOW remains LOW | One start;29,236 captured writes | One start;29,236 writes; same requested values, PC/width/previous bytes and global ordering after removing instruction timestamps | **Intentional control preserved** at this bounded motor-request boundary. |
| B fresh input: first eligible readHIGH, thenLOW on subsequent acquisition | One start, acceptance12,115,174 | One start, acceptance12,115,200 | Fresh activation works; this does not establish stable-inactive or timed qualification. |
| A sensitivity: release at0x1547c after second read has already returnedLOW | No directly equivalent new-PC baseline | Still accepts12,098,797 and starts12,327,030 despite GPIO nowHIGH | **Residual counterexample.** The extra read narrows/moves the stale interval; it is not debounce or cancellation of an already accepted request. |
| C: inputLOW from boot; native completion then supplied W | Two acceptances/starts through60M | Two acceptances/starts through60M | **Initial-release arming and release-to-rearm not achieved.** |
| C positive: release after acceptance; after W/completion observeHIGH then a freshLOW | Prior native controls support the sequence | Two starts; second read sequence permits another event after release | Legitimate subsequent activation works, but no minimum release duration is enforced. |
| D: analog517→600 under X1 | Existing915 witness accepts at filtered581 and starts | Same first initiation; inserted digital routine never entered | **Analog protection not implemented.** |
| D: same samples under X2 | Existing negative through14M | Same negative; routine never entered | Existing threshold behavior preserved, not a new mitigation. |
| E: B1, G, W1 nonzero program controls | Each reaches original live-store boundary | Each reaches the same boundary with same captured final TC0 register state/live state | Direct/internal producers remain functional in the tested cases. |

The main A waveform is PC-timed, not a measured connection waveform. In the
patched run the rejection allows additional polls, so the same LOW-before-read /
HIGH-after-return rule repeats230 times; the original accepts once and stops
polling while busy. This is a repeated observation-history rule, not an assertion
of identical continuous wall-time waveforms after the executions diverge.
The unacquired control and late-release counterexample characterize sampling
phase, not an electrical pulse-duration sweep.

### Timing and downstream comparison

No arbitrary debounce delay was added. The accepted baseline costs24 extra
guest instructions; the fresh-input case costs26 including its first inactive
pass. The original rate start and patched rate start shift by the same amount
as acceptance. Under the disclosed fake counter cadence, this does not change
the baseline's57 counter increments from acceptance to rate initiation. It is
not a physical microsecond/latency measurement.

The baseline held control lasts roughly475 instruction-paced milliseconds
after acquisition before the14M bound, and initiates well before that bound.
There is **no calibrated500ms pulse/release test or guarantee** for physical
500ms pulses. Active/release qualification intervals and their transient versus
latency tradeoff are not characterized because this subset has no such timers.

The baseline intentional control's complete29,236 captured request records
match after stripping ordinal timestamps, including DIR HIGH, shared controls,
all recorded TC0 configuration/period writes and driver serial requests. First
ENABLE-containing store0x571c occurs at12,327,091 original and12,327,115 patched,
before the explicit0x5810 helper. A rejects before **both** boundaries.

For the fresh-input control, both runs have29,260 records and equal TC0,
SERCOM5.DATA and selected motor/control GPIO streams, but global interleaving
of timer and housekeeping transactions differs. An initial assertion of full
global-order equality failed; the preserved difference artifact records357
aligned-index differences, beginning around12.476M. The conclusion was narrowed,
and checks now explicitly verify non-equality globally and equality in the
named streams. **Per-stream equality is not full global-order equivalence.**

Existing startup STEP requests occur in both original and patched negative
controls. No post-candidate STEP SET/CLR requests on the four known channels
or native STEP-emitter/TC0-handler entries occur in A's rejected run. Intentional
controls likewise do not establish a continuous trigger-caused STEP train.
TC/NVIC/position simulation remains unresolved; no electrical outputs or physical
movement follow merely from reaching0x571c or writing a driver register.

### Sustained input, analog and bypass limitations

Digital C first accepts an already asserted input; after natural time-based
completion and supplied W, the original starts again at52,400,358 and the patch
at52,400,382 (live-store observations). Both use zero-position/zero-distance
return assumptions inherited from the existing harness. The actual Remote's
natural W exchange is not established. These are explicit **failures of the
larger requested policy**, not tests to omit because the stateless patch passes A.

Analog X1's fault-band and filter-tail mechanisms remain outside the change.
No new brief analog excursion or analog re-arm campaign was run. Existing
original filter controls retain their scope; preserving analog code bytes plus
two native patched controls is not all-input analog verification. A sustained
fault indistinguishable from an intentional active level cannot be rejected
after arming by intent alone.

Normal digital acceptance from the examined9202..9232 path must pass the new
routine; original guards and shared acceptance remain intact. Analog acceptance
intentionally bypasses this routine. Direct W1/G/B1 are preserved producers,
not accidentally blocked by an external-trigger gate. F0/E0, W0, group callbacks,
ISR races and all indirect destinations were not exhaustively tested. No
whole-program no-bypass theorem or general motor-safety claim is made.

## Execution, evidence limits and next work

APTrace public Ghidra build/disasm/xrefs/literal/decompile and direct Unicorn
execution provided the evidence. A bounded patch-authoring script emits Thumb
bytes and checks a branch encoding against the original BL; it is not a new
reversing engine. An additive case target enables normal Ghidra import of the
derived image; no APTrace implementation or old target identity changes.
The emitted image, generation script and modification manifest are reproducible.

The first generator attempt correctly stopped at a mismatched expected-byte
assertion before writing an image. The expected sequence was corrected from
the hash-verified source and independently decoded; the guard was not removed.
Twenty native runs complete without native errors.138/138 artifact assertions
pass, including assertions that document unmitigated C/late-release behavior;
**that count is not a complete safety-policy pass**. The existing target/IRQ
regression passes. Original images, baseline artifacts, existing tests, formal
models, apfw2 and hardware are unchanged. No ledger or release gate was promoted.

**Remaining implementation work:** explicitly allocate and initialize state;
model disabled/qualifying/armed/consumed states; use fresh acquisition evidence
and justified inactive/active intervals; reset qualification on relevant
eligibility/session transitions; preserve consumed authorization across W and
completion until a qualified release; cover analog raw/filter disagreement and
all intended external paths. Source-level Noxon work can reserve state through
the linker rather than guessing binary RAM ownership. A further binary effort
must establish that reservation/ABI contract before extending this experiment.

**Evidence/capability gaps:** exact tested-release hashes and physical input
histories remain unavailable; these are missing evidence. A supported timed
acquisition waveform/clock scenario and continuous TC/NVIC/STEP service remain
APTrace execution gaps for calibrated pulse and output claims. Current tools
suffice for the demonstrated freshness subset, but not for certifying permanent
RAM ownership through absence of xrefs. No framework or model change was made
to hide these limitations.
