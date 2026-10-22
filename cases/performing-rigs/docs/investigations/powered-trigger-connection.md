# Powered-source connection, relay-like transients and unintended starts

2026-10-21. **Assessment: Noxon's explanation is conditionally consistent with
original-firmware behavior, but the capacitor mechanism and the necessity of a
hardware selector remain unestablished.** A connection that presents the same
MCU-visible history as an intentional relay closure can initiate the original
profile timer. Firmware can prevent several startup, stale-history and
configuration-transition starts, but cannot infer intent from two otherwise
identical observable histories without sacrificing some legitimate triggers or
receiving additional information.

This is a bounded APTrace operator investigation. No apfw2, original firmware,
analysis implementation or physical device was changed. No new admitted/
VERIFIED claim or release-gate promotion is asserted.

## Question, evidence and limits

The user reports Noxon's bench-supply reproduction and hypothesis: output
capacitance temporarily looks like a low-impedance/closed contact, and mixed
relay/powered-source support requires a hardware mode selector. That is a
reported physical observation/explanation, **not** a board reproduction made
by APTrace. We test its software consequences conditionally.

Evidence starts with the [trigger dossier](trigger-input.md),
[X/acceptance](x-trigger-acceptance.md), [request campaign](trigger-misfire-failure-modes.md#targeted-request-campaign-an-overlooked-motion-initiation-path),
[bring-up Pass1](autopilot-bring-up-pass1.md)/[Pass2](autopilot-bring-up-pass2.md),
[pin map](../hardware/firmware-pin-function-map.md) and
[hardware reference](../hardware/hardware-reference.md). The
[new evidence packet](../../research/generated/powered-trigger-connection-2026-10-21/README.md)
contains new full-reset original868 simulations, native queries, fresh independent
Macaw discovery, controls and provenance.

### What is and is not an electrical model

| Layer | Established / modeled | Unresolved |
|---|---|---|
| Jack/source | Manual documents tip/sleeve relay closure or externally powered input, either polarity. User reports supply-related misfire. | Actual inactive output voltage/impedance, C/ESR, current limit, connector contact order, bias circuit, protection/rectification and transfer to MCU. No capacitor value, RC waveform or safe MCU voltage follows from a jack rating. |
| Mode selection | Firmware samples PA02 once: HIGH→analog mode1, LOW→digital mode2. Startup configures its MCU pull-up. | Whether PA02 reflects a jack contact, separate selector or another circuit. Its pull-up is not evidence of the jack's relay-sensing bias. |
| Sense input | Firmware digital alias57 and analog59 resolve to PB05. Digital mode requests bare INPUT, without MCU pull/debounce. | Actual external pull/bias and physical jack route remain incompletely characterized. “No MCU pull” does not prove an electrically floating net. |
| Simulation boundary | External PB05 GPIO HIGH/LOW or ADC1.RESULT counts0/225/600/900; actual original filtering/classification and timer initiation. | No conversion of12/24V, source impedance or capacitance into those inputs. No board revision is assigned a waveform. |
| Time/waveform | Changes at explicit original PCs; parameterized level, startup/eligibility ordering, sampled versus unsampled intervals. Prior sample-aligned/opposite-phase repeated excursions reused. | No calibrated insertion duration, finite rise/fall slope, arbitrary timestamped ramp, stochastic bounce or physical sampling-jitter model. |

The firmware modes1/2 are not assigned to “dry contact” and “powered12/24V”
without circuit evidence. No dynamic source-type classifier is established.
Both12V and24V sources therefore have **unknown** MCU histories here; they are
not represented by ADC12/24, counts proportional to volts, or necessarily a
saturated input. The proposed low-impedance interval is relevant only if the
actual front end translates it into an active sampled input. An already powered
but inactive source can be harmless, active, or transient-producing at PB05;
nominal source labels do not settle which.

## Original interpretation and request boundary

All new cases use the natural Remote-built nonzero profile from the previous
campaign: `+2,1,1,0,98,1,0,50,1000,500,0,0|`, native MC4 and original AutoPilot
reset. No AP arm, record, reference, filter, eligibility or timer-start value is
seeded. Radio-ID/MMIO completion, DWT delay stub and instruction-paced tick
assumptions are inherited and recorded. Packets are supplied at the RX ring,
not proven RF delivery.

- Before MC4 completes setup, the normal input/loop path is unavailable. Program
  marker7b, channel bytes0 and idle byte9 are needed for reload acceptance.
- Analog input uses the correctly initialized alpha0.05 filter. X1's inactive
  band is inclusive[200,580]; X2's is[250,750]. Either extreme can be active.
  Non-due calls can use cached data; acquired values can be attenuated. Startup
  baseline/filter history is distinct from a new event.
- Digital input is polled active LOW at original `0x9228→0xd3dc`. The result
  is compared at`0x922c`; there is no release/history requirement in this gate.
  X does not change this digital decision. TR1 inhibits normal acceptance.
- Either active branch can reach`0x8f98`, then reload/profile preparation
  `0x6e4c→0x4b64→0x6b50`: channel state1, profile mode1, idle0 and phase arms0.
- The scheduled main-loop branch calls profile evaluator`0x6338`, which can
  call rate start`0x5f8c→0x5ee8→0x5810`. The original timer ENABLE write and
  live-byte1 at`0x5fa4` are observed; positive cases stop at`0x5fa6` afterward.
  No W or G is required. No`0x6fd8` call is observed in these runs.

This is a requested pulse-generation start. Actual timer clocking, STEP edges,
physical reference, displacement and motor movement are not simulated outcomes.
A prepared profile or displayed T flag alone is not counted as a start.

## Connection scenarios through the complete software path

Electrical descriptions below are **conditional interpretations** of the named
MCU history. A row never establishes that a real12/24V connection produces it.
“Same contact control” deliberately labels identical observable history with a
possible different origin; it is not a physical source comparison.

| Connection / contact hypothesis | MCU history and mode | Sample/classification and acceptance | Eligibility → timer-start outcome | Firmware opportunity / cost |
|---|---|---|---|---|
| Powered inactive source settles to inactive digital level; open contact equivalent | `digital-idle`: PA02 LOW at boot, PB05 HIGH | Inactive; no acceptance | Valid program/idle9 retained; no start by14M | Preserve as inactive; no source-type inference established. |
| A connection begins after one eligible inactive read; intentional later closure equivalent | `digital-connection-after-inactive-sample`: first HIGH, then LOW | Later LOW accepted | Native profile start | A startup-only inhibit is insufficient once armed. A deliberate closure can have identical history. |
| Relay-like LOW persists as setup becomes eligible; source already asserted equivalent | `digital-low-at-eligibility` / `digital-low-before-eligibility` | First qualified LOW accepted, no edge required | One original timer start in each | Require inactive qualification after eligibility to block; sacrifices legitimate already-asserted-at-enable operation. |
| Brief closed-contact-like interval overlaps the qualified read | `digital-acquired-transient`: LOW before`0x9228`, HIGH again at`0x922c` | Saved digitalRead result0 accepted while current GPIO is HIGH | Accept12,098,773; rate start12,327,006; original timer enable follows | Minimum-active persistence could reject a truly isolated sampled pulse, but also an intentional equally short relay trigger. |
| Intentional short dry-contact closure with exactly that observable interval | `same-history-contact-control` | Same result, byte-identical native snapshot | Same start | Origin/intent is not present in the history. A policy rejecting one must reject the other if no extra information is supplied. |
| Connection-like LOW occurs only while waiting for setup/Remote | `digital-setup-only-transient`: LOW at program delivery, HIGH before MC4 completion | No active qualified read; no acceptance | No start by14M | Sampling window matters. This negative is not proof that every setup transient is safe. |
| Repeated transitions miss every qualified read | `digital-unsampled-transient`: HIGH at read, LOW after return | All observed qualified reads HIGH; no acceptance | No start by14M | Avoiding a false start also means a legitimate unsampled pulse is missed. This is phase-locked, not a measured contact waveform. |
| Analog front end has low startup state, then settles inactive before first runtime acquisition | `analog-startup-transient-tail`: ADC0 at startup,225 at setup return | Filter11 at acceptance;148 at rate start, although supplied ADC is225 | One timer start; no new runtime active raw value needed | Inactive-before-arm plus fresh-history qualification can prevent this class; requires an explicit startup policy and may delay/discard intended startup triggers. |
| Analog low occurs only after baseline, during the setup wait, and ends before runtime | `analog-setup-only-low`:225 baseline,0 during wait,225 before MC4 completion | Runtime filter stays225; no acceptance | No start by14M | Contrasts startup history with an unacquired wait-period excursion. |
| Analog input settles marginally outside X1 upper band | `analog-marginal600`:225→600 | Filter eventually581, accepted; continued filtering reaches593 by start | One timer start | Filter delays but does not reject a sustained marginal active level. Qualification/hysteresis may help noise, but cannot define jack voltage margins without measurements. |
| One high analog acquisition, then inactive | Prior `profile-single-pulse`:225→900→225 | Peak259, no acceptance | No start by14M | Existing filtering already rejects this particular acquisition history; a legitimate pulse of the same sampled size is also lost. |
| Repeated analog connection chatter correlated with acquisition | Prior `profile-sample-aligned-pulses` versus opposite-phase control | Aligned highs accumulate to active; opposite phase stays225 | Aligned starts once; opposite phase does not | Not every short pulse is suppressed. Phase and accumulated history matter. No physical bounce rate/duty cycle is inferred. |
| Settled input remains unchanged while configuration/reporting eligibility changes | Prior `profile-x2` / `profile-tail` | Constant225 becomes active after X2; filtered866 accepted after TR0 while raw225 | Each reaches original timer start | Configuration barriers and stale-history policy can prevent these classes without changing the input circuit; an intended held event may be discarded. |

The transient injection at`0x9228/0x922c` fires whenever those PCs are reached.
In the positive original run the first acceptance changes eligibility, so later
qualified reads do not recur before the stopped timer start. This is **not** a
measured pulse width, and a modified policy that polls differently would not
inherit the same time-domain waveform merely by reusing these PC hooks.
All instruction counts are emulator scheduling coordinates, not physical latency.

## Candidate firmware policies: conditional comparison, not implemented fixes

The following compares conceptual policies against the **same defined observable
history**, including its possible contact or connection label. No alternative
firmware, executable policy model or new acceptance engine was built. A finite
prefix does not establish future samples; policy predictions assume the stated
continuation. Let I mean inactive, A active; K/N/T are uncalibrated requirements,
not recommended values for either board.

| Policy / defined history | Original outcome | Conceptual alternative outcome | Legitimate-trigger cost / limit |
|---|---|---|---|
| Require K stable inactive observations **after** eligibility; history begins A and stays A | Startup/eligibility LOW starts | Stay unarmed until release/inactive qualification | Intentionally asserted input at startup/enable does not start. Cannot cure a connection arriving after qualification. Original snapshots alone do not establish a safe K or wall-clock duration. |
| Require N consecutive active acquisitions, N≥2; defined history `I… I,A,I,I…` | Digital one-sample A can start | Reject isolated A | Rejects a legitimate one-sample closure too. Aligned chatter that gives `A,A,…` can still pass even if the physical signal bounces between acquisitions. |
| Same persistence rule; history `I^K,A,A,…` | Starts | Starts later after N | Preserves sufficiently long triggers but adds latency and can lose shorter ones. A capacitor transient lasting N acquisitions is not rejected by origin. |
| Release-to-rearm / consume one event per active episode | Tested held input starts once | At most one authorization until release, if enforced across all request paths | Does not prevent the **first** connection start. Suppresses intended level-repeat semantics. Full original completion/re-arm is not demonstrated by these fixtures. |
| Fresh raw input and fresh post-arm filter history required; startup low then inactive raw | Startup-tail case starts from old filter activity | Suppress an event whose only active evidence predates arm or has expired | Can lose legitimate pulses just before arming. Comparing instantaneous raw with filtered state changes noise immunity and must not be presented as a free improvement. |
| X/mode change disarms, resets event history, requires fresh inactive qualification under the new interpretation | Unchanged225/X2 can start | No new authorization solely from reclassification | Intentionally held active input requires release or explicit confirmation. Resetting a filter alone can itself introduce a classification jump unless arming is separate. |
| Passive diagnostics | TR1 currently suppresses acceptance; TR0 can expose stored activity | Observation has no acceptance side effect; event state remains separately controlled | Prevents diagnostic-induced behavior changes, **not** connection pulses by itself; removing suppression without event qualification can enable starts previously inhibited by TR1. |
| Ignore “connection-like” events for T after power/eligibility | Some startup starts | Reject/delay events inside T | Loses legitimate events inside T; later insertion remains ambiguous. No observed source signature supports a universal connection classifier. |
| Explicit source-type intent through configuration/selector | No demonstrated dynamic electrical type identification | Different documented sensing/arming contracts can be selected | Adds information, but the existing circuit's ability to support both safely in software-selected modes is unknown. A physical selector is not the only possible source of intent information. |

No numeric debounce interval, threshold voltage or acceptable timing penalty is
chosen. The current CLI can reproduce bounded PC-scheduled histories but does
not expose a calibrated RC/front-end waveform workflow. Implementing an
independent electrical or alternative-firmware simulator to fill that gap would
exceed the operator role.

### Information limit

If a powered-source insertion and a deliberate contact closure have the same
PA02 history, ADC/GPIO observations, timestamps and session/configuration state,
firmware receives identical evidence. Deterministic acceptance must produce the
same result. The identical digital replay supports this statement for the
selected original execution; the general conclusion follows from equality of
inputs, not a probability estimate.

This is a limit **given those observables**, not proof that no additional sensor,
active bias/probe response, analog read or explicit user configuration could
supply more information. We have not recovered a validated relay-bias circuit
or safe active-probing mechanism. A voltage/impedance distinction that exists
at the jack may be erased by the front end or by digital thresholding; whether
it is actually available to different firmware is unresolved.

## Scoped path coverage and independent analysis

A fresh documented `aptrace macaw-census-expand` run used vector roots and the
original image, without Ghidra-derived seeds. It recovered263 functions,
3,521 blocks and1,272 call records, with48 residual classification failures
and199 incomplete/unresolved terminator records. Geometry and source/image/tool
hashes are retained in the packet. These totals are discovery statistics, not
an exhaustive coverage claim.

The [selected graph extract](../../research/generated/powered-trigger-connection-2026-10-21/path-coverage-extract.json)
corroborates the main-loop branch to`0x6338`, calls to`0x5f8c/0x5810`, the input
branch to`0x42a4`, and the shared acceptance tail into`0x6e4c→0x6b50`. It also
retains independent G/phase/command paths to`0x6fd8` and the W1 reload path.
Macaw's overlapping parsed ownership/call records are not assumed to be unique
function boundaries. Its record at6638 corresponds to a parsed block beginning
with `mov r0,r4`; fresh Ghidra native disassembly places the actual BL at663a.
Native instructions and concrete stops resolve that boundary.

Fresh Ghidra callers identify `0x5f8c` from profile code663a/6722 and command
code84e2; `0x6fd8` from G state7dd6, phase8fee/9050 and unattributed command
sites72de/7312. These are search-relative direct references, not proofs excluding
indirect transfers. New positive witnesses observe both acceptance and actual
rate/timer start; all runs also stop if the separate6fd8 boundary is reached.

Selected regions still have incomplete terminator records: profile evaluator12,
trigger/phase5, main loop4, dispatcher20, startup2 and profile preparation2.
Residual failures remain in discovered regions attributed to6338 and8258,
including shared library/tail regions. No missing edge is silently treated as
an unreachable path. The original driver/timer path can also be initiated by
non-trigger commands; this campaign supplies no G/W commands and does not
claim protection against every concurrent command/ISR interleaving. Existing
pin/trigger evidence supports polled input, not a newly proven exhaustive
exclusion of every IRQ/indirect initiator. This is bounded path review with
independent corroboration, not whole-firmware verification.

## Engineering answer and next evidence

1. **Can the proposed transient start motion?** Yes, **if** it produces the
   active MCU histories demonstrated above while the normal gate is eligible,
   or leaves active filter history when eligibility arrives. Original code
   requests timer start. Supply capacitance producing those histories is not
   established.
2. **Which conditions matter?** Sample phase, startup-selected mode, retained
   filter history, X band, TR state, program/idle/channel eligibility and timing
   of source settling. Nominal12/24V or the word “inactive” is insufficient to
   predict the outcome without the front-end transfer.
3. **Can firmware distinguish intent?** Not for identical observable histories.
   It can impose explicit qualification/arming contracts that intentionally
   reject both the false event and its legitimate short/held equivalent.
4. **Can replacement firmware help existing boards?** It can eliminate the
   demonstrated stale-history/reclassification/active-at-enable starts under
   stated policies, and can reject some short connection disturbances at a
   defined pulse-width/latency cost. The actual fraction of V1/V2 field misfires
   reduced cannot be estimated from these simulations. Guaranteed preservation
   of every legitimate trigger while rejecting every indistinguishable
   connection transient is unsupported.
5. **Is hardware required?** Noxon's assertion that firmware cannot universally
   infer source type from an ambiguous history is supported conditionally.
   The stronger claims that supply capacitance is the cause and that a physical
   selector is necessary are **unresolved**, not demonstrated or disproved.
   A selector can provide intent, while different protection/bias/shaping may
   require actual circuit changes; software cannot change the circuit's voltage
   tolerance or prevent a physical low-impedance interval.

Execution:11 native concrete runs, all exit0/error-free, plus fresh Macaw and
Ghidra queries. All103 scoped artifact checks pass, including same-history
replay equality. Prior analog/X/TR/repeated-pulse request witnesses are reused
and explicitly labeled, rather than represented as new reruns.

The smallest useful new physical evidence is one synchronized connection
capture per relevant board revision, with firmware/X/mode/program/TR state
recorded: source output/jack waveform and the MCU-side sense waveform at an
already confirmed accessible node, plus PA02 at the startup decision. Compare
powered nominally inactive insertion, already-asserted insertion and a clean
intentional dry closure using the same cable/eligibility setup. Record source
inactive topology and whether the actual MCU history is distinguishable; then
vary source capacitance/current-limit behavior only if the first capture makes
that relevant. This tests Noxon's electrical premise without a broad new board
survey. An assumed jack rating must not be applied to an MCU probe node.

APTrace follow-up possible now: selected mode/band boundary and original path
queries; full completion/re-arm remains a separate evidence boundary from the
previous campaign. Framework/scenario work would be needed for validated timed
analog ramps/RC transfer and policy-comparison execution. **Capability gaps:**
front-end transfer (missing physical evidence, high priority); calibrated timed
waveform and independent alternative-policy replay (scenario/interface/model
validation gap, medium priority); unresolved indirect paths/terminators (static
coverage limitation, medium priority). Native backend execution was available;
no environment or permission failure blocked these simulations. No new model,
policy implementation or framework repair was introduced to hide those gaps.
