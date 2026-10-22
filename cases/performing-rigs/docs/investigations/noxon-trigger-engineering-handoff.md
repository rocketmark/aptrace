# Noxon trigger investigation — engineering handoff

2026-10-22. For Nathan and Noxon's firmware engineers.

**The negotiation-oriented patch evidence package is complete.** Under the
tested execution conditions, a firmware change prevents the reproduced
saved-active/current-inactive initiation while preserving the intentional-trigger
control. This establishes an actionable firmware-side contribution and a bounded
improvement, not a complete cure. The experimental image is research only; no
certification or deployment is intended or recommended.

## Demonstrated original behavior and binary change

In the analyzed original AutoPilot915 binary, digital eligibility checks at
`0x9202–0x9224` require four channel bytes zero, marker `0x7b`, idle byte 9 and
TR zero. `0x9228` calls `digitalRead(57)` (recovered PB05 sense input).
`0x922c` compares the returned, previously sampled value against zero;
`0x922e` branches on LOW to shared acceptance `0x8f98`. A subsequent HIGH
does not withdraw that saved LOW. Thus an acquired active level can authorize
the programmed profile after the input has become inactive.

The observed acceptance path is
`0x8f98 → 0x6e4c → 0x4b64 → 0x6b50`, establishing channel state 1/profile
mode 1. The scheduled evaluator `0x6338` reaches rate start `0x5f8c` and timer
initialization `0x5570`. The first captured TC0 ENABLE-containing store is
**`0x571c`**, writing CTRLA `0x602`; it precedes explicit enable helper
`0x5810` and live-flag store `0x5fa4`. This route needs neither G nor W to
initiate the first profile. These are executed CPU requests, not measured motor
movement. [Original motor-output report](vvr-trigger-motor-output.md)

Both images load at `0x4000`:

| Image | Size | SHA-256 |
|---|---:|---|
| Original `firmware_autopilot915.bin` | 70,768 bytes | `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |
| Experimental freshness image | 70,796 bytes | `ae9e6a749426fc3d800a0e26d016cc58f818ce8f84d5a7ba12c41d6d727bc616` |

At **`0x922c–0x9231`** (file offset `0x522c`), six bytes
`00283ff4b3ae` (`CMP r0,0; BEQ.W 0x8f98`) become `B.W 0x15470; NOP`.
The appended **`0x15470–0x1548b`** routine rejects an original HIGH, saves
registers, calls the original `digitalRead` helper `0xd3dc` again at `0x15478`,
compares at `0x1547c`, restores registers, and routes to acceptance `0x8f98`
only if the second result is also LOW; rejection returns to `0x9232`.
It uses 24 additional stack bytes and no permanent RAM. All other original-region
bytes are unchanged. This is an image extension, not a verified physical code
cave. [Modification manifest](../../research/generated/trigger-patch-2026-10-22/modification-manifest.json),
[patch report and disassembly](experimental-trigger-freshness-patch.md)

## Controlled evidence and confirmed limits

Matched reset-based original/patched runs use the same Remote-built nonzero
program and MC4 configuration; the firmware establishes application state.

| Input history / control | Observed result |
|---|---|
| LOW acquired at `0x9228`, HIGH supplied at `0x922c` before comparison | Original accepts and reaches TC0 initiation. Patched rejects before acceptance, rate start and `0x571c` through 14M instructions; 230 second reads return HIGH. |
| Acquired LOW remains LOW (intentional control) | Both initiate once. All **29,236 captured selected write requests** match in values, PCs, widths, previous bytes and global order after instruction timestamps are removed. |
| Fresh inactive-to-active control | Both initiate. Named motor/peripheral streams match, but global housekeeping interleaving differs; full ordering equivalence is not established. |
| Release after the added read returns LOW | Patched still accepts at `0x8f98` and executes the ENABLE-containing store at `0x571c`. Release before the read rejects; release after comparison also initiates. The patch moves/narrows the sampling window; it supplies neither sustained qualification nor cancellation. |
| Held LOW, native profile completion, then supplied `W\|` | Original and patched initiate a second time without release. Held LOW without W completes but remains at one start through 60M instructions. W restores eligibility; held input alone is not demonstrated to repeat. |

Reproduction recipes, raw records and comparisons are preserved in the
[authoring packet](../../research/generated/trigger-patch-2026-10-22/README.md),
[Gate 2 packet](../../research/generated/patch-gate2-2026-10-22/README.md) and
[Gate 3 packet](../../research/generated/patch-gate3-2026-10-22/README.md).
Gate 2 independently reproduced 14 historical runs and added two instrumentation
controls; Gate 3 ran nine scenarios, including both residual witnesses.

**Modeled assumptions:** instruction-paced input/tick schedules, radio-ID and
MMIO-completion responses, a DWT delay stub and RX-ring packet delivery replace
physical environmental observations. W is supplied, not a demonstrated natural
Remote exchange. Position stays zero, so the completion/W witness has a
zero-distance return. Continuous TC/NVIC/STEP service and physical travel are
not established. Startup STEP requests also occur in negative controls and are
not evidence of trigger-caused movement. The transient recipe is a PC-timed
observation history, not a measured connection waveform or calibrated pulse.

## Correspondence to Nathan's VVRs

| Report | Engineering correspondence and boundary |
|---|---|
| **VVR-003** — Rev1 fault band, mode dependence | Original915 analog 517→600-count history initiates under X1 and remains inactive under X2, consistent with reported diagnostic fault values. The digital patch leaves this mechanism unchanged. Exact pin waveform and successive physical moves are unproved. |
| **VVR-004** — Rev2 active indication/repeated moves and UI eligibility | Held-active acceptance plus completion/W re-eligibility offers a conditional software mechanism without a new edge. It does not prove the actual M3/Remote exchange or physical return. Reported 74mV flickers during quiet watch caused **no motion**; they must not be recast as repeated-start evidence. |
| **VVR-005** — one move on powered-source connection despite corrected settled idle | Saved-LOW/current-HIGH acceptance and matched motor requests provide a plausible software contribution; the patch rejects that specific history. No measured insertion waveform proves this was the physical cause. |

These are behavioral correspondences, not proven physical causation. The
packaged binary is **not hash-linked to Nathan's field-tested `firm05-08`**;
the displayed R39 label cannot establish exact release identity. See
[VVR correlation, primary-report provenance and differences between sessions](vvr-trigger-failure-correlation.md).

## Source-code safeguards for Noxon to evaluate

The following are **proposed safety requirements**, not established product
policy or implemented patch features:

- Allocate explicit initialized trigger state: disabled/qualifying/armed/consumed.
  Qualify fresh inactive and active observations over justified real-time intervals;
  reject stale pre-arm samples and reset qualification on relevant readiness,
  mode, program and session transitions.
- Consume each trigger authorization once. Require a qualified release before
  rearming across completion and W-driven eligibility restoration; evaluate
  initial-release arming for an input active at startup.
- Define the initiation commitment boundary and release-cancellation latency.
  A second read alone cannot guarantee cancellation between sampling and output.
- Apply the chosen authorization rules to all trigger-derived producers; evaluate
  analog raw/filter disagreement, retained history, hysteresis and threshold
  overlap. Keep diagnostic visibility separate from permission to initiate.

**Unresolved product decisions:** whether bare W independently authorizes motion
or merely restores eligibility; exemptions for G/W1/B1/manual/jog; valid pulse and
release durations; active-at-startup behavior; cancellation commitment and latency.
The firmware's permissiveness does not settle these requirements. No calibrated
500ms intentional-pulse compatibility claim is available.

Input circuitry may still need polarity, leakage/bias or interface correction.
A sustained electrical fault that presents the same acquired history as an
intentional closure cannot be distinguished by software intent alone. Choosing
qualification times or deciding circuit changes needs physical source/jack and
PB05/PA02 waveforms, mode/arming state, and synchronized output observations on
the exact hash-identified release. These are evidence needs for discussion,
not scheduled measurements or authorized follow-on work.

## Verification disposition and handoff scope

| Preserved report | Verdict |
|---|---|
| [Gate 1](trigger-patch-gate1.md) | **INCONCLUSIVE** |
| [Gate 2](trigger-patch-gate2.md) | **INCONCLUSIVE** |
| [Gate 3](trigger-patch-gate3.md) | **FAIL within modeled scope** |
| [Gate 4](trigger-patch-gate4.md) | **INCONCLUSIVE**; residual behaviors confirmed, policy unresolved |

Package completion does not promote these verdicts. Full safety policy remains
unestablished; Gate 5 is **NOT RUN**. Integrated frame/write preservation,
whole-route coverage, interrupt/read timing and global ordering remain unresolved.

This handoff used repository/document inspection and existing APTrace evidence;
no new firmware execution or verification gate was performed. No firmware,
apfw2, formal model or hardware changed. APTrace gaps include validated continuous
timer/IRQ/position execution and native temporal-property evaluation/admission;
the existing reports document their evidence, impact and needed capabilities.
Their impact is high for certification or physical-output claims, but does not
prevent this bounded engineering handoff. Release identity, waveforms and policy
are separate missing evidence/decisions, not tool defects. No new capability gap
was encountered in consolidation. Noxon's source review and policy decisions are
the recommended discussion next steps; further APTrace development or experiments
require a separately chosen scope. **No additional gates or research are scheduled.**
