# AutoPilot Replacement-Firmware Gap Audit

**Purpose**: assess whether existing reverse-engineering evidence is
sufficient to write a clean-room behavioral/hardware specification for
replacement AutoPilot firmware. The original audit pass was a pure
coverage audit against already-produced evidence, performing no new
reverse engineering. A follow-up, bounded resolution pass ("Gap
Resolution A", below) then closed the specific `CONCRETE`-type gaps it
identified, using two targeted concrete-execution scenarios plus the
minimal disassembly needed to construct them correctly — not a broader
re-audit.

**Machine-readable companion**: [`research/generated/autopilot-replacement-gaps.json`](../../research/generated/autopilot-replacement-gaps.json).

## Scope and sources

Evidence pulled from `docs/project-status.md`, every file under
`docs/investigations/`, `docs/hardware/hardware-reference.md`, every file
under `docs/protocol/`, every file under `docs/ui/`, `docs/firmware/`, and
the AutoPilot868 semantic-pass artifacts (`research/generated/autopilot-semantic-pass1.jsonl`
through `pass9-bounded-static.jsonl`). The Performing Rigs AutoPilot user
manual is not present as a raw file in this repo; its content is already
absorbed into `docs/hardware/hardware-reference.md` (condensed feature
summary) and `docs/ui/user-guide-workflows.md`/`action-command-map.md`
(full command-by-command cross-reference), which this audit treats as the
manual's current-truth representation.

Current AutoPilot868 semantic state at audit time: 95 residual functions,
52 semantic HIGH, 0 MEDIUM, 43 UNKNOWN (all mechanically LOW priority,
parked).

## Status legend

| Status | Meaning |
|---|---|
| `COMPLETE` | Sufficient evidence exists to write the spec for this subsystem now, with no material open question. |
| `IMPLEMENTABLE_WITH_ASSUMPTIONS` | The observable contract is understood well enough to implement cleanly; some vendor-internal detail (exact algorithm, exact register) remains unknown but isn't required for a compatible clean-room replacement. |
| `PARTIAL` | A real, load-bearing question remains — either an unconfirmed mechanism or a path never concretely exercised. |
| `EXTERNAL_EVIDENCE_REQUIRED` | No firmware-side trace exists at all; the manual documents user-visible behavior but the mechanism is entirely unaddressed by current evidence. |
| `NOT_REQUIRED_FOR_REPLACEMENT` | Out of RE scope — a standard/generic component whose behavior doesn't need to be reverse-engineered. |

## Product-behavior matrix

| # | Subsystem | Status | `missing_fact_type` |
|---|---|---|---|
| 1 | MCU / clocks / startup | COMPLETE | NONE |
| 2 | startup reference/input routine | PARTIAL | PHYSICAL_MAPPING |
| 3 | motor timer / STEP generation | IMPLEMENTABLE_WITH_ASSUMPTIONS | STATIC |
| 4 | direction control | PARTIAL | STATIC |
| 5 | per-channel position accounting | COMPLETE | NONE |
| 6 | move/ramp profile execution | IMPLEMENTABLE_WITH_ASSUMPTIONS | PRODUCT_DECISION |
| 7 | motor enable/disable GPIO handling | IMPLEMENTABLE_WITH_ASSUMPTIONS | STATIC |
| 8 | external STEP/DIR input behavior | EXTERNAL_EVIDENCE_REQUIRED | STATIC |
| 9 | Manual Mode | COMPLETE | NONE |
| 10 | Auto Mode | IMPLEMENTABLE_WITH_ASSUMPTIONS | STATIC |
| 11 | programmed positions/moves | IMPLEMENTABLE_WITH_ASSUMPTIONS | NONE |
| 12 | motor configuration | PARTIAL | STATIC |
| 13 | Quick Setup / MC / MT | COMPLETE | NONE |
| 14 | persistence / NVM | COMPLETE | NONE |
| 15 | trigger input — digital | COMPLETE | NONE |
| 16 | trigger input — analog boot behavior | COMPLETE | NONE |
| 17 | protocol RX parsing | COMPLETE | NONE |
| 18 | protocol TX/event system | COMPLETE | NONE |
| 19 | G / S / ! / I / + behavior | COMPLETE | NONE |
| 20 | radio transport | IMPLEMENTABLE_WITH_ASSUMPTIONS | STATIC |
| 21 | USB/update/runtime behavior | NOT_REQUIRED_FOR_REPLACEMENT | NONE |
| 22 | status LED / status reporting | EXTERNAL_EVIDENCE_REQUIRED | STATIC |
| 23 | error/failure behavior | PARTIAL | PRODUCT_DECISION |

Full `known_behavior` / `evidence_refs` / `implementation_requirements`
detail per subsystem is in the JSON companion, not duplicated here.

## Gap Resolution A (this session)

Two bounded concrete-execution investigations closed all four
`CONCRETE`-type gaps this audit originally identified. Both reuse the
existing `ConcreteMachine`/`virtual_link.py` infrastructure (no new
analysis framework) and the same `AUTOPILOT_RX_ENTRY` direct-dispatch
boundary every other command scenario in that module already uses.

**A — interactive `'+'` path** (`tools/unicorn/virtual_link.py
plus-interactive`): the Remote's real frame builder (`FUN_000049c4`),
called with the real interactive-screen arguments
`(confirm1,confirm2,channel,param_4,mode)=(1,1,0,1,0x00)`, produces a
real wire frame; delivered into the AutoPilot's real `'+'` handler at
the same direct-entry boundary the bulk-push scenario already uses
(sidestepping the separately-documented cold-boot delivery blocker),
it writes the wire-supplied delta into the per-channel record but
leaves `target` and the dirty flag exactly as they were beforehand —
concretely confirming, for the first time, that the interactive path
cannot arm or commit a move by itself. Two real, disclosed Remote-side
display/print calls (`FUN_00014bb6`, `FUN_00014c7a`) needed stubbing —
both dereference a real but uninitialized-in-this-scenario display
object, the same role `AUTOPILOT_PLUS_DISPLAY_STUB` already plays on
the AutoPilot side, traced by disassembly before stubbing rather than
guessed.

**B — Manual Mode `0xF0`/`0xE0`** (`tools/unicorn/virtual_link.py
manual-f0e0`): disassembling `ascii_dispatcher__CUSTOM`'s (`0x8258`)
own `0xE0` arm shows its per-record field layout is byte-identical to
`0xF0`'s; the only real difference is a per-channel latch/cache
(`0x20001fdd`/`0x20001fe4`/`0x20001ff4`) that suppresses a *repeat*
at-limit call once a channel is already latched. Concretely
demonstrated: an identical over-threshold `0xE0` record reaches the
at-limit handler on a cold delivery but is silently skipped once the
latch is pre-set, while `0xF0` (no latch) re-fires unconditionally
every time. The latch's own timestamp field has zero consumers
anywhere in the image (existing cached xref data, not a new scan) —
no dead-man/timeout mechanism exists in current evidence for either
frame family.

Full narrative, register-level results, and disassembly excerpts are
in each scenario function's own docstring; per-subsystem updates are
reflected in the matrix above and the JSON companion.

## Notable findings this audit surfaces

- **Two genuine hard gaps** (`EXTERNAL_EVIDENCE_REQUIRED`, no firmware
  trace at all): the RJ45 external STEP/DIR input path (an entire
  external-interface product feature — presence detection, Auto-Mode
  lockout, pulse passthrough) and the status LED. Both are documented
  only as physical/manual facts, never traced into any code path.
- **The radio-transport gap mostly closes itself**: firmware evidence
  alone only reaches PROBABLE for the external radio chip's identity
  (register-pattern match to an SX127x-family part), but
  `hardware-reference.md`'s physical board inspection independently
  names the actual part — an Ai-Thinker Ra-01H (SX1276-based, publicly
  documented) — which is enough to implement against directly without
  needing byte-exact vendor-driver RE.
- **The `'+'` command's interactive path was the recurring blocker across
  four matrix rows** (Auto Mode, programmed positions/moves, G/S/!/I/+
  behavior, and indirectly move/ramp profile execution) — **now closed**
  by Gap Resolution A, above, without needing the blocked cold-boot
  delivery path at all: entering directly at the same dispatcher boundary
  every other command scenario already uses was sufficient.
- **This session's own semantic passes (3–9) already closed real,
  previously-undocumented ground**: the stepper-driver enable/disable
  GPIO sequences (`0x77a0`/`0x77f8`/`0x7868`), the `pinMode()` primitive
  (`0xd300`), the per-channel move/ramp-profile initializer and its
  record-reversal counterpart (`0x6e68`/`0x4ae4`), and the trigger-input
  analog-arm smoothing filter's full mechanism (`0x42a4`) — none of this
  was in `docs/investigations/` before this audit's inputs existed. It is
  reflected in the matrix above but not yet folded into the canonical
  investigation docs (a follow-up documentation task, not a gap in the
  evidence itself).
- **Direction control's exact GPIO identity is unresolved** — the XLR-4
  bipolar output pinout is known, the STEP pin map is known, but no
  document names the per-channel DIR pin(s) feeding the onboard driver
  ICs.
- **Error/failure behavior has no systematic treatment** — only
  incidentally-discovered cases (radio-probe retry, NVM stall
  conditions, the `I9|` dead end, digital-trigger bounce) are documented.
  For a clean-room replacement, closing this is more a product-scoping
  decision (which vendor quirks to intentionally preserve vs. fix) than
  a pure evidence gap.

## Reopening the 43 parked LOW-priority UNKNOWNs

None were inspected this pass — that is out of this audit's scope. Three
candidate areas where one or more of the 43 plausibly holds the missing
mechanism are flagged for a future targeted pass, not confirmed:

1. **Status LED GPIO driver** — small, simple, RAM/protocol-light
   functions are exactly what census priority scoring ranks LOW, and a
   status-LED `digitalWrite` wrapper fits that shape.
2. **External STEP/DIR RJ45 handling / external-controller presence
   detection** — the entire mechanism is untraced; some of the 43 may be
   its presence-probe or pulse-counting code.
3. **Per-channel DIR GPIO pin** — plausibly a near-neighbor of the
   already-resolved STEP-pulse functions.

No specific address is identified for any of these; they are hypotheses
for where to look next, not classification results.

## Readiness assessment

**Ready now**: the 10 `COMPLETE` and 6 `IMPLEMENTABLE_WITH_ASSUMPTIONS`
subsystems (16 of 23) have sufficient evidence to write their spec
sections today — MCU/clock/startup, per-channel position accounting,
Quick Setup/MC/MT, persistence/NVM, both trigger-input subsystems,
protocol RX parsing, protocol TX/event system, Manual Mode, Auto Mode,
programmed positions/moves, G/S/!/I/+ behavior, motor timer/STEP
generation, move/ramp profile execution, motor enable/disable GPIO
handling, and radio transport.

**Not ready without a scoping decision first**: the 4 remaining `PARTIAL`
subsystems (startup reference/input routine, direction control, motor
configuration, error/failure behavior) each carry one specific, named
open question (a physical-mapping gap, an unidentified GPIO pin, an
unconfirmed field-to-hardware mapping, and a product-scoping decision,
respectively) that should be either resolved or explicitly descoped
("replacement will not attempt to bit-match this") before finalizing
those sections.

**Blocked until the gap is closed or descoped**: the 2
`EXTERNAL_EVIDENCE_REQUIRED` subsystems (external STEP/DIR input, status
LED) have no firmware evidence to write from at all.

**Out of scope, no action needed**: USB/update/runtime behavior — write
this section directly from the standard-bootloader facts already in
`hardware-reference.md`.
