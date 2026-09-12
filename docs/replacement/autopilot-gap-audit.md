# AutoPilot Replacement-Firmware Gap Audit

**Purpose**: assess whether existing reverse-engineering evidence is
sufficient to write a clean-room behavioral/hardware specification for
replacement AutoPilot firmware. The original audit pass was a pure
coverage audit against already-produced evidence, performing no new
reverse engineering. Two follow-up, bounded resolution passes then
closed specific named gaps it identified: **Gap Resolution A** (below)
closed the `CONCRETE`-type gaps via two targeted concrete-execution
scenarios; **Gap Resolution B** (below) closed several `STATIC`-type
hardware/behavior gaps via bounded flash-dump/disassembly against the
existing cached Ghidra project. Neither was a broader re-audit.

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
| 4 | direction control | IMPLEMENTABLE_WITH_ASSUMPTIONS | HARDWARE |
| 5 | per-channel position accounting | COMPLETE | NONE |
| 6 | move/ramp profile execution | IMPLEMENTABLE_WITH_ASSUMPTIONS | PRODUCT_DECISION |
| 7 | motor enable/disable GPIO handling | COMPLETE | HARDWARE |
| 8 | external STEP/DIR input behavior | EXTERNAL_EVIDENCE_REQUIRED | STATIC |
| 9 | Manual Mode | COMPLETE | NONE |
| 10 | Auto Mode | IMPLEMENTABLE_WITH_ASSUMPTIONS | STATIC |
| 11 | programmed positions/moves | IMPLEMENTABLE_WITH_ASSUMPTIONS | NONE |
| 12 | motor configuration | COMPLETE | NONE |
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

## Gap Resolution B (this session)

Six bounded static-evidence investigations, using only existing tooling
(`tools/ghidra/aptrace_ghidra.py`'s `literal`/`dump`/`disasm`/`callers`/
`xrefs` queries against the already-built cached Ghidra project — no
new whole-firmware analysis, no Unicorn, no SMT).

**1/2 — DIR and enable/disable pin identities (RESOLVED)**: both reuse
the exact technique `boot-and-hardware-bringup.md` already validated for
the STEP pins — the RAM address holding a pin-table *index* is
`.data`-initialized, so its real byte value lives in flash at a fixed
offset (`RAM_addr − 0xB2C0` for this image, re-derived and confirmed
against the 4 already-known STEP entries before trusting it on new
addresses) and can be read directly, then decoded through the same
24-byte-stride pin-descriptor table (flash `0x14284`). Per-channel DIR
pins came out PB11/PA09/PB13/PA11 — each exactly one pin number above
its channel's already-known STEP pin (PB10/PA08/PB12/PA10), a clean
adjacent-pin pattern across all 4 channels. `0x77a0`/`0x77f8`/`0x7868`
resolve to exactly 4 real control pins, not a "two distinct chips"
split: PB16/PB17 (driven HIGH by `0x77a0`'s enable path, LOW by both
`0x77f8`/`0x7868`'s disable paths) and PB06/PB07.
`0x77f8` and `0x7868` were confirmed **byte-for-byte identical** in
every literal address referenced — there really is only one pin set.

**Correction (later Ghidra+Macaw cross-checked pass)**: PB06/PB07 are
**not** a HIGH pulse in both disable sequences — `0x77f8` sets them
HIGH (and does not set them back LOW within that function); `0x7868`
sets them LOW instead. Each function writes PB06/PB07 to one static
value, once; the apparent "pulse" only exists across separate calls,
never inside one function body. `0x77a0` (enable) never touches
PB06/PB07 at all. See `firmware-pin-function-map.md`'s "Firmware
semantics of PB06/PB07/PB16/PB17" for the full write-site/value/
ordering table and the exhaustive boot-time finding (all four pins are
also driven HIGH once, at boot, inside `FUN_00006968`'s 1799ms-timeout
branch).

**3 — MC field semantics (RESOLVED)**: re-confirmed
`motor-subsystem-unlock.md`'s already-documented per-field storage/
transform/consumer table and pushed one bounded hop further on field 2.
Result: CURRENT and MICRO-STEPPING (fields 1, 3) are consumed **only**
by the already-confirmed LCD status-display functions — no traced
hardware effect in this image. STEPS/S MAX (field 2) feeds a **real**
fixed-point step-period computation (`24,000,000 / value`) in
`FUN_00006190`, stored alongside the established rate/phase machinery —
a genuine runtime effect. RETURN SPEED (field 4) is used purely as an
index into a per-channel-per-mode config table, but that table's
backing data is the same blank/all-`0xFF` blob
`motor-config-persistence.md` already established — so it is currently
a no-op by *data* absence, not by *mechanism* absence.

**4 — RF framing (PARTIALLY ADVANCED, not closed)**: one hop past the
already-known chip-ID probe found a real, unconditional 5-call
post-probe config sequence with literal arguments, plus (via the
existing `callers` cache query) a family of ~10 further register-
accessor wrapper functions consistent with a full SX127x config API.
Decoding which SX127x register each targets would mean decompiling each
wrapper individually — correctly out of this pass's one-hop-per-
candidate bound, so this remains a named, bounded, *specific* follow-up
rather than an open-ended one.

**5 — external STEP/DIR (checked, still `NO` confirmed mechanism)**: the
one architecturally-plausible candidate — the residual set's sole
EIC-tagged function, part of a 16-entry shared-dispatcher vector-table
family (the standard ArduinoCore-samd EIC callback pattern) — has a
callback table with **zero writers anywhere in the image** (existing
cached xref data). This mechanism is confirmed dormant, extending
`trigger-input.md`'s "EIC — inert" finding from one line to the whole
EIC line family. A polled (non-interrupt) mechanism was not ruled out.

**6 — status LED (checked, still not found)**: the one already-documented
"status" boot behavior (the radio-probe failure's infinite retry, "print
status; delay 1000ms; repeat") is, one hop down, a pure LCD print with
no GPIO write — ruling out the one candidate this evidence base
suggested.

## Notable findings this audit surfaces

- **Two genuine hard gaps remain** (`EXTERNAL_EVIDENCE_REQUIRED`): the
  RJ45 external STEP/DIR input path (an entire external-interface
  product feature — presence detection, Auto-Mode lockout, pulse
  passthrough) and the status LED. Both are still documented only as
  physical/manual facts — but Gap Resolution B (above) checked the one
  plausible firmware candidate for each and confirmed neither pans out
  (an unarmed EIC callback table; an LCD-only "status" print), so these
  are now negative findings on record rather than unexplored blanks.
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
- **Direction control's GPIO identity is now resolved** (Gap Resolution
  B) — PB11/PA09/PB13/PA11 per channel, one pin above each channel's
  already-known STEP pin. What remains is only the HIGH/LOW-to-physical-
  rotation correspondence, a hardware-datasheet fact this firmware's own
  code cannot fully disclose.
- **Error/failure behavior has no systematic treatment** — only
  incidentally-discovered cases (radio-probe retry, NVM stall
  conditions, the `I9|` dead end, digital-trigger bounce) are documented.
  For a clean-room replacement, closing this is more a product-scoping
  decision (which vendor quirks to intentionally preserve vs. fix) than
  a pure evidence gap.

## Reopening the 43 parked LOW-priority UNKNOWNs

**15 were reopened this pass** (Gap Resolution B, gap 5 — external
STEP/DIR): `0xcbb6, 0xcbbc, 0xcbc2, 0xcbc8, 0xcbce, 0xcbd4, 0xcbda,
0xcbe0, 0xcbe6, 0xcbec, 0xcbf2, 0xcbf8, 0xcbfe, 0xcc04, 0xcc0a`. The
justification is direct mechanical evidence, not a hunch: all 15 sit in
the same `0xcbb0`-`0xcc0a` vector-table range `firmware-layout.md`
already names (IRQ12-27), immediately adjacent to the already-resolved
`0xcbb0` (Pass 7's `INTERRUPT_HANDLER_EIC`), and disassembly confirms
all 16 entries (including `0xcbb0`) are structurally identical 6-byte
stubs (`movs r0,#N; b.w 0xcb6c`) tail-jumping into one shared EIC
callback dispatcher. They were not separately re-classified in the
semantic-pass pipeline (that pipeline is untouched by this task); this
gap-audit doc and its JSON companion record the finding instead.

No other candidate areas panned out to a specific address this pass —
the status-LED candidate checked (the radio-probe retry's status print)
was ruled out without touching any residual function at all (it isn't
one; it's already-known boot-sequence code).

## Readiness assessment

**Ready now**: the 12 `COMPLETE` and 6 `IMPLEMENTABLE_WITH_ASSUMPTIONS`
subsystems (18 of 23) have sufficient evidence to write their spec
sections today — MCU/clock/startup, per-channel position accounting,
Quick Setup/MC/MT, persistence/NVM, both trigger-input subsystems,
protocol RX parsing, protocol TX/event system, Manual Mode, Auto Mode,
programmed positions/moves, G/S/!/I/+ behavior, motor configuration,
motor enable/disable GPIO handling, motor timer/STEP generation,
direction control, move/ramp profile execution, and radio transport.

**Not ready without a scoping decision first**: the 2 remaining `PARTIAL`
subsystems (startup reference/input routine, error/failure behavior)
each carry one specific, named open question (a physical-mapping gap
and a product-scoping decision, respectively) that should be either
resolved or explicitly descoped ("replacement will not attempt to
bit-match this") before finalizing those sections.

**Blocked until the gap is closed or descoped**: the 2
`EXTERNAL_EVIDENCE_REQUIRED` subsystems (external STEP/DIR input, status
LED) have no firmware evidence to write from at all.

**Out of scope, no action needed**: USB/update/runtime behavior — write
this section directly from the standard-bootloader facts already in
`hardware-reference.md`.
