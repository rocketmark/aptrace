# AutoPilot / Remote: User-Guide Workflow Skeleton

**Purpose**: reconstruct how a human actually operates the AutoPilot system,
as a sequence of user-visible workflows, independent of firmware evidence.
This document should be readable by someone who has never seen either
firmware image. Firmware/command evidence is attached separately in
[`action-command-map.md`](action-command-map.md) — do not read firmware
addresses back into this file's own claims.

## Sourcing note — read this before using this document

No literal copy of `PerformingRigs_UserManual_AutoPilot.pdf` is present in
this repository. A prior research pass (recorded in
[`docs/hardware/autopilot-research-handoff.md`](../hardware/autopilot-research-handoff.md),
section 2 onward) read that PDF directly and produced a structured summary,
page-cited (pages 5-25). **That summary is this document's primary source**
— it is the "user guide material already in the repo" this document is
built from. `docs/firmware/firmware-inventory.md` separately notes that an
attempt to extract text programmatically from a copy of that PDF failed
("image-based/compressed PDF streams, not useful for firmware analysis") —
consistent with the manual being read and summarized by a human/prior
pass rather than machine-extracted here.

A second, independent source is used only as corroborating **landmarks**,
never as a substitute for the guide's own workflow description: the
Remote firmware's own embedded UI text strings, extracted via the
persistent Ghidra static export
(`research/runs/ghidra_cache/mando868/static_export.json`, 211 strings
total, addresses `0x0001c464`-`0x0001cfc8` plus a few unrelated
library/USB strings after that range). These are **real, compiled-in
screen text** — strong evidence that a given screen/prompt exists — but
knowing a string exists in the image does not by itself prove which
workflow step displays it, in what order, or under what exact
precondition. Every string used below is marked `[firmware string]`;
every workflow-shape claim (step order, what a control does, persistence
behavior, parameter meaning) is marked `[user manual]` and traces to the
handoff doc's citation of the PDF. Where the two disagree or a string's
placement is a guess, this document says so explicitly rather than
merging them into one undifferentiated narrative.

**Do not add workflow steps beyond what these two sources support.** If a
firmware string suggests a screen this document doesn't yet place (e.g. a
"USB-RF BRIDGE MODE" screen, or a "HOME:"/"TARGET:"/"ACC:" diagnostic
screen — both real, both found only as strings, neither described in the
handoff doc's manual summary), it is listed under "Screens found only as
firmware strings, not yet placed in a workflow" at the end, not forced
into one of the workflows above it.

## Confidence note

This document does not use the CONFIRMED/HIGH/PROBABLE/UNKNOWN scale
defined in [`action-command-map.md`](action-command-map.md) — that scale
is for firmware evidence, and this document deliberately contains none.
Instead, every claim here carries one of the two source tags above
(`[user manual]` / `[firmware string]`), or `[inferred]` for a small
number of structural connections this document draws between the two
(e.g. "the Quick Setup screen order below is inferred from the string
table's address order, not stated as an order by either source").

---

## 1. Power-on / startup

**Entry condition**: AutoPilot and Remote both powered off, paired (RF
channel already matched — see workflow 8).

**Steps**:
1. User connects 48V DC power to the AutoPilot and/or powers on the
   Remote (battery-powered handheld). `[user manual]`
2. `[user manual]` The AutoPilot has a status LED and a power button on
   its input panel.
3. `[firmware string]` The Remote's display shows a `"Charging"` string
   during at least one power-related state (battery charging screen,
   presumed — placement not otherwise confirmed).

**Resulting state**: both units running their own firmware; the Remote
begins a firmware-version / status handshake with the AutoPilot (see
workflow 9, Info / firmware version) rather than requiring an explicit
user action to establish contact.

**What becomes possible next**: Quick Setup (workflow 2) on a fresh
device, or Normal Runtime (Manual Mode / Auto Mode, workflows 3-4) if
setup has already been completed and persisted (workflow 10).

---

## 2. Quick Setup (first-time motor configuration)

**Entry condition**: **`[firmware, CONFIRMED by disassembly]`** — not
`[inferred]` as an earlier pass of this document had it. Quick Setup is
opened **by the AutoPilot, not by a Remote menu action**: the AutoPilot
detects, via four real GPIO probes, which of its four motor connectors
currently have a motor attached, sends the Remote a real
`MT<b0><b1><b2><b3><x>|` frame encoding that, and the Remote's inbound
radio-command handler reacts by assigning type `"Not connected"` to any
absent connector and opening the `"Motor <N>: Choose type"` screen
automatically. No Remote-side menu entry point into Quick Setup was
found by an exhaustive search. **The AutoPilot-side scheduling trigger is
now closed**: `MT` is sent exactly once per physical boot/MCU reset,
unconditionally, as a plain step of `sketch_setup()` — not periodic, not
change-driven, not reconnect-driven — so Quick Setup can only ever open in
response to whichever connector state existed at the AutoPilot's most
recent power-on/reset. See
[`mt-quick-setup-trigger.md`](../investigations/mt-quick-setup-trigger.md).
The
handoff doc's own section 8 ("Motor Configuration Constants") still
correctly describes the settings *data* this flow edits (current, max
speed, microstepping, return speed, motor type with auto-current for
built-in rig types); "Quick Setup" remains this document's own
descriptive label, not a term proven to appear on screen.

**Steps** (per motor channel, 1 through 4):
1. `[firmware string]` Screen prompts `"Motor <N>: Choose type"`.
2. `[firmware string]` Options observed in the string table:
   `"Motor <N>: Not connected"`, `"Motor <N>: POUR"`,
   `"Motor <N>: POUR HS"`, `"Motor <N>: SPIN"`, `"Motor <N>: Other"`.
   `[user manual]` Section 9 names these same rig types (Pour, Pour
   high-speed, Spin) with their gearbox/steps-per-rev relationship; "Other"
   is the manual's own custom-motor escape hatch (section 8.1), which
   allows manual current configuration instead of an auto-selected
   built-in current.
3. `[user manual]` (section 8) If a built-in type is chosen, current is
   auto-selected; "Other" requires the user to set current manually, in
   milliamps.
4. **`[firmware, CONFIRMED]`** A per-motor settings page (header
   `"MOTOR <N>"`) exposes four numeric rows — `"CURRENT (mA)"` (200-5000,
   step 50), `"STEPS/S MAX"` (1000-20000, step 20), `"MICRO-STEPPING"`
   (1-256), `"RETURN SPEED"` (0-100) — matching the manual's own
   quantities (section 8) closely, though only the Remote-side row
   identity is proven; what these four numbers mean to the AutoPilot's
   own motor driver remains PROBABLE, not proven (see
   `action-command-map.md`). **The Remote sends a wire command
   (`MC<0-3>`) every time the user clicks into a row, adjusts it with the
   jog wheel, and clicks out again** — not once per motor, and not tied
   to a "finish this motor" action. A motor's settings can be revisited
   and resent any number of times.
5. `[firmware string, CONFIRMED]` `"Continue"` exists exactly once in the
   Remote's entire string table, on the `"Motor <N>: Choose type"`
   screen (not on the per-motor settings page, whose equivalent row is
   labeled `"BACK"`). Clicking it, once all four motors have an assigned
   type, sends the all-channels wire command (`MC4`) and exits Quick
   Setup.

**Resulting state**: `[user manual]` per-channel motor type/current/speed/
microstepping/return-speed configuration established for up to 4 motors.
`[user manual]` (section 7) this configuration is stated to persist
across power-off (though no persistence mechanism connecting `MC0`-`MC4`
to the flash-backed config this project has otherwise characterized has
been found — see `action-command-map.md`'s Quick Setup entry).
**`[firmware, CONFIRMED]`** the `"Continue"` click additionally sends
`MC4`, which is the real, sole condition that lets the AutoPilot's own
`setup()` routine exit its internal loop and reach normal runtime.

**What becomes possible next**: `[inferred]` Normal Runtime (Manual Mode
/ Auto Mode) for any channel now configured as connected; also the
external-input passthrough behavior (workflow 8) and RF/settings screens
(workflow 8) are reachable independently of Quick Setup completion, per
the manual's own description of them as separate menu areas.

---

## 3. Manual Mode

**Entry condition**: `[user manual]` at least one motor channel configured
and connected; no external STEP/DIR controller currently driving the
AutoPilot (workflow 8 — external input disables Auto Mode but Manual Mode
"remains available").

**Steps**:
1. `[firmware string]` Screen shows `"MANUAL MODE"`.
2. `[user manual]` (section 4.1, 5) User rotates the jog wheel: motor
   moves continuously in one direction; rotating the other way moves the
   other direction; speed is centered around zero (rotation amount/rate
   maps to speed).
3. `[user manual]` User clicks the jog wheel: motor stops immediately.
4. `[user manual]` User double-clicks the jog wheel: cycles to the next
   *connected* motor channel (auto-detected; unconnected channels are
   skipped). `[firmware string]` Screen shows `"Direction"` (a
   configurable per-channel setting, presumed to be the A/B orientation
   invert the manual describes) and `"MOTOR 1"`/`"MOTOR 2"`/`"MOTOR 3"`/
   `"MOTOR 4"` channel labels.
5. `[user manual]` Direction can be inverted between A/B orientation (a
   configuration option, not a runtime jog-wheel gesture).

**Resulting state**: motor position changes live, in real time, with no
persisted "programmed move" — this is direct manual jogging, not Auto
Mode's stored-segment model.

**What becomes possible next**: switching to Auto Mode (workflow 4);
double-click to another channel and repeat.

---

## 4. Auto Mode: overview

**Entry condition**: `[user manual]` at least one motor channel configured.

**Steps**:
1. `[firmware string]` Screen shows `"AUTO MODE"`.
2. `[user manual]` (section 6) The user works with up to 4 motor channels
   (M1-M4), each with up to 4 programmed points (A, B, C, D) and up to 3
   segments between consecutive points (A->B, B->C, C->D). The manual
   states the **direction of rotation is recorded** as part of a segment,
   not just a distance.
3. `[user manual]` Each segment carries parameters: duration (ms) OR
   maximum speed (1-99 user scale), ramp (accel/decel proportion, example
   given: `50` = ~25% each way), delay (ms, pause before the move starts),
   and loop (YES/NO, causes back-and-forth motion).

**Resulting state**: none yet — this is the mode-selection step. See
workflows 5-7 for what happens inside Auto Mode.

**What becomes possible next**: recording/programming a segment
(workflow 5), testing a programmed segment (workflow 6), or executing a
programmed move (workflow 7).

---

## 5. Auto Mode: recording/programming a segment

**Entry condition**: Auto Mode selected, a motor channel selected.

**Steps** (best-effort reconstruction; exact on-screen order across all
4 points and up to 3 segments is `[inferred]`, not directly stated by
either source):
1. `[firmware string]` `"REC A-B"` / `"REC M1 A-B"` — presumed to be the
   screen/menu entry for recording the A->B segment on a given motor.
2. **`[firmware string, CONFIRMED by disassembly + concrete execution]`**
   The Remote's real point-recording dialog (Auto-Mode screen 5) shows
   exactly three lines: `"Click"`, then `"to rec A"` (segment 1, before
   the first point is recorded) or `"to rec B"`/`"to rec C"`/`"to rec
   D"` (after, depending on which of the 3 segments is being recorded),
   then `"Long-click to end"`. A short jog-wheel click is confirmed, by
   disassembly, to be the exact gesture that writes the current position
   into the segment's recorded point; a long click (>400ms) ends the
   dialog — matching the manual's own general jog-wheel semantics
   (section 4.1: click sets a programmed point; long press goes back).
   This is this project's first `'+'`-adjacent screen-text mapping closed
   end to end (string -> input -> state -> wire bytes) rather than
   inferred from string proximity — see
   [`action-command-map.md`](action-command-map.md)'s Part 3 for the
   full chain. `[firmware string]` `"to set A"` / `"to set B"` also exist
   as separate strings from `"to rec A"`/`"to rec B"` and were **not**
   part of this recording dialog's own render call — a second, still
   unplaced screen; **left unresolved**, not merged.
3. `[user manual]` The user positions the motor (via the jog wheel, same
   real-time control as Manual Mode) at each endpoint and confirms it as
   a programmed point.
4. `[user manual]` The user then sets that segment's duration/speed,
   ramp, delay, and loop parameters. `[firmware string]` `"DURATION"` is
   a confirmed on-screen label somewhere in this function family; which
   of `FUN_0000e670`'s screens 9/10 (the two remaining interactive `'+'`
   call sites) actually highlights it at send time is still PROBABLE, not
   CONFIRMED — see `action-command-map.md`'s Part 3.
5. `[firmware string]` `"CLEAR A-B"` / `"CLEAR ALL"` / `"CLEAR M1"`.."M4"`
   — clearing a previously recorded segment or channel. `[firmware
   string]` A confirmation dialog exists: `"Are you sure that / you want
   to clear / the selected movement?"`.
6. `[firmware string, CONFIRMED by disassembly]` `"NO MOVEMENT"` is shown
   specifically when **no channel at all** has any recorded segment data
   yet (not per-segment, as an earlier pass of this project's own
   investigation had loosely suggested) — a distinct Auto-Mode menu state
   from the point-recording dialog in step 2, not reached from any `'+'`
   call site. See `action-command-map.md`'s Part 3 "Corrections" note.

**Resulting state**: `[user manual]` a programmed segment (point pair +
duration/ramp/delay/loop) exists for this channel; `[user manual]`
persists across power-off (workflow 10). **`[firmware, CONFIRMED]`**
Recording a segment alone does **not** make it AutoPilot-drivable —
that requires a separate, non-interactive AutoPilot-side compute+persist
step, which this project has traced to a specific, real trigger (the
Remote's own boot sequence, or a reconnect after a communication gap —
never this recording action itself). See
[`action-command-map.md`](action-command-map.md)'s workflow 6 and
[`bulk-push-trigger-provenance.md`](../investigations/bulk-push-trigger-provenance.md).

**What becomes possible next**: testing the segment (workflow 6),
executing it (workflow 7), recording the next segment (B->C, C->D),
or clearing it.

---

## 6. Auto Mode: testing a programmed segment

**Entry condition**: at least one segment recorded for the selected
channel (workflow 5).

**Steps**:
1. `[firmware string]` `"TEST A-B"` / `"TEST B-C"` / `"TEST C-D"` —
   per-segment test/preview action, matching the manual's own A->B/B->C/
   C->D segment naming exactly.
2. `[firmware string]` `"PRESS BUTTON"` / `"TO STOP"` — a live-test
   control (press to halt the test move).
3. `[firmware string]` `"PREVIEW"` and `"RESUME"` / `"GOTO 0"` — related
   controls in the same area, not yet individually placed in the step
   sequence above (`[inferred]` grouping, not a proven order).

**Resulting state**: the motor physically moves through the tested
segment; the segment's own stored parameters are unchanged by testing
(testing is presumed non-destructive — not independently confirmed by
either source).

**What becomes possible next**: re-recording/adjusting the segment
(workflow 5), or committing to normal execution (workflow 7).

---

## 7. Auto Mode: executing a programmed move

**Entry condition**: `[user manual]` a segment (or full A/B/C/D program)
already recorded and saved for the selected channel.

**Steps**:
1. `[firmware string]` `"SET POINT"` / `"GO TO POINT"` — selecting a
   specific programmed point to move to.
2. `[firmware string]` `"Move to A"` / `"Move to B"` / `"Move to C"` /
   `"Move to D"` — direct point-to-point execution.
3. `[firmware string]` `"Travelling"` / `"RUNNING"` — in-progress state
   shown while the move executes.
4. `[user manual]` If loop is set to YES for the segment, motion
   continues back and forth rather than stopping at the far endpoint.
   `[firmware string]` `"REPEAT"` may correspond to this same concept
   (not confirmed to be the identical control).
5. `[firmware string]` `"Click to" / "switch movements"` — changing which
   programmed segment/channel is active while in this screen.

**Resulting state**: the motor is now at (or cycling between) the
programmed point(s); this is the "physical intent" the whole Auto Mode
recording workflow (5) was building toward.

**What becomes possible next**: re-entering programming (workflow 5),
running a different channel's program, or returning to the top-level
mode menu.

---

## 8. Motor selection / channel changes, position/return operations

**Steps** (cross-cutting; applies inside both Manual Mode and Auto Mode):
1. `[user manual]` Double-click cycles connected motor channels (Manual
   Mode, per section 4.1/5) — only channels the AutoPilot has
   auto-detected as connected are cycled through.
2. `[firmware string]` `"MOTOR 1"`/`"MOTOR 2"`/`"MOTOR 3"`/`"MOTOR 4"` —
   channel-selection labels (also reused inside Quick Setup, workflow 2).
3. `[user manual]` (section 8.4) "Return speed" is a configured parameter
   (default 25, up to 99) governing how fast the motor returns to a
   reference point; `[firmware string]` `"RETURN SPEED"` on the
   per-motor settings screen (workflow 2) is presumed to be this same
   setting, and `"GOTO 0"` (workflow 6/7) is presumed to be a manual
   trigger of a return-to-reference move, though the exact relationship
   between the two is `[inferred]`, not proven.

**External input passthrough** (a distinct, cross-cutting condition):

- `[user manual]` (section 10) When an external STEP/DIR controller
  (Dragonframe DMC-32, MRMC Ulti/Quad/Octo-Box) is connected to one of
  the four RJ45 "motor signal inputs," Manual Mode remains available but
  **Auto Mode is disabled/grayed out**.
- `[firmware string]` `"DMC32 inputs"` / `"MRMC/Other"` — source-type
  labels shown on the Remote in this state.

---

## 9. Info / firmware version

**Entry condition**: none — available at any time, and (per this
project's own already-execution-confirmed firmware finding) exercised
automatically as part of the Remote/AutoPilot connection handshake, not
only on explicit user request.

**Steps**:
1. `[firmware string]` `"Remote firm. ver."` / `"AutoPilot firm. ver."` —
   two separate version-display fields.
2. `[firmware string]` `"Signal:"` / `"IR Sens:"` / `"Trigger:"` — live
   status fields shown on the same or an adjacent screen.
3. `[firmware string]` `"Developed by"` / `"Firmware version"` /
   `"868MHz band"` — an about/credits-style screen, also naming the RF
   band variant (see workflow 13, firmware update, for the paired
   868 MHz / 915 MHz image split).
4. `[user manual]`/execution-confirmed (see `action-command-map.md`):
   the AutoPilot's firmware-version string is what this screen's
   "AutoPilot firm. ver." field displays, delivered over the wire via the
   `&|` -> `V01R39` transaction — the single most concretely proven
   transaction in this entire project.

**Resulting state**: informational only; no persistent state change.

---

## 10. Save / load / reset behavior (persistence)

**Steps**:
1. `[user manual]` (section 7) Programmed Auto Mode moves remain stored
   after the AutoPilot is powered off — the manual states this directly,
   without describing an explicit "save" button distinct from the
   recording workflow itself (i.e., recording IS saving, from the user's
   perspective).
2. `[user manual]` Per-motor configuration (workflow 2) is implied to
   persist the same way, since it would be impractical to redo Quick
   Setup on every power cycle, though the manual is not quoted as saying
   this explicitly in the handoff doc's summary.
3. `[firmware string]` No explicit "SAVE" or "LOAD" string was found in
   the Remote's own string table — consistent with save-on-confirm rather
   than a separate save step, but not proof of it.
4. Reset: no user-guide-described "factory reset" workflow was found in
   the handoff doc's summary. **Not covered by current evidence.**

---

## 11. RF / settings / configuration screens

**Steps**:
1. `[firmware string]` `"BRIGHTNESS"`, `"RF CHANNEL"`, `"TRIGGER"`,
   `"IR-SENSOR MODE"`, `"TRACTION CTRL"` — a settings-menu family,
   separate from per-motor Quick Setup settings.
2. `[user manual]` (section 12) Trigger input (3.5mm TRS) behavior:
   connecting the trigger cable *before* power-up establishes a noise
   baseline (less sensitive, less false-triggering); connecting it
   *after* power-up is more sensitive but more prone to false triggers.
   `[firmware string]` `"Relay contact"`, `"12/24Vdc"`, `"Start"`,
   `"Current"`, `"Delay"`, `"Pingpong mode"` are all found near a
   `"SET LIMITS"` string in the table and plausibly belong to the
   trigger/relay settings screen family, but this placement is
   `[inferred]` from string proximity only — exactly the kind of
   inference this project's own standing caution warns against treating
   as proof (see `action-command-map.md`'s confidence-scale note).

---

## 12. Limit-setting workflow

**Entry condition**: `[inferred]` a channel selected, not yet limit-set.

**Steps**:
1. `[firmware string]` `"SET LIMITS"`.
2. `[firmware string]` `"Make sure that / the slider can / move freely."`,
   `"Click the knob / to continue"`.
3. `[firmware string]` `"Setting first"` / `"Detecting first / limit..."`
   / `"Done!"`.
4. `[firmware string]` `"Move to the"` / `"second limit"` / `"Setting
   second"` / `"Detecting second"` / `"Centering..."` / `"Finished!"`.
5. `[firmware string]` Failure/empty states: `"No limits set"`,
   `"Process failed"`; success: `"Limits successfully"` (string appears
   truncated in the table — likely continues on a second line not
   separately extracted).
6. `[firmware string]` `"Press knob to start"` / `"using the cablecam"` /
   `"Press knob to exit"`.
7. `[firmware string]` Related settings found nearby: `"Reset limits"`,
   `"Set limits"`, `"Surpass limits"`, `"Speed limit"`.

**Resulting state**: `[inferred]` two limit positions established for the
selected channel/context, matching this project's own firmware-side
finding (see `action-command-map.md`'s `LL1`/`LL2` entry) that a real
protocol pair exists for exactly "first limit" / "second limit"
recording, with a validity flag set only once the two differ.

**What becomes possible next**: `[user manual]` "surpass limits" implies
Auto Mode / cablecam motion can be configured to continue past a limit
rather than stop there ("ON: Cablecam continues to move slowly surpassing
limits" / "OFF: The cablecam stops when reaching a limit" —
`[firmware string]`, both lines found verbatim in the table).

---

## 13. Firmware update

**Steps**:
1. `[user manual]` (section 13) A Windows-only updater, "NOXON Firmware
   Uploader," connects over USB-C.
2. `[user manual]` Separate firmware images exist per device and per RF
   region: Remote EU/868MHz, Remote NA/SA 915MHz, AutoPilot EU/868MHz,
   AutoPilot NA/SA 915MHz — matching this project's own four firmware
   files (`firmware_mando868.bin`, `firmware_mando915.bin`,
   `firmware_autopilot868.bin`, `firmware_autopilot915.bin`).
3. `[user manual]` The updater screenshots show serial parameters
   (1200 baud, 7E1, RTS enabled) associated with reset/bootloader entry —
   explicitly not assumed to be the actual firmware transfer protocol
   itself.

**Resulting state**: new firmware image running on the target device.

---

## Screens found only as firmware strings, not yet placed in a workflow

These are real, compiled-in Remote UI strings with no corresponding
description in the handoff doc's user-manual summary. Listed here rather
than forced into a workflow above, per this document's own sourcing
discipline.

- **A ramp/diagnostic-looking screen**: `"HOME:"`, `"TARGET:"`,
  `"TOTAL LENGTH:"`, `"Max speed:"`, `"ACC OUT OF LIMITS!:"`,
  `"ACC NOW LIMITED TO:"`, `"ACC:"`, `"Testing with Ramp:"`,
  `"NEW MIN DURATION:"` — reads like a live-value or debug/engineering
  display, possibly only reachable through a service/hidden menu. Not
  mentioned anywhere in the handoff doc.
- **USB-RF bridge mode**: `"USB-RF BRIDGE MODE STARTED"`, `"USB-RF"`,
  `"BRIDGE"`, and a support-contact string
  (`"Contact info@noxon.tech for information regarding the accepted
  control messages"`) — suggests a PC-bridge/passthrough mode entirely
  absent from the handoff doc's manual summary.
- **A Spanish-language string**: `"Posicion grabada: "` ("position
  recorded") — suggests either a leftover localization string or a
  second-language build path; not explained by any English-language
  manual content summarized so far.
- **Test/clear-per-motor family distinct from per-segment testing**:
  `"CLEAR M1"`.."CLEAR M4"`, `"TEST M1"`.."TEST M4"` — these test/clear
  a whole *motor*, as opposed to `"TEST A-B"`/`"CLEAR A-B"` which test/
  clear a *segment*. The relationship between the two (does "TEST M1"
  run all of that motor's recorded segments in sequence?) is not
  addressed by the manual summary.
- **`"E1,0,|"` / `"E1,400000,|"` / `"E1,1500,|"` / `"E1,10000,|"`** — look
  like literal wire-command frames embedded as UI-adjacent constants
  (default values for an `E1,...` command already flagged as
  low-confidence/unresolved in
  [`docs/protocol/command-inventory.md`](../protocol/command-inventory.md)'s
  "Lower-confidence / unresolved" section) rather than display text.
  Flagged here for completeness, not claimed as a UI screen.

## See also

- [`action-command-map.md`](action-command-map.md) — firmware evidence
  overlay on top of this document's workflows.
- [`../hardware/autopilot-research-handoff.md`](../hardware/autopilot-research-handoff.md) —
  this document's primary source (sections 2-13).
- [`../protocol/command-inventory.md`](../protocol/command-inventory.md) —
  the flat command list this document's workflows are now layered on top
  of.
