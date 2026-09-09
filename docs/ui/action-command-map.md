# Action -> Command Map

**Purpose**: attach the firmware evidence this project has already built (or
is building) onto the user-visible workflow skeleton in
[`user-guide-workflows.md`](user-guide-workflows.md). This is an overlay,
not a replacement, for [`../protocol/command-inventory.md`](../protocol/command-inventory.md)
(the flat command list) — read that first if you want "what does command
`X` do"; read this file for "what sequence of user actions gets the system
into the state where command `X` is emitted and means something."

## Confidence scale

| Label | Meaning |
|---|---|
| **CONFIRMED** | Proven by disassembly and/or concrete (Unicorn) execution against real, unmodified firmware. A command being CONFIRMED as Remote-generated, or CONFIRMED to have a given wire schema, does **not** by itself make the exact UI action/label CONFIRMED — those are graded separately. |
| **HIGH** | Strong, mostly-closed evidence chain (e.g. disassembly-confirmed call site plus a plausible but not fully independent string correlation), short of full proof. |
| **PROBABLE** | A real, disassembly-grounded finding exists, but the specific user-guide/manual-label mapping rests on circumstantial correlation (string proximity, structural shape) rather than a proven screen-text-to-input-to-command chain. |
| **UNKNOWN** | No firmware-side evidence placing this workflow step against any command, or vice versa. |

This mirrors, and does not replace, the evidence-level scale already in use
elsewhere in this project (`docs/tooling/tool-selection.md`'s "Evidence
levels": static / concrete / solver-confirmed) — those grade *how* a
firmware fact was established; the scale above grades *how confidently a
firmware fact is attached to a specific user-guide action*. A command can
be evidence-level-3 (solver-confirmed) on the firmware side and still only
PROBABLE on the user-action side, and this document keeps both dimensions
visible rather than collapsing them into one number.

---

## Part 1 — Workflow x Command overlay

Each block below follows the suggested field list: Workflow, User-guide
action, Visible Remote text/screen, Preconditions, Remote state/function,
User input/event, Wire command(s), AutoPilot handler/function, AutoPilot
state effect, Persistent-state effect, Hardware/motion effect, Confidence,
Evidence, Open question.

### 1. Power-on / Info-firmware-version (workflows 1, 9)

- **User-guide action**: device powers on; Remote establishes contact with
  AutoPilot and can show firmware version info.
- **Visible Remote text/screen**: `"Remote firm. ver."` / `"AutoPilot firm.
  ver."` `[firmware string]`.
- **Preconditions**: none (this is the AutoPilot milestone this whole
  project bootstrapped from).
- **Remote state/function**: `FUN_0000ba98` (real `&|` query routine).
- **User input/event**: none required — this transaction is not gated
  behind a specific button press in any evidence found; it is plausibly
  sent automatically on connect/periodically (not concretely proven
  either way).
- **Wire command(s)**: `&|` (Remote -> AutoPilot).
- **AutoPilot handler/function**: dispatcher `0x8258` -> `0x8890` (writes
  `pending[5]=1`); outbound dispatcher `0x9268` case 5 -> TX hook `0x8c10`
  with pointer to `0x20003134` = `"V01R39\0"` (written once at startup by
  `FUN_00004328`).
- **AutoPilot state effect**: `pending[5]` 1 -> 0 (consumed).
- **Persistent-state effect**: none.
- **Hardware/motion effect**: none.
- **Confidence**: **CONFIRMED** (concrete, both firmwares, full round
  trip — `tools/unicorn/virtual_link.py all`/no-arg run) that `&|` ->
  `V01R39` happens exactly as described. **UNKNOWN** what Remote-UI event
  actually triggers a real `&|` send (connect-time handshake vs. user
  opening the Info screen vs. periodic poll — no evidence distinguishes
  these).
- **Evidence**: [`dispatcher-loop-concrete-trace.md`](../investigations/dispatcher-loop-concrete-trace.md),
  [`tx-hook-verification.md`](../investigations/tx-hook-verification.md),
  [`mando-first-execution.md`](../investigations/mando-first-execution.md),
  [`virtual-rf-link.md`](../investigations/virtual-rf-link.md).
- **Open question**: what Remote-side event calls `0xba98` for real (menu
  navigation to the Info screen? a fixed post-connect handshake? both?).

### 2. Quick Setup / per-motor configuration -> `MC<0-3>` / `MC4` (workflow 2)

**Correction to the workflow's own entry condition**: Quick Setup is
**AutoPilot-initiated, not opened from a Remote menu**. The Remote's
inbound radio-command handler (`FUN_00010ce4`) is the only writer of the
Remote's Quick-Setup-in-progress flag, and it fires in response to a real
AutoPilot-built `MT<b0><b1><b2><b3><x>|` frame, itself built from four
real GPIO motor-connector presence probes on the AutoPilot side (flash
`0x740c`-`0x74ac`, frame written at `0x74ac`-`0x74dc`). No Remote-side
menu entry point into Quick Setup was found. See
[`mc-command-remote-provenance.md`](../investigations/mc-command-remote-provenance.md)
Part 4.

**The AutoPilot-side scheduling trigger, closed**: `MT` is sent exactly
once per physical boot/MCU reset, unconditionally, as a plain step of
`sketch_setup()` (`FUN_00009464`) — reached by a single, exhaustively-
confirmed-unique static path (`sketch_setup` → `BL FUN_00007770`
→ `B.W 0x7334`, with zero branches anywhere on that path and no other
entry anywhere in the compiled image), after the startup reference/input
routine and radio-ID handshake complete and before `setup()`'s own
`MC4`-wait loop begins. Never periodic, edge/change-driven, or
reconnect-driven — `setup()` itself is called exactly once, ever
(standard Arduino `main()` idiom), so Quick Setup is strictly
boot/setup-only. The four connector probes are a guarded 2-valued
(boolean) read per channel (not an arbitrary digit); their slot↔probe-
object mapping (`A→b0, C→b1, B→b2, D→b3` — not naive order) and the 5th
field's source (`0x20001fc0`) are both identified. See
[`mt-quick-setup-trigger.md`](../investigations/mt-quick-setup-trigger.md).

- **User-guide action**: choose each motor's type (or "Not connected"),
  set current/steps-per-second/microstepping/return-speed, press
  `"Continue"` through all four motors.
- **Visible Remote text/screen**: `"Motor <N>: Choose type"`, `"MOTOR <N>"`
  (settings page header), `"CURRENT (mA)"`, `"STEPS/S MAX"`,
  `"MICRO-STEPPING"`, `"RETURN SPEED"`, `"Continue"`, `"BACK"`
  `[firmware string, CONFIRMED co-located with the sender — see below]`.
- **Preconditions**: for `MC<0-3>`: a motor-settings page must be open
  (`*0x200018e7` in `0x32`-`0x35`) and a numeric row actually clicked
  into. For `MC4`: all four motors must already have an assigned type
  (including "Not connected").
- **Remote state/function**: **CONFIRMED**. A single function,
  `FUN_00005a8c`, builds every `"MC"` frame in the image (proven the sole
  builder by four independent full-image scans, not just a literal
  search) — it has exactly three call sites, confirmed by both the
  Ghidra call graph and an independent from-scratch decode of every
  `BL`/`BLX` in the image: `0xcb4c` (`FUN_0000c440`, the already-known
  `'S'`-handler bulk push), `0x1039e` (`FUN_00010258`, the "Choose type"
  screen's `"Continue"` handler), `0x10cbe` (`FUN_00010698`, the
  motor-settings numeric-row editor).
- **User input/event**: **CONFIRMED** for two of the three call sites.
  `MC<0-3>`: clicking out of an edited numeric row on the `"MOTOR <N>"`
  settings page (a real jog-wheel button press, `FUN_000171f0(0x2d)`, a
  direct `PORT.IN` read). `MC4` (via `0x1039e`): clicking the
  `"Continue"` row on the `"Motor <N>: Choose type"` screen, gated on all
  four motor-type bytes (`0x20001811`) being nonzero. `MC4` (via
  `0xcb4c`, the `'S'`-handler bulk push): **UNKNOWN**, unchanged — see
  workflow 6 below.
- **Wire command(s)**: `MC<0-3><a>,<b>,<c>,<d>,|` (per-channel, does not
  unlock anything); `MC4<a0>,<b0>,<c0>,<d0>,...|` (all four channels, 16
  fields total). Real captured frames at factory defaults: `MC1` ->
  `b'MC120,2400,1,25,|'`; `MC4` ->
  `b'MC420,2400,1,25,20,2400,1,25,20,2400,1,25,20,2400,1,25,|'`.
  **Mechanically distinct from every other command in this table**:
  `FUN_00005a8c` sends its frame **three times, with no ack wait** —
  matching this firmware's wake-preamble idiom, not `'+'`'s
  request/ack pattern. Any harness or model built on `MC` frames should
  expect up to three identical transmissions and no acknowledgement.
- **AutoPilot handler/function**: `FUN_00008258`'s `M`/`C` branch
  (`0x86f0`-`0x872a`) -> `FUN_00007a98` x4, writing
  `0x2000006c`/`0x200000dc`/`0x200000f0`/`0x20000138` per channel. `MC4`
  additionally executes `*0x20000060 = 0` at `0x8714` — the **sole**
  instruction anywhere in the image that clears this byte.
- **AutoPilot state effect**: per-channel config fields written (3 of 4
  feed unrelated boot-time/display functions; the 4th,
  `0x20000138[channel]`, is read by the locked motor subsystem itself as
  a secondary-table index). `MC4` only: `0x20000060=0`, which is the real,
  concretely-confirmed condition that lets `FUN_00009464`'s internal boot
  loop exit and hand control to `FUN_000093fc` (the sketch's real
  `loop()`), making `FUN_00007e2c`/`FUN_00008e18`/`FUN_00006338`/
  `FUN_00008a80` reachable on every iteration from then on. This slice
  reconfirmed the unlock concretely using a **Remote-produced** `MC4`
  frame (not an AutoPilot-side-fabricated one) for the first time, and
  confirmed a single-channel `MC1` frame does *not* trigger it.
- **Persistent-state effect**: none identified for `MC<0-3>`/`MC4`
  themselves (distinct from `'+'`'s persisted motor-target struct).
- **Hardware/motion effect**: none directly; `MC4` is a pure unlock —
  every subsequent motion-committing command (`G`, `I`, `'+'`-then-`G`)
  is meaningless without it having run first.
- **Confidence**: **CONFIRMED**, full chain (displayed string -> input
  gesture -> state -> sender -> exact wire bytes), for `MC<0-3>` and for
  `MC4`'s `0x1039e` call site. **PROBABLE** that the Remote's own field
  identities (`"CURRENT (mA)"`/`"STEPS/S MAX"`/`"MICRO-STEPPING"`/
  `"RETURN SPEED"`, CONFIRMED on the Remote side) carry the same meaning
  into the AutoPilot's own `0x2000006c`/`0x200000dc`/`0x200000f0`/
  `0x20000138` — structurally consistent, not proven; note in particular
  that the AutoPilot side uses field 4 (the Remote's own `"RETURN
  SPEED"` value) as a **table index**, not read directly as a speed,
  a real but unresolved cross-purpose worth flagging rather than
  smoothing over. **UNKNOWN** for `MC4`'s second call site's own trigger
  (the `'S'`-handler bulk push) — pre-existing, unchanged.
- **Evidence**: [`mc4-transition.md`](../investigations/mc4-transition.md),
  [`g-command-motor-subsystem-unlock.md`](../investigations/g-command-motor-subsystem-unlock.md),
  [`mc-command-remote-provenance.md`](../investigations/mc-command-remote-provenance.md)
  (this slice — full disassembly, independent scan methodology, and
  concrete captures for everything above).
- **Open question**: what writes `*0x2000027d` (selects a 4-row vs. 2-row
  settings-page variant). (The `MT` scheduling question is now closed —
  see above.)

### 3. Manual Mode jog -> (no confirmed wire command)

- **User-guide action**: rotate jog wheel to move motor in real time;
  click to stop; double-click to cycle channel.
- **Visible Remote text/screen**: `"MANUAL MODE"`, `"Direction"`, `"MOTOR
  1"`.."MOTOR 4"` `[firmware string]`.
- **Preconditions**: `[user manual]` a motor connected on the selected
  channel.
- **Wire command(s)**: **UNKNOWN**. No investigation in this project has
  identified a real-time "jog" wire command. `I<channel><mode>|` is the
  closest candidate structurally (per-channel, async) but
  `i-command-motor-chain.md` characterizes it as writing a per-channel
  mode/signal byte and (conditionally) a direction sign — not obviously a
  continuous streaming command a jog wheel's rotation would emit at a
  UI-interaction rate. `G<d><d><seq>|` is a synchronous, discrete
  request/ack, not a natural fit for continuous jogging either.
- **Confidence**: **UNKNOWN** for the wire-level mapping. The motor-side
  mechanism Manual Mode would eventually drive (`FUN_00006338`'s
  phase/velocity executor, `FUN_00005c00`'s TC rate-register writer, the
  TC0-3 ISR -> GPIO pulse chain) is independently CONFIRMED to exist and
  work — see workflow 7's evidence — but nothing yet connects it
  backward to a live jog-wheel-rate wire command.
- **Evidence**: [`i-command-motor-chain.md`](../investigations/i-command-motor-chain.md)
  (closest candidate, not confirmed as "the jog command"),
  [`motor-timer-survey.md`](../investigations/motor-timer-survey.md).
- **Open question**: what wire command(s), if any, does the Remote send
  while the jog wheel is actively turning in Manual Mode? (Candidate
  bounded question, not "reverse Manual Mode": does `I<channel><mode>|`
  repeat at a rate matching jog-wheel rotation speed, or is Manual Mode
  driven by a completely different, not-yet-catalogued command?)

### 4. Auto Mode: record/confirm a segment -> `'+'` (workflow 5)

See [Part 3 — Auto Mode deep dive](#part-3--auto-mode-deep-dive) below for
the full treatment (the three interactive `FUN_000049c4` call sites). Summary:

- **Visible Remote text/screen**: candidates found near the call sites'
  own function family: `"TEST A-B"`/`"TEST B-C"`/`"TEST C-D"`,
  `"DURATION"`, `"to rec C"`/`"to rec D"`, `"NO MOVEMENT"` (all rendered
  by `FUN_00005474`) — **CONFIRMED**, by disassembly and concrete
  execution, as the literal on-screen text at the two screen-5 call
  sites specifically; **PROBABLE at best** for screens 9/10, which
  render `"RUNNING"` right after the send but whose *pre-send* highlighted
  menu-row label is inferred from an arithmetic pattern, not observed —
  see Part 3 for the exact chain and exactly what's missing. `"COMMIT!"`/
  `"COMMIT2!"` are **ruled out** for all four call sites: `FUN_0000e670`
  loads no string address anywhere in its own body (confirmed: zero data
  references into the `0x1c000`-`0x1d000` string range across the whole
  function), and `"COMMIT!"`'s own renderer (`FUN_00007f90`) is not on
  any path reachable from these call sites.
- **Remote state/function**: `FUN_0000e670` (Auto-Mode configuration
  screen state machine, menu-index variable `*0x200001a0` observed values
  1-10) has **four** `'+'` call sites, not three — screen 5 has two
  mutually-exclusive call sites (identical arguments, collapsed into one
  by the decompiler, separated by disassembly this pass): `0xf40c` (a
  segment/channel's record is still empty) and `0xf5a6` (no channel has
  any recorded data at all) — both reach the same point-recording dialog;
  plus `0xf60c` (screen 10) and `0xf68c` (screen 9).
- **User input/event**: a real, blocking confirm/select wait
  (`FUN_0000cd70`, exactly two call sites in the whole image, both
  immediately gating a `'+'` send) returns `1` (short click, "record this
  point" — proven to be the same code path that writes the point into the
  record at offsets `+0xc`/`+0x10`/`+0x0`, the same convention
  `FUN_000049c4`'s own `param_4==1` branch reads) or `2` (long click,
  ">400ms held, with a two-pulse haptic" — ends the dialog).
- **Wire command(s)**: `'+'` with `param_4=1, mode=0` (both screen-5 call
  sites), `param_4=2, mode=0x14` (screen 10), `param_4=0, mode=0x14`
  (screen 9). Channel argument is `*0x2000180c - 1` at every site (the
  same 1-based-UI-to-0-based-wire convention already documented).
- **AutoPilot handler/function**: `FUN_00008258` -> tail-jumped region
  `0x806c` -> `FUN_000046c8`/`FUN_00004910` (per-record field write) ->
  (only if `mode>50`) `FUN_00004ca8` (target=start+delta) + `FUN_000043f0`
  (persist).
- **AutoPilot state effect**: writes per-record fields (delta, ramp
  params, validity byte) into `0x20001b40`'s channel struct.
  **`mode=0` and `mode=0x14` do NOT cross the `>50` compute+persist
  threshold** — the interactive screens write the delta field but do
  **not** themselves advance it into a live target or persist it.
- **Persistent-state effect**: none for the interactive calls (see above)
  — only the separate bulk-push call (workflow 6 below) crosses the
  persist threshold.
- **Hardware/motion effect**: none directly from the interactive `'+'`
  sends alone; a subsequent `G<channel>1<seq>|` would be needed, and even
  then the interactive calls' `mode` values don't populate a live target
  the way the bulk-push path does.
- **Confidence**: **CONFIRMED**, both statically and concretely (real
  captured `'+'` frames for all three distinct argument tuples — see Part
  3), that `FUN_0000e670` is a real UI caller of `'+'` with these exact
  four call sites and arguments, and **CONFIRMED** that the two screen-5
  sites' on-screen text is exactly `"Click"` / `"to rec A"`-`"to rec D"`
  (segment-dependent) / `"Long-click to end"`. **PROBABLE at best** that
  screens 9/10 correspond to "confirm/save an Auto Mode segment" the way
  the user-guide action label implies — see Part 3 for exactly what
  remains unresolved there.
- **Evidence**: [`plus-command-remote-provenance.md`](../investigations/plus-command-remote-provenance.md),
  [`persistent-record-motor-target-mapping.md`](../investigations/persistent-record-motor-target-mapping.md).
- **Open question**: see Part 3.

### 5. Auto Mode: execute a move -> `G<d><d><seq>|` mode-1 (workflow 7)

- **User-guide action**: select a programmed point/segment and execute
  the move ("GO TO POINT", "Move to A/B/C/D").
- **Visible Remote text/screen**: `"SET POINT"`, `"GO TO POINT"`, `"Move
  to A"`.."Move to D"`, `"Travelling"`, `"RUNNING"` `[firmware string]` —
  **none of these have been traced to a specific `G`-send call site**;
  listed here as the plausible landmark family, not a proven mapping.
- **Preconditions**: `MC4` already run (workflow 2); a target already
  populated for this channel/mode via `'+'` (workflow 4/11) — otherwise
  `G` mode-1 resolves a target of `0` or `-1` and never crosses
  `FUN_00006fd8`'s real-move threshold.
- **Remote state/function**: `0xb680` (`G` request builder).
- **Wire command(s)**: `G<channel><type=1><seq>|`.
- **AutoPilot handler/function**: `FUN_00008258` `G` branch -> arms
  `0x200025e1=2` -> `FUN_00007e2c` (state machine, called twice: once
  resolves target and advances state 0->1, once calls `FUN_00006fd8`) ->
  `FUN_00006fd8(channel, distance, ...)`.
- **AutoPilot state effect**: `FUN_00006fd8`'s own `if (8 < abs(distance))`
  branch: with a real, `'+'`-populated target, this project has
  concretely observed `distance=500` take the real move-commit branch
  (move-committed flag `0x20002524[0]=1`) — as opposed to `distance=0`
  (blank config) taking the documented `<=8` no-op branch.
- **Persistent-state effect**: none from `G` itself (the persist happened
  earlier, at `'+'` time).
- **Hardware/motion effect**: `FUN_00006fd8`'s move-commit arms the
  phase-machine (`0x2000310c[channel]=1`); the subsequent phase/timer/ISR/
  GPIO chain is independently CONFIRMED as a mechanism
  (`motor-timer-survey.md`/`i-command-motor-chain.md`) but was **not**
  re-verified in the same concrete run as this specific `distance=500`
  value (see `plus-target-distance-roundtrip.md`'s own "what this does
  not yet demonstrate" section).
- **Confidence**: **CONFIRMED**, concretely, for the entire chain from a
  real `'+'`-populated target through `G` mode-1 to a real move-commit
  decision — this project's single most complete concrete result.
  **PROBABLE** for the UI-label mapping ("Move to A" etc.) — no string has
  been traced to `0xb680`'s call site.
- **Evidence**: [`plus-target-distance-roundtrip.md`](../investigations/plus-target-distance-roundtrip.md),
  [`mc4-transition.md`](../investigations/mc4-transition.md),
  [`target-config-provenance.md`](../investigations/target-config-provenance.md).
- **Open question**: which Remote UI action (of "GO TO POINT" / "Move to
  A-D" / a Test action) actually calls `0xb680` with `type=1`? (`type`
  digits 0 and 2-9 are also structurally available and untraced against
  any UI label.)

### 6. Auto Mode: `'S'`-driven bulk config-push -> `'+'` mode `0x62` (workflow: reconnect/status refresh, not directly named in the guide)

- **User-guide action**: **UNKNOWN** — no explicit user-guide step names
  this. Most plausibly an automatic reconnect/status-refresh event, not a
  discrete button press.
- **Visible Remote text/screen**: none identified.
- **Preconditions**: this channel's locally-stored Auto Mode config must
  be nonzero (the loop skips channels with all-zero stored data).
- **Remote state/function**: `FUN_0000c440` (the same function that
  handles `'S'`/`!0`/`!1` queries), a loop over channels 0-3.
- **User input/event**: **UNKNOWN** — not gated behind a visible
  confirmation dialog the way the interactive screens are.
- **Wire command(s)**: `'+'` with `confirm1=confirm2=1`, `param_4=0`,
  `mode=0x62` (98), once per nonzero-data channel, each followed by
  `MC4` for all channels (per the disassembly of `FUN_0000c440`'s tail).
- **AutoPilot handler/function**: same as workflow 4, but `mode=0x62`
  **does** cross the `>50` compute+persist threshold: `FUN_00004ca8`
  computes `target=start+delta` and `FUN_000043f0` persists the whole
  struct.
- **AutoPilot state effect**: real, nonzero target computed and written
  (concretely demonstrated: `delta=500` -> `target=500`).
- **Persistent-state effect**: `FUN_000043f0` persists offsets 300, 301,
  and 500-1651 (the entire 4-channel motor-config struct) into the
  flash-backed buffer, dirtying it.
- **Hardware/motion effect**: none by itself — sets up state that a
  subsequent `G` mode-1 (workflow 5) consumes.
- **Confidence**: **CONFIRMED**, concretely and statically, that this
  exact call (mode `0x62`) is the one and only `'+'` call site that
  crosses the persist threshold, and that it fires from the `'S'`
  handler's bulk-push loop, not from an interactive screen. **PROBABLE at
  best** for what real-world event actually triggers `FUN_0000c440`'s
  `'S'`-branch to run in bulk-push mode (reconnect is the working
  hypothesis, not proven).
- **Evidence**: [`plus-command-remote-provenance.md`](../investigations/plus-command-remote-provenance.md)
  section 4B, [`plus-target-distance-roundtrip.md`](../investigations/plus-target-distance-roundtrip.md).
- **Open question**: what real Remote-side event calls `FUN_0000c440`
  with the bulk-push argument (as opposed to an ordinary `'S'` status
  query)? Reconnect-after-power-cycle is the leading hypothesis but
  untraced.

### 7. Motor-timer / GPIO hardware chain (workflow 7's physical consequence)

- **User-guide action**: n/a — this is the hardware layer underneath
  "executing a programmed move," not a separate user action.
- **Wire command(s)**: none directly; reached only as a consequence of a
  real move-commit (`FUN_00006fd8`, workflow 5) or (structurally,
  untested this way) `I<channel><mode>|`.
- **AutoPilot handler/function**: `FUN_00006338` (phase/velocity executor,
  gated on `0x20001b14[channel]!=0`) -> `FUN_00005ee8` -> `FUN_00005c00`
  (writes TC's CC0/period register) -> TC0-3's own ISR (IRQ107-110) ->
  `FUN_00005898`/`0xd388` -> real GPIO OUTSET/OUTCLR pulse.
- **Hardware/motion effect**: **CONFIRMED**, concretely, on all four
  channels: TC0->PB10, TC1->PA08, TC2->PB12, TC3->PA10 (a `.data`-segment
  startup fact, not application-written). This is the real step-pulse
  mechanism a completed move ultimately drives.
- **Confidence**: **CONFIRMED** as a standalone mechanism. **NOT
  re-verified** in the same concrete run as any specific `'+'`/`G`-driven
  distance value (e.g. this project's own `500`-distance scenario stops
  at `FUN_00006fd8`'s decision, per `plus-target-distance-roundtrip.md`'s
  explicit scope note) — the connective tissue between "a move was
  committed" and "these exact GPIO pulses fired for this move" is
  believed to hold (same firmware, same functions) but has not been
  chained in one continuous run.
- **Evidence**: [`motor-timer-survey.md`](../investigations/motor-timer-survey.md),
  [`pin-index-provenance.md`](../investigations/pin-index-provenance.md),
  [`i-command-motor-chain.md`](../investigations/i-command-motor-chain.md).
- **Open question**: chain a real `'+'`/`G`-driven nonzero distance
  through `FUN_00008e18`'s phase state machine into a concretely observed
  GPIO pulse, in one continuous run — the next step
  `plus-target-distance-roundtrip.md` itself names and does not take.
  Also unresolved (exhaustively searched, not found): what sets
  `0x20001b14[channel]` nonzero in the first place — see Part 4.

### 8. Limit-setting -> `LL1`/`LL2` (workflow 12)

- **User-guide action**: `"SET LIMITS"` -> detect first limit -> move to
  second limit -> detect second limit -> centering/finish.
- **Visible Remote text/screen**: `"SET LIMITS"`, `"Detecting first /
  limit..."`, `"Move to the / second limit"`, `"Detecting second"`,
  `"Centering..."`, `"Finished!"`, `"No limits set"`, `"Process failed"`,
  `"Limits successfully"` `[firmware string]`.
- **Preconditions**: none (reachable pre-`MC4`, like every ASCII command).
- **Remote state/function**: **UNKNOWN** — no investigation has found the
  Remote-side sender for `LL1`/`LL2` (only the AutoPilot side is
  characterized, and only by inference from `commands.csv`'s note that
  "remote UI strings around this command describe setting the first
  limit" — itself a static, unverified note, not firmware-code
  confirmation).
- **Wire command(s)**: `LL1|` (clear), `LL2|` (order and validate).
- **AutoPilot handler/function**: shared `'L'`-family handler
  `FUN_000054e0`. `LL1`: unconditionally clears two globals (`posA`
  `0x20003114`, `posB` `0x20002414`) plus a validity flag
  (`0x20002458`). `LL2`: compares/reorders `posA`/`posB` into
  `minDest`/`posB`, sets the validity flag **only if they differ**.
- **AutoPilot state effect**: as above. **CONFIRMED, exhaustively**: no
  other code anywhere in this firmware image writes `posA`/`posB` with a
  real (nonzero) value — meaning the mechanism that is supposed to
  *capture* a real limit position (presumably from live position during
  the "Detecting first/second limit..." UI sequence) is **not reachable
  through this firmware's ASCII protocol by any direct-literal-referenced
  instruction**. This is the same class of external/unprovisioned-data
  boundary as the blank `0x12000` motor-target default (workflow 4/11).
- **Persistent-state effect**: none — pure `.bss` RAM, not part of the
  `0x12000`-backed persisted struct.
- **Hardware/motion effect**: none — no GPIO/MMIO dependency at all
  (confirmed both by disassembly and by a live `--watch-mem-write` run).
- **Confidence**: **CONFIRMED** for everything on the AutoPilot side
  (schema, effects, and the negative result that no real position ever
  reaches `posA`/`posB` via any static path this project can find).
  **UNKNOWN** for the Remote-side sender and the exact UI-input mapping.
- **Evidence**: [`ll-limit-workflow.md`](../investigations/ll-limit-workflow.md).
- **Open question**: find the Remote-side `LL1`/`LL2` sender (same method
  as `'+'`'s provenance pass) and confirm whether the "Detecting first/
  second limit..." screens actually send these two commands, or whether
  they send something else entirely that a static scan of the AutoPilot
  side alone couldn't reveal a producer for.

### 9. Persistence field -> `D<value>,|` (workflow 10, partially)

- **User-guide action**: **UNKNOWN** — no user-guide screen or string has
  been connected to this command; it was found by pulling every caller of
  the shared "write one config byte" accessor, not from any UI trace.
- **Wire command(s)**: `D<value>,|` (trailing comma required to parse
  cleanly).
- **AutoPilot handler/function**: `FUN_00008258` `D` branch ->
  `FUN_00004370` (writes 32-bit value at persisted logical offset `0x15`)
  -> `FUN_0000977c` (marker `0xDE` at offset `0x19`).
- **AutoPilot state effect / Persistent-state effect**: dirties the
  persisted buffer; a real save (triggered by the already-disclosed PA22
  digital-input hold, or the periodic 20000-tick elapsed check) reaches a
  real NVM erase+write, confirmed to physically mutate flash `0x12000`
  with the exact value and marker, byte-for-byte, recoverable on a fresh
  boot with zero commands re-sent.
- **Hardware/motion effect**: none.
- **Confidence**: **CONFIRMED**, concretely, for the entire AutoPilot-side
  round trip (command -> dirty -> save -> flash mutation -> reboot
  recovery). **UNKNOWN** for any Remote-side sender or user-guide
  meaning — this command's *value* is understood; its *purpose* (what
  setting `0x15`-`0x18` actually represents to the user) is not.
- **Evidence**: [`dirty-flag-persistence.md`](../investigations/dirty-flag-persistence.md),
  [`d-command-persistence-roundtrip.md`](../investigations/d-command-persistence-roundtrip.md),
  [`nvm-param-and-full-roundtrip.md`](../investigations/nvm-param-and-full-roundtrip.md).
- **Open question**: what user-facing setting does the value at persisted
  offset `0x15` represent? (candidates, unconfirmed: brightness, RF
  channel, return speed, a global default — any of workflow 11's settings
  screens).

### 10. `S`/`!` status queries (workflow 9, extended)

- **User-guide action**: **UNKNOWN** specific trigger, but this is a
  synchronous status/config query, structurally similar to the firmware-
  version query.
- **Wire command(s)**: `S|` -> `P<value0>,` or extended form; `!0|`/`!1|`
  -> 11-field CSV (event 7) — **known, real 11-vs-10 field mismatch**
  between what AutoPilot emits and what the Remote's parser consumes; per
  this project's standing caution, **do not "fix" this** in any future
  harness work — it is a documented, real firmware discrepancy.
- **AutoPilot handler/function**: `FUN_0000083b2`/`0x87be` `S` branch;
  event 6 -> `P...` built from `0x20002524` (device state/mode, 0-4).
- **Confidence**: **CONFIRMED**, concretely, both response forms
  (`s-p-roundtrip.md`), including a real "don't downgrade" guard in the
  Remote's own parser. **UNKNOWN** what UI action(s) trigger `S`/`!`
  specifically (as opposed to them running automatically as part of
  connection maintenance, which `FUN_0000c440`'s bulk-push tail — see
  workflow 6 — suggests is at least part of the real picture).
- **Evidence**: [`s-p-roundtrip.md`](../investigations/s-p-roundtrip.md).
- **Open question**: event-7's 11 named fields (per
  `docs/protocol/open-questions.md` item 1) and the 11-vs-10 mismatch's
  real consequence — not pursued this slice, per this task's own
  explicit scope ("do not feel compelled to newly reverse every unknown
  command").

---

## Part 2 — Command prerequisites and stacks

### `MC4` -> everything motion-related

```
MC4<...>|
  -> writes 0x20000060=0 (the ONLY instruction anywhere in the image
     that does this)
  -> FUN_00009464's internal boot loop can now exit
  -> FUN_000093fc (the sketch's real loop()) becomes reachable
  -> FUN_00007e2c / FUN_00008e18 / FUN_00006338 / FUN_00008a80 become
     reachable on every subsequent iteration
  -> G, and any future real I-driven move, are now meaningful; before
     this, FUN_00006fd8 (real move-commit) is provably unreachable
```

Every workflow below "MC4 has run" in this document assumes this chain
has already completed; every workflow above it (Quick Setup itself, `S`/
`&`/`!`/`LL1`/`LL2`/`D`/the interactive `'+'` screens) does **not**
require it, since all of those are dispatched by the same top-level ASCII
chain reachable straight from cold boot.

### `'+'` -> target populated -> `G` mode-1 consumes it

```
'+' (mode > 50, e.g. 0x62)
  -> FUN_000046c8/FUN_00004910 writes delta (wire-supplied, unclamped)
  -> FUN_00004ca8 computes target = start + delta
  -> FUN_000043f0 persists the whole 4-channel struct

G<channel>1<seq>|  (type digit = 1, "mode 1" in this project's own
                    terminology for FUN_00007e2c's target-source selector)
  -> FUN_00007e2c resolves target from the SAME struct '+' just wrote
  -> distance = target - live_position
  -> FUN_00006fd8(channel, distance, ...)
  -> if |distance| > 8: real move-commit; else: documented no-op
```

`G` mode-1 **cannot be understood in isolation** from how the target was
populated — a `G` mode-1 sent against a blank/never-`'+'`-written channel
resolves `distance=0` (mode 0) or `distance=-1` (modes 1-9), per
`target-config-provenance.md`'s own exhaustive exercise of every type
digit against unpopulated config. This project has now demonstrated both
ends of this dependency concretely: the "nothing populated" case
(`mc4-transition.md`) and the "'+' populated it for real" case
(`plus-target-distance-roundtrip.md`).

### `'+'`'s three interactive call sites vs. its one bulk-push call site

```
Interactive (FUN_0000e670, screens 5/9/10, mode=0 or 0x14)
  -> writes delta field into the record
  -> does NOT cross the >50 persist threshold
  -> does NOT, by itself, produce a live target a later G can consume

Bulk push (FUN_0000c440's 'S'-handler tail, mode=0x62, once per
           nonzero-data channel)
  -> DOES cross the >50 persist threshold
  -> DOES produce a live, G-consumable target
  -> ALSO sends MC4 for all channels immediately after, in the same
     disassembled tail
```

Any workflow narrative that says "the user confirms a segment and it
immediately becomes drivable" is **not proven** by current evidence — the
one concretely-demonstrated path to a drivable target is the bulk-push
path, whose real-world trigger is itself only PROBABLE (most likely
reconnect/status-refresh, not a segment-confirm button press). This is
one of the most important corrections this modeling pass makes explicit:
**the interactive Auto-Mode confirm screens and the mechanism that
actually arms a move are not the same event**, contrary to what a naive
reading of "user confirms segment -> segment becomes drivable" would
assume.

### `LL1` -> `LL2`: an isolated pair, not connected to any motion state

```
LL1| -> clears posA, posB, validity flag (unconditional)
LL2| -> if posA != posB: reorders into minDest/posB, sets validity=1
        if posA == posB (e.g. right after LL1): no-op
```

Unlike `'+'`/`G`, this pair's precondition is trivial (nothing needs to
have run first) — but its *usefulness* precondition (posA/posB actually
holding real, distinct captured positions) has no confirmed producer
anywhere in this firmware image. Treat any workflow narrative describing
"the AutoPilot remembers where you set the limits" with caution — the
mechanism that would make that true has not been found.

### `D` -> dirty -> save: independent of the motion-command stack entirely

```
D<value>,| -> dirties the persisted buffer
  -> (independently, driven by a real GPIO hold or elapsed-tick check,
     NOT by anything D itself triggers)
  -> save fires -> real NVM erase+write -> flash 0x12000 mutated
```

`D` does not require `MC4`, does not touch the motor-target struct, and
its save trigger is not something `D` itself causes — it is a background
condition (digital input state, or elapsed time) that happens to check
the same dirty flag any other config write (including `'+'`'s bulk-push
persist) would also have set.

---

## Part 3 — Auto Mode deep dive

A dedicated disassembly-plus-concrete-execution pass closed most of this
section (against `mando868`'s persistent Ghidra cache and
`ConcreteMachine`, no re-import/re-analysis, no hand-picked SP/LR); full
disassembly excerpts and proof are in
[`../investigations/auto-mode-plus-callsite-identity.md`](../investigations/auto-mode-plus-callsite-identity.md),
summarized here. It corrects `plus-command-remote-provenance.md` on one
structural point:
**there are four `'+'` call sites in `FUN_0000e670`, not three** — screen
5 has two mutually-exclusive call sites with identical arguments, which
collapsed into one in that earlier, decompile-only pass.

### Exact call sites

| Call site | Address | Screen index (`*0x200001a0`) | Gate | Arguments `(confirm1,confirm2,channel,param_4,mode)` |
|---|---|---|---|---|
| A | `0xf40c` | 5 | `*0x20001099 != 0` AND this channel/segment's record is still empty (`FUN_00005450`-shaped zero check) | `(1, 1, *0x2000180c-1, 1, 0x00)` |
| B | `0xf5a6` | 5 | `*0x20001099 == 0` AND no channel anywhere has recorded data (`FUN_00005450()==0`) | `(1, 1, *0x2000180c-1, 1, 0x00)` |
| C | `0xf60c` | 10 | `*0x20001099 != 0` (unconditional past the screen-index check) | `(1, 1, *0x2000180c-1, 2, 0x14)` |
| D | `0xf68c` | 9 | `*0x20001099 != 0` AND `*0x20001905 == 0` | `(1, 1, *0x2000180c-1, 0, 0x14)` |

A and B are mutually exclusive (same screen index, opposite sense of
`*0x20001099`) and reach the **same** point-recording dialog body
afterward — for the purpose of this document they are one user-visible
action reached two structurally different ways, not two different
actions.

### Call site A/B — CONFIRMED, closed end to end

The ideal proof chain — displayed string -> input event -> state
transition -> `FUN_000049c4` -> exact `'+'` bytes — is **closed** for A
and B:

- **Screen rendering (CONFIRMED, disassembly + concrete)**: both blocks
  call `FUN_00005474(0, 2)` before the confirm wait. Disassembling
  `FUN_00005474`'s `param_2==2` arm and reproducing it concretely
  (`ConcreteMachine.call`) shows it fills three on-screen text slots from
  a RAM string table whose index (`*0x20002694`) is never written
  anywhere in the compiled image and lies in `.bss` — confirmed `0` by
  both static and concrete evidence. Table entry 0 (flash `0x2526c`)
  resolves the three lines actually shown: **`"Click"`** (`0x1ceca`,
  always), then **`"to rec A"`** (`0x1ced0`, segment 1) / **`"to rec
  B"`** (`0x1ceeb`, segment 1 after one short click) / **`"to rec
  C"`** (`0x1c57f`, segment 2) / **`"to rec D"`** (`0x1c576`, segment 3),
  then **`"Long-click to end"`** (`0x1ced9`, always). `"COMMIT!"`/
  `"COMMIT2!"` and the `"TEST A-B"`-family strings are **ruled out** for
  this call site — `FUN_0000e670` makes zero data references anywhere
  into the `0x1c000`-`0x1d000` string range; every string reaches the
  screen through `FUN_00005474`'s own table lookup, never a direct
  literal load in the caller.
- **Input event (CONFIRMED, disassembly)**: `FUN_0000cd70` — exactly two
  call sites in the entire firmware image, both gating a `'+'` send —
  returns `1` for a short click and `2` for a long click (>400ms, with a
  two-pulse haptic). The **same** code path that writes the confirmed
  point into the per-channel record (`+0xc`/`+0x10`/`+0x0`, the identical
  offset convention `FUN_000049c4`'s own `param_4==1` branch later reads)
  runs only when this returns `1` — proving "short click" is the real
  "record this point" gesture the manual's "click sets a programmed
  point" describes, and "long click" is "Long-click to end," matching
  the on-screen text exactly.
- **`'+'` bytes (CONFIRMED, concrete)**: entering `FUN_000049c4` directly
  with the real arguments captured at `0xf40c`/`0xf5a6` (a disclosed
  representative per-channel record, the same evidence tier this
  project's `plus-target-distance-roundtrip.md` already uses) produces
  the real frame `b'+1,1,1,2,0,1,0,50,0,0,0,0|'` for a seeded channel-2,
  segment-2 scenario.

**Verdict: CONFIRMED.** This is the first `'+'` call site in this project
to have its exact on-screen text, exact input gesture, and exact wire
bytes all proven in one closed chain, rather than inferred from string
proximity.

### Call sites C (screen 10) and D (screen 9) — partially closed

- **CONFIRMED**: neither block loads any string address directly, and
  both reach `FUN_0000b59c` (ack wait) then, on a successful ack,
  render **`"RUNNING"`** (`0x1c918`, via `FUN_0000cfc8`) — a real,
  disassembly-proven post-send state.
- **PROBABLE, not CONFIRMED**: which menu row (and therefore which
  string) is *highlighted at the moment of the send*, before the ack.
  Screens 6/7/8/9 each make their own row-indexed `FUN_00006558` call
  with a literal row argument, giving a clean `row = screen - 3`
  arithmetic progression (screen 6->row 3 `SPEED`/`DURATION`, 7->row 4
  `RAMP`, 8->row 5 `DELAY`, 9->row 6 — the `LOOP` toggle, confirmed by
  label match: `FUN_00005474`'s row-6 fill is exactly `record[+0x40]`'s
  YES/NO text). Extending that same arithmetic gives screen 10 -> row 7
  (`"TEST A-B"`/`"TEST B-C"`/`"TEST C-D"`, by table position) and screen
  5 -> row 2 (`"REC A-B"`/`"CLEAR A-B"` family, consistent with A/B being
  the point-recording dialog). **The missing edge is exact**: screens 5
  and 10 make no row-indexed `FUN_00006558` call of their own, so this
  extrapolation is not directly observed the way screens 6-9's own rows
  are — closing it needs either tracing the highlight-cursor variable
  (`0x20000fae`, set to `screen-2` on menu entry) into `FUN_00005474`'s
  highlight-selection logic, or a concrete run with the row-count/cursor
  state a real boot establishes.
- **`'+'` bytes (CONFIRMED, concrete)**: real captured frames —
  `b'+2,1,1,2,20,1,0,0,0,0,0,0|'` (site C) and
  `b'+2,1,1,2,20,3,1,50,0,500,9,0,60,0,600,0,0,0,0,700,0,0|'` (site D),
  for a seeded channel-2, three-segment scenario. Note the reference
  bulk-push frame (workflow 6, mode `0x62`) for the identical seed is
  `b'+2,1,1,2,98,3,1,50,0,500,9,0,60,0,600,0,0,0,0,700,0,0|'` — **byte-
  identical to site D except the mode field** (`0x14` vs `0x62`),
  visually confirming exactly what "does not cross the persist
  threshold" means at the wire level: same record data, different mode
  digit, different AutoPilot-side consequence.

**Verdict: `"RUNNING"` after the send is CONFIRMED for both C and D; the
pre-send highlighted-row label (`"TEST A-B"`-family for C, the `LOOP` row
for D) is PROBABLE**, one arithmetic extrapolation away from CONFIRMED —
not promoted further per this project's own standing discipline against
inferring on-screen co-location from proximity alone.

### Corrections this pass makes to prior documents

- `"NO MOVEMENT"` (`0x1c56a`) is rendered only in `FUN_00005474`'s
  "no channel anywhere has recorded data" branch (`FUN_00005450()==0`,
  `param_2==1`) — **not** on any `'+'` call path, interactive or
  bulk-push. `plus-command-remote-provenance.md`'s listing of it as a
  candidate landmark near the `'+'` call sites is superseded by this more
  precise placement.
- `"COMMIT!"`/`"COMMIT2!"` are definitively **not** shown at any of the
  four `'+'` call sites (see above) — remove them as candidates for this
  specific mapping; they remain real strings somewhere else in the same
  general menu family, per the original doc's own hedged framing.

---

## Part 4 — State-transition view

Descriptive analyst names, not firmware-internal state names (no such
named states exist in the compiled image beyond what's cited above as
specific bytes/flags):

```
COLD BOOT
  -> Reset_Handler / .data,.bss init (pin-index table, etc. fixed here)
  -> real startup reference/input routine ("homing" -- not that name)
  -> real radio-ID probe (external SX127x-shaped device check)
  -> setup()-equivalent's own internal loop (FUN_00009464)
       -- every ASCII command already reachable here: &, S, !, G, LL1,
          LL2, D, MC<0-3>, the interactive '+' screens, MC4 itself

MC4 RECEIVED
  -> 0x20000060 cleared
  -> loop()-equivalent (FUN_000093fc) now runs every main-loop pass
  -> NORMAL RUNTIME

NORMAL RUNTIME
  -> Manual Mode jogging (wire-level mechanism UNKNOWN -- see workflow 3)
  -> Auto Mode
       -> record/confirm a segment (interactive '+', mode 0/0x14 --
          writes delta, does NOT populate a live target)
       -> [separately, PROBABLE-reconnect-triggered] bulk config push
          ('+' mode 0x62 -- DOES populate a live target, persists it)
       -> G mode-1 request
       -> AutoPilot resolves target, computes distance
       -> if |distance| > 8: MOVE COMMITTED
            -> phase machine armed (0x2000310c[channel]=1)
            -> [independently-confirmed mechanism, not yet chained to
               this specific transition in one run] TC ISR / GPIO pulse
       -> else: NO-OP (matches "NO MOVEMENT" firmware string's likely
          referent)
```

---

## Part 5 — Next highest-value unknowns

Ranked by how many downstream mappings each would unlock, not by ease.
Four items from this list's earlier drafts — the screen-5 call-site
identity, whether `FUN_00005474` renders different strings per
screen-index, the `MC<0-3>`/`MC4` Remote sender, and the `MT` AutoPilot-side
scheduling trigger — are now closed (Part 3,
[`mc-command-remote-provenance.md`](../investigations/mc-command-remote-provenance.md),
and [`mt-quick-setup-trigger.md`](../investigations/mt-quick-setup-trigger.md))
and removed; the ranking below reflects what remains.

1. **What real Remote-side event calls `FUN_0000c440`'s bulk-push branch
   (mode `0x62`)?** Unlocks: turning this project's single strongest
   concrete result (the `500`-distance round trip) from "triggered by a
   PROBABLE reconnect hypothesis" into a CONFIRMED user-visible or
   protocol-level event.
2. **What wire command(s), if any, does the Remote send while the jog
   wheel is turning in Manual Mode?** Unlocks: workflow 3 entirely, one
   of the two top-level modes the manual describes, currently 0% mapped.
3. **What Remote function builds `LL1`/`LL2`, and does the "Detecting
   first/second limit..." UI sequence actually send them?** Unlocks:
   workflow 12, and would either close or definitively reopen the
   "posA/posB never gets a real value" negative result from the
   AutoPilot side.
4. **What does persisted offset `0x15` (the `D` command's field)
   represent to the user?** Unlocks: workflow 9/11's connection to a
   concrete settings screen — currently `D` is fully characterized
   mechanically with zero user-facing meaning attached.
5. **Does the highlight-cursor variable (`0x20000fae`, set to `screen-2`
   on menu entry) resolve, in `FUN_00005474`'s own highlight-selection
   logic, to row 7 for screen 10 and row 6 for screen 9** — closing the
   one remaining gap in Part 3's C/D verdicts (currently PROBABLE by
   arithmetic extrapolation from screens 6-9's own row arguments, not
   directly observed for 9/10)? Unlocks: promoting call sites C and D
   from PROBABLE to CONFIRMED, matching what this pass already closed for
   A/B.
6. **Trace the `param_4==1` record-field-to-wire-position mapping
   precisely** — the captured call-site-A/B frame
   (`b'+1,1,1,2,0,1,0,50,0,0,0,0|'`) shows the seeded `+0x14` value (50)
   land on the wire but not the `+0x10 - +0xc` delta (500) this
   project's other `'+'` analysis (`persistent-record-motor-target-mapping.md`)
   already attributes to that branch — a real, disassembly-answerable
   discrepancy between two of this project's own documents, not yet
   reconciled.
7. **What does `*0x2000027d` (the byte selecting the Remote's 4-row vs.
   2-row motor-settings variant) represent, and who writes it?** Lower
   priority than the above — likely a fixed product/hardware-variant
   identifier rather than user-configurable state, but not confirmed.
8. **Concretely deliver a real `MT` frame through the Remote's
   `FUN_0000c340`/`FUN_00010ce4` per-character inbound state machine** to
   reconfirm the already-disassembly-CONFIRMED Quick-Setup-flag effect
   concretely — assessed this pass as a materially larger, structurally
   different undertaking than this project's existing whole-packet
   `REMOTE_*_ENTRY` anchors; see
   [`mt-quick-setup-trigger.md`](../investigations/mt-quick-setup-trigger.md)'s
   own "Remaining unknowns."

Each of these is phrased as a single bounded question with a specific
function/address/mechanism named, not "reverse Manual Mode" or
"understand Quick Setup" — per this project's own standing discipline
against open-ended reversing campaigns.

## See also

- [`user-guide-workflows.md`](user-guide-workflows.md) — the workflow
  skeleton this file overlays evidence onto.
- [`../protocol/command-inventory.md`](../protocol/command-inventory.md) —
  the flat command list.
- [`../investigations/plus-command-remote-provenance.md`](../investigations/plus-command-remote-provenance.md),
  [`../investigations/plus-target-distance-roundtrip.md`](../investigations/plus-target-distance-roundtrip.md),
  [`../investigations/auto-mode-plus-callsite-identity.md`](../investigations/auto-mode-plus-callsite-identity.md),
  [`../investigations/mc4-transition.md`](../investigations/mc4-transition.md),
  [`../investigations/mc-command-remote-provenance.md`](../investigations/mc-command-remote-provenance.md),
  [`../investigations/ll-limit-workflow.md`](../investigations/ll-limit-workflow.md) —
  primary evidence sources.
