# Trigger-Input Investigation — Current Model

Reported bug: connecting a certain chain to the AutoPilot's 3.5mm trigger
input causes exactly one trigger, then normal operation continues. The
firmware-side mechanism is now fully characterized, cross-checked by
disassembly, concrete (Unicorn) execution, and solver (Crucible/What4/Z3)
proof: the trigger pin is polled, not interrupt-driven, has two
mutually-exclusive boot-selected arms (digital and analog), and neither
arm's accept path can arm motor motion or bridge back into motion via the
Remote. A software mitigation (consecutive-sample debounce) has been
designed and prototyped in Unicorn, but **no firmware has been patched or
flashed** — the physical root cause of the transient itself remains
unmeasured.

**A later, deliberately adversarial falsification pass** (started from
"assume the no-motion conclusion is wrong, try to break it," not from
re-confirming it) found two genuinely new per-channel RAM writes on the
trigger-accept reload path that this investigation's own original state
audit had missed, traced both to their real consumers by decompile plus
concrete Unicorn replay, and still could not find a reachable path to
motor motion. See "Falsification pass," below — the headline conclusion
is unchanged, but the evidence underneath it is now substantially
deeper, and one bookkeeping error in the original write-up (below) was
caught and corrected in the process.

## Current model

**Boot-time mode select.** `FUN_00006968` ("startup reference/input
routine"), called once from `sketch_setup__CUSTOM` before any trigger
logic runs, configures **PA02** (pin index `0x25`, port A bit 2)
`INPUT_PULLUP` and reads it exactly once. HIGH → mode flag `0x20001fc0=1`
(the **analog arm**); LOW → mode flag `0x20001fc0=2` (the **digital
arm**), and only on this arm is **PB05** (pin index `0x39` / analog alias
`0x3b`, port B bit 5) explicitly configured as a bare digital `INPUT`
(`pinMode` mode `0`, no pull). The two arms are mutually exclusive for
the entire power cycle — decided once, by PA02's level at boot, never
re-evaluated. EIC is proven uninvolved (Evidence, below): the trigger is
read by plain polled `digitalRead()`/`analogRead()`, not an interrupt.

**The digital arm** (mode flag `2`). PB05 is a floating (no-pull) digital
input. `phase_ramp_state_machine__CUSTOM` (`FUN_00008e18`, reachable only
after `MC4` unlocks it) polls it every main-loop iteration with no
history between polls — level-sampled, not edge-latched, no debounce.
Two consumers of that poll: (1) a `TR1|`-gated, ~500-tick-rate-limited
**T-status** send (`"T<0 or 1023>,<1 or 0>,|"`) to the Remote; (2) a
**seven-guard accept gate** (four idle-channel bytes, two provenance-
traced state cells, the `TR0|`/`TR1|` enable byte, then the PB05 read
itself) that, when satisfied and PB05 reads LOW, reaches a shared
**accept target** at `0x8f98`.

**The analog arm** (mode flag `1`) has two consumers of PB05, one dead,
one live and previously unknown. The **dead** one is a 128-sample ADC
baseline average (`FUN_00005d44`) computed once at boot and never read
by anything else in the image — structurally matches the user guide's
"establish a noise baseline" language but is disassembly-confirmed
unconsumed. The **live** one — found and fully characterized only in
this cluster's later work — is a second, complete accept/status path
inside the same state machine (`0x8e68`-`0x8f98`): it calls
`analogRead(PB05)` (really ADC1, not ADC0), compares the result against
a `[lower, upper]` RAM-resident threshold band (default `[200, 580]` on
the raw 12-bit scale), and on out-of-band reads either sends an analog
T-status frame (`"T<raw ADC1.RESULT>,<0 or 1 band flag>,|"`) or falls
through to the **same** `0x8f98` accept target the digital arm uses.

The analog arm's `analogRead()` runs through a real exponentially-
smoothed filter (`FUN_000042a4`) whose blend coefficient (`0x20000014`)
is cold, unwritten RAM — permanently `0.0f` — combined with a one-shot
"already sampled" latch (`0x20003118`) that is set once and never
cleared. The practical effect: the very first sample this function ever
takes, during the already-dead 128-sample boot loop milliseconds into
`sketch_setup()`, is **permanently latched** for the rest of the power
cycle; every later call re-executes the filter's math but the coefficient
being zero makes every subsequent blend a no-op. **A transient occurring
after boot cannot affect the analog path at all — it never resamples.**
But a trigger chain **already connected / electrically present at
power-up** *can* influence that first boot-time sample, and therefore the
latched analog-path state for the whole session — it is specifically a
**post-boot** insertion event this path is immune to, not a "connected
before insertion is physically possible" claim. If that one boot-time
sample happened to fall outside the threshold band, the accept path fires
on every subsequent idle poll for the rest of the session (still
non-motion-arming) — a consequence of a bad boot-time reading, not of a
post-boot transient.

**Why neither arm's accept path can arm motion.** `0x8f98`, the shared
accept target for both arms, writes a status byte and unconditionally
tail-jumps into a real config-reload chain (`config_loader__CUSTOM` →
`FUN_00006b50` → `FUN_00006952`): it re-reads the persisted motor-target
config, computes per-channel motion-profile arrays, and toggles a GPIO
pulse (PB30 high / PB31 low). But it **clears**, and never sets,
`phase_ramp_arm_byte` (`0x20002318[channel]`) — the *only* byte
`phase_ramp_state_machine__CUSTOM`'s own per-channel loop checks before
ever calling `motor_move_commit__CUSTOM`. An exhaustive cross-reference
of `0x20002318` finds exactly three writers in the whole image: the
reload itself (clears to idle), the state machine's own internal
self-transitions (only reachable once already armed), and one *other*,
structurally unrelated ASCII command (`0x865a`, part of the `'W'`
family, gated on the idle-check cell — not PB05 or the `'+'`-push cell).
That command is the sole `0`→`1` (armed) producer anywhere in the image.
**Neither trigger arm can reach it.**

**Why the T-status frame can't bridge back to motion either.** The
Remote's own inbound dispatcher (`FUN_00010ce4`) has a plain `'T'` branch
that parses both frame fields, stores them plus a "received" flag into
three RAM cells, and returns — no send call anywhere in the branch. The
only consumer of those three cells anywhere in the Remote's image is a
UI screen's render loop, which scales and redraws the value on screen.
Pure telemetry, concretely confirmed by delivering both real frame
shapes into the Remote's real inbound path and watching its TX wrapper
never fire.

**The self-correcting one-shot explanation.** With both accept paths
proven non-motion-arming and the T-status path proven to have no return
path, the mechanism that best matches the reported symptom is purely a
transient artifact of a floating, no-pull digital input: physically
connecting a chain to the jack is itself a transient electrical event
(bounce, coupling, partial seating) on a pin with nothing holding it
steady. If that transient overlaps a poll, the digital arm can accept
(reload the persisted config, harmless) and/or, if `TR1|` reporting is
armed and the rate-limit window happens to be open, send exactly one
T-status frame. Fault injection (Evidence, below) shows a bouncy
insertion can produce **multiple** accepted config-reloads (one per
LOW-reading poll) but **at most one** T-status frame per ~500-tick
window — "normal operation continues" is just the next ordinary,
independent poll of a mechanism with no memory, not a recovery path.

**Recommended mitigation.** Of six mitigation shapes evaluated,
**consecutive-sample debounce** (require PB05 LOW for *N* consecutive
polls of the accept gate before accepting) is the strongest: it protects
both boot-time and mid-session connection events without a real-time
clock, and — uniquely among the candidates — preserves the firmware's
own confirmed repeat-refire-while-held behavior exactly, so it changes
nothing about legitimate held-trigger use. It has been prototyped as a
34-byte Thumb-2 trampoline and exercised concretely in Unicorn against a
9-scenario regression matrix; it has not been flashed to any real device.

## Falsification pass — deeper producer→consumer audit

This pass deliberately did not start from "the prior conclusion is
correct." It re-derived both accept paths from scratch, then went beyond
the original state audit (which stopped at "`0x8f98` clears
`phase_ramp_arm_byte`") to mechanically enumerate **every** persistent
RAM write the trigger-accept reload (`FUN_00006b50`) makes, and traced
every one of them forward to a real consumer or to a proven dead end.

**Two genuinely new writes were found**, both previously uncharacterized
in this file, both gated on the same per-channel "has a valid stored
program" flag (`config_struct[ch].0x44 != 0`) the reload already checks
for its other work:

| Address | Value | Previously documented? |
|---|---|---|
| `0x20002524[ch]` (device-state byte) | `=1` | No |
| `0x2000310c[ch]` | `=1` | No — and see the correction below |
| `0x2000016c[ch]` | `=1`, unconditionally, all 4 channels | No |

`0x2000016c` was resolved first: an exhaustive raw-binary scan of the
compiled image for its literal address (not just Ghidra's `xrefs`
command — see the methodology note below) finds **exactly one**
reference anywhere in the whole firmware, the write itself. No reader
exists. **CONFIRMED** dead, the same class of finding as the ADC
baseline / `0x20001b14`.

`0x20002524[ch]=1` and `0x2000310c[ch]=1` are not dead — they have real
consumers, which is exactly the kind of thing this falsification pass
was looking for:

- **`0x2000310c==2`** is written by `FUN_00004d18`, but only when it is
  called, and its only caller (`FUN_00005274`) only reaches it when
  `0x20002318[ch]==1` (phase-1, already-armed) or `0x20002524[ch]∈{2,3}`
  (two periodic pollers) — **not** the value `1` the trigger reload
  writes. Closed.
- **`0x20002524==1`** (the value Trigger actually produces) has exactly
  one every-main-loop-tick consumer that accepts it:
  **`FUN_00005fac`**, called unconditionally from `sketch_loop__CUSTOM`.
  Full decompile of `FUN_00005fac` and its own terminal call
  (`FUN_00005958`) shows both of its branches — "not yet elapsed, update
  a timestamp" and "elapsed, advance a breakpoint index, and if that was
  the last one, clear state" — contain **zero** calls to
  `motor_move_commit__CUSTOM`, `FUN_00004d18`, or any GPIO/`digitalWrite`
  primitive. `channel_event_monitor__CUSTOM` (`FUN_00008a80`,
  `sketch_loop__CUSTOM`'s other direct callee) was also checked: its
  `switch(0x20002524[ch])` only acts on values `2`/`3`, making `1` a
  no-op case for it.
- **Concretely reconfirmed** (`tools/unicorn/trigger_device_state_closure.py`):
  starting from the real post-reload state (`device_state[0]=1`,
  `flag_310c[0]=1`, a real non-blank segment-duration table populated by
  the same reload), `FUN_00005fac` was run across 4 simulated main-loop
  ticks and `channel_event_monitor__CUSTOM` once more — zero writes
  beyond what the reload itself already made, zero reach into any motion
  primitive.
- **`FUN_00007e2c`/`phase_ramp_state_machine__CUSTOM`'s own re-entrant
  calls into `motor_move_commit__CUSTOM`** (`0x8fee`/`0x9050`,
  previously unattributed "callers" in a raw `xrefs` query) were also
  resolved this pass: phase-2/3 **continuation** logic, reachable only
  from an already-armed state, not a second arming path.
- **The analog arm's convergence onto `0x8f98`** was independently
  re-disassembled this pass (`0x8e68`-`0x8fa8`) rather than taken on the
  original write-up's word: it is the exact same address and bytes as
  the digital arm's target, not merely "nearby" code.

**Methodology correction.** Ghidra's `xrefs` command, queried for
`0x2000310c`, returned exactly 5 references and — critically — none of
them were the two real writes inside `FUN_00006b50` that a full
decompile then surfaced (it attributed those instructions to unrelated
addresses). This is now known to be a real blind spot, not a one-off:
every claim in this section was cross-checked by either a full decompile
or a raw little-endian literal-byte scan of the compiled `.bin` before
being trusted. **The pre-existing sentence in "Accept target `0x8f98`"
below, which said `0x2000310c`'s "one other reader" is
`motor_move_commit__CUSTOM`, was itself downstream of this same `xrefs`
gap and is corrected in place.**

**PB30/PB31 status, re-examined.** Confirmed real SAMD51 port-B bits
30/31 (pin-descriptor table, validated formula), pulsed unconditionally
by `FUN_00006952` on both the G-commit and the trigger-reload paths —
state-independent, so it cannot itself encode run/idle. A same pin-index
number on the *Remote* firmware drives its jog-wheel quadrature encoder,
but that is a different firmware image and not evidence for the
AutoPilot's own PB30/PB31. Physical role beyond "shared GPIO pulse" is
left **unresolved**, not invented.

**Conclusion of this pass**: `TRIGGER_NO_MOVEMENT_CONFIRMED`, now
resting on a full producer→consumer closure over every RAM cell the
trigger-accept path writes (including the two new ones above), each
traced to a proven-dead or proven-inert consumer, cross-checked against
a caught tooling failure, and closed with fresh concrete replay — not
merely "the immediate handler doesn't set `phase_ramp_arm_byte`."

## Evidence

Confidence tags follow this project's standard scale: **CONFIRMED**
(disassembly and/or concrete Unicorn execution), **SOLVER-CONFIRMED**
(Crucible/What4/Z3), **PROBABLE**/**INFERENCE**, **UNKNOWN**.

**Pins.** PA02 = pin-descriptor index `0x25` (port A, bit 2). PB05 = pin
index `0x39` (digital) / `0x3b` (analog alias), port B bit 5. Both
resolved directly from the real Arduino-core pin-descriptor table
(`0x00014284`, stride `0x18` bytes) — **CONFIRMED**. An exhaustive
call-site enumeration finds PA02 read in exactly one place in the whole
image, PB05 in exactly the paths named here (`digitalRead` twice,
`analogRead` via `FUN_000042a4`'s two total callers) — **CONFIRMED**.

**EIC ruled out.** The AutoPilot's EIC vector table stubs all tail-jump
into one shared handler whose three support addresses (callback table
`0x2000525c`, line count `0x200052e4`, per-line mask `0x200052a0`) each
have **exactly one** reference anywhere in the image — the handler's own
load. Nothing ever writes the line count, so the handler's loop body
never executes on any real interrupt. **CONFIRMED** by two independent
exhaustive whole-image scans.

**The seven-guard gate**, `0x9202`-`0x9228` (48 bytes, zero slack,
instruction-for-instruction from the raw firmware bytes):

| Addr | Instruction | Role |
|---|---|---|
| `0x9202`-`0x9211` | four `ldrb`/`cbnz` pairs | `0x20002524[0..3]` (per-channel device state) all `==0` |
| `0x9212`-`0x9219` | `ldr`/`cmp #0x7b`/`bne` | gate cell 1, `0x20001b38 == 0x7b` |
| `0x921a`-`0x9221` | `ldr`/`cmp #9`/`bne` | gate cell 2, `0x200000d8 == 9` |
| `0x9222`-`0x9225` | `ldrb`/`cbnz` | `0x20003120 == 0` (`TR0\|`, reporting disarmed) |
| `0x9226`-`0x922e` | `movs r0,#0x39; bl 0xd3dc (digitalRead); cmp r0,#0; beq.w 0x8f98` | the trigger read itself |

All seven guards, plus the `digitalRead` branch, are **SOLVER-CONFIRMED**
(a targeted Crucible/What4/Z3 query, 175s wall-clock, 9 queries): Query A — the gate is SAT with Z3
*independently deriving* `r5[0..3]=0, state32=0x7b, state8=0x9, r6[0]=0`,
matching Ghidra-provenance/Unicorn exactly. Query B — UNSAT for each of
the seven guards individually negated (no combination of the other six
compensates). Query C — the `digitalRead` branch reaches `0x8f98` iff
`R0=0`; `R0≠0` (fully symbolic, not a spot check) is UNSAT. An earlier,
broader attempt to prove the same region hit a real, exhaustively-confirmed Macaw/dismantle
classifier limitation (`CBZ_T1`/`CBNZ_T1` narrow compare-and-branch
lifts to a doubly-nested mux Macaw's classifier doesn't pattern-match;
4/4 classify failures in the function are this exact instruction,
worked around by re-seeding discovery at each known successor) and did
not converge to a SAT/UNSAT answer within a practical time budget (a
41MB/267,385-assertion formula, ~73.5% of it the entire RAM region
individually asserted `==0` byte-by-byte — a memory-model encoding
overhead, not a correctness gap); the narrower crosscheck query above
superseded it by dropping the RAM zero-overlay entirely, since this
bounded region reads only the seven named cells.

**Gate cell provenance.** Gate cell 1 (`0x20001b38=0x7b`) is set by the
already-known `'+'` command's `mode=0x62` bulk-push finalize path
(`FUN_00004ca8`/`FUN_000043f0`) — the same real event this project has
already proven fires on every Remote power-on/reconnect. Gate cell 2
(`0x200000d8=9`) is set by a real "all four channels idle" check inside
`phase_ramp_state_machine__CUSTOM` itself, and — a clean finding — is
**unconditionally reset to `0`** by the config-reload function
(`FUN_00006b50`) on every reload, a genuine self-clearing mechanism.
Both **CONFIRMED** by exhaustive cross-reference and Unicorn replay.

**Accept target `0x8f98`** (identical first instruction/address for both
arms): `ldr r3,[0x9148]` (`=0x200025bc`); `movs r2,#3`; `strb r2,[r3,#1]`
(status byte `=3`); `pop.w {r4-r11,lr}; b.w 0x00006e4c` (tail-jump into
the reload chain). Confirmed **not** to arm motion: `FUN_00006b50` writes
motion-profile arrays with no other reader anywhere in the image (dead,
same pattern as the ADC baseline), and it explicitly **clears**
`0x20002318[channel]` and `0x20002014[channel]` rather than setting
them. It also writes `0x2000310c[channel]=1` and
`0x20002524[channel]=1` for channels with a valid stored program — see
"Falsification pass," above, for the full trace of those two cells to
their real (non-motion) consumers; the version of this sentence claiming
`0x2000310c`'s only other reader is `motor_move_commit__CUSTOM` was
incorrect (a downstream effect of a `xrefs` blind spot on that address)
and is corrected here. Concretely confirmed via
a real `'+'`-push predecessor state (not fabricated): PB05 LOW reaches
`0x8f98` (288 real memory writes, real PB30/PB31 GPIO pulse); PB05 HIGH
(identical predecessor) touches none of the watched state; a labeled,
non-PB05 control that force-arms `0x20002318` **does** reach
`motor_move_commit__CUSTOM` two calls later, proving the missing
ingredient is the actual blocker, not a harness limitation.

**T-status has no return path.** The Remote's `'T'` branch
(`0x10f0a`-`0x10f32`) parses both fields and a received flag into
`0x200002e8`/`0x200027f8`/`0x200027f9`, with **no** call to any send
function anywhere in the branch (disassembly-complete). The only
consumer of all three cells anywhere in the image is `FUN_0000fa10`, a
UI screen's render loop, which scales the first field (`*3300/1023`) and
redraws it in a color chosen by the second — a pure display readout.
Concretely confirmed by delivering both real frame shapes
(`"T1023,0,|"`, `"T0,1,|"`) into the Remote's real inbound ring buffer
and watching its TX wrapper (`0x58a8`) never fire.

**Threshold band and its RAM cells.** Default `[lower=0x200000c0,
upper=0x200000a8]` = `[200, 580]` (raw ADC1.RESULT, 10-bit-ish scale),
selected via `*0x20000194` (0=custom, 1=preset A [200,580], 2=preset B
[250,750]) defaulting to preset A because the persisted config blob is
blank and `config_read_byte__CUSTOM`'s out-of-range handling resolves the
selector to `1`. **CONFIRMED** by disassembly and reproduced concretely
(seeding no threshold at all yields exactly 580/200 from the real preset
code).

**`0x20000014` (filter smoothing coefficient)**: cold `.bss`, exactly one
reference in the whole image (a read inside `FUN_000042a4`), no writer
anywhere — permanently `0.0f`. **`0x20003118` (one-shot latch)**: exactly
two references, both self-contained inside `FUN_000042a4` (one read, one
write-only-to-`1`), never cleared. Both **CONFIRMED** by exhaustive
cross-reference. The boot-then-runtime latch was confirmed end-to-end by
chaining a real boot run (first sample forced to `77`, a floating-pin-
like reading) into a real runtime poll (`ADC1.RESULT` forced to `4095`,
full-scale, obviously out-of-band): the live-value cell (`0x20000190`)
still reads `77` — the runtime injection has zero effect.

**Fault-injection matrices** (`tools/unicorn/trigger_transient_
propagation.py`), all **CONFIRMED concretely**:

- *Digital arm*, accept-gate counting vs. sequence (H=HIGH, L=LOW):
  `H L H`→1 accept, `H L L H`→2, `H L H L H`→2, `H L L L H`→3, `L L L L`→4
  — accepts equal the LOW-poll count exactly, no rate limit on this gate.
  T-status sends: exactly 1 per sequence if the rate-limit window is open
  at sequence start ("startup" context), 0 if it was already spent
  ("runtime" context) — regardless of how many transitions occur inside
  one window.
- *Analog arm*, "burst" (single window) vs. "sustained" (gate forced
  open every poll) conditions produce **byte-identical** results for
  every tested stream (steady, single spike, several spikes, alternating
  extremes, settling ramp) — direct confirmation that only poll 0's own
  raw sample determines the outcome for the entire session; later
  samples, however wild, change nothing.
- *Dead ADC baseline* (`FUN_00005d44`), reconfirmed under five
  adversarial streams: only the two already-known dead cells
  (`0x20003128` average, `0x200023c0` low-baseline flag) ever change;
  no third cell, no new consumer, under any tested shape.

**Peripheral rule-outs**, all this cluster's own fresh evidence unless
noted: **EIC** — inert (above), inherited unchanged. **EVSYS** — a raw
whole-image literal scan for its base address (`0x4100E000`) finds
**zero** occurrences anywhere in the 70,768-byte image. **AC** (analog
comparator) — exactly one reference to its base (`0x42002000`), inside
the already-documented one-time boot clock/analog-block bring-up, absent
from every trigger-cell RAM cross-reference. **DAC** — touched
unconditionally, in program order strictly *before* `RESULT` is ever
read, so its configuration cannot depend on PB05's value; no output
channel is data-dependent on the trigger state. **DMA** — six references,
all inside one generic, unrelated channel-dispatch driver, absent from
every trigger-cell cross-reference; no descriptor touches `ADC1.RESULT`
or any trigger RAM cell. **Timer capture (TC/TCC)** — already exhaustively
mapped elsewhere to other pins (TC0→PB10, TC1→PA08, TC2→PB12, TC3→PA10,
TCC1→PB22), none PB05; `pinMode()`'s own body never writes `PMUX` on the
digital-input configuration path, independently confirming no peripheral
mux is engaged. **Direct/inline PORT access** — every PB05 touch goes
through the shared, pin-descriptor-table-driven `digitalRead`/`pinMode`/
`analogRead` functions; `pinPeripheral()` (the only function that writes
`PMUX`) has 7 call sites total, 4 of which are generic driver helpers not
traced to confirm they never pass PB05's index (named in Open/unknowns).

## Mitigation design

Six candidates were evaluated against the confirmed trigger semantics
(level-sensitive, active-LOW at the accept gate, no debounce, no latch,
repeat-refire while held, unreachable until `MC4` unlocks the state
machine):

- **A — Startup arming** (require PB05 seen HIGH once after MC4-unlock
  before ever accepting LOW): weak alone — only protects the one window
  right after unlock, and conflicts with the user guide's own documented
  "connect the trigger before power-up" workflow. Retained only as a
  possible supplementary layer.
- **B — Consecutive-sample debounce** (require PB05 LOW for *N*
  consecutive polls before accepting): **the recommended candidate**.
  General — protects boot-time *and* mid-session connection events — needs
  no real-time clock (a plain poll counter, since this gate's own poll
  cadence is untethered from the ~500-tick T-status throttle and runs
  every main-loop iteration), and uniquely preserves the confirmed
  repeat-refire-while-held behavior exactly: once qualified, every
  subsequent LOW poll still accepts, unchanged from today.
- **C — Edge qualification** (accept only on HIGH→LOW transition):
  rejected — removes the confirmed repeat-refire behavior (an unforced
  change) and can be *worse* on a bouncy line, since a bare edge check
  accepts every transition in a bounce rather than filtering it.
- **D — Dwell/re-arm state machine** (full `WAIT_INACTIVE → ARMED →
  CANDIDATE_ACTIVE → ACCEPTED → WAIT_RELEASE`): strictly more capable
  than B (also suppresses refire-while-held) but more state and code;
  rejected as primary since nothing in the firmware's design or the
  reported bug requires suppressing refire-while-held.
- **E — Fixed startup delay**: rejected — doesn't address a connection
  made later in the session, and this gate isn't even reachable until
  `MC4` unlock, so "after boot" doesn't align with when the code first runs.
- **F — One-shot suppression of the first trigger**: rejected —
  confirmed unsafe against the user guide's own documented "trigger
  connected before power-up" workflow, which relies on that first
  trigger being legitimate.

**Patch site.** The narrowest safe rejection point is the 4-byte
`beq.w 0x8f98` at `0x922e` — after the real `digitalRead(0x39)` call
(so the mitigation still observes the real pin) but before `0x8f98`'s own
first RAM write (the earliest irreversible action on the accept path).
Replacing it in place with a same-size `b.w <cave>` requires no shift of
anything else in the image (the 48-byte gate and the literal pool /
next function immediately after it have zero slack). Registers `r2`/`r3`
are free to clobber (confirmed dead at both landing points, `0x9232`
reject and `0x8f98` accept); `r0` (the real `digitalRead` result) must be
read, not destroyed before use; no stack push/pop needed.

**No verified real flash code cave was found.** Three candidate classes
were checked and rejected: (1) the ~12KB zero-looking region at flash
`0x1113f`-`0x14000` is not free — it's the persisted, flash-backed
motor-target config blob (`0x12000`, currently blank but live NVM); (2)
an 18-byte gap at `0x401a` is inside the vector table, a reserved slot,
not code space; (3) three 12-13 byte zero runs (`0x48d8`, `0x4ab8`,
`0x7238`) are all the same pattern — a function's own alignment pad plus
its literal pool, compiler-emitted data, not slack. The most promising
unexplored option — flash beyond the current 70,768-byte image's end, up
to the part's real 512KB — was not verified this cluster (would need a
real device flash dump or bootloader documentation).

**The Unicorn-prototyped trampoline** (`tools/unicorn/trigger_
mitigation_prototype.py`) lives only at a harness-only scratch address
(`0x00020000`), not a real flash location. 34 bytes of Thumb-2, using
`movw`/`movt` for the counter's RAM address (avoiding any literal-pool
placement concern): re-checks `cmp r0,#0`, increments/resets a one-byte
poll counter reusing already-dead RAM (`0x20001fc4`, confirmed
unconditionally zeroed at boot and unread elsewhere on this exact arm),
and branches directly to the firmware's own real `0x8f98` (accept) or
`0x9232` (reject) — no synthetic return point needed. Every instruction
was hand-encoded from the ARMv7-M reference manual and verified two ways:
a capstone disassembly round-trip, and empirical execution landing on
the intended PC in every regression run.

**9-scenario regression matrix** (threshold *N*=4 polls, poll-count not
milliseconds — the real main-loop period is unmeasured): inactive
throughout (never accepts); active throughout (accepts at poll 3, the
4th consecutive LOW); a 1-poll startup transient then inactive (never
accepts — nuisance correctly rejected); a 1-poll runtime transient
(never accepts); a 3-poll transient, shorter than N (never accepts); a
5-poll clean trigger (accepts, continues accepting); **a rejected 1-poll
blip followed by a later 5-poll sustained trigger — accepts normally**
(the single most important case: a nuisance transient does not poison a
subsequent real trigger); held-active for 8 polls (accepts at poll 3,
continues accepting every poll after — repeat-refire preserved exactly);
release-then-second-trigger (first accepts at poll 3, counter resets on
release, second accepts at poll 9). All nine **PROTOTYPE**-tier (real
Unicorn execution of an in-memory candidate patch) — none is a claim
about the real firmware or hardware.

**No firmware has been patched or flashed.** Every patch above exists
only inside an in-memory `ConcreteMachine` (Unicorn) copy of the image.
This is a validated design, not a deployed fix, and no distributable
image has been produced.

## Test / repro

- **`tools/unicorn/trigger_transient_propagation.py`** — the digital and
  analog fault-injection matrices (bounce/spike/ramp streams against
  both arms), the dead-ADC-baseline reconfirmation under adversarial
  input, and the boot-then-runtime latch chain for the analog arm's
  first-sample-only behavior. Run with `--only digital` / `--only
  adc-live` / `--only adc-dead` / `--only all`.
- **`tools/unicorn/trigger_mitigation_prototype.py`** — the Candidate B
  debounce trampoline, hand-encoded and capstone-verified, exercised
  against the 9-scenario regression matrix above. Run with
  `--threshold N` (a free experiment parameter, not a claimed real-world
  value).
- **`tools/unicorn/virtual_link.py pb05`** — delivers a real `'+'`
  bulk-push (establishing gate 1 for real) then forces PB05 LOW/HIGH,
  confirming the reload fires and never reaches
  `motor_move_commit__CUSTOM`, plus a labeled control that does reach it
  when the arm byte is force-set.
- **`tools/unicorn/trigger_device_state_closure.py`** — the
  falsification pass's own script: reuses the pb05 scenario's real
  predecessor state, then runs `FUN_00005fac` (4 simulated main-loop
  ticks) and `channel_event_monitor__CUSTOM` from the real post-reload
  `0x20002524`/`0x2000310c` state, watching for any reach into
  `motor_move_commit__CUSTOM`, `FUN_00004d18`, or the shared
  `digitalWrite` helper. Run with no arguments.
- **`tools/unicorn/virtual_link.py t-status`** — delivers both real
  T-status frame shapes into the Remote's real inbound ring buffer and
  confirms its TX wrapper is never reached.
- **`aptrace explore` / `aptrace trigger`** (Crucible/What4/Z3 harness,
  `src/APTrace/ProtocolHarness.hs`'s `runGateReachability` and
  `SymbolicRunner.hs`'s `bqExcludeObserved`) — the solver-confirmed
  seven-guard cross-check (Queries A/B/C) described in Evidence.
- **`ConcreteMachine` direct entry at `0x8e18`** — the sound,
  zero-fabricated-register entry point for
  `phase_ramp_state_machine__CUSTOM` used by every concrete result above.

## Open / physical unknowns

- The real transient shape at the jack and at PB05 — polarity, duration,
  bounce count, floating behavior, boot-only vs. runtime-insertion.
- The real main-loop period, needed to translate any poll-count
  threshold (the debounce's *N*) into real milliseconds.
- The minimum legitimate trigger pulse width (bounds how large *N* can
  safely be without rejecting a real short trigger).
- Whether the analog boot-mode (PA02 HIGH at boot) is a real, commonly
  used field configuration or a vestigial/rare one — this bears directly
  on how much the boot-latch behavior matters in practice.
- Whether any of `pinPeripheral()`'s 4 generic-driver call sites ever
  passes PB05's own pin index (bounded, not exhaustively chased).
- The sensitivity-selector protocol command's exact wire identity (the
  `ascii_dispatcher__CUSTOM` writer of `0x20000194` at `0x892a`/`0x892e`).
- The debug-log sink for the `"TRIGGER: <val>"` line (likely USB-serial,
  not traced to its final destination).
- Whether, and when, to actually flash a mitigation — contingent on the
  physical measurements above, since the debounce threshold *N* cannot
  be called correct, only possible, without them.
- Smaller named-not-chased items inherited from this cluster: the two
  other readers of the shared status byte (`0x200025bc+1`, at `0x7a50`/
  `0x81f8`); the exact wire bytes for the `'W'`-family sub-case that
  reaches the real arm-byte producer (`0x865a`) and the sibling `'W1'`
  route into the same reload chain (`0x8624`); the other writer of
  `0x20002014` (`0x80ec`, a config-invalidation path); PA22/PB30/PB31's
  roles beyond their confirmed GPIO side effects.
