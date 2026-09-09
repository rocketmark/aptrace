# Investigation: The AutoPilot Trigger-Input Concrete Path

**Question**: trace the 3.5mm TRS trigger input from MCU-visible pin/state
through configuration, read path, edge/debounce logic, the earliest
unambiguous "trigger accepted" event, and any downstream consequence —
without assuming EIC — and use that to explain (or bound) a reported bug:
*"connecting a certain chain to the trigger input causes exactly one
trigger, then normal operation continues."*

**Scope**: static disassembly against the persistent `autopilot868` Ghidra
cache, cross-checked by raw whole-image byte/literal scans, plus targeted
`ConcreteMachine` execution for the boot-time half of the path. No fresh
Ghidra project, no full from-scratch boot reconstruction (see "What this
slice did not do"). This is explicitly a scoping/closing-in slice for a
later Macaw/Crucible/What4/Z3 pass, not that pass itself.

**Update (follow-up slice, same date)**: the runtime PB05 poll is now
reproduced **concretely**, entering at `phase_ramp_state_machine__
CUSTOM`'s own real function start (`0x8e18`) rather than mid-function —
no fabricated `r4`-`r11` needed, since a backward trace found they are
all established by the function's own real prologue and real control
flow. The second `digitalRead(PB05)` path (`0x9226`/`0x8f98`) is also now
closed: it reaches a real motor-config reload, gated behind a
newly-found, protocol-settable enable byte. See "Part 8" and "Part 9"
below, and the confidence table's updated rows.

## Result, in one paragraph

**EIC is proven, not assumed, to be uninvolved.** The trigger input is
read by plain, polled `digitalRead()` on two physical pins — **PA02**
(pin-descriptor index `0x25`) and **PB05** (index `0x39`, also aliased as
analog channel index `0x3b`) — both identified by decoding the real
Arduino-core pin-descriptor table directly from the firmware image, the
same table `FUN_0000d3dc`/`FUN_0000d300` (the real `digitalRead()`/
`pinMode()`) already use elsewhere in this project. **PA02 is sampled
exactly once, at boot**, inside `FUN_00006968` (this project's own
"startup reference/input routine"): configured `INPUT_PULLUP` and read;
the result seeds a mode flag (`0x20001fc0`, already known from
`mt-quick-setup-trigger.md` as the `MT` frame's 5th field) with `1` (PA02
read high) or `2` (PA02 read low) — concretely confirmed both ways.
**Only in the `2` (PA02-low) case does the firmware explicitly configure
PB05 as a plain digital `INPUT`** (mode `0`, no pull — concretely
confirmed: `r1=0` at the real `pinMode` call, `PORTB.PINCFG[5]=0x2`,
`PORTB.DIR` bit 5 clear). In the `1` case, the firmware instead runs a
128-sample ADC baseline-averaging routine (`FUN_00005d44`) over the same
physical PB05 pin (via its ADC-channel alias) — matching the user
manual's documented "establish a noise baseline" behavior structurally —
**but this averaged baseline is never read by any other code in the
image** (exhaustive xref check): a real, disassembly-confirmed dead end,
the same class of finding as this project's other "computed but never
consumed" results. **The one live, runtime consumer of the trigger
signal** is a `digitalRead(PB05)`-gated branch inside the AutoPilot's
motor-phase/ramp/monitor state machine (`phase_ramp_state_machine__
CUSTOM`, `FUN_00008e18` — already known to be reachable only after `MC4`
unlocks it), rate-limited to once per ~500 firmware ticks, which builds
and sends a **previously undocumented outbound frame, `"T<0 or 1023>,
<1 or 0>,|"`**, through the AutoPilot's real, already-proven TX wrapper
(`0x8c10`) — every ~500 ticks, regardless of the pin's value, with the
first field differing only by whether PB05 read high or low that cycle.
This is a **level-sampled, not edge-latched, poll** — there is no
debounce, no interrupt, no state carried between polls beyond a rolling
sequence counter. **This directly explains a self-correcting one-shot
symptom without any further mechanism needed**: a transient level on a
floating (no-pull) input, sampled during exactly one ~500-tick window,
produces exactly one "high" reading of this frame and then reverts on
the very next independent poll — see "The self-correcting one-shot
explanation" below.

## Confidence scale

Same as this project's other investigations: **CONFIRMED** (disassembly
and/or concrete) / **PROBABLE** / **UNKNOWN**.

---

## Part 1 — Ruling out EIC, exhaustively

The AutoPilot's vector table (flash `0x4000`+, entries 28-43) has the
identical structure this project already found on the Remote: 16
six-byte stubs (`movs r0,#N; b.w 0xcb6c`), one per EIC line, all
tail-jumping into one shared handler (`0xcb6c`). Disassembling that
handler in full:

```c
// FUN_0000cbb0 @ 0xcb6c (shared EIC dispatch, standard Arduino/ASF idiom)
for (line = 0; line < *count; line++) {           // *count @ 0x200052e4
    if (mask[line] & EIC.INTFLAG) {                // mask[] @ 0x200052a0
        callback_table[line]();                     // @ 0x2000525c
        EIC.INTFLAG = mask[line];                    // write-1-to-clear
    }
}
```

This is a real, generic dispatcher — but **an exhaustive whole-image raw
32-bit literal scan for each of its three support addresses
(`0x2000525c` the callback table, `0x200052e4` the line count,
`0x200052a0` the per-line mask) finds exactly one occurrence of each,
inside this handler itself**:

```
0x2000525c (callback table) -> [0xcbac]  (one hit, the handler's own load)
0x200052e4 (line count)     -> [0xcba4]  (one hit, the handler's own load)
0x200052a0 (per-line mask)  -> [0xcba0]  (one hit, the handler's own load)
```

**Nothing anywhere in this firmware image ever writes the line count or
the callback table** — the standard Arduino `attachInterrupt()`
machinery is compiled in (it always is, as part of the core) but this
application never calls it. With `*count` cold-zero, the handler's own
first comparison (`line(0) < count(0)`? false) means the loop body never
executes for any line, on any real EIC interrupt, ever.

A second raw scan, for the EIC peripheral base address itself
(`0x40002800`), found two further occurrences beyond the handler
(`0xa038`, `0xa058`) — both inside a small critical-section helper
(`FUN_0000a000`, called from `radio_reg_readwrite__THIRD_PARTY`, the
already-known SX127x-shaped LoRa driver cluster) that conditionally
saves/restores one bit of `EIC.CONFIG` around an SPI transaction — a
real, but structurally unrelated, radio-driver interrupt-masking idiom,
not a trigger-input registration.

**Conclusion: EIC is present, wired, and inert for this application.
The trigger input is not interrupt-driven — it is polled.** This is
proven by two independent whole-image scans (xref-cache-based and raw
byte-based), not inferred from absence of evidence.

---

## Part 2 — Identifying the physical pins

`FUN_0000d3dc` (`digitalRead`) and `FUN_0000d300` (`pinMode`) both index
the same real pin-descriptor table (`0x00014284`, stride `0x18` = 24
bytes/entry — `{port:u8, bit:u32, valid:u8, ...}`, `valid==0xFF` meaning
"no such pin"), confirmed by direct disassembly of both:

```c
// FUN_0000d3dc(pin) -- real digitalRead()
entry = table[pin];
if (entry.valid != 0xFF)
    return (PORT.Group[entry.port].IN >> entry.bit) & 1;
return 0;

// FUN_0000d300(pin, mode) -- real pinMode(); mode 0=INPUT, 1=OUTPUT,
// 2=INPUT_PULLUP, 3=INPUT_PULLDOWN (all four confirmed by their real
// DIR/DIRSET/DIRCLR/OUTSET/OUTCLR/PINCFG register effects)
```

Reading the raw table bytes directly from the firmware image (no Ghidra
needed for this step) for every pin-index literal this project has found
passed to either function:

| Pin index | Port | Bit | Physical pin | Already known as |
|---|---|---|---|---|
| `0x01` | 0 (PORTA) | 22 | **PA22** | the already-disclosed NVM-save-hold signal (`d-command-persistence-roundtrip.md`) |
| `0x25` | 0 (PORTA) | 2 | **PA02** | new this slice |
| `0x39` | 1 (PORTB) | 5 | **PB05** | new this slice |
| `0x3b` | 1 (PORTB) | 5 | **PB05** (same pin, analog-channel alias) | new this slice |
| `0x31` | 1 (PORTB) | 30 | PB30 | configured (`OUTPUT`) alongside PB05/PA22 in the same boot routine, role not chased this slice |
| `0x32` | 1 (PORTB) | 31 | PB31 | same |

An exhaustive whole-image `digitalRead()` call-site enumeration (10 real
call sites total, found via the cached call-graph — the same method used
for every other exhaustive-sender search in this project) shows **pin
index `0x25` (PA02) is read in exactly one place in the entire image**,
and **pin index `0x39` (PB05) in exactly two places**, both inside the
same function. No other pin indices anywhere near this range are read.

---

## Part 3 — The boot-time path: `FUN_00006968`

`FUN_00006968` (already named in this project's own terminology
discipline as the real "startup reference/input routine," not "homing" —
unchanged, and this slice's findings live entirely *inside* that same
function, not a separate one) is called exactly once, from
`sketch_setup__CUSTOM` (`FUN_00009464`, at `0x9488`), before that same
function's own `FUN_00005d44` call (`0x949c`) — confirmed ordering, not
assumed.

Disassembled entry sequence:

```
pinMode(0x25 /* PA02 */, 2 /* INPUT_PULLUP */)
r0 = digitalRead(0x25)
if (r0 != 0) {                 // PA02 reads HIGH
    *0x20001fc0 = 1
    pinMode(1 /* PA22 */, 3 /* INPUT_PULLDOWN */)
    ...                        // PB05 pinMode NOT reached on this arm
} else {                       // PA02 reads LOW
    *0x20001fc0 = 2
    pinMode(0x39 /* PB05 */, 0 /* INPUT, no pull */)   // <-- concretely confirmed below
    goto <shared tail: pinMode(PA22,3), delay, ...>
}
```

### Concrete confirmation (`ConcreteMachine`, entering directly at `0x6968`)

Two runs, differing only in the disclosed, harness-external input — the
electrical level Unicorn's `PORT.GROUP0.IN` (`0x41008020`) bit 2 presents
at the moment of the real `digitalRead(0x25)` call (matrix items
"inactive/active through startup" for PA02):

```
PA02 = HIGH (bit 2 set):  *0x20001fc0 becomes 1   (real write observed)
PA02 = LOW  (bit 2 clear): *0x20001fc0 becomes 2   (real write observed)
    -> at the real pinMode(PB05, ...) call site (0x69d2), r1 = 0
       (concretely resolved, not assumed -- r1 is not set between the
       branch and this call, so its value could not be read off the
       disassembly alone)
    -> after the call: PORTB.PINCFG[5] = 0x2 (INEN only), PORTB.DIR
       bit 5 clear -- confirms real INPUT configuration, no pull
```

No fabricated packet/register content beyond the one disclosed PA02
electrical level; every other value (the mode-0 argument, the resulting
PINCFG/DIR bits) is the real, unmodified firmware's own output.

**This closes the "connect before vs. after power-up" half of the
manual's documented behavior at the mechanism level**: PA02's boot-time
level is a real, one-shot, hardware-sampled decision point that
determines whether PB05 gets explicitly reconfigured as a bare digital
input before the runtime poll (Part 5) ever starts consuming it. Whether
PA02 is physically wired to "cable present at boot" (matching the
manual's framing) or something else was not verified against a schematic
— stated as inference from behavior, not asserted as a hardware fact.

---

## Part 4 — The dead-end ADC baseline path: `FUN_00005d44`

Called once, from `sketch_setup__CUSTOM`, immediately after
`FUN_00006968`. Structurally matches the manual's own predicted shape
("sample trigger input / baseline -> establish threshold"):

```c
void FUN_00005d44(void) {
    ...                              // real init/delay sequence
    *0x20002098 = 0; *0x2000313c = 0; *0x20001fc4 = 0;   // clear state
    if (*0x20001fc0 != 2) {          // only when PA02 read HIGH at boot
        sum = 0;
        for (i = 0; i < 128; i++)
            sum += analogRead(PB05);          // FUN_000042a4 -> FUN_0000d1b4(0x3b)
        avg = (sum < 0) ? (sum + 127) >> 7 : sum >> 7;
        *0x20003128 = avg;                     // the "baseline"
        if (sum < 0xaf00 /* 44800 */)
            *0x200023c0 = -100;                // a "low baseline" flag
    }
}
```

`FUN_000042a4` is a real, rate-limited (`millis()`-gated, ~500-tick
period), exponentially-smoothed `analogRead()` wrapper — genuine ADC
sampling code, not a stub. **An exhaustive xref check of every RAM
address this routine writes (`0x20002098`, `0x2000313c`, `0x20001fc4`,
`0x20003128`, `0x200023c0`) finds no reader anywhere else in the
image.** This is a real, compiled, structurally-correct baseline
calibration that computes a real average and a real low-baseline flag,
and then the result is never consulted by anything — the same
"computed, never consumed" pattern this project has repeatedly found
elsewhere (the blank `0x12000` motor-target default, `posA`/`posB`).
**This is not the live trigger-detection path** — it is a real but
disconnected piece of the sensing design.

---

## Part 5 — The runtime path: the `phase_ramp_state_machine__CUSTOM` poll

This is the one live, exercised consumer of the trigger pin. Located at
`0x9160`-`0x9244`, confirmed by the Ghidra cache's own `containing` query
to be part of `FUN_00008e18` (`phase_ramp_state_machine__CUSTOM`) — the
**already-known-and-gated** motor-phase/ramp/monitor subsystem this
project has established, independently, is **not reachable from a cold
boot without `MC4` having already run** (`g-command-motor-subsystem-
unlock.md`, `mc4-transition.md`). This inherited precondition is not
re-derived here.

Disassembled structure:

```c
// Reached after the per-channel ramp loop (0x8e26-0x8e66) completes --
// see Part 9 for why this happens on essentially every real call, not
// just a special case.
if (*0x20003120 != 0) {          // TR-reporting enable byte -- CLOSED, Part 9
    now = millis();                                    // 0x200052ec
    if (now - *0x20002410 >= 500) {                     // rate limit / "debounce"
        *0x20002410 = now;
        buf[0] = 'T';                                    // 0x20002548 = buf base
        *0x200025ac = 1;                                  // sequence/index reset
        if (digitalRead(0x39 /* PB05 */) != 0) {
            append_decimal(buf, 1023);   // "1023,"        via FUN_00004644
            append_decimal(buf, 0);      // "0,"
        } else {
            append_decimal(buf, 0);      // "0,"
            append_decimal(buf, 1);      // "1,"
        }
        buf[...] = '|'; buf[...+1] = 0;
        send(buf);                        // real TX wrapper, 0x8c10 (already
                                           // proven -- the same one &|->V01R39
                                           // and every other AutoPilot->Remote
                                           // response in this project uses)
    }
}
// ... separately, later in the same case: a second digitalRead(0x39),
// gated behind a distinct condition (see "Remaining bounded unknowns")
```

**A previously undocumented outbound frame, `"T<field1>,<field2>,|"`**
(not in `command-inventory.md` before this slice), sent AutoPilot ->
Remote every ~500 ticks once this subsystem is unlocked, with exactly
two observed shapes: `"T1023,0,|"` (PB05 read high that cycle) and
`"T0,1,|"` (PB05 read low that cycle). The `1023` (`0x3FF`, a 10-bit
full-scale value) alongside a plain digital read is consistent with — but
not proven to be — a leftover/placeholder sentinel from the analog
sensing design in Part 4, reused here as "active" once the mechanism was
simplified to a digital read; this is **inferred, not confirmed**.

**Crucially: this is a level-sampled poll, not an edge-latched or
debounced one.** There is no state carried between one ~500-tick check
and the next besides the rolling append-buffer index and the timestamp
itself — no "was it already high last time," no minimum-hold-time logic,
no interrupt. Each check is fully independent.

---

## The self-correcting one-shot explanation

This directly answers the task's specific ask ("look for a condition
that produces one trigger and then self-corrects") **without requiring
any further mechanism**:

1. PB05 is configured as a bare digital `INPUT` with **no internal
   pull** (Part 3) — its logic level floats unless something external
   drives it.
2. The only runtime consumer samples it **once every ~500 ticks**, with
   no memory of prior reads (Part 5).
3. **Physically connecting a chain to the trigger jack is itself a
   transient electrical event** (contact bounce, cable-insertion
   coupling, a brief partial connection as the plug seats) on a pin with
   no pull to hold it steady beforehand.
4. If that transient happens to overlap the instant of one ~500-tick
   poll, `digitalRead(PB05)` reads whatever the transient produced —
   **exactly one** `"T1023,0,|"` (or `"T0,1,|"`, depending on the
   transient's polarity) frame is sent for that one cycle.
5. On the **very next independent poll**, ~500 ticks later, the
   connection has settled to its real steady-state level, and the
   opposite (or simply unchanged) frame shape is sent from then on —
   **"normal operation continues"** is not a special recovery path, it
   is just the next ordinary poll of a mechanism with no memory.

This is a **PROBABLE**, not yet concretely reproduced end-to-end,
explanation — see "What this slice did not do" for exactly what would
promote it to CONFIRMED, and note it assumes the reported "trigger"
*is* this `"T..."` frame (or whatever downstream Remote-side behavior
consumes it) rather than some other consequence this slice didn't find.
The mechanism itself (level-sampled, no-pull, periodically-polled,
independent-per-cycle) is CONFIRMED by disassembly; its identification
as *the* explanation for the specific reported bug is the inferential
step that remains open.

---

## Part 6 — State inventory (what affects acceptance)

| State | Role | Source |
|---|---|---|
| `PORT.GROUP0.IN` bit 2 (PA02 electrical level) | Boot-time mode-select sample | **Harness/external** — real hardware signal, sampled once |
| `PORT.GROUP1.IN` bit 5 (PB05 electrical level) | Live trigger signal, sampled every poll | **Harness/external** |
| `*0x20001fc0` (mode flag, 1 or 2) | Set once at boot from PA02; gates PB05 pinMode and the ADC-calibration branch | **Firmware-produced**, boot-derived |
| `PORTB.PINCFG[5]` / `PORTB.DIR` bit 5 | PB05's real digital-input configuration | **Firmware-produced**, boot-time, only on the PA02-low arm |
| `*0x200052ec` (`millis()` tick variable) | Time source for the ~500-tick rate limit | **Firmware-produced** (SysTick-driven); this project's existing `--fake-tick 0x200052ec:N` mechanism applies directly |
| `*0x20002410` (last-check timestamp) | Rate-limit state, compared against `millis()` | **Firmware-produced** |
| `*0x200025ac` (append-buffer index) | Reset to 1 each poll before building the frame | **Firmware-produced**, transient per-poll |
| `*0x20003120` (TR-reporting enable byte) | Whether the poll sends a `"T..."` frame (nonzero) or instead falls into the four-way idle-state gate toward a config reload (zero) — **CLOSED this slice, Part 9**: set by the real `TR0\|`/`TR1\|` ASCII command | **Firmware-produced**, protocol-settable |
| `0x20002524[0..3]` (per-channel device-state/mode, all four must be `0`), `*0x20001b38` (must `==0x7b`), `*0x200000d8` (must `==9`) | The four-way idle-state gate before the second `digitalRead(PB05)` at `0x9226` | **Firmware-produced** — CLOSED this slice, Part 9; the latter two cells' own producers not traced further |
| `0x20000060` (the `MC4` unlock byte) | Whether `phase_ramp_state_machine__CUSTOM` runs *at all* | **Firmware-produced**, already fully characterized (`mc4-transition.md`) — inherited precondition |
| `0x20001fc4`, `0x20002098`, `0x2000313c`, `0x20003128`, `0x200023c0` | Dead-end ADC-baseline state (Part 4) | **Firmware-produced**, confirmed unconsumed |

No pending-interrupt state applies (EIC is inert — Part 1). No debounce
state applies (the poll is level-sampled with no history — Part 5).

---

## Part 7 — Concrete matrix: what was run, and the exact boundary of what wasn't

| Matrix item | Result |
|---|---|
| PA02 inactive through startup | **CONFIRMED concretely**: `*0x20001fc0` becomes `2`; PB05 configured `INPUT` mode 0 (`r1=0` at the real call, resolved concretely, not guessed) |
| PA02 active through startup | **CONFIRMED concretely**: `*0x20001fc0` becomes `1`; PB05's explicit reconfiguration is skipped on this arm (the ADC path runs instead) |
| PB05 inactive (poll) | **CONFIRMED concretely** (Part 9): real frame `"T0,1,\|"` |
| PB05 active (poll) | **CONFIRMED concretely** (Part 9): real frame `"T1023,0,\|"` |
| PB05 active for one allowed poll, then inactive | **CONFIRMED structurally + concretely per-cycle** (Part 9): each poll is independently reproduced above; since the mechanism carries no state between polls (disassembly-confirmed, Part 5), one high poll followed by one low poll is exactly the two runs above in sequence — no separate "transition" state exists to exercise |
| Repeated active polls | Same as above — each poll is independent; "repeated" produces the same `"T1023,0,\|"` every time, concretely confirmed once, not re-run redundantly |
| Active when trigger subsystem initializes / transition during-or-immediately-after init | Still not concretely exercised — this is a boot-sequencing question (does the very first post-`MC4` main-loop pass reach this poll before or after other one-time init) distinct from the poll mechanism itself, out of this slice's bounded scope |
| Pending EIC state with static input | **N/A — moot**: Part 1 proves EIC is never armed, so no pending-interrupt state can exist to test |

### How the sound entry point was found (resolves the prior slice's open gap)

Backward-tracing `phase_ramp_state_machine__CUSTOM` from its own real,
documented start (`0x8e18`) found that **`r4`, `r5`, `r8`, `r9` are all
freshly established in the function's own prologue** (`r5=[0x9108]=
0x20001b40`, the channel-struct base; `r8=[0x9168]=0x20002318`, the
per-channel mode-byte array; `r4=0`; `r9=r5`) — nothing here needs to be
guessed. The per-channel loop that follows (`0x8e26`-`0x8e66`) was then
traced instruction-by-instruction for **every** branch it can take
(mode `0`, `1`, `2`, `3`, and the `0x9090`/`0x909a` early-exit sub-case):
**every real branch funnels back to the loop's own increment (`0x8e5e`)
except one narrow combination** (`0x20002014[channel]==1` *and*
`0x20001b40[channel]+0x44 != 0`) that this slice did not fully resolve
(see "Remaining bounded unknowns") — under this project's standard
cold-RAM convention, and under the already-known fact that the busy gate
`0x20001b14[channel]` has no producer anywhere in the image
(`channel-busy-gate-search.md`), that narrow combination does not fire,
and **the loop completes all four channels naturally**, reaching the
trigger-poll region exactly as a real call would. **This means
`0x8e18` — the function's own real entry — is itself the smallest sound
entry point**: no mid-function register fabrication is needed at all,
resolving the prior slice's open question in the simplest possible way
(enter where the real function starts, not partway through it).

---

## Part 8 — The outer enable byte, closed: `TR0|`/`TR1|`

Backward-tracing the trigger-poll's own gate (`*0x20003120`, checked
identically by both the analog arm at `0x8eca` and the digital arm at
`0x919e`) found **exactly one writer anywhere in the image**:
`ascii_dispatcher__CUSTOM` (`FUN_00008258`), inside its real top-level
`'T'`→`'R'` branch:

```asm
0x84fa  cmp r3,#0x54 ('T')
0x84fc  bne 0x85d8
0x84fe  ldrb r3,[r4,#1]
0x8500  cmp r3,#0x52 ('R')
0x8502  bne 0x85a4
0x8504  ldrb r3,[r4,#2]        ; the digit after "TR"
0x8506  sub.w r2,r3,#0x31 ('1')
0x850a  rsbs r3,r2
0x850c  adcs r3,r2              ; normalizes to exactly 1 if digit=='1', else 0
0x850e  ldr r2,[0x859c]         ; = 0x20003120
0x8510  strb r3,[r2,#0x0]
```

**This is the already-known `TR0|`/`TR1|` command**
(`command-inventory.md`'s "Boolean family," Remote-side sender already
confirmed in `manual-mode-wire-provenance.md`) — its AutoPilot-side
effect was previously undocumented beyond "inline state change." It is
now closed: **`TR1|` sets `0x20003120=1` (arms trigger-status
reporting); `TR0|` sets it to `0` (disarms it, the default/cold-RAM
value)**. `command-inventory.md` is updated accordingly.

With the enable byte closed, the mechanism is now fully connected: an
already-proven, protocol-reachable command (`TR1|`) is the real
precondition for the `"T..."` frame ever being sent at all. This closes
one of the prior slice's two named open questions completely.

## Part 9 — Concrete confirmation of the runtime poll, and the second `digitalRead(PB05)` path closed

### The confirmed `"T..."` poll, reproduced concretely

Entering at the sound entry point (`0x8e18`) with `*0x20001fc0=2` (the
real, already-proven boot-time output when PA02 reads low),
`*0x20003120=1` (the real, already-proven `TR1|` effect above), the
rate-limit timestamp seeded so the real ~500-tick gate is satisfied, and
only the genuinely external `PORT.GROUP1.IN` bit 5 (PB05) varied:

```
PB05 = LOW  -> real frame sent to the real TX wrapper (0x8c10): b'T0,1,|'
PB05 = HIGH -> real frame sent to the real TX wrapper (0x8c10): b'T1023,0,|'
```

Both runs completed with **zero fabricated register state** — every
register the function's own real code uses along this path (`r4`-`r11`)
was established by real, executed instructions, not seeded. This
satisfies this slice's acceptance criterion directly: the confirmed poll
is now reproduced concretely, from a sound entry, with no `r4`-`r11`
fabrication.

### The second `digitalRead(PB05)` path (`0x9226`), closed

With `*0x20003120=0` (`TR0|`, the disarmed/default state), both the
analog and digital arms instead fall into a shared four-way idle-state
gate before reaching this point:

```
0x9202-0x9210: 0x20002524[0..3] (per-channel device-state/mode) all == 0
0x9212-0x9218: *0x20001b38 == 0x7b   ; producer not traced further
0x921a-0x9220: *0x200000d8 == 9      ; producer not traced further
0x9222-0x9224: *0x20003120 == 0      ; TR0, closed above
0x9226-0x922c: digitalRead(PB05) == 0 (LOW)   -> 0x8f98
                                        != 0 (HIGH) -> 0x9232 (ordinary return, no-op)
```

**Concretely confirmed** (seeding the two untraced cells to their
required values, `0x20001b38=0x7b` and `0x200000d8=9`, as disclosed test
values to reach and characterize this branch — not claimed as a
naturally-occurring state): the gate is satisfiable, and with PB05 LOW,
execution reaches `0x8f98`:

```asm
0x8f98  ldr r3,[0x9148]         ; = 0x200025bc
0x8f9a  movs r2,#3
0x8f9c  strb r2,[r3,#1]         ; *(0x200025bc+1) = 3  -- a status byte;
                                ; two other readers exist (0x7a50, 0x81f8,
                                ; both in other unattributed regions) --
                                ; not traced further this slice
0x8fa0  pop.w {r4-r11,lr}
0x8fa4  b.w 0x00006e4c          ; tail-jump, NOT a return
```

`0x6e4c` (inside `FUN_00006b50`) unconditionally clears one RAM word and
then calls **`config_loader__CUSTOM`** (`FUN_00004b64`, already fully
characterized in `target-config-provenance.md` as the bulk loader that
reads the persisted 4-channel motor-target/config struct, logical
offsets `500`-`1651`, from the flash-backed `0x12000` buffer) — **a real
config reload**, confirmed by concretely reaching its own real read loop
(`config_read_byte__CUSTOM`, offsets counting up from `500`) before
hitting the *same, already-documented* lazy-initialized-buffer boundary
`target-config-provenance.md` already found and named (not a new gap —
the crash address and call shape match that doc's own description
exactly).

**Answering this slice's Goal 3 directly**: this path is **not** another
status/control dead end, and it does **not** start or arm a new move —
it triggers a real **reload of the persisted motor-target configuration
from flash**, only reachable when trigger-status reporting is
*disarmed* (`TR0|`, the default) and the whole system is otherwise idle
(all four channels' device-state `0`). This is a plausible, concrete
contributor to "then normal operation continues": a stray low reading on
the trigger pin, in the default (unarmed) mode, causes the firmware to
re-load its known-good persisted config rather than commanding any new
motion — consistent with, and adding a second real mechanism to, the
already-documented self-correcting explanation. It does **not** explain
the reported bug's "trigger" framing as well as the `TR1|`-armed
`"T..."` frame does (this path fires on PB05 *low*, the opposite polarity
from the `"1023"`/"active" convention used in the status frame), so it
is best read as a related but distinct finding, not a replacement for
the Part "self-correcting one-shot" explanation.

### What's left for a genuine symbolic slice

With both the poll and the second-`digitalRead` path now concretely
closed, the remaining open question narrow enough to be worth a solver
is precisely named in
[`research/workflows/trigger-input.yaml`](../../research/workflows/trigger-input.yaml)
(updated this slice): whether the two untraced gate cells
(`0x20001b38`, `0x200000d8`) are ever naturally driven to `0x7b`/`9` by
real code elsewhere, or whether the `0x8f98` path is reachable only
under this slice's disclosed test values — a reachability question a
Crucible/What4/Z3 pass is well suited to answer once `config_loader__
CUSTOM`'s own lazy-init boundary (shared with `target-config-
provenance.md`) is modeled or stubbed.

## What this slice did not do

- Did not trace the two untraced gate cells' own producers
  (`0x20001b38`, `0x200000d8`) — used as disclosed test values to
  characterize `0x8f98`, not shown to be naturally reachable to those
  exact values by other real code.
- Did not resolve `0x200025bc`'s full role (two more readers found,
  `0x7a50`/`0x81f8`, both in other unattributed/tail-jumped regions) —
  named, not chased.
- Did not resolve the narrow per-channel loop combination
  (`0x20002014[channel]==1` and `0x20001b40[channel]+0x44 != 0`) that
  this slice's backward trace found is the *only* way to skip the
  trigger-poll region entirely — argued, from cold-RAM/known-busy-gate
  evidence, not to fire in practice, but not exhaustively disproven.
- Did not verify PA02/PB05's physical identity against a schematic — the
  pin assignment is confirmed against the compiled firmware image, not
  cross-checked with board-level documentation.
- Did not attempt a full `Reset_Handler`-to-main-loop boot reconstruction
  — the sound direct-entry approach (Part 9/10) made this unnecessary for
  the runtime poll; it would still be the natural way to exercise the
  lazy-init boundary `config_loader__CUSTOM` hits, if that ever becomes
  the next question.
- Did not chase pins `0x31`/`0x32` (PB30/PB31), configured alongside
  PA22/PB05 in the same boot routine — their role is unrelated to this
  slice's question as far as traced, but not characterized.

---

## Confidence table

| Item | Status |
|---|---|
| EIC is never armed anywhere in this firmware image | **CONFIRMED** (two independent exhaustive whole-image scans) |
| The trigger circuit is read via polled `digitalRead()`, on PA02 and PB05 | **CONFIRMED** (disassembly of the real pin-descriptor table, cross-checked by raw byte reads with zero Ghidra involvement) |
| PA02 is sampled exactly once, at boot, gating a mode flag and PB05's explicit configuration | **CONFIRMED** (disassembly + concrete, both PA02 outcomes) |
| The PB05 `pinMode` argument on the PA02-low arm is `0` (bare `INPUT`) | **CONFIRMED concretely** (register value at the real call site, plus the resulting PINCFG/DIR MMIO state) |
| The 128-sample ADC baseline routine is real but never consumed | **CONFIRMED** (exhaustive xref of every address it writes) |
| The runtime poll (`phase_ramp_state_machine__CUSTOM`) sends a real, previously-undocumented `"T<>,<>,\|"` frame via the proven TX wrapper, gated on PB05's live level and a ~500-tick rate limit | **CONFIRMED concretely** (reproduced end to end from the function's own sound entry point, `0x8e18`, with zero fabricated registers — both `"T0,1,\|"` and `"T1023,0,\|"` observed) |
| This poll only runs after `MC4` | **CONFIRMED**, inherited unchanged from `mc4-transition.md`/`g-command-motor-subsystem-unlock.md` |
| `0x8e18` (the function's own real entry) is a sound boundary requiring no `r4`-`r11` fabrication | **CONFIRMED** (exhaustive backward trace of every per-channel-loop branch; all funnel to real, freshly-loaded state) |
| The poll's level-sampled, no-history structure explains a self-correcting one-shot symptom in general | **CONFIRMED** structurally (disassembly) and now also concretely (each poll reproduced independently) |
| This mechanism is *the* explanation for the specific reported bug | **PROBABLE** — plausible and consistent, now concretely reproduced per-cycle; still not chained through a real multi-poll timeline |
| The outer enable byte gating the whole trigger-status feature (`0x20003120`) | **CONFIRMED**: set by the real `TR1\|`/`TR0\|` ASCII command (`0x8510`), a previously-undocumented AutoPilot-side effect of an already-known command |
| The second `digitalRead(0x39)`/`0x8f98` branch's real consequence | **CONFIRMED**: reloads the persisted motor-target config (`config_loader__CUSTOM`/`FUN_00004b64`) when trigger-status reporting is disarmed (`TR0\|`) and the system is otherwise idle; concretely reached to its own known lazy-init boundary (shared with `target-config-provenance.md`, not a new gap) |
| The two remaining gate cells' own producers (`0x20001b38`, `0x200000d8`) | **UNKNOWN** — precisely bounded, not chased; this slice used disclosed test values to reach and characterize `0x8f98`, not proof they arise naturally |
| PA02/PB05's physical identity as "the trigger jack" (vs. schematic-verified) | **PROBABLE** — strong behavioral fit, not hardware-verified |

## Evidence level

Level 1 (static, disassembly-confirmed, cross-checked by independent raw
byte scans) for the EIC negative result, the `TR0|`/`TR1|` effect, and
the full control-flow structure. Level 2 (concrete, Unicorn) for the
boot-time PA02/PB05 configuration matrix, the full runtime `"T..."` poll
(both PB05 states, from the sound entry point), and the `0x8f98`
config-reload path. No level-3 (solver-confirmed) claims — the remaining
narrow reachability question (do `0x20001b38`/`0x200000d8` naturally
reach `0x7b`/`9`) is what this slice hands off, bounded, to the next
one.
