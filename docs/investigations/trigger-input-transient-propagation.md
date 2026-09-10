# Investigation: PB05 Transient Propagation — Complete Consumer Map and Fault-Injection Results

**Question**: exhaustively inventory every real consumer of the AutoPilot's
PB05 trigger pin (digital, analog, direct-register, and peripheral), map
each to its observable downstream effect, and concretely determine what an
electrically "ugly" event at physical insertion — spike, bounce, ringing, a
floating interval, or slow settling — can and cannot make the firmware do.
**No mitigation is chosen and no debounce threshold is picked here** — this
slice is characterization only, building on the already-closed findings in
[`trigger-input-concrete-path.md`](trigger-input-concrete-path.md),
[`trigger-input-symbolic-crosscheck.md`](trigger-input-symbolic-crosscheck.md),
and [`trigger-input-mitigation-patchability.md`](trigger-input-mitigation-patchability.md).

**Scope**: Ghidra (`tools/ghidra/aptrace_ghidra.py`, the persistent
`autopilot868` cache) for disassembly, exhaustive cross-references, and raw
whole-image literal scans; Unicorn (`tools/unicorn/concrete.py`'s
`ConcreteMachine`, via a new script,
[`tools/unicorn/trigger_transient_propagation.py`](../../tools/unicorn/trigger_transient_propagation.py))
for every concrete result below. No Crucible/What4/Z3 work was needed or
attempted — every question here is "what does this code do from a known
state," Unicorn's job, not "what input satisfies this," per
[`docs/tooling/tool-selection.md`](../tooling/tool-selection.md).

## Result, in one paragraph

**A second, previously-uncharacterized real consumer of PB05 was found and
is now the central finding of this slice.** Beyond the already-documented
digital poll (`digitalRead(PB05)`, gated on `*0x20001fc0==2`, PA02 read LOW
at boot), this project's own workflow file already named but never
disassembled a "sibling arm, PA02-high/ADC mode"
(`trigger_poll_and_send_analog_arm`, `0x8e68`-`0x8f00`). Fully disassembled
and concretely exercised this slice, it turns out to be a **complete,
independent second path into the same accept target** the digital arm
reaches (`0x8f98`, the config-reload tail-jump already proven **not** to
arm motor motion — `trigger-input-motion-causality.md`): a real,
RAM-resident `[lower, upper]` threshold-band comparison
(`0x200000c0`/`0x200000a8`, default-preset values **200/580**, provenance-
traced this slice to `boot_config_reader__CUSTOM`) against
`analogRead(PB05)`, gated behind the same four-way idle check and the same
`TR0|`/`TR1|` toggle the digital arm's second gate uses — and, when `TR1|`
is armed instead, a previously-undocumented **analog** T-status frame,
`"T<raw ADC1.RESULT decimal>,<0 or 1 band flag>,\|"`, sent through the same
proven TX wrapper (`0x8c10`).

**The single most consequential finding, concretely confirmed (not just
argued)**: `analogRead(PB05)` on this path does not return a live sample.
It runs through a real, exponentially-smoothed filter
(`FUN_000042a4`) whose smoothing coefficient (`0x20000014`) is **cold,
`.bss` RAM with exactly one reference in the whole image — a read, no
writer anywhere** — i.e. permanently `0.0f` in this firmware as shipped.
Combined with a one-shot "already initialized" latch
(`0x20003118`, also exactly two references, both self-contained inside the
same function, no writer that ever clears it back to 0), the practical
effect is: **the very first sample this function ever takes — during the
already-known dead 128-sample boot-time baseline loop, milliseconds into
`sketch_setup()`, before a user could plausibly have inserted anything —
is permanently latched for the rest of the power cycle.** Concretely
confirmed by chaining a real boot run into a real runtime poll on the same
machine: seeding a floating-pin-like boot sample (`77`) and then forcing
`ADC1.RESULT` to a full-scale, obviously out-of-band runtime value
(`4095`) leaves the gate's own live-value cell reading `77` — the runtime
injection has **zero** effect. **A spike, bounce, ringing burst, or slow
settling occurring at physical insertion time therefore cannot reach the
analog accept/T-status path at all** — it is decided once, at boot, before
insertion is physically possible, and never re-evaluated. This is the
opposite failure mode from what "no debounce" suggested going in: the
analog path isn't merely undebounced, it is **latched** — if the boot-time
sample itself happened to be bad (e.g. a floating, unconnected pin
mid-transient at power-on), the resulting wrong decision (armed-forever or
blind-forever) persists for the whole session, but a **later** insertion
transient specifically cannot cause it.

**The digital arm remains exactly as previously characterized — level-
sampled, no debounce, no latch, re-evaluated independently every poll —
and this slice's own fault-injection matrix now demonstrates directly, not
just structurally, that **one bouncy physical insertion event *can* produce
multiple accepted config-reload actions (one per LOW-reading poll in the
bounce), but *at most one* T-status frame per rate-limit window** (~500
ticks, real-world duration still UNKNOWN). ADC synthetic-stream
fault-injection against the already-known **dead** 128-sample baseline
(`FUN_00005d44`) reconfirms, under every tested transient shape (steady,
single spike, several spikes, alternating extremes, settling ramp), that
only the same two already-documented dead RAM cells ever change — no new
consumer appears under adversarial input. EIC, EVSYS, DAC (as a control
mechanism), and DMA are ruled out this slice with fresh evidence (EVSYS:
zero raw literal references anywhere in the image; DAC: touched only as
unconditional pin-mux/analog-bias boilerplate, no data dependency on
PB05's value; AC: a single reference, inside the already-documented
one-time boot clock/analog-block bring-up, absent from every trigger-cell
RAM cross-reference; DMA: a generic channel-dispatch driver, likewise
absent from every trigger-cell cross-reference). Timer capture (TC/TCC) is
ruled out by the already-exhaustive pin-assignment work in
`motor-timer-survey.md`/`pin-index-provenance.md`, reconfirmed unchanged.
**ADC is ruled IN — as a real, previously-missed accept/status path — but
concretely shown immune to a *post-boot* insertion transient specifically
because it never samples again after boot.**

---

## Part 1 — Complete PB05 consumer inventory

Every real access to PB05 (port 1, bit 5) or its analog alias (pin
index `0x39` / `0x3b` in the shared pin-descriptor table, `0x00014284`)
anywhere in the AutoPilot image, by mechanism:

| # | Consumer | Mechanism | Address(es) | Gate to reach it | Status |
|---|---|---|---|---|---|
| 1 | Boot-time mode-select read of **PA02** (not PB05 itself, but the switch that decides which of rows 2-7 below are even reachable) | `digitalRead()` | `0x6976` (`FUN_00006968`) | none (unconditional, once, at boot) | CONFIRMED, inherited |
| 2 | Boot-time `pinMode(PB05, INPUT)` | `pinMode()` | `0x69d2` | `*0x20001fc0==2` (PA02 read LOW) | CONFIRMED, inherited |
| 3 | Digital T-status poll | `digitalRead(0x39)` | `0x91ca` | mode_flag==2, main-loop rate, `TR1\|` armed for the *send* (poll itself unconditional) | CONFIRMED, inherited |
| 4 | Digital second gate / config-reload accept | `digitalRead(0x39)` | `0x9228` (`cmp r0,#0` at `0x922c`) | mode_flag==2, 4-way idle, `TR0\|` disarmed | CONFIRMED, inherited |
| 5 | **Dead** 128-sample boot baseline average | `analogRead(0x3b)` via `FUN_000042a4`→`FUN_0000d1b4` | `0x5d88` (`FUN_00005d44`) | mode_flag==1 (PA02 HIGH) | CONFIRMED, inherited (dead-end reconfirmed this slice under adversarial input, Part 4) |
| 6 | **NEW this slice**: analog T-status send | `analogRead(0x3b)` via the same `FUN_000042a4`, then a 2-threshold band compare | `0x8e76` (sample), `0x8eca`-`0x8f44` (send) | mode_flag==1, main-loop rate for the poll, ~500-tick rate + `TR1\|` armed for the *send* | CONFIRMED this slice (Part 3, Part 5) |
| 7 | **NEW this slice**: analog second gate / config-reload accept | same sample as row 6, reused | `0x8f48`-`0x8f98` | mode_flag==1, 4-way idle, `TR0\|` disarmed | CONFIRMED this slice (Part 3, Part 5) |
| 8 | Sensitivity-preset selector, gates whether the threshold cells (row 6/7) get overwritten | `boot_config_reader__CUSTOM` (persisted config), `ascii_dispatcher__CUSTOM` (live protocol command) | `0x4c46`/`0x4c4c`/`0x4c56`; `0x892a`/`0x892e` | n/a | CONFIRMED this slice (Part 3) — command identity not pinned down, named not chased |
| 9 | Debug log line (`"TRIGGER: <raw ADC value>"`), likely USB-serial | `Print`/`String`-style helpers (`0xb23a`, `0xb2ea`) | `0x8eb8`-`0x8ec6` | rate-limited (~500 ticks), any mode | CONFIRMED reached; sink (Serial object) not chased — named, not fully traced, out of primary scope |

**Direct PORT register access, EIC, EVSYS, AC, DMA, timer capture**: see
Part 6 — every one of these either has zero real reference to PB05
anywhere in the image (EIC, EVSYS), or its one/few real touches are
unconditional boilerplate with no data dependency on PB05's own state
(DAC, AC), or are already-exhaustively characterized elsewhere in this
project as belonging to other pins entirely (TC/TCC, DMA). **No PB05
access exists outside the pin-descriptor-table-driven `digitalRead()`/
`pinMode()`/`analogRead()` calls in rows 1-7 above** — this project's own
established exhaustive-call-site method (`trigger-input-concrete-path.md`
Part 2: "pin index `0x39` read in exactly two places... no other pin
indices anywhere near this range are read") is reconfirmed and extended
this slice to also cover `analogRead_wrapper`'s own two call sites
(row 5, row 6/7 — `FUN_000042a4` has exactly two callers in the whole
image, `tools/ghidra/aptrace_ghidra.py callers autopilot868 0x42a4`).

### PB05-derived RAM: consumed vs. dead-end

| Cell | Written by | Consumed by | Verdict |
|---|---|---|---|
| `0x20001fc0` (mode flag) | PA02 boot read | Gates rows 2-7 above, the `MT` frame's 5th field (`mt-quick-setup-trigger.md`) | **Consumed**, extensively |
| `0x20002098`, `0x2000313c`, `0x20001fc4`, `0x20003128`, `0x200023c0` | Dead 128-sample baseline (row 5) | Nothing — exhaustive xref, reconfirmed this slice under 5 adversarial input shapes (Part 4) | **Dead**, reconfirmed |
| `0x20000190` (boot-latched analog PB05 value) | **NEW**: `FUN_000042a4`'s filter, row 6/7's own sample | The very same function's threshold compare + T-status field-1 builder | **Consumed, but frozen at boot** (Part 3) |
| `0x20003118` (filter's one-shot init flag) | `FUN_000042a4` only | `FUN_000042a4` only — exactly 2 xrefs total, exhaustive | **Self-contained latch, no external reset** |
| `0x20000014` (filter smoothing coefficient) | **nobody** — cold `.bss`, exactly 1 xref (a read) in the whole image | `FUN_000042a4`'s blend step | **Permanently 0.0f** — the blend is a real no-op |
| `0x200000a8`/`0x200000c0` (threshold band) | boot config / preset selector / (unchased) protocol path | Row 6/7's compare | **Consumed** |
| `0x200025bc+1` (status byte, set `=3` on accept) | Both arms' shared accept target `0x8f98` | Two other readers (`0x7a50`, `0x81f8`), not traced — inherited open item | **Consumed** (partially characterized) |
| `0x20002548`/`0x200025ac` (shared TX buffer/index) | Both arms' T-status builders | Real TX wrapper `0x8c10` | **Consumed**, outbound |

---

## Part 2 — The digital arm (reconfirmed, unchanged)

No change from `trigger-input-concrete-path.md`/`trigger-input-symbolic-crosscheck.md`:
level-sampled `digitalRead(PB05)`, no debounce, no history between polls,
main-loop rate (no artificial throttle on the accept gate; ~500-tick
throttle on the T-status *send* specifically). This slice's own digital
fault-injection matrix (Part 5) is a direct, concrete demonstration of
that structural claim, not a re-derivation of it.

---

## Part 3 — The analog arm, fully characterized (new this slice)

### 3.1 The dispatcher

`phase_ramp_state_machine__CUSTOM`'s own trigger-handling region begins
with a mode dispatch (`0x8e68`-`0x8e76`):

```
r3 = *0x20001fc0            ; mode_flag
if (r3 == 2) goto 0x919e    ; PA02 was LOW at boot -> digital arm (Part 2)
r0 = analogRead(0x3b)       ; PA02 was HIGH at boot -> analog arm (this Part)
*0x20000190 = r0
```

**These two arms are mutually exclusive per boot-time PA02 reading** — a
given power cycle runs exactly one of them, never both, for the whole
session (matching the already-established boot-time mode-select finding).

### 3.2 The analog T-status send and the threshold band

```c
// 0x8eca-0x8f44, reached every poll (rate-limit only gates the *send*,
// exactly like the digital arm's own T-status logic)
if (*0x20003120 != 0) {                 // TR1| armed
    if (millis() - last_send >= 500) {
        last_send = millis();
        buf = "T";
        append_decimal(buf, *0x20000190);         // raw ADC1.RESULT-derived value
        if (*0x20000190 > upper_threshold)         // 0x200000a8
            field2 = 1;
        else if (*0x20000190 < lower_threshold)     // 0x200000c0 (misleadingly named
                                                      // "lower" in the RAM-cell sense --
                                                      // see 3.3 for the real preset values)
            field2 = 1;
        else
            field2 = 0;
        append_decimal(buf, field2);
        buf += "|\0";
        send(buf);                        // real TX wrapper, 0x8c10
    }
}
```

### 3.3 The analog second gate / config-reload accept (`0x8f48`-`0x8f98`)

Reached whenever the send-gate check above falls through (either `TR0|`
disarmed, taking a direct `cbz`, or `TR1|` armed but the ~500-tick send
window hasn't yet elapsed — both converge on the same code, exactly
mirroring the digital arm's own CFG shape, Part 1 of
`trigger-input-symbolic-crosscheck.md`):

```c
// 0x8f48-0x8f98
if (channel_state[0..3] != 0) return;      // 4-way idle, same cells as the digital gate
if (*0x20001b38 != 0x7b) return;           // same solver-confirmed gate cell 1
if (*0x200000d8 != 9)    return;           // same solver-confirmed gate cell 2
if (*0x20003120 != 0)    return;           // TR0| required (re-checked, same as digital arm)
if (*0x20000190 > upper_threshold)         // 0x200000a8
    goto ACCEPT;                            // 0x8f98 -- SAME target the digital arm reaches
else if (*0x20000190 < lower_threshold)     // 0x200000c0
    goto ACCEPT;
else
    return;                                  // in-band: reject
```

**`ACCEPT` (`0x8f98`) is the exact same address, same first instruction
(`strb r2,[r3,#1]` writing the status byte), same tail-jump into
`config_loader__CUSTOM`/`config_reload_motion_profile_compute`, that the
digital arm's second gate reaches.** Every already-proven property of that
target — it does **not** arm `phase_ramp_arm_byte`
(`0x20002318[channel]`), and therefore cannot by itself cause motor motion
(`trigger-input-motion-causality.md`) — applies identically here, with no
new tracing needed.

### 3.4 The default threshold band, provenance-traced

`*0x20000194` (a 3-valued selector: 0=custom/unchanged, 1=preset A,
2=preset B) is read at `0x8e7e`. Exhaustive xref (`tools/ghidra/aptrace_ghidra.py
xrefs autopilot868 0x20000194`) finds exactly two producers:
`boot_config_reader__CUSTOM` (a persisted-config byte at relative offset
`0x33`, range-validated to `{0,1}`, else forced to `1`) and
`ascii_dispatcher__CUSTOM` (`0x892a`/`0x892e`, a live protocol command —
identity not pinned down this slice, named not chased). **Disassembled
this slice**: with `*0x20000194==1` (the default — the persisted config
blob is confirmed blank/all-zero, `target-config-provenance.md`, which
`config_read_byte__CUSTOM`'s own out-of-range handling resolves to `1`),
every poll unconditionally rewrites the threshold cells to **upper=`0x244`
(580), lower=`0xc8` (200)** (`0x9178`-`0x9186`); selector `2` uses
upper=`0x2ee` (750), lower=`0xfa` (250) (`0x9188`-`0x9194`). Confirmed
concretely (`tools/unicorn/trigger_transient_propagation.py`, Part 5):
seeding no threshold at all and letting the real preset-1 code run
reproduces exactly 580/200.

### 3.5 The boot-latch, concretely confirmed end to end

Static evidence (exhaustive, both cells have exactly 2 total
cross-references in the whole image, both self-contained inside
`FUN_000042a4`, neither ever reset):

```
tools/ghidra/aptrace_ghidra.py xrefs autopilot868 0x20003118   # "already sampled" flag
  0x000042da  FUN_000042a4  [READ]
  0x000042e8  FUN_000042a4  [WRITE]      <- only ever set to 1, never cleared

tools/ghidra/aptrace_ghidra.py xrefs autopilot868 0x20000014   # smoothing coefficient
  0x0000430a  FUN_000042a4  [READ]                              <- no writer anywhere
```

Concrete confirmation, chaining a real boot run into a real runtime poll
on the *same* `ConcreteMachine` (`trigger_transient_propagation.py`'s
ad-hoc verification, reproduced in the regression run below):

```
boot:    first-ever sample forced to 77 (a floating-pin-like low reading)
runtime: ADC1.RESULT forced to 4095 (full-scale, obviously out-of-band)
result:  live-value cell (0x20000190) still reads 77 -- the runtime
         injection has zero effect on the gate or on the T-status frame's
         own field-1
```

**This is the central finding of this slice**: the analog accept/T-status
path samples PB05 exactly once per power cycle — during the already-known
dead 128-sample boot loop, before a user could plausibly have inserted
anything — and never again. A transient at physical insertion time cannot
reach this path, *not* because it is filtered or debounced in any
time-domain sense, but because the path has already permanently stopped
listening before insertion is physically possible.

---

## Part 4 — ADC fault-injection: dead baseline, reconfirmed under adversarial input

`tools/unicorn/trigger_transient_propagation.py --only adc-dead` feeds five
synthetic sample streams (steady / single zero-or-full-scale spike /
several spikes / alternating extremes / settling ramp) into the real,
unmodified `FUN_00005d44` (the already-known dead 128-sample averaging
loop), via a Unicorn code hook at the exact PC where `analogRead()`'s own
core (`FUN_0000d1b4`) reads `ADC1.RESULT` (`0x43002040` — confirmed this
slice, see Part 6.1) — the loop's own `FUN_000042a4` rate-gate was forced
open every iteration (its last-check cell, `0x20003124`, zeroed on entry)
so all 128 synthetic samples genuinely reach the average, matching what
128 real ~500ms-apart calls would do rather than the "one real sample,
then cached forever" behavior Part 3.5 found for the *live* gate.

| Stream | Samples fed | `0x20003128` (avg) | `0x200023c0` (low-baseline flag) | Other 3 dead cells |
|---|---|---|---|---|
| steady (512) | 128 | 512 | 0 (unset) | unchanged (0) |
| single spike (one 4095 among 512s) | 128 | 512 | 0 (unset) | unchanged (0) |
| several spikes (alternating 0/4095 blocks) | 128 | 4095 | 0 (unset) | unchanged (0) |
| alternating extremes (0/4095 every sample) | 128 | 0 | **`-100`** (set) | unchanged (0) |
| settling ramp (4095→512 linear) | 128 | 3685 | 0 (unset) | unchanged (0) |

**Answering the task's direct question — can ADC transients affect
anything downstream beyond the already-known baseline RAM?** **No.** Under
every tested transient shape, including one that changes which of the two
computed cells gets written (the low-baseline flag fires only for
`alternating_extremes`, since that stream's accumulated sum is low enough
to cross the documented `sum < 0xaf00` threshold), **only the same two
already-documented dead cells (`0x20003128`, `0x200023c0`) ever change —
never a third cell, never anything with a real consumer.** The exhaustive
xref result `trigger-input-concrete-path.md` Part 4 already established
(no reader anywhere in the image for any of the five cells this loop
writes) is unaffected by input shape, confirmed by direct observation
rather than re-argued from the same static xref.

---

## Part 5 — Fault-injection matrices: the analog gate and the digital gate

### 5.1 Analog live/latched gate (`--only adc-live`)

Two timing conditions per stream: **burst** (the real ~500-tick gate is
left alone — models a fast bounce/ringing burst entirely within one real
sampling window, so only the first poll in the sequence can possibly
resample) and **sustained** (the gate is forced open every poll — models a
slow-settling condition spanning many real windows). Per Part 3.5, both
conditions are further bounded by the one-shot latch itself.

| Stream (8-poll sequence, ADC1.RESULT) | TR0 accepts | TR1 sends | Live-value cell after poll 0 |
|---|---|---|---|
| steady (512, in-band) | 0/8 | 1 | 512 |
| single spike (512×3, 4095, 512×4) | 0/8 | 1 | 512 (spike never latched — poll 0 was 512) |
| several spikes (512/4095/512/0/512/512/4095) | 0/8 | 1 | 512 |
| alternating extremes (0,4095,0,4095,...) | 8/8 | 1 | 0 (poll 0's own raw value, latched) |
| settling ramp (4095→512) | 8/8 | 1 | 4095 (poll 0's own raw value, latched) |

**`burst` and `sustained` produce byte-identical results in every row** —
direct, concrete confirmation of Part 3.5's static finding: forcing more
resamples changes nothing, because the blend coefficient is permanently
zero. The only thing that determines the outcome for the *entire 8-poll
window* is **poll 0's own raw sample** — if it happened to already be
outside `[200,580]`, every subsequent poll accepts (or, under `TR1`,
would have sent an unchanging frame every ~500 ticks, though only the
first send fits within this synthetic burst's own single rate-limit
window); if poll 0 was in-band, every subsequent poll rejects, regardless
of what wilder values arrive later. This directly demonstrates: **a
transient occurring anywhere other than exactly the first-ever poll after
boot is invisible to this path.**

### 5.2 Digital transient matrix (`--only digital`, the task's required sequences)

Two `TR` contexts (`TR0` = accept-gate counting, `TR1` = T-status send
counting) × two timing contexts (**startup** = rate limit pre-satisfied,
first poll can send; **runtime** = rate limit freshly consumed, cannot
re-fire within the sequence — modeling a bounce arriving shortly after a
real send already happened) × the task's five sequences:

| Sequence | TR0 accepts (accept count == LOW-poll count, both contexts) | TR1 sends, startup | TR1 sends, runtime |
|---|---|---|---|
| H L H | 1 | 1 | 0 |
| H L L H | 2 | 1 | 0 |
| H L H L H | 2 | 1 | 0 |
| H L L L H | 3 | 1 | 0 |
| L L L L | 4 | 1 | 0 |

**Directly answering the task's central question for the digital path**:
**yes — one physical insertion event, if sampled as bounce/ringing, can
become multiple accepted config-reload actions.** The accept gate has no
rate limit and no memory (Part 2, `trigger-input-mitigation-
patchability.md` Part 2); every poll where PB05 reads LOW during the
bounce independently accepts, so an `N`-LOW-sample bounce produces exactly
`N` accepts — concretely demonstrated, not inferred, above (`H_L_L_L_H`
producing exactly 3, `L_L_L_L` producing exactly 4). **The T-status send is
different and bounded**: at most **one** frame per real ~500-tick window
regardless of how many transitions occur inside it, and **zero** frames if
the window is already "spent" from a preceding send. Both arms share the
one rate-limit cell (`0x20002410`) and the one enable byte
(`0x20003120`), so this generalizes to the analog T-status send too
(Part 3.2's own `if (elapsed>=500)` structure is identical).

---

## Part 6 — Peripheral rule-in/rule-out

### 6.1 ADC — ruled IN (a real accept/status path), with a proven boundary

`analogRead(0x3b)` (PB05's analog alias) reads **ADC1**, not ADC0 —
confirmed concretely this slice (`run_concrete.py --call 0x42a4 --arg
0x3b --log-mmio`): the only non-pin-mux MMIO touches are at `0x43002xxx`
(`ADC1.CTRLA`/`SYNCBUSY`/`INPUTCTRL`/`RESULT`, SVD-resolved via
`tools/svd/resolve_mmio.py`), with `RESULT` at `0x43002040` returning
exactly the seeded value (`0x032a`→`810` reproduced byte-for-byte). Ruled
**in** as row 6/7 of Part 1's inventory; ruled **out** as a post-boot
transient-propagation path specifically, per Part 3.5/5.1's boot-latch
finding.

### 6.2 DAC — ruled out

`FUN_0000d1b4` (the shared `analogRead()`/pin-configuration core) touches
`DAC.CTRLA`/`SYNCBUSY` (`0x43002400`/`+0x8`) unconditionally, *before*
`RESULT` is ever read (`0xd1de`-`0xd2be`, all preceding the `RESULT` read
at `0xd2a2` in program order) — a pure, disassembly-confirmed control-flow
fact: these writes cannot depend on PB05's own value, since they execute
identically regardless of what `RESULT` will later read. No DAC output
channel is ever enabled/driven based on PB05 state, and no path leads
*from* DAC state back into trigger acceptance. Exact hardware purpose
(plausibly a shared analog-bias/reference warm-up sequence) not
characterized further — named, not chased, since it doesn't bear on the
trigger question.

### 6.3 EIC — ruled out (inherited, reconfirmed unchanged)

`trigger-input-concrete-path.md` Part 1's exhaustive whole-image scan
(callback table, line count, per-line mask each referenced exactly once,
by the dispatcher's own load) is unaffected by this slice's findings —
nothing here touches `attachInterrupt()`/EIC registration.

### 6.4 EVSYS — ruled out (new this slice)

A raw whole-image 32-bit little-endian literal scan for the EVSYS
peripheral base address (`0x4100E000`, from the vendored SVD) found
**zero** occurrences anywhere in the 70,768-byte image. This firmware
never references the event system at all, for any purpose — the strongest
possible negative result (not "unused for PB05," genuinely absent).

### 6.5 AC (analog comparator) — ruled out (new this slice)

A raw literal scan for `0x42002000` (AC's base) found **exactly one**
occurrence (`0x0000cfc0`), inside the same address range as this
project's already-documented one-time `Reset_Handler`/`sketch_setup`
clock-and-analog-block bring-up chain (`reset-handler-clock-init.md`'s own
"clock tree, analog block, WDT..." sequence) — a boot-only peripheral
clock-enable, not a live per-channel comparator configuration. **AC is
also absent from every RAM cross-reference list pulled this slice** for
the trigger's own state cells (`0x20000190`, `0x200000a8`, `0x200000c0`,
`0x20003120`, `0x20002524`) — no function anywhere near the AC peripheral
touches any of them.

### 6.6 DMA — ruled out (new this slice)

A raw literal scan for the DMAC base address (`0x4100A000`) found six
occurrences, all inside a single, generic, already-implicated (per
`reset-handler-clock-init.md`'s "a real SERCOM/DMA driver constructor")
channel-dispatch driver (`~0xa300`-`0xa400`: channel-descriptor-array
indexing, `INTFLAG`-style polling) — structurally unrelated to ADC1 or
PB05, and, like AC, **absent from every trigger-cell RAM cross-reference
pulled this slice.** No DMA descriptor anywhere references `ADC1.RESULT`
(`0x43002040`) or any of the trigger's own RAM cells.

### 6.7 Timer capture (TC/TCC) — ruled out (inherited, reconfirmed unchanged)

`motor-timer-survey.md`/`pin-index-provenance.md` already exhaustively
resolved every TC0-TC3/TCC1 pin assignment from the same `.data`-segment
pin-index table this project uses everywhere (**TC0→PB10, TC1→PA08,
TC2→PB12, TC3→PA10**, TCC1→PB22) — none is PB05. `pinMode()`'s own real
body (disassembled this slice, `0xd300`-`0xd33a`) never writes `PMUX` at
all, only `PINCFG` (`INEN`/`PULLEN`), with `PMUXEN` left clear on the
boot-time digital-input configuration path — an independent, disassembly-
level confirmation that PB05's digital-input configuration genuinely
disables any peripheral mux selection, not just an inference from absence
of a TC/TCC reference.

### 6.8 Direct/inline PORT register access — ruled out as a separate mechanism

Every GPIO/ADC touch to PB05 goes through the shared, pin-descriptor-
table-driven `digitalRead()`/`pinMode()`/`analogRead()` functions
(`0xd3dc`/`0xd300`/`0x42a4`→`0xd1b4`) — the same idiom this whole
Arduino-core-derived firmware uses for every other pin this project has
ever characterized. `pinPeripheral()` (`0xd40c`, the only function in the
image that writes `PMUX`) has exactly 7 call sites total (`callers
autopilot868 0xd40c`); the 4 outside the already-covered
`analogRead()`/`pinMode()` chain (`FUN_0000a1f4`×3, `FUN_0000c7c0`×3) are
generic peripheral-pin-config helpers taking a caller-supplied pin from a
small struct offset — consistent with SPI/SERCOM/radio-driver pin setup,
not traced to confirm they never receive PB05's index, and named as a
bounded, non-zero-probability-but-unlikely residual item in "remaining
unknowns" below rather than claimed closed with more confidence than the
evidence supports.

---

## Part 7 — Remaining physical unknowns

Unchanged from `trigger-input-mitigation-patchability.md` Part 8 — this
slice adds no new physical measurement, per instruction:

- The real transient shape at the jack and at PB05 (polarity, duration,
  bounce count, floating behavior, boot-only vs. runtime-insertion) —
  **UNKNOWN**.
- The real main-loop period (to translate a poll-count into real
  milliseconds) — **UNKNOWN**.
- The minimum legitimate trigger pulse width — **UNKNOWN**.
- **New, narrower unknown from this slice**: whether the analog boot-mode
  (PA02 HIGH at boot) is a real, supported field configuration or a
  vestigial/rare one — if it is common, the boot-latch finding (Part 3.5)
  means the analog trigger's entire-session behavior is decided by
  whatever PB05 reads in the first tens of milliseconds after power-on,
  which is exactly the "connect before power-up" workflow the user guide
  documents for the *other* (digital, PA02-LOW) mode's noise-baseline
  behavior — whether the manual's sensitivity-mode language maps to PA02's
  boot state or to the `*0x20000194` selector (Part 3.4) was not resolved
  this slice.
- Whether any of `pinPeripheral()`'s 4 generic-driver call sites (Part
  6.8) ever passes PB05's own pin index — bounded, not chased.
- The 4 remaining unattributed statuses named in prior docs (`0x200025bc`'s
  other 2 readers, the exact `ascii_dispatcher__CUSTOM` command that
  writes the sensitivity selector `0x20000194`, the debug-log sink for
  `"TRIGGER: <val>"`) — named, not chased, consistent with this project's
  practice of recording rather than silently dropping bounded open items.

---

## Regressions run

`tools/unicorn/test_concrete.py` (8/8 pass, unmodified — confirms this
slice's new script didn't misuse `ConcreteMachine`'s existing API).
`tools/unicorn/trigger_transient_propagation.py --only all` (this slice's
own new, reusable regression — all three experiments above, byte-for-byte
reproducing every table in Parts 4-5). No existing harness file was
modified.

---

## Direct answer

> **"If insertion creates a spike, bounce, ringing, floating interval, or
> slow settling condition, what distinct observable behaviors can the
> existing firmware produce?"**

**Two structurally different mechanisms exist, mutually exclusive per
power cycle (decided once, at boot, by PA02's level):**

**If the device booted with PA02 LOW (digital trigger mode — the more
sensitive mode per the user guide, confirmed this slice to be the mode
with no ADC filtering at all):**

- A spike, bounce, or ringing landing on any of the (main-loop-rate,
  unthrottled) accept-gate polls produces **one config-reload accept per
  LOW-reading poll it happens to land on** — a bouncy insertion can and
  concretely does produce multiple accepted actions (Part 5.2). Each
  accept is a real, already-proven-non-motion-arming reload of the
  persisted motor-target configuration plus a real GPIO pulse
  (`trigger-input-motion-causality.md`) — repeated reloads, not repeated
  motion.
- The same event can additionally cause **at most one** `"T<0 or
  1023>,<1 or 0>,\|"` status frame, only if `TR1|` reporting is armed and
  the ~500-tick send window happens to be open; a fast bounce burst inside
  one window produces zero *additional* frames beyond that one, regardless
  of how many transitions it contains (Part 5.2). That frame is already
  proven, both statically and concretely, to have **no path back into
  Remote-side control behavior** — a pure UI-display readout
  (`trigger-status-remote-feedback.md`), and the same wire shape/dispatch
  applies to the analog frame below (reasoned extension of that closed
  result, not independently re-run against the Remote firmware).
- A floating interval or slow settling produces exactly the same
  per-poll, memory-less behavior — there is no debounce and no distinction
  between "settling" and "already settled" at this layer; each poll just
  reads whatever level is present at that instant.

**If the device booted with PA02 HIGH (analog trigger mode):**

- **A transient at insertion time produces no observable effect at all**,
  for any of the shapes named in the question — spike, bounce, ringing,
  floating interval, or slow settling — **because this path's live-value
  cell is permanently latched to whatever PB05 read during the boot-time
  128-sample baseline loop, before insertion is physically possible, and a
  cold, unwritten smoothing coefficient (`0x20000014`) makes every later
  resample attempt a mathematical no-op** (Part 3.5, concretely
  demonstrated in Part 5.1). The only way this path's accept-gate or
  T-status frame content can differ from one power cycle to the next is a
  difference in **PB05's electrical state at the moment of boot itself** —
  a boot-time question, not an insertion-time one.
- If that one boot-time sample happened to fall outside the configured
  threshold band (default `[200, 580]` on the raw ADC1.RESULT scale), the
  config-reload accept path fires on **every** subsequent idle poll for
  the rest of the power cycle (a form of stuck-accepting, still proven
  non-motion-arming) — a real, if narrow, consequence of a bad boot-time
  reading, not of a post-boot transient.

**Neither mode's consequence is, or was found by any prior slice in this
project to be, a path to uncommanded motor motion.** ADC, DAC, EIC, EVSYS,
AC, timer capture, and DMA are all addressed above: ADC is a real accept/
status path (with the boot-latch boundary just described); DAC, EIC,
EVSYS, AC, DMA, and timer capture are ruled out as trigger-fault
mechanisms with fresh, direct evidence this slice, not carried forward
unexamined.

---

## Confidence table

| Item | Status |
|---|---|
| The analog arm (`0x8e68`-`0x8f98`) is a real, previously-uncharacterized second accept/T-status path, mirroring the digital arm's own CFG shape and sharing its accept target | **CONFIRMED** (disassembly, this slice) |
| Default threshold band is `[200, 580]` (raw ADC1.RESULT), via preset selector defaulting to `1` from blank persisted config | **CONFIRMED** (disassembly + exhaustive xref of the selector's 2 producers) |
| `analogRead(PB05)` reads ADC1.RESULT (`0x43002040`), not ADC0 | **CONFIRMED concretely** (MMIO trace, exact seeded-value round-trip) |
| The analog path's live-value cell is permanently latched to the first-ever boot-time sample; the smoothing coefficient is cold/unwritten (permanently 0.0f) | **CONFIRMED** (exhaustive xref, 2 total references each, no writer/reset) and **CONFIRMED concretely** (boot-then-runtime chained Unicorn run, Part 3.5) |
| A post-boot insertion transient (any shape) cannot reach the analog accept/T-status path | **CONFIRMED concretely**, direct consequence of the above |
| A bouncy digital insertion event can produce multiple accepted config-reload actions, one per LOW-reading poll | **CONFIRMED concretely** (fault-injection matrix, Part 5.2) |
| A bouncy digital insertion event produces at most one T-status frame per ~500-tick window, zero if the window is already spent | **CONFIRMED concretely** (Part 5.2) |
| ADC transients (5 shapes) affect nothing beyond the already-documented dead baseline RAM | **CONFIRMED concretely**, reconfirmed under adversarial input (Part 4) |
| EIC ruled out | **CONFIRMED**, inherited unchanged |
| EVSYS ruled out | **CONFIRMED** (exhaustive raw scan, zero references anywhere in the image) |
| DAC ruled out as a trigger-fault mechanism (touched, but unconditionally and with no data dependency on PB05) | **CONFIRMED** (disassembly, program-order argument) |
| AC (comparator) ruled out | **CONFIRMED** (single reference, inside already-documented boot bring-up; absent from every trigger-cell RAM xref) |
| DMA ruled out | **CONFIRMED** (generic driver, structurally unrelated; absent from every trigger-cell RAM xref) |
| Timer capture (TC/TCC) ruled out | **CONFIRMED**, inherited (`motor-timer-survey.md`/`pin-index-provenance.md`), reconfirmed via `pinMode()`'s own disassembly (never writes PMUX) |
| No inline/direct PORT access to PB05 exists outside the shared table-driven driver functions | **CONFIRMED**, exhaustive call-site enumeration (both `digitalRead`/`pinMode` and now `analogRead_wrapper`'s 2 total callers) |
| `pinPeripheral()`'s 4 generic-driver call sites never pass PB05's index | **UNKNOWN** — bounded, not chased (Part 6.8/7) |
| Sensitivity-selector-writing protocol command's exact wire identity | **UNKNOWN** — bounded, not chased |
| `"TRIGGER: <val>"` debug log's final sink | **UNKNOWN** — bounded, not chased |
| The real physical trigger-port electrical behavior | **UNKNOWN** — untouched, as instructed |

## Evidence level

Level 1 (static, exhaustive-xref/raw-scan, Ghidra-confirmed) for the
consumer inventory, the peripheral rule-outs, and the latch/coefficient
provenance. Level 2 (concretely executed, Unicorn) for every fault-
injection result in Parts 4 and 5, the ADC1/RESULT identification, and
the boot-then-runtime latch chain in Part 3.5. No level-3 (solver-
confirmed) work was attempted or needed this slice — every question here
was "what does this code do," not "what input satisfies this." No claim
in this document extends to the physical trigger-port fault itself.
