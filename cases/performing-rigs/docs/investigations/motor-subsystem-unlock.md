# Motor Subsystem Unlock and Commands — Current Model

From a cold boot, the AutoPilot's motor-phase/ramp/monitor subsystem is
not merely idle — it is structurally unreachable: the function long
assumed to be a straight-line `setup()` (`FUN_00009464`) actually
contains its own internal loop that never returns, so the real `loop()`
(`FUN_000093fc`, and everything it calls — `FUN_00007e2c`,
`FUN_00008e18`, `FUN_00006338`, `FUN_00008a80`) is never even called.
The one and only exit from that internal loop is a single RAM byte
(`0x20000060`), and the only code anywhere in the firmware image that
clears it is the `MC4<...>|` command (motor configuration, all four
channels). Once `MC4` unlocks the subsystem, `G` and `I` can drive it —
`G` reaches the real move-commit function (`FUN_00006fd8`) and `I`
threads into the same timer/ramp chain — but a second, independent gate
(`0x20001b14[channel]`) turns out, after an exhaustive search, to have
no writer anywhere in this firmware image: a genuine dead gate, not a
missing feature. Separately, the Remote's own Quick Setup screen (where
`MC4` is normally sent from) is not opened by any Remote menu action at
all — it is opened because the AutoPilot itself sends an `MT` frame,
once per boot, built from four real motor-connector-presence GPIO
probes.

## Current model

### The real boot structure

`FUN_0000cd90` (`main()`) calls, in order: `FUN_00009464` (`0xcdb2`),
`FUN_000093fc` (`0xcdb6`), `FUN_0000cd88` (`0xcdba`). `FUN_00009464` is
the sketch's real `setup()` — after its real init calls (startup
reference/input routine, radio-ID probe, per-channel init, config load,
version-string write, and, unconditionally, the call that turns out to
send `MT` — see "Quick Setup" below), it enters its **own** internal
`do {} while` loop at `0x94be`-`0x94e2`, calling only `FUN_00008960`
(receive/dispatch) and `FUN_00005dd0` each pass. This loop has exactly
one exit: `ldrb r3,[r5,#0]; cbz r3,0x94e4` where `r5 = 0x20000060`
(loaded once at function entry). **This is the loop actually running
today.** It does not return on its own, so `FUN_0000cd90` never reaches
its next call, `FUN_000093fc` (the sketch's real `loop()`), and
therefore `FUN_00007e2c`, `FUN_00008e18`, `FUN_00006338`, and
`FUN_00008a80` — every function this project has ever described as
running "every main-loop iteration" — are unreachable from a cold boot
without a prior, specific unlock event.

### What `MC4` does

`FUN_00008258` (the ASCII command dispatcher), `M`/`C` branch: if
`packet[2]=='4'`, calls `FUN_00007a98(0)`, `FUN_00007a98(1)`,
`FUN_00007a98(2)`, `FUN_00007a98(3)` in sequence, then writes
`*0x20000060 = 0` at `0x8714` — **the only instruction anywhere in the
compiled image that writes this address** (exhaustive literal-pool scan
for the value `0x20000060`: exactly two hits total, `0x8868`'s pool cell
feeding this write and `0x94ec`, `FUN_00009464`'s own read). Per-channel
`MC<0-3>` calls `FUN_00007a98(channel)` once and returns without ever
reaching this instruction. `FUN_00007a98(channel)` parses 4
comma-terminated signed-decimal fields off the shared packet buffer
(`0x2000232a`, cursor `0x20001fd4`) via `FUN_0000799c`, writing:

| Field | Storage (per-channel array) | Transform | Consumed by |
|---|---|---|---|
| 1st | `0x2000006c[channel]` | `value * 0x50` (80 decimal) | `FUN_00007514`/`FUN_00007770` (display/status) |
| 2nd | `0x200000dc[channel]` | raw | `FUN_00006190` (boot-time init) |
| 3rd | `0x200000f0[channel]` | raw, except `1 -> 0` remap | `FUN_00007514`/`FUN_00007770` |
| 4th | `0x20000138[channel]` | raw | **`FUN_00007e2c`/`FUN_00008e18` — the locked subsystem** |

Only field 4 reaches the locked subsystem, as a table index
(`FUN_00007e2c`'s `DAT_00007e24`; `FUN_00008e18`'s
`DAT_00009154`/`DAT_00009158` pair) — not read directly as a speed
value. A per-channel timestamp (`0x200023e8[channel]`) additionally
gates a real LCD refresh (`FUN_00007514`) if more than 300 ticks have
passed since the channel's last `MC`/`MC4` call.

Clearing `0x20000060` on `FUN_00009464`'s next loop pass lets it exit
(`0x94e4: pop {r4,r5,r6,pc}`) back to `FUN_0000cd90`, which then calls
`FUN_000093fc` for the first time — a plain, unconditional handoff, not
a new dispatch mechanism. `MC4` does not call the locked functions
directly; it only removes the one obstacle to `FUN_000093fc` ever being
called at all.

### How `G` reaches the real move-commit function

`G<d><d><seq>|`, dispatched through the same `FUN_00008258`, arms a
state byte at `0x83de`: `0x200025e1 = 2`. `FUN_00007e2c` gates its own
state-0 entry on `*0x200025e1==2`. `0x200025e1` and `0x20000060` are
confirmed **independent** — disjoint literal-pool xrefs (four hits for
`0x200025e1`: `FUN_00007e2c` reading/clearing it, `FUN_00008258`'s `G`
branch setting it; two hits for `0x20000060`, above) and disjoint
control flow (neither function's logic references the other's gate).
Sending both is necessary only because `FUN_00007e2c` itself is
unreachable until `MC4` unlocks `FUN_000093fc` — a reachability
dependency, not a designed-together coupling.

Once unlocked, `FUN_00007e2c` (state 0, gated on the `G` arm) calls
`FUN_00006fd8(channel, percent=0x1e, distance, rate)` — the real
"commit a new move" function. `FUN_00006fd8`'s first branch is `if (8 <
abs(distance))`: **more than 8 units** populates the shared
segment-breakpoint tables, resets the segment index
(`0x200025e2[channel]=0`), and sets `0x20002524[channel]=1` and
`0x2000310c[channel]` (phase) `=1`, arming `FUN_00008e18`'s
phase-1→2→3 state machine. **8 units or fewer** clears the same tables
and sets both to `0` — a documented no-op.

### How `I` threads into the same chain — and the dead gate

`I<channel><mode>|` (`FUN_00008258`, `0x872e`-`0x877c`) does three things
unconditionally: `selector (0x20002328) = channel_digit`,
`mode[channel] (0x200029d8) = mode_digit`, and
**`0x20002524[channel] = 5`**. This corrects the older static-inventory
record (`synchronous-responses.md`), which said the handler's "=5" write
targets `0x20001b14[channel]` — disassembly shows it targets
**`0x20002524[channel]`**, a different, adjacent-in-role byte. Only
*conditionally* — when `0x20001b14[channel]` is already nonzero **and**
`0x2000309d[channel]==0` **and** (`*0x2000209f!=0` **or**
`0x20002524[channel]==2`) — does `I` call `FUN_00005274(channel, 4)`,
a real entry into the motor-side rate machinery. Both branches were
exercised concretely (Unicorn): with `0x20001b14[0]=0`,
`FUN_00005274` is not called but the three unconditional writes still
happen; with `0x20001b14[0]=1` (and the other gates set to take the
call path), `FUN_00005274(0,4)` is called (`r0=0,r1=4` at `0x8768`,
stub hit `lr=0x876d`) and the same three writes follow.

`0x20002524[channel]` is a genuine small per-channel state value (not a
global): written `5` by `I`, `1` by `FUN_00006fd8` on committing a real
move, `2` by an unnamed periodic poller (`0x541c`-`0x543c`, re-issuing
`FUN_00005274(ch,4)` whenever this byte is `2` and `0x20001b14[ch]!=0`),
and cleared to `0` by `FUN_00006338` except when it is exactly `5`
(preserved, not clobbered).

`0x20001b14[channel]` — the busy/rate-update gate — is read (never set
nonzero) by the `I` handler, `FUN_00005ee8`, `FUN_00006338`,
`FUN_00008e18`'s phase dispatcher, and the monitor (`0x8b5c`-`0x8b66`,
waits for it to reach `0`); cleared to `0` only by `FUN_00005958`
(called from `FUN_00006338`'s and `FUN_00005be8`'s target-reached
paths — genuine completion detections). **Nothing anywhere in this
firmware image was found to set it nonzero** — a real,
exhaustively-confirmed negative result (Evidence below), not a gap in
searching: `FUN_00006338`'s own phase-2/3 bodies end with `if
(0x20001b14[channel] == 0) { return; }`, so this byte is the real
runtime switch deciding whether a rate update ever reaches the timer
chain (`FUN_00005ee8` → `FUN_00005c00` → `FUN_00005898` → GPIO pulse) at
all — and no code path, reachable or not, ever throws that switch on.

`step_delta[channel]`'s **sign** is set concretely: `FUN_00004d18`'s
mode-2 body (reached via `FUN_00005274`, itself reached from `I`'s
alternate gate path when `0x20002524[channel]==2`), gated on
`0x20001b14[channel]==0` at entry, computes
`step_delta[channel] = (comparison ? 1 : -1)` from a target/position
comparison. `step_delta`'s **magnitude** was not traced to a specific
writer — the real per-pulse timing is `FUN_00005c00`'s `CC0` value,
computed from `FUN_00006338`'s phase-2 target/position delta, not
visibly from `step_delta`'s magnitude — kept deliberately unresolved
rather than assumed.

### How Quick Setup actually starts

Quick Setup is **not** entered from any Remote menu action. The only
writer of the Remote's Quick-Setup-in-progress flag (`0x20001810`) is
the Remote's own inbound radio-command handler (`FUN_00010ce4`),
reacting to a real AutoPilot-built `MT<b0><b1><b2><b3><x>|` frame. The
AutoPilot sends this frame **exactly once per boot**, unconditionally,
as a plain straight-line step of `sketch_setup()` — after the startup
reference/input routine and the radio-ID handshake, before
`setup()`'s own `MC4`-wait loop begins — via `sketch_setup()` (`0x94b4`,
`BL FUN_00007770`) tail-jumping (`0x7794`, `B.W`, unconditional,
always taken) into the frame-builder at `0x7334`. `b0`-`b3` come from
four real GPIO connector-presence probes with a non-naive slot mapping
(A→b0, C→b1, B→b2, D→b3); the Remote turns each `'0'` digit into
per-motor type `1` ("Not connected"), sets `0x20001810=1`, and opens
`"Motor <N>: Choose type"` automatically. From there, `MC<0-3>` is sent
by leaving an edited numeric row on the `"MOTOR <N>"` settings page
(any time, independent of Quick Setup), and `MC4` is sent by clicking
`"Continue"` once all four motors have an assigned type — closing the
loop back to the AutoPilot's own unlock.

## Evidence

**`0x20000060`** (loop-guard/unlock byte): exhaustive literal-pool scan,
exactly 2 hits total — `0x94ec` (read) and `0x8714` (write, `MC4`-only).
Confirmed concretely in the Test/repro runs below: `MC4` alone reaches
`0x8714` and `FUN_000093fc` starts running; per-channel `MC<0-3>` never
reaches it.

**`0x20001b14[channel]`** (rate-update enable gate): cold `.bss` value
`0` (`Reset_Handler`'s zero loop covers `[0x20000830, 0x2000531c)`).
Exhaustively searched for a nonzero-setter and **none found**:
- All 12 functions with a direct literal reference — `FUN_00004cdc`,
  `FUN_00004d18`, the unnamed poller (`0x5420`/`0x541c`-`0x543c`),
  `FUN_00005958` (clears to 0), `FUN_00005ee8`, `FUN_00005f8c`,
  `FUN_00006338`, `FUN_00007e2c`, `FUN_00008258` (`I` handler),
  `FUN_00008960`, `FUN_00008a80` (monitor), `FUN_00008e18` — all read
  it; only `FUN_00005958` writes it, and only to `0`.
- 7 one-hop candidates fully decompiled — `FUN_00006fd8`, `FUN_00006e68`,
  `FUN_0000693c`/`FUN_00006952`, `FUN_00004ae4`, `FUN_00007a98`,
  `FUN_00005570` — none touch it.
- The full one-time-init chain from `FUN_00009464` — `FUN_00006968`
  (startup reference/input), `FUN_0000610c`, `FUN_00006190`,
  `FUN_00004c20`/`FUN_00004b64`, `FUN_00004328`, `FUN_00005d44` — none
  touch it.
- A neighbor-offset sweep of every literal-referenced address from
  `0x20001af0` to `0x20001b40` confirms `0x20001b14` is a standalone
  4-byte per-channel array with no aliasing computed-pointer arithmetic
  passing through it.
- A Ghidra decompiler artifact (a spurious 64-bit index computed from
  `FUN_00005858`'s return in `FUN_00005958`) was ruled out by direct
  disassembly: `FUN_00005858` never writes `R0` in any of its switch
  cases.
- Concretely (Unicorn), a `--watch-mem-write 0x20001b14:4` watchpoint
  covering channel 0's phase-0 branch of `FUN_00008e18` ran to
  completion with **zero writes**; an unhandled FPU exception (not
  investigated) blocked channels 1-3 from the same run. A full-boot
  concrete run (`--fake-tick` past the homing timeout) reached a
  different, genuine dependency first — an uninitialized DMA/SERCOM-
  shaped peripheral object, root-caused to the already-documented
  `FUN_0000cdd8` clock-init stall — before any code that could set the
  byte. No write beyond the cold `.bss` clear was ever observed, in any
  run, by any method. **This is reported as a genuine, load-bearing
  negative result: a real dead gate in this firmware image, not an
  unsearched corner.** The best defensible name, given what is proven
  about its *use* and not its (unresolved) *cause*, is "a per-channel
  rate-update enable gate" — "busy"/"moving" is a plausible but
  unconfirmed reading.

**`0x20002524[channel]` correction**: `synchronous-responses.md`'s "=5
write to `0x20001b14[channel]`" is wrong; disassembly (`0x8742`-`0x8774`)
shows the write targets `0x20002524[channel]` instead (see model above).

**`MC4`'s field 4** as the sole field the locked subsystem consumes:
confirmed by exhaustive literal-pool cross-reference — fields 1-3 lead
only to display/boot-init code; field 4 (`0x20000138[channel]`) alone is
read by `FUN_00007e2c`/`FUN_00008e18`.

**`FUN_00006fd8`'s threshold** (`if (8 < abs(distance))`) confirmed by
disassembly and by a concrete run that captured the real call arguments
(`r0=0, r1=0x1e, r2=0, r3=0x121fa`), showing `distance=0` took the no-op
branch, clearing `0x20002524[0]`.

**`MT` frame's connector probes and slot mapping**: two indirect
(vtable-style) per-channel calls, `FUN_0000a970` (bit 29, a "guard") and
`FUN_0000a982` (bit 30, "raw state"); `digit=0` if the guard fails, else
`FUN_0000a982(obj) ^ 1` — a genuinely 2-valued (boolean) quantity, not
an arbitrary digit. Slot↔object mapping (**A→b0, C→b1, B→b2, D→b3** —
not naive A,B,C,D order) confirmed both by disassembly (probe order in
code is A, C, B, D) and concretely, by seeding a distinguishable
presence pattern per object and reading back which wire digit it landed
in. The 5th field (`<x>`) is a single byte read from `0x20001fc0`,
written by `FUN_00006968` (`1`=pin-check succeeded, `2`=timeout) — in
practice always `'1'` or `'2'`, never `'0'`.

**The per-byte/cumulative inter-byte timing dependency**: `FUN_00008960`
(receive/dispatch) re-runs a real SX127x-style radio IRQ-flags poll
(`FUN_0000801c`→`FUN_00007fdc`→`FUN_00009eac`) on every byte-availability
check, at real cost (thousands of instructions per check under
zero-behavior MMIO), and enforces a real inter-byte assembly timeout
(`0x82`/`0x83` ≈ 130-131 ticks) — diagnosed to be measured
**cumulatively from the start of the in-progress packet** (the
timestamp `0x20002010` only refreshes at packet-start or after a
timeout fires), not per byte. At `--fake-tick` period 20, the radio-poll
cost alone (2,800+ instructions ≈ 140+ ticks) already exceeded the
timeout on every byte, so every byte looked like a stale packet. Fixed
first for `G` (5 bytes) by raising the period to 300; then, for the
36-byte `MC4` frame, by measuring a stable **~5,696 instructions
(~19 ticks) per byte-check** and sizing a period from the *whole
packet's* real cost against the 131-tick budget (`35 × 5,696 / 131 ≈
1,522` break-even; **period 2000** chosen for margin). This is a harness
timing recalibration, disclosed as such, not a claim about real elapsed
microseconds — the mapping from `--fake-tick` period to real-world time
was never established and remains open (see Open items).

## Test / repro

**`run_concrete.py --force-mem TRIGGER:MEMADDR:HEXBYTES`**: the
memory-range counterpart to `--force-reg` — immediately before the
instruction at `TRIGGER` executes, writes `HEXBYTES` into `MEMADDR`,
standing in for bytes arriving over the real RX ring, never a claim
about real traffic. The trigger point used throughout is `0x94bc`
(`mov r4,r0`, inside `FUN_00009464`) — a genuine one-time program point
reached exactly once, right after all real boot init and immediately
before the cold-boot loop's first back-edge.

**The `MC4`-then-`G` sequencing technique**: sending `G000|MC4...|`
queued together in one injection does *not* cleanly exercise both — by
the time the receive loop resumes after `G`'s dispatch, `MC4`'s already-
buffered bytes are silently discarded by a real "flush stale bytes
while busy" check in `FUN_00008960` (`(last_cmd != 10 ||
0x20001b14[0] != 0) && last_cmd > 9`) — a genuine transport behavior,
not evidence of coupling. Fixed by a **second** `--force-mem` at
`0x94e4` (`FUN_00009464`'s own return instruction, confirmed to execute
exactly once), which delivers `"G000|"` at the exact moment control is
handed to `FUN_000093fc`, after `MC4`'s bytes are already fully
consumed.

**Concrete `MC4`-alone run** (`--max-instructions 9000000`, period 2000):

| Instruction | Address | What |
|---|---|---|
| 5,817,862 | `0x94bc` | `--force-mem` fires — 36-byte `MC4` frame seeded |
| 6,023,746 | `0x8a20` | real terminator recognized |
| 6,177,986 | `0x8714` | `0x20000060 = 0` — the real unlock |
| 6,180,925 | `0x93fc` | `FUN_000093fc` reached for the first time |
| 6,183,720 | `0x7e2c` | `FUN_00007e2c` reached (212 hits total) |
| 6,186,687 | `0x8e18` | `FUN_00008e18` reached (72 hits total) |

**Concrete `MC4`-then-`G` run**:

| Instruction | Address | What |
|---|---|---|
| 6,177,986 | `0x8714` | `MC4` unlock fires |
| 6,180,923 | `0x94e4` | second `--force-mem` fires — `"G000\|"` seeded |
| 6,180,925 | `0x93fc` | `FUN_000093fc` running |
| 6,240,733 | `0x83de` | `0x200025e1 = 2` — `G` dispatched through the new loop |
| 6,250,593 | `0x6fd8` | `FUN_00006fd8` fires — first time in this project |

`--watch-mem-write 0x20001b14:4` across every run above: no write
beyond the already-known cold `.bss` clear.

`--watch-mem-write` is a new `run_concrete.py` capability disclosed in
this cluster, used both for the `MC4` proofs above and for the
exhaustive `0x20001b14` search.

**Remote-originated `MC4` against the AutoPilot's real dispatcher**: a
byte-for-byte frame actually produced by `FUN_00005a8c` (`ConcreteMachine`,
real `.data` seeded from flash `0x25248`) — `b'MC420,2400,1,25,20,2400,1,
25,20,2400,1,25,20,2400,1,25,|'` — was fed into the AutoPilot's real
packet buffer at its real RX dispatcher entry (`0x8a34`). Result: `0x8714`
reached, `0x20000060=0`, `0x2000006c=(1600,1600,1600,1600)` (`20×80`),
`0x200000dc=(2400,2400,2400,2400)`, `0x200000f0=(0,0,0,0)` (`1→0`
remap), `0x20000138=(25,25,25,25)`. The same harness given a real
single-channel `MC1` frame (`b'MC120,2400,1,25,|'`) does **not** reach
`0x8714`; `0x20000060` stays `0x01`; only channel 1's fields are
written — confirming, with a Remote-produced frame, that `MC4` alone
crosses the unlock and `MC<0-3>` does not.

**Concrete `MT` frames, produced from disclosed connector-GPIO inputs**
(`ConcreteMachine`, entering at `FUN_00007770`, its sole call site
confirmed unconditional): mixed presence (A present, C absent, B
present, D absent) → probe bytes `01 00 01 00` → `b'MT10101|'`; all-guard
failure control → `b'MT00001|'` (confirms the guard forces `0`
regardless of the raw-state probe).

**An independent Thumb-2 branch/call decoder** (`scan_all_branches.py`,
ad hoc, not persisted to `tools/`) recovered the `MT`-builder's entry
path where Ghidra's call graph reported zero callers — because the only
real entries into that flash region are unconditional `B.W` tail-jumps,
not `BL`/`BLX`, so Ghidra never built a function object there. It
independently confirmed the same 3 branch/call instructions the
existing call graph implied, with a separate raw 32-bit address-taken
scan ruling out any indirect/table dispatch.

## Open items

- **What sets `0x20001b14[channel]` nonzero — genuinely unresolved.**
  The static search is believed exhausted (12 direct-reference
  functions, 7 one-hop candidates, the full one-time-init chain, a
  neighbor-offset sweep). The concrete path is blocked by a real
  dependency chain: a full-boot run needs `--fake-tick` past the homing
  timeout, which then hits an uninitialized DMA/SERCOM-shaped peripheral
  object rooted in the already-known `FUN_0000cdd8` clock-init stall —
  solving that is a larger undertaking than this cluster's scope. If
  that expectation holds once resolved, the strongest honest conclusion
  is that **this firmware image contains no code path, reachable or
  not, that ever writes `0x20001b14` nonzero.**
- **`step_delta[channel]`'s magnitude** (as opposed to its sign, which
  is confirmed set by `FUN_00004d18`'s mode-2 body) was not traced to a
  specific writer — deliberately left open rather than assumed to be
  "the" step-rate driver.
- **The exact real-time period `--fake-tick`'s calibrated values
  correspond to** was never established — the period-2000/period-300
  fixes are sized from measured real-instruction costs against the
  firmware's own tick-based timeout, not from any known
  ticks-to-microseconds ratio.
- **Whether a real, non-placeholder motor-config/target value would
  drive `FUN_00006fd8` past its ≤8-unit branch into the full ramp/GPIO
  chain** is not established — would require threading a real
  target/position value through `FUN_00007e2c`'s own per-channel-per-
  mode config struct (`0x20001b40`+, offset `0x10` target, offset
  `0x44` "valid"), whose "valid" byte reads as `0xff` under this
  harness's cold-RAM model (disclosed as uninitialized-pattern RAM, not
  a claim about a real provisioned unit).
- **Remote-side delivery of a real `MT` frame through `FUN_00010ce4`**
  (the Remote's actual per-character inbound radio state machine) was
  assessed but not attempted — it is structurally larger than this
  project's existing whole-packet `REMOTE_*_ENTRY` harness anchors and
  was deferred as a separate, bounded follow-up.
- **What schedules the `MC4` call site at `0xcb4c`** (the `'S'`-handler
  bulk-push tail) remains its own pre-existing open question, unrelated
  to this cluster's resolution of the `0x1039e`/"Continue" call site.
- **What writes `*0x2000027d`** (the Remote's 4-row vs. 2-row
  settings-page variant selector) — no direct-literal writer was found.
