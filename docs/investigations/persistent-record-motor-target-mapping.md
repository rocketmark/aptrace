# Investigation: Reconnecting `0x12000` Persistence to the Motor Target — the `'+'` Command

**Question**: `nvm-param-and-full-roundtrip.md` closed the generic
persistence mechanism end to end (protocol change -> RAM record -> dirty
flag -> real NVM save @ `0x12000` -> fresh boot -> real load path), using
the `D` command as its vehicle. `target-config-provenance.md` had
separately found that the motor target/config struct at `0x20001b40` is
real, protocol-consumed state, but concluded its backing data (the
`0x12000` flash blob) is blank in this firmware image, and that no
command it tried could write a *meaningful* nonzero target into it. This
slice: reconnect the two findings — which persisted-record offsets
actually back `0x20001b40`, what custom code writes those offsets, and
whether any real, protocol-reachable path can populate a target with
`|target - live_position| > 8` (the threshold `FUN_00006fd8` needs to
attempt a real move).

**Scope**: static analysis (full Ghidra disassembly + direct literal-pool/
data-reference resolution against the loaded firmware image — no
guessing at DAT_ names, every address below is read directly from the
compiled image, not inferred from decompiler variable naming) to find and
characterize the writer; concrete Unicorn to exercise the smallest real
path once found. Per the task's explicit constraint, no direct write to
`0x20001b40` or `0x12000` was performed to force a result.

## Result

**Both halves closed by disassembly, with very high confidence; the
concrete confirmation is incomplete for a precisely-identified harness-
cost reason, not a logic gap.** `FUN_00004b64`'s already-known bulk *load*
(persisted logical offsets `500`-`1651` -> `0x20001b40[0..1151]`) has a
real, previously-unexamined *write-back* counterpart —
**`FUN_000043f0`** — and a real, previously undocumented ASCII command,
**`'+'`**, is the only place in the firmware that calls it. Along the way,
`'+'`'s own handler (reached via a tail-jump Ghidra's decompiler silently
follows, the same class of artifact this project has corrected before)
copies **wire-supplied, signed delta values with no clamp toward live
position** directly into the exact struct fields `FUN_00007cc0`'s
`G`-command target lookup already reads for modes `1`-`9`. This is a
real, protocol-reachable, unbounded-magnitude producer of the missing
data `target-config-provenance.md` needed — closing that investigation's
main open question. Concretely delivering `'+'` and observing the result
was attempted but not completed this slice: reaching its handler at all,
from a fresh `Reset_Handler` boot, now costs far more instructions than
any previous single-command injection in this project's history, for
reasons traced to real (not looping) SERCOM-based device-probe activity
this session's boot recipe doesn't yet budget for — a precisely bounded,
named gap, not a logic uncertainty.

## Part 1 — Backward: which persisted offsets back the motor struct

Already known, restated for this slice's frame: `FUN_00004b64`'s bulk
load calls `FUN_00009768(buffer=0x20003145, k)` for `k = 500..1651`
(1152 = 4 x `0x120` bytes), storing sequentially into
`0x20001b40[0..1151]`. **So persisted logical offsets `500`-`1651` are
the entire 4-channel motor-config struct, byte for byte, with no
transformation.** Offsets outside that window (e.g. `0x15`-`0x19`,
`0x1a`, `0x33`, `300`, `301`, `400`) back separate, non-motor global
config bytes (the `D` command's value/marker, a boot-time clamp setting,
an `X`-command byte, and two more bytes this slice traced to `'+'`'s own
header fields — see Part 3).

## Part 2 — Forward: the write-back function, found by tracing the shared accessor's real callers

`dirty-flag-persistence.md` found `FUN_0000977c`'s callers by searching
for the specific `movw #0x1002` immediate (the dirty-flag offset) — a
narrow, correct method for *that* question, but it only surfaces callers
that touch offset `0x1002` specifically. This slice instead pulled every
caller of `thunk_FUN_0000977c` (`0x97a0`) from the Ghidra-exported call
graph (`research/runs/ghidra/firmware_autopilot868.json`), regardless of
which offset each passes:

| Caller | Offset(s) touched | Already known? |
|---|---|---|
| `FUN_00004370` | `0x15`-`0x18` (4 bytes) | Yes — the `D` command's 32-bit writer |
| `FUN_00004c20` | `0x1a` | Yes — the boot-time clamp-to-default |
| `FUN_00005dd0` | `0x14` | Yes — the digital-input/timeout save trigger |
| `FUN_00008258` (`0x87ae`) | `0x19` | Yes — the `D` command's `0xDE` marker |
| **`FUN_000043f0`** | **`300`, `0x12d`(301), `500`-`0x673`(1651)** | **No — new this slice** |
| **`0x8186`** (a tail-jumped region, not a Ghidra-recognized function — see Part 3) | **`400`** | **No — new this slice** |

`FUN_000043f0`, disassembled in full, resolved against its own literal
pool by direct file read (not decompiler guessing):

```
DAT_00004434 = 0x20003145   (persisted buffer base -- confirmed, same constant as every other accessor)
DAT_00004438 = 0x20001b40   (source array -- CONFIRMED to be the motor-config struct, not a separate copy)
DAT_00004430 -> *0x20002941  (a single global byte, offset 300)
DAT_0000443c -> *0x200029d0  (a single global byte, offset 301)

void FUN_000043f0(void) {
    write_byte(buffer, 300, *0x20002941);
    write_byte(buffer, 0x12d, *0x200029d0);
    for (i = 500; i <= 0x673; i++)
        write_byte(buffer, i, 0x20001b40[i-500]);   // the whole 1152-byte struct
}
```

**This is the exact write-back mirror of `FUN_00004b64`'s Step A**: same
buffer, same offset range, same byte-for-byte semantics, opposite
direction. Every call dirties the buffer (via `FUN_0000977c`'s own
change-detection) for any byte that actually differs from what's stored
— meaning **any live change to `0x20001b40` becomes real, persisted,
protocol-reachable flash content, the instant `FUN_000043f0` runs.**

## Part 3 — Who calls `FUN_000043f0`, and the decompiler-vs-disassembly correction it required

The Ghidra-decompiled `FUN_00008258` (the ASCII dispatcher) appears, at
first read, to have a giant, self-contained `'+'` branch containing all
of this logic. **It doesn't** — exactly the same silent-tail-jump
artifact `target-config-provenance.md` already found once for
`FUN_00007e2c`/`0x7cc0`. Disassembling the real instructions shows
`'+'`'s actual dispatcher entry (`0x8386`-`0x838a`) branches to **`0x806c`
-`0x8208`, a separate code region *before* `FUN_00008258`'s own entry
point in the address space**, entirely un-attributed by Ghidra's function
boundaries (its own calls-graph export lists this region's call sites
with `fromFunction: None`). Every literal-pool address below was read
directly from the compiled image (`research/firmware/originals/
firmware_autopilot868.bin`), not inferred from decompiler variable names.

### The real wire frame, reconstructed from disassembly

Cursor semantics match every other command in this project (the shared
`0x20001fd4` receive/parse cursor, doing double duty as documented in
`mc4-transition.md`). Fields, in order, with their real destination
addresses:

| Order | How parsed | Destination | Role |
|---|---|---|---|
| header | raw bytes, indices 1-2 (cursor starts at 3, skipping them) | — | unread by this handler; index 1 selects `FUN_000046c8` vs `FUN_00004910` later (see below) |
| 1 | `FUN_0000799c` | `0x2000252d` | "confirm" value 1 |
| 2 | `FUN_0000799c` | `0x2000252b` | "confirm" value 2 — **must equal value 1**, checked later, or the whole write/persist tail is skipped |
| 3 | `FUN_0000799c` | **`0x20002060`** | **channel** (0-3) — confirmed by direct match against `FUN_000046c8`/`FUN_00004910`'s own channel-source literal |
| 4 | `FUN_0000799c` | **`0x20003140`** | **mode**: `0x62`(98,'b') triggers a live-position resync (`FUN_00004b24` x4); `> 50` triggers compute+persist (below); `0x14`(20) triggers an unrelated live-position snapshot copy |
| — | one raw digit (not comma-terminated) | `0x2000252f` | **record count** (0-3 meaningfully; the `FUN_000046c8`/`FUN_00004910` loop always processes exactly 3 slots, zero-padding any beyond the given count) |
| 5.. | `FUN_0000799c`, 5 fields per record, up to 3 records | **`0x20002960`** (a 15-int staging array) | per-record: flag byte, a 0-100 percentage, a rate divisor, a **signed delta**, a duration |

### The compute+persist branch (mode `> 50`)

```
FUN_00004ca8(0); FUN_00004ca8(1); FUN_00004ca8(2); FUN_00004ca8(3);
FUN_000043f0();                                    // <-- the persist call
thunk_FUN_0000977c(0x20003145, 400, 0x7b);          // an unrelated global byte, also persisted
```

`FUN_00004ca8(channel)`, disassembled in full — this is the *chaining*
step `target-config-provenance.md`'s `FUN_00004b24` already showed a
single-record version of:

```c
void FUN_00004ca8(int channel) {
    record = 0x20001b40 + channel*0x120;      // record[0] = channel base
    count  = record->offset_0x3c;             // "how many sub-records are active"
    for (i = 0; i <= count; i++) {
        record->offset_0xc = record->offset_0x10 + record->offset_0x0;   // target = start + delta
        (record + 0x48)->offset_0x10 = record->offset_0xc;               // chain into next sub-record's start
        record += 0x48;
    }
}
```

### The wire-controlled delta writer (`FUN_000046c8`/`FUN_00004910`)

Selected by the raw byte at packet index 1 (`'1'` -> `FUN_000046c8`, an
Adafruit/Arduino-shaped units family; anything else -> `FUN_00004910`,
using different scaling constants — both confirmed, by direct literal-
pool resolution, to write the **identical fields**, just with a
different unit conversion):

```c
void FUN_000046c8(void) {
    wire = (int*)0x20002960;                    // the staging array
    dest = 0x20001b40 + channel*0x120;           // channel selected by the '+' command's field 3
    count = *0x2000252f;                          // record count, from the raw digit
    for (i = 0; i < 3; i++, dest += 0x48, wire += 5) {
        if (i < count) {
            dest->offset_0x0  = wire[3];          // <-- THE SIGNED DELTA, copied straight from the wire, no clamp
            dest->offset_0x14 = (wire[1]==100) ? 0x5f : wire[1];
            dest->offset_0x28 = wire[4];
            dest->offset_0x2c = wire[2];
            dest->offset_0x44 = 1;                // <-- validity byte for this record, set true
            ... (a real S-curve/ramp velocity-profile computation, using the
                 already-classified libgcc-shaped fixed-point math cluster,
                 populating offsets 0x4/0x8/0x18/0x1c/0x20/0x24/0x30-0x37 --
                 real motion-profile parameters, not further characterized
                 this slice, since they're not on the distance-threshold path)
        } else {
            (zero the whole record)
        }
    }
}
```

**`dest->offset_0x0` (the delta) is copied from the wire with no
clamping toward live position anywhere in this function or in
`FUN_00004ca8`.** This directly answers the task's question 5: **yes, a
real, protocol-reachable path can populate a target differing
arbitrarily from live position** — the magnitude is bounded only by
whatever `FUN_0000799c`'s own signed-integer parser accepts (already
established elsewhere in this project to handle ordinary 32-bit signed
decimals).

## Part 4 — Closing the loop back to `FUN_00006fd8`

`FUN_00007cc0` (the real target-lookup body, per `target-config-
provenance.md`) reads, for mode `N > 0`: `record(N-1)->offset_0xc`
(target) and `record(N-1)->offset_0x44` (valid), where
`record(N-1) = channel_base + (N-1)*0x48`. For `N=1`, `record(0)` is the
channel base itself — **the exact same record `FUN_000046c8`/
`FUN_00004ca8` just populated**: `offset_0xc` now holds
`start(offset_0x10) + wire_delta(offset_0x0)`, and `offset_0x44` (valid)
is now `1`, both real writes from this pass. `FUN_00004b24`'s earlier,
one-shot boot resync already established `offset_0x10` (this record's
"start") equals the channel's live position at boot (confirmed cold-zero
in `target-config-provenance.md`). So, following a real `'+'` write with
a delta whose magnitude exceeds `8`, then a real `G<channel>1<seq>|`
command (type digit `1`, selecting mode 1 = this exact record):

```
distance = target(0xc) - live_position = (0 + wire_delta) - 0 = wire_delta
```

**This is a complete, disassembly-grounded, arithmetic answer to the
task's question 6**: `FUN_00006fd8`'s `distance` argument is designed to
receive exactly this wire-controlled value, and any `|wire_delta| > 8`
should cross its real-move threshold. This is reported as a strong
static prediction, not yet a concretely observed register capture (see
Part 5).

## Part 5 — Concrete exercise: attempted, incomplete, for a precisely-named reason

Per the task's instruction to concretely exercise the smallest real path
once a writer is found, this slice attempted two concrete runs, reusing
and extending the established boot recipe (`Reset_Handler` entry,
`OSC32KCTRL`/`OSCCTRL`/`DPLL0`/`DPLL1` ready bits, `SERCOM5`/`SERCOM2`
`SWRST`/`SYNCBUSY` self-clear, the disclosed radio-ID `--force-reg`, the
`NVMCTRL.PARAM`/`INTFLAG.DONE` bits from `nvm-param-and-full-
roundtrip.md`, and the `--stub-call` on the cycle-counter pulse delay):

1. **`MC4` alone** (needed to reach `FUN_00006fd8` at all, since it's
   only called from `FUN_000093fc`, which only runs after `MC4` clears
   `0x20000060` — already established in `mc4-transition.md`), intending
   to follow with `'+'` then a `G...1...` command.
2. **`'+'` alone** (does *not* need `MC4` — it's dispatched through the
   same real ASCII dispatcher reachable pre-`MC4`, exactly like `D`/`G`/
   `LL1`/`LL2`), to isolate and concretely confirm the write into
   `0x20001b40` without the added cost/complexity of also reaching
   `FUN_00006fd8`.

**Neither run reached its target address within a large instruction
budget** (up to 250,000,000 instructions for the `MC4` attempt, ~80,000,000
for the `'+'`-alone attempt — both far beyond any previous single-command
injection in this project, which have typically completed within a few
million). Two real, distinct issues were found and fixed along the way
(reported for the tooling record, not as blockers):

- **A genuine conflict between two already-documented, independently-
  correct facts**: this project's disclosed `PA22` GPIO seed
  (`PORT.GROUP0.IN` bit 22, held high from boot to satisfy the real
  homing-loop exit condition) is *also* the exact signal
  `dirty-flag-persistence.md` documented as triggering `FUN_00005dd0`'s
  "held past 1000 ticks -> save, then an intentional infinite halt" path.
  Holding `PA22` for the *entire* run (as every prior slice needing it
  did, since none previously ran far enough into the main loop to notice)
  eventually trips this real, firmware-intentional halt, before any
  later command can be processed. **Fixed** by adding a second
  `--force-mem` at the same one-time main-loop-entry trigger
  (`0x94bc`) that clears `PORT.GROUP0.IN` bit 22 back to `0` right as the
  main loop is reached — PA22 is real high for exactly as long as
  homing needs it, then real low, avoiding the later trigger without
  touching homing's own already-established requirement.
- **A `SERCOM` `SYNCBUSY`/`INTFLAG` bit-breadth gap**: the existing,
  narrowly-scoped clear/force-bit masks (`:1` for `SYNCBUSY.SWRST`,
  `:4` for one specific `INTFLAG` bit, both correct and sufficient for
  the one-time clock-init/driver-construction sequence
  `reset-handler-clock-init.md` characterized) are not broad enough for
  *later*, different `SERCOM` operations (an Adafruit-core `SPIClass`
  constructor, confirmed by a literal string reference inside
  `FUN_00009f60` — `"SPIClass::SPIClass(SERCOM*, uint...)"` — pinning
  this precisely as `CONFIRMED_ADAFRUIT_CORE`, not custom or radio-
  specific code). Broadened to `SYNCBUSY:0xffffffff` and
  `INTFLAG:0xff` (still register-scoped, still the same "let a real
  self-completing status register read as done" class of fix as every
  other `--mmio-force-bits`/`--mmio-clear-bits` use in this project) —
  this measurably changed execution (the stall's own program counter
  moved forward between attempts) but did not by itself close the gap.

**After both fixes, the runs still did not complete.** In the `'+'`-alone
run, program counter progress *was* observed between a 9M- and an
80M-instruction attempt (advancing from one small `SERCOM`-address-
resolution utility to a different one further along), and the injected
frame's staging array (`0x20002960`) remained all-zero throughout —
confirming the real bottleneck is **upstream of `'+'`'s own dispatch
entirely**: some real, finite (not infinitely looping — the program
counter visibly advances) sequence of `SERCOM`-based device activity
that a from-`Reset_Handler` run now reaches before any injected command
gets a chance to be processed, and that costs far more raw instructions
than this project's existing boot-recipe calibrations (tuned for
reaching the main loop quickly, then dispatching one short command)
ever needed to budget for.

**This is reported precisely as the remaining gap, not chased further**,
per the task's own scope discipline ("do not spend this slice on
unrelated persistence loose ends"): it is a harness/reproduction-cost
question (how many instructions, and which specific further `SERCOM`
completion condition, are needed to get a from-scratch boot all the way
to a point this deep into real firmware execution), not a new open
question about the `'+'` command's logic, which the static disassembly
above already answers completely and consistently three independent
ways (the struct-base literal, the staging-array literal, and the
channel-index literal all cross-confirm the same wiring).

## Answering the six questions

1. **Which persisted-record offsets feed motor configuration?**
   Logical offsets `500`-`1651`, the entire 4-channel `0x20001b40`
   struct, byte for byte — **confirmed**, both directions (`FUN_00004b64`
   load, `FUN_000043f0` write-back use the identical range).
2. **How do those offsets map to channel/mode?** `base + channel*0x120
   [+ (mode-1)*0x48]`, exactly as `target-config-provenance.md`
   established for the *read* side — **confirmed** to be the same
   addressing on the *write* side (`FUN_00004ca8`/`FUN_000046c8`/
   `FUN_00004910` all use the identical formula, independently
   cross-checked via direct literal-pool resolution, not assumed).
3. **Which custom functions write those fields?** `FUN_000043f0`
   (persist), `FUN_00004ca8` (chain target = start + delta),
   `FUN_000046c8`/`FUN_00004910` (wire-controlled delta/parameter
   writer) — all newly classified this slice, all **CUSTOM_APPLICATION**
   (see provenance update below).
4. **Reachable from protocol, setup, or another workflow?** **Protocol**
   — a real, previously undocumented ASCII command, `'+'`, dispatched
   through the same real dispatcher as every other command, confirmed
   reachable pre-`MC4` by the same reasoning already established for
   `D`/`G`/`LL1`/`LL2`. Not yet concretely delivered (Part 5).
5. **Can a real path populate a target differing meaningfully from live
   position?** **Yes, statically confirmed**: the wire-supplied delta is
   copied with no clamp toward live position, magnitude bounded only by
   the shared integer field parser.
6. **Does this explain `FUN_00006fd8` receiving a real distance `> 8`?**
   **Yes, as a strong, arithmetic, disassembly-grounded prediction**:
   mode-1's target (`record(0)->0xc`) becomes exactly
   `live_position_at_write_time + wire_delta`, so a subsequent
   `G<channel>1<seq>|` should compute `distance = wire_delta` — crossing
   the threshold for any `|wire_delta| > 8`. **Not yet confirmed by a
   completed concrete run** (Part 5's precisely-named gap).

## Provenance updates

Added to `research/provenance/function_classification.csv` /
`ghidra_labels.tsv`, all **CUSTOM_APPLICATION** (confirmed by full
disassembly and direct data-reference resolution against the loaded
image): `FUN_000043f0` (persist write-back), `FUN_00004ca8` (target
chain), `FUN_000046c8`/`FUN_00004910` (wire delta writer, two unit
variants). Also newly classified **CONFIRMED_ADAFRUIT_CORE**:
`FUN_00009f60` (the Adafruit `SPIClass` constructor, pinned by a direct
string-literal match — `"SPIClass::SPIClass(SERCOM*, uint...)"` — found
while diagnosing Part 5's stall), narrowing what's left as genuinely
uncharacterized in that stall to non-application `SERCOM`/library
plumbing, not custom logic.

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| Persisted offsets `500`-`1651` = the whole `0x20001b40` struct | **Confirmed** (byte-range match, both load and write-back directions) |
| `FUN_000043f0` is `FUN_00004b64`'s write-back counterpart | **Confirmed** (full disassembly + literal-pool resolution) |
| `'+'` is the only caller of `FUN_000043f0`, via a tail-jumped region (`0x806c`) `FUN_00008258` branches into | **Confirmed** (Ghidra call-graph + direct disassembly, the same tail-jump-correction method used before in this project) |
| The `'+'` wire frame's field order and destinations | **Confirmed** (every address read directly from the compiled image, none inferred from decompiler naming) |
| The delta field (`record->offset_0x0`) is wire-controlled with no clamp | **Confirmed** (full disassembly of `FUN_000046c8`/`FUN_00004910`) |
| Mode-1's target after a `'+'` write equals `live_position_at_write_time + wire_delta` | **Confirmed by static arithmetic**, tracing the exact same fields `FUN_00007cc0` reads |
| A real `'+'` write, followed by `G...1...`, drives `FUN_00006fd8`'s `distance` past `8` | **Not concretely confirmed this slice** — a strong, disassembly-grounded prediction, blocked by the harness-cost gap in Part 5 |
| `FUN_00009f60` is the Adafruit `SPIClass` constructor | **Confirmed** (direct string-literal match in the decompiled output) |
| The exact further `SERCOM` condition/instruction budget needed to get a from-`Reset_Handler` run all the way to `'+'`'s own dispatch | **Not established** — real, finite progress was observed (PC advanced between two runs), not an infinite loop, but the total cost remains uncharacterized |

## Evidence level

Level 1 (static) for the complete writer/mapping/prediction chain
(Parts 1-4) — full disassembly, cross-validated three independent ways,
no guessed addresses. Level 2 (concrete, Unicorn) attempted but
incomplete for Part 5, honestly reported as such rather than claimed.

## Next step

Two independent, narrow follow-ups, neither started this slice:

1. **Characterize the new `SERCOM` stall precisely** (a `--log-mmio`
   pass across the window between `0x94bc` and wherever `'+'`'s own
   dispatch would begin, on a run seeded exactly as this slice's) to
   name the specific real device-probe sequence responsible, the same
   way `post-homing-radio-probe.md` named the earlier radio-ID stall —
   then either model its one real completion condition (if it's a
   documented, self-completing status bit) or budget for its real,
   finite instruction cost explicitly.
2. Once `'+'`'s dispatch is concretely reached, complete the originally
   planned chain (`'+'` with a real `|delta| > 8` -> `MC4` -> a real
   `G<channel>1<seq>|` -> watch `FUN_00006fd8`'s `distance` register)
   to convert this slice's static prediction into the first fully
   concrete, nonzero real move this project has ever observed.
