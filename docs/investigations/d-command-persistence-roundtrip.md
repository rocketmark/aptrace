# Investigation: A Real `D<value>|` -> Dirty -> Save Round Trip, Concretely

**Question**: `dirty-flag-persistence.md` found the exact dirty byte, its
sole setter (`FUN_0000977c`), and a real but undelivered protocol
command (`D<value>|`) that writes through it. This slice: deliver a real
`D` command through the live RX path, watch the buffer and dirty flag
change for real, and — without fabricating a completed move or
force-calling the save routine — see how far the real firmware carries
that state toward an actual flash write at `0x12000`.

**Scope**: concrete Unicorn only, reusing the already-proven boot recipe
and RX-injection technique. No GPIO/MMIO seeding beyond what the project
already discloses and carries forward from prior slices (the PA22
boundary condition); no new completion-bit modeling; no seeded
buffer/dirty-flag/config state; no fabricated move or direct call into
`FUN_0000449c`/`FUN_000097a4`.

## Result

**Outcome A, as far as the existing concrete model supports, plus a
precise identification of the exact remaining blocking edge.** A real
`D1234,|` command, delivered through the real RX ring and real parser,
writes the correct value (`1234`) and marker (`0xDE`) into the real
persisted-config buffer via `FUN_0000977c`. The real firmware then
**naturally** reaches the save path (`FUN_00005dd0` -> `FUN_0000449c` ->
`FUN_000097a4`) — using only the project's already-disclosed PA22
GPIO-input assumption, not a new one — and calls the real NVM erase
primitive with real arguments (destination `0x00012000`, length
`0x1001`, matching the read path exactly). It then stalls forever inside
the erase loop, for a **precisely reconfirmed, already-known reason**:
the shared driver object's own "page size" field
(`0x20004148+0xc`) is `0`. No flash byte at `0x12000` is ever actually
written in this run, so the reboot/recovery half of the round trip could
not be exercised — not because of a missing trigger, but because of this
one confirmed downstream stall.

## Step 1: delivering a real `D` command — a real framing subtlety found along the way

`D` requires no `MC4` unlock (same tier as `&`/`G`/`S`/`LL`, reachable
directly from `FUN_00009464`'s real boot chain). Three framings were
tried, concretely, to find one that parses cleanly — a real protocol
question the static pass didn't need to answer:

| Frame | Result |
|---|---|
| `"D12345\|"` (no comma) | **Dispatches**, but `FUN_0000799c`'s field parser (whose only real terminator, confirmed by fresh disassembly, is a literal `,`) reads past the packet's own NUL terminator into adjacent memory for the full 1000-tick timeout, producing garbage (`r1=0x53d83ab0`, not `12345`) |
| `"D12345,\|"` (8 bytes, comma before the final `\|`) | **Never dispatches at all** — the outer receive-loop's own terminator recognition (a separate mechanism from `FUN_0000799c`'s comma check) never fires; all 8 bytes are consumed as plain data and the loop idles forever. Not chased further — a real, length/byte-pattern-sensitive framing quirk, the same *class* of dependency `mc4-transition.md`/`ll-limit-workflow.md` already found (a receive-path timing/framing subtlety), not a new exhaustive search target per this slice's scope |
| `"D1234,\|"` (7 bytes, comma present) | **Dispatches cleanly and parses correctly**: `FUN_0000799c` returns exactly `0x000004d2` (`1234`) |

The third framing was used for the rest of this investigation. This is a
real, useful protocol fact for `command-inventory.md`: **`D` needs a
trailing comma before `|`, like `MC4`'s per-field convention, not a bare
`D<value>|`.**

## Step 2: the buffer, concretely, before and after

Watched the exact physical bytes (`buffer_base + offset + 1`, the
`FUN_0000977c` addressing convention from `dirty-flag-persistence.md`)
at logical offsets `0x15`-`0x19` (physical `0x2000315b`-`0x2000315f`):

| When | Bytes (offset `0x15..0x19`) |
|---|---|
| Before (cold, blank-fill sentinel from `target-config-provenance.md`) | `ff ff ff ff ff` |
| Right before `FUN_00004370`'s call (inside the real `'D'` dispatch, register-captured) | `ff ff ff ff ff`, `r0=0x15`, `r1=0x000004d2` |
| Right before the marker tail-call | `00 00 04 d2 ff` — the 32-bit value correctly written, big-endian, marker not yet touched |
| After the full run reaches the save attempt | `00 00 04 d2 de` — **marker `0xDE` confirmed written** |

**Every byte of the 32-bit value and the marker differs from the `0xFF`
sentinel**, so `FUN_0000977c`'s own change-detection (`cmp`+`itttt ne`,
confirmed in `dirty-flag-persistence.md`) genuinely fires on this real
command's real data — not assumed, the resulting bytes are exactly what
a real `D1234,|` should produce.

## Step 3: the dirty flag — a new, real producer found by running the boot for real

The dirty flag (`0x20004147`) was **already `1` before the `D` command
even ran** — a real, previously-unenumerated producer, found only
because this slice ran the boot far enough to see it:
`FUN_00004c20` (the boot-time config reader) has its own real
"out-of-range setting, clamp to a default" logic — reading a byte at
logical offset `0x1a`, and if it falls outside `[0x14,0x19]` (which the
blank-fill's `0xFF` always does), **writing a real default (`0x14`)
back through the same `FUN_0000977c` accessor**. Since `0x14 != 0xFF`,
this genuinely dirties the buffer on **every cold boot with blank
config** — not a bug in this investigation's model, a real firmware
behavior, confirmed by disassembly (`0x4c7a`-`0x4c86`, previously
undocumented) and by the concrete `mem_write_hits` log showing it fire
before any injected command runs. This is folded into
`dirty-flag-persistence.md`'s producer list below, not treated as a new
open-ended search (per the task's own "don't broaden without a specific
reason" — this one specific, concretely-surfaced fact is exactly that
kind of reason, and no further searching was done beyond confirming it).

`D`'s own writes further (redundantly) satisfy the same change-detection
independently of the boot-time clamp — both are real, independent dirty
events, not conflated.

## Step 4: `FUN_000097a4` is reached naturally — using only the existing disclosed GPIO assumption

Running the same boot substantially further (no new commands, no new
seeding) shows, at instruction 6,018,637, **`FUN_0000449c` fires for
real** — with *zero* additional harness intervention beyond the recipe
every prior slice already uses. Tracing why: `FUN_00005dd0` (real,
called every main-loop iteration) reads a real digital input via
`FUN_0000d3dc(1)` — disassembled fresh this pass:

```c
uint FUN_0000d3dc(int pin) {
    entry = pin_table[pin];          // a real, .data/flash pin-descriptor table
    if (entry.valid_byte != 0xFF) {
        return PORT.Group[entry.group].IN >> entry.bit & 1;
    }
    return 0;
}
```

— a genuine `digitalRead()`-shaped function (the read-side sibling of
the `digitalWrite`-shaped helper `standard-library-provenance.md`
already classified). **Resolving pin-index `1`'s table entry directly
from the firmware image**: `group=0, bit=22` — **exactly `PA22`, the
same `PORT.GROUP0.IN` bit this entire project has disclosed and carried
forward since `systick-tick-injection.md`** (`--seed-mem
0x41008020:00004000`, forcing bit 22 high — originally justified as a
real dependency of the startup-reference routine). **No new GPIO
assumption was introduced this slice.** The same, already-disclosed PA22
signal has a real second effect: with it held high, `FUN_00005dd0`'s
"digital input sustained past 1000 ticks" branch is satisfied, which
calls `FUN_0000449c` -> `FUN_000097a4` for real.

## Step 5: the real NVM erase call — real arguments, matching the read path

At instruction 6,020,610, `FUN_000097a4` runs for real (dirty flag still
`1`, confirmed) and calls the real erase primitive:

```
FUN_000098f0(obj=0x20004148, dest=0x00012000, len=0x00001001)
```

**`dest=0x00012000` and `len=0x1001` are exactly the values
`target-config-provenance.md`'s read path uses** (the same driver
object, the same address, the same 4097-byte length) — concretely
confirming, for the first time by register capture rather than static
disassembly alone, that the write path targets the identical flash
region the read path consumes.

## Step 6: the real, already-known blocking edge — reconfirmed with real arguments

Extending the run to 60,000,000 instructions: execution never leaves
`FUN_000098f0`'s own erase loop, and `FUN_0000984c` (the actual write)
is never reached. Checked directly (`--watch-mem` on the loop's own
comparison inputs): `*(0x20004148+0xc)` — the object's "page size" field
`FUN_000098f0`'s loop divides its remaining length by — **reads `0`**.
Given the loop's shape (`if (page_size >= remaining) done; else erase
one page, advance by page_size, subtract page_size, repeat`), a
zero page size means the loop erases the same (zero-length) "page"
forever, never advancing and never terminating. **This is the same
class of dependency `post-probe-main-loop.md` already found and did not
chase** (a real bulk-NVM-operation stall, hypothesized there to be a
zero-valued step-size field) — this pass **confirms it concretely, with
real register values, in this specific, meaningful context** (the
persistence write path, not an arbitrary earlier probe), rather than
re-deriving it from scratch.

**Not chased further**, per the task's explicit scope: fixing this would
require either (a) fabricating a nonzero page-size value (forbidden —
this is exactly the kind of state the task said not to invent), or (b)
a genuine new investigation into whether this field is *supposed* to be
populated from a real, silicon-guaranteed source (e.g. `NVMCTRL.PARAM`,
a real, read-only SAMD51 register reporting the true page size — which,
if confirmed, would make modeling it a legitimate MCU-completion-bit-style
fix, not a fabrication) or whether it depends on a driver-construction
step this project hasn't traced. Named precisely as the next edge, not
guessed at.

## Step 7: the reboot/recovery half — could not be exercised, and why

Since flash `0x12000` is never actually written (the erase never
completes, so `FUN_0000984c` never runs), there is no new persistent
state to preserve or reload. A fresh-boot recovery test was not
performed — there is nothing yet to recover. This is a direct,
honest consequence of Step 6, not a separate gap.

## The dirty-flag lifecycle, revisited with this run's evidence

`dirty-flag-persistence.md` found `FUN_000097a4` never clears the dirty
flag after saving, and that the one function that does,
`FUN_000097f4`, has no confirmed caller. This run adds a real nuance:
**`FUN_000097a4` doesn't get the *chance* to reach its own "did we
finish" point at all** — it never returns, stuck in the erase loop.
Whether `FUN_000097a4`'s save is "supposed to" eventually clear the flag
(via code after the point this run ever reaches) remains exactly as
unresolved as before; this run does not newly contradict or confirm that
question, since it never gets there. `FUN_000097f4` was not reached in
this run either.

## Evidence classes, kept explicit

| Class | Example this pass | What it licenses claiming |
|---|---|---|
| **Real firmware control flow, executed concretely** | `FUN_0000799c`'s real parse of `"1234"`, `FUN_0000977c`'s real change-detected writes, `FUN_00005dd0`'s real branch into `FUN_0000449c`, `FUN_000097a4`'s real call into `FUN_000098f0` with real arguments | What the actual compiled instructions do, given the inputs below |
| **Harness-supplied external radio-ID assumption** | `--force-reg 0x9dd4:r0:0x12` (unchanged from `post-probe-main-loop.md`) | Needed only to get past boot; untouched by this investigation's own findings |
| **Already-disclosed GPIO-input boundary condition, reused (not newly introduced)** | PA22 (`PORT.GROUP0.IN` bit 22, `--seed-mem 0x41008020:00004000`) — this pass found it is also `FUN_0000d3dc(1)`'s real input | A real, previously-disclosed external-input assumption now shown to have a second real effect; no new claim about its physical function |
| **MCU completion-bit modeling** | The existing `--mmio-force-bits`/`--mmio-clear-bits` set (clock/SERCOM), unchanged | Real, SVD-documented, silicon-guaranteed bits — not touched or extended this pass |
| **Persisted flash state produced by the firmware** | None yet — `0x12000` was never actually written in this run | N/A this pass; the read-side blank-fill state (`target-config-provenance.md`) is unchanged |
| **Harness intervention to preserve/reload state** | None used or needed — no flash write occurred to preserve | N/A this pass |

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| `D` requires a trailing comma (`D<value>,\|`) to parse cleanly through `FUN_0000799c` | **Confirmed concretely** (three framings tried, one clean) |
| The 8-byte `"D12345,\|"` framing fails to dispatch at all | **Confirmed concretely**; **root cause not investigated** (out of this slice's scope) |
| `FUN_0000977c` correctly writes the parsed value and marker at the real physical offsets | **Confirmed concretely** (byte-exact before/after capture) |
| `FUN_00004c20`'s "clamp out-of-range setting to default" logic dirties the buffer on every cold boot with blank config | **Confirmed** (disassembly + concrete `mem_write_hits`) — a new producer, not previously enumerated |
| `FUN_0000d3dc(1)` reads `PA22` (`PORT.GROUP0.IN` bit 22) — the same signal already disclosed and carried forward since `systick-tick-injection.md` | **Confirmed** (disassembly of `FUN_0000d3dc` + direct resolution of the real pin-descriptor table in the firmware image) |
| The real save path (`FUN_00005dd0`->`FUN_0000449c`->`FUN_000097a4`) is reached using only that pre-existing disclosed assumption, no new fabrication | **Confirmed concretely** |
| The real erase call's arguments (`0x00012000`, `0x1001`) match the read path exactly | **Confirmed concretely** (register capture) |
| The erase loop stalls because the driver object's page-size field (`0x20004148+0xc`) is `0` | **Confirmed concretely** (direct memory read at the loop's own comparison point) — same class of gap as `post-probe-main-loop.md`'s already-known NVM stall |
| Whether that field should be populated from a real `NVMCTRL.PARAM`-style register, or from an untraced driver-construction step | **Unresolved** — the precise next question, not guessed at |
| Whether flash `0x12000` was ever actually written, or a reboot recovers the value | **Not reached this pass** — no flash write occurred |
| `FUN_000097a4`'s own dirty-flag-clearing behavior after a *successful* save | **Still unresolved** — this run never reaches that point either |

## Evidence level

Level 2 (concrete, Unicorn) for every claim in Steps 1-6: real register
captures, real memory before/after snapshots, real control-flow hits, no
seeded buffer/dirty-flag/config/move state anywhere. Level 1 (static)
only for the fresh disassembly of `FUN_0000d3dc` and the direct
pin-table read from the firmware image (used to explain, not to
fabricate, the concrete result). No solver/symbolic step used or needed.

## Next step

The one precisely-named remaining edge: **whether `0x20004148+0xc`
(the driver object's page-size field) should be populated from a real,
silicon-guaranteed SAMD51 register** (a legitimate `--mmio-force-bits`-
style fix, if confirmed) **or from an untraced driver-construction call**
this project hasn't followed yet. Resolving that — not fabricating a
page-size value — is the direct continuation that would let a future
slice reach `FUN_0000984c` for real, observe an actual flash write at
`0x12000`, and finally attempt the reboot/recovery half of this round
trip. Separately, and independently, the `"D12345,\|"` (8-byte) framing
failure noted in Step 1 is a real, minor, un-investigated receive-path
curiosity for whenever a future slice needs multi-digit `D` values.
