# Manual Mode and Limits — Current Model

Manual Mode's live jog does not use any known ASCII command: it is a
previously-unknown binary frame family (`0xF0`/`0xE0`), sent
continuously — once per UI tick, for as long as the jog wheel is not
clicked — into the same motor-rate entry point the `I` command already
uses. `LL1`/`LL2` ("Set Limits") are a self-contained pair of RAM
bookkeeping operations, sent by the same live-jog engine, that can
never actually capture a real physical position through this protocol:
no code path anywhere in either firmware image ties them to a real
value, confirmed three independent ways (disassembly, a concrete
`--watch-mem-write` run, and an exhaustive trace of the Remote's own
position-query mechanism).

## Current model

### The binary `0xF0`/`0xE0` jog frame

The jog wheel is a real quadrature encoder read through the SAMD51 EIC
(External Interrupt Controller); both firmwares are confirmed
ATSAMD51J19A. `FUN_00007c3c` (Remote boot init) registers a real
interrupt callback, `FUN_00007de8`, the velocity-sensitive quadrature
decoder (`±1`/`±5`/`±10` per tick depending on transition speed) that
writes a 16-bit position counter at `0x20001084`. `FUN_00007abc`/
`FUN_00007b00`, called every UI pump tick, turn that counter into two
shared globals used throughout the Remote firmware: `0x20001818`
(sign of the delta) and `0x2000181c` (accel-curved magnitude).

`FUN_0000e314` — the function the "Direction" row (`0x2c`) of the
`"MANUAL MODE"`-titled screen (`FUN_0000d988`) calls — reaches, via
`FUN_0000dd38`/`FUN_0000de3c`, a loop that consumes `0x20001818`
directly. This is the point where the UI-side trace (starting from the
`"MANUAL MODE"` string) and the physical-input-side trace (starting
from the EIC vector table) converge on the same address, independently.

`FUN_0000de3c`'s loop is the actual jog mechanism:

```c
do {
    FUN_0000c340();                       // pump: updates 0x20001818/0x2000181c
    if (*direction_invert_flag != 1) {
        delta = *DAT_0x20001818;
        if (accumulator + delta is within [-100, 100])
            accumulator += delta;          // 0x20001714
        *DAT_0x20001818 = 0;
    }
    FUN_0000be94();                        // SEND a real wire frame, EVERY iteration
} while (FUN_000171f0(0x2d) == 0);          // loop while the wheel is NOT clicked
```

It sends a frame on **every** pump tick regardless of whether the wheel
moved that tick — an idle/heartbeat frame goes out even with nothing to
report (confirmed concretely, see Test/repro). Clicking the wheel is
the only thing that ends the loop; there is no explicit stop/zero-rate
command — stop is silence.

The wire grammar (`FUN_0000be94` → `FUN_00004898`/`FUN_00004880`/
`FUN_0000468c`/`FUN_000048c8`):

```
buf[0]     = 0xF0 (mode==1) or 0xE0 (mode==2)
buf[1]     = base length (0x07, grows +4 per record)
buf[2..5]  = 0xFF 0xFF 0xFF 0xFF
buf[6+4i]  = channel (low nibble)
buf[7+4i]  = sign(value)<<7 | (|value|>>16)&0x7F
buf[8+4i]  = (|value|>>8)&0xFF
buf[9+4i]  = |value|&0xFF
buf[6+4N]  = '|' (0x7C)
buf[7+4N]  = rolling 1-9 sequence digit
```

The AutoPilot's ASCII dispatcher (`FUN_00008258`) checks `packet[0] ==
0xF0`/`0xE0` at its very entry, **before any lettered ASCII branch**.
For `0xF0`, each record's channel/value is compared against a
per-channel threshold at `0x20000180` (the same array
`motor-subsystem-unlock.md` already identified as `FUN_00005274`'s
mode-4 clamping ceiling) and routed into **`FUN_00005274`/
`FUN_00004d18`** — the exact entry point the `I` command's chain
already uses. `I` and Manual Mode are two different senders converging
on one receiver. From there the chain is already proven elsewhere and
not re-derived: `step_delta[channel]` → gated on the still-unresolved
`0x20001b14[channel]` busy gate → `FUN_00005ee8` → `FUN_00005c00` (TC
`CC0`) → `FUN_00005898` (GPIO pulse). The `0xE0` variant is
structurally similar but not byte-identical, and routes to the same
receiver via `FUN_00005448`→`FUN_00004d18`; its exact field layout was
not fully decoded.

As a side effect, this same shared row-action body (`FUN_0000d988`/
`FUN_0000db34`, driven by a per-row action-code byte) closed three
other previously-`UNKNOWN`-sender commands: `N|` (action codes `2`-`6`,
flash `0x1c9fb`), `B0|` (action code `0x1e`, flash `0x1c9fe`), and
`TR0|` (action code `0xc`, flash `0x1ca02`) — all one-shot toggles sent
once per confirmed row selection, not part of the jog stream.

### LL1/LL2 — pure RAM bookkeeping, never fed a real position

Both `LL1|` and `LL2|` reach the AutoPilot's top-level `'L'` dispatch
branch in `FUN_00008258` and tail-jump unconditionally to a shared
handler, **`FUN_000054e0`** (resolved by disassembly after the
decompiler's variable reuse across the `'H'`/`'L'` branches proved
misleading). This branch is reachable pre-`MC4`, the same tier as
`&`/`G`/`S`.

`FUN_000054e0` operates on exactly three fixed globals — `posA`
(`0x20003114`), `posB` (`0x20002414`), and `valid` (`0x20002458`), plus
a fourth (`minDest`, `0x20002424`) `LL2` alone writes:

- **`LL1`**: unconditionally zeros `posA`, `posB`, and `valid`. No
  comparison, no condition.
- **`LL2`**: compares `posA` and `posB`; only if they differ does it
  order them into `minDest`/`posB` and set `valid=1`. If they are equal
  (including the degenerate case right after `LL1`), it silently
  no-ops.

Neither instruction touches live position (`0x20002064`), the
target/config struct (`0x20001b40`+), `0x20001b14`, any rate/timer
register, or any GPIO/MMIO address — `FUN_000054e0`'s entire body is
RAM reads/writes plus a tail call to `FUN_00004480` (itself pure RAM:
clears a flag, records a timestamp). An exhaustive whole-firmware
literal-pool scan (the same method used for `0x20001b14` and
`0x20000060`) found **no other code anywhere in the image writes
`posA`/`posB` with a real value.**

The Remote-side sender for both commands is the **same function** as
the live-jog loop above: `FUN_0000de3c` sends `LL1|` three times as an
entry preamble, runs a jog phase, **resends `LL1|`** three more times
once the user clicks and a position query succeeds, runs a second jog
phase, then sends `LL2|` three times once a second position query
succeeds. This is one shared Set-Limits/Manual-Mode live-jog engine,
not two separate implementations.

The position query is a previously-unattributed real mechanism:
**`FUN_0000b834`** sends `I9|` or `I1|` (selected by `*0x200018e7`) —
closing `command-inventory.md`'s long-standing "used by a separate
Remote routine, sender unknown" note on those short forms — waits for a
signed-decimal response, and parses it via `FUN_0000b51c`. Its result
is stored at a **fixed** address, `0x200027f0`, and only the
success/failure of the query (not the value itself) gates whether
`LL1`(resend)/`LL2` are sent at all. An exhaustive xref of `0x200027f0`
found exactly two writers (`FUN_0000b834` itself, and an unrelated
one-time NVM boot-config loader reusing the same scratch slot) and
**no readers at all** — the queried position is computed, then
discarded, and never reaches `FUN_000058a8` (the bare
string-pointer-only sender both `LL1|`/`LL2|` and `I9|`/`I1|` go
through). **This is a third, independent confirmation, from the
opposite direction (the Remote's own query path) of the same negative
result**: whatever is supposed to populate `posA`/`posB` with a real
captured value is not reachable through this firmware's ASCII protocol
by any traced mechanism.

### UI-string correction

`user-guide-workflows.md` had hedged `"SET LIMITS"` as a *possible*
member of the trigger/relay settings-screen family, based only on
flash-string-table proximity to `"Pingpong mode"`/`"Relay contact"`.
That placement is disproven: `"SET LIMITS"` (flash `0x1c7d5`) has
exactly one real code reference (`FUN_0000cb70`, the screen-title
renderer), and `FUN_0000cb70` is called from exactly one place —
`FUN_0000e314`, part of the Manual-Mode-cluster screen family. Inside
`FUN_0000e314`, the `"Direction"` row and the Set-Limits row are two
rows of the *same* screen/menu, gated by a sub-state selector
(`cmp r3,#5` at `0xe598`): a value of `1` or `8` routes to
`FUN_0000dd38` (the Set-Limits sub-flow); anything else continues the
plain jog screen. The string-table proximity to trigger/relay strings
was coincidental compiler layout, not a shared implementation.

## Evidence

- EIC interrupt chain: vector table entries 28-43 (`EIC_0`-`EIC_15`)
  tail-jump into a shared ISR (`0x166dc`) iterating a callback table at
  `0x40002800`. `FUN_00007c3c` reads pins `0x31`/`0x32` and registers
  callback `FUN_00007de8` via `FUN_0001240c` (`attachInterrupt`
  equivalent).
- Shared live-jog/Set-Limits entry point: `FUN_0000de3c` (jog loop,
  `LL1`/`LL2` sends); frame sender `FUN_0000be94`; AutoPilot receiver
  branch in `FUN_00008258`; motor-rate entry `FUN_00005274`/
  `FUN_00004d18` (same as the `I` command).
- LL1/LL2 shared handler: `FUN_000054e0`, globals `posA` (`0x20003114`),
  `posB` (`0x20002414`), `minDest` (`0x20002424`), `valid`
  (`0x20002458`).
- Position-query mechanism: `FUN_0000b834` (sender of `I9|`/`I1|`),
  storage slot `0x200027f0` (written, never read elsewhere).
- Shared UI-rendering function for both the Direction row and the Set
  Limits row: `FUN_0000e314`; screen title renderer `FUN_0000cb70`
  (sole reference to `"SET LIMITS"`, flash `0x1c7d5`).
- `LL1`'s two flash string occurrences: `0x1ca83` (four total
  references — three-preamble entry send plus one later resend at
  `0xe014`). `LL2`'s one flash string occurrence: `0x1cb1e` (exactly
  one reference, `FUN_0000de3c` @ `0xe114`).

## Test / repro

- **`ConcreteMachine.call(0xbe94, ...)`, idle/heartbeat capture** (cold
  RAM, no channel dirty): `b'\xf0\x07\xff\xff\xff\xff|\x00...'` — fixed
  header plus immediate `'|'` terminator, confirming a frame is sent
  every tick even with nothing to report.
- **Same entry point, one real record** (channel 0 marked dirty):
  `b'\xf0\x0b\xff\xff\xff\xff\x00LK@|\x00...'` — decodes to
  `packet[1]=0x0B` (one record), channel 0, positive sign, magnitude
  5,000,000, matching the disassembled grammar field-for-field.
- **LL1-then-LL2 through the real RX path**, `--watch-mem-write` across
  the entire run on `0x20001b14`, the `0x20001b40`+`0x10` target field,
  and `0x20002064`: no hits attributable to either command — every hit
  is the already-known boot-time `.bss` clear / config-load sequence
  predating both `LL` dispatches. At `LL2`'s entry, `posA=posB=valid=
  minDest=0`; `LL2` takes the degenerate equal-values no-op branch, no
  write to `minDest`/`valid` occurs.
- **Concrete send-site captures** (`capture_tx_bytes`,
  `REMOTE_TX_WRAPPER=0x58a8`), all on the real, unmodified `mando868`
  image with no fabricated packet bytes:
  ```
  0xdeb0 (LL1 preamble send)   -> bytes=b'LL1|\x00'
  0xe00e (post-phase-1 resend) -> bytes=b'LL1|\x00'
  0xe10e (LL2 send)            -> bytes=b'LL2|\x00'
  0xb834 (position query, cold RAM)         -> bytes=b'I1|\x00'
  0xb834 (position query, *0x200018e7=0x1a) -> bytes=b'I9|\x00'
  ```
  The first three needed no register seed at all. The `FUN_0000b834`
  captures stubbed three real-but-irrelevant helper calls (haptic,
  idle/exit-check pump pair) and used a larger instruction budget to
  let the real multi-hundred-tick retry wait play out; the command
  choice and bytes themselves are exactly what the real code computes.

## Open items

Whether the `0xF0`/`0xE0` binary-frame mechanism is Manual Mode's
**only** live-jog entry point remains **PROBABLE, not proven**. The
same code (`FUN_0000e314`/`FUN_0000de3c`) is concretely reached both
directly from the "Direction" row and from the Set-Limits sub-flow
inside the same screen — both readings are consistent with the user
guide (which lists "Direction" as a Manual Mode feature) and are not
mutually exclusive. What remains open is only whether some other,
undiscovered entry point also reaches this loop; no such alternate
entry has been found, but the search was not exhaustive over every
screen in the image.
