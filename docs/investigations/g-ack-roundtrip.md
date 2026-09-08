# Investigation: `G -> #` Through the Virtual RF Link (M4)

**Question**: [`docs/investigations/virtual-rf-link.md`](virtual-rf-link.md)
built two reusable primitives (`capture_tx_bytes`, `deliver_and_observe`)
around the `&|` -> `V01R39` transaction — do they genuinely generalize to
a more dynamic transaction with request fields and Remote-side retry/ack
behavior, or was `&|` easy in ways that don't transfer? Per
[`docs/harness/roadmap.md`](../harness/roadmap.md)'s M4 item 9 and
[`research/autopilot_static_inventory/protocol-bidirectional.md`](../../research/autopilot_static_inventory/protocol-bidirectional.md)'s
"G acknowledgement" scenario:

```
Remote 0xb680 builds G<d><d><seq>|
    -> 0xb59c sends / retries
    -> AutoPilot G branch
    -> 0x83ea schedules event 17
    -> "#"
    -> Remote 0xb59c accepts acknowledgement
```

**Scope**: reuse the existing primitives wherever they fit; investigate
the Remote retry loop (`0xb59c`) and the AutoPilot `G` handler only as
far as needed to run this transaction concretely; no new Ghidra work
beyond decompiling/disassembling the specific functions this transaction
touches; no Crucible/Macaw work (nothing genuinely symbolic came up); no
peripheral/radio/timer emulation.

## Result: yes, the primitives generalize — with two real additions

Both needed to be extended, in ways that are themselves reusable, not
special-cased to this one transaction:

- **`capture_tx_bytes`/`deliver_and_observe` gained `reg_seed`** (register,
  not just memory, seeding) — `0xb680` (`int FUN_0000b680(char param_1,
  int param_2)`) and the mid-function entry into `0xb59c`'s retry loop
  both need register arguments set up, not just RAM state. `&|`'s
  `0xba98` happened to need no register seeding at all, which is why this
  gap hadn't been hit yet.
- **A new `capture_tx_byte` primitive**, for AutoPilot's *other* TX-wrapper
  calling convention. Event 17's real output goes through `0x7f84` (`void
  wrapper(char b)` — a byte passed **by value** in R0), not `0x8c10`
  (`void wrapper(char *s)` — a pointer). This was flagged as "not
  attempted this pass" in `virtual-rf-link.md`'s own docstring; this slice
  needed it. Confirmed directly by decompiling `0x9268`'s full switch
  statement (not previously done — only case 5 had been traced): case
  `0x11` (17) is `uVar10 = 0x23; FUN_00007f84(uVar10);` — a literal `'#'`
  handed to the byte wrapper.

Neither addition is transaction-specific: both are now available to `S ->
P...` or any future transaction the same way.

## Leg 1: Remote constructs its real G request

`FUN_0000b680(char param_1, int param_2)` builds the packet directly
(`buf[0]='G'; buf[1]=param_2+'0'; buf[2]=param_1+'0'; buf[3]=<sequence
digit, pre-increment>; buf[4]='|'; buf[5]=0`) then calls `FUN_0000b59c()`
to send/retry it.

**Parameters seeded, not captured**: `param_1=0, param_2=0` (R0, R1).
`0xb680` is entered directly rather than through its real caller
(`FUN_0000e670`, a ~4KB UI/menu state machine — decompiled far enough to
find its three call sites, not further, per this task's scoping). Two of
those three real call sites pass `param_1=0` in the common case (a
channel-index argument that's 0 when the relevant UI counter is at its
first position); `0,0` is a real, representative value from that
survey, not an arbitrary choice — see `0xe670`'s decompile
(`FUN_0000b680(0,*DAT_0000e938 - 1 & 0xff)` appearing twice).

**A real wake-preamble, same shape as `0xba98`'s**: `0xb59c` begins with
`if (*DAT_0000b66c == 0) FUN_00005a14();` — a one-time "wake up" call
that itself sends via `0x58a8` first, with a different message. Left
un-skipped, `capture_tx_bytes`'s "stop at the first hit of the TX
wrapper" logic would capture the *preamble's* bytes, not the real G
request — confirmed directly (first attempt captured a flash string at
`0x1c596`, not the G-buffer). Fixed by seeding `DAT_0000b66c`
(`0x20000fc8`) nonzero — "this device has sent before," skipping the
one-time preamble via the firmware's *own* logic, not by choosing a
different entry point. `--stub-call 0xb440` (the radio poll, exactly as
already established for `0xba98`) gets past the drain loop the same way
it did there.

**Result, real bytes**: `b'G000|\x00'`.

**A genuine, minor static-vs-concrete correction**:
`research/autopilot_static_inventory/functions-of-interest.md` describes
the sequence digit as "cycles 1..9." Concretely, from cold RAM, the
*first* request's sequence digit is `'0'` (`0x30`) — `0xb680`'s own logic
stores the sequence digit *before* incrementing it
(`puVar2[3] = cVar1 + '0'` uses the pre-increment value), and cold RAM's
initial value is `0`. The "1..9" cycle is accurate for the second request
onward (`0` -> `1` -> ... -> `9` -> wraps to `1`, per the `if (cVar6 ==
'\n') cVar6 = '\x01';` guard) — just not for the very first one. Not
worth correcting the static doc over (this project's `README.md`-level
convention is that `docs/protocol/` is curated from execution, and
`research/autopilot_static_inventory/` stays as the historical static
record) — noted here as the kind of small gap concrete execution catches
that a static read doesn't.

## Leg 2a: AutoPilot concretely schedules event 17

Decompiling the real `G` handler (inside `FUN_000083b2`, the same
function `docs/harness/protocol-harness-results.md` already
solver-confirmed reachability for) shows it is **not** a simple
"schedule event 17" — it has its own guard logic:

```c
if (in_r3 == 0x47) {                                    // 'G'
  if (*DAT_00008548 == *(char *)(unaff_r4 + 3)) return;  // dedup: same seq as last time?
  if (*DAT_00008550 != '\0') return;                     // busy guard
  *DAT_00008548 = *(char *)(unaff_r4 + 3);
  FUN_0000b258(uVar3, uVar26);                           // helper 1
  ...
  FUN_00004b64();                                        // helper 2
  ...
  *(undefined1 *)(DAT_00008568 + 0x11) = 1;              // pending[17] = 1
  return;
}
```

Both guards resolve harmlessly from cold RAM (`DAT_00008548` and
`DAT_00008550` are both `0`, and a real sequence digit is never `0x00`),
so a fresh run reaches the write — **if** the two helper calls survive.

`DAT_00008568` resolves (literal-pool read, same technique used
throughout this project) to `0x200025bc` — the pending-event array
base — confirming `+0x11` (17) is genuinely `pending[17]`, not assumed
from the address arithmetic alone.

**Two real-but-irrelevant helpers needed `--stub-call`, for two different
reasons**:

- **`FUN_0000b258`** (via `FUN_0000b216`) does `(**(code**)(*param_1 +
  4))(param_1, param_2, uVar1)` — a C++-style virtual call through an
  object pointer. Concretely: `*param_1` is `0` in cold RAM (the object
  is only constructed by real startup, unreached here), so the call jumps
  to address `0x4` and faults — **the same class of runtime
  driver-object boundary** already documented for the RF/SPI drivers in
  [`docs/investigations/samd51-peripheral-mapping.md`](samd51-peripheral-mapping.md)
  and [`mando-first-execution.md`](mando-first-execution.md), here on the
  AutoPilot side, unrelated to RF. `FUN_0000b258`'s return value is
  discarded by the `G` handler (a bare statement), so stubbing it is
  exactly the same "opaque, real, return-value-unused" pattern already
  established, not a new kind of shortcut.
- **`FUN_00004b64`** loops calling `FUN_00009768` ~372 times to refresh
  per-channel state, plausibly from persistent (NVM-backed) motor-config
  data per the hardware handoff doc's "persistent storage" section — not
  yet investigated further, and not needed to be: concretely, it lands in
  a `memcpy`-shaped loop (`FUN_0000e648`) that never terminates within any
  reasonable instruction budget from cold RAM (confirmed via `--trace`:
  stuck at a fixed PC for 2000+ instructions, not progressing). Its return
  value is likewise discarded by the `G` handler.

With both stubbed: **44 instructions, `pending[17] = 0x01`** — a genuine
concrete confirmation of the event-17 scheduling behavior, not just the
previously-existing solver-confirmed *entry* reachability
(`docs/harness/roadmap.md`'s M2 item 4, "currently only entry
reachability is solver-verified for `G`/`!`/`S`" — this closes that gap
for `G` specifically, at the concrete tier).

## Leg 2b: AutoPilot's real outbound response

Decompiling `0x9268`'s **entire** switch statement (previously only case
5 had been traced) shows case `0x11` (17):

```c
case 0x11:
  uVar10 = 0x23;              // '#'
LAB_000092f2:
  FUN_00007f84(uVar10);       // the single-BYTE wrapper, not 0x8c10
  goto switchD_000092da_caseD_2;
```

Seeding `pending[17]=1` (the real value observed in leg 2a, not
hardcoded), the scan-table slot with `17` instead of `5` (the same
already-documented scan-table simplification from
`tx-hook-verification.md`, unrelated to which event is being tested), and
stopping at `0x7f84`: **57 instructions, `R0 = 0x23`** — the real `'#'`,
confirmed the same way `V01R39` was.

## Leg 3: Remote's real retry/ack path

Disassembling `0xb59c` (previously only decompiled) pins the exact
addresses needed:

```
0xb5be: <retry-loop top: drain, then send>
0xb5ca: mov r0,r7 ; bl 0x58a8        <- the real send
0xb5d0: bl 0x16840 ; str r0,[r5,#0]  <- timestamp
0xb5d6..0xb5e6: <up to 200-tick wait for any RX data>
0xb5e8: ldr.w r8,[0xb678] ; ldr.w r9,[0xb67c]   <- ring buffer base, read ptr (literal pool)
0xb5f0..0xb600: <poll for a byte, compare to '#'>
0xb602: bl 0x583c ; movs r0,#0x3c ; bl 0x168c0 ; movs r4,#1   <- ACCEPTED
0xb60e: bl 0xb4f8 ; ...                                        <- shared tail (both outcomes land here)
0xb638: subs r4,#1 ; bne 0xb5be ; b 0xb60e                     <- retry, or exhausted (r4 stays 0)
```

`0xb678`/`0xb67c` resolve to `0x20001773`/`0x200017d7` — the **same** RX
ring buffer and read pointer already established for `0xba98`'s
collection loop in `mando-first-execution.md`, confirming (again, not
assumed) that these synchronous-request routines share one RX ring
buffer across the whole Remote firmware.

**The same "don't let the pre-seeded response get drained as stale data"
problem `mando-first-execution.md` solved for `&|`'s Leg 3, solved the
same way**: entering at `0xb59c`'s own top would hit its leading drain
check *before* the send, and a pre-seeded ring buffer would be consumed
as if it were stale. Entering instead at `0xb5ca` — past both of `0xb59c`'s
own drain checks, right before the real send — needs `0xb59c`'s own
prologue registers seeded by hand (`R4=5` the retry count, `R5=R6=
0x2000276c` the shared timestamp cell, `R7=0x2000183c` the G-buffer
address, all resolved from `0xb59c`'s own literal pool, not guessed), and
`--stub-call`s on `0x58a8` (already proven separately in leg 1 — no need
to re-run its real body here), `0xb440` (radio poll), and `0x168c0`
(the SysTick-based delay in the success path itself).

Seeding the ring buffer with the real `0x23` byte from leg 2b (read
pointer 0, write pointer 1 — "one byte available"), stopping at `0xb60e`
(the shared tail both the accept and retry-exhausted paths reach) and
reading `R4` — the function's own `int` return value, computed in-register
across the whole loop — gives **59 instructions, `R4 = 1`**: the real
acceptance path, not the retry-exhausted one (which would leave `R4 = 0`
at the identical stop address — a real, reachable *other* outcome of the
same code, not ruled out by construction).

## The round trip

```sh
tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py g
```

```
=== Leg 1: Remote constructs its real G request ===
  Remote's real, unmodified 0xb680/0xb59c calls 0x58a8 with a pointer to RAM 0x2000183c, bytes = b'G000|\x00'
=== Leg 2a: AutoPilot receives it and schedules event 17 ===
  AutoPilot's real, unmodified 0x8258 dispatcher, given the real wire bytes b'G000|', sets pending[17] = 0x01
=== Leg 2b: AutoPilot's outbound dispatcher builds its real "#" response ===
  AutoPilot's real, unmodified 0x9268 dispatcher calls 0x7f84 with R0 = 0x23 (b'#')
=== Leg 3: Remote's real retry/ack path accepts it ===
  Remote's real, unmodified 0xb59c retry/ack loop, given the real ack byte 0x23, returns 1 (1 = accepted)

Round trip PASSED: Remote "G" request -> AutoPilot event 17 -> Remote accepts "#"
```

(`tools/unicorn/virtual_link.py` with no argument, or `ampersand`, runs
the original M3 `&|` transaction too — both pass; see
[`virtual-rf-link.md`](virtual-rf-link.md).)

## What the harness still substitutes for real hardware/firmware behavior

New to this transaction, beyond what `virtual-rf-link.md` and
`mando-first-execution.md` already documented (radio/SPI drivers, SysTick
delays, drain loops):

- **`0xb680`'s real caller (`0xe670`, the Remote's UI/menu state machine)
  is not exercised.** `param_1`/`param_2` are seeded to a representative
  real value (`0,0`), not derived from running the actual menu logic —
  investigating `0xe670` far enough to drive it for real would be a much
  larger UI-state-modeling task, out of scope per "only as far as
  needed."
- **Two AutoPilot-side helpers inside the `G` handler are stubbed**
  (`0xb258`'s driver-object virtual call; `0x4b64`'s persistent-config
  refresh loop) — neither's real effect is modeled, only that they return
  without altering the outcome this transaction checks (`pending[17]`).
  `0xb258` is architecturally the same "needs real startup" boundary
  already documented for RF; `0x4b64`'s real dependency (likely NVM/
  persistent motor-config data, per the hardware handoff doc) is a
  genuinely new, not-yet-investigated substitution, flagged here rather
  than quietly worked around.
- **The Remote's post-request routine (`FUN_00005a50`, called after
  `0xb59c` returns in the real `0xb680`) is not exercised** — this
  script's Leg 1 stops at the send, well before it.
- Same single-shot-process caveat as `virtual-rf-link.md`: each leg is a
  separate `run_concrete.py` invocation, not a persistent session.

## Evidence level

**Concrete (level 2)**, matching M3. No genuinely symbolic question arose
(the two new `--stub-call` targets were found by running with `--trace`
and reading the crash/stall point, not by needing a solver) — consistent
with the task's own framing to stay concrete unless one does.

## Next logical transaction

**`S -> P...`**: Remote's `0xc440` sends `S|`, AutoPilot schedules event
6, Remote's `0xc440` parses the `P<value0>,` (or the conditional 3-field
`P<value0>,<value1>,<bool>,`) response — per
`research/autopilot_static_inventory/protocol-bidirectional.md`. Same
primitives (`capture_tx_bytes`/`deliver_and_observe`/`capture_tx_byte`
as needed); `0xc440` is a much larger function (also handles `!0|`/`!1|`)
so expect to spend some of the slice narrowing down which part of it the
`S` path actually is, similar to this pass's `0x83b2`/`0x9268` work — not
started here, per the task's explicit scope.
