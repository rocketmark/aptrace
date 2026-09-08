# Investigation: Concretely Tracing the Real Dispatcher Entry State

**Question**: why does the real firmware's `0x827e`-`0x82c4` loop terminate
(if it even runs at all) while the whole-function Crucible replay lets `R6`
"grow linearly and unboundedly"? Per
[`docs/tooling/tool-selection.md`](../tooling/tool-selection.md) (concrete
execution answers "what does this code do from a known state"), this used
Ghidra to find the real entry context, then Unicorn to run it.

**Scope**: AutoPilot firmware only. No Crucible model changes, no lazy-CFG
implementation. One reusable addition to the Unicorn backend
(`--watch`/`--watch-mem`, multi-point register/memory capture without
stopping — needed for a per-iteration trace, which `--stop-at` alone can't
give).

## Headline result: **the loop is never entered at all for a `&` packet.**

Disassembling the dispatcher's actual entry sequence (`0x8258`-`0x82c8`, via
`tools/ghidra/analyze_firmware.sh`'s extra-seed mechanism) found a branch
that earlier passes over this region had not documented:

```
0x8258: push  {r4,r5,r6,r7,r8,r9,r10,lr}
0x825c: ldr   r4, [0x8528]        ; r4 = buffer pointer (0x2000232a)
0x825e: ldrb  r3, [r4, #0x0]      ; r3 = buffer[0]
0x8260: cmp   r3, #0xf0           ; is buffer[0] == 0xF0?
0x8262: mov   r6, r0
0x8264: mov   r5, r4
0x8266: bne   0x82c6              ; if NOT 0xF0, skip the entire loop region
0x8268: ...                       ; (only reached when buffer[0]==0xF0)
        ...sets R7=TABLE, R6=0, falls into the loop at 0x827e...
0x82c6: cmp   r3, #0xe0           ; else: is buffer[0] == 0xE0?
0x82c8: bne   0x8368              ; if not, continue down the ASCII command chain
```

**The `0x827e`-`0x82c4` loop is gated on `buffer[0] == 0xF0`** — it is the
"binary motor/control frame" path the *original* v0.1 static model
(`research/autopilot_static_inventory/parser-dispatch.md`) actually got
right (`0xF0`/`0xE0` -> binary frame path), before that model was marked
not-fully-trusted by
[`docs/investigations/parser-dispatch.md`](parser-dispatch.md). ASCII
commands like `&` (`0x26`), `G` (`0x47`), etc. take the **completely
separate** chain starting at `0x82c6` -> `0x8368` -> ... -> `0x888c`,
and never come near the loop, `0x5274`, `0x5448`, or `TABLE[]`.

**This means the entire `0x5274`/`0x5448`/loop investigation
([`dispatcher-loop-callees.md`](dispatcher-loop-callees.md)) was analyzing
a code path that is structurally unreachable for the `&` command the
current milestone is about.** That investigation's own findings (no memory
overlap between the loop and its callees) remain correct and are still
useful for any future `0xF0`/`0xE0` binary-frame work — they just aren't
the explanation for the `&`-packet non-termination, because the `&` packet
never reaches that code at all.

## Establishing R0 concretely, not by assumption

Per [`trigger-input.md`](trigger-input.md), `R6` is seeded from the
dispatcher's caller argument (`MOV R6,R0` at `0x8262`), and that argument's
real value was previously unresolved (blocked on the `0x801c` A32 anomaly,
since resolved as a Macaw decode limitation, not dead code).

Tracing the real caller (`FUN_00008960`, the UART/serial receive state
machine that assembles the packet into `0x2000232a` byte-by-byte — found by
resolving its literal pool: `DAT_00008a78 = 0x2000232a`, confirming this
*is* the function that fills the RX buffer) to the exact `0x8a34: bl
0x8258` call site:

```
0x8a28: bl    0x801c
0x8a2c: cbnz  r0, 0x8a3a
0x8a2e: ldrb  r0, [r4, #0x0]      ; r0 = *(byte*)0x20001fd4   (r4 loaded earlier, AAPCS callee-saved -- unmodified across the intervening calls)
0x8a30: movs  r3, #0x0
0x8a32: strb  r3, [r5, r0]        ; null-terminate the buffer at index r0
0x8a34: bl    0x8258              ; <-- R0 here is that same *(byte*)0x20001fd4 value
```

So `R0` at the real call site is `*(byte*)0x20001fd4` — a RAM byte that
`FUN_00008960` only *reads*, never *writes*, in this function (confirmed by
its full disassembly). In the project's standard cold/zero-initialized RAM
convention (the same one `APTrace.FirmwareLoader.buildMemory` and every
prior Crucible test already use), this byte is `0`.

**Concretely verified, not assumed**: running `0x801c()` alone via Unicorn
from cold RAM (`tools/unicorn/run_concrete.py --entry 0x801c ...`) returns
`R0 = 0` after 22 real instructions — confirming the flag byte at
`0x20000018` that `0x801c()` branches on is `0` in cold RAM, and the
resulting "elapsed time" computation it falls through to also evaluates to
`0`. This is a demonstrated fact about the real code, not a chosen number.

**What was not fully re-derived**: the byte-by-byte arrival of the `&|`
frame into `0x2000232a` via the UART/serial ring buffer (`0x801c()`'s other
branch, `0x7f38()`/read-byte) was not simulated — that would require
reverse-engineering the ring-buffer format `0x801c()`/`0x7f38()` use when
their mode flag (`0x20000018`) is nonzero, a materially larger task than
this investigation's question needed. Instead, the packet buffer was seeded
directly with the real `&|` bytes (`0x2000232a = 0x26, 0x2000232b = 0x7c`
or `0x01`), matching every prior test in this project. Given the finding
above (the loop is gated purely on `buffer[0]`, unrelated to how the buffer
was filled), this simplification does not affect the result.

## The concrete trace

Two runs, entering at the real call site `0x8a34` (not directly at `0x8259`
— this exercises the actual `bl` and its real argument-setup, per the
task's request to instrument "the call to `0x8259`" as a separate point
from "`0x8259` entry"):

**Packet `[0x26, 0x7c, 0x00, 0x00]`** (`&`, `|` terminator):

| Watch | Address | R3 | R6 | buffer[0:2] |
|---|---|---|---|---|
| call site | `0x8a34` | `0x00` | `0x00` | `26 7c` |
| dispatcher entry | `0x8258` | `0x00` | `0x00` | `26 7c` |
| gate branch | `0x8266` | `0x26` | `0x00` | `26 7c` |
| (loop `0x827e`/`0x8286`/`0x82aa`/`0x82b0`/`0x82c0`) | — | *(never hit)* | | |
| ASCII-chain gate | `0x82c6` | `0x26` | `0x00` | `26 7c` |
| `&` handler | `0x8890` | `0x26` | `0x00` | `26 7c` |
| exit | `0x83ec` | `0x200025bc` | `0x00` | `26 7c` |

**46 total instructions. Zero loop iterations** (every loop-body watchpoint
recorded zero hits). `pending[]` array at exit:
`00 00 00 00 00 01 00 00 00 ...` — **`pending[5] = 1`, confirmed
concretely.**

**Packet `[0x26, 0x01, 0x00, 0x00]`** (the *exact* bytes
`app/Main.hs`'s existing "Test 0" Crucible run uses): identical result —
46 instructions, loop never entered, `pending[5] = 1`.

## Comparison with the Crucible run: where they diverge

`app/Main.hs`'s whole-function test (`PH.runPacketTransaction`) seeds:
- `entry` = `0x8259` (same as this trace)
- The packet buffer at `0x2000232a` = `[0x26, 0x01, 0x00, 0x00]` (identical
  to the second run above)
- **Every register concretely zero** except `PC`/`SP`
  (`src/APTrace/ProtocolHarness.hs`, `regVals <- Ctx.traverseWithIndex
  (concreteZeroVar sym) regTypes`) — i.e. `R0 = 0`, matching this trace
  exactly.

**Every nominal input matches between the two tests.** Yet the recorded
Crucible behavior (`docs/harness/protocol-harness-results.md`: "R6 grows
linearly and unboundedly") is completely different from what real,
concrete execution of the identical inputs does (46 instructions, loop
never entered, clean return with `pending[5]=1`).

**First point of divergence**: the `0x8266: bne 0x82c6` branch (testing
`buffer[0] == 0xF0`). Concretely, with `buffer[0]=0x26`, this branch is not
taken and the loop is never reached. The Crucible run's recorded symptom
(stuck in the loop, `R6` growing) means its execution took the *other*
side of this exact branch despite having the identical concrete
`buffer[0]=0x26` — since nothing else differs between the two setups, the
branch itself (or the whole-function CFG's representation of it) is the
most likely locus of the discrepancy, not any register or memory
assumption upstream of it.

## What this means for the current blocker

**The memory-side-effect hypothesis is now superseded, not just
unconfirmed.** It's not just that `0x5274`/`0x5448` don't write anything
the loop reads ([`dispatcher-loop-callees.md`](dispatcher-loop-callees.md))
— the loop is provably not on the execution path for this command at all.
**The real remaining question is why Crucible's whole-function CFG for
this merged ~340-block region doesn't correctly resolve the `0x8266`
branch away from the loop given a concrete, non-`0xF0` `buffer[0]`.**

This is *not* a register/memory-seeding fix (both already match between
the two tests).

**Update (2026-09-07)**: all three candidates below were checked in
[`gate-block-crucible-isolation.md`](gate-block-crucible-isolation.md) and
ruled out — the `0x8266` branch, isolated in Crucible with the same
concrete inputs, behaves correctly, and `mkFunCFG`'s entry/branch-wiring
machinery is confirmed correct by both source reading and an address
match. The remaining candidate is a finer-grained re-run of the actual
whole-function test, not yet done. Original candidates, for the record:

1. ~~Whether `mkFunCFG`'s translated entry block for this discovered function
   actually corresponds to physical `0x8258`~~ — confirmed it does
   (`discoveredFunAddr fn == 0x8259`, and the generic entry-jump mechanism
   in `mkFunRegCFG`'s source is correct by construction).
2. Whether the buffer write (`writeBuffer` in `ProtocolHarness.hs`) is
   actually visible to the *first* block's memory reads in the CFG Crucible
   executes, given the LLVM memory model's initialization order — not
   directly tested, but the isolated block test's own memory-seeding
   (once its own SP-aliasing bug was fixed) confirmed the same underlying
   mechanism works correctly.
3. Whether `debugFeature`'s address trace, if re-examined against *this*
   specific run, ever printed `0x8266`/`0x8267` before diverging into the
   loop — still not done; this is now the recommended next step (see the
   isolation doc's "Smallest next experiment").

## Reusable addition: `--watch`/`--watch-mem` in the Unicorn backend

`tools/unicorn/run_concrete.py` gained `--watch HEXADDR` (repeatable):
records full register state every time an address is hit, without halting
— unlike `--stop-at`. Combined with `--watch-mem ADDR:LEN`, this gives a
per-iteration trace of a loop (or, as here, confirmation that a suspected
loop is never entered) in one run instead of many. See the updated
[`docs/tooling/unicorn-backend.md`](../tooling/unicorn-backend.md).
