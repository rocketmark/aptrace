# Protocol Pipeline — Current Model

This cluster established the real shape of the AutoPilot dispatcher at
`0x8258` (a binary-frame gate in front of the ASCII command chain, not a
flat if/else scan), then used that corrected model to concretely prove —
with real, unmodified firmware on both sides and no radio hardware
modeled — the full `"&|"` -> `"V01R39"` transaction end to end across
both the AutoPilot and Remote (mando) firmwares, and generalized the same
harness primitives to two further transactions, `G -> #` and `S ->
P...`. Along the way it found and root-caused a genuine Crucible/macaw
tooling limitation (readonly-flash literal-pool reads are solver
assumptions, not folded literals, so plain whole-function execution can't
resolve a branch that depends on one) and left it deliberately unfixed
because the milestone closed at the concrete (Unicorn) tier without
needing it.

## Current model

**The dispatcher is not a flat if/else chain.** The original static model
(`research/autopilot_static_inventory/protocol-pipeline.md`, v0.1) read the
character-comparison blocks directly and assumed nothing structurally
interesting precedes them. Concrete tracing of the real entry sequence
found otherwise:

```
0x8258: push  {r4,r5,r6,r7,r8,r9,r10,lr}
0x825c: ldr   r4, [0x8528]        ; r4 = buffer pointer (0x2000232a)
0x825e: ldrb  r3, [r4, #0x0]      ; r3 = buffer[0]
0x8260: cmp   r3, #0xf0
0x8262: mov   r6, r0
0x8264: mov   r5, r4
0x8266: bne   0x82c6              ; if NOT 0xF0, skip to the ASCII/0xE0 check
        ...                       ; (0xF0 path only) falls into the
                                  ; 0x827e-0x82c4 binary-frame loop
0x82c6: cmp   r3, #0xe0           ; else: is buffer[0] == 0xE0?
0x82c8: bne   0x8368              ; if not, continue down the ASCII chain
```

Entry (`0x8259`) branches on `buffer[0]` first: `0xF0` enters a
per-channel binary-frame loop (`0x827e`-`0x82c4`); `0xE0` is a second,
still-unexplored binary case; anything else (all ASCII commands) falls
through to the character-comparison chain reached via `0x82c6`->`0x8368`.
**For `&`, `G`, `!`, `S`, and every other ASCII command, the loop is never
entered at all.** The four solver-confirmed character checks from the
original model remain accurate endpoints on this chain:

| Command | Check block | Handler block | Solver-derived R3 |
|---|---|---|---|
| `&` | `0x888c` | `0x8890` (`pending[5]=1`) | `0x26` |
| `G` | `0x83b2` | `0x83b6` | `0x47` |
| `!` | `0x87b2` | `0x87b6` | `0x21` |
| `S` | `0x87be` | `0x87c2` | `0x53` |

The binary-frame loop's own structure (fully decoded, relevant to future
`0xF0`/`0xE0` work, not to the ASCII milestone): for each 4-byte channel
record starting at buffer offset 6, compare a shared table's value
(`TABLE[channel]`, RAM `0x20000180`) against a packed target decoded from
3 of those bytes; call `0x5274(channel, 4, _, TABLE[channel])` if
`TABLE[channel] <= target`, else `0x5448(channel, ±target, _, _)`. Exit
condition is an ordinary bounded count: `r6 >= (buffer[1]-adjusted)/4`.
Neither `0x5274` (mode==4 arm, the only arm this call site reaches) nor
`0x5448` nor their shared callee `FUN_00004d18` write any address the
loop itself reads — no memory-effect coupling between loop iterations and
the exit test.

**Real caller chain, concretely confirmed.** The dispatcher's caller is
`FUN_00008960` (the UART/serial receive state machine that assembles a
packet into `0x2000232a` byte-by-byte):

```
0x8a28: bl    0x801c
0x8a2c: cbnz  r0, 0x8a3a
0x8a2e: ldrb  r0, [r4, #0x0]      ; r0 = *(byte*)0x20001fd4
0x8a30: movs  r3, #0x0
0x8a32: strb  r3, [r5, r0]        ; null-terminate the buffer
0x8a34: bl    0x8258              ; real caller -> dispatcher entry
```

`R0` at this call site is `*(byte*)0x20001fd4`, read-only in this
function, `0` in cold RAM (confirmed by running `0x801c()` alone: `R0=0`
after 22 instructions). Entering at the real call site `0x8a34` (not
directly at `0x8259`) with the packet buffer seeded `[0x26, 0x7c, 0x00,
0x00]`: **46 instructions, zero loop iterations, `pending[5]=1`** —
matches identically for `[0x26, 0x01, 0x00, 0x00]` too.

**TX side, concretely confirmed.** `pending[5]=1` is consumed by the
outbound dispatcher `0x9268` (loop over a scan table, `switch
(event_id)`); case 5 loads `puVar9 = DAT_000093d4` (-> `0x20003134`) and
calls `FUN_00008c10(puVar9)`. `"V01R39"` is not a contiguous string
literal in flash — it's built by `FUN_00004328`, called unconditionally
at startup (`FUN_0000cd90 -> FUN_00009464 -> ... -> FUN_00004328`,
strictly before the main loop's first call to either `0x9268` or
`0x8960`), writing six literal byte-stores (`0x56 0x30 0x31 0x52 0x33
0x39 0x00`) to `0x20003134`. Concretely seeding `pending[5]=1` and the
already-confirmed version buffer, entering at `0x9268` and stopping at
`0x8c10`: **57 instructions, `R0 = 0x20003134`, bytes = `"V01R39\0"`,
and `pending[5]` decremented back to 0** — the real case-5 arm of the
real, unmodified dispatcher, not a stubbed jump.

**The virtual RF link.** Both firmwares gate real radio I/O behind a
runtime driver-object layer that only becomes valid after real startup
(AutoPilot's `0x8c10`/`0x7f84`; Remote's `0x58a8`/`0xb440` chain down into
a real SPI register-access driver via `0x11830`/`0x11326`/`0x112e8`,
gated on a config struct at `0x200038fc` populated by a constructor at
`0x1129c`). `tools/unicorn/virtual_link.py` **deliberately does not model
any of this** — no LoRa/SPI hardware, no peripheral emulation — and
instead hooks at the application boundary immediately above it, on both
ends, exactly where `research/autopilot_static_inventory/rf-boundaries.md`
originally (statically) recommended:

```
Remote 0xba98/0xb680/0xc440          AutoPilot 0x8258 (dispatcher)
  real code builds the request         real code parses it, sets pending[N]
        | capture: stop at the               ^ deliver: seed the real RX
        | real TX wrapper's own               | packet buffer, run from the
        | entry, read its argument            | real dispatcher call site
        v register, dump the string           |
   [[ harness: exact bytes, no radio ]] ------+

AutoPilot 0x9268 (event dispatcher)          Remote 0xba98/0xb59c/0xc440
  real code builds the response          real code copies it into its own
        | capture, same technique,            capture buffer / parses it
        v AutoPilot's 0x8c10 or 0x7f84        ^ deliver: seed the real RX
   [[ harness: exact bytes, no radio ]] ------+ ring buffer + write pointer,
                                                run with driver-layer calls
                                                stubbed
```

Two reusable primitives carry every transaction: `capture_tx_bytes` (run
real firmware from an entry point until it reaches a `void
wrapper(char*)`-convention TX call, entered fresh so the wrapper's own
body never runs, and return exactly the NUL-terminated bytes handed to
it — two real Unicorn runs, one to discover the argument address, one to
dump it) and `deliver_and_observe` (seed a firmware's real RX state —
packet buffer, or ring buffer plus read/write pointers — with bytes
captured from the other side, run its real code, return an observed
memory range). A third, `capture_tx_byte`, was added for AutoPilot's
other TX calling convention (`0x7f84`, byte passed by value in R0, not a
pointer). All three are thin wrappers around `tools/unicorn/run_concrete.py`
invoked as a subprocess — no new emulation code path.

**Evidence tier**: `&|`->`V01R39`, `G`->`#`, and `S`->`P...` are all
closed at the **concrete (Unicorn, level 2)** tier, end to end, real
unmodified code on both sides, every payload byte observed rather than
hardcoded (only the RF-boundary *addresses* are constants in
`virtual_link.py`). The **solver-confirmed (level 3, Crucible/What4/Z3)**
tier is reached only for individual pieces at single-block granularity
(the four character checks in the table above, and the isolated
`0x8266` gate branch) — no transaction has a solver-confirmed
whole-function proof; see the tooling-limitation section below for why.

## Evidence

**AutoPilot addresses**: dispatcher entry `0x8258`/`0x8259`; real caller
`0x8a34 -> 0x8259` (inside `FUN_00008960`, RX buffer `0x2000232a`, buffer
byte read at `0x20001fd4`); binary-frame gate `0x8260`/`0x8266`
(`cmp r3,#0xf0` / `bne 0x82c6`) and `0x82c6`/`0x82c8` (`cmp r3,#0xe0` /
`bne 0x8368`); binary-frame loop `0x827e`-`0x82c4` (table base
`0x20000180`, callees `0x5274`/`0x5448`, shared callee `FUN_00004d18`
writing `0x200030c8`); `&` check/handler `0x888c`/`0x8890`
(`pending[5]`, base `0x200025bc`); `G` check/handler `0x83b2`/`0x83b6`;
`!` check/handler `0x87b2`/`0x87b6`; `S` check/handler `0x87be`/`0x87c2`;
outbound dispatcher `0x9268`; TX hooks `0x8c10` (`void wrapper(char*)`)
and `0x7f84` (`void wrapper(char)`); version-string writer `FUN_00004328`
-> `0x20003134`; startup call order `FUN_0000cd90 -> FUN_00009464 -> ...
-> FUN_00004328`, main loop `FUN_000093fc -> FUN_00009268 /
FUN_00008960`; `G` handler internals (`0x8548`/`0x8550` guards,
`pending[17]` at `0x200025bc+0x11`, helpers `0xb258`/`0xb216` and
`0x4b64`/`0x9768`/`0xe648`); `S` handler internals (mode byte
`0x20002524`, `value0` at `0x200025ad`, `pending[6]` at `0x200025c2`,
response buffer `0x20002548`, `itoa_and_comma` at `FUN_00004644`,
sub-select flags `0x2000252e`/`0x2000312c`/`0x200030dc`, extended fields
`0x20002530`/`0x20003100`).

**Remote (mando) addresses**: `0xba98` (`&|` query: drain via `0xb4f8`/
`0x583c`, preamble `0x5a14`, send via literal `0xbb04 -> 0x1c7ec`
(`"&|\0"`), TX call at `0xbab0`/entry `0xbaaa`, response capture at
`0xbb10 -> 0x200002fc`, 7-byte collection loop `0xbac0`-`0xbafe`,
post-request `0x5a50`); `0x58a8` (Remote TX wrapper, `void
wrapper(char*)`, shared calling convention with AutoPilot's `0x8c10`);
`0xb440`/`0xb4f8`/`0x583c` (LoRa receive poll / bytes-available / byte
read, RX ring buffer `0x20001773`, read pointer `0x200017d7`, write
pointer `0x200017d8` — cross-consistent across three independent
literal-pool reads); `0xb680` (`G` request builder: `buf[0]='G'`,
`param_2+'0'`, `param_1+'0'`, sequence digit, `'|'`) and `0xb59c` (send/
retry loop: send at `0xb5ca`, timestamp `0x2000276c`, ring-buffer base/
read-pointer literal pool at `0xb678`/`0xb67c` -> `0x20001773`/
`0x200017d7`, accept path `0xb602`, shared tail `0xb60e`, retry-exhausted
at `0xb638`, wake-flag `0xb66c -> 0x20000fc8`, G-buffer `0x2000183c`);
`0xc440` (combined `S`/`!` routine: request string `0xc660 -> 0x1c58c`
(`"S|\0"`), unconditional preamble `0x5a14`, parse loop `0xc4dc`-`0xc55e`
with `'P'`/`'N'` checks at `0xc4f8`/`0xc508`, decimal-field parser
`0xb51c`, stored-state guard at `0xc524`/`0xc528`, extended-form select
at `0xc530`/`0xc53a`, stored state `0x200018e7`, value1 `0x20002688`,
bool `0x20002671`); LoRa/SPI driver chain `0xb440 -> 0x11830 ->
0x11326`/`0x112e8`, config struct `0x200038fc`, constructor `0x1129c`.

**Solver-confirmed ASCII dispatch values** (single-block `mkParsedBlockCFG`
queries, R3 symbolic): `&`=`0x26`, `G`=`0x47`, `!`=`0x21`, `S`=`0x53`.

**Captured frames, per transaction** (all concrete, Unicorn):

- `&|` -> `V01R39`: Remote `0xba98` -> `0x58a8` with `b'&|\x00'`;
  AutoPilot `0x8258` sets `pending[5]=0x01`; AutoPilot `0x9268` -> `0x8c10`
  with `b'V01R39\x00'`; Remote `0xba98` collection loop captures
  `b'V01R39\x00'` at `0x200002fc`.
- `G -> #`: Remote `0xb680`/`0xb59c` -> `0x58a8` with `b'G000|\x00'`
  (first-request sequence digit is `'0'`, not `'1'` — v0.1's "1..9" cycle
  is accurate from the second request onward, since `0xb680` stores the
  pre-increment digit and cold RAM starts at 0); AutoPilot `0x8258` sets
  `pending[17]=0x01` (44 instructions, with `0xb258`/`0x4b64` stubbed);
  AutoPilot `0x9268` -> `0x7f84` with `R0=0x23` (`'#'`, 57 instructions);
  Remote `0xb59c` retry/ack loop, given ack byte `0x23`, returns `R4=1`
  (accepted, 59 instructions).
- `S -> P...`, two forms: Remote `0xc440(0)` -> `0x58a8` with
  `b'S|\x00'`; AutoPilot `0x8258` (mode=0) sets `pending[6]=0x01`,
  `value0=0x01` in 55 instructions, no stubbing needed; `0x9268 -> 0x8c10`
  with `b'P1,\x00'`; Remote `0xc440` parser stores `state=0x00`
  (unchanged — see guard below). Mode=4: `pending[6]=0x01`,
  `value0=0x0b`; `0x9268 -> 0x8c10` with `b'P11,0,0,\x00'`; Remote stores
  `state=0x0b, value1=0, bool=0x00`.

## The readonly-flash / Crucible limitation (tooling gap, not a firmware bug)

The whole-function Crucible replay of the `&` transaction (`app/Main.hs`
Test 0, `PH.runPacketTransaction`) hits a 300000-step abort, oscillating
through `0x827e`-`0x82c4` with `R6` climbing linearly — even though every
nominal input (entry `0x8259`, packet `[0x26, 0x01, 0x00, 0x00]`, all
other registers concretely zero) is identical to a concrete Unicorn run
that takes 46 instructions and never enters the loop. Three levels of
narrowing ruled out the obvious suspects before finding the real cause:

1. **Isolating the `0x8266` gate branch alone in Crucible**
   (`checkBranchModel` extended with `bqMemoryBytes` to seed memory, not
   just registers) reproduces the correct behavior exactly: `buffer[0]=
   0x26` -> `0x82c6` reachable (SAT, model `R3=0x26`), `0x8268`
   unreachable (UNSAT); `buffer[0]=0xF0` -> the reverse. (A real bug was
   found and fixed *in this new test itself* along the way: with `SP`
   left symbolic, the block's own `push {r4..lr}` could alias and
   overwrite the seeded buffer byte before the `CMP` ran — fixed by
   seeding `SP` concretely, the same convention the whole-function
   harness already used.)
2. **`mkFunCFG`'s entry wiring** was confirmed to land on the right
   physical address (`discoveredFunAddr fn == 0x8259`, address-matched,
   not just read) and its generic `ParsedBranch -> CR.Br` translation
   (`Data.Macaw.Symbolic.CrucGen`) is unremarkable library code with no
   project-specific defect.
3. **Fine-grained instrumentation of the actual whole-function run**
   (`RichTraceConfig`/`runPacketTransactionTraced`, a new `ExecutionFeature`
   using the existing `Data.Macaw.Symbolic.Regs.simStateRegs` and
   `MS.lookupReg` APIs, firing every step in a range rather than every
   2000) found the real divergence: `buffer[0]` is concretely `0x26` when
   read directly off the live memory global, **but the block's own R3
   (loaded through the dispatcher's own `LDR`/`LDRB` chain) never
   resolves to a concrete literal** — `printSymExpr` shows an unfolded
   multi-line `let` expression instead of `0x26:[8]`. At `0x8268` (the
   binary-frame path), execution has already taken the wrong successor.

**Root cause**: the dispatcher's buffer pointer is loaded from a literal
pool in flash (`LDR R4, [0x8528]`), and `Data.Macaw.Symbolic.Memory.
populateSegmentChunk` represents **readonly memory** (flash, unconditionally,
regardless of `ConcreteMutable`/`SymbolicMutable`) by asserting equality
to the solver rather than baking it into the backing array as a literal —
a documented, deliberate tradeoff ("directly updating the array... has
been crashing solvers"). A **solver query** (like the isolated
`checkBranchModel` test above) sees the assumption set and resolves
everything correctly. **Plain Crucible execution stepping through an
ordinary `Br` statement has no solver in the loop** and needs the branch
condition to already be a concrete `Pred`; given a non-concrete R4/R3/Z-flag,
Crucible falls back to picking a side — the wrong one for this input —
rather than computing the answer. This fully explains both the
reproduced symptom and the original historical one (`R4` becoming
symbolic partway through is exactly the sliding buffer pointer computed
from this same non-concrete base).

**Status: root cause documented, fix deliberately deferred.** This is
not Macaw's decode (byte-identical to Ghidra's), not `mkFunCFG`'s entry
or branch wiring (both confirmed correct), and not the branch's own
logic (isolated and correct given concrete inputs) — it is a gap in how
the whole-function harness's memory model interacts with plain,
non-solver-mediated execution. The AutoPilot milestone this was blocking
closed at the concrete (Unicorn) evidence tier without needing it fixed.
**Do not implement a general fix** (no baking all of flash into
literals, no `populateSegmentChunk` redesign). If a future symbolic use
case genuinely needs a whole-function proof through a literal-pool-derived
branch, the narrowest fix is baking the *specific* literal-pool words
that target reads as direct concrete values — the same `CLM.doStore`/
`writeConcreteByte` pattern already used (and already proven to fold
cleanly) for seeding the packet buffer itself — applied in
`APTrace.ProtocolHarness`'s memory setup (or wherever `MSM.newGlobalMemory`/
`populateSegmentChunk` is invoked), not in Macaw's decoding or `mkFunCFG`.

## Test / repro

`tools/unicorn/virtual_link.py` runs all three closed transactions:

```sh
tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py        # &| -> V01R39 (M3)
tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py g      # G -> #        (M4)
tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py s      # S -> P...     (M4)
```

Each scenario drives `capture_tx_bytes`/`capture_tx_byte`/
`deliver_and_observe`, all thin wrappers around `run_concrete.py`
subprocess invocations — no persistent-session Unicorn mode exists, so
each leg is a separate process and running a second transaction means
calling the primitives again, not resuming state. Simplifications
carried by every scenario: AutoPilot's RX buffer and outbound scan-table/
count/timestamp are seeded directly rather than derived from the real
UART assembly loop or table-init code; Remote's radio poll, TX-wrapper
body, and SysTick delay are `--stub-call`-stubbed rather than executed
(both firmwares' real SPI/radio driver objects are only valid after real
startup, which every entry point here deliberately skips); Remote's
drain loops, preambles (`0x5a14`), and post-request routines (`0x5a50`)
are bypassed by entry-point choice, not exercised.

Two harness additions came out of this cluster and are reusable beyond
it: `run_concrete.py --watch`/`--watch-mem` (per-hit register/memory
capture without halting, needed for per-iteration loop traces) and
`run_concrete.py --stub-call HEXADDR` (installs a hook that sets `PC :=
LR` on reaching an address instead of executing its body — for real
`void`-returning functions whose internals a scenario doesn't depend on,
e.g. a radio poll or a driver-object virtual call through an
uninitialized pointer). The ARM Private Peripheral Bus
(`0xE0000000`-`0xE00FFFFF`: SysTick, NVIC, SCB) was also found unmapped
and is now mapped unconditionally as a zero-behavior stub, fixing any
firmware that touches SysTick (essentially all non-trivial Cortex-M
code) — a platform-completeness fix, not scenario-specific, applying to
both firmwares.

**Calling-convention bug fixed by this cluster**: the existing Crucible
"opaque function-call override" mechanism was clobbering AAPCS
callee-saved registers across an overridden call — since fixed (tracked
previously as `docs/project-status.md`'s "A real calling-convention bug,
fixed"; the Unicorn side's `--stub-call` is a from-scratch analog of the
same concept, added fresh for this cluster rather than inheriting the
bug, since it is a full PC-redirect rather than a register-clobbering
override).

Two real firmware behaviors worth flagging for anyone re-running this:
(1) `S`'s short response `"P1,"` does **not** update the Remote's stored
state on a genuinely cold device — `0xc440` has its own guard (`if
(value0 != 1 || stored_state > 6) store it`) that a fresh `stored_state
== 0` fails, silently dropping the `1`; this is real behavior, not a
harness artifact. (2) AutoPilot's `S`-mode extended-response condition
(`0x20002524 == 4`) and Remote's "extended if stored state becomes 10,
11, or 28" are the same design decision, not two independently-tuned
constants — case 4 of the mode switch is the only case that can produce
`value0 ∈ {10, 11, 28}`.

## Open items

- **`!` and `I` were never exercised through the virtual link** —
  deliberately paused after `S -> P...` to pivot toward hardware
  provenance (completing the SAMD51 motor-timer mapping started in
  `docs/investigations/boot-and-hardware-bringup.md`: TCC1/IRQ93/`0x60ec`
  toggling `PB22` is done; TC0/TC1/TC2's ISR/pin pairs are not). Still
  open, not abandoned — `0xc440` already contains the `!0|`/`!1|` path
  (Remote side), and `!`'s known 11-vs-10 field mismatch (below) awaits
  it.
- **Dormant-event reachability**: events 2, 3, 8, 9, 11, 12, 14 in the
  outbound dispatcher (`0x9268`) have no known trigger path traced yet —
  only 5, 6, and 17 have been concretely exercised by this cluster.
- **The event-7 11-vs-10 field mismatch**: flagged by prior static/
  solver work and not resolved here — not investigated in this cluster.
- **Remote-transmitted packets not in the dispatch tree**: the original
  v0.1 model's "important mismatches" (`MS|`, `MR|`, `MM|`, `N|`, `KK|`,
  `E1,...|`, bare `W|`, short `I9|`/`I1|`) remain unresolved by the
  corrected dispatcher model — newly plausible as reachable through a
  table-driven mechanism the character-comparison chain wouldn't show,
  but not confirmed either way.
- **`PN...`'s producer**: the Remote's `0xc440` parser fully implements
  the `PN` branch (`if stored_state in {9,10,11}: stored_state = 1`), but
  no AutoPilot build examined so far ever emits a second byte `'N'` from
  the `S` handler's switch (only cases 0-4 exist). A different AutoPilot
  firmware build/config could reach it without any Remote-side change —
  not this build.
- **Naming the TX path's real transport peripheral**: `0x8c10` (and
  Remote's `0x58a8`) dispatch through a runtime driver-object pointer
  that this cluster deliberately left unmodeled (real SPI/radio timing
  and register-level behavior). Which specific peripheral populates that
  pointer, and what real startup does to initialize it, is not yet
  named — the boundary is documented (`0x200038fc` config struct,
  constructor `0x1129c` on the Remote side) but not walked through.
