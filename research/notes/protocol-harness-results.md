# Protocol Harness Results — `aptrace protocol` (roadmap M2/M3)

Follow-up to [protocol-harness-roadmap.md](protocol-harness-roadmap.md). This is the
first concrete execution of that roadmap: seed the AutoPilot inbound packet dispatcher
directly, model its input as controlled/symbolic, and ask What4/Z3 for the byte values
that reach specific command-scheduling code -- cross-checked against
`research/autopilot_static_inventory/`'s independently-derived command table.

## Setup

- `aptrace protocol firmware_autopilot868.bin`
- Entry seeded directly at Thumb address `0x8259` (flash `0x8258`), per the static
  inventory's `functions-of-interest.md` naming this as "Main inbound packet
  parser/dispatcher."
- Macaw discovery from that one seed reaches **339 blocks / 57 callees** -- Macaw
  follows real control flow, not the human notion of "one function," and this dispatcher
  is apparently merged (via plain jumps, not calls) with a lot of surrounding code.

## Important correction to the static inventory's model

`research/autopilot_static_inventory/parser-dispatch.md` models the dispatcher as a
flat if/else-if chain on the packet's leading byte(s). **That is not what the compiled
entry sequence actually does.** Seeding discovery at `0x8259` and running the *whole*
merged function via `Data.Macaw.Symbolic.mkFunCFG` (with a from-scratch memory/register
setup: concrete-zero RAM, all registers concrete-zero except SP/PC) reliably hangs.

Diagnosis process (see below for the technique, which is reusable): added timing
instrumentation and a custom Crucible `ExecutionFeature` that logs the visited program
location every 2000 simulator steps. This showed:

- `mkFunCFG` translation itself is fast (~0.08s for 339 blocks) -- the hang is in
  *execution*, not translation.
- Execution cycles indefinitely through a tight block of addresses (`0x827e`-`0x82c4`),
  occasionally reaching `0x83ec` (a real, correctly-classified function `return`) and then
  *looping back* rather than actually terminating -- i.e. this address range is visited
  repeatedly across what looks like multiple "iterations."
- Reading the actual lifted IR for that range: it is **not** a character comparison at
  all. It loads a byte from `[R5+1]`, computes an index from bytes at `[R4+6..9]`, and
  does an indexed load `[R7 + R0*4]` compared against another loaded value -- the shape of
  a **hash-table or lookup-table probe** (compute a key, index into a table, compare,
  advance to the next slot on mismatch), not a linear string of `CMP`+branch pairs.
- Because `R4`-`R7` were defaulted to concrete zero (no established initial value), the
  table-probe reads near-null memory and its exit condition never becomes true --
  hence the infinite loop. This is an artifact of not yet knowing how the compiler set up
  those registers before reaching this code, not a bug in Macaw or Crucible.

**Open question for a future pass**: trace backward from `0x827e` to find where
`R4`/`R5`/`R6`/`R7` are established (a real table base pointer, bucket count, etc.), so the
*whole* dispatcher can eventually be run end-to-end. Filed as a refinement of roadmap M3.

## Working technique (what actually succeeded)

Rather than running the whole merged function, target **one specific block already known
by inspection** to implement a single character check, using the exact same
single-block techniform proven safe and fast in `symbolic-execution-results.md`
(`Data.Macaw.Symbolic.mkParsedBlockCFG` via `APTrace.SymbolicRunner.checkBranchModel`,
which turns the block's own terminator into a Crucible return -- no risk of running into
the loop above, since we never execute past this one block).

For each single-character top-level command, the pattern is: find the block whose IR is
`CMP R3, #<ascii>` followed by a conditional branch (grep the already-discovered
function's pretty-printed IR for `CMP_i_T1 ... Rn 3, imm8 <n>`), confirm by inspection
which branch target is the "matched" handler vs. the "keep checking" fallthrough, then
run `checkBranchModel` with R3 left symbolic (or seeded concretely, for a sanity check)
and ask whether the handler address is a reachable value of the ending PC -- extracting a
model of R3 on success.

`checkBranchModel` here seeds **R3 directly** rather than writing a packet buffer in
memory (contrast with `symbolic-execution-results.md`'s MMIO demo, where the *address*
being read was the interesting symbolic value). This is justified because block `0x888c`
(and the equivalent blocks for other commands) is confirmed by direct inspection to
already assume "R3 holds the packet's first byte" as its precondition -- however that got
established upstream (the still-unresolved hash-lookup mechanism above). Once the
backward trace above is done, this could be replaced by genuinely modeling the packet
buffer as memory and letting the real entry code populate R3, closing the gap.

## Results

| Command | Check block | Handler block | Z3 model for R3 | Matches ASCII? |
|---|---|---|---|---|
| `&` | `0x888c` | `0x8890` (writes `pending[5]=1` then returns -- confirmed by inspection, see `symbolic-execution-results.md`-style reading) | `0x26` | yes (`'&'` = 0x26) |
| `&` fallthrough | `0x888c` | `0x889e` (continues to next check) | `0x0` | any non-`0x26` value is valid; solver picked `0x0` |
| `G` | `0x83b2` | `0x83b6` | `0x47` | yes (`'G'` = 0x47) |
| `!` | `0x87b2` | `0x87b6` | `0x21` | yes (`'!'` = 0x21) |
| `S` | `0x87be` | `0x87c2` | `0x53` | yes (`'S'` = 0x53) |

Every value was **derived by the solver**, not hand-fed -- `checkBranchModel` only knows
"is address X reachable," and asks Z3 to produce a witness. All four match the ASCII
values `research/autopilot_static_inventory/commands.md` independently assigned to these
commands from separate static reading, which is a strong cross-validation of that
inventory's command-letter claims (though not yet of what each handler actually *does*,
beyond `&`, which was independently confirmed to write `pending[5]=1`).

Solver cost varies noticeably per query (tens of seconds each for the `&`/`G`/`!`/`S`
checks -- the `CMP` instruction's full NZCV flag computation produces a sizeable
nonlinear-bitvector formula per branch), so `aptrace protocol`'s full run takes a few
minutes; each individual `checkBranchModel` call remains a clean, bounded query with no
risk of the hang described above.

## Follow-up session: tracing the caller, R4-R7, and the whole-function attempt

Per direct instruction, went back to fully trace the caller/state setup into
`0x8258` and understand the `0x827e`-`0x82c4` indexed-lookup loop, then tried
again to run a real in-memory `&|` packet through the *whole* dispatcher
function (not just the isolated `0x888c` block).

### Root-cause diagnosis of the original hang: a real bug, now fixed

Added a custom Crucible `ExecutionFeature` (`APTrace.ProtocolHarness.debugFeature`)
that logs the visited program location every N steps -- this is the key
reusable technique: it turns an opaque hang into a visible "stuck cycling
through addresses X, Y, Z" trace. Using it, plus register-value logging
inside the opaque-call override, found the actual bug:

**The original opaque-call override clobbered *every* register on every call,
including R4-R11 -- registers a real ARM (AAPCS) function call is not allowed
to touch (only R0-R3, R12, and the condition flags are caller-saved/undefined
after a call).** The loop at `0x827e` keeps its own counter in R6 and a table
pointer in R4; clobbering them on every one of its two calls-per-iteration
corrupted the loop's own control state. This has nothing to do with the
firmware's real behavior -- it was purely an artifact of an over-eager
"conservative" approximation. Fixed by rewriting the override to only
substitute fresh values for R0-R3/R12 via `MS.updateReg`, preserving
everything else from the incoming register struct. Confirmed fixed by
direct observation: R6 now increments cleanly (0, 0, 1, 1, 2, 2, ...) across
calls instead of jumping to arbitrary fresh values.

### Caller trace: found the real call site, and a Macaw discovery anomaly

Seeding discovery at `0x8a35` (LoRa RX area) reaches `0x8259` as a properly
call-classified function (`call and return to 0x8259` at flash `0x8a34`),
confirming: R4 = R5 = the packet buffer pointer (`0x2000232a`, loaded via
`LDR [0x8528]`), R6 = R0 (the caller's argument, `MOV R6, R0` at `0x8262`),
R7 = a fixed literal (`0x20000180`, loaded via `LDR [0x8534]`).

Tracing *what sets R0* led to `0x8a1b -> 0x896a -> BL 0x801c -> CBZ R0`.
**`0x801c` is lifted by Macaw as ARM (A32) mode code** (`BL_i_A1`, `BX_A1`,
`PSTATE_T => 0`) -- which is architecturally impossible on a Cortex-M4
(M-profile has no ARM execution state at all). Its second block (`0x8020`)
hits a Macaw discovery "classify failure" on an indirect `BX R11`. This is
either a genuine Macaw/dismantle decode edge case for this call site, or
this specific path is dead/unreachable code on real hardware; either way, it
means **R0's "correct" value cannot be reliably derived from this trace**.
Not investigated further -- out of scope for this pass, but worth flagging
upstream or revisiting.

### The `0x827e` loop's real dependency: not the packet, not R0 either

With the calling-convention bug fixed, re-ran the whole-function test with a
real `&`-command packet. It still does not terminate (confirmed via the same
step-tracing technique: R6 grows linearly and unboundedly, R4 becomes
symbolic partway through). Ruled out packet content as the cause by directly
testing two different concrete values for `buffer[1]` (`0x7c` and `0x01`,
the latter a value the single-block solver confirmed reaches the loop's exit
block `0x83ec` when queried in isolation) -- **both produce identical,
non-terminating behavior**. This proves the loop's true termination does not
depend on the packet buffer content the way the block-level probe suggested
(that probe's result was likely an artifact of R0-R3 and the condition flags
still being free/symbolic in that isolated single-block query, letting the
solver "cheat" via an unrelated free variable rather than genuinely
reflecting the whole-function dependency).

**Current leading hypothesis**: the loop's real per-iteration state includes
memory, not just registers -- specifically, `0x5274`/`0x5448` (per-channel
"motor state" functions per `research/autopilot_static_inventory/
functions-of-interest.md`) are called once per iteration and very plausibly
*write* to the per-channel table this loop scans (e.g. marking a channel
processed). Our opaque-call override has *zero* memory side effects, so if
the real exit condition depends on such a write, it can never be satisfied
under this approximation -- a modeling gap, not evidence of a real infinite
loop in the firmware.

**The architecturally correct fix, not yet implemented**: rather than
stubbing `0x5274`/`0x5448` opaquely, use `MS.LookupFunctionHandle`'s support
for *lazily building and registering a real Crucible CFG* for the actual
callee (looking it up in the full discovered-function map, which `cfgFromAddrs`
already has as part of the same 57-function call graph) instead of an opaque
override -- letting these functions genuinely execute and produce real memory
effects. This is a real, well-supported Crucible/macaw-symbolic mechanism, not
a missing tool; it just requires more implementation (extracting the call
target from the incoming PC, resolving it against both possible discovery-key
parities, caching one handle per callee, and threading the updated
`CrucibleState` back through the lookup callback).

### Where the working, solver-verified evidence stands

The single-block results from the first pass of this session remain valid and
unaffected by any of the above (they never depended on the `0x827e` loop or
on opaque-call memory effects): `&`, `G`, `!`, `S` all solver-confirmed to
require exactly their ASCII byte value at R3 to reach their respective
event-scheduling handler blocks. What is *not yet* demonstrated is the fully
faithful "real packet bytes in memory, run the unmodified whole function,
observe `pending[5]`" version -- that is blocked on the memory-side-effect
modeling gap above.

## Next steps (per protocol-harness-roadmap.md)

1. Resolve the `R4`-`R7` hash-lookup setup so the *whole* dispatcher (or at least the
   full character-dispatch mechanism) can be run end-to-end, closing the "however it got
   there" gap above -- would also let us model the packet as real memory again.
2. Verify `G`/`!`/`S`'s handler blocks actually perform their claimed event-scheduling
   writes the same way `&`/`0x8890` was confirmed (currently only reachability of the
   handler *entry* is solver-verified for these three; the write itself was read
   statically from `research/autopilot_static_inventory/pending-writes.csv`, not
   independently confirmed via this harness yet).
3. Hook outbound transmission at `0x8c10`/`0x7f84` (per the user's instruction) rather
   than modeling LoRa/SPI -- not yet attempted.
4. Add the Remote (mando) firmware and connect the two TX/RX boundaries with an
   in-memory virtual RF queue -- not yet attempted; blocked on (1)-(3) first per the
   roadmap's suggested order.
