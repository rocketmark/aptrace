# Investigation: Locating the First Divergence in the Whole-Function `&` Replay

**Question**: [`gate-block-crucible-isolation.md`](gate-block-crucible-isolation.md)
proved the `0x8266` branch, Macaw's lift of it, and `mkFunCFG`'s entry/
branch-wiring are all correct in isolation. So why does the actual
whole-function replay still take the wrong path? This instruments the
*existing* whole-function harness directly (no bypassing it with manual
block-chaining) to find the first real state difference.

**Scope**: AutoPilot firmware only. No Remote/mando work. Did not revisit
`R6`/`0x5274`/`0x5448` (settled) or the gate branch's own correctness
(settled). **No execution-model changes made** — this is instrumentation
only, per the task's constraint.

## Reproduction check first

Before adding new instrumentation, confirmed the discrepancy still exists
under the *current* code (several harness fixes have landed since the
original "R6 grows unboundedly" observation, so this wasn't assumed).
Result: **it still reproduces, unchanged.** The current whole-function `&`
test (`app/Main.hs`'s "Test 0", `PH.runPacketTransaction`, same packet
`[0x26, 0x01, 0x00, 0x00]`) still hits the 300000-step abort, still
oscillating through `0x827e`-`0x82c4`, with the opaque-call diagnostic
showing `R6` climbing linearly (`6799 -> 6899 -> 6999 -> 7099 -> ...`) —
identical in character to the original symptom. No prior fix invalidated
it.

## Reusable addition: `RichTraceConfig` / `runPacketTransactionTraced`

`debugFeature`'s existing every-2000-steps sampling is far too coarse to
see which successor a specific branch took. Added (exported from
`APTrace.ProtocolHarness`, alongside the existing `runPacketTransaction`
which now just calls this with `Nothing`):

```haskell
data RichTraceConfig = RichTraceConfig
  { rtLoAddr   :: W.Word32
  , rtHiAddr   :: W.Word32
  , rtWatchMem :: Maybe W.Word32
  , rtMaxHits  :: Int   -- safety cap on recorded (not executed) hits
  }

runPacketTransactionTraced
  :: MM.Memory 32 -> MDS.DiscoveryFunInfo ARM.AArch32 ids
  -> W.Word32 -> [PacketByte] -> W.Word32 -> Integer
  -> Maybe RichTraceConfig -> IO PacketResult
```

Implemented as a new `ExecutionFeature`, `richTraceFeature`, using two
existing macaw-symbolic/Crucible APIs rather than any manual state
threading:

- `Data.Macaw.Symbolic.Regs.simStateRegs` — an **existing, exported**
  macaw-symbolic helper (`external/macaw/symbolic/src/Data/Macaw/Symbolic/Regs.hs`)
  that recovers the live `ArchRegStruct` from a running `SimState`. Exactly
  the "prefer existing APIs over manual derivation" tool for this job —
  not previously used anywhere in this codebase, but built for precisely
  this purpose.
- `MS.lookupReg` (already used throughout this codebase) to project R0-R7/
  SP out of that struct.
- `st ^. CSET.stateGlobals` + `CSG.lookupGlobal memVar` + the existing
  `CLM.doLoad`/`resolvedPointer` pattern to read one watched memory byte
  live, independent of the block's own computation of it (this
  independent read is what exposed the divergence — see below).

Fires on **every** step (not sampled) while the current PC is within
`[rtLoAddr, rtHiAddr]`, capped by `rtMaxHits` so a genuine in-range
infinite loop doesn't flood output. Reusable for any future investigation
needing a fine-grained trace of a bounded region, not tied to the
dispatcher.

Wired into `app/Main.hs`'s Test 0 with range `0x8258`-`0x8900` (entry
through past the `&` handler) and `rtWatchMem = Just bufAddr`.

## The trace, and the first divergence

```
#1-5   pc=0x8259  r0..r7=0x0  sp=0x1000  buffer[0]=0x26      -- entry, prologue
#6-8   pc=0x8267  r3=<sym: let -- aptrace:0x825d ...>         -- mid-CMP; R3 NOT concrete
#9     pc=0x8268  r3=<sym: let -- aptrace:0x825d ...>         -- >>> WRONG SUCCESSOR <<<
#10-19 pc=0x8272,0x8278,0x8274,...                             -- loop-setup / binary-frame code
...
(300000 steps later) stuck cycling 0x827e-0x82c4, R6 climbing linearly, abort
```

**`buffer[0]` is concretely `0x26`** — confirmed independently at every
hit via a direct `doLoad` on the live memory global (`buffer[0]=0x26`,
hits #1-5). **Yet the block's own computation of R3 (the same byte, read
via the dispatcher's own `LDR`/`LDRB` chain) never resolves to a concrete
literal** — `WI.printSymExpr` shows a multi-line, unfolded `let`
expression instead of `0x26:[8]`. At `0x8268` (hit #9), execution takes
the **binary-frame/loop path** — the branch this project has now proven
(twice) should only be taken when `buffer[0]==0xF0`.

**First point of divergence: the `0x8266`/`0x8267` branch itself, and
specifically that its condition value never reduces to a concrete
boolean during plain execution — not the buffer content, not any
register, not the CFG's control-flow wiring** (all independently
confirmed correct in `gate-block-crucible-isolation.md`).

## Why the condition doesn't fold: readonly memory is assumption-backed, not literal

The dispatcher's buffer pointer isn't a register argument — it's loaded
from a **literal pool in flash** (`LDR R4, [0x8528]`). Per
`Data.Macaw.Symbolic.Memory.populateSegmentChunk` (read in the prior
investigation), a memory chunk's initial content is baked into the
backing array as literals only when `conc_flag` is true, and:

```haskell
let (mut_flag, conc_flag) =
      case MMP.isReadonly (MC.segmentFlags seg) of
        True -> (CL.Immutable, True)
        False -> case mmc of
          MSMC.ConcreteMutable -> (CL.Mutable, True)
          MSMC.SymbolicMutable -> (CL.Mutable, False)
```

— readonly memory (flash, including this literal pool) always takes the
"assert equality to the solver" branch of `populateSegmentChunk`, **not**
the direct array-literal branch, regardless of `ConcreteMutable`/
`SymbolicMutable`. That's a documented, deliberate tradeoff (the comment
there: "directly updating the array... has been crashing solvers") — and
it's fine for a **solver query**, which sees the assumption set and
resolves everything correctly (exactly what
`APTrace.SymbolicRunner.checkBranchModel`'s single-block queries do, and
why the isolated gate-block test came back correct). **It is not fine for
plain Crucible execution stepping through an actual `Br` statement**,
which has no solver in the loop and needs the condition to already be a
concrete `Pred` to know deterministically which successor to take. Given
`R4` (from the literal-pool load) is represented as an unresolved,
assumption-backed expression rather than a literal, `R3` (loaded through
it) inherits the same non-concreteness, and so does the `CMP`'s Z flag and
the branch condition built from it — Crucible falls back to picking a
side (here, the wrong one for this input) rather than deterministically
computing the answer.

**This is a real architectural gap in how the whole-function harness's
memory model interacts with plain (non-solver-mediated) Crucible
execution — not a bug in Macaw's decode, not a bug in `mkFunCFG`'s
wiring, and not the buffer content being wrong.** It fully explains both
today's reproduction and the original historical symptom (`R6` growing
unboundedly, `R4` becoming symbolic partway through — `R4` is exactly the
sliding buffer pointer computed by repeatedly adding to this same
non-concrete base).

## Answering the reproduction-check questions directly

1. Does execution hit `0x8266`? **Yes** (as `0x8267`, the branch
   statement's position tag).
2. Which successor is taken? **`0x8268`** (binary/loop path) — the wrong
   one for `buffer[0]=0x26`.
3. Does it ever hit `0x827e`? **Yes**, repeatedly — confirmed both in this
   trace and via the `[opaque_call]` diagnostic's climbing `R6`.
4. Does it reach `0x8890`? **No.**
5. Does `pending[5]` become 1? **No** — the run never finishes.
6. Does the run terminate? **No** — hits the existing 300000-step abort.

## Narrowest likely cause

The literal-pool read that establishes the dispatcher's buffer pointer
(and, transitively, everything computed from it, including this branch's
condition) is represented via solver assumptions rather than folded
literals, because it lives in a `readonly` memory segment — a property of
`populateSegmentChunk` that applies regardless of the chosen
`MemoryModelContents` mode. Plain Crucible execution (no solver in the
loop for ordinary branch resolution) cannot resolve such a condition
deterministically and takes the wrong side for this input.

## Status: root cause documented, fix deliberately deferred

This is a **resolved investigation** — the divergence is fully explained
(above), not an open mystery. What remains is a decision already made
explicitly, not a TODO: **do not implement a general fix for the
readonly-flash/plain-Crucible gap** (no baking all of flash into
literals, no redesign of `populateSegmentChunk`). The AutoPilot milestone
this investigation was blocking has since been closed at the concrete
(Unicorn) evidence tier without needing this fixed — see
[`docs/investigations/tx-hook-verification.md`](tx-hook-verification.md)
and [`docs/project-status.md`](../project-status.md). Revisit this gap
only if a future symbolic (Crucible/What4/Z3) use case actually requires
a whole-function proof through a literal-pool-derived branch; at that
point, the narrowest fix is baking the *specific* literal-pool words that
target reads as direct concrete values (the same `CLM.doStore`/
`writeConcreteByte` pattern already used for the packet buffer and
already proven to fold cleanly) — not the general redesign.

Either way, the fix (if and when needed) belongs in
`APTrace.ProtocolHarness`'s memory setup (or in how
`MSM.newGlobalMemory`/`populateSegmentChunk` is invoked), not in Macaw's
decoding or `mkFunCFG`'s CFG construction — both remain exonerated.

## Completing the pending `0xF0` control query

[`gate-block-crucible-isolation.md`](gate-block-crucible-isolation.md)'s
G4 query (`buffer[0]=0xF0` reaching `0x8268`) was left running when that
pass wrapped up, logically forced `SAT` by exhaustiveness (G1-G3 already
prove the branch is a total, mutually-exclusive function of `buffer[0]`).
Not re-run here — per the task's guidance not to let it distract from the
higher-value whole-function divergence finding above, and it adds no new
information beyond what G1-G3 already established.
