# Investigation: Isolating the `0x8258`-`0x8266` Gate Branch in Crucible

> **Update (2026-09-07)**: the "smallest next experiment" below (fine-
> grained whole-function tracing) was run and found the actual root
> cause — see
> [`docs/investigations/whole-function-trace-divergence.md`](whole-function-trace-divergence.md).
> Short version: it's not Macaw, `mkFunCFG`, or this branch's own logic
> (all confirmed correct here) — it's that literal-pool (readonly-flash)
> reads are represented via solver assumptions rather than folded
> literals, so this branch's condition never becomes concrete during
> plain Crucible execution, and Crucible picks the wrong side for this
> input.

**Question**: [`dispatcher-loop-concrete-trace.md`](dispatcher-loop-concrete-trace.md)
found that Unicorn concretely takes the `buffer[0]!=0xF0` (skip-the-loop)
path at `0x8266`, while the whole-function Crucible replay was observed
stuck inside the `0x827e` loop with the *same nominal inputs*. Is the bug
in Macaw's decoding/lifting of this branch, or in Crucible's handling of
it? Per [`docs/tooling/tool-selection.md`](../tooling/tool-selection.md),
this uses the *existing single-block* Crucible machinery
(`APTrace.SymbolicRunner.checkBranchModel`) to test the block in isolation,
with the same concrete state Unicorn used.

**Scope**: AutoPilot firmware only. No Remote/mando work. Did not
re-investigate `R6`, `0x5274`, or `0x5448` (settled in prior docs).

## Method: extending the existing single-block machinery, not inventing a new one

`checkBranchModel`/`BranchQuery` could previously only seed *registers* to
concrete pointer values (`bqPointerOverrides`) — it had no way to seed
*memory content*, which this block's `buffer[0]` load needs (the buffer
address is loaded from a literal pool, not passed as an argument). Added
one field, `bqMemoryBytes :: [(Word32, Word8)]`, applied via a small
`writeConcreteByte` helper (the same `CLM.doStore` pattern
`APTrace.ProtocolHarness.writeBuffer` already uses, kept local to avoid
cross-module coupling) — a minimal, targeted extension of the existing
tool, not a new one. All 8 pre-existing `BranchQuery` call sites in
`app/Main.hs` were updated with `bqMemoryBytes = []` (no behavior change
for them).

## 1-2. What Macaw decoded, and its IR for the load/compare/branch

The function's entry block (`Map.lookup entry (fn ^. MD.parsedBlocks)` —
the same block both `mkParsedBlockCFG` *and* `mkFunCFG` read from the same
`DiscoveryFunInfo`) covers exactly `0x8258`-`0x8266`, decoded as:

```
0x8258: STMDB_T1   push {r4,r5,r6,r7,r8,r9,r10,lr}
0x825c: LDR_l_T1   r4  = [0x8528]           ; literal pool: buffer address 0x2000232a
0x825e: LDRB_i_T1  r3  = [r4, #0]           ; buffer[0]
0x8260: CMP_i_T1   r3, #0xf0
0x8262: MOV_r_T1   r6  = r0
0x8264: MOV_r_T1   r5  = r4
0x8266: B_T1 (cond) branch to 0x82c6 if not-equal, else fall through to 0x8268
```

This matches [`dispatcher-loop-concrete-trace.md`](dispatcher-loop-concrete-trace.md)'s
Ghidra/Unicorn-derived disassembly exactly — no discrepancy between Macaw's
and Ghidra's decode of these bytes.

Macaw's lifted IR for the branch (via `PP.pretty` on the `ParsedBlock`,
existing API, no manual flag derivation) computes each NZCV flag bit
explicitly from the `CMP`'s subtraction, then the terminator:

```
r3223 := (eq r3170 (0x1 :: [1]))      -- r3170 = PSTATE_Z (the zero flag)
branch r3223 0x8268 0x82c6
```

i.e. **"if Z==1 (buffer[0]==0xF0), go to 0x8268 (enter the loop);
otherwise go to 0x82c6 (skip it)."** Querying the block's own
`pblockTermStmt` directly (existing `MDP.ParsedTermStmt` API — no string
parsing) confirms the same structure at the typed level:

```
Decoded terminator: ParsedBranch
  condition : r3223
  trueAddr  : 0x8268
  falseAddr : 0x82c6
```

**This is exactly the semantics real hardware implements** (per the
concrete trace) — Macaw's lift of this specific instruction pair is
correct.

## 3-4. Isolated Crucible result, for `buffer[0]=0x26` and the `0xF0` control

**First attempt found a real bug — in this new test, not in Macaw or
Crucible.** Seeding only `bqMemoryBytes = [(bufAddr, 0x26)]` (no register
overrides) initially reported *both* `0x82c6` and `0x8268` as "reachable,"
with nonsense models for the observed register (`R3 = 0x1`, `R3 = 0xf0` —
neither matching the seeded `0x26`). Printing the raw symbolic expression
for the observed register (`WI.printSymExpr`, existing What4 API) showed
why: this block's *first* instruction is `push {r4,...,lr}`, which writes
to `[SP-32..SP-1]` — and with `SP` left as the default fresh-symbolic value
(`checkBranchModel`'s usual convention for anything not explicitly
overridden), **the solver was free to choose `SP` so that one of the eight
push-target addresses aliased `0x2000232a` and overwrote the seeded byte**
with a fresh register's low byte before the `CMP` ever ran. This is a
soundness gap specific to testing a block whose *own* semantics write
memory (most single-block queries in this project's history have queried
blocks with no memory writes, so it hadn't come up) — not a Macaw or
Crucible defect. Fixed by adding `AR.sp` to `bqPointerOverrides`, seeding
it to the top of RAM (the same convention `APTrace.ProtocolHarness` and
`tools/unicorn/run_concrete.py` already use).

**With `SP` and `buffer[0]` both concretely seeded, the isolated block
behaves exactly as expected:**

| Query | Seed | Target | Result |
|---|---|---|---|
| G1 | `buffer[0]=0x26` | `0x82c6` (skip-the-loop) | **SAT**, model `R3 = 0x26` |
| G2 | `buffer[0]=0x26` | `0x8268` (enter-the-loop) | **UNSAT** |
| G3 (control) | `buffer[0]=0xF0` | `0x82c6` | **UNSAT** |
| G4 (control) | `buffer[0]=0xF0` | `0x8268` | not run to completion (solver query in progress when this pass wrapped up), but forced **SAT** by exhaustiveness — G1-G3 already prove the branch is a total, mutually-exclusive function of `buffer[0]` alone, so `0xF0`'s only remaining possibility is `0x8268` |

**Conclusion: isolated Crucible execution of this exact block is
correct.** Given identical concrete inputs, it reproduces precisely what
Unicorn found concretely and what the real hardware does. **Macaw's
decoding/lifting and Crucible's single-block branch-translation machinery
are both exonerated for this block.**

## Comparing against `mkFunCFG`: entry alignment and branch translation

Per the task's request to inspect whether `mkFunCFG` really starts at the
physical entry we expect: read `Data.Macaw.Symbolic.mkFunRegCFG`'s source
(`external/macaw/symbolic/src/Data/Macaw/Symbolic.hs`). Its entry
mechanism is two lines: build a synthetic init block that loads the input
registers, then `addTermStmt $ CR.Jump (parsedBlockLabel blockLabelMap
entryAddr)` where `entryAddr = M.discoveredFunAddr fn` — i.e. it
mechanically jumps to whatever address the caller told Macaw's discovery
was the function's entry. `app/Main.hs` also now prints this directly:

```
discoveredFunAddr fn = 0x8259  (our resolved entry = 0x8259, match: True)
```

**This rules out "the whole-function CFG's entry doesn't correspond to
physical `0x8258`"** — confirmed both by reading the generic library code
(not project-specific, used by every macaw-symbolic consumer) and by this
concrete address comparison.

Also read `addMacawParsedTermStmt`'s handling of `M.ParsedBranch` in
`Data.Macaw.Symbolic.CrucGen` (the function `mkFunRegCFG` calls for every
non-entry block, unlike `mkParsedBlockCFG`, which instead converts the
terminator to a `Return` via `termStmtToReturn` — a different code path
from the one whole-function execution uses for the *same* `ParsedBranch`
value):

```haskell
M.ParsedBranch regs c trueAddr falseAddr -> do
  setMachineRegs =<< createRegStruct regs
  crucCond <- valueToCrucible c
  let tlbl = parsedBlockLabel blockLabelMap trueAddr
  let flbl = parsedBlockLabel blockLabelMap falseAddr
  addTermStmt $! CR.Br crucCond tlbl flbl
```

Generic, straightforward, and — like `mkFunRegCFG`'s entry jump — not
project-specific code with an obvious defect. Given the isolated test
proves the underlying `ParsedBranch` (`cond`/`trueAddr`/`falseAddr`) is
itself correct, and this translation of it into a Crucible `Br` is
textbook, **this specific mechanism is not a plausible location for the
bug either** (though it was read, not independently tested in isolation —
see "Open follow-up" below).

Finally, checked whether `APTrace.ProtocolHarness.runPacketTransaction`
(the whole-function harness) has the *same* symbolic-SP hazard this
investigation found in its own new single-block test: it does not — it
already allocates a real stack and sets `SP` concretely
(`CLM.doMalloc ... "aptrace_stack"`, `initSP <- CLM.ptrAdd ...`) before
building the initial register struct. **This specific hazard is already
absent in the whole-function harness.**

## Where the fault is: before or after `mkFunCFG`?

**Neither of the two "before mkFunCFG" candidates (bad discovery/decode,
bad `ParsedBranch` extraction) nor the obvious "after mkFunCFG" candidate
(bad entry-block wiring) checked out.** The isolated block's own semantics
are proven correct, `mkFunCFG`'s entry jump is proven correct by
construction and confirmed address-matched, and the generic
`ParsedBranch`-to-`Br` translation is unremarkable, well-tested library
code. The whole-function harness's own stack setup is also fine.

**This means the fault, if it is a fault in APTrace's code or a Macaw/
Crucible library defect rather than a mis-run test, is specific to
something about the whole-function *execution* that this pass's static
reading and isolated-block test can't see** — most plausibly something
analogous to the aliasing hazard found and fixed here, but located
somewhere else in the ~339-block whole-function graph (a different
symbolic pointer this investigation didn't seed, in a *different* block
along the real path, not the gate block itself).

## Smallest next experiment (not run in this pass)

Re-run the actual whole-function test (`app/Main.hs`'s "Test 0" /
`PH.runPacketTransaction`) with **much finer-grained tracing** than
`debugFeature`'s current default (every 2000 steps — far too coarse to see
where within the first few blocks execution actually diverges). Print
every step for at least the first ~2000-5000 steps, or add a one-off
`--verbose-until N` style cap, and directly observe whether execution ever
visits `0x8266`/`0x82c6` before ending up in the loop, or whether it
diverges even earlier. This is the concrete follow-up the source-code
reading above couldn't substitute for — everything in this pass narrowed
*where to look* (an aliasing-style hazard elsewhere in the whole-function
graph, not the gate block's own logic or the generic CFG-construction
machinery) without pinpointing the exact block. Do not modify the Crucible
model itself until this trace is in hand.

## Open follow-up

- `CR.Br`'s Crucible-level execution (as opposed to `ParsedBranch`'s
  Macaw-level correctness, verified here) was read, not independently
  tested — a `mkBlocksCFG`/multi-block isolated test of just `{gate block,
  0x82c6 block}` (two real blocks wired together, bypassing the other 337)
  would test this specific translation path empirically rather than by
  code reading, if the finer-grained whole-function trace above doesn't
  find the answer directly.
