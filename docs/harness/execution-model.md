# Harness Execution Model

How APTrace actually drives Crucible/What4/Z3 against lifted Macaw IR — the
reusable mechanisms, not any one experiment's results. See
[`docs/harness/symbolic-execution-results.md`](symbolic-execution-results.md)
and [`docs/harness/protocol-harness-results.md`](protocol-harness-results.md)
for the experiments that use these mechanisms.

## Two execution granularities

### Single block (`APTrace.SymbolicRunner.checkBranchModel`)

Translates exactly one Macaw `ParsedBlock` via `mkParsedBlockCFG`, which
turns the block's own terminator into a Crucible return. This is the
**safe default** for any block that might be part of a loop or a large
call graph: since execution never proceeds past the one block, there is no
risk of running into an unrelated infinite loop or unbounded call chain
elsewhere in the same function.

- Optionally seed one or more registers to concrete values
  (`bqPointerOverrides`); everything else starts fresh/symbolic.
- Ask whether a given target PC value is reachable, and if so, get a
  solver-produced model for one named "observe" register.
- Memory is `SymbolicMutable` (all RAM/MMIO is symbolic) — appropriate when
  you're asking "what memory content reaches this outcome," but see the
  soundness note below.

**Soundness caveat**: because every register not explicitly overridden is
free, a single-block query can be satisfied by an unrelated free variable
rather than the one you think you're testing — this is exactly what
happened when the `0x827e` loop-body block was queried in isolation (see
[`docs/harness/protocol-harness-results.md`](protocol-harness-results.md)):
the solver's answer looked like it depended on the packet buffer, but a
whole-function test with the same concrete buffer value proved it didn't.
**Cross-check single-block results against a whole-function run before
trusting them as a statement about real program behavior**, especially when
several registers are left free.

### Whole function (`APTrace.ProtocolHarness.runPacketTransaction`)

Translates an entire Macaw `DiscoveryFunInfo` via `mkFunCFG`. Needed when
the question depends on real control flow across multiple blocks (e.g. "does
writing this packet into the real buffer, then running the unmodified
parser, set this pending-event byte?").

Requirements this mode needs that single-block mode doesn't:
- A real stack (the function may push/pop registers) — a small malloc'd,
  zero-filled region.
- `ConcreteMutable` memory (not `SymbolicMutable`) as the base, so anything
  you don't explicitly make symbolic — like the pending-event array — starts
  at a *known* value. This matters for soundness: if that array were
  symbolic too, "did it become 1" could be satisfied by guessing a favorable
  initial value instead of by the code actually writing it.
- A policy for calls the function makes to other, not-yet-lifted functions
  (see next section).

## Function calls: the opaque-call mechanism, and its calling-convention bug

`mkFunCFG` only lifts one function; any `BL` to another address needs a
`MS.LookupFunctionHandle` callback to supply a Crucible function handle for
the simulator to actually call.

**Current implementation**: a single "opaque call" handle, returned for
every call regardless of target. Its override:

1. Reads the incoming register struct.
2. Produces fresh symbolic values for the AAPCS **caller-saved** registers
   only: R0-R3 and R12.
3. **Preserves every other register from the incoming struct unchanged** —
   in particular R4-R11 and SP, which a real ARM function call is not
   permitted to clobber.
4. Performs no memory writes at all.

**This was not the original implementation, and the original version had a
real bug**: it substituted fresh symbolic values for *every* register,
including R4-R11. A loop that keeps its counter or a table pointer in one of
those registers across a call — a completely ordinary and correct thing for
compiled code to do — would have that state silently destroyed on every
call, corrupting its own control flow. This produced a hang that looked like
firmware complexity but was actually a harness bug. Fixed by rewriting the
override to only touch the genuinely caller-saved set, via `MS.updateReg`
applied selectively rather than a blanket fresh-register-struct. **Any
future opaque-call mechanism must preserve this property** — if you're
tempted to "simplify" by clobbering everything again, don't; it silently
breaks any callee that relies on ordinary register preservation, which is
most compiled code.

**Known remaining limitation**: because the opaque call never performs
memory writes, any real callee whose side effects other code depends on
(e.g. marking a data structure updated) cannot be faithfully modeled this
way. This is the current, understood cause of the whole-function replay not
terminating for the AutoPilot dispatcher — see
[`docs/project-status.md`](../project-status.md). The architecturally
correct fix — not yet implemented — is to make `LookupFunctionHandle`'s
callback *lazily build and register a real Crucible CFG* for the actual
callee (looked up by address in the already-discovered function map, which
`cfgFromAddrs` already computed as part of the same call graph) instead of
always returning the one opaque handle. This is a supported
macaw-symbolic/Crucible pattern (the callback is explicitly allowed to
return an updated `CrucibleState` with new handles registered), not a
missing capability.

## Diagnostics: the step-tracing execution feature

`APTrace.ProtocolHarness.debugFeature` is a custom
`Lang.Crucible.Simulator.EvalStmt.ExecutionFeature` that, every N simulator
steps, logs the currently-visited program location (and, in ad hoc uses,
specific register values) to stderr, and can force-abort after a step cap.

**This is a supported, reusable diagnostic, not a one-off debugging hack.**
It is what turned two otherwise-opaque hangs into legible findings:

1. The R4-R11 clobbering bug above (visible as the loop counter jumping to
   arbitrary values instead of incrementing).
2. The realization that the whole-function loop's non-termination doesn't
   depend on packet content (visible as identical step-count growth for two
   different concrete packet values).

**Use it whenever a whole-function run doesn't terminate as expected**,
before spending time on manual instruction-level analysis. Pattern:

```haskell
stepCounter <- newIORef (0 :: Int)
execRes <- CS.executeCrucible [debugFeature stepCounter] initState
```

Print frequency and the abort threshold are currently hardcoded in the
function (every 2000 steps, abort past 300000) — adjust inline for a given
investigation rather than trying to generalize prematurely.

## Solver setup

Both execution modes use a hand-rolled Z3 online-solver backend
(`withZ3Backend` in both `SymbolicRunner.hs` and `ProtocolHarness.hs` —
currently duplicated; consider factoring out if a third consumer appears).
This mirrors `Data.Macaw.Refinement.Solver`'s Z3 case, which could not be
imported directly because it's an internal (`other-modules`) definition in
the `macaw-refinement` package, and depending on that package pulls in
unwanted x86/PPC/RISC-V builds. See
[`docs/harness/symbolic-execution-results.md`](symbolic-execution-results.md)
for how this was found.
