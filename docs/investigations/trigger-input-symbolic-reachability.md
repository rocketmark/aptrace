# Investigation: Symbolic Reachability of the Bounded PB05 Trigger Path

**Question**: use Macaw to independently check the bounded CFG from
`phase_ramp_state_machine__CUSTOM`'s real entry (`0x8e18`) through the
PB05 decisions and the config-reload write at `0x8f98`; model the region
in Crucible/What4; ask Z3 what reaches active `"T..."` reporting and what
reaches `0x8f98`; trace the real provenance of the two previously-
unresolved gate cells; replay any solver witness with `ConcreteMachine`.

**Scope**: Macaw discovery (`aptrace explore`), a new, purpose-built
Crucible/What4/Z3 harness path (`aptrace trigger`, this slice's own
addition to `app/Main.hs` and `src/APTrace/ProtocolHarness.hs`), and
`ConcreteMachine` (Unicorn) replay. Builds directly on
`trigger-input-concrete-path.md` and `research/workflows/trigger-input.yaml`
(both updated). No fresh Ghidra project; no Macaw/Crucible source patch —
every workaround below is a harness-side, disclosed accommodation of a
real, precisely-diagnosed tool limitation.

## Result, in one paragraph

**Goal 1 (Macaw cross-check) found a real, systematic Macaw limitation**:
every `CBZ_T1`/`CBNZ_T1` (narrow compare-and-branch) instruction in this
function fails Macaw's branch classifier ("IP is not a mux" — its ASL
lifting produces a semantically-correct but doubly-nested mux this
classifier's pattern match doesn't recognize), confirmed exhaustively
(4/4 classify failures in the whole function are this exact instruction).
This blocks automatic whole-function discovery from `0x8e18` past the
first such branch. **Worked around, not patched**: since each CBZ's two
real successor addresses are already independently proven (disassembly
+ the prior slice's concrete execution), Macaw discovery was re-seeded
directly at each successor (`0x9203` — the TR0/disarmed four-way gate;
`0x91a3` — the TR1/armed reporting continuation), both cleanly
discovered with no classify failures over the addresses this query
touches. **Goal 4 (gate-cell provenance) is fully closed, and better
than the task's own success bar** ("provenance-closed, or one precise
remaining edge") **— both cells are real, protocol/state-reachable, not
synthetic**: gate cell 1 (`0x20001b38`) is set to exactly `0x7b` by the
**already-known `'+'` command's `mode=0x62` bulk-push finalize path**
(the same `FUN_00004ca8`/`FUN_000043f0` chain `bulk-push-trigger-
provenance.md` already proved fires on boot/reconnect); gate cell 2
(`0x200000d8`) is set to exactly `9` by a real "all four channels idle"
check inside this same function, and — a clean, previously-unknown
finding — **is unconditionally reset to `0` by the config-reload
function itself** (`FUN_00006b50`, reached via `0x8f98`'s own tail-jump),
a genuine self-clearing mechanism. **Goal 5 (Unicorn replay) is
complete**: entering at the sound entry point (`0x8e18`, zero fabricated
`r4`-`r11`) with the real provenance-traced gate values (`0x7b`, `9`)
concretely seeded, `0x8f98` is reached (status byte becomes `3`) when
PB05 reads low and is *not* reached (status byte stays `0`) when PB05
reads high — both branches concretely confirmed — and a second,
independent Unicorn run entering directly at the config-reload
function's own real start confirms it clears gate cell 2 to `0`.
**The Crucible/What4/Z3 SAT query itself, in both its fully-symbolic
and narrowed (gate cells concrete, only PB05 free) forms, did not
converge within a practical session time budget** (killed after 17+ and
~9 minutes respectively) — a genuine, reportable cost finding about this
harness configuration for multi-instruction runs, not a correctness gap
or an exposed ambiguity. **A follow-up made this observable rather than
guessed at further**: a minimal solver-logging path added to the harness
(Part 6) shows the narrowed query is a **41MB, 267,385-assertion**
SMT-LIB2 formula with only **2 real free variables** — `~73.5%` of the
assertions (196,615) are the *entire RAM region* individually asserted
`== 0` byte by byte, a uniform fact that could be one constant-array
assertion instead; the rest is the flash image's own content, similarly
baked in byte-by-byte. The actual query logic is a few dozen terms. Per
instruction, this was observed, not yet optimized.

## Classification (per this slice's own required scheme)

| Question | Status |
|---|---|
| Gate cell 1 = `0x7b` is firmware-reachable | **firmware-reachable (provenance)** — real `'+'` mode=0x62 producer, disassembly-confirmed |
| Gate cell 2 = `9` is firmware-reachable | **firmware-reachable (provenance)** — real all-idle-channels producer, disassembly-confirmed |
| Gate cell 2 is reset to `0` by the config reload | **firmware-reachable (provenance) + Unicorn-replayed** |
| PB05 low reaches `0x8f98` (given the real gate values) | **Unicorn-replayed** (concrete, both polarities) |
| PB05 high does *not* reach `0x8f98` | **Unicorn-replayed** (concrete) |
| The bounded region (`0x8e18` onward) is a valid, classify-failure-free Crucible target once re-seeded past each CBZ | **solver-model-built** (Macaw discovery + `mkFunCFG` succeed in ~10-20ms; execution reaches the target address) — but **not solver-confirmed**: the SAT query itself did not terminate |
| "What reaches `0x8f98`" / "what reaches active `T...` reporting", asked of Z3 directly | **attempted, not solver-satisfiable within budget** — explicitly not promoted to a solver-confirmed finding |

No solver witness was ever produced, so none was promoted to
firmware-reachable on the solver's own authority — the firmware-reachable
claims above rest entirely on direct Ghidra provenance tracing and
Unicorn replay, per this slice's own instruction not to promote a solver
witness (there wasn't one) past what its provenance actually supports.

---

## Part 1 — Macaw cross-check: an exhaustive, real classifier limitation

`aptrace explore ... 0x8e19` (Thumb-bit-set entry, matching this
project's established `resolveEntry` convention) discovers `"function
target @ 0x8e19"` as one large, ~11,800-line pretty-printed CFG with
**zero translation errors** and **exactly four classify failures**, each
confirmed by disassembly to be a `CBZ_T1` instruction:

| Address | Real instruction (Ghidra) | Role |
|---|---|---|
| `0x8e4e` | `cbz r3,0x8e58` | inside the per-channel loop's mode==1 handling |
| `0x6dd4` | `cbz r6,...` | inside an unrelated helper reached from the loop |
| `0x90ba` | `cbz r3,...` | inside the mode==0 extended handling |
| `0x91a0` | `cbz r3,0x9202` | **the TR-enable check gating the whole trigger-poll region** |

Example Macaw IR at `0x91a0` (the one this slice's own query needed to
cross):

```
r133197 := (eq r133195 (0x0 :: [8]))
r133199 := (mux r133197 (0x9202) (0x91a0))
r133200 := (mux r133197 r133199 (0x91a2))
classify failure
  IP is not a mux
  Pattern match failure in 'do' block at src/Data/Macaw/ARM/Identify.hs:141:3-15
  Branch: True branch value r133199 is not a valid address.
  ...
  Call: Call classifier failed.
```

The two nested muxes are semantically correct and reduce to exactly
`r3==0 -> 0x9202, else -> 0x91a2` — matching Ghidra's `cbz r3,0x9202`
exactly — but Macaw's classifier (`Data.Macaw.ARM.Identify`) only
pattern-matches a *single* mux over two concrete addresses, not this
doubly-nested (redundant, but real) shape its own CBZ lifting produces.
**This is a genuine Macaw/dismantle-ARM limitation for the `CBZ_T1`/
`CBNZ_T1` instruction family specifically** — not a Ghidra disagreement
(Ghidra's disassembly, and the prior slice's concrete Unicorn execution,
already independently and exactly establish both successor addresses)
and not evidence of anything wrong with the underlying values.

**Two workarounds were tried; one works, one doesn't, and both are
recorded as real findings**:

1. **Seeding the tail-jump target (`0x6e4c`) as a second, simultaneous
   known-function entry, hoping Macaw's tail-call classifier would then
   recognize `pop {r4-r11,lr}; b.w 0x6e4c` as a call rather than
   inlining it.** Does **not** work: Macaw classifies a direct `B.W` by
   its own instruction form (an ordinary intra-function jump)
   regardless of whether the target is independently known as a
   function; the known-function heuristic only applies to *indirect*
   jump/call classification. Confirmed by testing directly (`0x8f98`'s
   own block is still inlined into the caller's CFG).
2. **Re-seeding Macaw discovery directly at each CBZ's own already-known
   successor address** (`0x9203`, `0x91a3`) instead of trying to cross
   the CBZ automatically. **Works**: both re-seeded regions discover the
   exact blocks this query needs (`0x9202`-`0x9244`, `0x8f98`, and
   `0x91a2`-`0x9238`) cleanly, with only two further classify failures
   in each — both confirmed to be *downstream* of this query's own
   observable, inside the shared config-reload continuation (one a
   second `CBZ_T1` inside that unrelated code, one a genuine
   `Data.Macaw.Discovery.Classifier` "expected stack height of 0"
   artifact of re-entering mid-function without the real caller's own
   stack-height bookkeeping — an expected, disclosed consequence of the
   synthetic re-entry point, not a new tool bug).

---

## Part 2 — Building the bounded Crucible/What4 model

### Tooling additions (disclosed, minimal, mirroring existing patterns)

`src/APTrace/ProtocolHarness.hs`'s `runPacketTransactionTraced` gained
two parameters, both following `APTrace.SymbolicRunner.BranchQuery`'s
own existing conventions:

- **`regOverrides :: [(AR.ARMReg (MT.BVType 32), W.Word32)]`** — seed
  specific registers to known real addresses *after* IP/SP are set,
  before the run starts. Used here for `r5`/`r6` (the per-channel
  device-state array base and the TR-enable byte's own address) at the
  `0x9203` entry — both real, disassembly-confirmed literal-pool loads
  at that exact point, not fabricated.
- **`stopAtAddr :: Maybe W.Word32`** — the first time execution reaches
  this PC, answer the same reachability question the function's own
  return would normally trigger, using the real path condition
  accumulated so far, and **keep that answer even if the run is later
  killed by an exception** (e.g. `MissingSemanticsForT32Instruction
  VSTMDB_T1` — a real ARM VFP/NEON instruction downstream, inside the
  config-reload continuation, that this Macaw version's semantics table
  has no lifting for at all, and this query never needed to reach). This
  is sound specifically because `0x8f98`'s own write has a *unique*,
  non-re-merged predecessor structure within each re-seeded sub-region —
  documented explicitly in the code as a precondition, not a general
  license to stop anywhere.

**A real bug found and fixed in the same pass**: the original
"is the observed byte concrete" check assumed `anySymbolic == False`
(no symbolic buffer bytes) implied a concrete result. **This is false**
once opaque calls are involved: a branch gated on an opaque `millis()`/
`digitalRead()` return can leave a *downstream* memory value
represented as an ITE over that call's fresh symbolic result, with zero
buffer bytes of the caller's own involved. Found by Query B initially
reporting `HarnessError "expected a concrete result but got a symbolic
one"` despite seeding nothing symbolic at all. Fixed by always
attempting `WI.asBV` first and falling back to the solver check either
way, in both the stop-address feature and the end-of-run path — strictly
more correct, and it made the pre-existing "no symbolic bytes" fast path
faster on top for the common case (still tries the cheap concrete read
first).

### Discovering both blocks, and mapping the block-granularity subtlety

Both `0x9203` and `0x91a3` discover cleanly (Part 1). A real-trace run
(`RichTraceConfig`) found a genuinely useful, previously-undocumented
fact about this harness: **Crucible/macaw-symbolic's own location
tracking is per discovered-Macaw-*block*, not per-ARM-instruction** — an
address mid-block (e.g. `0x8f9e`, the instruction right after the real
write at `0x8f9c`) never registers as a distinct `stateLocation`, so a
`stopAtAddr` set there never fires. The fix is mechanical once known:
target the *next real block-start address* instead (`0x8fa4` for the
`0x8f98` write; `0x91ce`, right after the `bl digitalRead` call returns,
for the `"T"` write at `0x91c4`) — confirmed empirically via the trace,
and now documented here for any future harness use of `stopAtAddr`.

---

## Part 3 — Gate-cell provenance, closed

### Gate cell 1 (`0x20001b38` = `0x7b`): the real `'+'` mode=0x62 finalize path

Exhaustive xref search (cached export) found exactly two real writers.
The live one:

```asm
0x8140  ldr r3,[r6,#0]
0x8142  cmp r3,#0x62        ; '+' mode == 0x62 (98) -- the already-known
0x8144  bne 0x815c          ;   bulk-push mode, bulk-push-trigger-provenance.md
0x8146  bl 0x4b24           ; (per-record apply, x4 channels)
...
0x815c  ldr r3,[r6,#0]
0x815e  cmp r3,#0x32        ; > 50 -- the already-known compute+persist threshold
0x8160  ble 0x81de
0x8162  bl 0x4ca8           ; target = start + delta  (already-known '+' chain)
...
0x817a  bl 0x43f0           ; persist the whole struct (already-known '+' chain)
0x817e  movs r2,#0x7b
...
0x818e  str r2,[r3,#0]      ; *0x20001b38 = 0x7b
```

**This is the exact, already-documented `'+'` command's `mode=0x62`
bulk-push finalize path** (`FUN_00004ca8`/`FUN_000043f0`,
`command-inventory.md`'s own `'+'` row, `plus-target-distance-
roundtrip.md`/`bulk-push-trigger-provenance.md`'s own proof that this
path fires for real on Remote boot and on reconnect) — not a new or
obscure mechanism. Gate cell 1 becoming `0x7b` is a **direct, real
side effect of the same bulk-push event this project has already
concretely proven happens on every Remote power-on.** A second reader
(not writer), `ascii_dispatcher__CUSTOM` at `0x8612`, checks the same
cell against the same value as a precondition for a *different* command
handler entirely — a real, additional consumer, not chased further
(out of this slice's scope).

### Gate cell 2 (`0x200000d8`): a real multi-valued status code, self-clearing

Exhaustive xref search found **three writers, all inside functions
already reached from this same investigation**:

| Writer | Value written | Real condition |
|---|---|---|
| `tc0_isr_completion__CUSTOM` (`0x5b1a`) | `1` | a per-channel timer-completion byte equals `9` (an unrelated per-channel state code, not this cell) |
| `FUN_00005fac` (`0x6044`) | `1` | a structurally similar per-channel completion check |
| `phase_ramp_state_machine__CUSTOM` (`0x9088`) | **`9`** | **the real precondition for this query**: all four channels pass a two-part per-channel idle check (`0x9062`-`0x9082`) inside the same function's own "mode==0 extended" handling |
| `phase_ramp_state_machine__CUSTOM` (`0x9104`) | `2` | a different, related idle-adjacent condition in the same handler |
| `FUN_00006b50` (config-reload, `0x6b60`) | **`0`** | **unconditional**, right at that function's own real entry |

Gate cell 2 reaching `9` is therefore also **firmware-reachable via a
real predecessor state**: all four motor channels being idle
simultaneously, checked inside this exact function. And — found while
tracing this — **the config-reload function `0x8f98` itself triggers
unconditionally resets gate cell 2 back to `0`**, a genuine, real
self-clearing mechanism: once the reload fires, the same idle-channel
precondition can't immediately re-fire from the same state, without a
fresh "all channels idle" event re-establishing it.

**Neither cell's exact value is a synthetic assumption.** Both were
disclosed as concrete seeds in the Unicorn replay below *because* their
real producers are now identified and disassembly-confirmed — the same
tier of disclosure this project already uses for e.g. a real GPIO input
level or a prior command's already-proven RAM effect.

---

## Part 4 — Unicorn replay, both PB05 polarities, plus the self-clear

Entering at the sound entry point (`0x8e18`, per `trigger-input-
concrete-path.md`'s own established convention — zero fabricated
`r4`-`r11`), with `*0x20001fc0=2` (PA02-low/digital mode, the real
concretely-confirmed boot output), `*0x20003120=0` (`TR0`, disarmed —
the default), and the two gate cells seeded to their real, provenance-
traced values (`0x20001b38=0x7b`, `0x200000d8=9`):

```
PB05 = LOW  -> *(0x200025bc+1) becomes 3 (0x8f98 REACHED)
               then: unmapped memory access at 0x00000004
               (the ALREADY-KNOWN, unrelated config_loader__CUSTOM
                lazy-init boundary from target-config-provenance.md --
                not a new gap, and downstream of this query's own
                observable)
PB05 = HIGH -> *(0x200025bc+1) stays 0 (0x8f98 NOT reached)
               run completes normally
```

A second, independent Unicorn run, entering directly at the
config-reload function's own real, declared start (`0x6b50` — the
smallest sound boundary for checking *this* function's own effect,
sidestepping the unrelated lazy-init crash deeper inside the same
function), with gate cell 2 disclosed-seeded to its real pre-reload
value (`9`):

```
entry 0x6b50, *0x200000d8 = 9 (disclosed, real pre-reload value)
  -> after reaching 0x6b68 (just past the real write at 0x6b60):
     *0x200000d8 = 0
```

**This concretely confirms, end to end (across two runs bridging the
one already-known, unrelated lazy-init gap, not a new discontinuity this
slice introduced): PB05 low reaches the config-reload write; PB05 high
does not; and the reload itself clears gate cell 2 to `0`.**

---

## Part 5 — Why the solver query itself did not converge

Two variants were run, both via the same `aptrace trigger` harness:

1. **Fully symbolic**: both gate cells symbolic (5 bytes total), `r5`/
   `r6` seeded, entry `0x9203`, stop at `0x8fa4`. Killed after **17+
   minutes** (Z3 online process, steady ~99% CPU, memory climbing to
   ~370MB — genuinely computing, not hung).
2. **Narrowed, per instruction**: both gate cells seeded **concrete**
   (`0x7b`, `9`), leaving **only PB05** (via the existing opaque-call
   override on `bl digitalRead`) free. Same entry/stop. Killed after
   **~9 minutes**, memory climbing past **1.2GB**.

**The second result is itself the useful finding**: removing 5 symbolic
bytes and leaving only 1 truly free variable did **not** meaingfully
change the query's tractability. This rules out "too many symbolic
bytes" as the cause and points instead at something structural to this
harness configuration for a *multi-instruction* run — plausibly the
`ConcreteMutable`/`SymbolicMutable` memory model representing every
memory access (concrete or not) as a genuine array-theory `select`/
`store` term, combined with the `useNonlinearArithmetic`/
`useSymbolicArrays` problem features this project's `withZ3Backend`
enables unconditionally (`SymbolicRunner.hs`/`ProtocolHarness.hs`,
inherited from before this slice) forcing a harder decision procedure
than the query's own logic actually needs. **Not chased further this
slice**, per explicit instruction once the narrowed query also failed
to converge quickly and exposed no ambiguity to resolve — a precise,
bounded item for a future tooling slice (see "Remaining bounded
unknowns"), not a correctness gap in anything reported above.

**mkFunCFG itself is fast** (10-20ms) for both entries in both variants
— the bottleneck is specifically the online-solver SAT check, not
Macaw's lifting or Crucible's own CFG construction.

---

## Part 6 — Making the problem observable: the query is ~267K assertions, ~73% of them redundant

**Follow-up to Part 5**: rather than continue tuning blind, a minimal,
disclosed observability path was added to
`src/APTrace/ProtocolHarness.hs` (`runPacketTransactionTraced` gained an
optional `solverLogPath :: Maybe FilePath` parameter) so the exact
SMT-LIB2 this harness sends Z3 could be inspected directly, per instruction, with **no change to the query's own semantics**. Two artifacts are written when a path is given:

1. A **standalone `.standalone.smt2`** file (`What4.Solver.Z3.writeZ3SMT2File`, asserting exactly `[assumptions, reachedPred]`) — written *before* the solver is even started, so it's available regardless of whether the online check ever converges.
2. An **incremental `.interaction.smt2`** log (`WPO.startSolverProcess`'s own, pre-existing but previously always-`Nothing` log-handle argument) — the literal, real-time SMT-LIB2 traffic to and from Z3.

Re-running the narrowed query (Part 5's second variant — both gate cells
concrete, only PB05 symbolic) with logging enabled:

| Artifact | Size |
|---|---|
| `aptrace_trigger_A.stop.standalone.smt2` | **41,260,653 bytes** (~41.3 MB), 802,222 lines |
| `aptrace_trigger_A.stop.interaction.smt2` | grew to **44,202,597 bytes** (~44.2 MB) before the run was stopped — Z3 had received essentially the whole formula (the final `check-sat-assuming` had just been sent) after roughly a minute, meaning a real share of the elapsed time in Part 5 was construction/serialization/parsing of this payload, not "the search" in isolation |

**Structure, counted directly from the standalone file**:

| Command | Count |
|---|---|
| `(assert ...)` | **267,385** |
| `(define-fun ...)` | 534,810 |
| `(declare-fun ...)` | **2** — `globalMemoryBytes` (the whole-address-space byte array) and `opaque_r0` (PB05's `digitalRead` result) |

**The two `declare-fun`s confirm the narrowing (Part 5) worked exactly
as intended**: this query has exactly **one genuine free variable**.
Everything else is concrete. And yet it produces 267K assertions,
because of how that concreteness gets encoded:

```
(define-fun x!0 () (_ BitVec 8) (select globalMemoryBytes (_ bv16384 32)))
(define-fun x!1 () Bool (= (_ bv0 8) x!0))
(assert x!1)
(define-fun x!2 () (_ BitVec 8) (select globalMemoryBytes (_ bv16385 32)))
(define-fun x!3 () Bool (= (_ bv0 8) x!2))
(assert x!3)
... (one such pair per byte, address by address) ...
```

**Breaking down the 267,385 assertions by address range** (grepping the
literal `bv<addr> 32` terms directly):

- **196,615 assertions** (**~73.5% of the total**) are addresses in
  `0x20000000`-`0x2002FFFF` — the **entire RAM region**, matching
  `ramSize = 0x30000` almost exactly. **Every single one asserts the
  same thing: `globalMemoryBytes[addr] == 0`.** This is the single most
  "obviously large/repetitive" pattern in the formula: a uniformly-zero
  192KB region, individually asserted one byte at a time instead of as
  one constant-array fact.
- **~70,770 assertions** are addresses in the flash range (from
  `0x4000` upward) — the *actually varying* firmware image content,
  asserted byte-by-byte for (apparently) the whole loaded image or a
  large prefix of it, not just the bytes this specific execution path
  touches.

**This confirms and meaningfully extends this project's own already-documented "Known limitation: readonly flash and plain Crucible
execution"** (`docs/tooling/tool-selection.md`): that note names only
flash's `populateSegmentChunk` behavior. **This session's logging shows
the identical per-byte-assertion treatment also applies to the entire
RAM region** (`ConcreteMutable`, not readonly) — previously undocumented,
and, by raw assertion count, the *larger* of the two contributions
(196,615 vs. ~70,770).

**The actual query logic, once found (the file's tail), is tiny and
clean** — roughly 40-50 `define-fun`s implementing the real address
computation, the `store` for the write at `0x8f98`, and the final
observed-byte equality check:

```
(define-fun x!534805 () (_ BitVec 32) (concat x!534803 x!534804))   ; reconstruct the pointer
(define-fun x!534806 () (_ BitVec 32) (bvadd x!534805 (_ bv1 32)))  ; +1 (the status byte's own offset)
(define-fun x!534807 () (Array ...) (store x!534760 x!534806 (_ bv3 8)))  ; the real write
(define-fun x!534808 () (_ BitVec 8) (select x!534807 (_ bv536880573 32)))
(define-fun x!534809 () Bool (= (_ bv3 8) x!534808))
(assert x!534809)
(check-sat)
```

**Conclusion**: the query Z3 is actually being asked is small and
simple (one free 32-bit variable, a handful of real operations). The
41MB/267K-assertion size is **overwhelmingly encoding overhead** — a
known Macaw-symbolic memory-model tradeoff (baking concrete regions in
as individual equalities rather than constant-array literals,
specifically to avoid a different, previously-worse solver failure mode
— see `tool-selection.md`'s own note on *why* this tradeoff exists) —
applied here to two *entire* address regions (all of RAM, and apparently
most/all of flash) rather than only the handful of bytes this specific
bounded query actually reads. **Not fixed this pass, per instruction**
("do not change the semantics of the query yet") — this is the
precise, now-quantified starting point for an actual optimization
attempt (e.g., only populating the byte ranges the discovered CFG can
actually reach, or a narrower memory model for regions never touched by
this particular sub-function).

**Follow-up, 2026-09-09**: the RAM half of this was fixed and measured —
see [`docs/tooling/compact-ram-initialization.md`](../tooling/compact-ram-initialization.md).
On this exact query, the fix drops the standalone SMT-LIB2 file from
41.3MB/267,385 asserts to 10.8MB/70,775 asserts (RAM's own per-byte
assertions eliminated entirely) and the online Z3 check now *converges*
(367.7s) instead of needing to be killed — but to `unknown`, not a
reachability answer, so **no claim in this document changes**: no solver
witness existed before that fix and none exists after it either. Flash's
own per-byte assertions (the remaining ~70,775) are untouched.

Query B's own logging was not captured this pass (the process was
stopped, per instruction not to over-invest, before reaching it) — the
identical root cause applies structurally, since both queries build
their memory the same way (`MSM.newGlobalMemory (Proxy @ARM.AArch32) bak
LDL.LittleEndian MSM.ConcreteMutable mem`, the same `mem` object, same
code path).

---

## Confidence table

| Item | Status |
|---|---|
| Macaw's `CBZ_T1`/`CBNZ_T1` branch classifier fails on this instruction family | **CONFIRMED** (4/4 occurrences in the function, all independently disassembly-cross-checked) |
| Seeding a tail-jump's target as a known function entry does not change Macaw's direct-jump classification | **CONFIRMED** (tested directly) |
| Re-seeding discovery at each CBZ's own known successor works and is classify-failure-clean over this query's own addresses | **CONFIRMED** |
| Gate cell 1 = `0x7b` via the real `'+'` mode=0x62 finalize path | **CONFIRMED** (disassembly, reusing this project's own already-proven `'+'` bulk-push mechanism) |
| Gate cell 2 = `9` via a real all-4-channel-idle check; = `0` via the config-reload's own unconditional write | **CONFIRMED** (disassembly) |
| PB05 low reaches `0x8f98`; PB05 high does not (given the real gate values) | **CONFIRMED concretely** (Unicorn, both polarities, sound entry) |
| The config-reload function clears gate cell 2 to `0` | **CONFIRMED concretely** (Unicorn, sound entry into that function's own real start) |
| Crucible/What4/Z3 SAT-confirms any of the above | **NOT ACHIEVED** — both the fully-symbolic and narrowed queries failed to converge within a practical time budget; not promoted to solver-confirmed |
| The `regOverrides`/`stopAtAddr` harness additions are sound for the specific structural case used here (unique, non-remerged predecessor to the stop address) | **CONFIRMED** by construction and cross-checked against a rich-trace run |

## Remaining bounded unknowns

1. **CLOSED, precisely, by Part 6; the RAM half fixed 2026-09-09**: why
   the query doesn't converge even with only one free variable is no
   longer a mystery — it's a ~41MB/267,385-assertion formula, ~73.5% of
   which (196,615 assertions) is the entire RAM region individually
   asserted `== 0` byte by byte (a uniform fact expressible as one
   constant-array assertion), plus ~70,770 more for the flash image's own
   content, dwarfing the actual query logic (~40-50 terms). The RAM half
   is now fixed and measured — see
   [`docs/tooling/compact-ram-initialization.md`](../tooling/compact-ram-initialization.md):
   the formula drops to 10.8MB/70,775 asserts and the query itself now
   converges (367.7s, to `unknown` — still not a reachability answer, so
   no claim above changes). **What remains, narrower still**: flash's own
   per-byte population (out of this fix's scope), and why the compact
   encoding's `forall`-quantified array term yields `unknown` rather than
   a decided result (hypothesized, not confirmed, in that same note).
2. The two classify failures found *inside* each re-seeded region (both
   downstream of this query's own observable, inside the shared
   config-reload continuation) were not further diagnosed — named,
   not chased, since neither blocks anything this slice needed.
3. `ascii_dispatcher__CUSTOM`'s own read of gate cell 1 (`0x8612`, a
   different command's own precondition check) was not traced to that
   command's identity — out of this slice's scope.

## Evidence level

Level 1 (static, disassembly-confirmed, cross-checked by the cached
xref export) for both gate cells' full provenance and the Macaw
classifier diagnosis. Level 2 (concrete, Unicorn) for the full
PB05-dependent reachability result and the config-reload's self-clear.
No level-3 (solver-confirmed) claim is made anywhere in this document —
the solver was tried, twice, and is reported as not having converged,
per this slice's own explicit instruction not to promote a witness that
was never produced.
