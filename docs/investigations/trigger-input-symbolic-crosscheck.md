# Investigation: A Targeted Crucible/What4/Z3 Cross-Check of the Trigger Gate

**Question**: `trigger-input-symbolic-reachability.md`'s own whole-region
attempt (entering `phase_ramp_state_machine__CUSTOM`'s re-seeded
`0x9203` region and stopping deep inside it) did not converge to a
useful answer — the narrowed query returned `unknown` after 367s, and a
sibling query never converged at all. This slice does **not** retry that
approach. Instead: a deliberately small, targeted solver cross-check of
the *exact* trigger gate Unicorn has already concretely isolated
(`trigger-input-concrete-path.md`, `trigger-input-motion-causality.md`)
— asking Z3 to *independently derive* the same gate values Ghidra's
disassembly and Unicorn's concrete replay already established, rather
than re-attempting a whole-function proof.

**Scope**: Ghidra (`aptrace explore`) for the exact block structure;
`Data.Macaw`/Crucible/What4/Z3 via two small, narrowly-scoped Haskell
additions (`APTrace.ProtocolHarness.runGateReachability`, a
`BranchQuery`/`checkBranchModel` extension in `APTrace.SymbolicRunner`);
no Macaw patch, no readonly-flash redesign, no peripheral modeling. Does
not repeat or supersede the concrete Unicorn work — cross-checks it.

## Result, in one paragraph

**Full success — a real, converging, solver-confirmed cross-check of the
entire seven-guard gate, in 175 seconds total for all nine queries,**
compared to the prior whole-region attempt's 367s for one query that
still only returned `unknown`. **Query A** (positive reachability, all
seven guard values left genuinely free): **SAT**, with Z3 *independently
deriving* `r5[0]=0, r5[1]=0, r5[2]=0, r5[3]=0, state32=0x7b, state8=0x9,
r6[0]=0` — the exact values this project's own prior Ghidra provenance
tracing and Unicorn replay already established, not assumed into the
query. **Query B** (seven separate negative checks, one per guard,
`extraNotEqual` added as a genuine solver constraint rather than a
concrete substitution): **UNSAT for all seven** — no assignment of the
*other* six free variables can compensate for any one guard being
violated. **Query C** (the `digitalRead` return-value branch at `0x922c`,
`R0` fully symbolic): **SAT at `R0=0`**, and the *true* negative check
(`R0 != 0`, `R0` still otherwise fully symbolic — not a concrete
spot-check) is **UNSAT**: `0x8f98` is reachable from `0x922c` if and only
if `R0=0`. **All results agree exactly with the existing Unicorn
concrete findings** — no disagreement to reconcile, and neither backend
was adjusted to force agreement.

## Part 0 — Starting state and the build fix

Per instruction, the working tree was inspected first: `git status
--short` was clean (everything from the prior sessions already
committed — `git log` shows `results from first macaw testing`, `more
trigger port regression tests`, `more trigger port tests`), and `cabal
build aptrace` from `external/macaw` was already green (`regOverrides`,
the "narrow initial-register override capability" the task description
referenced, already exists in `APTrace.ProtocolHarness.runPacketTransactionTraced`,
with `foldM` already imported). No build error was found to fix in the
starting state — noted here for the record, since the task described one,
rather than silently proceeding as if nothing had been asked.

## Part 1 — Ghidra: the real block structure (not one block, not a loop)

`aptrace explore FIRMWARE.bin 0x4000 0x9203` (Thumb bit set, per
`FirmwareLoader.resolveEntry`'s own convention — using `0x9202` directly
produces bogus A32 decoding, exactly the failure mode this project has
already documented for other entries) shows the real instruction range
`0x9202`-`0x9228` is **seven chained Macaw blocks**, each ending in
exactly one comparison/branch, with **zero classify failures** anywhere
in this specific range (the `CBZ_T1`/`CBNZ_T1` classifier problem
`trigger-input-symbolic-reachability.md` found affects *other*
instructions in the same function, not this gate):

| Block | Instruction(s) | Terminator |
|---|---|---|
| `0x9202` | `ldrb r3,[r5,#0]; cbnz r3,0x9232` | `branch r5[0]==0 -> 0x9206 : 0x9232` |
| `0x9206` | `ldrb r3,[r5,#1]; cbnz r3,0x9232` | `branch r5[1]==0 -> 0x920a : 0x9232` |
| `0x920a` | `ldrb r3,[r5,#2]; cbnz r3,0x9232` | `branch r5[2]==0 -> 0x920e : 0x9232` |
| `0x920e` | `ldrb r3,[r5,#3]; cbnz r3,0x9232` | `branch r5[3]==0 -> 0x9212 : 0x9232` |
| `0x9212` | `ldr r3,[0x9260]; ldr r3,[r3]; cmp r3,#0x7b` | `branch ==0x7b -> 0x921a : 0x9232` |
| `0x921a` | `ldr r3,[0x9264]; ldrb r3,[r3]; cmp r3,#9` | `branch ==9 -> 0x9222 : 0x9232` |
| `0x9222` | `ldrb r3,[r6,#0]; cbnz r3,0x9232` | `branch r6[0]==0 -> 0x9226 : 0x9232` |
| `0x9226` | `movs r0,#0x39; bl 0xd3dc` | **`ParsedCall`**, target `0xd3dc`, return address `0x922c` |

**`0x9228` (the task's own requested `target`) is not a Macaw block-start
address** — it is the second instruction of the `0x9226` block, and
Crucible/macaw-symbolic's own location tracking is per discovered-block,
not per-instruction (`trigger-input-symbolic-reachability.md` Part 2
already established this for a different address in the same function).
**`0x9226` is therefore this project's own established proxy for "is
`0x9228` reached"**: it is a real block boundary, and reaching it means
the *entire* gate (all seven guards) has already been satisfied and
`movs r0,#0x39` — the sole instruction between the block start and
`0x9228` — has already executed unconditionally; nothing else can
intervene. Every query below targets `0x9226`, documented as exactly
this.

## Part 2 — the build fix, and the harness addition it needed

No build error existed to fix (Part 0). The real harness gap was
different: neither existing mechanism fit this query.
`APTrace.SymbolicRunner.checkBranchModel` only models **one** block
(this gate is seven chained blocks with no loop and no call *until* the
very end — safe to run as a small whole-CFG, unlike the general
whole-function case, but not a single block).
`APTrace.ProtocolHarness.runPacketTransactionTraced` **can** run a
small re-seeded multi-block region (exactly how it modeled this same
gate previously), but always pays for a RAM zero-initialization overlay
(`docs/tooling/compact-ram-initialization.md`) that this bounded query
has no use for — nothing here reads any RAM address other than the
seven guard cells, all seven of which are meant to be free anyway. That
overlay is the most likely cause of the prior slice's own non-convergence
(a `forall`-quantified array term, confirmed present in that query's own
SMT-LIB2 output).

**`APTrace.ProtocolHarness.runGateReachability`** (new, ~140 lines):
builds via `MS.mkFunCFG` from a re-seeded entry exactly as
`runPacketTransactionTraced` does, with the **same** `regOverrides`
mechanism (concrete pointer registers only — this task's own "finish the
initial-register override support," already present, reused unchanged)
and the **same** block-granular `stopAtAddr` early-stop feature — but
**no RAM zero-overlay, and no packet-buffer/event-dispatch machinery at
all**. A small, named `GateVar` list (label, address, byte width) marks
which RAM cells the caller cares about; every other byte of RAM is left
exactly as `SymbolicMutable` leaves it (fully free, no seeding, no
assertions) since nothing else in this bounded region ever reads it. An
optional `extraNotEqual` list adds genuine solver constraints ("this
`GateVar`'s own value must not equal this concrete value") for Query
B's negative checks, without needing a second code path.

**`APTrace.SymbolicRunner.BranchQuery`** gained one new field,
`bqExcludeObserved :: [Integer]` — the same "must not equal" idea,
applied to `checkBranchModel`'s own single observed register, for Query
C's negative check (`R0 != 0`, `R0` otherwise still fully symbolic — not
a concrete substitution, which would only test one alternate value, not
the whole nonzero space). All twelve pre-existing `BranchQuery`
construction sites (`runSolve`, `runProtocol`'s G1-G4/Test1-3/single-char
checks) were updated to `bqExcludeObserved = []`, reproducing their exact
original behavior — reconfirmed below, not assumed.

Neither addition touches `runPacketTransactionTraced`, `runTrigger`, or
any other existing entry point's own behavior.

## Part 3 — Query A: positive reachability

```
entry   = 0x9202 (0x9203, Thumb bit)
stop    = 0x9226 (this investigation's own established proxy for 0x9228 -- Part 1)
regOverrides:
  r5 = 0x20002524  (per-channel device-state array base -- known, concrete, from trigger-input-concrete-path.md)
  r6 = 0x20003120  (TR-enable byte's own address -- known, concrete, same source)
symbolic (GateVars, no seeding at all -- SymbolicMutable's own default):
  r5[0]   @ 0x20002524
  r5[1]   @ 0x20002525
  r5[2]   @ 0x20002526
  r5[3]   @ 0x20002527
  state32 @ 0x20001b38  (the address the real flash literal @ 0x9260 loads -- itself concretely
                          resolved from the loaded firmware image, per Ghidra/prior tracing, not seeded)
  state8  @ 0x200000d8  (address loaded via the flash literal @ 0x9264, same basis)
  r6[0]   @ 0x20003120
```

**Result: SAT.**

```
r5[0]   = 0x0
r5[1]   = 0x0
r5[2]   = 0x0
r5[3]   = 0x0
state32 = 0x7b
state8  = 0x9
r6[0]   = 0x0
```

This is the model the task's own instructions predicted **as an
expectation, not a solver assumption** — nothing above constrains any of
the seven values; Z3 derived them independently from the real lifted
instruction semantics (four `CBNZ` zero-checks, two immediate
comparisons against `0x7b`/`9`, one more `CBNZ` zero-check). Solved in
well under the 175s total for all nine queries below (per-query
breakdown not separately timed; the whole batch, including SMT2-artifact
writing for eight of the nine, completed in 175s wall-clock).

**Solver-artifact evidence** (`/tmp/aptrace_crosscheck_A.gate.standalone.smt2`,
written via the same solver-observability mechanism
`compact-ram-initialization.md` added): 10,534,871 bytes, 212,369 lines,
70,775 asserts, 141,573 define-funs, **exactly one** `declare-fun`
(`globalMemoryBytes` itself — no per-`GateVar` array or overlay term, as
designed). The ~70,775 asserts are entirely the readonly-flash content
(`tool-selection.md`'s own already-documented "readonly flash always
populated via solver assumptions" behavior, addresses starting at
`0x4000`) — this bounded query does not touch RAM at all beyond the
seven free `GateVar`s, and that shows directly in the artifact: the file
is essentially the **same size** as the prior slice's own *post-compact-RAM-fix*
query (10.8MB), yet converges in seconds rather than 367s-to-`unknown`.
This is strong, direct evidence (not just the hypothesis
`compact-ram-initialization.md` left open) that the RAM zero-overlay's
own `forall`-quantified term — absent here entirely — was the real
convergence blocker, not raw file size or the flash population itself.

## Part 4 — Query B: one negative check per guard

Same entry/stop/regOverrides/GateVars as Query A; each row below adds
**exactly one** extra constraint (`extraNotEqual`), leaving the other six
`GateVar`s fully free — a real, independent solver call per row, not a
single combined query (per instruction).

| Guard violated | Extra constraint | Result |
|---|---|---|
| `r5[0]` | `r5[0] != 0` | **UNSAT** |
| `r5[1]` | `r5[1] != 0` | **UNSAT** |
| `r5[2]` | `r5[2] != 0` | **UNSAT** |
| `r5[3]` | `r5[3] != 0` | **UNSAT** |
| `state32` | `state32 != 0x7b` | **UNSAT** |
| `state8` | `state8 != 0x9` | **UNSAT** |
| `r6[0]` | `r6[0] != 0` | **UNSAT** |

**Every guard is independently necessary**: for each one, there is *no*
assignment of the remaining six free variables that reaches `0x9226`
while that one guard is violated. This is a different, stronger claim
than the existing Unicorn tests establish (Unicorn showed the *known*
values reach the gate; this shows *no other combination*, with that one
value excluded, ever does) — exactly the "different question" the task's
own instructions named.

## Part 5 — Query C: the `digitalRead` return-value branch

```
block  = 0x922c (already a real Macaw block-start address in the same
                 re-seeded 0x9203 discovery -- no new capability needed,
                 reused checkBranchModel unmodified in every way except
                 the new bqExcludeObserved field)
0x922c  cmp r0,#0
0x922e  beq.w 0x8f98
target = 0x8f98
observe = R0, fully symbolic (no override)
```

**Positive**: SAT, `R0 = 0x0`.

**Negative** (`bqExcludeObserved = [0]` — a genuine solver constraint
that `R0`'s own symbolic value differ from `0`, with `R0` otherwise still
completely free, not a concrete substitution at one alternate value):
**UNSAT** — no value of `R0` other than `0` reaches `0x8f98`.

**What this does and does not prove**: this is a claim about the
*firmware's own branch condition* at `0x922c` — given whatever `R0`
`digitalRead(0x39)` returns, `0x8f98` is reached exactly when that
returned value is `0`. It says nothing about, and this document makes no
claim about, what physical voltage or pin state on PB05 produces `R0=0`
versus `R0!=0` — that mapping (a real `digitalRead()` reading the
`PORT.GROUP1.IN` MMIO register, already characterized architecturally,
never symbolically modeled) is established in
`trigger-input-concrete-path.md` via Ghidra/Unicorn, not here. This
slice deliberately did not attempt to symbolically execute
`digitalRead` itself (per instruction) — `checkBranchModel`'s own
`lookupFunctionHandle = MS.unsupportedFunctionCalls` means the `bl
0xd3dc` at `0x9228` is never actually entered by any query in this
document; Query C starts *after* it returns, with only its return value
(`R0`) treated as free.

## Part 6 — Comparison with Unicorn

| Claim | Unicorn (concrete) | This slice (solver) | Agreement |
|---|---|---|---|
| Gate satisfied by `r5[0..3]=0, state32=0x7b, state8=9, r6[0]=0` | Confirmed (the real, provenance-traced values used as concrete seeds) | Z3 *independently derived* the identical values as the unique-in-practice SAT witness | **Agree** |
| No other combination satisfies the gate | Not tested (Unicorn ran only the known-good values plus, separately, a PB05-high control) | UNSAT for all seven single-guard violations | **New, stronger result** — not a disagreement, a genuine extension |
| `digitalRead` returning `0` (low) reaches `0x8f98`; nonzero does not | Confirmed (`PORT.GROUP1.IN` bit 5 forced low vs. high, two separate real runs) | `R0=0` is SAT; `R0!=0` is UNSAT | **Agree** |

**No disagreement was found or needed reconciling.** Neither backend was
adjusted to make the other agree — both independently converge on the
same gate values and the same branch condition, from different evidence
(Unicorn: one concrete execution per case; Z3: derivation over the full
symbolic space of the modeled region).

## What this does and does not tell us about the physical trigger-port fault

**Tells us**: the firmware-side gate at `0x9202`-`0x9228`, and the
firmware-side branch at `0x922c`, behave *exactly* as the existing
Ghidra/Unicorn evidence already claimed — now with a solver-derived
guarantee that no *other* combination of these seven RAM values, nor any
other `digitalRead` return value, reaches the same points. Combined with
`trigger-input-motion-causality.md`'s own already-closed finding (this
gate's own downstream reload cannot arm motion), this cross-check adds
confidence to, but does not change, the standing conclusion: **the
firmware-modeled portion of the trigger path is fully and now
solver-confirmed characterized, and it is not — by itself — a plausible
software root cause for uncommanded motion.**

**Does not tell us**: anything about the real electrical behavior of the
3.5mm trigger jack itself — contact bounce, cable-insertion transients,
the physical reason a "certain chain" produces the reported one-time
trigger. That remains explicitly out of scope (per instruction), and
nothing in this document should be read as bearing on it. It also does
not evaluate `digitalRead`'s own body, any MMIO/peripheral behavior, or
anything beyond the two bounded regions modeled above.

## Regressions run

`aptrace protocol FIRMWARE.bin` (exercises 12 of the pre-existing
`checkBranchModel`/`BranchQuery` call sites the `bqExcludeObserved`
field addition touched) reproduces its exact prior output for every
query checked: the loop-probe exit case (`SAT: buffer[1]=0x1`), and all
four gate-block tests (`G1` SAT `0x26`, `G2`/`G3`/`G4` UNSAT) —
byte-identical to the pre-existing, already-documented results. The
same run's whole-function `pending[5]` check hits the same
pre-existing, already-documented, unrelated flash/Crucible step-limit
issue (`docs/harness/execution-model.md`'s own "Known architectural
gap") this project has already root-caused as a flash-literal branch
divergence bug, confirmed in an earlier slice (via `git stash`
A/B comparison) to be unrelated to any RAM/harness change — not
re-litigated here, and not touched by this slice's own additions
(neither `runGateReachability` nor the `BranchQuery` extension is
exercised by that specific check).

## Confidence table

| Item | Status |
|---|---|
| The 0x9202-0x9228 gate is seven chained Macaw blocks, zero classify failures, one call terminator at the end | **CONFIRMED** (Ghidra-cross-checked Macaw discovery, `aptrace explore`) |
| 0x9226 is the correct, established block-granular proxy for "0x9228 reached" | **CONFIRMED** by construction (only one non-branching instruction, `movs r0,#0x39`, lies between them) |
| Query A: the gate is satisfiable, and Z3 independently derives the known-good values | **SOLVER-CONFIRMED** |
| Query B: each of the seven guards is independently necessary | **SOLVER-CONFIRMED**, a new result beyond what Unicorn established |
| Query C: 0x8f98 is reached from 0x922c iff R0=0 | **SOLVER-CONFIRMED** |
| Agreement with Unicorn | **CONFIRMED**, no disagreement found |
| Existing `checkBranchModel` call sites unaffected by the `bqExcludeObserved` addition | **CONFIRMED** (`aptrace protocol` regression, byte-identical results) |
| Physical trigger-port electrical behavior | **NOT ADDRESSED** — explicitly out of scope |

## Evidence level

Level 3 (solver-confirmed) for every claim in Parts 3-5, each independently
cross-checked against Level 2 (concrete, Unicorn) evidence already on
record in `trigger-input-concrete-path.md`/`trigger-input-motion-causality.md`.
Level 1 (static, Ghidra-confirmed) for the block-structure claims in
Part 1. No claim in this document extends to the physical trigger-port
fault.
