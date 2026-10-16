# Architecture Provenance and Capability Reconciliation

**Question.** What did APTrace originally set out to build, and what works
today? Where did recent work repeat or bypass existing capability? What
single milestone would most advance the target-centered question: in what
ways can a firmware function be exercised?

**Verdict: PARTIALLY ALIGNED** (§J). The engines and APTrace's evidence layer
fit the original objective, and most of the pieces exist. What is missing is
composition. No operation asks "how can T run?". The Macaw/Crucible path
machinery was left as case scripts and per-function summaries. Meanwhile the
recent target-centered work was built as one-site-at-a-time Python resolvers.

**Recommendation** (§H). One vertical slice, *target invocation paths with
bounded path feasibility*. A backward, census-graph enumeration from a target
to roots, with an explicit frontier, is fed into path-directed Macaw/Crucible
feasibility. Concrete Unicorn witness replay checks the solver's answers, and
both results are typed ledger operations the controller can use.

Case evidence, addresses and run results:
[`cases/performing-rigs/research/architecture-reconciliation-v1.md`](../../cases/performing-rigs/research/architecture-reconciliation-v1.md).
Nothing canonical was modified: the ledger, census DB, Ghidra projects, claims
and Beads state are untouched. All runs used scratch outputs or a scratch copy
of the census DB.

Evidence tags used below:

- **[doc]**: stated in a document or commit;
- **[code]**: read in source;
- **[run]**: executed for this report;
- **[inferred]**: a judgment from the above.

---

## A. Original design

### A.1 Timeline of direction

| Date | Commit(s) | Direction | Evidence |
|---|---|---|---|
| 09-07 | `5a2e96d` | **Galois-first feasibility spike.** "Reuse as much of the Galois Macaw/Crucible/What4 stack as possible rather than writing a new symbolic execution engine." Raw Cortex-M loading, vector roots, Macaw discovery (25 functions, 0 lift failures), and a Crucible/Z3 model for both sides of an MMIO-gated branch. | [doc] first `README.md`, `research/notes/macaw-cortexm-assessment.md` (now `cases/performing-rigs/docs/firmware/cortexm-assessment.md`) |
| 09-07 | `ed851ba` | **Reachability is the purpose.** The protocol-harness roadmap: "Macaw code discovery already proves *what code is reachable from where*, and … Crucible … turns 'is X reachable, and under what input?' into a solver-checked answer." Its M4: discover the reachable call graph from a dispatcher, then check whether any reachable path can write a given cell. | [doc] `research/notes/protocol-harness-roadmap.md` at `ed851ba` |
| 09-07 | `ed93f16` | Ghidra and Unicorn added the same day as first-class backends. | [doc] |
| 09-08 | `6819a7d` | Tool hierarchy recorded: **Ghidra (static) → Unicorn (concrete truth) → Macaw/Crucible/What4 (symbolic, targeted).** | [doc] `galois-premeeting.md` "What did not change" |
| 09-08 to 09-10 | M3–M6 | Investigations ran mostly on Unicorn concrete replay. Crucible whole-function replay hit the readonly-flash folding limit and was left unfixed by decision. | [doc] case `protocol-pipeline.md`, `roadmap.md` "Tooling gaps" |
| 09-09 to 09-10 | `d6a9453` | **Macaw `cbz` classify failure found** while asking Z3 "what reaches the trigger accept block". Discovery was re-seeded at successors by hand. The SAT query did not converge (267k assertions, 73.5% RAM zero-fill). | [doc] `trigger-input-symbolic-reachability.md` at `d6a9453` |
| later | — | That trigger question was **solved**: `runGateReachability` gives SAT with a Z3-derived witness matching Unicorn, UNSAT for each negated guard, and the branch condition; 175 s. | [doc] case `trigger-input.md` |
| 09-10 | `3c9767e` … | **Python census** built on Ghidra + Capstone sweep + Unicorn coverage. It deliberately excludes symbolic evidence ("reserved for later targeted questions"). Its reachability is forward from vector roots. | [doc] case `census-results.md` |
| 09-11 to 09-12 | `eafc652` … `7e70e9a` | **Macaw census**: vector-root discovery, Cortex-M Thumb fixes, `MacawNormalize`/`MacawExpand` repairing `cbz` classify failures, `MacawIsaClassify`, `macaw_compare.py`, and a `MacawRefinement` attempt that never refined a block. Commit messages carry no rationale. The documented purpose is "independent CFG discovery" cross-checked against Ghidra. | [doc] `macaw-analysis-results.md`; [code] |
| 09-16 to 09-20 | `7920849` … `0bd5d89` | Agent pipeline and `ResearchController`. | [code] |
| 10-12 | `ce67062` | **Galois-first roadmap again** (`aptrace-agent-framework.md`): Macaw as *primary* census source, Ghidra optional, Crucible function summaries for every function. Its Phase 2 spike became production `function_effects` on unrepaired discovery. | [doc] |
| 10-13 | `46a7799` … `dac24d3` | Ledger, Beads, verification policy v1. **Macaw's role becomes the independent lineage** for cross-engine corroboration. | [doc] `cross-engine-verification.md` |
| 10-14 to 10-15 | `ee1fb9b` … `2070310` | **Target-centered work on `FUN_0000b4b4`**, built as Unicorn observation and Python/Capstone backward resolvers: `indirect_target`, `callback_provenance`, `slot_dispatch`. No Haskell changed. | [code] |
| 10-15 | `5d383b5` | **Decision B**: Ghidra p-code for instruction-level dataflow; Macaw independent and Crucible's front end; Crucible for bounded questions; stop Capstone semantics. It also decided (step 5) to point `function_effects` at repaired discovery. | [doc] `architecture-evaluation.md` |
| 10-15 | `eb6bca9`, `1bdeaef` | p-code `value_forward_use`; planner gate. `indirect_target` v3 halted by a tooling blocker. | [doc] `pcode-migration-baseline/migration-interruption.md` (untracked) |

### A.2 What Macaw was for

Established from documents:

1. **The lifter and front end for Crucible** (`5a2e96d`). This is still its
   operational role in `function_effects`, `ProtocolHarness` and
   `SymbolicRunner`.
2. **A reachability engine paired with Crucible**: "what code is reachable from
   where", then "is X reachable, and under what input" (`ed851ba`). The trigger
   slice pursued exactly this: a bounded CFG from a real entry, then Z3 on what
   reaches a target block, then Unicorn replay of the witness.
3. **Independent discovery** for cross-checking Ghidra (Macaw census, 09-11).
   Since 10-13 this is also its role as the independent lineage in verification
   policy.
4. **The primary census source** in the 10-12 roadmap (Phase 1). This was never
   implemented and was implicitly overruled by decision B.

Not established. No document assigns Macaw the job of *enumerating invocation
mechanisms backward* from a target: callers, indirect transfers, vtables,
interrupts. The original framing is forward and rooted: from an entry, what is
reachable and under which inputs. The "possible ways a function could be
exercised" objective is therefore present **in its forward, rooted, solver
form** from day one. Its **backward, mechanism-enumeration form** first appears
in the `FUN_0000b4b4` work of 10-14, where it was built in Python. The
commit history does not record why the Macaw census was built beyond
independent cross-checking; there are no commit messages.

### A.3 Division of labor as originally intended

[doc] The intended division was: Ghidra for structure and naming, Unicorn for
concrete truth, Macaw for discovery and lifting, Crucible/What4/Z3 for
"reachable, under what input", and APTrace for orchestration, evidence and
verification. That matches the working hypothesis in the request, and decision
B refines it rather than replacing it.

---

## B. Current implementation

| Engine / subsystem | What it actually does today | Evidence |
|---|---|---|
| **Ghidra** | Persistent headless projects with cache identity; census export (functions, blocks, CFG edges including unresolved computed flow, RAM/MMIO refs); decompiler for display; p-code `value_forward_use` (intraprocedural, no memory flow); census reachability input. The census graph has edge kinds but **no stored path witnesses**. | [run] doctor: 436 functions; census: 438 functions, 335 `DEFINITELY_REACHABLE`, 103 `NO_KNOWN_PATH`; [code] |
| **Python census dataflow** (Capstone over Ghidra blocks) | Backward reaching definitions (`indirect_target` v2), one-hop callback provenance, RAM function-pointer resolution, slot-dispatch sweep, indexed writes. These are the only backward dataflow and indirect-entry tools. Frozen by decision B; bug fixes only. | [run] 8/8 census test modules OK; [doc] `pcode-migration.md` |
| **Macaw** | Vector-root discovery with Cortex-M Thumb fixes; normalization and expansion repair of `cbz`/nested-mux classify failures; ISA classification; rooted discovery from any entry (`aptrace explore`, CLI only). Expansion works only from vector roots in the CLI, though `expandWithNormalization` accepts any `DiscoveryState`. `macaw-refinement` is non-functional: its local compatibility patch is lost and Haskell test 16 fails. | [run] expand: 263 functions / 3,521 blocks in 13 s, 2.3 GB; rooted `explore` recovers a 4-function chain in 0.3 s; [code] |
| **Crucible/What4/Z3** | `function_effects`: one function, opaque AAPCS calls, symbolic RAM/MMIO, raw accesses, call records with **target, argument terms and path guard**, plus Z3 enrichment of accesses and return. It uses **unrepaired** discovery (`EffectsSpike.hs:153`), has no per-query solver timeout, and does not solve call guards. `runGateReachability` (`ProtocolHarness`): "can this function's entry reach block T, given register overrides and named symbolic cells", with SAT model and UNSAT; only a case CLI calls it. `SymbolicRunner` (single block), `DebugHarness` (experimental). | [run] 12 recorded runs: 6 complete, 1 partial, 2 step-bound, 2 failed; a fresh run had one Z3 query exceed 13 min; [code] |
| **Unicorn** | ARM Thumb/M-class only; case boot recipe and 10 virtual-link scenarios; `observed_call_arguments` (caller-grounded arguments, in-function MMIO, watched fields); coverage ingested into the census. General concrete runs and witness replay are **not** ledger operations. | [run] doctor OK; 1/1 test module OK |
| **Agent / ResearchController** | Local Qwen planner over a budgeted projection. Actions: `analyze_peripheral`, `analyze_usb_interface`, `find_common_paths`, `analyze_function_effects`, `observe_call_arguments`, `resolve_indirect_call`, `trace_callback_argument`, `trace_value_use` (opt-in), `follow_lead`, `search_case_evidence`, `finish`, `select_claims`. Durable ledger, replay, admission, candidates, call-relation checks, verification policy v1, Beads continuity. **No action asks "how is T reached"**: `common_paths` is forward descendant convergence between two sets. Macaw reaches the agent only as the stored **base** census in structural source agreement (audit). | [run] 575 passed, 1 skipped; [code] `controller.py:35`, `source_agreement.py:382` |

---

## C. Capability provenance

| Capability | Original requirement | Implementation (where, when) | Tests / experiments | Consumers | Status |
|---|---|---|---|---|---|
| Raw loading, vector roots | feasibility spike | `FirmwareLoader`, `VectorTable` (`5a2e96d`) | Haskell tests | all Haskell commands | active |
| Macaw independent discovery | cross-check Ghidra; independence | `MacawCensus` (09-11) | tests 1–36 | `source_agreement` (base JSON only), `macaw_compare.py` (standalone) | active, **under-consumed** |
| Macaw repair (`cbz`) | unblock Macaw past `cbz` for Crucible reachability | `MacawNormalize`/`MacawExpand` (09-12) | tests 20–30 | `macaw-census-expand` CLI only | active, **disconnected from Crucible** |
| Macaw SMT refinement | resolve classify failures | `MacawRefinement` (`370a4e8`) | test 16 **fails** | none | **broken; patch lost** |
| Rooted Macaw exploration | "what is reachable from where" | `aptrace explore` (09-07) | used by hand | none programmatic | active, **disconnected** |
| Bounded reachability / input solving | "is X reachable, under what input" | `ProtocolHarness.runGateReachability`, `SymbolicRunner` | trigger Query A/B/C [doc] | case `trigger*`/`protocol`/`solve` CLIs | active, **case-only** |
| Function effects | agent roadmap Phase 2 | `EffectsSpike` → `function-effects` (`ce67062`) | recorded runs | agent `analyze_function_effects` | active, **unrepaired, untyped guards, no solver timeout** |
| Census + reachability | bulk mechanical inventory | `tools/census` (09-10) | 8 modules | agent census/common paths | active; forward only; no witnesses |
| Indirect target derivation | `b4b4` slot-7/8 question | `indirect_target` v1/v2 (`7326018`, `2070310`) | tests; 86-site inventory | `resolve_indirect_call` | active, **frozen** (decision B) |
| Callback provenance (one hop) | `b4b4` callback sites | `callback_provenance` (`2070310`) | tests; 23 sites | `trace_callback_argument` | active, frozen |
| p-code forward use | decision B pilot | `pcode_forward_use` (`eb6bca9`) | 11 Thumb + 7 RV32 controls | `trace_value_use`, opt-in | active, experimental |
| Caller-grounded observation | `b4b4` callers | `call_observation.py` (`ee1fb9b`, `29b8bbc`) | tests; 278 entries | `observe_call_arguments` | active |
| Ledger, admission, candidates, call relations, policy v1 | evidence discipline | `agent/…/ledger`, `research` (10-13 to 10-14) | 575 agent tests | controller, CLI | active |

**Which recent work was genuinely new, and which revisited existing capability:**

- **New.** Indirect-entry analysis: vtable slots, callback values across a call
  boundary, pointer-entry sweeps. No engine in the tree produces it. Macaw's
  discovery leaves the same sites unresolved, and refinement never worked. The
  substrate was wrong (Capstone semantics; decision B), but the capability was
  new.
- **New.** Caller-grounded concrete observation, and call-relation admission.
- **Revisited.** The downstream half of the `b4b4` path was derived by
  disassembly: the chain of direct calls, "on every path", and "`r0` at the
  call = `*(this+0x10)`". Macaw rooted discovery plus `function_effects` produce
  the same facts mechanically: target, argument terms and per-path guards per
  call site [run].
- **Revisited.** "What conditions reach this point" was solved once with
  `runGateReachability` (trigger) and never generalized. The `b4b4` work did
  not attempt feasibility at all.
- **Revisited.** Forward reachability exists three times: census
  `reachability.py`, Macaw vector-root discovery, and `common_paths` BFS. None
  answers the backward question or keeps a witness.

**Forgotten or contradicted decisions:**

1. `aptrace-agent-framework.md` (Galois-first map, Ghidra optional, Macaw as
   primary census) was never reconciled with decision B. It is still the
   indexed "roadmap".
2. Decision B step 5 (`function_effects` on `MacawExpand`) was decided and not
   done. The original reason `MacawExpand` exists (getting Crucible past `cbz`)
   is the same gap.
3. The original "reachable, under what input" capability (`runGateReachability`)
   stayed in a case script. Framework `status.md` lists "ask What4/Z3
   reachability questions" as a capability, but neither the agent nor any
   generic CLI can.
4. The agent's independent Macaw source is the base census, not the repaired
   one the Macaw docs describe as the normal discovery path.

---

## D. Toolchain reconciliation

`docs/toolchain.md` describes GHC/Cabal, Python, Ghidra, Unicorn and Z3 with
Macaw/Crucible/What4. It omits the agent environment, the local model server,
Beads, and version pins. One picture of the actual toolchain:

| Category | Component | Version here | Pinned / recorded? | Runs? | Exposed to the autonomous investigator? |
|---|---|---|---|---|---|
| 1. Development tools | GHC / cabal / ghcup | 9.6.7 / 3.16.1 | freeze file | yes | — |
| | Python | 3.12.14 | no | yes | — |
| | uv (agent env) | 0.12.13 | `agent/uv.lock` | yes | — |
| | clang (fixture assembly) | system | no | — | — |
| 2. Runtime dependencies | Z3 | **5.1.0** (4.15.3 recorded 09-08) | **no** | yes | via `function_effects` |
| | Unicorn / Capstone (`tools/unicorn/.venv`) | 2.1.4 / 5.0.9 | requirements file | yes | via census and observation |
| | SQLite census DB | — | file hash in operation inputs | yes | yes |
| 3. Analysis engines | Ghidra headless | 12.1.3 | in cache identity | yes (436 functions) | census-backed operations; `value_forward_use` (opt-in) |
| | Macaw aarch32 (vendored `external/macaw`, gitignored) | `593a918d` | **no**: checkout not tracked | yes | base census in audit only |
| | Crucible / What4 | `a98310893` / `4ce24dc4` | **no** | yes | `function_effects` only |
| | Unicorn | 2.1.4 | yes | yes | `observed_call_arguments` |
| | Python/Capstone dataflow | — | module hashes | yes | `resolve_indirect_call`, `trace_callback_argument` |
| 4. Experimental backends | macaw-refinement | — | patch **lost** | **no** (test 16 fails) | no |
| | crucible-debug (`aptrace debug`) | vendored | no | partial | no |
| | GREASE | external scratch clone | no | one experiment | no |
| | Ghidra decompiler | 12.1.3 | — | yes | display only |
| | REA | — | — | spike: defer | no |
| | `effects-spike` CLI | — | — | yes | no (scaffolding) |
| 5. External development agents | Claude Code (`CLAUDE.md`), Codex operator (`AGENTS.md`, `codex-operator.md`) | — | — | — | they *are* the investigator for anything not in the action list |
| 6. Internal autonomous components | ResearchController + local planner (OpenAI-compatible endpoint, oMLX, Qwen3-Coder-30B-A3B 4-bit) | — | model recorded on runs | yes | — |
| | Research ledger, admission, candidates, verification policy v1, audit model | — | policy digest | yes | — |
| | Beads work store (`bd`) | 1.3.1 | no | yes | operator commands |

Contradictions:

- `README.md` says to build with `cabal build aptrace` from the repo root after
  `cd ../..`. `toolchain.md` builds inside `external/macaw`.
- `README.md` lists a root `test/` directory for framework tests. There is
  none; the Haskell tests live in `cases/performing-rigs/test`.
- `architecture.md`'s component diagram omits the agent, ledger, census and
  p-code. Its first sentence calls APTrace a Cortex-M workbench, unlike the
  `CLAUDE.md` goal.
- `census.md`'s flow shows "Ghidra/Macaw static exports → census database".
  Macaw output is never ingested.
- `status.md` lists Crucible reachability questions as a capability. They are
  reachable only through case CLIs.
- Engine identity (Macaw/Crucible/What4 commits, Z3 version) is recorded
  neither in ledger evidence nor in the repository, and the vendored Macaw tree
  is gitignored. Rebuilding on another machine cannot reproduce the lost patch.

---

## E. Target-function workflow

How APTrace should determine the ways a target function T can execute, using
what exists. The address-level `FUN_0000b4b4` mapping, with the records each
row was checked against, is in the case note §4.

| Step | Existing component | Needs | Produces | Callable by APTrace? | Limiting assumptions | Missing |
|---|---|---|---|---|---|---|
| 1. Invocation mechanisms (direct, tail, pointer-taken, vector, indirect) | census edges, `function_pointers`, vectors, `slot_dispatch` sweep, `indirect_edge_candidates` | census DB | per-mechanism entry list | partly (`follow_lead` shows callers) | Ghidra boundaries; pattern sweeps | one operation listing *all* mechanisms with kinds |
| 2. Upstream paths | census call graph | step 1 | paths T ← … ← X | **no** (forward only) | strong vs candidate edges | backward bounded enumeration with witnesses |
| 3. Entry-point connectivity | census roots (vectors, resolved targets); `indirect_call_target`, `callback_argument_provenance` | step 2 | rooted / unrooted, plus a frontier | per site only | resolved-target roots mix static and observed evidence | a **frontier object**: the exact unresolved edges a path needs |
| 4. Path conditions | Macaw rooted discovery + `MacawExpand` + `function_effects` call guards | a path | per-hop guard and argument terms | per function; guards untyped | opaque calls; symbolic RAM; step bound; unrepaired discovery | path-directed simulation across hops; typed guards |
| 5. Feasibility | `runGateReachability` pattern; Z3 | step 4 | SAT model / UNSAT / unknown | **no** (case script) | memory over-approximation; opaque callee effects | generic path feasibility; solver timeouts |
| 6. Argument and state at T | `function_effects` argument terms; watched fields; recorded assumptions | steps 4–5 | T's arguments as terms over path-head inputs | **no** | same as 5 | composition; assumptions as recorded inputs |
| 7. Concrete observation | Unicorn scenarios; `observed_call_arguments` | scenario | observed entries and arguments | yes | harness assumptions; scenario coverage | witness replay of a solver model |
| 8. Conclusions | admission (paths of ≤ 8 cited edges), candidates, policy v1 | typed evidence | admitted claims | yes | policy v1 leaves most classes UNEVALUABLE | path evidence and a reachability candidate extractor |

Evidence levels stay distinct: step 2 is a statically established relationship
(call instructions connect); step 3's conditional edges are conditional; step 5
is symbolic (SAT under modeled memory is a possibility, and UNSAT is an
exclusion only under stated assumptions); step 7 is concrete for one harness
state. A path that reaches the frontier is **unestablished, not unreachable**.

---

## F. Gaps and duplicated work

**Most consequential missing connections (correctness and integration):**

1. **No target-centered path operation** (integration). The census holds every
   edge kind, and the indirect tools add conditional edges, but nothing walks
   backward from T, keeps witnesses, or emits a frontier. Today the planner or a
   development session composes paths by crawling `function_facts`.
2. **Symbolic feasibility is not connected** (correctness and integration):
   - `function_effects` runs on unrepaired discovery;
   - calls are opaque, so no path spans functions;
   - call guards are recorded but never solved or typed;
   - one solver query can stall a run with no per-query timeout. The agent's
     300 s wrapper then discards the already-written raw result and caches the
     timeout as a permanent failure. Its planner summary calls it "likely an
     input-dependent loop", which presents a solver stall as firmware behavior
     (`function_effects.py:195-201`);
   - `runGateReachability` is reachable only from a case CLI.
3. **No typed path evidence for claims** (integration). Admission already checks
   "A reaches B" over ≤ 8 cited edges. No operation produces such edge chains,
   and call relations have no candidate extractor.
4. **Witness replay is missing** (verification). There is no operation that
   takes a solver model and replays it in Unicorn. That replay is the existing
   cross-check pattern from the trigger work.

**Defects found:**

- `MacawIsaClassify` labels every `BL` ParsedCall `true_indirect_call`,
  including direct `BL_i_T1`: 1,206 of the 1,229 `true_indirect_call` labels
  on the case image are direct calls. The
  `BL`-prefix rule does not separate immediate from register forms. No current
  consumer reads the field.
- The `macaw-refinement` compatibility patch existed only in the gitignored
  vendored tree. It is gone, and Haskell test 16 fails.
- Macaw output records no firmware digest, and evidence records no
  Macaw/Crucible/What4/Z3 versions (already noted in
  `cross-engine-verification.md`).
- Census "DEFINITELY_REACHABLE" means a path in the strong static graph, whose
  roots include dynamically observed indirect targets. The label reads stronger
  than that evidence supports. Admission already scopes it as "the census's
  static result".

**Duplicated or parallel work:**

- Three forward reachability computations: census, Macaw vector-root discovery,
  and `common_paths` BFS.
- Four Crucible harnesses with copied setup and different memory postures:
  `SymbolicRunner`, `ProtocolHarness`, `EffectsSpike` and `DebugHarness`.
- Instruction semantics in Capstone, already scheduled for retirement
  (decision B).
- Two roadmaps with opposite engine primacy (`aptrace-agent-framework.md` and
  `architecture-evaluation.md`).

**Not blockers for the target-centered slice:**

- The precision of indirect resolution (p-code v3). It changes the size of the
  frontier, not whether a frontier can be produced.
- Interrupt preemption modeling.
- Planner prompt size.
- The operation-descriptor refactor. It is real integration cost, but it is
  cleanup.

---

## G. Recommended architecture (reconciled, not new)

| Responsibility | Owner | Change from today |
|---|---|---|
| Structural discovery, xrefs, edge kinds, pointer words | Ghidra (census) | none |
| Instruction-level dataflow, including indirect-target derivation | Ghidra p-code (decision B) | continue the migration when unblocked |
| **Invocation-path enumeration and the frontier** | **APTrace policy over the census graph** (no instruction semantics) | new operation; graph-level, ISA-neutral |
| Independent discovery for corroboration | Macaw, vector-rooted, expanded | the agent should consume the expanded census (new source version) |
| **Path lifting for symbolic questions** | Macaw rooted at path functions, with `MacawExpand` repair; recorded as **assisted** lineage because roots come from the census | new; this is Macaw's original Crucible front-end role, now made explicit |
| Bounded feasibility, conditions, argument terms | Crucible/What4/Z3, path-directed, with per-query timeouts | generalize `runGateReachability` + `function_effects` |
| Concrete truth and witness replay | Unicorn | add model replay |
| Orchestration, evidence, admission, verification | APTrace | consume typed path evidence |

Macaw cannot answer backward questions by itself. Its discovery is forward from
roots. The target-centered question is answered by composition:

1. a backward walk over a graph from the Ghidra lineage;
2. forward, rooted, repaired Macaw lifting of each candidate path;
3. Crucible on that lifted path.

Rooting Macaw at census-derived addresses makes those runs assisted. That is
acceptable for feasibility, and it must never be counted as independent
corroboration (`cross-engine-verification.md`). Independent corroboration of
path *edges* still comes from the vector-rooted expanded Macaw census, where it
discovered both endpoints.

No result may claim complete path enumeration while the frontier is non-empty,
or while the enumeration reports any bound, unattributed code or unresolved
computed transfer.

---

## H. One major next milestone

### Target invocation paths with bounded path feasibility

**Objective.** For a target function T, APTrace should answer in one bounded,
replayable investigation step:

- which known mechanisms and upstream paths can invoke T from declared roots;
- exactly which unresolved edges stop the rest;
- whether a candidate path's conditions are jointly satisfiable;
- what T's arguments are in terms of the path head's state;
- whether that answer survives concrete replay.

**Existing components reused:**

- the census graph loader (`census_graph._Graph`), reachability roots,
  `indirect_edge_candidates`, `function_pointers` and the `slot_dispatch`
  direct-transfer sweep;
- recorded `indirect_call_target` and `callback_argument_provenance` results,
  as conditional edges;
- `FirmwareLoader`, `MacawExpand.expandWithNormalization` (over a rooted
  state), and `explore`'s rooted discovery;
- `EffectsSpike`'s simulation setup and access and call recording, the
  `runGateReachability` stop-and-query pattern, and the enrichment queries;
- `ConcreteMachine.call` and watch hooks;
- ledger operations, replay, admission's path check, and candidate selection
  by id.

**Necessary changes:**

1. **`invocation_paths(target)`** (Python, `agent/` plus census reads; no
   instruction semantics). A bounded backward search from T. Edges carry
   evidence kinds:
   - `DIRECT_CALL` and `TAIL_BRANCH`;
   - `RESOLVED_INDIRECT` (static);
   - `OBSERVED_INDIRECT` (scenario-scoped);
   - `POTENTIAL_INDIRECT` (conditional, from recorded resolver evidence);
   - `POINTER_ENTRY` (address-taken word, such as a table slot).

   Roots are declared by the target configuration: vectors plus declared
   entries. The output has three parts:
   - paths of at most 8 edges with status `ROOTED_STATIC`, `ROOTED_OBSERVED`,
     `CONDITIONAL` or `UNROOTED`;
   - a frontier with reason codes (`POINTER_ENTERED_NO_KNOWN_TRANSFER`,
     `UNRESOLVED_SITE_MAY_TARGET`, `UNATTRIBUTED_CODE`, `BOUND`);
   - an explicit completeness verdict.

   Each direct edge also carries independent corroboration from the expanded
   Macaw census, where Macaw discovered both endpoints.
2. **`aptrace path-feasibility`** (Haskell, framework). Inputs:
   - a path (head entry, call sites, T);
   - recorded head constraints (equalities or finite sets on head registers and
     memory cells, each with an evidence reference or labeled `ASSUMED`);
   - an optional property on T's arguments (for example, region membership).

   Execution:
   - Discover rooted at each path function and repair with
     `expandWithNormalization`.
   - Simulate from the head. The call lookup dispatches only the designated next
     hop to its CFG; other calls stay opaque.
   - Stop at T's entry.
   - Query reach SAT/UNSAT with a model, T's r0–r3 terms, the property, and
     per-guard necessity (negate each guard, as in the trigger's Query B).
   - Apply per-query solver timeouts. A timeout is UNKNOWN.

   UNSAT is reported as `EXCLUDED_UNDER_ASSUMPTIONS` and lists every opaque
   call that precedes a material guard. An opaque callee's memory effects are
   not modeled, so a bare UNSAT would be unsound.
3. **Witness replay**: a SAT model becomes a Unicorn run from the head, with
   only the model's named registers and cells applied, watching T's entry. The
   result is `REPLAY_REACHES` or `REPLAY_DIVERGES`. A divergence is recorded as
   a discrepancy to investigate. It is labeled a hypothetical-input witness,
   never caller-grounded.
4. **Prerequisite fixes inside the milestone:**
   - `function_effects` moves to repaired discovery as a new analysis version
     (decision B step 5);
   - enrichment gets per-query timeouts; a stalled query is UNKNOWN for that
     fact only, the raw result is kept, and a stall is never cached or
     summarized as firmware behavior;
   - call guards become typed;
   - Macaw/Crucible/What4/Z3 identities and the firmware digest are recorded on
     evidence.
5. **Ledger and controller:**
   - two typed operations (`invocation_paths`, `path_feasibility`) with
     analysis versions, input artifacts and limitation codes;
   - controller actions `find_invocation_paths(function)`, for known functions,
     and `check_path_feasibility(path_id)`, offered only for path ids already in
     session evidence, so the model selects ids and never composes arguments;
   - a mechanically derived reachability candidate (`CALL_RELATION`, "T reached
     from root R via cited edges", scoped).

**Evidence and completeness requirements:**

- Grades:
  - a rooted static path of direct edges is STRONG (static relationship), not
    "reachable at runtime";
  - a conditional path is PROBABLE;
  - SAT without replay is PROBABLE (memory over-approximation);
  - SAT with replay is STRONG concrete-under-hypothetical-input;
  - `EXCLUDED_UNDER_ASSUMPTIONS` is BOUNDED, with the assumptions inherited by
    any claim;
  - timeouts, aborts and missing semantics are UNKNOWN with a code.
- An empty path set with a non-empty frontier is `NO_KNOWN_PATH`, never
  unreachable.
- Rooted Macaw runs are marked assisted, with seed references.
- Replay produces byte-identical canonical results.

**Real-firmware demonstration:**

- **AutoPilot `FUN_0000b4b4`.** Mechanically reproduce the four manual reports'
  structure:
  - observed direct paths, rooted;
  - the `c7c0 → b658 → b5bc → b4b4` path, unrooted;
  - a frontier that names the slot-7 thunk as pointer-entered with no known
    transfer, plus the unresolved sites.

  Then run feasibility on that path. It should derive
  `T.r0 = load32(head.r0 + 0x10)` and the `+0x2e8` guard. Under the recorded
  object assumptions, "T.r0 in the SERCOM0 window" should be UNSAT; without
  them, SAT. The witness should replay in Unicorn.
- **AutoPilot trigger gate**: the solver-confirmed seven-guard result is the
  regression for path length 0.
- **A Remote (`mando868`) target**, with a scratch census build, so that nothing
  AutoPilot-specific is exercised.

**Measurable acceptance criteria:**

1. `invocation_paths(FUN_0000b4b4)` lists the 4 direct call sites and a rooted
   path through each observed caller. It reports the unrooted path through
   `c7c0`, and its frontier contains the slot-7 entry. Its unresolved-site set
   matches the 27 recorded sites, or every difference is classified. Two runs
   are byte-identical, it runs in under 5 s, and it contains no case-specific
   code.
2. `path_feasibility` on the 4-hop path returns SAT with a model and the
   argument relation above. The SERCOM0-window query is UNSAT under the
   recorded assumptions and SAT without them. The witness replay reaches T with
   the predicted `r0`. Budget: ≤ 300 s and ≤ 2.5 GB, or UNKNOWN with the bound
   named.
3. The trigger regression reproduces the recorded Query A model and all seven
   negated-guard UNSATs.
4. One `mando868` target reproduces its documented callers and yields at least
   one rooted path with a feasibility result.
5. Controls (synthetic Thumb), all passing:
   - direct chain;
   - tail branch;
   - pointer entry;
   - vtable dispatch;
   - cross-hop contradiction (UNSAT);
   - memory-dependent guard (SAT);
   - bound hit (UNKNOWN);
   - **negative control**: an opaque call that writes the guard cell must yield
     `EXCLUDED_UNDER_ASSUMPTIONS` naming that call, never plain UNSAT.
6. The `function_effects` new version completes on a function that failed on
   the unrepaired `cbz` gap (`e8a8` in the case records), or the remaining
   cause is recorded.
7. Live planner trials (≥ 3, the tool not named in the objective):
   - zero admitted claims assert reachability without cited path edges;
   - zero admitted claims assert unreachability.

   Tool selection alone is not a success measure.
8. Haskell test 16 is either restored (patch committed under the repo) or
   retired with `MacawRefinement` recorded as experimental; no silent failure.

**Major risks:**

- Path explosion and step bounds in larger head functions. `c7c0` already hits
  3,000 steps. Mitigation: stop at the next call site per hop; report UNKNOWN
  per hop.
- Solver cost. A single query exceeded 13 min. Per-query timeouts are mandatory.
- Unsound exclusions from opaque callees. This is handled by
  `EXCLUDED_UNDER_ASSUMPTIONS` and the negative control.
- Missing ASL semantics (for example `VSTMDB`). These abort with a code.
- `MacawExpand` on rooted states is untested on arbitrary roots.
- Census-lineage boundaries shape both the path set and the roots. This is
  disclosed, and Macaw edge corroboration is reported separately.
- Agent wiring touches about 10 modules (known cost).

**Explicit non-goals:**

- resolving the slot-7 entry or any indirect transfer;
- resuming p-code `indirect_target` v3;
- general interprocedural symbolic execution beyond a given path;
- interrupt preemption;
- complete path enumeration;
- new Capstone semantics;
- reviving `macaw-refinement`;
- GREASE adoption;
- the operation-descriptor refactor;
- RISC-V feasibility (path enumeration is ISA-neutral; feasibility is per Macaw
  architecture backend, AArch32 now);
- changing canonical claims or relaxing admission.

**New investigative outcome unlocked:**

- the precise unresolved edge preventing each conclusion, as a typed frontier;
- conditions required to reach a target across functions;
- a mechanical scoped exclusion (the SERCOM0 argument under stated object
  assumptions);
- reproducible witnesses.

None of this exists as an agent capability today.

---

## I. Remaining uncertainties

- Whether path-directed Crucible stays within budget on large head functions,
  and whether stopping per hop at the next call site is enough.
- Whether `MacawExpand` converges from arbitrary roots. It is tested only from
  vector roots.
- How far UNSAT remains useful once every preceding opaque call is listed as an
  assumption. The fraction of guards behind opaque calls is unmeasured.
- How to find pointer-entered code without a Ghidra function. Ghidra records no
  references to such entries, and the census pointer scan is a pattern match.
- Whether the local planner reliably uses path ids. This is untested.
- Interrupt handlers are roots, but preemption-dependent paths and shared state
  are out of scope.
- Why the Macaw census was built beyond independent cross-checking. Its commits
  carry no rationale.
- Whether the lost `macaw-refinement` patch is worth recovering. No block ever
  refined.

---

## J. Verdict

**Partially aligned.** The architecture is the original one: specialist
engines, Unicorn as concrete truth, and Macaw/Crucible for "reachable, under
what input". APTrace owns evidence and verification. Decision B refines rather
than replaces it.

The drift is in where work landed. The target-centered question was answered by
hand and with frozen Python resolvers. Meanwhile, the rooted Macaw/Crucible
reachability machinery that the original roadmap named for exactly this
question stayed in case scripts and per-function summaries.

No significant architectural change is warranted. The next step is composition,
with the honesty rules the ledger already enforces.

---

## K. Documentation update list

Stale or contradictory documents, and the change each needs. These are
documentation-only edits, best done as one small separate change, so that
settled decisions are not undone by accident.

| Document | Problem | Update |
|---|---|---|
| `docs/aptrace-agent-framework.md` | Galois-first map: Ghidra "optional", Macaw "primary census source", controller "parked". Contradicts decision B and the Agent v0 note. | Mark Phases 0–1 and the engine-primacy principle superseded by decision B. Keep Phase 2 history; point to this report. |
| `docs/README.md` | Describes the above as the roadmap. Seven docs are not indexed: `claim-admission`, `claim-call-relations`, `claim-candidates`, `research-continuity`, `codex-operator`, `spikes/architecture-evaluation`, `spikes/investigation-continuity`. | Re-index; name decision B as the current engine ownership. |
| `docs/architecture.md` | Cortex-M "workbench" framing; diagram omits agent, ledger, census and p-code; lists `SymbolicRunner`/`ProtocolHarness` but not `function_effects`. | Align with `CLAUDE.md` and §G. |
| `docs/toolchain.md` | Omits the agent env (uv), local model server, Beads, Ghidra version, Z3 version; no categories. The vendored Macaw tree is gitignored and unpinned. | Adopt §D's table; record engine commits; state where local patches must live. |
| `README.md` | Nonexistent root `test/`; build path differs from `toolchain.md`; no agent. | Fix the layout and quick start; mention the agent and ledger. |
| `docs/status.md` | "Ask What4/Z3 reachability questions" is listed as a capability (case CLIs only). Agent v0 action list is outdated. `function_effects` limitations omit unrepaired discovery and solver stalls. | Correct all three. |
| `docs/tooling/census.md` | Flow shows Macaw exports entering the census (they don't). | Fix the diagram. |
| `docs/tooling/macaw-analysis.md` | Omits rooted `explore`, the agent's use of the base census, `MacawRefinement`'s broken state, and the `true_indirect_call` labeling. | Add them. |
| `cases/performing-rigs/docs/investigations/macaw-analysis-results.md` | Headline numbers stale (233/3,368/26,014/136/39 vs 263/3,521/26,658/151/48). The semantic-kind table covers indirect sites only. | Refresh with digest and engine commits. |
| `docs/tooling/tool-selection.md` | Crucible row names only the `cbz` gap. Macaw's role omits rooted, assisted lifting for Crucible. | Add solver-stall and assisted-lifting notes. |
| `docs/spikes/architecture-evaluation.md` | "Branch `spike/architecture-evaluation`; nothing is committed" is false (`5d383b5`). | Correct the line. |
| `docs/tooling/pcode-migration.md` | Does not record the v3 interruption. The interruption note is untracked. | Link or commit the interruption record (owner's choice). |
| `cases/performing-rigs/status.md` | Engine table "Macaw / Crucible: in use, proven" without scope. | Scope to what each produced. |
| `cases/performing-rigs/roadmap.md` | Predates the agent and SERCOM0 work; still frames dormant events as a Crucible target with no tool path. | Refresh open items; reference the §H milestone. |
| `docs/cross-engine-verification.md` | No rule for rooted Macaw runs seeded from census addresses. | State they are assisted (§G). |

## What should happen next

1. Review this report, especially §A.2 on the Macaw objective, which separates
   the documented forward form from the undocumented backward form. Correct
   anything that misremembers intent.
2. Make the §K documentation corrections as one small docs-only change. The
   first priority is marking `aptrace-agent-framework.md` superseded where it
   conflicts with decision B.
3. Decide the `macaw-refinement` question (restore the patch under version
   control, or retire it as experimental), and pin the vendored engine commits.
4. Start the §H milestone, `invocation_paths` first. It is useful on its own: it
   turns three manual reports into one typed result with a frontier. Then add
   `path-feasibility` with its prerequisite fixes.
