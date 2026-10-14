# Indirect Dispatch Resolution v1

**Question.** Can any reachable register-indirect call dispatch through
vtable `0x14900`, especially slot 7 or slot 8, and so enter the unexecuted
path `FUN_0000c7c0 → FUN_0000b658 → FUN_0000b5bc → FUN_0000b4b4`?

**Short answer (PARTIAL).**

1. **Slots 7 and 8 are different code.**
   - Slot 7 (`+0x1c`) holds `0xc744`. It is a 4-instruction thunk with no
     Ghidra function: it tail-dispatches slot 8 with `r2 = 0x413`.
   - Slot 8 (`+0x20`) holds `0xc7c0`, the function that calls `b658`.
2. **Exactly one site can load slot 8.**
   - All 86 register-indirect sites were classified, including the reported
     56.
   - The only site whose target can be a slot-7 or slot-8 entry is `0xc74c`,
     the thunk's own `bx r3`.
   - 58 sites are excluded within a stated scope; 27 remain unresolved.
3. **Nothing enters the thunk.**
   - No direct `BL`, `B.W` or `B<c>.W` targets `0xc744`.
   - No analyzed site loads `+0x1c` from any base that could reach the
     table.
4. **The path is unestablished, not unreachable.**
   - The upstream edge into `0xc744` or `0xc7c0` is still missing.
   - The 27 unresolved sites take their targets from callbacks, stack spills
     or runtime tables, so this analysis cannot exclude them.
5. **The path's `b4b4` argument would not be SERCOM0.** For each of the
   three objects that hold vtable `0x14900`, `b4b4` would read the RAM SERCOM
   object for SERCOM3, SERCOM4 or SERCOM1. None is bound to SERCOM0's object
   (`0x20004c3c`).

The global negative ("`b4b4` never accesses SERCOM0") remains **not
established**. `C9:v1` and the canonical ledger are unchanged.

Firmware `firmware_autopilot868.bin`, sha256 `6dcdb4c1…52e3`, flash base
`0x4000`.

## 1. Baseline

- Branch `feat/indirect-dispatch-resolution`, created from
  `feat/scenario-grounded-observation` at `b00cef3`. That is the
  investigation commit; `29b8bbc` before it is the capability.
- A single checkout. The census DB, Ghidra cache and venvs are untracked
  local state, so a separate worktree could not run.
- The 38 pre-existing uncommitted SERCOM0 ledger files were left as found.
  The canonical ledger and census DB fingerprints are unchanged.

**The "56" sites.** The census has 57 `UNRESOLVED` rows in
`indirect_edge_resolutions`:

- 56 are `instr_shape = reg-indirect`. These are the reported 56.
- One is `udf #0xff` at `0xe344`, a trap after `cbnz` and not a transfer.

The full indirect inventory has 105 rows:

| Group | Count |
|---|---|
| Statically resolved table branches | 16 |
| `mem-indirect` | 2 |
| `DYNAMICALLY_OBSERVED` register-indirect | 29 |
| `RESOLVED_RAM_FUNCTION_POINTER` | 1 |
| `UNRESOLVED` register-indirect (the 56) | 56 |
| `UNRESOLVED` other (`udf`) | 1 |

An observed target set is not a complete one. The 30 already
observed/resolved register-indirect sites were therefore classified as
well (86 in total).

## 2. The path, from firmware bytes

**Vtable `0x14900`** (`vtable.json`):

- The two words before the table, at `0x148f8` and `0x148fc`, are zero.
  This matches an Itanium C++ ABI offset-to-top/typeinfo header
  (pattern-matched).
- There are 11 Thumb code-pointer slots, ending at `0x1492c` (the string
  "sqrt").

| Slot | Offset | Target | Ghidra block owner | Census reachability |
|---|---|---|---|---|
| 0 | `0x00` | `0xca58` | `FUN_00007f84` (tail-branch absorbed) | — |
| 1 | `0x04` | `0xb1f4` | `FUN_00008c10` (tail-branch absorbed) | — |
| 2 | `0x08` | `0xc974` | `FUN_0000c974` | NO_KNOWN_PATH |
| 3 | `0x0c` | `0xc922` | `FUN_0000c922` | NO_KNOWN_PATH |
| 4 | `0x10` | `0xc93e` | `FUN_0000c93e` | DEFINITELY_REACHABLE |
| 5 | `0x14` | `0xcb18` | `FUN_0000cb18` | DEFINITELY_REACHABLE |
| 6 | `0x18` | `0xc74e` | `FUN_0000c74e` | DEFINITELY_REACHABLE |
| **7** | **`0x1c`** | **`0xc744`** | unattributed block | — |
| **8** | **`0x20`** | **`0xc7c0`** | `FUN_0000c7c0` | NO_KNOWN_PATH |
| 9 | `0x24` | `0xc768` | `FUN_0000c768` | NO_KNOWN_PATH |
| 10 | `0x28` | `0xc740` | unattributed block | — |

Ghidra function boundaries disagree with the code-pointer evidence for four
slots:

- `ca58` and `b1f4` are slot entries that Ghidra folded into the bodies of
  the functions that tail-branch to them (`0x7fc2 b.w ca58`,
  `0x8c5a b.w b1f4`).
- `c744` and `c740` have Ghidra blocks but no function.
- Macaw's root-seeded census discovers none of the 11 targets.

**Slot 7, `0xc744`** (static, exact decode):

```
c744  ldr  r3, [r0]          ; vptr
c746  movw r2, #0x413        ; second argument
c74a  ldr  r3, [r3, #0x20]   ; slot 8 of the receiver's table
c74c  bx   r3                ; tail dispatch
```

Slot 7 is not interchangeable with slot 8: it re-dispatches slot 8 of
**whatever table the receiver points to**, with a fixed `r2`.

**Identification (probable, pattern-matched only).** The layout matches
the Arduino SAMD core's `Uart` class:

- slot 7 is `begin(baud)`, which calls `begin(baud, SERIAL_8N1)`; `0x413` is
  `SERIAL_8N1`;
- slot 8 (`c7c0`) is `begin(baud, config)`, which configures pins, then
  calls `initUART` (`b658`), `initFrame`, `initPads` and `enableUART`.

The rest of this report uses "begin-like" only in that sense. No conclusion
depends on the names.

**Path calls** (static; `straight_line_call`):

| Call | Caller → callee | Direct BL | On every path from caller entry | `r0` at the call |
|---|---|---|---|---|
| `0xc84a` | `c7c0 → b658` | yes | yes (4 calls before it: `d40c`×3, `d300`) | `ldr r0, [r4, #0x10]`, `r4 = this` |
| `0xb662` | `b658 → b5bc` | yes | yes | caller's `r0`, unchanged |
| `0xb5c2` | `b5bc → b4b4` | yes | yes | caller's `r0`, unchanged |

So if `c7c0` runs to `0xc84a`, `b4b4` receives `r0 = *(this + 0x10)`.

`b4b4` loads the word at `[r0]` and compares it with the six SERCOM base
constants. It returns their index 0–5, or −1. It never dereferences the
loaded word.

## 3. The 86 register-indirect sites

Each site's target register is traced by the new
`tools/census/indirect_target.py` (§7). It follows every reaching
definition back over census blocks and edges, across joins, and reports the
dataflow shape.

Ghidra's decompiler was then compared function by function: 55 functions,
78 sites. The vtable offsets it dispatches through match in every function.
That comparison shares Ghidra's CFG but not this tool's dataflow.

Two mismatches were investigated before that result held:

- **A resolver gap.** `aa0c` loads the vptr with `ldrd r3, r2, [r0]`, which
  the resolver did not model. The decompiler was right, and `LDRD` support
  was added.
- **A cross-check regex miss.** The decompiler prints slot 0 as
  `*(code **)*param_1`, which the regex did not match. It was not a tool
  disagreement.

**The reported 56, by shape:**

| Shape | Sites | Slot-7/8 relevance |
|---|---|---|
| vtable slot `ldr rT,[rV,#d]` with `rV = ldr [rO]` | 25 | 24 excluded (`d` ∈ {0, 4, 8, 0xc, 0x10, 0x14}); **`0xc74c` possible (`d = 0x20`)** |
| several reaching definitions | 6 | `a340` (object fields `+8`/`+0xc`/`+0x10`) and `b0d4` (vtable `+0x24`) excluded; `ee38`, `f092`, `f396`, `f3b6` unresolved (argument + unknown) |
| callback argument (`blx r7` = incoming `r3`) | 16 | unresolved: `FUN_0000ec48` ×15, `FUN_0001059c` ×1 |
| object field `[arg + d]` | 3 | excluded (`FUN_0001026c` `+0x28`/`+0x2c`) |
| stack spill | 3 | unresolved (`FUN_0000f0b4`) |
| indexed table `[b + i<<2]` | 2 | unresolved (`cb92` RAM table `0x2000525c`; `10e1a` loaded base) |
| pointer-array walk | 1 | unresolved (`e5f8`) |

Totals: of the 56, 1 is possible, 29 excluded and 26 unresolved. Of all 86,
1 is possible, 58 excluded and 27 unresolved. The extra unresolved site is
`e602`, an observed init-array walk.

The complete per-site record is in `inventory.json`. For each site it gives:

- the instruction, register and both attributions;
- the reaching definitions and pattern;
- the slot offsets, and the potential `0x14900` targets;
- reachability, boot observation, Macaw discovery and the decompiler check;
- the reasons for its relevance status.

**Why these sites are excluded.** A load reads a slot-7 or slot-8 entry
(`0x1491c`/`0x14920`) only through a base `b` with `b + d` equal to that
entry. The image was swept for every constant it can materialize within
4 KB below the entries (`0x13921..0x14920`): aligned words, `movw/movt`
pairs and `adr`. That finds 24 constants and no `movw/movt` or `adr`.

Under the offsets the sites actually use, only `0x14900 + 0x20` lands on an
entry. The exclusion holds under three assumptions:

- **A1.** No pointer arithmetic forms a table pointer, and no copy of the
  table or of its entries exists.
- **A2.** The census inventory plus the halfword sweep cover the transferring
  code.
- **A3.** The bounded reaching definitions are complete. Incomplete results
  stay unresolved.

**Macaw.** 4 of the 56 lie in Macaw-discovered blocks (`b246`, `b2be`,
`cb92`, `e5f8`), all as unresolved indirect calls. The other 52 are in code
Macaw's vector-seeded discovery does not reach. Macaw resolves none of them.

## 4. Objects and provenance

**One vptr store.** `vptr_installations` finds 8 constructor stores in the
image, one per vtable. Only `FUN_0000c8bc@0xc8d0` installs `0x14900`:
`str r3, [r0], #0x14`, with the literal `0xc90c`.

That literal is the only flash materialization of `0x14900`:

- no other aligned word, `movw/movt` pair or `adr` produces it;
- the only flash words equal to `0xc745` or `0xc7c1` are the table entries
  themselves.

**Constructor calls** (static, constant arguments; boot-observed end state
matches):

| Call | Object | `this+0x10` (SERCOM object) | Word there at end of boot | Peripheral the word names |
|---|---|---|---|---|
| `0xb192` | A `0x20004348` | `0x20004c60` | `0x41014000` | SERCOM3 (`b4b4` index 3) |
| `0xb1a2` | B `0x20004644` | `0x20004c6c` | `0x43000000` | SERCOM4 (index 4) |
| `0xb1b2` | C `0x20004940` | `0x20004c48` | `0x40003400` | SERCOM1 (index 1) |

All three calls are in `FUN_0000b144`, a static constructor. Boot calls it
from the init-array walk at `0xe602`: observed target `0xb145`.

**Uses of the objects.** Every flash literal that names an object is
followed by a direct transfer:

- **Object A**, from application code:
  - `0x7f18 bl c74e` (slot 6);
  - `0x7f66 bl cb18` (slot 5);
  - `0x7fc2 b.w ca58` (slot 0);
  - `0x804c bl c93e` (slot 4);
  - `0x8c5a b.w b1f4` (slot 1).
- **Objects A, C and B**, from the interrupt handlers `0xb0fc`, `0xb114` and
  `0xb12c`: `b.w c980` (not a slot).
- **All three**, from `b144`: the constructor calls.

There is no direct transfer to slot 7 or slot 8. The code calls this
object's methods directly (devirtualized), and among those direct calls
`begin`-like slots 7 and 8 do not appear.

Inside slot 1's body, `0xb20a` dispatches slot 0. Its recorded path
receiver is object A, through the `0x8c5a` tail branch. Its other entries,
through the vtable word, are not followed. It loads `+0x0`, never slot 7
or 8.

**Field stability.** The v2 watched-field result is reused, not repeated:
each vtable word and `this+0x10` field was stored once in boot. This pass
adds end-of-boot RAM:

- `0x14900` appears exactly at the three objects;
- no RAM word holds `0xc745`, `0xc7c1` or any other pointer into the table.

This is an end state only; a transient copy is not excluded.

## 5. Dispatch edges and reachability

Roots are those of the census reachability reduction: the reset vector, 2
system vectors, 40 IRQ vectors, and 133 confirmed indirect targets.

| Edge | Status | Basis |
|---|---|---|
| any site → `0xc744` (slot 7) | **UNRESOLVED** | no direct transfer (exhaustive halfword sweep: `BL`, `B.W`, `B<c>.W`); no analyzed site can load `+0x1c` from a table base; 27 sites unresolved |
| `0xc74c` → `0xc7c0` (slot 8) | **CONDITIONALLY_POSSIBLE** | target `= [[r0] + 0x20]`, established; `0xc7c0` iff the receiver's vptr is `0x14900`. Other vtables' `+0x20` is `0xa7ec`. Receiver is live-in at an unattributed, pointer-entered block |
| any other site → `0xc7c0` | EXCLUDED_WITHIN_ANALYSIS_SCOPE for 58 sites; UNRESOLVED for 27 | §3 |
| `0xc84a` `c7c0 → b658` | STATICALLY_ESTABLISHED (given `c7c0` runs) | direct BL on every path |
| `0xb662` `b658 → b5bc` | STATICALLY_ESTABLISHED (given `b658` runs) | direct BL |
| `0xb5c2` `b5bc → b4b4` | STATICALLY_ESTABLISHED; OBSERVED via other `b5bc` callers | direct BL; 270 boot calls |
| the path from a root | **UNRESOLVED** | first link missing |

Containing-function reachability of the 56:

- 21 are STATICALLY_ESTABLISHED (census DEFINITELY_REACHABLE);
- 35 are UNRESOLVED (no known path, or unattributed);
- none was OBSERVED.

**Concrete boot** (`boot-dispatch.json`; 450,000 instructions, budget;
14 disclosed assumptions):

- all 86 register-indirect sites were watched;
- 29 executed, exactly the census `DYNAMICALLY_OBSERVED` set;
- none of the 56 executed;
- no vtable-shaped dispatch saw a `0x14900` object as its receiver;
- at `0xe602` (init-array walk) `r0` held object C. That `r0` is a stale
  register, not a receiver.

## 6. Hypotheses

| | H1: a reachable dispatch enters the path | H2: present but unused | H3: unresolved |
|---|---|---|---|
| For | `0xc74c` can load slot 8; the path calls are direct and unconditional; 27 sites are unresolved | `begin`-like slots are never called directly while slots 0, 1, 4, 5 and 6 are; no site loads `+0x1c`; 0 boot entries | the 27 unresolved sites, the 35 sites with unresolved containing reachability, end-of-boot-only RAM evidence |
| Against | no entry to `0xc744` found; `0xc74c` lives inside slot 7 | the 27 unresolved sites; a lack of callers is not exclusion | — |
| Assumes | an unresolved site's runtime value equals `0xc745`/`0xc7c1` | A1–A3; that the analyzed roots are complete | — |
| Next test | a scenario that drives a serial `begin` (UART reconfiguration) under concrete execution, watching `0xc744`/`0xc7c0` | caller-argument provenance for the 16 callback sites (§9) | either of those |

**Verdict on the question: H3, narrowed.** The only candidate dispatch is
the thunk's own tail call. Every other analyzed site is excluded within the
stated scope, apart from 27 whose targets come from callbacks, spills or
runtime tables.

## 7. Capability added

**`tools/census/indirect_target.py`** (analysis `indirect_target` v1) adds
`resolve_indirect_call(conn, firmware_key, image, site, vtables=…)`. It
extends the census's own `fnptr_resolve` and `indexed_writes` machinery.

**What it does:**

- Computes the reaching definitions of the branch register, as a union over
  every predecessor rather than only a single-predecessor chain.
- Handles IT-conditional definitions, call clobbers, register moves,
  writebacks, `LDRD`, stack slots and literal pools.
- Marks code-pointer-entered blocks as indirect entries.
- Classifies the definitions as one of: constant, constant slot, vtable
  slot, object-table slot, object field, indexed table, pointer iteration,
  argument, call result, multiple, or unresolved.
- Computes potential targets for a vtable slot only against vtables the
  caller supplies, each labeled with its condition.
- Never claims a dispatch or a reachability.
- Every result records the firmware digest, its bounds and its limitations.

`vptr_installations()` lists the constructor vptr stores.

**`tools/census/slot_dispatch.py`** (v2) now also reports `B.W` and
`B<c>.W` direct branches. v1 decoded only `BL`, so it would have missed the
tail branches `0x7fc2` and `0x8c5a`.

**Planner integration:**

- The agent operation `indirect_call_target(site)` validates the site
  against the census's register-indirect inventory.
- ResearchController offers `resolve_indirect_call(site)`:
  - only for sites already named in session evidence;
  - at most 2 per session, with duplicates withheld.
- Grades: STRONG only for a statically established target; PROBABLE for a
  conditional candidate set.
- Every result carries four limitations: potential-target, not
  reachability, intraprocedural, heuristic boundaries.
- Results derive a scoped `[DF]` session fact.

## 8. Planner trials

**Setup.**

- Seed `FUN_0000c5cc`; objective asks what its indirect call can reach and
  whether it could dispatch through slot 7 or 8 of `0x14900`.
- The objective does not name the tool.
- 6 steps per run; recorded in a fresh scratch copy of the ledger.
- Record: `planner-trials.json`.

**Scripted** (a scripted selection, not autonomous):

- Offered with exactly one grounded site, `0x0000c6d8`; it appears in the
  seed's disassembly.
- Executed through the real executor and recorded as
  `TI-3476399b1621604f`.
- Graded PROBABLE, with the four limitation codes.
- Its replay matched.

**Live** (local oMLX, `Qwen3-Coder-30B-A3B-Instruct-4bit`, 3 trials):

| # | Chose the tool | Site | Later steps | Final claims |
|---|---|---|---|---|
| 1 | yes, at step 1 | `0x0000c6d8` | peripheral census, function effects, 3 leads | admitted PROBABLE "`FUN_0000c7c0` is called by `FUN_0000c5cc`" (E7, E8) |
| 2 | yes, at step 1 | `0x0000c6d8` | same | admitted PROBABLE "`FUN_0000c5cc` can call `FUN_0000c4b8` or `FUN_0000c7c0`" (E7, E8) |
| 3 | yes, at step 1 | `0x0000c6d8` | same | same as 2 |

Each trial also had one claim rejected as `ENTITY_MALFORMED` (`E0000c5cc`).

What the trials show (one model, one objective, so none of this is a rate):

- **Selection.** Qwen selected the operation unprompted in all three trials.
  It was offered once per run, because the session had only one grounded
  site.
- **Interpretation.** Its claims never cited the `indirect_call_target`
  evidence, and did not use its slot or potential-target content. This
  matches the v2 finding for the observation tool.
- **An admission gap, not repaired here.**
  - E8 is `function_facts(FUN_0000c7c0)`, which reports **no callers**.
  - The admitted claims nevertheless state or imply a `c5cc → c7c0` call,
    the second as a disjunction with a true callee.
  - Admission checks identifiers and citations, not call relations. The
    claims exist only in the scratch ledger. Fixing this is out of scope:
    admission and canonical claim states are unchanged by this milestone.

## 9. What would change the answer

| Finding | Effect |
|---|---|
| A concrete scenario reaching `0xc744`/`0xc7c0` (a serial `begin`) | H1 observed; its `this` gives `b4b4`'s `r0` directly |
| Caller-argument provenance for the 16 `ec48`/`1059c` callback sites, or the `f0b4` spill slots | they leave UNRESOLVED; one of them could only matter by supplying `0xc745`/`0xc7c1` |
| A fourth object with vtable `0x14900`, or a store to `this+0x10` after construction | the SERCOM conclusion in §10 no longer holds |
| A RAM copy of the table or of its slot-7/8 words | A1 fails; the 58 exclusions must be redone |

## 10. SERCOM0 implications

- **What changed.** The missing link is now one specific edge: an entry
  into the slot-7 thunk `0xc744`, or a slot-8 load other than `0xc74c`.
  Nothing analyzed establishes that edge.
- **What the path would pass if it ran.** For all three objects that hold
  vtable `0x14900`, `b4b4` would receive the RAM SERCOM object of SERCOM3,
  SERCOM4 or SERCOM1. It would read that object's first word, which is RAM,
  and return index 3, 4 or 1. No `0x14900` object is bound to SERCOM0's
  object `0x20004c3c`. This rests on static constructor arguments and the
  observed end of boot. Fields not seen to change are not proven immutable.
- **Where SERCOM0 MMIO could come from.** `b4b4` touches no MMIO itself
  (static decode: one load at `[r0]`). It could access SERCOM0 registers
  only if a caller passed an `r0` inside SERCOM0's window. On this path
  that `r0` is `*(this + 0x10)`, which the constructors set to RAM.
- **What is not established.** "`b4b4` never accesses SERCOM0" remains
  unestablished: unknown objects, unresolved dispatch and real hardware are
  outside this analysis. The RAM reads and the hypothetical MMIO reads stay
  separate, as in v1/v2.

## 11. Reproduce

```sh
tools/unicorn/.venv/bin/python3 tools/census/test_indirect_target.py
tools/unicorn/.venv/bin/python3 tools/census/test_slot_dispatch.py
tools/unicorn/.venv/bin/python3 cases/performing-rigs/test/test_indirect_dispatch.py
(cd agent && .venv/bin/python -m pytest -q tests/test_indirect_call_target.py)

# one site (deterministic JSON)
agent/.venv/bin/python tools/census/indirect_target.py autopilot868 --site 0xc74c --vtables-from-installations

# the investigation (static + Macaw + Ghidra decompiler + one boot)
tools/unicorn/.venv/bin/python3 cases/performing-rigs/scripts/indirect_dispatch_investigation.py

# planner trials into a NEW scratch ledger (refuses the canonical one)
agent/.venv/bin/python cases/performing-rigs/scripts/indirect_dispatch_planner_trials.py \
    --ledger-dir "$TMPDIR/indirect-dispatch-ledger" --live 3
```

**Outputs** (`research/runs/indirect-dispatch-v1/`):

- `inventory.json`: every indirect site;
- `vtable.json`: layout, installations, materializations, objects and path
  calls;
- `boot-dispatch.json`: per-site boot observations and the end-of-boot RAM
  scan;
- `summary.json`: input and tool hashes, counts, groups, the sweep, the
  slot-7/8 results and their assumptions;
- `planner-trials.json`: the planner trials.

**Reproducibility.** Two independent runs of the investigation produced
byte-identical outputs.
