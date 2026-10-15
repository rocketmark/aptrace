# Callback-Argument Provenance v1

**Question.** Where do the targets of the unresolved callback indirect calls
come from, one call boundary up? Could any caller supply the target needed
to enter the slot-7 thunk `0xc744`?

**Short answer (PARTIAL).**

1. **One real callback value crosses a function boundary, with
   provenance.**
   - `e8a8` calls `ec48` at `0xeaac` (`bl`).
   - It passes `r3 = 0x0000e883`, loaded from the literal `0xeb00`.
   - That value is a valid Thumb code pointer to `FUN_0000e882`.
   - The same value reaches `f190` through `0xeae0`.
2. **The reported relationship is a constant, not a forward.**
   - `e8a8 → ec48` supplies a literal. `e8a8` does not forward one of its
     own arguments.
   - The real forwarding edges are `ec48 → f0b4` (`0xed00`) and
     `f190 → f0b4` (`0xf2ec`). Each passes its own incoming `r3` as
     `f0b4`'s stack argument 4.
3. **23 argument-derived sites were analyzed:**
   - 20 have a CONCRETE caller value;
   - 3 are FORWARDED_ARGUMENT;
   - none is MEMORY_DEPENDENT or UNKNOWN.
4. **`0xc744` is a candidate at no site.**
   - It is **excluded within scope** at 3 sites: `f396`, `f3b6` and
     `105d2`, whose target sets are CLOSED.
   - It is **not excluded** at 20 sites, whose sets are OPEN.
   - For each OPEN site the missing upstream value is named (§5).
5. **No existing scenario reaches any of this code.** Boot and the 10
   virtual-link scenarios were checked, with 66 observations.

`0xc744` stays unestablished, not unreachable. The SERCOM0 global negative
is still not established. The canonical ledger, census DB and claims are
unchanged.

Firmware `firmware_autopilot868.bin`, sha256 `6dcdb4c1…52e3`. Census DB
read-only. Evidence levels are tagged in brackets: [static], [concrete],
[manual static].

## 1. Baseline

- Branch `feat/callback-argument-provenance` from `main` at `24fa33b`
  (call-relation admission). The working tree was clean.
- Test baseline:
  - agent: 515 passed, 1 skipped;
  - all census and case tests passed.

**The callback inventory, re-derived from `indirect-dispatch-v1/inventory.json`:**

| Group | Sites | v1 shape |
|---|---|---|
| The 16 "callback argument" sites | `ec48` ×15 (`ee60`…`f05e`), incoming `r3` via `mov r7, r3`; `105d2` in `1059c`, incoming `r1` via `mov r8, r1` | `argument` |
| Argument plus a hit bound | `ee38`, `f092` (`ec48`) | `multiple` (block limit 64) |
| Argument plus switch-case blocks | `f396`, `f3b6` (`f190`) | `multiple` (blocks treated as pointer entries) |
| "Stack spills" | `f114`, `f152`, `f184` (`f0b4`) | `unresolved` (stack slot) |
| Runtime table or walk | `cb92`, `10e1a`, `e5f8`, `e602` | indexed / pointer-iteration |

These 27 sites are the v1 unresolved set. The 16 are a subset.

## 2. Capability

### `indirect_target` v2: narrow fixes the callback sites needed

Each fix closes a gap located by a first divergence:

- **Resolved jump tables.** `f190`'s `ldr.w pc,[r0,r3,lsl #2]` at `0xf1cc`
  is a STATICALLY_RESOLVED table. Its 22 words sit at `0xf1d0..0xf227`.
  - v1 followed only fallthrough/branch/cbranch edges.
  - v1 also flagged every case block as a code-pointer entry, because the
    table words are Thumb pointers.
  - v2 follows the resolved `computed-jump` edges of such sites. It drops
    their table words, and only those, from the pointer-entry set.
- **Stack arguments.** A load `ldr rT,[sp,#d]` in the entry block is AAPCS
  stack argument `4 + (d − Δ)/4` when both of these hold:
  - SP's offset Δ is known from the prologue (`push`, `vpush`, immediate
    `sub sp`; `vpush` is mnemonic-modeled);
  - nothing stores into the frame first.

  `f0b4`: `push {8 regs}; ldr.w r8,[sp,#0x20]` gives argument 4. `ec48`'s
  `ldr.w r8,[sp,#0x60]` after `push`+`vpush`+`sub` is also argument 4. A
  store-then-reload stays a spill.
- **Constants.** `movw` (this Capstone build reports it with the `MOV` id),
  `movt`, `adr`, and add/sub-immediate across blocks.

Compatibility over all 86 register-indirect sites at the v1 bound
(`site-derivations-v2.json`):

- exactly 6 change: `f114`, `f152`, `f184`, `f396` and `f3b6` gain
  argument shapes, and `b0d4` goes PARTIAL→ESTABLISHED;
- no candidate target changes anywhere.

### `tools/census/callback_provenance.py` (analysis `callback_provenance` v1)

`trace_callback_argument(site)` takes these steps:

1. It runs the v2 derivation with a 128-block bound (`ec48` has 107
   blocks) and takes each `argument` origin as `(entry, argument)`.
2. It sweeps every halfword for `BL`, `B.W`, `B<c>.W` and 16-bit
   `B`/`B<c>` into the entry.
   - A hit is a caller only where the census decodes an instruction.
   - Callers are cross-checked against census call/branch edges. A
     census-only edge, or a 32-bit hit outside decoded code, opens the
     set.
   - A `BLX` immediate is an *invalid transfer*: UNDEFINED on M-profile.
   - A branch back to the entry from inside the function is not a caller.
3. At each caller it derives the same argument: the register, or the word
   stored at the outgoing slot `[sp,#4(k−4)]` in the transfer's block.
   The derivation uses the same reaching-definition machinery.
4. It classifies each value as follows. The site status is the most
   limiting value.

   | Status | Value |
   |---|---|
   | CONCRETE | one constant |
   | FINITE_TARGET_SET | several constants (a join or IT definition) |
   | FORWARDED_ARGUMENT | the caller's own argument; the next hop is named, not taken |
   | MEMORY_DEPENDENT | a RAM slot, object field or table load |
   | UNKNOWN | anything else, including a call result or a hit bound |

5. It checks every constant with `fnptr_resolve.canonical_code_pointer`:
   - a valid value needs the Thumb bit, an in-image address and a
     decodable instruction;
   - `NULL`, `THUMB_BIT_CLEAR` (BLX would raise INVSTATE),
     `OUTSIDE_IMAGE` and `DOES_NOT_DECODE` values are kept and labeled,
     and never become targets;
   - the raw value is retained beside the normalized target.
6. **CLOSED** requires all of the following:
   - a complete site derivation;
   - complete caller sets: no flash-word or `MOVW`/`MOVT` materialization
     of the entry, no census-only edge, no undecoded hit, no truncation;
   - every caller value constant.

   Anything else is **OPEN**, with reasons.

Each result also carries:

- callee-to-site static path (CFG only, feasibility *not* established);
- caller conditionality;
- caller and target census reachability;
- recorded census coverage;
- next hops;
- bounds: callers 16, blocks 128, definitions 16, targets 16, work 4096,
  path 512;
- work used and limitations.

### Agent and planner

The agent operation is `callback_argument_provenance(site)`:

- **Eligible sites:** census register-indirect sites only. No address,
  path, bound or hop count is accepted from the planner.
- **Recorded inputs:** census DB plus 6 tool modules.
- **Grade:** STRONG only for a CLOSED constant set; PROBABLE for useful
  but open results; UNKNOWN otherwise.
- **Limitation codes:**
  - `ONE_HOP_CALLER_PROVENANCE`
  - `POTENTIAL_TARGET_NOT_DISPATCH`
  - `DISPATCH_IS_NOT_REACHABILITY`
  - `CALLER_SET_OPEN`
  - `PROVENANCE_ANALYSIS_BOUNDED`
  - `FUNCTION_BOUNDARIES_HEURISTIC`
- **Session fact:** a scoped `[DF]` fact, plus next-hop questions.

ResearchController exposes it as `trace_callback_argument(site)`:

- grounded sites only, at most 2 per session, duplicates withheld;
- sites whose `indirect_call_target` result names an argument come first.

Call-relation admission is unchanged in policy:

- decoded callers are DIRECT_CALL/TAIL_TRANSFER edges;
- recovered targets are `POTENTIAL_INDIRECT` edges conditional on the
  caller site ("IF entered from caller site S …"), never categorical.

So "`ec48` calls `e882`" is rejected, while "`ec48` may call `e882` if
entered from the call at `0xeaac`" is admitted.

## 3. Callback-site inventory (before → after)

Full rows: `inventory.json` and `callback-sites.json`.

| Site(s) | Function | Before (v1) | Argument source | Direct callers | Value | Candidates | Set | `0xc744` |
|---|---|---|---|---|---|---|---|---|
| `ee60` `ee80` `eeb4` `eed0` `eef0` `ef14` `efae` `efc4` `efd4` `efee` `f000` `f01a` `f02c` `f04e` `f05e` | `ec48` | argument, unresolved | `r3` of `ec48` | `0xeaac` bl (`e8a8`) | CONCRETE `0xe883` | `0xe882` | OPEN | not excluded |
| `ee38` `f092` | `ec48` | multiple PARTIAL | `r3` of `ec48` (complete at 128 blocks) | same | CONCRETE `0xe883` | `0xe882` | OPEN | not excluded |
| `f396` `f3b6` | `f190` | multiple PARTIAL | `r3` of `f190` | `0xeae0` bl (`e8a8`) | CONCRETE `0xe883` | `0xe882` | **CLOSED** | **excluded within scope** |
| `105d2` | `1059c` | argument, unresolved | `r1` of `1059c` | `0x1043a` b.w (unattributed stub `0x10438`) | CONCRETE `0x10379` | `0x10378` | **CLOSED** | **excluded within scope** |
| `f114` `f152` `f184` | `f0b4` | stack spill, unresolved | stack argument 4 of `f0b4` | `0xed00` bl (`ec48`, `str r7,[sp]`), `0xf2ec` bl (`f190`, `str.w sl,[sp]`) | FORWARDED (`r3` of `ec48`; `r3` of `f190`) | — | OPEN | not excluded |
| `cb92` `10e1a` `e5f8` `e602` | — | table / walk | not an argument | — | — | — | — | unchanged, not excluded |

**Counts:**

- Of the **16** callback sites:
  - all 16 gained a caller-grounded constraint;
  - 1 (`105d2`) is CLOSED.
- Of the **27** unresolved sites:
  - 3 are now excluded within scope;
  - 20 are constrained but open: 17 CONCRETE, 3 FORWARDED;
  - 4 are unchanged.

No site is globally resolved. "OPEN" means some other entry or upstream
value is possible.

Further facts [static]:

- `ec48`, `f190`, `f0b4`, `1059c`, `e8a8` and both targets are census
  `NO_KNOWN_PATH`.
- Every caller's root reachability is therefore **unresolved**.
- The `105d2` caller `0x10438` is unattributed and itself address-taken:
  its address `0x10439` is stored to `[r4,#0x28]` at `0x104c0` and to
  `[r6,#0x28]` at `0x1067a`.
- Each callee has a static CFG path from entry to every site. Feasibility
  is not established.

## 4. Concrete cross-check [concrete]

`observed_call_arguments` was run for `FUN_0000ec48`, `f190`, `f0b4`,
`1059c`, `e882` and `10378`, in all 11 registered scenarios (66 runs,
`dynamic.json`):

- Boot ran to its 450,000-instruction budget. The vl-* slices ran 101 to
  79,221 instructions.
- **No entry was observed into any of the six functions.**
- Every static call site (`0xeaac`, `0xeae0`, `0xed00`, `0xf2ec`, …) is
  UNOBSERVED.
- The census's own recorded boot coverage agrees: none of these PCs ran.

There is no observed value to compare with the static `0xe883`/`0x10379`.
Agreement or disagreement is therefore **not available**; it is not
assumed. No scenario was created.

## 5. `0xc744` implications

| Edge | Status | Basis |
|---|---|---|
| any callback site → `0xc744` with a recovered value | **none** | the only recovered values are `0xe883` and `0x10379` |
| `f396`/`f3b6` → `0xc744` | **EXCLUDED_WITHIN_SCOPE** | closed set {`0xe882`}; `f190` has one direct caller and no address-taken copy |
| `105d2` → `0xc744` | **EXCLUDED_WITHIN_SCOPE** | closed set {`0x10378`}; `r1` is loaded in the stub itself, so it does not depend on how the stub is entered |
| 17 `ec48` sites → `0xc744` | **UNRESOLVED** | missing: indirect entries into `ec48` (its address `0xec49` is the flash word `0xeafc`, loaded at `0xea54`) |
| 3 `f0b4` sites → `0xc744` | **UNRESOLVED** | missing: what callers of `ec48` and `f190` pass in `r3` (the next hop, not taken) |
| other 4 unresolved sites | unchanged | runtime table / pointer walk |

**Scope of the exclusions:**

- **A1.** The census plus the halfword sweep cover the transferring code.
- **A2.** No ADR-based or computed materialization of the entry exists.
  Only flash words and `MOVW`/`MOVT` are swept.
- **A3.** The bounded derivations are complete, as they are here.
- **A4.** The outgoing stack slot is not rewritten before the callee's
  load. This applies to the stack argument only.

**What a manual reading suggests [manual static; not an operation
result].**

- The only use of `ec48`'s address is `ldr r3,=0xec49; cbnz r3`, a
  presence test.
- `r3` is redefined on both successors (`0xeaa0 add r3,sp,#0xc` and
  `0xea58 ldr r3,[sp,#0xc]`) before the call.

If a mechanical check confirms this:

- `ec48` would have no indirect caller in the analyzed code;
- the 17 `ec48` sites would close on {`0xe882`};
- the 3 `f0b4` sites would be determined by the two already-recorded
  one-hop results, giving {`0xe882`}.

That composition is not made here.

None of this establishes or refutes an entry into `0xc744`:

- The callback sites' values are not it.
- The four runtime-table sites, and entries outside the analyzed code,
  remain.
- The concrete `begin`-like scenario from v1 §9 remains the direct test.

## 6. Planner trials (scratch ledger copies)

Record: `planner-trials.json`.

- Seed `FUN_0000ec48`. The objective names neither tool.
- 6 steps per run.

**Scripted** (not autonomous):

- Selections: `resolve_indirect_call(0xee60)`, then
  `trace_callback_argument(0xee60)`.
- Both invocations were recorded through the real executor:
  - provenance `TI-…` with operation key `e1088f12…`, graded PROBABLE,
    with 5 limitation codes;
  - the 7 recorded input artifacts include `callback_provenance_tool` and
    `census_slot_dispatch`.
- Both replays matched.
- Historical lookup reuses the identical operation ("identical operation
  … under current inputs"). The agent tests show it is refused when any
  input module or the analysis version changes.

**Live** (`Qwen3-Coder-30B-A3B-Instruct-4bit`, 5 trials):

| Measure | Result |
|---|---|
| Selected the new tool | 5/5, at step 2, after `resolve_indirect_call` at step 1 |
| Relevant site | 5/5 `0xee38`, an `ec48` callback site |
| Derived session fact | correct and scoped: "`0xeaac` (`e8a8`) passes `0xe883` [CONCRETE]; possible target `0xe882` (set OPEN)" |
| Claims citing the provenance evidence | trial 1 only (E4), rejected `ENTITY_SESSION_REFERENCE`: it used evidence ids as entities |
| Claims distinguishing concrete vs forwarded | none |
| Unsupported call claims admitted | 0; no claim at all was admitted |
| Useful next lead | no: trials 2–5 drifted to an unrelated `FUN_0000d388` PORT claim |

Selection works. Interpretation does not. This matches the previous two
milestones: Qwen chooses the operation but does not build claims from its
content. Trials 2–5 are identical, so this is one behavior, not a rate.

`indirect_call_target` on `0xee38` reports PARTIAL at its own 64-block
bound, while the provenance run (128 blocks) reports ESTABLISHED. This is a
disclosed bound difference, not a tool disagreement.

## 7. Next milestone (not implemented)

**A mechanical use check for address-taken entries.** For each literal
load of a function's Thumb address, follow the loaded register forward
within the function until one of these happens:

- it is redefined;
- it is compared or branched on and dies;
- it escapes into a store, a call argument or a register-indirect
  transfer.

Only an escaping copy keeps the caller set open. This is bounded,
intraprocedural, and reuses the census blocks and edges. On this image it
would test the single `0xea54`/`cbnz` use. That test decides whether 17
`ec48` sites close.

## 8. Reproduce

```sh
tools/unicorn/.venv/bin/python3 tools/census/test_callback_provenance.py
tools/unicorn/.venv/bin/python3 tools/census/test_indirect_target.py
(cd agent && .venv/bin/python -m pytest -q tests/test_callback_provenance.py)
agent/.venv/bin/python cases/performing-rigs/test/test_callback_provenance.py

# one site (deterministic JSON)
agent/.venv/bin/python tools/census/callback_provenance.py autopilot868 --site 0xee60

# the investigation (static + 66 existing-scenario observations)
agent/.venv/bin/python cases/performing-rigs/scripts/callback_provenance_investigation.py

# planner trials into a NEW scratch ledger (refuses the canonical one)
agent/.venv/bin/python cases/performing-rigs/scripts/callback_provenance_planner_trials.py \
    --ledger-dir "$TMPDIR/callback-provenance-ledger" --live 5
```

Outputs are in `research/runs/callback-provenance-v1/`:

- `provenance.json`
- `callback-sites.json`
- `inventory.json`
- `site-derivations-v2.json`
- `dynamic.json`
- `summary.json` (input and tool hashes)
- `planner-trials.json`

Two investigation runs produced byte-identical outputs.
