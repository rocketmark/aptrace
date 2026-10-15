# P-code Forward Use v1: AutoPilot 868 results

This note is the case-side record for the framework operation
`value_forward_use`, documented in
[`docs/tooling/pcode-forward-use.md`](../../../docs/tooling/pcode-forward-use.md).
It applies the operation to the open question from
[`callback-argument-provenance-v1.md`](callback-argument-provenance-v1.md)
§5–§7 and to the code pointers left over from the architecture spike
([`architecture-eval-v1.md`](architecture-eval-v1.md)).

**Inputs.**

| Input | Value |
|---|---|
| Firmware | `firmware_autopilot868.bin`, sha256 `6dcdb4c1…52e3`, base `0x4000` |
| Ghidra | 12.1.3, `ARM:LE:32:Cortex` (language 1.108), cspec `default` (`__stdcall` prototype: r0–r3 and s0–s15 arguments, r0 return) |
| Project | `runs/ghidra_cache/autopilot868`, identity `meta.json` sha256 `3bf4c7c0…a04e`; copied to a scratch workspace and opened read-only |
| Walker / driver | sha256 `2de9ae3d…921c` / `43b07cb9…cba0` |

Raw outputs are in [`runs/pcode-forward-use-v1/`](runs/pcode-forward-use-v1/).

**Not changed:**

- the canonical ledger, claims and Beads state;
- the census database and the Ghidra project;
- every callback-provenance classification.

Ledger records were written only to scratch copies.

## 1. The `0xea54` load [static, complete, BOUNDED]

| Field | Result |
|---|---|
| Origin | `0x0000ea54` `ldr r3,[0x0000eafc]`; tracked `r3` |
| Value | `0x0000ec49`, read from flash `0xeafc`. Ghidra's language rule normalizes it to the code address `0x0000ec48` = `FUN_0000ec48`. |
| Scope | `FUN_0000e8a8`, body 574 bytes; 3 instruction visits |
| Uses | `COMPARE` at `0xea56` (`cbnz r3`); `DEAD` at `0xea58` (`ldr r3,[sp,#0xc]`) and at `0xeaa0` (`add r3,sp,#0xc`) |
| Verdict | `NO_ESCAPE_WITHIN_SCOPE`, complete, no incompleteness reasons |
| Ledger | operation key `d51982cd…a5e3`; evidence `EV-712998836c269120` graded `BOUNDED`; limitation codes `CALLING_CONVENTION_MODEL`, `FUNCTION_BOUNDARIES_HEURISTIC`, `INTRAPROCEDURAL_DERIVATION_ONLY`, `NO_ESCAPE_IS_WITHIN_FUNCTION_SCOPE` |
| Replay | two replays byte-identical (result sha256 `6462256f…f9d`); 2.7 s per invocation |

This reproduces the spike's raw p-code probe and its Capstone-v2 walker
exactly. It is also consistent with the decompiler slice, the Macaw IR and
the single concrete path recorded in `architecture-eval-v1.md`.

The difference from the spike: the result is now a typed, replayable ledger
operation. It is not a probe, and it is not a manual reading.

## 2. Every census code-pointer reference

The census rows checked are every `literal_refs` row that references a
`function_pointers` flash word with a known target. All of them ran in one
invocation: 3.1 s wall, 25 ms of analysis, 352 MB peak.

| Origin | Ref | Function | Result | vs spike p-code | vs Capstone v2 |
|---|---|---|---|---|---|
| `0xbc76` | READ | `FUN_0000bc44` | ARGUMENT at `bl 0xccc4` | agree | agree |
| `0xea54` | READ | `FUN_0000e8a8` | no escape | agree | agree |
| `0xeaa6` | READ | `FUN_0000e8a8` | ARGUMENT at `bl 0xec48` | agree | agree |
| `0xeada` | READ | `FUN_0000e8a8` | ARGUMENT at `bl 0xf190` | agree | agree |
| `0x10412`, `0x10416`, `0x1041a` | READ | `FUN_000103f0` | STORE `[r4,#0x24/0x28/0x2c]` | agree | agree |
| `0x10438` | READ | none (unattributed stub) | ESCAPE: ARGUMENT, tail transfer into `0x1059c`; INCOMPLETE `NO_CONTAINING_FUNCTION` | the spike reported INCOMPLETE with no uses; this finds the escape as well | same escape; Capstone calls itself complete because it was handed the stub range as an assumption (scope difference) |
| `0x9942`, `0xb04a`, `0xb82e` | DATA | — | UNSUPPORTED `NO_VALUE_OUTPUT` (a store defines no value) | — | — |
| `0xab2a`, `0xae28`, `0xaefc` | DATA | various | analyzed the store's **writeback base register**, not a pointer | — | — |

The `DATA` rows are stores. Ghidra attributes them to pointer-table words in
flash; they are not loads of the pointer. The planner offering therefore uses
`READ` rows only.

The three writeback results are correct for what they track: the `tracked`
field names the base register. They answer a different question, which is a
reason to keep origins grounded in census loads.

## 3. Backward/forward duality with `indirect_target` v2 [static, same lineage]

For each of the census's **86** register-indirect sites, every top-level
reaching definition that `indirect_target` v2 reports with an instruction
became an origin, with the branch register named. That is 95 definition
pairs over 76 distinct origins, in one invocation: 2.7 s wall, 87 ms of
analysis.

Each origin was traced forward in p-code to see whether it reaches its site
as a `CONTROL_TRANSFER`.

| Outcome | Pairs |
|---|---|
| p-code reaches the site (agree) | **95 / 95** |
| — with p-code complete | 46 |
| — escape found, then `COMPUTED_FLOW_UNRESOLVED` at the `bx rN` site itself (the walk cannot continue through an unresolved computed jump) | 41 |
| — v2 PARTIAL sites in unattributed code, with `NO_CONTAINING_FUNCTION` (7 also have `COMPUTED_FLOW_UNRESOLVED`) | 8 |

What this establishes:

- every definition the Capstone backward analysis finds is confirmed by
  p-code semantics, across loads (61), moves (31) and stack arguments (3);
- this includes the IT-predicated, `ldrd` and stack-argument shapes the spike
  listed as untested.

What it does not establish:

- whether v2 **misses** definitions. That needs a p-code backward analysis
  (the next milestone in
  [`pcode-migration.md`](../../../docs/tooling/pcode-migration.md)).
- independence. Both sides use Ghidra's blocks and boundaries, so this is a
  semantics-layer consistency check, not corroboration.
- the 2 v2 definitions with no instruction (`incomplete`). They were not
  tested.

## 4. What this changes for the 17 `ec48` sites, and what it does not

**Removed.** Before this result, callback-argument-provenance-v1 §5 had only
a manual reading [manual static; not an operation result] for the single
known use of `ec48`'s address (`0xeafc`, loaded at `0xea54`). That use is
now a recorded, replayable operation result: the loaded value is only
presence-tested and is overwritten on both successors, with nothing escaping
`FUN_0000e8a8`.

That was the one remaining open input for the 17 `ec48` sites in the §7
plan.

**Not changed here.**

- No callback-provenance result, classification or claim changes.
- The 17 sets stay OPEN in the recorded operation. The composition is not
  made.

**What closing them would still require.** A callback-provenance version
bump would have to state and check all of the following:

1. **The materialization inventory is complete.** `ec48`'s address exists
   only as the aligned flash word `0xeafc`. The spike checked halfword
   alignment too. There is no `MOVW`/`MOVT`, and no recorded indirect-edge
   candidate. Assumption A2 (no ADR or computed materialization) still
   applies.
2. **Every reader of that word is known.** Today the only reader is the
   Ghidra reference `0xea54`. A read through a computed address, a copy of
   the containing flash region (for example a data-init copy), or code
   outside the census decode would not appear. A1 covers decode, but not
   non-literal reads of the word.
3. **Every address-taken load is a complete `NO_ESCAPE_WITHIN_SCOPE`.** That
   is now true for the one load. The rule must refuse INCOMPLETE and
   UNSUPPORTED.
4. **The result is recorded as a new callback-provenance analysis version,**
   with the rule, A1–A4 and the condition (2) assumption in its
   limitations. Historical v1 evidence keeps its OPEN results.

If all four hold:

- the 17 sets would close on {`0xe882`};
- the 3 `f0b4` sites would follow from the two recorded one-hop results.

None of this says anything about whether `0xc744` is reached.

## 5. Planner trials [`Qwen3-Coder-30B-A3B-Instruct-4bit`, scratch ledgers]

[`runs/pcode-forward-use-v1/planner-trials.json`](runs/pcode-forward-use-v1/planner-trials.json):

- seed `FUN_0000e8a8`;
- objective: where does the loaded pointer to `FUN_0000ec48` go;
- 5 steps.

The operation was offered once the seed's disassembly put `0xea54` in
evidence.

**Scripted.** It ran through the real investigator, recorded and replayed
the operation, and produced the same evidence id as the standalone run.

**Live, two batches of 3.** The first batch was run with an earlier walker
that differed only in a timing field; its outputs live in the scratch ledger
and are summarized here. The second batch is in the JSON.

| | Batch 1 | Batch 2 |
|---|---|---|
| Selected `trace_value_use(0x0000ea54)` as step 1 | 3/3 | 3/3 |
| Verdict read into session facts | correct, scoped ("covers this one load only") | same |
| Second trace | `0xeaa6` ×2, `0xbc76` | `0xbc76` ×3 |
| Claims admitted (PROBABLE, untyped) | 3 | 3 |
| Claims that are correct | 1 ("e8a8 loads `0xe883` and passes it to `ec48`") | 0 |

**Selection works. Interpretation does not.** Five of the six admitted claims
merge two results into a false statement:

- "e8a8 … passes [the pointer to `ec48`] to `ec48`" (×1);
- "e8a8 loads `0xec48` and passes it to `ccc4`" (×3), where the `ccc4` call
  belongs to `FUN_0000bc44`;
- "e8a8 … passes it to `ccc4`" (×1).

Each cites only the second result. Admission accepts them by design: untyped
prose is a PROBABLE hypothesis and is checked only for peripheral and
call-relation rules. Two gaps let these through:

- the call-relation classifier does not read "passes X to `FUN_Y`" as a call
  relation;
- `call_relations` extracts no edges from `value_forward_use`.

Admission was not changed in this milestone. These claims exist only in
scratch ledgers.

## 6. Reproduce

```sh
python3 tools/ghidra/test_pcode_forward_use.py                         # framework controls
tools/unicorn/.venv/bin/python3 cases/performing-rigs/scripts/pcode_forward_use_parity.py
agent/.venv/bin/python cases/performing-rigs/scripts/value_forward_use_ea54.py
agent/.venv/bin/python cases/performing-rigs/test/test_value_forward_use.py
agent/.venv/bin/python cases/performing-rigs/scripts/value_forward_use_planner_trials.py \
    --ledger-dir "$TMPDIR/vfu-ledger" --live 3
```
