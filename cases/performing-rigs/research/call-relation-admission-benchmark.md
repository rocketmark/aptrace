# Call-Relation Admission: Indirect-Dispatch Benchmark

**Question.** Can an unsupported call relation still enter the ledger
because the planner asserted it?

**Answer.** Not the one the indirect-dispatch trials admitted. Correctly
scoped call claims about the same evidence are still admitted. The
mechanism is framework-level; see
[`docs/claim-call-relations.md`](../../../docs/claim-call-relations.md).

- Baseline: `feat/indirect-dispatch-resolution` at `3c74b5a`.
- Firmware: `autopilot868` (`6dcdb4c1…52e3`).
- Model: `Qwen3-Coder-30B-A3B-Instruct-4bit` (local oMLX).
- Objective, seed (`FUN_0000c5cc`), 6 steps and tool set unchanged from
  [`indirect-dispatch-resolution-v1.md`](indirect-dispatch-resolution-v1.md)
  §8.

## 1. What was admitted, and why

The three live trials of indirect-dispatch-v1 each admitted one claim at
`PROBABLE STRUCTURE`, citing E7 and E8:

| Trial | Admitted claim |
|---|---|
| 1 | `FUN_0000c7c0 is called by FUN_0000c5cc` |
| 2, 3 | `FUN_0000c5cc can call FUN_0000c4b8 or FUN_0000c7c0` |

What the cited evidence shows. These results were read from the trials'
surviving scratch ledger and match their recorded hashes; the benchmark
summary is not relied on.

| Session id | Result | Call content |
|---|---|---|
| E7 | `function_facts(FUN_0000c4b8)` | caller `FUN_0000c5cc` at `0xc66a`, so `c5cc → c4b8` is a direct call |
| E8 | `function_facts(FUN_0000c7c0)` | **no callers**; nine direct callees |
| E3 (not cited) | `indirect_call_target(0xc6d8)` | `CONDITIONALLY_POSSIBLE`; potential targets `0x991a`, `0xacd8`, `0xb702`, `0xbb22`, and `0xca58` (slot 0 of vtable `0x14900`), each only if the receiver holds that vtable. **`c7c0` is not among them.** |

Nothing cited, or recorded in the session, connects `c5cc` to `c7c0`.

Why admission passed:

1. **Shape.** The claims were well-formed. Every identifier was canonical
   and known, and every citation resolved.
2. **No check applied.** The only prose relation checks were peripheral
   access and absence. Call wording triggered nothing.
3. **Grade.** `PROBABLE` was within the untyped cap and below the cited
   evidence's ceiling (`STRONG`).
4. **No typed form.** No typed predicate represented a call relation.
   Candidate extraction states "call-site relations: not extracted", so no
   typed path existed either.

## 2. Reproduction

[`runs/call-admission-v1/trial-evidence.json`](runs/call-admission-v1/trial-evidence.json)
holds:

- the session evidence E1–E8, with durable ids and result hashes;
- the claim lines of all three trials.

All three trials recorded byte-identical results. E5, a 1.2 MB
`function_effects` result that no claim cited, is kept by hash only.

The baseline (`3c74b5a`, in a separate worktree) and the hardened code
admit the trial lines as follows:

| Proposal | Baseline | Hardened |
|---|---|---|
| `FUN_0000c7c0 is called by FUN_0000c5cc` (E7,E8) | admitted | rejected `CALL_RELATION_UNSUPPORTED` |
| `FUN_0000c5cc can call FUN_0000c4b8 or FUN_0000c7c0` (E7,E8) | admitted | rejected: `c4b8` checked, `c7c0` `CALL_RELATION_UNSUPPORTED` |
| `FUN_0000c5cc calls FUN_0000c7c0` (E1–E8) | admitted | rejected `CALL_TARGET_MISMATCH` (E1/E2 enumerate `c5cc`'s direct calls) |
| `FUN_0000c5cc calls 0x0000ca58` (E3) | admitted | rejected `CALL_CONDITION_OMITTED` |

The diagnostic for the original claim:

> `FUN_0000c5cc -> FUN_0000c7c0`: no cited evidence connects
> `FUN_0000c5cc` to `0x0000c7c0` (edges from `FUN_0000c5cc`: E7:
> `FUN_0000c5cc -> 0x0000c4b8` at `0x0000c66a` DIRECT_CALL; E8 lists no
> callers of `FUN_0000c7c0`); naming both functions in cited results is not
> an edge

The rule is general. No address appears in the implementation. Framework
tests apply the same shape to synthetic functions.

## 3. Deterministic checks on this evidence

[`test/test_call_admission.py`](../test/test_call_admission.py): 20
checks, all pass.

**Admitted:**

| Claim | Supported by |
|---|---|
| `c5cc calls c4b8 at 0xc66a` | E7 |
| `c5cc calls b890 at 0xc5ea` | decoded `BL` in E2 |
| `c5cc`'s indirect call at `0xc6d8` may dispatch to `0xca58` if the receiver's vptr is `0x14900` | E3, with its condition retained |
| `c7c0` has no recorded callers in the Ghidra call graph | E8 (`CALL_ABSENCE_SCOPED`) |

**Rejected:**

| Claim | Code |
|---|---|
| wrong call site (`c4b8 at 0xc6d8`) | `CALL_SITE_MISMATCH` |
| the `0xca58` target stated unconditionally | `CALL_CONDITION_OMITTED` |
| the `0xca58` target under another vtable's condition | `CALL_CONDITION_OMITTED` |
| `c7c0` under the `0x14900` condition (`c7c0` is no candidate of `0xc6d8`) | rejected |
| unscoped "`c7c0` has no callers" | `CALL_ABSENCE_NOT_ESTABLISHED` |

## 4. Live benchmark

5 trials, run after the deterministic tests passed:

- the same script, run with `--out` into scratch;
- a fresh scratch copy of the canonical ledger;
- no prompt changes.

Records:
[`planner-trials.json`](runs/call-admission-v1/planner-trials.json),
[`live-hardened.json`](runs/call-admission-v1/live-hardened.json), and
[`live-replayed-baseline.json`](runs/call-admission-v1/live-replayed-baseline.json):
the same proposals re-admitted by the baseline code against the same cited
evidence.

| | Original (n=3, baseline) | Hardened (n=5) |
|---|---|---|
| Chose `resolve_indirect_call` at step 1 | 3/3 | 5/5 |
| Proposals per trial (round 1 + correction) | 2 | 2 |
| Unsupported call proposals | 6 (2 per trial) | 10 (2 per trial) |
| Admitted unsupported call claims | **3** | **0** |
| Rejected by `ENTITY_MALFORMED` (round 1, `E0000c5cc …`) | 3 | 5 |
| Rejected by `CALL_RELATION_UNSUPPORTED` (round 2) | 0 | 5 |
| Admitted call claims, correctly scoped | 0 | 0 (none proposed) |
| Legitimate claims rejected | 0 | 0 |
| Proposals citing `indirect_call_target` evidence | 0 | 0 |
| Planner requests per trial | 11, or 12 with a correction retry | 12 |
| Prompt tokens: decision / final / correction | 15101 / 1105 / 1183–1211 | 15101 / 1105 / 1211 |

- **The scripted selection** was recorded and replayed with an identical
  result.
- **Overhead.** The hardening adds no request or token. In both versions,
  the second correction attempt is the model server's memory guard
  rejecting a 1856-character prompt. The original trials 2 and 3 needed it
  too, and the round-1 diagnostics the correction shows are unchanged.
- **Determinism.** Qwen's round-1 line was identical in all eight runs.
  Its round-2 line was identical in seven; the original trial 1 phrased it
  passively. The counts describe one model on one objective, not a rate.

**Claim-generation limitation (not an admission result).** The model never
produced a correctly scoped call claim, and never cited E3, which holds
the conditional targets. It also never saw a call diagnostic:

1. Its round-1 line (`E0000c5cc can call …`) has a malformed subject, so
   the call check cannot identify the source. The line is rejected only
   as `ENTITY_MALFORMED`, with a `CALL_RELATION_UNCHECKED` note.
2. The one correction round therefore fixed only the identifier.
3. The call diagnostic arrives in round 2, after which there is no
   further round.

## 5. Over-rejection check on recorded model output

Every claim-admission record in the scratch ledgers that survive from
earlier live runs was re-admitted by both versions against its cited
evidence. That covers 16 records:

- SERCOM0 v2: `live-ledger-1` to `live-ledger-5`;
- indirect-dispatch v1.

**Baseline.** The replay reproduces all 16 recorded decisions.

**Hardened.** It changes exactly three decisions: the three admitted
`c5cc → c7c0` claims.

**Retained.** The two SERCOM0 v2 call claims stay admitted, now with
`CALL_RELATION_CHECKED` against their cited `function_facts`:

- `FUN_0000a084 calls FUN_0000b4b4 with r0 loaded from memory`
- `FUN_0000a0a8 calls FUN_0000b4b4 …`

**Already rejected:** "`FUN_0000b658` is called by `FUN_0000b5bc`, which
is called by `FUN_0000b4b4`". It was rejected for other reasons, and is
now also `CALL_SOURCE_MISMATCH`. The direction is reversed: the case's
path is `c7c0 → b658 → b5bc → b4b4`. The ", which is called by" clause has
a pronoun subject and is noted, not checked.

## 6. Canonical claims (reported, not changed)

The call rule over every canonical claim and its stored evidence flags one:

- `C9:v1`, "`FUN_0000b4b4` is definitively reachable…": the code is
  `CALL_REACHABILITY_UNSUPPORTED`. The claim names no root and no scope.
  - Its cited census result does record `DEFINITELY_REACHABLE` (static,
    census roots).
  - SERCOM0 v2 observed `b4b4` entered in boot through `a084`/`a0a8`.
  - So the wording is what fails, not the fact. A census- or
    scenario-scoped restatement would pass.
  - Its state stays `PROPOSED`. Re-verifying it would now block it in
    phase B, so it was not re-verified.

The other nine claims assert no checkable call relation.

`C1:v1`'s "dispatch at `FUN_0000cc0a` invokes a computed target at
`0xcb92`" has no identifiable endpoints and is not checked; it is already
`BLOCKED`.

The canonical ledger tree hash is identical before and after all runs.

## 7. Reproduce

```sh
agent/.venv/bin/python cases/performing-rigs/test/test_call_admission.py
(cd agent && .venv/bin/python -m pytest -q tests/test_call_relations.py)

# live trials into a NEW scratch ledger (the script refuses the canonical one)
agent/.venv/bin/python cases/performing-rigs/scripts/indirect_dispatch_planner_trials.py \
    --ledger-dir "$TMPDIR/cav1-ledger" --live 5 --out "$TMPDIR/cav1-trials.json"

# summarize, and replay the same proposals with another admission implementation
agent/.venv/bin/python -I cases/performing-rigs/scripts/call_admission_benchmark.py \
    --ledger-dir "$TMPDIR/cav1-ledger" --trials "$TMPDIR/cav1-trials.json" \
    [--agent-src <baseline-worktree>/agent/src --label "baseline 3c74b5a"] --out FILE
```

The original trials' scratch ledger, used for the `original-replayed-*.json`
records, is not in the repository. `trial-evidence.json` preserves its
cited results.
