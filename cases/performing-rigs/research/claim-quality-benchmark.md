# Claim Quality Benchmark: SERCOM0 Follow-up of C9:v1

- **Mechanism:** [`docs/claim-admission.md`](../../../docs/claim-admission.md).
- **Setup:** identical to
  [`continuity-v2-benchmark.md`](continuity-v2-benchmark.md). Same question,
  source run, candidate, 8-step budget, tools, and model configuration.
  Every trial runs in a temporary copy of the canonical ledger.
- **Script:** [`scripts/continuity_benchmark.py`](../scripts/continuity_benchmark.py),
  which now also records claim admission and a no-replay precheck of each
  admitted claim.
- **Per-trial results:** [`runs/claim-quality-v1/`](runs/claim-quality-v1/).
- **Isolation:** the canonical ledger was hashed before and after every
  batch and was unchanged.

## What the spike-era record looked like

`C10:v1` was proposed (STRONG) in the earlier live trials and **admitted**
then, because no admission existed: "E0000b4b4 does not read or write
SERCOM0 registers via r0 address; it only uses the address as a value."

## Live results (Qwen3-Coder-30B, final code, n = 3 per mode)

Each mode was identical across its 3 repetitions.

| | baseline (no history) | improved (continuity) |
|---|---|---|
| direct callers inspected / new evidence | 0 / 2 | 4 / 6 |
| proposals (round 1 + correction) | 1 + 1 | 1 + 1 |
| admitted | 0 | 0 |
| round-1 rejection | `ENTITY_MALFORMED` (`E0000b4b4`) | `ENTITY_SESSION_REFERENCE` (`E10` as subject) |
| correction-round rejection | `ABSENCE_NOT_ESTABLISHED` | `ENTITY_SESSION_REFERENCE` |
| model or runtime errors | 0 | 0 |
| verification outcomes | none (nothing admitted) | none |

### Round 1

- **Baseline:** "PROBABLE STRUCTURE E3,E5 E0000b4b4 does not read or write
  SERCOM0 registers."
  - Rejected: `E0000b4b4` is not a canonical identifier.
- **Improved:** "PROBABLE STRUCTURE E12,E11 E10 E10 loads SERCOM0 base
  address at 0x0000b4b6 and E10 does not show direct access to SERCOM0
  registers."
  - Rejected: its subject is a session evidence id. This claim was
    **admitted** by the first version of admission, which had no
    session-id rule. That batch is described below; the rule was added
    because of it.

### Correction round

- **Baseline:** Qwen corrected the identifier, giving "FUN_0000b4b4 does not
  read or write SERCOM0 registers". It was rejected with
  `ABSENCE_NOT_ESTABLISHED`: the cited effects evidence (`EV-f9a9…`) has
  accesses whose addresses depend on `r0`, and their concrete values in
  reachable callers are not established.
- **Improved:** Qwen repeated the evidence-id subject.

## Earlier batches on this branch

These are disclosed because they shaped the final code.

| Batch | Code | Outcome |
|---|---|---|
| 1 | admission without the session-id rule | improved mode admitted the `E10 … E10` claim in 3 of 3 runs (`C10:v1` in the trial copy; precheck held it `PROPOSED` on `claim_class`) |
| 2 | session-id rule added | 0 admitted; every correction was `CLAIM_UNPARSEABLE`, because Qwen copied the literal `GRADE` placeholder from the correction prompt's format string |
| 3 (final, above) | correction prompt shows a concrete example line | corrections parse; 0 admitted |

The same 1 claim was rejected in each of the 3 improved runs. Qwen did not
produce a claim that satisfies the rules in any of 12 live trials on this
branch. This is reported as a model and interface limitation. The checks
were not relaxed.

The deterministic tests (`agent/tests/test_claim_quality.py`) show that a
properly scoped hypothesis on the same evidence is admitted as `PROPOSED`
and is not verified. Example: "FUN_… has no observed SERCOM register access
in the recorded symbolic analysis; the r0 values its callers pass are
unresolved."

## Status of the central question

Unchanged: **not answered**. The four direct-caller call sites are now
inspected in every improved run (static evidence). Whether
`FUN_0000b4b4` accesses SERCOM0 registers depends on the concrete `r0`
values, and these are not established. `C9:v1` remains `PROPOSED`.
