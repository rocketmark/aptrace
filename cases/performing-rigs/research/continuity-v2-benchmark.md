# Controller Continuity Benchmark: SERCOM0 Follow-up of C9:v1

The mechanism is described in
[`docs/research-continuity.md`](../../../docs/research-continuity.md). The
baseline is the spike in [`continuity-spike.md`](continuity-spike.md). The
benchmark script is
[`scripts/continuity_benchmark.py`](../scripts/continuity_benchmark.py).
Per-trial results are in [`runs/continuity-v2/`](runs/continuity-v2/).

## Setup

- **Question:** does `FUN_0000b4b4` read or write SERCOM0 registers, or only
  load `0x40003000` as a value?
- **Source:** follow-up candidate `34aa722266ae1091ee464ad0` of
  `R-20261013T190420-edcfa7`. It has 6 seeded leads: the 4 direct callers
  of `FUN_0000b4b4` and 2 call sites into `FUN_0000a064`.
- **Isolation:** each trial copies the canonical ledger to a temporary
  directory, re-derives the candidate, runs one follow-up with the real
  firmware tools, and records it in the copy. The canonical ledger was
  hashed before and after every batch and was unchanged. No Beads store was
  used.
- **Modes:**
  - `baseline`: seeding without history. This is the spike behaviour; with
    no history the controller code path is unchanged.
  - `improved`: seeding with `HistoricalOperations` (continuity-v1).
- **Held constant across modes:** budget of 8 steps, the same tools
  (`usb_inventory`, `common_paths`, `function_effects`, census peripherals),
  and the same model configuration (temperature 0, 512 tokens). Modes
  alternate within each repetition.
- **Planners:**
  - `rules` is a deterministic stand-in that applies the decision prompt's
    rule order literally.
  - `qwen` is the local `Qwen3-Coder-30B-A3B-Instruct-4bit` via oMLX on the
    24 GB Mac mini.

## Results

Each row is identical across its repetitions unless noted. Trials:
scripted n = 2 per mode; live n = 3 per mode on the final code, repeated
in two batches. Earlier pre-fix trials are not counted.

| Metric | rules baseline | rules improved | Qwen baseline | Qwen improved |
|---|---|---|---|---|
| seeded leads attempted (of 6) | 0 | 6 | 2 | 6 |
| seeded leads completed (analysis ran, of 6) | 0 | 6 | 2 | 6 |
| direct callers of `FUN_0000b4b4` inspected (of 4) | 0 | 4 | 0 | 4 |
| source-run operations re-executed | 7 | 0 | 6 | 0 |
| historical results reused (preloaded + on request) | 0 | 6 + 1 | 0 | 6 + 0 |
| reuse refusals | 0 | 2 (case-document search: not deterministic) | 0 | 2 (same) |
| new operations executed | 1 | 7 | 2 | 6 |
| new evidence | 1 | 7 | 2 | 6 |
| tool executions / steps charged (budget 8) | 8 / 8 | 7 / 7 | 8 / 8 | 6 / 6 |
| planner requests | 9 | 10 | 13 | 11 |
| requests rejected by validation | 0 | 1 (duplicate effects) | 4 | 4 |
| model runtime errors (prefill) | 0 | 0 | 0 | 0 |
| max prompt chars / tokens | 3,063 / – | 3,148 / – | 3,000 / 2,003 | 2,983 / 1,945 |
| stop | budget | planner finished | budget | contract exhausted after all 6 seeded leads |
| claims proposed | 0 | 0 | 0 (both batches) | 1 (3 of 3, then 2 of 3) |
| provenance checks (4) | pass | pass | pass | pass |

The provenance checks are:

- no reused operation was re-executed;
- reused evidence is not listed as run evidence;
- reused originals exist;
- every invocation input is durable evidence.

An earlier live batch, run before the final-claims rule, gave the same
lead, redundancy and caller numbers. In that batch the baseline proposed a
claim in 1 of 3 runs and the improved mode in 0 of 3: without the rule, the
improved mode ended on planner failure before the claims request.

**Variance.** Every live metric except claim proposal was identical within
each mode, at temperature 0, across 9 baseline and 9 improved runs. The
final claims request varies: the improved mode proposed a claim in 2 of 3
runs and then 3 of 3. That is still a small sample. Live runs used about
2,000 prompt tokens per decision at most in both modes.

### What the planner did

- **Qwen baseline:** follows one seeded call site, re-runs the SERCOM0
  census, re-runs `function_effects` on `FUN_0000b4b4`, then follows
  census-derived function leads. These are facts and disassembly that the
  source run already recorded.
- **Qwen improved:** follows the 6 seeded leads in turn. All four direct
  callers are inspected. The planner then fails its decision contract, and
  no seeded lead is left for the fallback.
  - Prior results are visible as `(E…=prior)` and cost no step: the census,
    effects, facts and disassembly of `FUN_0000b4b4` and `FUN_0000a064`.
  - No peripheral rediscovery is offered.

### Claim produced (Qwen improved)

`C10:v1` (STRONG, PROPOSED in the trial ledger copy, not in the canonical
ledger): "E0000b4b4 does not read or write SERCOM0 registers via r0
address; it only uses the address as a value."

- **Provenance is correct.** It cites the reused prior evidence by its
  original ids (`EV-be1965ce…` census, `EV-f9a9ae31…` effects, facts and
  disassembly) plus the two newly executed `FUN_0000a0cc` call sites.
- **Quality is poor:**
  - the subject is garbled (`E0000b4b4`);
  - STRONG overstates bounded symbolic-effects evidence;
  - it does not cite the four direct-caller call sites it collected;
  - it has no typed semantics, so deterministic verification would hold it
    `PROPOSED`.

## Status of the central question

**Not answered.** The new evidence is static: the call-site disassembly of
the four direct callers.

- Each caller passes `r0` loaded through its own argument (`ldr r0, [r0]`)
  and treats the return value as a signed index:
  - it checks the value against zero;
  - it scales the value by 12 or 16 bytes;
  - it uses the result to index a table.
- That fits a lookup that returns an instance index rather than a register
  access. This is a *pattern-matched* (probable) reading.
- It does not establish what `r0` holds.

The analysis that could decide it is a *different* operation: function
effects of `FUN_0000b4b4` with `r0` specialized to a SERCOM base, or an
analysis of the callers' pointer origin. It would run normally; it is not a
reuse. `C9:v1` is unchanged (`PROPOSED`).

## Reproducing

```bash
uv run --project agent python cases/performing-rigs/scripts/continuity_benchmark.py \
    --planner rules --repeat 2 --out /tmp/continuity-v2
uv run --project agent python cases/performing-rigs/scripts/continuity_benchmark.py \
    --planner qwen --repeat 3 --out /tmp/continuity-v2     # needs OMLX_BASE_URL, APTRACE_MODEL
```
