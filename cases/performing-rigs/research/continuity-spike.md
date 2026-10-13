# Investigation Continuity Spike — SERCOM0 Demonstration

Case demonstration for the framework spike
[`docs/spikes/investigation-continuity.md`](../../../docs/spikes/investigation-continuity.md).
Evidence files are in [`runs/continuity-spike/`](runs/continuity-spike/).

## Scope and isolation

- Source: investigation run `R-20261013T190420-edcfa7`, work item `apt-d1z`,
  claim `C9:v1`, context `X-bb5103e57baa4458`. These were verified in the
  canonical ledger and the production Beads store before use.
- Every write went to disposable copies: the canonical ledger copied into a
  scratch directory, and a scratch `bd` 1.3.1 store. The canonical ledger and
  `~/.aptrace/work/performing-rigs` were not written. The follow-up runs
  below exist only as the saved records in `runs/continuity-spike/`.
- The scratch store did not contain `apt-d1z`, so the created item has no
  `discovered-from` edge. That edge is covered by the fixture and real-`bd`
  tests.

## Investigation A (recorded)

`R-20261013T190420-edcfa7` was a live Qwen run. It took 12 steps, recorded
12 evidence items, proposed `C9:v1`, and stopped at `step_budget_exhausted`.
Its last planner request recorded `open_leads: 25`.

`C9:v1` (`PROPOSED`, `STRONG`, `RESOLUTION`, no typed semantics) asserts:
"FUN_0000b4b4 is definitively reachable and involves SERCOM0 peripheral
access."

## Follow-up generation (deterministic, real ledger, preview)

File: `01-followups-preview.json`. A byte-for-byte snapshot of the canonical
ledger was identical before and after the preview.

**Frontier.** Replaying `LeadDeriver` over the 12 durable observations
re-derived 25 open leads, equal to the recorded count. The level of this
claim is *re-derived* (deterministic re-execution of derivation over
recorded evidence), not recorded.

**Shortlist.** 25 leads became 3 candidates.

| # | Rank | Candidate | Leads | Basis |
|---|---|---|---|---|
| 1 | 1 | Does `FUN_0000b4b4` read/write SERCOM0 registers via the `r0` address its callers supply, or only use `0x40003000` as a value? | 6 (callers of `FUN_0000b4b4`; callers of `FUN_0000a064`) | `PERIPHERAL_ACCESS_UNESTABLISHED` on `C9:v1` |
| 2 | 2 | Unresolved call relationships of `FUN_0000b144` (`FUN_0000b312`, `FUN_0000c8bc`) | 13 (8 seeded) | anchor in firmware-derived evidence supporting `C9:v1` |
| 3 | 3 | `FUN_0000cc24`, `FUN_0000cc10`, `FUN_0000cca4` named by case documents | 6 | documentary link only |

**Why candidate 1 exists.** This is static evidence, from recorded
results:

- Census `EV-be1965ceaf243a66` attributes to `FUN_0000b4b4` one
  literal-pool load of `0x40003000` (pool `0x0000b500`), with
  `mmio_site_count 0`.
- `function_effects` `EV-f9a9ae317433aceb` (RAW, complete) shows
  0 MMIO accesses and 0 writes. One read takes its address from `r0`.

Loading a peripheral address constant does not establish a peripheral read
or write. The reachability half of `C9:v1` has census support
(`DEFINITELY_REACHABLE`), so it was not flagged.

These are observations about recorded evidence, not new firmware findings.
Whether `FUN_0000b4b4` accesses SERCOM0 remains **unknown**.

## Beads persistence (real bd, scratch store)

`--create --select 1` created `apt-fq34aa722266`:

- priority 1
- objective = candidate 1's objective
- metadata references only (`05-beads-item-after-completion.json`)

A second `--create --select 1` returned `already open`, and the store held
one item.

## Investigation B (live Qwen, real firmware tools)

`research --ledger --work-item apt-fq34aa722266 --max-steps 8`, recorded as
`R-20261013T221650-31e3c5` (`02-live-run-b1.json`).

- **Linkage.**
  - `parent_run_id` is the source run.
  - `followup.followup_key = 34aa722266ae1091ee464ad0`.
  - `followup.prior_evidence_ids` lists the 8 cited source-run evidence
    ids.
  - 6 seeded caller call sites are recorded.
- **Context.**
  - 1,091 seeded chars.
  - Planner prompts 1.7–3.0 k chars, at most 2.0 k prompt tokens per
    decision.
  - The planner saw `PH1` (prior claim, unverified), `PQ1` (the gap), and
    the seeded caller leads.
- **What it did** (`04-continuity-reviews.json`, `b1`):
  - It followed 2 of 6 seeded leads: the call sites from `FUN_0000a0cc`
    into `FUN_0000a064`, giving 2 new evidence items.
  - It spent 6 steps re-running analyses that A had already recorded
    (SERCOM0 census, `function_effects`/facts/disassembly of
    `FUN_0000b4b4`, facts/disassembly of `FUN_0000a064`). The tools
    reproduced identical evidence ids. That shows they are deterministic;
    a re-run is not corroboration.
  - It proposed no claims.
  - The four direct callers of `FUN_0000b4b4`, which supply `r0`, were not
    inspected.
- **Outcome.**
  - The item was completed by the operator.
  - `C9:v1` is still `PROPOSED`, with no lifecycle event added.
  - Regenerating suppresses candidate 1 as `redundant`:
    `R-20261013T221650-31e3c5 (2/6 seeded leads followed,
    step_budget_exhausted)` (`06-followups-after-run-b1.json`).
  - The question is **still open**.

Invocation records of this run predate the recorder fix: two of them list
the session id `E7` in `input_evidence_ids`.

### Objective variant (reverted)

`R-20261013T221954-1b911e` (`03-live-run-b2-objective-variant.json`)
appended "already recorded by the source run: …" to the objective. It ran
in a fresh scratch copy. It followed 1 seeded lead, re-ran the SERCOM0
census anyway, and stopped after 3 steps with `planner_contract_exhausted`.
With n = 1 per variant, no effect can be attributed. The variant was
reverted.

## Status of the originating question

| Question | Status | Evidence level |
|---|---|---|
| Does `FUN_0000b4b4` read/write SERCOM0 registers? | open | unknown; static evidence shows only a constant load and an `r0`-addressed read |
| Is `C9:v1` supported? | `PROPOSED`, unverified | — |

Next for this question: run the item again once the follow-up planner
treats prior analyses as already run (framework next milestone), or have
an operator inspect the four callers' call sites directly.
