# Claim Candidates Benchmark: SERCOM0 Follow-up of C9:v1

- **Mechanism:** [`docs/claim-candidates.md`](../../../docs/claim-candidates.md),
  which adds deterministic typed candidates that the planner selects by id.
- **Prior result:** [`claim-quality-benchmark.md`](claim-quality-benchmark.md).
  It had 0 admitted claims in 12 live trials.
- **Setup:** identical to that benchmark:
  - same source run, follow-up candidate, 8-step budget, tools, and model
    configuration;
  - each trial runs in a fresh temporary copy of the canonical ledger.
- **New in this benchmark:**
  - `--candidates 5`: at most 5 candidates are offered.
  - `--restart`: after each trial, the same follow-up runs a second time in
    the same scratch copy, to measure duplicate avoidance.
- **Script:** [`scripts/continuity_benchmark.py`](../scripts/continuity_benchmark.py).
- **Per-trial results:** [`runs/claim-candidates-v1/`](runs/claim-candidates-v1/).
  The first batch and one diagnostic run are in `batch1/`.
- **Isolation:** the canonical ledger tree was hashed before and after every
  batch, and was unchanged each time.

## Candidates the evidence supports

All modes and trials generate the same three candidates, with the same
ids. The read-only preview of the source run
(`aptrace-agent candidates R-20261013T190420-edcfa7`) gives the same three.

| Id | Typed fact | Grade | Support |
|---|---|---|---|
| `K-880293731f9c` | `FUNCTION_ROLE(FUN_0000b4b4 is ADDRESS_CONSTANT_LOADER, peripheral=SERCOM0)` | STRONG | `EV-be1965ceaf243a66` (census, original id) |
| `K-1a234180aad3` | `FUNCTION_ROLE(FUN_0000a064 is ADDRESS_CONSTANT_LOADER, peripheral=SERCOM0)` | STRONG | same |
| `K-38b9e4b82265` | `FUNCTION_ROLE(FUN_0000b144 is ADDRESS_CONSTANT_LOADER, peripheral=SERCOM0)` | STRONG | same |

Notes on the candidates:

- **No access candidate.** No `MMIO_USER` candidate is generated, and none
  is withheld. The census records `mmio_site_count: 0` for all three
  functions. The `FUN_0000b4b4` effects evidence (`EV-f9a9ae317433aceb`)
  has no access in the MMIO region.
- **Limitations on the `FUN_0000b4b4` candidate.** It carries two:
  - It does not establish or exclude a SERCOM0 register access.
  - The effects analysis has accesses whose addresses depend on `r0`, and
    the `r0` values in reachable callers are not established.
- **Accountability.** The effects evidence and the seeded caller
  call-site evidence are listed as considered, not supporting. Admission
  rule 7 is satisfied by these explained omissions, which carry the
  `OMISSION_EXPLAINED` note.
- **Ids do not depend on how evidence arrived.** In baseline mode the
  census is re-executed; in improved mode it is reused by reference. Both
  give the same ids, because identity comes from evidence content, not
  session numbering.

## Live results (Qwen3-Coder-30B-A3B 4-bit, final code, n = 3 per mode)

| | baseline | improved |
|---|---|---|
| free-form proposals (round 1 + correction) | 1 + 1, rejected (`ENTITY_MALFORMED`, `ABSENCE_NOT_ESTABLISHED`) | 1 + 1, rejected (`ENTITY_SESSION_REFERENCE` ×2) |
| candidates generated / offered / omitted / withheld | 3 / 3 / 0 / 0 | 3 / 3 / 0 / 0 |
| selection response | `K-1a234180aad3,K-880293731f9c` (3/3) | same (3/3) |
| invalid selections | 0 | 0 |
| typed claims admitted | 2 per trial | 2 per trial |
| precheck outcome of admitted claims | `PROPOSED` (held on `claim_class`) | same |
| restart: selection | same two ids | same two ids; prompt shows "Already recorded as claim C1x:v1 in state PROPOSED." |
| restart: claims created / duplicates avoided | 0 / 2 | 0 / 2 |
| selection request | 1 per run, first attempt valid 6/6 (restarts 6/6) | same |
| selection prompt | 784 tokens, 2005 B (restart 784 / 2005) | 784 tokens, 2005 B (restart 814 / 2109) |
| planner requests per run (claim-quality-v1 → now) | 14 → 15 | 12 → 13 |
| run time per trial | about 16 s | about 14 s |

Run-to-run variability is zero in this batch:

- every trial in a mode produced the same selections and admissions;
- the free-form proposals differed only between run and restart, because
  the restart sees more history.

`FUN_0000b144` was offered and not selected in every trial. Qwen's stated
reason was that the other two relate to `FUN_0000b4b4` and its caller
`FUN_0000a064`, which the objective names.

### Admitted claims (each trial's scratch copy)

- `C10:v1`: "FUN_0000a064 loads SERCOM0 address constant 0x40003028 from its
  literal pool; the census records no constant-address MMIO site in it.
  Loading an address is not a register access."
  - Typed: `ADDRESS_CONSTANT_LOADER`, STRUCTURE, STRONG.
  - Supporting evidence: `EV-be1965ceaf243a66`.
  - `proposed_by: candidate-selection:qwen`.
- `C11:v1`: the same statement for `FUN_0000b4b4`, with `0x40003000`.

`0x40003028` is SERCOM0's DATA register address. The census classifies
that value by the SVD range. The claim states only that the constant is
loaded.

### Quality assessment

These claims are correct and correctly scoped. They are useful as a
precise correction of `C9:v1`'s overstatement ("involves SERCOM0
peripheral access"), because they record what the evidence actually
establishes. They are also modest: they are static structural facts,
which the census already showed. Candidate selection did not create new
knowledge. It made existing knowledge durable as typed claims, which the
local planner previously could not do. `C9:v1` itself is unchanged; it
is not superseded or rewritten.

## Earlier batch (disclosed, `batch1/`)

The first batch used a bracketed annotation for already-recorded
candidates: `[already recorded: C10:v1 PROPOSED]`. Its results:

- Every improved-mode restart's first selection attempt (3 of 3, plus the
  diagnostic run) returned no tool call. The single correction retry
  recovered each one.
- One improved restart aborted on an oMLX HTTP 500 (`invalid_tool_call`)
  during research. It is recorded as a trial error.
- Baseline trial 1's first selection attempt also failed. It was the
  batch's first, cold request (68.6 s), and the cause was not captured.

I replayed the logged failing request verbatim. oMLX returned
`incomplete_tool_call` 3 of 3 times. Replays with other wordings:

| Wording | Result |
|---|---|
| annotation removed | valid (2/2) |
| "Already recorded as claim C10:v1." | valid (2/2) |
| "Already recorded as claim C10:v1 in state PROPOSED." | valid (3/3) |
| "(already recorded as …)" | fails |
| "…, state PROPOSED." | fails (3/3) |

The last valid wording was adopted. This is a measured sensitivity of the
runtime's tool-call parsing, not a robust property. It is documented as a
limitation.

## Status of the central question

Still **not answered**.

- The admitted claims establish that `FUN_0000b4b4` loads `0x40003000`
  (static, census). They say explicitly that this is not a register access.
- Whether `FUN_0000b4b4` reads or writes SERCOM0 registers depends on the
  concrete `r0` values its callers pass. These remain unresolved: the
  effects analysis shows only an `r0`-dependent read.
- No candidate was generated for an access or for its absence. None could
  be, from this evidence.
