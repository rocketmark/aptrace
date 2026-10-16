# Arrow: work

Long-horizon work tracking around investigations. It covers:
- **Storage:** the storage-independent work-store boundary, and a Beads
  (`bd`) adapter.
- **Ownership:** host-local item ownership locks.
- **Run handoff:** connecting work items to ledger runs (start, link,
  reconcile, complete).
- **Follow-ups:** audit-based and continuity-based follow-up work items.
- **Interfaces:** the `work`/`followups` CLIs and the Beads spike script.

## Status

**MAPPED**: mapped 2026-10-16 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been verified against code (no audit has
run).

## References

### HLD
- docs/high-level-design.md (skeleton); docs/intent/investigation/investigation-design.md (skeleton)

### LLD
- docs/intent/investigation/work/work-design.md

### EARS
- docs/intent/investigation/work/work-specs.md (prefix `INV-WORK`; 22 specs: 22 `[x]`, 0 `[ ]`, 0 `[D]`)

### Tests
All in `agent/tests/`.
- **test_work_beads.py:** needs the real `bd` CLI (pinned 1.3.1) through `APTRACE_BD` or `PATH`, and is skipped otherwise. Every store sits under `tmp_path` with a sandbox `HOME`, outside any git tree.
  - *Coverage:* metadata round-trip; ready frontier; competing claims; crash and restart recovery; audit follow-ups; closing work cannot promote a claim; no ledger write path; no `ledger`/`research` → `work` import; JSONL round-trip; version pin; refusal inside a git tree.
  - *Slow test:* the lease-expiry test needs `APTRACE_SLOW_TESTS=1`.
- **test_work_handoff.py:** fake work store and temporary ledgers.
  - *Coverage:* identity validation; blockers; the reconciliation cases a–e; idempotence; concurrency; completion never changes claim state; lock-id restriction.
  - `test_persisted_case_ledger_runs_still_load` reads the canonical case ledger `runs/` in place (read-only).
- **test_work_cli.py:**
  - plain `research` never loads `work`;
  - work-item research records and links;
  - refusals;
  - write-back failure;
  - create, reconcile and complete;
  - a conflict exits non-zero.
- **test_followups.py (work parts):** materialization idempotence and concurrency; real Beads dedup (needs `bd`).

### Code
- agent/src/aptrace_agent/work/{`__init__`, store, beads, ownership, handoff, followups}.py
- agent/src/aptrace_agent/work_cli.py
- agent/scripts/beads-spike.sh

### Related docs
- docs/work-store.md, docs/spikes/investigation-continuity.md

## Architecture

**Purpose:** keep work state (identity, status, dependencies, claiming,
history) apart from knowledge state (runs, evidence, claims, audits,
verification). Closing a work item never verifies, promotes, blocks or
supersedes a claim. `work/` has no ledger write path, and `ledger/` and
`research/` do not import `work/` (`docs/work-store.md:20-33`).

**Key components:**
1. **`WorkStore` protocol and `WorkItem`:** a storage-independent boundary. "work status never says whether a claim is valid" (`work/store.py:5-8`).
2. **`BeadsWorkStore`:**
   - *Execution:* one `bd … --json` subprocess per operation, with `BEADS_DIR` set and telemetry, hooks and pager disabled.
   - *Version:* the `bd` 1.3.x series.
   - *Location:* refuses to open or initialize inside a git work tree.
   - *Errors:* classified by output substring.
3. **`ItemLock`:** a host-local `flock` per item, with lock files holding pid, host and time.
4. **`handoff`:**
   - *Investigation items:* validated against case, firmware and kind; the objective must match; unclosed blockers refuse a start.
   - *Run:* lock, reconcile, claim, attempt marker, investigate, verify `work_item_id`, link. Never auto-closed.
   - *Reconciliation:* 9 states.
   - *Completion:* only from `AWAITING_COMPLETION`, with a close reason saying claim state is ledger-owned.
   - *Audit follow-ups:* for CHALLENGED and UNRESOLVED audits.
5. **`work/followups`:** materializes continuity candidates as `investigation` items with deterministic ids (`<prefix>-fq<key>`); never recreates a closed item.
6. **`work_cli`:**
   - `work init|create|reconcile|complete`;
   - `followups`;
   - `research --work-item`.

   The default work directory is `~/.aptrace/work/performing-rigs`.

## Spec Coverage

`[x]` means observed in source only. *needs-bd* tests are skipped without the
real Beads CLI. No tests were run during mapping.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Asserting test | needs-bd only |
|---|---|---|---|---|---|---|
| Work/knowledge boundary | INV-WORK-BND-001 to 003 | 3 | 0 | 0 | 3 | 0 |
| Beads adapter | INV-WORK-STORE-001 to 004 | 4 | 0 | 0 | 3 | 2 |
| Ownership | INV-WORK-LOCK-001 to 002 | 2 | 0 | 0 | 1 | 0 |
| Run handoff | INV-WORK-RUN-001 to 004 | 4 | 0 | 0 | 4 | 0 |
| Reconciliation and completion | INV-WORK-REC-001 to 004 | 4 | 0 | 0 | 3 | 0 |
| Follow-up items | INV-WORK-FU-001 to 002 | 2 | 0 | 0 | 2 | 1 |
| Command line | INV-WORK-CLI-001 to 003 | 3 | 0 | 0 | 2 | 0 |

**Summary:** all 22 specs are observed in source, and none is an
approved-intent gap.
- *The approved boundary:* no ledger write path, and work never changing
  claim state (BND-001, BND-002). It is met and test-asserted.
- *Not decided:* LOCK-002 (a read-only reconcile writes lock files) and
  CLI-001 (the canonical ledger default) are recorded for decision.

18 specs have an asserting test. Three of them are asserted only by needs-bd
tests. No `@spec` annotations exist.

## Key Findings

1. **There is no ledger write path, and that is tested.**
   - *Assertions:* `test_g_work_package_has_no_ledger_write_path`, `test_ledger_and_research_do_not_import_work_package`, `test_g_closing_work_cannot_promote_a_claim`.
   - *What work does with the ledger:* handoff reads it (runs, claims, states, audits). Run linkage is stored in work-store metadata.
2. **Defaults point at canonical locations.**
   - *Ledger:* `followups`, `work reconcile`/`complete` and `research --work-item` use the canonical case ledger unless `--ledger-dir` or `APTRACE_LEDGER_DIR` is set.
   - *What writes:* `research --work-item --ledger` records the run there (evidence-record).
   - *Work directory:* outside the checkout by design (`ledger_wiring.py:38-40`).
3. **A "read-only" reconcile writes lock files.** `work reconcile` without `--apply` builds an `ItemLock`, and `probe()` acquires and releases it. That creates the lock directory and file (`work/ownership.py:62-63, 92-104`; `work_cli.py:88, 160`). The files are never deleted.
4. **Store errors are classified by text.** `bd` failures map to ClaimConflict, DuplicateWork, WorkNotFound and WorkStoreUnavailable by substring of the output (`work/beads.py:140-153`). Any 1.3.x is accepted, though 1.3.1 is pinned (`:34-35, 171-177`).
5. **Write-back can fail after recording.** When the run is recorded but the work-store write-back fails, `WriteBackFailed` is raised and the run is still reported (`work/handoff.py:125-133, 353-358`).
6. **Attempts on other hosts count as active, and lookalike runs are never linked.** An attempt on another host is treated as ACTIVE (liveness unknown). Lookalike runs without the work-item reference are reported as heuristic candidates, never linked (`work/handoff.py:551-583`).
7. **Some operations are not reachable from production.**
   - *Supervisor methods:* `heartbeat`, `reclaim_stale`, `history` and export/import exist but no production code uses them (`work/beads.py:271-306`).
   - *Audit follow-ups:* `followup_for_audit` is called only from tests.
8. **Some code scans the whole ledger.** `runs_for_item` and the partial-claim scan iterate over the whole ledger on each call (`work/handoff.py:449-450, 541-549`).
9. **The work CLI is case-bound.** It binds to Performing Rigs through `ledger_wiring`; the `--work-dir` help names `performing-rigs` (`work_cli.py:27`).

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
*None identified in this segment.*
- *Tests:* Beads tests sandbox the store under `tmp_path`, and the
  canonical-ledger test only reads `runs/`.
- *Beads store:* refuses to live inside a git work tree.

### Confirmed defects
*None demonstrated by execution.*

### Evidence-integrity risks
*None specific to evidence.* Work state never changes claim state, and that
is test-asserted. Canonical-state touchpoints are the default ledger
(Finding 2), recorded under evidence-record.

### Architectural coupling
1. **Case-bound defaults and help text** (Finding 9).
2. **`NEXT_STEP` strings embed CLI command text**, coupling the library to `work_cli` (`work/handoff.py:84-100`).
3. **The audit-id metadata key is a literal string,** `"aptrace_audit_id"` in `work/followups.py:76`, with no constant.

### Semantic inconsistencies
4. **A "read-only" reconcile creates lock files** (Finding 3).
5. **The default actor differs.** `aptrace` in the adapter vs `aptrace-agent` in the CLI (`work/beads.py:86`; `work_cli.py:23`).
6. **The version pin is loose.** 1.3.1 is pinned, but any 1.3.x is accepted (Finding 4).

### Maintenance debt
7. **Substring error classification** (Finding 4).
8. **Unused supervisor methods** (Finding 7).
9. **Whole-ledger scans per reconcile** (Finding 8).
10. **N+1 subprocess calls in `find_work`** (`work/beads.py:253-255`).
