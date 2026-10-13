# Spike: Beads as APTrace's Long-Horizon Work Store

Status: **spike, not adopted**. Branch `spike/beads-workstore` from
`46a7799`. Nothing here changes the research ledger, audit, or verification.

**Recommendation: ADOPT WITH CONDITIONS** (see the end of this document).

## Question

Can Beads own investigation *work* (items, priorities, dependencies,
ready/blocked, claiming, completion, recovery, follow-ups) while APTrace keeps
sole authority over research *knowledge* (runs, evidence, claims, audits,
verification, lifecycle)?

## Tested version and mode

- Beads `bd 1.3.1` (`c1c4b642a`), darwin/arm64 release binary, sha256
  `508ba807996e2b9c992c538a6f405f2fc7d2e16cf8b4e5b0d1bf9fe860367007` (matches
  the release `checksums.txt`). Source read at tag `v1.3.1`.
- Storage: **embedded Dolt** (default; no server process). Server and
  proxied-server modes were not tested.
- Host: Apple-silicon Mac, macOS 26.

## Current architecture (verified at 46a7799)

| Concern | Location | Owner after this spike |
|---|---|---|
| Planner loop | `agent/src/aptrace_agent/research/controller.py` (`ResearchController.run`) | APTrace (unchanged) |
| Investigation entry point | `investigator.py` (`run_autonomous_investigation`), CLI `research --ledger` in `cli.py` | APTrace (unchanged) |
| Run recording | `ledger/recorder.py` (`record_investigation`), `ledger_cli.py` (`record_research_run`) | APTrace (unchanged) |
| Ledger store, claims, staleness | `ledger/store.py`, `ledger/models.py` | APTrace (unchanged) |
| Audit | `ledger/auditor.py`, `ledger/pipeline.py` | APTrace (unchanged) |
| Verification | `ledger/verifier.py` (`ClaimVerifier`; only `aptrace-verifier` may emit `VERIFIED`) | APTrace (unchanged) |
| Case wiring | `ledger_wiring.py` | APTrace (unchanged) |
| **Work items** | none before this spike | **Beads via `aptrace_agent/work/`** |

Facts that shaped the design:

- `record_investigation` writes the `InvestigationRun` only **after** the
  controller finishes. An interrupted run leaves no ledger run record.
- The controller's session (leads, planner context) is in memory only. There
  is no checkpoint or resume.
- Evidence is content-addressed (`EV-` from operation key + result hash), so
  re-running an investigation reuses evidence. Claims are not deduplicated:
  each run proposes new claim ids.

Beads **replaces** nothing that exists. It **adds** the work layer APTrace did
not have. It **leaves untouched** every ledger, audit, and verification
component.

## What was built

```
agent/src/aptrace_agent/work/
  store.py     WorkItem, WorkStore protocol, error types (no Beads knowledge)
  beads.py     BeadsWorkStore: one `bd ... --json` subprocess per call
  handoff.py   work item <-> ledger run/audit; reads the ledger, never writes it
agent/tests/test_work_beads.py   25 tests (22 need bd; 3 run without it)
agent/scripts/beads-spike.sh     experiments H, I, J (commands + output)
```

Boundary rules enforced in code and tests:

- `ledger/` and `research/` do not import `work/` (test).
- `work/` contains no ledger write call: `transition`, `propose_claim`,
  `record_*`, `invalidate_evidence`, … (test).
- Ledger records are referenced by id only, in flat `aptrace_*` metadata keys
  (Beads metadata filters only match top-level keys). No evidence blobs or
  claim records are copied.
- Every `bd` call sets `BEADS_DIR`, runs from the store's parent directory,
  and sets `DO_NOT_TRACK=1`.
- `initialize()` refuses to run inside a git work tree.
- Unsupported `bd` versions are refused (the adapter accepts `1.3.x`).
- All Beads failures surface as `WorkStoreError` subclasses
  (`WorkStoreUnavailable`, `ClaimConflict`, `DuplicateWork`, `WorkNotFound`).

### Safety findings from setup

Each of these was observed, not read from documentation:

- `bd` sends usage metrics by default (command names, version, OS) to
  `gastownhall-eventsapi.com`. `DO_NOT_TRACK=1` turns them off and writes
  nothing to `HOME`. `bd metrics off` writes `~/.config/bd/config.yaml`.
- `bd init` without `BEADS_DIR`, in a non-git directory, ran `git init`,
  wrote `.gitignore`, and **made a commit** under the user's identity.
- `bd init` with `BEADS_DIR`, inside a git repo, with `--skip-agents
  --skip-hooks`: no commit, no `AGENTS.md`/`CLAUDE.md`, no hooks. It still
  **appended 7 lines to the `.gitignore` in its working directory**. Hence the
  adapter's cwd rule and its git-tree refusal.
- `bd init` writes `~/.dolt/config_global.json`.

## Results

Evidence level for every row: **concrete** (executed against bd 1.3.1),
unless stated otherwise.

| Exp | Result | Evidence |
|---|---|---|
| A durable work | **PASS** | `test_a_…`: metadata (case, firmware key/sha256, context id, objective) equals what was written when read by a new store instance; found by `aptrace_firmware_sha256` filter; run id added later round-trips. |
| B dependencies | **PASS** | `test_b_…`: `bd dep add A B` means *A depends on B* (verified); 3-item chain + independent item; frontier advances on completion; ordering identical after reopen. |
| C claiming | **PASS** (atomicity) | 8 concurrent processes on one item: exactly one winner, 7 clean `ClaimConflict`s naming the holder. Stress: 25/25 rounds one winner, 0 errors. `claim_next` (`ready --claim`): 20 claims, 0 double assignments. Holder re-claim idempotent; release is compare-and-swap. Fairness: not tested, not claimed. |
| D hand-off | **PASS** | `test_d_…`: work item → objective → real `ResearchController` (scripted planner) → `record_investigation` → run id written back → item closed. Proposed claims stay `PROPOSED`; every ledger event's actor is `aptrace-ledger`. |
| E interruption | **PASS with limits** | Crash before run: `restart`; same actor may re-claim, others get `ClaimConflict`. Run recorded but write-back failed: recovery finds the orphan run; `apply_recovery` links it once and closes, 3 repeats idempotent, ledger byte-identical. Fresh Python process reconstructs the same state. Lease expiry: claim survives `reclaim` while live; after 5 min 10 s `reclaim` reopens it (317 s opt-in test). |
| F follow-up | **PASS** | `test_f_…` (CHALLENGED and UNRESOLVED from the real `ClaimAuditor`): item carries claim version, audit id, verdict, reason, claim's run id, source item; `discovered-from` edge; stays ready. Sequential repeat and 4 concurrent repeats yield one item (deterministic id, `bd` refuses duplicates atomically). Audit file and event count unchanged; claim stays BLOCKED/PROPOSED. SUPPORTED → no follow-up. |
| G authority | **PASS** | `test_g_…`: closing the follow-up of an UNRESOLVED claim leaves it `PROPOSED`, ledger byte-identical; `ClaimVerifier.verify` still holds it at `PROPOSED`. Static test: no ledger write path in `work/`. |
| H history/portability | **PASS** | Event history (`created/claimed/closed`, actor, time) and Dolt commit snapshots per item. `bd backup init/sync` → `bd init` + `bd backup restore --force` restores ids, metadata, **and history**. `export`/`import` JSONL restores ids, metadata, run ids, dependencies, **but not history** (1 snapshot, `created` only). |
| I resources | **PASS** | No resident process after commands. Peak RSS 122 MB per transient `bd` call. Latency: `ready` 210 ms, `show` 340 ms, `update` 300 ms, `create` 470 ms. Store 3.2 MB at ~13 items, 8.7 MB at ~215. 8 parallel readers 2.8 s wall (serialized by the embedded lock). |
| J workflows | **PARTIAL** | A formula expressing investigate → audit → (follow-up if `challenged`) → verify cooks and pours; `pour` honours `condition` (4 vs 5 issues); the ready frontier starts at "Investigate". But `condition` is evaluated **at pour time from variables**, and upstream documents `on_complete` as a runtime no-op. Beads cannot branch on an audit verdict; APTrace must decide and create follow-ups (as `handoff.followup_for_audit` does). |

### Experiment E: what resumes and what restarts

| Interrupted at | Durable state | Next safe action |
|---|---|---|
| Before claim | item `open` | `start` |
| After claim, before run recorded | item `in_progress`, attempt marker, **no ledger run** | `restart` from the objective. Controller context is lost; nothing resumes. Same actor re-claims immediately; another worker waits for lease expiry (5 min) and `bd reclaim`. |
| After run recorded, before write-back | ledger run exists; item unlinked | `link-orphan-run`, then close. |
| After write-back | item closed, run linked | `none`; claims proceed through audit/verification in the ledger. |

The orphan link is **probable, not exact**. It matches on objective, case,
firmware sha256, and `run.started_at` ≥ the attempt marker, because the
ledger run carries no work-item id. Two matching runs give `operator-review`.

Restarting re-proposes claims (`test_e_restarting_…`): evidence ids are
reused, but each run gets new claim ids. Automated restarts would accumulate
duplicate `PROPOSED` claims.

## Integration design

```
Beads work item (apt-…)                     APTrace ledger
  aptrace_objective ──claim──► run_investigation(investigate=existing path)
                                     │
                                     ▼
                               InvestigationRun R-… ──► evidence EV-… ──► claims C…:vN
  aptrace_run_ids ◄── run id ────────┘                                       │
  closed ("work completed …")                         audit A-… ◄────────────┘
                                                        │ CHALLENGED / UNRESOLVED
  follow-up apt-fu<hash(claim version, audit)> ◄────────┘  (discovered-from source item)
                                                      ClaimVerifier decides lifecycle
```

| Relationship | Stored where | Meaning |
|---|---|---|
| work → run | `aptrace_run_ids`, `aptrace_run_link_basis` on the item | this work produced these runs |
| work → ledger identity | `aptrace_case`, `aptrace_firmware_*`, `aptrace_context_id` | which firmware the work concerns |
| follow-up → audit | `aptrace_claim_version`, `aptrace_audit_id`, `aptrace_audit_verdict`, `aptrace_followup_reason` | why the work exists |
| follow-up → work | `discovered-from` edge, `aptrace_source_work` | provenance; **not** blocking |
| work → work | `blocks` edge | ordering of work; **not** claim dependency |

Failure behaviour:

- **Beads down before a run:** `claim_work` raises; the investigation never
  starts; the ledger is untouched.
- **Beads down after a run:** the run stays in the ledger; recovery links it
  later.
- **Investigation raises:** the claim is released (CAS) and the error
  re-raised.
- **The research CLI and ledger run without Beads**, and the routine test
  suite skips Beads tests when `bd` is absent.

## Recommendation: ADOPT WITH CONDITIONS

The work boundary held in every executed test. Persistence, dependency
frontiers, atomic claiming, idempotent follow-ups, and history/backup work in
embedded mode at negligible cost on a 24 GB Mac mini. Nothing in the ledger
needed to change, and no work-store action can move a claim.

**Keep in APTrace:** ResearchController, ledger, evidence, claims, staleness,
audit, verification, reports. All unchanged.

**Stop building in APTrace:** task queues, ready/blocked computation, work
priorities, claim/lease logic, work history. Beads covers these.

**Embedded Dolt is sufficient** for one controller. Consider server mode only
when one of these holds:

- concurrent writers make the serialized lock (~0.3 s per op) the
  bottleneck;
- workers run on more than one machine (leases are node-local);
- `bd sql` is needed (it is unsupported in embedded mode).

**Conditions before relying on it:**

1. **Exact run correlation.** Today the work-item id is not on the ledger
   run, so a crash between run recording and write-back is recovered by
   heuristic match. The ledger owner should decide whether to add an
   optional work reference to `InvestigationRun`. That is a schema change
   and was deliberately not made here.
2. **Restart policy for claims.** Restarting an interrupted investigation
   duplicates `PROPOSED` claims. Before unattended restarts, decide whether
   to supersede or deduplicate prior-run proposals.
3. **Heartbeat for long runs** once any reaper runs `bd reclaim`. Local LLM
   investigations can exceed the fixed 5-minute lease, which the CLI cannot
   change.
4. **Backups.** bd's own `.gitignore` excludes `embeddeddolt/`, so the work
   database is not versioned with the repo. Schedule `bd backup sync` (keeps
   history). JSONL export is state-only.
5. **Pin and isolate.** Pin `bd` to 1.3.x and keep the store outside the
   checkout via `BEADS_DIR`. Keep `DO_NOT_TRACK=1`, and parse `bd` errors by
   message text: contended claims exit 1 with "already claimed by", not a
   distinct code.
6. **Follow-up key policy.** Follow-ups are keyed by (claim version, audit
   id). `audit-repeat` batches would open one per audit; decide whether
   batches share one.

**Next step (smallest):** a `--work-item <id>` option on `aptrace-agent
research --ledger` that calls `handoff.run_investigation` with the existing
`run_autonomous_investigation` + `record_research_run` path as `investigate`.

**Defer until multi-agent work is justified:** server mode, federation,
`bd reclaim` supervisors, molecules/formulas, Gas City, and scheduler
fairness.

## Reproducing

```sh
gh release download v1.3.1 -R gastownhall/beads -p 'beads_1.3.1_darwin_arm64.tar.gz' -p checksums.txt
shasum -a 256 -c --ignore-missing checksums.txt && tar -xzf beads_1.3.1_darwin_arm64.tar.gz bd

cd agent
APTRACE_BD=$PWD/../bd uv run pytest tests/test_work_beads.py -q            # 24 pass, 1 skip (~70 s)
APTRACE_SLOW_TESTS=1 APTRACE_BD=$PWD/../bd uv run pytest tests/test_work_beads.py -k abandoned   # ~5.5 min
BD=$PWD/../bd scripts/beads-spike.sh                                       # H, I, J
```
