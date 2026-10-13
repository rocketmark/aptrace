# Work Store: Beads-Backed Investigation Work

> Beads remembers what APTrace needs to do. APTrace remembers what it learned
> and how it knows.

APTrace can track long-horizon investigation work as items in a
[Beads](https://github.com/gastownhall/beads) store, and run an item
through the normal `research --ledger` pipeline. This is optional. Without
`--work-item`, research never loads the work package, never touches a store,
and does not need `bd` installed.

Code: `agent/src/aptrace_agent/work/` (store boundary, Beads adapter,
ownership lock, hand-off) and `agent/src/aptrace_agent/work_cli.py` (CLI).
The default store location is set by the application wiring
(`ledger_wiring.work_dir`). The evaluation that led here is
[`spikes/beads-work-store.md`](spikes/beads-work-store.md).

## Who owns what

| Beads (work) | APTrace (knowledge) |
|---|---|
| work item identity, status, priority | ResearchController execution |
| work dependencies, ready/blocked | `InvestigationRun`, tool invocations, replay |
| claiming and assignment | evidence and provenance |
| work history | claims, claim versions, claim dependencies, staleness |
| follow-up work items | adversarial audits, deterministic verification |

Beads is not an evidence database. A work item holds ledger ids in flat
`aptrace_*` metadata keys and nothing else from the ledger. Closing a work
item never verifies, promotes, blocks, supersedes, or otherwise changes a
claim: `work/` contains no ledger write path, and `ledger/` and `research/`
do not import `work/`. Work dependencies order work. They are never claim
dependencies.

The same holds for cross-engine discrepancies
([`cross-engine-verification.md`](cross-engine-verification.md)): a
discrepancy and its resolution are ledger records, and a work item that
schedules its investigation only references the discrepancy id. Closing that
item never resolves the discrepancy.

## The link between a work item and its runs

Correlation is exact in both directions:

- **Run → item.** `InvestigationRun.work_item_id` is an optional, opaque
  string set when the run is first recorded. It is immutable like the rest
  of the record. Standalone runs and every run recorded before this field
  existed have no value. An unset value is left out of the serialized
  record, so those records are byte-for-byte unchanged and no schema version
  bump was needed. Several runs may carry the same item id. Run ids stay
  independently unique.
- **Item → run.** `aptrace_run_ids` lists the item's runs.
  `aptrace_run_link_basis` says how each id got there: `direct` (written
  back by the run) or `reconciled:work_item_id` (repaired from the run's
  reference).

Reconciliation follows only these references. A run without a reference
that merely matches an item's objective, case, and firmware is reported as a
heuristic candidate for operator review. It is never linked.

## Setup

1. Install `bd` **1.3.1** (the adapter refuses anything outside 1.3.x) and
   put it on `PATH` or set `APTRACE_BD=/path/to/bd`.
2. Create the store. It must live outside any git work tree, because
   `bd init` writes a `.gitignore` into its working directory. Without
   `BEADS_DIR`, it also runs `git init` and commits.

   ```sh
   aptrace-agent work init            # default: ~/.aptrace/work/<case>/
   aptrace-agent work init --work-dir /Volumes/data/aptrace-work
   ```

   `APTRACE_WORK_DIR` overrides the default. The root holds `.beads/`
   (embedded Dolt) and `aptrace-locks/`. `bd init` also writes
   `~/.dolt/config_global.json`.

Every `bd` call from APTrace sets `BEADS_DIR`, runs from the store root,
and sets `DO_NOT_TRACK=1`. bd sends usage metrics by default. The adapter
refuses to open a store inside a git work tree. When you run `bd` by hand,
do the same:

```sh
cd ~/.aptrace/work/performing-rigs
export BEADS_DIR=$PWD/.beads DO_NOT_TRACK=1
bd list --all
```

## Running an investigation from a work item

```sh
aptrace-agent work create --priority 1 "Determine which handler services USB_OTHER."
#   apt-3fa [open] Investigate: Determine which handler services USB_OTHER.
aptrace-agent research --ledger --work-item apt-3fa
aptrace-agent work reconcile apt-3fa          # inspect the result
aptrace-agent work complete apt-3fa --reason "reviewed; claims go to audit"
```

`work create` stamps the item with the current case, firmware key, firmware
sha256, and execution-context id. `research --work-item` (which requires
`--ledger`):

1. takes the item lock (see Ownership);
2. loads the item and validates it: it must be an investigation with the
   required metadata, and its case, firmware key, and firmware sha256 must
   match the current execution context. Changed input artifacts (a
   different context id) are reported but allowed. An objective given on
   the command line must equal the item's objective;
3. reconciles the item against the ledger (below) and refuses unless the
   state allows a new attempt; refuses if any blocking item is not closed;
4. claims the item in Beads and writes an attempt marker (`aptrace_attempt_*`:
   id, state `running`, actor, host, pid, start time);
5. runs the existing `run_autonomous_investigation` + `record_research_run`
   path, recording the run with `work_item_id`;
6. writes the run id back and marks the attempt `recorded`, in a single
   metadata update;
7. prints the research summary and the work item's reconciled state.

### Completion is explicit

The item is **not closed** after a run. Every controller stop reason
(`planner_finished`, `step_budget_exhausted`, `research_graph_exhausted`,
`discovery_*`) can coexist with open questions. Nothing the controller
returns says the objective was answered, so APTrace does not invent success
semantics. `work complete` closes an item only when:

- at least one linked run exists in the ledger and references the item;
- no attempt is running, interrupted, or unlinked;
- there are no conflicts;
- no other actor holds the item.

Closing means "the operator accepts this work as done". The close reason
says so and states that claim state is owned by the ledger. Claims still go
through audit and verification as usual. Completing an already closed item
is a no-op.

## Reconciliation

`aptrace-agent work reconcile <id> [--json]` classifies an item from
durable state only: the Beads item, the ledger, and the item lock. It
changes nothing. `--apply` performs the one automatic repair, linking runs
that reference the item. It never claims, closes, restarts, or writes the
ledger. Reconciling repeatedly gives the same result and writes nothing
further.

| State | Meaning | Next step |
|---|---|---|
| `ready` | no attempt or run | `research --ledger --work-item <id>` |
| `active` | another local process holds the item lock, or an attempt is running on another host | wait; never restart |
| `link-runs` | ledger runs reference the item but are not listed on it | `work reconcile <id> --apply` |
| `awaiting-completion` | linked run(s), item open | review; `work complete`, or `--rerun` |
| `interrupted` | attempt `running`/`failed` with no run, and no process holds the lock | `research --work-item <id> --restart` |
| `claimed-by-other` | assigned to another actor | coordinate; release only once you know it is not running |
| `operator-review` | unreferenced runs look like this item's attempt | inspect; nothing is linked |
| `conflict` | missing run, run for another item, listed run without a reference, or case/firmware mismatch | inspect `problems`; nothing is repaired |
| `completed` | item closed | none |

The recovery cases:

- **A. Claimed, no run.** An item that is open, or claimed by this actor
  with no attempt marker, is `ready`. An item assigned to another actor is
  refused.
- **B. Run recorded, write-back failed.** `research` exits non-zero but still
  prints the run. The run already carries `work_item_id`, so `reconcile`
  reports `link-runs` with the exact id. `--apply` links it without
  rerunning anything and without touching the ledger.
- **C. Interrupted before recording.** The ResearchController keeps its
  session and planner context in memory, and the ledger records a run only
  after the controller finishes. An unrecorded attempt therefore cannot
  resume. If no process holds the lock, the state is `interrupted` and a new
  attempt needs `--restart`. If the lock is held, or the attempt ran on
  another host, the state is `active` and APTrace refuses, even with
  `--restart`. Claim versions whose run record is missing (a crash during
  recording) are listed as `partial_claims` and kept.
- **D. Repeated reconciliation** writes nothing further.
- **E. Conflicts** are reported with structured `problems` (`missing-run`,
  `foreign-run`, `unreferenced-linked-run`, `identity-mismatch`,
  `invalid-item`). `work reconcile` exits 1. Nothing is repaired.

### Duplicate claims

Each run proposes new claim ids. Evidence is content-addressed and reused.
So `--rerun` (after a recorded run) and `--restart` (after an interrupted
one) may propose equivalent claims again. Both print a note saying so.
Reconciliation lists `duplicate_claims`: groups of claim versions from the
item's runs with the same type and assertion text. This is a diagnostic.
Nothing is merged, superseded, or discarded, and every claim keeps its id
and provenance. Deduplication belongs in a later milestone.

## Ownership and leases

While APTrace executes, reconciles, or completes an item, it holds three
things:

1. **A Beads claim** (assignee = `--actor`, default `aptrace-agent`, or
   `APTRACE_WORK_ACTOR`). This records assignment durably and refuses other
   actors atomically.
2. **A host-local item lock**: an exclusive `flock` on
   `aptrace-locks/<id>.lock`, held for the whole command. The kernel releases
   it when the process exits for any reason. A free lock is therefore an
   exact statement that no APTrace process on this host is working on the
   item. The lock covers what the claim cannot: the same actor's
   re-claim is idempotent in Beads, so only the lock stops a second
   invocation with the same actor.
3. **An attempt marker** on the item, which identifies the attempt and its
   host. It lets reconciliation tell an interrupted attempt from a finished
   one.

Guarantees:

- A second `research --work-item` for the same item on the same host fails
  with "held by another APTrace process" while the first runs, whatever
  actor it uses.
- An attempt that recorded no run is never restarted automatically, and is
  never restarted at all while its process may still be running.
- If the claim changes hands during a run, for example through `bd reclaim`
  and another actor's claim, the finished run is still linked (an exact
  fact), but the item and its attempt marker are left as found and the
  outcome reports the lost ownership.

Leases (observed with bd 1.3.1): a claim carries a fixed 5-minute lease that
the CLI cannot configure. **Lease expiry alone releases nothing.** After
the lease expired (checked 10–20 s past expiry), another actor's `--claim`
was still refused with "already claimed by". Only `bd reclaim` reverted the
claim, and bd's help text says the same. APTrace never runs
`bd reclaim` or `bd heartbeat`, and never treats an expired lease or a
timeout as evidence that an attempt stopped.

Limitations:

- The lock is host-local, and the embedded Dolt store is node-local. Run
  every APTrace process for a store on one host. An attempt marker from
  another host is treated as possibly active.
- Running `bd reclaim` by hand, or from any supervisor, while a long
  investigation is running will reopen its item. APTrace then detects the
  lost ownership at write-back, but cannot prevent the reclaim.

Required before autonomous claiming and reclaiming can be enabled:

- a heartbeat that runs only while the attempt is alive (tied to the
  process holding the item lock) and refreshes the lease well inside the
  5-minute TTL, using `bd heartbeat`;
- a reaper that reclaims only items whose lock is free, and whose attempt
  marker names this host;
- for more than one host: Dolt server mode, plus a liveness signal that
  works across hosts (the flock does not);
- a restart policy for duplicate claim proposals (see above).

## Backup and restore

The Beads store is not versioned with the repository. bd's own
`.gitignore` excludes `embeddeddolt/`. The research ledger is backed up with
the case and is unaffected by any of this.

Durable backup (keeps items, metadata, dependencies, **and history**):

```sh
cd ~/.aptrace/work/performing-rigs && export BEADS_DIR=$PWD/.beads DO_NOT_TRACK=1
bd backup init /Volumes/backup/aptrace-work     # once
bd backup sync                                   # each time you back up
```

Restore into a fresh store. Stop every APTrace process using the store
first:

```sh
mkdir -p ~/restore && cd ~/restore && export BEADS_DIR=$PWD/.beads DO_NOT_TRACK=1
bd init --non-interactive --skip-agents --skip-hooks --quiet -p apt
bd backup restore /Volumes/backup/aptrace-work --force
aptrace-agent work reconcile <id> --work-dir ~/restore   # check items against the ledger
```

`bd export -o work.jsonl` / `bd import work.jsonl` carries ids, metadata,
run ids, and dependencies, but **not history**. Treat it as a portable
snapshot, not a backup. Lock files need no backup. Backups are manual: no
scheduled or background backup exists.

## Follow-up work from a recorded run

`aptrace-agent followups <run-id>` ranks at most three follow-up
investigations for a recorded run (preview: no ledger or work-store
writes). `--create --select N` makes the selected candidate an ordinary
`investigation` item with a deterministic id (`apt-fq<key>`), the specific
objective, `discovered-from` the source run's work item, and ledger ids in
`aptrace_*` metadata. `research --ledger --work-item` re-assembles the
candidate's bounded context from the ledger and seeds the session with it.
Selection, ranking, identity and context are APTrace's; see
[`spikes/investigation-continuity.md`](spikes/investigation-continuity.md).

## Not yet automated

- choosing or claiming work automatically (`bd ready`/`claim_next` are not
  used by any command), scheduling, and multiple concurrent workers;
- creating or executing follow-ups without an operator selecting them
  (`followups --create` requires `--select`);
- lease heartbeat and reclaiming abandoned work;
- completing work items;
- resuming an interrupted ResearchController run (only a fresh attempt);
- merging or superseding duplicate claim proposals;
- creating follow-up items from audits from the CLI (`handoff.followup_for_audit`
  exists and is tested, but no command calls it);
- scheduled backups.
