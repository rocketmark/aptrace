# Sweep 4 — agent work store, CLIs, packaging

Scope: `agent/src/aptrace_agent/work/*`, `work_cli.py`, `cli.py`, work/CLI tests,
`agent/pyproject.toml`, `agent/scripts/beads-spike.sh`,
`agent/benchmarks/trigger-role.md`, `agent/.vscode/settings.json`.
`agent/uv.lock` exists (162,898 bytes, dated Oct 13); content not read, per scope.

All paths below are relative to the repo root. Line numbers are from the files as read.

```yaml
- path: agent/src/aptrace_agent/work/__init__.py
  purpose: Package marker for long-horizon work tracking; re-exports the store boundary types.
  exports: ClaimConflict, DuplicateWork, WorkActive, WorkItem, WorkNotFound, WorkStore, WorkStoreError, WorkStoreUnavailable (L21-30)
  dependencies: aptrace_agent.work.store (L10-19)
  data_shapes: none beyond re-exports
  side_effects: none
  role: package facade
  observations: >
    Docstring L1-8 says the research ledger does not import this package
    (test_work_beads.py L444-447 checks it for ledger/ and research/). It does
    not re-export beads, handoff, ownership, or followups; callers import those
    submodules directly.

- path: agent/src/aptrace_agent/work/store.py
  purpose: Storage-independent work-item boundary (Protocol plus dataclass plus error hierarchy).
  exports: >
    Constants OPEN/IN_PROGRESS/CLOSED (L17-19); errors WorkStoreError(RuntimeError) L22,
    WorkStoreUnavailable L26, WorkNotFound(WorkStoreError, KeyError) L30, ClaimConflict L34,
    DuplicateWork L38, WorkActive L42; frozen dataclass WorkItem L46-61 with property `blockers`;
    Protocol WorkStore L64-93 (create_work, get_work, find_work, ready_work, add_dependency,
    claim_work, claim_next, release_work, update_metadata, complete_work).
  dependencies: dataclasses, typing only
  data_shapes: >
    WorkItem{id, title, status, priority:int, assignee|None, description, close_reason|None,
    metadata: dict[str, Any], dependencies: tuple[(other_id, relation)]}; blockers = relation == "blocks" (L59-61).
  side_effects: none
  role: work-state boundary / interface
  observations: >
    Docstring L5-8: work status never says whether a claim is valid; work dependency is not an
    evidentiary dependency. The Protocol has no heartbeat/reclaim/history/export/import; those exist
    only on BeadsWorkStore. Default priority 2 (L70).

- path: agent/src/aptrace_agent/work/ownership.py
  purpose: Host-local exclusive advisory flock per work item, marking it as being executed.
  exports: hostname() L34; class ItemLock L38-110 (path, held, holder(), acquire(), release(), probe(), context manager)
  dependencies: fcntl, json, os, re, socket, datetime, pathlib; aptrace_agent.work.store.WorkActive (L28)
  data_shapes: lock file `<dir>/<item_id>.lock` containing JSON {pid, host, at} (L77)
  side_effects: >
    Creates the lock directory (L62), opens/truncates/writes the lock file (L63, L75-78), flock
    LOCK_EX|LOCK_NB (L66), LOCK_UN (L87). Reads the lock file in holder() (L54). socket.gethostname().
  role: work ownership / liveness
  observations: >
    Item ids are restricted to ^[A-Za-z0-9][A-Za-z0-9._-]*$ (L31, L40-41), which prevents path escape
    (tested test_work_handoff.py L558-560). probe() acquires and releases the lock to test it
    (L92-104). The lock files are never deleted. POSIX-only (fcntl). The docstring L12-14 says
    the lock is host-local.

- path: agent/src/aptrace_agent/work/beads.py
  purpose: WorkStore implementation that shells out to the Beads `bd` CLI (embedded Dolt).
  exports: >
    PINNED_BEADS_VERSION="1.3.1" L34, SUPPORTED_SERIES="1.3." L35, DEFAULT_TIMEOUT_S=60.0 L36;
    find_bd() L39; _inside_git L43; _edge L53; _item L62; _one L76; class BeadsWorkStore L80-306 with
    _environment, _exec, _json, version, check_version, open_checked, initialize(prefix="apt",
    allow_inside_git=False), create_work, get_work, find_work, ready_work, add_dependency,
    claim_work, claim_next, heartbeat, reclaim_stale(older_than="10m"), release_work,
    update_metadata, complete_work, history, export_jsonl, import_jsonl.
  dependencies: >
    json, os, shutil, subprocess; aptrace_agent.work.store errors and WorkItem (L24-31).
    External binaries: `bd` (APTRACE_BD or PATH, L40); `git -C <dir> rev-parse --is-inside-work-tree` (L49).
  data_shapes: >
    Parses bd 1.3.1 JSON: `show` returns a list or object with embedded dependencies {id, dependency_type};
    `list`/`ready` return edge rows {issue_id, depends_on_id, type} (L53-59). Metadata is passed as a
    sorted-key JSON string (L236, L289).
  side_effects: >
    subprocess per call with env BEADS_DIR, DO_NOT_TRACK=1, BD_NON_INTERACTIVE=1, BD_NO_INSTALL_HOOKS=1,
    BD_NO_DEP_TYPE_WARNING=1, BD_NO_PAGER=1 (L98-109); cwd = beads_dir.parent (L117); stdin DEVNULL;
    timeout 60s. Reads env APTRACE_BD and os.environ. initialize() mkdirs the parent and beads_dir and
    runs `bd init --non-interactive --skip-agents --skip-hooks --quiet -p <prefix>` (L207-213).
    export_jsonl writes a file (L301-303); import_jsonl writes to the store.
  role: work-state persistence adapter
  observations: >
    Error classification is by substring of stderr/stdout (L144-151): "already claimed by" or
    "cannot close ... assignee is" -> ClaimConflict; "already exists" -> DuplicateWork; "not found" /
    "no issues found" -> WorkNotFound; "database is locked" / "timeout" -> WorkStoreUnavailable.
    Any 1.3.x is accepted though only 1.3.1 is pinned (L174). open_checked refuses a store inside a
    git work tree and never creates one (L179-192). initialize() is a no-op if metadata.json exists,
    and does not run the git check in that case (L202-203). _json requires metadata.json (L135-136),
    but version() does not. find_work makes N+1 subprocess calls (list, then show per row; L253-255).
    create_work always uses `-t task` (L231) and maps depends_on to "blocked-by:" and discovered_from
    to "discovered-from:" (L240-245). heartbeat/reclaim_stale are commented as unused in production,
    "for experiments and for a future supervisor (see docs/work-store.md)" (L271-274). The default actor
    is "aptrace" (L86); work_cli passes "aptrace-agent". complete_work passes actor=None, which falls
    back to self.actor (L115).

- path: agent/src/aptrace_agent/work/followups.py
  purpose: Materialize research follow-up candidates as Beads `investigation` work items with deterministic ids.
  exports: >
    Metadata key constants QUESTION_KEY, SOURCE_RUN, CATEGORY, GENERATOR, CLAIM_VERSIONS, AUDIT_IDS,
    VERIFICATION_IDS, EVIDENCE_IDS, PRIOR_FOLLOWUPS, RELATED_WORK (L31-40); MAX_EVIDENCE_REFS=24 L43;
    FollowUpRefused L46; followup_item_id(prefix, key) -> "<prefix>-fq<key[:10]>" L50-51; dataclass
    Materialized L54-62; existing_followups L65-77; _description L80-96; materialize L99-179;
    followup_reference L182-190; __all__ L193.
  dependencies: >
    aptrace_agent.ledger.models.ExecutionContext; aptrace_agent.research.followups (CLAIM_FOLLOWUP,
    GENERATOR_VERSION, PROPOSED, FollowUpCandidate) L26; aptrace_agent.work.handoff metadata constants L27;
    aptrace_agent.work.store L28.
  data_shapes: >
    Item metadata: aptrace_kind="investigation", objective, case, firmware_key, firmware_sha256,
    context_id, followup_key, followup_question, source_run, category, generator, claim_versions,
    evidence_ids (truncated to 24), optional audit_ids, verification_ids, prior_followups, related_work
    (L135-160). Priority = candidate.rank (L169). Materialized.as_dict -> {item_id, status, created, detail, notes}.
  side_effects: work-store reads and one create_work; no ledger access (docstring L109)
  role: follow-up materialization (work side)
  observations: >
    Refuses non-PROPOSED or blocked candidates (L112-115). Dedup is by id from the candidate key; on
    DuplicateWork it returns the existing item (L174-177); a closed item is never recreated (L120-123).
    "related" lookup uses the literal key "aptrace_audit_id" (L76), which is defined only inline in
    handoff.followup_for_audit (L671) and has no constant. Title is built from text after the first
    ". " of the objective, capped at 90 chars (L163). A missing source item is noted, not refused (L128-133).

- path: agent/src/aptrace_agent/work/handoff.py
  purpose: Connect work items to ledger runs and audits; run, reconcile, and complete investigation items without writing the ledger.
  exports: >
    Metadata key constants KIND..FOLLOWUP_KEY (L44-59); REQUIRED, ATTEMPT_KEYS (L61-62); attempt states
    RUNNING/RECORDED/FAILED (L65-67); link bases LINK_DIRECT/LINK_RECONCILED (L70-71); reconciliation
    states READY, ACTIVE, LINK_RUNS, AWAITING_COMPLETION, INTERRUPTED, CLAIMED_BY_OTHER,
    OPERATOR_REVIEW, CONFLICT, COMPLETED (L74-82); NEXT_STEP map (L84-100); FOLLOWUP_VERDICTS
    (CHALLENGED, UNRESOLVED) L102; errors HandoffError, InvalidWorkItem, WorkRefused(reconciliation,
    action, detail), WriteBackFailed(item_id, run_id, cause) (L109-133); create_investigation L139;
    validate_item L164; link_run L200; _attempt_state L206; _link L211; dataclass Outcome L245;
    run_investigation L266; complete_investigation L369; dataclasses Problem L405, Reconciliation L412
    (next_step, as_dict); runs_for_item L449; _identity_problems L453; _claim_state L460; _duplicates
    L467; reconcile L482; apply_reconciliation L600; followup_id L625; _followup_reason L629;
    followup_for_audit L642. Also re-exposes ItemLock and hostname by import (used as handoff.ItemLock
    in work_cli L160).
  dependencies: >
    aptrace_agent.ledger.hashing.digest; aptrace_agent.ledger.models (AuditVerdict, ExecutionContext,
    InvestigationRun); aptrace_agent.ledger.store (LedgerError, ResearchLedger, new_id, now);
    aptrace_agent.work.ownership (ItemLock, hostname); aptrace_agent.work.store (L37-41).
  data_shapes: >
    Investigation metadata {aptrace_kind, aptrace_objective, aptrace_case, aptrace_firmware_key,
    aptrace_firmware_sha256, aptrace_context_id} (L153-160); run linkage aptrace_run_ids (list) and
    aptrace_run_link_basis {run_id: basis}; attempt marker {attempt_id "WA-...", state, started_at,
    actor, host, pid, detail} (L322-333). Reconciliation.as_dict (L432-446). Problem.code in
    {missing-run, foreign-run, unreferenced-linked-run, identity-mismatch, invalid-item} (L406).
    Audit follow-up metadata {aptrace_kind="audit-followup", aptrace_followup_key, aptrace_claim_version,
    aptrace_audit_id, aptrace_audit_verdict, aptrace_followup_reason, aptrace_claim_run_id,
    optional aptrace_source_work} (L667-678); id "<prefix>-fu<digest[:10]>" (L626).
  side_effects: >
    Work-store writes (claim, update_metadata, complete_work, create_work); lock files via ItemLock;
    reads the ledger (runs, run, claim, state, audit, all_claim_versions). os.getpid(), hostname().
    No ledger writes (asserted by test_work_beads.py L436-441).
  role: work/ledger handoff, reconciliation state machine
  observations: >
    run_investigation holds the item lock throughout (L293), validates, reconciles, and refuses unless
    the state is READY, or INTERRUPTED with restart, or AWAITING_COMPLETION with rerun (L298-303).
    It refuses while blockers are unclosed (L305-308), claims, writes the attempt marker, calls
    investigate(objective, item_id), and on any BaseException marks FAILED and re-raises (L337-343,
    swallowing a WorkStoreError on that write, L340-341). It verifies run.work_item_id == item_id
    (L350-351), links the run, and never closes the item (docstring L287-290). Ownership-changed runs
    are linked but the attempt marker is left (L355-364). reconcile has a priority order
    (L567-595): CONFLICT > ACTIVE (lock probe) > ACTIVE (remote host) > LINK_RUNS > COMPLETED >
    OPERATOR_REVIEW > CLAIMED_BY_OTHER > INTERRUPTED > AWAITING_COMPLETION > READY. Heuristic lookalike
    runs (same objective/case/sha/time) are reported, never linked (L551-561). partial_claims is a
    time-window scan of all_claim_versions whose run_id is not a recorded run (L545-549). runs_for_item
    and the partial-claim scan iterate the whole ledger (L450, L544-548), which is O(ledger) per call.
    _duplicates groups claims by (type, normalized assertion) as a diagnostic only (L467-479).
    apply_reconciliation's only repair is linking exactly referenced runs (L600-619); if the lock is
    held elsewhere it returns a read-only reconcile (L609-610). The legacy-state fallback in
    _attempt_state (L206-208) handles items written before attempt states existed.
    followup_for_audit skips SUPPORTED and diagnostic audits (L661). Priority is 1 for CHALLENGED and
    2 otherwise (L684). followup_for_audit has no CLI command in this scope; it is called only from
    tests (test_work_beads.py L383, L423). NEXT_STEP strings embed CLI command text (L85-99),
    coupling the library to work_cli command names. A forward reference to Reconciliation in WorkRefused
    (L120) depends on `from __future__ import annotations`.

- path: agent/src/aptrace_agent/work_cli.py
  purpose: argparse wiring and handlers for `work`, `followups`, and the `research --work-item` handoff; the only place that reaches Beads.
  exports: >
    DEFAULT_ACTOR="aptrace-agent" L23; _store_options L26; add_research_work_options L31;
    add_work_commands L38; add_followup_command L67; _open L83; _context L91; print_reconciliation L98;
    handle_work_command L125; _followup_report L182; _select L189; print_followup_report L207;
    handle_followups_command L240; followup_for_work_item L306; research_work_item L338;
    print_work_summary L375; __all__ L396-405.
    CLI surface:
      shared store options (L26-28): --work-dir (default APTRACE_WORK_DIR or ~/.aptrace/work/performing-rigs),
        --actor (default env APTRACE_WORK_ACTOR or "aptrace-agent").
      research additions (L31-35): --work-item, --restart, --rerun, plus --work-dir, --actor.
      work init (L42-44): --prefix (default "apt"), --work-dir, --actor.
      work create (L46-51): --priority (int, default 2), --depends-on (repeatable), --title, objective (nargs +), --work-dir, --actor.
      work reconcile (L53-58): item, --apply, --json, --ledger-dir, --work-dir, --actor.
      work complete (L60-64): item, --reason (default ""), --ledger-dir, --work-dir, --actor.
      followups (L67-80): run_id, --limit (default 3), --create, --select (repeatable; position or key prefix),
        --json, --no-store, --ledger-dir, --prefix (default "apt"), --work-dir, --actor.
  dependencies: >
    aptrace_agent.ledger.store.ResearchLedger; aptrace_agent.ledger_wiring (ledger_dir, work_dir)
    at module top (L19-20). Lazy: aptrace_agent.work.beads.BeadsWorkStore (L84), aptrace_agent.executor.EvidenceExecutor,
    ledger_wiring.context_provider, lead_deriver_factory, aptrace_agent.research.followups.generate_followups,
    aptrace_agent.work, work.handoff, work.followups. ledger_wiring imports aptrace_agent.census
    PERFORMING_RIGS_CASE and performing_rigs_svd (ledger_wiring.py L18), so these CLIs are bound to the
    Performing Rigs case through ledger_wiring. Invokes `bd` indirectly.
  data_shapes: >
    followups --json -> {report: FollowUpReport.model_dump, work: {candidate_key: annotation}, created: [{key, item_id, status, created, detail, notes}]} (L296).
    reconcile --json -> Reconciliation.as_dict. research_work_item returns (Outcome.as_dict | {item_id, run_id, write_back:"failed"}, error|None) (L367-372).
  side_effects: >
    Reads env APTRACE_WORK_ACTOR at parser build (L28). Work dir is resolved via ledger_wiring.work_dir
    (APTRACE_WORK_DIR or ~/.aptrace/work/performing-rigs); locks live at <work_dir>/aptrace-locks (L88).
    The ledger is resolved via ledger_wiring.ledger_dir (--ledger-dir, else APTRACE_LEDGER_DIR, else the
    canonical cases/performing-rigs/research/ledger). Constructs EvidenceExecutor and context_provider,
    which hash case artifacts. stdout printing. SystemExit on errors.
  role: CLI subcommand module
  observations: >
    Docstring L6-8: plain `research` never imports the work package (tested test_work_cli.py L69-87);
    the work imports are lazy inside handlers. `work init` builds the store with initialize=True and
    skips open_checked (L134-135). `work reconcile` without --apply still constructs an ItemLock, and
    probe() creates the lock dir and file (ownership L62-63), so a "read-only" reconcile writes lock
    files. `work reconcile` exits 1 on CONFLICT (L167-168). `followups` reads the store by default
    unless --no-store; if the store is unavailable without --create, it annotates rather than failing
    (L269-275). --create with no --select is refused (L261-262). `_select` dedupes by key (L204).
    followups and `research --work-item` default to the canonical case ledger when --ledger-dir and
    APTRACE_LEDGER_DIR are both unset. followup_for_work_item regenerates the follow-up report and
    refuses if the candidate key no longer derives (L327-333). The --work-dir help string hardcodes
    "performing-rigs" (L27). The `work` subcommands do not expose ready/list/claim/release/history/export;
    those operations exist on BeadsWorkStore only. There is no CLI path to handoff.followup_for_audit.

- path: agent/src/aptrace_agent/cli.py
  purpose: `aptrace-agent` console entry point (argparse) dispatching investigate, research, ledger, work, and followups commands.
  exports: >
    _research_payload L32-80; _print_research_summary L83-137; main L140-524; `__main__` guard L527-528.
    Subcommands and flags:
      investigate (L154-182): question (nargs +), -v/--verbose, --json.
      research (L184-277): --function (dest seed_function), --max-steps (int, default 12), --json,
        --output (path), --ledger (store_true), --ledger-dir, --experimental-tool (dest experimental_tools,
        repeatable, choices=EXPERIMENTAL_STRUCTURAL_TOOLS, default []), --claim-candidates (int, default
        research.candidates.DEFAULT_LIMIT; 0 disables), objective (nargs *), plus from work_cli:
        --work-item, --restart, --rerun, --work-dir, --actor.
      ledger ...: registered by aptrace_agent.ledger_cli.add_ledger_commands (L278); its subcommands are
        defined in ledger_cli.py (outside this sweep).
      work init|create|reconcile|complete (L279, from work_cli).
      followups (L280, from work_cli).
  dependencies: >
    argparse, json, os, datetime, pathlib; aptrace_agent.ledger_cli (add_ledger_commands,
    handle_ledger_command, record_research_run) L10-14; aptrace_agent.work_cli (L15-21);
    aptrace_agent.research.candidates.DEFAULT_LIMIT; aptrace_agent.research.controller.EXPERIMENTAL_STRUCTURAL_TOOLS;
    aptrace_agent.research.projection.conclusion; aptrace_agent.investigator (AutonomousInvestigationRun,
    run_autonomous_investigation, run_investigation) L25-29. Lazy: executor.EvidenceExecutor,
    ledger.recorder.RecordingExecutor (L308-311), ledger_wiring.context_provider/ledger_dir,
    work_cli.followup_for_work_item/research_work_item/print_work_summary, ledger.store.ResearchLedger,
    research.history.HistoricalOperations (L326), research.ResearchController (L362).
  data_shapes: >
    Research payload schema_version 1 (L35-80): {schema_version, generated_at, models{planner, reconciler},
    objective, seed_function, stop_reason, reconciled, trajectory[{number, action, lead_id, evidence_id,
    reason}], planner_requests, conclusion, evidence[], state}; with --ledger adds proposed_claims and
    ledger_run_id (L364-365); with --work-item adds work_item (L398-399). Investigate --json payload
    {question, routing, plan, evidence, answer, usage{synthesis}} (L470-483).
  side_effects: >
    Reads env APTRACE_MODEL (L41-43) and APTRACE_REVIEW_MODEL (default "gemma-4-26b-a4b-it-4bit", L44-47)
    for the payload only. --output mkdirs the parent and writes JSON (L403-419). --ledger records to the
    ledger via record_research_run with ledger_dir_override=args.ledger_dir (L365-377); without
    --ledger-dir or APTRACE_LEDGER_DIR that is the canonical case ledger. Model/network side effects
    come from run_autonomous_investigation / run_investigation (outside this sweep).
  role: CLI entry point
  observations: >
    Validation (L298-303): --work-item requires --ledger; --restart/--rerun require --work-item; the
    objective is required unless --work-item. The --work-item path relies on recorder being set (L321,
    L389 use recorder.inner), which the --ledger check guarantees. context_provider(recorder.inner)() is
    called up to three times in the work-item path (L321, L329, L389). The investigate closure records
    to the ledger and returns the run id, or None without --ledger (L332-378). completed["run"] is read
    after research_work_item (L395); if the work handoff refused before running, SystemExit is raised
    earlier, so this is not reached. Heavy one-arg-per-line formatting style (e.g. L32-137) differs from
    work_cli.py. The --function help hardcodes the AutoPilot example FUN_0000d3dc (L196-198). The
    reconciler model default "gemma-4-26b-a4b-it-4bit" is recorded in the payload but is not otherwise
    used here. The final `if args.command != "investigate": raise SystemExit(2)` (L449-450) is a fallthrough
    guard. Dispatch order: ledger, then work, then followups, then research, then investigate (L284-296).

- path: agent/tests/work_support.py
  purpose: Shared test fixtures, including an in-memory FakeWorkStore that mirrors bd 1.3.1 claim semantics, a scripted planner, an investigator closure, and a directory snapshot hash.
  exports: OBJECTIVE, CLAIMS (L44-45); FakeWorkStore L48-147 (+snapshot, reclaim, fail_metadata_after); Planner L150-167; investigator(ledger, context, claims, calls) L170-190; snapshot(root) L193-198
  dependencies: aptrace_agent.investigator, ledger.models.SourceRevision, ledger.recorder (RecordingExecutor, record_investigation), ledger.store.now, research (LeadFollower, LeadRegistry, ResearchController, ResearchSession), work.store; tests' ledger_support.FakeExecutor
  observations: >
    The docstring L6-12 lists the bd semantics it mirrors. FakeWorkStore.update_metadata can simulate
    failure after N writes (L129-130). The fixture objective and claims hardcode AutoPilot specifics
    (USB_OTHER, FUN_0000cc14; L44-45, L180).

- path: agent/tests/test_work_beads.py
  purpose: Real-`bd` integration tests for BeadsWorkStore and the handoff; skipped without bd.
  behaviors_covered: >
    A metadata round-trip and reopen (L93-112); B dependency ready frontier (L118-134); C concurrent
    claim exactly once, claim_next uniqueness, idempotent holder claim and CAS release (L140-188);
    D the run drives an investigation, links the run id, and completion does not touch the ledger
    (L205-227); E crash before run needs --restart, write-back failure recovered by
    apply_reconciliation, recovery from a fresh process, restart reuses evidence but makes new claims,
    lease-expiry reclaim (slow, APTRACE_SLOW_TESTS) (L233-363); F CHALLENGED/UNRESOLVED audit opens one
    follow-up (also concurrently), SUPPORTED opens none (L369-412); G closing work cannot promote a
    claim, the work package has no ledger write-call text, and ledger/research do not import work
    (L418-447); H history and JSONL export/import round-trip (L453-474); failure isolation for a missing
    binary, missing store, research without a store, pinned version, and refusal inside a git tree
    (L480-543); CLI end to end against real bd (L549-591).
  observations: >
    The session-scoped store template runs bd init once and is copied per test (L46-64). It uses a
    sandbox HOME (L56). It asserts case "performing-rigs" and firmware_key "autopilot868" from the
    ledger_support context (L104-105). The forbidden-call test is a text grep over work/*.py (L436-441).
    The import-direction test greps ledger/*.py and research/*.py top level only, not subpackages (L444-447).

- path: agent/tests/test_work_cli.py
  purpose: CLI wiring tests for `research --work-item` and `work ...` with faked executor, context, store, and recorder.
  behaviors_covered: >
    Plain research never loads the work package or creates the work dir (subprocess, L69-87); plain
    --ledger runs carry no work reference (L90-96); --work-item runs, records, and links (L99-108);
    work summary printed (L111-115); --work-item requires --ledger (L118-122); objective required
    (L125-129); refusal before rerunning (L132-138); mismatched objective rejected (L141-145);
    write-back failure still reports the run, then reconcile --apply repairs it (L148-161);
    work create/reconcile/complete flow (L164-181); reconcile CONFLICT exits 1 (L184-190).
  observations: >
    Monkeypatches work_cli._open and _context (L58-59), so the real _open/BeadsWorkStore path is
    covered only in test_work_beads L549. The fake `autonomous` signature (L39) lacks
    experimental_tools/followup/history kwargs; the tests do not pass those.

- path: agent/tests/test_work_handoff.py
  purpose: Policy tests of handoff/reconciliation/ownership against FakeWorkStore (no bd).
  behaviors_covered: >
    Legacy runs without work_item_id load (L130-139); the persisted canonical case ledger loads (reads
    DEFAULT_LEDGER_DIR, skip if absent; L142-157); standalone runs omit the field (L160-164); the linked
    run reference is immutable (L167-179); invalid kind/case/firmware/objective rejected before claim
    (L185-210); a changed context is a note (L213-216); blocked items are refused (L219-226); cases
    A-E: ready, claimed-by-self, claimed-by-other, write-back recovery, lookalikes ignored, store down
    before run, error -> INTERRUPTED -> restart, crash marker, locally ACTIVE via a subprocess lock
    holder, remote-host ACTIVE, partial claims, OPERATOR_REVIEW, idempotent reconcile in all states,
    missing-run/identity-mismatch/foreign/unreferenced conflicts (L232-463); rerun required and
    duplicates reported (L469-483); a completed item is never re-executed (L486-494); concurrent
    invocation blocked (L500-513); lease reclaim mid-run (L516-533); completion requires a linked run
    and leaves claims unchanged (L539-555); lock id restriction (L558-560).
  observations: >
    test_persisted_case_ledger_runs_still_load reads the canonical ledger under cases/performing-rigs
    (read-only) (L142-157). HeldElsewhere spawns a python subprocess that sleeps 120s holding the lock (L94-111).

- path: agent/tests/test_autonomous_cli.py
  purpose: Basic `research` CLI JSON and --output artifact tests with run_autonomous_investigation faked.
  behaviors_covered: --function/--max-steps passthrough and the JSON payload (L14-95); --output writes a schema_version 1 artifact with the models from env (L98-191).
  observations: Uses the AutoPilot seed FUN_0000d3dc (L19, L65). The fake signature has only seed_function and max_steps (L34-39, L119-124).

- path: agent/pyproject.toml
  purpose: Package metadata for aptrace-agent 0.1.0.
  exports: console script aptrace-agent = aptrace_agent.cli:main (L11-12)
  dependencies: python >=3.12; capstone>=5.0.9; pydantic-ai-slim[openai] (L6-9); dev group pytest (L14-17); build hatchling (L19-21); wheel packages src/aptrace_agent (L23-24)
  side_effects: none
  role: packaging
  observations: >
    Beads (`bd`) is an undeclared external binary dependency. No pytest config, markers, or testpaths
    are set here; the tests import sibling modules (ledger_support, work_support) directly. Dependencies
    are unpinned except a capstone floor; uv.lock holds the resolution.

- path: agent/scripts/beads-spike.sh
  purpose: Exploratory bash spike for Beads experiments H (history/backup/portability), I (resources/latency), and J (formulas/molecules).
  exports: script `BD=/path/to/bd agent/scripts/beads-spike.sh [workdir]` (L6)
  dependencies: bash, bd, python3, /usr/bin/time, pgrep, du, mktemp
  side_effects: >
    Creates a temp ROOT (default mktemp -d; L10) with sandbox HOME (L11-12), several stores (a, b, c),
    backups, a JSONL export, 200 bulk items, and a formula TOML under $A/.beads/formulas (L94-128);
    exports DO_NOT_TRACK etc. Spawns 8 concurrent readers (L89).
  role: experiment / spike script (not used by code or tests)
  observations: >
    Hardcodes "performing-rigs" and R-/C1:v1 ids in sample metadata (L30-31). If [workdir] is passed, it
    is used without checking that it is outside a git tree (contrast BeadsWorkStore L209). Uses bd
    features the adapter does not wrap (backup, formula, cook, mol pour). Many steps end in `|| true`, so
    failures are tolerated.

- path: agent/benchmarks/trigger-role.md
  purpose: AutoPilot trigger/PA22 autonomous-research regression benchmark description (objective, grading facts, reference trajectory, required protections, model roles).
  exports: none (document)
  dependencies: none
  side_effects: none
  role: benchmark specification
  observations: >
    Entirely AutoPilot-specific content (FUN_0000d3dc, PA22, PB05, FUN_00006968 @0x000069a4; L5-32, L41-72)
    located under agent/ rather than cases/performing-rigs/, contrary to the CLAUDE.md case-boundary rule.
    Names models Qwen3-Coder-30B-A3B-Instruct-4bit and gemma-4-26b-a4b-it-4bit (L86-92); the latter matches
    the cli.py reconciler default (cli.py L46). No code in scope references this file.

- path: agent/.vscode/settings.json
  purpose: VS Code interpreter setting.
  exports: python.defaultInterpreterPath = ${workspaceFolder}/.venv/bin/python3 (L2)
  dependencies: none
  side_effects: none
  role: editor config
  observations: Assumes a .venv inside agent/.

- path: agent/uv.lock
  purpose: uv dependency lock (exists, 162,898 bytes). Content not read, per scope.
```

## Observed behaviors

- The work store reaches `bd` only through subprocess, one `bd ... --json` call per operation, with BEADS_DIR set explicitly and cwd = the store parent (work/beads.py L111-128, L98-109).
- Usage metrics, hooks, pager, and interactivity are disabled per bd call through env vars (work/beads.py L102-107).
- The bd binary is located through APTRACE_BD, then PATH (work/beads.py L39-40).
- The bd version must be 1.3.x; 1.3.1 is pinned (work/beads.py L34-35, L171-177).
- bd failures are classified into ClaimConflict / DuplicateWork / WorkNotFound / WorkStoreUnavailable / WorkStoreError by output substring (work/beads.py L140-153).
- The store refuses to open or initialize inside a git work tree, checked with `git rev-parse` (work/beads.py L43-50, L187-188, L209-210).
- Opening a store never creates it; only `work init` does (work/beads.py L179-192, L194-216; work_cli.py L134-135).
- The default work dir is ~/.aptrace/work/performing-rigs, overridable by --work-dir or APTRACE_WORK_DIR (ledger_wiring.py L42, L47-50; work_cli.py L27).
- The default ledger dir is the canonical cases/performing-rigs/research/ledger, overridable by --ledger-dir or APTRACE_LEDGER_DIR (ledger_wiring.py L34, L43-44; work_cli.py L57, L63, L78; cli.py L239-242).
- The default actor is "aptrace-agent", overridable by --actor or APTRACE_WORK_ACTOR (work_cli.py L23, L28); the adapter's own default is "aptrace" (work/beads.py L86).
- Per-item host-local flock lock files live at <work_dir>/aptrace-locks/<id>.lock and hold JSON {pid, host, at} (work_cli.py L88; work/ownership.py L58-80).
- Lock ids are restricted by regex to prevent path traversal (work/ownership.py L31, L40-41).
- A lock probe acquires and releases the lock, which creates the lock file as a side effect (work/ownership.py L62-63, L92-104).
- Investigation work items carry case, firmware key, firmware sha256, context id, and objective metadata (work/handoff.py L153-160).
- An item is validated against the current case/firmware/kind before it is claimed; a context-id change produces a note, not a refusal (work/handoff.py L164-197).
- A CLI objective must match the item's objective (work/handoff.py L186-187).
- Unclosed `blocks` dependencies prevent a start (work/handoff.py L305-308).
- Starting an item: lock, reconcile, claim, write the attempt marker (WA-id, running, host, pid), investigate, verify the run's work_item_id, link the run; the item is never auto-closed (work/handoff.py L293-366).
- An exception during the investigation marks the attempt FAILED and re-raises (work/handoff.py L337-343).
- When the run is recorded but the work-store write-back fails, WriteBackFailed is raised and the run is still reported (work/handoff.py L125-133, L353-358; work_cli.py L367-368; cli.py L444-445).
- An ownership change during the run is recorded as a note; the run is linked but the attempt marker is untouched (work/handoff.py L355-364).
- Reconciliation classifies an item into 9 states by a fixed priority order, from the work store, the ledger, and the lock (work/handoff.py L482-597).
- An attempt recorded on another host is treated as ACTIVE (liveness unknown) (work/handoff.py L564, L571-574).
- Lookalike runs without a work-item reference are reported as heuristic candidates and never linked (work/handoff.py L551-561, L579-583).
- Claim versions whose run was never recorded are reported as partial_claims (work/handoff.py L541-549).
- Duplicate claim proposals across runs are grouped by type and normalized assertion, as a diagnostic only (work/handoff.py L467-479).
- The only automatic repair is linking runs whose work_item_id names the item (`work reconcile --apply`) (work/handoff.py L600-619; work_cli.py L157-158).
- Completion requires the AWAITING_COMPLETION state, records a close reason that says claim state is ledger-owned, and is idempotent (work/handoff.py L369-398).
- Reconciliation outputs include next-step CLI hints (work/handoff.py L84-100, L428-430).
- `work reconcile` exits 1 on CONFLICT (work_cli.py L167-168).
- Audit follow-ups: only CHALLENGED/UNRESOLVED non-diagnostic audits open an item, with a deterministic id from the digest of claim_version+audit_id; DuplicateWork returns the existing item (work/handoff.py L625-692).
- Follow-up candidate materialization uses id <prefix>-fq<key[:10]>, refuses non-proposed or blocked candidates, never recreates a closed item, and links prior items for the same question (work/followups.py L50-51, L99-179).
- The `followups` CLI previews a ranked shortlist; --create with --select materializes items; the store is consulted unless --no-store, and an unavailable store degrades to annotations in preview (work_cli.py L240-303).
- `research --work-item` on a follow-up item re-derives the candidate from the ledger and refuses if it no longer derives (work_cli.py L306-335; cli.py L317-330).
- Plain `research` never imports aptrace_agent.work or touches the work dir (work_cli.py L6-8; cli.py L317, L382; test_work_cli.py L69-87).
- The work package source contains no ledger write calls (test_work_beads.py L436-441); ledger/ and research/ do not import work (test_work_beads.py L444-447).
- `research` emits a schema_version 1 JSON payload with model names from APTRACE_MODEL and APTRACE_REVIEW_MODEL (cli.py L32-80).
- `research --output` writes the payload to a file, creating parent dirs (cli.py L403-419).
- `research --ledger` wraps EvidenceExecutor in RecordingExecutor and records the run with the claim contract and claim candidates (cli.py L307-311, L346, L365-377).
- `--experimental-tool` passes experimental structural tools to the planner (cli.py L244-255, L344).
- `investigate` runs one deterministic bounded query, with --json and --verbose output (cli.py L154-182, L452-524).
- CLI argument validation: --work-item requires --ledger; --restart/--rerun require --work-item; the objective is required otherwise (cli.py L298-303).
- The console script entry is aptrace-agent -> aptrace_agent.cli:main (pyproject.toml L11-12).
- work_cli and ledger_wiring bind these CLIs to the performing-rigs case (ledger_wiring.py L18, L31; work_cli.py L27).
- BeadsWorkStore heartbeat/reclaim_stale/history/export/import exist but are unused by production code (work/beads.py L271-306; used only in test_work_beads.py L353-360, L461-468).
- The Beads spike script exercises backup, export/import, latency, RSS, concurrency, and formulas in a temp sandbox (agent/scripts/beads-spike.sh L23-142).
- An AutoPilot-specific benchmark spec lives under agent/benchmarks (agent/benchmarks/trigger-role.md L1-92).
