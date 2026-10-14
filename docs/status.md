# APTrace Framework Status

This document answers: **what can APTrace itself currently do?** It does not
track conclusions or open questions for any particular firmware target. Those
belong in each case's status document.

## Available capabilities

- Load raw Cortex-M firmware at a caller-supplied flash/RAM geometry and parse
  its vector table.
- Discover and normalize machine-code control flow with Macaw, including an
  APTrace semantic classification layer for ambiguous control transfers.
- Build persistent headless Ghidra projects and query disassembly,
  decompilation, references, and exported static-analysis data.
- Execute Thumb firmware concretely with Unicorn using explicit memory maps,
  hooks, state carry-forward, bounded traces, and structured failure snapshots.
- Translate bounded Macaw regions into Crucible and ask What4/Z3 reachability
  and input-model questions.
- Combine static and dynamic evidence in the census database, including CFG,
  RAM/MMIO, vector, coverage, fingerprint, reduction, and comparison data.
- Summarize one function's effects (`aptrace function-effects`): Macaw
  discovery and Crucible simulation give raw parametric accesses, calls and
  return dependencies; one Z3 session adds guard, region, return-range and
  argument-specialization facts. Geometry comes from the case; callers supply
  only the entry and optional `rN=` specializations.
- Observe caller-grounded arguments (`observed_call_arguments`, a typed,
  replayable ledger operation): a case scenario is replayed concretely in
  Unicorn with a passive watch at one function entry; every entry is
  attributed to its call instruction (decoded `BL`/`BLX rm`, or `OTHER` for
  a tail branch), and each argument value and the word it points at is
  classified against the case geometry (`tools/unicorn/call_observation.py`,
  `ConcreteMachine.run(watch_reg_pointee=...)`). Static call sites never
  reached are reported `UNOBSERVED`, not unreachable; evidence is labeled
  `CALLER_GROUNDED_CONCRETE` and carries the scenario's harness
  assumptions. Chosen-input `function_effects` specializations are labeled
  `HYPOTHETICAL_ARGUMENT_SPECIALIZATION`.
- Resolve statically initialized RAM function pointers
  (`tools/census/fnptr_resolve.py`): an unresolved `bx`/`blx` whose target
  is loaded from one constant RAM slot, every known store to that slot a
  mechanically constant Thumb code pointer (intraprocedural, or one hop
  through a constant call argument; call-clobber aware). Raw and canonical
  values, every store/callsite, and bounded branch forwarding are kept.
  STRONG results become `indirect_edge_candidates`
  (`RESOLVED_RAM_FUNCTION_POINTER`, graph edge kind `resolved_indirect`) and,
  via `aptrace_census.py fnptr-seeds`, provenance-carrying Ghidra seeds that
  participate in the Ghidra cache identity.
- Run a bounded autonomous research agent (`agent/`, Agent v0): the local
  planner chooses among case-evidence search, census peripheral analysis, a
  USB structural inventory, call-graph common-path analysis, function effects,
  and validated per-function leads. The planner sees a character-budgeted
  projection of the research state; the evidence ledger, claims and
  provenance stay complete in APTrace.
- Keep a durable research ledger with adversarial audit and deterministic
  verification ([`research-ledger.md`](research-ledger.md)): content-addressed
  evidence with typed-operation replay, versioned claims with dependencies,
  an APTrace-owned lifecycle (`PROPOSED`/`VERIFIED`/`BLOCKED`/`STALE`/
  `SUPERSEDED`), a bounded audit-model loop over one claim version with a
  typed tool allowlist, deterministic staleness propagation, and a generated
  Markdown report. Audits record structural source agreement (census,
  Ghidra, Macaw; coverage gap vs boundary disagreement vs conflict), count
  only successful analyses toward falsification, and carry a deterministic
  audit-input fingerprint for repeated-audit stability measurement. Claims
  may carry typed semantics (resolved function pointer, function role, typed
  path relation over set scopes) that APTrace verifies deterministically in
  phased verification; the audit model is consulted only for claims that
  pass structural, semantic, and replay checks.
- Track long-horizon investigation work in an optional Beads store
  ([`work-store.md`](work-store.md)): `research --ledger --work-item` runs a
  validated work item through the normal pipeline, the run records the
  item id (`InvestigationRun.work_item_id`), and exact reconciliation repairs
  a failed write-back without re-running. Ownership is a Beads claim plus a
  host-local item lock. Closing work never changes claim state.
- Propose follow-up investigations from a recorded run
  ([`spikes/investigation-continuity.md`](spikes/investigation-continuity.md)):
  `followups <run-id>` re-derives the run's open-lead frontier from durable
  evidence, finds evidence gaps, audit requests, unmet verification
  conditions and stale claims, consolidates related leads, and ranks a
  shortlist by documented categories; `--create` persists a selected
  candidate as a deduplicated Beads item, and the follow-up run records the
  bounded prior context it received (`InvestigationRun.followup`).
- Continue follow-ups from prior operations
  ([`research-continuity.md`](research-continuity.md)): a follow-up session
  uses compatible historical results by reference (same tool, canonical
  arguments, firmware, input artifacts, analysis version; valid, intact
  evidence) instead of re-executing them, records no new invocation or
  evidence for a reuse, ranks its seeded leads first, withholds broad
  peripheral rediscovery while they are open, and bounds reuse and planner
  fallback in its step budget (`InvestigationRun.continuity`).
- Admit planner claim proposals deterministically
  ([`claim-admission.md`](claim-admission.md)): canonical, known entities
  (no `E0000b4b4`, no session ids as subjects), typed semantics checked
  against cited evidence, peripheral access/absence supported by
  structured evidence, untyped claims at most PROBABLE, follow-up evidence
  cited or its omission explained; one bounded correction round; rejected
  proposals are recorded on the run with diagnostics and never become
  claims. Typed `MMIO_USER` now requires an actual access; a constant-only
  census entry is `ADDRESS_CONSTANT_LOADER`.
- Offer mechanically derived claim candidates for selection by id
  ([`claim-candidates.md`](claim-candidates.md)): typed `FUNCTION_ROLE`
  (`MMIO_USER`, `ADDRESS_CONSTANT_LOADER`) and `RESOLVED_FUNCTION_POINTER`
  facts generated from session evidence with stable content-derived ids,
  scope, limitations and an evidence-grade ceiling. The planner selects
  ids only; selected candidates pass unchanged admission, and an
  equivalent existing typed claim creates no new version. Read-only
  preview: `aptrace-agent candidates <run-id>`.

## Current limitations

- Cortex-M exception delivery and peripherals are modeled only through narrow,
  explicit harness mechanisms; APTrace is not a general MCU simulator.
- Function and CFG discovery remain heuristic and require cross-checking when a
  boundary is material to a conclusion.
- Symbolic execution works best for targeted, already-understood regions; whole
  firmware replay is neither its purpose nor a supported workflow.
- Caller-grounded observation covers only the contexts one scenario reaches
  (currently the case boot recipe); it is not exposed to the planner, and it
  reports immediate call sites only, not full calling contexts.
- Function effects do not resolve Thumb `tbb`/`tbh` jump tables or other
  computed transfers; these are modeled as opaque calls and the summary is
  marked `bounded`. Callee effects, write values, and loops are not
  summarized.
- RAM function-pointer resolution sees only stores Ghidra attributed to the
  slot's constant address; stores through computed pointers are not excluded,
  so results are graded STRONG (static), never EXACT. No indexed slots,
  pointer arithmetic, or data pointers.
- Common-path analysis uses the census strong call graph only; unresolved
  indirect transfers are reported as frontier and absence of a path is
  `NO_KNOWN_PATH`, never unreachability.
- The local planner's usable prompt size is set by the model server's
  prefill memory guard, not by the model's context length. On a 24 GB host
  serving a 30B 4-bit model this was measured at roughly 1.2–3.7k prompt
  tokens and moves with server memory state; the agent retries rejected
  requests with a compact projection.
- The research ledger's verification is mechanical: references, context,
  hashes, replay, grade ceilings, inherited limitations, bounded negatives,
  typed semantics when a claim carries them, and the audit verdict. For
  claims without typed semantics, whether the assertion's entities and roles
  match the evidence is left to the audit model, whose verdicts are not
  stable across runs on identical input.
- Cross-engine verification
  ([`cross-engine-verification.md`](cross-engine-verification.md)) is
  enforced only as a safety gate: verification policy v1 (phase P). Before
  any audit model, it evaluates `contradictory_evidence_ids` against typed
  assertions, gates on structural `CONFLICT`s at asserted code, and
  requires independent corroboration per claim class. It records the policy
  identity and named conditions on every verification. Only
  `CODE_EXISTENCE` (`CODE_PRESENCE`) claims have an evidence contract, and
  only when sources declare an independence envelope, which no real source
  does yet. Every other class, including resolved pointers, paths, bounded
  negatives, MMIO usage, and untyped claims, stays `PROPOSED` as
  `UNEVALUABLE`, so no current case claim can newly reach `VERIFIED`.
  Pre-policy `VERIFIED` decisions (`C2:v2`, `C5:v1`) are unchanged and are
  reported as pre-policy by `policy-status`. There is still no per-observation
  lineage, assisted marking by the engines themselves, common
  target-configuration record, discrepancy record or resolution lifecycle,
  or comparison of CFG edges, calls, or memory accesses in the ledger. The Macaw/Ghidra function
  and call comparison (`tools/census/macaw_compare.py`) is standalone and not
  recorded as ledger evidence; Macaw census output does not carry the
  firmware digest; Unicorn concrete execution is not a ledger operation.
- The local Qwen3-Coder planner does not reliably emit structured claim
  output as tool arguments: nested and multiple array arguments degrade into
  malformed tool-call text. Typed claims therefore reach the ledger through
  candidate selection, which covers only the facts its extractors derive;
  call-site relations, bounded effects observations, and accesses observed
  only under argument specialization have no typed predicate and no
  candidate.
- Work items are run and completed only by explicit operator commands.
  There is no scheduler, lease heartbeat, or reclaim. Ownership liveness is
  host-local (one host per work store), an interrupted investigation restarts
  from its objective rather than resuming, and restarts may duplicate
  `PROPOSED` claims (reported, not merged).
- Follow-up generation re-derives open leads because runs do not record
  them; it refuses when the run's input artifacts differ from the current
  ones. Its evidence-gap rule covers peripheral-access assertions only, and
  matches assertion prose. An inconclusive follow-up suppresses its
  question until the evidence basis changes or an operator reruns the item.
  Historical reuse does not detect tool changes that do not bump a declared
  analysis version (replay does).
- Case selection is currently wired explicitly by the application and some
  scripts. A plugin/provider architecture is intentionally deferred until more
  than one real case demonstrates the need.

The exact remaining integration seams and their rationale are tracked in
[`case-boundary.md`](case-boundary.md).

## Capability status versus case status

Framework implementation work is recorded here. Investigation progress,
firmware-specific blockers, addresses, hashes, and behavioral conclusions are
recorded under the applicable case—for example
[`cases/performing-rigs/status.md`](../cases/performing-rigs/status.md).
