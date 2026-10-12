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

## Current limitations

- Cortex-M exception delivery and peripherals are modeled only through narrow,
  explicit harness mechanisms; APTrace is not a general MCU simulator.
- Function and CFG discovery remain heuristic and require cross-checking when a
  boundary is material to a conclusion.
- Symbolic execution works best for targeted, already-understood regions; whole
  firmware replay is neither its purpose nor a supported workflow.
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
