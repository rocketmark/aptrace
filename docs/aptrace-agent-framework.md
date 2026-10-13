# APTrace Agent Framework Roadmap

This roadmap redirects the APTrace agent from question-driven autonomous
research toward a Galois-first, whole-binary behavioral map that local models
label and that later investigation tools query. It records the plan and its
exit criteria; implemented capability status stays in [`status.md`](status.md).

> **Recalibration (Agent v0).** The whole-binary map is no longer a
> prerequisite for useful research. The autonomous controller is un-parked as
> Agent v0: it uses the targeted capabilities that exist now (census
> subsystem analysis, call-graph common paths, a USB structural inventory,
> and on-demand function effects from the Phase 2 spike) behind a bounded
> planner projection. The phases below remain the plan for broader coverage;
> each is pursued when agent use shows it is needed, not as a gate.

## Jobs to be done

1. **Map the full binary.** Every function and flash range is accounted for,
   with a machine-derived description of what each function does: memory and
   MMIO it reads and writes, calls, return behavior, and possible faults.
2. **Research the mapped binary.** Answer questions about bugs, test
   harnesses, hardware dependencies, and behavior by querying the map and
   running targeted concrete or symbolic checks.
3. **Patch.** Modify the binary and verify that the change affects only the
   intended behavior.

Job 1 must be complete and trustworthy before job 2 is built on it. Job 3 is
out of scope for this roadmap beyond tool evaluation.

## Design principles

- **Coverage, not curiosity, drives job 1.** The map is built by a
  deterministic, resumable batch pipeline with a measurable definition of done.
  It is not an autonomous agent exploring from a seed.
- **Galois tools produce the facts.** Macaw provides discovery and lifting
  with ASL-derived instruction semantics; macaw-symbolic, Crucible, and What4
  provide function effect summaries and solver-backed resolution. Ghidra
  becomes an optional second source and human viewing surface, not the
  critical path *for building the map*. Promoting a claim is different: a
  claim class that requires cross-engine corroboration
  ([`cross-engine-verification.md`](cross-engine-verification.md)) needs an
  independent second engine, so "Ghidra optional" means the map can be built
  without it, not that corroboration can be skipped.
- **Local models label; they do not establish facts.** Qwen and Gemma, served
  locally through an OpenAI-compatible endpoint such as oMLX, perform bounded,
  schema-constrained, per-function tasks over machine-derived evidence. Frontier
  models are reserved for a small, explicitly escalated slice.
- **Every record carries status and provenance.** Summaries are `complete`,
  `bounded`, or `failed(reason)`; labels record model, prompt hash, and
  evidence. Nothing is silently dropped.
- **The framework/case boundary holds.** All pipeline code is framework code.
  Cases supply geometry, known RAM roles, and other configuration, and own
  their generated maps.

## Starting point

| Component | Current state | Direction |
|---|---|---|
| Census database and query CLI (`tools/census/`) | Mature; about 30 query commands | Remains the map store; its queries become the job 2 tool surface |
| Macaw census (`APTrace.MacawCensus`) | Standalone JSON; compared with Ghidra but never ingested | Promote to a primary census producer |
| Census build | Fed from Ghidra exports | Make Ghidra optional and source-tagged |
| `APTrace.SymbolicRunner` | Single-block branch reachability | Grow into whole-function effect summaries |
| Agent executor (`agent/`) | Wired to one case's Ghidra index and evidence | Refactor to query the census database case-neutrally |
| Autonomous research controller, leads, reconciliation (`agent/`) | Built ahead of a map to operate on | Parked; resumes in job 2 over map-derived leads |
| Semantic packets and rule-based classification | Packet export is framework; classification is case-specific | Basis for the local-model labeling pass |

## Phases

### Phase 0 — Freeze and triage

Stop feature work on the autonomous controller. Keep the code; mark which
parts are reused in later phases.

*Exit:* this roadmap is agreed and the controller is documented as parked.

### Phase 1 — Macaw as a primary census source

- Ingest `aptrace macaw-census` output into the census database, with a source
  column on functions, blocks, and edges (`macaw`, `ghidra`).
- Add a **coverage ledger** classifying every flash range as code, data,
  padding, or unknown, with its source.
- Record unresolved indirect transfers and Macaw/Ghidra disagreements as
  ledger discrepancy records
  ([`cross-engine-verification.md`](cross-engine-verification.md)); a work
  item may reference a discrepancy to schedule its investigation but is never
  where it is recorded. Use macaw-refinement with What4/Z3 to resolve
  indirect transfers where possible.
- Add an `aptrace_census.py coverage` report.

*Exit:* a case census builds with Ghidra disabled, and the coverage report
states the remaining gaps.

### Phase 2 — Function effect summaries

This is the principal new capability and the main technical risk.

- Add an `APTrace.FunctionSummary` module and an `aptrace summarize` command.
- Build each function's CFG with macaw-symbolic and simulate it with Crucible:
  - model MMIO reads as fresh symbolic values;
  - instrument the memory model to log each load and store with its address
    term, width, and path condition;
  - apply callee summaries at call sites, or an explicit, flagged havoc of
    callee effects when no summary exists;
  - bound loops and record when a bound is hit.
- Emit one JSON record per function: reads, writes, calls, return expression,
  reachable faults or assertion failures, and status.
- Process functions leaves-first in call-graph order.

*Exit:*

1. **Spike:** summaries for the reference function and caller in a case
   regression benchmark reproduce that benchmark's independently established
   findings (for the current case, see
   [`agent/benchmarks/trigger-role.md`](../agent/benchmarks/trigger-role.md)).
2. **Batch:** every discovered function has a summary record, with a report of
   the `complete` / `bounded` / `failed` distribution and failure reasons.

The spike runs in parallel with Phase 1 so that the viability of the approach
is known before the rest of the pipeline is built.

### Phase 3 — Whole-program facts

- Ingest summaries into a `function_effects` table.
- Derive, as census queries with provenance and evidence level:
  - the peripheral dependency graph;
  - globals shared between interrupt handlers and the main loop;
  - reachability from reset and each interrupt handler;
  - dead code.

*Exit:* each derived fact is available as a census query and reports the
summary statuses it depends on.

### Phase 4 — Local-model labeling (completes job 1)

- Extend semantic packets to include each function's effect summary.
- Qwen fills a strict label schema (name, description, subsystem, hardware
  touched, confidence, evidence references) through pydantic-ai against the
  local endpoint.
- A deterministic validator rejects any label citing an address, register,
  or callee absent from the packet.
- Gemma labels independently; disagreements go to a review queue for a human
  or an escalated frontier model. Labels are candidate discoveries: agreement
  between models is not engine corroboration and never satisfies a
  verification policy.
- Store model, prompt hash, and label so the map can be regenerated when
  models change.
- Produce subsystem rollups and a map report.

*Exit — job 1 definition of done:*

- 100% of flash classified in the coverage ledger;
- every function either labeled or explicitly queued as unknown;
- every tool or model disagreement resolved or documented.

### Phase 5 — Job 2 tool surface

- Expose census queries, summary lookup, targeted What4 queries, and Unicorn
  concrete confirmation through an MCP server.
- Refactor the agent executor to use the census database instead of a
  case-specific Ghidra index.
- Place chat front ends and the parked research controller on top of this
  surface; the controller chooses among leads derived from the map.
- Evaluate GREASE (Galois under-constrained symbolic execution for binaries)
  for bug finding.

*Exit:* a job 2 question can be answered from the map and targeted checks
without case-specific wiring in the agent.

## Job 3 candidates

Evaluate before committing: Renovate for binary rewriting and PATE for
verifying that a patched binary is trace-equivalent to the original outside the
intended change. Thumb/Cortex-M support in both is unverified.

## Risks and open questions

- **Summary scalability.** Path explosion, loops, indirect calls, and memory
  modeling will leave some functions `bounded` or `failed`. The ledger must
  make these visible rather than hide them.
- **Model input quality.** Without Ghidra decompilation, local models read
  summaries plus disassembly. This favors accuracy but may reduce labeling
  fluency; measure it in Phase 4.
- **Chat front end.** Whether oMLX's chat interface can call MCP tools is
  unverified. If not, oMLX remains the model server and an MCP-capable client
  provides the chat.
- **Documentation drift.** [`tooling/tool-selection.md`](tooling/tool-selection.md)
  names Ghidra as the primary static tool; update it when Phase 1 lands.
