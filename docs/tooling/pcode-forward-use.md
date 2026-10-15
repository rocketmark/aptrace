# P-code Forward Use

APTrace's first static-dataflow operation built on Ghidra p-code. It answers:

> Given a value defined by one instruction, where can it flow inside the
> containing function, and does it escape?

Ghidra supplies the instruction semantics (SLEIGH p-code) and the calling
convention (the program's compiler spec). APTrace supplies the walk, the
completeness rules, the verdict policy and the evidence record. No part of
the implementation names an instruction set, register or mnemonic; a static
check in the tests enforces this.

The decision behind it is in
[`../spikes/architecture-evaluation.md`](../spikes/architecture-evaluation.md).
The plan for retiring the Capstone-based dataflow modules is in
[`pcode-migration.md`](pcode-migration.md).

## Components

| Layer | File | Role |
|---|---|---|
| Walker | [`tools/ghidra/scripts/APTracePcodeForwardUse.java`](../../tools/ghidra/scripts/APTracePcodeForwardUse.java) | Ghidra headless script. Walks raw p-code and reports uses, kills, derivation steps and incompleteness reasons. Implements no verdict policy. |
| Driver | [`tools/ghidra/pcode_forward_use.py`](../../tools/ghidra/pcode_forward_use.py) | Binds an explicit target, isolates the project in a scratch workspace, runs Ghidra once for a batch of origins, checks the engine's identity against the target, and applies the verdict policy. Stdlib only; imports no case. |
| Headless locator | [`tools/ghidra/headless.py`](../../tools/ghidra/headless.py) | Finds `analyzeHeadless` and its version. Shared with `aptrace_ghidra.py`. |
| Agent operation | [`agent/src/aptrace_agent/value_forward_use.py`](../../agent/src/aptrace_agent/value_forward_use.py) | `value_forward_use(origin[, register])`: typed result, ledger provenance, planner summary. |
| Acceptance controls | [`tools/ghidra/test_pcode_forward_use.py`](../../tools/ghidra/test_pcode_forward_use.py), [`tools/ghidra/fixtures/pcode_forward_use/`](../../tools/ghidra/fixtures/pcode_forward_use/) | The spike's 11 Thumb and 7 RV32 controls plus added negative controls, with exact expectations in `controls.json`. |

An application binds the operation to a target. The Performing Rigs wiring
(`structural_wiring.performing_rigs_value_forward_use`) reads the case
project's cache identity (`meta.json`: language, compiler spec, load base,
firmware hash) and refuses a stale project.

## Planner exposure (temporarily restricted)

`value_forward_use` is implemented and usable: through the executor, ledger
operations and replay, and by scripted controllers. Autonomous selection of
its planner action, `trace_value_use`, is **off by default**. In live
trials the local planner chose the tool correctly, but admission accepted
untyped claims that merged two traces into false value-flow statements.
Admission does not check value-flow assertions against these results yet
(see the case's `pcode-forward-use-v1` note, §5).

- It is listed in `EXPERIMENTAL_STRUCTURAL_TOOLS`
  (`research/controller.py`). A controller offers an experimental tool only
  when it is named in both `structural_tools` and `experimental_tools`.
  Naming it in `structural_tools` alone is a `ValueError`.
- Without opt-in, the action is not offered, a planner call to it is
  rejected as an unexpected tool, and open leads that would run the
  operation are not offered for following or fallback.
- Explicit experimental use: `aptrace-agent research --experimental-tool
  value_forward_use …`, or `run_autonomous_investigation(...,
  experimental_tools=("value_forward_use",))`. Use a scratch ledger.

Remove the restriction once deterministic value-flow claim admission is
implemented and validated against these trials.

## Target and request

The driver takes the target explicitly:

- image path and expected sha256;
- Ghidra language id and compiler-spec id;
- load base;
- **project mode**: an analyzed Ghidra project (directory, name, program) and
  an opaque identity string the caller records; or
- **import mode** (fixtures): a raw import with no auto-analysis, plus the
  function entries (optionally with explicit bodies) and code seeds to
  disassemble. These are harness assumptions and are recorded in the result.

Origins are instruction addresses. By default the tracked location is the
single pointer-sized register the instruction writes, excluding the program
counter and the stack pointer. If the instruction writes none, or several
(for example a two-register load), the result is UNSUPPORTED unless the
request names the register.

Bounds: a step budget (default 20,000 instruction visits, at most 200,000),
at most 256 origins per invocation, and a 300 s timeout.

## The walk

- The state at an instruction is the set of storage locations (registers
  and instruction-local temporaries) that may hold the value.
- Within an instruction, p-code is interpreted op by op. An internal
  conditional branch forks the state. A write predicated by SLEIGH
  therefore kills a copy only on the path that executes it.
- Across instructions it is a monotone may-dataflow to a fixpoint over the
  containing function. Gen/kill is distributive, so this equals the union
  over paths. A second pass over the fixpoint states records uses, kills and
  derivation steps.
- A write kills a copy only if it covers the whole location. A partial
  write keeps it.
- The value propagates through every data operation except predicates.
  Comparisons and boolean operations consume it: one bit flows, and the use
  is local. A `LOAD` through the value is a dereference, and the loaded
  value is not the tracked value.
- Calls follow the default prototype model of the compiler spec. Live
  argument storage at a call is an `ARGUMENT` use. Registers outside the
  unaffected list are then killed.
- A transfer to another function's entry is a tail call: argument storage
  is checked, and the path ends.
- A call to a function Ghidra marks no-return ends the path. Computed-jump
  targets come from Ghidra's flow references. Both are recorded as
  assumptions when used.

Raw p-code is read without flow overrides (`Instruction.getPcode(false)`).
The value's image-time content is reported when the defining p-code reads a
constant address. Ghidra's language rule normalizes it to a code address
(`PseudoDisassembler.getNormalizedDisassemblyAddress`), which handles the
Thumb bit with no APTrace code.

## Uses and verdict

| Walker use | Escape kind | Meaning |
|---|---|---|
| `CONTROL_TRANSFER` | `CONTROL_FLOW_ESCAPE` | target of an indirect call, indirect branch or return |
| `ARGUMENT` | `ARGUMENT_ESCAPE` | live in argument storage at a call or tail transfer |
| `STORE` | `MEMORY_ESCAPE` | stored to memory (the store target is classified as stack, absolute or computed) |
| `RETURN_VALUE` | `RETURN_ESCAPE` | live in return storage at a return |
| `COMPARE`, `DEREFERENCE_LOAD`, `DEREFERENCE_STORE`, `DEAD`, `ENDS_AT_RETURN`, `TAIL_TRANSFER`, `UNMODELED` | — | local, or the value ends |

The verdict policy belongs to the driver:

| Verdict | When |
|---|---|
| `ESCAPE` | Some escaping use was found. It stands even if the analysis is incomplete; then `complete` is false and other escapes may exist. |
| `NO_ESCAPE_WITHIN_SCOPE` | No escaping use **and** the analysis is complete. |
| `INCOMPLETE` | No escaping use was found, but some path was not analyzed. |
| `UNSUPPORTED` | The origin cannot be analyzed as asked, or Ghidra is unavailable (`ENGINE_UNAVAILABLE`). |

An unknown walker use kind is an error, not an ignored use.

### Incompleteness codes

Each code is reported with an address and detail. None of them can produce
`NO_ESCAPE_WITHIN_SCOPE`.

| Code | Cause |
|---|---|
| `NO_CONTAINING_FUNCTION` | The origin is in no Ghidra function. The walk still runs, without a body, and any escape it finds is still reported. |
| `FLOW_LEAVES_FUNCTION` | While the value may be live, flow reaches an address outside the body that is not a function entry. This is a possible boundary gap. |
| `COMPUTED_FLOW_UNRESOLVED` | A computed jump has no known targets while the value may be live. |
| `UNMODELED_OPERATION` | The value reaches a user-defined p-code op (`CALLOTHER`). |
| `NO_INSTRUCTION` | Flow reaches undecoded bytes. |
| `DELAY_SLOT_UNSUPPORTED` | The instruction has a delay slot. Delay-slot ISAs are not supported yet. |
| `BUDGET_EXHAUSTED` | The step budget ran out. |
| `PCODE_PATH_BOUND`, `PCODE_BRANCH_OUT_OF_RANGE` | Pathological instruction p-code. |

### Precision labels

These do not make a result incomplete. They disclose over-approximation.

- `MEMORY_FLOW_NOT_FOLLOWED`: a stored value is not tracked through memory.
  A stack spill that is reloaded and called is reported as
  `MEMORY_ESCAPE`, which is sound but imprecise. The decompiler resolves
  this case; raw p-code without a memory model does not.
- `ARGUMENT_BY_STORAGE`: `ARGUMENT` means the value may be in argument
  storage. It does not mean the callee reads it.

## Evidence identity

The ledger operation `value_forward_use` is a new operation identity (analysis
version 1). It never substitutes for `indirect_call_target` or
`callback_argument_provenance` results.

**Input artifacts.** The ledger records these:

- `ghidra_cache_identity`: the project's `meta.json`, which covers the
  firmware, language, cspec, base, Ghidra version and build scripts;
- `pcode_forward_use_walker`;
- `pcode_forward_use_driver`;
- `ghidra_headless_locator`.

A change to any of them refuses historical reuse.

**Result provenance.** The result carries:

- Ghidra version, language id and version, compiler-spec id, calling
  convention name;
- argument, return and unaffected storage, pointer size, and the
  low-bit code mode;
- program sha256, image base and memory blocks with permissions;
- walker and driver sha256, walker name and version;
- target description and bounds.

**Determinism.** Two runs give byte-identical results, and replay matches.
Wall time, peak RSS and in-script analysis time are reported separately as
the measurement. They are never part of the result.

**Grades.** These are deterministic and do not change any existing tool:

| Result | Grade |
|---|---|
| complete `NO_ESCAPE_WITHIN_SCOPE` | `BOUNDED` (supports only claims of the same scope) |
| `ESCAPE` | `PROBABLE` (a may-flow, not a demonstrated dispatch) |
| anything else | `UNKNOWN` |

**Limitation codes.** `FUNCTION_BOUNDARIES_HEURISTIC`,
`INTRAPROCEDURAL_DERIVATION_ONLY`, `CALLING_CONVENTION_MODEL`,
`NO_ESCAPE_IS_WITHIN_FUNCTION_SCOPE`, `MEMORY_FLOW_NOT_FOLLOWED` and
`FORWARD_USE_INCOMPLETE`.

## Hosting

The operation runs as a headless Ghidra script:

- one `analyzeHeadless` invocation per request;
- in project mode, a scratch copy of the project opened `-noanalysis -readOnly`;
- in import mode, `-deleteProject`.

The source project is never opened, locked or written. The tests check that
its files are byte-identical afterward.

Measured on the development machine (Ghidra 12.1.3, JDK 21, Apple silicon):

| Invocation | Wall | Peak RSS | In-script analysis |
|---|---|---|---|
| 11 Thumb controls (import) | 3.0–3.5 s | 380–400 MB | 11 ms |
| 7 RV32 controls (import) | 2.1–2.6 s | 250–400 MB | — |
| one origin, 2.4 MB analyzed project (copy + open) | 2.4–2.9 s | 350 MB | ms |
| 95 origins, same project, one invocation | 2.4 s | 330–360 MB | ms |

JVM start-up, script compilation and project open account for nearly all of
the cost. Batching makes additional origins almost free. The driver already
accepts up to 256 origins, but the agent operation sends one origin per
invocation, so that each origin has its own ledger identity.

At planner scale (a few traces per session) this is acceptable. A persistent
Ghidra process (PyGhidra or a long-lived headless server) becomes worthwhile
only for bulk use, for example re-deriving every census site per build. That
should be decided with the first bulk consumer (see
[`pcode-migration.md`](pcode-migration.md)), not built speculatively.

## Not established

- Real non-ARM firmware. RV32 coverage is synthetic fixtures only.
- Flow through memory (no alias model), interprocedural flow, and
  delay-slot ISAs.
- How it behaves on a project whose function boundaries came from different
  auto-analysis settings. At base 0 the Cortex analyzer creates functions
  inside one fixture: C1 then becomes a tail-transfer `ESCAPE`, never a
  silent negative. The test suite checks this property.
