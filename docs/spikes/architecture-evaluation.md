# Spike: Firmware-Analysis Architecture Evaluation

**Question.** Is APTrace using its analysis engines for the problems they
solve best? Is it re-growing a program-analysis engine in Python? What
should own which analysis as APTrace moves beyond one Cortex-M case?

**Verdict: PARTIAL.** There is a direction and a pilot to test it (§7, §9).
The parts not established are listed in §10.

**Decision: B.** Move instruction-level and intraprocedural dataflow onto
**Ghidra p-code**, behind a narrow APTrace adapter. Keep Python for
interpretation, policy and evidence. Keep Macaw for independent discovery
and as Crucible's front end, Crucible for bounded symbolic questions, and
Unicorn for concrete observation. Stop adding Capstone-operand semantics
to `tools/census/`.

Experiments and raw results: [`architecture-evaluation/experiments/`](architecture-evaluation/experiments/).
Case-side results (firmware addresses, hashes):
[`cases/performing-rigs/research/architecture-eval-v1.md`](../../cases/performing-rigs/research/architecture-eval-v1.md).
Branch `spike/architecture-evaluation`; nothing is committed.

---

## 1. Current state: who does what today

| Analysis | Documented owner | Actual owner (code) |
|---|---|---|
| Disassembly, function and block boundaries, refs | Ghidra | Ghidra (`APTraceExportCensus.java` → census tables), cross-checked by a Capstone sweep (`capstone_sweep.py`) |
| Instruction semantics for dataflow | — (unstated) | **Python over Capstone ARM operands**: `indirect_target.py`, `callback_provenance.py`, `fnptr_resolve.py`, `indexed_writes.py`, `interproc_writes.py`, `slot_dispatch.py`, `indirect_resolve.py`. About 2,800 lines with 106 direct `ARM_INS_/ARM_OP_/ARM_REG_/ARM_CC_`/mnemonic references. 1,375 of those lines were added in the last two milestones. |
| Reaching definitions, value propagation, stack arguments, IT predication, call clobbers | — | The same Python, over Ghidra's blocks re-decoded by Capstone (`indirect_target._reaching`, `_definition`, `_stack_argument`) |
| Calling convention | — | Hard-coded AAPCS sets (`ARG_REGS`, `CALL_CLOBBERED`) in several modules |
| Independent CFG discovery | Macaw | Macaw plus APTrace's `MacawNormalize`/`MacawExpand` classify-failure repair |
| Symbolic function effects | Crucible/What4/Z3 | `EffectsSpike.hs` over **upstream** Macaw discovery. It does not use `MacawExpand` (see §4.4). |
| Concrete execution | Unicorn | Unicorn (`tools/unicorn/concrete.py`), `UC_ARCH_ARM`/`UC_MODE_THUMB\|MCLASS` hard-coded |
| Ghidra p-code / decompiler SSA | — | **Unused** for analysis. The decompiler is used only to show C text (`APTraceDecompileFunctions.java`). |
| Evidence, replay, claims, admission, continuity | APTrace | APTrace (`agent/src/aptrace_agent/ledger/`, `research/`). Engine-neutral envelope. |

The documented four-engine model ([`tooling/tool-selection.md`](../tooling/tool-selection.md))
no longer matches the implementation. A fifth analysis engine, Python
dataflow over Capstone, now answers the dataflow questions. It is not in
the tool-selection table.

## 2. Architectural coupling

| Component | Class | Where it sits | Assessment |
|---|---|---|---|
| Ledger, evidence envelope, replay, claim admission, continuity, follow-ups | device-independent | root | correct |
| Census schema, ingestion, reachability, reduction | device-independent | root | correct |
| Census dataflow modules listed above | **architecture-dependent** (ARM/Thumb, AAPCS) | root, presented as generic | No ISA boundary. Each module is ARM-only. |
| `APTraceExportCensus.java` | mostly ISA-neutral; access width from Thumb mnemonics | root | Width should come from p-code `LOAD`/`STORE` sizes. |
| `aptrace_ghidra.py` | `PROCESSOR = "ARM:LE:32:Cortex"`; imports `FIRMWARE_REGISTRY` and geometry from the case at import time | root | Language, cspec and seed recipe belong to the target configuration. |
| `APTraceSeedVectorTable.java`, `raw_scan.py`, `FirmwareLoader.armCortexMInfo`, `macawCortexMEntry` | platform-dependent (ARMv7-M vector table, Thumb bit) | root | Fine as platform recipes, but they are hard-wired, not selected by target. |
| `concrete.py`, `call_observation.py` | architecture-dependent (ARM Unicorn, r0-r3) | root | Fine; the architecture needs to be a parameter. |
| `EffectsSpike.hs`, `SymbolicRunner.hs` | architecture-dependent (`macaw-aarch32-symbolic`, r0-r3) | root | Fine; inherent. |
| `agent/.../executor.py`, `census.py`, `disassembly.py`, `ghidra_index.py`, `ledger_wiring.py`, `structural_wiring.py` | **case-specific wiring inside the framework agent** (`autopilot_ghidra_index()`, `performing_rigs_census`, ATSAMD51 SVD path) | root | Avoidable. 34 framework files name the case. |
| `aptrace.cabal` library includes `cases/performing-rigs/src` | case-specific inside the framework library | root | Recorded seam ([`case-boundary.md`](../case-boundary.md)) |
| `cases/performing-rigs/config/svd/resolve_mmio.py` | **platform-generic SVD lookup** (stdlib XML) | case | Inverted: a reusable mechanism lives in the case. Only the SVD file is case data. |
| Controller tool prose ("blx/bx register", "rN") | architecture-dependent text | root | Minor, but the planner is told an ISA. |

The [`case-boundary.md`](../case-boundary.md) seams are real and recorded.
The new finding is a different kind of coupling. The analysis core is
**ISA-coupled**, and nothing marks it as such. Supporting a second
architecture means rewriting the dataflow modules, not configuring them.

## 3. Engine evaluation

| | Ghidra raw p-code | Ghidra decompiler (HighFunction) | Macaw IR | Crucible/What4/Z3 | Unicorn | Python/Capstone |
|---|---|---|---|---|---|---|
| Semantics source | SLEIGH spec (vendor-maintained, 30+ ISAs here) | p-code + heuristics | ASL-derived (AArch32), plus PPC, x86, RISC-V packages | Macaw → Crucible | QEMU-derived | **APTrace, per ISA** |
| ABI knowledge | cspec (`PrototypeModel`): args, return, unaffected | cspec + inference | arch package; no AArch32 `RegisterUse` instance | from APTrace setup | none | **hard-coded** |
| Predication (Thumb IT) | internal p-code `CBRANCH` (generic) | resolved | value-level `mux` | exact | executed | needs decoder context (§4.3) |
| Discovery on this ISA | robust (census primary) | — | upstream fails on `cbz`/`cbnz`/`pop {pc}`; APTrace repairs part | inherits Macaw | n/a | inherits Ghidra blocks |
| Determinism | deterministic per Ghidra version and language | version- and memory-permission-sensitive heuristics | deterministic | deterministic per solver version | deterministic per harness | deterministic |
| Cost on this machine | 3.3–5.7 s JVM and project open per invocation, about 440 MB; **0–10 ms** per query | about 250–290 ms per function | 5.9 s, 1.3 GB (runghc driver, whole-reachable discovery) | 3.3 s, 406 MB (failed run) | < 1 s | < 1 s |
| Consumer language | Java/Jython script, or PyGhidra | same | Haskell (GADTs) | Haskell | Python | Python |
| Best use | instruction semantics, intraprocedural dataflow, refs, ABI | readable cross-check; spill/stack resolution | independent discovery and lifting; symbolic front end | bounded input and reachability questions | caller-grounded concrete observation | orchestration, interpretation, policy |

## 4. Grounded experiments

### 4.1 The question and the probes

Question: does a code pointer loaded from a literal flow into a control
transfer, store, argument or return value, or only a local check? The
real instance is the grounding case's open escape question, which leaves
17 callback target sets OPEN.

Probes, all disposable, under `experiments/`:

- [`ghidra/PointerUseProbe.java`](architecture-evaluation/experiments/ghidra/PointerUseProbe.java)
  (320 lines). It has two parts:
  - (a) a forward worklist over Ghidra's **raw p-code**, using instruction
    flows and the program's calling-convention model;
  - (b) the decompiler's `DecompilerUtils.getForwardSliceToPCodeOps`.

  It contains **no ISA-specific code**.
- [`python/capstone_forward_use.py`](architecture-evaluation/experiments/python/capstone_forward_use.py)
  (192 lines) is the same question in the current census style. It has 11
  marked ISA/ABI-specific sections. The first cut is kept as `capstone_forward_use_v1.py`.
- [`macaw/DumpBlocks.hs`](architecture-evaluation/experiments/macaw/DumpBlocks.hs)
  prints Macaw's discovered IR, after `MacawExpand`, for a function.
- [`python/unicorn_ea54.py`](architecture-evaluation/experiments/python/unicorn_ea54.py)
  is a single-path concrete check.
- Function effects: the production `aptrace function-effects` run on the
  real function.

### 4.2 Controls

[`fixtures/thumb_controls.s`](architecture-evaluation/experiments/fixtures/thumb_controls.s)
has 11 Thumb-2 cases, assembled with `clang -target thumbv7em-none-eabi`.
Expected results are in [`expected.json`](architecture-evaluation/experiments/fixtures/expected.json).
[`fixtures/rv32_controls.py`](architecture-evaluation/experiments/fixtures/rv32_controls.py)
has 7 hand-encoded RV32I cases, the same shapes as C1–C7.

| Case | Expected escape | Ghidra raw p-code | Decompiler slice | Capstone v1 | Capstone v2 | Macaw IR (inspected) |
|---|---|---|---|---|---|---|
| C1 compare only | none | ✓ | ✓ | ✓ | ✓ | ✓ |
| C2 guard + call through | transfer | ✓ (+ARGUMENT, sound over-approx.) | ✓ | ✓ | ✓ | call `_PC = _R3_0`; `cbz` classify failure |
| C3 store | store | ✓ | ✓ | ✓ | ✓ | — |
| C4 argument via move | argument | ✓ | ✓ | ✗ missed | ✓ | call terminal `_R1 = r274` ✓ |
| C5 return | return | ✓ | ✓ | ✗ missed | ✓ | — |
| C6 join hides store | store | ✓ | ✓ | ✗ missed | ✓ | — |
| C7 killed on both paths | none | ✓ | ✓ | ✓ | ✓ | — |
| C8 spill, reload, call | transfer | store (sound, imprecise) | **✓ CALLIND** | store | store | — |
| C9 IT-conditional kill | store | ✗, then ✓ after one *generic* fix | ✓ | ✗ missed | ✓ | `mux` → `write_mem` ✓ |
| C10 tail call with arg | argument | ✓ | escapes, but as `RETURN` (wrong kind) | ✓ | ✓ | — |
| C11 compare then loop | none | ✓ | ✓ | ✓ | ✓ | — |
| **RV32 R1–R7** (same script, `RISCV:LE:32:default`) | as C1–C7 | **7/7, no change** | 7/7 (C text) | needs a new ISA layer | needs a new ISA layer | not run |

Notes:

- **Ghidra raw p-code.** The one fix needed, a "conditional p-code write
  may not kill" rule, is ISA-neutral. Any SLEIGH predication lowers to an
  internal `CBRANCH`. Spurious `COMPARE` uses appear from flag and
  interworking bookkeeping (`blx` Thumb-bit test, flags after a predicated
  `mov`). They never affect the escape decision.
- **Capstone v1 → v2** took three ISA-specific fixes:
  - Capstone's `regs_access()` omits the implicit ABI reads of `bl` and
    `bx lr`;
  - matching the mnemonic `b` missed `beq`;
  - **decoding one Thumb address in isolation loses IT state**. A
    predicated `moveq` decodes as an unconditional move.

  The production census avoids the third by block-sequential decoding
  (`indexed_writes._decode_block`). It is still a hazard every
  Capstone-based module must remember.
- **Decompiler.** It resolves the stack spill (C8), which a raw-p-code
  walker would need a stack model for. But it renders the C10 tail call as
  a return. On the real image its slice holds 24 memory-SSA ops
  (`INDIRECT`/`MULTIEQUAL`) besides the 2 real uses. Flash was imported
  writable, so the decompiler models the literal as a mutable global. It
  is useful, but heuristic and configuration-sensitive.
- **Fixture default.** With base 0, Ghidra's Cortex language labels the
  vector-table words (`MasterStackPointer`, …) and the decompiler shows
  them in comparisons. This is a reminder that language defaults are
  target assumptions.

### 4.3 Real-firmware result (details in the case note)

All static methods agree. The loaded pointer is used only by the presence
test and is overwritten on both successors:

- Ghidra raw p-code (complete);
- the decompiler slice;
- Capstone v2;
- Macaw IR after `MacawExpand`.

A concrete single-path run agrees. Two same-function loads are correctly
reported as `ARGUMENT`. That is a positive control in the real image.

Scaled to every flash code-pointer load in the image, 8 loads in one
invocation:

- 3 ARGUMENT, 3 STORE, 1 compare-only, 1 INCOMPLETE;
- about 10 ms of analysis inside about 4.4 s of Ghidra start-up.

**A defect the scale run exposed.** For a definition outside any Ghidra
function, the first probe returned "complete, no uses". That answer is
misleading. The fixed probe reports INCOMPLETE. Lesson: whatever
engine owns the dataflow, missing function attribution must surface as
incompleteness. That is an APTrace adapter responsibility, not an engine
one.

### 4.4 Macaw, Crucible, Unicorn on the same question

**Macaw.** Its IR is semantically the most exact:

- typed SSA per block;
- predication as `mux`;
- call terminals carry the full register map, so arguments are explicit;
- the abstract state refines `_R3 ∈ {0}` on the not-taken edge.

But:

- **Upstream AArch32 discovery recovers 1 block** of the real function. It
  stops at the first `cbz` ("IP is not a mux"). With APTrace's
  `MacawExpand` it recovers 66 blocks in 10 rounds with 47 resolutions.
  `pop {…,pc}` returns also fail classification in the fixtures.
- macaw-aarch32 has no instance of Macaw's `RegisterUse`/`FunctionArgs`
  analyses, so a dataflow analysis over Macaw IR would be new Haskell over
  GADTs plus APTrace's repair layer.
- The run costs 1.3 GB.

Macaw is right as the **independent** engine. It is the wrong foundation
for APTrace's day-to-day dataflow.

**Crucible.** The production `function-effects` on the real function returns
`failed: all paths aborted` after **1 Macaw block** and 12 steps. It
uses upstream discovery without `MacawExpand`. That is a real, previously
unreported limitation (status.md names only `tbb`/`tbh`). "Does this value
reach any store, argument or return on any path" is an all-uses dataflow
question. Symbolic execution answers it only on explored paths,
records write addresses but not values, and explodes on loops. Its role
should stay the bounded input/reachability questions it already serves.

**Unicorn.** It confirms one path under harness state. It cannot
establish an absence, and it should not be asked to.

## 5. Portability: a RISC-V target

Thought experiment: a GD32VF103-class RV32IMAC part. It has:

- raw `.bin` at `0x08000000`;
- ECLIC interrupts;
- a `j` instruction at the reset entry, not a vector table of pointers;
- no Thumb bit;
- the RISC-V psABI (`a0`–`a7`, `ra`).

The RV32 fixtures stand in for real firmware.

| Layer | Today | Needed | Kind |
|---|---|---|---|
| Load / memory map | Ghidra `BinaryLoader` works; `aptrace_ghidra.py` hard-codes `ARM:LE:32:Cortex` and the case registry | language, cspec and base from target config | **avoidable coupling** (config) |
| Function seeding | `APTraceSeedVectorTable.java` (ARMv7-M table, Thumb bit) | a RISC-V/ECLIC seed recipe | inherent platform recipe |
| Decoding / CFG | Ghidra: language switch only. Capstone sweep: `CS_MODE_THUMB`. | Ghidra unchanged; sweep re-moded | config / small |
| Calling convention | hard-coded AAPCS in each census module | from cspec (Ghidra) | **avoidable**, if moved to p-code |
| Static dataflow | ~2,800 lines of Capstone-ARM semantics | **rewrite per ISA**; the p-code probe ran unchanged (7/7) | **the decision point** |
| Pointer canonicalization | Thumb-bit logic (`fnptr_resolve.canonical_code_pointer`) | target pointer-tagging rule | platform config |
| Macaw / Crucible | `armCortexMInfo`, `macaw-aarch32-symbolic` | `macaw-riscv(-symbolic)` exist upstream; new FirmwareLoader arch info and repair validation | inherent; real work |
| Unicorn | `UC_ARCH_ARM`, Thumb-M mode, r0–r3 | `UC_ARCH_RISCV`, ABI registers | architecture parameter |
| Interrupts / peripherals | ARM vector delivery; SVD lookup lives in the case, hard-wired to ATSAMD51 | ECLIC model; generic SVD lookup | platform recipe; move the SVD mechanism to root |
| Evidence / ledger / claims | engine-neutral envelope | unchanged; entity regexes (`FUN_`, peripheral names) still fit | works |
| Controller | operations wired per tool in about 12 agent files; prose names ARM instructions | descriptors with prerequisites (architecture, inputs) | avoidable |

Most cost on a second ISA would land in the census dataflow modules.
Moving those onto p-code removes it. Seeding, interrupt and peripheral
models, and Macaw/Unicorn architecture parameters are inherent and
config-sized.

## 6. Architectural risks

1. **A second analysis engine in Python.** Reaching definitions, IT
   predication, stack-argument offsets, literal pools, `movw/movt`, call
   clobbers and conditional target sets are now hand-written over ARM
   operands. Each new question extends it, and each ISA multiplies it. The
   v1 prototype missed 4 of 11 controls and both real-image argument
   controls before three fixes. That error rate is inherent to owning
   instruction semantics.
2. **Two decoders on one CFG.** Census blocks come from Ghidra, and
   semantics come from Capstone re-decoding the same bytes. Disagreements,
   such as IT state, block-boundary assumptions and Thumb vs A32, are
   silent unless someone cross-checks.
3. **Opaque failure.** A missing function attribution produced "complete,
   no uses" in the probe. The same risk exists in the census modules,
   which use Ghidra body attribution (`indirect_target` limitations
   already note this).
4. **Production symbolic path diverges from repaired discovery.**
   `function_effects` runs on unrepaired Macaw, so any function with an
   early `cbz` fails.
5. **Integration cost per operation.** Callback provenance touched 12
   agent modules: controller, semantics, operations, executor, wiring,
   projection, fact derivation, history, call relations… There is no
   operation descriptor, so prerequisites, limitations and offer
   conditions are imperative code.
6. **Case wiring in the framework agent.** `executor.py` constructs the
   AutoPilot Ghidra index and disassembler directly. A second case cannot
   run without editing framework code.
7. **Decompiler output is configuration-sensitive.** Writable flash
   produces memory-SSA noise. If the decompiler is ever used as evidence,
   memory permissions must be part of target configuration and evidence
   identity.

## 7. Recommended architecture

### Ownership

| Responsibility | Owner | Notes |
|---|---|---|
| Instruction semantics | **SLEIGH via Ghidra** (primary). Macaw/ASL as the independent second semantics. | APTrace owns none. |
| Control-flow recovery | Ghidra (primary), Macaw plus APTrace repair (independent) | unchanged; compare both, never merge silently |
| Intraprocedural dataflow (reaching definitions, forward use, constants, stack slots) | **Ghidra raw p-code**, through one APTrace-owned generic p-code walker library (Java/PyGhidra) | p-code is ISA-neutral; ABI from cspec |
| Interprocedural composition (one-hop caller provenance, call-site enumeration) | APTrace Python **policy** over Ghidra xrefs and per-site p-code derivations | CLOSED/OPEN rules and scope stay APTrace's |
| Indirect target resolution | shape classification and candidate policy in APTrace; definitions from p-code | `indirect_target` keeps its output schema |
| Symbolic reasoning | Crucible/What4/Z3 over Macaw (repaired discovery) | bounded input and reachability only |
| Concrete execution | Unicorn | architecture as a parameter |
| Hardware interpretation | APTrace, from target configuration (SVD, memory map, seeding recipe) | generic SVD lookup moved to root |
| Evidence normalization, cross-engine comparison, verification | APTrace | unchanged in kind |

The decompiler is a cross-check and stack-resolution aid. It is not
primary evidence.

### Why B and not the alternatives

- **A (keep Python/Capstone).** It is cheap and fast today and correct
  after fixes. But it grows linearly with questions × ISAs, and it
  duplicates semantics Ghidra already computes from the same bytes.
- **C (Macaw).** It has the most exact IR. But upstream ARM discovery
  needs APTrace repair, the needed analyses are missing for AArch32, it is
  Haskell-only, and it uses about 3× the memory. Macaw's value to APTrace
  is **independence**. Making it the primary dataflow engine would spend
  that independence.
- **D (a generic "hybrid").** Rejected as a label. The ownership above
  gives each analysis class one engine, plus an independent cross-check.
- **E (defer).** Not needed for direction. The remaining uncertainty is
  operational: whether p-code dataflow keeps parity on the existing
  harder shapes (stack arguments, vtables, jump tables). The pilot and
  migration step 3 test exactly that.

### Trade-offs

| Factor | Effect |
|---|---|
| Correctness | p-code inherits SLEIGH semantics for all instructions, including ones the Python never modeled. APTrace still owns the walker's soundness rules, such as conditional writes and the incompleteness rules. |
| Architectures | every Ghidra language (30+ installed) vs one |
| Maintenance | one generic walker vs N ISA-specific modules. Java/PyGhidra skill becomes required. |
| Deployment | Ghidra is already a hard dependency (census primary) |
| Resources | about 4 s of JVM/project start-up per invocation, about 440 MB. Mitigate by batching per operation or exporting per-function p-code once per census build. |
| Reproducibility | deterministic per Ghidra version, language and cspec. These must enter evidence identity, as the Ghidra cache identity already does. |
| Evidence transparency | p-code ops carry instruction addresses (SeqNum), so derivations stay instruction-level and auditable |
| Controller integration | unchanged operation surface; prerequisites become "language supported by Ghidra" |
| Extensibility | new questions become new walker clients, not new ISA semantics |

### Evidence normalization

No new universal IR is needed. Two additions are needed:

1. **Engine identity in the operation record.** Add engine, engine version,
   language/ISA id, ABI/cspec id, and analysis-script hash to
   `ExecutionContext`/`ToolInvocation`. Today they are implied only by
   input-artifact hashes of Python modules.
2. **A shared derivation-step record:**
   `{addr, instruction_text, op, effect, varnode/register}`. Both the
   p-code walker and the existing Python results already carry this
   (`def_addr`, `instruction`, `kind`). With it, `macaw_compare`-style
   deterministic comparison can run on dataflow results without either
   engine's native format.

Completeness becomes an explicit enum with reasons. Missing function
attribution, unresolved computed flow and bounds are separate reasons,
never "no result".

## 8. Migration strategy

Ordered; each step keeps current results and evidence identities:

0. **Target descriptor, configuration only.** Ghidra language and cspec,
   base and memory map with permissions, seed recipe, pointer-tagging rule,
   and SVD path. The case supplies it. `aptrace_ghidra.py` and
   `executor.py` receive it instead of importing case modules. Move the
   SVD lookup mechanism to root. *No analysis change.*
1. **Pilot (§9).** A p-code forward-use operation, plus engine-identity
   fields.
2. **Freeze Capstone dataflow.** No new semantics in `tools/census/`
   Capstone modules. Bug fixes only. Record this in tool-selection.md.
3. **Port the reaching-definitions core** (`indirect_target._reaching` /
   `_definition`) to the p-code walker as `indirect_target` v3, keeping
   the output schema. Run both on every census register-indirect site and
   record agreements and disagreements as deterministic comparison
   evidence. Retire the Capstone path only after a full-agreement run, or
   after every disagreement has been explained. Historical v1/v2 evidence
   is untouched: a new analysis version is a new operation identity.
4. **Re-base `callback_provenance` and `fnptr_resolve`** on the same walker.
5. **Point `function_effects` at repaired discovery** (`MacawExpand`).
   This is independent of steps 1–4.
6. **Operation descriptors.** Name, argument schema, prerequisites
   (architectures, required inputs), limitations and grade policy as
   data, to cut the 12-module wiring. Planner prompts unchanged until
   then.

## 9. First production pilot

**`pointer_forward_use(def_site)`.** Given an instruction that materializes
a value (a literal load first), it classifies every forward use within the
containing function:

- `CONTROL_TRANSFER`
- `STORE`
- `ARGUMENT`
- `RETURN_VALUE`
- `DEREFERENCE_*`
- `COMPARE`
- `DEAD`
- `INCOMPLETE(reason)`

It runs over Ghidra raw p-code, with ABI from the cspec.

Why this pilot rather than porting `indirect_target` first:

- It is small: one walker, no shape taxonomy.
- It has a real consumer: callback-provenance's address-taken entries,
  where it decides the grounding case's 17 OPEN sets.
- It exercises everything the decision depends on:
  - generic p-code semantics;
  - cspec ABI;
  - incompleteness;
  - engine identity in evidence;
  - comparison against an existing independent implementation.

The indirect-target port (step 3) is the larger follow-on milestone.

**Acceptance criteria (measurable):**

1. **Boundary.** The walker lives in `tools/ghidra/` with no case
   import. Language, cspec and memory map come from the target
   descriptor.
2. **Controls.**
   - 11/11 Thumb and 7/7 RV32 fixture escape decisions match
     `expected.json`.
   - Imprecise-but-sound answers (C8 stack store) are labeled as such.
   - Added negative controls must report INCOMPLETE, never NO_ESCAPE:
     - a definition outside a function;
     - an unresolved computed jump;
     - a bound hit.
3. **Real image.**
   - All census flash code-pointer loads are classified (8 on the
     grounding image).
   - Each is deterministically compared with the Capstone forward walker.
   - Every disagreement is recorded, none silently resolved.
4. **Evidence.**
   - It is a typed ledger operation recording firmware sha256, Ghidra
     version, language id, cspec id, walker hash and project identity.
   - Replay matches.
   - Two runs give byte-identical canonical results.
5. **Consumer.**
   - `callback_provenance` v2 may treat an address-taken load as
     non-escaping only on a complete NO_ESCAPE.
   - The change is a new analysis version.
   - Historical evidence is unchanged.
6. **Budget.** At most 10 s and 1 GB per invocation on the development
   machine.

**What the outcome teaches:**

- **Pass without ISA-specific branches in the walker.** B is confirmed.
  Proceed to step 3.
- **ISA-specific special cases needed in the walker.** p-code is not
  sufficiently neutral at this layer. Reconsider A, with a declared ISA
  plug-in boundary.
- **Disagreements with Capstone.** Each one either finds a bug in the
  existing Python or shows a p-code subtlety. Both outcomes are what
  cross-engine comparison is for.

## 10. Verdict: PARTIAL

**Established:**

- Engine roles as implemented, versus as documented.
- The ISA coupling of the census dataflow layer.
- A working, ISA-neutral p-code answer to the grounding question, that:
  - agrees with three other methods on real firmware;
  - is correct on 18 controls across two ISAs, after one generic fix.
- The upstream Macaw ARM discovery gap, and the production
  `function_effects` failure on the grounding function.
- The case-wiring sites inside the framework agent.
- A concrete migration path and pilot.

**Not established:**

- Whether p-code dataflow matches the existing modules on the harder
  shapes: AAPCS stack arguments, vtable and object-table slots, jump-table
  predecessors, `ldrd`. This is migration step 3's comparison.
- Real non-ARM firmware. Only synthetic RV32 fixtures were used. The
  GD32VF103 walkthrough is analysis, not a run.
- A dataflow analysis implemented over Macaw IR. It was inspected, not
  built. Its cost estimate is a judgment from the observed IR, the missing
  AArch32 `RegisterUse` instance and the discovery gaps.
- Ghidra decompiler behavior with flash imported read-only.
- PyGhidra (persistent JVM) as a way to cut the about 4 s start-up.
- Whether the operation-descriptor refactor (step 6) helps the local
  planner. Planner behavior was not touched or measured.

## Reproduce

```sh
X=docs/spikes/architecture-evaluation/experiments
H=$(brew --prefix ghidra)/libexec/support/analyzeHeadless
# Thumb controls (and RV32: rv32_controls.bin, -processor RISCV:LE:32:default -cspec gcc)
clang -target thumbv7em-none-eabi -c $X/fixtures/thumb_controls.s -o /tmp/t.o
python3 $X/fixtures/extract_text.py /tmp/t.o $X/fixtures/thumb_controls.bin
$H /tmp/gfix fix -import $X/fixtures/thumb_controls.bin -processor ARM:LE:32:Cortex -cspec default \
   -loader BinaryLoader -loader-baseAddr 0 -noanalysis -deleteProject -scriptPath $X/ghidra \
   -postScript PointerUseProbe.java out.json "0x800@0x800,0x1000@0x1000,0x0@0x0,…" create 0x1001
tools/unicorn/.venv/bin/python3 $X/python/capstone_forward_use.py $X/fixtures/thumb_controls.bin 0 0x200 --fn 200:240
(cd external/macaw && cabal exec -v0 -- runghc ../../$X/macaw/DumpBlocks.hs IMAGE BASE ENTRY LO HI)
```

The real-image commands are in the case note. They run against a copy of
the case's Ghidra project opened `-readOnly`.
