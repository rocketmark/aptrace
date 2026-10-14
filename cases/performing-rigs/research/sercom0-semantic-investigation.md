# SERCOM0 Targeted Semantic Investigation v1 (`FUN_0000b4b4`)

**Question.** Does `FUN_0000b4b4` access SERCOM0 peripheral registers during
reachable execution, or are its SERCOM0 references address constants used
for another purpose?

**Short answer (PARTIAL).** In every execution observed, it does not access
SERCOM0 registers. The boot replay entered it 278 times, through all four
static call sites. Each time, its only data-dependent access read RAM.

The SERCOM0 base `0x40003000` is loaded from flash and used only as a
comparison operand. This holds mechanically for all inputs.

One static calling context was never reached and remains open:
`FUN_0000b658 → FUN_0000b5bc`. The boot state constrains that context's
argument to RAM pointers, but nothing was observed there. The global
negative ("never, in any reachable execution") is therefore **not**
established.

Firmware: `firmware_autopilot868.bin`, sha256 `6dcdb4c1…52e3`. Evidence was
recorded in a scratch ledger copy. The canonical ledger, `C9:v1` and the
typed address-loader claims are unchanged.

## 1. Baseline

- Branch `feat/claim-candidates`, HEAD `bbcbfca`. The claim-candidate
  milestone was already committed. The 38 pre-existing SERCOM0 smoke-test
  ledger files (including `C9`) were left as found.
- Agent tests: 397 collected, 396 passed and 1 skipped in the checkout.
  A clean worktree of `bbcbfca` lacks the gitignored census DB and Ghidra
  cache, so there 2 tests fail and 8 skip. That is environmental, not
  regression.

## 2. Known facts, re-verified

| Reported observation | Status | Evidence |
|---|---|---|
| `FUN_0000b4b4` loads `0x40003000` | **Mechanically established.** `ldr r2,[pc,#0x48]` at `0xb4b6`; the flash word at `0xb500` is `0x40003000`. | `EV-29fef5d8723a352a` (disassembly, EXACT); `EV-f9a9ae317433aceb` (RAW read `@0xb4b6 0xb500 FLASH`) |
| 4 reads, 0 writes, 0 calls, 0 MMIO sites | **Established (RAW, complete, 14 blocks).** | `EV-f9a9ae317433aceb` (STRONG, symbolic, not solver-confirmed) |
| "Some addresses depend on `r0`" | **Sharpened:** exactly one access is data-dependent: a 4-byte read at address `r0` (`@0xb4b4`, unconditional). The other three are flash literal-pool reads at `0xb500`/`0xb504`/`0xb508`. | same |
| Return value | **Established (RAW expression).** It returns 0..5 when `*(u32*)r0` equals `0x40003000`, `0x40003400`, `0x41012000`, `0x41014000`, `0x43000000` or `0x43000400` respectively, else −1. The constants appear only in comparisons, never in an access address. | same |
| Four direct call sites | **Established.** `0xa068`, `0xa088`, `0xa0ac` and `0xb5c2` decode as `BL 0xb4b4`; all four were executed. | Ghidra export; `EV-63ef…`, `EV-bb6e…`, `EV-12d7…`, `EV-dc93…` (callsite context, EXACT); `EV-a4451ac21f0b2d73` |
| Callers use the return as a table index | **Decoded dataflow, but "table" is interpretation.** `a064`/`a084`/`a0a8` compute `*(0x14140 + 12·idx + {0,4,8})` when `idx ≥ 0`. `b5bc` uses `16·idx + 6`. | disassembly |
| `C9:v1` is `PROPOSED` | **Unchanged.** It asserts "definitively reachable and involves SERCOM0 peripheral access"; this investigation supports the first half and not the second. | `ledger/claims/C9/v1.json` |
| Address-loader claims establish only constant loading | **Consistent.** Nothing here changes them. | — |
| "This is a SERCOM-index lookup" | **Pattern-based** (the constants are the six SAMD51 SERCOM bases). Not a mechanical claim. | — |

One boundary observation came up: Ghidra attributes the `BL 0xb6b4` at
`0x9fe2` to `FUN_0000a000`, but the instruction lies in the function that
starts at `0x9fc4`. Boot entries at `0x9fc4` confirm that function. Function
boundaries remain heuristic.

## 3. Tool capabilities (tested, not assumed)

| Question | Answer |
|---|---|
| Can Macaw/Crucible recover a register value at a call site? | No. `function_effects` summarizes one function with symbolic `r0`–`r3`. It has no caller context. |
| Can it propagate values caller → callee? | No. Calls are opaque. There is no interprocedural mode (a non-goal). |
| Does `function_effects` accept constrained inputs? | Only as post-hoc **solver specializations** (`rN=` equalities over the same terms). That is hypothetical and does not re-simulate. The spike entry (`effects-spike`) has concrete overrides, but it is spike-only. |
| Bounded symbolic run with caller constraints? | Only an equality per register via specialization. Range or set constraints are not exposed. |
| Can Unicorn run the function with controlled inputs? | Yes. `ConcreteMachine.call` (AAPCS) works with arbitrary inputs, which is hypothetical. The case boot recipe also reaches `b4b4` with **firmware-produced** inputs (census coverage). |
| Can tools tell a dereference from loading an address as data? | Yes, for one function: Crucible observes every memory access, so a constant used only as an operand never appears as an access address. Unicorn's MMIO log shows actual accesses. Neither was previously tied to caller values. |
| Assumptions required | Thumb/Cortex-M; flash concrete; RAM/MMIO symbolic (Crucible). For Unicorn, the boot recipe's 14 disclosed assumptions: tick stand-in, forced ready bits, the radio-ID `force_reg`, a PA22 GPIO seed, a stubbed DWT delay, and a zero-filled NVM calibration page. |
| Reproducible and recordable? | `function_effects` and `callsite_context` already were. Concrete observation was not a ledger operation; that was the gap. |

## 4. Capability added: `observed_call_arguments`

This is the smallest capability that closes the gap: a call-site
argument-value query over an executed scenario.

- **Framework** `tools/unicorn/call_observation.py`: summarizes the watch
  hits at a function entry, per call site.
  - It attributes each entry by decoding the instruction that ends at LR:
    a `BL` whose decoded target is the entry, a `BLX rm`, or `OTHER` for a
    tail branch, where no site is attributed.
  - It classifies every argument value, and the word it points at, against
    the supplied geometry.
- **Framework** `ConcreteMachine.run(watch_reg_pointee=…)`: captures the
  bytes at a register's value at each watch hit. It uses `mem_read`, so it
  fires no hooks and never perturbs the MMIO model or logs (tested).
- **Case** `scripts/observe_call_arguments.py`: runs the canonical boot
  recipe with one passive watch at the entry. It optionally logs MMIO
  accesses from PCs inside the function extent.
- **Agent**: a typed, replayable ledger operation `observed_call_arguments`
  (analysis version 1), with these properties:
  - **Inputs.** It names only a function; APTrace binds everything else.
    Its input artifacts are the census DB, Ghidra export, SVD, boot recipe,
    `concrete.py` and `call_observation.py`, so a changed recipe or harness
    is a different operation.
  - **Labeling.** Results carry `basis: CALLER_GROUNDED_CONCRETE`.
  - **Call-site status.** Static call sites that were never reached are
    `UNOBSERVED`, never unreachable.
  - **Grading.** STRONG ("concrete execution under disclosed harness
    assumptions; observed contexts only") with limitations
    `CONCRETE_HARNESS_ASSUMPTIONS`, `OBSERVED_CONTEXTS_ONLY`,
    `UNOBSERVED_CALL_SITES_NOT_UNREACHABLE` and, when truncated,
    `OBSERVATION_TRUNCATED`. It is BOUNDED when the function is never
    entered, and UNKNOWN on failure.
- `function_effects` evidence with a non-empty specialization now carries
  `HYPOTHETICAL_ARGUMENT_SPECIALIZATION`. This keeps chosen-input solver
  facts distinct from caller-grounded values. Grades are unchanged.

The operation is not exposed to the planner (follow-up).

## 5. Four caller contexts

Static `r0` preparation was decoded from the image (EXACT). Concrete values
come from `EV-a4451ac21f0b2d73` (CALLER_GROUNDED_CONCRETE, boot scenario,
450,000 instructions, all 9 recipe milestones, `init_status=complete`).

| Call site (caller) | Static `r0` source | Reachable | Target | Observed `r0` (hits) | `*r0` observed | Class |
|---|---|---|---|---|---|---|
| `0xa068` (`FUN_0000a064`) | `ldr r0,[r0]`: memory-derived from caller arg | yes (observed) | direct `BL` | `0x20004c54`, `0x20004c78` RAM (4) | `0x41012000`, `0x43000400` | CONCRETE (observed set) |
| `0xa088` (`FUN_0000a084`) | same pattern | yes | direct `BL` | same two RAM values (2) | same | CONCRETE |
| `0xa0ac` (`FUN_0000a0a8`) | same pattern | yes | direct `BL` | same two RAM values (2) | same | CONCRETE |
| `0xb5c2` (`FUN_0000b5bc`) | arg passthrough (`mov r5,r0` saves it) | yes | direct `BL` | same two RAM values (270) | same | CONCRETE for context via `b6c2` |

One level up (`EV-c6b9066ed03758d5`, `EV-c704505bba5d6aa4`,
`EV-ba8dbfddfb1e44cf`):

- **`FUN_0000b5bc`.** Its two static callers are `0xb6c2` in `FUN_0000b6b4`
  (observed, 270 entries) and `0xb662` in `FUN_0000b658`, which is
  **UNOBSERVED**.
- **`FUN_0000b658`** was never entered (BOUNDED). Its only static caller is
  `0xc84a` in `FUN_0000c7c0`. There, `r0 = *(this+0x10)`, and `b658` does
  not change `r0` before the `BL`.
- **`FUN_0000c7c0`** has no static caller. Its only reference is a Thumb
  pointer at `0x14920`, slot 8 of a pointer table whose address point
  (`0x14900`) is installed only by the constructor-like `FUN_0000c8bc`.
  This rests on a raw flash-word scan plus the census `function_pointers`;
  the "vtable" reading is pattern-based.
- **`FUN_0000c8bc`** stores its `r1` into `this+0x10`. During boot it ran
  three times, from `FUN_0000b144`, with `r1` equal to `0x20004c60`,
  `0x20004c6c` and `0x20004c48`. All are RAM; the words there were
  `0x41014000`, `0x43000000` and `0x40003400`.
- **Context `b658 → b5bc → b4b4`** is classed **UNKNOWN (unobserved)**, with
  a state-derived constraint. If `c7c0` runs on one of those three objects
  and `this+0x10` has not been rewritten, `r0` is one of those three RAM
  addresses. That is a conditional bound, **not** a caller-grounded value.
  Stores to `this+0x10` through computed pointers are not excluded.

Exploratory only (scratch read at end of boot, not ledger evidence): RAM
`0x20004c3c` holds `0x40003000`, next to the five other words at stride
`0xC`. Even if that address reached `b4b4`, the access would be a RAM read
returning 0. It would not touch a SERCOM0 register.

## 6. Callee memory behavior

| Access | Classification | Basis |
|---|---|---|
| read `@0xb4b6` → `0xb500` | flash literal: constant loading (`0x40003000`) | RAW, concrete address |
| read `@0xb4c4` → `0xb504`, `@0xb4d8` → `0xb508` | flash literal: constant loading (`0x41012000`, `0x43000400`), conditional | RAW + solver guard status |
| `add.w r2,#0x400`, `#0x2000`, `cmp.w #0x43000000` | constant formation and comparison only; no access | decode + RAW (no access term) |
| read `@0xb4b4` → address `r0` (4 bytes) | **RAM read** in all 278 observed executions (`0x20004c54`/`0x20004c78`) | CALLER_GROUNDED_CONCRETE |
| same, with `r0 := 0x40003000` | would be MMIO `SERCOM0.CTRLA` (always-true guard) | **HYPOTHETICAL** solver specialization, `EV-d54391e40b4a6658`; no caller shown to supply it |
| MMIO accesses from code in `0xb4b4..0xb4fe` | **0** (log of 17,755 entries, not truncated) | concrete Unicorn MMIO log, independent of Crucible's access model; extent is a Ghidra boundary |
| writes, calls | none | RAW complete |

## 7. Hypotheses

- **H1** (an actual SERCOM0 register access in at least one reachable
  context): **not supported**.
  - It is contradicted in every observed context: 278/278 entries had RAM
    `r0` and no MMIO access from the function.
  - It is not refuted for the unobserved `b658` context, nor for calls
    outside the 450k-instruction boot scenario.
  - H1 requires some reachable call with `r0` in `[0x40002ffd, 0x400033ff]`.
    By the complete RAW summary, that is the only way.
- **H2** (the constant is incidental; its uses are non-MMIO data accesses):
  **supported**.
  - This holds as a function summary for all inputs (RAW): the constant is
    a flash-literal operand.
  - For the data access, it holds in all observed contexts (concrete).
  - It is not proven for unobserved contexts.
- **H3** (cannot yet distinguish): remains correct **only** for the global
  statement. It is narrowed to one static path and to post-boot behavior.

What would change this:
- H1 would be **supported** by any observed or solver-proven reachable call
  passing an `r0` in the SERCOM0 window.
- H2 would extend to a **scoped negative** if every reachable context were
  shown to have `r0` outside that window. That needs the `b658` path, the
  stability of the `this+0x10` fields, and the indirect callers covered.

Absence in the observed set is not proof of impossibility.

## 8. Benchmark against the recorded investigation

| Measure | Before (continuity-v2, claim-candidates) | This milestone |
|---|---|---|
| Direct caller contexts classified | 4 inspected, 0 with values | 4/4 CONCRETE (observed); 1 second-level context UNKNOWN with a conditional bound |
| Caller `r0` values constrained | 0 | 4/4 call sites → 2 RAM values; unobserved branch bounded to 3 RAM values (conditional) |
| Memory-address relationships established | 0 (access parametric) | the `@0xb4b4` read resolved to RAM in 278/278 executions; constant shown to be operand-only |
| Actual MMIO accesses established | 0 | 0 by `b4b4` (concrete); SERCOM0 access only under a hypothetical input |
| Unresolved paths | all | 1 static path (`c7c0 → b658 → b5bc`), plus anything outside boot |
| New durable evidence (scratch ledger) | — | 4 `observed_call_arguments`, 1 hypothetical `function_effects`, 4 `callsite_context`; replay matches |
| Cost | — | observation ≈0.4 s wall, ≈0.32 GB RSS each; hypothetical specialization 85 s, ≈1.06 GB peak; whole experiment ≈88 s on the 24 GB Mac mini |
| Supported hypothesis | H3 | H2 within observed contexts; H3 only for the global statement |

## 9. Reproduce

```sh
# framework + case harness tests
tools/unicorn/.venv/bin/python3 tools/unicorn/test_call_observation.py
tools/unicorn/.venv/bin/python3 cases/performing-rigs/test/test_concrete.py
(cd agent && .venv/bin/python -m pytest -q tests/test_observed_call_arguments.py)

# one observation (deterministic JSON; no timestamps)
tools/unicorn/.venv/bin/python3 cases/performing-rigs/scripts/observe_call_arguments.py \
    --firmware-key autopilot868 --entry 0xb4b4 --extent 0xb4b4:0xb4fe

# the full experiment into a NEW scratch ledger (refuses the canonical one)
agent/.venv/bin/python cases/performing-rigs/scripts/sercom0_semantic_investigation.py \
    --ledger-dir "$TMPDIR/sercom0-ledger"
```

Outputs: `research/runs/sercom0-semantic-v1/` (`summary.json` with every
step's evidence id, grade, limitations and timing, plus each observation
result). Two independent runs produced byte-identical observation output and
the same evidence ids.

## 10. Recommendations

- **Next (smallest):** let `observed_call_arguments` take a scenario from
  the existing `dynamic_export.py` corpus, not only boot. Then:
  1. Ask whether any scenario enters `FUN_0000b658`.
  2. If one does, read the `r0` it delivers to `b4b4` directly.

  Pair this with a `watch_mem_write` on the three `this+0x10` fields across
  boot, to test their stability. Only if no scenario reaches slot 8 should
  the question move to symbolic reachability of the `0x20` table-slot call.
- **Claim vocabulary:** no current predicate expresses "the arguments
  observed at this function's call sites under scenario S lie in region R".
  A minimal `OBSERVED_ARGUMENT_REGION(function, register, region, scenario)`
  with `OBSERVED_CONTEXTS_ONLY` scope would represent this result without
  implying absence. No candidate was generated.
- **Identity quirk (not fixed):** `function_effects` with `specialize: {}`
  and without `specialize` give different operation keys for the same
  result (`EV-f9a9…` vs `EV-0371…`). Canonicalizing empty defaults would
  let historical reuse recognise them.
