# Arrow: concrete-execution

Concrete execution of firmware with Unicorn. It covers:
- a reusable Cortex-M/Thumb machine (`ConcreteMachine`) with runs, direct
  AAPCS calls, interrupt delivery, reset isolation, and passive
  observation hooks;
- its CLI;
- deterministic post-processing of watch hits and write hits into
  call-site argument observations and watched-field histories;
- the agent's `observed_call_arguments` operation, which replays a
  registered case scenario.

## Status

**MAPPED**: mapped 2026-10-16 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been verified against code (no audit has
run).

## References

### HLD
- docs/high-level-design.md (skeleton; written after all leaves)
- docs/intent/production/production-design.md (the `production` sub-HLD; skeleton)

### LLD
- docs/intent/production/concrete-execution/concrete-execution-design.md

### EARS
- docs/intent/production/concrete-execution/concrete-execution-specs.md (prefix `PROD-CONC`; 48 specs: 46 `[x]`, 2 `[ ]`, 0 `[D]`)

### Tests
- **Framework, executing Unicorn:** tools/unicorn/test_call_observation.py. It runs a hand-assembled synthetic Thumb image, round-trip-verified with Capstone, and covers:
  - BL decoding and caller attribution (BL, BLX_REG, OTHER);
  - pointee capture without MMIO side effects;
  - watched-write forms, previous and new values, initialization, final bytes;
  - truncation;
  - that the write watch is passive.
- **Framework, adapter-only** (recorded harness documents, no Unicorn run):
  - agent/tests/test_observed_call_arguments.py: classification, grading and limitations, failure statuses, ledger identity and reuse;
  - agent/tests/test_scenario_observation.py: scenario and watch validation, scenario identity, limitations, planner action, claim boundaries.
- **Case-owned, executing Unicorn** on case firmware, but testing framework `ConcreteMachine` behavior:
  - cases/performing-rigs/test/test_concrete.py: CLI numeric semantics, direct call with stack args, structured failure snapshot, explicit carry-forward, fresh isolation, default SP with no trampoline in RAM, `error_free` vs `completed`, scenario order independence, `_ranges_excluding`, `log_ram` with `fake_tick`;
  - cases/performing-rigs/test/test_observe_scenarios.py: boot determinism, watched SERCOM field, virtual-link scenarios, refusals.
- **Not covered by any framework-owned test:** `ConcreteMachine.run`/`call`/`reset`/`deliver_interrupt`. Only the case tests above exercise them.

### Code
- tools/unicorn/concrete.py: `ConcreteMachine`, `RunResult`, `CallResult`, `Carried`, `ConcreteExecutionError`
- tools/unicorn/run_concrete.py: CLI over `run`/`call`, emitting `RunResult` JSON
- tools/unicorn/call_observation.py: `bl_target`, `classify_return_address`, `summarize_entry_observations`, `store_addressing`, `summarize_watched_writes`, `correlate_calls_with_fields`
- tools/unicorn/requirements.txt: pins `unicorn==2.1.4`, `capstone==5.0.9`
- agent/src/aptrace_agent/call_observation.py: the `observed_call_arguments` adapter (`ObservedCallArgumentsRunner`)

### Case inputs consumed (not owned here)
- cases/performing-rigs/scripts/observe_call_arguments.py: the scenario runner the adapter executes. It produces the harness document, joining `ConcreteMachine` and `call_observation`.
- cases/performing-rigs/scripts/virtual_link.py, config/boot_recipes.py, config/observation_scenarios.json: scenario definitions and boot recipes
- Wiring: agent/src/aptrace_agent/structural_wiring.py (`performing_rigs_observed_calls`, `OBSERVATION_INPUTS`, the venv interpreter path; evidence-record segment)

### Related docs
- docs/tooling/unicorn-backend.md; docs/harness/execution-model.md ("validate against Unicorn")
- docs/status.md "Available capabilities" (observed call arguments)

## Architecture

**Purpose:** run real firmware code concretely and record what happens under
explicit, disclosed harness inputs, so concrete observations can be kept
distinct from static and symbolic evidence. CLAUDE.md assigns Unicorn to
"concrete execution: runtime registers, memory accesses, reproducible
scenario observations".

**Key components:**
1. **`ConcreteMachine`:**
   - *Memory:* one Unicorn instance per image (ARM Thumb | M-class, Cortex-M4 model) mapping flash, RAM, an MMIO window, the PPB, extra maps, and a harness-only trampoline page at `0x2FFF0000`.
   - *Isolation:* dirty-page reset from a pristine snapshot, so `fresh=True` runs are isolated.
   - *Execution:* `run()` with seeds, stubs, stops, watches, forced state and logs; `call()` with AAPCS argument placement and trampoline return detection; `deliver_interrupt()` as a nested AAPCS call that restores `r0`–`r3`/`r12`.
2. **`RunResult`:** always returned, even on failure. It carries `error_free` and `completed` (distinct), a recent-PC ring, applied seeds tagged `seed` or `carried:<source>`, and every requested capture.
3. **`call_observation`:** pure post-processing. It attributes each entry hit to the call instruction ending at LR (BL decoded from the image, `blx rm` by encoding, otherwise OTHER), classifies argument values by region, summarizes watched-field stores with Capstone-decoded addressing form, and correlates calls with field history.
4. **`observed_call_arguments` adapter:**
   - *Validation:* the function identity, a registered scenario and up to 8 small RAM watch fields.
   - *Execution:* checks the image SHA-256, then runs the case scenario script under the Unicorn venv with a 300-second timeout.
   - *Interpretation:* classifies call sites OBSERVED, UNOBSERVED or DYNAMIC_ONLY against Ghidra static callers, and attaches harness assumptions and coverage text.

## Spec Coverage

`[x]` means observed in source only. Tests are split three ways:
- **tool-script**: the framework script `test_call_observation.py`, which
  executes Unicorn on a synthetic image. Its checks fail only through the
  script's `main()` exit code; the test functions themselves do not raise.
- **adapter-only**: a fake harness document, no Unicorn run.
- **case-script**: case-owned, executes Unicorn on case firmware.

No tests were run during mapping.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Tool-script | Adapter-only | Case-script |
|---|---|---|---|---|---|---|---|
| Memory map, geometry, ISA | PROD-CONC-MAP-001 to 005 | 5 | 0 | 0 | 0 | 0 | 3 |
| Isolation and reset | PROD-CONC-ISO-001 to 004 | 4 | 0 | 0 | 0 | 0 | 3 |
| Run, call, interrupt | PROD-CONC-RUN-001 to 006 | 6 | 0 | 0 | 0 | 0 | 4 |
| Harness inputs | PROD-CONC-HAR-001 to 003 | 3 | 0 | 0 | 0 | 0 | 1 |
| Raw result recording | PROD-CONC-REC-001 to 004 | 4 | 0 | 0 | 1 | 0 | 0 |
| Call attribution | PROD-CONC-OBS-001 to 005 | 4 | 1 (OBS-005) | 0 | 4 | 0 | 0 |
| Watched writes, correlation | PROD-CONC-WW-001 to 005 | 5 | 0 | 0 | 5 | 0 | 0 |
| CLI | PROD-CONC-CLI-001 to 004 | 4 | 0 | 0 | 0 | 0 | 1 |
| Agent operation: request, identity | PROD-CONC-ADP-001 to 006 | 5 | 1 (ADP-006) | 0 | 0 | 5 | 0 |
| Agent operation: interpretation | PROD-CONC-INT-001 to 006 | 6 | 0 | 0 | 0 | 6 | 0 |

**Summary:** 46 of 48 specs are observed in source. There are 2
approved-intent gaps:
- **OBS-005:** state whether the custom Thumb decoding fills an engine gap or
  is a cross-check (CLAUDE.md).
- **ADP-006:** make results bindable to the engine version (CLAUDE.md
  "Evidence discipline").

Mechanisms are left to LLD Open Questions 2 and 9.

**Contradicted specs:**
- MAP-002: SAMD51 defaults vs "no target-specific meaning".
- REC-004: write cap per run vs "per range" help.
- CLI-004: stale `--sp` help.
- WW-002 (in part): addressing forms.

**Test counts:** 10 specs have a tool-script check, 11 an adapter-only test
and 12 a case-script check. The machine's `reset`, `call`, failure snapshot
and `completed` semantics are checked only by case scripts. No `@spec`
annotations exist.

## Key Findings

1. **The framework machine's core behavior is tested only by the case.**
   - Reset isolation, `call()` stack arguments, failure snapshots, carry-forward, default SP and `error_free`/`completed` are covered only by `cases/performing-rigs/test/test_concrete.py`, which runs case firmware.
   - The only framework test that executes Unicorn is `test_call_observation.py`, on a synthetic image, and it covers watch and post-processing behavior.
2. **Results carry little identity.** `RunResult.to_dict()` records the firmware *path*, entry, stop reason and captures (`concrete.py:263-300`). It does not record:
   - a firmware hash;
   - the Unicorn version or CPU model;
   - the memory map (flash base, RAM and MMIO windows, extra maps);
   - `reg_seed` values, the initial SP or `stub_calls`.

   Applied memory seeds, forced-state hits, fake ticks and MMIO bit forcing *are* recorded.
3. **The agent operation's identity covers more.**
   - *Adapter provenance:* the firmware SHA-256 is verified before the run and again in the returned document, plus the scenario and the scenario-registry SHA-256 (`agent/.../call_observation.py:260-265, 300-317`).
   - *Ledger:* `OBSERVATION_INPUTS` hashes the case scenario registry, boot recipes, `virtual_link.py`, the case script, `concrete.py` and `call_observation.py` (`structural_wiring.py:127-134`).
   - *Gaps:* the Unicorn version and memory map are still not recorded.
4. **The machine defaults to SAMD51 geometry.** `ConcreteMachine` defaults to flash base `0x4000`, RAM `0x20000000`/`0x30000` and MMIO `0x40000000`/`0x100000`, and the trampoline-placement comments reason from ATSAMD51J19A RAM (`concrete.py:88-110, 380-399`). The CLI repeats these defaults (`run_concrete.py:126-130`) and the adapter defaults RAM to `(0x20000000, 0x30000)` (`agent/.../call_observation.py:232`). `docs/case-boundary.md:23-25` records these defaults as an intentional current seam that callers can override. `docs/tooling/unicorn-backend.md` says the engine maps caller-supplied geometry "without assigning target-specific meaning". The two docs disagree. The production path supplies case geometry.
5. **The architecture is fixed to Cortex-M4 Thumb.** That covers Unicorn mode and CPU model, the ARM register set, the forced Thumb bit on entry, AAPCS call placement, the `r0`–`r3`/`r12` restoration on interrupt delivery, and Thumb BL/BLX decoding in `call_observation` (`concrete.py:432-433, 583, 894-1003`; `call_observation.py:65-101`). The adapter's planner summary renders `r0` only (`agent/.../call_observation.py:454-485`).
6. **The observation operation depends on a case script.** The harness document the adapter interprets is produced by `cases/performing-rigs/scripts/observe_call_arguments.py`. The adapter's `SCENARIO_KINDS` hardcodes the case's two registry kinds, `boot-recipe` and `virtual-link` (`agent/.../call_observation.py:49-52`). A document without a scenario registry is treated as `boot-recipe` (`:389-390`).
7. **Some outcomes are not recorded.**
   - *MMIO and RAM logs:* they stop logging at their caps with no dropped counter (`concrete.py:716-738`), unlike the write-watch log, which counts `mem_write_dropped`.
   - *`--stop-at` in `--call` mode:* `run_concrete.py` parses the stop addresses but never passes them (`:215-228`), so they are silently ignored.
   - *Reset:* zeroes the 17 named registers in `REG_BY_NAME` (`r0`–`r12`, `sp`, `lr`, `pc`, `cpsr`), not other CPU state such as special-purpose or floating-point registers (`concrete.py:70-76, 519-522`).
   - *Watch-hit cap:* a stop on the cap counts as `completed` when no `stop_at` was requested (`:203-213, 696-699`).
8. **Capstone semantics live outside `tools/census/`.** `call_observation.store_addressing` decodes store addressing forms with Capstone Thumb M-class and ARM mnemonics (`call_observation.py:195-240`), and `bl_target` hand-decodes Thumb-2 BL (`:65-79`). Neither says whether it fills an engine gap or is a cross-check (CLAUDE.md "custom instruction interpretation … say which"). If Capstone is absent the form is `undecoded`, and Capstone's presence is not recorded.
9. **Concrete-only claims are scoped.**
   - Module docstrings and the adapter's coverage text state that unobserved call sites and values are "not thereby impossible", and that a field never written was "not thereby immutable" (`call_observation.py:9-12, 34-35`; `agent/.../call_observation.py:363-371`).
   - Static call sites never reached are `UNOBSERVED`, never "unreachable".
   - Observations are labeled `CALLER_GROUNDED_CONCRETE` (`agent/.../call_observation.py:43`).
10. **Some mismatches raise instead of returning a status.** A returned document naming another firmware or scenario raises `RuntimeError` (`agent/.../call_observation.py:300-304`). Timeouts, non-zero exits and non-JSON output become statuses.
11. **Docs and comments have drifted.**
    - `requirements.txt` says Capstone is "optional … in trigger_mitigation_prototype.py only", but `call_observation.py` and its test use it, and the test requires it.
    - The `run_concrete.py --sp` help still places the trampoline in RAM, though `concrete.py` moved it out (`:134` vs `concrete.py:102-110`).
    - `unicorn-backend.md` lists three addressing forms; the code also emits `other` and `undecoded`.
    - `concrete.py` cites the nonexistent `cases/performing-rigs/docs/investigations/toolchain-cleanup.md` (`:43, 108, 183`) and the case's `virtual_link.py` (`:5, 360`).

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
*None identified in this segment.* No test or tool in scope writes canonical
case state. The case tests run case firmware read-only.

### Confirmed defects
*None demonstrated by execution.*

### Evidence-integrity risks
1. **Raw run results do not disclose their inputs.** They record no firmware hash, engine version, memory map or `reg_seed`. Consumers of raw `RunResult` JSON (the CLI, case scripts, census dynamic ingest) cannot bind a run to its exact inputs from the result alone. (Finding 2; PROD-CONC-REC-001, HAR-003)
2. **Silent log truncation.** MMIO and RAM logs stop at their caps with no dropped count. (Finding 7; PROD-CONC-REC-003)
3. **Correlation omits the completeness of the history it states.** `correlate_calls_with_fields` states `field_state` without consulting `dropped_writes`. A store with unreadable previous bytes is not counted as value-changing. It has not been shown to produce a wrong statement. (LLD Open Question 7; PROD-CONC-WW-003, WW-004)
4. **Capstone presence and version are not recorded.** Store addressing silently degrades to `undecoded` without Capstone. (Finding 8; PROD-CONC-WW-002)
5. **Engine identity is missing.** The agent operation's identity has no Unicorn version or memory map. (Finding 3; PROD-CONC-ADP-005, ADP-006 `[ ]`)
6. **Downstream promotion.** A `bounded…` scenario with observed entries is graded `STRONG`, which is test-asserted. Its derived fact is merged into session state as `PROVEN` (`research/fact_derivation.py:780-790`). This is recorded for evidence-record and investigation/controller, not decided here (LLD Open Question 13; cross-segment register).

### Architectural coupling
7. **SAMD51 defaults** in a framework library and CLI. This is a recorded seam (`docs/case-boundary.md`) that conflicts with `unicorn-backend.md`. (Finding 4; PROD-CONC-MAP-002)
8. **Cortex-M4 Thumb is fixed** throughout. (Finding 5; PROD-CONC-MAP-004)
9. **The case owns the scenario runner.** The agent operation's harness document comes from a case script, and the scenario kinds are hardcoded in the framework adapter. (Finding 6; PROD-CONC-INT-005)

### Semantic inconsistencies
10. **`--stop-at` is silently ignored in `--call` mode.** (Finding 7; PROD-CONC-CLI-003)
11. **Watch-hit-cap stops count as `completed`** when no `stop_at` is requested. (Finding 7; PROD-CONC-RUN-003)
12. **The write-log cap is per run, but the help says per range.** (PROD-CONC-REC-004)
13. **Documentation contradicts the code.**
    - `unicorn-backend.md` says "no target-specific meaning", but the defaults are SAMD51.
    - The `requirements.txt` comment and the `--sp` help are stale.
    - `unicorn-backend.md` lists fewer addressing forms than the code emits.

    (Findings 4, 11; PROD-CONC-MAP-002, CLI-004, WW-002)
14. **The role of the custom Thumb decoding is undeclared.** It sits outside the frozen census modules. This is an approved-intent gap. (Finding 8; PROD-CONC-OBS-005 `[ ]`)
15. **`static_target_match` and null-site `DYNAMIC_ONLY` are named ambiguously.** (PROD-CONC-INT-001, INT-002)

### Maintenance debt
16. **The core machine tests are case-owned.** (Finding 1)
17. **The framework script-style checks do not raise** inside test functions. They fail only through the script's exit code. (Spec Coverage)
18. **CPU state is only partly reset.** (Finding 7; PROD-CONC-ISO-002)
19. **A doc reference is missing** (`toolchain-cleanup.md`). (Finding 11)
