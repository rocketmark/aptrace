# SERCOM0 Scenario-Grounded Observation v2

**Question.** v1 found that every observed call to `FUN_0000b4b4` passed a
RAM pointer, so the function read RAM and never touched SERCOM0 registers.
One static path was never executed:
`FUN_0000c7c0 → FUN_0000b658 → FUN_0000b5bc → FUN_0000b4b4`. This pass asks
three things:

1. Does any existing scenario reach that path?
2. Can the RAM fields that select the peripheral change during execution?
3. Can ResearchController run and read these observations itself?

**Short answer (PARTIAL).**

1. **No registered scenario reaches the path.** Eleven scenarios were
   executed and one was skipped as incompatible; none failed. `c7c0` and
   `b658` were never entered. The closest prerequisite reached is
   `FUN_0000c8bc`, which ran 3 times in boot and installed vtable `0x14900`
   into three objects. Reaching `c7c0` needs a virtual call through slot 7
   or slot 8 of that table. No static dispatch site for either slot was
   found outside the slot-7 thunk itself. That result is pattern-matched,
   not a proof.
2. **The fields did not change in boot.** Boot writes each of the 12 watched
   fields exactly twice: a zero-fill, then its constructor store. None
   changes again. All 278 calls to `b4b4` saw the initialized value. No
   AutoPilot code in the virtual-link scenarios writes these fields.
3. **The planner selected the tool by itself, but its claims are weak.**
   Qwen chose the new tool on its own in all five live trials. It picked a
   useful scenario once it was told what each scenario kind runs. Its final
   claims did not cite or scope the observation.

The global negative ("`b4b4` never accesses SERCOM0 in any reachable
execution") remains **not established**.

Firmware: `firmware_autopilot868.bin`, sha256 `6dcdb4c1…52e3`. All evidence
was recorded in scratch ledger copies. The canonical ledger, `C9:v1` and the
address-loader claims are unchanged.

## 1. Baseline

- Branch `feat/caller-grounded-observation`.
- HEAD `c871b87` (v1 investigation), on top of `ee1fb9b` (capability).
- A single worktree; the 38 pre-existing uncommitted SERCOM0 ledger entries
  were left as found.
- Agent tests at baseline: 409 passed, 1 skipped (the 5-minute Beads lease
  test).
- `tools/unicorn/boot_recipes.py` does not exist; the recipes are in
  `config/boot_recipes.py`.

## 2. v1 evidence, re-verified

| v1 statement | Category | Status in v2 |
|---|---|---|
| Four direct call sites (`0xa068`, `0xa088`, `0xa0ac`, `0xb5c2`) | statically established | Unchanged (Ghidra export, EXACT decode). |
| 278 boot calls; `r0` ∈ {`0x20004c54`, `0x20004c78`} | observed | **Reproduced** in `EV-108f831aec91fdcd`: 278 entries, the same call-site summary as the committed v1 script. The v1 and v2 documents are identical apart from the summarizer version and new fields. |
| The words there hold `0x41012000` / `0x43000400` | observed | Reproduced. These are RAM contents, not accesses. |
| No MMIO access from `b4b4` code | observed | Reproduced: 0 of 17,755 logged MMIO accesses, log not truncated. |
| 14 harness assumptions | observed (disclosure) | `AUTOPILOT_RECIPE["assumptions"]` has 14 entries; all are carried in the evidence. |
| `b658` never reached | observed (bounded) | Reproduced for boot and extended to 10 more scenarios (§4). |
| `r0 = 0x40003000` reads `SERCOM0.CTRLA` | **hypothetical** | Unchanged: `EV-d54391e40b4a6658`, solver specialization, labeled `HYPOTHETICAL_ARGUMENT_SPECIALIZATION`. No caller was shown to supply that value. |
| RAM `0x20004c3c` holds `0x40003000` | was exploratory | **Now recorded** (§5): boot stores `0x40003000` there at instruction 17,731 via `FUN_0000b312@0xb314`. It is never passed to `b4b4`. |

## 3. Capability added

- **Scenario registry** (`config/observation_scenarios.json`).
  - It lists the canonical boot recipe and the 11 existing
    `virtual_link.py` scenarios. Each entry records its kind, the firmware
    images it executes, its source, its entry conditions and its
    termination condition.
  - No hardware behavior was added.
  - The registry, the case script and `virtual_link.py` are recorded
    operation inputs, so different scenarios are different operations.
  - A different corpus version is never reused for another.
- **Case script** (`scripts/observe_call_arguments.py --scenario --watch`).
  - Virtual-link scenarios run unmodified. `ConcreteMachine.run` is wrapped
    for one scenario, as `dynamic_export.py` does.
  - On legs that execute AutoPilot code, the wrapper adds the entry watch,
    pointee capture and write watch. It removes them before the scenario's
    own code sees the result.
  - Tested on `vl-plus`, `vl-pb05` and `vl-bang`: the same legs, instruction
    counts and stops as an unobserved run, and the scenarios' own
    assertions pass.
  - Each leg's seeds, register seeds, stubs and forced state are recorded as
    its harness inputs.
- **Watched fields.**
  - `ConcreteMachine.run(watch_mem_write=…)` now also records the bytes each
    store overwrote and a dropped-store count.
  - `tools/unicorn/call_observation.py` reports, for each store in run
    order: address, width, previous and new value, PC, census function,
    first-write flag, and addressing form.
  - It also correlates each call's argument with the field it points into.
  - Requests are limited to RAM, at most 8 fields of at most 16 bytes each.
- **Static sweep** (`tools/census/slot_dispatch.py`, pattern-matched). It
  covers every halfword offset, regardless of function boundaries, and
  reports:
  - every slot load feeding `blx`/`bx`;
  - every `BL` to a target;
  - every Thumb pointer word to a target.

## 4. Scenario coverage

Run `R-sercom0-scenario-v2` produced 61 ledger operations. Every scenario was
observed at `b4b4`, `c7c0`, `b658`, `b5bc` and `c8bc`.

| Scenario | Executed AutoPilot code | `c7c0` | `b658` | `b5bc` via `0xb662` | `c8bc` | `b4b4` calls | Distinct `r0` | Read region via `r0` | Watched-field changes after init | Limits |
|---|---|---|---|---|---|---|---|---|---|---|
| `boot` | 450,000 instr (budget) | 0 | 0 | UNOBSERVED | 3 | 278 | 2 | RAM (content looks like SERCOM2/5 bases) | none (12/12 initialized once) | budget-bound; 14 assumptions |
| `vl-ampersand` | 103 instr, 2 legs | 0 | 0 | UNOBSERVED | 0 | 0 | — | — | 0 stores | mid-firmware, non-booted RAM |
| `vl-g` | 101, 2 legs | 0 | 0 | UNOBSERVED | 0 | 0 | — | — | 0 stores | same |
| `vl-s` | 456, 4 legs | 0 | 0 | UNOBSERVED | 0 | 0 | — | — | 0 stores | same |
| `vl-bang` | 1,499, 4 legs | 0 | 0 | UNOBSERVED | 0 | 0 | — | — | 0 stores | same |
| `vl-i` | 583, 6 legs | 0 | 0 | UNOBSERVED | 0 | 0 | — | — | 0 stores | same |
| `vl-i9i1` | 215, 4 legs | 0 | 0 | UNOBSERVED | 0 | 0 | — | — | 0 stores | same |
| `vl-plus` | 62,129, 4 legs | 0 | 0 | UNOBSERVED | 0 | 0 | — | — | 0 stores | same |
| `vl-plus-interactive` | 2,519, 1 leg | 0 | 0 | UNOBSERVED | 0 | 0 | — | — | 0 stores | same |
| `vl-manual-f0e0` | 219, 5 legs | 0 | 0 | UNOBSERVED | 0 | 0 | — | — | 0 stores | same |
| `vl-pb05` | 79,221, 6 legs | 0 | 0 | UNOBSERVED | 0 | 0 | — | — | 0 stores | same |

Scenarios by outcome:

- **Executed:** the 11 above. No virtual-link leg reached its instruction
  budget, and none errored.
- **Skipped (incompatible):** `vl-t-status`, which runs only Remote
  (`mando868`) legs. It is recorded as `unsupported`, graded UNKNOWN.
- **Attempted but failed:** none.
- **Not attempted:**
  - `trigger_device_state_closure.py` and
    `trigger_transient_propagation.py` are unregistered mid-firmware
    trigger/ADC experiments. They share the virtual-link limitation (no
    booted objects).
  - `trigger_mitigation_prototype.py` runs a **patched** in-memory image, so
    it is not the hash-verified firmware.

Reading the matrix:

- The virtual-link scenarios cannot reach this path from the state they
  start in. They enter mid-firmware with pristine RAM, so the three objects
  are never constructed. Their vtable words and `this+0x10` fields stay zero
  in every AutoPilot leg (observed: no stores).
- Only boot constructs the objects, and boot's main loop never dispatches
  slot 7 or slot 8.
- A 3,000,000-instruction boot check still shows 0 entries to `c7c0` and
  `b658`, and still 278 to `b4b4`. This check used the case-script budget
  override, not a ledger operation; it is in `summary.json`.
- An exploratory scratch probe found no new PCs between 450k and 3M
  instructions. That probe was not recorded.

## 5. Watched fields

Field choice comes from existing structural evidence, not adjacency:

- **SERCOM words.** `b4b4`'s only data-dependent access is a 4-byte read at
  `r0` (RAW effects, `EV-f9a9ae317433aceb`). The watched words are:
  - `0x20004c54` and `0x20004c78`: observed as `r0`;
  - `0x20004c48`, `0x20004c60` and `0x20004c6c`: the words `c8bc` stores,
    which the unobserved branch would pass;
  - `0x20004c3c`: the requested reproduction.
- **Object fields.** On each of the three `c8bc` objects (`0x20004348`,
  `0x20004644`, `0x20004940`): the vtable word at `this+0`, and the
  SERCOM-object pointer at `this+0x10`, which `c7c0` loads before
  `BL b658`. Static decode at `0xc84a`, `EV-9f2e30c2a6cdcba3`:
  `ldr r0,[r4,#0x10]`.

Boot results (`EV-108f831aec91fdcd`, `EV-72389a24daeadfc7`). Writes were
complete; none were dropped.

| Field | Store 1 | Store 2 (initialization) | Later changes |
|---|---|---|---|
| SERCOM words `0x20004c3c`…`0x20004c78` (6) | instr ≈15k, `FUN_0000cc24@0xcc82` `str r1,[r3],#4`, 0→0 (the zero-fill loop's running pointer) | instr 17,731–17,768, `FUN_0000b312@0xb314` `str r1,[r0]`: `0x40003000`, `0x40003400`, `0x41012000`, `0x41014000`, `0x43000000`, `0x43000400` | none observed |
| vtable words `this+0` (3) | the zero-fill, 0→0 | `FUN_0000c8bc@0xc8d0` `str r3,[r0],#0x14` → `0x00014900` | none observed |
| `this+0x10` (3) | the zero-fill, 0→0 | `FUN_0000c8bc@0xc8f4` `str r7,[r4,#0x10]`, through the object pointer → `0x20004c60`, `0x20004c6c`, `0x20004c48` | none observed |

None of the 12 fields changed after initialization during boot, under its
14 assumptions. That does not show they cannot change: no code path that
might rewrite them was exercised. `0x20004c3c` held `0x40003000` from
instruction 17,731 to the end of the run, and no observed call passed
`0x20004c3c`.

## 6. Correlation (boot, `b4b4`)

| Call site | `r0` (region) | Calls | Word at `r0` (content) | Field state at every call |
|---|---|---|---|---|
| `0xa068` | `0x20004c54` (RAM) / `0x20004c78` (RAM) | 2 / 2 | `0x41012000` / `0x43000400` | initialized value unchanged |
| `0xa088` | same | 1 / 1 | same | unchanged |
| `0xa0ac` | same | 1 / 1 | same | unchanged |
| `0xb5c2` | same | 149 / 121 | same | unchanged |

The effective address of `b4b4`'s data-dependent read is `r0`, which is RAM
in all 278 calls. The word it loads happens to equal a SERCOM2 or SERCOM5
base. That is a RAM read of a peripheral address, not an access to that
peripheral.

## 7. The unresolved path

| Step | Evidence | Status |
|---|---|---|
| `c8bc` constructs 3 objects (vtable `0x14900`, `this+0x10` = SERCOM object) | observed, boot, `EV-56f2439f96001860` (3 entries) | **reached**: the closest prerequisite |
| Something calls slot 7 (`c744`, which tail-dispatches slot 8) or slot 8 (`c7c0`) on one of them | static sweep (pattern-matched): the only `+0x1c`/`+0x20` dispatch is inside `c744` itself; no `BL` to `c744` or `c7c0`; the only references are the vtable words `0x1491c` and `0x14920`; the only flash word pointing into the table is `c8bc`'s literal `0x14900`. `c744` is not a census function (a Ghidra-unattributed gap at `0xc72a`–`0xc74e`) | **missing condition**; no candidate dispatch site found |
| `c7c0` executes | observed in 11 scenarios: 0 entries (BOUNDED) | not observed |
| `b658` executes; `0xc84a` `BL b658` | 0 entries; `0xc84a` UNOBSERVED | not observed |
| `b5bc` via `0xb662` | UNOBSERVED in all scenarios | not observed |
| `r0` that would reach `b4b4` | conditional static bound only: `*(this+0x10)` ∈ {`0x20004c48`, `0x20004c60`, `0x20004c6c`} (RAM), provided the fields stay unchanged | not caller-grounded |

The path is **unexecuted, not unreachable**. The static sweep cannot exclude
three cases:

- an offset computed in a register;
- a vtable copied to RAM and dispatched from there;
- code that decodes only from another alignment.

The census also lists 56 register-indirect transfer sites as `UNRESOLVED`.

## 8. Planner integration and live trials

- ResearchController offers `observe_call_arguments(function, scenario)`.
  - Its parameters are a known `FUN_` name and an enumerated, registered
    scenario. Watches, budgets and any other parameters are rejected.
  - At most two observations per session.
  - Duplicates are withheld, using the existing cooldown.
- An observation adds a scoped session fact (`[OBS]`, basis
  `concrete-observed`) that names its scenario and says other values are
  not excluded. It never becomes a ledger claim. Only admitted proposals
  reach the ledger, and admission is unchanged.
- The tool description distinguishes observed values from hypothetical
  `analyze_function_effects` r0/r1 values.

Five trials were run on the local oMLX runtime with
`Qwen3-Coder-30B-A3B-Instruct-4bit`, 6 steps each, each in a scratch ledger
copy. Records are in `runs/sercom0-scenario-v2/live-planner.json`.

| # | Code state | Chose the tool | Scenario | Used the result in claims | Notes |
|---|---|---|---|---|---|
| 1 | bare scenario ids | yes, at step 1 | `vl-ampersand` (0 entries) | no | Re-issued the identical request twice (both withheld as duplicates). |
| 2 | + one-line scenario-kind note | yes, at step 1 | `boot` | no | The planner saw only the summary's header line (330-character view). |
| 3 | + first-line digest | yes, at step 1 | `boot` | no | By the final-claims phase, E3 had left the 2-item LATEST window. |
| 4 | + scoped `[OBS]` fact | yes, at step 1 | `boot` | partially | Admitted PROBABLE claim "b4b4 reads 4 bytes from RAM addresses": right direction, but it cites E1/E2 rather than E3 and has no scenario scope. |
| 5 | same as 4; objective about `b658` | yes, at step 1 | `boot` (b658 not entered) | — | No unreachability claim. It drifted into an MCLK census, and its malformed claims were rejected by admission. Nothing entered the ledger. |

Trials 1–3 found presentation defects, which were fixed in planner-visible
rendering only. Admission was not relaxed.

What the five trials show (one sample per code state, so none of these is a
rate):

- Qwen recognizes that static analysis does not answer a caller-value
  question, and selects the observation tool unprompted.
- With the kind note, it chooses `boot`.
- It does not confuse RAM with MMIO.
- It does not cite the observation it relied on, and it does not carry the
  scenario's scope into its prose claims.

## 9. Operation identity

- `function_effects` with `specialize` omitted, `null` or `{}` is
  semantically identical. `validate_request` maps `None` to `{}`, the
  executor passes `arguments.get("specialize") or {}`, and the cache key
  and result are the same.
- Operation keys are now computed over the defaulted form
  (`ARGUMENT_DEFAULTS`, listing only this tool and `observed_call_arguments`).
- The canonical ledger records only the `{}` form (7 invocations), so every
  persisted key is unchanged.
- Older omitted-form keys are still accepted on lookup (history and
  follow-up `performed`). No record was rewritten.
- A non-empty specialization stays distinct.

## 10. What would change the answer

| Finding | Effect |
|---|---|
| An observed slot-7/8 dispatch on a `0x14900` object | `b658` executes; its observed `r0` resolves the branch directly |
| A resolved indirect site (among the 56) loading `+0x1c`/`+0x20` from such an object | `c7c0` becomes statically reachable; a targeted scenario is then justified |
| A store to a `this+0x10` field or SERCOM word after initialization | the conditional bound in §7 no longer holds |
| Any reachable call passing `r0` in `[0x40002ffd, 0x400033ff]` | H1 (a SERCOM0 access through `b4b4`) |

## 11. Reproduce

```sh
tools/unicorn/.venv/bin/python3 tools/unicorn/test_call_observation.py
tools/unicorn/.venv/bin/python3 cases/performing-rigs/test/test_observe_scenarios.py
agent/.venv/bin/python tools/census/test_slot_dispatch.py
(cd agent && .venv/bin/python -m pytest -q tests/test_scenario_observation.py tests/test_observed_call_arguments.py)

# one observation (deterministic JSON)
tools/unicorn/.venv/bin/python3 cases/performing-rigs/scripts/observe_call_arguments.py \
    --firmware-key autopilot868 --entry 0xb4b4 --scenario boot --watch 0x20004c54:4

# the full corpus into a NEW scratch ledger (refuses the canonical one)
agent/.venv/bin/python cases/performing-rigs/scripts/sercom0_scenario_investigation.py \
    --ledger-dir "$TMPDIR/sercom0-v2-ledger"
```

Outputs are in `research/runs/sercom0-scenario-v2/`:

- `coverage.json`: the matrix and scenario categories;
- `observations.json`: full `b4b4` and `c7c0` results per scenario;
- `summary.json`: every step's evidence id, grade and limitations, the
  replays, the static sweep and the budget check;
- `live-planner.json`: the five live trials.

Two independent runs produced byte-identical observations and the same 61
evidence ids. Both replays matched.
