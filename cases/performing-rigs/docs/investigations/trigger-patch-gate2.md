# Binary patch verification — Gate 2

2026-10-22. Research only; **NOT FOR HARDWARE DEPLOYMENT**. Operator investigation under `docs/codex-operator.md`. Baseline HEAD `6cf2bd904a3fdbfcab7e198ad28c9196e2067ef3`.

## A. Executive verdict

**INCONCLUSIVE.** The specified transient rejection and intentional initiation controls reproduce. The intentional control preserves the ordered 29,236 captured CPU write requests after instruction timestamps are removed. G, W1 and B1 reach their requested live-state boundary. No mandatory mitigation/initiation failure was demonstrated in these histories.

Material behavioral obligations remain unresolved: the fresh-input control changes global write ordering; unacquired-input polling also changes the bounded housekeeping trace; direct initiation controls do not capture ordered peripheral stores; and selected write ranges cannot exclude unexpected RAM/stack/peripheral effects elsewhere. These are reasons to withhold PASS, not evidence of confirmed corruption or physical malfunction. No defined mandatory preservation failure has been established, so FAIL would also overstate the evidence.

[Gate 1](trigger-patch-gate1.md) remains **INCONCLUSIVE**. These finite native observations do not close its integrated state/write, incoming-CFG, interrupt or physical-read timing obligations. Gate 3 was not executed.

## B. Artifact identity and execution provenance

| Input | Case-relative path | SHA-256 |
|---|---|---|
| Original915, 70768 bytes, base `0x4000` | `research/firmware/originals/firmware_autopilot915.bin` | `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |
| Research915, 70796 bytes, same base | `research/generated/trigger-patch-2026-10-22/RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_freshness.bin` | `ae9e6a749426fc3d800a0e26d016cc58f818ce8f84d5a7ba12c41d6d727bc616` |
| `tools/unicorn/concrete.py` | Repository backend | `fcf4529322de345b3f6dd7f4c373084b1957348ade2bb4c1d6acf285d6266f3b` |
| `tools/unicorn/run_concrete.py` | Repository public CLI | `e91dce33ec855c883dd9ba8ca7c1976020c096552e3300649399b682c3256735` |

Backend hashes match the authoring manifest. Documented interpreter: `tools/unicorn/.venv/bin/python3`, Python 3.9.6, Unicorn 2.1.4. All native commands were invoked directly using `--out` and no wrapper/redirection/security change. No initialization failures occurred. The [new packet](../../research/generated/patch-gate2-2026-10-22/README.md) preserves command files, raw snapshots, source identities, inspection displays and comparison outputs. The [original packet](../../research/generated/trigger-patch-2026-10-22/README.md), both authoritative images, source, tests, models and hardware were not changed.

Fourteen fresh original/patched replay snapshots are byte-for-byte identical to their corresponding historical decompressed snapshots, including recorded checkpoints, forces, writes and final state (`historical-replay-byte-comparison.txt`, all `cmp_exit=0`). Two additional instrumentation controls remove only `--watch-mem-write` arguments from the intentional recipes. Thus there are **16 fresh executions**, not a fresh 20-run campaign.

The existing authoring comparator `check-artifacts.py` was copied unchanged into the new packet because it derives its input/output directory from `__file__` and writes fixed names. Its SHA-256 is `bff7c6dc9d2fb98d75341b0028fae754aaab26705affc679dde60c02f478aaab`. It generated **138/138 passing artifact assertions** using 14 fresh raw files and six copied historical gzip files. Those six are analog X1/X2, held/W original/patched, release-fresh/W and late-release; they were **not rerun**. The checker and its authoring assumptions were inspected rather than accepted as an independent oracle. `checker-execution.txt` identifies the split and limitations. No new comparator, harness or tests were written.

## C. Differential execution results

### Comparable initial conditions and boundaries

`paired-command-differences.txt` compares tokenized command files: each original/patched pair differs only in firmware and output path. Each starts a fresh process/machine at application reset entry `0xcc24`, not through a physical bootloader. The CLI maps flash at `0x4000`, RAM `[0x20000000,0x20030000)`, MMIO `[0x40000000,0x44000000)`, the PPB and the extra calibration page. Registers are reset; initial SP defaults to RAM top `0x20030000` and startup establishes its actual frames. No retained RAM or physical nonvolatile device state is imported. Initial mapped memory, explicit seeds, placeholder calibration, stack initialization and all force/watch arguments are otherwise the same. The added image bytes are the intended input difference.

Disclosed environment includes a tick increment at `0x200052ec` every 4000 executed instructions, stubbed `0xcd34`, forced radio response at `0x9dd4`, ADC/DWT/input values and completion/status read overrides. Remote program and MC4 payloads are supplied at established receive/parser boundaries (`0x94b8`, `0x81ca`), allowing original firmware reconstruction downstream; this does not reproduce an RF/USB exchange. No counter-forcing or interrupt train is added. Hardware timers, peripheral side effects and interrupt scheduling remain the existing modeled assumptions, not physical devices.

Input histories are **PC-indexed, repeated rules**, not calibrated electrical waveforms or a fixed wall-clock stimulus. In particular the transient forces PB05 LOW at `0x9228`, then HIGH at `0x922c` on every hit. The two images therefore receive the same modeled rule, but different paths can produce different polling counts and tick phases. An added instruction also changes when instruction-count ticks land relative to firmware operations. Equivalent setup is established; equivalent physical time is not.

All fresh runs have `error=null`, `execution_mode=memory-hook-single-step`, no watch-cap stop and zero dropped captured writes. Fourteen-million-instruction histories intentionally end with `completed=false`, `instruction limit reached`; they are bounded observations, not completed applications. G/W1/B1 end with `completed=true` at requested `0x5fa6`, before executing that instruction. The prior live-store at `0x5fa4` has executed. No mere completion flag is used as proof of initiation.

| History | Original | Patched | Differential interpretation |
|---|---|---|---|
| Saved-LOW/current-HIGH transient | Acceptance `0x8f98` once; initiation `0x5f8c` once; timer precursor `0x571c` twice; `0x5810` once | 230 entries at `0x15470`, 230 fresh returns at `0x1547c`, each r0=1; none of those acceptance/initiation/precursor PCs | Targeted rejection reproduced through 14M; selected writes 29,236 versus 29,899 reflect different subsequent execution, not equal traces. |
| Intentional LOW | One acceptance and start; 29,236 writes | One acceptance and start; 29,236 writes | Full selected ordered projection equal; acceptance +24 instructions. |
| Fresh intentional (HIGH first read, LOW at comparison site) | One acceptance/start; 29,260 writes | One acceptance/start; 29,260 writes | Acceptance +26 instructions; named TC0/serial/motor GPIO streams equal, global ordered projection unequal. |
| Unacquired (HIGH returned, LOW after read) | No acceptance/start; 224 site observations; 30,322 selected writes | No acceptance/start; 226 site/extension entries, no second-read returns; 30,211 writes | Nonzero bypass exercised; bounded housekeeping/polling trace differs. Neither begins motion. |
| G initiation | Stop `0x5fa6` at 12,154,616 instructions | Same boundary at 12,154,618 | One `0x5f8c`, `0x571c`, `0x5810`, `0x5fa4` each; matching dumped TC0/live state and terminal registers. |
| W1 nonzero initiation | Stop at 12,348,366 | Same boundary at 12,348,380 | Same initiation checkpoints, dumped TC0/live state and terminal registers; +14 total instructions is not a physical delay measurement. |
| B1 full-reset initiation | Stop at 11,357,618 | Same boundary/count | Same initiation checkpoints, dumped TC0/live state and terminal registers; extension never entered in this history. |
| Intentional, no write watches (two runs) | Same per-image final registers/dumped memory and 14M boundary as watched original | Same per-image final registers/dumped memory and boundary as watched patch | Removing write collection did not change these inspected states. MMIO hooks still require single-step mode. |

### Transient causation and observed state

`transient-checkpoint-inspection.txt` shows both images at `0x922c`, instruction 12,098,771, with identical captured registers: r0=0, SP=`0x2002ffb8`, LR=`0x922d`, CPSR=`0x40100033`; input memory already contains `20000000` (PB05 HIGH), idle byte `0x200000d8=9` and live `0x20001b14=0`. This is the matched old-sample/current-input discrepancy, before the changed instruction executes.

The original reaches acceptance two instructions later, then `0x5f8c` at 12,327,006 and `0x5810` at 12,327,140. The patch reaches its new entry at 12,098,772 and fresh-read return at 12,098,793 with r0=1, SP=`0x2002ffa0` (24 bytes lower), LR=`0x1547d`. Continued polling, rather than acceptance, follows. The instruction itself at `0x9232` is not a watched checkpoint in these recipes; its routing is corroborated by Gate 1's decoded graph, not claimed as a new direct checkpoint observation.

Final patched TC0 dump is `0006000000020000001000000100000000000000000000000000000000000000` (CTRLA low byte `00`); original is `02010000000000000010000001000000000000000000000000000000659f0000` (enable bit set). The patch does not reach the identified enable path in this bound. This supports rejection before activation, not physical timer or motor inactivity certification. Startup GPIO/driver traffic exists in both; “no firmware writes at all” would be false.

### Ordered writes and state preservation

The unchanged comparator's `project` uses **ordered tuples `(pc,address,size,value,previous)`**, not write count alone. For the intentional control all 29,236 tuples match. Instruction count is deliberately excluded; LR/range labels are also not part of that equality. The named TC0, serial and motor GPIO comparisons provide additional projections. No dropped records are reported.

Captured ranges are `0x200025e0:2`, `0x20001b14:4`, `0x40003800:32`, GPIO group A/B output command ranges `0x41008014:12` and `0x41008094:12`, and `0x43000428:4`. They are selected CPU store **requests**, not every write, physical pin transitions, successful driver transactions or movement. Direct `mem_write` injections for ticks, seeds and force rules bypass CPU store hooks; their provenance is separately recorded in `applied_seeds`, `force_mem_hits`, `force_reg_hits` and tick/override records. They must not be counted as firmware output requests.

At intentional/fresh acceptance the existing checker compares r0-r12, SP and LR and the motor record. Both pass. It does not compare CPSR in that assertion or certify all live RAM. Intentional final selected memory agrees, but final registers/PC at the same 14M count differ because the patch adds instructions: those are different program points, not demonstrated register corruption. Direct G/W1/B1 terminal checkpoints instead have matching register dictionaries, including CPSR/SP/LR (`direct-controls-inspection.txt`).

The direct controls collect only the configuration-state write range: seven G writes, three W1 writes, **zero B1 captured writes**. G records match address/value/order after instruction shifts; W1's three startup records match, and B1 provides no ordered peripheral-write evidence. Zero B1 captured writes does not mean B1 performs no stores. Its initiation and enabled TC0/live state are observed independently. A claim that these recipes verify all G/W1/B1 output-write ordering would be unsupported.

## D. Gate 2 verification matrix

Evidence references below are relative to the new packet unless identified as historical. VERIFIED always means finite modeled conditions, not universal correctness.

| Property | Disposition | Evidence, method and limits |
|---|---|---|
| Original transient behavior reproduced | **VERIFIED** | Fresh `transient-original.json`; matched old r0=0/current HIGH, acceptance and original initiation/enable checkpoints. Whole snapshot equals historical record. |
| Patched transient rejection reproduced | **VERIFIED** | Fresh patched record and existing checker: 230 actual fresh-HIGH returns, no acceptance/initiation through 14M. Repeating PC rule, not measured physical transient. |
| Rejection precedes acceptance or TC0 enable | **VERIFIED** | New-entry/read-return observations followed by continued polling; zero `8f98/571c/5810/5f8c` hits and disabled final TC0 in bound. Gate 1 supplies decoded rejection exit. |
| G initiation preserved | **VERIFIED** | Both fresh G records reach watched start/enable/live-store and requested stop; equal terminal TC0/live and register state. Does not verify complete output trace. |
| W1 initiation preserved | **VERIFIED** | Equivalent W1 observations; +14 instruction count retained. No physical timing guarantee. |
| B1 initiation preserved | **VERIFIED** | Matching B1 checkpoint sequence/count and terminal state, despite no captured write requests in its selected watch range. |
| Intentional-control write sequence preserved | **VERIFIED** | `outcomes.json`, unchanged comparator: all ordered 29,236 `(pc,address,size,value,previous)` tuples equal after timestamps removed. Applies to LOW intentional history only; fresh-input global equality is false. |
| No unexpected side effects in exercised paths | **INCONCLUSIVE** | Selected acceptance/register/memory equality and named write streams support preservation; unobserved stack/RAM effects and changed global housekeeping order remain unresolved. |
| Comparisons use equivalent conditions | **VERIFIED** | Paired command differences only image/out; fresh machine and common model/seeds/hooks/budgets. Scope is PC-indexed/instruction-clock simulation; no claim of equal physical timestamps. |
| Instrumentation does not invalidate conclusions | **INCONCLUSIVE** | Corrected single-step backend, exact 14 historical replays, and two no-write-watch state controls support reliability. No model-independent peripheral timing/interrupt oracle or comprehensive trace noninterference certificate for these histories. |
| Relevant behavioral paths adequately exercised for Gate 2 | **INCONCLUSIVE** | Targeted veto, permitted continuation, nonzero bypass and direct initiation all reached. Exact exit/stack-after-pop checkpoints, full ordered direct-control peripheral traffic and meaningful cross-peripheral ordering equivalence remain uncovered. |

## E. Behavioral differences and classification

| Difference | Classification and basis |
|---|---|
| Transient fresh-HIGH veto prevents acceptance/enable | **Intended.** Matched checkpoint plus added read causes the specified rejection. Subsequent idle-loop traffic is not expected to equal an accepted-motion history. No claim of complete rejection-side-effect confinement. |
| Intentional extra read and +24 acceptance instructions; fresh +26 | **Intended local work.** Captured requests and initiation are preserved under the respective stated projections. Absolute timing preservation is not established. |
| Temporary 24-byte stack frame; fresh leaf LR | **Intended local state change.** Observed SP/LR at `1547c`, restored acceptance registers in permitted controls. Rejected-path whole-frame preservation remains Gate 1 INCONCLUSIVE. |
| Fresh-control global ordering difference | **Unresolved / potential regression.** Historical `fresh-control-ordering-difference.json` records 357 differing indices; byte-identical new snapshots reproduce its inputs. First divergence at index 9705 is GPIO `0x41008014 <- 0x80000` versus TC0 `0x40003805 <- 0x80`; later serial/TC0 housekeeping interleaves differently. Equal named streams do not prove cross-device ordering harmless. No requirement/evidence establishes that this interleaving is benign, nor that it violates required motion behavior. |
| Unacquired history: 224 versus 226 polls and 30,322 versus 30,211 selected stores | **Unresolved phase-sensitive difference.** Added bypass instructions and instruction-clock timing change scheduling at the common budget. Both remain noninitiating; no event-aligned semantic comparison isolates all differing writes. Do not call its entire trace preserved or benign. |
| G +2, W1 +14 instructions, unchanged initiation states | **Observed initiation preservation; timing significance unresolved.** A nonzero patch bypass is observed in these histories; the full count difference is not translated to calibrated time. |
| Terminal registers differ at a fixed instruction count | **Not by itself a corruption finding.** Program points differ. State preservation must use corresponding checkpoints, not budget endpoints. |
| Held/W repeat initiation and post-read release still accepted | **Known safety limitations, historical only.** Original packet retains counterexamples; no release-to-rearm or post-read atomicity policy is claimed. They were not new Gate 3 tests or newly reproduced in this gate. |

No confirmed regression against a defined preservation requirement was established. “Unresolved” is deliberately not “benign.” The fresh-control contradiction was already documented; it remains visible rather than normalized away by per-stream comparison.

## F. Coverage, reliability and limits

Actual paths include old-sample-zero/fresh-HIGH veto, old-zero/fresh-LOW continuation, old-nonzero bypass without second read, and the G/W1/B1 original motion-initiation route. B1 never enters the extension in this replay; it is a useful preserved producer, not coverage of patched code. Watched points establish exercised paths; `visited_pcs` is not populated by these recipes, so no complete instruction/basic-block coverage percentage is asserted. Patch exits and every save/pop instruction are decoded, not individually watched in these dynamic runs.

All 14 main replay records reproduce exactly, ruling out observed run-to-run nondeterminism for those repeat samples. Removing write watches changes neither inspected final registers/memory nor boundaries/ticks for each intentional image. Those controls still have MMIO read hooks and remain single-step; they do not compare corrected hooked execution with fully hook-free continuous execution, which would require changing the peripheral model. The [write-watch repair](write-watch-instrumentation.md) and pinned hashes are relevant support, not proof against every native-engine defect.

The remaining limits are significant: chosen RX payloads and MMIO completion assumptions, no physical clock calibration, no asynchronous RF or physical pin waveform, no continuous real timer/interrupt/STEP service, no full RAM/stack write capture, no exhaustive interleavings or all-program-state exploration. Current firmware conclusions concern CPU requests in these models. No RF reliability, flash integrity, bootloader behavior, deployment suitability or motor operation follows.

## G. APTrace capability assessment

APTrace directly executed original firmware instructions, applied the recorded scenarios, captured checkpoints/registers/memory and selected ordered CPU stores, and recorded stop/error/drop information. Its existing case comparator performed ordered tuple/stream comparisons and acceptance/register/motor-record checks. These are stronger than counts alone.

Codex selected histories, invoked direct CLI commands, redirected only the CLI's **output path**, staged the unchanged comparator/inputs to preserve its fixed-path historical outputs, inspected command token differences and snapshot fields, and interpreted the results. Standard `gzip`/`cmp` established raw replay identity. No new comparison semantics or replacement verification scripts were added. The comparator is still the authoring comparator, not an independently implemented semantic oracle. The copied six historical inputs explain why its assertion count exceeds freshly replayed scope.

| Capability gap | Impact / evidence | Needed improvement and priority |
|---|---|---|
| Reusable differential replay/comparison operation | Existing CLI runs one image; case-specific checker has fixed paths, fixed history names, projections and no fresh/historical distinction. Operator manually orchestrated 16 runs and staged unchanged files. | **High, general-purpose:** pair manifest, output-directory/input selection, model/input identity, fresh provenance, explicit comparator policy and checkpoint correspondence. |
| Semantic event/time alignment | Instruction-clock changes alter poll counts and cross-peripheral interleaving. Existing checker reports global mismatch but cannot classify required ordering or align common semantic events. | **High, general-purpose:** event-aligned trace diff with justified normalization, explicit temporal/ordering requirements and preserved counterexamples. Do not erase mismatches by sorting. |
| Complete bounded state/side-effect comparison | Sparse ranges and acceptance checks omit stack-after-return and most RAM; direct G/W1/B1 recipes omit ordered peripheral writes. No supported integrated certificate was located. | **High, general-purpose:** differential state/write sets at declared exits with observer coverage, path completion and interrupt assumptions. Case would supply relevant boundaries/register contracts. |
| Scenario-level noninterference/model coverage | Existing synthetic watch regression and two controls support the workaround, but cannot remove MMIO hooks while preserving this model. Physical synchronizer latency is absent. | **Medium for simulation / high for hardware claims:** reusable instrumentation variants with model equivalence and explicit unsupported peripheral semantics. |
| Behavioral coverage export/report | Native engine can collect visited PCs, but these authoritative recipes do not request it; watch hits are sparse. | **Medium, existing capability not exercised:** future bounded replays may collect coverage through the public option. No new tests were added here. |

These are capability findings, not implementation work. A malformed inspection loop initially used zsh's read-only `history` variable; it was rerun with `replay_case` before generating command differences. Neither that inspection failure nor a missing aggregate command-file lookup affected execution. There were no aborted native runs to suppress. The 14M budget terminations are retained as incomplete application executions. No repeat firmware campaigns were needed after exact historical reproduction and targeted instrumentation controls.

## H. Gate 3 readiness

The image is a reproducible **research candidate** for later bounded adversarial exploration, carrying Gate 1 and Gate 2 uncertainties; neither gate is certified PASS. Highest-value later questions are event timing around the second read, held-input/W reauthorization, release/re-arm requirements, eligibility/startup transitions, and whether changed cross-peripheral order affects authorization. Existing counterexamples must remain controls, not requirements Gate 2 silently removes. Resolve the semantics of the observed ordering differences before labeling them harmless. No new Gate 3 histories, timing sweep or safety-policy proof was run here.

## I. Overall verification state

| Item | Current state |
|---|---|
| Gate 1 | **INCONCLUSIVE**, unchanged |
| Gate 2 | **INCONCLUSIVE**; targeted mitigation and specified initiation/LOW-control sequence reproduced |
| Gates 3–5 | **NOT RUN** |
| Full safety policy | **NOT ESTABLISHED** |
| Hardware deployment | **NOT APPROVED** |
