# Replacement firmware readiness

Investigation date: 2026-10-17. Role: APTrace operator. Target: POC 0.1 preparation for an independent replacement on the ATSAMD51J19A. No apfw2 files were read or changed. This report assesses evidence preparation, not electrical approval.

## Phase 0: repository and architecture

Initial checkout: clean `main`, HEAD `fa32c4bf239964ccfd76e48176f78c7676008636`; `HEAD...origin/main` = 0 ahead / 0 behind. This compares the locally available remote-tracking reference; no fetch or internet access was performed. `git -C agent status` and `git -C cases/performing-rigs status` resolve to the same clean root checkout. No uncommitted implementation was present. Recent commits: fa32c4b / 5105dd7 evidence-semantics documentation, 2f3513b LID audit, 3c21469 p-code baseline. No branch reconciliation performed.

**Repository update during investigation:** the user updated the checkout to `3750c3522da062ce8c48838f7bc201d9ef025eac`, still `main` and 0/0 against local origin/main. Intervening commits 096c58a/68c90cb add continuity measurements/hardware reconciliation; 9233314 adds `.codex/config.toml`; 3750c35 adds operator execution-autonomy instructions. These were not commits made by this investigator. The updated instructions and config were read: workspace-write, on-request approval, network disabled; repeated existing operations authorized, actual sandbox blockers reported. No analysis implementation changed between these revisions. The final exports incorporate the new raw bench sheet and explicitly flag conflicts with its narrative summaries. Initial and final source identities are retained separately.

Sources: `docs/status.md`, `docs/architecture.md`, `docs/tooling/tool-selection.md`, `docs/tooling/pcode-migration.md`, `docs/spikes/architecture-reconciliation.md`, `docs/arrows/cross-segment-findings.md`, `docs/architecture-reconciliation/evidence-semantics.md`, case `status.md`, and the case dossiers cited in the hardware contract.

Implemented: Ghidra structural discovery and intraprocedural p-code forward use; ARM/Capstone backward definitions remain in service. Macaw supplies independent discovery/lifting; Crucible/What4/Z3 supplies bounded symbolic constraints; Unicorn supplies concrete modeled observations. APTrace owns evidence, orchestration and verification. No general MCU simulator or composed target-invocation feasibility workflow exists. Solving constraints in either direction is supported in bounded symbolic questions; that is not proof of directional causation.

The p-code retirement plan explicitly says nothing listed has migrated. `research/runs/pcode-migration-baseline/migration-interruption.md` records a halted v3 attempt, not a working backward p-code engine. The architecture-reconciliation target-path slice and evidence-semantics D1–D12 / T1–T15 are proposals. Their acceptance tests are explicitly **not implemented, not run**. Passing current tests cannot establish these proposed rules.

## LID reconciliation

No X finding below is classified as remediated by this session. The latest semantics assessment refines several original findings; these refinements must not be mistaken for fixes.

| Finding | Current status / consequence for this investigation |
|---|---|
| X1 | Open policy/terminology issue. Resolved indirect targets can become census roots independently of their callers. `DEFINITELY_REACHABLE` is not demonstrated execution from reset. Callback `ESTABLISHED` has no agent consumer; that reduces this particular propagation risk. |
| X2, X12, X18 | Open: effects raw status drives grading; access guards/model conditions are insufficiently enforced; opaque direct callees limit absence. Do not derive universal runtime access or absence from effects summaries. |
| X4, X21 | Open: bounded observations can be STRONG and session facts uniformly PROVEN. Preserve scenario, bound and mode instead of adopting the planner's label. Positive observed events remain useful. |
| X6 | Open: strongest cited artifact can set unrelated fact ceilings; call-path ceiling uses maximum rather than weakest link. No grade promotion is performed here. |
| X10 | Open with corrected scope: table-scan/dynamic candidates do not enter `resolved_indirect_edges`; STRONG RAM-fnptr candidates do. Their closed-world assumptions remain relevant. Unknown legacy edge basis stays unknown, never presumed heuristic. |
| X11, X24 | Open lineage/seeding issues. Ghidra-derived census agreement is not independence. Prior Macaw agreement supports structure only; it does not independently verify GPIO values or execution. |
| X15 | Implemented **fail-closed safeguard**, not a resolved provenance gap: production sources lack required independence envelopes, and only CODE_EXISTENCE has a policy-v1 evidence contract. New production VERIFIED claims are unavailable. Current policy tests validate rejection/holding and fixture-only positive controls. |
| X14, X16 | Open audit/lifecycle concerns: coverage-gap/zero-budget falsification, and HOLD demotion. No audit or state-changing verification was run. |
| X3, X5, X7, X9, X13, X20 | Open identity/replay issues: incomplete engine/implementation identity, frozen historical grades, cached replay, missing inputs, stored versus recomputed grades and historical reuse. Preserve original evidence and distinguish fresh execution from archival summaries. |
| X22 | Open incompleteness issues, including bounded/truncated logs and failed leads. No incomplete search is used to assert universal absence. |
| X8, X17, X19, X23 | Open canonical-state hazards: check/invalidation, default writes, and nominal read paths that can write. No canonical ledger check, replay, audit, census migration or historical rewrite was performed. Ghidra output-cache writes are disclosed. |

Existing safeguards validated by 148 focused tests: typed semantic matching, call versus conditional target distinction, scoped call relations, unrelated versus material conflicts, same-lineage/repeated-engine rejection, missing-envelope hold, classes without contracts and protected historical decisions. These are implementation tests, not merely documentation checks. They do **not** establish general scope containment, polarity-aware grading, per-fact ceilings, unknown-facet fail-closed, or inference-rule enforcement proposed in T1–T15.

## Capability classification and gate

| Capability | Verdict | Exact constraint and POC relevance |
|---|---|---|
| Evidence retrieval / provenance | LIMITED | Existing files, hashes and ledger blobs are usable; historical producer identities vary (X3/X9). Missing provenance is retained as unknown. |
| Static / census interpretation | LIMITED | Code sites and bounded graph relationships usable; heuristic boundaries/roots do not demonstrate execution (X1/X10). |
| Ghidra p-code / function analysis | LIMITED | Forward use implemented and fixture-tested historically; no memory flow or backward p-code migration. Established pin paths need no rediscovery. |
| Unicorn / MMIO | LIMITED | Real instructions, bounded traces, explicit seeds/stubs; MMIO is memory without hardware register semantics. Suitable logical write-order reference, not waveforms. |
| Macaw / Z3 | LIMITED | Bounded solving works historically, including SAT witnesses/UNSAT guards; effects uses unrepaired discovery, opaque calls, no loop/write-value summary. Full ramp proof is unavailable. No new symbolic requirement justifies a solver run here. |
| IRQ / timer / peripherals | BLOCKED | General timing, autonomous timer expiry, nested exceptions and physical pin waveforms unavailable. AutoPilot recipe has zero interrupt bridges; no natural timed move can be certified. Explicit ISR entry only establishes handler-body behavior. |
| Claim admission | LIMITED | Existing typed/prose checks useful, but X2/X6/X10/X12/X18 remain. Documentary exports are not new admitted claims. |
| LID safeguards / verification | LIMITED | Existing fail-closed gate works; proposed evidence-semantics contract remains unimplemented. Production VERIFIED promotion is blocked (X15). |
| Machine-readable export | LIMITED | Native concrete JSON and existing case JSON usable; no universal trace completeness or physical-time guarantee. Export unknowns explicitly. |
| Reproducibility | LIMITED | Local firmware available and SHA verified; exact operation commands can be retained. Legacy narratives lack some original snapshots, cache replay is not fresh execution. |

**Gate: proceed** with independently supportable Phases 1–5. Stop at missing hardware models, ungrounded electrical interpretations and full-motion proofs. None requires bypassing safeguards to consolidate observed logical states. Evidence is sufficient for POC software preparation, **insufficient for first motor energization** until the bench requirements close.

## Execution and coverage

Read the operator methodology, architecture/LID records, current case status, pin/causal audits, bring-up, motor, persistence, TMC and physical-reference evidence. Verified AutoPilot868 SHA-256 `6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3`; application load base 0x4000. Address claims below apply to that image, not automatically to 915 MHz or bootloader.

Initial focused validation command:

```
agent/.venv/bin/python -m pytest agent/tests/test_claim_semantics.py agent/tests/test_claim_candidates.py agent/tests/test_call_relations.py agent/tests/test_verification_policy.py agent/tests/test_observed_call_arguments.py agent/tests/test_source_agreement.py -q
```

Result: **148 passed in 10.85 s**. Additional operations/results and native trace references are recorded in the hardware contract and test-vector export. No replacement tests or analysis engines were written.

Subsequent existing validation: `python3 tools/ghidra/test_pcode_forward_use.py` passed all checks, including actual Thumb/RV32 Ghidra fixture execution, incomplete-negative controls, determinism and unchanged scratch-project source. `tools/unicorn/.venv/bin/python3 cases/performing-rigs/test/test_concrete.py` passed all checks, including error versus completion, state isolation, carry-forward and logging controls. Initial sandbox failures (Java configuration access, native interpreter exit132) required permitted execution outside the sandbox; they were environment failures, not evidence of failed firmware semantics. No dependency installation or external research occurred.

Canonical ledger review: the generated report lists historical C2:v2 and C5:v1 as VERIFIED. Their records are respectively a static USB callback pointer finding (EV-d9343c6252f6f61a / EV-5399815447618e02) and a census-bounded EIC/USB NO_KNOWN_PATH (EV-bab8f6cc269494ab). Neither is a motor-safety or timed-motion claim. `test_persisted_case_verifications_predate_the_policy` passed: these decisions predate the current policy and do not pass it now. They were not reverified or rewritten. Reviewed EV-9bb45350b02d18c2 / EV-aec58644e0021efd retain heuristic boundaries, unresolved frontier and computed-pointer-store limitations; their common-path graph summaries do not prove execution. Firmware-inventory hashes are usable, but its old “Mando not analyzed” narrative is superseded by case status.

Coverage achieved: existing evidence consolidated for all five investigation phases; fresh native boot, control helper, channel-0 ISR-body, timer-init/stop/partial-period and reset-request traces retained. The newly available raw continuity sheet establishes mux A-to-driver routing, reported RJ45 resistance paths, TMC1 straps and reported serial-pin MCU connections. It does not close MCU STEP/DIR-to-driver mapping, control GPIO destinations, effective current, reset waveforms, actual timed movements, exact ramp coefficients, DIR setup or fault recovery. A historical control-enable ordering error was corrected in the new contract using disassembly and direct execution; historical sources were preserved. New hardware summaries call serial rows blank despite populated raw §6, and generalize TMC1 strap readings to all drivers; these conflicts are retained rather than promoted.

## Capability gaps and recommended next work

| Gap / evidence | Impact | Likely cause | Needed capability / priority |
|---|---|---|---|
| General timer/IRQ simulation absent; boot recipe `interrupt_bridges: []` | No bounded natural motion waveform, jitter, race or stop-latency proof | Deliberately narrow concrete harness | Evidence-grounded timer/IRQ model and external waveform validation; HIGH |
| Proposed semantics T1–T15 absent; current extraction/grading source and focused tests | Automated labels cannot substitute for per-fact scope/conditions | Artifact/status grading and qualifier loss | Implement reviewed contract in a separate development task; HIGH |
| Real independence envelopes absent, X15 / policy tests | No new production VERIFIED export | Producer integration incomplete | Producer identity/lineage plus qualified evidence contracts, after semantics; HIGH |
| Historical cache and identity gaps X3/X7/X13/X20 | Some archival findings cannot be reproduced from a summary alone | Mixed analysis generations | Versioned engines, inputs and uncached replay; MEDIUM |
| Full ramp/whole-call-tree symbolic composition absent, architecture reconciliation | No end-to-end legacy ramp or universal negative guarantee | Opaque calls, unrepaired discovery and missing composition | Bounded invocation-path feasibility and concrete witness replay; MEDIUM |
| Physical evidence now partly available, but MCU STEP/DIR/control mapping, effective current and reset observations remain absent; raw/summary conflicts | Cannot approve any control level or current for energization | Missing physical evidence and documentary reconciliation, not an APTrace engine defect | Use raw bench readings, close only remaining checklist items, obtain local device mode truth table; HIGH |
| `run_concrete.py` 216–232 forwards `--stop-at` only to raw `run`, not `--call`; bounded reset call ignores checkpoint | A caller expecting the requested checkpoint instead exhausts its budget | Confirmed CLI argument-forwarding omission | Pass/validate stop options for calls; LOW here, corrected by supported raw-entry invocation |
| Reset-request snapshot has empty MMIO log although final AIRCR memory is 0x05fa0004 | MMIO write stream alone omits PPB reset request | MMIO log window excludes PPB | Explicit PPB capture/export or disclosed memory/checkpoint evidence; MEDIUM |

Existing-capability work: retain/replay narrowly scoped concrete cases and inspect specific Ghidra functions when an implementation question remains. Development work: the model/semantics/identity items above, separately authorized. New-evidence work: continuity, current configuration, reset/startup and pulse measurements. No broad census, serial-bus hunt or LID remediation is warranted in this investigation.

## Final delivery state

Five requested files produced: three Markdown reports under `docs/replacement/`, two JSON exports under `research/generated/`. Native evidence, query excerpts, reproducible equivalent commands, source hashes and artifact-validation results are under `research/runs/replacement-firmware-readiness/`. Final consistency checks: 19 unique finding IDs; 10 native execution cases plus one explicitly reconstructed static expectation; all current source references/hashes match; exported writes/memory match native records; no captured MMIO log reached its configured cap. Source scope remains bounded despite that cap check.

At final inspection HEAD is 3750c35 on main, 0/0 against local origin/main. The only investigator-owned changes are these new case reports/exports/run artifacts (untracked). No implementation, configuration, test suite, prior ledger or historical finding was edited by this investigator, and no commit/push was performed. User-originated hardware/config/instruction commits during the run are separately recorded above. No required operation remains blocked solely by permission: earlier environment failures were rerun under the granted command rules; unresolved period/IRQ/reset/electrical questions are model/evidence limitations. No dependencies installed, network accessed or apfw2 files changed.

**Final verdict:** APTrace supports evidence extraction and POC 0.1 preparation with explicit LID and modeling constraints. It does not establish first-motor electrical readiness. Use the new physical trace file to avoid repeating settled measurements; resolve the raw/summary serial-mode conflict, missing MCU/control routing, effective current and reset/startup containment before energization. Do not equate creation of these artifacts with completion of those engineering requirements.
