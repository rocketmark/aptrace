# Sweep 1 — agent ledger subsystem

Scope: `agent/src/aptrace_agent/ledger/` (18 files), `ledger_cli.py`, `ledger_wiring.py`, and 8 test files. All 28 files were read in full (about 11,750 lines). Line numbers refer to the files at the time of the sweep (branch `feat/pcode-indirect-target`).

## Production files

```yaml
- path: agent/src/aptrace_agent/ledger/__init__.py
  purpose: Package docstring describing the three authorities (investigation model, audit model, APTrace verifier); re-exports the main types.
  exports: AuditRecord, AuditVerdict, ClaimState, ClaimType, ClaimVerifier, ClaimVersion, EvidenceArtifact, EvidenceGrade, ExecutionContext, InvestigationRun, LedgerImmutableError, LedgerOperationRunner, ResearchLedger, ToolInvocation, VerificationRecord
  dependencies: ledger.models, ledger.operations, ledger.store, ledger.verifier
  data_shapes: none (re-exports)
  side_effects: none (importing it pulls in operations -> schemas, and verifier -> gate/policy/claim_semantics/call_relations)
  role: package facade
  observations:
    - 4-11 docstring states that only APTrace moves a claim to VERIFIED, BLOCKED, STALE or SUPERSEDED, and that the audit model never changes claim state.

- path: agent/src/aptrace_agent/ledger/hashing.py
  purpose: Canonical JSON, a sha256 digest of it, and a streaming file sha256.
  exports: canonical_json, digest, file_sha256
  dependencies: hashlib, json, pathlib
  data_shapes: any JSON-serialisable value -> str (hex digest); Path -> hex or None
  side_effects: file_sha256 reads the file in 1 MiB chunks
  role: identity / hashing utility
  observations:
    - 12 canonical_json uses sort_keys, compact separators, ensure_ascii=False, and default=str, so non-JSON values are stringified silently.
    - 22-23 file_sha256 returns None for a missing path. Callers (ledger_wiring.context_artifacts:70) drop missing artifacts from the context without saying so.

- path: agent/src/aptrace_agent/ledger/models.py
  purpose: Frozen pydantic records for the durable ledger (runs, invocations, evidence, claims, lifecycle events, audits, verifications, policy gate, admission/candidate/continuity provenance).
  exports: LEDGER_SCHEMA_VERSION, EvidenceGrade, GRADE_RANK, ClaimType, ClaimState, AuditVerdict, APTRACE_ACTORS, ExecutionContext, SourceRevision, FollowUpProvenance, OperationReuse, ReuseRefusal, SeededLeadOutcome, ContinuityRecord, ClaimDiagnostic, ClaimAdmission, ClaimCandidate, CandidateWithheld, CandidateSelection, InvestigationRun, ToolInvocation, Limitation, EvidenceArtifact, ClaimVersion, version_key, parse_version_key, LifecycleEvent, AuditStep, FollowUpRequest, AuditRecord, VerificationCheck, PolicyRef, GateCondition, PolicyGate, VerificationRecord
  dependencies: pydantic (BaseModel, ConfigDict, Field, model_serializer), ledger.claim_semantics (ClaimSemantics, SemanticCheck); ledger.hashing (lazy import, 106)
  data_shapes: All records use extra="forbid", frozen=True (88). Key ids are ExecutionContext.context_id "X-"+16 hex (108) and the claim version key "C<n>:v<N>" (460-466).
  side_effects: none
  role: data model / schema
  observations:
    - 19 LEDGER_SCHEMA_VERSION = 1. It is a field on InvestigationRun, ClaimVersion, AuditRecord and VerificationRecord.
    - 22-46 EvidenceGrade ordering EXACT>STRONG>PROBABLE>BOUNDED>UNKNOWN. The docstring ties EXACT/STRONG to the census indirect_edge_candidates.confidence vocabulary.
    - 49-62 ClaimType includes UNREACHABLE, which "no current APTrace analysis establishes".
    - 84 APTRACE_ACTORS = {aptrace-ledger, aptrace-verifier, aptrace-staleness}. Model actors are deliberately absent.
    - 95-97 ExecutionContext.artifacts names the inputs census_db, ghidra_export, firmware_image, svd and ghidra_seeds. SVD is a Cortex-M/CMSIS concept.
    - 100 ExecutionContext.case is a free string, so the case identity is carried in every evidence identity.
    - 238-245 and 359-367 custom wrap serializers drop unset optional fields (candidate_id; work_item_id, followup, continuity, claim_admission, candidate_selection) so older serialized records stay byte-identical. This keeps historical records compatible.
    - 317 run kind values: investigation | audit | benchmark-setup | replay. These are free strings, not an enum.
    - 388 ToolInvocation.status is a free string (ok | error). 474 LifecycleEvent.state is a free string (a ClaimState, or VALID/INVALIDATED for evidence).
    - 496-503 the AuditStep outcome vocabulary is versioned "audit-v0.4+". It is absent on older records.
    - 535-555 AuditRecord audit-v0.4+ fields default so that older records load.
    - 565-568 VerificationCheck.phase: A structural, B semantics, C replay/freshness, P policy, D audit.
    - 630 VerificationRecord.mode is precheck | full. 638 policy=None marks a record that predates the policy.
    - 641-644 VerificationRecord.note embeds the meaning of "Verified" in every record.

- path: agent/src/aptrace_agent/ledger/store.py
  purpose: Append-only, content-addressed filesystem ledger. Writes each record once, stores result blobs by content address, folds lifecycle state from events.jsonl, and propagates staleness.
  exports: LARGE_BLOB_BYTES, EVIDENCE_VALID, EVIDENCE_INVALIDATED, LedgerError, LedgerImmutableError, now, new_id, ResearchLedger, ensure_key
  dependencies: ledger.hashing, ledger.models, ledger.policy.current_policy, ledger.semantics (canonical_arguments, canonical_result, evidence_grade, evidence_limitations, inherited_limitations)
  data_shapes: The directory layout is in the docstring (4-13): runs/, invocations/, evidence/, blobs/<sha[:2]>/, blobs-large/, claims/<id>/v<N>.json, audits/, verifications/, events.jsonl.
  side_effects: Filesystem reads and writes under the ledger root (mkdir, exclusive create "x", append to events.jsonl). new_id uses the wall clock and secrets.token_hex.
  role: persistence / lifecycle authority
  observations:
    - 61-63 LARGE_BLOB_BYTES = 4 MiB. Larger results go to blobs-large/, which "a case may keep out of version control".
    - 69-71 staleable states are {PROPOSED, VERIFIED}. States that trigger staleness are {SUPERSEDED, STALE, BLOCKED}.
    - 100-113 _write_once compares parsed JSON. A semantically equal rewrite is a no-op and a different one raises LedgerImmutableError. It writes with open("x").
    - 131-143 put_blob skips the write if the path exists, without checking the existing content.
    - 160-169 load_blob returns (value, integrity_ok) by re-digesting the parsed JSON.
    - 183-211 operation_key = digest(tool, canonical arguments, input artifacts, firmware_sha256). operation_keys also returns the key over the arguments as recorded, for records written before defaults were canonicalised.
    - 233 invocation_id = "TI-"+digest(run, seq, op)[:16]. 240 evidence_id = "EV-"+digest(op, result_sha)[:16]. Identical operation plus identical result gives one evidence id across runs (244 reuses the existing artifact).
    - 264 path_status is filled only for tool == "census_common_paths". 265 the summary is result.planner_summary truncated to 600 characters.
    - 316-319 the next claim id is the maximum numeric C<n> directory + 1. This is not safe under concurrent writers.
    - 395-417 propose_claim always writes version 1 at PROPOSED (actor aptrace-ledger), inheriting evidence limitations mechanically (_inherit 363-368).
    - 419-453 supersede_claim refuses a non-latest base (428-429), recomputes inherited limitations unless limitations were passed explicitly (436-438), sets the old version SUPERSEDED, and propagates staleness.
    - 488-495 transition rejects non-APTrace actors, rejects VERIFIED from anyone but aptrace-verifier, and rejects unknown or unversioned keys.
    - 515-546 _require_policy_verification: VERIFIED must cite a full verification of this exact version with outcome VERIFIED, policy == current_policy(), and gate PASSED under the same policy.
    - 504 the event seq is len(events)+1, computed by re-reading the whole file. 548-559 state() scans all events. Both are O(n) per call. There is no locking.
    - 574-598 invalidate_evidence appends an INVALIDATED event (once) and stales claims that cite the evidence as supporting. Claims that cite it only as contradictory are not staled.
    - 603-638 propagate_staleness is a BFS over depends_on, transitive, with no repair.
    - 673-680 the fingerprint covers events text, claim keys and audit file names. It does not cover evidence, runs or verifications.

- path: agent/src/aptrace_agent/ledger/semantics.py
  purpose: Deterministic per-tool evidence grading, mechanical limitation codes, result and argument canonicalisation, and the absolute-negative wording guard.
  exports: limitation code constants (COMPUTED_POINTER_WRITES ... ABI_MODEL, 27-58), ABSOLUTE_NEGATIVE_RE, asserts_absolute_negative, VOLATILE_RESULT_FIELDS, canonical_result, ARGUMENT_DEFAULTS, canonical_arguments, evidence_grade, evidence_limitations, inherited_limitations, grade_ceiling
  dependencies: aptrace_agent.census_graph (NO_KNOWN_PATH_LIMITATION, RESOLVED_INDIRECT_LIMITATION), ledger.models
  data_shapes: (tool, result dict) -> (EvidenceGrade, basis str); (tool, args, result) -> sorted [(code, text)]
  side_effects: none
  role: evidence semantics / grading policy
  observations:
    - 60 _FUNCTION_RE FUN_[0-9a-f]{8} assumes 32-bit Ghidra default names.
    - 62-86 asserts_absolute_negative is a regex guard with a 40-character look-behind for negators.
    - 97-99 VOLATILE_RESULT_FIELDS strips only function_effects.provenance.cached.
    - 128-131 ARGUMENT_DEFAULTS: function_effects.specialize={} and observed_call_arguments scenario="boot", watch=[]. These identities depend on other modules' validate_request behaviour (documented 124-127).
    - 161-267 evidence_grade is one if-chain per tool name, covering 13 tools. An unknown tool gets UNKNOWN (267). function_effects "complete*" -> STRONG "symbolic extraction, not solver-confirmed" (204). value_forward_use NO_ESCAPE complete -> BOUNDED, ESCAPE -> PROBABLE (249-259).
    - 194-195 function_disassembly, callsite_context and pin_table_entry are graded EXACT ("decoded from the hash-verified firmware image").
    - 301-309 the census_common_paths label convention is split on "+". "IRQ:" prefixes and FUN_ names are skipped. Other parts get PERIPHERAL_SET_IS_MMIO_USAGE:<part>.
    - 315 the specialisation text formats values as hex.
    - 363-367 the "virtual-link" scenario kind is special-cased (NON_BOOTED_STATE). This looks like a case-specific scenario name in framework code.
    - 450-453 the value_forward_use limitation text names the calling convention generically (no ISA tokens).
    - 489-509 grade_ceiling takes the maximum grade over supporting evidence. A BOUNDED artifact counts as STRONG only for NO_KNOWN_PATH claims.

- path: agent/src/aptrace_agent/ledger/claim_semantics.py
  purpose: Typed claim predicates (pydantic) and their deterministic verification against structured evidence fields.
  exports: Predicate, FunctionRole, SetKind, CallEdgeKind, CheckCode, to_int, addr, fun, SetScope, ResolvedPointer, FunctionRoleClaim, PathRelation, CodePresence, CallRelation, ClaimSemantics, COMPATIBLE_CLAIM_TYPES, PATH_CLAIM_TYPE, SemanticCheck, PointerFact, RoleFact, PathFact, EvidenceFacts, _maybe_int (imported by gate.py), extract_facts, check_resolved_pointer, check_function_role, check_path, check_code_presence, verify_semantics
  dependencies: pydantic; lazy ledger.call_relations.typed_call_checks (822)
  data_shapes: ClaimSemantics has a predicate and exactly one body (284-297). Addresses normalise to 0x%08x and functions to FUN_%08x (122-127).
  side_effects: none
  role: typed claim model / semantic verification
  observations:
    - 24-36 there are five predicates. 39-54 eight roles. 57-70 SetKind includes INTERRUPT_DISPATCH_SET, which "no current APTrace analysis produces".
    - 80-90 the CallEdgeKind docstrings are ARM-specific ("decoded BL/BLX immediate", "B/B.W/B<c>.W").
    - 102-127 FUN_ regex up to 8 hex digits and addresses up to 8 hex digits, formatted as 32-bit. This assumes a 32-bit address space.
    - 259-263 a CallRelation validator requires conditions for POTENTIAL_INDIRECT and a scenario for OBSERVED_DISPATCH.
    - 322-328 COMPATIBLE_CLAIM_TYPES maps each predicate to the claim types it may accompany.
    - 384-394 _EDGE_FIELDS maps census resolved_indirect edge keys to pointer fields.
    - 412-423 _census_containing reads the source literally named "census" from structural agreement observations.
    - 458-459 and 501-508 "USB" is hardcoded for census_usb_inventory (SetKind.INTERFACE_INVENTORY, MMIO_USER peripheral="USB"). This is case/peripheral-specific coupling in a framework module.
    - 516-524 a census_peripheral_usage function is MMIO_USER only with mmio sites, and ADDRESS_CONSTANT_LOADER with constant loads only.
    - 535-537 a function_effects access in an "MMIO*" region becomes MMIO_USER, with the peripheral taken from the register_name prefix.
    - 626-635 the raw/canonical check masks bit 0 and reports "canonical Thumb target". This is Thumb-specific.
    - 797-826 verify_semantics: claim-type compatibility check, then dispatch on the body.

- path: agent/src/aptrace_agent/ledger/claim_checks.py
  purpose: Shared deterministic claim-quality checks (entity identity, peripheral access/absence) and the stable diagnostic-code vocabulary for admission and verification.
  exports: REJECT, NOTE, PATTERN, all diagnostic code constants (43-78), entity_diagnostics, access_diagnostics, _clause_negated (private)
  dependencies: ledger.claim_semantics (FunctionRole, extract_facts, to_int), ledger.models.ClaimDiagnostic
  data_shapes: text -> [ClaimDiagnostic]; (assertion, [(artifact, result)]) -> [ClaimDiagnostic]
  side_effects: none
  role: claim admission / verification checks
  observations:
    - 2-27 the docstring says the access rules are applied by pattern-matching the assertion wording and are marked basis=pattern-matched.
    - 82-89 the malformed-identifier regex flags letter-prefixed zero-padded hex (e.g. E0000b4b4), FUN_ names of the wrong width or case, and bare zero-padded hex.
    - 93 bare "E<n>" session evidence ids in the assertion are rejected (ENTITY_SESSION_REFERENCE).
    - 95 the numbered-peripheral regex [A-Z]{2,6}\d{1,2} (SERCOM0, TCC1, ADC0) is Microchip SAM naming.
    - 174 un-numbered peripheral names "USB" and "EIC" are hardcoded. These are SAMD51 peripherals.
    - 225-234 the absence check needs function_effects coverage == "complete" and no parametric accesses.
    - 241-251 qualified wording (observed/recorded/symbolic/unknown...) downgrades an absence rejection to the ABSENCE_SCOPED note.
    - 75-78 the candidate-selection codes are defined here but used in research/candidates.py (out of scope).

- path: agent/src/aptrace_agent/ledger/call_relations.py
  purpose: Extracts call edges, unresolved sites and enumerations from structured evidence. Checks prose (pattern parser) and typed CALL_RELATION assertions against them at the asserted kind, scope and grade.
  exports: CallAssertion, CallEdge, CallFacts, Finding, MODALITY_KINDS, STATIC, SUPPORTS, call_diagnostics, check_absence, check_edge, check_reach, extract_call_facts, parse_assertions, typed_call_checks, typed_grade_diagnostics (plus typed_finding, assertion_findings, Scope, UnresolvedSite)
  dependencies: ledger.claim_checks (CALL_* codes, GRADE_ABOVE_CEILING, NOTE, PATTERN, REJECT), ledger.claim_semantics (CallEdgeKind, CallRelation, CheckCode, SemanticCheck, addr, fun, to_int), ledger.models (GRADE_RANK, ClaimDiagnostic, EvidenceGrade)
  data_shapes: CallEdge(source, target, kind, evidence_id, site, conditions, condition_addresses, scenario); CallFacts aggregates edges, unresolved, callers_listed, callees_listed, entered, census_reach, site_owner, grades.
  side_effects: none
  role: claim checking (call relations)
  observations:
    - 1-54 the docstring defines the edge sources per tool and the support rules. It references docs/claim-call-relations.md.
    - 152-153 _BRANCH_RE and the mnemonic checks at 183-186 are ARM/Thumb-specific: bl/blx -> DIRECT_CALL, b<cond>(.w/.n) leaving the extent -> TAIL_TRANSFER. This is Capstone/Ghidra disassembly text interpretation in Python, an ISA-specific path. Under CLAUDE.md rules this is ISA-specific custom instruction interpretation.
    - 156 _MIN_CONDITION_ADDRESS = 0x100 is a heuristic threshold for condition addresses.
    - 189-216 indirect_call_target results: STATICALLY_ESTABLISHED with an ESTABLISHED derivation -> ESTABLISHED_INDIRECT. Anything else -> POTENTIAL_INDIRECT with conditions and named condition addresses (vtable, entry_addr, slot_addr, addresses in basis).
    - 219-253 callback_argument_provenance callers become DIRECT_CALL/TAIL_TRANSFER edges. Candidate targets are always POTENTIAL_INDIRECT ("never categorical, even for a closed caller set").
    - 256-277 observed_call_arguments: OBSERVED/DYNAMIC_ONLY with hits>0 -> OBSERVED_DISPATCH. OBSERVED/UNOBSERVED with a caller -> DIRECT_CALL. The scenario defaults to "boot".
    - 332-341 census resolved_indirect_edges with EXACT/STRONG confidence -> ESTABLISHED_INDIRECT, otherwise POTENTIAL_INDIRECT.
    - 343-348 census reachability status is read from functions[].reachability.status.
    - 352-357 dynamic edges with no source are attributed through site_owner from other cited evidence.
    - 102 and 550-570 MAX_PATH_EDGES = 8 bounds the BFS for reachability.
    - 494-499 and 582 "universal" wording (always/every execution) is always rejected.
    - 590-593 census DEFINITELY_REACHABLE supports a rootless reachability claim only when the text names census/static scope.
    - 627-649 absence is contradicted by any matching edge. Otherwise it is admitted only with scoped wording (CALL_ABSENCE_SCOPED), else rejected.
    - 654-891 parse_assertions is a large regex/token-based English parser (forms, modalities, hedges, subject/object heuristics). 854-856 hedged clauses ("whether", "not established") are noted as unchecked, not parsed.
    - 710-713 _SITE_LEFT_RES includes the "blx|bx" mnemonics (ARM).
    - 969 diagnostics are deduplicated by (code, detail).

- path: agent/src/aptrace_agent/ledger/policy.py
  purpose: Versioned claim-verification policy as data. Classifies claims mechanically into a ClaimClass with corroboration requirements and accepted evidence kinds, and computes the policy identity digest.
  exports: POLICY_ID, POLICY_VERSION, ClaimClass, MIN_INDEPENDENT_LINEAGES, SOURCE_ENVELOPE_FIELDS, CLASS_POLICY, SEVERITY, policy_definition, current_policy, claim_class
  dependencies: ledger.claim_semantics (CallEdgeKind, ClaimSemantics, FunctionRole, Predicate), ledger.hashing.digest, ledger.models (ClaimType, PolicyRef)
  data_shapes: PolicyRef(policy_id, version, digest of policy_definition())
  side_effects: none
  role: verification policy
  observations:
    - 27-28 POLICY_ID "aptrace-claim-verification", POLICY_VERSION "1" (versioned identity).
    - 51-83 only CODE_EXISTENCE has a non-empty evidence_kinds (["structural_source_agreement"]). Every other class (RESOLVED_INDIRECT_CALL, CONTROL_FLOW, BOUNDED_NEGATIVE, MEMORY_ACCESS, VECTOR_MAPPING, UNDETERMINED) has no evidence contract, so it cannot reach VERIFIED (12-14).
    - 44 MIN_INDEPENDENT_LINEAGES = 2. 49 SOURCE_ENVELOPE_FIELDS = (lineage, firmware_sha256, engine_version).
    - 86-91 SEVERITY: CONTRADICTED -> block. UNRESOLVED, UNMET and UNEVALUABLE -> hold.
    - 119-171 claim_class is computed from claim_type and semantics only ("the proposer never chooses it"). Untyped claims are UNDETERMINED unless NO_KNOWN_PATH (BOUNDED_NEGATIVE) or PATH_EXISTS (CONTROL_FLOW).
    - 37-39 VECTOR_MAPPING ("vector-table slot") reflects the Cortex-M vector-table concept.

- path: agent/src/aptrace_agent/ledger/gate.py
  purpose: Phase-P verification-policy gate. Classifies contradictory evidence, structural source conflicts and independent corroboration into GateConditions and an overall status. Also provides a read-only assessment of historical VERIFIED decisions against the current policy.
  exports: AGREEMENT_TOOL, MAX_STRUCTURAL_ADDRESSES, CONTRADICTED, UNRESOLVED, UNMET, UNEVALUABLE, NOT_MATERIAL, SATISFIED, FAILING, MaterialAddress, material_code, PolicyGateEvaluator, structural_addresses, PolicyAssessment, verified_decision, assess_policy
  dependencies: ledger.claim_semantics (ClaimSemantics, Predicate, _maybe_int [private], addr, extract_facts), ledger.models, ledger.policy, ledger.store (EVIDENCE_INVALIDATED, ResearchLedger)
  data_shapes: PolicyGate(policy, claim_class, class_basis, status PASSED|BLOCKED|HELD|UNEVALUABLE, conditions, agreement_evidence_ids)
  side_effects: none (reads the ledger only)
  role: verification policy gate
  observations:
    - 46 AGREEMENT_TOOL = "structural_source_agreement". 48 MAX_STRUCTURAL_ADDRESSES = 16.
    - 60-62 _canon clears bit 0 ("Declared normalization: the Thumb state bit is not part of an address"). Every address comparison in the gate applies the Thumb normalisation, whatever the ISA.
    - 73-111 material_code returns None (materiality not established mechanically) for untyped or PATH_RELATION claims.
    - 190-231 structural(): a CONFLICT at a material address -> CONTRADICTED. A CONFLICT with no typed assertions -> UNRESOLVED. A CONFLICT elsewhere -> NOT_MATERIAL. A function-start DISAGREE where the claim asserts an entry -> UNRESOLVED.
    - 235-286 contradiction(): checks resolution, compatibility, invalidation, result availability, typed semantics, structural, typed contradictions, then path or named-entity. Anything it cannot classify becomes UNRESOLVED or UNEVALUABLE, never passed.
    - 288-324 typed contradictions are implemented only for resolved pointers (same slot, different field value) and paths (same scopes, different status).
    - 340 an assert hard-codes that only CODE_EXISTENCE reaches the corroboration evaluator. A new evidence contract for another class would hit an AssertionError until this is extended.
    - 346-433 _code_corroboration needs observations that are available and recognise code, a matching start (if an entry is asserted), complete envelope fields, a matching firmware, and not assisted. It then needs two qualifying sources with disjoint lineage. Missing envelope -> UNEVALUABLE. Shared lineage or no coverage -> UNMET.
    - 155-164 a derived_from engine prefix is added to a source's lineage, so a derived source cannot claim independence.
    - 437-501 evaluate(): status precedence is CONTRADICTED > {UNRESOLVED, UNMET} > UNEVALUABLE > PASSED. Agreement evidence must be the AGREEMENT_TOOL, compatible, not invalidated, readable, and not listed as contradictory.
    - 514-591 PolicyAssessment / assess_policy is read-only, uses recorded evidence only (no replay, no fresh agreement), and reports whether the latest VERIFIED decision applied the current policy.
    - 569-570 assess_policy takes firmware and case from the first supporting artifact unless the run is known.

- path: agent/src/aptrace_agent/ledger/verifier.py
  purpose: The only component that moves a claim's state from a verification. Runs phased checks A (structural), B (semantics), C (replay/freshness), P (policy gate) and D (dependencies + audit), records a VerificationRecord, and transitions state.
  exports: BLOCK, STALE, HOLD, GATE_CHECKS, VerificationOutcome, ClaimVerifier
  dependencies: ledger.call_relations (call_diagnostics, typed_grade_diagnostics), ledger.claim_checks (REJECT, entity_diagnostics), ledger.claim_semantics (SemanticCheck, verify_semantics), ledger.gate (AGREEMENT_TOOL, FAILING, MAX_STRUCTURAL_ADDRESSES, UNEVALUABLE, PolicyGateEvaluator, structural_addresses), ledger.models, ledger.operations (LedgerOperationRunner, input_artifacts), ledger.policy (SEVERITY, current_policy), ledger.semantics (asserts_absolute_negative, grade_ceiling), ledger.store (EVIDENCE_INVALIDATED, ResearchLedger, new_id, now)
  data_shapes: VerificationOutcome(record, previous, current, staled)
  side_effects: Writes verification records and lifecycle events. Invalidates evidence. Executes replays and structural_source_agreement through the runner, which writes invocations, evidence and blobs.
  role: verification authority
  observations:
    - 79-80 replay=True needs a runner.
    - 142-145 SUPERSEDED or STALE claims are HOLD-ed with lifecycle_eligible=False, all phases skipped, and an advice to propose a new version.
    - 156-160 the expected firmware is taken from the claim's run if that run is known, otherwise from the context.
    - 180-186 entity_identity is BLOCK for malformed identifiers. Function and peripheral resolvers are not passed here, unlike in admission.
    - 190-202 untyped claims run the prose call_diagnostics. The severity drops to HOLD when some supporting result blob is not available locally.
    - 215-217 typed CALL_RELATION claims get an extra call_relation_grade check.
    - 230-233 limitations_preserved: every evidence limitation code must be present on the claim.
    - 237-247 claim type UNREACHABLE is always BLOCKED. An absolute-negative wording over NO_KNOWN_PATH evidence is BLOCKED.
    - 257-277 a missing blob gives evidence_available (HOLD, or passes when replay is on). A hash mismatch gives evidence_integrity STALE plus invalidation.
    - 282-316 with replay off, input-artifact drift is HOLD. With replay on, every replayable supporting invocation is replayed under one new "RV" run id, and a mismatch is STALE plus invalidation.
    - 318-319 invalidation is applied before phase C closes, so it can stale other claims as a side effect.
    - 329-343 gate conditions map to the checks claim_class, contradictory_evidence, structural_conflicts and independent_corroboration. BLOCK if any condition is CONTRADICTED, else HOLD.
    - 345-347 precheck stops after P.
    - 356-373 phase D: non-diagnostic audits only. Any CHALLENGED audit on this version blocks permanently, even if a later audit is SUPPORTED. No audit or UNRESOLVED -> HOLD.
    - 391-407 the gate records a fresh structural_source_agreement for the material addresses under a new "VG" run id. A failure or more than 16 addresses gives UNEVALUABLE conditions.
    - 427-482 _finish chooses the outcome (BLOCK > STALE > HOLD -> PROPOSED > VERIFIED). A precheck never advances a claim (443-445).
    - 439 and 469-477 on HOLD the outcome is PROPOSED, so a claim currently BLOCKED or VERIFIED is transitioned back to PROPOSED when a later verification only holds. test_verification_policy.py:633 asserts this for VERIFIED -> PROPOSED. BLOCKED -> PROPOSED is exercised at test_ledger_audit.py:636-637 (a new version) but not for the same version. A re-verification can therefore un-block a version unless the block reason is recomputed every time. The CHALLENGED rule keeps re-blocking challenged versions.
    - 474 a STALE outcome uses actor aptrace-staleness. Every other outcome uses aptrace-verifier.

- path: agent/src/aptrace_agent/ledger/pipeline.py
  purpose: Verification-gated audit orchestration. Runs a precheck and calls the audit model only if phases C and P passed and the claim is not BLOCKED, STALE or SUPERSEDED. Optionally re-verifies afterwards.
  exports: GatedAudit, eligible, semantic_summary, audit_if_eligible
  dependencies: ledger.models (AuditRecord, ClaimState), ledger.verifier (ClaimVerifier, VerificationOutcome)
  data_shapes: GatedAudit(precheck, audit, verification, skipped_reason)
  side_effects: through the verifier and auditor
  role: orchestration glue
  observations:
    - 33-39 eligibility = phase C passed and phase P passed and state not in {BLOCKED, STALE, SUPERSEDED}.
    - 61-67 skipped_reason lists failing checks (block/stale severity or phase P) and the non-satisfied gate codes.
    - 69-74 a diagnostic audit of an ineligible claim is recorded with diagnostic=True and never counted.

- path: agent/src/aptrace_agent/ledger/operations.py
  purpose: Executes typed APTrace operations through an executor, records the invocation and evidence durably, and replays recorded invocations with hash comparison and bounded structural diffs.
  exports: TOOL_INPUTS, DETERMINISTIC_TOOLS, DIFF_LIMIT_BYTES, OperationExecutor (Protocol), input_artifacts, source_revision, ReplayResult, _differences, LedgerOperationRunner
  dependencies: subprocess, ledger.hashing, ledger.models, ledger.store (ResearchLedger, now), aptrace_agent.schemas.EvidenceObservation
  data_shapes: ReplayResult(original, replay, matches, original_sha256, replay_sha256, input_drift, differences)
  side_effects: source_revision runs `git` subprocesses (rev-parse, status --porcelain, diff HEAD) with a 20 s timeout. The runner writes ledger records. Executor side effects depend on the executor.
  role: operation execution / replay
  observations:
    - 31-56 TOOL_INPUTS is a hardcoded per-tool registry of context artifact names (census_db, svd, ghidra_export, macaw_census, unicorn_harness, boot_recipe, pcode_forward_use_walker, ...). Adding a tool means editing this table (part of the "~10 modules" integration cost).
    - 51-53 value_forward_use inputs: ghidra_cache_identity, pcode_forward_use_walker, pcode_forward_use_driver, ghidra_headless_locator.
    - 58-61 DETERMINISTIC_TOOLS = every TOOL_INPUTS key except search_case_evidence. A tool missing from TOOL_INPUTS is silently non-replayable.
    - 116-138 _differences is a bounded recursive diff (8 entries, 80-character values).
    - 168-176 a per-run in-memory seq counter. The session evidence id passed to the executor is "E<seq>".
    - 178-179 every exception is caught and recorded as error text truncated to 500 characters.
    - 206-207 replay refuses non-replayable invocations. 217-218 it refuses cross-firmware replay (only when the original evidence exists).
    - 225-236 when results differ, it reports a missing blob, or a hash-only note for results over DIFF_LIMIT_BYTES (16 MiB), or a structural diff.

- path: agent/src/aptrace_agent/ledger/recorder.py
  purpose: Maps a completed investigation (session evidence E1..En, failures, planner claim proposals, admission records, candidate selection) into durable ledger records.
  exports: ExecutionTrace, RecordingExecutor, code_identity, record_investigation
  dependencies: inspect, ledger.claim_checks (CLAIM_EQUIVALENT_EXISTS, NOTE), ledger.hashing, ledger.models, ledger.operations (DETERMINISTIC_TOOLS, input_artifacts), ledger.store (ResearchLedger, new_id, now), aptrace_agent.schemas; lazy aptrace_agent.research.candidates.equivalent_claims (161)
  data_shapes: consumes a duck-typed `run` object (objective, evidence, state.leads, result.steps/proposed_claims/claim_admission/candidate_selection/planner_requests/stop_reason, continuity); produces an InvestigationRun.
  side_effects: ledger writes
  role: glue (investigation -> ledger)
  observations:
    - 46-47 RecordingExecutor.__getattr__ proxies everything to the inner executor.
    - 65-68 code_identity = digest of inspect.getsource of objects [:12]. It is used as planner_version in ledger_cli. It fails for objects without source.
    - 97-103 reused observations (reused_from) are not re-recorded. Their session alias maps to the original evidence id.
    - 118-122 input_evidence_ids are only earlier-session or already-durable evidence from the lead's sources.
    - 132-146 executor failures are recorded as error invocations with seq numbers after the evidence.
    - 154 unknown session references are kept verbatim so verification rejects them (documented 8-9).
    - 157-167 a selected candidate whose typed fact already exists creates no new claim version and is marked "duplicate" with a CLAIM_EQUIVALENT_EXISTS note (194-204).
    - 174 proposed_by is "candidate-selection:<model>" or "investigator:<model>".
    - 161 ledger -> research is a lazy import (dependency direction from the ledger package into research).

- path: agent/src/aptrace_agent/ledger/auditor.py
  purpose: Bounded adversarial audit of one ClaimVersion by an LLM. Builds a compact independent context, offers a typed tool allowlist that APTrace validates and executes, enforces falsification and budget rules, and records an immutable AuditRecord with an input fingerprint.
  exports: AUDIT_TEMPLATE_VERSION, DEFAULT_AUDIT_MODEL, EVIDENCE_DIGEST_CHARS, RESULT_CHARS, SYSTEM_PROMPT, RESPONSE_FORMAT, ToolRejected, FALSIFYING_OUTCOMES, parse_decision, pointer_provenance, evidence_digest, MAX_AGREEMENT_ADDRESSES, agreement_targets, containing_functions, agreement_digest, AuditBudget, AuditToolbox, build_audit_context, audit_input_fingerprint, ClaimAuditor
  dependencies: pydantic; ledger.hashing, ledger.models, ledger.operations.LedgerOperationRunner, ledger.store; aptrace_agent.research.controller._prefill_rejected (private symbol); aptrace_agent.research.projection (clip, known_functions, summarize_observation); aptrace_agent.schemas.EvidenceObservation; aptrace_agent.source_agreement.AGREEMENT_SEMANTICS; lazy openai.OpenAI (911)
  data_shapes: Model decisions are JSON {action: request|verdict, ...} (104-113). AuditRecord is defined in models.
  side_effects: Network calls to an OpenAI-compatible endpoint (OMLX_BASE_URL/OMLX_API_KEY env, 240 s timeout). time.sleep on prefill rejection (1040). Runner executions and ledger writes.
  role: adversarial audit (model-facing)
  observations:
    - 42-58 version history audit-v0.1..v0.5. The current AUDIT_TEMPLATE_VERSION is "audit-v0.5".
    - 59 DEFAULT_AUDIT_MODEL "gemma-4-26b-a4b-it-4bit". 923 it can be overridden with APTRACE_REVIEW_MODEL.
    - 36 imports the private _prefill_rejected from research.controller (tight coupling to the controller's internals).
    - 128-136 KeyError, LookupError and FileNotFoundError from a runner become "coverage gap" outcomes. Any other error is a tool_error.
    - 256-286 pointer_provenance renders census resolved-pointer edges, including a "(Thumb bit cleared)" note (263-265). Thumb-specific.
    - 324-347 agreement_targets takes up to 16 code addresses from resolved pointer edges. 330 addresses must have at most 8 hex digits.
    - 361 containing_functions reads only the "census" source.
    - 413-481 the toolbox exposes inspect_evidence, function_facts, function_disassembly, analyze_peripheral, analyze_usb_interface, find_common_paths, analyze_function_effects, replay_evidence, and optionally search_case_evidence. analyze_usb_interface (census_usb_inventory) is a USB/case-specific tool in the generic auditor.
    - 469 the description says "one MCU peripheral's registers". 629 the example name is "TCC1" (SAMD).
    - 492-503 function arguments must be FUN_xxxxxxxx names that appear in the visible evidence.
    - 531-535 the "USB" set is hardcoded from census_usb_inventory.
    - 564-580 an unanalysed catalog peripheral in find_common_paths triggers a census_peripheral_usage run recorded under the audit id.
    - 649-664 analyze_function_effects accepts register names r0/r1 with 32-bit unsigned ranges (ARM AAPCS argument registers, 32-bit).
    - 672 the case-search query is fixed at max_results=6, purpose "audit".
    - 685-693 duplicate requests (the same operation and validated args, including already-visible evidence) are rejected and do not count.
    - 763-842 build_audit_context omits the derivation narrative. It includes the objective, subject, assertion, typed semantics and deterministic check summary, type, grade, scope, assumptions, limitations, dependencies with state, compact evidence, and structural agreement.
    - 845-848 _claim_identity excludes created_at, and excludes semantics when it is None, so pre-semantics fingerprints stay unchanged (historical compatibility).
    - 851-892 the input fingerprint is "AI-"+16 hex over ten components (claim, limitations, evidence, source_agreement, context, template, model, generation, tools, budget). It has no timestamps.
    - 934 generation is temperature 0.0, max_tokens from the budget, plus extra parameters.
    - 1015-1179 decision loop: at most max_decisions decisions, with one retry per decision for parse failures. A verdict is rejected before the first successful falsification. Requests after the final budget are rejected. Prefill-memory rejections are retried after a sleep.
    - 1182-1206 a verdict without a successful falsification is recorded as UNRESOLVED, with model_verdict kept and verdict_synthesized=True. No verdict gives a synthesized UNRESOLVED.
    - 1208 and 1228 evidence_inspected and contradictory_evidence are filtered to visible evidence ids.

- path: agent/src/aptrace_agent/ledger/benchmark.py
  purpose: Known-answer benchmark runner. Fixture setup operations, proposal of fixture claims, gated audit, verification, and evaluation against a separate expected file.
  exports: ClaimOutcome, BenchmarkResult, load_fixture, run_setup, propose_fixture_claims, evaluate, run_benchmark
  dependencies: ledger.models.InvestigationRun, ledger.operations (LedgerOperationRunner, source_revision), ledger.pipeline.audit_if_eligible, ledger.store, ledger.verifier.ClaimVerifier
  data_shapes: fixture JSON {benchmark, objective, setup:[{name, tool, arguments, sets}], claims:[{label, subject, assertion, claim_type, proposed_grade, evidence, contradictory_evidence, depends_on, scope, assumptions, limitations, derivation, semantics}]}; expected JSON {claims:{label:{final_state, audit_verdict, must_not_be, verifier_failed_checks, audit_skipped, semantic_failures, gate_status, policy_conditions, audit_should_mention}}}
  side_effects: reads fixture files; ledger writes; git subprocess through source_revision
  role: evaluation harness
  observations:
    - 5-8 expected outcomes live in <name>.expected.json and are never shown to models. Keyword grading never affects state.
    - 128-131 the "USB" set is hardcoded for census_usb_inventory (case coupling).
    - 146 source_revision defaults to Path.cwd() when no repo is given.
    - 247 the audit is gated with verify_after=False, then 249 runs a full verification.
    - 223-224 "audit_mentions" is excluded from the pass/fail computation.

- path: agent/src/aptrace_agent/ledger/stability.py
  purpose: Measures audit stability. Groups audits by (claim_version, input_fingerprint) and computes agreement metrics and a coverage-gap heuristic.
  exports: COVERAGE_GAP_TEXT, cites_coverage_gap, audit_row, group_summary, stability_summary
  dependencies: ledger.models.AuditRecord
  data_shapes: {groups:[...], rows:[...]} dictionaries
  side_effects: none
  role: measurement / reporting
  observations:
    - 22-29 the COVERAGE_GAP_TEXT regex is labelled an evaluator-side heuristic that never affects state.
    - 50-51 a SUPPORTED verdict's reasoning is not scanned for coverage-gap text. Only its challenges are.
    - 92 agreement = modal frequency / n, rounded to 3 places.

- path: agent/src/aptrace_agent/ledger/report.py
  purpose: Renders a Markdown report derived from the ledger, with the ledger fingerprint embedded for staleness detection.
  exports: FINGERPRINT_RE, render_report, report_is_stale, write_report
  dependencies: ledger.gate.assess_policy, ledger.models.ClaimState, ledger.stability.stability_summary, ledger.store.ResearchLedger
  data_shapes: Markdown text
  side_effects: write_report creates parent directories and writes a file
  role: reporting / view
  observations:
    - 38 the sort key int(claim_id[1:]) assumes "C<n>" ids.
    - 51 the text tells the reader to regenerate with `aptrace-agent report`.
    - 160-162 a fallback heuristic counts "Function not found" in result summaries as coverage gaps for pre-v0.4 audits.
    - 223-230 VERIFIED claims not decided under the current policy get a read-only current-policy eligibility line.
    - 238-243 the report is stale if the file is missing, has no fingerprint, or the fingerprint differs.

- path: agent/src/aptrace_agent/ledger_cli.py
  purpose: argparse subcommands for the ledger (claims, candidates, policy-status, propose, supersede, audit, audit-repeat, runtime-probe, verify, replay, check, report, benchmark) and recording of `research --ledger` runs.
  exports: LEDGER_COMMANDS, add_ledger_commands, handle_ledger_command, record_research_run, ClaimState (re-export); private _stack, _auditor, _runtime_snapshot, _print_audit, _print_verification
  dependencies: ledger.models, ledger.store, ledger_wiring (BENCHMARK_DIR, DEFAULT_REPORT_PATH, REPO_ROOT, context_provider, irq_handler_resolver, ledger_dir); lazy: aptrace_agent.executor.EvidenceExecutor, ledger.operations, ledger.auditor, ledger.gate, ledger.report, ledger.pipeline, ledger.verifier, ledger.stability, ledger.benchmark, ledger.recorder, research.candidates.candidates_for_run, research.projection, runtime_probe (build_request, post, run_probe)
  data_shapes: CLI args; JSON spec files for propose/supersede; JSON output files for audit-repeat, runtime-probe and benchmark
  side_effects: stdout printing; SystemExit codes (report --check, replay mismatch, audit-repeat ineligible); ledger writes; network to the oMLX endpoint (audit, runtime-probe); reads ~/.omlx settings (_runtime_snapshot); git subprocess; writes output files
  role: CLI
  observations:
    - 33 every subcommand takes --ledger-dir. The default is the case ledger (ledger_wiring.DEFAULT_LEDGER_DIR), so commands write to the canonical case ledger unless overridden.
    - 78 the help text says "--precheck: Phases A-C only (no audit)", but precheck also runs phase P (verifier.py:345). The help text is stale.
    - 119 the audit budget max_tool_requests = max(1, max_decisions - 1).
    - 256-262 `propose` passes the JSON spec straight into ResearchLedger.propose_claim(**spec). It bypasses research/admission.py, so operator claims get no admission checks; verification still applies.
    - 264-270 `supersede` likewise writes a new version from arbitrary changed fields.
    - 286-335 runtime-probe needs OMLX_BASE_URL/OMLX_API_KEY (KeyError if unset). 130-140 it snapshots ~/.omlx settings.json and model_settings.json.
    - 337-356 `check` re-hashes every evidence blob and invalidates mismatched or missing ones. A missing blob (KeyError -> ok=False) is treated like corruption here, whereas the verifier treats a missing blob as unavailable (HOLD). The two paths disagree for large blobs kept out of version control.
    - 358 every command after `check` builds the full EvidenceExecutor stack (_stack), even replay.
    - 536 record_research_run hardcodes execution_config {temperature 0.0, max_tokens 512, endpoint "local-omlx", claim_contract True}. These are not read from the actual controller configuration.
    - 537 planner_version = code_identity of the controller class and the projection module.

- path: agent/src/aptrace_agent/ledger_wiring.py
  purpose: Performing Rigs application wiring. Case name, ledger/report/benchmark/work paths, context artifact hashing, IRQ handler resolution from the SVD, lead-deriver factory.
  exports: CASE_NAME, DEFAULT_LEDGER_DIR, DEFAULT_REPORT_PATH, BENCHMARK_DIR, REPO_ROOT, DEFAULT_WORK_DIR, ledger_dir, work_dir, context_artifacts, context_provider, irq_handler_resolver, lead_deriver_factory
  dependencies: aptrace_agent.census (PERFORMING_RIGS_CASE = <repo>/cases/performing-rigs, performing_rigs_svd); ledger.hashing.file_sha256; ledger.models.ExecutionContext; aptrace_agent.structural_wiring (CALLBACK_PROVENANCE_INPUTS, INDIRECT_TARGET_INPUTS, OBSERVATION_INPUTS, VALUE_FORWARD_USE_INPUTS, ghidra_seeds_path, macaw_census_path); lazy aptrace_agent.research.LeadDeriver
  data_shapes: ExecutionContext(case="performing-rigs", firmware_key, firmware_sha256, artifacts{name: sha256})
  side_effects: hashes files on every context call (70, 76-82); reads env APTRACE_LEDGER_DIR and APTRACE_WORK_DIR
  role: application/case wiring (a recorded framework/case seam)
  observations:
    - 1-9 self-described as "Performing Rigs application wiring". It lives at framework level (agent/src/aptrace_agent) and refers to the case via census.PERFORMING_RIGS_CASE (a cases/ path). It does not import Python from cases/, but it binds to case paths and data.
    - 31 CASE_NAME = "performing-rigs" is hardcoded.
    - 32-37 the ledger, report and benchmark directories are under cases/performing-rigs/research/. REPO_ROOT = PERFORMING_RIGS_CASE.parents[1].
    - 40 DEFAULT_WORK_DIR = ~/.aptrace/work/performing-rigs. The comment says Beads writes .gitignore files, so the work store is kept outside the checkout.
    - 57 the hardcoded SVD path is cases/performing-rigs/config/svd/ATSAMD51J19A.svd (a specific Microchip SAMD51 part).
    - 65-68 ghidra_cache_identity = meta.json next to the Ghidra export, only if present.
    - 70 artifacts whose files are missing are dropped silently. This changes input_artifacts and so operation keys.
    - 79-80 firmware identity comes from executor.census (firmware_key, expected_sha256): the expected hash, not a freshly computed one.
    - 87-103 irq_handler_resolver maps image vector-table handlers (executor.usb.vector_handlers()) to SVD interrupt names, cached with lru_cache. Cortex-M vector table plus SVD.
    - 106-111 lead_deriver_factory wires the research LeadDeriver (not ledger-related; placed here).
```

## Test files

```yaml
- path: agent/tests/ledger_support.py
  purpose: Shared fakes. FakeExecutor (deterministic typed operations with drift injection), FakeCodeSource (census/ghidra/macaw structural sources), MutableContext, stack(), irq_handlers, ScriptedAuditModel (OpenAI-shaped), and request/verdict helpers.
  covers: test infrastructure for all ledger tests
  observations:
    - 16 FIRMWARE is a fixed sha256. 18-36 USB_EDGE, USB_FUNCTIONS and EIC_STUBS use real Performing Rigs (AutoPilot) addresses (0x0000cc1a, slot 0x200052e8, etc.).
    - 98 census is derived_from "ghidra:v1" by default.
    - 84-90 INDEPENDENT_ENVELOPE: the comment says real sources declare no envelope today.
    - 132 peripherals are ["EIC", "TCC1", "SERCOM2", "USB"] (SAMD naming).
    - 167 the context case is "performing-rigs" and the firmware key "autopilot868".
    - 192 when its script runs out, ScriptedAuditModel defaults to request("analyze_usb_interface").

- path: agent/tests/test_ledger.py
  purpose: Ledger persistence, identity, versioning, lifecycle, staleness and report.
  covers: store, models, report, verifier (no-replay), operations, semantics.canonical_result
  behaviors_asserted:
    - InvestigationRun round-trips through disk (34-61).
    - Invocation ids differ per run while operation keys and evidence ids are equal for identical operations and results; input_artifacts are filtered per tool (65-76).
    - Evidence references, blobs, grade and PROPOSED state survive a reload (80-91).
    - Supersession creates v2, sets v1 SUPERSEDED, resolves a bare id to the latest version, re-inherits limitations, and refuses a stale base (95-110).
    - Historical versions are byte-unchanged and _write_once raises on different content (114-127).
    - Evidence limitations are inherited (130-138).
    - A tampered blob makes the claim STALE and invalidates the evidence (142-155).
    - Supersession stales dependents transitively with actor aptrace-staleness (159-170).
    - Evidence invalidation stales the claims citing it and their dependents (173-183).
    - A dangling dependency BLOCKs (186-193).
    - The report contains the claim, evidence, limitations and fingerprint, and becomes stale after a change (197-215).
    - Volatile cached metadata does not change the evidence id or replay match (218-228).
    - The large-blob tier is used; a missing large blob HOLDs without replay and is re-derived with replay (231-251).
  observations:
    - The numbered comments (# 1, # 2, ...) refer to an external numbered requirement list that is not in scope.

- path: agent/tests/test_ledger_audit.py
  purpose: Audit contract, deterministic verification, benchmarks, the research-controller claim contract, and the recorder.
  covers: auditor, verifier, store.transition, operations.replay, benchmark (with the real case fixtures), recorder; research.controller (claim contract, _sanitize_claims, admission rounds)
  behaviors_asserted:
    - An audit is persisted and reloadable with steps, tokens, context and inspected evidence (58-76).
    - The audit context excludes the derivation narrative and includes limitations (79-87).
    - parse_decision accepts fenced or embedded JSON and rejects missing JSON, verdict "VERIFIED", an unknown action, or a missing scope_check (91-107).
    - The toolbox rejects shell/sql, unknown functions, paths, extra args, bad fields, unknown peripherals, string registers, unknown IRQ prefixes, and disabled case search, without executing anything; IRQ:EIC resolves to the stubs (111-141).
    - Rejected requests are recorded and reported back to the model (144-153).
    - Decision and tool budgets are enforced, giving a synthesized UNRESOLVED with decision_budget_exhausted and no state change (157-173).
    - A verdict before a falsification is rejected (176-185).
    - A KeyError tool failure is presented as a coverage gap and recorded as an error invocation (188-202).
    - Duplicate queries, and queries matching already-visible evidence, are prevented (206-225).
    - Only aptrace-verifier can set VERIFIED, and only by citing a passing policy verification; audits never append events; an untyped claim stays PROPOSED with gate UNEVALUABLE/CLAIM_CLASS_UNDETERMINED (229-259).
    - An unknown evidence reference BLOCKs (263-277).
    - A replay mismatch gives STALE plus invalidation (281-293).
    - Input drift without replay HOLDs (296-306).
    - A grade above the ceiling BLOCKs despite a SUPPORTED audit (310-320).
    - Dropped limitations are re-inherited by the API, and a hand-written stripped record is BLOCKED (323-341).
    - UNREACHABLE type and unreachable wording over NO_KNOWN_PATH are BLOCKED; a bounded NO_KNOWN_PATH claim is held by BOUNDED_NEGATIVE/NO_EVIDENCE_CONTRACT (345-380).
    - Replay needs no model and detects drift (384-396); case search is not replayable (399-406).
    - Benchmarks usb-callback and eic-convergence (real case fixtures under BENCHMARK_DIR): the good untyped claim is held before audit, the bad claim is BLOCKED by grade_ceiling before audit, and the convergence claim is never audited and inherits PERIPHERAL_SET_IS_MMIO_USAGE:EIC (417-471).
    - The claim contract is off by default; sanitised proposals and admission decisions are recorded; one-claim-per-line parsing; final-claims and claim-correction phases (498-616).
    - The recorder maps E1 to a durable id, keeps unknown E42 verbatim, and sets proposed_by investigator:<model> (542-569).
    - A CHALLENGED version stays BLOCKED after a later SUPPORTED audit; a new version can pass the audit check (619-638).
  observations:
    - 21 and 413 depend on case data (ledger_wiring.BENCHMARK_DIR under cases/performing-rigs/research/benchmarks/ledger-v0). Framework tests read case fixtures.
    - 474-616 test research.controller behaviour, which is outside the ledger package.

- path: agent/tests/test_audit_stability.py
  purpose: audit-v0.4 features. Compact provenance, source agreement, falsification counting, input fingerprints, immutable history, stability summary.
  covers: auditor (build_audit_context, pointer_provenance, falsification logic, fingerprint), store.record_audit, stability
  behaviors_asserted:
    - The compact context shows consumer, writer, registration (with containing function only when agreement is recorded), raw->canonical "(Thumb bit cleared)", forwarding, grade and limitations (53-68).
    - Source agreement is recorded over sorted pointer-edge addresses, reported with a MACAW_COVERAGE_GAP note and agreement semantics, and the context stays under 9000 characters (72-84).
    - Duplicate rejections do not satisfy falsification; a duplicate-only run gives a synthesized UNRESOLVED with model_verdict kept (88-106).
    - Unavailable tools, unparseable responses and invalid arguments do not count (110-125).
    - A successful execution counts (129-136); a coverage gap counts and is not contradictory; a harness RuntimeError is tool_error and does not count (140-171).
    - The fingerprint is deterministic, independent of model output, has ten components and no timestamps (175-189).
    - Changed source agreement changes the {source_agreement, context} components; changed evidence changes the evidence component (193-211).
    - Model, budget and template changes each change the fingerprint (215-228).
    - Audit records are immutable and multiple audits coexist (232-244).
    - A historical audit-v0.3 record in the canonical case ledger is readable read-only from a copy (skipped if absent) (248-268).
    - The stability summary groups by fingerprint with agreement and coverage-gap metrics (271-286).
  observations:
    - 14 and 251-254 read the canonical case ledger (DEFAULT_LEDGER_DIR), copying it to tmp first (protecting canonical state). They depend on the specific historical id A-20261012T234455-90a51c.

- path: agent/tests/test_claim_semantics.py
  purpose: Typed claim semantics, phased verification, and the audit gate.
  covers: claim_semantics, verifier phases, pipeline.audit_if_eligible, report, benchmark (semantic-usb-eic case fixture)
  behaviors_asserted:
    - Semantics normalise addresses and FUN names, uppercase set names, round-trip, and reject a mismatched body (92-107).
    - Semantics round-trip through stored claims (110-116).
    - Entity roles are checked against the evidence (ENTITY_ROLE_MISMATCH with roles) (120-139).
    - Pointer relations: consistent with 7 checks, the registration caller sourced from agreement evidence, field mismatches, swapped endpoints, an unknown slot gives RELATION_UNSUPPORTED (143-164).
    - Set scopes are typed from evidence provenance; a dispatch-set claim on MMIO-usage evidence is SCOPE_MISMATCH (168-181) and BLOCKED with phase skipping (184-196).
    - Members differing from the evidence sets become UNATTRIBUTED (199-206).
    - The NO_KNOWN_PATH status mismatch and predicate-type mismatch are checked; unreachable wording BLOCKs (210-222).
    - Grade ceiling and limitation checks still block typed claims (226-243).
    - A semantic failure blocks before the audit model, with no model request (257-269).
    - A valid CODE_PRESENCE claim with an independence envelope proceeds A-P, is audited, and becomes VERIFIED (272-283).
    - A typed pointer claim is held at P (RESOLVED_INDIRECT_CALL / NO_EVIDENCE_CONTRACT) and never audited (286-301).
    - Diagnostic audits are recorded but never counted (305-318).
    - Supersession preserves history and audits per version (322-333).
    - Semantic results persist and are reported (337-351).
    - The fingerprint covers semantics and explicit generation params (355-371).
    - The semantic-usb-eic benchmark fixture passes deterministically (374-385).
  observations:
    - 376 uses the case benchmark directory.

- path: agent/tests/test_claim_quality.py
  purpose: Claim admission and evidence accountability for model proposals.
  covers: research/admission.admit (out of scope) together with ledger/claim_checks; verifier phase B entity_identity; recorder; controller claim rounds
  behaviors_asserted:
    - A malformed "E0000b4b4" subject is rejected (ENTITY_MALFORMED, UNTYPED_GRADE), with one correction round and no ledger claim (66-83).
    - The verifier precheck BLOCKs a malformed identifier in an operator claim (86-96).
    - Session evidence ids used as subjects are rejected (99-106).
    - A constant load is not an access (ACCESS_NOT_ESTABLISHED, literal-pool detail, pattern-matched) (112-119); a typed MMIO_USER on a constant-loader is SEMANTICS_INCONSISTENT while ADDRESS_CONSTANT_LOADER is admitted (122-133); a function_effects MMIO access establishes access (136-145).
    - A categorical absence with a symbolic r0 is rejected (151-159).
    - Omitted executed evidence is reported (EVIDENCE_OMITTED); an explained omission is admitted but does not rescue an unsupported claim (165-186).
    - Reused evidence keeps its original id with a HISTORICAL_REFERENCE note (192-207).
    - A scoped hypothesis is admitted as PROPOSED and not VERIFIED (213-230).
    - USB/EIC controls: bad claims rejected, good pointer admitted (244-264).
    - Invalid semantics and garbage are bounded (270-290).
    - Persisted case-ledger records load unchanged and contain no malformed identifiers (296-310, skipped if absent; read-only).
  observations:
    - 28-29 import fixtures from test_continuity and test_followups (cross-test coupling). 32 PERIPHERAL/GAP come from the SERCOM-shaped fixture.
    - 297 reads the canonical case ledger directly (read-only assertions).

- path: agent/tests/test_verification_policy.py
  purpose: Phase-P verification policy gate. Contradictions, structural conflicts, corroboration, policy identity, CLI parity, historical decisions.
  covers: gate.PolicyGateEvaluator, gate.assess_policy, policy, verifier phase P, store._require_policy_verification, pipeline, ledger_cli (audit/verify handlers)
  behaviors_asserted:
    - Positive control: an independently corroborated CODE_PRESENCE claim is VERIFIED, with an INDEPENDENT_CORROBORATION SATISFIED naming macaw (91-103).
    - Material pointer contradiction gives BLOCKED before audit, and a later SUPPORTED audit cannot override it (109-130); a structural conflict in contradictory evidence BLOCKs even when corroboration is satisfied (133-148).
    - An unclassifiable contradiction gives HELD/UNRESOLVED (154-166, 169-180); incompatible or invalidated contradictory evidence gives UNEVALUABLE (183-194).
    - An unrelated contradiction is NOT_MATERIAL and the claim can still verify (200-209); a contradiction about another slot is NOT_MATERIAL (212-222).
    - A structural conflict at an asserted entry or pointer code gives CONTRADICTED/BLOCKED (228-251); out of scope is NOT_MATERIAL (254-266); a function-start discrepancy is UNRESOLVED/HELD (269-277); a conflict without typed assertions is STRUCTURAL_CONFLICT_UNCLASSIFIED (280-290).
    - Missing corroboration gives UNMET with coverage-gap and shared-lineage detail (296-305); same lineage, a derived source declaring lineage, or repeated runs are not corroboration (308-341).
    - Missing, null, empty or mismatched envelope fields give INDEPENDENCE_METADATA_MISSING/UNEVALUABLE; assisted gives UNMET (344-367).
    - Caller-supplied provenance in arguments or a mimic result cannot manufacture corroboration (370-396).
    - Repeated verification reuses comparison evidence ids and writes no new evidence files (406-417); changed inputs or results give new evidence ids without rewriting old ones (420-437).
    - A failed structural analysis gives STRUCTURAL_AGREEMENT_FAILED/UNEVALUABLE (440-453).
    - The class mapping table for untyped and typed shapes holds, and classes without a contract are UNEVALUABLE (456-477).
    - A passing gate does not bypass audit, CHALLENGED, phase B, or replay drift (483-503).
    - A direct VERIFIED transition requires the claim's own passing policy verification (509-528).
    - The CLI audit/verify paths enforce the same policy as the API (534-566).
    - The policy identity is recorded and reproducible (572-590).
    - Historical pre-policy VERIFIED decisions are preserved, assessed read-only, and a new verification appends (VERIFIED -> PROPOSED) without rewriting (596-636).
    - Persisted case verifications C2:v2 and C5:v1 predate the policy (639-653, skipped if absent).
  observations:
    - 633 asserts that re-verification moves a historically VERIFIED claim back to PROPOSED (the hold-to-PROPOSED behaviour, verifier.py:439).
    - 178, 189, 261, 288, 337 and 474 hardcode case "performing-rigs" in the evaluator.

- path: agent/tests/test_call_relations.py
  purpose: Call-relation checking for prose and typed CALL_RELATION claims, over a synthetic firmware.
  covers: call_relations (extract_call_facts, parse_assertions, call_diagnostics), claim_semantics.CallRelation validation, policy.claim_class, verifier phase B call_relations, research.admission and research.candidates (out of scope)
  behaviors_asserted:
    - A target named without an edge is rejected (CALL_RELATION_UNSUPPORTED) with context detail; a disjunction needs every target; the check is general (121-145).
    - Direct calls are admitted from function_facts or disassembly (151-156); a tail transfer comes only from a decoded branch leaving the function; typed kinds must match (CALL_KIND_MISMATCH) (159-172).
    - A vtable entry is not a call or reachability (178-189); a conditional target with its condition is admitted (200-204); dropped or wrong conditions give CALL_CONDITION_OMITTED (215-219); an established indirect needs no condition (222-226); typed POTENTIAL requires conditions (SEMANTICS_INVALID), ESTABLISHED on potential evidence is CONDITION_OMITTED, and STRONG on a PROBABLE edge is GRADE_ABOVE_CEILING (229-241).
    - An observed dispatch needs its scenario and site attribution (247-258); generalisation to static, always, or another scenario is rejected (261-277).
    - Source, target and site mismatch and unresolved targets (283-306).
    - Absence is not established from an incomplete call graph unless scoped (312-319).
    - Unrelated call words are not claims (325-337); scoped hypotheses are admitted (340-350); reachability needs a cited path, a condition, or a named scenario (353-362).
    - Unparsed call wording is noted and capped (365-368); parser forms (371-384).
    - USB/EIC controls are unchanged; the census resolved_indirect edge is ESTABLISHED_INDIRECT (390-405).
    - Candidates generate no CALL_RELATION and still admit (411-418).
    - The correction round admits a corrected claim (439-455); verifier phase B applies the same rule (458-469); policy classes for call relations (472-477); reused evidence keeps its original identity (483-495).
    - Persisted case-ledger records load and diagnostics only report; the case ledger tree digest is unchanged (511-534).
    - Typed semantics round-trip (543-549).
  observations:
    - 51-58 the synthetic disassembly uses ARM mnemonics (bl, beq, blx r3, b.w), so the edge-extraction tests cover Thumb only. There is no second-ISA control.
    - 10-11 the docstring points to the case-local replay test cases/performing-rigs/test/test_call_admission.py.
    - 531 asserts the specific case claim C9:v1 gives CALL_REACHABILITY_UNSUPPORTED (case-specific expectation in a framework test).
```

## Observed behaviors

Storage, identity and immutability
- Ledger records are written once. Writing semantically identical JSON is a no-op, and writing different content raises LedgerImmutableError. — store.py:100-113
- Records are written with exclusive create (`open("x")`). — store.py:112, 140
- Result blobs are content-addressed by sha256 of canonical JSON under blobs/<sha[:2]>/. — store.py:131-143, hashing.py:9-16
- Results larger than 4 MiB go to the blobs-large/ tier. Lookup checks both tiers. — store.py:63, 134, 145-152
- Loading a blob reports integrity by re-digesting its content. — store.py:160-169
- Records are frozen pydantic models that forbid extra fields. — models.py:87-88, claim_semantics.py:130-131
- Unset optional run and admission fields are omitted from serialisation so older records stay unchanged. — models.py:238-245, 359-367
- The operation key is a digest of tool, canonicalised arguments, input-artifact hashes and firmware sha256. — store.py:183-211
- Historical operation keys over the arguments as recorded stay matchable alongside canonical keys. — store.py:189-200
- The invocation id is derived from (run, seq, operation key). — store.py:233
- The evidence id is derived from (operation key, result sha). An identical operation with an identical result reuses one evidence artifact. — store.py:240-244
- The execution context id is a digest of case, firmware key, firmware sha and artifact hashes. — models.py:105-108
- Volatile execution metadata (function_effects provenance.cached) is stripped before hashing. — semantics.py:97-118
- Equivalent argument defaults (function_effects.specialize, observed_call_arguments scenario/watch) are filled before keying. — semantics.py:128-142
- Claim ids are allocated as max existing C<n> + 1. — store.py:316-319
- A bare claim id resolves to its latest version. A "C<n>:v<N>" key resolves exactly. — store.py:321-327, models.py:460-466
- The ledger fingerprint digests the events text, claim keys and audit filenames. — store.py:673-680

Claims, lifecycle and staleness
- A proposed claim is always written as version 1 and gets a PROPOSED event from aptrace-ledger. — store.py:395-417
- Limitations carried by supporting evidence are inherited mechanically at proposal and merged by code. — store.py:363-368, semantics.py:471-486
- Supersession only works from the latest version. — store.py:425-429
- Supersession writes version+1, recomputes inherited limitations unless they were given explicitly, marks the new version PROPOSED and the old one SUPERSEDED, and propagates staleness. — store.py:419-453
- Claim state is folded from the append-only events.jsonl, never stored on the record. — store.py:548-559
- Only APTrace actors may append claim lifecycle events. Model actors raise PermissionError. — store.py:488-489, models.py:84
- Only aptrace-verifier may set VERIFIED. — store.py:491-492
- A VERIFIED transition must cite a full, VERIFIED-outcome verification of the same version under the current policy with a PASSED gate. — store.py:499-546
- A transition to an unknown or unversioned claim key raises KeyError. — store.py:494-495
- Evidence invalidation appends an INVALIDATED event once and stales the PROPOSED or VERIFIED claims that cite the evidence as supporting. — store.py:574-598
- Staleness propagates transitively over depends_on from SUPERSEDED, STALE or BLOCKED claims to PROPOSED or VERIFIED dependents. — store.py:603-638
- Lifecycle event seq numbers are assigned as event count + 1. — store.py:504

Evidence semantics
- Each tool's result maps deterministically to an evidence grade and basis. Unknown tools are UNKNOWN. — semantics.py:161-267
- NO_KNOWN_PATH census results are graded BOUNDED. — semantics.py:185-186
- Disassembly, callsite context and pin table entries are graded EXACT. — semantics.py:194-195
- Each tool's result carries mechanical limitation codes: function boundaries heuristic, MMIO usage set, harness assumptions, scenario-specific, non-booted state, budget, watch absence, intraprocedural, ABI model, and others. — semantics.py:274-468
- The claim grade ceiling is the strongest supporting evidence grade. BOUNDED supports NO_KNOWN_PATH claims at STRONG only. — semantics.py:489-509
- Absolute-negative wording is detected unless a negator appears within 40 characters before it. — semantics.py:62-86
- Evidence path_status is recorded only for census_common_paths. — store.py:264

Operations and replay
- Each tool has a fixed set of input artifacts that is included in its invocation identity. — operations.py:31-56, 71-72
- Every tool listed in TOOL_INPUTS except search_case_evidence is replayable. — operations.py:61
- Operation exceptions are recorded as error invocations rather than raised. — operations.py:175-196
- The runner passes per-run session evidence ids "E<seq>" to the executor. — operations.py:168-176
- Replay refuses non-replayable invocations and cross-firmware replay. — operations.py:206-218
- Replay compares result hashes and reports input drift and a bounded structural diff, or a hash-only note above 16 MiB, or a missing-blob note. — operations.py:209-246, 116-138
- The source revision records git commit, branch, dirty flag and a dirty fingerprint over the diff plus untracked names. — operations.py:75-102

Recording investigations
- Session observations map to durable invocations and evidence. Reused historical observations are referenced by original id and not re-recorded. — recorder.py:97-130
- Executor failures are recorded as error invocations. — recorder.py:132-146
- Unknown session evidence references in proposals are kept verbatim. — recorder.py:154
- A selected candidate equivalent to an existing claim creates no new version and is marked duplicate with a CLAIM_EQUIVALENT_EXISTS note. — recorder.py:157-204
- Offered candidates get durable evidence ids filled in at record time. — recorder.py:211-219
- The planner and projection code identity is a digest of their source text. — recorder.py:65-68, ledger_cli.py:537

Verification phases
- Verification of SUPERSEDED or STALE claims is held with every phase skipped. — verifier.py:142-145
- Phase A blocks unknown evidence references, missing supporting evidence, evidence from another firmware or case, and dangling or unversioned dependencies. — verifier.py:147-171
- Phase B blocks non-canonical identifiers and session ids in the subject or assertion. — verifier.py:180-186, claim_checks.py:109-153
- Phase B blocks untyped claims whose prose call relations are unsupported. It holds instead when some result blob is unavailable locally. — verifier.py:190-202
- Phase B blocks typed claims whose semantics are inconsistent with the evidence. — verifier.py:203-213
- Phase B blocks a typed CALL_RELATION graded above its supporting edge's evidence. — verifier.py:215-217, call_relations.py:1012-1017
- Phase B blocks a proposed grade above the evidence ceiling. — verifier.py:219-228
- Phase B blocks dropped inherited limitation codes. — verifier.py:230-233
- Phase B blocks UNREACHABLE-type claims, and absolute-negative wording over NO_KNOWN_PATH evidence. — verifier.py:235-247
- A failure in A or B skips the later phases. A failure in C skips P and D. — verifier.py:176-178, 249-251, 321-323
- Phase C stales and invalidates evidence whose blob hash mismatches. A missing blob is held without replay and re-derived with replay. — verifier.py:257-277
- Phase C stales claims with invalidated supporting evidence. — verifier.py:279-280
- Phase C replays every replayable supporting invocation. A changed result stales the claim and invalidates the evidence. — verifier.py:292-309
- Without replay, phase C holds on input-artifact drift. — verifier.py:310-316
- Phase P records a fresh structural_source_agreement for material addresses, capped at 16. Above the cap or on failure it is UNEVALUABLE. — verifier.py:378-417
- Phase P condition kinds map to checks. Any CONTRADICTED condition blocks; other failing conditions hold. — verifier.py:329-343
- Precheck mode stops after phase P and never advances a claim (it only blocks or stales it). — verifier.py:345-347, 443-445
- Phase D holds when dependencies are not VERIFIED. — verifier.py:351-354
- Phase D ignores diagnostic audits. Any CHALLENGED audit permanently blocks the version. No audit, or an UNRESOLVED latest audit, holds. — verifier.py:356-373
- The outcome precedence is BLOCK > STALE > HOLD (-> PROPOSED) > VERIFIED. A state already staled during verification is kept. — verifier.py:427-441
- On a HOLD outcome a claim in any non-SUPERSEDED/STALE state, including VERIFIED or BLOCKED, is transitioned to PROPOSED. — verifier.py:439, 469-477
- Every verification writes a VerificationRecord with the current policy identity, phases, semantic checks and gate. — verifier.py:447-465
- BLOCKED and STALE outcomes propagate staleness to dependents. — verifier.py:479-480

Typed semantics
- Claim semantics carry exactly one body matching the predicate. — claim_semantics.py:284-297
- Addresses normalise to 0x%08x and functions to FUN_%08x. Set names are uppercased. — claim_semantics.py:106-149
- A POTENTIAL_INDIRECT relation requires conditions, and an OBSERVED_DISPATCH relation requires a scenario. — claim_semantics.py:257-265
- Each predicate is compatible only with listed claim types. A path status must match its claim type. — claim_semantics.py:322-330, 797-809
- Pointer, role and path facts are extracted from census resolved edges, the USB inventory, peripheral usage (MMIO site vs constant load), function_effects MMIO accesses, and common-path labels. — claim_semantics.py:476-544
- The registration caller is derived from the census containing function in structural agreement evidence. — claim_semantics.py:412-423, 487-490
- Resolved-pointer checks report consistent fields, swapped endpoints, role mismatches, unsupported fields, and a raw/canonical Thumb-bit mismatch. — claim_semantics.py:554-637
- Function-role checks match role, slot and peripheral context. — claim_semantics.py:640-678
- Path checks require evidence over exactly the claimed typed scopes. Set-kind equivalence is never assumed. — claim_semantics.py:681-730
- Common-path sides whose members differ from the sets the evidence produced become UNATTRIBUTED. — claim_semantics.py:469-471
- Code-presence checks require some agreement source recognising code at the address, and a matching start when an entry is asserted. — claim_semantics.py:733-794

Claim-quality and call-relation checks
- Malformed identifiers, session ids, unknown functions (with a resolver) and unknown numbered peripherals (with a known set) are rejected. — claim_checks.py:109-153
- An asserted peripheral access needs an MMIO_USER role in the cited evidence. A literal-pool load alone is reported. — claim_checks.py:163-205
- An asserted absence of access is rejected if the evidence shows access, or if effects coverage is incomplete or parametric, unless the wording is scoped. — claim_checks.py:207-251
- Call edges are extracted from function_facts, disassembly (bl/blx and b<cond> leaving the extent), callsite_context, indirect_call_target, callback_argument_provenance, observed_call_arguments and census resolved edges. — call_relations.py:170-358
- Edges with no source are attributed through instruction ownership from other cited evidence. — call_relations.py:352-357
- An asserted edge is checked by kind and scope. Missing, source, target or site mismatches and unresolved targets are classified. — call_relations.py:436-547
- Universal wording ("always", "every execution") is rejected for edges and reachability. — call_relations.py:494-499, 582
- Reachability needs a path of at most 8 cited edges, or a concrete entry in a named scenario, or census DEFINITELY_REACHABLE with census-scoped wording. — call_relations.py:550-617
- Absence is contradicted by any cited edge and admitted only with scoped wording. — call_relations.py:627-649
- Prose is parsed by a regex/token parser into edge, reach and absence assertions. Hedged clauses and clauses with unidentifiable endpoints become CALL_RELATION_UNCHECKED notes. — call_relations.py:830-891, 961-967
- A grade above the ceiling of the edge evidence is rejected for checked relations. — call_relations.py:897-920
- Call diagnostics are deduplicated by (code, detail). — call_relations.py:969

Policy and gate
- The verification policy has an id, version and digest over its canonical definition. — policy.py:27-28, 104-116
- The claim class is derived mechanically from claim type and semantics. Unmapped shapes are UNDETERMINED. — policy.py:119-171
- Only CODE_EXISTENCE has an evidence contract. Other classes yield NO_EVIDENCE_CONTRACT or CLAIM_CLASS_UNDETERMINED (UNEVALUABLE). — policy.py:51-83, gate.py:328-338
- Addresses are compared with bit 0 cleared. — gate.py:60-62
- Material code addresses come from typed pointer, role, code-presence and call bodies. Untyped and path claims have no materiality. — gate.py:73-111
- Contradictory evidence is classified as UNEVALUABLE (unresolvable, incompatible, invalidated, unavailable), UNRESOLVED (untyped claim, unclassifiable path, named entities), CONTRADICTED (structural or typed field or status conflict), or NOT_MATERIAL. — gate.py:235-324
- Structural CONFLICT at a material address is CONTRADICTED, without typed assertions UNRESOLVED, and elsewhere NOT_MATERIAL. A function-start disagreement on an asserted entry is UNRESOLVED. — gate.py:190-231
- Agreement evidence counts only if it is the agreement tool, compatible, valid, readable, and not cited as contradictory. — gate.py:461-481
- Code corroboration needs two qualifying sources with disjoint lineage and complete envelope fields on the same firmware, not assisted. A derived_from engine joins the lineage. — gate.py:155-164, 346-433
- Gate status precedence: CONTRADICTED -> BLOCKED; UNRESOLVED/UNMET -> HELD; UNEVALUABLE -> UNEVALUABLE; otherwise PASSED. — gate.py:483-492
- A read-only policy assessment re-evaluates a VERIFIED claim on recorded evidence and reports whether its decision applied the current policy. — gate.py:514-591

Audit
- The auditor context excludes the investigator's derivation and includes typed semantics, deterministic check summaries, limitations, dependencies, compact evidence and structural agreement. — auditor.py:763-842
- Before an audit, APTrace records structural source agreement for code addresses named by resolved pointer edges (at most 16). — auditor.py:324-347, 939-952
- Auditor decisions must be one JSON object (fenced or embedded). A verdict requires scope_check, and an unknown action or verdict is rejected. — auditor.py:139-217
- Auditor tools are a fixed allowlist with APTrace-validated arguments. Functions must appear in the visible evidence; peripherals must be in the catalog; registers r0/r1 are 32-bit ints. — auditor.py:413-674
- Duplicate audit requests, including requests matching visible evidence, are rejected and do not count. — auditor.py:436-443, 685-693
- KeyError, LookupError and FileNotFoundError results are coverage gaps that count as falsification. Other errors are tool errors that do not count. — auditor.py:126-136, 719-739
- A verdict before any successful falsification is rejected while budget remains. — auditor.py:1068-1090
- Requests after the budget are rejected. — auditor.py:1092-1111
- Parse failures get one correction retry per decision. — auditor.py:1023-1066
- Prefill-memory rejections are retried after a delay. — auditor.py:1029-1041
- A verdict without a successful falsification is recorded as a synthesized UNRESOLVED, keeping the model's verdict. No verdict gives a synthesized UNRESOLVED. — auditor.py:1182-1206
- Cited and contradictory evidence in a verdict is filtered to visible ids. — auditor.py:1208-1228
- Every audit records a deterministic ten-component input fingerprint without timestamps. — auditor.py:851-892
- Audit generation is temperature 0. Extra sampling parameters are part of the fingerprint. — auditor.py:931-937
- Audits never change claim state. — auditor.py:10-11 (asserted test_ledger_audit.py:244)
- A diagnostic audit of an ineligible claim is recorded and never counted. — pipeline.py:69-74, verifier.py:356
- The audit model is consulted only when precheck phases C and P passed and the claim is not BLOCKED, STALE or SUPERSEDED. — pipeline.py:33-78

Benchmarks, stability, report, CLI, wiring
- Benchmark fixtures run setup operations, propose claims, gate audits, verify, and compare against hidden expected outcomes. Keyword mentions do not affect pass/fail. — benchmark.py:96-267
- Audit stability groups audits by claim version and input fingerprint, computing verdict, tool-sequence and first-tool agreement and a coverage-gap heuristic. — stability.py:32-135
- The Markdown report is generated from the ledger with the embedded fingerprint, and is stale when the fingerprint differs. — report.py:36-243
- The report shows current-policy eligibility for VERIFIED decisions made under another or no policy. — report.py:223-230
- The CLI provides claims, candidates, policy-status, propose, supersede, audit, audit-repeat, runtime-probe, verify, replay, check, report and benchmark, each with --ledger-dir. — ledger_cli.py:27-93
- `propose` and `supersede` write claims directly from JSON specs, without admission. — ledger_cli.py:256-270
- `check` invalidates evidence whose blob is missing or hash-mismatched and stales its claims. — ledger_cli.py:337-356
- `replay` exits 1 on mismatch. `report --check` exits 1 if stale. `audit-repeat` refuses ineligible claims. — ledger_cli.py:278-281, 376-377, 414-417
- `runtime-probe` sends byte-identical requests to the oMLX runtime and records a sanitised runtime snapshot. — ledger_cli.py:126-140, 286-335
- Research runs are recorded with a hardcoded execution_config and a code-identity planner version. — ledger_cli.py:516-550
- The ledger directory defaults to the case ledger and can be overridden by --ledger-dir or APTRACE_LEDGER_DIR. The work dir defaults to ~/.aptrace/work/performing-rigs. — ledger_wiring.py:34-50
- The execution context hashes the census DB, Ghidra export, SVD, seeds, Macaw census, observation, indirect-target, callback and p-code inputs, and the Ghidra cache meta on every call. Missing files are dropped. — ledger_wiring.py:53-84
- IRQ handler prefixes resolve via the image vector table and SVD interrupt names. — ledger_wiring.py:87-103

## Cross-cutting observations (not segmentation)

- ISA/Cortex-M assumptions in framework ledger code: Thumb bit-0 normalisation (gate.py:60-62, claim_semantics.py:626-635, auditor.py:263-265); ARM mnemonics in call-edge extraction (call_relations.py:152-153, 183-186, 710-713); r0/r1 registers (auditor.py:649-664); 32-bit address formatting (claim_semantics.py:102-127); vector-table and SVD concepts (policy.py:37-39, ledger_wiring.py:87-103, models.py:95-97).
- Case or peripheral literals in framework ledger code: "USB" (claim_semantics.py:458, 508; auditor.py:531-535; benchmark.py:131); "USB"/"EIC" (claim_checks.py:174); SAM-style peripheral regex (claim_checks.py:95); "virtual-link" scenario kind (semantics.py:363); "census" source name (claim_semantics.py:420, auditor.py:361); "TCC1" example (auditor.py:629); the analyze_usb_interface audit tool (auditor.py:453, 633-637).
- ledger_wiring.py is case wiring at framework level (case name, SVD part ATSAMD51J19A, case research paths). ledger_cli.py binds to it directly, so every ledger CLI command defaults to the canonical case ledger.
- Dependency direction: the ledger package imports research (auditor.py:36-37 including a private symbol; recorder.py:161 lazily), source_agreement, census_graph and schemas.
- Adding a tool touches TOOL_INPUTS (operations.py:31-56), evidence_grade and evidence_limitations (semantics.py), ledger_wiring context_artifacts, and possibly extract_facts and extract_call_facts.
- Inconsistencies noted: the CLI help says precheck is "A-C" but it includes P (ledger_cli.py:78 vs verifier.py:345); `check` treats a missing blob as corruption while the verifier treats it as unavailable (ledger_cli.py:345-352 vs verifier.py:258-261); a HOLD outcome demotes VERIFIED or BLOCKED versions to PROPOSED (verifier.py:439).
- Tests depend on case data: the benchmark fixtures in cases/performing-rigs/research/benchmarks/ledger-v0, the canonical case ledger (read-only or copied), and AutoPilot addresses in ledger_support.py. All call-edge tests use ARM mnemonics only.
