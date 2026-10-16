# Sweep 2 — agent research controller subsystem

Scope: `agent/src/aptrace_agent/research/` (17 modules, 8,568 lines) and 17 test files in `agent/tests/` (4,045 lines). All files were read in full. Line numbers refer to the working tree on branch `feat/pcode-indirect-target` (2026-10-15).

## Production modules

```yaml
- path: agent/src/aptrace_agent/research/__init__.py
  purpose: Package facade; re-exports the research subsystem's public names.
  exports: Claim, ClaimGrade, Contradiction, DerivationResult, EvidenceLedger, FactDerivationResult, Hypothesis, Lead, LeadAction, LeadDeriver, LeadFollower, LeadGenerationIssue, LeadGenerationResult, LeadRegistry, LeadStatus, OpenQuestion, QuestionStatus, CaseReconciler, EntityReconciliation, ReconciliationProposal, ResearchSession, ResearchController, ResearchRunResult, ResearchStep, ResearchState, ResearchStateUpdater, StateFactDeriver, generate_case_search_leads_from_pin_table, generate_function_fact_leads, generate_pin_table_leads_from_callsite
  dependencies: research.controller, derivation, evidence, reconciliation, session, fact_derivation, follow, lead_generation, leads, state_updates, state
  data_shapes: none (re-export only)
  side_effects: none (importing it imports controller.py and transitively everything it imports)
  role: glue
  observations:
    - L1-10 docstring states the split of responsibility: APTrace owns evidence/provenance/execution/dedup/budgets/structural lead resolution; the model chooses direction, proposes claims/hypotheses, decides sufficiency.
    - L36-39 exports "pin_table" lead generators by name at package level (pin-table is a target-specific concept; see lead_generation).
    - Not exported: admission, candidates, followups, history, projection (imported by module path elsewhere).

- path: agent/src/aptrace_agent/research/admission.py
  purpose: Claim admission — decides whether a parsed model claim proposal becomes a PROPOSED claim or is rejected, with diagnostics.
  exports: UNTYPED_GRADE_CAP, admit, feedback, function_resolver
  dependencies: pydantic.ValidationError; ledger.claim_checks (EVIDENCE_MISSING, EVIDENCE_OMITTED, EVIDENCE_REFERENCE_UNKNOWN, GRADE_ABOVE_CEILING, HISTORICAL_REFERENCE, NOTE, OMISSION_EXPLAINED, REJECT, SEMANTICS_INCONSISTENT, SEMANTICS_INVALID, UNTYPED_GRADE, access_diagnostics, entity_diagnostics); ledger.call_relations (call_diagnostics, typed_grade_diagnostics); ledger.claim_semantics (ClaimSemantics, verify_semantics); ledger.models (GRADE_RANK, ClaimAdmission, ClaimDiagnostic, ClaimType, EvidenceGrade); ledger.semantics (evidence_grade, grade_ceiling). No case imports.
  data_shapes: consumes proposal dict {subject?, assertion, grade, claim_type?, semantics?, evidence_ids, omissions{E#: reason}, raw?}; session duck-typed (ledger.get, deriver.function_facts_reader, continuity.{seeded, followed, anchors}); produces ledger.models.ClaimAdmission {round, raw(<=600 chars), decision admitted|rejected, assertion, grade, claim_type, evidence_ids, omissions, diagnostics[]}.
  side_effects: none (reads session ledger in memory)
  role: admission
  observations:
    - L1-37 docstring enumerates six admission rules (references, entity identity, typed semantics/untyped prose rules, grade ceiling with untyped cap PROBABLE, follow-up accountability, historical reference notes).
    - L69 UNTYPED_GRADE_CAP = EvidenceGrade.PROBABLE.
    - L70 _FUNCTION_RE = r"\bFUN_[0-9a-f]{8}\b" — Ghidra default naming with exactly 8 hex digits (32-bit address assumption).
    - L73-89 function_resolver reaches into session.deriver.function_facts_reader (duck-typed via getattr chain); KeyError/ValueError => unknown function.
    - L92-106 _cited builds SimpleNamespace artifacts with evidence_grade(tool, result) for each cited id; unknown ids collected.
    - L109-157 _accountability: for each continuity-seeded lead that was followed, if its anchor or arguments["function"] is named in subject/assertion (or typed function_role), the follow-up evidence must be cited or omitted with explanation; missing => EVIDENCE_OMITTED REJECT; explained => OMISSION_EXPLAINED NOTE.
    - L185-199 typed semantics: validation failure => SEMANTICS_INVALID (first line of message, 300 chars); each failed verify_semantics check => REJECT.
    - L203-207 typed call semantics use typed_grade_diagnostics; untyped prose uses access_diagnostics and call_diagnostics (regex/prose checks in ledger).
    - L209-218 grade ceiling from grade_ceiling(ClaimType, artifacts); unknown claim type => ceiling UNKNOWN.
    - L220-227 untyped claims above PROBABLE rejected (UNTYPED_GRADE).
    - L231-241 reused-from evidence produces HISTORICAL_REFERENCE NOTE.
    - L257-270 feedback(): bounded (900 char) correction text listing rejected records' REJECT diagnostics.
    - Never mutates proposal ("Nothing is rewritten", L36).

- path: agent/src/aptrace_agent/research/evidence.py
  purpose: In-memory session evidence ledger that allocates sequential evidence ids E1, E2, ...
  exports: EvidenceLedger
  dependencies: research.state.ResearchState; aptrace_agent.schemas.EvidenceObservation
  data_shapes: dict[str, EvidenceObservation]; ids "E{n}"
  side_effects: none
  role: state model (evidence store)
  observations:
    - L20-21 next_id returns "E{n}" without reserving; L29-35 add() requires observation.id == next_id() else ValueError (ids allocated by APTrace, not the model, L11-13).
    - L37-40 duplicate id check (unreachable given the expected-id check, effectively defensive).
    - L45-46 optionally registers the id on ResearchState.evidence_ids.

- path: agent/src/aptrace_agent/research/follow.py
  purpose: LeadFollower — resolve one lead via LeadRegistry and execute its operation through an executor; mark FOLLOWED on success.
  exports: EvidenceOperationExecutor (Protocol), LeadFollower
  dependencies: research.leads.LeadRegistry; schemas.EvidenceObservation
  data_shapes: Protocol execute_operation(tool, arguments, *, evidence_id) -> EvidenceObservation
  side_effects: whatever the executor does (tool execution)
  role: glue (lead execution)
  observations:
    - L43-51 mark_followed is called only after execute_operation returns (exception leaves lead OPEN); no check of observation.status (a failed-but-returned observation still marks FOLLOWED).
    - Controller does not appear to use LeadFollower directly (see controller notes); used in tests (test_follow_lead.py).

- path: agent/src/aptrace_agent/research/state.py
  purpose: Pydantic models for the model-visible research state (claims, hypotheses, contradictions, open questions, leads).
  exports: ClaimGrade(PROVEN, SUPPORTED), LeadStatus(OPEN, FOLLOWED, DISMISSED), QuestionStatus(OPEN, RESOLVED), Claim, Hypothesis, Contradiction, OpenQuestion, Lead, ResearchState
  dependencies: pydantic, enum.StrEnum
  data_shapes: Claim{id, statement, grade, evidence_ids, basis?}; Hypothesis{id, statement, evidence_ids, source?}; Contradiction{id, description, evidence_ids}; OpenQuestion{id, question, evidence_ids, status, source?}; Lead{id, kind, description, source_evidence_ids, status, origin?}; ResearchState{objective, evidence_ids, claims, hypotheses, contradictions, open_questions, leads}
  side_effects: none
  role: state model
  observations:
    - L9-11 ClaimGrade has only PROVEN/SUPPORTED — distinct from ledger.models.EvidenceGrade used by admission (two grade vocabularies).
    - L30-35 Claim.basis documented values: "census", "raw-symbolic", "solver", "concrete-observed", "static-dataflow", "case-document"; None for older claims.
    - L60-66 Lead deliberately carries no tool name/address/pin index/path (backend payload kept in LeadRegistry).
    - L73-75 Lead.origin "followup:<key>" ranks first.
    - L91-94 add_lead raises on duplicate id; L96-100 lead() raises KeyError.

- path: agent/src/aptrace_agent/research/leads.py
  purpose: LeadRegistry — issues opaque lead ids (L1, L2, ...) and keeps the executable (tool, arguments) payload private; dedups by action.
  exports: LeadAction (frozen dataclass tool, arguments), LeadRegistry
  dependencies: json; research.state (Lead, LeadStatus)
  data_shapes: _LeadRecord{lead, action}; action key = canonical JSON {"tool","arguments"} sort_keys, default=str
  side_effects: none
  role: state model (lead registry)
  observations:
    - L40-53 dedup key is canonical JSON of tool+arguments; L69-89 re-registering an identical action returns the existing Lead and merges new source_evidence_ids into it (first kind/description win).
    - L113-124 resolve() raises KeyError unknown, ValueError if status not OPEN.
    - L126-138 mark_followed / dismiss mutate the shared Lead object (same object referenced from ResearchState.leads).
    - No method to list records or reopen a lead.

- path: agent/src/aptrace_agent/research/derivation.py
  purpose: LeadDeriver — maps a new evidence observation, by tool name, to mechanically derived leads (and issues).
  exports: DerivationResult (frozen dataclass leads, issues), LeadDeriver
  dependencies: research.lead_generation (CallsiteReader, FunctionFactsReader, LeadGenerationIssue, generate_case_search_leads_from_pin_table, generate_function_fact_leads, generate_function_leads_from_census, generate_function_leads_from_case_evidence, generate_pin_table_leads_from_callsite); research.leads.LeadRegistry; research.state.Lead; schemas.EvidenceObservation
  data_shapes: consumes EvidenceObservation{tool, arguments, result, id}; produces DerivationResult
  side_effects: none directly (readers may read census/Ghidra-derived data)
  role: lead generation (dispatch)
  observations:
    - L52-148 dispatch by hardcoded tool names: function_facts, callsite_context, search_case_evidence (only purpose=="discovery" and with a facts reader), census_peripheral_usage, _STRUCTURAL_TARGETS (census_common_paths, census_usb_inventory, function_effects), pin_table_entry; everything else yields no leads.
    - L150-189 _function_leads validates each target with function_facts_reader.function_facts(); invalid => LeadGenerationIssue kind "invalid-structural-function"; valid => function_facts lead.
    - L192-197 common-paths: excludes shared_utility, first 2.
    - L200-204 USB targets: "which accesses USB registers", first 3 — USB-specific lead kind.
    - L207-217 function_effects call targets: name = f"FUN_{int(target,16) & ~1:08x}" — clears bit 0 (ARM Thumb interworking bit) and assumes 8-hex-digit Ghidra naming; Cortex-M/Thumb-specific assumption in generic derivation. First 3 unique.
    - Limits (2, 3, 3) are hardcoded caps.

- path: agent/src/aptrace_agent/research/session.py
  purpose: ResearchSession — deterministic plumbing: owns ResearchState, evidence ledger, lead follower, derivations, and follow-up reuse via ContinuityTracker.
  exports: ResearchSession
  dependencies: research.derivation (LeadDeriver, LeadGenerationIssue), research.evidence.EvidenceLedger, research.fact_derivation.StateFactDeriver, research.follow.LeadFollower, research.history.ContinuityTracker, research.leads.LeadRegistry, research.state.ResearchState, schemas.EvidenceObservation
  data_shapes: state: ResearchState; derivation_issues: list[LeadGenerationIssue]; continuity: ContinuityTracker|None (followed[lead_id] = (evidence_id, reused: bool, step))
  side_effects: lead execution through follower/executor; otherwise in memory
  role: glue / session plumbing
  observations:
    - L55-87 _incorporate: always runs StateFactDeriver; derives leads only if deriver set and derive_leads; dedups by lead id; accumulates issues.
    - L89-132 follow_lead: if continuity present, resolves action and looks up history; reusable => _reuse (no execution); non-reusable decision => continuity.refuse(decision, trigger) then executes fresh; exceptions add lead_id to continuity.failed and re-raise; on success records followed tuple, ledger.add, incorporate.
    - L96 evidence id reserved via next_id() before execution; ledger.add later enforces it.
    - L134-153 _reuse: creates an EvidenceObservation with reused_from=original evidence id and historical result; marks lead FOLLOWED; appends reuse_record; derives leads from reused result.
    - L155-184 preload: reference-only historical result, facts only (derive_leads=False), records in continuity.preloaded; non-reusable => refuse(decision, "preload").
    - L186-199 record(): adds externally produced observation and incorporates it.
    - Docstring L19-25: "contains no model policy".

- path: agent/src/aptrace_agent/research/state_updates.py
  purpose: ResearchStateUpdater — merge claims/hypotheses/contradictions/open questions into ResearchState with whitespace/case-normalized dedup and sequential ids.
  exports: ResearchStateUpdater (merge_claim, merge_hypothesis, merge_contradiction, merge_open_question)
  dependencies: re; research.state (Claim, ClaimGrade, Contradiction, Hypothesis, OpenQuestion, ResearchState)
  data_shapes: ids C#, H#, X#, Q# computed as max existing numeric suffix + 1
  side_effects: none (mutates passed state)
  role: state model (update rules)
  observations:
    - L16-17 normalization: collapse whitespace, lowercase.
    - L53-69 merge_claim on duplicate: grade upgraded to PROVEN if either is PROVEN, else SUPPORTED; evidence ids unioned; basis of existing claim not updated.
    - L98-112 / L141-155 / L187-201 duplicates only union evidence ids; source of existing not changed.
    - L20-38 _next_id is gap-tolerant (max+1), ignores non-matching ids.

- path: agent/src/aptrace_agent/research/history.py
  purpose: Historical-operation lookup and reuse policy for follow-up sessions (continuity-v1), plus per-session continuity bookkeeping and its ledger record.
  exports: ContinuityTracker, DEFAULT_FALLBACKS(3), DEFAULT_FREE_REUSES(4), HistoricalOperations, POLICY("continuity-v1"), ReuseDecision, current_analysis_versions
  dependencies: ledger.hashing.canonical_json; ledger.models (ContinuityRecord, ExecutionContext, OperationReuse, ReuseRefusal, SeededLeadOutcome, ToolInvocation); ledger.operations (DETERMINISTIC_TOOLS, input_artifacts); ledger.semantics.canonical_arguments; ledger.store (EVIDENCE_VALID, ResearchLedger); lazy imports in current_analysis_versions: aptrace_agent.call_observation, callback_provenance, function_effects, indirect_target, value_forward_use (ANALYSIS_VERSION each)
  data_shapes: index canonical-operation-json -> [ToolInvocation] newest first; ReuseDecision{reusable, reason, invocation}; ContinuityTracker fields seeded{lead_id: (tool, args, description)}, anchors, followed{lead_id: (session_eid, reused, step)}, failed, offered, preloaded, counters; ContinuityRecord{policy, history_runs, history_invocations, reused, refused, seeded_leads[SeededLeadOutcome outcome reused|executed|attempted-failed|offered|not-offered], budget{...}}
  side_effects: reads the persistent ResearchLedger (runs, invocations, evidence, blobs); no writes
  role: state model / continuity policy
  observations:
    - L21-38 docstring: seven ordered reuse requirements; tool code changes without an analysis-version bump are not detected (replay needed).
    - L61 POLICY = "continuity-v1" (versioned policy identity); L62 MAX_HISTORY_INVOCATIONS=256; L65 DEFAULT_FREE_REUSES=4; L68 DEFAULT_FALLBACKS=3.
    - L71-80 current_analysis_versions hardcodes a five-tool map (function_effects, observed_call_arguments, indirect_call_target, callback_argument_provenance, value_forward_use) — new versioned tools must be added here by hand (tight coupling).
    - L83-84 operation identity = canonical_json of tool + canonical_arguments (defaults filled).
    - L112-125 history bounded to listed runs + cited evidence invocations, truncated at limit with self.truncated flag (truncated is not surfaced in ContinuityRecord, L289-305).
    - L141-145 for_followup: source run + earlier runs with the same followup_key + candidate.evidence_ids.
    - L150-163 lookup returns newest reusable decision, else the newest candidate's refusal.
    - L165-209 _check order: deterministic tool, ok+evidence, evidence present, same firmware sha256+key, input-artifact drift, operation key recomputed equal (operation_keys may return multiple keys for pre-canonicalization records), evidence VALID, blob present, blob integrity, declared analysis_version equal.
    - L258-265 charge(): reuses free up to max_free_reuses, else 1 step.
    - L286 seeded outcome precedence: attempted-failed > offered > not-offered.

- path: agent/src/aptrace_agent/research/lead_generation.py
  purpose: Lead producers that turn specific tool results into validated, registered leads (callsite, function, disassembly, pin-table, case-evidence) plus generation issues.
  exports: CallsiteReader (Protocol context(function, address, before=8, after=8)), FunctionFactsReader (Protocol function_facts(function)), LeadGenerationIssue{kind, description, reason, source_evidence_ids}, LeadGenerationResult{leads, issues}, generate_function_fact_leads, generate_pin_table_leads_from_callsite, generate_case_search_leads_from_pin_table, generate_function_leads_from_case_evidence, generate_function_leads_from_census
  dependencies: re; research.leads.LeadRegistry; research.state.Lead. No case imports.
  data_shapes: function_facts result {name|function|function_name, callers[{function|caller|caller_name|name, address|callsite|callsite_address|site}], callees[...]}; callsite_context result {function, address, instructions[{address, mnemonic, operands}]}; pin_table_entry result {gpio}; search_case_evidence result {query, matches[{source, excerpt}]}, arguments {purpose}; census_peripheral_usage result {status, peripheral, functions[{function}], unattributed_sites[{site, basic_block, detail}]}
  side_effects: none (validation calls readers)
  role: lead generation
  observations:
    - L45-59 _mapping accepts Mapping, pydantic model_dump, or __dict__ — duck-typed inputs.
    - L74-86 _address formats to 0x%08x (32-bit address width assumption).
    - L89-364 generate_function_fact_leads: incoming callers capped at max_incoming_calls=8; each validated via callsite_reader.context(caller, addr, before=0, after=0) (ValueError => issue "invalid-callsite"); lead tool callsite_context with before/after 8. Outgoing callees: callsite leads uncapped (only function expansion capped by max_outgoing_functions=6); each valid, non-self, non-duplicate callee additionally gets function_facts and function_disassembly leads; invalid => "invalid-outgoing-function".
    - L156-164 / L238-246 dedup identity (function, address) shared across incoming and outgoing.
    - L379-444 _direct_r0_literal_before_callsite: scans backward from the call instruction for the nearest instruction whose first operand is r0; only mov/movs/mov.w/movs.w with an immediate produce a literal; any other r0 writer stops the scan. This is ARM-mnemonic/register-specific text parsing (r0, ARM mov forms, '#' immediates) — ISA-specific operand semantics in the agent.
    - L447-495 generate_pin_table_leads_from_callsite: docstring L454-456 names "the Performing Rigs logical pin table" — case-specific concept in a framework module; lead kind "pin-table", tool pin_table_entry {index: literal}.
    - L498-544 generate_case_search_leads_from_pin_table: GPIO string => search_case_evidence {query: gpio, max_results: 8}, kind "case-evidence".
    - L548-554 regexes FUN_[0-9a-fA-F]{8} and 0x[0-9a-fA-F]{4,8}; L640-660 naked addresses become FUN_%08x candidates (no Thumb-bit clearing here, unlike derivation.py L214).
    - L557-762 discovery search: explicit FUN_ names validated (invalid => issue "invalid-discovered-function"), then address candidates validated silently (L704-708 invalid naked addresses not reported); cap max_functions=8; each yields function_facts + function_disassembly leads.
    - L765-903 census leads: only status=="ok"; cap max_functions=4 in census order; invalid => "invalid-census-function"; every unattributed_sites entry becomes an issue "unattributed-census-site" (incompleteness recorded, not dropped).

- path: agent/src/aptrace_agent/research/fact_derivation.py
  purpose: StateFactDeriver — converts structurally explicit tool results into atomic claims (all graded PROVEN in ResearchState) with a basis tag, plus APTrace-sourced open questions.
  exports: FactDerivationResult{claims}, StateFactDeriver (derive(observation, state)), MAX_CENSUS_FUNCTION_CLAIMS(4), MAX_CENSUS_UNATTRIBUTED_CLAIMS(2) (module constants)
  dependencies: research.state (Claim, ClaimGrade, ResearchState); research.state_updates.ResearchStateUpdater; schemas.EvidenceObservation
  data_shapes: per-tool result dicts — pin_table_entry {index, gpio, group, bit}; callsite_context {function, address, instructions[{address, mnemonic, operands}]}; census_peripheral_usage {status, peripheral, peripheral_base, provenance.reduction_status, totals, functions[{function, mmio_sites, mmio_site_count, constant_loads, reachability}], unattributed_sites}; census_common_paths {status, left_label, right_label, max_hops, left/right[{roots}], common[{function, shared_utility, path_left, path_right}], shared_state, frontier}; census_usb_inventory {register_users, irq_vectors, descriptors}; function_effects {status, accesses, coverage, inputs_used, reads, writes, calls, return_depends_on, return_bit_valued, specialized}; observed_call_arguments {status, function, scenario, call_sites, observed_entries, run, mmio_in_function}; callback_argument_provenance {status, argument_origins, site, candidate_targets, target_set, next_hops, open_reasons}; value_forward_use {status, origin, origin_value, scope, verdict, uses, incomplete, complete}; indirect_call_target {status, patterns, candidate_targets, derivation_status}
  side_effects: none (mutates ResearchState through the updater)
  role: fact derivation (evidence -> state claims)
  observations:
    - L652-658 docstring "Convert structurally explicit evidence into atomic PROVEN claims"; every derived statement uses ClaimGrade.PROVEN (L700, 743, 761, 787) including concrete-observed scenario facts, raw-symbolic Crucible facts, and "may escape" ESCAPE statements; evidence level carried only in basis and in statement wording.
    - basis values used: "static-table" (L701), "disassembly" (L744), "census" (L765), "census-graph", "raw-symbolic", "solver", "concrete-observed", "static-dataflow" — "static-table", "disassembly", "census-graph" are not in the Claim.basis comment list (state.py L30-35).
    - L21-101 _direct_r0_literal duplicates lead_generation._direct_r0_literal_before_callsite but requires a '#' immediate (L90-91), whereas lead_generation's _parse_immediate accepts without '#' — two diverging copies of ARM r0-literal parsing.
    - L104-142 _call_target: callsite mnemonic must start with "bl" (ARM BL/BLX; also matches any "bl*" mnemonic) and uses operand text as target — ARM-specific.
    - L177-288 census claims include explicit incompleteness text for no_matching_accesses / no_code_references ("runtime-computed addresses are not excluded").
    - L296-377 common-path: statuses KNOWN_COMMON_PATH/NO_KNOWN_PATH/SHARED_UTILITIES_ONLY; negative statements state "not proof of unreachability"; frontier generates an open question.
    - L380-444 USB inventory facts: USB-specific (IRQ vectors, USB descriptors); open question for handlers outside census vector table.
    - L447-482 observed-call facts: r0 argument values only (register "r0" hardcoded L468-470); "not entered... not thereby unreachable"; unobserved call sites => open questions.
    - L485-487 _argument: arg < 4 => r{arg}, else stack argument — AAPCS (ARM) register-argument convention hardcoded.
    - L526-558 value_forward_use facts: NO_ESCAPE_WITHIN_SCOPE and ESCAPE verdicts; incomplete items => questions; other verdicts produce only questions.
    - L561-594 indirect target facts: vtable-slot/object-table-slot/argument patterns; non-ESTABLISHED derivation => question.
    - L597-649 function_effects facts (status prefix complete/partial/"bounded: step limit"): "raw-symbolic" summary + up to 3 calls; return_bit_valued "proven" => solver claim; specialized accesses (non FLASH/RAM) => solver claims "Under {assumption}..." (conditional).
    - L769-777 tool->fact function map hardcoded; must be extended per new tool.
    - Open questions merged with source="aptrace" (L798).

- path: agent/src/aptrace_agent/research/candidates.py
  purpose: Deterministic claim candidates — typed facts extracted from session evidence (peripheral roles, resolved function pointers) with content-derived ids, ranking, rendering for the planner, selection parsing, and proposal construction.
  exports: ACCESS_UNDER_ASSUMPTION, CandidateSet{candidates, withheld; offer(limit), find(id)}, DEFAULT_LIMIT(5), GENERATOR("candidates-v1"), GRADE_INSUFFICIENT, POINTER_CONFLICT, ROLE_CONFLICT, SEMANTICS_UNSUPPORTED, SeededEvidence, candidates_for_run, equivalent_claims, evidence_identity, generate_candidates, parse_selection, proposal_for, render, seeded_evidence (also CANDIDATE_ID_RE, ROLE_EXTRACTOR, POINTER_EXTRACTOR module-level)
  dependencies: ledger.claim_checks (ENTITY_UNKNOWN, PERIPHERAL_UNKNOWN); ledger.claim_semantics (ClaimSemantics, FunctionRole, FunctionRoleClaim, Predicate, ResolvedPointer, addr, extract_facts, fun, verify_semantics); ledger.hashing.digest; ledger.models (CandidateWithheld, ClaimCandidate, ClaimState, ClaimType, EvidenceGrade); ledger.semantics (canonical_result, evidence_grade, grade_ceiling); lazy ledger.store.EVIDENCE_VALID (L618)
  data_shapes: ClaimCandidate{candidate_id "K-"+12hex, extractor, subject, claim_type, semantics, grade, assertion, scope, assumptions, limitations, supporting_evidence_ids, prior_evidence_ids, considered{E#: reason}, seeded_leads, existing_claims}; CandidateWithheld{code, fact, detail, evidence_ids}; proposal dict as consumed by admission plus limitations, scope, assumptions, candidate_id, derivation, raw="select K-..."
  side_effects: none (reads persistent ledger only in candidates_for_run / equivalent_claims)
  role: claim candidates (extraction, ranking, selection)
  observations:
    - L1-40 docstring: extraction vs selection vs admission separated; extractors deliberately few; not extracted: call-site relations, bounded effects, negative assertions; candidate id excludes session numbering so reuse and fresh execution give the same id.
    - L67 GENERATOR = "candidates-v1" (versioned identity, enters the id digest L523-531).
    - L82 only EXACT/STRONG/PROBABLE support positive facts.
    - L83 _FUNCTION_RE FUN_[0-9a-f]{8}; L84 _PERIPHERAL_RE \b[A-Z]{2,6}\d{1,2}\b (heuristic peripheral token pattern, e.g. USART1/SPI2 naming convention).
    - L198-216 function_effects MMIO access withheld (ACCESS_UNDER_ASSUMPTION) if argument specialization present or addresses parametric/input-dependent.
    - L219-244 effects limits: parametric inputs or non-complete coverage recorded as "limits, does not support" on loader candidates.
    - L247-301 peripheral roles grouped by (entry, peripheral); ADDRESS_CONSTANT_LOADER withheld as ROLE_CONFLICT when any MMIO access for the same function (including unattributed-peripheral accesses) exists.
    - L319, 322, 327 scope texts name engines (Ghidra reference manager, Macaw/Crucible) and "heuristic function boundaries".
    - L384-446 resolved pointers grouped by slot; any field disagreement => POINTER_CONFLICT withheld; text "RAM function-pointer slot".
    - L478-548 per-draft gates in order: support grade, unknown function (ENTITY_UNKNOWN), unknown peripheral (PERIPHERAL_UNKNOWN), grade ceiling, verify_semantics (defensive SEMANTICS_UNSUPPORTED); seeded-lead evidence about named functions that does not support becomes a "considered" omission text (_NOT_SUPPORT); dedup by semantics JSON (first wins).
    - L553-554 _session_order parses "E<n>".
    - L557-575 ranking: objective function names, objective peripherals, seeded-lead relation, novelty (no existing claim first), kind order MMIO_USER<RESOLVED_FUNCTION_POINTER<ADDRESS_CONSTANT_LOADER, id.
    - L578-602 equivalent_claims: existing ledger claim versions with identical semantics, excluding SUPERSEDED.
    - L605-641 candidates_for_run: read-only preview over a recorded run's evidence + reused evidence, skipping invalid/missing/tampered blobs; reused_from=None there.
    - L671-673 comment: render uses a plain sentence because bracketed annotations caused local runtime "incomplete_tool_call" rejections in measured replays (model-runtime-specific workaround).
    - L683-707 parse_selection: only K- tokens; must exactly match offered ids; non-empty text other than none/no/n/a without tokens recorded as invalid.

- path: agent/src/aptrace_agent/research/followups.py
  purpose: Deterministic follow-up candidate generation for a recorded investigation run (frontier re-derivation, claim evidence gaps, audits, verification conditions, staleness), redundancy/bounds finalization, continuity review, and seeding of a follow-up session.
  exports: AVAILABLE_TOOLS, BLOCKED, CLAIM_FOLLOWUP, DEFAULT_LIMIT(3), FollowUpCandidate, FollowUpGenerator, FollowUpReport, Frontier, FrontierLead, GENERATOR_VERSION("followups-v1"), LEAD_GROUP, PROPOSED, REDUNDANT, generate_followups, continuity_review, rederive_frontier, seed_session (also MAX_SEED_LEADS=8, MAX_QUESTIONS=3, QUESTION_CHARS=200, OBJECTIVE_CHARS, DEVICE_IDENTITY_CODE, HARDWARE_BLOCKER, DeriverFactory)
  dependencies: pydantic; ledger.hashing (canonical_json, digest); ledger.models (AuditVerdict, ClaimState, ClaimVersion, EvidenceArtifact, ExecutionContext, FollowUpProvenance, InvestigationRun); ledger.operations (TOOL_INPUTS, input_artifacts); ledger.store.ResearchLedger; research.derivation.LeadDeriver; research.history (ContinuityTracker, HistoricalOperations); research.leads.LeadRegistry; research.projection (ProjectionBudget, clip); research.session.ResearchSession; research.state (Hypothesis, OpenQuestion); schemas.EvidenceObservation. Does not import the work package (L8-9).
  data_shapes: FrontierLead{kind, description, tool, arguments, source_evidence_ids, anchor, documentary}; Frontier{status re-derived|unavailable, detail, recorded_open_count, leads, issues}; FollowUpCandidate{key(24 hex), question_key(16 hex), category claim-followup|lead-group, rank 1-3, priority_basis, objective, reason, information_gain, source_run_id, claim_versions, audit_ids, verification_ids, evidence_ids, seeded_leads, lead_count, open_questions, prior_hypotheses, analyses_performed, limitations, status proposed|redundant|blocked, status_detail, blocker, firmware_derived}; FollowUpReport{generator_version, run_id, case, firmware_key, run_context_id, current_context_id, limit, frontier, shortlist, deferred, suppressed, limitations}; internal _Gap; continuity_review returns dict.
  side_effects: reads the persistent ResearchLedger (runs, invocations, evidence, blobs, audits, verifications, events, claims); no writes. seed_session mutates the in-memory session and may preload historical results.
  role: follow-up generation / continuity
  observations:
    - L1-39 docstring: sources (re-derived frontier, claim gaps, audits, verification conditions, STALE); rank categories 1-3 (not confidence); ties by relationships, firmware-derived, key.
    - L70 GENERATOR_VERSION = "followups-v1"; question_key digests include {"v": 1, ...} (L798, L832, L910).
    - L88-95 AVAILABLE_TOOLS = TOOL_INPUTS keys plus six audit tool-surface names (inspect_evidence, analyze_peripheral, analyze_usb_interface, find_common_paths, analyze_function_effects, replay_evidence) — duplicated surface naming from ledger/auditor.py.
    - L101-105 DEVICE_IDENTITY_CODE "STRUCTURAL_USAGE_NOT_DEVICE_IDENTITY"; HARDWARE_BLOCKER text (no APTrace operation provides board-routing evidence).
    - L107-109 regexes: FUN_ 8-hex, access verbs, device-attachment phrasing (prose pattern-matching disclosed in basis).
    - L282-365 rederive_frontier: unavailable without a deriver factory or when run.context_id != current context id; replays LeadDeriver over run invocations in order with session ids mapped to durable ids; leads whose action was attempted (any status) are excluded; anchor = first source evidence's function/peripheral/query; documentary = source tool search_case_evidence; mismatch against recorded planner_requests open_leads count noted "(MISMATCH: frontier may be incomplete)".
    - L385-405 _call_neighbours from function_facts evidence callers/callees.
    - L408-494 PERIPHERAL_ACCESS_UNESTABLISHED gap (rank 1): census shows mmio_site_count 0 with constant loads and no function_effects MMIO access.
    - L497-514 DEVICE_IDENTITY_REQUIRES_HARDWARE gap: blocked with HARDWARE_BLOCKER.
    - L517-558 audit gaps: latest non-diagnostic CHALLENGED (rank 1) / UNRESOLVED (rank 2); each follow_up_request => AUDIT_REQUEST (blocked when suggested tool unavailable); otherwise AUDIT_CHALLENGE per challenge.
    - L561-600 verification gaps from latest non-VERIFIED record: gate conditions UNMET/UNEVALUABLE/UNRESOLVED => GATE_*; CONTRADICTED => note only ("revising the claim is an operator decision"); failed "hold" checks => CHECK_*.
    - L603-618 STALE_CLAIM (rank 2) with last lifecycle event reason.
    - L641-658 performed(): maps operation_key -> (evidence, run) over all ok invocations; uses private ResearchLedger._key to alias pre-canonicalization keys (coupling to a private ledger method).
    - L678-716 generate: claim candidates per run claim (only PROPOSED/STALE states), then lead-group candidates for remaining anchors; shortlist = first `limit` PROPOSED; rest deferred; non-PROPOSED suppressed.
    - L731-829 claim candidate absorbs lead groups whose anchor is the gap's functions or their direct call neighbours, and leads elsewhere targeting those functions; objective text clipped "Confirm or falsify ... do not assume the claim is true"; prior claim becomes a prior_hypothesis "[prior KEY STATE, unverified]".
    - L831-849 blocked candidates: information_gain "none obtainable with available tools".
    - L876-929 lead-group candidates: rank 2 when linked to a run claim through firmware-derived evidence and not documentary, else 3; documentary groups phrased as "prior human findings".
    - L933-978 _finalize: seeded leads already performed under current inputs moved to analyses_performed; seeded leads capped at MAX_SEED_LEADS with a limitation note; REDUNDANT when a previous follow-up run has the same key, or a lead-group has no remaining leads.
    - L995-1031 continuity_review: read-only; question_status always "OPEN" — a follow-up run never resolves the question.
    - L1037-1088 seed_session: registers seeded leads, adds open questions PQ#, prior hypotheses PH# with source "followup:<key>"; with history: creates ContinuityTracker, sets Lead.origin, records seeded/anchors, preloads candidate evidence via session.preload. Without history: "spike behaviour" (L1047-1048).

- path: agent/src/aptrace_agent/research/projection.py
  purpose: Bounded, deterministic planner-facing rendering of a research session (already-run analyses, inspected functions, newest facts, open items, latest results) and a final conclusion that groups by evidence level.
  exports: SUBSYSTEM_TOOLS, INSPECTION_TOOLS, ProjectionBudget, COMPACT_BUDGET, clip, functions_in, summarize_observation, analysis_label, PlannerProjection (sections, render, objective), known_functions, conclusion
  dependencies: json, re; research.session.ResearchSession; research.state.Claim; schemas.EvidenceObservation
  data_shapes: ProjectionBudget character budgets (objective 640, analyses 300, inspected 170, facts 700, fact_line 160, open_items 260, item_line 130, latest 480, latest_first 330, latest_count 2, total 1700); COMPACT_BUDGET (total 850, inspected 0, latest_count 1); conclusion -> {proven, probable, open} lists of strings
  side_effects: none
  role: projection (planner context rendering)
  observations:
    - L14-25 SUBSYSTEM_TOOLS list of 8 tools; L28-33 INSPECTION_TOOLS tags; both hardcoded per tool.
    - L37-47 _BASIS_TAGS map (census, census-graph->graph, raw-symbolic->RAW, solver->SOLVER, case-document, disassembly, static-table, concrete-observed->OBS, static-dataflow->DF).
    - L50-60 budgets in characters, not tokens (documented ~3.5-4 chars/token proxy).
    - L75-85 COMPACT_BUDGET "Used for one retry when the local model rejects a request at prefill" (local-runtime-specific).
    - L134-224 summarize_observation: tool-owned planner_summary wins; per-tool renderers for function_facts, function_disassembly, callsite_context (window -2..+4 around call), census_peripheral_usage, pin_table_entry, search_case_evidence; unknown tools dumped as JSON then clipped.
    - L257-296 analysis_label: labels for subsystem tools and discovery case searches; specialization args appended to effects label.
    - L317-328 reused results marked "=prior".
    - L381-414 facts ranked by newest evidence number; non-PROVEN tagged ",supported"; omitted count shown "retained by APTrace".
    - L416-449 open items: hypotheses, contradictions, OPEN questions (newest first).
    - L476-493 preloaded continuity results excluded from LATEST but included in ALREADY RUN/INSPECTED.
    - L495-520 render: trims the longest section repeatedly to fit total; stops when all sections <=124 chars (may still exceed total).
    - L526-540 known_functions: FUN_ names from results and arguments (8-hex regex L35).
    - L543-578 conclusion: "proven" = all PROVEN-grade state claims (which include concrete-observed, raw-symbolic, static-dataflow facts per fact_derivation), "probable" = SUPPORTED claims + hypotheses, "open" = OPEN questions; limit 8 each.

- path: agent/src/aptrace_agent/research/reconciliation.py
  purpose: CaseReconciler — LLM-driven reconciliation of collected (non-discovery) case-document search results with APTrace PROVEN pin-table/callsite claims, producing SUPPORTED entity-role claims and open questions.
  exports: EntityReconciliation{query, status SUPPORTED|NO_SUPPORTED_INTERPRETATION, role, context, unresolved}, ReconciliationProposal{reconciliations}, CaseReconciler (run(session))
  dependencies: os, re; openai.OpenAI; pydantic (BaseModel, ConfigDict, Field, ValidationError); research.session.ResearchSession; research.state.ClaimGrade; research.state_updates.ResearchStateUpdater
  data_shapes: consumes search_case_evidence observations {result.query, result.matches[{source, line, excerpt}]}; model JSON per ReconciliationProposal (extra="forbid")
  side_effects: network model calls via OpenAI-compatible client (env OMLX_BASE_URL, OMLX_API_KEY, APTRACE_MODEL; max_retries=0, timeout 120 s, temperature 0.0); up to 3 requests (initial, schema correction, semantic correction); mutates session state
  role: reconciliation (model-assisted, documentary)
  observations:
    - L45 docstring "cannot create PROVEN claims"; L590-595 writes SUPPORTED claims with no basis set.
    - L54-64 constructor reads env vars directly with os.environ[...] (KeyError if absent and no client supplied).
    - L136-206 _structural_claim_ids_for_query: regex over claim statement prose "Logical pin-table index N maps to GPIO X " and " with r0 literal N (0x..)." — couples to fact_derivation's exact English templates (fact_derivation.py L695-698, L737-741) and to the pin-table / r0 concept.
    - L236-286 _validate: queries must exactly equal collected case queries, no duplicates; SUPPORTED requires role and at least one deterministic structural claim id.
    - L341-410 prompt: L386 "- Do not re-analyze FUN_0000d3dc." — hardcoded firmware function address (case-specific, presumably the Performing Rigs/AutoPilot target) in a framework module.
    - L434-472 schema-validation failure => one correction request; L479-541 semantic validation failure => one correction; second failure raises RuntimeError ("never ingest the invalid first proposal", L474-478).
    - L603-612 unresolved items become open questions citing only the case evidence id (source unset).
    - Only applies to case searches whose purpose != "discovery" (L296-303).

- path: agent/src/aptrace_agent/research/controller.py
  purpose: ResearchController — the model-directed bounded research loop: builds a per-decision tool palette, prompts an OpenAI-compatible local planner, validates its single tool call, executes leads/structural analyses via the session, enforces budgets, and at termination handles hypotheses/open questions, claim admission (claim contract), claim-candidate selection, and terminal case reconciliation.
  exports: STRUCTURAL_TOOLS, EXPERIMENTAL_STRUCTURAL_TOOLS, MAX_OFFERED_SITES(12), CLAIM_TYPES, CLAIM_GRADES, MAX_PROPOSED_CLAIMS(3), CLAIM_FORMAT, ResearchStep, ResearchRunResult, ResearchController (public method run(session)); internal _Palette, _function_tool, _prefill_rejected
  dependencies: json, os, re, sys, time; openai.OpenAI; research.projection (COMPACT_BUDGET, PlannerProjection, ProjectionBudget, clip, known_functions); research.reconciliation.CaseReconciler; research.session.ResearchSession; research.state_updates.ResearchStateUpdater; lazy imports: ledger.claim_checks (CLAIM_UNPARSEABLE, REJECT, CANDIDATE_NOT_OFFERED, CANDIDATE_UNKNOWN), ledger.models (ClaimAdmission, ClaimDiagnostic, CandidateSelection), research.admission (admit, function_resolver, feedback), research.candidates (module, render). No case imports.
  data_shapes: ResearchStep{number, action, lead_id, evidence_id, reason, reused_from}; ResearchRunResult{stop_reason, steps, reconciled, planner_requests, proposed_claims, claim_admission, candidate_selection}; planner request record {phase, evidence, open_leads, claims, prompt_chars, state_chars, message_bytes, tool_bytes, tools, total_bytes, attempt, compact?, error?, prompt_tokens, decision?}; OpenAI function-tool JSON schemas (additionalProperties false); parsed claim proposal dict {subject, assertion, claim_type, grade, evidence_ids, limitations, semantics, omissions, raw}
  side_effects: network chat-completions calls (temperature 0.0, max_tokens 512, tool_choice auto) to planner via env OMLX_BASE_URL/OMLX_API_KEY/APTRACE_MODEL; reconciler model via APTRACE_REVIEW_MODEL (default "gemma-4-26b-a4b-it-4bit"); time.sleep on prefill rejection; optional stderr debug print (APTRACE_DEBUG_PLANNER_REQUEST=1); optional JSONL append to file APTRACE_PLANNER_LOG; tool execution through session.follow_lead
  role: controller loop
  observations:
    - L35-43 STRUCTURAL_TOOLS (usb_inventory, common_paths, function_effects, observed_call_arguments, indirect_call_target, callback_argument_provenance, value_forward_use); L48 EXPERIMENTAL_STRUCTURAL_TOOLS = ("value_forward_use",) requires explicit opt-in (L231-241), comment cites admission gap (docs/tooling/pcode-forward-use.md).
    - L50 _FUNCTION_RE FUN_[0-9a-f]{8} (no word boundary); L52 _ADDRESS_RE 0x 1-8 hex; addresses rendered 0x%08x (L559-562) — 32-bit address assumption.
    - L57-70 claim line format "GRADE [TYPE] E#,E# assertion"; L60-62 comment: one scalar string because the local planner's tool-call output degenerates on nested arrays (model-runtime-driven design); L64-65 "[omit E#: reason]" suffix.
    - L74-84 _STRUCTURAL_SOURCES tool names ranking leads first.
    - L160-172 _prefill_rejected: detects oMLX "prefill_memory_exceeded"/"prefill memory guard" in exception or body (local-server-specific).
    - L175-185 docstring names "Qwen" as the planner.
    - L187-216 constructor parameters and bounds: max_steps 12, max_discovery_steps 3, recent_evidence_limit 2, max_structural_analyses 4, max_effects_analyses 3, max_path_analyses 3, max_observations 2, max_indirect_targets 2, max_callback_traces 2, max_value_traces 2, max_visible_leads 6, prefill_retry_delay 3.0, claim_contract False, max_claim_candidates 0; validation errors for invalid values.
    - L243-260 OpenAI client constructed from env when not injected (KeyError on missing env); reconciler constructed eagerly (also needs env).
    - L273 withheld_tools: experimental tools not opted in are never offered and leads that would run them are hidden (L1452-1458).
    - L296 max_claim_corrections hardcoded 1.
    - L342-359 analyzable peripherals: excluded when census budget reached, while follow-up seeded leads are open, or already analyzed (USB counted as analyzed if usb inventory ran).
    - L391-528 _structural_palette: each tool offered only when enabled, under its budget (counting only executed, not reused, observations), and grounded: analyze_usb_interface only if objective mentions "usb" or USB census exists (L399-402, USB-specific relevance rule); find_common_paths needs >=2 named sets; effects/observation need known functions; indirect/callback/value tools need allowed addresses that already appear in evidence.
    - L447 analyze_function_effects exposes "r0/r1 optionally fix arguments" — ARM register names in the planner tool schema; L971 range 0..0xFFFFFFFF (32-bit).
    - L482 resolve_indirect_call description "(blx/bx register)" — ARM mnemonics in planner text.
    - L530-562 _grounded_sites: allowed addresses found by regex over JSON of other tools' results, newest evidence first; callback sites prioritized where indirect_call_target reported an "argument" pattern; capped at 12.
    - L564-572 cooldown: tool dropped while remaining >0 if more than one tool remains.
    - L574-597 decision palette: follow_lead (enum of visible lead ids), structural tools, finish; records offered seeded leads into continuity.offered.
    - L599-619 discovery palette: search_case_evidence + structural + finish("End discovery").
    - L621-642 finish tool: reason, hypotheses, open_questions; with claim_contract adds claims string.
    - L644-648 _sanitize_claims classmethod wraps _parse_claims (not called within controller; appears to be kept for external/test use).
    - L650-725 _parse_claims: string split into lines; at most MAX_PROPOSED_CLAIMS*3 items scanned and MAX_PROPOSED_CLAIMS kept; regex parse, dict items also accepted; clipping (subject 120, assertion 400, limitations 240 x4, evidence 8); unknown claim_type -> OTHER.
    - L727-752 _admit_round: unparseable lines recorded as ClaimAdmission decision "unparseable" with CLAIM_UNPARSEABLE; each proposal through admission.admit with function resolver and census peripherals; admitted ones appended to proposed_claims with admission index.
    - L754-771 _accept_claims: one correction request after rejections (round 2) only if planner returns finish.
    - L773-855 _select_candidates: only when claim_contract and max_claim_candidates>0; existing-claim lookup only when the session has continuity history ledger; outcomes no-candidates | planner-failed | selected | none; invalid tokens recorded as rejected admissions (CANDIDATE_NOT_OFFERED if in omitted list, else CANDIDATE_UNKNOWN); selected proposals pass admit(); no correction round.
    - L859-875 _analysis_problem: duplicate peripheral sets palette.duplicate; withheld while follow-up leads open.
    - L877-901 _resolve_set: 1-4 members, analyzed peripheral names (upper-cased) or known FUN_ names; label truncated to 40 chars.
    - L903-1066 _parse_structural: per-tool argument validation, extra-argument rejection, duplicate detection against existing observations (sets palette.duplicate), enum membership; returns (action, args) | problem | None.
    - L1070-1093 _record_request: measures each planner request (bytes/chars) into planner_requests.
    - L1096-1126 _tool_call: takes the first of several parallel calls; JSON-object arguments required.
    - L1128-1133 _begin_decision: compact projection for decisions while _compact_decisions > 0.
    - L1183-1339 _ask_once: up to 2 attempts; prefill rejection => sleep(delay), sleep(delay*3.3) retries with compact projection and 3 compact decisions, then "planner_prefill_exhausted"; duplicate analysis requests retried without that tool (cooldown 2) without consuming the correction (bounded by len(STRUCTURAL_TOOLS)+1); one correction message on first invalid response; exhaustion returns "finish" (discovery) or the `exhausted` action with both errors.
    - L1248-1269 env-controlled debug output and planner log file append (writes full messages/tools/content).
    - L1346-1407 _analysis_guidance: ordered preference text; "Census facts do not identify attached devices."
    - L1409-1461 _planner_open_leads: follow-up (origin) leads first, then base rank by tool (function_facts 0, disassembly 1, pin_table/search 2, census 0, callsite 4, other 3; +2 for non-structural function crawling), newest first; limit 4 when compact else max_visible_leads.
    - L1467-1497 _compact_lead_text: planner sees tool+identity, not description; L1480 `origin = ""` is a dead variable concatenated into strings; follow-up leads tagged "[follow-up]" (L1465).
    - L1505-1516 _prompt/_decision_prompt accept a bare list "compatibility path" (L1509-1516); L1559-1565 _discovery_prompt wrapper likewise.
    - L1527-1545 decision prompt rules 0-4 (follow-up first, analyze named subsystem, common paths, follow leads, finish); "Never repeat an ALREADY RUN analysis or invent identifiers."
    - L1579-1582 discovery prompt: one lexical search 1-3 terms; L1653-1657 query 2..120 chars, not previously tried (casefold).
    - L1683-1727 _request_final_claims: finish-only request after budget; prompt says "claims are graded PROBABLE" and "Name functions exactly as FUN_xxxxxxxx".
    - L1749 example claim text uses FUN_0000a000 (illustrative address).
    - L1778-1838 _request_candidate_selection: small request (objective + rendered candidates, no state); select_claims tool with "selected" string.
    - L1842-1854 _follow_new_lead: structural actions are registered as leads with no source evidence and followed immediately (so LeadRegistry dedup applies).
    - L1856-1873 peripheral analysis args {peripheral, limit: 25}; discovery search args {query, max_results: 8, purpose: "discovery"}.
    - L1961-1975 _record_conclusions: up to 3 hypotheses/open questions each, clipped 240, source "planner", no evidence ids; never PROVEN.
    - L1977-1989 terminal reconciliation only if non-discovery case searches exist.
    - L2007-2016 _fallback_lead: only in follow-up sessions, bounded by continuity.max_fallbacks.
    - L2018-2155 run(): loop while charged < max_steps; stop reasons: discovery_exhausted, research_graph_exhausted, planner_prefill_exhausted, planner_contract_exhausted, discovery_finished, planner_finished, step_budget_exhausted; discovery mode only when session started empty (no evidence, no leads) and no open leads; fallback lead on planner_contract_exhausted; follow-up final-claims request when planner fails after doing work; exceptions from session.follow_lead are not caught (propagate out of run).
    - L2036-2041 charge(): continuity.charge (free reuses) else 1 step.
    - discovery_exhausted and discovery_finished return reconciled=False without reconciliation (L2069, L2116).

```

## Test files

```yaml
- path: agent/tests/test_research_controller.py
  purpose: Unit tests of ResearchController loop termination and planner retry using fake planner/executor/reconciler.
  covers: research.controller.ResearchController.run, _request_discovery; research.session; research.leads
  behaviors:
    - zero open leads, discovery disabled -> stop "research_graph_exhausted", no planner call, no reconciliation (L140-167)
    - follow_lead executes and assigns E1, then graph exhausts (L170-211)
    - finish respected -> "planner_finished" with one finish step (L214-254)
    - recorded non-discovery case evidence triggers terminal reconciliation once (L257-291)
    - missing tool call gets exactly one retry (L294-328)
    - response with no choices is retried (L383-411)
    - repeated discovery query (already tried) twice -> discovery returns finish with "could not produce" (L414-453)
  observations:
    - Fixture data uses case-flavoured strings ("PA22", "TMC5160 SPI") (L265, L422).
    - Drives private method controller._request_discovery directly (L443).

- path: agent/tests/test_research_session.py
  purpose: Tests EvidenceLedger id allocation and ResearchSession.follow_lead bookkeeping.
  covers: research.evidence.EvidenceLedger, research.session.ResearchSession, research.follow.LeadFollower
  behaviors:
    - ledger next_id E1 -> E2 after add, len, get (L40-58)
    - out-of-sequence id rejected with "expected evidence id E1" (L61-75)
    - follow_lead records E1 in ledger and state, marks lead FOLLOWED, passes evidence id to executor (L78-116)
    - sequential follows get E1, E2 (L119-159)
  observations:
    - Uses AutoPilot-looking identifiers FUN_0000d3dc, FUN_00006968, 0x000069a4 as fixture data (L50, L86-87).

- path: agent/tests/test_research_state.py
  purpose: Tests Lead payload hiding, LeadRegistry resolution/status, ResearchState bookkeeping.
  covers: research.leads.LeadRegistry, research.state (Lead, ResearchState, Claim)
  behaviors:
    - model-visible Lead dump contains no tool/address/function payload (L12-37)
    - registry resolves private (tool, arguments) (L40-54)
    - followed lead cannot be resolved again ("not open") (L57-72)
    - state dedups evidence ids, tracks claims and open leads (L75-110)
    - duplicate lead id rejected (L113-127)
  observations:
    - Fixture objective "Determine the role of FUN_0000d3dc(1)." and FUN_00006968/0x000069a4 (L77, L100-101).

- path: agent/tests/test_state_updates.py
  purpose: Tests ResearchStateUpdater merge/id rules.
  covers: research.state_updates.ResearchStateUpdater
  behaviors:
    - claim ids C1, C2 (L8-30)
    - whitespace-normalized duplicate merges, upgrades to PROVEN, unions evidence (L33-62)
    - H1, X1, Q1 id allocation (L65-101)
    - PROVEN not downgraded by SUPPORTED duplicate (L104-129)
  observations: none.

- path: agent/tests/test_reconciliation.py
  purpose: Tests CaseReconciler with a fake model client.
  covers: research.reconciliation.CaseReconciler; research.fact_derivation (pin_table_entry claim used as structural provenance)
  behaviors:
    - SUPPORTED reconciliation ingests a SUPPORTED claim and open question (L94-136)
    - reconciliation missing a required query fails "semantic validation twice" (L139-157)
    - SUPPORTED without structural PROVEN claim fails twice (L160-190)
    - claim evidence ids attached by APTrace: structural claim's evidence + case evidence (E1, E2) (L193-233)
  observations:
    - Fixture GPIO "PA22" (AutoPilot/Performing Rigs pin); comment L229 names "Gemma" (the review model).
    - NeverExecutor.execute_operation signature takes evidence_id positionally, unlike the Protocol's keyword-only (L14-21) — unused.

- path: agent/tests/test_fact_derivation.py
  purpose: Tests StateFactDeriver for pin-table and callsite r0-literal facts.
  covers: research.fact_derivation.StateFactDeriver
  behaviors:
    - pin_table_entry -> PROVEN "Logical pin-table index 1 maps to GPIO PA22 (group 0, bit 22)." (L9-44)
    - callsite with "movs r0, #1" before "bl" -> PROVEN "FUN_00006968 calls #0xd3dc at 0x000069a4 with r0 literal 1 (0x1)." (L47-95)
    - ldr r0 (non-immediate) not promoted (L98-131)
  observations:
    - ARM Thumb mnemonics/operands and AutoPilot addresses (0xd3dc, FUN_00006968) as fixtures; no second-ISA or negative-control beyond ldr.

- path: agent/tests/test_followups.py
  purpose: End-to-end tests of follow-up candidate generation, Beads work-item materialization, seeded follow-up investigation, and CLI wiring, using a SERCOM-shaped fake executor and a scripted planner (no Ghidra/model/Beads required, except one optional real-Beads test).
  covers: research.followups (generate_followups, seed_session, continuity_review, rederive_frontier via generate, FollowUpCandidate statuses); research.controller (run with claim_contract); research.derivation.LeadDeriver; ledger.recorder.record_investigation; work.handoff; work.followups (materialize, followup_reference, existing_followups); cli main("followups", "research --work-item"); work.beads.BeadsWorkStore (optional)
  behaviors:
    - frontier re-derived from durable evidence, equals recorded open-lead count (12), sources are durable EV- ids (L244-252)
    - frontier refused when input artifacts changed; only claim candidates; no lead groups (L255-262)
    - without deriver, limitation reported (L265-269)
    - scenario A: related leads consolidate into one lead group (7 leads) and a 3-item shortlist covering 12 leads (L275-286)
    - scenario B: constant load without MMIO -> rank-1 PERIPHERAL_ACCESS_UNESTABLISHED candidate with pattern-matched basis, r0 question, callers seeded first, prior hypothesis (L292-308); no gap when effects show MMIO access (L311-319)
    - scenario C: lead group already executed elsewhere -> REDUNDANT with analyses_performed (L325-345)
    - scenario D: CHALLENGED audit request -> rank-1 candidate tied to audit, materialized with related-work link; claim stays PROPOSED (L368-389)
    - scenario E: device identity claim blocked (hardware), materialize refuses (L395-405); audit request for unavailable tool blocked, executable gap still proposed (L408-416)
    - scenario F: stable across reloads (L422-427); idempotent creation (L430-439); concurrent creation yields one item (L442-455); completed follow-up not recreated (L458-465); changed evidence basis -> new key, same question_key, linked prior item (L468-479)
    - preview and creation write nothing to the ledger/claim state (L485-507)
    - follow-up via work item: bounded prior context in first prompt (<6000 chars, PQ1/PH1, no raw evidence), durable linkage parent_run/followup/input evidence, continuity_review OPEN, completion verifies nothing, regeneration marks REDUNDANT (L513-570)
    - input evidence never names a later session observation (L573-584)
    - standalone runs unchanged (no followup field) (L587-592)
    - seed_session bounds seeds (<=8), PQ ids, <=200-char questions, hypothesis source, no ledger replay (L595-607)
    - CLI preview/create/run wiring with monkeypatched executor/context/deriver (L613-669)
    - real Beads: concurrent materialize creates one item; dedup by question key; metadata/provenance (L681-718, skipped without bd)
  observations:
    - L1-9 docstring: "Scenario letters follow the continuity spike".
    - L52-53 synthetic peripheral SERCOM9 at 0x40009000 (SAM-family-style naming); claims such as "connected to the sub-GHz radio" (L62).
    - L173-203 run_research `pre_admission` mode uses ResearchController._sanitize_claims to emulate runs recorded before claim admission ("the canonical SERCOM0 run and its C9:v1", L177-179) — references a canonical case run.
    - Imports work-package and CLI modules (cross-subsystem integration test); test writes to tmp_path ledgers only.
    - Real-Beads test spawns the bd CLI (subprocess via BeadsWorkStore) when installed.

- path: agent/tests/test_continuity.py
  purpose: Tests continuity-v1 behaviour in follow-up sessions: historical reuse, refusals, seeded-lead priority, budget accounting, provenance, backward compatibility, Beads hand-off.
  covers: research.history (HistoricalOperations, ContinuityTracker), research.session (follow_lead reuse, preload), research.followups.seed_session, research.controller (seeded-lead ranking, analyze_peripheral withholding, fallback leads, final claims after failure, charge), ledger.recorder
  behaviors:
    - A: compatible history used by reference, not rerun; reuse record points at original invocation/evidence/run; cited prior analyses preloaded (L154-169)
    - B: different firmware never reused; refusal recorded (L175-186)
    - C: changed census_db refuses only census tool, function_facts still reusable (L192-200); changed analysis version refuses (L203-208); invalidated evidence and tampered blob refused (L211-221); case-document search never reusable (L224-228)
    - D: prior function analysis does not resolve call-site leads; seeded call-site outcomes offered/not-offered and leads stay OPEN (L234-245)
    - E: peripheral rediscovery not executed while seeded leads open; "=prior" marking, "0) [follow-up]" rule, follow-up leads listed first; rejected request costs no step (L251-265); without preload a requested historical analysis is reused with zero steps charged (L268-276)
    - F: repeated requests for a historical analysis terminate with bounded decisions and fallbacks (L282-295); free reuses capped then charged (L298-313)
    - G: reuse creates no new invocation/evidence; original records untouched; claim citing session alias cites original evidence id (L319-338)
    - H: standalone and history-less seeding unchanged (no tracker/origin/preload) (L344-354)
    - I: follow-up work item runs with history; completion verifies nothing (L360-381)
    - planner failure after follow-up work still issues final-claims request and records claims (L384-398)
  observations:
    - L1-9 docstring: "Scenario letters follow the continuity-v2 milestone" while history.POLICY is "continuity-v1".
    - Uses private HistoricalOperations._check (L226) and imports fixtures from test_followups (L29-38).
    - L220 writes to a blob in the tmp ledger to simulate tampering.

- path: agent/tests/test_claim_candidates.py
  purpose: Tests deterministic claim candidates (generation, identity, withholding, ranking, rendering) and selection-by-id in the controller's final phase, against the SERCOM-shaped follow-up world and USB/EIC controls.
  covers: research.candidates (generate_candidates, candidates_for_run, parse_selection, proposal_for, seeded_evidence, offer, ranking, render), research.controller (_select_candidates, _request_candidate_selection, max_claim_candidates), research.admission.admit, ledger.recorder (duplicate handling), ledger.verifier.ClaimVerifier.precheck
  behaviors:
    - 1: repeated extraction identical; ids K-<12 hex>; renumbered observations give same ids; planner prose does not enter identity (L161-175)
    - 2: unknown function and unknown peripheral subjects withheld (ENTITY_UNKNOWN, PERIPHERAL_UNKNOWN) (L181-190)
    - 3: constant load -> ADDRESS_CONSTANT_LOADER STRUCTURE STRONG candidate, never MMIO_USER; r0-dependent effects recorded as limiting "considered" and limitation text (L196-208)
    - 4: census MMIO site and unspecialized effects access -> scoped MMIO_USER candidates with scope/assumptions; loader withheld as ROLE_CONFLICT (L214-230); specialized or input-dependent access withheld ACCESS_UNDER_ASSUMPTION (L233-242)
    - 5: no negative/absence/path candidates; NO_KNOWN_PATH supports nothing (L248-258)
    - 6: historical support keeps original EV- id, HISTORICAL_REFERENCE note, not new evidence (L264-276)
    - 7: failed result and invalidated evidence support no candidate (L282-292)
    - 8: incompatible analysis version not reused as support (L295-307)
    - 9: unknown ids rejected CANDIDATE_UNKNOWN; unoffered valid id CANDIDATE_NOT_OFFERED; parse_selection exact/case-sensitive (L313-330)
    - 10: selection response cannot alter semantics/grade/evidence (forged extra args ignored); claim proposed_by "candidate-selection:scripted" (L333-347)
    - 11: admission rejects tampered candidate copies (grade above ceiling, missing omission); admitted claim stays PROPOSED under verifier precheck (L353-369)
    - 12/13: duplicate selection is one claim; reselection in a later run -> admission decision "duplicate", CLAIM_EQUIVALENT_EXISTS note, prompt shows "Already recorded as claim"; existing files unchanged (L375-394)
    - 14: extraction and preview write nothing (tree hash) (L400-408)
    - 15: bounded, ranked offer (objective function first), order-independent; selection prompt reports omitted count, <3000 bytes, no research state (L414-435)
    - 16: free-form hypothesis round admitted alongside selection round (L441-455)
    - 17/18: USB control pointer candidate (slot 0x200052e8 -> 0x0000c724, writer FUN_0000ccc4) admitted; no CALLBACK_TARGET or EIC path; disagreeing pointer edges withheld POINTER_CONFLICT (L461-485)
    - 19: records without candidates serialize unchanged; new fields round-trip; disabled by default (L491-507); canonical case ledger preview read-only, FUN_0000b4b4 is loader not MMIO user (L510-525)
  observations:
    - L510-525 reads the canonical case ledger under cases/performing-rigs/research/ledger (run R-20261013T190420-edcfa7, FUN_0000b4b4) — framework test depending on case data (skips if absent; asserts tree hash unchanged).
    - L466-468 USB control addresses come from ledger_support.usb_inventory fixture (likely AutoPilot-derived values).
    - Imports fixtures from test_claim_quality, test_continuity, test_followups (test-to-test coupling).
    - Uses ClaimCandidate.durable_evidence_ids (L272, L345), a field/property defined outside this scope (ledger.models).

- path: agent/tests/test_lead_derivation.py
  purpose: Tests LeadDeriver dispatch for function_facts, callsite_context, pin_table_entry, and LeadRegistry dedup.
  covers: research.derivation.LeadDeriver, research.lead_generation, research.leads.LeadRegistry
  behaviors:
    - function_facts caller -> callsite_context lead with address (L19-57)
    - callsite with "movs r0, #1" -> pin_table_entry {index: 1} lead (L60-103)
    - pin_table_entry GPIO -> search_case_evidence lead query "PA22" (L106-137)
    - identical action registered twice -> same id, merged provenance (L140-171)
  observations:
    - AutoPilot fixture addresses (FUN_0000d3dc, FUN_00006968, 0x000069a4) and ARM mnemonics.

- path: agent/tests/test_lead_generation.py
  purpose: Tests generate_function_fact_leads incoming-callsite behaviour.
  covers: research.lead_generation.generate_function_fact_leads
  behaviors:
    - callers -> L1, L2 callsite leads; description format; address normalized to 0x%08x (L42-78)
    - model-visible lead hides tool/arguments; private action has before/after 8 (L81-117)
    - duplicate callsites (0x69a4 vs 0x000069a4) -> one lead (L120-145)
    - invalid callsite (reader ValueError) -> "invalid-callsite" issue, not lead (L148-187)
  observations:
    - AutoPilot fixture addresses (FUN_0000d3dc, FUN_00008e18, FUN_000093fc, 0x78f2).

- path: agent/tests/test_discovery_leads.py
  purpose: Tests discovery-purpose case search -> validated function leads.
  covers: research.derivation.LeadDeriver (search_case_evidence branch), research.lead_generation.generate_function_leads_from_case_evidence
  behaviors:
    - explicit FUN_ names validated: valid -> function_facts + function_disassembly leads; invalid (FUN_deadbeef) -> one issue (L25-87)
    - non-discovery (reconciliation) case search -> no leads (L90-120)
    - naked address 0x1234 matching a function promoted; stale 0x9999 silently ignored (L123-186)
  observations:
    - Query terms "TMC5160", "PA22", "SPI transport" are case-flavoured fixtures.

- path: agent/tests/test_dynamic_leads.py
  purpose: Tests pin-table lead generation from callsite r0 literals.
  covers: research.lead_generation.generate_pin_table_leads_from_callsite
  behaviors:
    - "movs r0, #1" -> kind pin-table, index 1, source E4 (L52-74)
    - hex literal "#0x25" parsed (L77-94)
    - ldr r0 (non-immediate) -> no lead (L97-116)
    - non-callsite evidence -> no lead (L119-139)
  observations:
    - ARM Thumb instruction fixtures; AutoPilot addresses.

- path: agent/tests/test_case_search_leads.py
  purpose: Tests pin-table GPIO -> case-evidence search lead.
  covers: research.lead_generation.generate_case_search_leads_from_pin_table
  behaviors:
    - GPIO PA22 -> kind case-evidence, query "PA22", max_results 8 (L26-51)
    - query adds no semantic terms (trigger/startup/reference) (L54-70)
    - missing gpio -> no lead (L73-80); non-pin evidence -> no lead (L83-97)
  observations:
    - L68-70 negative checks name terms ("trigger", "startup", "reference") specific to the AutoPilot PA22 finding.

- path: agent/tests/test_outgoing_function_leads.py
  purpose: Tests outgoing-callee expansion and incoming-call bound in generate_function_fact_leads.
  covers: research.lead_generation.generate_function_fact_leads
  behaviors:
    - valid callee -> callsite_context, function_facts, function_disassembly leads; no issues (L34-88)
    - 12 callers bounded to 8 callsite leads (L91-128)
  observations: none beyond synthetic addresses.

- path: agent/tests/test_follow_lead.py
  purpose: Tests LeadFollower execution and status transitions.
  covers: research.follow.LeadFollower, research.leads.LeadRegistry
  behaviors:
    - executes private action with given evidence id; marks FOLLOWED (L51-95)
    - followed lead cannot execute twice ("not open"), executor called once (L98-132)
    - failed execution leaves lead OPEN and resolvable (L135-166)
  observations: AutoPilot fixture addresses.

- path: agent/tests/test_function_facts_flow.py
  purpose: Integration tests of question routing and function_facts execution over the real AutoPilot Ghidra index (not the research package).
  covers: aptrace_agent.router.route_question, aptrace_agent.executor.EvidenceExecutor, aptrace_agent.ghidra_index.autopilot_ghidra_index (outside this sweep's production scope)
  behaviors:
    - routes "What calls FUN_0000d3dc?" to one function_facts request; result entry 0x0000d3dc, size 44, 3 unique callers, 5 call sites with exact addresses (L12-56)
    - rejected (inconsistent) Ghidra caller edges to FUN_0000d3dc retained with "lies outside" reason (L59-98)
  observations:
    - Depends on real AutoPilot firmware export via autopilot_ghidra_index (case-named framework function) and hardcoded AutoPilot addresses; no research-module code exercised despite inclusion in this sweep.
```

## Observed behaviors

Paths are relative to `agent/src/aptrace_agent/research/`.

### Evidence ledger and state
- Session evidence ids are allocated sequentially as E1, E2, ... by APTrace, never by the model (evidence.py:20-21).
- Adding an observation whose id is not the next expected id raises ValueError (evidence.py:29-35).
- Adding evidence optionally registers its id once on ResearchState.evidence_ids (evidence.py:45-46; state.py:87-89).
- Unknown evidence lookup raises KeyError "unknown evidence" (evidence.py:50-56).
- ResearchState rejects a duplicate lead id (state.py:91-94) and raises KeyError for an unknown lead (state.py:96-100).
- open_leads returns leads with status OPEN (state.py:102-103).
- Model-visible Lead carries kind/description/source ids/status/origin only, never tool or arguments (state.py:60-75; leads.py:11-20).
- Claims, hypotheses, contradictions and open questions are deduplicated by whitespace-collapsed, lowercased text; duplicates union evidence ids (state_updates.py:16-17, 53-69, 98-112, 141-155, 187-201).
- Merging a duplicate claim yields PROVEN if either grade is PROVEN, otherwise SUPPORTED (state_updates.py:55-61).
- New state item ids are prefix + (max numeric suffix + 1): C#, H#, X#, Q# (state_updates.py:20-38).

### Lead registry and following
- Leads get opaque ids L1, L2, ... (leads.py:91-92).
- Registering an action (tool + canonical-JSON arguments) already registered returns the existing lead and merges new source evidence ids (leads.py:40-89).
- Resolving an unknown lead raises KeyError; resolving a non-OPEN lead raises ValueError (leads.py:113-124).
- Leads can be marked FOLLOWED or DISMISSED (leads.py:126-138).
- LeadFollower executes the resolved action with a caller-supplied evidence id and marks the lead FOLLOWED only after the executor returns (follow.py:37-53).
- A failed execution leaves the lead OPEN (follow.py:43-51; session.py:109-118).

### Session plumbing
- Following a lead reserves the next evidence id, executes, records evidence, derives facts, then derives leads (session.py:89-132).
- Every incorporated observation goes through StateFactDeriver; lead derivation runs only with a deriver and when enabled (session.py:55-87).
- Newly derived leads are added to state only if their id is not already present; derivation issues accumulate on the session (session.py:73-87).
- Externally produced observations can be recorded and incorporated (session.py:186-199).
- In follow-up sessions, a lead whose operation has a reusable historical result is satisfied by reference: a session alias with reused_from, no execution, lead marked FOLLOWED, reuse recorded (session.py:99-104, 134-153).
- A non-reusable historical match is recorded as a refusal and the lead executes fresh (session.py:106-107).
- Execution failures in follow-up sessions record the lead as failed (session.py:114-118).
- Preload makes a cited reusable historical result visible as facts only (no leads, no step), recorded as preloaded (session.py:155-184).

### Lead derivation
- Lead derivation dispatches by tool name: function_facts, callsite_context, discovery search_case_evidence, census_peripheral_usage, census_common_paths, census_usb_inventory, function_effects, pin_table_entry; other tools yield no leads (derivation.py:48-148, 220-224).
- Structurally surfaced function targets are validated against FunctionFacts; invalid ones become "invalid-structural-function" issues (derivation.py:150-189).
- Common-path leads: up to 2 non-shared-utility common descendants (derivation.py:192-197).
- USB inventory leads: up to 3 register users (derivation.py:200-204).
- function_effects call-target leads: target address with bit 0 cleared, named FUN_%08x, up to 3 unique (derivation.py:207-217).
- function_facts callers become validated callsite_context leads (before/after 8), capped at 8 incoming (lead_generation.py:89-208).
- function_facts callees become validated callsite leads; up to 6 valid, non-self, distinct callees also become function_facts and function_disassembly leads (lead_generation.py:210-359).
- Callsite identities (function, 0x%08x address) are deduplicated within one facts result (lead_generation.py:74-86, 156-164, 238-246).
- Callsites rejected by the callsite reader become "invalid-callsite" issues; invalid callees become "invalid-outgoing-function" issues (lead_generation.py:171-189, 299-318).
- A callsite whose nearest preceding r0 writer is mov/movs/mov.w/movs.w with an immediate yields a pin_table_entry lead for that literal (lead_generation.py:379-495).
- A pin_table_entry result with a non-empty GPIO string yields a search_case_evidence lead with exactly that query and max_results 8 (lead_generation.py:498-544).
- A discovery-purpose case search promotes explicitly named, validated FUN_ names and naked addresses that exactly match a known function into function_facts + function_disassembly leads, capped at 8 functions; invalid explicit names are issues, invalid naked addresses are ignored (lead_generation.py:557-762).
- A successful census peripheral analysis promotes up to 4 attributed, validated functions (facts + disassembly leads) and records every unattributed site as an "unattributed-census-site" issue (lead_generation.py:765-903).

### Fact derivation
- A complete pin_table_entry result becomes a PROVEN claim "Logical pin-table index N maps to GPIO X (group G, bit B)." with basis static-table (fact_derivation.py:677-708).
- A callsite with an r0 '#'-immediate before a bl* instruction becomes a PROVEN "calls ... with r0 literal" claim with basis disassembly (fact_derivation.py:21-142, 710-751).
- Census peripheral results become PROVEN census claims: summary counts, up to 4 per-function statements, up to 2 unattributed-site statements; no-access statuses produce bounded negative statements that disclose what is not excluded (fact_derivation.py:145-288, 753-767).
- Common-path results become census-graph statements per status, shared-state statements, and an open question for unresolved indirect frontier sites (fact_derivation.py:296-377).
- USB inventory results become statements about register users, IRQ vector handlers and descriptors, and an open question for handlers outside census vector coverage (fact_derivation.py:380-444).
- Observed-call results become scenario-scoped concrete-observed statements of r0 values, with "not entered ... not thereby unreachable" and open questions for unobserved call sites (fact_derivation.py:447-482).
- Callback-provenance results become static-dataflow statements and next-hop/open-reason questions (fact_derivation.py:490-523).
- value_forward_use results become no-escape or may-escape static-dataflow statements and incomplete-use questions (fact_derivation.py:526-558).
- Indirect-target results become static-dataflow statements of branch shape and potential targets, with a question when derivation is not ESTABLISHED (fact_derivation.py:561-594).
- function_effects results become raw-symbolic summaries and call statements, a solver statement for proven bit-valued returns, and conditional solver statements for specialized accesses (fact_derivation.py:597-649).
- All derived statements are merged as PROVEN with a basis tag; derived questions are merged with source "aptrace" (fact_derivation.py:769-799).

### Planner projection
- The planner view consists of ALREADY RUN analyses, INSPECTED functions, newest FACTS, OPEN items, and LATEST results, each with its own character budget, under a total cap (projection.py:50-72, 476-520).
- Reused historical results are marked "=prior"; preloaded results are excluded from LATEST (projection.py:317-328, 476-493).
- A tool-provided planner_summary is used verbatim (clipped); known tools have deterministic renderings; unknown tools are rendered as clipped JSON (projection.py:134-224).
- Facts are ordered by newest cited evidence; non-PROVEN facts are tagged supported; omitted counts are reported (projection.py:381-414).
- When the whole view exceeds the total, the longest section is trimmed repeatedly (projection.py:508-518).
- A compact budget exists for retry after local-model prefill rejection (projection.py:75-85).
- The conclusion groups PROVEN facts, PROBABLE (supported claims + hypotheses) and OPEN questions, 8 each (projection.py:543-578).
- Known functions are FUN_ names found in results or function arguments (projection.py:526-540).

### Controller: configuration and palette
- Unknown structural tool names, non-experimental names in experimental_tools, and experimental tools without opt-in are rejected at construction (controller.py:226-241).
- Non-opted experimental tools are never offered and leads that would run them are hidden from the planner (controller.py:273, 1452-1458).
- Planner and reconciler clients default to environment-configured OpenAI-compatible endpoints (controller.py:243-260).
- A decision palette offers follow_lead (enum of visible lead ids), enabled structural tools, and finish (controller.py:574-597).
- A discovery palette offers search_case_evidence, enabled structural tools, and finish (controller.py:599-619).
- Peripheral analysis is offered only for configured peripherals not yet analyzed, under the census budget, and not while follow-up leads are open (controller.py:342-359, 391-395).
- The USB inventory tool is offered only when the objective mentions USB or USB census evidence exists, and not after it ran or while follow-up leads are open (controller.py:397-417).
- Common paths are offered only with at least two named function sets and under its budget (controller.py:423-436).
- Function effects and observed call arguments are offered only with known functions, under their budgets; observation also needs registered scenarios (controller.py:438-469).
- Indirect-target, callback-provenance and value-use tools are offered only for allowed addresses that already appear in evidence and were not yet analyzed, at most 12 (controller.py:471-562).
- Budgets count only executed observations, not reused ones (controller.py:328-332).
- A tool that the planner asked to repeat is withheld for the next two decisions (cooldown) (controller.py:564-572, 1286-1298).
- Offered seeded leads are recorded on the continuity tracker (controller.py:592-595).
- The finish tool accepts reason, hypotheses, open questions, and (claim contract) a claims string (controller.py:621-642).

### Controller: validation and planner I/O
- Each planner response must contain one tool call with JSON-object arguments; the first of several calls is used (controller.py:1096-1126).
- Structural tool arguments are validated: extra keys rejected, function names must be known FUN_ names, r0/r1 integers in 32-bit range, scenarios/sites/origins from the offered enum, set members from analyzed peripherals or known functions (controller.py:877-1066).
- Requests that repeat an analysis already in evidence are rejected deterministically (controller.py:859-869, 938-1063).
- One correction message is sent after an invalid response; a second failure yields a contract-exhausted outcome (or finish in discovery) with both errors (controller.py:1300-1337).
- Duplicate-analysis rejections are retried as a fresh request without that tool and do not consume the correction (controller.py:1286-1298).
- Local-server prefill rejections trigger two delayed retries with the compact projection, keep compact mode for three more decisions, and otherwise end with planner_prefill_exhausted (controller.py:160-172, 1208-1243).
- Every planner request is measured and recorded (phase, sizes, tools, attempt, compact, error, prompt tokens, decision) (controller.py:1070-1093, 1202-1246, 1279).
- Planner requests can be printed to stderr or appended to a JSONL log by environment variable (controller.py:1248-1269).
- Discovery queries must be 2-120 characters and not previously tried (case-insensitive) (controller.py:1650-1659).
- finish requires a non-empty reason (controller.py:1615-1621, 1661-1663).

### Controller: lead presentation
- Visible leads are ranked follow-up-origin first, then by tool class and structural source, newest first, limited to max_visible_leads (4 in compact mode) (controller.py:1409-1461).
- Leads are rendered to the planner by tool identity only; follow-up leads are tagged "[follow-up]"; the count of hidden leads is shown (controller.py:1463-1497, 1518-1523).
- The decision prompt states ordered rules, with a follow-up rule first when seeded leads are open (controller.py:1527-1551).

### Controller: run loop and termination
- The loop continues while charged steps are below max_steps (controller.py:2043).
- Each executed action costs one step; in follow-up sessions reuses are free up to max_free_reuses, then cost one step (controller.py:2036-2041; history.py:258-265).
- Discovery mode runs only for a session that started with no evidence and no leads, while no leads are open and attempts remain (controller.py:2029, 2051-2055).
- With no open leads, no discovery, and no available structural analysis, the run stops as discovery_exhausted or research_graph_exhausted (controller.py:2059-2071).
- On planner_contract_exhausted in a follow-up session, APTrace follows the top open seeded lead as a fallback, bounded by max_fallbacks (controller.py:2007-2016, 2078-2094).
- Planner failure stops the run with planner_prefill_exhausted or planner_contract_exhausted; a follow-up that did work still gets a final-claims request under the claim contract (controller.py:2096-2110).
- Planner finish stops the run as discovery_finished (in discovery) or planner_finished, after recording conclusions and, under the claim contract, claim admission and candidate selection (controller.py:2112-2124).
- Discovery searches, lead follows and structural analyses each append a ResearchStep with evidence id and reused_from (controller.py:2126-2144).
- Structural actions are executed by registering a source-less lead and following it (controller.py:1842-1959).
- At step-budget exhaustion with the claim contract, a finish-only final-claims request is made, then candidate selection (controller.py:2146-2155).
- Terminal case reconciliation runs only when non-discovery case searches are present (controller.py:1977-1989).
- Planner hypotheses and open questions (up to 3 each, 240 chars) are recorded with source "planner" and no evidence (controller.py:1961-1975).
- Exceptions raised during lead execution propagate out of run (controller.py:2082, 2129, 2137, 2142).

### Claim proposals and admission
- Claim lines are parsed as "GRADE [TYPE] E#,E# assertion" with optional "[omit E#: reason]"; at most 3 proposals kept; unparseable lines recorded as "unparseable" admissions (controller.py:57-70, 650-741).
- Rejected first-round proposals get one finish-only correction request showing bounded diagnostics (controller.py:754-771, 1729-1776; admission.py:257-270).
- Admission rejects proposals with no evidence ids or unknown evidence ids (admission.py:174-177).
- Admission checks entity identity (known functions, known peripherals) (admission.py:179-180).
- Typed semantics must validate and pass verify_semantics against cited evidence (admission.py:185-199).
- Untyped prose is checked by peripheral access/absence and call-relation rules; typed call semantics use typed grade rules (admission.py:203-207).
- A proposed grade above the cited evidence's ceiling is rejected (admission.py:209-218).
- An untyped claim above PROBABLE is rejected (admission.py:69, 220-227).
- In follow-up sessions, followed seeded-lead evidence about a named function must be cited or explicitly omitted (admission.py:109-157).
- Citing reused historical evidence adds a HISTORICAL_REFERENCE note (admission.py:231-241).
- Admission never rewrites a proposal; the decision is admitted or rejected (admission.py:243-254).

### Claim candidates
- Candidates are extracted only from evidence graded above UNKNOWN, via the verifier's fact readers (candidates.py:158-174, 471).
- MMIO_USER candidates come from census MMIO sites, USB register users, or unspecialized concrete function-effects MMIO accesses; specialized or input-dependent accesses are withheld (candidates.py:198-216, 247-301).
- ADDRESS_CONSTANT_LOADER candidates are withheld when any MMIO access is recorded for the function (candidates.py:278-299).
- Function-effects limits (parametric addresses, incomplete coverage) are attached as limitations and "considered" entries to loader candidates (candidates.py:219-244, 351-381).
- RESOLVED_FUNCTION_POINTER candidates come from census resolved edges; disagreeing edges for one slot are withheld (candidates.py:384-446).
- Candidates are withheld for insufficient grade, unknown function, unknown peripheral, grade ceiling, or failed verification (candidates.py:478-510).
- Non-supporting seeded-lead evidence about a candidate's functions is listed as considered (candidates.py:512-516).
- Candidate ids are "K-" + 12 hex of a digest over generator version, type, semantics, grade and content identity of supporting evidence (candidates.py:523-531, 152-155).
- Candidates are deduplicated by semantics and ranked by objective entities, seeded leads, novelty, kind, id (candidates.py:518-521, 557-575).
- Existing equivalent ledger claims (not SUPERSEDED) are attached to candidates when a ledger is available (candidates.py:578-602; controller.py:797-807).
- A read-only candidate preview can be computed for a recorded run, skipping invalid or tampered evidence (candidates.py:605-641).
- Candidates are rendered as plain sentences with an omitted-count line (candidates.py:664-680).
- Selection reads only exact offered K- ids; other tokens are invalid; "none"/"no"/"n/a"/empty selects nothing (candidates.py:683-707).
- A selected candidate's proposal is built solely from the candidate record and passes admission; unknown or unoffered ids are recorded as rejected selections; no correction round (candidates.py:644-661; controller.py:773-855).
- Candidate selection runs only with the claim contract and max_claim_candidates > 0, and records outcome no-candidates, planner-failed, selected or none (controller.py:785-855).

### Continuity (history)
- Historical lookup is bounded to the source run, earlier runs of the same follow-up key, and cited evidence, up to 256 invocations (history.py:94-145).
- Operation identity is canonical JSON of tool and canonical (default-filled) arguments (history.py:83-84).
- Lookup returns the newest reusable invocation or the newest candidate's refusal reason (history.py:150-163).
- Reuse is refused for non-deterministic tools, failed invocations, missing evidence, different firmware, input-artifact drift, differing operation key, non-VALID evidence, missing or corrupt blobs, or a differing declared analysis version (history.py:165-209).
- Current analysis versions are taken from five tool modules (history.py:71-80).
- The continuity record lists policy, history runs and size, reuses, refusals, per-seeded-lead outcomes (reused, executed, attempted-failed, offered, not-offered), and budget counters (history.py:270-305).

### Follow-ups
- The open-lead frontier of a recorded run is re-derived by replaying LeadDeriver over its durable evidence, only when its context equals the current one; leads whose action was already attempted are excluded; a mismatch with the recorded open-lead count is reported (followups.py:282-365).
- Claim gaps are generated for PROPOSED/STALE claims from: peripheral access supported only by constant loads, device-identity wording with a device-identity limitation (blocked), latest CHALLENGED/UNRESOLVED audits, unmet/unevaluable/unresolved verification gate conditions and held checks, and STALE state (followups.py:408-618, 731-740).
- CONTRADICTED verification conditions generate only a note (followups.py:572-573).
- Audit requests naming a tool APTrace does not provide are blocked (followups.py:528-542, 88-95).
- Claim follow-ups absorb open leads about the gap's functions and their direct call neighbours, seeding the function's own leads first (followups.py:759-773).
- Remaining lead groups (by anchor) become lead-group candidates ranked 2 or 3 by firmware-derived claim linkage (followups.py:876-929).
- Candidate keys and question keys are digests of case, firmware, category, subject and evidence basis (followups.py:798-810, 832-835, 910-915).
- Seeded leads already performed under current inputs are moved to analyses_performed; seeded leads are capped at 8; candidates investigated by an earlier follow-up run with the same key, or lead groups with nothing left, are REDUNDANT (followups.py:933-978).
- The report shortlists the first `limit` proposed candidates, defers the rest, and lists non-proposed ones as suppressed (followups.py:678-716).
- Continuity review of a follow-up run reports new/reused evidence, claim states, followed/unfollowed seeded leads, and always reports the question as OPEN (followups.py:995-1031).
- Seeding a session registers seeded leads, adds PQ#/PH# questions and hypotheses tagged followup:<key>, and (with history) attaches a continuity tracker, marks lead origins, and preloads cited reusable evidence (followups.py:1037-1088).

### Case reconciliation
- Reconciliation considers only non-discovery case searches and does nothing without them (reconciliation.py:289-309).
- The reconciliation model is asked for exactly one JSON reconciliation per collected query (reconciliation.py:341-428).
- Schema-invalid output gets one correction request; semantically invalid output gets one correction; a second semantic failure raises (reconciliation.py:434-541).
- A SUPPORTED reconciliation requires a role and deterministic structural provenance found by matching pin-table and r0-literal claim text (reconciliation.py:136-206, 236-286).
- SUPPORTED reconciliations become SUPPORTED claims citing the structural claims' evidence plus the case evidence; unresolved items become open questions (reconciliation.py:543-612).
- Reconciliation never creates PROVEN claims (reconciliation.py:45, 593).
