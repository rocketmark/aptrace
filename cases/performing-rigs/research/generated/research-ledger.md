# Research ledger report

<!-- ledger-fingerprint: 533da2eae7671dc0 -->

> Generated from the APTrace research ledger (`ledger/`, fingerprint `533da2eae7671dc0`). Do not edit by hand; regenerate with `aptrace-agent report`.
>
> **VERIFIED** means consistent with the currently recorded evidence and APTrace's deterministic checks, after an independent audit returned SUPPORTED. It is not a proof of semantic truth. Evidence grade and lifecycle state are independent.

States: BLOCKED 5, PROPOSED 1, SUPERSEDED 1, VERIFIED 2

| Claim | State | Grade | Last audit | Assertion |
|---|---|---|---|---|
| C2:v2 | VERIFIED | STRONG | SUPPORTED | The indirect call at 0x0000cc1a in the USB_OTHER interrupt handler FUN_0000cc14 loads its target from RAM slot 0x200052e8, whose only known store (0x0000ccc6 in |
| C5:v1 | VERIFIED | STRONG | SUPPORTED | No census call-graph path within the hop bound connects the EIC interrupt-vector handlers (EIC_EXTINT_0..15) with the USB function set; this is NO_KNOWN_PATH, n |
| C6:v1 | PROPOSED | STRONG | — | The indirect call at 0x0000cc1a in FUN_0000cc14 loads RAM slot 0x200052e8, written by FUN_0000ccc4 at 0x0000ccc6 with the r0 argument of the call at 0x0000bcda  |
| C1:v1 | BLOCKED | STRONG | CHALLENGED | The USB interrupt handler's indirect callback dispatch at FUN_0000cc0a invokes a computed target at 0xcb92. |
| C3:v1 | BLOCKED | EXACT | SUPPORTED | The USB callback target is FUN_0000ccc4 and the result is EXACT. |
| C4:v1 | BLOCKED | STRONG | UNRESOLVED (synthesized) | The physical/EIC interrupt-dispatch path converges with the USB interrupt path. |
| C7:v1 | BLOCKED | EXACT | — | The USB callback target is FUN_0000ccc4 and the result is EXACT. |
| C8:v1 | BLOCKED | STRONG | — | The physical/EIC interrupt-dispatch path converges with the USB interrupt path. |
| C2:v1 | SUPERSEDED | STRONG | SUPPORTED | The indirect call at 0x0000cc1a in the USB_OTHER interrupt handler FUN_0000cc14 loads its target from RAM slot 0x200052e8, whose only known store (0x0000ccc6 in |

## Repeated-audit stability

Audits of the same claim version with the same audit-input fingerprint (identical claim, evidence, projection, source agreement, template, model, generation parameters, tools, and budget). Measurement only: verification uses the existing audit rule.

| Claim | Input fingerprint | Runs | Verdicts | Verdict agreement | Executed-analysis agreement | Challenges citing coverage gaps |
|---|---|---|---|---|---|---|
| C3:v1 | `AI-254895dbc1ad1fc1` | 10 | CHALLENGED 1, SUPPORTED 9 | 90% | 100% | 0 |
| C4:v1 | `AI-485712c83ee950c1` | 10 | CHALLENGED 4, SUPPORTED 1, UNRESOLVED 5 | 50% | 80% | 0 |
| C2:v1 | `AI-782d9c510216db1a` | 10 | SUPPORTED 10 | 100% | 100% | 0 |

## C2:v2 — VERIFIED

- **Assertion:** The indirect call at 0x0000cc1a in the USB_OTHER interrupt handler FUN_0000cc14 loads its target from RAM slot 0x200052e8, whose only known store (0x0000ccc6 in FUN_0000ccc4, storing the r0 argument of the call at 0x0000bcda) holds the raw Thumb pointer 0x0000c725; the canonical target is 0x0000c724 (FUN_0000c724), which forwards to 0x0000c5cc.
- **Subject:** Indirect call at 0x0000cc1a in USB_OTHER handler FUN_0000cc14
- **Type / proposed grade:** RESOLUTION / STRONG
- **Scope:** Static census resolved function pointers for firmware autopilot868; RAM slot 0x200052e8 only.
- **Proposed by:** benchmark-fixture:semantic-usb-eic in run `R-20261012T234454-bb6cfa`
- **Supersedes:** C2:v1
- **Structured semantics (authoritative for verification):** `RESOLVED_FUNCTION_POINTER(slot=0x200052e8, writer=FUN_0000ccc4, writer_instruction=0x0000ccc6, registration_caller=FUN_0000bc44, registration_callsite=0x0000bcda, raw_pointer=0x0000c725, canonical_target=0x0000c724, forwarding_target=0x0000c5cc, indirect_site=0x0000cc1a, indirect_caller=FUN_0000cc14)`
- **Depends on:** none
- **Supporting evidence:**
  - `EV-d9343c6252f6f61a` census_usb_inventory — grade STRONG (census structure; resolved_indirect confidence STRONG); result sha256 `372b1f264b5c6d82…`; invocation `TI-6d49d1ca71fa3819`
  - `EV-5399815447618e02` structural_source_agreement — grade STRONG (static structural agreement between code-discovery sources (heuristic boundaries)); result sha256 `a15353d2fa55f29c…`; invocation `TI-2d71df2ebaf542d6`
- **Assumptions:**
  - The registration call at 0x0000bcda executes before USB_OTHER interrupts that reach 0x0000cc1a are serviced; ordering is not established by this evidence.
- **Limitations:**
  - Stores to 0x200052e8 through computed pointers are not excluded by static analysis.
  - `AGREEMENT_SOURCES_NOT_INDEPENDENT` Not every agreeing source is independent (census <- ghidra:2c80bf9dfade293e).
  - `COMPUTED_POINTER_WRITES_NOT_EXCLUDED` resolved_indirect edges come from statically initialized RAM function pointers whose every known store is one constant code pointer; stores through computed pointers are not excluded.
  - `FUNCTION_BOUNDARIES_HEURISTIC` Census structure is statically derived from Ghidra references; function boundaries and attribution are heuristic.
  - `SOURCE_AGREEMENT_IS_STRUCTURAL` Source agreement is structural consistency between analysis sources about where code and functions are; it does not establish behavior, and a source coverage gap is not negative evidence.
- **Last audit:** `A-20261013T011732-582390` by `gemma-4-26b-a4b-it-4bit` (audit-v0.5) — **SUPPORTED**; 3 analysis request(s)
  - Reasoning: The analysis of the disassembly confirms the mechanics of the claim. In FUN_0000cc14, the instruction at 0x0000cc1a is 'bx r3', where r3 is loaded from a pointer at 0x0000cc16 (which is the address 0x200052e8, as established by the census). In FUN_0000ccc4, the instruction at 0x0000ccc6 is 'str r0, [r3]', where r3 is the address 0x200052e8 (loaded at 0x0000ccc4). In FUN_0000bc44, the call to FUN_0000ccc4 occurs at 0x0000bcda, passing the target pointer in r0. The relationship between the raw pointer (0x0000c725) and the canonical target (0x0000c724) is a standard Thumb-mode adjustment (clearing the LSB). The flow is: FUN_0000bc44 calls FUN_0000ccc4 (at 0x0000bcda) -> FUN_0000ccc4 stores the pointer (at 0x0000ccc6) into 0x200052e8 -> FUN_0000cc14 loads the pointer (at 0x0000cc16) and branches (at 0x0000cc1a).
  - Scope check: The assertion specifically targets the indirect call at 0x0000cc1a in FUN_0000cc14 and the relationship between the RAM slot 0x200052e8, its writer FUN_0000ccc4, and the registration context in FUN_0000bc44. All entities and addresses match the scope.
- **Audit history** (all audits of this version, oldest first; never rewritten):
  - `A-20261013T011732-582390` audit-v0.5 input `AI-f745dc37ba9b71c8` → **SUPPORTED**; 3 request(s), 3 executed
- **Structural source agreement** (`EV-5399815447618e02`, latest audit context):
  - 0x0000bcda AGREE (CONSISTENT): census=FUN_0000bc44, ghidra=FUN_0000bc44, macaw=FUN_0000bc44
  - 0x0000c5cc PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000c5cc, ghidra=FUN_0000c5cc, macaw=—; gaps MACAW_COVERAGE_GAP
  - 0x0000c724 PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000c724, ghidra=FUN_0000c724, macaw=—; gaps MACAW_COVERAGE_GAP
  - 0x0000cc14 PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000cc14, ghidra=FUN_0000cc14, macaw=FUN_0000cc14
  - 0x0000cc1a PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000cc14, ghidra=FUN_0000cc14, macaw=—; gaps MACAW_COVERAGE_GAP
  - 0x0000ccc6 AGREE (CONSISTENT): census=FUN_0000ccc4, ghidra=FUN_0000ccc4, macaw=FUN_0000ccc4
- **Last verification:** `V-20261013T011825-e3f8bd` [full] → VERIFIED (all checks passed)
  - Phases: A passed, B passed, C passed, D passed
  - Semantic check `CONSISTENT` writer=FUN_0000ccc4 — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` writer_instruction=0x0000ccc6 — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` registration_caller=FUN_0000bc44 — `EV-5399815447618e02`
  - Semantic check `CONSISTENT` registration_callsite=0x0000bcda — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` raw_pointer=0x0000c725 — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` canonical_target=0x0000c724 — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` forwarding_target=0x0000c5cc — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` indirect_site=0x0000cc1a — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` indirect_caller=FUN_0000cc14 — `EV-d9343c6252f6f61a`
- **Lifecycle:** PROPOSED (aptrace-ledger) → VERIFIED (aptrace-verifier)

## C5:v1 — VERIFIED

- **Assertion:** No census call-graph path within the hop bound connects the EIC interrupt-vector handlers (EIC_EXTINT_0..15) with the USB function set; this is NO_KNOWN_PATH, not a proof that no path exists at runtime.
- **Subject:** EIC interrupt-vector handlers and USB function set
- **Type / proposed grade:** NO_KNOWN_PATH / STRONG
- **Scope:** Census strong call graph (direct transfers plus statically resolved indirect edges), within the census hop bound.
- **Proposed by:** benchmark-fixture:eic-convergence in run `R-20261012T234605-3218bc`
- **Depends on:** none
- **Supporting evidence:**
  - `EV-d9343c6252f6f61a` census_usb_inventory — grade STRONG (census structure; resolved_indirect confidence STRONG); result sha256 `372b1f264b5c6d82…`; invocation `TI-6d49d1ca71fa3819`
  - `EV-bab8f6cc269494ab` census_common_paths — grade BOUNDED (NO_KNOWN_PATH within census hop bound); result sha256 `e0b3be773d9d7d50…`; invocation `TI-bb924fc173c22207`
- **Limitations:**
  - `COMPUTED_POINTER_WRITES_NOT_EXCLUDED` resolved_indirect edges come from statically initialized RAM function pointers whose every known store is one constant code pointer; stores through computed pointers are not excluded.
  - `FUNCTION_BOUNDARIES_HEURISTIC` Census structure is statically derived from Ghidra references; function boundaries and attribution are heuristic.
  - `NO_KNOWN_PATH_IS_NOT_UNREACHABILITY` NO_KNOWN_PATH means no path this census can construct within the hop bound; it is not a proof of unreachability.
  - `PERIPHERAL_SET_IS_MMIO_USAGE:USB` Set 'USB' is the census structural set for USB (constant-address register/MMIO users), not a semantic subsystem, event, or interrupt-dispatch path.
  - `UNRESOLVED_INDIRECT_FRONTIER` 7 unresolved indirect transfer site(s) in the explored region; paths through them are unknown.
- **Last audit:** `A-20261012T234634-b982e2` by `gemma-4-26b-a4b-it-4bit` (audit-v0.3) — **SUPPORTED**; 2 analysis request(s)
  - Reasoning: The claim is a 'NO_KNOWN_PATH' assertion, which is a negative claim (absence of a path in the census). The evidence [EV-bab8f6cc269494ab] shows that within the census hop bound (8 hops), no path was found between the EIC interrupt handlers and the USB function set. The grade 'STRONG' is appropriate for a 'NO_KNOWN_PATH' claim where the search space was explicitly explored (45/16 functions) and the result is limited by the census structure and unresolved indirect sites, as noted in the limitations. The claim correctly identifies itself as not being a proof of unreachability, respecting the limitations of the census-based analysis.
  - Scope check: The assertion targets the relationship between EIC interrupt handlers and the USB function set. The evidence [EV-bab8f6cc269494ab] specifically compares the 'USB' set (defined in [EV-d9343c6252f6f61a]) against the 'IRQ:EIC' set. The scope of the 'NO_KNOWN_PATH' result matches the assertion's scope.
- **Audit history** (all audits of this version, oldest first; never rewritten):
  - `A-20261012T234634-b982e2` audit-v0.3 input `not recorded (pre-v0.4)` → **SUPPORTED**; 2 request(s)
- **Last verification:** `V-20261012T234651-f05b9b` [full] → VERIFIED (all checks passed)
- **Lifecycle:** PROPOSED (aptrace-ledger) → VERIFIED (aptrace-verifier)

## C6:v1 — PROPOSED

- **Assertion:** The indirect call at 0x0000cc1a in FUN_0000cc14 loads RAM slot 0x200052e8, written by FUN_0000ccc4 at 0x0000ccc6 with the r0 argument of the call at 0x0000bcda in FUN_0000bc44; the stored raw Thumb pointer 0x0000c725 has canonical target 0x0000c724 (FUN_0000c724), which forwards to 0x0000c5cc.
- **Subject:** RAM function pointer 0x200052e8 consumed by the USB_OTHER handler
- **Type / proposed grade:** RESOLUTION / STRONG
- **Scope:** Static census resolved function pointers for firmware autopilot868; RAM slot 0x200052e8 only.
- **Proposed by:** benchmark-fixture:semantic-usb-eic in run `R-20261013T011707-ea649e`
- **Structured semantics (authoritative for verification):** `RESOLVED_FUNCTION_POINTER(slot=0x200052e8, writer=FUN_0000ccc4, writer_instruction=0x0000ccc6, registration_caller=FUN_0000bc44, registration_callsite=0x0000bcda, raw_pointer=0x0000c725, canonical_target=0x0000c724, forwarding_target=0x0000c5cc, indirect_site=0x0000cc1a, indirect_caller=FUN_0000cc14)`
- **Depends on:** none
- **Supporting evidence:**
  - `EV-d9343c6252f6f61a` census_usb_inventory — grade STRONG (census structure; resolved_indirect confidence STRONG); result sha256 `372b1f264b5c6d82…`; invocation `TI-6d49d1ca71fa3819`
  - `EV-5399815447618e02` structural_source_agreement — grade STRONG (static structural agreement between code-discovery sources (heuristic boundaries)); result sha256 `a15353d2fa55f29c…`; invocation `TI-2d71df2ebaf542d6`
- **Assumptions:**
  - The registration call at 0x0000bcda executes before USB_OTHER interrupts that reach 0x0000cc1a are serviced; ordering is not established by this evidence.
- **Limitations:**
  - `AGREEMENT_SOURCES_NOT_INDEPENDENT` Not every agreeing source is independent (census <- ghidra:2c80bf9dfade293e).
  - `COMPUTED_POINTER_WRITES_NOT_EXCLUDED` resolved_indirect edges come from statically initialized RAM function pointers whose every known store is one constant code pointer; stores through computed pointers are not excluded.
  - `FUNCTION_BOUNDARIES_HEURISTIC` Census structure is statically derived from Ghidra references; function boundaries and attribution are heuristic.
  - `SOURCE_AGREEMENT_IS_STRUCTURAL` Source agreement is structural consistency between analysis sources about where code and functions are; it does not establish behavior, and a source coverage gap is not negative evidence.
- **Last audit:** none
- **Last verification:** `V-20261013T011707-3a9d52` [full] → PROPOSED: independent_audit (no audit of this exact claim version)
  - Phases: A passed, B passed, C passed, D passed
  - Semantic check `CONSISTENT` writer=FUN_0000ccc4 — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` writer_instruction=0x0000ccc6 — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` registration_caller=FUN_0000bc44 — `EV-5399815447618e02`
  - Semantic check `CONSISTENT` registration_callsite=0x0000bcda — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` raw_pointer=0x0000c725 — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` canonical_target=0x0000c724 — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` forwarding_target=0x0000c5cc — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` indirect_site=0x0000cc1a — `EV-d9343c6252f6f61a`
  - Semantic check `CONSISTENT` indirect_caller=FUN_0000cc14 — `EV-d9343c6252f6f61a`
- **Lifecycle:** PROPOSED (aptrace-ledger)

## C1:v1 — BLOCKED

- **Assertion:** The USB interrupt handler's indirect callback dispatch at FUN_0000cc0a invokes a computed target at 0xcb92.
- **Subject:** USB interrupt handler indirect callback dispatch
- **Type / proposed grade:** OTHER / STRONG
- **Scope:** (not stated)
- **Proposed by:** investigator-transcribed:Qwen3-Coder-30B-A3B-Instruct-4bit in run `R-20261012T234354-4170ad`
- **Depends on:** none
- **Supporting evidence:**
  - `EV-2bdc3898b4a334e2` search_case_evidence — grade PROBABLE (case documents (documentary)); result sha256 `2588081fd5e267d1…`; invocation `TI-7689a2199c883a23`
  - `EV-1ad3ca6d2d5fbd49` function_effects — grade BOUNDED (function effects bounded: step limit 3000); result sha256 `f6d7871ee287c0f6…`; invocation `TI-c5474450bf29277f`
- **Limitations:**
  - `DOCUMENTARY_NOT_FIRMWARE_DERIVED` Case documents are prior human findings, not firmware-derived evidence.
  - `EFFECTS_COVERAGE_BOUNDED` Function effects coverage is bounded: bounded: step limit 3000.
- **Last audit:** `A-20261012T234733-efc740` by `gemma-4-26b-a4b-it-4bit` (audit-v0.3) — **CHALLENGED**; 4 analysis request(s)
  - Reasoning: The claim asserts that the dispatch at FUN_0000cc0a invokes a target at 0xcb92. However, the evidence (EV-1ad3ca6d2d5fbd49) identifies 0xcb92 as a 'computed control transfer' site (the call site itself) within the function. In standard terminology, a dispatch 'at' an address invokes a target 'at' another address. If 0xcb92 is the location of the instruction performing the dispatch, it cannot be the target being invoked by that same instruction. The claim confuses the dispatch site with the target.
  - Scope check: The claim specifies the dispatch occurs at FUN_0000cc0a and invokes a target at 0xcb92. The evidence provided for FUN_0000cc0a (EV-1ad3ca6d2d5fbd49) shows a call site at 0xcb92, which implies 0xcb92 is the address of the instruction performing the call (the dispatch site), not the target being invoked. The disassembly (EV-0584b43428839045) shows the function ends with a branch to 0xcb6c, and the effect analysis shows a call site at 0xcb92. If 0xcb92 is the call site, it cannot be the target.
  - Challenge: The claim identifies 0xcb92 as the target, but the evidence identifies 0xcb92 as the location of the computed call (the dispatch site).
- **Audit history** (all audits of this version, oldest first; never rewritten):
  - `A-20261012T234733-efc740` audit-v0.3 input `not recorded (pre-v0.4)` → **CHALLENGED**; 4 request(s)
- **Last verification:** `V-20261012T234831-759e1a` [full] → BLOCKED: grade_ceiling (proposed STRONG; strongest supporting derivation permits PROBABLE (EV-2bdc3898b4a334e2=PROBABLE, EV-1ad3ca6d2d5fbd49=BOUNDED)); independent_audit (A-20261012T234733-efc740 CHALLENGED: The claim identifies 0xcb92 as the target, but the evidence identifies 0xcb92 as the location of the computed call (the dispatch site).)
- **Lifecycle:** PROPOSED (aptrace-ledger) → BLOCKED (aptrace-verifier)

## C3:v1 — BLOCKED

- **Assertion:** The USB callback target is FUN_0000ccc4 and the result is EXACT.
- **Subject:** USB callback target
- **Type / proposed grade:** RESOLUTION / EXACT
- **Scope:** USB interrupt callback dispatch.
- **Proposed by:** benchmark-fixture:usb-callback in run `R-20261012T234454-bb6cfa`
- **Depends on:** none
- **Supporting evidence:**
  - `EV-d9343c6252f6f61a` census_usb_inventory — grade STRONG (census structure; resolved_indirect confidence STRONG); result sha256 `372b1f264b5c6d82…`; invocation `TI-6d49d1ca71fa3819`
- **Limitations:**
  - `COMPUTED_POINTER_WRITES_NOT_EXCLUDED` resolved_indirect edges come from statically initialized RAM function pointers whose every known store is one constant code pointer; stores through computed pointers are not excluded.
  - `FUNCTION_BOUNDARIES_HEURISTIC` Census structure is statically derived from Ghidra references; function boundaries and attribution are heuristic.
- **Last audit:** `A-20261013T002518-d9234e` by `gemma-4-26b-a4b-it-4bit` (audit-v0.4) — **SUPPORTED**; 1 analysis request(s)
  - Reasoning: The evidence [EV-d9343c6252f6f61a] shows that the USB interrupt handler (FUN_0000cc14) performs an indirect call using a pointer loaded from RAM 0x200052e8. The analysis shows that this RAM location is written by FUN_0000ccc4 at address 0x0000ccc6 (as confirmed by the disassembly [EV-3034f7d75faff00f]). The value written is 0x0000c725, which resolves to the target FUN_0000c724. Thus, the 'USB callback target' (the function being called via the pointer) is the result of the write from FUN_0000ccc4. The claim identifies FUN_0000ccc4 as the target, but in the context of 'the USB callback target is [the function that writes it]', it is slightly ambiguous. However, looking at the 'resolved_indirect' field, the 'writer' is FUN_0000ccc4. The claim 'The USB callback target is FUN_0000ccc4' likely refers to the source of the pointer being dispatched. Given the 'resolved_indirect' field explicitly labels FUN_0000ccc4 as the 'writer' and the 'target' as the result of that write, the relationship is established. The grade EXACT is supported because the address and the role are deterministically linked via the provided evidence.
  - Scope check: The scope is the USB interrupt callback dispatch. The evidence identifies the writer of the callback pointer (FUN_0000ccc4) and the consumer (FUN_0000cc14).
- **Audit history** (all audits of this version, oldest first; never rewritten):
  - `A-20261012T234535-2ccfbe` audit-v0.3 input `not recorded (pre-v0.4)` → **CHALLENGED**; 4 request(s), 2 coverage-gap result(s)
  - `A-20261013T002337-5db236` audit-v0.4 input `AI-254895dbc1ad1fc1` → **CHALLENGED**; 1 request(s), 1 executed; batch `B-20261013T002337-4ada15`
  - `A-20261013T002356-d6cbba` audit-v0.4 input `AI-254895dbc1ad1fc1` → **SUPPORTED**; 1 request(s), 1 executed; batch `B-20261013T002337-4ada15`
  - `A-20261013T002406-90840c` audit-v0.4 input `AI-254895dbc1ad1fc1` → **SUPPORTED**; 1 request(s), 1 executed; batch `B-20261013T002337-4ada15`
  - `A-20261013T002415-983d14` audit-v0.4 input `AI-254895dbc1ad1fc1` → **SUPPORTED**; 1 request(s), 1 executed; batch `B-20261013T002337-4ada15`
  - `A-20261013T002428-9d23bf` audit-v0.4 input `AI-254895dbc1ad1fc1` → **SUPPORTED**; 1 request(s), 1 executed; batch `B-20261013T002337-4ada15`
  - `A-20261013T002438-94a3a4` audit-v0.4 input `AI-254895dbc1ad1fc1` → **SUPPORTED**; 1 request(s), 1 executed; batch `B-20261013T002337-4ada15`
  - `A-20261013T002448-3c6e14` audit-v0.4 input `AI-254895dbc1ad1fc1` → **SUPPORTED**; 1 request(s), 1 executed; batch `B-20261013T002337-4ada15`
  - `A-20261013T002458-a32bf9` audit-v0.4 input `AI-254895dbc1ad1fc1` → **SUPPORTED**; 1 request(s), 1 executed; batch `B-20261013T002337-4ada15`
  - `A-20261013T002508-2977f3` audit-v0.4 input `AI-254895dbc1ad1fc1` → **SUPPORTED**; 1 request(s), 1 executed; batch `B-20261013T002337-4ada15`
  - `A-20261013T002518-d9234e` audit-v0.4 input `AI-254895dbc1ad1fc1` → **SUPPORTED**; 1 request(s), 1 executed; batch `B-20261013T002337-4ada15`
- **Structural source agreement** (`EV-5399815447618e02`, latest audit context):
  - 0x0000bcda AGREE (CONSISTENT): census=FUN_0000bc44, ghidra=FUN_0000bc44, macaw=FUN_0000bc44
  - 0x0000c5cc PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000c5cc, ghidra=FUN_0000c5cc, macaw=—; gaps MACAW_COVERAGE_GAP
  - 0x0000c724 PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000c724, ghidra=FUN_0000c724, macaw=—; gaps MACAW_COVERAGE_GAP
  - 0x0000cc14 PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000cc14, ghidra=FUN_0000cc14, macaw=FUN_0000cc14
  - 0x0000cc1a PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000cc14, ghidra=FUN_0000cc14, macaw=—; gaps MACAW_COVERAGE_GAP
  - 0x0000ccc6 AGREE (CONSISTENT): census=FUN_0000ccc4, ghidra=FUN_0000ccc4, macaw=FUN_0000ccc4
- **Last verification:** `V-20261013T003509-b779d9` [full] → BLOCKED: grade_ceiling (proposed EXACT; strongest supporting derivation permits STRONG (EV-d9343c6252f6f61a=STRONG)); independent_audit (A-20261012T234535-2ccfbe CHALLENGED this version (later A-20261013T002518-d9234e SUPPORTED does not override))
- **Lifecycle:** PROPOSED (aptrace-ledger) → BLOCKED (aptrace-verifier)

## C4:v1 — BLOCKED

- **Assertion:** The physical/EIC interrupt-dispatch path converges with the USB interrupt path.
- **Subject:** EIC interrupt dispatch and USB interrupt path
- **Type / proposed grade:** PATH_EXISTS / STRONG
- **Scope:** Census strong call graph, within the census hop bound.
- **Proposed by:** benchmark-fixture:eic-convergence in run `R-20261012T234605-3218bc`
- **Depends on:** none
- **Supporting evidence:**
  - `EV-d9343c6252f6f61a` census_usb_inventory — grade STRONG (census structure; resolved_indirect confidence STRONG); result sha256 `372b1f264b5c6d82…`; invocation `TI-6d49d1ca71fa3819`
  - `EV-d816b5c25a8f750b` census_peripheral_usage — grade STRONG (census constant-address MMIO references (heuristic function boundaries)); result sha256 `870bc32c09d20bae…`; invocation `TI-de9955ee736cb17d`
  - `EV-aec58644e0021efd` census_common_paths — grade STRONG (census strong graph path (KNOWN_COMMON_PATH)); result sha256 `b784bf8495797aca…`; invocation `TI-77cc1d70ca84f536`
- **Limitations:**
  - `COMPUTED_POINTER_WRITES_NOT_EXCLUDED` resolved_indirect edges come from statically initialized RAM function pointers whose every known store is one constant code pointer; stores through computed pointers are not excluded.
  - `FUNCTION_BOUNDARIES_HEURISTIC` Census structure is statically derived from Ghidra references; function boundaries and attribution are heuristic.
  - `PERIPHERAL_SET_IS_MMIO_USAGE:EIC` Set 'EIC' is the census structural set for EIC (constant-address register/MMIO users), not a semantic subsystem, event, or interrupt-dispatch path.
  - `PERIPHERAL_SET_IS_MMIO_USAGE:USB` Set 'USB' is the census structural set for USB (constant-address register/MMIO users), not a semantic subsystem, event, or interrupt-dispatch path.
  - `STRUCTURAL_USAGE_NOT_DEVICE_IDENTITY` Structural usage does not identify what external device is attached to the peripheral; that requires hardware-routing evidence.
  - `UNRESOLVED_INDIRECT_FRONTIER` 7 unresolved indirect transfer site(s) in the explored region; paths through them are unknown.
- **Last audit:** `A-20261013T003244-5a930c` by `gemma-4-26b-a4b-it-4bit` (audit-v0.4) — **UNRESOLVED** (synthesized: decision_budget_exhausted); 4 analysis request(s)
  - Reasoning: No valid verdict was produced (decision_budget_exhausted); APTrace recorded UNRESOLVED.
- **Audit history** (all audits of this version, oldest first; never rewritten):
  - `A-20261012T234605-72b150` audit-v0.3 input `not recorded (pre-v0.4)` → **CHALLENGED**; 2 request(s)
  - `A-20261013T002531-184181` audit-v0.4 input `AI-485712c83ee950c1` → **UNRESOLVED**; 4 request(s), 1 executed; batch `B-20261013T002531-2a7d1c`
  - `A-20261013T002634-e8b598` audit-v0.4 input `AI-485712c83ee950c1` → **CHALLENGED**; 3 request(s), 2 executed; batch `B-20261013T002531-2a7d1c`
  - `A-20261013T002715-63232f` audit-v0.4 input `AI-485712c83ee950c1` → **UNRESOLVED**; 4 request(s), 2 executed; batch `B-20261013T002531-2a7d1c`
  - `A-20261013T002800-34400f` audit-v0.4 input `AI-485712c83ee950c1` → **CHALLENGED**; 3 request(s), 2 executed; batch `B-20261013T002531-2a7d1c`
  - `A-20261013T002846-3502da` audit-v0.4 input `AI-485712c83ee950c1` → **SUPPORTED**; 3 request(s), 2 executed; batch `B-20261013T002531-2a7d1c`
  - `A-20261013T002926-277bcd` audit-v0.4 input `AI-485712c83ee950c1` → **UNRESOLVED**; 4 request(s), 2 executed; batch `B-20261013T002531-2a7d1c`
  - `A-20261013T003010-8095a3` audit-v0.4 input `AI-485712c83ee950c1` → **UNRESOLVED**; 4 request(s), 2 executed; batch `B-20261013T002531-2a7d1c`
  - `A-20261013T003110-606145` audit-v0.4 input `AI-485712c83ee950c1` → **CHALLENGED**; 3 request(s), 2 executed; batch `B-20261013T002531-2a7d1c`
  - `A-20261013T003158-f33c05` audit-v0.4 input `AI-485712c83ee950c1` → **CHALLENGED**; 3 request(s), 1 executed; batch `B-20261013T002531-2a7d1c`
  - `A-20261013T003244-5a930c` audit-v0.4 input `AI-485712c83ee950c1` → **UNRESOLVED**; 4 request(s), 2 executed; batch `B-20261013T002531-2a7d1c`
- **Structural source agreement** (`EV-5399815447618e02`, latest audit context):
  - 0x0000bcda AGREE (CONSISTENT): census=FUN_0000bc44, ghidra=FUN_0000bc44, macaw=FUN_0000bc44
  - 0x0000c5cc PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000c5cc, ghidra=FUN_0000c5cc, macaw=—; gaps MACAW_COVERAGE_GAP
  - 0x0000c724 PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000c724, ghidra=FUN_0000c724, macaw=—; gaps MACAW_COVERAGE_GAP
  - 0x0000cc14 PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000cc14, ghidra=FUN_0000cc14, macaw=FUN_0000cc14
  - 0x0000cc1a PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000cc14, ghidra=FUN_0000cc14, macaw=—; gaps MACAW_COVERAGE_GAP
  - 0x0000ccc6 AGREE (CONSISTENT): census=FUN_0000ccc4, ghidra=FUN_0000ccc4, macaw=FUN_0000ccc4
- **Last verification:** `V-20261013T003509-217ec0` [full] → BLOCKED: independent_audit (A-20261012T234605-72b150 CHALLENGED this version (later A-20261013T003244-5a930c UNRESOLVED does not override))
- **Lifecycle:** PROPOSED (aptrace-ledger) → BLOCKED (aptrace-verifier)

## C7:v1 — BLOCKED

- **Assertion:** The USB callback target is FUN_0000ccc4 and the result is EXACT.
- **Subject:** USB callback target
- **Type / proposed grade:** RESOLUTION / EXACT
- **Scope:** USB interrupt callback dispatch.
- **Proposed by:** benchmark-fixture:semantic-usb-eic in run `R-20261013T011707-ea649e`
- **Structured semantics (authoritative for verification):** `FUNCTION_ROLE(FUN_0000ccc4 is CALLBACK_TARGET, slot=0x200052e8)`
- **Depends on:** none
- **Supporting evidence:**
  - `EV-d9343c6252f6f61a` census_usb_inventory — grade STRONG (census structure; resolved_indirect confidence STRONG); result sha256 `372b1f264b5c6d82…`; invocation `TI-6d49d1ca71fa3819`
  - `EV-5399815447618e02` structural_source_agreement — grade STRONG (static structural agreement between code-discovery sources (heuristic boundaries)); result sha256 `a15353d2fa55f29c…`; invocation `TI-2d71df2ebaf542d6`
- **Limitations:**
  - `AGREEMENT_SOURCES_NOT_INDEPENDENT` Not every agreeing source is independent (census <- ghidra:2c80bf9dfade293e).
  - `COMPUTED_POINTER_WRITES_NOT_EXCLUDED` resolved_indirect edges come from statically initialized RAM function pointers whose every known store is one constant code pointer; stores through computed pointers are not excluded.
  - `FUNCTION_BOUNDARIES_HEURISTIC` Census structure is statically derived from Ghidra references; function boundaries and attribution are heuristic.
  - `SOURCE_AGREEMENT_IS_STRUCTURAL` Source agreement is structural consistency between analysis sources about where code and functions are; it does not establish behavior, and a source coverage gap is not negative evidence.
- **Last audit:** none
- **Last verification:** `V-20261013T011707-93d8f9` [full] → BLOCKED: claim_semantics (ENTITY_ROLE_MISMATCH: supporting evidence identifies FUN_0000ccc4 as WRITER, not CALLBACK_TARGET); grade_ceiling (proposed EXACT; strongest supporting derivation permits STRONG (EV-d9343c6252f6f61a=STRONG, EV-5399815447618e02=STRONG))
  - Phases: A passed, B failed, C skipped, D skipped
  - Semantic check `ENTITY_ROLE_MISMATCH` role=FUN_0000ccc4 (claimed role CALLBACK_TARGET; evidence role WRITER) — `EV-d9343c6252f6f61a`: supporting evidence identifies FUN_0000ccc4 as WRITER, not CALLBACK_TARGET
  - Audit model not consulted: deterministic verification failed before phase D.
- **Lifecycle:** PROPOSED (aptrace-ledger) → BLOCKED (aptrace-verifier)

## C8:v1 — BLOCKED

- **Assertion:** The physical/EIC interrupt-dispatch path converges with the USB interrupt path.
- **Subject:** EIC interrupt dispatch and USB interrupt path
- **Type / proposed grade:** PATH_EXISTS / STRONG
- **Scope:** Census strong call graph, within the census hop bound.
- **Proposed by:** benchmark-fixture:semantic-usb-eic in run `R-20261013T011707-ea649e`
- **Structured semantics (authoritative for verification):** `PATH_RELATION(INTERRUPT_DISPATCH_SET:EIC KNOWN_COMMON_PATH INTERFACE_INVENTORY:USB)`
- **Depends on:** none
- **Supporting evidence:**
  - `EV-d9343c6252f6f61a` census_usb_inventory — grade STRONG (census structure; resolved_indirect confidence STRONG); result sha256 `372b1f264b5c6d82…`; invocation `TI-6d49d1ca71fa3819`
  - `EV-d816b5c25a8f750b` census_peripheral_usage — grade STRONG (census constant-address MMIO references (heuristic function boundaries)); result sha256 `870bc32c09d20bae…`; invocation `TI-de9955ee736cb17d`
  - `EV-aec58644e0021efd` census_common_paths — grade STRONG (census strong graph path (KNOWN_COMMON_PATH)); result sha256 `b784bf8495797aca…`; invocation `TI-77cc1d70ca84f536`
- **Limitations:**
  - `COMPUTED_POINTER_WRITES_NOT_EXCLUDED` resolved_indirect edges come from statically initialized RAM function pointers whose every known store is one constant code pointer; stores through computed pointers are not excluded.
  - `FUNCTION_BOUNDARIES_HEURISTIC` Census structure is statically derived from Ghidra references; function boundaries and attribution are heuristic.
  - `PERIPHERAL_SET_IS_MMIO_USAGE:EIC` Set 'EIC' is the census structural set for EIC (constant-address register/MMIO users), not a semantic subsystem, event, or interrupt-dispatch path.
  - `PERIPHERAL_SET_IS_MMIO_USAGE:USB` Set 'USB' is the census structural set for USB (constant-address register/MMIO users), not a semantic subsystem, event, or interrupt-dispatch path.
  - `STRUCTURAL_USAGE_NOT_DEVICE_IDENTITY` Structural usage does not identify what external device is attached to the peripheral; that requires hardware-routing evidence.
  - `UNRESOLVED_INDIRECT_FRONTIER` 7 unresolved indirect transfer site(s) in the explored region; paths through them are unknown.
- **Last audit:** none
- **Last verification:** `V-20261013T011707-f2e533` [full] → BLOCKED: claim_semantics (SCOPE_MISMATCH: no supporting common-path evidence was computed over the claimed set scopes; no APTrace derivation establishes equivalence between different set kinds)
  - Phases: A passed, B failed, C skipped, D skipped
  - Semantic check `SCOPE_MISMATCH` scope=INTERFACE_INVENTORY:USB | INTERRUPT_DISPATCH_SET:EIC — `EV-aec58644e0021efd`: no supporting common-path evidence was computed over the claimed set scopes; no APTrace derivation establishes equivalence between different set kinds
  - Audit model not consulted: deterministic verification failed before phase D.
- **Lifecycle:** PROPOSED (aptrace-ledger) → BLOCKED (aptrace-verifier)

## C2:v1 — SUPERSEDED

- **Assertion:** The indirect call at 0x0000cc1a in the USB_OTHER interrupt handler FUN_0000cc14 loads its target from RAM slot 0x200052e8, whose only known store (0x0000ccc6 in FUN_0000ccc4, storing the r0 argument of the call at 0x0000bcda) holds the raw Thumb pointer 0x0000c725; the canonical target is 0x0000c724 (FUN_0000c724), which forwards to 0x0000c5cc.
- **Subject:** Indirect call at 0x0000cc1a in USB_OTHER handler FUN_0000cc14
- **Type / proposed grade:** RESOLUTION / STRONG
- **Scope:** Static census resolved function pointers for firmware autopilot868; RAM slot 0x200052e8 only.
- **Proposed by:** benchmark-fixture:usb-callback in run `R-20261012T234454-bb6cfa`
- **Depends on:** none
- **Supporting evidence:**
  - `EV-d9343c6252f6f61a` census_usb_inventory — grade STRONG (census structure; resolved_indirect confidence STRONG); result sha256 `372b1f264b5c6d82…`; invocation `TI-6d49d1ca71fa3819`
- **Assumptions:**
  - The registration call at 0x0000bcda executes before USB_OTHER interrupts that reach 0x0000cc1a are serviced; ordering is not established by this evidence.
- **Limitations:**
  - Stores to 0x200052e8 through computed pointers are not excluded by static analysis.
  - `COMPUTED_POINTER_WRITES_NOT_EXCLUDED` resolved_indirect edges come from statically initialized RAM function pointers whose every known store is one constant code pointer; stores through computed pointers are not excluded.
  - `FUNCTION_BOUNDARIES_HEURISTIC` Census structure is statically derived from Ghidra references; function boundaries and attribution are heuristic.
- **Last audit:** `A-20261013T002322-2a48cb` by `gemma-4-26b-a4b-it-4bit` (audit-v0.4) — **SUPPORTED**; 2 analysis request(s)
  - Reasoning: The disassembly of FUN_0000cc14 confirms that at 0x0000cc1a, the processor performs a branch to the value loaded from the address in r3 (which is loaded from the PC-relative offset at 0x0000cc16). The disassembly of FUN_0000ccc4 confirms that at 0x0000ccc6, the value in r0 is stored to the address in r3 (which is loaded from the PC-relative offset at 0x0000ccc4). The census evidence establishes that the address in r3 at 0x0000ccc4 is 0x200052e8. The claim's logic regarding the Thumb bit (0x0000c725 -> 0x0000c724) is consistent with standard ARM Thumb branch targets. The grade 'STRONG' is appropriate as the derivation is based on static analysis of a single known store to the target RAM slot.
  - Scope check: The assertion correctly identifies the consumer (FUN_0000cc14), the indirect call site (0x0000cc1a), the RAM slot (0x200052e8), the writer (FUN_0000ccc4), the store instruction (0x0000ccc6), and the relationship between the r0 argument at 0x0000bcda and the target 0x0000c724.
- **Audit history** (all audits of this version, oldest first; never rewritten):
  - `A-20261012T234455-90a51c` audit-v0.3 input `not recorded (pre-v0.4)` → **CHALLENGED**; 4 request(s), 3 coverage-gap result(s)
  - `A-20261013T002035-2e542c` audit-v0.4 input `AI-782d9c510216db1a` → **SUPPORTED**; 2 request(s), 2 executed; batch `B-20261013T002035-256882`
  - `A-20261013T002121-2d6725` audit-v0.4 input `AI-782d9c510216db1a` → **SUPPORTED**; 2 request(s), 2 executed; batch `B-20261013T002035-256882`
  - `A-20261013T002137-2c2e2a` audit-v0.4 input `AI-782d9c510216db1a` → **SUPPORTED**; 2 request(s), 2 executed; batch `B-20261013T002035-256882`
  - `A-20261013T002152-931af3` audit-v0.4 input `AI-782d9c510216db1a` → **SUPPORTED**; 2 request(s), 2 executed; batch `B-20261013T002035-256882`
  - `A-20261013T002207-8bcdd7` audit-v0.4 input `AI-782d9c510216db1a` → **SUPPORTED**; 2 request(s), 2 executed; batch `B-20261013T002035-256882`
  - `A-20261013T002223-622969` audit-v0.4 input `AI-782d9c510216db1a` → **SUPPORTED**; 2 request(s), 2 executed; batch `B-20261013T002035-256882`
  - `A-20261013T002237-5ce4da` audit-v0.4 input `AI-782d9c510216db1a` → **SUPPORTED**; 2 request(s), 2 executed; batch `B-20261013T002035-256882`
  - `A-20261013T002252-7e508b` audit-v0.4 input `AI-782d9c510216db1a` → **SUPPORTED**; 2 request(s), 2 executed; batch `B-20261013T002035-256882`
  - `A-20261013T002307-aab0c1` audit-v0.4 input `AI-782d9c510216db1a` → **SUPPORTED**; 2 request(s), 2 executed; batch `B-20261013T002035-256882`
  - `A-20261013T002322-2a48cb` audit-v0.4 input `AI-782d9c510216db1a` → **SUPPORTED**; 2 request(s), 2 executed; batch `B-20261013T002035-256882`
- **Structural source agreement** (`EV-5399815447618e02`, latest audit context):
  - 0x0000bcda AGREE (CONSISTENT): census=FUN_0000bc44, ghidra=FUN_0000bc44, macaw=FUN_0000bc44
  - 0x0000c5cc PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000c5cc, ghidra=FUN_0000c5cc, macaw=—; gaps MACAW_COVERAGE_GAP
  - 0x0000c724 PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000c724, ghidra=FUN_0000c724, macaw=—; gaps MACAW_COVERAGE_GAP
  - 0x0000cc14 PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000cc14, ghidra=FUN_0000cc14, macaw=FUN_0000cc14
  - 0x0000cc1a PARTIAL_AGREEMENT (CONSISTENT): census=FUN_0000cc14, ghidra=FUN_0000cc14, macaw=—; gaps MACAW_COVERAGE_GAP
  - 0x0000ccc6 AGREE (CONSISTENT): census=FUN_0000ccc4, ghidra=FUN_0000ccc4, macaw=FUN_0000ccc4
- **Last verification:** `V-20261013T003509-bf0329` [full] → BLOCKED: independent_audit (A-20261012T234455-90a51c CHALLENGED this version (later A-20261013T002322-2a48cb SUPPORTED does not override))
- **Lifecycle:** PROPOSED (aptrace-ledger) → BLOCKED (aptrace-verifier) → SUPERSEDED (aptrace-ledger)
