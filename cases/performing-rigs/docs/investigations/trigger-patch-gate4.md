# Binary patch verification — Gate 4: safety properties

2026-10-22. **RESEARCH ONLY — NOT APPROVED FOR HARDWARE DEPLOYMENT.**
Operator investigation under root `AGENTS.md` and `docs/codex-operator.md`.
Repository baseline `c00f6afdf5e1809ced630ca4d5a51518fac359c0`; initially clean.

## A. Executive verdict

**INCONCLUSIVE.** Material safety requirements lack authoritative policy or
parameters, and material verification obligations remain incomplete. No
mandatory authoritative safety-property violation is established. This is not
an absence-of-violations proof and cannot support PASS.

CE-1 (release after the new read, then acceptance and TC0 ENABLE-containing
store) and CE-2 (held LOW, completion-time W, then another initiation without
release) remain confirmed bounded firmware behaviors. They contradict precisely
stated candidate cancellation/rearming rules below. Those rules remain
**Proposed**; the corresponding Gate 4 dispositions are **BEHAVIOR CONFIRMED —
POLICY UNRESOLVED**. Gate 3's **FAIL within modeled scope** is preserved as
published, including its P2/P3 interpretations. Gate 4 adds policy attribution;
it does not rewrite those witnesses or earlier verdicts.

No new firmware execution, symbolic query, TLC run, planner run, claim admission,
firmware modification, implementation change, custom verifier, hardware operation
or Gate 5 work occurred. Existing APTrace evidence suffices for the concrete
behavior questions; rerunning it would not establish missing product policy.

## B. Artifact identity and evidence index

Both images load at `0x4000`; application reset entry `0xcc24`. Fresh standard
`shasum -a 256` inspection agrees with Gates 1–3:

| Artifact (case-relative unless stated) | Bytes / SHA-256 |
|---|---|
| `research/firmware/originals/firmware_autopilot915.bin` | 70768 recorded; `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |
| `research/generated/trigger-patch-2026-10-22/RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_freshness.bin` | 70796 recorded; `ae9e6a749426fc3d800a0e26d016cc58f818ce8f84d5a7ba12c41d6d727bc616` |
| Repository `tools/unicorn/concrete.py` | `fcf4529322de345b3f6dd7f4c373084b1957348ade2bb4c1d6acf285d6266f3b` |
| Repository `tools/unicorn/run_concrete.py` | `e91dce33ec855c883dd9ba8ca7c1976020c096552e3300649399b682c3256735` |

This is unambiguously the same patched file evaluated in all three gates:
six original-region bytes replaced at `0x922c`, 28 appended at `0x15470`.
APTrace identity is the repository baseline plus backend hashes, not an invented
release number. Historical runtime: Python 3.9.6 / Unicorn 2.1.4 (Gate 3);
versions not freshly executed in Gate 4. Field-tested release hash correspondence,
physical flash ownership and bootloader compatibility remain unknown.

Stable evidence references used throughout:

| ID | Source and evidentiary scope |
|---|---|
| E1 | [Gate 1](trigger-patch-gate1.md), [packet](../../research/generated/patch-gate1-2026-10-22/): independent Ghidra/Macaw decode, rooted CFG and helper/fragment effects; integrated fragment aborted. |
| E2 | [Gate 2](trigger-patch-gate2.md), [packet](../../research/generated/patch-gate2-2026-10-22/): 14 exact replays, two watch-disabled controls, ordered selected-store comparison and unresolved global differences. |
| E3 | [Gate 3](trigger-patch-gate3.md), [packet and execution record](../../research/generated/patch-gate3-2026-10-22/README.md): nine firmware runs, six exact historical replays, three controls, static writer evidence. |
| E4 | [Original authoring packet](../../research/generated/trigger-patch-2026-10-22/README.md): immutable original witnesses, recipes, manifests and 20 historical native records. |
| E5 | [Reference contract](../../specifications/trigger-acceptance/README.md), [handoff](../../specifications/trigger-acceptance/HANDOFF.md), [assessment](reference-trigger-contract.md): proposed policy and finite TLA+ checks, no binary refinement. |
| E6 | [Target1](startup-voltage-learning.md), [Target2](trigger-symbolic-reachability-target2.md), [Target3](motion-initiation-route-coverage.md): retained-filter dependence, original-image digital symbolic slices and bounded alternative-route inventory. |
| E7 | [Manual/UI sourcing and workflows](../ui/user-guide-workflows.md), [manual traceability](../replacement/manual-to-firmware-traceability.md), [machine-readable companion](../../research/generated/manual-to-firmware-traceability.json), [W framing](../protocol/protocol-orphan-disposition.md#bare-w--variant_or_framing_mismatch), [command inventory](../protocol/command-inventory.md). |

Fresh digests of E3 `late-release-patched.json`, `held-w-patched.json` and
`observations.json` match its preserved `artifact-hashes.json`, respectively:
`d1a0de5070f4a7462a48af0e14de506b82e1a2e8a574b2a39b374764020fabe4`,
`4892eaeea3bcc9f4b783568e7219e7cc4abaa8915690552628a1797ee3ae3b7c`,
`75749b6c62f26fa20832a88f85dcb8ab8d86371799234baf2a5bf59d01fad4ce`.
Hashes establish identity, not model correctness. Raw snapshots and command
records remain in place; no historical output was overwritten.

### Policy authority review

**Authoritative for this investigation:** research-only scope, evidence discipline,
preservation of prior gates, no deployment and no Gate 5, as explicitly instructed
by the user. These are investigation constraints, not product initiation rules.

**Product authority boundary:** E7's workflow skeleton states that the literal
manual PDF is absent; its primary source is a prior page-cited manual summary.
Its section 11 attributes a startup cable/noise-baseline sensitivity claim to
manual section 12. This establishes documented operating expectations through a
secondary source, not a quantified analog protection rule. E6 demonstrates
retained-filter dependence without proving the implied adaptive-threshold
mechanism. No inspected manual-derived requirement specifies release cancellation,
a release duration, initial-release arming, or W's exemption from those rules.
No complete mandatory authorization policy was located. This is a bounded
repository authority review, not a claim that no external product requirement exists.

E5 explicitly labels its contract **proposed**. Its choices D2/D3/D4/D8 require
qualified episodes, cancellation before Start, fresh inactive qualification after
completion and a common trigger-derived gate; independent manual/jog authorization
is separately unresolved. Model authority over its transition system does not
make it product-policy authority over this binary.

W's **inferred firmware role** in CE-2 is return/phase progression restoring
software eligibility (idle2→idle9); parsing and subsequent initiation are observed.
Whether W also *authorizes* a new operation independently, or must await release,
is **Unknown**. Bare W, W0 and W1 are distinct forms (E7); W1's direct playback
witness cannot decide bare W's product meaning. No policy exception is inferred
from the firmware's permissiveness.

## C. Safety-property catalog

Catalog version **G4-v1**. IDs and event meanings remain stable across revisions;
product decisions fill named parameters or create an explicitly versioned policy.
A new revision must supply its own address/event mapping and evidence. All ten
normative safety statements are **Proposed**, with Unknown parameters identified
below; inferred implementation facts are recorded separately. None is promoted
to Authoritative by a successful test or by existing behavior.

Common scope: CPU-level initiation requests across the specified firmware image;
physical output is a separate observation. Common assumptions/limits are in D/E.
Each entry specifies preconditions, state, observables, rule, timing, evidence,
counterexamples and outstanding decisions.

### SAFE-001 — Authorized initiation

**Statement / authority:** Proposed (E5 D8); every initiation must have the
prescribed authorization for its producer. Complete authorization conditions are
Unknown, including product readiness and independent command authority.
**Scope / preconditions:** every new profile/direct initiation, with producer
and event identity known. **Inputs/state:** digital/analog observations,
configuration validity, channel/idle/TR state, command, pending authorization.
**Observables/rule:** Start implies `Auth(producer,event,state)` at commitment;
trigger-derived authorization is single-use under the E5 candidate policy.
**Timing:** authorization expiry/freshness unspecified. **Evidence:** E1 local
digital guard, E2 positive/veto controls, E6 producer inventory. **Counterexamples:**
CE-1/2 challenge particular proposed Auth clauses, not an established complete
policy. **Limits/questions:** marker7b and idle9 are software predicates, not
validated physical readiness; define command permissions and authorization lifetime.

### SAFE-002 — Release cancellation

**Statement / authority:** Proposed (E5 D3): a release before commitment cancels
that pending external-trigger request. **Scope / preconditions:** an acquired
pending request, no intervening new authorized episode, release before selected
commitment event. **Inputs/state:** source level, sampled level, pending request,
cancellation flag. **Observables/rule:** Release invalidates pending eligibility;
no Accept or Start for that request afterward under the strict candidate in D.
**Timing:** cancellation deadline/latency and commitment boundary Unknown; no
instruction-to-time conversion. **Evidence/CE:** E3 CE-1 and after-CMP variant;
release-before-read negative control. **Limits/questions:** modeled GPIO update
is not a measured physical edge; choose sample-relative versus source-relative
cancellation, Accept versus timer commitment, and post-commit behavior.

### SAFE-003 — Release-to-rearm

**Statement / authority:** Proposed (E5 D2/D4): each subsequent external-trigger
initiation requires a new qualified inactive→active episode after completion.
**Scope / preconditions:** prior trigger start and completion in the same session;
no reset or independent authorization exemption. **Inputs/state:** episode identity,
completion, release history, W, software eligibility. **Observables/rule:** second
Accept/Start must consume a distinct post-completion episode. **Timing:** inactive
qualification duration Unknown. **Evidence/CE:** E3 CE-2, matched original,
held/no-W and release/repress controls. **Limits/questions:** W authority is
unresolved; physical release and idle restoration are different events. Resolve
whether a W-authorized operation is a separate producer; do not erase CE-2.

### SAFE-004 — Sustained qualification

**Statement / authority:** Proposed (E5); only fresh, sufficiently stable qualified
input may authorize initiation. **Scope / preconditions:** trigger recognition
before Accept. **Inputs/state:** raw/filtered input history, sample ages and
qualification accumulator. **Observables/rule:** Recognize implies `Q(history,
policy)`; local two-read LOW agreement is only a weaker implementation fact.
**Timing:** active/inactive windows, maximum observation age, consistency and
pulse requirements Unknown. **Evidence:** E1 second-read predicate, E2 veto,
E5 parameterized qualification. **CE:** CE-1 is not evidence of a particular
minimum-duration violation. **Limits/questions:** two reads do not prove sustained
physical input; specify parameters, acquisition model and legitimate short pulses.

### SAFE-005 — Startup arming

**Statement / authority:** Proposed (E5 D2); reset must establish prescribed
readiness and initial arming before an external-trigger initiation.
**Scope / preconditions:** reset-reachable initialization, not arbitrary RAM.
**Inputs/state:** reset/retention, configuration, readiness, initial input history,
armed state. **Observables/rule:** no trigger Accept/Start until `StartupArmed`;
E5 candidate requires fresh inactive qualification after readiness.
**Timing:** startup/inactive windows Unknown. **Evidence/CE:** E3 held LOW from
reset reaches first acceptance; E6 startup histories. This contradicts a candidate
initial-release rule but does not establish unintended product behavior.
**Limits/questions:** modeled zero RAM/MMIO versus hardware reset/retention;
define readiness providers and whether active-at-power-up is legitimate.

### SAFE-006 — Analog-state protection

**Statement / authority:** Proposed protection rule (E5), informed by manual-derived
operating expectation (E7); analog initiation must satisfy prescribed validated
history and limits. **Scope / preconditions:** analog-selected recognition.
**Inputs/state:** ADC history, selector X, retained filter, derived average/low flag,
threshold and mode. **Observables/rule:** analog Accept/Start implies `AnalogOK`.
**Timing/limits:** thresholds, hysteresis, history age and qualification windows
Unknown. **Evidence:** E6 Target1 separates retained filter from average/flag;
E3 X1 starts at filtered581, X2 does not for supplied517→600 history.
**CE:** that difference is confirmed behavior, not a specified unsafe band.
**Limits/questions:** no arbitrary-history proof or calibrated electrical mapping;
define safety envelope and reconcile manual baseline expectation with mechanism.

### SAFE-007 — No unauthorized alternative initiation path

**Statement / authority:** Proposed (E5 D8, with independent producer policy still
Unknown); every producer reaching a relevant initiation sink obeys its own Auth.
**Scope / preconditions:** all producers, including command, analog, callback,
catch-up/group and IRQ-related output requests. **Inputs/state:** route identity,
authorization, live/timer/position and per-channel state. **Observables/rule:**
no route bypasses its required authorization; classify rate maintenance separately
from new authorization and STEP emission separately from timer enable.
**Timing:** producer-dependent, unspecified. **Evidence:** E2 patched G/W1/B1,
E3 analog, E6 Target3 original868 group/catch-up/direct inventory.
**CE:** bypass of the new digital guard is established; unauthorized status is
not. **Limits/questions:** incomplete CFG/alias coverage, variant-qualified
witnesses; decide independent command/jog authority and relevant sink inventory.

### SAFE-008 — Interrupt and timing robustness

**Statement / authority:** Proposed; selected safety invariants remain true under
permitted interrupt/peripheral interleavings. **Scope / preconditions:** defined
schedule, priorities, masking and peripheral contracts. **Inputs/state:** pending
IRQ, interrupt-visible eligibility, ticks, input synchronization and timer updates.
**Observables/rule:** SAFE-001–007 remain invariant for every allowed interleaving.
**Timing:** schedule and latency contracts Unknown. **Evidence:** E3 static idle
WRITE1 at0x5b1a in TC0-linked service; no feasible concurrent bypass established.
**CE:** CE-1 demonstrates peripheral update sensitivity, not an IRQ witness.
**Limits/questions:** no autonomous NVIC/exception model or calibrated clock;
define allowed schedules and establish writer reachability before race claims.

### SAFE-009 — Execution-state integrity

**Statement / authority:** Proposed gate preservation obligation (E1), required
in investigative scope; exact live-state/frame contract remains incomplete.
**Scope / preconditions:** matching caller state at patch entry, valid stack and
callee/peripheral contracts, intended predicate change permitted.
**Inputs/state:** registers/flags, stack, RAM, MMIO and incoming CFG.
**Observables/rule:** paired exits preserve required live state and confined effects
modulo declared temporary stack/read and intended behavior. **Timing:** stack/IRQ
margin required, no numerical bound established. **Evidence:** E1 independent
decode/balanced24-byte frame, helper zero writes; E2 selected state agreement.
**CE:** no demonstrated corruption; aborted paths are not absence proofs.
**Limits/questions:** framed relational proof, rejection exit, global entry coverage,
stack headroom, unexpected writes and hardware-read effects remain obligations.

### SAFE-010 — Intended-behavior preservation

**Statement / authority:** Proposed preservation obligation (E2); preserve required
valid initiation and unrelated required behavior. Full allowed-input set and
observable equivalence policy Unknown. **Scope / preconditions:** paired original/
patched scenarios with equivalent semantic inputs/environment, intentional veto
excluded from equivalence. **Inputs/state:** valid program/commands, input history,
clock and observer projection. **Observables/rule:** preservation of required
ordered outputs and live state; permitted valid requests eventually start under
explicit progress assumptions (liveness component).
**Timing:** acceptable added latency and cross-peripheral order Unknown.
**Evidence:** E2 intentional ordered29,236 tuples and G/W1/B1 endpoints;
357 fresh-control global differing indices and polling differences remain open.
**CE:** global projection equality is false in the fresh control; required-behavior
violation not established. **Limits/questions:** sparse writes, no full lifetime,
no event/time-aligned equivalence; define valid pulses, projections and ordering.

## D. Formal definitions and model boundary

The following are precise **documentation predicates**, not a new executable
verification language or a claim that APTrace natively evaluated temporal logic.
E5's unchanged TLA+ representation supplies analogous `AuthorizedStarts`,
`UniqueStarts`, `StartTransitionAuthorized` and `CancellationInvalidates` for
its abstract controller only. No trace-refinement adapter binds that state to
this patched binary. No new model or verification script was authored.

Let a trace be an ordered sequence of environment updates, instruction-boundary
observations and CPU stores. `i<j` means trace order, not elapsed physical time.
Use producer `p`, pending request `e` and generation/episode IDs as conceptual
identities; the patch does not implement these tokens.

| Symbol | Definition / binary mapping |
|---|---|
| `Rphys(e,t)` | Physical source releases; requires independent measurement, absent here. |
| `Rmodel(e,i)` | Scenario changes modeled PB05 IN at0x410080a0 to HIGH. It approximates release but is not Rphys. |
| `Sample(v,i)` | digitalRead57 returns v; new helper return at0x1547c. This is firmware observation, not necessarily contemporaneous physical level. |
| `Accept(e,i)` | Execution reaches0x8f98; acceptance continuation writes0x200025bd=3 and reaches reload0x6e4c. |
| `RateStart(p,i)` | Execution reaches0x5f8c; distinguish profile service0x6338 from direct request0x6fd8. |
| `Enable(i)` | Executed CPU store to TC0 CTRLA0x40003800 containing ENABLE; CE-1 first observed at0x571c with0x602. Helper0x5810 alone is not the first store. |
| `Output(t)` | Independently established physical output transition; unavailable in these witnesses. CPU STEP SET/CLR requests are a different observable. |
| `Eligible(s)` | Inferred pre-read software guard: four channel bytes zero, marker7b, idle9 and TR0 (seven fields, E6); not the full product Auth. |
| `Q(h;θ)` | Input-history qualification under unresolved duration/stability/freshness parameters θ. |
| `Auth(p,e,s;π)` | Product-authorized producer/event under unresolved policy π, including any W exemption. |

**SAFE-001:** for every Start(p,e,i), require Auth(p,e,state(i);π).
For trigger-derived starts under E5, each event can be consumed at most once.
Here Start must be bound to an agreed commitment sink; do not count every
rate update or every ENABLE-containing store as another authorization.

**SAFE-002 strict candidate C2:** if Rmodel(e,i) precedes commitment of a pending
request e and no new authorized episode intervenes, forbid Accept(e,j) and
Start(e,j) for j>i. Cancellation invalidates e until a new episode.
A weaker candidate permits Accept but forbids Enable before a new authorization;
CE-1 contradicts both in its prefix. A *sample-relative* rule instead requires
rejection only when firmware observes HIGH before acceptance; CE-1 does not
establish a HIGH return after its last LOW read and therefore is not a witness
against that weaker rule. Source-relative physical cancellation needs a specified
latency δ and Rphys measurements. No numerical δ is selected.

**SAFE-003 candidate C3:** for consecutive trigger episodes accepted at a1<a2
and completed at c1, require c1<r<q<a2, where r begins a post-completion inactive
qualification, q completes a subsequent qualified active episode, and a2 consumes
that new episode. Merely writing idle9 is insufficient. If product policy permits
independent W authorization, classify its event/producer explicitly and revise
π through policy review; do not relabel the historical held-input facts.

**SAFE-004:** Recognize(e,i) implies Q(history≤i;θ) and Fresh(history,i;θ).
**SAFE-005:** reset clears trigger authorization and forbids trigger Accept/Start
until StartupArmed(readiness,post-ready history;π,θ).
**SAFE-006:** analog Recognize/Accept implies AnalogOK(history,mode;π,θ).
**SAFE-007:** SAFE-001 quantified over every producer and sink selected by π,
with unresolved routes explicitly retained.
**SAFE-008:** the selected invariants hold for all schedules in permitted set S;
S is unresolved and is not approximated by arbitrary RAM edits.
**SAFE-009:** at paired exits, `LiveState_original ≡ LiveState_patch` modulo the
declared predicate/read/frame changes, with only allowed writes and valid stack;
requires non-aborted framed paths and specified equivalence relation.
**SAFE-010 safety part:** paired valid histories preserve required ordered output
projection and state modulo allowed differences. **Liveness part:** valid authorized
requests eventually Start or undergo a permitted cancellation under fair scheduling,
valid readiness and actual completion assumptions. Finite starts are examples,
not proof of eventuality for every valid request.

Environmental assumptions inherited from E3: mapped zero-initialized RAM/MMIO,
PA22 handshake, radio-ID return, stub0xcd34, MMIO completion/clear contracts,
program/MC4 RX delivery and W bytes supplied at0x6056, tick0x200052ec every4000
executed instructions. GPIO rules are PC-indexed and repeat on every hit.
Natural reset/program/completion state is executed within that environment;
no application busy/idle/rearm cell is forced in the digital controls. Position
stays modeled, including zero-distance return. These are environmental assumptions,
not proven hardware facts. No universal source-intent classifier is assumed.

## E. Verification matrix and completeness

No complete SAFE property has an adequate satisfaction proof. Dispositions refer
to the catalog statements, with bounded positive subresults called out separately.

| Property | Disposition | Method / evidence and explored scope | Counterexample / missing proof obligations |
|---|---|---|---|
| SAFE-001 | **SPECIFICATION INCOMPLETE** | E1 local decode, E2 concrete permitted/veto histories, E6 fixed digital symbolic slice. | Auth incomplete; producer policy, readiness, reachability and all paths unresolved; CE-1/2 relevant to candidate clauses only. |
| SAFE-002 | **BEHAVIOR CONFIRMED — POLICY UNRESOLVED** | E3 CE-1 reset-derived14M prefix, before-read rejection and after-CMP variation; E1 routing. | C2 contradicted; authority, latency/commitment and physical mapping missing. No universal cancellation proof. |
| SAFE-003 | **BEHAVIOR CONFIRMED — POLICY UNRESOLVED** | E3 held/W patched+original60M, no-W60M and release/repress control. | C3 contradicted for a single completion/W cycle; W exemption and release qualification unresolved. |
| SAFE-004 | **SPECIFICATION INCOMPLETE** | E1 two-read predicate; E2 saved-LOW/current-HIGH rejection,230 fresh-HIGH returns; E3 before-read230 rejections. | Weak fresh-HIGH veto supported only in those finite scenarios; Q/age/duration absent, no sustained-time proof. |
| SAFE-005 | **SPECIFICATION INCOMPLETE** | E3 reset-to-first-initiation with LOW throughout; E6 startup dependence. | Initial-release candidate contradicted in modeled reset scenario; intended arming, RAM/retention and readiness unknown. |
| SAFE-006 | **SPECIFICATION INCOMPLETE** | E3 X1 positive stop0x5fa6 at12,587,757; X2 negative14M; E6 retained-history controls. | AnalogOK absent; histories/thresholds/calibration unquantified, original symbolic effects incomplete. |
| SAFE-007 | **SPECIFICATION INCOMPLETE** | E2 patched G/W1/B1 stop0x5fa6, E3 analog; E6 original868 route inventory and typed sinks. | Alternative routes confirmed, unauthorized status unknown; no exhaustive patched915 route certificate or natural group/jog/W0 lifecycle. |
| SAFE-008 | **INCONCLUSIVE** | E3 static TC0-linked service0x607c→0x5be8, idle writer0x5b1a; input updates around comparison. | No feasible IRQ race witness or completed permitted-interleaving proof. S and peripheral timing also unspecified. |
| SAFE-009 | **INCONCLUSIVE** | E1 decode/local frame and completed helper effects; E2 selected state/store preservation. | Integrated fragment all paths aborted; caller frame, rejection exit, stack headroom, writes, incoming CFG and interrupts unresolved. |
| SAFE-010 | **INCONCLUSIVE** | E2 finite paired controls,29,236 ordered tuples equal for intentional LOW; G/W1/B1 observed starts. | Fresh-input global ordering differs357 indices; polling differs; requirements/projection/timing incomplete, no full-state/liveness proof. |

Completeness accounting applying to the matrix:

- **Initial states/reachability:** E3 full-reset recipes reconstruct relevant
  states through firmware rather than transplanting arbitrary application RAM.
  That establishes scenario reachability under injected MMIO and command contracts,
  not every hardware boot/retention state. E6 Target2 arbitrary symbolic eligibility
  assignments are not universally boot-reachable.
- **Input bounds:** E3 nine finite runs (six exact replays, three variations);
  eight budget stops14M/60M, one requested X1 boundary. Both CEs are already
  executed prefixes before budget stop. No arbitrary pulse/history/count proof.
  E2 has14 fresh replay records plus two instrumentation controls;138 assertions
  include six historical records and are not20 fresh executions.
- **Symbolic scope:** no new query. E6 original868 fixed-pointer slices provide
  two SAT anchors and eight UNSAT exclusions; seven pre-read software exclusions
  and nonzero captured-R0 exclusion. Stable state, fixed r5/r6 and local targets
  are assumptions. They neither execute the patched915 helper nor establish
  whole-program reachability. E1 read helper completes22 steps, five reads,
  zero writes/calls; patch fragment fails all paths after51 steps with an opaque
  call and missing original frame. Its post-abort UNSAT is inadmissible. No new
  solver abort or unsupported-instruction result is invented for Gate 4.
- **CFG/branches:** E1 local routes decode independently, but rooted census
  retains199 incomplete/unresolved terminators (48 residual classification
  failures). Sparse watchpoints are not whole-CFG coverage; E2 recipes do not
  populate visited_pcs. Analog, direct and original868 group/catch-up observations
  do not close all patched915 producers or indirect/interior entries.
- **Observation coverage:** E2 selected CPU stores include configuration/live,
  TC0, output-command and serial ranges, not all RAM/stack or physical outputs.
  Direct G/W1/B1 controls lack ordered peripheral capture (B1 has zero selected
  writes, not zero actual writes). CE-2 has helper/live/state corroboration,
  not individually ordered first ENABLE stores. Direct input/tick injections
  bypass CPU-store hooks and remain environmental events.
- **Timing/interrupts:** no continuous physical TC/NVIC/STEP schedule. The library's
  deliver_interrupt is a nested handler call without complete EXC_RETURN,
  priority or masking behavior; no supported one-shot interleaving workflow closes
  this case. Instruction counts/fake tick/physical time differ. PORT INEN,
  synchronization/SAMPLING and clock state need independent validation.
- **Execution/instrumentation:** E3 reports error=null, zero dropped captured writes,
  no watch-cap stops for all nine final runs, memory-hook-single-step. Three
  earlier sourced-command host SIGILL initialization failures produced no firmware
  snapshots; successful direct invocations are retained. E2 watch-disabled controls
  support selected state noninterference only; MMIO hooks persist. No gate claims
  physical activation, global alias exclusion or absence of unobserved effects.

## F. Counterexample relationships and first violations

### CE-1 / historical G3-CE-01 → SAFE-002 candidate C2

Preconditions hold in the modeled trace: request acquires LOW at0x9228; the added
helper returns r0=0, then the rule sets current PB05 HIGH at0x1547c, instruction
12,098,793. No intervening new authorized episode is supplied. CMP uses the
captured LOW; POP.W preserves its flags. First observed C2-forbidden **Accept**
is0x8f98 at12,098,797. For the weaker Enable-only candidate, first logged violating
store is0x571c at12,327,115: TC0 CTRLA0x40003800 receives0x602, previous0x600.
Rate start0x5f8c is12,327,030; helper0x5810 is later at12,327,164.
The after-CMP control releases at0x1547e,12,098,794 and still initiates.
The before-read control releases at0x15478 and rejects through14M.

[Raw witness](../../research/generated/patch-gate3-2026-10-22/late-release-patched.json),
[recipe](../../research/generated/patch-gate3-2026-10-22/late-release-patched-command.txt)
and [observations](../../research/generated/patch-gate3-2026-10-22/observations.json)
retain event/store provenance. E3 reports byte-identical replay of E4's
`late-release-patched.json.gz`. The trace requires modeled GPIO changes, stubs,
MMIO completion and instruction-paced time; no physical synchronizer or source
edge is measured. It establishes firmware behavior and contradiction of C2 in
that environment, not an authoritative product violation or physical output.
**Disposition: BEHAVIOR CONFIRMED — POLICY UNRESOLVED.**

### CE-2 / historical G3-CE-02 → SAFE-003 candidate C3

PB05 is LOW from reset with no release rule. First Accept12,098,797 and
RateStart12,327,030 are followed by natural completion boundary0x6056 at52,125,562.
W is supplied there; idle2 is visible at handler0x865a,52,140,327. Return request
0x6fd8 occurs52,155,465; restoration boundary0x9088 at52,167,621 precedes idle9
at subsequent acquisition. First C3-forbidden second **Accept** is0x8f98 at
52,167,801, with no release/qualified new episode. Second RateStart52,400,236,
enable helper52,400,370 and live-store52,400,382 corroborate another initiation.
Do not assert a captured first ENABLE-containing store for each held/W start.

[Patched witness](../../research/generated/patch-gate3-2026-10-22/held-w-patched.json)
and [recipe](../../research/generated/patch-gate3-2026-10-22/held-w-patched-command.txt)
match the historical E4 snapshot; original control repeats too (second acceptance
52,167,777). Held/no-W completes but stays at one start through60M; release/repress
allows another start without proving any minimum released duration.
C3 preconditions hold **if** bare W restores eligibility without granting independent
authorization. That interpretation is proposed, not an established product fact.
W delivery is injected RX, position remains modeled/zero-distance return, and
physical return/RF exchange/output are unproved. This is retained behavior, not
a new patch-induced repetition. **Disposition: BEHAVIOR CONFIRMED — POLICY
UNRESOLVED.** If W is independent authorization, the same trace remains valid
but a different Auth classification is needed; preserve C3 and record the exemption
as a product decision rather than deleting the witness.

## G. Specification ambiguities and missing evidence

Product decisions needed before a mandatory policy can be evaluated:

1. Define each producer's authority: external input, bare W, W0, W1, G, B1,
   analog, manual/jog and callback/group routes. Does W independently authorize,
   only restore software eligibility, or require release? Resolve explicit exemptions.
2. Select commitment boundary and cancellation semantics: physical release,
   firmware HIGH observation, Accept, first ENABLE store or physical output.
   Define allowed detection latency and behavior after commitment.
3. Select rearming episode boundary: release after completion versus an earlier
   busy-period release; qualify inactive/active windows, freshness and valid short
   pulses without inventing timing values.
4. Define startup readiness/initial arming, active-at-reset intent, physical
   reference/driver validity providers and retained-state behavior.
5. Define analog safety limits, selector bands, filter/history lifecycle,
   hysteresis, calibration and startup baseline expectation.
6. Specify permitted output/state differences, global cross-peripheral ordering,
   progress assumptions and interrupt/environment schedules.

These are missing requirements or engineering evidence, not automatically
APTrace defects. The missing field-release hash, electrical waveform and
physical output correspondence cannot be supplied by a software verifier.

## H. APTrace capability assessment and execution

Gate 4 used repository/source/document inspection and standard identity hashing;
it **reused** APTrace-produced evidence through E1–E6. No property was evaluated
by a new native property operation. APTrace previously owned binary decoding,
concrete execution, symbolic helper/slice queries and raw verification records.
Codex assigned policy authority, defined documentation predicates, linked prefixes
to properties and assessed completeness. No manual firmware simulation or new
trace-checking algorithm replaces APTrace. No native planner was invoked; its
current action palette does not expose this catalog as a property-verification job.

Source inspection: repository `agent/src/aptrace_agent/research/controller.py`
`_ACTION_TOOLS` exposes structural/effects/scenario/evidence operations, not a
SAFE catalog or bounded temporal evaluator. `agent/src/aptrace_agent/ledger/policy.py`
`CLASS_POLICY` provides populated corroboration evidence kinds only for
CODE_EXISTENCE; control-flow, memory and other classes lack such contracts.
The [claim verification specs](../../../../docs/intent/claims/verification/verification-specs.md)
describe that boundary. Existing claims/audit machinery is not absent, but it
must not be advertised as temporal safety certification. No new SAFE claim IDs,
ledger verification records or admissions were created; this is a case report,
not an admitted VERIFIED proof. Existing records retain their prior status.

| Gap / priority | Observed evidence / impact | Likely cause (assessment) / needed capability |
|---|---|---|
| First-class policy/property definitions — **high, general** | SAFE catalog, authority and missing parameters must be documented manually; no exposed corresponding planner action. | Existing interfaces focus on lower-level questions. Need versioned property/event schemas, authority provenance and structured dispositions, cross-revision mappings and unresolved-parameter handling. |
| Trace-to-property evaluation / CE linkage — **high, general** | C2/C3 truth on existing prefixes requires Codex event-order reasoning; checkpoints/stores/forces are separate records. | Missing semantic trace adapter/evaluator. Need native bounded temporal predicates, event identity/observer coverage, first violating event and immutable witness/property links; no physical-time inference by default. |
| Reachability-constrained framed verification — **high, general** | E1 all-path abort, E6 original fixed slices and E3 concrete reset states do not compose into a patched-state proof. | Present fragment/callee/frame boundary. Need completed-path/non-vacuity checks, callable summaries, realistic initial-state constraints and original/derived exit relations. |
| Peripheral/IRQ and timing coverage — **high** | No complete NVIC/synchronizer/continuous timer model; input schedules instruction-paced. SAFE-008 unresolved. | Engine integration/contracts and missing case validation evidence. Need supported bounded schedule exploration with explicit unsupported behavior and independently validated peripheral contracts. |
| Producer/sink and property coverage — **high, general** | E6 incomplete/variant-qualified routes; E1 unresolved CFG; E2 sparse observer ranges/global differences. | Existing operations do not yield a whole-property coverage argument. Need typed routes, image identity, unexplored-edge obligations, event-aligned global comparison and state/write coverage. |
| Property evidence admission/reuse — **high, general** | Evidence reusable but SAFE dispositions not mechanically admitted; structural corroboration policy is insufficient for behavior. | Missing behavioral/temporal evidence contract, not missing ledger entirely. Need scope-aware admission, proof/test/assumption distinctions, model version and reuse invalidation across revisions. |

Highest general value: native property/event definitions plus bounded trace evaluation
and CE linkage, then scoped admission and reachability/framed proof support.
Physical contracts remain separate dependencies; an improved interface alone
would not resolve product policy or validate hardware.

No APTrace runtime failure or permission block was encountered in Gate 4. Two
inspection issues (an incorrect source path, and overly broad output truncation)
were corrected with actual source paths and focused reads; neither was a firmware
analysis outcome. No dependencies or tools were installed and no internet used.

## I. Gate 5 readiness and recommended next work

**Gate 5 NOT RUN.** Identity-bound witnesses and explicit event/policy distinctions
are ready as inputs; independent model confidence remains incomplete.

Priority validation targets for a separately authorized Gate 5:

1. **Peripheral-read semantics:** PORT GROUP1.IN read-only behavior versus actual
   INEN/CTRL.SAMPLING/clock/synchronization state, ADC sampling/filter contracts,
   and injected completion responses.
2. **Interrupt/scheduling:** allowed NVIC priorities/masks/pending/exception return,
   timer COUNT/CC behavior and reachable TC0-linked idle writer interleavings.
3. **Instruction count versus physical time:** fake tick cadence, sampling/cancellation
   latency, physical pulse widths and relation to execution timing; no count-based
   duration threshold may be assumed.
4. **Initialization/reachability:** hardware RAM/retention/peripheral reset versus
   modeled zeros, PA22/radio/stub contracts, real Remote/program/MC4/W delivery,
   nonzero return/position and application-ready predicates.
5. **Cross-peripheral order:** explain E2's357 global differences and unacquired
   polling traffic against required device ordering, not sorted stream equality.
6. **Instrumentation noninterference:** corrected hooked execution, sparse store
   coverage, direct injection visibility and independent event/state observations;
   distinguish host initialization failure from guest execution failure.

**Existing APTrace work, after policy selection:** reuse these witnesses as scoped
regression evidence; inspect specific ISR-writer prerequisites, selected retained
filter histories or natural command lifecycles where supported; request broader
public coverage capture only for a specific missing obligation. These operations
cannot by themselves certify missing hardware semantics or complete policy.

**APTrace development recommendations:** property/event definitions, native
trace evaluation/CE linkage, behavioral admission, framed reachable-state proofs,
validated bounded IRQ scenarios and route/observer coverage. None implemented.

**New evidence/product work:** approve policy parameters/W semantics, obtain
hash-linked field binaries and measured source/output/timing contracts. No
hardware work or deployment is authorized by this report.

## J. Cumulative verification state

| Item | State |
|---|---|
| Gate 1 — structural correctness | **INCONCLUSIVE**, unchanged |
| Gate 2 — differential behavior | **INCONCLUSIVE**, unchanged |
| Gate 3 — adversarial exploration | **FAIL within modeled scope**, unchanged |
| Gate 4 — safety properties | **INCONCLUSIVE** |
| Gate 5 — model validation | **NOT RUN** |
| Full safety policy | **NOT ESTABLISHED** |
| Hardware deployment | **NOT APPROVED** |
