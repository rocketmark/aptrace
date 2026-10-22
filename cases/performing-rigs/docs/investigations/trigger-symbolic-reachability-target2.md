# Target2 — bounded binary trigger reachability and exclusions

2026-10-22. **The recovered digital eligibility gate and captured-sample branch
now have feasible, instruction-level symbolic reachability/exclusion results.**
A positive SAT witness anchors seven state-guard UNSAT exclusions; a separate SAT
witness anchors exclusion of every nonzero captured R0 at the acceptance branch.
These support a bounded binary-to-model correspondence for digital acceptance,
not a whole-startup, analog-history or motion-initiation theorem.

The analog fixed-band decision remains supported by native instructions and
concrete witnesses/controls. No trustworthy symbolic quantification of arbitrary
filter histories is claimed. The accepted-trigger→profile initiation join remains
a continuous original-code witness with disclosed timer/environment assumptions.

[Packet](../../research/generated/trigger-symbolic-target2-2026-10-22/README.md),
[solver results](../../research/generated/trigger-symbolic-target2-2026-10-22/solver-results.json),
[complete symbolic log](../../research/generated/trigger-symbolic-target2-2026-10-22/crosscheck-868.log),
[22/22 new fragment controls](../../research/generated/trigger-symbolic-target2-2026-10-22/concrete-checks.json),
[continuous native correspondence](../../research/generated/trigger-symbolic-target2-2026-10-22/native-correspondence.json).

## Starting evidence and scope

[Target1](startup-voltage-learning.md) separates stored average/low flag from
shared filter history: retained history matters; crossing over the stored results
has no observed effect within its tested paths. [The descriptive model](noxon-trigger-state-machine.md)
and [formal package](../../specifications/noxon-trigger/README.md),
[failure-mode campaign](trigger-misfire-failure-modes.md),
[powered-input work](powered-trigger-connection.md), and
[X/acceptance](x-trigger-acceptance.md) provide known positive/negative witnesses.
Normal alpha is0.05; no permanent normal first-sample freeze is assumed. Profile
initiation is not restricted to the separate0x6fd8/G path.

This investigation uses existing public `aptrace trigger-crosscheck`, Ghidra
queries and direct Unicorn CLI. No new solver harness, handwritten firmware SMT
model, replacement controller, framework change or new analysis framework was
created. Source inspection audited the existing harness assumptions. No original
firmware/apfw2/hardware/proposed controller was modified; no ledger verification
or release-gate promotion is asserted. Target3's comprehensive sink/route audit
was not performed.

New symbolic analysis is AutoPilot868, SHA256
`6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3`.
Target1 established byte equality for868/915 in the relevant classifier region;
this pass does not claim a separate915 symbolic execution or whole-image theorem.

## Trustworthy scope: two call-free components

The existing `trigger-crosscheck` command explicitly reseeds Macaw at the
recovered gate rather than relying on incomplete whole-function0x8e18 discovery.
It executes actual lifted instructions, using Crucible/What4/Z3. This differs
from the earlier opaque-call `function-effects` run that became stuck in the
per-channel phase paths and produced unvalidated guard/refutation UNSAT pairs.

### Component A/B: pre-read state gate

Native instruction interval: **0x9202 through0x9224**, exit at block0x9226 before
`mov r0,#0x39; bl0xd3dc`. Macaw's Thumb seed is0x9203; initial program-location
labels can retain the low bit (`gate-smt-pcs.json`). Those are not additional
native instruction addresses. Ghidra disassembly and native fragment controls
cross-check the actual0x9202 entry.

Inputs fixed by the existing harness:

- r5=`0x20002524`, channel-state array; r6=`0x20003120`, TR flag pointer.
- Thumb image/load geometry and actual flash literal bytes. Other registers
  default to zero except IP/SP/pointer overrides; a4KiB allocated zeroed stack
  exists. This region reads only r5/r6, scratch r3, literal pointers and the named
  state cells. It has no calls, stores, loops or stack accesses on the queried
  positive path. Register/stack defaults do not stand in for hidden readiness.
- RAM is symbolic, **without a zero-RAM overlay**. Seven named little-endian
  values are read from the same symbolic memory the original load instructions
  access: four8-bit channel bytes,32-bit marker,8-bit idle,8-bit TR.
- No modeled interrupt/concurrent writer or peripheral execution occurs in this
  interval. Entry is already on the mode2/TR0 normal-poll path; entry from startup
  is an independently evidenced upstream condition, not proved by this fragment.

Let

`G = ch[0]=0 ∧ ch[1]=0 ∧ ch[2]=0 ∧ ch[3]=0 ∧ marker32=0x7b ∧ idle8=9 ∧ TR8=0`.

Query A asks SAT of the path condition at0x9226, with all seven cells free.
It is **SAT**, and returns exactly G. The returned assignment is replayed at
native0x9202 and reaches0x9226. Existing continuous reset/program/MC4/digital
witnesses independently establish these state cells and r5/r6 pointer bindings in
normal operation, not merely a guessed synthetic entry.

Each Query B repeats the same reachability question with **one** named guard
constrained to differ from its good value; the remaining six stay free. All seven
are **UNSAT**. The32-bit marker exclusion covers every other word, not just122;
each byte exclusion covers all255 wrong values. These exclude reaching **this
pre-read boundary through this fragment** under the stated assumptions. They do
not exclude another firmware entry/route, state changing later, or later
eligibility restoration. Native one-bad-cell controls all exit to0x9232, before
the epilogue; no invalid SP/LR execution is used to manufacture a negative.

These results establish necessity for the represented local reachability path.
The SAT model alone is not a universal sufficiency proof. Local sufficiency of G
also follows from the audited loop-free instruction chain: each guard passes to
the next, each failure branches to0x9232, and no other condition precedes0x9226.
The native all-good replay corroborates it. No opaque return or modeled driver
behavior contributes to this derivation.

### Component C: captured digital value

Native **0x922c cmp r0,#0;0x922e beq0x8f98** is checked as a single Macaw block.
All registers/memory are symbolic; R0 is not constrained to a boolean by this
query. The solver asks whether finalPC=0x8f98 and returns **SAT, R0=0**. The
companion asks the same predicate with **R0≠0**, and is **UNSAT**. The positive
query makes the companion exclusion nonvacuous.

Thus, for this branch, captured32-bit R0 equal0 is necessary and sufficient for
acceptance entry, conditional on execution already reaching0x922c. Current GPIO,
program marker, TR, elapsed sample age and previous input level are **not read**
in this block. New native controls confirm:

- captured0/current GPIO HIGH →0x8f98;
- captured1/current GPIO LOW →0x9232;
- captured256 →0x9232: the comparison is on the word, not its low byte.

The256 entry is a branch-semantics negative control, not a naturally produced
return from the fixed valid PB05 alias. Native helper0xd3dc..0xd406 reads the pin
metadata and GPIO register and masks the selected bit. There is no input-history
lookup, state-cell store or nested call in that helper. The fixed alias57 maps
to PB05 in existing pin evidence. Invalid-pin metadata has its own zero-return
branch; it is outside this fixed-image/valid-pin scope.

**No symbolic execution of digitalRead is claimed.** The components stop before
the call and start after it. The original continuous
`digital-acquired-transient` witness supplies the join: at0x922c, r5/r6 match the
symbolic pointer bindings, R0=0 while GPIO1.IN already has bit5 HIGH. It then
accepts and reaches the original profile timer initiation. The source-level
harness rejects unsupported calls rather than fabricating a return. Its
reachability result is collected before the call; continuing/aborting simulation
after that point does not extend the verified interval.

Under stable state cells during the read, normal helper completion and this
entry path, the composition is `G at pre-read checks ∧ capturedR0=0 → acceptance`.
This is not an instruction-level proof of the helper/environment or a theorem
that G still holds at acceptance time.

## Timing qualification: eligibility is checked before acquisition

The final state guard is0x9224; the actual GPIO read is inside the following
call, and only R0 is tested afterward. **G is a pre-read condition**, not a guard
rechecked at0x922e. A targeted injected0x922c entry with captured0, all channel
bytes1, marker122, idle0 and TR1 still reaches0x8f98. The same bad fields at
0x9202 prevent reaching the read.

This establishes the absence of a post-read recheck in the actual instructions.
It does **not** establish a natural race: no original interrupt/callback writer
of those fields during digitalRead was demonstrated. The helper itself does not
write them; normal command dispatch is not automatically concurrent with this
call. Do not label arbitrary RAM corruption or injected state a product misfire.

The distinction matters to binary-to-model correspondence. The descriptive TLA+
`ClassifyAndGate` action combines classification and eligibility atomically.
That matches the existing trace projections under their no-intervening-writer
assumption. It is not yet a refinement for asynchronous state mutation between
pre-read checks and the post-read branch. A future concurrency claim would need
an evidenced writer plus separate gate-passed/acquire/decide states; no speculative
transition was inserted into either model here.

## Analog classification and history: what is and is not proved

Native0x8f48..0x8f80 checks the same seven values on the analog path. Then
0x8f84..0x8f94 reads filtered32-bit value F via r4, upper/lower bands from
0x200000a8/0x200000c0 and performs signed comparisons:

`active = (F > upper) ∨ (F < lower)`.

Within this stable-state, correctly bound call-free suffix, native control flow
therefore selects acceptance exactly when G and this outside-band test hold.
This is an instruction-chain argument, not a new analog solver theorem.
Equal endpoints are inactive. X writers0x9178/0x9188 set upper/lower to580/200
or750/250. These are actual original instructions, not a learned average band.
Native fragment controls replay199/200/580/581 and866 for X1, and249/250/750/751
for X2. All nine agree. These fragments seed thresholds/filtered state at a
recovered boundary; they do not claim to execute X parsing, sampling, float math
or startup. They are **concrete/static evidence, not new analog SMT exclusions**.

The fixed-band consumer does not read current ADC.RESULT, prior GPIO or an edge
counter. Supported histories include:

| Original history / control | Classification/acceptance and initiation | Evidence status |
|---|---|---|
| Previous filter900, raw now225 under X1 | First subsequent returned866 active; accept; later timer start with filter455 | Continuous original Target1 witness; causal filter-only control removes acceptance/start. No universal symbolic history characterization. |
| Startup filter initialized0, raw later225 | Returned11,22,… remains below200 initially; accepts and starts | Continuous powered-connection low-side tail witness. |
| Single acquired900 among225 | Returned259 then257…; never leaves X1 band in the recorded run; no acceptance/start by14M | Continuous negative control; not a promise to recognize every physical pulse. |
| Constant225, X1→X2 | Unchanged value moves from inside band to below250; accepts and starts | Continuous original X2 witness plus native X writers/comparators. No fresh electrical event required. |
| Active900 already present while program/MC4 eligibility becomes true | First eligible active interpretation accepts and initiates | Continuous startup-active witness. Eligibility change does not need a fresh input transition. |
| TR1→TR0 with retained active history | Reporting can occur without acceptance; later existing filtered history is exposed | Existing tail fixture includes another MC4 packet, so it does not isolate TR0 alone. |

The first two demonstrate that inactive current raw input does not imply inactive
filtered classification. They do not establish every feasible analog history,
physical voltage mapping, acquisition deadline interleaving or float rounding
boundary. Non-due helper calls can return cached history; first-sample flag and
alpha initialization are separate from X and stored average. Target1's corrected
contract is preserved.

**Why no new analog symbolic proof?** The existing public gate command is fixed
to the digital pre-read cells and captured-R0 block. The reusable internal gate /
branch functions can express other slices, but no public operator command accepts
the analog entry, r4/r5/r6 bindings, target and symbolic filtered/band values.
`function-effects` does not expose those pointer overrides and uses unrepaired,
whole-region discovery with opaque calls/step limits. Its previous partial result
cannot become an exclusion proof by relabeling it. We did not write a new harness,
hand-encode ARM comparison/filter semantics in SMT, or invoke internal libraries
as an alternate analysis interface.

## Solver feasibility, reproducibility and exclusions

Ten queries complete: **two SAT and eight UNSAT**. Every accepted exclusion has
a positive SAT control in the same fragment. The seven-cell model and captured0
model agree with native replay. The first gate's symbolic bytes are the exact
memory expressions read by original loads, not disconnected parallel variables.
Actual readonly image bytes are constrained; RAM is not silently zeroed.

The eight gate query dumps each have standalone and interaction SMT-LIB files,
preserved losslessly as16 gzip archives with decompressed SHA256. The standalone
positive query was independently replayed through installed Z3 with a30-second
limit and returned SAT; the TR-violation query returned UNSAT. This rechecks the
exported formulas, not a different proof engine. Component C has no exposed dump
option in this command; exact source/binary hashes and command/log reproduce it.

For each B query, the proposition is

`SAT(base_memory_and_instruction_assumptions ∧ reached0x9226 ∧ chosen_guard≠good)`.

UNSAT excludes assignments satisfying that conjunction. Query A proves its
positive reachability assumptions are satisfiable. The native negative entries
also show the chosen bad cell can be instantiated without an invalid memory
setup; their failure to reach is the intended gate behavior. No general claim
that all asynchronous real-world entries are feasible or represented follows.

For C, the excluded proposition is

`SAT(single_block_assumptions ∧ finalPC=0x8f98 ∧ capturedR0≠0)`.

It says nothing about physical source intent or future GPIO changes. These
queries do not include the earlier whole-function effects assumptions, opaque
AAPCS calls, profile evaluator or unknown loop invariants. There are no symbolic
memory-address aliases in the queried gate other than the fixed image literals
and fixed r5/r6 bindings; general program aliases are not thereby proved absent.

Full CFG recovery remains incomplete elsewhere. This proof boundary is the
small call-free, loop-free gate/branch, cross-checked against all native branch
sites and controls. Source comments refer to older investigation filenames no
longer present as separate reports; present native artifacts and source, rather
than those missing documents, are the evidence. No whole-function completeness
claim is inferred from command exit0.

## Binary-to-model correspondence and property matrix

| Property/transition | New support / remaining boundary |
|---|---|
| Digital seven-state eligibility gate | **Symbolically strengthened:** SAT witness plus seven quantified cell exclusions over actual lifted instructions. Local sufficiency from complete native instruction chain, not SAT alone. Setup completion/mode selection are upstream assumptions. |
| Captured LOW→acceptance | **Symbolically strengthened:** R0=0 SAT; all nonzero32-bit R0 excluded in the post-read branch. Current GPIO is not an operand. Native continuous witness joins acquisition and later initiation. |
| Fresh electrical transition required | **Contradicted as a universal requirement:** native held-active/startup and X witnesses accept without one. The recovered digital components consult state/sample, not previous input. No claim about every possible trigger route. |
| Analog inactive-band classification | **Instruction/static + concrete support:** signed outside-band test, inclusive inactive endpoints, nine new controls. No new analog-history SMT theorem. |
| X/current eligibility exposes old active value | **Continuous native support**, consistent with model; no symbolic startup/program producer reconstruction. |
| Pre-read gates remain current at acceptance | **Not established; missing atomicity qualification.** Instructions do not recheck; injected post-read bad state still accepts. Natural concurrent mutation remains unknown. |
| Accepted reload→prepared profile→timer initiation | **Existing continuous native support only:** original0x6e4c→0x6b50→0x6338→0x5f8c→0x5810/live1. Profile timing/float evaluator remains a native oracle in TLA+. No symbolic progress/sufficiency theorem. |
| Valid marker guarantees motion eligibility | **Not established.** Marker is a shared gate; individual record validity, usable profile and later scheduling are separate. G does not prove trigger authorization. |
| Duplicate-after-completion, STOP/reset/re-arm | **Unknown**, not exercised symbolically here. The held22M window has one start but no recovered natural completion. |

The strongest new relation is between bounded digital binary entry/exit state and
the descriptive model's shared-guard/captured-input decision, conditional on
stable state during the read. It is not a general binary refinement. No proposed
replacement model was changed; no formal result about physical reference/driver
health was manufactured from these seven software fields.

## Execution, capability gaps and next work

All22 final new fragment executions completed exit0 and matched their exact stop
boundaries (100-instruction budget each; reported counts3..33). They do not initialize the full application or authorize hardware
operation. Three initial post-read commands could not seed GPIO outside the
default MMIO mapping; the corrected existing `--mmio-size0x4000000` option fixed
the fixture before execution. Those initial failures/commands are retained.
The symbolic command exited0; solver statuses and scope, not exit alone, justify
the conclusions. Ghidra native queries and existing continuous witnesses provide
independent comparison. No new full-reset run was necessary to validate the
already-preserved join;10 selected native witnesses are hash-bound in the packet.

**Capability gap, medium/high for extending the proof:** a public parameterized
analog slice workflow is missing despite internal gate/branch support. Needed
inputs are the actual analog entry/stop, r4/r5/r6 pointer bindings, symbolic
filtered/band/eligibility cells and a feasible positive companion for each
exclusion. A finite float/filter-history query also needs actual supported
acquisition/clock semantics and validated lifting. This is subsequent APTrace
capability work, not an independent operator SMT rewrite. Existing whole-function
effects output is insufficient for that purpose.

**Existing-tools follow-up if concurrency becomes consequential:** identify a
specific original interrupt/callback writer of the seven fields, then a bounded
state-preserving original execution through digitalRead. Do not infer a natural
race from the synthetic post-read fragment. For motion, the next useful work is
Target3's requested route/sink audit, keeping accepted reload, prepared profile,
rate start, timer enable and physical movement distinct.

**Ready for Target3: yes**, with the bounded digital strengthening and analog /
progress limits explicit. No prior demonstrated natural trigger conclusion is
overturned. The material qualification is temporal: G holds at pre-read checks;
the descriptive model's atomic guard/decision abstraction is conditional, not an
asynchronous authorization invariant. Physical misfire causes and implementation
refinement remain outside this proof.
