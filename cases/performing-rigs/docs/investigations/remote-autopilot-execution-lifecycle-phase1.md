# Remote / AutoPilot execution lifecycle — Phase 1

2026-10-22. **Partial reconstruction.** AutoPilot becomes eligible for another
external-trigger acceptance when its channel-state bytes are all zero, the
program marker is `0x7b`, idle byte is **9**, and TR is zero. A currently active
sample then suffices; this gate has no fresh-release/activation requirement.
Ordinary time-based profile completion in the existing continuous original-image
witnesses leaves **idle 2**, not 9. Bare `W|`, processed through the return/phase
state machine, can restore 9 and permit held-input acceptance again.

**The original Remote really has W producers, including a RUNNING-screen exit;
an automatic completion → Remote W → second-start lifecycle is not established.**
The newly recovered exit condition is a button result OR an inbound-X-derived
flag. No supported continuous trace yet connects natural completion to that X
event. A button-mediated sequence is statically supported, but its coupled
Remote/UI/transport execution has not been demonstrated. This is neither a
universal exclusion of automatic retriggering nor a completed field-failure
explanation.

No firmware, apfw2, formal model, hardware, patch artifact or Gate 1–4 verdict was
changed. These are descriptive original-firmware findings, not replacement safety
requirements. New results have no admitted/VERIFIED claim or ledger promotion.

## Evidence and confidence

New evidence is in the [Phase 1 packet](../../research/generated/remote-autopilot-lifecycle-2026-10-22/README.md).
Its commands, native snapshots, Ghidra outputs and hashes distinguish fresh
execution from reused historical evidence. Addresses below are original915
unless a row explicitly says868. All instruction counts are execution counts,
not physical times.

| Evidence | What it supports |
|---|---|
| Fresh original Remote915 Ghidra listings, references and decompilation | W strings/callers, RUNNING-screen guard, X flag producer and status parser. Listings anchor consequential branches; decompiler text assists interpretation and is not an independent proof. |
| Nine fresh public Unicorn CLI runs | Six W send requests with transport/timing/button callees stubbed; three wait-screen guard controls; bounded X flag setting; phase-1 stop-request entry; two seeded outbound-status controls. These are fragments, not a natural paired lifecycle. |
| Two fresh original full-reset continuations | Original915 digital and original868 analog release/repress, using established program/MC4/completion-time W recipes. Both reach two live-store entries through60M, with no guest errors or dropped watched writes. W and input changes remain supplied. |
| [VVR correlation](vvr-trigger-failure-correlation.md), [raw packet](../../research/generated/vvr-trigger-correlation-2026-10-22/README.md) | Original868 continuous reset/program/MC4/profile completion; held/no-W, held/W and released/W controls. Reused, not rerun in Phase 1. |
| [Gate 3](trigger-patch-gate3.md), [raw packet](../../research/generated/patch-gate3-2026-10-22/README.md) | Original915 held/completion/W second initiation; patched release/repress control and no-W control remain separately identified. Reused; patch behavior is not silently substituted for an original control. |
| [Motor/reference ownership](motor-state-ownership-and-reference.md), [bring-up 1](autopilot-bring-up-pass1.md), [bring-up 2](autopilot-bring-up-pass2.md) | Startup, program transfer, reference reconstruction, MC4 and independent G semantics. |
| [Trigger failure mechanisms](trigger-misfire-failure-modes.md), [descriptive model report](noxon-trigger-state-machine.md), [Target2](trigger-symbolic-reachability-target2.md), [Target3](motion-initiation-route-coverage.md) | Level acceptance, analog history, bounded SMT gate exclusions and independent initiation routes. Earlier incomplete completion statements are superseded by the VVR/Gate3 continuations. |
| [Motor-output evidence](vvr-trigger-motor-output.md), [handoff](noxon-trigger-engineering-handoff.md) | Initiation versus physical movement, first ENABLE store, and preserved patch/Gate scope. |

## Actual state representation and ownership

This is a consequential-field inventory, **not an exhaustive alias-aware list of
all writers**. A byte called “idle” is an analyst name; values 0/1/2/9 are not a
single enumerated ARMED/RUNNING/COMPLETED variable. Native-width accesses matter:
the program marker has word comparisons, whereas idle and channel states use
byte comparisons.

| State / location | Initialization, reads and writes | Authority / meaning and limit |
|---|---|---|
| Setup `0x20000060` | Startup setup1; MC4 dispatch clears0 at `0x8718`; setup polling `0x94b8`, runtime entry `0x93fc`. | AutoPilot session/setup gate. MC4 is desired motor configuration, not proof programs arrived or hardware is ready. |
| Program marker `0x20001b38` | Loaded from local stored payload; bulk-plus finalization `0x81ca` yields7b; trigger checks `0x8f68`, `0x9214` region. | AutoPilot's local execution-copy marker. Remote authors programs; there is no demonstrated global version/reconciliation authority. |
| Channel records `0x20001b40 + ch*0x120` | Transfer/loader/chain/resync mutate records; reload `0x6e4c→0x4b64→0x6b50` prepares profiles. Delta+0, endpoint+0x0c, reference/start+0x10, helper index+0x3c, validity+0x44; subrecord stride0x48. | AutoPilot-resolved program/reference state, based on Remote data and software current. Truthy validity is not physical reference or integrity certification. |
| Idle `0x200000d8` | Startup/configured witness9; preparation `0x6b50` clears0; completion store `0x6044` writes1 conditionally; phase `0x9104` writes2; return completion `0x9088` writes9. Read by W at `0x8630/34/3a`, trigger at `0x8f74/0x921c`. ISR-linked writer `0x5b1a` also exists. | AutoPilot authoritative gate. The ISR writer's feasible scheduling and all alternate paths remain unresolved. |
| Channel states `0x20002524[4]` | Reset/configured0; valid reload/profile preparation sets1; external trigger requires all0. Also read by W1 and other request routes. | AutoPilot execution mode/state, separate from hardware timer live flags. Other values occur in jog/manual paths; no complete enum recovered here. |
| Live `0x20001b14[4]` | Startup0; start store `0x5fa4`; stop `0x5958`; read by phase service `0x8e18`. | AutoPilot software activity, not independently measured movement. |
| Completion flags `0x20002014[4]` | Written1 by terminal profile path `0x5fac`; consumed alongside valid records and record+0x39 in phase service. | AutoPilot completion bookkeeping; no electrical release significance. |
| Phase bytes `0x20002318[4]` | Preparation clears; bare W sets1 for valid channels whose phase is0 (`0x865a`); phase service handles1→2→3. | AutoPilot return/stop sequencing. They are not required for the initial trigger-driven profile start. |
| Record continuation byte +0x39 | Phase completion reads it; phase2 request clears selected byte at `0x900c`; value1 with mode<98 can take next-record path `0x4ae4→0x6e68`. | Program continuation versus finished-session branching. Multi-record lifecycle not dynamically closed by this pass. |
| Profile stage `0x200025e2[ch]`, duration table `0x200025e8 + ch*200`, timestamp `0x200030cc[ch]` | Prepared by `0x6b50`; elapsed-time stage service `0x5fac` compares original microsecond-clock result `0xccdc`, advances stage and rebases timestamp. | AutoPilot timed profile; not an independently progressing timer/STEP model. |
| Position `0x20002064[4]`, targets `0x2000201c[4]`, resync `0x20000134[4]` | Software position starts0; STEP service updates it. Resync/chain reconstruct references; phase requests subtract current from selected reference/endpoint. | AutoPilot software coordinates. No homing/encoder/physical-zero evidence follows. Existing completion/W returns have distance0. |
| G phase/arm `0x200025e0/e1` | Nonduplicate G arms at `0x83e0`, phase initialized at `0x83e6`; target service `0x7e2c`. | Separate manual/program request route; shared packet-sequence freshness is not electrical freshness. |
| Mode `0x20001fc0`, TR `0x20003120`, X `0x20000194` | Startup PA02 chooses analog1/digital2. TR command changes reporting/inhibit. X1/X2 change bands through actual parser. | AutoPilot classifies PB05/ADC inputs. Remote requests configuration; receipt/local state determine behavior. |
| Analog alpha `0x20000014`, initialized `0x20003118`, float `0x2000311c`, deadline `0x20003124`, integer sample `0x20000190`, bands `0x200000a8/c0` | Full reset alpha0.05. `0x42a4` updates on due acquisitions, caches otherwise; X1 inclusive inactive[200,580], X2[250,750]. | Retained filter state can differ from current raw input. No release-qualified latch identified in the trigger gate. W/completion do not establish a filter reset contract. |
| Outbound queue `0x200025bc[]` | Acceptance `0x8f9c` sets index1 to3. Dispatcher `0x9268` decrements pending count when due; index0 sends X, indices1/4 send @. | AutoPilot owns pending messages. Full writer coverage for index0 is unresolved. |
| Remote RUNNING exit word `0x20000ff4` | Screen tests at `0xd03a`; consumes/clears at `0xd070`. Inbound X path writes at `0x10e3e/56`. | Remote owns local UI exit request, not AutoPilot trigger qualification. Zero-valued encoder accumulator still makes X set exit1. |
| Remote encoder accumulator `0x200017f0`; local screen word `0x20001818` | X parser reads signed accumulator and can clear it. RUNNING loop clears the latter word at `0xd034` each iteration. | Separate local state; do not confuse these two words or infer a naturally generated X from an accumulator value. |
| Remote page `0x200018e7` and communication/session flags | `@` parser sets page9 unless page12, then calls RUNNING screen; `0xfd7c` routes several pages into it after other events/reconnection. | Remote UI/session authority. Page numbers are recovered selectors, not product safety states. |

868 cross-check: Remote W callers and exit-word references match the same screen
and helper addresses. The receive parser is `0x10ce4` in868, `0x10cf4` in915;
X stores correspondingly shift by0x10. Delay/digitalRead helpers also shift
(`0x168c0/0x171f0` versus `0x168d0/0x17200`). Original868 and915 lifecycle
witnesses support common AutoPilot behavior at the cited points. This is not a
complete byte/semantic equivalence certificate for both paired systems.
The packet's `variant-region-comparison.json` additionally records byte-identical
AutoPilot868/915 ranges `[0x85a0,0x8670)`, `[0x8e18,0x9238)` and
`[0x5fac,0x6058)` for W dispatch, phase/trigger service and timed completion.
This local identity does not validate upstream environment or indirect callees.

## Transition map

Evidence labels: **N** = original continuous AutoPilot instructions under the
historical disclosed environment; **I** = explicitly injected command/input;
**F** = seeded/stubbed bounded original-instruction fragment; **S** = static;
**U** = unresolved. N does not mean physical execution or a paired Remote run.

| Starting conditions | Event and exact consequential guard | Changes / motion eligibility | Evidence |
|---|---|---|---|
| Startup/setup1, local/default program | Original boot; Remote configuration/transfer inputs at supported RX boundary | Mode/filter/runtime initialized; software position0. Program/reference and MC4 are distinct milestones. | N+I, bring-up reports |
| Setup wait | Remote-built `+…|`, then MC4 | Native parsing/chain/store creates valid selected record and marker7b; MC4 clears setup. With idle9/channels0/TR0, trigger polling can accept. | N+I |
| Eligible idle9 | Digital saved return0 from `digitalRead(57)`; analog effective value outside inclusive inactive band; all four channel-state bytes0, marker7b, TR0 | Acceptance `0x8f98`, pending @ count3; reload clears idle0 and phase arms, prepares valid profiles/state1. No previous-input comparison in gate. | N, prior SMT/local exclusions, fresh listing |
| Prepared profile/state1 | Evaluator `0x6338` reaches due start | `0x5f8c→0x5570`; first ENABLE-containing store `0x571c`, helper `0x5810`, live1 `0x5fa4`. | N; not STEP/movement proof |
| Live profile with nonzero current duration | `elapsed >= duration` in `0x5fac` | Advance stage; next nonzero stage rebases timestamp. | N |
| Terminal next duration0, live-state1 | End-of-profile branch `0x6026` | Conditional idle1, completion[ch]=1, timer stop `0x5958`, live0. Main phase completion with valid record+0x39==0 and all live0 calls `0x693c`, then idle2 at `0x9104`. | N; no rearm yet |
| Completion flag + valid record, continuation byte1 | Mode<98 takes continuation branch | `0x4ae4→0x6e68`; continuation program behavior differs from the finished-record case. Mode>=98 takes finished branch. | S; multi-record execution U |
| Idle0/1/2, valid record+0x44!=0, phase0 | Bare W (second byte neither0 nor1) | Clears command-sequence state; sets phase1 at `0x865a`. Does not directly write idle9 or perform trigger qualification. | N+I; fresh listing |
| Phase1, valid record | Live[ch]!=0 | Request stop/deceleration `0x5274(ch,4)`; then phase2 on return. If not live, advances to2 without stop call. | F+S; physical STOP U |
| Phase2, live[ch]==0, auxiliary activity `0x2000309d[ch]==0` | Scheduler services phase | Request `0x6fd8(ch,0x32,target-current,rate)`, set phase3, clear selected record+0x39. Mode20 has a four-channel alternate-target loop; otherwise record+0x40 chooses start or selected endpoint. | N+I for zero-distance fixture; S for alternatives |
| Phase3 | All four live bytes0 AND every selected duration-table entry0 | Write idle9 `0x9088`; call `0x693c`. Active input may now be accepted without a release. | N+I, zero-distance return |
| Idle outside0/1/2 | Bare W | Tail `0x541c`: for channel-state2 and live!=0 request `0x5274(ch,4)`. Not the phase1 initialization route above. | S |
| Remote receives @, page!=12 | Status parser `0x10cf4` | Drain RX; page9; enter `0xcfc8`, send J three times on entry and display RUNNING. | S; physical delivery U |
| Remote RUNNING loop | Exit word!=0 OR `digitalRead(45)!=0` | Clear exit word; call `0x591c(0)`; six W send requests. If both0, remain in timed screen loop. | F+S |
| Remote receives X | `0x10e22` recognizes X, drains RX | Signed accumulator>0→exit+1; <0→−1; ==0→+1. Thus X itself can cause screen exit. | F+S; natural X producer U |

`0x693c` requests writes to two GPIOs; it is **not** the radio completion-status
sender. `L` dispatch reaches limit bookkeeping `0x54e0`; this must not be renamed
STOP merely because of its command letter. J toggles ancillary state/outputs;
its presence before W does not by itself establish a motion stop.

## Remote W producers and command/event sequences

The flash literal at `0x1c598` is `W|\0`. `0x591c` selects it for argument0;
nonzero selects `G|` at `0x1c5a3`. The loop counter is6, delay argument0x23
between requests. New `remote-w-six-arguments.json` captures six pre-call
`0x5930` hits with r0=`0x1c598` and the literal bytes. Transport `0x58a8` is
stubbed: this proves six sender requests, not six RF transmissions/receipts.
Static transport code `0x58a8` waits for its pacing condition and invokes the
radio/string path. Actual delivery, retries and dropped duplicates are unproved.

The resolved direct callers of `0x591c` in both Remote variants are:

| Call site | Conditions and meaning recovered | What remains open |
|---|---|---|
| `0xd074`, RUNNING routine `0xcfc8` | Unconditional W0 call after its loop exits on the local exit word or button. Screen is entered from Auto UI `0xe670` (`0xf620/0xf69e/0xf6ee`), page router `0xfd7c` (`0xfdd2`), or @ handler (`0x10dd8` in915). | Exact user gesture/page/session histories at all entries; paired completion-driven exit. |
| `0xe004`, Set-Limits/live-jog routine `0xde3c` | After the live-jog loop ends on button input, render next screen then W0 call before the following query/wait. | Complete UI/transport execution and target behavior under actual position. |
| `0xe104`, same routine | Conditional second adjustment path ends its jog loop on button input, then W0 call. | Same; not evidence of an unconditional periodic W sender. |

The direct-caller/literal-reference search is complete **relative to the current
Ghidra export**, not all indirect calls, hidden literals or unattributed tails.
Program loading does not intrinsically mean “send W”: it can lead into UI
routines that later call the screen. `0xfd7c` routes pages9/10 and other listed
selectors to RUNNING, so reconnection/menu state can matter. INFO/page12 is
explicitly excluded from the @→RUNNING branch. A complete INFO-exit causal
sequence has not been executed here.

The examined RUNNING entry does **not** clear `0x20000ff4` before testing it;
the clear is on exit. Consequently a previously pending X-derived exit request
can also satisfy the guard on entry. That is a statically supported stale-UI
state dependency, not proof it is naturally pending after motion completion.
Resolving only a hypothetical new completion-time X would therefore be too
narrow: the incoming screen state and earlier X/button history also matter.

Supported interaction segments, with the missing joins visible:

```text
Remote builder -> +program -> AutoPilot native program acceptance
Remote configuration -> MC4 -> setup exits
active trigger -> acceptance -> outbound queue[1]=3 -> profile starts
AutoPilot dispatcher queue[1] or [4] -> @ -> Remote RUNNING screen
    [packet delivery/UI progression not continuously executed]
Remote RUNNING entry -> J| x3
    wait until button result !=0 OR exit word !=0
inbound X -> exit word +/-1 -> screen exit -> W| x6
    [natural source/time of X relative to completion unresolved]
W received in idle0/1/2 -> phase1 -> stop request if live -> phase2
live/aux clear -> return request -> phase3
all live and selected durations zero -> idle9
held active trigger -> second acceptance -> second timer initiation
```

Natural profile completion independently reaches idle2. It does not, on the
examined path, set the Remote's exit word. The AutoPilot status dispatcher
`0x9268` emits X for queue index0, @ for indices1/4, gated by pending count
and at least51 clock ticks since its previous dispatch. Fresh seeded dispatcher
controls reach `0x7f84` with r0=0x58 and0x40 respectively. **They do not establish
which natural event queues index0.** No completion→X assertion follows from
these controls. Likewise, repeated @ requests after acceptance can re-enter UI
code, but do not alone satisfy the recovered screen-exit guard.

## Completion versus STOP and retained trigger history

Completion is timed-program bookkeeping followed by a stop helper and idle2.
W can be a UI-originated interruption/return request while busy, or a
post-completion reeligibility request. These different arrival times matter.
Its phase1 calls stop/deceleration helper `0x5274(ch,4)` when live; this helper
sets per-channel stop state and uses motor/profile state. Phase2 waits for
activity to clear before the return request. Natural profile completion calls
`0x5958` directly. Equating these two mechanisms would discard real control
flow.

The fresh phase1 fragment reaches `0x5274` in24 instructions with r0=0/r1=4.
It seeds phase1/valid/live and stops **before** the helper executes. It proves
neither completion of deceleration nor cancellation of every pending producer,
timer/NVIC quiescence, final position, physical stopping or a full STOP UI path.
No phase/idle state was forced in the reused full-reset completion witnesses.

| State/history | Completion evidence | STOP/W evidence |
|---|---|---|
| Trigger acceptance | Acceptance prepares profile/clears idle; no durable edge-consumed state in recovered gate. | W phase sequencing does not itself qualify release; W1 is a separate reload producer. |
| Last digital input | Gate uses returned r0 for that poll, without comparing a previous electrical level. | No post-STOP inactive qualification established. |
| Analog history | Filter can keep updating during runtime; no demonstrated completion filter reset. | No complete stop/reset/filter-history trace. Do not assert universal preservation or clearing. |
| Program/progress | Selected durations/stage reach terminal0; completion flags and idle1→2 observed. | Stop request and return phases are separate; complete multi-record interruption remains unknown. |
| Motion readiness | Live0/ENABLE clear in completion witness; software position remains0. | Neither stop helper invocation nor idle9 confirms driver health/reference. |
| Pending requests | No automatic second acceptance with no W within historical bound. | G, W1, B1, jog/catch-up and pending interrupts remain distinct producers; no global cancellation certificate. |
| Rearming | Completion alone leaves2. | Bare W can progress to9; fresh electrical activation is not required by the normal level gate afterward. |

## Three input histories and repeated-initiation reassessment

| Controlled history | Existing original-firmware evidence | Defensible conclusion |
|---|---|---|
| Held active through completion, no W | Original868 `held-completion`: stages at22,246,440 /42,249,832 /52,249,040; stop and channel clear by52,249,088; one start through65M, idle2. | Held input alone did not repeat in this program/environment/bound. Not an all-program or all-event exclusion. |
| Held active, supplied completion-time W | Original868 `held-completion-w`: idle9 at52,291,959; second acceptance52,292,297; second live52,524,554. Original915 Gate3 `held-w-original` corroborates a digital second initiation. | Input need not release once the command/phase path restores eligibility. W is supplied; no natural Remote sequence is proved by this experiment. |
| Released before completion/rearm, same W | Original868 `released-completion-w`: release to225 at first acceptance; rearm idle9 at52,289,719; one start through60M. | Reeligibility is distinct from active classification. Same supplied W does not restart inactive input. |
| Released then activated again | Fresh original915 `original-release-repress-w`: HIGH supplied at first acceptance12,098,773; held HIGH through completion52,125,562; LOW at idle9 restoration52,167,621; second acceptance52,167,777 and live52,400,358. | Two initiations with release/repress and supplied W, through60M. The PC-scheduled HIGH write repeats at each acceptance, so the second accepted LOW is also followed by HIGH. This is a sampled-event control, not a sustained-pulse guarantee. |
| Released then activated again, matched analog fixture | Fresh original868 `original868-release-repress-w` changes only output path and adds ADC900 at `0x9088` to the original released/W recipe. Completion52,246,833 and first idle9 boundary52,289,719 match the released control. Effective sample225→259→…→587; second acceptance52,428,031; live52,660,283. | This completes the three-history original868 comparison with reused held/W and released/W controls. Native filter history and reeligibility both affect acceptance. Every acceptance supplies raw225 again, so second live occurs with effective355 and released raw input, not a sustained900 input. |

The first three original868 rows already separate input history from command
and idle-state effects. They are inherited reproducible evidence, not fresh
Phase1 executions. The new analog reactivation is supplied whenever `0x9088`
executes: fifteen same-value ADC900 writes occur before the second acceptance,
not fifteen electrical activation edges. The phase3 byte remains3 and the
service repeatedly writes idle9 while the sample rises. Trigger reload then
changes that state. The first idle9 write is consequently an eligibility
boundary, not necessarily a one-shot “rearm event.”
All completion/W returns use zero software distance; a
nonzero physical out-and-back sequence remains unresolved. The result supports
a conditional mechanism for VVR-004's UI-dependent repeated moves, not its
actual M3 command sequence or physical cause. VVR quiet-watch flickers with no
motion remain negative observations.

## Comparison with unchanged descriptive TLA+ package

[`NoxonTrigger.tla`](../../specifications/noxon-trigger/NoxonTrigger.tla) correctly
separates sampled/effective activity, marker/channels/idle/TR eligibility,
reload/profile preparation and timer/live initiation. Its `Eligible` requires
setup-complete, marker123, channels0, idle9, TR0. Freshness/episode variables are
property monitors, not discovered Noxon RAM flags.

The checked `Apply` relation has no completion, W, Remote RUNNING/X exit, STOP,
return phase or rearm event. `OTHER -> s` cannot stand in for those transitions.
`OneStartInObservedWindow` and finite single-episode checks therefore do not
exclude the longer completion/W counterexample. This is a **scope omission**,
not a discovered mismatch in the modeled initial gate. `DirectG.tla` covers an
independent producer, not the missing return lifecycle. Neither package proves
physical stopping, reference validity or timer/NVIC behavior.

Future descriptive work would need actual phase/live/duration/continuation
conditions, outbound queue events and separate Remote/UI state. A proposed
release-before-rearm policy belongs to the replacement model or later patch
requirements; it cannot be inserted into a description of Noxon's permissive
gate. No model was edited or checker rerun in this phase.

## Candidate future intervention boundaries

These are candidate boundaries, not a validated patch design or RAM allocation.

1. **Acquisition → acceptance:** digital `0x9228–0x922e`, analog classification
   suffix and shared acceptance `0x8f98`. A stateful grant must cover both
   acquisition modes and must not mistake filtered/cached returns for new raw
   observations. The existing freshness patch covers a smaller digital window.
2. **Acceptance → program execution:** shared reload `0x6e4c`, preparation
   `0x6b50`, evaluator `0x6338`, rate start `0x5f8c`. Distinguish trigger-derived
   authorization from independent W1/G/B1/manual routes before choosing a common
   hook; otherwise a guard may suppress intentional non-trigger operations.
3. **Completion → eligibility:** terminal `0x6026–0x6056`, idle2 store `0x9104`,
   phase3 idle9 store `0x9088`. Preserve consumption/release requirements across
   these transitions if that is the chosen policy; completion must not silently
   mint a new electrical event.
4. **STOP/W → subsequent eligibility:** W arm `0x865a`, phase1 stop request,
   phase2 return and phase3 restoration. A patch only at the initial sample gate
   cannot define cancellation/quiescence or control independent producers.
5. **Session/configuration barriers:** program transfer/selection, MC4/setup,
   X/TR changes and reset/reconnect require explicit qualification-history policy.
   Evidence shows these affect classification/eligibility; it does not validate
   a universal reset list or prove atomicity with ISR `0x5b1a`.

## Execution, capability gaps and exact next evidence

APTrace public Ghidra and Unicorn interfaces produced the new evidence. Existing
Crucible/What4/SMT gate results are reused only for their bounded claims; no new
solver or Macaw run was needed for the concrete guard questions. No independent
firmware interpreter, semantic script, new harness, test or framework change was
introduced. Packet generation only records commands, hashes and snapshot fields.

Invocation failures were operational: initial Ghidra without the documented
JAVA_HOME/temp user-home failed before querying; the established environment
worked. System Python lacked Unicorn; the existing venv worked. A guessed
`0x8cc0` function query returned no function; actual exported senders were then
queried. `0x541c` is an unattributed tail, recovered using public disassembly.
An attempted flash dump at RAM0x100 was rejected and provided no evidence.
One wildcard file search had no matching files. The first W run watched a
stubbed callee and recorded no watch hits; a separate run watched the real caller
instruction and captured all six arguments. All eleven final native runs exit0
without guest error. The two continuous runs reach the60M budget, have no dropped
watched writes and each reach live-store twice; fragment `completed` is not
product READY/completion.

| Gap / impact | Observed evidence and likely cause | Needed capability / priority |
|---|---|---|
| Natural coupled completion→Remote W remains unproved | Independent fragments and injected packets do not execute both peers/UI/radio together. No reconstructed completion→queue0(X) writer/path. Cause includes missing firmware control-flow closure and missing coupled scenario, not proven absence of a natural path. | Existing APTrace: resolve queue0 writers/aliases and feasibility, then run a supported peer scenario if its prerequisites fit. A new general coupled event/transport workflow would be separate development. **High.** |
| Whole-program writer/caller coverage incomplete | Literal/caller export finds W helper callers, but tails are unattributed and memory references miss aliases. | Alias-aware interprocedural writer/caller closure with explicit completeness; do not convert no-xref into impossible. **High.** |
| Running STOP/nonzero return not closed | Fresh stop fragment ends at helper entry; continuous historical position stays0 without autonomous STEP/IRQ service. | Existing bounded stop-helper/continuation experiments can recover more software stores; validated timer/NVIC/position scenarios or synchronized physical evidence needed for actual stop/return. **High.** |
| Continuous physical input-history comparison remains absent | Matched software original868 histories now exist; PC-timed ADC/GPIO changes and supplied W are not physical waveforms or natural Remote command timing. | Use the existing recipes for further bounded software controls; physical synchronization needs new evidence. **Medium.** |
| Formal model lacks lifecycle | No W/completion/STOP actions in descriptive relation. | Future separately authorized model extension, provenance-aware trace correspondence; no current model verdict strengthened. **Medium.** |
| No physical readiness/time/field-release correspondence | Fake tick, RX injection, radio-ID/MMIO responses, DWT delay stub and no STEP-counted travel in inherited runs; field release not hash-linked. | New synchronized button/RF/trigger/STEP/driver observations and exact release hashes. Missing evidence, not merely framework development. **High for field causation.** |

Specific unresolved transitions and closure targets:

- **AutoPilot completion → outbound X:** identify every writer capable of
  increasing `0x200025bc[0]`, including base aliases and IRQ callers, and obtain a
  feasible original instruction trace with completed-program state. Existing
  terminal path does not demonstrate this write.
- **@ → Remote RUNNING while already running/reconnecting:** preserve actual
  RX consumption, page12 exclusion, recursive screen/service behavior and flag
  state; demonstrate the delivery/exit sequence without supplying an exit flag.
- **RUNNING exit through button:** execute actual button acquisitions in a
  proper Remote setup/UI context, then capture W bytes at sender/receive
  boundaries. The current fragment supplies the button result.
- **Interrupted motion → live0 → nonzero return → idle9:** execute genuine
  `0x5274` consequences and all necessary timer events; count software position
  changes and verify target/duration guards. Do not force busy/live clear.
- **Multi-record continuation and repeated W arrival:** enumerate selected
  record+0x39/+0x3c/+0x40, mode and phase states; establish whether later W copies
  arrive in idle2 versus9 and which branch each takes. Six send requests do not
  prove six accepted resets.
- **Configuration/program changes around acceptance or STOP:** preserve filter,
  phase, program and sequence histories through actual parser operations;
  distinguish changed eligibility from a new electrical activation.
- **ISR-linked idle restoration:** establish feasible delivery/masking and
  dependencies of `0x5b1a`, rather than treating arbitrary state injection as a
  reachable race.

**Patch-readiness assessment:** enough is known to identify the stale-input and
held-input authorization boundaries and draft candidate stateful requirements.
It is not yet enough to validate a second patch across normal lifecycle and
STOP/rearm behavior. First close natural X/button→W provenance, running STOP and
nonzero return and multi-record/repeated-command behavior. The matched original
release/repress software control is now established, within supplied-W and
zero-distance-return assumptions. Product
choices about initial-active behavior, legitimate W/manual authorization and
release qualification remain separate decisions. This phase implements none of
them.
