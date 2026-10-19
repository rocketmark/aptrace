# Remote-to-motor causal trace

Investigation: 2026-10-17–19; APTrace operator, original 868 MHz images only. Result: **partial causal chain**, with a continuous concrete receiver-to-motion-state segment and a separate concrete ISR-to-STEP segment. There is no demonstrated Remote-input-to-timed-STEP/DIR execution, RF delivery, or motor rotation. No claim from this investigation is VERIFIED.

Companions: [causal graph](../../research/generated/remote-to-motor-causal-graph.json), [reference vectors](../../research/generated/remote-to-motor-reference-vectors.json), [APTrace assessment](remote-to-motor-aptrace-assessment.md). Paths inside JSON are repository-relative.

## Identity and scope

| Image | SHA-256 | Load base |
|---|---|---|
| `firmware_mando868.bin` | `cf74cf03b375eaed1f48ff2ab0852a2cbbca4ece1ea8eb0989ec938af5e431bc` | `0x4000` |
| `firmware_autopilot868.bin` | `6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3` | `0x4000` |

Both files were freshly hashed. Addresses below are image-specific application addresses; no bootloader or 915 MHz equivalence is assumed. Final inspected repository revision: `2e74a1a01f095fbcf1bc92985e6d0732b7454056`. The workspace advanced externally since the October 17 run; model artifacts retain their own timestamps. The user's updated `.codex/config.toml` was read on October 19; it was not edited by this investigation.

## Selected command and exact prerequisites

Select the original Remote's `F0` jog-family channel-0 record with decoded positive magnitude **5,000,000**:

```
f0 0b ff ff ff ff 00 4c 4b 40 7c
```

This is an **11-byte binary frame**: marker, length, four `ff` bytes, channel nibble zero, sign/magnitude, and `|`. The next buffer byte is `00`, a sentinel. Fresh builder decompilation shows `0x48c8` writes `|`, writes NUL, and updates length; `0xbe94`'s TX loop uses that length. The older grammar describing a rolling sequence digit after `|` is not supported for this binary builder. ASCII sequence conventions must not be imported into it. The existing `manual-f0e0` scenario synthesizes a twelfth numeric sequence byte; its observed dispatch results do not validate transmission of that extra byte.

Exact fresh Remote scenario: direct entry `0xbe94`, zero-initialized RAM/MMIO, dirty channel byte `0x20002679=1`, and millis counter `0x20005a08=1`. No boot, encoder IRQ, display loop, radio model, fake tick, or stub is used. Execution stops **before** radio-start `0x117f4`: 367 instructions, TX buffer `0x2000183c` begins with the bytes above plus NUL; length `0x200018e6=0x0b`; dirty byte has decremented to zero. A separate cold direct call with only the dirty seed returns after 333 instructions with the same constructed frame but does not reach radio start: construction does not imply transmission eligibility. These are exact software prerequisites, not a known physical wheel gesture.

The channel-0 helper `0x47e8` writes record channel zero and, on the dirty/zero-value branch, passes flash constant `0x004c4b40` to `0x468c`. This explains the selected captured value without asserting it is a measured position, requested rate, or encoder-derived distance. The original `0xbe94` builds via `0x4898 → 0x4880 → 0x48c8`; its subsequent dirty/time checks gate radio start, byte writes through `0x11282`, and end through `0x113b0`. Fresh evidence reaches the first boundary; later TX calls are static structure only.

## Causal edges and evidence strength

| Connection | Strongest evidence and qualification |
|---|---|
| Physical input → Remote UI state | Reused static dossier: EIC callback `0x7de8`, counter `0x20001084`, pump helpers `0x7abc/0x7b00`, shared sign/magnitude `0x20001818/0x2000181c`, jog loop `0xde3c`. No fresh concrete physical-input replay. Exact wheel-event-to-selected-record mapping remains unresolved. |
| UI loop → sender | Reused structure plus fresh decompile: `0xde3c` calls `0xbe94`, then checks wheel click through `0x171f0(0x2d)`. Sender invocation on a UI iteration is distinct from its gated radio transmission. Ghidra's decompiled function extends into adjacent menu code; only the identified loop and known calls are relied on. |
| Remote seeded state → encoded TX buffer → radio-start boundary | Fresh continuous 367-instruction run in `remote-tx-boundary.json`; no radio-driver execution beyond entry and no RF emission established. |
| TX bytes → AutoPilot RX | Separate machines and reset state. Operator checked byte correspondence against the RX seed. This is a bounded buffer-level composition, **not APTrace-validated cross-image state continuity**. No antenna, SPI, LoRa delivery, receive interrupt, packet assembly, checksum, address filtering, or freshness validation was executed. |
| RX boundary → binary dispatch → selected motor state | Fresh continuous 2,537-instruction execution from `0x8a34` to `0x83ec`, through `0x8258`, `0x5448`, `0x4d18`. Details below. |
| Motion state → periodic rate update/timer activation | Reused structural paths in the motor dossier; not demonstrated by this command. The nonzero writer for busy gate `0x20001b14[ch]` remains unidentified. Historical exhaustive wording is treated as search-relative, not a proof of impossibility. |
| Rate helper → timer period | Reused decompile `0x5ee8 → 0x5c00`; separate native period trace writes TC0 CC0 then stalls on unmodeled READSYNC. No natural scheduling or command-derived period established. |
| TC0 interrupt → pulse helper → STEP MMIO | Reused complete direct handler-body execution `0x607c → 0x5898 → 0xd388`, positive delta/divisor seeds. This is not interrupt delivery from an enabled timer. |
| Direction state → DIR MMIO | PB11 pin identity is established in the existing map. The selected run establishes no DIR write, polarity, or setup interval. A sign value in RAM is insufficient to close this edge. |
| MCU outputs → driver → rotation | Unresolved for this scenario. Existing continuity evidence does not establish logical channel-0 MCU routing to a particular physical driver/motor connector. No physical waveform or rotation inferred. |

## Fresh AutoPilot execution and motion state

The existing virtual link has a `manual-f0e0` scenario. It passed again, including under-threshold `F0(0,10) → 0x5448(0,10)` and over-threshold `F0(0,200) → 0x5274(0,4)` under threshold seed 100, and the E0 latch controls. It stops at handlers; it does not execute an end-to-end jog. Its final timeout statements are printed archival xref conclusions, not new dynamic checks.

The older Manual Mode dossier's simplified route through `0x5274` is incomplete: **under threshold reaches `0x5448`; at/over threshold reaches `0x5274(channel,4)`**. Fresh decompile confirms both. In `0x5448`, the changed target and signed-position comparison condition a call to `0x4d18`; this is not an unconditional pulse request.

For the selected frame, the new native RX runs use the full 12-byte buffer prefix including sentinel, `r0=12`, threshold `0x20000180=6,000,000`, delta `0x20000094=1`, and otherwise cold RAM/MMIO. Threshold and delta are disclosed infrastructure seeds, not values produced by the Remote or real boot. These RX entries bypass earlier validation. At instruction 37, `0x5448` receives `(channel,value)=(0,5000000)`; at instruction 71, `0x4d18` is reached with channel zero. Execution to the real post-dispatch block takes 2,537 instructions and records:

| RAM location | Final observation |
|---|---|
| `0x20000134` | `1` at planner-entry checkpoint: handler activity flag |
| `0x200023d8` | `0` at checkpoint: current unadvanced millis snapshot |
| `0x200024cc` | `5,000,000`: per-channel target/value slot |
| `0x20002524` | `2`: motion mode/state selector |
| `0x2000310c` | `2`: phase state |
| `0x20000094` | `+1`: final delta sign, initially seeded +1 |
| `0x20000040..47` | `61 32 55 30 2a a9 33 3f`: raw computed eight-byte rate/ramp slot; no engineering-unit rate asserted |
| `0x2000309d` | `0` |
| `0x20001b14..17` | all zero; no watched writes |

The run makes **zero MMIO accesses**, and watch sites `0x5ee8`, `0x5c00`, `0x607c` are not reached before the declared exit. This is a scoped negative over one completed command segment, not a negative about later main-loop or real-device behavior. No start/ENABLE write, timer period, DIR write, or STEP pulse follows within it.

## Timer, ISR and output evidence reused

The existing readiness native artifacts provide a separate reference: TC0 init requests `CTRLA=0x600`, WAVE=1 and MC0 interrupt setup; this configuration alone is not a start. Direct period call `0x5c00(0,10000)` writes `CC0=0x2710` at `0x4000381c`, requests READSYNC, and remains bounded at 20,000 instructions because plain-memory MMIO cannot self-clear the command. It must not be labeled a completed period update.

IRQ107 is mapped to `0x607c`; the handler-body reference completes in 108 instructions, with delta=1, divisor=1 and original STEP pin indices seeded. Position `0x20002064` becomes 1. Writes to `0x41008098` then `0x41008094`, both mask `0x400`, are PB10 OUTSET then OUTCLR requests. This establishes software write ordering, not pulse width or pin voltage. The AutoPilot boot recipe has no autonomous interrupt bridge; no artificial periodic ISR scheduling was added.

## Release / STOP

Stopping wheel rotation is not established as stopping the sender: the loop can continue invoking it. In the traced `0xde3c` live-jog loop a wheel **click**, not physical release alone, exits that loop after the current send invocation. The identified exit does not emit an explicit zero-rate/STOP frame; the surrounding Set-Limits flow can later send position queries and LL bookkeeping commands. Consequently “silence” here means cessation of that jog stream, not permanent radio silence or proof that every UI path behaves identically.

Existing xrefs in the gap audit identify no independent consumer of the E0 timestamp/latch outside its dispatcher arm and no demonstrated F0/E0 dead-man mechanism. This supports **no demonstrated silence-to-stop path**. It does not prove that every possible firmware state keeps moving indefinitely or that no computed consumer exists.

The separate completed timer-stop reference `0x5858(0)` clears TC0 ENABLE from seeded `0x602` to `0x600`. Completion/target-reached helpers structurally reach stopping logic. **No demonstrated click/release/RF-loss causal edge reaches that helper in this investigation.** Pending interrupts, stop latency, actual cessation, final position, and driver energization remain unknown. No moving scenario was started and then released, so this report cannot certify that movement ceases.

## Execution attribution and result

Qwen autonomously chose and executed discovery/PORT queries in its first run, then effects, call observation and function follow-ups in the seeded run. Neither run supplied this causal synthesis. Gemma produced no valid review: its supported diagnostic audit was rejected by the local server's memory ceiling. Codex operated the existing virtual-link, Ghidra and native concrete interfaces for the bounded captures above, compared evidence scopes, and authored these four artifacts. No independent reverse-engineering script, engine, test, interrupt model, or APTrace improvement was implemented.

Fresh firmware evidence consists of the Remote construction/TX-boundary captures, RX-to-state captures, bounded Ghidra queries, and the existing manual-frame scenario replay. The ISR, timer init/disable/partial-period, GPIO identity, RF boundary, motor-gate and TMC evidence were reused. Commands, assumptions, native references and hashes are in the vectors and graph. The normal `--ledger` run created C10–C13 as PROPOSED structural claims and appended normal ledger artifacts; it did not establish motor claims. Diagnostic C10 audit remained PROPOSED/UNRESOLVED.

## Next work and apfw2 POC 0.1

Further broad firmware research is **not required to begin POC 0.1 software preparation**. Existing pin, timer, SPI and reference contracts support a replacement with explicit motion and STOP requirements. This investigation does not make legacy end-to-end jog behavior a usable safety oracle. Exact legacy jog compatibility would still require input-value mapping, naturally reachable motion activation, and click/RF-loss behavior evidence. Physical first movement additionally needs the unresolved routing/current/containment and STOP/reset waveform evidence already identified in the readiness and TMC contracts. Those are separate engineering evidence needs, not a reason to repeat the settled TMC/GPIO work.
