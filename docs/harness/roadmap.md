# Harness Roadmap (current, authoritative)

This supersedes [`docs/history/protocol-harness-roadmap-v1.md`](../history/protocol-harness-roadmap-v1.md),
which was written before any symbolic execution had been attempted against
the real dispatcher and assumed a flat-chain model later found to be
incomplete (see
[`docs/investigations/parser-dispatch.md`](../investigations/parser-dispatch.md)).
For a blow-by-blow of what changed and why, see
[`docs/harness/protocol-harness-results.md`](protocol-harness-results.md).

For the fuller "APTrace as a workbench" direction this roadmap sits inside,
see [`docs/architecture.md`](../architecture.md).

## Milestone ordering (do not skip ahead)

### M1 — AutoPilot-only `&` transaction, end to end — **COMPLETE (concrete tier)**

Closed as of 2026-09-07, at the concrete (Unicorn) evidence tier — see
[`docs/project-status.md`](../project-status.md)'s "Current milestone" for
the full status and what remains at the solver-confirmed tier (a known,
deliberately unfixed tooling gap, not a blocker). What actually resolved
this, for the record (the three steps below as originally planned turned
out not to be the right order — the non-termination was a harness bug,
not something `0x5274`/`0x5448` needed a real-CFG fix for):

1. ~~Resolve the whole-function replay's non-termination~~ — root cause
   was a harness memory-model limitation (readonly flash populated via
   solver assumptions, not folded literals), not `0x5274`/`0x5448` or a
   missing lazy-real-CFG mechanism. See
   [`docs/investigations/whole-function-trace-divergence.md`](../investigations/whole-function-trace-divergence.md).
   Deliberately left unfixed (see `docs/project-status.md`'s "Tooling
   gaps") since the milestone closed without needing it.
2. ~~Confirm a real in-memory `&` packet, run through the *unmodified*
   whole dispatcher function, sets `pending[5]`~~ — done concretely via
   Unicorn. See
   [`docs/investigations/dispatcher-loop-concrete-trace.md`](../investigations/dispatcher-loop-concrete-trace.md).
3. ~~Hook outbound transmission at `0x8c10`/`0x7f84` and verify the emitted
   bytes equal `V01R39`~~ — done concretely via Unicorn. See
   [`docs/investigations/tx-hook-verification.md`](../investigations/tx-hook-verification.md).

### M2 — Strengthen the AutoPilot-side evidence

M1 is done; this is a smaller, parallel task, not a prerequisite for M3:

4. Independently verify `G`/`!`/`S`'s handlers perform their claimed
   event-scheduling writes (currently only handler-*entry* reachability is
   solver-verified for these three).
5. Attempt the reachability question for the "dormant" events (2, 3, 8, 9,
   11, 12, 14) per [`docs/protocol/open-questions.md`](../protocol/open-questions.md)
   #9 — a natural fit once whole-function execution of the relevant call
   graph is reliable.
6. **Ground firmware analysis in the confirmed ATSAMD51J19A hardware** —
   started: real peripheral/register naming
   (`tools/svd/resolve_mmio.py`), a confirmed startup peripheral survey,
   and one fully-resolved pin fact (PB22, from a real timer ISR). See
   [`docs/investigations/samd51-peripheral-mapping.md`](../investigations/samd51-peripheral-mapping.md)
   for what's done and its own "next logical slice" (the other three
   motor channels' pin/ISR pairs; naming the TX path's real transport
   peripheral).

### M3 — Remote (`mando`) firmware — **COMPLETE (concrete tier)**

M1 is done, so this began 2026-09-08 and closed the same day. See
[`docs/investigations/mando-first-execution.md`](../investigations/mando-first-execution.md)
and [`docs/investigations/virtual-rf-link.md`](../investigations/virtual-rf-link.md)
for the full result.

6. ~~Point APTrace's loader/discovery at `firmware_mando868.bin`~~ — done:
   clean discovery, 563 functions, every named Remote function of interest
   (`0x58a8`, `0xb440`, `0xb59c`, `0xb680`, `0xba98`, `0xc440`, `0xfa10`,
   `0xfadc`, `0x10cf4`) resolved at its documented address, zero
   platform-specific harness changes needed.
7. ~~Complete the `&|` -> `V01R39` transaction from the *Remote's* side~~
   — done at the **concrete (Unicorn)** evidence tier, both halves: real
   TX construction (`0xba98` calling the real TX wrapper with a real
   `"&|\0"` literal) and real RX capture (the real byte-collection loop
   copying the AutoPilot's already-proven response into `0x200002fc`).
   **Not** done at the solver-confirmed (Crucible) tier — deliberately,
   consistent with M1's own evidence-level discipline; revisit only if a
   real use case needs it.
8. ~~Connect the two sides with an in-memory virtual RF queue~~ — done:
   `tools/unicorn/virtual_link.py` runs the complete `&|` -> `V01R39`
   round trip as one harness-driven script, hooking each side's real
   TX-wrapper argument and seeding it into the other side's real RX state
   (AutoPilot: packet buffer `0x2000232a`; Remote: ring buffer
   `0x20001773` + write pointer `0x200017d8`) — no LoRa/SPI hardware
   modeled. Built as two reusable primitives (`capture_tx_bytes`,
   `deliver_and_observe`), not a transaction-specific script — see
   `virtual-rf-link.md` for the full design and what the harness still
   substitutes for real radio behavior.

### M4 — Broader protocol reachability

9. ~~Exercise the next protocol transaction through the virtual link
   built in M3~~ — `G -> #` done (`tools/unicorn/virtual_link.py g`):
   Remote's real `0xb680`/`0xb59c` request+retry, AutoPilot's real `G`
   handler concretely scheduling event 17 (not just solver-confirmed
   reachability), AutoPilot's real `0x7f84` single-byte response, and
   Remote's real `0xb59c` accepting the ack — all at the concrete tier.
   Confirmed the M3 primitives generalize (needed register seeding and a
   new byte-value TX-capture primitive, both now reusable). See
   [`docs/investigations/g-ack-roundtrip.md`](../investigations/g-ack-roundtrip.md).
   Then `S -> P...` also done (`tools/unicorn/virtual_link.py s`): both
   the short (`"P1,"`) and extended (`"P11,0,0,"`) response forms
   exercised concretely, AutoPilot's event-6 scheduling and field
   computation confirmed in one pass, and a real "don't downgrade" guard
   in the Remote's parser found by running it (a fresh device receiving
   `"P1,"` does not update its stored state). No new harness capability
   needed. See
   [`docs/investigations/s-p-roundtrip.md`](../investigations/s-p-roundtrip.md).
   **Deliberate pause here, per the task that closed `S -> P...`**: not
   continuing into `!`/`I` yet — pivoting to hardware provenance instead
   (see M6 below). `!`/`I` remain queued for whenever protocol-transaction
   work resumes.
10. Resolve the Remote-transmitted-packets-not-in-dispatch-tree question
    (`docs/protocol/open-questions.md` #8) now that the real dispatch
    structure is better understood.
11. Resolve the event-7 11-vs-10 field mismatch by symbolically tracing the
    Remote's `0xc440` parser with the real 11-field output as input.

### M5+ — Tool-workbench integration — **done**

Ghidra and Unicorn are both integrated (see
[`docs/tooling/ghidra-backend.md`](../tooling/ghidra-backend.md) and
[`docs/tooling/unicorn-backend.md`](../tooling/unicorn-backend.md)) and
were exactly what closed M1 above — not deferred any further. See
[`docs/tooling/tool-selection.md`](../tooling/tool-selection.md) for the
current, durable guidance on when to use which tool.

**Toolchain cleanup (2026-09-09, not a firmware-behavior slice)**: the
mechanics both backends required got a focused refactor once M6's own
investigation docs started documenting harness friction *as if it were a
finding* (repeated Ghidra re-import/re-analysis for one query, a
two-run pattern to dereference one register, hand-built stack frames for
direct function calls, a real `--reg` hex/decimal ambiguity that produced
a genuine false investigative path in item 30 below). See
[`docs/investigations/toolchain-cleanup.md`](../investigations/toolchain-cleanup.md)
for the full writeup:

- `tools/ghidra/aptrace_ghidra.py` — a persistent, cache-identity-checked
  per-firmware Ghidra project (`build` once; `decompile`/`disasm` reopen
  it without re-analyzing; `callers`/`xrefs`/`containing`/`symbol`
  answered from a cached export with no Ghidra invocation at all).
- `tools/unicorn/concrete.py` — the Unicorn setup/hook/snapshot logic
  extracted into a reusable `ConcreteMachine` class; `run_concrete.py`
  is now a thin CLI wrapper over it, and `virtual_link.py` uses it
  directly (one machine per firmware, reused across every scenario leg,
  instead of a subprocess per leg — all four `virtual_link.py`
  scenarios together now run in ~0.1s).
- A proper ARM-AAPCS direct-function-call helper (`ConcreteMachine.call`
  / CLI `--call`/`--arg`), replacing hand-picked stack pointers,
  manually-placed stack arguments, and invented LR-crash-to-infer-return
  patterns with a real trampoline and a genuine clean-return signal.
- `--reg`/`--arg`/length values now parse as `int(value, 0)` (28 decimal,
  0x28 hex) instead of always-hex — the direct fix for the bug named
  above.
- Structured, never-thrown-away failure snapshots, a bounded always-on
  recent-PC trace (`--trace-last`), and explicit, visibly-tagged state
  carry-forward between runs (`RunResult.carry`).

All four existing regressions (`tools/doctor.sh`,
`virtual_link.py all`/`plus`) pass unchanged; two new regression scripts
(`tools/unicorn/test_concrete.py`, `tools/ghidra/test_aptrace_ghidra.py`)
cover the new mechanics. No firmware-behavior conclusion from any prior
M6 item was revisited.

A follow-up hardening pass (same date) checked the reuse this cleanup
introduced against the exact isolation the old fresh-subprocess/
fresh-import model gave for free, and fixed two real gaps it found
(`fresh=True` wasn't restoring flash/MMIO/PPB; `call()`'s trampoline
briefly lived inside real device RAM) plus two smaller ambiguities
(Ghidra cache identity now hashes build-script/provenance-TSV content;
`RunResult.success` split into explicit `error_free`/`completed`) — see
[`docs/investigations/toolchain-cleanup.md`](../investigations/toolchain-cleanup.md)'s
"Hardening pass" section. Also not a firmware-behavior slice.

### M6 — Behavior-to-hardware provenance (new, 2026-09-08)

A deliberate pivot from protocol mapping toward physical hardware:
`command/state -> internal variable/function -> timer/MMIO -> ISR/GPIO ->
MCU pin -> physical hardware behavior`. Not a replacement for M4's
remaining items — a parallel track, per
[`docs/investigations/s-p-roundtrip.md`](../investigations/s-p-roundtrip.md)'s
closing recommendation.

12. ~~Find TC0/TC1/TC2's ISR/pin pairs~~ — done: TC0-TC3 are IRQ107-110
    (`0x607c`/`0x6098`/`0x60b4`/`0x60d0`), each clearing its own MC0+OVF
    flags then reaching a shared, table-indexed GPIO-pulse helper
    (`FUN_00005898`/`FUN_0000d388`) rather than TCC1's inline toggle — a
    confirmed *mechanism*, concretely exercised on all four channels via
    `--log-mmio`, but the real per-channel pin assignment depends on a
    RAM index byte this pass found no static producer for (cold RAM
    gives the same pin for all four, an artifact, not a hardware fact).
    Also found, falling out naturally: `FUN_00005c00`/`FUN_00006260`
    write/read each TC's `CC0` (period) — the rate-control mechanism. See
    [`docs/investigations/motor-timer-survey.md`](../investigations/motor-timer-survey.md).
13. ~~Find what writes the per-channel pin-index RAM bytes
    (`0x20000164`-`0x20000167`)~~ — done: they are `.data`-segment
    initializers copied into RAM by `Reset_Handler`'s own startup copy
    loop, not written by any application instruction — a static
    (level-1), compiled-image fact. **TC0->PB10, TC1->PA08, TC2->PB12,
    TC3->PA10**, cross-validated against the independently-known
    PB22/TCC1 fact. Also ruled out with evidence: NVM/EEPROM-persisted
    config and board/runtime detection. See
    [`docs/investigations/pin-index-provenance.md`](../investigations/pin-index-provenance.md).
14. ~~Connect `I<channel><mode>|`'s protocol-level state machine to the
    timer/pin chain~~ — done, meet-in-the-middle: the `I` handler's own
    `0x20001b14[channel]!=0` gate conditionally calls
    `FUN_00005274`->`FUN_00004d18` (writes `step_delta[channel]`'s
    direction sign, concretely validated); independently,
    `FUN_00006338`'s ramp logic only forwards a rate update to the
    already-proven `FUN_00005ee8`->`FUN_00005c00`->`FUN_00005898` chain
    when that same gate is nonzero — both directions converge on the
    identical byte. Also corrected the record: the handler's `=5` write
    targets `0x20002524[channel]`, not `0x20001b14[channel]`. **One edge
    still open**: what sets `0x20001b14[channel]` nonzero. See
    [`docs/investigations/i-command-motor-chain.md`](../investigations/i-command-motor-chain.md).
15. ~~Find the `0x20001b14[channel]` setter~~ — searched exhaustively,
    **not found** (a genuine negative result, not abandoned): all 12
    direct-reference functions, 7 one-hop candidates (including the two
    originally suspected, `FUN_00006fd8` and `FUN_00008e18`), the
    complete one-time-init boot chain, and a neighbor-offset sweep of
    every global packed around the byte all checked. Confirmed `.bss`
    (cold value `0`); confirmed standalone (not aliased with a
    neighboring array). Added a genuine Unicorn memory watchpoint
    (`--watch-mem-write`) and got a partial concrete confirmation. See
    [`docs/investigations/channel-busy-gate-search.md`](../investigations/channel-busy-gate-search.md).
16. Concrete follow-up
    ([`docs/investigations/systick-tick-injection.md`](../investigations/systick-tick-injection.md)):
    diagnosed the `FUN_0000ccd0` tick source precisely (a
    firmware-maintained RAM counter incremented by the real
    `SysTick_Handler`, not a SysTick register) and resolved it with a
    new, narrow `--fake-tick` capability; also needed one disclosed
    real-GPIO-input boundary condition and one disclosed delay stub. The
    run escaped `FUN_00006968`'s homing timeout with
    `--watch-mem-write 0x20001b14:4` live, then hit a *different*
    dependency — an uninitialized DMA/SERCOM-shaped peripheral driver
    object, root-caused to `FUN_0000cdd8`'s clock-init stall. No write
    observed.
17. ~~Solve `FUN_0000cdd8`'s clock-init stall for real~~ — done
    ([`docs/investigations/reset-handler-clock-init.md`](../investigations/reset-handler-clock-init.md)):
    of 16 status polls in the function, exactly 4 don't already pass
    under zero-behavior MMIO — each a real, SVD-named ready/lock bit
    (`OSC32KCTRL.STATUS.XOSC32KRDY`, `OSCCTRL.STATUS.DFLLRDY`,
    `OSCCTRL.DPLL0/DPLL1.DPLLSTATUS.{LOCK,CLKRDY}`) — modeled with a
    new, explicit `--mmio-force-bits`/`--mmio-clear-bits` mechanism
    (never a general peripheral model). Rerunning from the true
    `Reset_Handler`: clock init completes, the real SERCOM/DMA driver
    object (two SERCOM instances) constructs without the previous
    null-pointer crash, and real homing runs and exits — confirmed via
    `--watch` hits at the same exit point (16)'s routed-around entry
    found. **Still no write to `0x20001b14`**: reaching a directly
    observable main-loop state (`FUN_00008960`) needs far more simulated
    tick-time than expected — a newly identified characterization gap
    (not a hardware-modeling one).
18. ~~Enumerate the post-homing delay/init call sites~~ — done
    ([`docs/investigations/post-homing-radio-probe.md`](../investigations/post-homing-radio-probe.md)):
    not a timing gap. `FUN_00009464`'s real post-homing sequence reaches
    `FUN_0000610c` *second* (before either of the named "likely
    hotspots," `FUN_00007770`/`FUN_00005d44`, which turn out to be
    unreached) — a real device bring-up that performs a real SPI
    chip-ID read (register `0x42`, expects `0x12`, matching the
    well-known SX127x LoRa `RegVersion` check) through the already-real
    SERCOM/DMA driver, concretely confirmed (`--watch 0x9dd4`) to read
    `0` with no chip attached. On failure the firmware takes its own
    real, **infinite** retry loop (print + `delay(1000ms)`, forever) —
    this, not a sum of finite delays, is what consumed the large tick
    counts in (17). Correctly **not faked**: an external device's real
    response is a different evidence class from the MCU-internal
    completion bits modeled in (17), and this is likely the same
    unmodeled transport-peripheral boundary already on record
    (`docs/project-status.md`'s TX-path next step).
19. ~~Get past the radio-ID boundary honestly and reach the real main
    loop~~ — done
    ([`docs/investigations/post-probe-main-loop.md`](../investigations/post-probe-main-loop.md)):
    confirmed no software bypass exists (both call sites and the probe
    body checked), then introduced the narrowest possible disclosed
    assumption — a new `run_concrete.py --force-reg ADDR:REG:HEX`
    mechanism (deliberately stricter-disclosure than `--mmio-force-bits`:
    it fabricates one external value at one exact instruction, not a
    documented MCU behavior), used exactly once
    (`--force-reg 0x9dd4:r0:0x12`, the instruction right after the SPI
    read returns). The real main loop is now reached and confirmed
    stable (`FUN_00008960`, 5 iterations, ~400,000 instructions total
    from `Reset_Handler`) — resolving the "excessive tick cost" question
    as entirely the now-bypassed infinite retry loop, not a sum of
    delays needing further characterization. `0x20001b14` remains
    unwritten through genuine idle main-loop execution, concretely
    confirmed. **The real RX injection point is identified** (a 100-byte
    RAM ring buffer at `0x2000245c`, index `0x200024c0`, selected by
    flags `0x20000018=0`/`0x2000006a=1` — both observed, not assumed) —
    not used this pass. A second, deeper dependency (a real bulk NVM
    erase loop that doesn't advance over millions of instructions,
    likely gated on a zero-valued config field rather than a status bit)
    was found and reported precisely, not chased, since it doesn't block
    the above. **Next**: inject a real "M"/"I" command into the
    identified ring buffer and watch `0x20001b14` through a real
    dispatch — once found, the full `I<channel><mode>| -> ... ->
    now-known GPIO -> event-15 result` chain closes completely.
20. ~~Inject a real command into the RX ring and catch the `0x20001b14`
    setter~~ — done, and the answer is a structural one, not a missing
    write: a new `run_concrete.py --force-mem TRIGGER:MEMADDR:HEXBYTES`
    flag (the memory-range counterpart to `--force-reg`) delivered a
    real `G<d><d><seq>|` end to end through the real RX ring, real
    parser, and real dispatcher — the first fully real command delivery
    in this project — after diagnosing and fixing a real harness-timing
    artifact (a per-byte real radio-poll cost that exceeded the
    firmware's own real inter-byte assembly timeout at the previous
    `--fake-tick` calibration; raised 20 -> 300). Found a previously
    undocumented write (`G`'s handler arms `0x200025e1=2`, a byte
    `FUN_00007e2c` gates on) but still no write to `0x20001b14`. Tracing
    why found the real structural answer: `FUN_00007e2c`/`FUN_00008e18`/
    `FUN_00006338`/`FUN_00008a80` — every function this roadmap has
    described as running "every main-loop iteration" since (14) — are
    **not reachable from a cold boot at all**. The real, currently-
    running main loop lives entirely inside `FUN_00009464` (confirmed
    concretely to never exit, several runs, up to 4,000,000
    instructions) and only calls `FUN_00008960`/`FUN_00005dd0`;
    `FUN_000093fc` (which calls all four motor-phase functions) is only
    reached after `FUN_00009464` returns, which requires clearing a byte
    (`0x20000060`) traced, via the same exhaustive literal-pool-scan
    method (15) used for `0x20001b14` itself, to exactly one writer in
    the whole firmware: **`MC4<...>|`** (motor configuration, all four
    channels — never per-channel `MC<0-3>`). A concrete `MC4` delivery
    attempt hit a second, distinct per-byte timing dependency and was
    not chased further. See
    [`docs/investigations/g-command-motor-subsystem-unlock.md`](../investigations/g-command-motor-subsystem-unlock.md).
    **Next**: characterize `MC4`'s own per-byte timing cost (the same way
    this item characterized `G`'s) and concretely confirm the unlock;
    per (15)'s already-exhaustive search, no new `0x20001b14` writer is
    expected to appear even once `FUN_000093fc` is reachable — if that
    holds, the honest conclusion becomes that no code path in this
    firmware image, reachable or not, ever sets `0x20001b14` nonzero.
21. ~~Characterize `MC4` and confirm the unlock concretely~~ — done.
    Statically: `MC4`'s handler (`FUN_00008258` at `0x86f0`, the
    `packet[2]=='4'` sub-branch, calling `FUN_00007a98` x4) writes four
    per-channel fields (`0x2000006c`/`0x200000dc`/`0x200000f0`/
    `0x20000138`); an exhaustive literal-pool xref finds only the 4th is
    consumed by the locked subsystem (`FUN_00007e2c`/`FUN_00008e18`, as
    a lookup-table index) — the other three feed unrelated boot-time/
    display functions. The unlock write (`0x20000060=0` at `0x8714`) is
    confirmed, by exhaustive scan, to be the *only* write to that byte
    anywhere in the firmware. The second per-byte timing dependency
    (19)/(20) both hit is now precisely diagnosed: `FUN_00008960`'s
    inter-byte timeout is cumulative from packet start, not per byte —
    a longer frame needs proportionally more `--fake-tick` headroom,
    sized from a direct ~5,696-instruction-per-byte measurement (period
    300 -> 2000), not guessed. With that fix, `MC4` alone concretely
    unlocks `FUN_000093fc` (`0x8714` -> `FUN_00009464` returns ->
    `FUN_000093fc`/`FUN_00007e2c`/`FUN_00008e18` all reached repeatedly,
    hundreds of hits). Sending `G` and `MC4` in the same buffer back to
    back found a real "flush stale bytes while busy" firmware behavior
    that silently drops the second command — not a bug, and not
    coupling between the two commands (confirmed independent by both
    xref and control flow: no function touches both `0x200025e1` and
    `0x20000060`). Fixed by sequencing a second injection at
    `FUN_00009464`'s own one-time return instruction. With `MC4` then
    `G` properly sequenced, `G`'s arm lets `FUN_00007e2c` reach
    **`FUN_00006fd8` — the real motor move-commit function — for the
    first time in this project's history** (register-captured:
    `channel=0, distance=0, rate=0x121fa`). Still no `0x20001b14` write:
    with `distance=0`, `FUN_00006fd8`'s own code takes its documented
    "8 units or fewer, no real move" branch — a concrete, register-level
    explanation. See
    [`docs/investigations/mc4-transition.md`](../investigations/mc4-transition.md).
    **Next**: thread a real, nonzero target/position value through
    `FUN_00007e2c`'s own per-channel-per-mode config struct
    (`0x20001b40`+, a *different* structure from the one `MC4`
    populates) so a delivered `G` computes a nonzero distance, and watch
    whether `FUN_00006fd8`'s real-move branch reaches
    `FUN_00005274`/`FUN_00006338` and, through the already-proven
    `FUN_00005ee8`->`FUN_00005c00`->`FUN_00005898` chain, a real GPIO
    pulse — completing the full `I<channel><mode>|`-equivalent chain end
    to end, concretely, for the first time. `0x20001b14` remains
    unwritten through every path exercised across (14)-(21); no further
    setter search is expected to find one.
22. ~~Trace the target/position config producer and try for a real
    nonzero move~~ — done, and it's a real external-data boundary, not a
    missing mechanism. `FUN_00006fd8`'s config struct base is
    `0x20001b40` (a same-session decompiler-vs-disassembly correction:
    `FUN_00007e2c`'s tail body silently jumps to `0x7cc0`, which
    `APTraceDecompileFunctions` presents as if it were `FUN_00007e2c`'s
    own code, misattributing which literal is the struct base versus a
    separate small "this cycle's target" array). `FUN_00004b64`
    bulk-loads all 4 channels' `0x120`-byte blocks from a
    lazily-initialized RAM buffer (`FUN_00009724`), sourced from a plain
    flash-address read (register-captured: `src=0x00012000`, no
    driver/peripheral indirection) — and that exact flash address is, in
    this firmware image, **entirely `0x00`** (confirmed by reading the
    raw `.bin` directly — the strongest possible evidence tier, no
    execution needed). The loader's own real fallback (fully
    disassembled, including a genuine ARM void-return subtlety the
    decompiled pseudo-C got wrong) then fills the struct with `0xFF`; a
    separate, one-shot, `.data`-driven resync (`FUN_00004b24`, gated on a
    real `.data`-initialized flag, confirmed to fire exactly once per
    boot across all 4 channels) immediately overwrites each channel's
    mode-0 target with that channel's own live position
    (`0x20002064[channel]`, cold-zero) — a real "no move commanded yet"
    default, not a bug. Exhaustively trying every `G` "type" digit
    (`0`-`9`) after a real `MC4`, with real register-captured
    `FUN_00006fd8` calls, gives exactly two outcomes: mode `0` ->
    `distance=0`; modes `1`-`9` -> `distance=-1` (the untouched
    blank-fill pattern) — **never `>8` in magnitude**, so
    `FUN_00006fd8`'s real-move branch is never reached by any input this
    firmware's current configuration can produce. This is the same
    evidence class as the unmodeled radio-ID chip in (18): a real
    external-data/provisioning gap, not something to model or fabricate
    around. See
    [`docs/investigations/target-config-provenance.md`](../investigations/target-config-provenance.md).
    **Next**: try `LL1|`/`LL2|` (the "limit workflow," unresolved
    semantics) as the most plausible remaining real command for
    advancing `0x20002064[channel]` or writing a genuine target, without
    fabricating data; independently, `FUN_00004c20` (the sibling
    bulk-config-loader named alongside `FUN_00004b64` since (15)) has not
    yet been traced for other fields it might populate.
23. ~~Characterize `LL1|`/`LL2|` and try it as the missing target
    producer~~ — done: it isn't, and this is a second, independent
    negative result of the same class as (22). Both commands reach a
    single shared handler, `FUN_000054e0` (disassembly-corrected — an
    initial decompile misattributed which branch does what across the
    `'H'`/`'L'` split), via the top-level `'L'` dispatch character,
    reachable pre-`MC4` exactly like `&`/`G`/`S`. `LL1` unconditionally
    clears two fixed globals (`0x20003114`, `0x20002414`) plus a
    validity flag (`0x20002458`); `LL2` compares and reorders them,
    writing the smaller into a third global (`0x20002424`) and setting
    the validity flag **only if they differ**. Neither touches live
    position (`0x20002064`), the target/config struct (`0x20001b40`+),
    `0x20001b14`, or any timer/rate register — confirmed by full
    disassembly (no MMIO/GPIO address appears anywhere in either
    command) and by a real `--watch-mem-write` run. An exhaustive
    literal-pool scan (the same method that found (22)'s blank flash
    blob) found **no other code anywhere in the firmware writes either
    of `LL`'s two globals** — this workflow cannot capture a real
    physical position through the ASCII protocol at all. Delivering
    `LL1` then `LL2` concretely surfaced a *third* real receive-path
    behavior (distinct from (20)'s cumulative timeout and (22)'s
    per-byte cost): right after recognizing a `'|'` terminator, the
    receive routine drains and silently discards any bytes already
    sitting in the ring, checking each only for a literal `'O'`
    (`0x4f`) byte, before dispatching — meaning two commands queued
    back-to-back in one buffer always lose the second one, regardless
    of `--fake-tick` calibration. Fixed the same way (20) sequenced `G`
    after `MC4`: a second injection at the point right after the first
    command's dispatch returns. With only `LL1`'s cleared state feeding
    it, `LL2` concretely takes its own documented "values equal, no-op"
    branch. See
    [`docs/investigations/ll-limit-workflow.md`](../investigations/ll-limit-workflow.md).
    **Next**: `FUN_00004c20` (still untraced) or accept this firmware
    image's real motor-position data as a genuine, unmodelable
    external-provisioning boundary — the same evidence class as the
    unanswered radio-ID chip in (18) — and treat the `distance`/
    `0x20001b14` question as closed pending real provisioning data this
    harness has no way to supply.
24. ~~A bounded standard-library/provenance classification pass~~ —
    done, deliberately not another provisioning slice: fetched the exact
    evidenced toolchain (Adafruit `ArduinoCore-samd` git tag `1.7.11`,
    named directly by embedded build-path strings) and structurally
    matched it against the infrastructure functions this project keeps
    re-deriving across investigations. Confirmed `Reset_Handler`, the
    shared default-handler stub, `SysTick_Handler`, and `millis()`
    against the fetched source; newly named `FUN_0000cd90` as `main()`
    and, from its call order, **`FUN_00009464` as the AutoPilot sketch's
    real `setup()`** (with its own internal, permanent loop that only
    returns once `MC4` clears `0x20000060`) **and `FUN_000093fc` as the
    sketch's real `loop()`** — the exact Arduino-idiom names for what
    (20) already characterized behaviorally without naming. Classified
    (honestly, at LIKELY tiers where a byte-for-byte match wasn't
    practical) SERCOM SPI reset/SPI transceive, the `digitalWrite`-shaped
    GPIO pulse helper, `memcpy`/`memset`, a `libgcc`-shaped 64-bit
    arithmetic cluster, an SX127x-register-map-matched radio driver
    cluster, and a vtable-call-shaped LCD status function — recorded in
    a new, reusable CSV
    (`research/provenance/function_classification.csv`) and applied
    back into the Ghidra pipeline via a small, optional, concretely
    tested post-script (`APTraceApplyProvenance.java`, 42 functions
    renamed against the real firmware image, 2 correctly skipped).
    **Sharpened the `0x12000` question** from (22): every decision-making
    function in the read chain is confirmed custom application code
    built on a standard `memcpy` — and, while checking for other
    references to the same flash address, found a **real, previously
    unexamined write path** (`FUN_0000449c` -> `FUN_000097a4` -> the
    same NVM erase/write primitives, reached from a channel-0
    move-completion handler called from `FUN_00005be8`/`FUN_00005dd0`).
    See
    [`docs/investigations/standard-library-provenance.md`](../investigations/standard-library-provenance.md).
    **Next**: this write path was found statically, not exercised — the
    next persistence slice should trace what sets the `+0x1002` "dirty"
    byte that gates the save, and whether the handler's apparent
    channel-0-only scope is real, before attempting a concrete run.
25. ~~Trace the `+0x1002` dirty byte to its setter/clearer~~ — done,
    entirely statically, per the task's explicit "don't exercise the
    write yet." The byte is `0x20004147` (buffer base `0x20003145` +
    `0x1002`) — found only by a full-image disassembly scan for the
    16-bit immediate `#0x1002` used in a `movw` instruction (the offset
    exceeds Thumb-2's encodable `ldrb.w` immediate range, so it's
    materialized in a register rather than ever appearing in the flash
    literal pool — an ordinary xref search, the method used for every
    other address in this project, would have found **nothing**). Exactly
    three sites reference this immediate anywhere in the image: the
    setter, the save-gate reader, and one clearer. **The setter is
    `FUN_0000977c`**, a single shared "write one byte into the persisted
    config buffer" accessor used by several callers — it sets the flag
    only when the new byte value genuinely differs from what's already
    stored (`cmp`+`itttt ne`), a real change-detection guard, not a
    channel- or event-specific trigger. Found, in the process, **a
    previously undocumented ASCII command, `D<value>|`**, that writes
    through this exact accessor (a 32-bit value at logical offset `0x15`
    then a `0xDE` marker at `0x19`, read back at boot by the already-
    known `FUN_00004c20`) — a real, protocol-native way to dirty the
    buffer, not delivered concretely this pass. `FUN_000097a4` (the
    save-if-dirty path `FUN_0000449c` calls) never clears the flag after
    saving; the only function that does, `FUN_000097f4`, has **no
    confirmed caller anywhere in the image** (checked via both the calls
    graph and a full-image branch-target scan) — a genuine open question,
    not guessed at. The save trigger's channel-0 association traces to a
    real, already-documented TC0-ISR asymmetry (`channel-busy-gate-
    search.md`'s own original finding), not a new per-channel design;
    the dirty flag and the buffer itself are global, covering all four
    channels together. **This settles the task's central caution**:
    `0x12000` is confirmed real, firmware-owned, round-trip persistent
    storage — not an external-provisioning boundary — since a real,
    protocol-reachable write path (`D`) into it now exists in evidence.
    See
    [`docs/investigations/dirty-flag-persistence.md`](../investigations/dirty-flag-persistence.md).
    **Next**: deliver a real `D<value>|` command concretely through the
    live RX path (the same injection technique already proven for `G`/
    `MC4`/`LL1`/`LL2`) and watch `0x20004147` transition `0`->`1` with a
    true `--watch-mem-write`; then reach a real `FUN_00005be8` completion
    condition and watch whether the real erase/write actually fires
    against flash `0x12000`.
26. ~~Deliver a real `D` command concretely and trace dirty -> save~~ —
    done, outcome A as far as the existing concrete model supports, plus
    a precise identification of the exact remaining edge. `D` needs a
    trailing comma (`D1234,|`) to parse cleanly — a bare `D<value>|`
    dispatches but its field parser (whose only real terminator,
    confirmed by disassembly, is a literal `,`) runs past the packet
    into adjacent memory for a full 1000-tick timeout; an 8-byte
    `D12345,|` failed to dispatch at all (an unexplored framing
    curiosity, not chased). With `D1234,|`, the real value (`1234`) and
    `0xDE` marker land exactly where predicted, byte-for-byte confirmed
    before/after. Running the boot further, with **no new GPIO
    seeding, no seeded state, and no forced call**, found the real save
    path fires on its own: `FUN_0000d3dc(1)` (a real `digitalRead()`-
    shaped call, the read-side sibling of the already-classified
    `digitalWrite`-shaped helper) reads `PA22`
    (`PORT.GROUP0.IN` bit 22) — resolved directly from the real
    pin-descriptor table in the firmware image — **the exact same GPIO
    signal this project has disclosed and carried forward since (16)**,
    not a new assumption. That real signal satisfies `FUN_00005dd0`'s
    "held past 1000 ticks" branch, calling `FUN_0000449c` ->
    `FUN_000097a4` for real, which issues a real NVM erase call with
    **`dest=0x00012000, len=0x1001`** — matching (22)'s read path
    exactly, confirmed by register capture rather than static
    disassembly alone. It then stalls forever: `*(0x20004148+0xc)` (the
    driver object's own page-size field) is `0`, the same class of
    real, already-known NVM stall (19) found and didn't chase, now
    reconfirmed with real arguments in this specific context. No flash
    byte at `0x12000` was actually written, so the reboot/recovery half
    of the round trip wasn't reached. Also found, in passing: a real
    boot-time "clamp an out-of-range setting to a default" step
    (`FUN_00004c20`) dirties the buffer on every cold boot with blank
    config — a real producer this project hadn't enumerated. See
    [`docs/investigations/d-command-persistence-roundtrip.md`](../investigations/d-command-persistence-roundtrip.md).
    **Next**: determine whether `0x20004148+0xc` should be populated
    from a real, silicon-guaranteed SAMD51 register (a legitimate
    completion-bit-style fix) or an untraced driver-construction step —
    not fabricated — before attempting to observe a real flash write and
    the reboot/recovery half of this round trip.
27. ~~Resolve the page-size field and complete the `D` round trip~~ —
    done, Option B confirmed. Meet-in-the-middle found `0x20004148+0xc`
    is not stale/uninitialized firmware state at all: **`FUN_0000981c`**
    (previously mis-filed as opaque NVM plumbing) is the real constructor
    called fresh before every save, and it computes the field from
    **`NVMCTRL.PARAM`** (`0x41004008`) — a real, read-only SAMD51 register,
    confirmed via this project's own vendored SVD, whose `PSZ`-to-byte-size
    enumeration matches, byte-for-byte, a lookup table read directly out of
    the firmware image at flash `0x14000`. The harness's zero-behavior MMIO
    model returns `0` for this never-written hardware register, so the
    field always computed to `0` — not a missing firmware initializer.
    Modeled the one real value this exact, physically-confirmed part
    (ATSAMD51J19A, 512KB flash) guarantees (`PSZ=6`, `NVMP=0x400` ->
    `0x00060400`) via the existing `--mmio-force-bits` mechanism — no new
    tooling, no generic NVM emulator. A second stall on
    `NVMCTRL.INTFLAG.DONE` was the same bit `post-probe-main-loop.md`
    already modeled, just missing from this recipe. With both in place,
    the real erase (`FUN_000098f0`->`FUN_000098d8`) and real write
    (`FUN_0000984c`) both execute against flash `0x12000`, confirmed by a
    direct memory dump matching the RAM buffer's `D1234,|` value (`1234`)
    and marker (`0xDE`) byte-for-byte. A disclosed harness step (patching a
    firmware-image copy with those real, Unicorn-produced bytes, standing
    in for a power cycle) let a genuinely fresh boot — zero commands
    injected — recover the same value through the real
    `FUN_00004c20`/`FUN_000043ac` load path. See
    [`docs/investigations/nvm-param-and-full-roundtrip.md`](../investigations/nvm-param-and-full-roundtrip.md).
    **This closes the `0x12000` persistence investigation's core round
    trip** (items 22/24/25/26/27). Two minor loose ends remain, neither
    blocking: `FUN_000097a4`'s post-save dirty-clear behavior on a
    second, later save was not directly observed this pass, and the
    `D12345,|` (8-byte) dispatch-failure curiosity from (26) is still
    unchased.
28. ~~Reconnect `0x12000` persistence to the motor target~~ — the
    mapping and the real writer are found; concrete confirmation is
    attempted but incomplete, for a precisely-named reason. Pulling
    every caller of the shared config-write accessor (`FUN_0000977c`,
    via its thunk) from the Ghidra call graph — a broader method than
    (25)'s single-offset immediate scan — found `FUN_000043f0`: the
    exact write-back counterpart to `FUN_00004b64`'s already-known bulk
    load, persisting the whole 4-channel `0x20001b40` struct (persisted
    logical offsets `500`-`1651`) back into the flash-backed buffer.
    Its only caller is a previously undocumented ASCII command, `'+'`,
    reached via a tail-jumped region (`0x806c`) `FUN_00008258`'s
    decompile silently follows into — the same class of correction
    (22)'s `FUN_00007e2c`/`0x7cc0` case already established. Full
    disassembly, every address resolved directly against the compiled
    image: `'+'`'s mode`>50` branch calls **`FUN_00004ca8`** (chains
    `target = start + delta` across a channel's mode sub-records, the
    multi-record generalization of (22)'s `FUN_00004b24`) and
    **`FUN_000046c8`/`FUN_00004910`** (copies a **wire-supplied,
    unclamped signed delta** into the exact struct field `FUN_00007cc0`
    reads for mode `1`), then `FUN_000043f0` persists it. Arithmetically:
    a real `'+'` write followed by a real `G<channel>1<seq>|` should
    compute `distance = wire_delta` for `FUN_00006fd8` — closing (22)'s
    "why is this always `<=1`" question with a real, protocol-reachable
    producer, not a fabricated one. **Concrete delivery attempted, not
    completed**: found and fixed two real gaps (the disclosed `PA22`
    seed, held for an entire run, eventually trips (25)/(26)'s own
    already-documented "held past 1000 ticks -> save then an intentional
    halt" path before a later command can be processed — fixed by
    clearing it via a second injection at the same one-time main-loop
    trigger once homing no longer needs it; a `SERCOM`
    `SYNCBUSY`/`INTFLAG` bit-breadth gap for a real, newly-classified
    `CONFIRMED_ADAFRUIT_CORE` `SPIClass` construction, (17)'s narrower
    bits not being broad enough for it — broadened, same class of fix).
    Even so, reaching `'+'`'s own dispatch from a fresh boot costs far
    more instructions than any single-command injection in this
    project's history (real, finite, non-looping `SERCOM` device
    activity — PC visibly advances across attempts — that this
    project's existing boot-recipe calibration doesn't budget for). See
    [`docs/investigations/persistent-record-motor-target-mapping.md`](../investigations/persistent-record-motor-target-mapping.md).
    **Next**: an `--log-mmio` diagnostic pass across the window between
    the main-loop-entry trigger and `'+'`'s own dispatch, to name the
    specific real device-probe sequence responsible (the same method
    (18) used for the earlier radio-ID stall), then either model its one
    real completion condition or budget for its real cost explicitly —
    after which the originally planned `'+'`(delta)->`MC4`->`G...1...`
    chain should produce this project's first fully concrete, nonzero
    real motor move.
29. ~~Trace `'+'` backward through the Remote firmware~~ — done. A
    full-image disassembly scan for the literal `'+'` (0x2b) byte,
    cross-checked against every caller of the shared TX wrapper
    (`FUN_000058a8`, 22 direct callers) and its numeric-field encoder
    (`FUN_000043b0`, 4 callers), found exactly one real sender:
    **`FUN_000049c4`**, confirmed by disassembly to build the identical
    wire frame (28)'s AutoPilot-side analysis reconstructed field for
    field — including the `confirm1 == confirm2` invariant every real
    call site satisfies, and the same `+0xc`/`+0x10` delta-computation
    convention as the AutoPilot side (independent cross-confirmation,
    not just internal consistency within one side's own analysis). Its
    callers: the **Auto-Mode configuration screen state machine**
    (`FUN_0000e670`), three call sites each gated behind a real,
    blocking user-confirmation wait (`FUN_0000cd70`); and a **bulk
    "push all channels' stored config" path** inside the already-known
    `'S'` handler (`FUN_0000c440`, mode `0x62` — the same mode value
    that triggers both the AutoPilot-side position resync and the
    compute+persist branch). Correlating the Remote's own embedded UI
    strings (`"TEST A-B"`/`"TEST B-C"`/`"TEST C-D"`, `"DURATION"`,
    `"to rec C"`/`"to rec D"`, `"NO MOVEMENT"`) against the user
    manual's Auto Mode section (A/B/C/D points; duration/ramp/delay/
    loop segment parameters; persisted after power-off) gives a
    **probable**, not byte-exact-proven, mapping: `'+'` is sent when
    the user confirms/saves a programmed Auto Mode move segment.
    **Ruled out**: `'+'` is not host/service/internal-only — a real,
    disassembly-confirmed Remote sender exists. See
    [`docs/investigations/plus-command-remote-provenance.md`](../investigations/plus-command-remote-provenance.md).
    **Next**: trace what writes the Remote's own local per-channel
    record data before `'+'` sends it (almost certainly the jog-wheel-
    driven parameter-adjustment screens of `FUN_0000e670` itself, not
    directly confirmed); if exact manual-page correspondence is wanted,
    a concrete Unicorn run driving the jog wheel/button inputs and
    watching which screen text renders would settle (5)'s remaining
    "UNRESOLVED" row more precisely than static string correlation can.
30. ~~Close one concrete, end-to-end `'+'` -> motor-target -> `G` mode-1
    -> `FUN_00006fd8` distance path~~ — done, with a new reusable
    regression fixture. `tools/unicorn/virtual_link.py plus` (folded
    into `... all`) drives, entirely with real, unmodified firmware
    code and no full boot: the Remote's real `FUN_000049c4`, called
    with (28)'s own real `'S'`-handler bulk-push parameters
    (`confirm1=confirm2=1`, `param_4=0`, `mode=0x62` — the one mode
    value confirmed to cross AutoPilot's `>50` compute+persist
    threshold), produces `"+1,1,1,0,98,1,0,0,0,500,0,0|"`; AutoPilot's
    real handler computes and persists `target=500`; the Remote's real
    `0xb680` produces `"G010|"` (channel 0, type 1); AutoPilot's real
    `FUN_00007e2c` state machine (entered directly, twice — once per
    real internal state transition) resolves the same `target=500` and
    calls `FUN_00006fd8(channel=0, distance=500, const=0x1e, rate=0)`;
    `FUN_00006fd8`'s own real `>8` branch fires (move-committed flag
    `0x20002524[0]` observed `=1`), the opposite of (21)'s `distance=0`
    no-op result. **`500` is the same number throughout, never
    hand-patched into motor-target RAM** — carried from a disclosed
    Remote-side "already-recorded A->B segment" seed, through the
    Remote's own real delta computation, through AutoPilot's own real
    target computation, to `FUN_00006fd8`'s own real argument. Two
    disclosed, narrowly-scoped harness boundaries made this possible
    without the full boot (29)'s own concrete attempt was blocked by:
    the Remote-side seed (above), and directly seeding
    `FUN_00007e2c`'s own arm byte (`0x200025e1=2`) to the exact value a
    real `G` dispatch is independently confirmed (by disassembly, at
    `0x83de`) to set — bypassing the real MC4-unlocked main loop this
    state machine is normally driven from, without fabricating the
    distance itself. Also found and fixed, precisely: `FUN_000049c4`
    doesn't call the TX wrapper itself (its real callers do, via
    `0xb59c`); `--reg` values are hex, not decimal (a `28` meant to be
    length silently became `0x28`, corrupting a real dedup guard); `G`'s
    two digit fields are `(type, channel)` on the wire, not
    `(channel, type)`; and entering a real function directly with a
    fabricated `LR` needs a real, decodable, Thumb-bit-set return
    address, or `run_concrete.py`'s own `--stop-at` hook never gets a
    chance to fire before Unicorn's decoder crashes on it. See
    [`docs/investigations/plus-target-distance-roundtrip.md`](../investigations/plus-target-distance-roundtrip.md).
    **Next**: extend the same direct-entry technique to `FUN_00008e18`
    (the phase state machine) to chain this exact `500`-distance
    scenario all the way to a concretely observed real GPIO pulse —
    not reached this slice, since `FUN_00008e18` has its own additional,
    not-yet-resolved preconditions (a per-channel loop, further internal
    state) beyond what `FUN_00007e2c` needed.
