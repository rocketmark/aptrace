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
