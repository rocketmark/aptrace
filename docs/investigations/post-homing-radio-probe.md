# Investigation: Characterizing the Post-Homing Init Sequence — a Real Radio-ID-Probe Dependency, Not a Timing Gap

**Question**: [`reset-handler-clock-init.md`](reset-handler-clock-init.md)
got a real, unmodified concrete run all the way from `Reset_Handler`
through real clock/peripheral init, a real SERCOM/DMA driver
constructor, and real homing — then found that reaching a directly
observable main-loop state (`FUN_00008960`) needed far more simulated
tick-time than a normal boot should, without any new stuck-status-bit
poll. This slice traces the post-homing call graph for real, function by
function, to determine whether that cost is genuinely the sum of finite
delays, or something else.

**Scope, per the task**: start from the real homing exit and follow the
*actual* call graph (not assume `FUN_00007770`/`FUN_00005d44` are the
whole story); for each significant delay/init call, identify the caller,
the requested delay/timeout, the timing source, the expected tick cost,
and compare against what Unicorn observes; add no new fake hardware
behavior unless the evidence proves a new status dependency; add no new
tooling beyond small diagnostics if even needed.

## Result

**Not a timing gap.** The apparent "excessive tick cost" from the prior
slice is fully explained: `FUN_00009464`'s real post-homing call chain
reaches `FUN_0000610c` — a **radio chip-ID probe** — second, immediately
after homing and *before* either `FUN_00007770` or `FUN_00005d44` are
ever reached. The probe reads a real peripheral register over SPI
(through the already-confirmed SERCOM/DMA driver) and requires the
response to equal a specific value. Under concrete execution with no
real chip attached, the read returns `0`, the check fails, and the
firmware takes its own real, intentional failure branch: an **infinite**
retry loop (`print status; delay(1000ms); repeat`), never returning.
This is a genuine external-hardware dependency — the task's category
(b), not (a) — correctly identified and **not** faked. No new
`run_concrete.py` capability was needed; the existing `--watch`
mechanism was sufficient to confirm the exact register value concretely.

## The real call graph from homing exit (not assumed)

`FUN_00009464`'s own post-homing sequence, already known from
`motor-timer-survey.md`, re-confirmed by re-reading its decompile:

```
FUN_00006968()   -- homing (already confirmed to exit via real timeout)
FUN_0000610c()   -- <-- reached second; this is where the real path stops
FUN_00006190()   -- never reached this pass
FUN_00004c20()   -- never reached this pass
FUN_00004328()   -- never reached this pass
FUN_00005d44()   -- never reached this pass (one of the task's "likely hotspots")
[3 word-zeros + 1 byte-write]
FUN_00007770()   -- never reached this pass (the other named "likely hotspot")
-- main loop: while(*flag) { ...; FUN_00008960(); FUN_00005dd0(); }
```

**`FUN_00007770` and `FUN_00005d44` are red herrings for this specific
question** — real, existing functions, but positioned *after*
`FUN_0000610c` in the real call order, so they are never reached while
`FUN_0000610c`'s own check keeps failing. Following the actual call
graph rather than the two named candidates was the right call per the
task's own instruction.

## `FUN_0000610c`: not a delay, a device probe with a real failure branch

Decompiled and disassembled:

```c
iVar3 = FUN_00009d88(DAT_617c, ...);   // DAT_617c = 0x20004160 -- the SERCOM/DMA
                                        // driver object reset-handler-clock-init.md
                                        // already confirmed constructs cleanly
if (iVar3 == 0) {
    FUN_00005d24();                    // one-time setup
    do {
        FUN_0000b258(status_line, msg);  // print/refresh a status line
        FUN_0000cd50(1000);              // real ~1-second delay
    } while (true);                      // <-- never exits
}
// success path: configure the device for real use, return normally
```

`FUN_00009d88(obj, ...)` is a real device bring-up routine:

```c
FUN_0000d300(obj->cs_pin, 1);  FUN_0000d388(obj->cs_pin, 1);      // CS pin config
if (obj->reset_pin != -1) {                                      // real reset pulse:
    FUN_0000d388(obj->reset_pin, 0); FUN_0000cd50(10);            //   low 10ms
    FUN_0000d388(obj->reset_pin, 1); FUN_0000cd50(10);            //   high 10ms
}
FUN_0000a1f4(obj->driver_handle);                                 // (the already-known
                                                                    //  DMA/SERCOM driver init)
iVar2 = FUN_000099c2(obj, 0x42);         // read register 0x42
if (iVar2 == 0x12) {                     // must equal 0x12 to proceed
    ... configure registers 0x8e, 0x8f, 0x8c, 0xa6, 0x11 ...
}
return iVar2 == 0x12;
```

`FUN_000099c2(obj, reg)` -> `FUN_00009984(obj, reg & 0x7f, 0)` -> a real
SPI transaction: CS low, `FUN_0000a000`/`FUN_0000a05c`/`FUN_0000a03c`
(the SERCOM driver's configure/transceive/deselect primitives, the same
driver `reset-handler-clock-init.md` got constructing cleanly), CS high
— sends the register address (bit 7 clear = read, a standard SPI
register-map convention), clocks out a dummy byte, and returns whatever
comes back on MISO.

**Register `0x42` read expected to equal `0x12` is the textbook
"RegVersion" chip-identification check used by the Semtech SX127x LoRa
transceiver family** (a check present in essentially every SX127x driver
library) — a strong pattern match, not an independently-verified fact
about this specific board's silicon. This lines up with, and gives a
concrete mechanism to, this project's own already-standing open note
that "the real transport peripheral is gated behind a runtime
driver-object pointer, not a literal address" and that "no LoRa/SPI
hardware [is] modeled" (`samd51-peripheral-mapping.md`,
`virtual-rf-link.md`) — this is very plausibly that same transport
peripheral's own startup identification step, reached for the first time
this pass because earlier slices never got this far into real boot.

## Concretely confirmed, not just inferred from the decompile

A `--watch 0x9dd4` (the `cmp r0,#0x12` instruction immediately after the
register-0x42 read) on the same working configuration from
`reset-handler-clock-init.md`:

```
instr 71250  pc=0x0000610c  (FUN_0000610c entered)
instr 74157  pc=0x00009dd4  r0=0x00000000   (the real ID-check comparison: 0, not 0x12)
```

`r0=0`, not `0x12` — the check genuinely fails under concrete execution,
confirmed at the exact instruction, not assumed from reading the
decompile. This is expected and correct: the harness has no real SPI
peripheral behind the SERCOM DATA register, so a read returns `0` (the
zero-behavior model's default), not a real chip's identification byte.

## Answering the task's four primary questions

1. **Is the current long runtime simply the sum of legitimate finite
   delays/init work?** No. It is one real, intentional **infinite**
   retry loop (`FUN_0000610c`'s failure branch), not an accumulation of
   finite steps.
2. **What is the expected total tick cost from homing exit to the main
   receive path?** Not computable as posed under current conditions —
   the real firmware itself does not reach the main receive path from
   here without a satisfied radio-ID check. Per-iteration cost of the
   loop actually taken: one `FUN_0000cd50(1000)` (~1000 tick-units) plus
   a status-line print, repeating forever — this fully explains the
   large, still-climbing tick counts and the "10 -> 9 -> 8 -> ..."-style
   countdown samples seen in `reset-handler-clock-init.md` (those were
   this same loop's per-iteration `cd50` countdown, sampled mid-count,
   not a stuck one-time boot delay).
3. **Is there any remaining unexpected stall or timing-model
   discrepancy?** No timing-model discrepancy. This is a genuine
   control-flow branch, correctly taken given a real (and correctly
   unfaked) external-device absence.
4. **What is the first reliable normal-runtime entry point after
   startup?** Not reachable yet: `FUN_00006190` would be the next real
   function *if* `FUN_0000610c`'s check passed, but that is gated on the
   radio-ID dependency above. This is the honest, current answer, not a
   forced one.

## Why this was not faked, per the task's evidence discipline

Returning `0x12` from the register-0x42 read would satisfy the check —
but that is exactly the "assumption we cannot justify" / fabricated
external-device-response category the task explicitly excludes, and
different in kind from the `OSC32KCTRL`/`OSCCTRL` completion bits
`reset-handler-clock-init.md` modeled: those were the MCU's *own*
internal state, guaranteed by the chip's own documented behavior once
its own preceding register write took effect. A chip-ID byte from a
*different, external* physical device is not something any internal
MCU behavior guarantees — it depends on a real chip actually being
present, powered, and wired correctly, which this concrete-execution
harness has no way to establish and no evidence for either way. Per the
task, this is identified and reported, not patched around.

## Confirmed vs. modeled — evidence discipline

| Claim | Status |
|---|---|
| Post-homing call order is `FUN_0000610c` before `FUN_00007770`/`FUN_00005d44` | **Confirmed** (static, re-read from `FUN_00009464`'s decompile) |
| `FUN_0000610c`'s failure branch is an infinite loop, not a finite delay | **Confirmed** (static disassembly: `do{...}while(true)`, no exit) |
| `FUN_00009d88` performs a real SPI register read via the already-confirmed SERCOM/DMA driver | **Confirmed** (static, traced through `FUN_000099c2`/`FUN_00009984`/`FUN_0000a05c`) |
| The read genuinely returns `0`, not `0x12`, under concrete execution | **Confirmed concretely** (`--watch 0x9dd4`, `r0=0x00000000`) |
| Register `0x42`/expected `0x12` is the SX127x `RegVersion` check | **Pattern match, not independently verified against this board's actual silicon** — flagged as such, not asserted as fact |
| This is the same "unmodeled transport peripheral" boundary already on record elsewhere in the project | **Plausible connection**, not proven identical — both are real, disclosed boundaries around the same physical subsystem (SPI-attached radio), not necessarily the exact same code path |

## Evidence level

Level 1 (static) for the call-graph tracing and the SPI-transaction
shape. Level 2 (concrete, Unicorn) for the exact failing comparison,
directly observed via `--watch`, not inferred. No new tooling was
needed — the existing `--watch` facility was sufficient to settle the
question precisely, consistent with the task's "use existing mechanisms
as measurement tools, not a shortcut."

## Next step

This is a real hardware/external-device boundary, matching the project's
established practice of naming such boundaries rather than modeling
past them (see `virtual-rf-link.md`'s own "no LoRa/SPI hardware
modeled" note). Two honest options for a future slice, neither attempted
here:

1. **Determine whether this check is skippable via a different, real
   code path** (e.g., a debug/bypass flag, a different boot mode, or
   whether real hardware boot logs/behavior — if ever available —
   confirm this really always requires a populated radio module). Purely
   a static question, no new execution needed.
2. **If a specific slice's goal genuinely requires reaching the main
   loop**, the narrowest honest option would be a single, clearly
   disclosed `--seed-mem` on the SERCOM DATA register to return `0x12`
   for this one read — explicitly labeled "assumed radio module present
   and responding with its expected ID, not observed," a materially
   different and weaker evidence class than every `--mmio-force-bits`
   use in `reset-handler-clock-init.md`, and only worth doing if a task
   explicitly asks to see what lies beyond this specific check.
