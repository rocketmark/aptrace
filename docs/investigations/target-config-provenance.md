# Investigation: Where the Motor Target/Position Config Comes From, and Why It's Always ≤1 Unit

**Question**: [`mc4-transition.md`](mc4-transition.md) reached `FUN_00006fd8`
(the real move-commit function) for the first time, with `distance=0`,
and flagged the per-channel-per-mode config struct at `0x20001b40` (valid
at `+0x44`, target at `+0x10`/`+0xc`) as the next thing to trace. This
slice: find the real producer of that struct, and use it — not seeded
state — to try to reach a genuine `|distance| > 8` move.

**Scope**: concrete Unicorn plus disassembly (one real decompiler-vs-
disassembly correction below, per this project's standing practice). No
seeded distance, no seeded `0x20001b14`, no seeded TC/GPIO state. The
"type" (mode) digit exercised below is an *existing* documented field of
the already-real `G`/manual-move command — trying its other legal values
is not inventing a new command or state.

## Result

**Found, concretely, exactly why every reachable path currently produces
`|distance| ≤ 1`, never `> 8`.** The `0x20001b40` struct is populated,
once per boot (and re-populated, harmlessly, on each `G`/`MC4`-triggered
reload), from a **compiled-in default-configuration flash blob at
address `0x12000`** — which, in *this* firmware image, is entirely
`0x00`. The loader's own real fallback logic (a genuine, disassembly-
confirmed blank-detection check) then fills nearly the whole struct with
`0xFF`. A separate, real, `.data`-driven one-time step immediately
overwrites each channel's mode-0 target with its *own current tracked
position* (`0x20002064[channel]`, itself cold-zero) — a real "no move
yet" default, not a bug. Exhaustively trying every "type" digit (`0`-`9`)
of a real `G` command after `MC4` gives exactly two outcomes: mode `0`
→ `distance=0`; modes `1`-`9` → `distance=-1` (from the untouched
blank-fill pattern). Neither exceeds `FUN_00006fd8`'s `8`-unit
real-move threshold. **This is a real external-data/provisioning
boundary — the same evidence class as the unanswered radio-ID chip —
not a missing mechanism this harness could complete without fabricating
motor-position data.**

## A decompiler-vs-disassembly correction, made before trusting anything downstream

`mc4-transition.md` (and this investigation's own first pass) initially
mis-attributed which literal is the struct's *base pointer* versus its
*destination array* inside `FUN_00007e2c`'s tail body, because the
`APTraceDecompileFunctions` output for address `0x7e2c` silently follows
an unconditional tail jump (`0x7e2c`-`0x7e38` is a 6-instruction gate:
`if (*0x200025e1==2) goto 0x7cc0; else return;`) and presents `0x7cc0`'s
real body as if it were `FUN_00007e2c`'s own straight-line code, with no
indication the addresses jumped. Disassembling `0x7cc0` directly (not
trusting the decompile's variable names) resolved it: the struct base is
**`DAT_00007dfc = 0x20001b40`** (matching `mc4-transition.md`'s claim,
now confirmed at the instruction level, not just the decompile level);
`DAT_00007e00 = 0x2000201c` is a *different*, small "this cycle's
resolved target" array, one `int` per channel, that state 0 writes into
and state 1 reads back out of — not the config struct itself. This is
the same category of correction this project has made before
(`i-command-motor-chain.md`, `channel-busy-gate-search.md`,
`reset-handler-clock-init.md`): disassembly is the tie-breaker whenever a
decompile's variable reuse (or, here, a silent tail-jump) makes the real
code ambiguous.

## 1. What writes/populates `0x20001b40`'s per-channel config?

**`FUN_00004b64`**, disassembled in full (`0x4b64`-`0x4bfe`). Two real
steps, confirmed by a true memory watchpoint
(`--watch-mem-write`), not inferred:

**Step A — bulk load, all 4 channels, byte for byte** (`0x4b78`-`0x4b88`):
a tight loop calling `FUN_00009768(0x20003145, k)` for `k = 500..1651`
(1152 = 4 × `0x120` iterations) and storing each returned byte
sequentially into `0x20001b40[0..1151]` — i.e. the *entire* 4-channel
struct array, one byte per call.

**Step B — per-channel resync** (`0x4bde`-`0x4bfe`): for each channel
where a real, `.data`-initialized flag (`0x20000134[channel]`, confirmed
`.data`-initialized to `1,1,1,1` at Reset_Handler's own `.data`-copy
stage — a real compiled-in fact, not `.bss`) is set and a companion byte
(`0x20001fd6[channel]`, cold `.bss` `0`) is clear, calls
**`FUN_00004b24(channel)`** then clears the flag (`0x20000134[channel] =
0`) — **a one-shot, boot-time-only step**: confirmed concretely (see
below) that this flag never gets set again in any run this slice
performed, so the resync cannot re-fire later in the same session.

`FUN_00004b64` itself is called from two real places: `FUN_00009464`'s
boot chain (already known from `channel-busy-gate-search.md`) and
`FUN_00008258`'s `G`-command handler (`0x83da`, already noted in
`g-command-motor-subsystem-unlock.md` as "a real, but not-yet-modeled
callee" — now fully characterized).

## 2. Where do the bulk-loaded bytes (Step A) actually come from?

`FUN_00009768(base=0x20003145, k)` returns `base[k+1]`, lazily calling
**`FUN_00009724(base)`** first if `base[0]==0` (a one-time "is this
buffer initialized" gate). `FUN_00009724`, disassembled in full:

```
FUN_0000990e(driver_obj=0x20004148,
             src = *(driver_obj+0x10),   // = 0x00012000, confirmed by register capture
             dest = a 4104-byte stack buffer,
             len = *(driver_obj+0x14));  // = 0x1001
```

`FUN_0000990e` is a plain wrapper around `FUN_0000e648` — a byte-copy
loop, **not** a peripheral/driver call despite living in an object-like
structure at `0x20004148` (adjacent to, but distinct from, the
already-flagged, not-yet-fully-characterized TX/radio driver object at
`0x20004160` in `post-homing-radio-probe.md` — a coincidence of nearby
addresses, not the same object: this one's "source" field is a plain
flash address, confirmed by direct register capture, `r1=0x00012000` at
`FUN_0000990e`'s entry). **This is a real, compiled-in default-
configuration blob at flash address `0x12000`** — read directly from the
loaded firmware image, ground truth, no modeling needed:

```
$ python3 -c "print(open('research/firmware/originals/firmware_autopilot868.bin','rb').read()[0xe000:0xe000+4097].count(0))"
4097
```

**Every one of the 4097 bytes at flash `0x12000` (file offset `0xE000`,
well within the 70,768-byte image) is `0x00`.** Confirmed independently
by Unicorn's own mapped memory (`--dump-mem 0x12000:64`) matching the
raw file exactly.

`FUN_00009724`'s own disassembly then does the real, disassembly-
confirmed fallback: copies that (all-zero) blob into the persistent
buffer (`0x20003145[1..0x1001]`), checks the trailing byte
(`0x20003145[0x1001]`, itself `0` since the source was all-zero), and —
**because that "has this been provisioned" marker reads zero** — calls
`FUN_0000e664(0x20003146, 0xFF, 0x1000)`, explicitly overwriting the
*entire* just-copied region with `0xFF`. (A genuine ARM/void-return
subtlety confirmed by disassembling `FUN_0000e648`/`FUN_0000e664`
directly, not trusted from the decompile: `FUN_0000e648` never writes
`r0`, so the fill's destination is the *caller's own* unmodified `r0` —
`0x20003146`, the start of the just-copied region — not a separate
"extra" area past it, as the decompiled pseudo-C's invented `uVar1`
return value would suggest if taken at face value.)

**This is the real firmware's own "blank/never-configured EEPROM"
handling** — not a placeholder this harness invented. Concretely
confirmed, via `--watch-mem-write`, that this fill lands on *all four*
channels' struct regions identically (`0x20001b50`/`0x1c70`/`0x1d90`/
`0x1eb0` and their `+0x44` validity bytes all become `0xFF` at
instructions 3,752,240-3,765,245 in a plain-boot run).

## 3. How channel/mode select the correct instance

Confirmed by disassembly of `FUN_00007cc0` (the real tail-jumped body,
see the correction above): `base(0x20001b40) + channel*0x120` selects
the channel; for the "type" (mode) digit `0`, the read is at
`+0x44`(valid)/`+0x10`(target) directly; for mode `N>0`, at
`base + channel*0x120 + (N-1)*0x48 + 0x44`(valid)/`+0xc`(target) — a
sub-array of `0x48`-byte records inside each channel's `0x120`-byte
block. Confirmed uniform across channels: the `--watch-mem-write` trace
shows identical treatment (bulk load, then resync) for `0x20001b50`
(ch0), `0x20001c70` (ch1), `0x20001d90` (ch2), `0x20001eb0` (ch3), each
gated by its own `0x20000134[channel]` byte — all four `.data`-
initialized to `1` identically, so no channel is treated specially by
this mechanism.

## 4. The validity/enable condition, and why it's misleadingly "true"

`+0x44` (or `+(mode-1)*0x48+0x44`) must be nonzero. Under this firmware
image's real, disassembly-confirmed blank-config fallback, that byte
lands on `0xFF` — **truthy**, so every mode's config reads as "valid"
even though the *values* behind it are the blank-fill sentinel, not real
provisioned data. This is why `mc4-transition.md`'s observation
("`0x20001b84` reads `0xff`... disclosed as uninitialized-pattern RAM")
was directionally right but incomplete: it is not simply cold/unwritten
RAM, it is a *deliberately, explicitly written* `0xFF` sentinel, from a
real, traced code path — a stronger and more precise claim than "cold
RAM," now fully evidenced end to end.

## 5. `FUN_00004b24`'s resync: the mode-0 target becomes "wherever the motor already is"

`FUN_00004b24(channel)`, disassembled and confirmed via
`--watch-mem-write` (`pc=0x4b3a`, called from `FUN_00004b64` at
`0x4bec`/`lr=0x4bf1`):

```
target(+0x10) = *(0x20002064 + channel*4);      // = current tracked position
computed(+0xc) = target(+0x10) + delta(+0x00);   // this record's own "+0x00" field
```

`0x20002064` is the same live position counter `motor-timer-survey.md`
already identified as the event-15/`I`-command result value. Since it
is cold-zero (no real move has ever completed), `FUN_00004b24` writes
**`target(+0x10) = 0`** for every channel — concretely confirmed,
`--watch-mem-write`, all four channels, immediately after the boot-time
blank-fill (instructions 3,769,355/3,791,424/3,813,397/3,835,370). This
is a real, deliberate "no commanded move yet — mode 0's target defaults
to the current position" normalization, not a bug and not a missing
initializer. Because `0x20000134[channel]` is cleared to `0` right after
(confirmed, same trace), this resync is genuinely **one-shot per boot**
— a second call to `FUN_00004b64` (e.g. from a later `G` command) redoes
Step A (the blank byte-load) but *not* this resync, since its gate is
now closed.

The `+0xc` field (mode `1`'s target, same record) becomes `target + delta
= 0 + (-1) = -1`, since `delta(+0x00)` is untouched by the resync and
still holds the blank-fill's `0xFF` pattern.

## 6. Concretely exercising the real path: every `G` "type" digit tried

Real `MC4` (unlock) then real `G0<type>0|` (properly sequenced, per
`mc4-transition.md`'s two-injection technique), for `type = 0..9`,
`--watch 0x6fd8` capturing the real register arguments:

| Type digit | `FUN_00006fd8`'s `distance` (r2) | Source |
|---|---|---|
| `0` | `0x00000000` | mode-0 target (`+0x10`), resynced to current position (`0`) |
| `1`-`9` | `0xFFFFFFFF` (`-1`) | mode-`N` target (`+0xc` of the addressed record), the untouched blank-fill pattern |

**No type digit produces `|distance| > 8`.** `FUN_00006fd8`'s own branch
(`if (8 < abs(distance))`) is never taken by any value this firmware's
real, currently-loaded configuration can produce through this command.
This is not a harness limitation — every one of these runs used the
real parser, the real dispatcher, the real config-lookup code, and the
real register-captured call arguments; only the *source data* (the
blank flash blob) is unprovisioned.

## Answering the five producer questions

1. **What writes/populates this config?** `FUN_00004b64` (two real
   steps: bulk load from a lazily-initialized RAM staging buffer, then a
   one-shot per-channel resync of the mode-0 target to current position).
2. **What command/state transition supplies the target?** The bulk load
   is *not* protocol-driven — it is a real, generic "reload config from
   the persisted blob" step, run at boot and again on any `G` (and
   presumably `MC4`, given the parallel bulk-config-loader role
   `channel-busy-gate-search.md` already flagged for `FUN_00004c20`, not
   re-traced this pass). The specific *value* it supplies traces to a
   compiled-in flash blob (`0x12000`) that is blank in this image.
3. **How does channel/mode select the instance?** Plain, disassembly-
   confirmed arithmetic: `base + channel*0x120 [+ (mode-1)*0x48]` — no
   ambiguity, uniform across all 4 channels.
4. **What validity/enable condition makes the value live?** A nonzero
   byte at `+0x44`/`+(mode-1)*0x48+0x44` — which the real blank-config
   fallback sets to `0xFF` (truthy) for every mode of every channel, so
   in this firmware image's current state, *every* mode reads as
   "valid," even though the values are sentinel filler.
5. **Protocol input, persistent config, or another runtime subsystem?**
   **Persistent config** — a real, compiled-in default-configuration
   blob meant to be read once and normalized against live position at
   boot. In *this* firmware image, that blob was never provisioned with
   real motor-position data (it is genuinely all-zero), so the firmware's
   own real fallback (blank-fill + position-resync) is what a
   fresh/uncommissioned unit would concretely do — a real external-
   data/provisioning boundary, the same evidence class as the unanswered
   radio-ID chip in `post-homing-radio-probe.md`, not a gap this harness
   could close without fabricating motor-position data it has no way to
   know.

## Before/after model

**BEFORE** any config reload: `0x20001b40`'s struct is `.bss`-zero
(cold boot).

**CONFIG-LOAD TRANSITION** (`FUN_00004b64`, at boot and on each `G`):
bulk-loads all 4 channels' `0x120`-byte blocks from a lazily-initialized
staging buffer (`FUN_00009724`, sourced from flash `0x12000` — all-zero
in this image); the loader's own blank-detection fallback then
overwrites that whole region with `0xFF`; a one-shot per-channel resync
(`FUN_00004b24`, gated on a `.data`-initialized flag, fires exactly once
across the runs performed) overwrites each channel's mode-0 target
(`+0x10`) with that channel's live current position (`0`, cold).

**AFTER**: mode-0 lookups return `target=0` (→ `distance=0`); mode-`N>0`
lookups return the untouched blank-fill pattern (`target=-1` →
`distance=-1`). Both are real, concretely observed, register-captured
outcomes of the real `FUN_00007cc0`/`FUN_00006fd8` path — neither
crosses the `8`-unit real-move threshold.

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| Struct base is `0x20001b40` (not `0x2000201c`, an earlier same-session misreading corrected by disassembly) | **Confirmed** (disassembly of the real, tail-jumped `0x7cc0` body) |
| `FUN_00004b64` bulk-loads all 4 channels from a lazily-initialized buffer, then resyncs mode-0 target to current position, once per boot | **Confirmed concretely** (`--watch-mem-write`, all 4 channels, exact PCs/LRs captured) |
| The staging buffer's source is flash `0x12000`, and that blob is genuinely all-zero in this firmware image | **Confirmed** (direct file read + Unicorn `--dump-mem`, not inferred) |
| The blank-fill (`0xFF`) and position-resync (`0`) are real, disassembly-confirmed fallback/normalization logic, not harness artifacts | **Confirmed** (full disassembly of `FUN_00009724`/`FUN_0000e648`/`FUN_0000e664`) |
| Every `G` "type" digit `0`-`9` gives `distance` of exactly `0` or `-1`, never `>8` in magnitude | **Confirmed concretely** (10 real, register-captured `FUN_00006fd8` calls) |
| Whether `LL1`/`LL2` or another not-yet-tried command can write a real, large target into this struct (or advance `0x20002064` directly) | **Not established, and not chased this slice** — the next concrete, non-fuzzing candidate, per the task's own scope |
| Whether a real, physically-provisioned unit's flash blob at `0x12000` would contain meaningful non-blank data | **Out of scope** — an external-data boundary, same evidence class as the radio-ID chip |

## Evidence level

Level 2 (concrete, Unicorn) for every write/value claim in sections 1-6,
each backed by a true `--watch-mem-write` hit with PC/LR or a direct
register capture at the real call site. Level 1 (static) for the flash
blob's content (read directly from the firmware image, the strongest
possible evidence tier for a compiled-in constant — no execution
needed). One decompiler-vs-disassembly correction, resolved the same way
this project always resolves them: read the real instructions.

## Next step

Per the task's explicit "identify the exact remaining producer/state
dependency" framing: **this firmware image's compiled-in motor-position
default configuration is blank**, and the one mechanism this slice
found for writing a *meaningful* nonzero target (`FUN_00004b24`'s
position-resync) only ever writes `0` while the tracked position itself
is `0` — a real chicken-and-egg for an uncommissioned unit. Two
independent, narrower continuations, neither started this slice:

1. **Try `LL1|`/`LL2|`** (the "first/second limit workflow" from
   `command-inventory.md`, unresolved semantics) — the most plausible
   remaining *real* command for advancing `0x20002064[channel]` (via a
   real limit-switch/homing sequence) or writing a new target directly,
   without fabricating data.
2. **Trace `FUN_00004c20`** (the sibling bulk-config-loader
   `channel-busy-gate-search.md` already named alongside `FUN_00004b64`,
   not re-examined this pass) in case it writes a *different* field this
   investigation didn't check.
