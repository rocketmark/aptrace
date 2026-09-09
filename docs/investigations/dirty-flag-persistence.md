# Investigation: The Real `0x1002` Dirty Byte, Its Producers, and a Protocol-Reachable Write Path

**Question**: `standard-library-provenance.md` found a real, previously
unexamined persistence path (`FUN_0000449c` -> `FUN_000097a4` -> the
standard NVM erase/write primitives) gated on a byte at logical offset
`+0x1002` inside the persisted config buffer. Find the exact address,
every reader/writer (including computed ones ordinary xrefs would
miss), what sets and clears it, whether the save decision is genuinely
channel-0-only, and what `FUN_0000449c` actually hands to the save
routine — **without exercising any of it concretely yet.**

**Scope**: static only (disassembly + a full-image instruction scan for
immediates that never appear in the literal pool, since `+0x1002`
exceeds Thumb-2's immediate-offset encoding range and must be
materialized via `movw` instead — exactly the "computed store ordinary
xrefs might miss" case the task warned about). The already-classified
NVM/`memcpy` primitives (`FUN_0000e648`, `FUN_000098f0`/`FUN_0000984c`/
`FUN_0000981c`) were peeked into only once, specifically to answer
"does saving clear the dirty flag" — otherwise treated as known plumbing
per `standard-library-provenance.md`'s classification.

## Result

**Found the exact byte, its one true producer, its one (seemingly
unreached) clearer, and a real, protocol-reachable command (`D<value>|`)
that writes through the same producer — closing the loop the task asked
about.** The dirty flag is not set by a channel-0-specific event at the
low level at all: it is set generically, by a single shared "write one
byte into the persisted config buffer, only if the value actually
changes" accessor, used by several callers including a plain ASCII
command. `0x12000` is confirmed, by this pass's own evidence, to be
**real, firmware-owned, round-trip read/write persistent storage** — not
an external-provisioning boundary, exactly as the task cautioned not to
assume.

## 1. Exact RAM address of the dirty byte

`0x20003145 + 0x1002 = **0x20004147**`. Confirmed by disassembly of
`FUN_000097a4` (`movw r3,#0x1002; ldrb r3,[r4,r3]` — a *register*-offset
load, not an immediate one, because `0x1002` exceeds the 12-bit
unsigned immediate range Thumb-2's `ldrb.w` encoding allows (max
`0xFFF`); the compiler had no choice but to materialize the offset in a
register via `movw`). This is why a plain literal-pool scan for
`0x20004147` (the previous slice's first attempt) finds **zero** hits —
the constant that matters is the 16-bit immediate `0x1002` embedded
directly in a `movw` instruction's own encoding, never placed in the
flash literal pool at all.

## 2. What values can it take

A single byte (`strb`/`ldrb` throughout), boolean: `0` or `1`.

## 3. Every reader and writer (a full-image `movw #0x1002` scan, not xrefs)

A plain literal-pool xref search (as used for every other address in
this project) **cannot find this byte** — it must be found by
disassembling the whole image and grepping for the immediate itself, not
for a data reference to a computed address. Doing exactly that (a full
`0x4000`-`0x15470` disassembly, grepped for `#0x1002` and `#0x1001`)
finds **three** sites, all in one small neighborhood (`0x9768`-`0x9810`,
already known to be the config-buffer read/write accessor family):

| Address | Instruction | Function | Role |
|---|---|---|---|
| `0x9794` | `movw.ne r3,#0x1002` (conditional, inside an `itttt ne` block) | `FUN_0000977c` | **The setter** — writes `1` |
| `0x97b6` | `movw r3,#0x1002` | `FUN_000097a4` | Reader — the save-if-dirty gate |
| `0x9804` | `movw r1,#0x1002` | `FUN_000097f4` | **A clearer** — writes `0` |

No other function anywhere in the image references this offset, by
`movw` or otherwise. This is now as exhaustive a search as the
literal-pool method used elsewhere: a full-image scan for the exact
16-bit immediate, not a sample.

## 4. What sets it, and what event causes that

**`FUN_0000977c(buffer, offset, new_value)`** — the shared "write one
byte into the persisted config buffer" accessor, disassembled in full:

```asm
ldrb r3,[r0,#0]              ; buffer[0] -- "is this buffer loaded" flag
push {r4,r5,r6,lr}
r5=buffer; r4=offset; r6=new_value
cbnz r3,0x978c                ; skip lazy-init if already loaded
bl FUN_00009724                ; lazy-load from the flash blob (0x12000), as in target-config-provenance.md
0x978c:
r1 = buffer + offset
r3 = *(r1+1)                   ; CURRENT stored byte at this logical offset
cmp r3, r6                     ; compare current vs. new
itttt ne                       ; **only if the value is actually changing:**
    r3 = 0x1002 (movw.ne)
    r2 = 1
    buffer[r3] = 1              ; <-- dirty := 1
    *(r1+1) = r6                 ; <-- THEN actually store the new byte
pop {r4,r5,r6,pc}
```

**This is the answer to "what application event causes the set": there
is no single event — it is set by *any* successful write through this
one shared accessor, whenever the new byte differs from what's already
stored.** If the value is unchanged, **neither the dirty flag nor the
byte itself is written at all** — a real, deliberate "don't dirty (or
wear flash) on a no-op write" optimization, not a coincidence.

Confirmed callers of this accessor (the ones that can actually dirty the
buffer):

- **`FUN_00004370(offset, value32)`** — writes a 32-bit value
  byte-by-byte (4 calls to `FUN_0000977c`, one per byte, big-endian
  order) at a caller-supplied logical offset. **Reached from a real
  ASCII command**: `FUN_00008258`'s `'D'` branch (`packet[0]=='D'`)
  parses a numeric field from the packet (`FUN_0000799c`, the same
  field parser `MC4`/`G` use) and calls `FUN_00004370(0x15,
  parsed_value)` — then, in the same handler, tail-calls the write
  accessor once more directly: `thunk_FUN_0000977c(buffer, 0x19, 0xDE)`,
  writing a literal marker byte `0xDE` at logical offset `0x19`. **A
  real, protocol-reachable, single-command write path into the exact
  same persisted-config buffer the `0x12000`-backed read path
  (`target-config-provenance.md`) consumes** — not concretely delivered
  this pass (static disassembly only, per the task's explicit "don't
  exercise the flash write yet").
- **`FUN_00005dd0`** (called every real main-loop iteration) — writes a
  literal `0` at logical offset `0x14` directly, under one specific
  branch: a sustained-then-released digital input on pin index `1`
  (`FUN_0000d3dc(1)`, a real `digitalRead()`-shaped call — see
  `standard-library-provenance.md`'s classification of the sibling
  `digitalWrite`-shaped helper; the *physical* pin is not resolved this
  pass, per the task's explicit "don't jump to connector identity yet")
  held long enough to cross a **1000-tick** threshold (triggers
  `FUN_0000449c` directly, plus a display/delay sequence, then an
  intentional infinite halt — a real "hold this input to save & power
  down" shape) or, on release, a separate **20000-tick** elapsed check
  (writes offset `0x14=0`, then also calls `FUN_0000449c`).

**Confirmed non-writers of this specific byte**: `FUN_00004b64` and
`FUN_00004c20` (both call only the *read* accessor, `FUN_00009768`/
`FUN_000043ac`) — they consume the buffer but never dirty it.

## 5. What sets `D<value>|`'s marker (`0xDE` at offset `0x19`) up for

`FUN_00004c20` (called once, from the boot chain, alongside
`FUN_00004b64` — already known from `channel-busy-gate-search.md`)
reads offset `0x19` and, **only if it equals `0xDE`**, reads the 32-bit
value back from offset `0x15` (`FUN_000043ac(0x15)`) into a RAM
variable (`0x200029d4`). This is a complete, coherent, real
"write-a-value-then-remember-it-was-really-set" pattern spanning a boot
(read) and a runtime command (write) — not two unrelated facts.

## 6. What clears the dirty flag, and when

**`FUN_000097f4`** is the only code anywhere in the image that writes
`0` to `+0x1002`:

```asm
ldr r1,[=0x00012000]           ; the real flash destination, disclosed directly
ldr r0,[=0x20004148]           ; the driver object (see target-config-provenance.md)
movw r2,#0x1001                ; length = 4097 bytes
bl FUN_0000981c                 ; unconditional raw NVM write (no dirty check!)
ldr r3,[=0x20003145]           ; the buffer
movw r1,#0x1002
strb r2(=0),[r3,r1]              ; dirty := 0
strb r2(=0),[r3,#0]              ; "loaded" flag := 0  (forces a re-load from flash next touch)
```

**Two real asymmetries, confirmed by disassembly, not assumed**:

- **`FUN_000097a4` (the save-if-dirty path `FUN_0000449c` actually
  calls) never clears `+0x1002` after saving.** Once dirtied, it stays
  dirty for the rest of the session unless something else clears it —
  meaning every subsequent qualifying completion event
  (`FUN_00005be8`/`FUN_00005dd0`) will redundantly re-erase-and-rewrite
  the same, now-unchanged data. Reported exactly as observed: this may
  be intentional (simpler code, an accepted redundant-write cost) or an
  oversight — the disassembly doesn't say which, and no further
  evidence bears on it.
- **`FUN_000097f4` (the only clearer) has no confirmed caller anywhere
  in this image.** Checked two ways: the calls graph (zero hits) and a
  full-image scan for `0x97f4` appearing as *any* branch/call operand,
  literal or tail-jump (zero hits — this rules out the same
  "tail-jump target Ghidra's calls-list misses" pattern that explained
  `FUN_00007e2c`'s and `0x94e4`'s targets in earlier slices). It may be
  reached via an indirect function-pointer table this static pass
  can't see, or it may be effectively dead/vestigial code in this
  firmware build. **Not resolved — reported as a real open question,
  not guessed at either way.**
- The only *other* thing that plausibly clears `0x20004147` is a cold
  boot: it falls inside `Reset_Handler`'s own `.bss`-zero range
  (`0x20000830`-`0x2000531c`, already documented), so it reads `0` on
  every power-up regardless of `FUN_000097f4`'s reachability.

## 7. Is the persistence decision channel-0-only or global?

**Both, at different layers — confirmed, not conflated:**

- **The dirty flag and the persisted buffer are genuinely global,
  covering all four channels' config** (the same `0x20003145`-based
  blob `FUN_00004b64` loads into all four `0x120`-byte struct blocks,
  per `target-config-provenance.md`). Nothing about `FUN_0000977c`'s
  change-detection logic is channel-specific — any write through it, by
  any caller, dirties the one shared flag.
- **The save *trigger* really is asymmetric toward channel 0** — but
  this is an already-documented, real firmware asymmetry, not something
  this investigation introduces: `FUN_00005be8` (one of `FUN_0000449c`'s
  three call sites) is **TC0's own dedicated ISR** (already established
  in `channel-busy-gate-search.md` as "TC0's own, channel-0-only ISR
  ramp logic"), hard-coding channel `0` throughout its own body
  (`FUN_00005898(0)`, `FUN_00005958(0)`) — it is not a generic,
  per-channel-parameterized handler that happens to run for channel 0;
  it is *the* real ISR wired specifically to TC0's IRQ vector. Channels
  1-3's own TC ISRs (not re-examined this pass) are already known,
  independently, to lack this extra completion-and-persist logic.
  `FUN_0000449c`'s *other* two call sites, inside `FUN_00005dd0`, are
  **not channel-specific at all** — they're gated on a digital-input
  hold-time and an elapsed-tick timeout, global conditions unrelated to
  any particular motor channel.

**So: "channel 0 is merely where a shared save checkpoint happens" is
the more accurate framing for two of the three trigger sites, and "a
real, pre-existing channel-0-specific ISR asymmetry" is the accurate
framing for the third** — both confirmed, neither guessed.

## 8. What `FUN_0000449c` hands to `FUN_000097a4`, and what flash range that reaches

```
FUN_0000449c(void):
  FUN_0000a84a(0x200020a0, 0)   ; 4 display-object "clear/reset" calls
  FUN_0000a84a(0x2000213c, 0)     (LIKELY_THIRD_PARTY_LIBRARY per
  FUN_0000a84a(0x200021d8, 0)      standard-library-provenance.md --
  FUN_0000a84a(0x20002274, 0)      not re-examined here)
  FUN_000097a4(0x20003145)      ; <-- the ENTIRE persisted buffer base,
                                       not a smaller/partial slice
  FUN_0000cd50(100)              ; delay(100)
  FUN_0000d388(0, 1, ...)         ; a channel-0 GPIO pulse (already-known helper)
```

`FUN_0000449c` passes the **whole buffer** (`0x20003145`, the same base
every other reader/writer uses) to `FUN_000097a4` — not a per-channel
subset. `FUN_000097a4` in turn, if dirty, erases and rewrites using
`*(driver_obj+0x10)`/`*(driver_obj+0x14)` (address/length fields on the
object at `0x20004148`) — the **same object and same fields**
`FUN_00009724` reads on the load side, and the **same flash address
`0x00012000`** `FUN_000097f4` uses explicitly for its own unconditional
save. This directly confirms: **the write path targets the identical
flash region the `0x12000`-backed read path consumes.** There is no
partial-write, different-region, or per-channel-file scheme — one
buffer, one flash region, one dirty flag, covering all four channels'
config together.

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| Dirty byte address = `0x20004147` | **Confirmed** (disassembly, register-offset `movw` pattern explains why literal-pool scans miss it) |
| `FUN_0000977c` is the sole setter, gated on real value-change detection | **Confirmed** (full disassembly, full-image `movw #0x1002` scan — exhaustive) |
| `D<value>|` is a real, protocol-reachable writer of this buffer (offsets `0x15`-`0x19`) | **Confirmed statically** (disassembly of `FUN_00008258`'s `'D'` branch + `FUN_00004370`); **not delivered concretely this pass** |
| `FUN_00005dd0`'s two triggers are a real digital-input hold and an elapsed-tick timeout | **Confirmed statically**; the specific physical pin/purpose is **not established** (deliberately not chased, per task scope) |
| `FUN_000097a4` never clears the dirty flag after saving | **Confirmed** (disassembly) — whether this is intentional is **unresolved** |
| `FUN_000097f4` is the only clearer, and has no found caller | **Confirmed** (calls graph + full-image branch-target scan, both zero hits) — whether it's genuinely unreachable or reached indirectly is **unresolved** |
| Cold boot implicitly clears the flag via `.bss` zero | **Confirmed** (address falls in the already-documented `.bss` range) |
| The save trigger is channel-0-asymmetric via a real, pre-existing TC0 ISR asymmetry (not newly introduced by this investigation) | **Confirmed**, citing `channel-busy-gate-search.md`'s independent original finding |
| The dirty flag and buffer are global (all 4 channels), not per-channel | **Confirmed** (same buffer base used everywhere; `FUN_0000449c` passes the whole buffer, not a slice) |
| `FUN_0000449c`'s save reaches the identical flash region (`0x12000`) the read path consumes | **Confirmed** (shared driver-object fields, shared buffer base) |
| `0x12000` is real, firmware-owned, round-trip persistent storage, not external provisioning | **Confirmed** — a real write path exists and is protocol-reachable (`D`), even though not yet exercised |

## Evidence level

Level 1 (static) throughout: full disassembly of every function in the
chain, plus a full-image instruction scan (not a literal-pool xref) for
the specific immediate that ordinary tooling would miss. No concrete
(Unicorn) run was performed this slice, per the task's explicit
instruction not to exercise the flash write yet.

## Next step: the concrete experiment for the following slice

Per the task's "identify the best concrete experiment... but do not
fabricate motor/config state": the natural, non-fabricated next
experiment is to **deliver a real `D<value>|` command** through the
already-proven live-RX-injection technique (the same one used for `G`/
`MC4`/`LL1`/`LL2`) and watch, with a true `--watch-mem-write` on
`0x20004147`:

1. Confirm the dirty flag transitions `0` -> `1` after a real `D`
   command whose value differs from whatever `0x20003145+0x16` already
   holds (cold `.bss`/blank-fill state, so almost any nonzero value
   should trigger it).
2. Then reach a real completion event that calls `FUN_0000449c` — most
   directly, deliver `MC4` (to unlock the subsystem) then a properly
   sequenced `I`/`G` sequence that reaches `FUN_00005be8`'s own
   completion condition (`position == target`, a condition
   `target-config-provenance.md`'s own `distance=0` finding may make
   trivially true rather than requiring a real large move) — and watch
   whether the real erase/write (`FUN_000098f0`/`FUN_0000984c`) actually
   fires and what it writes to flash `0x12000`.
3. Separately, and independently, watch whether `+0x1002` ever clears on
   its own during a longer run (testing whether `FUN_000097f4` really is
   unreachable, or whether this pass's static search missed an indirect
   call site).

This would be the first concrete confirmation that this firmware's own
real code can round-trip data through flash `0x12000` — turning the
"external provisioning boundary" framing from `target-config-
provenance.md` into what the evidence in this doc already shows
statically: a real, firmware-owned persistence mechanism this project
just hasn't triggered yet.
