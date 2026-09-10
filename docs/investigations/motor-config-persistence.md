# Motor Configuration Persistence — Current Model

The motor target/position configuration lives in a single compiled-in
default-config blob at flash `0x12000`, loaded into RAM at boot, and the
firmware's own real dirty-flag/save mechanism can write that blob back
to flash and recover it on reboot. Every stage of that round trip —
protocol command in, dirty flag set, save triggered, NVM erase/write
executed, flash bytes mutated, fresh boot recovering the value — has
been driven concretely, register-by-register, through a real `D1234,|`
command. Along the way a second, previously undocumented ASCII command,
`'+'`, was found to be the real protocol-native producer of nonzero
motor-target deltas (the thing this mechanism actually exists to
persist), though delivering `'+'` itself concretely from a fresh boot is
still blocked by an uncharacterized real hardware-probe cost, not a
logic gap.

## Current model

### The config blob and the loader's fallback

The per-channel, per-mode motor target/position struct lives at RAM
`0x20001b40` (4 channels x `0x120` bytes; channel `n`'s block starts at
`base + n*0x120`; within a channel, mode `0` reads `+0x44`(valid)/
`+0x10`(target) directly, mode `N>0` reads `base + (N-1)*0x48 +
0x44`(valid)/`+0xc`(target)). It is populated by **`FUN_00004b64`**,
called from the boot chain and from every `G`-command handler:

- **Step A (bulk load)**: `FUN_00009768(0x20003145, k)` for `k =
  500..1651`, copying 1152 bytes (4 x `0x120`) sequentially into
  `0x20001b40`. This is a straight read of the persisted-config RAM
  buffer at `0x20003145` — logical offsets `500`-`1651` back this
  struct byte-for-byte, in both directions (load and write-back, see
  below).
- The RAM buffer itself is lazily populated (`FUN_00009724`) from a
  **compiled-in default-configuration blob at flash `0x12000`**, via
  `FUN_0000990e`/`FUN_0000e648` (`src = *(driver_obj+0x10) =
  0x00012000`, `len = *(driver_obj+0x14) = 0x1001`, `driver_obj =
  0x20004148`). In the currently loaded firmware image, that blob is
  **entirely `0x00`** for all 4097 bytes — confirmed by a direct read
  of `firmware_autopilot868.bin` (file offset `0xE000`) and
  independently by Unicorn's own mapped memory.
- Because the "has this been provisioned" marker byte
  (`0x20003145[0x1001]`) reads `0` on a blank blob, `FUN_00009724`'s
  real fallback fires: `FUN_0000e664(0x20003146, 0xFF, 0x1000)` fills
  the entire staging region with `0xFF`. This lands on all four
  channels' struct regions and their `+0x44` validity bytes, which read
  as truthy (`0xFF`) even though the underlying values are blank-fill
  sentinel, not real provisioned data.
- **Step B (one-shot resync)**, `FUN_00004b24(channel)`, gated on a
  `.data`-initialized flag (`0x20000134[channel]`, `1,1,1,1` at boot,
  cleared after firing once): `target(+0x10) = current tracked position
  (0x20002064[channel])`; `computed(+0xc) = target(+0x10) +
  delta(+0x00)`. Since `0x20002064` is cold-zero (no move has
  completed), mode-0's target becomes `0`, and mode-`N`'s target
  (`+0xc`) becomes `0 + 0xFFFFFFFF = -1` (the untouched blank-fill
  pattern) — a real "no move yet" default, not a bug.
- Exhaustively trying every `G` "type" digit `0`-`9` after `MC4`
  produces exactly two outcomes: type `0` -> `distance=0`; types
  `1`-`9` -> `distance=-1`. Neither crosses `FUN_00006fd8`'s `8`-unit
  real-move threshold — a genuine external-data/provisioning gap in
  *this* firmware image, not a missing mechanism.

### The dirty flag

`0x20003145 + 0x1002 = 0x20004147` — a single boolean byte, addressed by
a register-materialized `movw #0x1002` (it exceeds Thumb-2's 12-bit
immediate-offset range, so it never appears in the flash literal pool
and is invisible to an ordinary xref/literal-pool scan; only a
full-image scan for the `#0x1002` immediate itself finds all three real
touch points).

**`FUN_0000977c(buffer, offset, new_value)`** is the sole setter and the
one shared "write one byte into the persisted config buffer" accessor
used by every writer in the firmware:

```
r3 = *(buffer + offset + 1)      ; current stored byte
cmp r3, new_value
itttt ne                          ; only if the value is actually changing:
    buffer[0x1002] = 1            ; dirty := 1
    *(buffer + offset + 1) = new_value   ; then store the new byte
```

If the new value equals what's already stored, **neither the dirty
flag nor the byte is written** — a deliberate no-op/no-wear optimization.
Confirmed callers (all real, all dirtying the shared flag on an actual
change): `FUN_00004370` (the `D` command's 32-bit value writer, offsets
`0x15`-`0x18`); `FUN_00008258`'s `'D'` branch writing the `0xDE` marker
directly at offset `0x19`; `FUN_00004c20`'s boot-time "clamp
out-of-range setting to default" logic at offset `0x1a` (fires on
*every* cold boot with blank config, since `0xFF` is always
out-of-range and gets clamped to `0x14`); `FUN_00005dd0`'s digital-input
hold/timeout logic at offset `0x14`; and `FUN_000043f0` (the `'+'`
command's write-back of the entire motor struct, offsets `300`,
`0x12d`(301), and `500`-`0x673`(1651)). `FUN_00004b64`/`FUN_00004c20`'s
*read* paths never dirty the buffer — only writes through
`FUN_0000977c` do.

**`FUN_000097f4`** is the only code that clears the flag (`buffer[0x1002]
= 0`, plus resets the "loaded" flag at `buffer[0]` to force a reload) —
but it also does an *unconditional* raw NVM write first (no dirty
check), and has **no confirmed caller anywhere in the image** (checked
via both the calls graph and a full-image branch-target scan). Whether
it's reached indirectly or is vestigial is unresolved. `FUN_000097a4`
(the actual save-if-dirty path, see below) **never clears the flag
after saving** — a real asymmetry, reported as observed, not
adjudicated as bug vs. intentional. A cold boot implicitly clears it
regardless, since `0x20004147` falls inside `Reset_Handler`'s `.bss`-zero
range.

The dirty flag and the underlying buffer are global across all four
channels — nothing about `FUN_0000977c`'s change detection is
channel-specific. The save *trigger*, however, really is asymmetric
toward channel 0 at one of its three call sites (see below) — a
pre-existing firmware asymmetry, not something this mechanism
introduces.

### The `D` command's wire format

`D` needs a **trailing comma before the final `|`** to parse cleanly —
`D<value>,|`, not a bare `D<value>|`. Three framings were tried
concretely:

| Frame | Result |
|---|---|
| `D12345\|` (no comma) | Dispatches, but the field parser's only terminator is `,`; it reads past the packet's own NUL into adjacent memory, producing garbage |
| `D12345,\|` (8 bytes) | Never dispatches at all — the outer receive loop's own terminator recognition never fires; idles forever. Not chased further. |
| `D1234,\|` (7 bytes) | Dispatches cleanly, parses to exactly `0x000004d2` (`1234`) |

No `MC4` unlock is required (same tier as `&`/`G`/`S`/`LL`). On dispatch,
`FUN_00008258`'s `'D'` branch calls `FUN_00004370(0x15, parsed_value)`
(writes the 32-bit value byte-by-byte, big-endian, through
`FUN_0000977c`, at logical offsets `0x15`-`0x18`), then tail-calls
`thunk_FUN_0000977c(buffer, 0x19, 0xDE)` directly, writing a literal
marker byte at offset `0x19`. `FUN_00004c20` (boot-time reader) checks
offset `0x19` for exactly `0xDE`, and if set, reads the 32-bit value
back from offset `0x15` into `0x200029d4` — a complete
write-then-remember-it-was-set pattern spanning a runtime command and
the next boot.

### The save trigger and the NVM erase/write sequence

`FUN_0000449c` is the real save-checkpoint function (clears 4 display
objects, calls `FUN_000097a4(0x20003145)` — the *entire* buffer, not a
per-channel slice — then a delay and a channel-0 GPIO pulse). It has
three call sites:

- **`FUN_00005be8`**, TC0's own dedicated, channel-0-hardcoded ISR
  (`FUN_00005898(0)`, `FUN_00005958(0)`) — a real, pre-existing
  channel-0-only asymmetry, not something this investigation
  introduces. Channels 1-3's ISRs lack this completion-and-persist
  logic.
- **`FUN_00005dd0`**, called every main-loop iteration, two triggers,
  both channel-agnostic: a digital input on pin index `1` sustained
  past **1000 ticks** (then a display/delay sequence and an intentional
  infinite halt — "hold this input to save & power down"), or, on
  release, an elapsed **20000-tick** check. Pin index `1` resolves (via
  the real pin-descriptor table) to `group=0, bit=22` — **PA22**, the
  same signal this project has held high since boot for an unrelated
  homing-loop exit condition. No new GPIO assumption was needed to
  reach the save path: holding PA22 for the whole run naturally
  triggers this branch.

`FUN_000097a4`, if the dirty flag is set, calls `FUN_0000981c(obj,
dest, len)` to (re)build the driver object at `0x20004148`, then erases
and writes. `FUN_0000981c` is not a one-time boot constructor — it is
called fresh before *every* save attempt, and it reads
**`NVMCTRL.PARAM` (`0x41004008`)**, a real, read-only SAMD51 hardware
register: `PSZ = (param & 0x7ffff) >> 0x10` (bits 16-18) indexes a
firmware-embedded table at flash `0x14000` (`[8,16,32,64,128,256,512,
1024]`, confirmed to match the SVD's `PSZ` enumeration exactly) to get
the page byte count; `NVMP = param & 0xffff` is the page count; `obj+0xc
= (page_bytes * NVMP) >> 6`. On the harness's zero-behavior MMIO model,
`NVMCTRL.PARAM` reads `0`, so `obj+0xc` is `0`, and the erase loop
(`FUN_000098f0`, which divides remaining length by page size) never
advances — an infinite stall, not a fabricated blocker.

The real value for the physically-confirmed part (**ATSAMD51J19A**,
512 KB flash) is derived, not guessed: `PSZ=6` (512-byte pages, matching
the firmware's own table), `NVMP = 512KB / 512B = 1024 = 0x400`, giving
`NVMCTRL.PARAM = 0x00060400`. Modeled via `--mmio-force-bits
0x41004008:0x00060400`. A second, already-known dependency
(`NVMCTRL.INTFLAG.DONE`, bit 0 of `0x41004010`) is also required —
already modeled elsewhere in this project as `--mmio-force-bits
0x41004010:1`; reused here unchanged.

With both bits modeled, the erase call fires with real arguments —
`FUN_0000984c(dest=0x00012000, len=0x1001)` — identical to the read
path's address/length, confirming the write path targets the same
flash region the read path consumes. `0x12000` is real, firmware-owned,
round-trip persistent storage, not an external-provisioning boundary.

### The `'+'` command: the real producer of nonzero targets

`FUN_00004b64`'s bulk load has a real write-back counterpart,
**`FUN_000043f0`**: it writes `0x20002941` -> offset `300`, `0x200029d0`
-> offset `0x12d`(301), and the entire live `0x20001b40` struct ->
offsets `500`-`0x673`(1651) — the exact mirror of the load, same buffer,
same range, opposite direction, dirtying the buffer through
`FUN_0000977c` for any byte that actually differs.

The only caller of `FUN_000043f0` is a previously undocumented ASCII
command, **`'+'`**, dispatched through a tail-jumped code region
(`0x806c`-`0x8208`) that Ghidra's function boundaries don't attribute to
`FUN_00008258` at all (the same silent-tail-jump artifact already
corrected once for `FUN_00007e2c`/`0x7cc0`). `'+'` does not require
`MC4`. Its wire frame: two "confirm" values that must match, a channel
(`0x20002060`), a mode selector (`0x20003140`; `> 50` triggers
compute+persist), a raw record-count digit, then up to 3 records of 5
fields each (flag, percentage, rate divisor, **signed delta**,
duration) into a staging array at `0x20002960`.

For mode `>50`: `FUN_00004ca8(channel)` runs for all 4 channels
(`target(+0xc) = start(+0x10) + delta(+0x0)`, chaining into the next
sub-record's start), then `FUN_000043f0()` persists the whole struct,
plus an unrelated byte at offset `400`. The wire-controlled delta writer
(`FUN_000046c8` for a `'1'`-selected unit family, `FUN_00004910`
otherwise — same fields, different scaling) copies **`dest->offset_0x0
= wire[3]` (the signed delta) directly from the wire, with no clamp
toward live position**, and sets the record's validity byte
(`+0x44 = 1`).

This closes the loop back to `FUN_00007cc0`'s target lookup: for mode 1
(`record(0)`, the channel base), `offset_0xc` now holds `start(+0x10) +
wire_delta`, and `+0x44` (valid) is `1`. Since `FUN_00004b24`'s boot
resync already set `start` to the live (cold-zero) position, a `'+'`
write followed by `G<channel>1<seq>|` computes `distance = wire_delta -
0 = wire_delta` — arithmetically, any `|wire_delta| > 8` should cross
`FUN_00006fd8`'s real-move threshold. This is a strong, disassembly-
grounded, three-way cross-confirmed static prediction (struct-base
literal, staging-array literal, and channel-index literal all agree),
**not yet concretely observed** — see Open items.

## Evidence

- Flash `0x12000` (file offset `0xE000` in `firmware_autopilot868.bin`):
  confirmed entirely `0x00` for 4097 bytes, both by direct file read and
  Unicorn `--dump-mem`.
- Dirty byte: `0x20004147` (`0x20003145 + 0x1002`). Sole setter:
  `FUN_0000977c` (change-detecting accessor at `0x9794`). Reader (save
  gate): `FUN_000097a4` (`0x97b6`). Sole clearer: `FUN_000097f4`
  (`0x9804`), no confirmed caller.
- `D` command field layout: 32-bit value at logical offset `0x15`
  (physical `0x2000315b`-`0x2000315e`), marker `0xDE` at offset `0x19`
  (physical `0x2000315f`). Concretely observed bytes progression for a
  real `D1234,|`: `ff ff ff ff ff` -> `00 00 04 d2 ff` (value written) ->
  `00 00 04 d2 de` (marker written).
- Save trigger: PA22 (`PORT.GROUP0.IN` bit 22, `--seed-mem
  0x41008020:00004000`), read via `FUN_0000d3dc(1)`'s
  `digitalRead()`-shaped logic, sustained past 1000 ticks in
  `FUN_00005dd0`.
- NVM erase call arguments (register-captured): `dest=0x00012000,
  len=0x1001` — identical to the read path's `FUN_0000990e` arguments.
- `NVMCTRL.PARAM` = `0x41004008`; modeled value `0x00060400` (`PSZ=6`
  -> 512-byte pages, `NVMP=0x400` -> 1024 pages, derived from the SVD
  field layout, the firmware's own embedded PSZ table at flash
  `0x14000`, and the physically-confirmed ATSAMD51J19A part/flash
  size). `NVMCTRL.INTFLAG.DONE` bit 0 at `0x41004010`, forced to `1`
  (reused from an earlier, unrelated NVM stall already modeled
  elsewhere in this project).
- `FUN_000043f0` (the `'+'` write-back function): writes offsets `300`,
  `0x12d`(301), `500`-`0x673`(1651). Callees in the compute+persist
  path: `FUN_00004ca8` (per-channel target chaining, called for
  channels 0-3), `FUN_000046c8`/`FUN_00004910` (wire-controlled,
  unclamped signed-delta writer, two unit-conversion variants).
- Post-save flash dump (`0x12000`-`0x13008`, read directly from
  Unicorn's memory, not asserted): `byte[0x1000]=0x01` (provisioned
  marker); `bytes[0x14..0x1b] = 00 00 00 04 d2 de 14 ff` — offsets
  `0x15..0x18 = 1234`, `0x19 = 0xde`, `0x1a = 0x14` (the boot-time
  clamp default) — every byte matching what the RAM buffer held at
  save time.

## Test / repro

Boot recipe: `Reset_Handler` entry, `OSC32KCTRL`/`OSCCTRL`/`DPLL0`/
`DPLL1` ready bits, `SERCOM5`/`SERCOM2` `SWRST`/`SYNCBUSY` self-clear,
the disclosed radio-ID `--force-reg`, PA22 seeded high
(`--seed-mem 0x41008020:00004000`) for the pre-existing homing
condition, plus:

```
--mmio-force-bits 0x41004008:0x00060400   # NVMCTRL.PARAM (page size/count)
--mmio-force-bits 0x41004010:1            # NVMCTRL.INTFLAG.DONE
```

1. Inject `D1234,\|` (7 bytes, comma required) through the real RX ring
   and parser. Register capture confirms `FUN_0000799c` returns exactly
   `0x000004d2`.
2. Run forward with no further injected commands. At instruction
   6,018,637, `FUN_0000449c` fires (via the sustained-PA22 branch in
   `FUN_00005dd0`). At 6,020,610, `FUN_000097a4` runs with the dirty
   flag still `1`. At 6,037,023, `FUN_000098f0`'s erase loop correctly
   takes its single-erase-call path (`page_bytes=0x2000 >=
   remaining=0x1001`). At 6,037,043, `FUN_0000984c` — the real write
   call — executes for the first time in this project. `FUN_000097a4`
   returns at 6,057,742.
3. **Simulated power cycle (disclosed harness step, not fabricated
   data)**: Unicorn is single-shot with no persistent flash backing, so
   the exact bytes Unicorn's own execution produced at flash `0x12000`
   were written into a copy of the firmware image at the corresponding
   file offset (`0xE000`), standing in for what a real power cycle
   would do. Every byte came from a real, unforced prior run.
4. **Fresh boot from the patched image, with no `D` command injected**:
   at instruction 639,239, `FUN_00004c20`'s marker check takes the
   `==0xDE` branch; at 639,295, `r0 = 0x000004d2` — `1234`, correctly
   reassembled from the previously-saved flash bytes on a cold boot
   with zero commands sent. This closes the full round trip.

For the `'+'` command, two concrete delivery attempts were made
(`MC4` alone intending to chain into `'+'` then `G...1...`; `'+'` alone
in isolation) reusing the same boot recipe plus two fixes found along
the way: (a) clearing PA22 back to `0` at main-loop entry
(`--force-mem` at `0x94bc`) so the homing-required signal doesn't also
trip `FUN_00005dd0`'s later infinite-halt branch before `'+'` can be
processed; (b) broadening `SERCOM` `SYNCBUSY`/`INTFLAG` force/clear
masks from the narrow `:1`/`:4` used for one-time clock init to
`SYNCBUSY:0xffffffff`/`INTFLAG:0xff` for a later Adafruit `SPIClass`
constructor (`FUN_00009f60`, pinned by the literal string
`"SPIClass::SPIClass(SERCOM*, uint...)"`). Neither fix, nor budgets up
to 250,000,000 (`MC4` attempt) / ~80,000,000 (`'+'`-alone attempt)
instructions, reached `'+'`'s dispatch; the staging array
(`0x20002960`) remained all-zero throughout. Program counter progress
*was* observed between successive attempts (advancing across different
`SERCOM`-address-resolution utilities), ruling out an infinite loop —
the delivery is bounded by real, finite, uncharacterized hardware-probe
cost, not blocked by firmware logic.

## Open items

- **`'+'`'s own concrete delivery is still blocked**, not resolved: from
  a fresh `Reset_Handler` boot, reaching `'+'`'s dispatch entry costs far
  more instructions than any other single-command injection in this
  project (250M+ / 80M+ attempted, neither sufficient). The bottleneck
  is upstream of `'+'`'s own dispatch — some real, finite sequence of
  `SERCOM`-based device-probe activity the existing boot-recipe
  calibration doesn't budget for. The static prediction that a real
  `'+'` write with `|delta| > 8` followed by `G<channel>1<seq>|` drives
  `FUN_00006fd8`'s distance past its threshold has **not** been
  confirmed by a completed concrete run.
- **`FUN_000097a4`'s dirty-flag-clearing behavior on a second, later
  save was not directly observed.** The concrete round-trip run never
  extended far enough past the first successful save to see whether a
  subsequent `FUN_0000449c` firing (e.g., from the second `FUN_00005dd0`
  trigger) re-saves identical data or whether change-detection correctly
  no-ops it now that flash matches RAM. Left open, not assumed either
  way.
- **`FUN_000097f4` (the only dirty-flag clearer) has no confirmed
  caller** anywhere in the image (calls graph and full-image
  branch-target scan both zero hits). Whether it's reached via an
  indirect function-pointer table or is effectively dead code is
  unresolved.
- **The `D12345,|` (8-byte) framing curiosity is unchased.** Unlike the
  7-byte `D1234,|` (dispatches and parses correctly) or the no-comma
  `D12345|` (dispatches but overreads), the 8-byte comma-terminated
  frame never dispatches at all — the outer receive loop's terminator
  recognition never fires. Left as a minor, un-investigated
  receive-path quirk for whenever a future slice needs multi-digit `D`
  values.
- **`NVMCTRL.PARAM = 0x00060400` has not been independently verified
  against physical hardware.** It is a deterministic computation from
  the vendored SVD's field layout, the firmware's own embedded PSZ
  table, and the physically-confirmed ATSAMD51J19A part/flash size —
  the strongest evidence tier available without a real board read, but
  not itself a hardware-confirmed value.
