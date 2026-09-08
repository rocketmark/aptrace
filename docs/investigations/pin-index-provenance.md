# Pin-index provenance: what sets `0x20000164`-`0x20000167`

**Question this closes** (the one gap [`motor-timer-survey.md`](motor-timer-survey.md)
left open): what writes the four per-channel GPIO-descriptor-table index
bytes at RAM `0x20000164`-`0x20000167`, and what pins does each channel
actually resolve to?

**Result: found, confirmed, and it's the pin table above every candidate
list this project has been assembling.**

## Confirmed mapping

| Logical timer channel | RAM byte | Index value | Descriptor-table entry | GPIO pin |
|---|---|---|---|---|
| TC0 (channel 0) | `0x20000164` | `0x29` (41) | table[41] | **PB10** |
| TC1 (channel 1) | `0x20000165` | `0x2b` (43) | table[43] | **PA08** |
| TC2 (channel 2) | `0x20000166` | `0x07` (7)  | table[7]  | **PB12** |
| TC3 (channel 3) | `0x20000167` | `0x2d` (45) | table[45] | **PA10** |

These are compile-time-baked values, read directly from the firmware
image — not observed via cold-RAM concrete execution, not inferred, not
seeded. `FUN_00005898`/`FUN_0000d388` (the mechanism `motor-timer-survey.md`
already confirmed) is unchanged; this closes its one remaining gap.

Note channel 2's index (7) happens to equal one of the ten indices already
listed as "candidate" in `motor-timer-survey.md`'s survey (PB12) — that
survey enumerated indices *observed in use elsewhere in the firmware*
(homing, `FUN_00006968`, etc.), not the table's true extent, which turns
out to run to at least index 49 (see below). The coincidence at index 7 is
just that: PB12 was already a real table entry, now confirmed as the
actual value channel 2 uses, not a different resolution of the same
number.

## How this was found

`motor-timer-survey.md` and this investigation's first pass both looked for
an **instruction** that stores to `0x20000164`-`0x20000167` — via Ghidra's
`dataReferences` xref database (twice, from two different queries), a raw
byte-pattern scan of the whole flash image for the literal `0x20000164`,
and decompiling every one of the six functions that reference the address
at all (`FUN_00005898`, `FUN_00006968`, `FUN_00007770`, `FUN_000077a0`,
`FUN_000077f8`, `FUN_00007868` — all confirmed reads, several of them
motor homing/limit-switch sequences that read the array to drive pins
during startup homing, not writers).

That search was correctly exhaustive for its category and correctly found
nothing — because **there is no such instruction**. The four bytes are not
set by application code at all: they are part of the compiler's `.data`
segment, a block of statically-initialized globals whose *initial values*
are baked into flash and copied into RAM by the generic startup copy loop
in `Reset_Handler`, before any application code (including `main`/the
peripheral-init chain) ever runs. This is exactly the "computed/looped
store the static xref scan can't see" category the task asked to check
for — the destination address is computed at runtime from a pointer that
increments through a loop, never appearing as a literal `0x20000164` operand
anywhere in the binary, which is why the literal-address xref/pattern
searches correctly came up empty.

**The copy loop, confirmed by disassembly** (`Reset_Handler` itself, flash
`0xcc24`-`0xcc70`):

```
0xcc24  ldr r3, [0xcc8c]     ; r3 = __data_start__ (RAM dest start) = 0x20000000
0xcc26  ldr r0, [0xcc90]     ; r0 = __data_end__   (RAM dest end)   = 0x20000430
0xcc28  ldr r2, [0xcc94]     ; r2 = __etext        (flash src start)= 0x00014c40
...
0xcc62  ldr r2,[r2,#0]       ; word = *src
0xcc64  str.w r2,[r1],#0x4   ; *dst++ = word
0xcc68  adds r4,#0x4         ; src += 4
0xcc6a  b 0xcc38             ; loop until dst == data_end
```

This is the standard Cortex-M/newlib `.data` initializer copy (copy from
`__etext` in flash to `[__data_start__, __data_end__)` in RAM), reached
from `Reset_Handler` **before** the clock/peripheral-init call
(`bl 0xcdd8`) that begins the chain `motor-timer-survey.md` and
`samd51-peripheral-mapping.md` already traced.

`0x20000164` falls inside `[0x20000000, 0x20000430)`, at offset `0x164`
into the `.data` image. The corresponding flash source bytes are at
`__etext + 0x164 = 0x14c40 + 0x164 = 0x14da4`:

```
flash 0x14da4: 29 2b 07 2d   ->  channel 0=0x29, 1=0x2b, 2=0x07, 3=0x2d
```

read directly from the firmware `.bin` (`fw[0x14da4-0x4000 : +4]`), with no
execution involved — a pure static fact about the compiled image, exactly
as reliable as reading any other literal-pool constant this project already
treats as ground truth.

## Decoding the descriptor-table indices

The 24-byte-per-entry table at flash `0x14284` (already found by
`samd51-peripheral-mapping.md`/`motor-timer-survey.md`) decodes as:

- offset `0x00` (4 bytes, LE): PORT group (`0`=PORTA, `1`=PORTB)
- offset `0x04` (4 bytes, LE): pin number within that group

confirmed against all ten previously-known entries (indices 0-9: PA23,
PA22, PB17, PB16, PB13, PB14, PB15, PB12, PA21, PA20 — every one decodes
correctly under this scheme) and cross-checked independently: **table index
40 decodes to PB22**, which is the *exact* pin
`samd51-peripheral-mapping.md` separately, independently confirmed is
toggled by the real TCC1 interrupt handler (IRQ93) — strong corroboration
that this table, and this decode, are both correct, from a completely
unrelated investigation. The table is a full Arduino-style
`g_APinDescription[]`-shaped array, not the 10-entry subset previously
enumerated — reading it out to at least index 49 shows a well-formed,
contiguous board pin-description table (dumped during this investigation;
not reproduced in full here since only 41/43/7/45 are load-bearing).

Decoding the four target indices:

- `41` (`0x29`) -> group=1 (PORTB), pin=`0x0a`=10 -> **PB10**
- `43` (`0x2b`) -> group=0 (PORTA), pin=`0x08`=8  -> **PA08**
- `7`  (`0x07`) -> group=1 (PORTB), pin=`0x0c`=12 -> **PB12**
- `45` (`0x2d`) -> group=0 (PORTA), pin=`0x0a`=10 -> **PA10**

## Category

**Fixed startup initialization** — specifically, compiler/linker-generated
`.data`-segment initialization, not application code, not a computed
runtime loop written by the firmware author, not NVM/EEPROM-persisted
configuration, and not board/runtime detection. The values are permanently
fixed by the compiled binary; they cannot vary run to run or device to
device without reflashing.

This was cross-checked against the other four candidate categories the
task asked about, each with a concrete negative result, not just an
absence of a positive one:

- **NVM/persistent config**: the firmware does call real NVMCTRL flash
  operations (`FUN_0000984c`/`FUN_000098d8`, confirmed by decompile,
  using the real `0xA5xx` command-key sequence and status polling) — but
  these are flash **write** helpers (consistent with Arduino/Adafruit
  bootloader-adjacent self-programming code), not a config-read-into-RAM
  path, and neither is called anywhere near the `.data` array in question.
  No NVM read of any kind touches `0x20000164`-`0x20000167` or its flash
  source.
- **Board/runtime detection**: no code between `Reset_Handler` and the
  `.data` copy loop reads any pin, strap, or ID register — the copy loop
  is unconditional and runs first, before any peripheral is even clocked.
- **A nearby, superficially similar write, ruled out**: `FUN_00006b50` (a
  4-channel trapezoidal motion-profile update routine, unrelated to pin
  assignment) writes single bytes at `0x2000016c`-`0x2000016f` — 8 bytes
  past the target range, a different per-channel array (a "profile active"
  flag, per its loop `*local_54 = 1` for `local_54 = 0x2000016c +
  channel`). This was investigated as a lead (found via a wider
  `0x20000140`-`0x20000190` dataReferences window scan) and confirmed
  unrelated: it neither reads nor writes anything in
  `0x20000164`-`0x20000167`, and its own literal (`DAT_00006e10 =
  0x2000016c`) is a distinct, separately-initialized `.data` field.

## Concrete (Unicorn) corroboration, and its limit

A concrete run entering at `FUN_00009464` (the one-time-init function that
calls the homing routine `FUN_00006968`) with `--stub-call 0xcd50`
confirms `0x20000160`-`0x2000016f` are **still all zero** after 2,000,000
instructions of real startup/homing code — consistent with entering
*after* the `.data` copy already happened during a real boot (this run
starts past `Reset_Handler`, so it can't observe the copy itself, only
that nothing *after* it clobbers the values back to zero, which cold-RAM
runs had made look plausible). The run does not reach far enough to
independently re-observe the `.data` copy load the values to `0x29 0x2b
0x07 0x2d` — it gets stuck at `0x69ae`-`0x69ca`, a genuine hardware
homing/limit-switch wait loop (`FUN_0000ccd0` millis-style tick compared
against a real GPIO-input read via `FUN_0000d3dc(1)`) that the project's
zero-behavior MMIO model cannot pass without fabricating either a switch
trigger or tick advancement — the same class of tooling gap already
documented elsewhere (`docs/project-status.md`'s "Tooling gaps"). This is
a **known, unmodeled limitation**, not evidence against the `.data` finding
above, which was independently confirmed by direct inspection of the
compiled image and the `Reset_Handler` copy loop's disassembly — a
stronger form of evidence than a concrete run through this specific
address range would have added anyway (a concrete run only replays what
static reading of the same flash bytes already proves).

## Confirmed vs. inferred

| Fact | Status |
|---|---|
| `0x20000164`-`0x20000167` lie inside the linker's `.data` section (`0x20000000`-`0x20000430`) | **Confirmed** (direct read of `Reset_Handler`'s copy-loop literals) |
| `Reset_Handler` copies this region from flash `0x14c40`+ before any peripheral init | **Confirmed** (disassembly, `0xcc24`-`0xcc70`) |
| The flash-resident initial values are `0x29 0x2b 0x07 0x2d` | **Confirmed** (direct flash read at `0x14da4`) |
| No application-code instruction writes these bytes | **Confirmed** (two independent xref/pattern searches, all six referencing functions decompiled) |
| The descriptor-table group/pin decode (byte 0 = group, dword @4 = pin) | **Confirmed** (matches all 10 previously-known entries, cross-validated against the independently-known PB22/index-40 fact) |
| channel0->PB10, channel1->PA08, channel2->PB12, channel3->PA10 | **Confirmed**, at the static/compiled-image evidence tier |
| These pins correspond to physical "Motor 1/2/3/4" connectors | **Not claimed** — no evidence connecting a TC channel or these pins to a physical connector label was sought this pass |
| No later code overwrites these bytes at runtime | **Inferred, not fully confirmed** — the six known readers never write them, and a concrete run covering startup-through-homing shows no change, but a full boot through the real main loop was not achieved (blocked by the homing wait-loop tooling gap above); a `.data`-initialized global *could* in principle be reassigned later, though nothing found here suggests it is |

## Evidence level

**Level 1 (static)**, and the strongest kind available: a direct read of
compiled, unmodified flash bytes plus disassembly of the exact copy
mechanism that moves them into RAM — not decompiler inference, not a
concrete-execution artifact. No solver or concrete-execution step was
needed to establish the mapping itself; Unicorn was used only to check for
(and rule out) a later overwrite, with the limitation noted above.

## What this changes in the mechanism graph

`motor-timer-survey.md`'s "candidate pin (PA23 in cold RAM; real index
unresolved)" language for TC0-3 is now superseded by this doc for the pin
identity itself; the mechanism (ISR -> `FUN_00005898` -> `FUN_0000d388` ->
table lookup) is unchanged and was already confirmed there.
