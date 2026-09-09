# Investigation: The Page-Size Field Is `NVMCTRL.PARAM` — and the Full `D` Round Trip Now Completes

**Question**: `d-command-persistence-roundtrip.md` reached a real NVM
erase call with real arguments, then stalled forever because the driver
object's field at `0x20004148+0xc` read `0`. This slice: find where that
field is *supposed* to come from (meet in the middle — backward from the
object, forward from the erase routine), decide whether it's real
firmware state this project hasn't reached correctly or a deterministic
MCU property the harness needs to expose, and — if resolved — complete
the full round trip: real flash mutation, then a fresh boot that
recovers it.

**Scope**: static disassembly for the provenance question (no new
exhaustive search — the object's own literal-pool scan was already
exhaustive from the prior slice; this pass follows the *code*, not more
addresses), cross-checked against this project's own vendored SAMD51 SVD
and the real firmware's own embedded data. Concrete Unicorn for the
round trip, reusing the existing `--mmio-force-bits` discipline — no new
tooling, no generic NVM emulator, no fabricated page-size value.

## Result

**Option B, confirmed with unusually strong evidence, not merely
inferred.** The field is `NVMCTRL.PARAM` (a real, read-only, SVD-
documented SAMD51 register), reduced through a real firmware constructor
into a derived "erase-unit" value. It is not populated because
**`FUN_0000981c` — previously (mis)classified as an opaque "known
plumbing" NVM write helper — is actually the real, on-demand
constructor for this driver object**, and it reads real MCU hardware
state that this harness's zero-behavior MMIO model doesn't supply.
Modeling that one register's real, documented reset-configuration value
(the same class of fix as every other `--mmio-force-bits` use in this
project) unblocks the erase loop completely. With one more
already-known completion bit added back in, **the full round trip now
completes, concretely, byte-for-byte**: a real `D1234,|` command's value
and marker are actually written to flash `0x12000`, and a fresh boot
from that mutated flash genuinely recovers them through the real load
path.

## Backward: `0x20004148` is never touched by a literal reference — because it's built, not initialized

The prior slice's exhaustive literal-pool scan for `0x20004148` already
found only 3 consumers (`FUN_00009724`, `FUN_000097a4`, `FUN_000097f4`),
none of which write `+0xc`. Re-reading `FUN_000097f4` and `FUN_000097a4`
line by line (not just the fields they read) finds the answer sitting in
plain sight: both call **`FUN_0000981c(obj, dest_address, length)`**
immediately before using the object — not as a one-time boot
constructor, but **every single time**, right before each save attempt.
Disassembling `FUN_0000981c` in full (it was never fully disassembled
before — only referenced as "the raw NVM write helper" in
`standard-library-provenance.md`'s `UNKNOWN` classification) shows it is
the real constructor:

```c
void FUN_0000981c(int *obj, int dest_addr, int length) {
    param = *(uint*)0x41004008;               // NVMCTRL.PARAM
    psz_code = (param & 0x7ffff) >> 0x10;      // bits 16-18: PSZ
    page_bytes = flash_table_0x14000[psz_code]; // PSZ code -> byte count
    obj[0] = page_bytes;
    nvmp = param & 0xffff;                      // bits 0-15: NVMP (page count)
    obj[5 /*+0x14*/] = length;
    obj[1 /*+0x4*/]  = nvmp;
    total_bytes = page_bytes * nvmp;
    obj[2 /*+0x8*/]  = total_bytes;
    obj[3 /*+0xc*/]  = total_bytes >> 6;         // <-- the field FUN_000098f0 reads
    obj[4 /*+0x10*/] = dest_addr;
}
```

**`0x41004008` resolves, via this project's own vendored SVD
(`tools/svd/resolve_mmio.py 0x41004008`), to `NVMCTRL.PARAM` exactly.**
This is not firmware-owned RAM state waiting for some missed
initializer — it is a **real, read-only hardware register**, and the
field is recomputed fresh on every call. The "provenance" answer to the
backward half of the question is: **there is no missing firmware
initializer to find** — the constructor runs correctly every time; what's
missing is a correct *hardware register value* for it to read.

## Forward: confirmed against the real SVD and the firmware's own embedded table

`tools/svd/ATSAMD51J19A.svd`'s `NVMCTRL.PARAM` definition (already
vendored in this repo, not fetched new):

| Field | Bits | Meaning |
|---|---|---|
| `NVMP` | 0-15 | NVM Pages (total page count) |
| `PSZ` | 16-18 | Page Size code, `0`-`7` -> `8, 16, 32, 64, 128, 256, 512, 1024` bytes |
| `SEE` | 31 | SmartEEPROM present |

`(param & 0x7ffff) >> 0x10` is exactly bits `16`-`18` (`0x7ffff` = bits
`0`-`18`, masking off `SEE`; `>>0x10` isolates `PSZ`) — the constructor's
own mask/shift matches the SVD's field layout exactly, not
approximately. And the lookup table at flash `0x14000` — **read directly
from the firmware image, no assumption**:

```
$ python3 -c "print([int.from_bytes(open('research/firmware/originals/firmware_autopilot868.bin','rb').read()[0x10000+i*4:0x10000+i*4+4],'little') for i in range(8)])"
[8, 16, 32, 64, 128, 256, 512, 1024]
```

**matches the SVD's `PSZ` enumeration byte-for-byte.** This is about as
strong as static cross-referencing gets: the real firmware's own
compiled-in table agrees exactly with the independently-sourced SVD.

## Which value, and why it's not a guess

The SVD lists `PARAM`'s generic reset value as `0x00060000` (`PSZ=6` =
512-byte pages, `NVMP=0`) — a documented default, but `NVMP=0` cannot be
this chip's real value (it would mean zero total flash). `NVMP` is
device-density-specific, not a fixed reset constant across the whole
SAMD51 family. This project already has the real, physically-confirmed
part number: **ATSAMD51J19A** (`docs/firmware/firmware-layout.md`, from
direct board inspection, not inferred from the firmware) — a
512 KB-flash part. With the confirmed 512-byte page size:
`512 KB / 512 B = 1024 pages = 0x400`. So the real `PARAM` value for
*this exact, physically-confirmed part* is:

```
PSZ=6 (512B) | NVMP=0x400 (1024 pages) = 0x00060400
```

This is a deterministic computation from (a) the SVD's own field
layout, (b) the firmware's own embedded lookup table, and (c) a
physically-confirmed part number already on record — not a plausible-
sounding number chosen to make the loop terminate. Modeled the same way
every other MCU-internal completion/status value in this project is
modeled:

```
--mmio-force-bits 0x41004008:0x00060400
```

`NVMCTRL.PARAM` is read-only hardware, never written by firmware, so an
OR-forced value on every read is exactly the established
`--mmio-force-bits` semantics (a status/ready-style register a real
chip of this exact part number guarantees) — not a new mechanism, not a
generic NVM emulator, one named register.

## A second, already-known dependency — found, not new, and named precisely

With `PARAM` fixed, the erase loop's own comparison
(`page_bytes*nvmp>>6 = 0x2000` vs `remaining = 0x1001`) correctly takes
its single-erase-call path — confirmed by register capture
(`r3=0x00002000` at the branch). Execution then stalls a second time,
inside `FUN_000098d8` (the actual erase-command issuer), waiting on
`NVMCTRL.INTFLAG` bit `0` (`DONE`) at `0x41004010`. **This is not a new
mystery** — it is the exact same register/bit `post-probe-main-loop.md`
already identified and modeled (`--mmio-force-bits 0x41004010:1`) for a
different NVM call in an earlier slice; it simply wasn't part of this
slice's own recipe yet. Added back in, matching the task's instruction
to name any further exact dependency precisely rather than accumulate
arbitrary fixes — this one is precisely the same, already-justified bit,
reused, not invented.

## The full round trip, concretely, byte-for-byte

With both bits modeled (`0x41004008:0x00060400`, `0x41004010:1`), the
same real boot + real `D1234,|` injection from
`d-command-persistence-roundtrip.md`:

| Instruction | Address | What |
|---|---|---|
| 6,018,637 | `FUN_0000449c` | real save-checkpoint (via the pre-existing PA22 signal, unchanged) |
| 6,020,610 | `FUN_000097a4` | real save-if-dirty, calls `FUN_0000981c` (now correctly populates `+0xc`) |
| 6,037,023 | `FUN_000098f0` | real erase loop entry, `page_bytes=0x2000 >= remaining=0x1001` |
| 6,037,043 | **`FUN_0000984c`** | **the real write call — reached for the first time in this project** |
| 6,057,742 | `FUN_000097a4` returns | save completes |

Dumping flash `0x12000`-`0x13008` (4104 bytes) directly from Unicorn's
own memory after the run — **not asserted, read**:

```
byte[0x1000] = 0x01                        # "has real data" marker, correctly set
bytes[0x14..0x1b] = 00 00 00 04 d2 de 14 ff
  -> offset 0x15..0x18 = 00 00 04 d2 = 1234   (our D command's value)
  -> offset 0x19        = de                   (the D command's own marker)
  -> offset 0x1a         = 14                   (FUN_00004c20's earlier boot-time clamp default)
```

**Every byte matches what the real RAM buffer held at save time** —
this is a real firmware-produced flash mutation, not a placeholder.

### Preserving and reloading it — a disclosed harness step, not fabricated data

Unicorn is a single-shot process; there is no real flash to persist
across a process exit. To exercise "fresh boot recovers it," the
concrete bytes **Unicorn's own execution produced** (not invented) were
written into a copy of the firmware image at the corresponding file
offset (flash `0x12000` = file offset `0xE000`), standing in for what a
real power-cycle would do for a physically-persistent flash region. This
is disclosed explicitly as a harness continuity mechanism — the data
itself is 100% firmware-produced; only the "did this survive a power
cycle" step is harness-supplied, and only because Unicorn has no
persistent backing store, not because any byte was guessed.

Booting fresh from that patched image, with **no `D` command injected
this time**:

| Instruction | Address | What |
|---|---|---|
| 639,239 | `0x4c88` (inside `FUN_00004c20`) | the real marker check took the `==0xDE` branch |
| 639,295 | `0x4c8e` | `r0 = 0x000004d2` — **`FUN_000043ac(0x15)` correctly reassembled `1234`, read from the real, previously-saved flash bytes, on a cold boot with zero commands sent** |

**The full round trip is demonstrated, concretely, end to end.**

## Evidence classes, kept explicit

| Class | Example this pass | What it licenses claiming |
|---|---|---|
| **Firmware-produced state** | `1234` at flash `0x15`-`0x18`, `0xDE` at `0x19`, `0x14` at `0x1a`, `0x01` at `0x1000` — all read directly from Unicorn's memory after a real, unforced save | Real bytes the real firmware wrote, given the inputs below — not asserted, dumped |
| **MCU-internal hardware semantics modeled by the harness** | `NVMCTRL.PARAM = 0x00060400` (SVD-documented fields + the firmware's own embedded lookup table + the physically-confirmed part number's real flash size); `NVMCTRL.INTFLAG.DONE = 1` (already established in `post-probe-main-loop.md`) | Real, silicon-guaranteed values for this exact, physically-confirmed part — not external/board-dependent, not guessed |
| **Already-disclosed external assumptions, reused unchanged** | The radio-ID `--force-reg`, the `PA22` GPIO seed | Carried forward exactly as before; this pass adds no new external assumption |
| **Harness intervention to preserve/reload state** | Patching a copy of the firmware image with the bytes Unicorn's own execution produced, to stand in for a real power cycle | A disclosed continuity mechanism, not a data fabrication — every byte written came from a real, unforced prior run |

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| `0x20004148+0xc` is computed by `FUN_0000981c` from `NVMCTRL.PARAM`, not left uninitialized by a missed firmware step | **Confirmed** (full disassembly) |
| `0x41004008` is `NVMCTRL.PARAM`; its `PSZ`/`NVMP` field layout | **Confirmed** (this project's own vendored SVD) |
| The firmware's own `PSZ`-code-to-bytes table matches the SVD exactly | **Confirmed** (read directly from the firmware image) |
| The real value for this physically-confirmed part is `0x00060400` | **Confirmed by deterministic computation** from the SVD layout, the firmware's own table, and the already-confirmed ATSAMD51J19A part/flash-size — not an assumption about external/unknown data |
| `NVMCTRL.INTFLAG.DONE` is the second blocking bit, and it's the same one `post-probe-main-loop.md` already modeled | **Confirmed** (register capture at the exact wait loop, same address/bit as the prior slice) |
| The real NVM write call (`FUN_0000984c`) is reached and performs a real flash mutation matching the RAM buffer exactly | **Confirmed concretely**, byte-for-byte |
| A fresh boot from the mutated flash recovers the value and marker through the real load path | **Confirmed concretely**, register-captured |
| Whether real (non-Unicorn) SAMD51 hardware's actual `NVMCTRL.PARAM` for a real AutoPilot unit reads exactly `0x00060400` | **Not independently verified against physical hardware** — derived from documentation and the confirmed part number, the strongest evidence tier available without a real board read |

## Evidence level

Level 2 (concrete, Unicorn) for the full round trip, with every new
harness input tied to Level 1 (static, SVD/datasheet/firmware-image-
cross-referenced) justification — no value in this pass was chosen to
make the code proceed; each was derived first, then applied.

## Next step

The `0x12000` persistence question, as scoped by this and the prior two
slices, is now closed: read path, write path, dirty-flag lifecycle,
real save trigger, and a full concrete round trip are all demonstrated
or precisely characterized. Two much smaller loose ends remain, neither
blocking:

1. `FUN_000097a4`'s own dirty-flag-clearing behavior post-save is still
   unobserved directly (this run's `--stop-at 0x97ec` stopped right at
   its return; a longer run could check whether the *second* observed
   `FUN_0000449c` firing, from `d-command-persistence-roundtrip.md`,
   re-saves identical data or whether the change-detection correctly
   no-ops it now that flash matches RAM).
2. The `"D12345,|"` (8-byte) framing failure noted in the prior slice
   remains an open, minor receive-path curiosity.
