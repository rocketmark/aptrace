# AutoPilot 915 Differential Audit against AutoPilot 868

**Purpose**: determine whether `firmware_autopilot915.bin` changes any
behavior relevant to the replacement-firmware contract established in
[`autopilot-gap-audit.md`](autopilot-gap-audit.md), beyond RF-band/
build-specific constants — i.e. whether one common AutoPilot behavioral
specification can cover both radio-band variants.

**Machine-readable companion**: [`research/generated/autopilot-868-vs-915-diff.json`](../../research/generated/autopilot-868-vs-915-diff.json).

AutoPilot868 is treated as the authoritative semantic/reference
baseline throughout (per `docs/project-status.md`,
`docs/replacement/autopilot-gap-audit.md`,
`research/generated/autopilot-replacement-gaps.json`, every file under
`docs/investigations/` and `docs/protocol/`, and
`docs/hardware/hardware-reference.md`). AutoPilot915 is **not**
re-classified function-by-function anywhere in this pass.

## Method

Two independent, existing mechanisms were used together:

1. **Exhaustive raw byte diff** of the two firmware images
   (`research/firmware/originals/firmware_autopilot868.bin` vs
   `firmware_autopilot915.bin`, both 70,768 bytes) — every byte
   compared, not sampled.
2. **The existing census `diff` subcommand**
   (`tools/census/aptrace_census.py diff autopilot868 autopilot915
   --json`), which independently compares function fingerprints/exact
   hashes, MMIO sites, pin configs, hardware registers, and string
   constants across the two already-built, already-reduced census
   databases.

No new Ghidra analysis, no Unicorn execution, and no SMT/Crucible were
run. Both firmware images were already fully built and reduced in the
census database before this audit began (confirmed via `aptrace_census.py
summary` for both — identical function/basic-block/vector/MMIO-site
counts).

## Pass A — mechanical differential result

**The result is exhaustive and exceptionally clean: the two 70,768-byte
images differ in exactly 4 bytes, at one contiguous range.**

| | autopilot868 | autopilot915 |
|---|---|---|
| SHA-256 | `6dcdb4c1...` | `0e8e807a...` |
| Size | 70,768 | 70,768 |
| Differing byte ranges | — | **1**, at flash file offset `0x10c40`-`0x10c43` (4 bytes) |
| Everything else | byte-for-byte identical | byte-for-byte identical |

Decoded: flash address `0x00014c40` (file offset `0x10c40` + the
`0x4000` load base) is a `.data` **source** value, copied by
`Reset_Handler__ADAFRUIT_CORE`'s generic `.data` copy loop into RAM
`0x20000000`, which is READ by `radio_bringup__THIRD_PARTY` (`0x610c`)
— the same radio chip-ID-probe/post-probe-config function this
project's Gap Resolution B already characterized under "radio
transport." As a little-endian `uint32`:

| Build | Bytes (LE) | Value |
|---|---|---|
| autopilot868 | `00 98 7f 33` | **864,000,000** (864 MHz) |
| autopilot915 | `c0 ca 89 36` | **915,000,000** (915 MHz) |

This is the radio center frequency, read directly by the already-known
radio-bringup routine — confirmed by address xref, not inferred from
the round numbers alone.

The independent census `diff` cross-check agrees completely:

```
hardware_register_diffs:          0
mmio_sites_only_in_a/b:           0 / 0
pin_config_diffs:                 0
functions_only_in_a/b:            0 / 0
strings_only_in_a/b:              0 / 0
hardware_relevant_constant_diffs: 0
byte_identical_function_count:    396
residual_priority_diffs:          48
```

The 48 `residual_priority_diffs` are **not** firmware differences: every
one has `entry_a == entry_b` (same address) and an identical
`exact_hash` (byte-identical function body) — confirmed independently
by this audit's own zero-other-differing-bytes finding. They exist
because AutoPilot868 has 19 ingested dynamic-coverage runs across 6
scenarios and a full session of semantic-pass naming/classification,
while AutoPilot915 has 1 ingested run and zero semantic classification
— `residual_priority.py`'s scoring includes a dynamic-coverage-proximity
signal, so the *score* differs even though the *code* does not. 13 of
the 48 also show a name difference (e.g.
`tc0_isr_completion__CUSTOM` on 868 vs `FUN_00005be8` on 915) for the
same reason: naming reflects this session's own semantic work on 868
only.

### Difference classification

| Difference | Classification |
|---|---|
| Radio center-frequency constant (RAM `0x20000000`, flash `0x14c40`-`0x14c43`) | **RF_BAND_SPECIFIC** |
| 48 residual-priority-score / naming diffs (all byte-identical functions) | **BUILD_ARTIFACT** (census analysis-state, not firmware content) |

No difference was classified `ADDRESS_LAYOUT_ONLY`,
`SEMANTICALLY_EQUIVALENT`, `POTENTIAL_BEHAVIOR_CHANGE`, or `UNRESOLVED`
— there was nothing left to put in those buckets once the one real
difference and the one analysis-artifact bucket were accounted for.

## Pass B — bounded inspection of behavioral candidates

**Not entered.** Pass B is scoped to items classified
`POTENTIAL_BEHAVIOR_CHANGE` or `UNRESOLVED`; none exist. No function was
inspected beyond confirming, via existing xref queries (not new
analysis), that the one differing constant's provenance (`Reset_Handler`
→ RAM `0x20000000` → `radio_bringup__THIRD_PARTY`) matches the
already-established radio-bringup code path.

## Replacement-contract questions

All 21 questions resolve to **SAME** — each lives entirely in code/data
outside the single 4-byte differing range, and the exhaustive raw byte
diff already proved there is no other difference anywhere in either
image to account for:

boot/startup behavior · startup reference/input routine · STEP/DIR
behavior · motor enable/disable · move/ramp execution · position
accounting · Manual Mode · Auto Mode · programmed moves · MC / motor
configuration · Quick Setup / MT · persistence · digital trigger ·
analog trigger · protocol RX · protocol TX/events · G / S / ! / I / + ·
known protocol defects/quirks · USB/update behavior · status behavior ·
external STEP/DIR behavior

None are restated here beyond this list, per this audit's own
instruction not to re-narrate SAME subsystems.

## RF-band-specific differences (expected, recorded exactly)

Exactly one: the radio center-frequency `.data` constant at RAM
`0x20000000` (flash source `0x14c40`-`0x14c43`) — **864,000,000 Hz**
(autopilot868) vs **915,000,000 Hz** (autopilot915) — consumed by
`radio_bringup__THIRD_PARTY`. No other RF-related string, register, or
literal differs; no MCU-side protocol semantics are touched by this
constant.

## Conclusion

**One common AutoPilot behavioral specification covers both 868 and
915.** The AutoPilot868 replacement contract
(`docs/replacement/autopilot-gap-audit.md`,
`research/generated/autopilot-replacement-gaps.json`) applies unchanged
to AutoPilot915, with exactly one addendum: a replacement's own
radio-bringup code must set the correct center frequency per build
(864 MHz vs 915 MHz), mirroring the vendor firmware's own single-constant
difference. No follow-up concrete execution (Unicorn) is required — the
raw byte diff is exhaustive and the one real difference's provenance is
confirmed by static xref evidence alone.
