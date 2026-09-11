# Mando 915 Differential Audit against Mando 868

**Purpose**: determine whether one common Remote behavioral contract can
cover both `firmware_mando868.bin` and `firmware_mando915.bin`, with
only RF-band-specific differences. Mando868 is the established baseline
(`docs/replacement/mando868-counterpart-audit.md`,
`research/generated/mando868-counterpart-audit.json`). Mando915 is
**not** semantically classified function-by-function anywhere in this
pass.

**Machine-readable companion**: [`research/generated/mando-868-vs-915-diff.json`](../../research/generated/mando-868-vs-915-diff.json).

## Pass A — mechanical diff

### The raw byte diff is large — and that is not, by itself, meaningful

| | mando868 | mando915 |
|---|---|---|
| SHA-256 | `cf74cf03...` | `abb71190...` |
| Size | 138,304 | 138,304 |
| Differing bytes | — | **62,870** |
| Contiguous differing ranges | — | **4,870**, spanning file offset `0x4`-`0x21830` |

Unlike the AutoPilot868/915 pair (a single clean 4-byte diff), this is a
large, pervasive diff touching most of the image. Census `diff`
(`tools/census/aptrace_census.py diff mando868 mando915 --json`)
narrows this immediately to the function level:

```
byte_identical_function_count: 415  (of 561 total)
functions with mismatched content-hash: 125 (present in both images' hash sets, at different hashes)
  -- of which only 8 have a DIFFERENT start address (self-relocated)
  -- the remaining 117 keep their own address, differing only in
     references to relocated data/functions
strings_only_in_a / only_in_b: 2 / 2
hardware_register_diffs / mmio / pin_config / hardware_relevant_constant_diffs: 0 / 0 / 0 / 0
residual_priority_diffs: 40 (ALL with identical exact_hash — score/naming artifacts only)
```

### Root cause: one link-time relocation, not a rewrite

Three representative samples — chosen to span early/mid-file locations
and both "callee moved" and "function itself moved" cases, including
two functions already load-bearing in the Mando868 counterpart audit —
were compared instruction-by-instruction via direct disassembly
(existing cached Ghidra project, no new analysis):

1. **`FUN_000049c4`** (the `'+'` frame builder, item 6 of the contract
   audit) — own address and every instruction identical; exactly 2
   internal `BL` targets shifted (`0x14bb6→0x14bc6`, `0x14c7a→0x14c8a`,
   both `+0x10`).
2. **`FUN_0000e670`** (Auto-Mode state machine, item 11) — own address
   and instructions identical; 1 internal `BL` target shifted
   (`0x171f0→0x17200`, `+0x10` — the jog-wheel-click read primitive).
3. **`FUN_00010ce4→FUN_00010cf4`** (Remote's inbound radio-command
   handler, item 10's MT consumer) — the function's own start address
   moved by `+0x10`; every internal reference inside it shifted by the
   identical `+0x10`; every call to an *unmoved* external function
   (`0x583c`, `0xb4f8`) stayed byte-identical.

All three: **zero logic differences, only address references shifted**.
A structural cross-check of all 125 hash-mismatched functions confirms
the pattern holds broadly — the 8 that moved their own address all
shifted by small, consistent deltas (`+0xc` to `+0x10`), exactly what a
single cascading link-time size change (most plausibly the
region-specific RF configuration/string) produces, not independent
content edits scattered through the codebase.

**This conclusion is representative-sample-based, not an individual
re-verification of all 125 functions** — consistent with this audit's
own bound against manually inspecting every changed address. It is
supported by three independent disassembly comparisons plus one
structural cross-check across the full mismatched-function population,
all pointing the same direction with no counter-example found.

### Genuine content differences (2, both already known-shape)

| | mando868 | mando915 | Classification |
|---|---|---|---|
| RF-band display string | `"868MHz band"` | `"915MHz band"` | **RF_BAND_SPECIFIC** |
| Build timestamp string | `"12:22:42"` | `"12:20:52"` | **BUILD_ARTIFACT** |

### RF register configuration — checked, not found

The same technique that cleanly isolated AutoPilot's own
864,000,000/915,000,000 Hz frequency constant (scanning every differing
4-byte range for a plausible 800MHz–1000MHz value) was applied to
Mando's diff set. **No clean, round frequency constant was found.**
Mando's RF-band difference is confirmed only at the display-string
level (above); whether the Remote's own radio SPI/register
configuration differs between builds could not be isolated from the
pervasive link-shift noise via mechanical byte-diffing. Marked
separately, non-blocking — the identical treatment already given to
this class of gap on the AutoPilot side (radio transport) and in the
Mando868 counterpart audit (item 18, RF packet boundary): this is an
*equally* unresolved register-level question on both firmware pairs,
not a new 915-specific gap.

### Census-analysis-state artifact

The 40 `residual_priority_diffs` all carry an **identical `exact_hash`**
between the two images — confirmed byte-identical function bodies. The
score/naming differences (14 of 40 show a name difference) stem from
unequal dynamic-coverage ingestion (12 runs vs. 1) and unequal
semantic-naming progress (only mando868 has this project's own
counterpart-audit work applied) — the same artifact class already
documented for both AutoPilot868/915 and this project's census tooling
generally. **BUILD_ARTIFACT.**

### Classification tally

| Classification | Count |
|---|---|
| RF_BAND_SPECIFIC | 1 |
| BUILD_ARTIFACT | 2 (string + the 40-function census-state group) |
| ADDRESS_LAYOUT_ONLY | 1 (the entire relocation population) |
| SEMANTICALLY_EQUIVALENT | 0 |
| POTENTIAL_BEHAVIOR_CHANGE | 0 |
| UNRESOLVED | 0 |

## Pass B — behavioral candidates

**Not entered.** No difference was classified `POTENTIAL_BEHAVIOR_CHANGE`
or `UNRESOLVED` — the three samples taken to *establish* the
ADDRESS_LAYOUT_ONLY classification already satisfy this pass's own
"changed function + at most one direct callee" bound, and each
confirmed equivalence rather than exposing a candidate needing further
inspection.

## Contract matrix

All 17 items: **SAME**.

G transaction · S/P · ! · I · I9/I1 · interactive `+` · bulk `0x62`
re-arm · Manual `F0`/`E0` · MC/MC4 · MT/Quick Setup · program-position
handling · retry/timeouts · malformed-response behavior · known
protocol quirks · reconnect behavior · RF packet boundary · local
persistence expectations

Two items carry direct sampling evidence beyond the general
root-cause argument: **interactive `+`** (`FUN_000049c4` sampled
directly) and **MT/Quick Setup** (`FUN_00010ce4`/`FUN_00010cf4` sampled
directly, including its own address relocation). **G transaction** is
additionally reinforced by `0x0000b680` (the G builder) not appearing
in either firmware's hash-mismatch list at all — fully byte-identical,
same address, zero relocation.

None are restated beyond this list, per this audit's own instruction
not to re-narrate SAME items.

## The open Mando868 item (`0x20000b20` loader)

Not investigated here, per this audit's explicit scope instruction — the
915 diff does not touch this address or its known readers/writers in
any way that would require reopening it.

## Conclusion

**One common Remote behavioral contract covers both 868 and 915.** The
Mando868 contract
(`docs/replacement/mando868-counterpart-audit.md`,
`research/generated/mando868-counterpart-audit.json`) applies unchanged
to Mando915. The image-wide raw-byte diff, despite its scale, resolves
entirely to a single link-time address-relocation artifact plus two
cosmetic string differences — no logic or behavior difference was found
anywhere sampled. No concrete (Unicorn) follow-up is required.
