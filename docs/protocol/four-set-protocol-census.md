# Four-Set Protocol Census (AutoPilot + Remote)

Mechanical protocol-coverage sanity pass before freezing the
wire-compatibility contract. Enumerates and reconciles **Remote TX,
Remote RX, AutoPilot TX, AutoPilot RX** from existing evidence
(`research/autopilot_static_inventory/commands.csv`/`responses.csv`,
`docs/protocol/*`, `docs/investigations/*`) plus a small number of
bounded lookups this session — no Unicorn, no SMT, no command-semantics
deep-dive beyond what's needed to classify direction/framing.

**Machine-readable companion (authoritative)**:
[`research/generated/four-set-protocol-census.json`](../../research/generated/four-set-protocol-census.json),
53 families.

## Four-set summary

| Set | Count |
|---|---:|
| Remote TX | 29 |
| Remote RX | 13 |
| AutoPilot TX | 15 |
| AutoPilot RX | 28 |

| Diff | Count |
|---|---:|
| Remote TX ∩ AutoPilot RX (matched) | 20 |
| AutoPilot TX ∩ Remote RX (matched) | 12 |
| AutoPilot RX − Remote TX (AP_RX_ONLY) | 8 |
| Remote RX − AutoPilot TX (REMOTE_RX_ONLY) | 1 |
| Remote TX − AutoPilot RX (REMOTE_TX_ONLY) | 9 |
| AutoPilot TX − Remote RX (AP_TX_ONLY) | 3 |

## Matched families (Remote → AutoPilot, 20)

`0xF0`/`0xE0` (binary), `+`, `G`, `B0`/`B1`, `TR`, `W1`, `R0`, `R2`,
`MC`, `MC4`, `I<ch><mode>`, `I9`/`I1`, `LL`, `!`, `S`, `&`, `H`, `J`, `X1`/`X2`.

## Matched families (AutoPilot → Remote, 12)

`X` (event 0), `@` (events 1+4), `V01R39` (event 5), `P...` (event 6),
11-field CSV (event 7), `C` (event 10), `a0`/`a1`/`a2` (event 13),
signed-number (event 15), `MS` (event 16), `#` (event 17), `MT`, `T`.

## AutoPilot-RX-only families (8) — accepted, no confirmed Remote producer

`Y`, `B2`, `W0`, `R1`, `LH1-4`, `D`, `A`, `T_OTHER`. Each is a real,
confirmed parser branch with no matching literal/builder found anywhere
in the Remote image. **`D` is the notable case**: its AutoPilot-side
round trip (RX → persist to flash → reload on fresh boot) is
execution-confirmed, but no Remote UI sender was ever located —
"transaction proven" and "producer confirmed" are different claims,
and this census keeps them distinct.

## Remote-RX-only family (1) — parsed, no confirmed AutoPilot producer

`B_UNKNOWN` — the Remote's inbound dispatcher (`FUN_00010ce4`) has a
real, non-trivial case for a leading `0x42` (`'B'`) byte (calls the
same `S`/`!` parser, checks a state value against `0x28`). Already
documented (`auto-mode-and-plus-command.md`,
`manual-to-firmware-traceability.json`) as part of the shared
`['a','x']`/`'B'` reconnect-rearm dispatch — re-identified here, not
newly discovered — but no AutoPilot producer for a leading `'B'` byte
exists anywhere in the 18-event dispatcher, `MT`, or `T`. Genuinely
orphaned on the producer side.

## Producer-only / orphan families

**Remote-TX-only (9)**, no AutoPilot RX match: `V`, `MS` (with pipe —
see naming collision below), `MR`, `MM`, `KK`, `E1` (4 fixed-value
variants), `N`, `IX` (weakest evidence — literal only, xref
unresolved), and `W` bare (real sender, but AutoPilot's `W` branch
requires a second digit — a genuine variant-mismatch, not a clean
orphan).

**AutoPilot-TX-only (3)**, no Remote RX match: event 8 (3-part CSV),
event 9 (scaled numeric), events 11/12/14 (`M1`/`M2`/`M3`) — all
endpoint-only, no producer *and* no consumer found; likely dormant/legacy.

## Binary families

`0xF0` and `0xE0` are gated **before** the ASCII dispatch chain
(`0x8258`/`0x8260`/`0x82c6`) — confirmed not lost in this ASCII-oriented
enumeration. Both `BINARY_FAMILY_MATCHED`, direction Remote → AutoPilot,
sender `FUN_0000be94` (live-jog loop). `0xE0`'s exact field widths
remain unresolved (pre-existing gap, not addressed here).

## 868/915 comparison

**No genuine protocol differences.** Reused the existing whole-image
byte-diff audits rather than re-running per-variant census — any
dispatch/builder logic difference would already show up there:

- **AutoPilot 868 vs 915**: byte-identical except one 4-byte RF
  center-frequency `.data` constant.
- **Mando 868 vs 915**: resolves entirely to one link-time
  function-relocation artifact (confirmed directly for the Remote's own
  inbound dispatcher, `FUN_00010ce4`→`FUN_00010cf4`, +0x10 shift,
  logic identical) plus two cosmetic strings.

Per instruction, the RF-band constant is **not** counted as a protocol
family difference.

## Newly found `J`

- **AutoPilot RX accepts `J`**: yes — `0x88b2` (`cmp r3,#0x4a`),
  branches into the motor-driver disable path (`FUN_00007868`/
  `FUN_000077f8`).
- **Does Remote TX ever emit `J`**: yes — **concretely re-verified this
  session**: `FUN_00005a50` sends the literal bytes `J|\0` (dumped
  directly from flash) three times. It has **12 callers** across the
  image (`G`-builder, `&`-query, `S`/`!`-handler, the "RUNNING"
  renderer, `T`-status redraw, boot, and others) — `J` (like `H`) is a
  **generic transaction postamble**, not one dedicated UI action.
- **Does Remote RX understand a `J` response**: no evidence found.
- **Does AutoPilot TX emit anything in response**: no evidence found
  (no pending-event write visible in the handler, unlike `G`/`S`/`!`/`&`).

Semantics kept minimal per instruction: known effect = disable-related
path. Full `'J'` behavior not re-expanded here.

## Surprises / gaps

- `H`/`J` are shared pre/postambles around many transactions, not
  independent commands.
- `MS` is **two unrelated families** in opposite directions (AutoPilot
  literal `MS` vs. Remote `MS|`) — flagged to prevent future conflation.
- `B_UNKNOWN` is a real orphan Remote-RX case with no known AutoPilot
  producer.
- `D`'s proven round trip vs. unconfirmed producer is a distinct-claims
  case worth remembering.
- The event-7 11-vs-10 field mismatch is real and silent on both sides
  — exactly the class of thing this census exists to catch.

## See also

[`command-inventory.md`](command-inventory.md),
[`event-map.md`](event-map.md),
[`research/autopilot_static_inventory/commands.csv`](../../research/autopilot_static_inventory/commands.csv),
[`research/autopilot_static_inventory/responses.csv`](../../research/autopilot_static_inventory/responses.csv).
