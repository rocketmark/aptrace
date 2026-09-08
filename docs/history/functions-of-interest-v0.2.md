> **Superseded by v0.3.** This is an earlier pass of the same document;
> `research/autopilot_static_inventory/functions-of-interest.md` (v0.3) is
> the current version — it revises and extends this one (e.g. the AutoPilot
> function table gained many more entries and confidence annotations, and
> the event-8 "firmware version" hypothesis was downgraded once `&| ->
> V01R39` was proven). Kept here only for diff/provenance purposes.

# Functions of interest — v0.2 (historical, superseded by v0.3)

## Remote firmware

| Address | Role | Confidence |
|---:|---|---|
| `0x58a8` | **Primary text RF transmit wrapper** | high |
| `0x5864` | Single-byte RF transmit wrapper | medium-high |
| `0x58ec` | `MS|` / `MR|` sender | high |
| `0x591c` | `G|` / `W|` request loop | high |
| `0x5970` | `V<n>,|` builder/sender | high |
| `0x59cc` | `X<digit>|` builder/sender | high |
| `0x5a14` | `H|` sender | high |
| `0x5a50` | `J|` sender | high |
| `0x5a8c` | `MC...|` builder/sender | high |
| `0xb440` | **LoRa receive poll → RX ring buffer** | high |
| `0xb4f8` | Receive-ring bytes available | high |
| `0x583c` | Consume one RX byte | high |
| `0xb51c` | Parse signed decimal until comma | high |
| `0x10cf4` | **Main asynchronous AutoPilot-response dispatcher** | very high |

## AutoPilot firmware

| Address | Role | Confidence |
|---:|---|---|
| `0x8258` | **Main inbound packet parser/dispatcher** | very high |
| `0x8960` | LoRa packet assembly loop | very high |
| `0x89f0` | `|` terminator check | very high |
| `0x8a34` | RX loop → parser call | very high |
| `0x7f84` | **Single-byte AutoPilot outbound wrapper** | very high |
| `0x8c10` | **String/text AutoPilot outbound wrapper** | very high |
| `0x9268` | **Outbound pending-event dispatcher (IDs 0–17)** | very high |
| `0x74ac` | Builds periodic `MTddddx|` status packet | high |
| `0x9464` | Connect/boot loop that periodically sends MT status | high |
| `0x8c70` | Event-7 large numeric CSV/status builder | high |
| `0x8d74` | Event-8 decimal-component builder | high structure / medium semantics |
| `0x8ddc` | Event-15 selected numeric-value builder | high structure / low semantics |
| `0x8e18` | `T...|` telemetry builder(s) | high structure / medium semantics |
| `0x54e0` | L-family handler (`LH1..4`, `LL1/2`) | high |
| `0x7a98` | `MC` motor-config record parser/apply | high |
| `0x5274` | Candidate motor stop/state sink | medium-high |
| `0x5448` | Candidate motor motion update sink | medium-high |

## Recommended harness seams

The shortest end-to-end application-level loop is now:

`Remote 0x58a8 → AutoPilot 0x8258 → AutoPilot 0x9268 → AutoPilot 0x7f84/0x8c10 → Remote 0x10cf4`

For a first harness milestone, hook these application boundaries rather than emulating SPI/LoRa hardware.
