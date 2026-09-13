# Functions of interest — v0.3

## Remote firmware

| Address | Role | Confidence |
|---:|---|---|
| `0x58a8` | **Primary text RF transmit wrapper** | high |
| `0x5864` | Single-byte RF transmit wrapper | medium-high |
| `0x58ec` | `MS|` / `MR|` sender | high |
| `0x591c` | bare `G|` / `W|` request path | high |
| `0x5970` | `V<n>,|` builder/sender | high |
| `0x59cc` | `X<digit>|` builder/sender | high |
| `0x5a14` | `H|` sender | high |
| `0x5a50` | `J|` sender | high |
| `0x5a8c` | `MC...|` builder/sender | high |
| `0xb440` | **LoRa receive poll -> RX ring buffer** | high |
| `0xb4f8` | RX bytes available | high |
| `0x583c` | Consume one RX byte | high |
| `0xb51c` | Parse signed decimal until comma | high |
| `0xb59c` | **`G...|` synchronous request/retry, waits for `#`** | very high |
| `0xb680` | Builds `G<d><d><seq>|`, seq cycles 1..9 | very high |
| `0xb79c` | **`W1|` synchronous request/retry, waits for `#`** | very high |
| `0xb834` | Sends short `I9|` / `I1|`, parses numeric response | high structure / low semantic |
| `0xb958` | **Builds `I<1..4><0/1>|`, waits for per-channel numeric response** | very high structure |
| `0xba98` | **`&|` firmware-version request; captures `V01R39`** | very high |
| `0xc440` | **`S|`/`P...` then `!0|`/`!1|` bulk synchronous state/config exchange** | very high |
| `0xfa10` / `0xfadc` | Information-screen rendering; consumes captured AutoPilot firmware version | high |
| `0x10cf4` | **Main asynchronous AutoPilot-response dispatcher** | very high |

## AutoPilot firmware

| Address | Role | Confidence |
|---:|---|---|
| `0x4328` | Initializes firmware-version response buffer to **`V01R39`** | very high |
| `0x4440` | Builds event-13 `a0/a1/a2` status payload | very high structure |
| `0x4618` | Event-17 helper: schedules `#` count 2 when guard permits | very high |
| `0x4630` | Event-17 helper: schedules caller-supplied `#` count | very high |
| `0x8258` | **Main inbound packet parser/dispatcher** | very high |
| `0x8960` | LoRa packet assembly loop | very high |
| `0x89f0` | `|` terminator check | very high |
| `0x8a34` | RX loop -> parser call | very high |
| `0x7f84` | **Single-byte outbound wrapper** | very high |
| `0x8c10` | **String/text outbound wrapper** | very high |
| `0x9268` | **Outbound pending-event dispatcher (IDs 0-17)** | very high |
| `0x74ac` | Builds periodic `MTddddx|` status packet | high |
| `0x9464` | Connect/boot loop; startup schedules event13 x5 | high |
| `0x8c70` | **Event-7 11-field numeric CSV builder** | very high structure |
| `0x8d74` | Event-8 three-part numeric formatter; no producer found | high structure / low semantic |
| `0x8ddc` | **Event-15 selected per-channel signed numeric builder** | high |
| `0x8e18` | `T...|` telemetry builder(s) | high structure / medium semantics |
| `0x54e0` | L-family handler (`LH1..4`, `LL1/2`) | high |
| `0x7a98` | `MC` motor-config record parser/apply | high |
| `0x5274` | Candidate motor stop/state sink | medium-high |
| `0x5448` | Candidate motor motion update sink | medium-high |

## Pending-event producer sites

See `pending-writes.csv`. High-value injection/coverage points include:

- `0x83ea`: `G` -> event17 `#`
- `0x87ba`: `!` -> event7 CSV
- `0x87d2`: `S` -> event6 `P...`
- `0x889a`: `&` -> event5 `V01R39`
- `0x8b70`: `I` completion -> event15 numeric
- `0x5ea4`: event16 `MS` x3
- `0x94b2`: event13 `a0/a1/a2` x5 at startup

## Recommended harness seams

Fastest application-level loop:

`Remote 0x58a8 -> AutoPilot 0x8258 -> pending[event] -> AutoPilot 0x9268 -> 0x7f84/0x8c10 -> Remote synchronous parser or 0x10cf4`

For the first executable tests, the strongest known transactions are `G`, `&`, `S`, `!`, and dynamic `I`, because both sides of each exchange are now statically mapped.
