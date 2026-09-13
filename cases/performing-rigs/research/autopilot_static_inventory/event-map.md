# AutoPilot outbound event map — v0.3

Dispatcher: `0x9268`  
Pending counter base: `0x200025bc`

| Event | Output | Direct producer found? | Main active context |
|---:|---|---|---|
| 0 | `X` | no | endpoint only |
| 1 | `@` | yes | count 3 on bounds/position condition |
| 2 | none | no | — |
| 3 | none | no | — |
| 4 | `@` | yes | `R0` x1 / `R1` x2 |
| 5 | `V01R39` | yes | `&|` firmware-version query |
| 6 | `P...` | yes | `S|` query |
| 7 | 11-field numeric CSV | yes | `!0|` / `!1|` |
| 8 | three-part numeric CSV | no | dormant/unknown |
| 9 | scaled numeric | no | dormant/unknown |
| 10 | `C` | yes | timed monitor |
| 11 | `M1` | no | likely dormant/legacy |
| 12 | `M2` | no | likely dormant/legacy |
| 13 | `a0/a1/a2` | yes | startup x5 / state-change x1 |
| 14 | `M3` | no | likely dormant/legacy |
| 15 | signed per-channel numeric | yes | dynamic `I` completion |
| 16 | `MS` | yes | connection/state transition x3 |
| 17 | `#` | yes | `G` x1; helper x2; `W1` x5 conditional |

Literal endpoints remain verified at `0x1112b` (`MS`), `0x1112e` (`M1`), `0x11131` (`M2`), and `0x11134` (`M3`).
