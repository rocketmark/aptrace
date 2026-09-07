# AutoPilot parser dispatch map — v0.1

Entry: `0x8258`

```text
first byte
├─ 0xF0 -> binary motor/control frame path
├─ 0xE0 -> binary motor/control frame path
├─ 'Y'  -> parameterized path -> 0x7a00
├─ '+'  -> state/update path -> 0x806c
├─ 'G'  -> state/transition path
├─ 'B'
│  ├─ '0' -> B0
│  ├─ '1' -> B1
│  └─ '2' -> B2
├─ 'T'
│  └─ 'R' -> TR0/TR1 boolean family
├─ 'W'
│  ├─ '0' -> 0x72ac
│  └─ '1' -> state checks -> 0x4630 / 0x6e4c
├─ 'R'
│  ├─ '0' -> R0
│  ├─ '1' -> R1
│  └─ '2' -> R2
├─ 'M'
│  └─ 'C'
│     ├─ channel '0'..'3' -> 0x7a98(channel)
│     └─ channel '4'      -> 0x7a98(0..3)
├─ 'I'  -> channel/value parser; can stop/update a motor via 0x5274
├─ 'L'  -> 0x54e0
│  ├─ 'H' + '1'..'4'
│  └─ 'L'
│     ├─ '1' -> clear/reset first-limit state
│     └─ '2' -> compare/order two positions and mark limits valid
├─ 'D'  -> state/value path
├─ '!'  -> set event/state flag
├─ 'S'  -> derive a status code from current state
├─ '&'  -> handshake/state flags
├─ 'H'  -> set global flag + timestamp
├─ 'J'  -> clear same flag; state-dependent downstream routine
├─ 'A'  -> acquire value, constrain 20..25, update state
└─ 'X'
   ├─ '1'
   └─ '2'
```

## Important mismatches

The remote contains and actively transmits several packets that are **not explained by this visible dispatch tree**: `MS|`, `MR|`, `MM|`, `N|`, `KK|`, `E1,...|`, `V...|`, and possibly bare `W|`/`G|` variants. That does not mean they are dead. Possibilities include:

- a second parser or protocol state outside `0x8258`,
- commands consumed by the radio/remote side rather than AutoPilot,
- compatibility/legacy device modes,
- query packets handled by code paths we have not yet connected,
- version skew between shared code and current product behavior.

Resolving these mismatches is one of the next static-analysis goals.
