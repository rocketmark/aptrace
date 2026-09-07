# RF / protocol boundaries — v0.1

## Remote transmit boundary

`0x58a8` is the primary remote string-transmit wrapper. Its shape is:

1. wait for the inter-packet timing condition,
2. begin a radio packet,
3. write the supplied C string,
4. end/transmit the packet,
5. update the last-send timestamp.

This is the highest-value remote hook for the software-only harness: replacing or intercepting it captures the **actual packet produced by the real remote logic**.

A secondary routine at `0x5864` appears to transmit a single byte.

## AutoPilot receive boundary

The LoRa receive/assembly routine begins at `0x8960`. It reads bytes into a shared RAM buffer and checks incoming bytes against ASCII `|` (`0x7c`) at `0x89f0`. Once a complete packet is assembled, it null-terminates the buffer and calls the dispatcher at `0x8258` from `0x8a34`.

Therefore the cleanest software-only injection boundary is **immediately before `0x8258`**; the cleanest protocol-observation boundary is **`0x58a8` on the remote**.

## Protocol is hybrid, not purely text

Before the ASCII dispatch chain, `0x8258` checks the first byte for:

- `0xF0` — dedicated binary frame path
- `0xE0` — dedicated binary frame path

Both paths unpack compact motor/value records and can reach candidate motor sinks (`0x5274`, `0x5448`). These are priority targets because they may correspond to real-time/pass-through motion rather than menu commands.

## Suggested first virtual connection

```text
remote compiled logic
        |
     0x58a8  (capture C string)
        |
   virtual packet queue
        |
AutoPilot packet buffer
        |
     0x8258  (execute parser)
        |
 candidate state/motor sinks
```

This lets the harness prove remote -> protocol -> AutoPilot behavior without emulating LoRa/SPI first.
