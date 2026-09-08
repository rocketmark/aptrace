# Firmware Inventory

## Files

Source: `~/github/aptrace/Autopilot_firm/` (untouched originals) and
`research/firmware/originals/` (working copies + hashes; the `.bin` files
themselves are gitignored — proprietary firmware is not published from this
repo — only `SHA256SUMS.txt` is tracked).

| File | Size (bytes) | SHA-256 |
|---|---|---|
| `firmware_autopilot868.bin` | 70768 | `6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3` |
| `firmware_autopilot915.bin` | 70768 | `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |
| `firmware_mando868.bin` | 138304 | `cf74cf03b375eaed1f48ff2ab0852a2cbbca4ece1ea8eb0989ec938af5e431bc` |
| `firmware_mando915.bin` | 138304 | `abb71190982793872f5752f620adeaa3b3516d6266fe9433d0e6e680a4e629b9` |

Two products, each in EU (868 MHz) and US/other (915 MHz) radio variants:

- **`autopilot`** — the motion-control unit. This is APTrace's current and
  only target; see [`docs/project-status.md`](../project-status.md)'s
  "explicit do-not-start-yet items" for why the `mando` files haven't been
  touched yet.
- **`mando`** — the RF remote control. Not yet analyzed by APTrace beyond
  the vector-table scan (below) and the separate, purely static
  `research/autopilot_static_inventory/` pass, which reverse-engineered
  addresses in *both* images by reading disassembly, not by running
  anything.

868/915 variants of the same product are near-identical in size and vector
table content (radio configuration differs, not core logic).

## Provenance

- User manual: `PerformingRigs_UserManual_AutoPilot.pdf` (repo root) —
  yielded no extractable MCU-level text (image-based/compressed PDF
  streams), not useful for firmware analysis.
- Flashing mechanism: `Autopilot_firm/update_firmware.bat` invokes `bossac`
  (the standard flasher for Atmel/Microchip SAM-D/E parts) with
  `--offset=0x4000`, and searches for the device via USB VID `239A`
  (Adafruit Industries). See
  [`docs/firmware/firmware-layout.md`](firmware-layout.md) for what this
  implies about the memory layout.
