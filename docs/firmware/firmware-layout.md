# AutoPilot / Mando Firmware — Layout Notes

Source images: `~/github/aptrace/Autopilot_firm/` (originals, untouched).
Working copies + hashes: `~/github/aptrace/research/firmware/originals/` (see `SHA256SUMS.txt`).

## Files

| File | Size (bytes) | SHA-256 |
|---|---|---|
| firmware_autopilot868.bin | 70768 | 6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3 |
| firmware_autopilot915.bin | 70768 | 0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920 |
| firmware_mando868.bin | 138304 | cf74cf03b375eaed1f48ff2ab0852a2cbbca4ece1ea8eb0989ec938af5e431bc |
| firmware_mando915.bin | 138304 | abb71190982793872f5752f620adeaa3b3516d6266fe9433d0e6e680a4e629b9 |

Two products share this build: **autopilot** (motion-control unit, our primary target) and
**mando** (RF remote control), each in EU (868 MHz) and US (915 MHz) radio variants. The 868/915
pair for each product differs only in radio config, not core logic (autopilot868 vs autopilot915
have identical size and near-identical vector tables, offset by a few bytes).

## Flashing mechanism (`Autopilot_firm/update_firmware.bat`)

```
bossac -i -d --port=%com% -U -i --offset=0x4000 -w -v %FILENAME% -R
```

- Uses `bossac` (BOSSA), the standard flasher for Atmel/Microchip SAM-D/E parts with a
  UART/USB bootloader (used by Arduino Due/Zero and all Adafruit SAMD boards).
- Device is found via `wmic ... | findstr VID_239A` — **USB VID 0x239A is Adafruit
  Industries**. Board enters bootloader via the classic 1200-baud touch-reset trick.
- `--offset=0x4000`: application is flashed starting at flash address **0x00004000**,
  i.e. after a 16 KB bootloader region. **The `.bin` files are the application image
  only — file offset 0 corresponds to flash address 0x4000, not 0x0.**

## MCU identification

Embedded build-path strings in all four binaries (`strings` on the `.bin`):

```
C:\Arduinos\Arduino ATSAMD51 - autopilot\portable\packages\adafruit\hardware\samd\1.7.11\libraries\SPI\SPI.cpp
C:\Arduinos\Arduino ATSAMD51\portable\packages\adafruit\hardware\samd\1.7.11\libraries\SPI\SPI.cpp
```

This directly names the MCU and toolchain:

- **MCU: Microchip/Atmel ATSAMD51** — Cortex-**M4F** (has FPU), not the more common
  SAMD21 (Cortex-M0+). Confirmed independently by the initial stack pointer (see below).
- **Toolchain: Arduino IDE + Adafruit SAMD board package v1.7.11** (`arm-none-eabi-gcc`
  under the hood, Adafruit's fork of the Arduino SAMD core).
- **Bootloader: Adafruit UF2/bossac-style bootloader**, 16 KB (`0x0`–`0x3FFF`), consistent
  with the `--offset=0x4000` flashing command.

Initial stack pointer in every image is `0x20030000` = `0x20000000 + 0x30000` (192 KB from
RAM base). ATSAMD51 parts with 192 KB SRAM are the x19/x20 die variants (512 KB / 1 MB
flash respectively) — used on boards like Adafruit Feather M4 Express, ItsyBitsy M4, Grand
Central M4. Exact flash size is not yet pinned down (138 KB max firmware size observed is
consistent with either 512 KB or 1 MB flash); not needed for the feasibility spike.

**Working assumptions for APTrace:**
- Flash base (absolute): `0x00000000` (standard Cortex-M internal flash mapping; ATSAMD51 flash starts at 0x0)
- Bootloader region: `0x00000000`–`0x00003FFF` (not present in our `.bin` files)
- Application flash base (`.bin` file offset 0): `0x00004000`
- RAM base: `0x20000000`, size `0x30000` (192 KB), top `0x20030000`
- Endianness: little-endian (standard for Cortex-M)
- FPU: present (M4F) — VFP/NEON-lite instructions possible in float-heavy code paths

## Vector table (validated via `tools/vector_scan.py`)

All four images have a clean, standard ARMv7-M vector table at file offset 0
(= flash address 0x4000). Confirmed by: reserved slots (indices 7,8,9,10,13) are exactly
zero, and system fault handlers (NMI/HardFault/MemManage/BusFault/UsageFault/SVC/DebugMon/
PendSV) all share one common "default handler" stub address, which is the normal pattern
for a CMSIS-style startup file where most exceptions alias to a single weak handler and only
a few are actually implemented.

### firmware_autopilot868.bin / firmware_autopilot915.bin (near-identical)

| Vector | Address (autopilot868) | Note |
|---|---|---|
| Initial SP | 0x20030000 | top of 192KB RAM |
| Reset_Handler | 0x0000cc25 → 0xcc24 | distinct from default handler |
| Default handler (NMI/HardFault/.../PendSV/most IRQs) | 0x0000cc11 → 0xcc10 | shared stub |
| SysTick_Handler | 0x0000cca5 → 0xcca4 | distinct — real millis()/tick handler |
| IRQ10_Handler | 0x0000952d → 0x952c | distinct |
| IRQ12..IRQ27_Handler | 0xcbb1..0xcc0b range | distinct, sequential — likely a peripheral IRQ block (SERCOM0-7 style on SAMD51) |
| IRQ31..IRQ35_Handler | 0x0000a37d → 0xa37c (all identical) | distinct from default, shared among themselves — likely one handler registered for a group of related IRQs (e.g. all TC/TCC timer channels) |

### firmware_mando868.bin / firmware_mando915.bin (near-identical, larger image)

| Vector | Address (mando868) |
|---|---|
| Initial SP | 0x20030000 |
| Reset_Handler | 0x00016795 → 0x16794 |
| Default handler | 0x00016783 → 0x16782 |
| SysTick_Handler | 0x00016815 → 0x16814 |
| IRQ10_Handler | 0x00014881 → 0x14880 |
| IRQ12..IRQ27_Handler | 0x16721..0x1677b range, distinct |
| IRQ31..IRQ35_Handler | 0x00011d21 → 0x11d20 (shared) |

Full dumps (56 entries: 16 system + 40 IRQ) reproducible via:

```
python3 tools/vector_scan.py research/firmware/originals/firmware_autopilot868.bin \
    --flash-base 0x4000 --ram-size 0x30000 --num-irq 40
```

## Candidate entry points for Step 5/6/7 experiments

- **Reset_Handler** (0xcc24 / autopilot868) — likely CMSIS `SystemInit` + Arduino `init()` +
  `main()`, non-trivial; per the plan, prefer a smaller function first.
- **SysTick_Handler** (0xcca4 / autopilot868) — small, real, periodic; good "near-leaf"
  candidate for first Macaw→Crucible experiment (Step 7).
- **IRQ12–IRQ27 block** — 16 consecutive, distinct, tightly-packed handler addresses
  (each ~6 bytes apart) strongly suggest a set of trivial trampolines (each just tail-calls
  a common ISR body with a different argument) — classic SAMD51 SERCOM/EIC pattern. Good
  candidates for the Step 9 "MMIO read influences a branch" demonstration once we identify
  which peripheral they correspond to.
- **Default handler** (0xcc10 / autopilot868) — trivial (likely infinite loop or
  `__attribute__((weak))` stub), a good sanity-check target for the very first
  Macaw discovery + Crucible translation smoke test before attempting anything with real
  logic.

## Open questions / next steps

- Cross-check discovered handler addresses against Adafruit SAMD51 CMSIS startup file
  (`startup_samd51.c` in the Adafruit board package) to confirm IRQ numbering matches
  standard ATSAMD51 NVIC layout (SERCOM0-7, TC0-5, TCC0-4, EIC, ADC0/1, DAC, etc.).
- Identify MMIO ranges actually touched once we have basic block recovery (Step 5/6) —
  ATSAMD51 peripheral base addresses are well documented in the datasheet and are a fixed,
  known memory map we can hardcode into APTrace's `CortexMAddressSpace`.
- PDF manual (`PerformingRigs_UserManual_AutoPilot.pdf`) yielded no extractable MCU-level
  text (likely image-based/compressed streams) — not useful for firmware analysis, only
  possibly for end-user/operational context.
