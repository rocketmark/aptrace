#!/usr/bin/env python3
"""Non-distributable Unicorn prototype for the trigger-input mitigation
investigation (docs/investigations/trigger-input-mitigation-patchability.md).

This patches ONLY the in-memory Unicorn image of firmware_autopilot868.bin,
never the .bin file on disk. It exists to answer one narrow question: can a
consecutive-sample debounce, implemented as a real Thumb-2 machine-code
trampoline, be exercised concretely against the exact, already-confirmed
seven-guard gate (0x9202-0x9231) and second-digitalRead branch (0x922c/
0x922e) from trigger-input-concrete-path.md and trigger-input-symbolic-
crosscheck.md -- without hand-waving the machine code.

Patch (in Unicorn memory only):
  0x922e: beq.w 0x8f98   -- replaced with --   b.w CAVE
CAVE (a harness-only scratch page, 0x00020000, mapped via extra_maps --
not a real flash address in any AutoPilot unit) holds a hand-encoded,
capstone-verified Thumb-2 trampoline implementing consecutive-sample
debounce: PB05 (R0 at cave entry, already computed by the real,
unmodified digitalRead(0x39) call at 0x9228) must read LOW (R0==0) for N
consecutive polls of this exact gate before the real accept target
(0x8f98) is taken; any HIGH poll resets the count to 0. The counter lives
at 0x20001fc4, one of the RAM bytes trigger-input-concrete-path.md Part 4
confirms is unconditionally zeroed by FUN_00005d44 at boot and never read
by any other code in the image (exhaustive xref) -- reused, not invented,
per the investigation's own preference for existing dead state.

Every other input this script holds concrete (r5=0x20002524, r6=
0x20003120, the four per-channel idle bytes, the two provenance-closed
gate cells 0x20001b38/0x200000d8) is exactly the already-published,
disclosed background state from trigger-input-concrete-path.md Part 9 and
trigger-input-symbolic-crosscheck.md -- nothing new is assumed about the
firmware's own behavior, only about the candidate patch.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from concrete import ConcreteMachine  # noqa: E402

try:
    from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
    _CAPSTONE = True
except ImportError:
    _CAPSTONE = False

FIRMWARE = Path(__file__).parent.parent.parent / "research/firmware/originals/firmware_autopilot868.bin"

# -- real, already-confirmed addresses (trigger-input-concrete-path.md,
# trigger-input-symbolic-crosscheck.md) -----------------------------------
GATE_ENTRY = 0x9202
PATCH_SITE = 0x922e          # the beq.w 0x8f98 this prototype replaces
ACCEPT_TARGET = 0x8f98       # the real config-reload tail-jump
REJECT_TARGET = 0x9232       # the real "no-op" epilogue (add sp,#0xc; pop.w{r4-r11,pc})
R5_BASE = 0x20002524         # per-channel device-state array (confirmed via regOverrides)
R6_BASE = 0x20003120         # trigger_report_enable byte's own address
GATE_CELL_1 = 0x20001b38     # must == 0x7b (provenance-closed: '+' mode=0x62 finalize)
GATE_CELL_2 = 0x200000d8     # must == 9    (provenance-closed: all-4-idle check)
PB05_MMIO = 0x410080a0       # PORT.GROUP1.IN, bit 5 (confirmed pin mapping)
PB05_BIT = 5
MMIO_BASE = 0x40000000       # same wide window virtual_link.py uses -- default 1MB misses PORT at 0x41000000
MMIO_SIZE = 0x4000000

# -- candidate mitigation's own new state ----------------------------------
COUNTER_ADDR = 0x20001fc4    # confirmed dead RAM (trigger-input-concrete-path.md Part 4)
CAVE = 0x00020000            # harness-only scratch page; NOT a real flash address
CAVE_PAGE_SIZE = 0x1000


# ---------------------------------------------------------------------------
# Minimal, self-contained Thumb/Thumb-2 encoder for exactly the instructions
# this prototype needs. Cross-checked two ways: (1) capstone disassembly
# round-trip below, when capstone is importable; (2) the empirical Unicorn
# run itself -- if an encoding were wrong the trace would show it landing on
# the wrong PC or faulting, immediately visible in the printed regression
# matrix. Not a general assembler -- do not extend beyond this file's needs.
# ---------------------------------------------------------------------------

def u16(hw):
    return hw.to_bytes(2, "little")


def enc_movw(rd, imm16):
    imm4 = (imm16 >> 12) & 0xF
    i = (imm16 >> 11) & 0x1
    imm3 = (imm16 >> 8) & 0x7
    imm8 = imm16 & 0xFF
    hw1 = 0xF240 | (i << 10) | imm4
    hw2 = (imm3 << 12) | (rd << 8) | imm8
    return u16(hw1) + u16(hw2)


def enc_movt(rd, imm16):
    imm4 = (imm16 >> 12) & 0xF
    i = (imm16 >> 11) & 0x1
    imm3 = (imm16 >> 8) & 0x7
    imm8 = imm16 & 0xFF
    hw1 = 0xF2C0 | (i << 10) | imm4
    hw2 = (imm3 << 12) | (rd << 8) | imm8
    return u16(hw1) + u16(hw2)


def enc_cmp_imm(rn, imm8):
    # T1: 00101 Rn imm8
    hw = (0b00101 << 11) | (rn << 8) | (imm8 & 0xFF)
    return u16(hw)


def enc_ldrb_imm(rt, rn, imm5):
    # T1: 01111 imm5 Rn Rt
    hw = (0b01111 << 11) | ((imm5 & 0x1F) << 6) | (rn << 3) | rt
    return u16(hw)


def enc_strb_imm(rt, rn, imm5):
    # T1: 01110 imm5 Rn Rt
    hw = (0b01110 << 11) | ((imm5 & 0x1F) << 6) | (rn << 3) | rt
    return u16(hw)


def enc_adds_imm3(rd, rn, imm3):
    # T1 ADD (register/immediate small form): 0001110 imm3 Rn Rd
    hw = (0b0001110 << 9) | ((imm3 & 0x7) << 6) | (rn << 3) | rd
    return u16(hw)


def enc_movs_imm(rd, imm8):
    # T1: 00100 Rd imm8
    hw = (0b00100 << 11) | (rd << 8) | (imm8 & 0xFF)
    return u16(hw)


def enc_bcc_t1(cond, src_addr, target_addr):
    # narrow conditional branch, 2 bytes, PC = src_addr+4, range +-256
    pc = src_addr + 4
    offset = target_addr - pc
    assert offset % 2 == 0 and -256 <= offset <= 254, f"bcc range: {offset}"
    imm8 = (offset // 2) & 0xFF
    hw = (0b1101 << 12) | (cond << 8) | imm8
    return u16(hw)


def enc_bw_t4(src_addr, target_addr):
    # unconditional wide branch, 4 bytes, PC = src_addr+4, range +-16MB
    pc = src_addr + 4
    offset = target_addr - pc
    assert offset % 2 == 0, "b.w offset must be even"
    e = offset // 2  # 24-bit signed field
    assert -(1 << 23) <= e < (1 << 23), f"b.w out of range: {offset}"
    e &= (1 << 24) - 1  # two's complement, 24 bits
    s = (e >> 23) & 1
    i1 = (e >> 22) & 1
    i2 = (e >> 21) & 1
    imm10 = (e >> 11) & 0x3FF
    imm11 = e & 0x7FF
    j1 = (i1 ^ 1) ^ s  # I1 = NOT(J1 xor S)  =>  J1 = NOT(I1) xor S
    j2 = (i2 ^ 1) ^ s
    hw1 = 0xF000 | (s << 10) | imm10
    hw2 = 0x9000 | (j1 << 13) | (j2 << 11) | imm11
    return u16(hw1) + u16(hw2)


COND_NE = 0b0001
COND_LO = 0b0011  # unsigned lower (carry clear)


def build_cave(n_threshold):
    """Consecutive-sample debounce trampoline. R0 is the real digitalRead
    return value (0 = PB05 LOW) live at cave entry -- 0x922c's own
    `cmp r0,#0` already ran before the patched branch; this redoes the
    compare itself (2 bytes) rather than relying on flags surviving the
    intervening branch, so the cave is self-contained."""
    code = bytearray()
    addrs = {}

    def emit(name, enc_fn, *args):
        addrs[name] = CAVE + len(code)
        code.extend(enc_fn(*args))

    # r3 = COUNTER_ADDR
    emit("movw", enc_movw, 3, COUNTER_ADDR & 0xFFFF)
    emit("movt", enc_movt, 3, (COUNTER_ADDR >> 16) & 0xFFFF)
    emit("cmp_r0", enc_cmp_imm, 0, 0)
    bne_addr = CAVE + len(code)
    code.extend(b"\x00\x00")  # placeholder, patched below (2 bytes)
    emit("ldrb", enc_ldrb_imm, 2, 3, 0)
    emit("adds", enc_adds_imm3, 2, 2, 1)
    emit("strb1", enc_strb_imm, 2, 3, 0)
    emit("cmp_r2", enc_cmp_imm, 2, n_threshold)
    blo_addr = CAVE + len(code)
    code.extend(b"\x00\x00")  # placeholder
    accept_bw_addr = CAVE + len(code)
    code.extend(b"\x00\x00\x00\x00")  # placeholder b.w ACCEPT_TARGET
    reset_addr = CAVE + len(code)
    emit("movs0", enc_movs_imm, 2, 0)
    emit("strb2", enc_strb_imm, 2, 3, 0)
    reject_addr = CAVE + len(code)
    reject_bw_addr = CAVE + len(code)
    code.extend(b"\x00\x00\x00\x00")  # placeholder b.w REJECT_TARGET

    code[bne_addr - CAVE:bne_addr - CAVE + 2] = enc_bcc_t1(COND_NE, bne_addr, reset_addr)
    code[blo_addr - CAVE:blo_addr - CAVE + 2] = enc_bcc_t1(COND_LO, blo_addr, reject_addr)
    code[accept_bw_addr - CAVE:accept_bw_addr - CAVE + 4] = enc_bw_t4(accept_bw_addr, ACCEPT_TARGET)
    code[reject_bw_addr - CAVE:reject_bw_addr - CAVE + 4] = enc_bw_t4(reject_bw_addr, REJECT_TARGET)

    return bytes(code)


def verify_with_capstone(cave_bytes):
    if not _CAPSTONE:
        print("[!] capstone not installed -- skipping static disassembly cross-check "
              "(Unicorn's own concrete execution below is still authoritative)", file=sys.stderr)
        return
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    print("--- capstone disassembly of the hand-encoded cave (static cross-check) ---")
    for insn in cs.disasm(cave_bytes, CAVE):
        print(f"  0x{insn.address:x}:  {insn.mnemonic}\t{insn.op_str}")
    print()


def pb05_seed(level):
    """level: True = HIGH, False = LOW. Bit 5 of PORT.GROUP1.IN, as a
    seed_mem entry -- MUST go through run()'s own seed_mem (applied AFTER
    any fresh=True reset), never a direct pre-run mem_write. A direct
    write before calling run() is exactly the bug this script's own first,
    failing attempt had for the flash patch (see poll_once's docstring):
    on the first (fresh=True) poll of every scenario, reset() silently
    restored PORT.GROUP1.IN to its pristine (zero/LOW) value, making every
    scenario's poll 0 behave as LOW regardless of the requested level."""
    value = (1 << PB05_BIT) if level else 0
    return (PB05_MMIO, value.to_bytes(4, "little"))


def poll_once(machine, pb05_high, first, extra_seed_mem=()):
    """One real, concrete pass through the gate + patched branch, entering
    at the function's own real block start (0x9202, Part 1 of
    trigger-input-symbolic-crosscheck.md), with the same regOverrides that
    slice used. `first=True` also (re-)seeds the background idle-gate
    state (and, via extra_seed_mem, the patch itself -- see below); later
    polls in the same scenario reuse fresh=False so the debounce counter
    persists across polls, exactly like consecutive real main-loop
    iterations (FUN_000093fc calls phase_ramp_state_machine__CUSTOM every
    iteration -- g-command-motor-subsystem-unlock.md).

    IMPORTANT: any hand-patched bytes (the cave, the redirected branch)
    MUST be delivered via extra_seed_mem on the first (fresh=True) call,
    not written directly to machine.uc beforehand -- ConcreteMachine's own
    ``reset()`` (which every fresh=True run() calls first) restores every
    *dirty* page back to its pristine, pre-patch snapshot, which would
    silently erase a patch applied before this function ever ran. Feeding
    the patch through seed_mem works because seed_mem is applied *after*
    reset() inside the same run() call (concrete.py's own run() orders
    them that way) -- confirmed necessary by this script's own first,
    failing attempt (bookends showed unpatched firmware behavior; see the
    investigation doc's prototype section)."""
    seed_mem = [pb05_seed(pb05_high)] + list(extra_seed_mem)
    if first:
        seed_mem += [
            (R5_BASE + 0, b"\x00"), (R5_BASE + 1, b"\x00"),
            (R5_BASE + 2, b"\x00"), (R5_BASE + 3, b"\x00"),
            (GATE_CELL_1, (0x7b).to_bytes(4, "little")),
            (GATE_CELL_2, bytes([9])),
            (R6_BASE, b"\x00"),
        ]
    result = machine.run(
        entry=GATE_ENTRY,
        reg_seed=[("r5", R5_BASE), ("r6", R6_BASE)],
        seed_mem=seed_mem,
        stop_at=[REJECT_TARGET, ACCEPT_TARGET],
        max_instructions=2000,
        fresh=first,
    )
    counter = machine.uc.mem_read(COUNTER_ADDR, 1)[0]
    pc = result.reg("pc") & ~1
    outcome = "ACCEPT(0x8f98)" if pc == ACCEPT_TARGET else (
        "reject(0x9232)" if pc == REJECT_TARGET else f"UNEXPECTED(0x{pc:x}, {result.stop_reason})")
    return outcome, counter, result.instructions_executed


def run_scenario(name, pb05_sequence, n_threshold, patch_bytes, cave_bytes):
    machine = ConcreteMachine(str(FIRMWARE), mmio_base=MMIO_BASE, mmio_size=MMIO_SIZE,
                               extra_maps=[(CAVE, CAVE_PAGE_SIZE)])
    print(f"=== Scenario: {name} (N={n_threshold}) ===")
    rows = []
    for i, level in enumerate(pb05_sequence):
        extra = [(CAVE, cave_bytes), (PATCH_SITE, patch_bytes)] if i == 0 else ()
        outcome, counter, _ = poll_once(machine, pb05_high=level, first=(i == 0), extra_seed_mem=extra)
        rows.append((i, "HIGH" if level else "LOW", counter, outcome))
        print(f"  poll {i}: PB05={'HIGH' if level else 'LOW ':4s}  counter_after={counter}  -> {outcome}")
    print()
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--threshold", type=int, default=4, help="consecutive-LOW polls required (default 4)")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    N = args.threshold

    # 1) build + patch the outer branch that redirects into the cave
    patch_bytes = enc_bw_t4(PATCH_SITE, CAVE)
    assert len(patch_bytes) == 4, "patch must be in-place (4 bytes, same as the beq.w it replaces)"
    print(f"patch @0x{PATCH_SITE:x}: replacing beq.w 0x{ACCEPT_TARGET:x} "
          f"with b.w 0x{CAVE:x} -> bytes {patch_bytes.hex()}")

    cave_bytes = build_cave(N)
    print(f"cave @0x{CAVE:x}: {len(cave_bytes)} bytes -> {cave_bytes.hex()}")
    verify_with_capstone(cave_bytes)

    # sanity bookends: unconditional accept / unconditional reject, in-place,
    # no cave at all -- proves Unicorn can actually control this exact
    # decision via a bare 4-byte in-place patch before trusting the cave.
    print("--- Bookend A: patch 0x922e to always ACCEPT (b.w 0x8f98), PB05 held HIGH throughout ---")
    m = ConcreteMachine(str(FIRMWARE), mmio_base=MMIO_BASE, mmio_size=MMIO_SIZE,
                        extra_maps=[(CAVE, CAVE_PAGE_SIZE)])
    always_accept = enc_bw_t4(PATCH_SITE, ACCEPT_TARGET)
    outcome, _, _ = poll_once(m, pb05_high=True, first=True, extra_seed_mem=[(PATCH_SITE, always_accept)])
    print(f"  PB05=HIGH -> {outcome} (expect ACCEPT, proving the branch target -- not PB05 -- now controls the outcome)\n")

    print("--- Bookend B: patch 0x922e to always REJECT (b.w 0x9232), PB05 held LOW throughout ---")
    m = ConcreteMachine(str(FIRMWARE), mmio_base=MMIO_BASE, mmio_size=MMIO_SIZE,
                        extra_maps=[(CAVE, CAVE_PAGE_SIZE)])
    always_reject = enc_bw_t4(PATCH_SITE, REJECT_TARGET)
    outcome, _, _ = poll_once(m, pb05_high=False, first=True, extra_seed_mem=[(PATCH_SITE, always_reject)])
    print(f"  PB05=LOW  -> {outcome} (expect reject, proving the real-trigger LOW no longer reaches 0x8f98)\n")

    # 2) regression matrix (task's required 9 scenarios), using the debounce cave
    scenarios = {
        "1_inactive_throughout": [True] * 6,
        "2_active_throughout": [False] * 6,
        "3_short_transient_then_inactive": [False, True, True, True, True, True],
        "4_short_transient_after_runtime": [True, True, False, True, True, True],
        "5_longer_transient_after_runtime": [True, True, False, False, False, True, True],
        "6_clean_intentional_trigger": [True, True, False, False, False, False, False],
        "7_valid_trigger_after_rejected_transient": [True, False, True, False, False, False, False, False],
        "8_held_active": [False, False, False, False, False, False, False, False],
        "9_release_then_second_trigger": [False, False, False, False, True, True, False, False, False, False],
    }

    all_results = {}
    for name, seq in scenarios.items():
        rows = run_scenario(name, seq, N, patch_bytes, cave_bytes)
        all_results[name] = rows

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump({"threshold": N, "results": all_results}, f, indent=2)
        print(f"wrote {args.json_out}")


if __name__ == "__main__":
    main()
