"""SPIKE ONLY: concrete cross-check of the 0xea54 value with Unicorn.

Harness assumptions (not firmware-produced): execution starts mid-function at
0xea54 with zeroed registers, SP=0x20008000 and zeroed RAM; it stops at the
first call (0xeaac/0xeae0) or after 64 instructions. Reports, per executed
instruction, whether the loaded value 0xec49 is still held in a register or
is written to memory -- one concrete path, not an all-paths result.
"""
import struct
import sys

from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_THUMB, Uc
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_SP

image = open(sys.argv[1], "rb").read()
BASE, VALUE, STOPS = 0x4000, 0xEC49, {0xEAAC, 0xEAE0}
uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
uc.mem_map(0, 0x40000)
uc.mem_write(BASE, image)
uc.mem_map(0x20000000, 0x30000)
uc.reg_write(UC_ARM_REG_SP, 0x20008000)
regs = [UC_ARM_REG_R0 + i for i in range(13)]
trace, stores = [], []


def on_code(u, addr, size, _):
    held = [f"r{i}" for i, r in enumerate(regs) if u.reg_read(r) == VALUE]
    trace.append((addr, held))
    if addr in STOPS or len(trace) > 64:
        u.emu_stop()


def on_write(u, access, addr, size, value, _):
    if value == VALUE:
        stores.append((u.reg_read(UC_ARM_REG_PC), addr))


uc.hook_add(UC_HOOK_CODE, on_code)
uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
uc.emu_start(0xEA54 | 1, 0xEB00)
for addr, held in trace:
    print(f"{addr:#x} value held in: {held or '-'}")
print("stores of the value:", stores or "none")
