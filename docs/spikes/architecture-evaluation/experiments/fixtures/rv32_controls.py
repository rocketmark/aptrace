"""SPIKE ONLY: hand-encoded RV32I pointer-use fixtures (no RISC-V assembler on
the development machine). Mirrors a subset of thumb_controls.s; each case
loads a code pointer (0x1000) from a literal word at case+0x30 into a5 with
`auipc a5,0; lw a5,0x30(a5)` -- the tracked definition is the lw at case+4.

usage: rv32_controls.py OUT.bin
"""
import struct
import sys

ZERO, RA, SP, A0, A1, A5 = 0, 1, 2, 10, 11, 15


def i_type(op, rd, f3, rs1, imm):
    return ((imm & 0xFFF) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op


def s_type(rs2, rs1, imm):
    return (((imm >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15) | (0b010 << 12) | ((imm & 0x1F) << 7) | 0x23


def b_type(f3, rs1, rs2, off):
    return ((((off >> 12) & 1) << 31) | (((off >> 5) & 0x3F) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12)
            | (((off >> 1) & 0xF) << 8) | (((off >> 11) & 1) << 7) | 0x63)


def jal(rd, off):
    return ((((off >> 20) & 1) << 31) | (((off >> 1) & 0x3FF) << 21) | (((off >> 11) & 1) << 20)
            | (((off >> 12) & 0xFF) << 12) | (rd << 7) | 0x6F)


auipc = lambda rd: (rd << 7) | 0x17
lw = lambda rd, rs1, imm: i_type(0x03, rd, 0b010, rs1, imm)
addi = lambda rd, rs1, imm: i_type(0x13, rd, 0b000, rs1, imm)
jalr = lambda rd, rs1: i_type(0x67, rd, 0b000, rs1, 0)
ret = jalr(ZERO, RA)
beq = lambda rs1, rs2, off: b_type(0b000, rs1, rs2, off)
bne = lambda rs1, rs2, off: b_type(0b001, rs1, rs2, off)
sw = s_type
HELPER, CB = 0x800, 0x1000

# Each case: (offset, [instructions after the two-instruction literal load]).
# Branch offsets are relative to the branch instruction itself.
CASES = {
    "R1_compare_only": (0x000, [bne(A5, ZERO, 12), addi(A0, ZERO, 0), ret, addi(A5, SP, 4), addi(A0, ZERO, 1), ret]),
    "R2_call_through": (0x040, [beq(A5, ZERO, 8), jalr(RA, A5), ret]),
    "R3_store": (0x080, [sw(A5, A0, 8), ret]),
    "R4_argument_via_move": (0x0c0, [addi(A1, A5, 0), addi(A5, ZERO, 0), None, ret]),   # None: jal helper
    "R5_return": (0x100, [addi(A0, A5, 0), ret]),
    "R6_join_one_path_store": (0x140, [beq(A0, ZERO, 8), addi(A5, ZERO, 0), sw(A5, A1, 0), ret]),
    "R7_join_both_killed": (0x180, [beq(A0, ZERO, 12), addi(A5, ZERO, 0), jal(ZERO, 8), addi(A5, ZERO, 1),
                                    sw(A5, A1, 0), ret]),
}


def build():
    img = bytearray(0x1004)
    for name, (off, body) in CASES.items():
        words = [auipc(A5), lw(A5, A5, 0x30)]
        for w in body:
            if w is None:
                here = off + 4 * len(words)
                w = jal(RA, HELPER - here)
            words.append(w)
        assert 4 * len(words) <= 0x30, name
        for i, w in enumerate(words):
            struct.pack_into("<I", img, off + 4 * i, w)
        struct.pack_into("<I", img, off + 0x30, CB)
    struct.pack_into("<I", img, HELPER, ret)
    struct.pack_into("<I", img, CB, ret)
    return bytes(img)


if __name__ == "__main__":
    open(sys.argv[1], "wb").write(build())
    for name, (off, _) in CASES.items():
        print(f"{name} entry={off:#x} def={off + 4:#x}")
