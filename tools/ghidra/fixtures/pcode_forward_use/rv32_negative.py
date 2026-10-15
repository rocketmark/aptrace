"""Hand-encoded RV32I counterparts of thumb_negative.s N1-N4: each case
loads the code pointer 0x1000 into a5 (`auipc a5,0; lw a5,0x30(a5)`, the
tracked definition is the lw at case+4). Expectations in controls.json.

usage: rv32_negative.py OUT.bin
"""
import struct
import sys

from rv32_controls import A0, A1, A5, CB, HELPER, ZERO, addi, auipc, beq, bne, jalr, lw, ret, sw

# Q1 computed jump through a0 with a5 live; Q2 no containing function;
# Q3 compare then loop (run with a 2-step budget); Q4 R6 shape with the
# function body truncated before the store (case+0x10 is outside it).
CASES = {
    "Q1_computed_jump": (0x000, [jalr(ZERO, A0)]),
    "Q2_no_function": (0x040, [bne(A5, ZERO, 8), addi(A0, ZERO, 0), ret]),
    "Q3_loop_budget": (0x080, [beq(A5, ZERO, 16), addi(A5, ZERO, 0), addi(A5, A5, 1), bne(A5, A0, -4), ret]),
    "Q4_truncated_body": (0x0c0, [beq(A0, ZERO, 8), addi(A5, ZERO, 0), sw(A5, A1, 0), ret]),
}


def build():
    img = bytearray(0x1004)
    for name, (off, body) in CASES.items():
        words = [auipc(A5), lw(A5, A5, 0x30), *body]
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
