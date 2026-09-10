"""APTrace census: shared instruction-level normalization for reference-
source matching (tools/census/reference_corpus.py builds reference
symbols with these hashes; tools/census/reference_match.py computes the
SAME hashes for firmware functions -- using the SAME code here is what
makes the two comparable at all).

Four deterministic per-function fingerprints, most to least strict:

  exact_hash          -- sha256 of the raw CODE bytes only (a trailing
                          literal pool, if any, is excluded on both
                          sides -- see `code_only_instructions`).
  exact_instr_hash     -- sha256 of the verbatim decoded
                          (mnemonic, op_str) instruction sequence --
                          catches the rare case where raw bytes differ
                          (e.g. an equivalent instruction encoding) but
                          the disassembly text is identical.
  reloc_norm_hash        -- exact_instr_hash's instruction sequence,
                          but every operand this module can determine
                          IS relocation-derived (a direct branch/call
                          target, or an operand carrying a real ELF
                          relocation on the reference side) is replaced
                          with a fixed placeholder. Meaningful
                          constants (bit masks, `#0`, shift amounts)
                          are explicitly NOT touched.
  pcrel_norm_hash         -- reloc_norm_hash's sequence, ADDITIONALLY
                          masking a PC-relative memory operand's byte
                          offset (`[pc, #N]` -- a pure code-layout
                          artifact: the offset depends on exactly how
                          far the literal pool sits from this
                          instruction, not on program meaning).

On the REFERENCE side (reference_corpus.py), masking is GROUND TRUTH:
computed directly from the object file's own ELF relocation records
(objdump -dr), so "is this operand relocation-derived" is a fact, not a
guess. On the FIRMWARE side (reference_match.py), the binary is already
linked -- no relocation records survive -- so the SAME masking is
applied via a shape-based heuristic (a direct branch/call mnemonic's
target is ALWAYS relocation-derived by construction; an operand that is
itself a bare `0x`-prefixed address-shaped literal is treated the same
way). This asymmetry is real and disclosed, not hidden: see
docs/tooling/census.md's "Reference-source fingerprinting" section.
"""
import hashlib
import re

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

_BRANCH_CALL_MNEM = {"bl", "blx"}
_BRANCH_MNEM = {
    "b", "b.w", "b.n", "bne", "bne.n", "bne.w", "beq", "beq.n", "beq.w",
    "bcc", "bcc.n", "bcs", "bcs.n", "bhs", "blo", "bpl", "bmi", "bvs", "bvc",
    "bhi", "bhi.n", "bls", "bls.n", "bge", "bge.n", "blt", "blt.n",
    "bgt", "bgt.n", "ble", "ble.n", "cbz", "cbnz",
}
_ABS_ADDR_OPERAND_RE = re.compile(r"\b0x[0-9a-fA-F]{4,8}\b")
_PCREL_MEM_RE = re.compile(r"\[pc,\s*#(-?0x[0-9a-fA-F]+|-?\d+)\]")


def md():
    m = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    return m


def trim_trailing_padding(instructions):
    """Drop a trailing run of `nop`s -- pure 2/4-byte alignment padding
    GCC emits before a literal pool or the next function, not real
    code. Ghidra's own function-size convention on the firmware side
    already excludes this; a compiled reference object file's ELF
    symbol size does NOT -- without this trim, applied identically on
    BOTH sides, the two are never byte-comparable for any function
    padded this way (confirmed this pass: `millis()` alone was an
    8-byte reference symbol vs. Ghidra's own 6-byte firmware function,
    solely because of one trailing `nop`)."""
    out = list(instructions)
    while out and out[-1][2].lower() == "nop":
        out.pop()
    return out


def decode_code_bytes(chunk, addr):
    """Decode `chunk` (raw bytes starting at `addr`) with Capstone,
    stopping at the first byte Capstone can't decode (never guesses).
    Returns a list of (offset_from_addr, size, mnemonic, op_str)."""
    out = []
    for insn in md().disasm(chunk, addr):
        out.append((insn.address - addr, insn.size, insn.mnemonic, insn.op_str))
    return out


def reloc_mask(mnemonic, op_str, relocated):
    """`relocated`: True if this EXACT instruction carries a real ELF
    relocation (reference side, ground truth) OR this module's own
    shape-based heuristic says it must be relocation-derived (firmware
    side: any direct branch/call target -- ALWAYS relocation-derived in
    linked code by construction, regardless of operand shape)."""
    m = mnemonic.lower()
    if relocated or m in _BRANCH_CALL_MNEM or m in _BRANCH_MNEM:
        return f"{m} TARGET" if (m in _BRANCH_CALL_MNEM or m in _BRANCH_MNEM) else f"{m} RELOC"
    if _ABS_ADDR_OPERAND_RE.search(op_str):
        return f"{m} " + _ABS_ADDR_OPERAND_RE.sub("ADDR", op_str)
    return f"{m} {op_str}"


def pcrel_mask(mnemonic, op_str, relocated):
    text = reloc_mask(mnemonic, op_str, relocated)
    return _PCREL_MEM_RE.sub("[pc, #OFF]", text)


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def fingerprint_instructions(instructions, relocated_offsets=frozenset()):
    """`instructions`: list of (offset, size_or_None, mnemonic, op_str)
    -- `size_or_None` is unused here (kept for a uniform call shape
    between the reference-corpus objdump parser and the firmware-side
    Capstone decoder). `relocated_offsets`: set of instruction offsets
    (relative to the function start) known to carry a real ELF
    relocation -- empty on the firmware side (heuristic masking only).
    Returns a dict with all four hashes plus a small structural
    signature (n_instructions, n_branches) for STRONG_STRUCTURAL."""
    instr_lines, reloc_lines, pcrel_lines = [], [], []
    n_branches = 0
    for off, _size, mnemonic, op_str in instructions:
        m = mnemonic.lower()
        if m in _BRANCH_CALL_MNEM or m in _BRANCH_MNEM:
            n_branches += 1
        instr_lines.append(f"{m} {op_str}")
        is_relocated = off in relocated_offsets
        reloc_lines.append(reloc_mask(mnemonic, op_str, is_relocated))
        pcrel_lines.append(pcrel_mask(mnemonic, op_str, is_relocated))
    return {
        "exact_instr_hash": _sha("\n".join(instr_lines)),
        "reloc_norm_hash": _sha("\n".join(reloc_lines)),
        "pcrel_norm_hash": _sha("\n".join(pcrel_lines)),
        "n_instructions": len(instructions),
        "n_branches": n_branches,
    }
