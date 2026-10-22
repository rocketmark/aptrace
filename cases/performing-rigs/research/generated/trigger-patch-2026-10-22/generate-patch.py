"""RESEARCH ONLY — NOT FOR HARDWARE DEPLOYMENT. Exact915 freshness subset.

This authors a binary patch, not an instruction-analysis framework. It does
not allocate persistent RAM, implement timed qualification, or flash anything.
"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT.parents[2] / "research/firmware/originals/firmware_autopilot915.bin"
EXPECTED = "0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920"
BASE, SITE, EXTENSION = 0x4000, 0x922c, 0x15470


def branch(source, target, link=False):
    offset = target - (source + 4)
    assert offset % 2 == 0 and -(1 << 24) <= offset < (1 << 24)
    s, i1, i2 = (offset >> 24) & 1, (offset >> 23) & 1, (offset >> 22) & 1
    j1, j2 = 1 ^ i1 ^ s, 1 ^ i2 ^ s
    return struct.pack("<HH", 0xf000 | s << 10 | (offset >> 12) & 0x3ff,
                       (0xd000 if link else 0x9000) | j1 << 13 | j2 << 11 | (offset >> 1) & 0x7ff)


original = SOURCE.read_bytes()
assert hashlib.sha256(original).hexdigest() == EXPECTED
assert len(original) == EXTENSION - BASE == 70768
# Check our branch encoding against an existing BL, not a guessed opcode.
assert branch(0x9228, 0xd3dc, True) == original[0x9228-BASE:0x922c-BASE]
before = original[SITE-BASE:SITE-BASE+6]
assert before.hex() == "00283ff4b3ae", before.hex()

# 15470 cmp r0,#0; bne15488: original inactive read must remain rejected.
# 15474 push{r0-r4,lr}; movs r0,#57; bl original digitalRead.
# 1547c cmp r0,#0; pop.w{r0-r4,lr}: restore registers without changing flags.
# 15482 bne15488; b.w8f98; 15488 b.w9232.
routine = (bytes.fromhex("002809d11fb53920") + branch(0x15478,0xd3dc,True)
           + bytes.fromhex("0028bde81f4001d1") + branch(0x15484,0x8f98)
           + branch(0x15488,0x9232))
assert len(routine) == 28
replacement = branch(SITE, EXTENSION) + bytes.fromhex("00bf")
patched = bytearray(original)
patched[SITE-BASE:SITE-BASE+6] = replacement
patched.extend(routine)
assert patched[:SITE-BASE] == original[:SITE-BASE]
assert patched[SITE-BASE+6:len(original)] == original[SITE-BASE+6:]
assert patched[0x12000-BASE:0x13001-BASE] == original[0x12000-BASE:0x13001-BASE]
output = ROOT / "RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_freshness.bin"
output.write_bytes(patched)
manifest = {
    "warning": "RESEARCH ONLY; NOT FOR HARDWARE DEPLOYMENT",
    "scope": "Digital saved-active freshness recheck only; NOT timed qualification or release-to-rearm",
    "original_path": str(SOURCE), "original_sha256": EXPECTED,
    "patched_file": output.name, "patched_sha256": hashlib.sha256(patched).hexdigest(),
    "load_base": hex(BASE), "original_size": len(original), "patched_size": len(patched),
    "modifications": [{"address":hex(SITE),"file_offset":hex(SITE-BASE),"before":before.hex(),"after":replacement.hex()},
                      {"address":hex(EXTENSION),"file_offset":hex(EXTENSION-BASE),"before":"EOF","after":routine.hex()}],
    "storage": "No code cave or fixed RAM reuse. Explicit28-byte executable image extension;24-byte temporary aligned stack frame.",
    "flash_ownership": "No original-image byte outside922c..9231 changed; config12000..13000 unchanged. Extension is provisioned for simulation, NOT a claim about unowned physical flash.",
    "persistent_state": None,
    "limitations": ["No stable-inactive arming", "No active-duration qualification", "No release-to-rearm", "Analog unchanged", "Input can change after final read", "Physical flash ownership/bootloader integrity not qualified"],
}
(ROOT / "modification-manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
print(json.dumps({"original": EXPECTED,"patched":manifest["patched_sha256"],"bytes":len(patched)},indent=2))
