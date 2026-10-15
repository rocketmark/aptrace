"""SPIKE ONLY: copy the .text section of a 32-bit little-endian ELF object
to a raw image (fixtures are position-fixed with .org, no relocations)."""
import struct
import sys

data = open(sys.argv[1], "rb").read()
assert data[:4] == b"\x7fELF" and data[4] == 1
shoff, = struct.unpack_from("<I", data, 0x20)
shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2e)
secs = [struct.unpack_from("<IIIIIIIIII", data, shoff + i * shentsize) for i in range(shnum)]
strtab = secs[shstrndx]
name = lambda s: data[strtab[4] + s[0]:].split(b"\0", 1)[0].decode()
for s in secs:
    if name(s).startswith(".rel") and "text" in name(s) and s[5]:
        sys.exit(f"unexpected relocations in {name(s)}")
text = next(s for s in secs if name(s) == ".text")
open(sys.argv[2], "wb").write(data[text[4]:text[4] + text[5]])
print(f"{text[5]} bytes")
