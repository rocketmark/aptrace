#!/usr/bin/env python3
"""Resolve raw Cortex-M MMIO addresses to ATSAMD51J19A peripheral/register
names, using the real Microchip SVD file (ATSAMD51J19A.svd, from
cmsis-svd/cmsis-svd-data).

This is a thin, standalone address->name lookup -- not an SVD parser
reimplementation (it uses the plain stdlib XML parser against the vendor's
own SVD data) and not a peripheral behavior model. It exists to answer one
question: "what real SAMD51 register does this raw address touched by the
firmware correspond to?" See docs/tooling/tool-selection.md's SVD section.

Usage:
    python3 resolve_mmio.py 0x40001c04 0x4101c005
    python3 resolve_mmio.py --json addrs.json   # {"addrs": ["0x...", ...]}
    import resolve_mmio; resolve_mmio.resolve(0x40001c04)
"""
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SVD_PATH = Path(__file__).parent / "ATSAMD51J19A.svd"


def _reg_size_bytes(reg):
    size = reg.findtext("size")
    return (int(size, 0) // 8) if size else 1


def _walk_registers(container, prefix=""):
    """Yield (name, offset, size_bytes) for every register under a
    <registers> or <cluster> element, flattening clusters (SAMD51 uses
    clusters for mode unions like TC's COUNT8/COUNT16/COUNT32 and SERCOM's
    I2CM/I2CS/SPIM/SPIS/USART, and for repeated instances like PORT's
    GROUP[0]/GROUP[1] = PORTA/PORTB) and expanding dim/dimIncrement arrays
    (e.g. PORT's PMUX[0..15]/PINCFG[0..31], GCLK's GENCTRL[0..11])."""
    for child in container:
        name = child.findtext("name")
        if name is None:
            continue
        offset = child.findtext("addressOffset") or child.findtext("offset") or "0x0"
        off = int(offset, 0)
        clean_name = name.replace("[%s]", "")
        dim = child.findtext("dim")
        dim_inc = child.findtext("dimIncrement")
        n = int(dim, 0) if dim else 1
        inc = int(dim_inc, 0) if dim_inc else 0
        for i in range(n):
            idx_off = off + i * inc
            idx_name = f"{clean_name}{i}" if dim else clean_name
            if child.tag == "cluster":
                for sub_name, sub_off, sub_size in _walk_registers(child, prefix=f"{prefix}{idx_name}."):
                    yield (sub_name, idx_off + sub_off, sub_size)
            else:
                yield (f"{prefix}{idx_name}", idx_off, _reg_size_bytes(child))


class Samd51Map:
    def __init__(self, svd_path=SVD_PATH):
        tree = ET.parse(svd_path)
        root = tree.getroot()
        self.peripherals = []  # (base, size, name, [(regname, offset, sizebytes)])
        derived = {}
        raw = {}
        for p in root.find("peripherals"):
            name = p.findtext("name")
            base = p.findtext("baseAddress")
            if base is None:
                continue
            raw[name] = p
            derived_from = p.get("derivedFrom")
            if derived_from:
                derived[name] = (int(base, 0), derived_from)

        for p in root.find("peripherals"):
            name = p.findtext("name")
            base = p.findtext("baseAddress")
            if base is None:
                continue
            base = int(base, 0)
            ab = p.find("addressBlock")
            if ab is None and p.get("derivedFrom"):
                ab = raw[p.get("derivedFrom")].find("addressBlock")
            size = int(ab.findtext("size"), 0) if ab is not None else 0x400
            regs_elem = p.find("registers")
            if regs_elem is None and p.get("derivedFrom"):
                regs_elem = raw[p.get("derivedFrom")].find("registers")
            regs = list(_walk_registers(regs_elem)) if regs_elem is not None else []
            self.peripherals.append((base, size, name, regs))
        self.peripherals.sort()

    def resolve(self, addr):
        for base, size, name, regs in self.peripherals:
            if base <= addr < base + max(size, 1):
                off = addr - base
                matches = [r for r, o, _sz in regs if o == off]
                if matches:
                    return f"{name}.{'/'.join(sorted(set(matches)))} (+0x{off:x})"
                # No exact register match at this offset (e.g. a byte into a
                # multi-byte register, or an offset SVD doesn't enumerate).
                covering = [r for r, o, sz in regs if o <= off < o + max(sz, 1)]
                if covering:
                    return f"{name}.{'/'.join(sorted(set(covering)))} (+0x{off:x}, byte offset into register)"
                return f"{name} (+0x{off:x}, unlisted offset)"
        return None


_singleton = None


def resolve(addr):
    global _singleton
    if _singleton is None:
        _singleton = Samd51Map()
    if isinstance(addr, str):
        addr = int(addr, 0)
    return _singleton.resolve(addr) or f"<no SAMD51 peripheral at 0x{addr:08x}>"


def main(argv):
    if not argv:
        print(__doc__)
        return 1
    if argv[0] == "--json":
        data = json.loads(Path(argv[1]).read_text())
        addrs = data["addrs"]
    else:
        addrs = argv
    for a in addrs:
        addr = int(a, 0)
        print(f"0x{addr:08x}  {resolve(addr)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
