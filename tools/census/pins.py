"""APTrace census: SAMD51 MMIO/pin resolution on top of the existing SVD
resolver (tools/svd/resolve_mmio.py) -- no independent SVD parsing here,
per docs/tooling/tool-selection.md ("don't reimplement a peripheral
register map").

Two things this module adds on top of the plain address->name lookup:

  1. `resolve_mmio_addr` parses resolve_mmio.Samd51Map.resolve()'s
     human-readable string back into (peripheral, register, note) fields
     for the mmio_accesses/dynamic_mmio tables.
  2. `port_pin_evidence` turns a resolved PORT.GROUPn.PINCFGxx or
     PORT.GROUPn.PMUXxx register access into concrete pin_name/
     group_index/pin_index rows for the `pins` table.

Deliberately NOT attempted: per-bit pin attribution for PORT's 32-bit
bitmask registers (DIR/DIRSET/DIRCLR/OUT/OUTSET/OUTCLR/IN/CTRL/WRCONFIG)
-- which single pin(s) a given access touches depends on an immediate
bitmask value that would need real dataflow analysis to recover
reliably, not just this module's per-register-name pattern match. Those
accesses are still fully captured as ordinary mmio_accesses rows
(peripheral='PORT'), just not as row-per-pin evidence in the `pins`
table -- see docs/tooling/census.md's "Limitations" section.

Also deliberately NOT attempted: joining a resolved pin (e.g. 'PA08') to
a physical connector/silkscreen identity. That is a different evidence
class entirely (see docs/tooling/census.md's "Pin/peripheral evidence"
section) and may only come from an explicit curated annotation source,
never from this mechanical scanner.
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SVD_DIR = HERE.parent / "svd"
sys.path.insert(0, str(SVD_DIR))
import resolve_mmio  # noqa: E402

_RESOLVE_RE = re.compile(r"^([A-Za-z0-9_]+)(?:\.([^ (]+))? \(\+0x[0-9a-f]+(?:, (.+))?\)$")
_PINCFG_RE = re.compile(r"GROUP(\d+)\.PINCFG(\d+)$")
_PMUX_RE = re.compile(r"GROUP(\d+)\.PMUX(\d+)$")

_map = None


def _samd51_map():
    global _map
    if _map is None:
        _map = resolve_mmio.Samd51Map()
    return _map


def resolve_mmio_addr(addr):
    """(peripheral, register, note) for `addr`, or (None, None, None) if
    the SVD has no peripheral covering it at all (a real finding -- see
    scan_warnings' 'mmio-unresolved' category)."""
    raw = _samd51_map().resolve(addr)
    if raw is None:
        return None, None, None
    m = _RESOLVE_RE.match(raw)
    if not m:
        # Defensive only -- every Samd51Map.resolve() format is matched
        # above; if the resolver's own format ever changes, surface the
        # raw string rather than silently dropping it.
        return raw, None, None
    peripheral, register, note = m.group(1), m.group(2), m.group(3)
    return peripheral, register, note


def group_letter(group_index):
    return chr(ord("A") + group_index)


def port_pin_evidence(peripheral, register, from_addr, mmio_addr):
    """Concrete per-pin evidence rows (dicts, ready for the `pins`
    table's from_addr/mmio_addr/... columns still to be filled in by the
    caller) for a PORT.GROUPn.PINCFGxx (exact, one pin) or
    PORT.GROUPn.PMUXxx (heuristic, one byte shared by two pins --
    real SAMD5x/E5x PMUX packing, see the datasheet's PORT section, not
    a guess) access. Returns [] for every other peripheral/register."""
    if peripheral != "PORT" or not register:
        return []
    m = _PINCFG_RE.search(register)
    if m:
        group_index, pin_index = int(m.group(1)), int(m.group(2))
        return [{
            "pin_name": f"P{group_letter(group_index)}{pin_index:02d}",
            "group_index": group_index, "pin_index": pin_index,
            "evidence_kind": "pincfg", "confidence": "exact",
        }]
    m = _PMUX_RE.search(register)
    if m:
        group_index, pmux_index = int(m.group(1)), int(m.group(2))
        out = []
        for pin_index in (2 * pmux_index, 2 * pmux_index + 1):
            out.append({
                "pin_name": f"P{group_letter(group_index)}{pin_index:02d}",
                "group_index": group_index, "pin_index": pin_index,
                "evidence_kind": "pmux", "confidence": "heuristic",
            })
        return out
    return []
