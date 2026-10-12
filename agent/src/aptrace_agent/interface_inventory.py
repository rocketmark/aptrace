from __future__ import annotations

import hashlib
import re
import sqlite3
import struct
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from aptrace_agent.census import CensusReader
from aptrace_agent.census_graph import CensusGraph, MAX_HOPS, ResolvedIndirectEdge


ANALYSIS_NAME = "census_usb_inventory"
ANALYSIS_VERSION = 1

# APTrace-owned bounds.
DOWNSTREAM_HOPS = 4
MAX_LISTED = 6

# Mechanical lexical filter for strings plausibly used in USB enumeration.
# A match is a candidate only; nothing here proves a string is a descriptor.
_USB_STRING_RE = re.compile(r"usb|cdc|hid|midi|serial|adafruit|arduino|metro|vendor", re.IGNORECASE)

# USB 2.0 spec class codes (bInterfaceClass), for naming descriptor bytes.
_USB_CLASSES = {
    0x01: "audio",
    0x02: "CDC-control",
    0x03: "HID",
    0x08: "mass-storage",
    0x0A: "CDC-data",
    0xEF: "miscellaneous/IAD-composite",
    0xFE: "application-specific",
    0xFF: "vendor-specific",
}


class IrqVector(BaseModel):
    irq: int
    name: str
    handler: str | None
    census_function_at_entry: str | None
    inside_census_function: str | None
    in_census_vector_table: bool


class RegisterUser(BaseModel):
    function: str
    reachability: str | None
    roots: list[str] = Field(default_factory=list)
    reads: list[str] = Field(default_factory=list)
    writes: list[str] = Field(default_factory=list)


class DescriptorCandidate(BaseModel):
    kind: str
    address: str
    detail: str
    code_references: int


class StringCandidate(BaseModel):
    address: str
    value: str
    referenced_by: list[str] = Field(default_factory=list)


class DispatchCandidate(BaseModel):
    function: str
    hops: int
    table_branch_sites: list[str]


class UsbInventory(BaseModel):
    """
    Bounded structural USB inventory.

    Every entry is a mechanical fact from the census, the SVD, or the
    hash-verified firmware image. Nothing here identifies a function as a
    receive handler or command dispatcher; dispatch candidates are only
    functions with switch-table structure near USB register users.
    """

    status: str
    register_users: list[RegisterUser] = Field(default_factory=list)
    unattributed_sites: list[str] = Field(default_factory=list)
    irq_vectors: list[IrqVector] = Field(default_factory=list)
    census_vector_coverage: str = ""
    descriptors: list[DescriptorCandidate] = Field(default_factory=list)
    strings: list[StringCandidate] = Field(default_factory=list)
    downstream_total: int = 0
    dispatch_candidates: list[DispatchCandidate] = Field(default_factory=list)
    irq_reachable_total: int = 0
    irq_reachable: list[str] = Field(default_factory=list)
    resolved_indirect_edges: list[ResolvedIndirectEdge] = Field(default_factory=list)
    unresolved_total: int = 0
    unresolved_examples: list[str] = Field(default_factory=list)
    functions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    planner_summary: str = ""


_LIMITATIONS = [
    "Register users are constant-address MMIO sites and USB address constants; "
    "USB endpoint data moves through RAM descriptors/buffers, so receive-side "
    "code need not touch USB registers at all.",
    "Descriptor candidates are byte patterns of the USB 2.0 standard "
    "descriptor layouts in flash; descriptors assembled at runtime are not seen.",
    "Dispatch candidates are structural (switch tables near USB register "
    "users), not identified command handlers.",
]


def scan_usb_descriptors(data: bytes, flash_base: int) -> list[tuple[str, int, str]]:
    """Standard USB device/configuration descriptor byte patterns."""

    found: list[tuple[str, int, str]] = []

    for offset in range(0, len(data) - 18):
        b = data[offset: offset + 18]

        if b[0] == 0x12 and b[1] == 0x01:
            bcd = struct.unpack_from("<H", b, 2)[0]

            if bcd in (0x0110, 0x0200, 0x0201, 0x0210) and b[7] in (8, 16, 32, 64):
                vid, pid = struct.unpack_from("<HH", b, 8)
                found.append(
                    ("device", flash_base + offset, f"bcdUSB=0x{bcd:04x} class={_USB_CLASSES.get(b[4], f'0x{b[4]:02x}')} VID=0x{vid:04x} PID=0x{pid:04x}")
                )

        if b[0] == 0x09 and b[1] == 0x02 and data[offset + 9: offset + 11] == b"\x09\x04":
            total = struct.unpack_from("<H", b, 2)[0]

            if 18 <= total <= 1024 and 1 <= b[4] <= 8:
                iface = data[offset + 9: offset + 18]
                klass = _USB_CLASSES.get(iface[5], f"0x{iface[5]:02x}")
                found.append(
                    ("configuration", flash_base + offset, f"wTotalLength={total} interfaces={b[4]} first-interface-class={klass}")
                )

    return found


class UsbInventoryReader:
    """Read-only USB structural inventory over existing census evidence."""

    def __init__(
        self,
        *,
        census: CensusReader,
        graph: CensusGraph,
        interrupts: Mapping[int, tuple[str, str]],
        peripheral: str = "USB",
    ) -> None:
        self.census = census
        self.graph = graph
        self.interrupts = dict(interrupts)
        self.peripheral = peripheral

    def _image(self) -> bytes | None:
        path = self.census.firmware_image

        if not path.is_file():
            return None

        data = path.read_bytes()
        return data if hashlib.sha256(data).hexdigest() == self.census.expected_sha256 else None

    def vector_handlers(self) -> dict[int, int]:
        """IRQ number -> handler entry, read from the image's own vector table
        for every IRQ the SVD defines (Thumb bit cleared, empty slots and the
        shared default handler omitted)."""

        data = self._image()

        if data is None:
            return {}

        default = struct.unpack_from("<I", data, 4 * 2)[0] & ~1  # NMI slot
        handlers: dict[int, int] = {}

        for irq in sorted(self.interrupts):
            offset = 4 * (16 + irq)

            if offset + 4 > len(data):
                continue

            raw = struct.unpack_from("<I", data, offset)[0]

            if raw in (0, 0xFFFFFFFF) or (raw & ~1) == default:
                continue

            handlers[irq] = raw & ~1

        return handlers

    def inventory(self) -> UsbInventory:
        usage = self.census.peripheral_usage(self.peripheral, limit=25)

        if usage.status.value not in ("ok", "no_code_references", "no_matching_accesses"):
            return UsbInventory(
                status=usage.status.value,
                planner_summary=f"USB inventory unavailable: {usage.diagnostic}",
            )

        conn = sqlite3.connect(f"{self.census.db_path.resolve().as_uri()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row

        try:
            firmware = conn.execute(
                "SELECT id, flash_base FROM firmware WHERE key=?", (self.census.firmware_key,)
            ).fetchone()
            fw = int(firmware["id"])
            flash_base = int(firmware["flash_base"])
            census_max_vector = conn.execute(
                "SELECT MAX(vector_index) FROM vectors WHERE firmware_id=?", (fw,)
            ).fetchone()[0] or 0
            strings = self._strings(conn, fw)
            descriptors = self._descriptors(conn, fw, flash_base)
        finally:
            conn.close()

        users: list[RegisterUser] = []

        for item in usage.functions:
            member = self.graph.member(item.function)
            users.append(
                RegisterUser(
                    function=item.function,
                    reachability=item.reachability.status if item.reachability else None,
                    roots=member.roots if member else [],
                    reads=sorted({_reg(s.register_name or s.address) for s in item.mmio_sites if s.direction == "READ"}),
                    writes=sorted({_reg(s.register_name or s.address) for s in item.mmio_sites if s.direction == "WRITE"}),
                )
            )

        unattributed = [f"{s.site} {s.detail}" for s in usage.unattributed_sites]

        vectors: list[IrqVector] = []
        handlers = self.vector_handlers()

        for irq, (name, owner) in sorted(self.interrupts.items()):
            if owner != self.peripheral:
                continue

            entry = handlers.get(irq)
            at_entry = None
            inside = None

            if entry is not None:
                handler_name = f"FUN_{entry:08x}"
                at_entry = handler_name if self.graph.function_entry(handler_name) else None

                if at_entry is None:
                    inside = self.graph.containing_function(entry)

            vectors.append(
                IrqVector(
                    irq=irq,
                    name=name,
                    handler=None if entry is None else f"FUN_{entry:08x}",
                    census_function_at_entry=at_entry,
                    inside_census_function=inside,
                    in_census_vector_table=16 + irq <= census_max_vector,
                )
            )

        functions = list(dict.fromkeys(
            [u.function for u in users] + [v.census_function_at_entry for v in vectors if v.census_function_at_entry]
        ))
        downstream = self.graph.downstream(functions, DOWNSTREAM_HOPS)
        # Functions reachable from the USB IRQ handlers themselves over the
        # census strong graph (including resolved_indirect pointer edges).
        handler_functions = [v.census_function_at_entry for v in vectors if v.census_function_at_entry]
        irq_reachable = self.graph.downstream(handler_functions, MAX_HOPS)
        resolved_edges = self.graph.resolved_indirect_edges(sorted(set(downstream) | set(irq_reachable)))
        dispatch = [
            DispatchCandidate(function=name, hops=hops, table_branch_sites=sites[:3])
            for name, hops in sorted(downstream.items(), key=lambda kv: (kv[1], kv[0]))
            if (sites := self.graph.dispatch_sites(name))
        ]
        unresolved = [
            f"{site} in {name}"
            for name in sorted(downstream)
            for site, _kind in self.graph.unresolved_sites(name)
        ]

        result = UsbInventory(
            status="ok",
            register_users=users,
            unattributed_sites=unattributed[:MAX_LISTED],
            irq_vectors=vectors,
            census_vector_coverage=(
                f"census vectors 0..{census_max_vector} (IRQ0..{census_max_vector - 16}); "
                f"image vector table has {len(handlers)} populated non-default IRQ handlers, "
                f"{sum(1 for irq in handlers if 16 + irq > census_max_vector)} beyond census coverage"
            ),
            descriptors=descriptors[:MAX_LISTED],
            strings=strings[:MAX_LISTED],
            downstream_total=len(downstream),
            dispatch_candidates=dispatch[:MAX_LISTED],
            irq_reachable_total=len(irq_reachable),
            irq_reachable=sorted(irq_reachable, key=lambda n: (irq_reachable[n], n))[: 4 * MAX_LISTED],
            resolved_indirect_edges=resolved_edges,
            unresolved_total=len(unresolved),
            unresolved_examples=unresolved[:4],
            functions=functions,
            limitations=list(_LIMITATIONS),
            provenance={
                "analysis": ANALYSIS_NAME,
                "analysis_version": ANALYSIS_VERSION,
                "firmware_key": self.census.firmware_key,
                "firmware_sha256": self.census.expected_sha256,
                "sources": ["census", "svd-interrupts", "firmware-image-vector-table", "flash-descriptor-scan", "census-strings"],
                "downstream_hops": DOWNSTREAM_HOPS,
                "irq_reachable_hops": MAX_HOPS,
            },
        )
        result.planner_summary = _summary(result)
        return result

    def _strings(self, conn: sqlite3.Connection, fw: int) -> list[StringCandidate]:
        out: list[StringCandidate] = []

        for row in conn.execute("SELECT addr, value FROM strings WHERE firmware_id=? ORDER BY addr", (fw,)):
            if not _USB_STRING_RE.search(row["value"]) or len(row["value"]) > 60:
                continue

            refs = [
                f"FUN_{r['entry']:08x}"
                for r in conn.execute(
                    "SELECT DISTINCT f.entry FROM literal_refs l JOIN functions f ON f.id=l.from_function_id "
                    "WHERE l.firmware_id=? AND l.to_addr=? ORDER BY f.entry",
                    (fw, row["addr"]),
                )
            ]
            out.append(StringCandidate(address=f"0x{row['addr']:08x}", value=row["value"], referenced_by=refs[:3]))

        return out

    def _descriptors(self, conn: sqlite3.Connection, fw: int, flash_base: int) -> list[DescriptorCandidate]:
        data = self._image()

        if data is None:
            return []

        out: list[DescriptorCandidate] = []

        for kind, address, detail in scan_usb_descriptors(data, flash_base):
            refs = conn.execute(
                "SELECT COUNT(*) FROM literal_refs WHERE firmware_id=? AND to_addr=?", (fw, address)
            ).fetchone()[0]
            out.append(DescriptorCandidate(kind=kind, address=f"0x{address:08x}", detail=detail, code_references=refs))

        return out


def _reg(name: str) -> str:
    # SVD aliases DEVICE/HOST views of one register; keep the device view.
    return name.split("/")[0].replace("DEVICE.", "")


def _summary(r: UsbInventory) -> str:
    lines = [f"USB inventory (census+SVD+image; structure only, no function labeled a handler):"]

    users = "; ".join(
        f"{u.function} "
        + (f"R:{','.join(u.reads[:2])} " if u.reads else "")
        + (f"W:{','.join(u.writes[:2])} " if u.writes else "")
        + f"[{u.reachability or 'reach?'}]"
        for u in r.register_users[:4]
    )
    lines.append(f"  register users ({len(r.register_users)}): {users or 'none'}")

    if r.unattributed_sites:
        lines.append(f"  unattributed USB sites: {'; '.join(r.unattributed_sites[:2])}")

    vec = []

    for v in r.irq_vectors:
        where = (
            "" if v.census_function_at_entry
            else f" [inside {v.inside_census_function.split('@')[-1]}]" if v.inside_census_function
            else " [no census fn]" if v.handler
            else ""
        )
        vec.append(f"{v.name}({v.irq})->{v.handler or 'default'}{where}")

    roots = "" if all(v.in_census_vector_table for v in r.irq_vectors) else " (not census roots)"
    lines.append(f"  IRQ handlers{roots}: " + "; ".join(vec))
    lines.append(f"  {r.census_vector_coverage}")

    if r.descriptors:
        lines.append(
            "  descriptor candidates: "
            + "; ".join(f"{d.kind}@{d.address} {d.detail} refs={d.code_references}" for d in r.descriptors[:2])
        )
    else:
        lines.append("  no standard device/configuration descriptor bytes in flash (runtime-built not excluded)")

    if r.strings:
        lines.append(
            "  string candidates: "
            + "; ".join(f"{s.value!r}@{s.address}" + (f" refs {','.join(s.referenced_by[:2])}" if s.referenced_by else "") for s in r.strings[:3])
        )

    lines.append(
        f"  downstream <= {DOWNSTREAM_HOPS} hops of census USB functions: {r.downstream_total} functions; "
        f"switch-table dispatch in: {', '.join(f'{d.function}(h{d.hops})' for d in r.dispatch_candidates[:3]) or 'none'}; "
        f"unresolved indirect sites: {r.unresolved_total}"
    )
    lines.append(f"  reachable from USB IRQ handlers (<= census hop bound): {r.irq_reachable_total} functions")

    for e in r.resolved_indirect_edges[:2]:
        lines.append(
            f"  resolved_indirect {e.site} {e.from_function}=>{e.to_function}"
            + (f" (forwards to 0x{int(e.terminal_target, 16):08x})" if e.terminal_target and e.terminal_target != e.canonical_target else "")
            + f": RAM {e.slot}={e.raw_value} stored at {e.store}"
            + (f" from {e.arg_reg} of call {e.callsite}" if e.callsite else "")
            + f" [{e.confidence}, static]"
        )
    return "\n".join(lines)
