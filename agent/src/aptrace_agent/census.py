from __future__ import annotations

import bisect
import hashlib
import importlib.util
import re
import sqlite3
import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


ANALYSIS_NAME = "census_peripheral_usage"
ANALYSIS_VERSION = 1

DEFAULT_LIMIT = 25
MAX_LIMIT = 50
MAX_SITES_PER_FUNCTION = 8
MAX_REFS_PER_CONSTANT = 8
MAX_WARNINGS = 10

_PERIPHERAL_RE = re.compile(r"[A-Z][A-Z0-9_]{0,23}")


class CensusStatus(StrEnum):
    OK = "ok"
    CENSUS_MISSING = "census_missing"
    CENSUS_STALE = "census_stale"
    UNKNOWN_PERIPHERAL = "unknown_peripheral"
    NO_CODE_REFERENCES = "no_code_references"
    NO_MATCHING_ACCESSES = "no_matching_accesses"


class ReductionStatus(StrEnum):
    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PeripheralRange:
    base: int
    size: int


class CensusProvenance(BaseModel):
    analysis: str = ANALYSIS_NAME
    analysis_version: int = ANALYSIS_VERSION
    firmware_key: str
    expected_firmware_sha256: str
    census_firmware_sha256: str | None = None
    census_built_at: str | None = None
    census_ghidra_version: str | None = None
    reduction_status: ReductionStatus = ReductionStatus.UNKNOWN
    reduced_at: str | None = None
    peripheral_catalog: str
    flash_word_scan: str
    sources: list[str] = Field(default_factory=list)
    limit: int


class MmioSite(BaseModel):
    site: str
    address: str
    register_name: str | None
    direction: str
    width: int | None
    resolution_note: str | None
    source: str


class ConstantLoad(BaseModel):
    site: str
    pool_address: str
    value: str
    register_name: str | None
    ref_type: str | None
    source: str


class Reachability(BaseModel):
    status: str
    hops: int | None
    nearest_root: str | None
    nearest_root_kind: str | None
    source: str


class ComponentMembership(BaseModel):
    index: int
    n_functions: int
    source: str


class PeripheralFunction(BaseModel):
    function: str
    census_name: str
    entry: str
    size: int
    mmio_site_count: int = 0
    mmio_sites: list[MmioSite] = Field(default_factory=list)
    constant_load_count: int = 0
    constant_loads: list[ConstantLoad] = Field(default_factory=list)
    reachability: Reachability | None = None
    component: ComponentMembership | None = None


class UnattributedSite(BaseModel):
    """A reference site the census does not attribute to any function."""

    site: str
    kind: str
    basic_block: str | None
    detail: str


class AddressConstant(BaseModel):
    location: str
    value: str
    register_name: str | None
    referenced: bool
    reference_count: int


class CensusWarning(BaseModel):
    category: str
    address: str | None
    detail: str
    source: str


class PeripheralUsage(BaseModel):
    """
    Bounded structural usage of one MCU peripheral.

    Every entry is a statically derived census fact. Nothing here states
    what external device the peripheral talks to.
    """

    status: CensusStatus
    peripheral: str
    diagnostic: str | None = None
    peripheral_base: str | None = None
    peripheral_size: int | None = None
    total_mmio_sites: int = 0
    total_address_constants: int = 0
    unreferenced_address_constants: int = 0
    total_functions: int = 0
    functions: list[PeripheralFunction] = Field(default_factory=list)
    functions_truncated: bool = False
    unattributed_sites: list[UnattributedSite] = Field(default_factory=list)
    address_constants: list[AddressConstant] = Field(default_factory=list)
    address_constants_truncated: bool = False
    warnings: list[CensusWarning] = Field(default_factory=list)
    warnings_total: int = 0
    limitations: list[str] = Field(default_factory=list)
    provenance: CensusProvenance


_LIMITATIONS = [
    "MMIO sites are constant-address references resolved by Ghidra's "
    "reference manager; accesses through a base-address register are not "
    "attributed to a peripheral in mmio_accesses.",
    "Address constants are aligned flash words whose value lies in the "
    "peripheral's SVD range; loading an address is not proof of an access.",
    "Absence of evidence is bounded to these two static methods and does "
    "not exclude runtime-computed peripheral addresses.",
    "Structural usage does not identify what external device is attached "
    "to the peripheral; that requires hardware-routing evidence.",
]


def _hx(value: int | None) -> str | None:
    return None if value is None else f"0x{value:08x}"


def _describe(
    value: int,
    register: str | None,
    peripheral: str,
    base: int,
) -> str:
    if value == base:
        return f"{peripheral} base"

    if register and "/" not in register:
        return register

    return f"{peripheral}+0x{value - base:x}"


def clamp_limit(limit: Any) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_LIMIT

    return max(1, min(MAX_LIMIT, value))


def normalize_peripheral(name: Any) -> str | None:
    text = str(name).strip().upper()

    if not _PERIPHERAL_RE.fullmatch(text):
        return None

    return text


class CensusReader:
    """
    Read-only, bounded queries over an already-prepared APTrace census.

    APTrace binds the firmware identity, database, image and peripheral
    catalog at construction. Callers supply only a peripheral name, which
    is validated against the catalog. The reader never builds, reduces or
    writes the census.
    """

    def __init__(
        self,
        *,
        firmware_key: str,
        db_path: Path,
        firmware_image: Path,
        expected_sha256: str,
        peripherals: Mapping[str, PeripheralRange],
        resolve_register: Callable[[int], str | None],
        catalog_identity: str,
    ) -> None:
        self.firmware_key = firmware_key
        self.db_path = Path(db_path)
        self.firmware_image = Path(firmware_image)
        self.expected_sha256 = expected_sha256.lower()
        self.peripherals = dict(peripherals)
        self.resolve_register = resolve_register
        self.catalog_identity = catalog_identity

        self._ranges = sorted(
            (item.base, item.size, name)
            for name, item in self.peripherals.items()
        )
        self._range_bases = [
            base for base, _size, _name in self._ranges
        ]
        self._flash_words: list[tuple[int, int, str]] | None = None
        self._flash_scan_status: str | None = None

    # -- connection / state ------------------------------------------------

    def _connect(self) -> sqlite3.Connection | None:
        if not self.db_path.is_file():
            return None

        conn = sqlite3.connect(
            f"{self.db_path.resolve().as_uri()}?mode=ro",
            uri=True,
        )
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
        return conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone() is not None

    def _reduction(
        self,
        conn: sqlite3.Connection,
        firmware_id: int,
    ) -> tuple[ReductionStatus, str | None]:
        if not self._table_exists(conn, "function_reachability"):
            return ReductionStatus.ABSENT, None

        count = conn.execute(
            "SELECT COUNT(*) FROM function_reachability WHERE firmware_id=?",
            (firmware_id,),
        ).fetchone()[0]

        if not count:
            return ReductionStatus.ABSENT, None

        reduced_at = None

        if self._table_exists(conn, "hardware_snapshot_runs"):
            row = conn.execute(
                "SELECT ran_at FROM hardware_snapshot_runs WHERE firmware_id=?",
                (firmware_id,),
            ).fetchone()
            reduced_at = row["ran_at"] if row else None

        return ReductionStatus.PRESENT, reduced_at

    # -- flash word scan -----------------------------------------------------

    def _peripheral_for(self, value: int) -> str | None:
        index = bisect.bisect_right(self._range_bases, value) - 1

        if index < 0:
            return None

        base, size, name = self._ranges[index]

        if base <= value < base + max(size, 1):
            return name

        return None

    def _scan_flash(self, flash_base: int) -> list[tuple[int, int, str]]:
        """Return (location, value, peripheral) for every aligned flash
        word whose value lies inside a catalog peripheral range, only for
        an image whose hash matches the expected firmware identity."""

        if self._flash_words is not None:
            return self._flash_words

        if not self.firmware_image.is_file():
            self._flash_scan_status = "firmware_image_unavailable"
            self._flash_words = []
            return self._flash_words

        data = self.firmware_image.read_bytes()

        if hashlib.sha256(data).hexdigest() != self.expected_sha256:
            self._flash_scan_status = "firmware_image_hash_mismatch"
            self._flash_words = []
            return self._flash_words

        words: list[tuple[int, int, str]] = []

        for offset in range(0, len(data) - 3, 4):
            value = struct.unpack_from("<I", data, offset)[0]
            name = self._peripheral_for(value)

            if name is not None:
                words.append((flash_base + offset, value, name))

        self._flash_scan_status = "sha256-verified"
        self._flash_words = words
        return words

    # -- public API ----------------------------------------------------------

    def available_peripherals(self) -> list[str]:
        """Catalog peripherals with any census MMIO site or flash address
        constant, sorted. Empty when the census is unusable."""

        conn = self._connect()

        if conn is None:
            return []

        try:
            firmware = conn.execute(
                "SELECT id, sha256, flash_base FROM firmware WHERE key=?",
                (self.firmware_key,),
            ).fetchone()

            if (
                firmware is None
                or str(firmware["sha256"]).lower() != self.expected_sha256
            ):
                return []

            names = {
                row[0]
                for row in conn.execute(
                    "SELECT DISTINCT peripheral FROM mmio_accesses "
                    "WHERE firmware_id=? AND peripheral IS NOT NULL",
                    (firmware["id"],),
                )
            }
        finally:
            conn.close()

        names.update(
            name
            for _location, _value, name
            in self._scan_flash(int(firmware["flash_base"]))
        )

        return sorted(name for name in names if name in self.peripherals)

    def peripheral_usage(
        self,
        peripheral: Any,
        *,
        limit: Any = DEFAULT_LIMIT,
    ) -> PeripheralUsage:
        bounded = clamp_limit(limit)
        name = normalize_peripheral(peripheral)

        provenance = CensusProvenance(
            firmware_key=self.firmware_key,
            expected_firmware_sha256=self.expected_sha256,
            peripheral_catalog=self.catalog_identity,
            flash_word_scan="not_run",
            limit=bounded,
        )

        if name is None or name not in self.peripherals:
            return PeripheralUsage(
                status=CensusStatus.UNKNOWN_PERIPHERAL,
                peripheral=str(peripheral)[:32],
                diagnostic=(
                    "peripheral is not a known ATSAMD51 SVD peripheral"
                ),
                provenance=provenance,
            )

        span = self.peripherals[name]

        def failure(status: CensusStatus, diagnostic: str) -> PeripheralUsage:
            return PeripheralUsage(
                status=status,
                peripheral=name,
                diagnostic=diagnostic,
                peripheral_base=_hx(span.base),
                peripheral_size=span.size,
                provenance=provenance,
            )

        conn = self._connect()

        if conn is None:
            return failure(
                CensusStatus.CENSUS_MISSING,
                "no census database has been prepared",
            )

        try:
            firmware = conn.execute(
                "SELECT * FROM firmware WHERE key=?",
                (self.firmware_key,),
            ).fetchone()

            if firmware is None:
                return failure(
                    CensusStatus.CENSUS_MISSING,
                    "census database has no build for this firmware",
                )

            provenance.census_firmware_sha256 = firmware["sha256"]
            provenance.census_built_at = firmware["built_at"]
            provenance.census_ghidra_version = firmware["ghidra_version"]

            if str(firmware["sha256"]).lower() != self.expected_sha256:
                return failure(
                    CensusStatus.CENSUS_STALE,
                    "census was built from a different firmware image",
                )

            firmware_id = int(firmware["id"])
            reduction, reduced_at = self._reduction(conn, firmware_id)
            provenance.reduction_status = reduction
            provenance.reduced_at = reduced_at

            return self._usage(
                conn,
                firmware_id=firmware_id,
                flash_base=int(firmware["flash_base"]),
                name=name,
                span=span,
                limit=bounded,
                reduced=reduction == ReductionStatus.PRESENT,
                provenance=provenance,
            )
        finally:
            conn.close()

    # -- query implementation -------------------------------------------------

    def _usage(
        self,
        conn: sqlite3.Connection,
        *,
        firmware_id: int,
        flash_base: int,
        name: str,
        span: PeripheralRange,
        limit: int,
        reduced: bool,
        provenance: CensusProvenance,
    ) -> PeripheralUsage:
        sources: set[str] = set()
        functions: dict[int, dict[str, Any]] = {}
        unattributed: list[UnattributedSite] = []

        def function_record(row: sqlite3.Row) -> dict[str, Any]:
            entry = int(row["function_entry"])

            return functions.setdefault(
                entry,
                {
                    "id": int(row["function_id"]),
                    "entry": entry,
                    "name": row["function_name"],
                    "size": int(row["function_size"]),
                    "mmio": [],
                    "constants": [],
                },
            )

        mmio_rows = conn.execute(
            "SELECT DISTINCT m.from_addr, m.to_addr, m.width, m.direction, "
            "m.register_name, m.resolution_note, m.source, "
            "f.id AS function_id, f.entry AS function_entry, "
            "f.name AS function_name, f.size AS function_size "
            "FROM mmio_accesses m "
            "LEFT JOIN functions f ON f.id = m.from_function_id "
            "WHERE m.firmware_id=? AND m.peripheral=? "
            "ORDER BY m.from_addr, m.to_addr, m.direction, m.source",
            (firmware_id, name),
        ).fetchall()

        for row in mmio_rows:
            sources.add(str(row["source"]))
            site = MmioSite(
                site=_hx(row["from_addr"]),
                address=_hx(row["to_addr"]),
                register_name=row["register_name"],
                direction=row["direction"],
                width=row["width"],
                resolution_note=row["resolution_note"],
                source=row["source"],
            )

            if row["function_id"] is None:
                unattributed.append(
                    UnattributedSite(
                        site=site.site,
                        kind="mmio",
                        basic_block=self._block(conn, firmware_id, row["from_addr"]),
                        detail=f"{site.direction} {site.register_name or site.address}",
                    )
                )
            else:
                function_record(row)["mmio"].append(site)

        constants = [
            (location, value)
            for location, value, owner in self._scan_flash(flash_base)
            if owner == name
        ]
        provenance.flash_word_scan = self._flash_scan_status or "not_run"

        address_constants: list[AddressConstant] = []

        if constants:
            sources.add("flash-word-scan")

        for location, value in constants:
            register = self._register(value)
            refs = conn.execute(
                "SELECT l.from_addr, l.ref_type, l.source, "
                "f.id AS function_id, f.entry AS function_entry, "
                "f.name AS function_name, f.size AS function_size "
                "FROM literal_refs l "
                "LEFT JOIN functions f ON f.id = l.from_function_id "
                "WHERE l.firmware_id=? AND l.to_addr=? "
                "ORDER BY l.from_addr, l.ref_type",
                (firmware_id, location),
            ).fetchall()

            address_constants.append(
                AddressConstant(
                    location=_hx(location),
                    value=_hx(value),
                    register_name=register,
                    referenced=bool(refs),
                    reference_count=len(refs),
                )
            )

            for row in refs[:MAX_REFS_PER_CONSTANT]:
                sources.add(str(row["source"]))
                load = ConstantLoad(
                    site=_hx(row["from_addr"]),
                    pool_address=_hx(location),
                    value=_hx(value),
                    register_name=register,
                    ref_type=row["ref_type"],
                    source=f"{row['source']}+flash-word-scan",
                )

                if row["function_id"] is None:
                    unattributed.append(
                        UnattributedSite(
                            site=load.site,
                            kind="constant_load",
                            basic_block=self._block(conn, firmware_id, row["from_addr"]),
                            detail=(
                                f"loads {load.value} "
                                f"({_describe(value, register, name, span.base)}) "
                                f"from {load.pool_address}"
                            ),
                        )
                    )
                else:
                    function_record(row)["constants"].append(load)

        ordered = [functions[entry] for entry in sorted(functions)]
        selected = ordered[:limit]

        overlay_reach: dict[int, Reachability] = {}
        overlay_component: dict[int, ComponentMembership] = {}

        if reduced and selected:
            overlay_reach, overlay_component = self._overlay(
                conn,
                firmware_id,
                [item["id"] for item in selected],
            )

            if overlay_reach:
                sources.add("census-reachability")

            if overlay_component:
                sources.add("census-components")

        records = [
            PeripheralFunction(
                function=f"FUN_{item['entry']:08x}",
                census_name=item["name"],
                entry=_hx(item["entry"]),
                size=item["size"],
                mmio_site_count=len(item["mmio"]),
                mmio_sites=item["mmio"][:MAX_SITES_PER_FUNCTION],
                constant_load_count=len(item["constants"]),
                constant_loads=item["constants"][:MAX_SITES_PER_FUNCTION],
                reachability=overlay_reach.get(item["id"]),
                component=overlay_component.get(item["id"]),
            )
            for item in selected
        ]

        unattributed.sort(key=lambda item: (item.site, item.kind))
        warnings, warnings_total = self._warnings(
            conn,
            firmware_id,
            [(item["entry"], item["size"]) for item in selected],
            [item.basic_block for item in unattributed if item.basic_block],
        )

        if mmio_rows:
            sources.add("svd")

        provenance.sources = sorted(sources)

        code_referenced = bool(mmio_rows) or any(
            item.referenced for item in address_constants
        )

        if code_referenced:
            status, diagnostic = CensusStatus.OK, None
        elif constants:
            status = CensusStatus.NO_CODE_REFERENCES
            diagnostic = (
                "peripheral addresses appear only in flash data words "
                "that no census instruction references"
            )
        else:
            status = CensusStatus.NO_MATCHING_ACCESSES
            diagnostic = (
                "no static MMIO site or flash address constant "
                "references this peripheral"
            )

        return PeripheralUsage(
            status=status,
            peripheral=name,
            diagnostic=diagnostic,
            peripheral_base=_hx(span.base),
            peripheral_size=span.size,
            total_mmio_sites=len(mmio_rows),
            total_address_constants=len(constants),
            unreferenced_address_constants=sum(
                not item.referenced for item in address_constants
            ),
            total_functions=len(ordered),
            functions=records,
            functions_truncated=len(ordered) > len(selected),
            unattributed_sites=unattributed[:limit],
            address_constants=address_constants[:limit],
            address_constants_truncated=len(address_constants) > limit,
            warnings=warnings,
            warnings_total=warnings_total,
            limitations=list(_LIMITATIONS),
            provenance=provenance,
        )

    def _register(self, value: int) -> str | None:
        try:
            return self.resolve_register(value)
        except Exception:  # SVD lookup is advisory metadata only
            return None

    @staticmethod
    def _block(
        conn: sqlite3.Connection,
        firmware_id: int,
        address: int,
    ) -> str | None:
        row = conn.execute(
            "SELECT start_addr FROM basic_blocks WHERE firmware_id=? "
            "AND ? BETWEEN start_addr AND end_addr "
            "ORDER BY start_addr LIMIT 1",
            (firmware_id, address),
        ).fetchone()

        return _hx(row["start_addr"]) if row else None

    def _overlay(
        self,
        conn: sqlite3.Connection,
        firmware_id: int,
        function_ids: list[int],
    ) -> tuple[dict[int, Reachability], dict[int, ComponentMembership]]:
        placeholders = ",".join("?" for _ in function_ids)
        reach: dict[int, Reachability] = {}
        components: dict[int, ComponentMembership] = {}

        for row in conn.execute(
            "SELECT function_id, status, hops, nearest_root_addr, "
            "nearest_root_kind, source FROM function_reachability "
            f"WHERE firmware_id=? AND function_id IN ({placeholders})",
            (firmware_id, *function_ids),
        ):
            reach[int(row["function_id"])] = Reachability(
                status=row["status"],
                hops=row["hops"],
                nearest_root=_hx(row["nearest_root_addr"]),
                nearest_root_kind=row["nearest_root_kind"],
                source=row["source"],
            )

        if self._table_exists(conn, "component_members"):
            for row in conn.execute(
                "SELECT cm.function_id, c.component_index, c.n_functions, "
                "c.source FROM component_members cm "
                "JOIN components c ON c.id = cm.component_id "
                f"WHERE cm.firmware_id=? AND cm.function_id IN ({placeholders})",
                (firmware_id, *function_ids),
            ):
                components[int(row["function_id"])] = ComponentMembership(
                    index=row["component_index"],
                    n_functions=row["n_functions"],
                    source=row["source"],
                )

        return reach, components

    @staticmethod
    def _warnings(
        conn: sqlite3.Connection,
        firmware_id: int,
        function_spans: list[tuple[int, int]],
        block_starts: list[str],
    ) -> tuple[list[CensusWarning], int]:
        clauses: list[str] = []
        params: list[Any] = [firmware_id]

        for entry, size in function_spans:
            clauses.append("(addr >= ? AND addr < ?)")
            params.extend((entry, entry + max(size, 1)))

        for start in sorted(set(block_starts)):
            clauses.append(
                "(addr BETWEEN ? AND (SELECT end_addr FROM basic_blocks "
                "WHERE firmware_id=? AND start_addr=?))"
            )
            params.extend((int(start, 16), firmware_id, int(start, 16)))

        if not clauses:
            return [], 0

        where = f"firmware_id=? AND ({' OR '.join(clauses)})"
        total = conn.execute(
            f"SELECT COUNT(*) FROM scan_warnings WHERE {where}",
            params,
        ).fetchone()[0]
        rows = conn.execute(
            f"SELECT category, addr, detail, source FROM scan_warnings "
            f"WHERE {where} ORDER BY addr, category, id LIMIT ?",
            (*params, MAX_WARNINGS),
        ).fetchall()

        return (
            [
                CensusWarning(
                    category=row["category"],
                    address=_hx(row["addr"]),
                    detail=row["detail"],
                    source=row["source"],
                )
                for row in rows
            ],
            total,
        )


# -- Performing Rigs application wiring ---------------------------------------


def _load_svd_map(svd_module: Path) -> Any:
    spec = importlib.util.spec_from_file_location(
        "aptrace_case_resolve_mmio",
        svd_module,
    )

    if spec is None or spec.loader is None:
        raise ImportError(svd_module)

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _expected_sha(sums_file: Path, filename: str) -> str:
    for line in sums_file.read_text(encoding="utf-8").splitlines():
        parts = line.split()

        if len(parts) == 2 and parts[1] == filename:
            return parts[0].lower()

    raise KeyError(f"{filename} not listed in {sums_file}")


def performing_rigs_census() -> CensusReader:
    """AutoPilot 868 census reader. Every identity is fixed here."""

    repo_root = Path(__file__).resolve().parents[3]
    case = repo_root / "cases" / "performing-rigs"
    originals = case / "research" / "firmware" / "originals"
    svd_dir = case / "config" / "svd"
    svd_file = svd_dir / "ATSAMD51J19A.svd"

    module = _load_svd_map(svd_dir / "resolve_mmio.py")
    svd = module.Samd51Map(svd_file)

    peripherals: dict[str, PeripheralRange] = {}

    for base, size, name, _registers in svd.peripherals:
        peripherals.setdefault(name, PeripheralRange(base, size))

    def resolve_register(value: int) -> str | None:
        text = svd.resolve(value)
        return text.split(" ", 1)[0] if text else None

    svd_sha = hashlib.sha256(svd_file.read_bytes()).hexdigest()

    return CensusReader(
        firmware_key="autopilot868",
        db_path=(
            case / "research" / "runs" / "census" / "census.sqlite3"
        ),
        firmware_image=originals / "firmware_autopilot868.bin",
        expected_sha256=_expected_sha(
            originals / "SHA256SUMS.txt",
            "firmware_autopilot868.bin",
        ),
        peripherals=peripherals,
        resolve_register=resolve_register,
        catalog_identity=f"ATSAMD51J19A.svd sha256:{svd_sha}",
    )
