"""
Structural agreement between independent code-discovery sources.

For a code address, each analysis source (the census database, a Ghidra
static export, a Macaw census) is asked one mechanical question: does it
recognize executable code there, and if so in which function, with which
extent and which basic blocks? The answers are compared and classified.

The classification is deliberately weak:

- A source that does not know the code at an address is a COVERAGE GAP of
  that source. It is never negative evidence about the firmware.
- Sources that recognize the code but disagree about the containing
  function's start or extent are a BOUNDARY_DISAGREEMENT. Function
  boundaries are heuristic in every source; this is not a contradiction of
  a claim that depends only on the code being there.
- One source's blocks being a subset of another's is PARTIAL_AGREEMENT.
- Only CONFLICT (a source affirmatively classifies the address as
  non-code while another decodes code there) is contradictory structural
  evidence.

Agreement is structural consistency between sources, never semantic proof.
Sources are not necessarily independent (a census may be derived from the
same Ghidra export); each observation records what it was derived from.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field


class AgreementStatus(StrEnum):
    AGREE = "AGREE"
    PARTIAL_AGREEMENT = "PARTIAL_AGREEMENT"
    BOUNDARY_DISAGREEMENT = "BOUNDARY_DISAGREEMENT"
    SOURCE_MISSING = "SOURCE_MISSING"
    CONFLICT = "CONFLICT"


class EvidenceRelation(StrEnum):
    """What an agreement status means for a claim relying on the code."""

    CONSISTENT = "CONSISTENT"
    COVERAGE_GAP = "COVERAGE_GAP"
    STRUCTURAL_DISAGREEMENT = "STRUCTURAL_DISAGREEMENT"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"


RELATION = {
    AgreementStatus.AGREE: EvidenceRelation.CONSISTENT,
    AgreementStatus.PARTIAL_AGREEMENT: EvidenceRelation.CONSISTENT,
    AgreementStatus.SOURCE_MISSING: EvidenceRelation.COVERAGE_GAP,
    AgreementStatus.BOUNDARY_DISAGREEMENT: EvidenceRelation.STRUCTURAL_DISAGREEMENT,
    AgreementStatus.CONFLICT: EvidenceRelation.CONTRADICTORY_EVIDENCE,
}

AGREEMENT_SEMANTICS = (
    "SOURCE_MISSING / <SOURCE>_COVERAGE_GAP: a source has no code there; a coverage gap, not evidence "
    "against a claim. BOUNDARY_DISAGREEMENT: sources see code but disagree on function extent; "
    "structural, not a contradiction of a claim. PARTIAL_AGREEMENT: one source covers a subset. "
    "Only CONFLICT is contradictory structural evidence."
)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SourceObservation(_Model):
    """What one source says about one address."""

    source: str
    available: bool
    # sha256 (or other identity) of the artifact the source answered from.
    version: str | None = None
    # A source this one is derived from (e.g. census <- ghidra), if any.
    derived_from: str | None = None
    # None when the source is unavailable.
    recognizes_code: bool | None = None
    # True only when the source affirmatively classifies the address as data.
    non_code: bool = False
    function: str | None = None
    start: str | None = None
    # Exclusive end of the containing function's extent.
    end: str | None = None
    # Basic blocks of the containing function as [start, end) pairs
    # (bounded), if the source has blocks.
    blocks: list[tuple[str, str]] | None = None
    block_bytes: int | None = None
    seeded: str | None = None
    note: str = ""


class StructuralSourceAgreement(_Model):
    address: str
    observations: list[SourceObservation]
    recognizing_sources: list[str] = Field(default_factory=list)
    function_start_agreement: str = "N/A"  # AGREE | DISAGREE | N/A
    function_range_agreement: str = "N/A"  # AGREE | DIFFER | N/A
    # Byte coverage of the containing function's blocks.
    block_agreement: str = "N/A"  # AGREE | SUBSET | DISAGREE | N/A
    status: AgreementStatus
    relation: EvidenceRelation
    coverage_gaps: list[str] = Field(default_factory=list)
    disagreement: str | None = None

    def observation(self, source: str) -> SourceObservation | None:
        return next((o for o in self.observations if o.source == source), None)


class CodeSource(Protocol):
    name: str

    def observe(self, address: int) -> SourceObservation: ...


def hx(value: int | None) -> str | None:
    return None if value is None else f"0x{value:08x}"


def _int(value: str | None) -> int | None:
    return None if value is None else int(value, 16)


# -- classification ---------------------------------------------------------


def _coverage(observation: SourceObservation) -> set[int]:
    return {a for start, end in observation.blocks or () for a in range(int(start, 16), int(end, 16))}


def _coverage_relation(a: set[int], b: set[int]) -> str:
    if a == b:
        return "AGREE"

    if a <= b or b <= a:
        return "SUBSET"

    return "DISAGREE"


def classify(address: int, observations: Sequence[SourceObservation]) -> StructuralSourceAgreement:
    available = [o for o in observations if o.available]
    recognizing = [o for o in available if o.recognizes_code]
    gaps = [f"{o.source.upper()}_COVERAGE_GAP" for o in available if not o.recognizes_code and not o.non_code]
    gaps += [f"{o.source.upper()}_UNAVAILABLE" for o in observations if not o.available]
    conflicting = [o for o in available if o.non_code]
    base = dict(
        address=hx(address),
        observations=list(observations),
        recognizing_sources=[o.source for o in recognizing],
        coverage_gaps=gaps,
    )

    if conflicting and recognizing:
        detail = (
            f"{', '.join(o.source for o in conflicting)} classify {hx(address)} as non-code; "
            f"{', '.join(o.source for o in recognizing)} decode code there"
        )
        return StructuralSourceAgreement(**base, status=AgreementStatus.CONFLICT, relation=RELATION[AgreementStatus.CONFLICT], disagreement=detail)

    if len(recognizing) < 2:
        known = recognizing[0].source if recognizing else "no source"
        return StructuralSourceAgreement(
            **base,
            status=AgreementStatus.SOURCE_MISSING,
            relation=RELATION[AgreementStatus.SOURCE_MISSING],
            disagreement=f"only {known} recognizes code at {hx(address)}",
        )

    with_function = [o for o in recognizing if o.start]
    start_agreement = range_agreement = block_agreement = "N/A"

    if len(with_function) >= 2:
        start_agreement = "AGREE" if len({o.start for o in with_function}) == 1 else "DISAGREE"
        range_agreement = "AGREE" if len({(o.start, o.end) for o in with_function}) == 1 else "DIFFER"

    covered = [_coverage(o) for o in with_function if o.blocks]

    if len(covered) >= 2:
        relations = {_coverage_relation(covered[0], other) for other in covered[1:]}
        block_agreement = "DISAGREE" if "DISAGREE" in relations else "SUBSET" if "SUBSET" in relations else "AGREE"

    details = []

    if start_agreement == "DISAGREE":
        details.append("function start: " + ", ".join(f"{o.source}={o.function}@{o.start}" for o in with_function))

    if range_agreement == "DIFFER":
        details.append("function extent: " + ", ".join(f"{o.source}=[{o.start},{o.end})" for o in with_function))

    if block_agreement in ("DISAGREE", "SUBSET"):
        details.append(f"block coverage: {block_agreement.lower()}")

    # A differing extent whose block coverage is nested is one source
    # covering a subset of another's body, not a boundary dispute.
    boundary = (
        start_agreement == "DISAGREE"
        or block_agreement == "DISAGREE"
        or (range_agreement == "DIFFER" and block_agreement != "SUBSET")
    )

    if boundary:
        status = AgreementStatus.BOUNDARY_DISAGREEMENT
    elif block_agreement == "SUBSET" or gaps:
        status = AgreementStatus.PARTIAL_AGREEMENT
    else:
        status = AgreementStatus.AGREE

    if gaps:
        details.append("coverage gaps: " + ", ".join(gaps))

    return StructuralSourceAgreement(
        **base,
        function_start_agreement=start_agreement,
        function_range_agreement=range_agreement,
        block_agreement=block_agreement,
        status=status,
        relation=RELATION[status],
        disagreement="; ".join(details) or None,
    )


# -- sources ----------------------------------------------------------------

MAX_BLOCKS = 64


def _seeded(seeds: dict[int, str], entry: int | None) -> str | None:
    return None if entry is None else seeds.get(entry)


class CensusDbSource:
    """Function/basic-block inventory of a census database."""

    name = "census"

    def __init__(self, db_path: Path, firmware_key: str, *, version: str | None, derived_from: str | None = None, seeds: dict[int, str] | None = None):
        self.db_path = Path(db_path)
        self.firmware_key = firmware_key
        self.version = version
        self.derived_from = derived_from
        self.seeds = seeds or {}

    def observe(self, address: int) -> SourceObservation:
        if not self.db_path.is_file():
            return SourceObservation(source=self.name, available=False, note="census database not present")

        conn = sqlite3.connect(f"{self.db_path.resolve().as_uri()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row

        try:
            fw = conn.execute("SELECT id FROM firmware WHERE key=?", (self.firmware_key,)).fetchone()

            if fw is None:
                return SourceObservation(source=self.name, available=False, version=self.version, note=f"no census for {self.firmware_key}")

            fid = fw["id"]
            row = conn.execute(
                "SELECT id, entry, name, size FROM functions WHERE firmware_id=? AND entry<=? AND ?<entry+size ORDER BY entry DESC LIMIT 1",
                (fid, address, address),
            ).fetchone()

            if row is None:
                block = conn.execute(
                    "SELECT b.function_id, f.entry, f.name, f.size FROM basic_blocks b LEFT JOIN functions f ON f.id=b.function_id "
                    "WHERE b.firmware_id=? AND b.start_addr<=? AND ?<=b.end_addr LIMIT 1",
                    (fid, address, address),
                ).fetchone()

                if block is None:
                    return SourceObservation(source=self.name, available=True, version=self.version, derived_from=self.derived_from, recognizes_code=False)

                if block["function_id"] is None:
                    return SourceObservation(
                        source=self.name, available=True, version=self.version, derived_from=self.derived_from,
                        recognizes_code=True, note="block not attributed to a function",
                    )

                row = {"id": block["function_id"], "entry": block["entry"], "name": block["name"], "size": block["size"]}

            blocks = conn.execute(
                "SELECT start_addr, end_addr FROM basic_blocks WHERE firmware_id=? AND function_id=? ORDER BY start_addr",
                (fid, row["id"]),
            ).fetchall()
        finally:
            conn.close()

        return SourceObservation(
            source=self.name,
            available=True,
            version=self.version,
            derived_from=self.derived_from,
            recognizes_code=True,
            function=row["name"],
            start=hx(row["entry"]),
            end=hx(row["entry"] + row["size"]),
            blocks=[(hx(b["start_addr"]), hx(b["end_addr"] + 1)) for b in blocks[:MAX_BLOCKS]] if blocks else None,
            block_bytes=sum(b["end_addr"] - b["start_addr"] + 1 for b in blocks) if blocks else None,
            seeded=_seeded(self.seeds, row["entry"]),
        )


class GhidraExportSource:
    """Function table of an APTrace Ghidra static export (and, optionally,
    the basic blocks of the census export from the same Ghidra project)."""

    name = "ghidra"

    def __init__(self, static_export: Path, *, version: str | None, census_export: Path | None = None, seeds: dict[int, str] | None = None, note: str = ""):
        self.static_export = Path(static_export)
        self.census_export = Path(census_export) if census_export else None
        self.version = version
        self.seeds = seeds or {}
        self.note = note
        self._functions: list[tuple[int, int, str]] | None = None
        self._blocks: dict[int, list[tuple[int, int]]] | None = None

    def _load(self) -> None:
        if self._functions is not None:
            return

        data = json.loads(self.static_export.read_text())
        self._functions = sorted(
            (int(f["entry"], 16), int(f.get("size") or 0), str(f["name"]))
            for f in data.get("functions", [])
            if isinstance(f.get("entry"), str)
        )
        self._blocks = {}

        if self.census_export is not None and self.census_export.is_file():
            census = json.loads(self.census_export.read_text())

            for block in census.get("basicBlocks", []):
                entry = block.get("functionEntry")

                if entry:
                    self._blocks.setdefault(int(entry, 16), []).append((int(block["start"], 16), int(block["end"], 16)))

    def observe(self, address: int) -> SourceObservation:
        if not self.static_export.is_file():
            return SourceObservation(source=self.name, available=False, note="Ghidra export not present")

        self._load()
        assert self._functions is not None and self._blocks is not None
        match = next((f for f in reversed(self._functions) if f[0] <= address < f[0] + f[1]), None)

        if match is None:
            in_block = next(
                (entry for entry, blocks in self._blocks.items() if any(s <= address <= e for s, e in blocks)),
                None,
            )
            match = next((f for f in self._functions if f[0] == in_block), None) if in_block is not None else None

        if match is None:
            return SourceObservation(source=self.name, available=True, version=self.version, recognizes_code=False, note=self.note)

        entry, size, name = match
        blocks = sorted(self._blocks.get(entry, []))
        return SourceObservation(
            source=self.name,
            available=True,
            version=self.version,
            recognizes_code=True,
            function=name,
            start=hx(entry),
            end=hx(entry + size),
            blocks=[(hx(s), hx(e + 1)) for s, e in blocks[:MAX_BLOCKS]] if blocks else None,
            block_bytes=sum(e - s + 1 for s, e in blocks) if blocks else None,
            seeded=_seeded(self.seeds, entry),
            note=self.note,
        )


class MacawCensusSource:
    """Blocks of an `aptrace macaw-census` result (vector-root discovery only)."""

    name = "macaw"

    def __init__(self, census_json: Path, *, version: str | None, expected_size: int | None = None):
        self.census_json = Path(census_json)
        self.version = version
        self.expected_size = expected_size
        self._blocks: dict[int, list[tuple[int, int]]] | None = None
        self._error: str | None = None

    def _load(self) -> None:
        if self._blocks is not None:
            return

        doc = json.loads(self.census_json.read_text())
        self._blocks = {}

        if doc.get("discovery_error"):
            self._error = f"macaw discovery_error: {doc['discovery_error']}"

        size = doc.get("firmware", {}).get("size_bytes")

        if self.expected_size is not None and size is not None and int(size) != self.expected_size:
            self._error = f"macaw census was built for a {size}-byte image, expected {self.expected_size}"

        for block in doc.get("basic_blocks", []):
            entry = int(block["function_entry"], 16)
            start = int(block["block_start"], 16)
            self._blocks.setdefault(entry, []).append((start, start + int(block["size"])))

    def observe(self, address: int) -> SourceObservation:
        if not self.census_json.is_file():
            return SourceObservation(source=self.name, available=False, note="Macaw census not present")

        self._load()
        assert self._blocks is not None

        if self._error:
            return SourceObservation(source=self.name, available=False, version=self.version, note=self._error)

        owners = sorted(entry for entry, blocks in self._blocks.items() if any(s <= address < e for s, e in blocks))
        note = "Macaw discovery is seeded only from vector-table roots"

        if not owners:
            return SourceObservation(source=self.name, available=True, version=self.version, recognizes_code=False, note=note)

        entry = address if address in owners else owners[0]
        blocks = sorted(self._blocks[entry])
        return SourceObservation(
            source=self.name,
            available=True,
            version=self.version,
            recognizes_code=True,
            function=f"FUN_{entry:08x}",
            start=hx(entry),
            end=hx(max(e for _s, e in blocks)),
            blocks=[(hx(s), hx(e)) for s, e in blocks[:MAX_BLOCKS]],
            block_bytes=sum(e - s for s, e in blocks),
            note=note + (f"; address in {len(owners)} Macaw functions" if len(owners) > 1 else ""),
        )


def parse_addresses(values: Iterable[Any], limit: int = 16) -> list[int]:
    out: list[int] = []

    for value in values:
        address = int(value, 16) if isinstance(value, str) else int(value)

        if not 0 <= address <= 0xFFFFFFFF:
            raise ValueError(f"address out of range: {value!r}")

        out.append(address)

    unique = sorted(set(out))

    if not unique or len(unique) > limit:
        raise ValueError(f"structural_source_agreement takes 1..{limit} addresses")

    return unique


def source_agreement(sources: Sequence[CodeSource], addresses: Iterable[Any]) -> dict[str, Any]:
    """Deterministic agreement result for a bounded set of code addresses."""

    entries = [classify(address, [source.observe(address) for source in sources]) for address in parse_addresses(addresses)]
    counts: dict[str, int] = {}

    for entry in entries:
        counts[entry.status.value] = counts.get(entry.status.value, 0) + 1

    lines = [
        f"{e.address} {e.status.value}"
        + "".join(
            f" {o.source}={o.function or ('-' if o.available else 'n/a')}"
            + (f"[{o.start},{o.end})" if o.start else "")
            for o in e.observations
        )
        + (f" gaps={','.join(e.coverage_gaps)}" if e.coverage_gaps else "")
        for e in entries
    ]
    return {
        "status": "ok",
        "agreements": [entry.model_dump(mode="json") for entry in entries],
        "status_counts": dict(sorted(counts.items())),
        "sources": [
            {"source": s.name, "version": getattr(s, "version", None), "derived_from": getattr(s, "derived_from", None)}
            for s in sources
        ],
        "semantics": AGREEMENT_SEMANTICS,
        "planner_summary": "structural source agreement:\n  " + "\n  ".join(lines),
    }
