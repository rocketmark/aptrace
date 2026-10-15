"""
Indirect-call target derivation: for ONE register-indirect transfer site
the census inventories, which definitions of the branch register reach it
and what dataflow shape they form (tools/census/indirect_target.py:
intraprocedural reaching definitions over the census's basic blocks).

A vtable-slot shape yields candidate targets only against vtables the
census itself found installed by a constructor store. Each candidate is a
POTENTIAL table target, conditional on the receiver holding that vptr: it
is neither an observed dispatch nor a reachable path. A request names a
site only; the firmware, census, analysis bounds and vtable source are
bound here.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


ANALYSIS_NAME = "indirect_call_target"
ANALYSIS_VERSION = 1
TIMEOUT_SECONDS = 120
STATIC_DERIVATION = "STATIC_INTRAPROCEDURAL_DERIVATION"

_SITE_RE = re.compile(r"(?:0x)?([0-9a-fA-F]{1,8})")


class IndirectTargetInputError(ValueError):
    """The request names something APTrace does not allow."""


class IndirectCallTarget(BaseModel):
    status: str
    site: str
    basis: str = STATIC_DERIVATION
    instruction: str | None = None
    target_register: str | None = None
    containing_function: str | None = None
    pattern: str | None = None
    derivation_status: str | None = None
    resolution_status: str | None = None
    patterns: list[dict[str, Any]] = Field(default_factory=list)
    candidate_targets: list[dict[str, Any]] = Field(default_factory=list)
    vtables_considered: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    planner_summary: str = ""


def validate_site(site: Any, allowed: Iterable[int]) -> int:
    """A census register-indirect site address; nothing else is accepted."""

    match = _SITE_RE.fullmatch(str(site).strip())

    if match is None:
        raise IndirectTargetInputError("site must be a hex instruction address")

    address = int(match.group(1), 16)

    if address not in set(allowed):
        raise IndirectTargetInputError(f"0x{address:08x} is not a census register-indirect transfer site")

    return address


def census_register_indirect_sites(db_path: Path, firmware_key: str) -> list[int]:
    if not Path(db_path).is_file():
        return []

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

    try:
        return [row[0] for row in conn.execute(
            "SELECT r.from_addr FROM indirect_edge_resolutions r JOIN firmware f ON f.id=r.firmware_id "
            "WHERE f.key=? AND r.instr_shape='reg-indirect' ORDER BY r.from_addr", (firmware_key,))]
    finally:
        conn.close()


class IndirectTargetRunner:
    """
    Bounded static target derivation for one census indirect site.

    APTrace binds the interpreter, census tool, census database, firmware
    identity and time bound at construction; a request names one site from
    the census's register-indirect inventory.
    """

    def __init__(
        self,
        *,
        python: Path,
        script: Path,
        firmware_key: str,
        firmware_image: Path,
        expected_sha256: str,
        db_path: Path,
        sites: Callable[[], Iterable[int]] | None = None,
        run: Callable[[list[str]], subprocess.CompletedProcess] | None = None,
    ) -> None:
        self.python = Path(python)
        self.script = Path(script)
        self.firmware_key = firmware_key
        self.firmware_image = Path(firmware_image)
        self.expected_sha256 = expected_sha256.lower()
        self.db_path = Path(db_path)
        self._sites = sites or (lambda: census_register_indirect_sites(self.db_path, self.firmware_key))
        self._cached_sites: list[int] | None = None
        self._run = run or (
            lambda argv: subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)
        )

    def sites(self) -> list[int]:
        if self._cached_sites is None:
            self._cached_sites = sorted(self._sites())

        return self._cached_sites

    def resolve(self, site: Any) -> IndirectCallTarget:
        address = validate_site(site, self.sites())
        name = f"0x{address:08x}"
        base = IndirectCallTarget(status="failed", site=name)
        image = self.firmware_image.read_bytes() if self.firmware_image.is_file() else b""

        if hashlib.sha256(image).hexdigest() != self.expected_sha256:
            base.status = "firmware_unavailable"
            base.planner_summary = f"{name} indirect target: firmware image missing or hash mismatch"
            return base

        argv = [str(self.python), str(self.script), self.firmware_key, "--db", str(self.db_path),
                "--site", name, "--vtables-from-installations"]

        try:
            proc = self._run(argv)
        except subprocess.TimeoutExpired:
            base.status = f"bounded: timeout {TIMEOUT_SECONDS}s"
            base.planner_summary = f"{name} indirect target: analysis did not finish within {TIMEOUT_SECONDS}s; nothing concluded"
            return base

        if proc.returncode != 0:
            tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no output"]
            base.planner_summary = f"{name} indirect target: analysis failed ({tail[0][:160]})"
            return base

        try:
            doc = json.loads(proc.stdout)
            result = doc["sites"][0]
        except (ValueError, KeyError, IndexError):
            base.planner_summary = f"{name} indirect target: analysis emitted no result"
            return base

        if str(result.get("firmware_sha256", "")).lower() != self.expected_sha256:
            raise RuntimeError("indirect target analysis was produced for a different firmware image")

        if result.get("site") != name:
            raise RuntimeError(f"indirect target analysis answered {result.get('site')!r}, not {name!r}")

        out = IndirectCallTarget(
            status="ok",
            site=name,
            instruction=f"{result.get('mnemonic')} {result.get('target_reg') or ''}".strip(),
            target_register=result.get("target_reg"),
            containing_function=result.get("containing_function"),
            pattern=result.get("pattern"),
            derivation_status=result.get("derivation_status"),
            resolution_status=result.get("resolution_status"),
            patterns=list(result.get("patterns") or []),
            candidate_targets=list(result.get("candidate_targets") or []),
            vtables_considered=list(result.get("vtables_supplied") or []),
            limitations=list(result.get("limitations") or []),
            provenance={
                "analysis": ANALYSIS_NAME,
                "analysis_version": ANALYSIS_VERSION,
                "engine": {"analysis": result.get("analysis"), "analysis_version": result.get("analysis_version"),
                           "bounds": result.get("bounds")},
                "firmware_sha256": self.expected_sha256,
                "vtable_source": "constructor vptr stores found by indirect_target.vptr_installations (pattern-matched)",
                "blocks": "census basic blocks and resolved edges (Ghidra block model + Capstone sweep; heuristic boundaries)",
            },
        )
        out.planner_summary = planner_summary(out)
        return out


def _origin(origin: dict[str, Any] | None) -> str:
    if not origin:
        return "?"

    kind = origin.get("kind")

    if kind == "argument":
        return f"incoming r{origin.get('arg')}"

    if kind == "constant":
        return f"constant {origin.get('value')}"

    if kind == "multiple":
        return "one of " + "/".join(origin.get("kinds") or [])

    if kind == "load":
        return f"load {origin.get('instruction')}"

    return str(kind)


def planner_summary(result: IndirectCallTarget) -> str:
    """Compact, mechanically derived planner rendering."""

    if result.planner_summary:
        return result.planner_summary

    lines = [
        f"{result.site} {result.instruction} in {result.containing_function or 'unattributed code'} "
        f"[{result.basis}]: {result.pattern}, derivation {result.derivation_status}, target {result.resolution_status}"
    ]

    for p in result.patterns[:3]:
        kind = p.get("pattern")

        if kind in ("vtable-slot", "object-table-slot"):
            lines.append(
                f"  {p.get('load_instruction')} at {p.get('load_addr')}: slot +0x{p['slot_offset']:x} (index "
                f"{p.get('slot_index')}) of the table at [receiver+0x{p.get('table_pointer_offset', 0):x}]; "
                f"receiver {_origin(p.get('receiver'))}"
            )
        elif kind == "object-field":
            lines.append(f"  function pointer at [{_origin(p.get('pointer'))} + 0x{p['field_offset']:x}]")
        elif kind == "argument":
            arg = p.get("arg")
            where = f"r{arg}" if isinstance(arg, int) and arg < 4 else f"stack argument {arg}"
            lines.append(f"  callback passed in {where} (callers not followed)")
        elif kind == "constant-slot":
            lines.append(f"  fixed {p.get('slot_region')} word {p.get('slot_addr')}")
        elif kind == "indexed-table":
            lines.append(f"  indexed table at {_origin(p.get('table_base'))}")
        else:
            lines.append(f"  {kind}: {p.get('reason') or p.get('value') or ''}".rstrip())

    targets = [t for t in result.candidate_targets if t.get("is_code_pointer")]

    for t in targets[:4]:
        cond = f"IF the receiver's vptr is {t['vtable']}" if t.get("vtable") else t.get("basis", "")
        lines.append(f"  potential target {t['target']} ({cond})")

    if len(targets) > 4:
        lines.append(f"  +{len(targets) - 4} more potential targets")

    lines.append("  a potential target is not an observed dispatch, and a dispatch is not a reachable path")
    return "\n".join(lines)
