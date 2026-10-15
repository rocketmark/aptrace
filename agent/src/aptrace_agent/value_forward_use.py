"""
Value forward use: where can the value ONE instruction defines flow inside
its containing function, and does it escape (tools/ghidra/pcode_forward_use.py:
Ghidra raw p-code, calling convention from the program's compiler spec)?

Escapes are a control transfer, a call argument (by storage), a memory
store, or a return value. A use that is only compared, dereferenced or
overwritten stays local. NO_ESCAPE_WITHIN_SCOPE is reported only for a
complete analysis of the containing function; a missing function, an edge
leaving the body, an unresolved computed jump, an unmodeled operation or an
exhausted budget is INCOMPLETE with its reason, never a negative. Values
stored to memory are not followed (MEMORY_ESCAPE is an over-approximation).

The engine, language and compiler spec are taken from the analyzed Ghidra
project the runner is bound to; a request names an instruction address
(and optionally the register to track) only.
"""

from __future__ import annotations

import json
import re
import sqlite3
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from aptrace_agent.ledger.hashing import file_sha256


ANALYSIS_NAME = "value_forward_use"
ANALYSIS_VERSION = 1
TIMEOUT_SECONDS = 300
STATIC_PCODE = "STATIC_PCODE_FORWARD_USE"

_GHIDRA_TOOLS = Path(__file__).resolve().parents[3] / "tools" / "ghidra"
# Files whose content defines a value_forward_use result beyond the
# firmware and the Ghidra project: the p-code walker and its APTrace driver.
VALUE_FORWARD_USE_INPUTS = {
    "pcode_forward_use_walker": _GHIDRA_TOOLS / "scripts" / "APTracePcodeForwardUse.java",
    "pcode_forward_use_driver": _GHIDRA_TOOLS / "pcode_forward_use.py",
    "ghidra_headless_locator": _GHIDRA_TOOLS / "headless.py",
}

_ADDRESS_RE = re.compile(r"(?:0x)?([0-9a-fA-F]{1,8})")
_REGISTER_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,15}")

LIMITATIONS = [
    "intraprocedural: the containing Ghidra function bounds the analysis; a transfer to another function's entry is a tail call",
    "calls, tail calls and returns follow the program's default calling convention (cspec); ARGUMENT means the value may "
    "be in argument storage, not that the callee reads it",
    "values stored to memory are not followed: MEMORY_ESCAPE includes stack spills that are reloaded locally",
    "a value consumed only by a comparison is a local use (one bit of information flows)",
    "function bodies and computed-jump targets are Ghidra's analysis results (heuristic boundaries)",
]


class ValueForwardUseInputError(ValueError):
    """The request names something APTrace does not allow."""


class ValueForwardUse(BaseModel):
    status: str
    origin: str
    requested_register: str | None = None
    basis: str = STATIC_PCODE
    verdict: str | None = None
    complete: bool = False
    escape_kinds: list[str] = Field(default_factory=list)
    origin_instruction: str | None = None
    tracked: dict[str, Any] = Field(default_factory=dict)
    origin_value: dict[str, Any] = Field(default_factory=dict)
    scope: dict[str, Any] = Field(default_factory=dict)
    uses: list[dict[str, Any]] = Field(default_factory=list)
    kills: list[dict[str, Any]] = Field(default_factory=list)
    derivation: list[dict[str, Any]] = Field(default_factory=list)
    incomplete: list[dict[str, Any]] = Field(default_factory=list)
    precision: list[dict[str, Any]] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    unsupported: dict[str, Any] = Field(default_factory=dict)
    work: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    planner_summary: str = ""


def validate_origin(origin: Any, register: Any = None) -> tuple[int, str | None]:
    match = _ADDRESS_RE.fullmatch(str(origin).strip())

    if match is None:
        raise ValueForwardUseInputError("origin must be a hex instruction address")

    if register is not None and not _REGISTER_RE.fullmatch(str(register)):
        raise ValueForwardUseInputError("register must be a register name")

    return int(match.group(1), 16), (str(register) if register is not None else None)


def census_code_pointer_loads(db_path: Path, firmware_key: str) -> list[int]:
    """Instructions that READ a flash word the census holds as a pointer to a known function."""

    if not Path(db_path).is_file():
        return []

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

    try:
        return [row[0] for row in conn.execute(
            "SELECT DISTINCT l.from_addr FROM function_pointers p "
            "JOIN literal_refs l ON l.to_addr=p.location_addr AND l.firmware_id=p.firmware_id "
            "JOIN firmware f ON f.id=p.firmware_id "
            "WHERE f.key=? AND p.matches_known_function=1 AND l.ref_type='READ' ORDER BY l.from_addr", (firmware_key,))]
    finally:
        conn.close()


class ValueForwardUseRunner:
    """
    Bounded p-code forward use of one value, over an analyzed Ghidra project.

    APTrace binds the interpreter, driver, firmware image and hash, the
    project (copied to a scratch workspace per invocation by the driver),
    its language and compiler spec, the step budget and the time bound at
    construction. A request names an origin address and optionally a
    register.
    """

    def __init__(
        self,
        *,
        python: Path,
        firmware_image: Path,
        expected_sha256: str,
        project_dir: Path,
        project_name: str,
        program: str,
        project_identity: Path,
        driver: Path = VALUE_FORWARD_USE_INPUTS["pcode_forward_use_driver"],
        max_steps: int = 20000,
        run: Callable[[list[str]], subprocess.CompletedProcess] | None = None,
    ) -> None:
        self.python = Path(python)
        self.driver = Path(driver)
        self.firmware_image = Path(firmware_image)
        self.expected_sha256 = expected_sha256.lower()
        self.project_dir = Path(project_dir)
        self.project_name = project_name
        self.program = program
        # The project's cache identity record (language, cspec, base, Ghidra
        # version, firmware hash, build inputs).
        self.project_identity = Path(project_identity)
        self.max_steps = max_steps
        self._run = run or (
            lambda argv: subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)
        )

    def _identity(self) -> dict[str, Any] | None:
        try:
            return json.loads(self.project_identity.read_text())
        except (OSError, ValueError):
            return None

    def trace(self, origin: Any, register: Any = None) -> ValueForwardUse:
        address, reg = validate_origin(origin, register)
        name = f"0x{address:08x}"
        base = ValueForwardUse(status="failed", origin=name, requested_register=reg, limitations=list(LIMITATIONS))
        meta = self._identity()

        if file_sha256(self.firmware_image) != self.expected_sha256:
            base.status = "firmware_unavailable"
            base.planner_summary = f"{name} value forward use: firmware image missing or hash mismatch"
            return base

        if meta is None or str(meta.get("firmware_sha256", "")).lower() != self.expected_sha256:
            base.status = "project_unavailable"
            base.planner_summary = f"{name} value forward use: no Ghidra project for this firmware"
            return base

        argv = [
            str(self.python), str(self.driver), "project", str(self.firmware_image),
            "--sha256", self.expected_sha256, "--language", str(meta["processor"]), "--cspec", str(meta["cspec"]),
            "--base", str(meta["load_base"]), "--project-dir", str(self.project_dir),
            "--project-name", self.project_name, "--program", self.program,
            "--project-identity", file_sha256(self.project_identity) or "",
            "--origin", name + (f":{reg}" if reg else ""), "--max-steps", str(self.max_steps),
        ]

        try:
            proc = self._run(argv)
        except subprocess.TimeoutExpired:
            base.status = f"bounded: timeout {TIMEOUT_SECONDS}s"
            base.planner_summary = f"{name} value forward use: analysis did not finish within {TIMEOUT_SECONDS}s; nothing concluded"
            return base

        try:
            doc = json.loads(proc.stdout)
        except ValueError:
            doc = {}

        if proc.returncode == 2 and doc.get("status") == "invalid_request":
            raise ValueForwardUseInputError(doc.get("error", "invalid request"))

        if proc.returncode != 0 or "result" not in doc:
            tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no output"]
            base.planner_summary = f"{name} value forward use: analysis failed ({tail[0][:160]})"
            return base

        result = doc["result"]

        if result.get("status") == "engine_unavailable":
            base.status = "engine_unavailable"
            base.planner_summary = f"{name} value forward use: Ghidra is not available; nothing concluded"
            return base

        if str(result["target"].get("image_sha256", "")).lower() != self.expected_sha256:
            raise RuntimeError("value forward use was produced for a different firmware image")

        r = result["results"][0]

        if int(r["origin_address"], 16) != address:
            raise RuntimeError(f"value forward use answered {r['origin_address']!r}, not {name!r}")

        out = ValueForwardUse(
            status="ok" if r["verdict"] != "UNSUPPORTED" else "unsupported",
            origin=name,
            requested_register=reg,
            verdict=r["verdict"],
            complete=bool(r.get("complete")),
            escape_kinds=list(r.get("escape_kinds") or []),
            origin_instruction=r.get("origin_instruction"),
            tracked=dict(r.get("tracked") or {}),
            origin_value=dict(r.get("origin_value") or {}),
            scope=dict(r.get("scope") or {}),
            uses=list(r.get("uses") or []),
            kills=list(r.get("kills") or []),
            derivation=list(r.get("derivation") or []),
            incomplete=list(r.get("incomplete") or []),
            precision=list(r.get("precision") or []),
            assumptions=list(r.get("assumptions") or []),
            unsupported=dict(r.get("unsupported") or {}),
            work=dict(r.get("work") or {}),
            limitations=list(LIMITATIONS),
            provenance={
                "analysis": ANALYSIS_NAME,
                "analysis_version": ANALYSIS_VERSION,
                "engine": result.get("engine"),
                "program": result.get("program"),
                "target": result.get("target"),
                "walker": result.get("walker"),
                "pcode_analysis": result.get("analysis"),
                "pcode_analysis_version": result.get("analysis_version"),
                "walker_sha256": result.get("walker_sha256"),
                "driver_sha256": result.get("driver_sha256"),
                "bounds": result.get("bounds"),
                "firmware_sha256": self.expected_sha256,
                "project": "analyzed Ghidra project, copied to a scratch workspace and opened read-only",
            },
        )
        out.planner_summary = planner_summary(out)
        return out


def _use(u: dict[str, Any]) -> str:
    via = "/".join(u.get("via") or [])
    return f"{u['kind']} at {u['address']} ({u['instruction']}{', via ' + via if via else ''})"


def planner_summary(result: ValueForwardUse) -> str:
    """Compact, mechanically derived planner rendering."""

    if result.planner_summary:
        return result.planner_summary

    if result.verdict == "UNSUPPORTED":
        return f"{result.origin} value forward use: unsupported ({result.unsupported.get('code')}: {result.unsupported.get('detail')})"

    value = result.origin_value
    shown = ""

    if value.get("value"):
        shown = f" = {value['value']}" + (f" (code {value['code_address']}, {value['function_at_code_address']})"
                                          if value.get("function_at_code_address") else "")

    fn = result.scope.get("function_name") or "no containing function"
    lines = [
        f"{result.origin} {result.origin_instruction} defines {result.tracked.get('storage')}{shown} in {fn} [{result.basis}]: "
        f"{result.verdict}" + (f" ({', '.join(result.escape_kinds)})" if result.escape_kinds else "")
        + ("" if result.complete else " — analysis incomplete")
    ]
    escaping = [u for u in result.uses if u["kind"] in ("CONTROL_TRANSFER", "ARGUMENT", "STORE", "RETURN_VALUE")]
    local = [u for u in result.uses if u["kind"] in ("COMPARE", "DEREFERENCE_LOAD", "DEREFERENCE_STORE", "DEAD")]

    for u in (escaping or local)[:5]:
        lines.append("  " + _use(u))

    for i in result.incomplete[:3]:
        lines.append(f"  incomplete: {i['code']} {i.get('address') or ''} {i['detail'][:100]}")

    for p in result.precision[:2]:
        lines.append(f"  note: {p['code']}")

    lines.append("  scope: this one value inside its containing function; other loads of the same constant are separate questions")
    return "\n".join(lines)
