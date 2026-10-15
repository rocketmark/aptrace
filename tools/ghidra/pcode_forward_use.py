#!/usr/bin/env python3
"""
APTrace: where can a value defined at one instruction flow, and does it
escape the analyzed function? Answered over Ghidra p-code
(scripts/APTracePcodeForwardUse.java); this module is the APTrace side:
target binding, scratch isolation, identity checks, and the verdict policy.

Firmware-independent. A caller supplies the target explicitly:

- the image (path + expected sha256), Ghidra language id, compiler spec id,
  load base;
- either an analyzed Ghidra project to read (copied into a scratch
  workspace, opened -readOnly), or, for fixtures without a project, the
  function entries (and optional bodies) to create after a raw import.

Verdict policy (APTrace's, not the engine's):

- ESCAPE: at least one escaping use was found (CONTROL_FLOW_ESCAPE,
  ARGUMENT_ESCAPE, MEMORY_ESCAPE, RETURN_ESCAPE). It stands even when the
  analysis is incomplete; incompleteness then means other escapes may
  exist.
- NO_ESCAPE_WITHIN_SCOPE: no escaping use AND the analysis is complete.
- INCOMPLETE: no escaping use found, but some path was not analyzed
  (reasons with codes). Never reported as a negative.
- UNSUPPORTED: the origin cannot be analyzed as asked (no instruction, no
  single value output, ...), or the engine/language is unavailable.

Usage:
    pcode_forward_use.py import IMAGE --sha256 S --language L --cspec C --base B \\
        --function ENTRY[:LO-HI[,LO-HI...]] ... [--disassemble ADDR ...] --origin ADDR[:REG] ... [--max-steps N]
    pcode_forward_use.py project IMAGE --sha256 S --language L --cspec C --base B \\
        --project-dir DIR --project-name NAME --program PROGRAM \\
        [--project-identity SHA] --origin ADDR[:REG] ... [--max-steps N]

Prints one JSON document. `measurement` (wall time, peak RSS) is outside
the deterministic result and is reported separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from headless import find_headless, ghidra_version  # noqa: E402


ANALYSIS = "pcode_forward_use"
ANALYSIS_VERSION = 1
SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"
WALKER_SCRIPT = SCRIPTS_DIR / "APTracePcodeForwardUse.java"
DEFAULT_MAX_STEPS = 20000
MAX_MAX_STEPS = 200000
MAX_ORIGINS = 256
TIMEOUT_SECONDS = 300

# Walker use kinds that carry the value out of the analyzed function.
ESCAPE_KINDS = {
    "CONTROL_TRANSFER": "CONTROL_FLOW_ESCAPE",
    "ARGUMENT": "ARGUMENT_ESCAPE",
    "STORE": "MEMORY_ESCAPE",
    "RETURN_VALUE": "RETURN_ESCAPE",
}
# Walker use kinds that keep the value local (or end it).
LOCAL_KINDS = {"COMPARE", "DEREFERENCE_LOAD", "DEREFERENCE_STORE", "DEAD", "ENDS_AT_RETURN", "TAIL_TRANSFER", "UNMODELED"}

NO_ESCAPE = "NO_ESCAPE_WITHIN_SCOPE"
ESCAPE = "ESCAPE"
INCOMPLETE = "INCOMPLETE"
UNSUPPORTED = "UNSUPPORTED"


class ForwardUseError(Exception):
    """The target or request is invalid; nothing was analyzed."""


@dataclass(frozen=True)
class GhidraProject:
    directory: Path
    name: str
    program: str
    # Content identity of the project as the caller knows it (for example
    # the sha256 of the project's cache identity record). Recorded, not
    # interpreted.
    identity: str | None = None


@dataclass(frozen=True)
class FunctionSpec:
    entry: int
    body: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class Target:
    image: Path
    image_sha256: str
    language_id: str
    compiler_spec_id: str
    base: int
    project: GhidraProject | None = None
    # Import mode only, explicit harness assumptions: functions to create
    # and code seeds to disassemble without creating a function.
    functions: tuple[FunctionSpec, ...] = ()
    disassemble: tuple[int, ...] = ()

    def describe(self) -> dict:
        out = {
            "image_sha256": self.image_sha256,
            "language_id": self.language_id,
            "compiler_spec_id": self.compiler_spec_id,
            "base": f"0x{self.base:x}",
            "mode": "project" if self.project else "import",
        }
        if self.project:
            out["project_identity"] = self.project.identity
            out["program"] = self.project.program
        else:
            out["functions"] = [
                {"entry": f"0x{f.entry:x}", **({"body": [[f"0x{lo:x}", f"0x{hi:x}"] for lo, hi in f.body]} if f.body else {})}
                for f in self.functions
            ]
            out["disassemble"] = [f"0x{a:x}" for a in self.disassemble]
            out["auto_analysis"] = False
        return out


@dataclass(frozen=True)
class Origin:
    address: int
    register: str | None = None


@dataclass
class Measurement:
    wall_seconds: float = 0.0
    peak_rss_bytes: int | None = None
    walker_seconds: float | None = None
    extra: dict = field(default_factory=dict)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def implementation_identity() -> dict:
    """What defines this analysis's semantics besides the engine: walker and driver content."""

    return {
        "analysis": ANALYSIS,
        "analysis_version": ANALYSIS_VERSION,
        "walker_sha256": sha256_file(WALKER_SCRIPT),
        "driver_sha256": sha256_file(Path(__file__).resolve()),
    }


def _validate(target: Target, origins: list[Origin], max_steps: int) -> None:
    if not origins:
        raise ForwardUseError("no origin given")
    if len(origins) > MAX_ORIGINS:
        raise ForwardUseError(f"at most {MAX_ORIGINS} origins per invocation")
    if not 1 <= max_steps <= MAX_MAX_STEPS:
        raise ForwardUseError(f"max_steps must be 1..{MAX_MAX_STEPS}")
    if not target.image.is_file():
        raise ForwardUseError(f"image not found: {target.image}")
    if sha256_file(target.image) != target.image_sha256.lower():
        raise ForwardUseError("image sha256 does not match the target")
    size = target.image.stat().st_size
    for o in origins:
        if not target.base <= o.address < target.base + size:
            raise ForwardUseError(f"origin 0x{o.address:x} is outside the image [0x{target.base:x}, 0x{target.base + size:x})")
    if target.project and (target.functions or target.disassemble):
        raise ForwardUseError("function creation and code seeds are only allowed in import mode; a project is read as analyzed")
    if target.project and not (target.project.directory / f"{target.project.name}.gpr").exists():
        raise ForwardUseError(f"no Ghidra project {target.project.name}.gpr in {target.project.directory}")


def _run_measured(cmd: list[str], timeout: int) -> tuple[int, str, Measurement]:
    """Run a command; peak RSS comes from wait4 (the child and its waited-for descendants)."""

    started = time.perf_counter()
    with tempfile.TemporaryFile() as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
        deadline = started + timeout
        status = rusage = None
        while True:
            pid, status, rusage = os.wait4(proc.pid, os.WNOHANG)
            if pid:
                break
            if time.perf_counter() > deadline:
                proc.kill()
                _, status, rusage = os.wait4(proc.pid, 0)
                break
            time.sleep(0.05)
        proc.returncode = os.waitstatus_to_exitcode(status)
        log.seek(0)
        text = log.read().decode(errors="replace")
    rss = rusage.ru_maxrss if rusage else None
    if rss is not None and sys.platform != "darwin":
        rss *= 1024  # Linux reports KiB
    m = Measurement(wall_seconds=round(time.perf_counter() - started, 3), peak_rss_bytes=rss)
    if time.perf_counter() > deadline:
        return -1, text + f"\n[timeout after {timeout}s]", m
    return proc.returncode, text, m


def run_forward_use(
    target: Target,
    origins: list[Origin],
    *,
    max_steps: int = DEFAULT_MAX_STEPS,
    scratch_root: Path | None = None,
    timeout: int = TIMEOUT_SECONDS,
) -> tuple[dict, Measurement]:
    """
    One Ghidra invocation for every origin. Returns (deterministic result
    document, measurement). Raises ForwardUseError for an invalid request;
    an unavailable engine is an UNSUPPORTED document, not an exception.
    """

    _validate(target, origins, max_steps)
    headless = find_headless()
    doc = {
        **implementation_identity(),
        "target": target.describe(),
        "bounds": {"max_steps": max_steps},
    }
    if headless is None:
        doc["status"] = "engine_unavailable"
        doc["results"] = [_engine_unavailable(o) for o in origins]
        return doc, Measurement()

    with tempfile.TemporaryDirectory(prefix="aptrace-pcode-", dir=scratch_root) as tmp:
        work = Path(tmp)
        request = work / "request.json"
        output = work / "output.json"
        payload: dict = {
            "origins": [{"address": f"0x{o.address:x}", "register": o.register} for o in origins],
            "max_steps": max_steps,
        }
        if target.functions:
            payload["functions"] = [
                {"entry": f"0x{f.entry:x}", **({"body": [[f"0x{lo:x}", f"0x{hi:x}"] for lo, hi in f.body]} if f.body else {})}
                for f in target.functions
            ]
        if target.disassemble:
            payload["disassemble"] = [f"0x{a:x}" for a in target.disassemble]
        request.write_text(json.dumps(payload))
        script = ["-scriptPath", str(SCRIPTS_DIR), "-postScript", WALKER_SCRIPT.name, str(request), str(output)]

        if target.project:
            # A scratch copy: the source project is never opened, locked or written.
            proj = work / "project"
            proj.mkdir()
            shutil.copy2(target.project.directory / f"{target.project.name}.gpr", proj)
            shutil.copytree(target.project.directory / f"{target.project.name}.rep", proj / f"{target.project.name}.rep")
            cmd = [str(headless), str(proj), target.project.name, "-process", target.project.program,
                   "-noanalysis", "-readOnly", *script]
        else:
            proj = work / "project"
            proj.mkdir()
            cmd = [str(headless), str(proj), "scratch", "-import", str(target.image),
                   "-processor", target.language_id, "-cspec", target.compiler_spec_id,
                   "-loader", "BinaryLoader", "-loader-baseAddr", f"0x{target.base:x}",
                   "-noanalysis", "-deleteProject", *script]

        code, log, measurement = _run_measured(cmd, timeout)
        measurement.extra["ghidra_install_version"] = ghidra_version(headless)
        if not output.is_file():
            tail = "\n".join(log.strip().splitlines()[-12:])
            raise RuntimeError(f"Ghidra produced no result (exit {code}):\n{tail}")
        raw = json.loads(output.read_text())

    if not raw.get("complete_output"):
        raise RuntimeError("Ghidra result is truncated")
    measurement.walker_seconds = round(raw.pop("timing_analysis_ms", 0.0) / 1000, 4)
    _check_identity(target, raw)
    doc["status"] = "ok"
    doc["engine"] = raw["engine"]
    doc["program"] = raw["program"]
    doc["walker"] = {"name": raw["walker"], "version": raw["walker_version"]}
    if raw.get("functions_created"):
        doc["functions_created"] = raw["functions_created"]
    doc["results"] = [classify(r) for r in raw["results"]]
    return doc, measurement


def _check_identity(target: Target, raw: dict) -> None:
    """The engine must have analyzed the stated image under the stated language and cspec."""

    engine, program = raw["engine"], raw["program"]
    if (program.get("executable_sha256") or "").lower() != target.image_sha256.lower():
        raise RuntimeError(f"Ghidra program sha256 {program.get('executable_sha256')} is not the target image")
    if engine["language_id"] != target.language_id:
        raise RuntimeError(f"Ghidra language {engine['language_id']} is not the target's {target.language_id}")
    if engine["compiler_spec_id"] != target.compiler_spec_id:
        raise RuntimeError(f"Ghidra compiler spec {engine['compiler_spec_id']} is not the target's {target.compiler_spec_id}")


def _engine_unavailable(origin: Origin) -> dict:
    return {
        "origin_address": f"0x{origin.address:08x}",
        "verdict": UNSUPPORTED,
        "complete": False,
        "escape_kinds": [],
        "incomplete": [],
        "unsupported": {"code": "ENGINE_UNAVAILABLE", "detail": "Ghidra's headless analyzer was not found"},
    }


def classify(r: dict) -> dict:
    """APTrace verdict policy over one walker result (see module docstring)."""

    out = dict(r)
    if r.get("status") != "analyzed":
        out["verdict"] = UNSUPPORTED
        out["complete"] = False
        out["escape_kinds"] = []
        out["unsupported"] = {"code": r.get("unsupported_code"), "detail": r.get("unsupported_detail")}
        for k in ("unsupported_code", "unsupported_detail"):
            out.pop(k, None)
        return out

    unknown = sorted({u["kind"] for u in r["uses"]} - set(ESCAPE_KINDS) - LOCAL_KINDS)
    if unknown:
        raise RuntimeError(f"walker reported unclassified use kinds {unknown}")
    escapes = sorted({ESCAPE_KINDS[u["kind"]] for u in r["uses"] if u["kind"] in ESCAPE_KINDS})
    complete = not r["incomplete"]
    out["escape_kinds"] = escapes
    out["complete"] = complete
    out["verdict"] = ESCAPE if escapes else (NO_ESCAPE if complete else INCOMPLETE)

    precision = []
    stores = [u for u in r["uses"] if u["kind"] == "STORE"]
    if stores:
        regions = sorted({(u.get("store_target") or {}).get("region", "unknown") for u in stores})
        precision.append({
            "code": "MEMORY_FLOW_NOT_FOLLOWED",
            "detail": f"the value is stored to memory ({', '.join(regions)}); later reloads and uses through memory are "
                      "not tracked, so MEMORY_ESCAPE is a sound over-approximation"
                      + (" (a stack-slot store is usually a spill)" if "stack" in regions else ""),
        })
    if any(u["kind"] == "ARGUMENT" for u in r["uses"]):
        precision.append({
            "code": "ARGUMENT_BY_STORAGE",
            "detail": "ARGUMENT means the value may be in argument storage of the default calling convention at a "
                      "call or tail transfer; whether the callee reads it is not analyzed",
        })
    out["precision"] = precision
    return out


def _parse_function(text: str) -> FunctionSpec:
    entry, _, ranges = text.partition(":")
    body = []
    for part in filter(None, ranges.split(",")):
        lo, hi = part.split("-")
        body.append((int(lo, 0), int(hi, 0)))
    return FunctionSpec(int(entry, 0), tuple(body))


def _parse_origin(text: str) -> Origin:
    addr, _, reg = text.partition(":")
    return Origin(int(addr, 0), reg or None)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("mode", choices=("import", "project"))
    p.add_argument("image", type=Path)
    p.add_argument("--sha256", required=True)
    p.add_argument("--language", required=True)
    p.add_argument("--cspec", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--function", action="append", default=[])
    p.add_argument("--disassemble", action="append", default=[])
    p.add_argument("--project-dir", type=Path)
    p.add_argument("--project-name")
    p.add_argument("--program")
    p.add_argument("--project-identity")
    p.add_argument("--origin", action="append", required=True)
    p.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    p.add_argument("--scratch", type=Path)
    a = p.parse_args(argv)

    project = None
    if a.mode == "project":
        if not (a.project_dir and a.project_name and a.program):
            p.error("project mode needs --project-dir, --project-name and --program")
        project = GhidraProject(a.project_dir, a.project_name, a.program, a.project_identity)
    target = Target(a.image, a.sha256, a.language, a.cspec, int(a.base, 0), project,
                    tuple(_parse_function(f) for f in a.function), tuple(int(x, 0) for x in a.disassemble))
    try:
        doc, m = run_forward_use(target, [_parse_origin(o) for o in a.origin], max_steps=a.max_steps, scratch_root=a.scratch)
    except ForwardUseError as e:
        print(json.dumps({"status": "invalid_request", "error": str(e)}))
        return 2
    print(json.dumps({"result": doc, "measurement": m.__dict__}, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
