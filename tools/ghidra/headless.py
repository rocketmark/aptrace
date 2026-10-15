"""
Locate Ghidra's headless analyzer and its version.

Shared by the persistent-project backend (aptrace_ghidra.py) and the p-code
operations (pcode_forward_use.py). Imports no case module.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path


def find_headless() -> Path | None:
    """analyzeHeadless on PATH, under $GHIDRA_HOME, or in Homebrew's ghidra; None if absent."""

    found = shutil.which("analyzeHeadless")
    if found:
        return Path(found)
    env_home = os.environ.get("GHIDRA_HOME")
    if env_home and (Path(env_home) / "support" / "analyzeHeadless").exists():
        return Path(env_home) / "support" / "analyzeHeadless"
    try:
        prefix = subprocess.run(["brew", "--prefix", "ghidra"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    candidate = Path(prefix) / "libexec" / "support" / "analyzeHeadless"
    return candidate if candidate.exists() else None


def ghidra_version(headless_path) -> str:
    """
    Best-effort version from the resolved analyzeHeadless path (e.g.
    .../Cellar/ghidra/12.1.3/libexec/support/analyzeHeadless). Homebrew
    exposes it through a version-less symlink, so the real path is resolved
    first. 'unknown' when the path carries no version.
    """

    real = str(Path(headless_path).resolve())
    m = re.search(r"ghidra/([0-9][0-9A-Za-z.\-_]*)/", real)
    return m.group(1) if m else "unknown"
