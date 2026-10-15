"""
Performing Rigs application wiring for the research ledger.

Binds the case identity, ledger location, and the input artifacts whose
hashes identify deterministic evidence: the census database, the Ghidra
export (the seeded persistent-project export the census is built from) and
that project's cache identity, the SVD, the generated Ghidra seed file, and
the Macaw census. Generated artifacts are referenced by content hash only.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path

from aptrace_agent.census import PERFORMING_RIGS_CASE, performing_rigs_svd
from aptrace_agent.ledger.hashing import file_sha256
from aptrace_agent.ledger.models import ExecutionContext
from aptrace_agent.structural_wiring import (
    CALLBACK_PROVENANCE_INPUTS,
    INDIRECT_TARGET_INPUTS,
    OBSERVATION_INPUTS,
    ghidra_seeds_path,
    macaw_census_path,
)


CASE_NAME = "performing-rigs"
_RESEARCH = PERFORMING_RIGS_CASE / "research"

DEFAULT_LEDGER_DIR = _RESEARCH / "ledger"
DEFAULT_REPORT_PATH = _RESEARCH / "generated" / "research-ledger.md"
BENCHMARK_DIR = _RESEARCH / "benchmarks" / "ledger-v0"
REPO_ROOT = PERFORMING_RIGS_CASE.parents[1]
# The Beads work store lives outside the checkout: `bd` writes .gitignore
# files into its working directory, and work state is not research evidence.
DEFAULT_WORK_DIR = Path("~/.aptrace/work") / CASE_NAME


def ledger_dir(override: str | None = None) -> Path:
    return Path(override or os.environ.get("APTRACE_LEDGER_DIR") or DEFAULT_LEDGER_DIR).expanduser()


def work_dir(override: str | None = None) -> Path:
    """Work-store root: holds the Beads store (.beads/) and the item locks."""

    return Path(override or os.environ.get("APTRACE_WORK_DIR") or DEFAULT_WORK_DIR).expanduser()


def context_artifacts(executor) -> dict[str, str]:
    paths = {
        "census_db": executor.census.db_path,
        "ghidra_export": executor.ghidra.artifact,
        "svd": PERFORMING_RIGS_CASE / "config" / "svd" / "ATSAMD51J19A.svd",
        "ghidra_seeds": ghidra_seeds_path(executor.census.firmware_key),
        "macaw_census": macaw_census_path(executor.census.firmware_key),
        **OBSERVATION_INPUTS,
        **INDIRECT_TARGET_INPUTS,
        **CALLBACK_PROVENANCE_INPUTS,
    }
    meta = Path(executor.ghidra.artifact).parent / "meta.json"

    if meta.is_file():
        paths["ghidra_cache_identity"] = meta

    return {name: sha for name, path in paths.items() if (sha := file_sha256(Path(path))) is not None}


def context_provider(executor) -> Callable[[], ExecutionContext]:
    """Current execution context; artifact hashes are recomputed per call."""

    def current() -> ExecutionContext:
        return ExecutionContext(
            case=CASE_NAME,
            firmware_key=executor.census.firmware_key,
            firmware_sha256=executor.census.expected_sha256,
            artifacts=context_artifacts(executor),
        )

    return current


def irq_handler_resolver(executor) -> Callable[[str], list[str]]:
    """Interrupt-vector handlers (image vector table) whose SVD name has a prefix."""

    @lru_cache(maxsize=None)
    def handlers() -> tuple[tuple[str, str], ...]:
        names = performing_rigs_svd().interrupts
        return tuple(
            (str(names[irq][0]), f"FUN_{entry:08x}")
            for irq, entry in sorted(executor.usb.vector_handlers().items())
            if irq in names and names[irq][0]
        )

    def resolve(prefix: str) -> list[str]:
        prefix = prefix.upper()
        return list(dict.fromkeys(fn for name, fn in handlers() if name.upper().startswith(prefix)))

    return resolve


def lead_deriver_factory(executor):
    """The investigator's LeadDeriver wiring, for re-deriving a run's open leads."""

    from aptrace_agent.research import LeadDeriver

    return lambda registry: LeadDeriver(registry=registry, callsite_reader=executor.callsite_reader, function_facts_reader=executor.ghidra)
