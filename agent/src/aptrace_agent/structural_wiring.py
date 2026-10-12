"""
Performing Rigs application wiring for the structural research actions.

Every identity is fixed here: the census, the case SVD, the firmware image
and hash, the target MMIO window, the Haskell analysis binary and the
effects cache. The planner can only name functions, analyzed peripherals,
and bounded argument specializations.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

from aptrace_agent.census import (
    PERFORMING_RIGS_CASE,
    CensusReader,
    performing_rigs_svd,
)
from aptrace_agent.census_graph import CensusGraph
from aptrace_agent.function_effects import FunctionEffectsRunner
from aptrace_agent.interface_inventory import UsbInventoryReader


_REPO_ROOT = PERFORMING_RIGS_CASE.parents[1]


def _case_mmio_window() -> tuple[int, int]:
    """The case's census MMIO window (performing_rigs.py CENSUS_MMIO_*)."""

    spec = importlib.util.spec_from_file_location(
        "aptrace_case_performing_rigs",
        PERFORMING_RIGS_CASE / "config" / "performing_rigs.py",
    )

    if spec is None or spec.loader is None:
        raise ImportError("performing_rigs.py")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return int(module.CENSUS_MMIO_BASE, 0), int(module.CENSUS_MMIO_SIZE, 0)


def _analysis_binary() -> Path:
    override = os.environ.get("APTRACE_HASKELL_BIN")

    if override:
        return Path(override)

    candidates = sorted(
        (_REPO_ROOT / "external" / "macaw" / "dist-newstyle" / "build").glob(
            "*/ghc-*/aptrace-*/x/aptrace/build/aptrace/aptrace"
        )
    )
    return candidates[-1] if candidates else Path("/nonexistent/aptrace")


def performing_rigs_graph(census: CensusReader) -> CensusGraph:
    svd = performing_rigs_svd()

    return CensusGraph(
        firmware_key=census.firmware_key,
        db_path=census.db_path,
        expected_sha256=census.expected_sha256,
        irq_label=lambda irq: svd.interrupts.get(irq, (None, None))[0],
    )


def performing_rigs_usb_inventory(census: CensusReader, graph: CensusGraph) -> UsbInventoryReader:
    return UsbInventoryReader(
        census=census,
        graph=graph,
        interrupts=performing_rigs_svd().interrupts,
    )


def performing_rigs_function_effects(
    census: CensusReader,
    graph: CensusGraph,
    usb: UsbInventoryReader,
) -> FunctionEffectsRunner:
    svd = performing_rigs_svd()
    handler_entries = set(usb.vector_handlers().values())

    def entry_allowed(entry: int) -> bool:
        return graph.function_entry(f"FUN_{entry:08x}") is not None or entry in handler_entries

    return FunctionEffectsRunner(
        binary=_analysis_binary(),
        firmware_image=census.firmware_image,
        expected_sha256=census.expected_sha256,
        mmio_window=_case_mmio_window(),
        cache_dir=PERFORMING_RIGS_CASE / "research" / "runs" / "function_effects",
        entry_allowed=entry_allowed,
        resolve_register=svd.resolve,
    )
