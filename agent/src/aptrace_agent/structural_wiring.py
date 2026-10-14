"""
Performing Rigs application wiring for the structural research actions.

Every identity is fixed here: the census, the case SVD, the firmware image
and hash, the target MMIO window, the Haskell analysis binary and the
effects cache. The planner can only name functions, analyzed peripherals,
and bounded argument specializations.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

from aptrace_agent.census import (
    PERFORMING_RIGS_CASE,
    CensusReader,
    performing_rigs_svd,
)
from aptrace_agent.census_graph import CensusGraph
from aptrace_agent.call_observation import ObservedCallArgumentsRunner
from aptrace_agent.function_effects import FunctionEffectsRunner
from aptrace_agent.interface_inventory import UsbInventoryReader


_REPO_ROOT = PERFORMING_RIGS_CASE.parents[1]


def _case_geometry():
    spec = importlib.util.spec_from_file_location(
        "aptrace_case_performing_rigs",
        PERFORMING_RIGS_CASE / "config" / "performing_rigs.py",
    )

    if spec is None or spec.loader is None:
        raise ImportError("performing_rigs.py")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _case_mmio_window() -> tuple[int, int]:
    """The case's census MMIO window (performing_rigs.py CENSUS_MMIO_*)."""

    module = _case_geometry()
    return int(module.CENSUS_MMIO_BASE, 0), int(module.CENSUS_MMIO_SIZE, 0)


def _case_ram_window() -> tuple[int, int]:
    """The case's census RAM window (performing_rigs.py CENSUS_RAM_*)."""

    module = _case_geometry()
    return int(module.CENSUS_RAM_BASE, 0), int(module.CENSUS_RAM_SIZE, 0)


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



REPO_ROOT = PERFORMING_RIGS_CASE.parents[1]
UNICORN_PYTHON = REPO_ROOT / "tools" / "unicorn" / ".venv" / "bin" / "python3"
OBSERVE_CALLS_SCRIPT = PERFORMING_RIGS_CASE / "scripts" / "observe_call_arguments.py"
OBSERVATION_SCENARIOS = PERFORMING_RIGS_CASE / "config" / "observation_scenarios.json"
# Files whose content defines an observed_call_arguments result beyond the
# firmware and census: the scenario registry and the scenarios it names (boot
# recipe, virtual-link corpus), the case observation script, and the concrete
# harness and summarizer.
OBSERVATION_INPUTS = {
    "boot_recipe": PERFORMING_RIGS_CASE / "config" / "boot_recipes.py",
    "unicorn_harness": REPO_ROOT / "tools" / "unicorn" / "concrete.py",
    "call_observation": REPO_ROOT / "tools" / "unicorn" / "call_observation.py",
    "observation_scenarios": OBSERVATION_SCENARIOS,
    "observation_script": OBSERVE_CALLS_SCRIPT,
    "scenario_corpus": PERFORMING_RIGS_CASE / "scripts" / "virtual_link.py",
}


def performing_rigs_observation_scenarios() -> dict[str, dict]:
    """The case's registered observation scenarios (id -> registry entry)."""

    return json.loads(OBSERVATION_SCENARIOS.read_text())["scenarios"]


def performing_rigs_observed_calls(
    census: CensusReader,
    graph: CensusGraph,
    usb: UsbInventoryReader,
    ghidra,
) -> ObservedCallArgumentsRunner:
    """Caller-grounded argument observation over the case boot recipe."""

    svd = performing_rigs_svd()
    handler_entries = set(usb.vector_handlers().values())

    def entry_allowed(entry: int) -> bool:
        return graph.function_entry(f"FUN_{entry:08x}") is not None or entry in handler_entries

    def facts(name: str):
        try:
            return ghidra.function_facts(name, max_edges=10_000)
        except KeyError:
            return None

    def static_call_sites(name: str) -> list[tuple[str, str | None]]:
        record = facts(name)
        return [(f"0x{int(c.address, 16):08x}", c.function) for c in record.callers] if record else []

    def function_extent(name: str) -> tuple[int, int] | None:
        record = facts(name)

        if record is None or not record.size:
            return None

        start = int(record.entry, 16)
        return start, start + int(record.size)

    return ObservedCallArgumentsRunner(
        python=UNICORN_PYTHON,
        script=OBSERVE_CALLS_SCRIPT,
        firmware_key=census.firmware_key,
        firmware_image=census.firmware_image,
        expected_sha256=census.expected_sha256,
        entry_allowed=entry_allowed,
        static_call_sites=static_call_sites,
        function_extent=function_extent,
        resolve_register=svd.resolve,
        scenarios=performing_rigs_observation_scenarios(),
        ram=_case_ram_window(),
    )

MACAW_CENSUS_DIR = PERFORMING_RIGS_CASE / "research" / "runs" / "macaw"
GHIDRA_SEEDS_DIR = PERFORMING_RIGS_CASE / "research" / "runs" / "ghidra_seeds"


def macaw_census_path(firmware_key: str) -> Path:
    """`aptrace macaw-census` output for one image (regenerable, untracked)."""

    return MACAW_CENSUS_DIR / f"{firmware_key}.macaw-census.json"


def ghidra_seeds_path(firmware_key: str) -> Path:
    return GHIDRA_SEEDS_DIR / f"{firmware_key}.json"


def performing_rigs_source_agreement(census: CensusReader, usb: UsbInventoryReader):
    """
    Structural source agreement over the census database, the seeded Ghidra
    project export the census is built from, and the Macaw census. Returns
    a callable taking a bounded list of code addresses.
    """

    import json

    from aptrace_agent.ghidra_index import ghidra_cache_identity, ghidra_cache_paths
    from aptrace_agent.ledger.hashing import file_sha256
    from aptrace_agent.source_agreement import (
        CensusDbSource,
        GhidraExportSource,
        MacawCensusSource,
        source_agreement,
    )

    def run(addresses):
        meta = ghidra_cache_identity(census.firmware_key)
        paths = ghidra_cache_paths(census.firmware_key)
        seeds = {entry: "vector-table" for entry in usb.vector_handlers().values()}
        seed_doc = ghidra_seeds_path(census.firmware_key)

        if seed_doc.is_file():
            for seed in json.loads(seed_doc.read_text()).get("seeds", []):
                seeds[int(seed["addr"], 16)] = f"derived-seed:{seed.get('role', 'seed')}"

        ghidra_version = file_sha256(paths["static_export"])
        seeds_note = f"seeded Ghidra project (cache seeds sha256 {str(meta.get('derived_seeds_sha256'))[:16]})"
        sources = [
            CensusDbSource(
                census.db_path,
                census.firmware_key,
                version=file_sha256(census.db_path),
                derived_from=f"ghidra:{(ghidra_version or '')[:16]}",
                seeds=seeds,
            ),
            GhidraExportSource(
                paths["static_export"],
                census_export=paths["census_export"],
                version=ghidra_version,
                seeds=seeds,
                note=seeds_note,
            ),
            MacawCensusSource(
                macaw_census_path(census.firmware_key),
                version=file_sha256(macaw_census_path(census.firmware_key)),
                expected_size=census.firmware_image.stat().st_size if census.firmware_image.is_file() else None,
            ),
        ]
        return source_agreement(sources, addresses)

    return run
