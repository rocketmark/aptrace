"""
Pointer-derived (resolved_indirect) graph edges: statically initialized RAM
function pointers feed the census graph as a distinct edge kind with
provenance, never as direct calls, and never close other frontiers.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from aptrace_agent.census_graph import CensusGraph, PathStatus


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA = REPO_ROOT / "tools" / "census" / "schema.sql"
SHA = "cd" * 32

# 1: IRQ dispatcher (bx through RAM slot at 0x1004), 2: callback body,
# 3: helper below the body, 4: another dispatcher whose slot has a WEAK
# (disagreeing) resolution, 5: its candidate.
FUNCTIONS = {1: 0x1000, 2: 0x2000, 3: 0x3000, 4: 0x4000, 5: 0x5000}


def _db(tmp_path: Path) -> Path:
    db = tmp_path / "census.sqlite3"
    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA.read_text())
    conn.execute(
        "INSERT INTO firmware (id, key, path, sha256, flash_base, size_bytes, ram_base, ram_size, mmio_base, "
        "mmio_size, built_at) VALUES (1,'fw','x',?,0x1000,0x8000,0x20000000,0x1000,0x40000000,0x1000,'now')",
        (SHA,),
    )
    for fid, entry in FUNCTIONS.items():
        conn.execute(
            "INSERT INTO functions (id, firmware_id, entry, name, size, thunk, external, source) VALUES (?,1,?,?,0x40,0,0,'t')",
            (fid, entry, f"FUN_{entry:08x}"),
        )
        conn.execute(
            "INSERT INTO basic_blocks (firmware_id, start_addr, end_addr, function_id, source) VALUES (1,?,?,?,'t')",
            (entry, entry + 0x3F, fid),
        )
    conn.execute(
        "INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, to_function_id, source) "
        "VALUES (1,0x2010,0x3000,'call',1,2,3,'ghidra-basicblockmodel')"
    )
    for site, fid, classification in ((0x1004, 1, "RESOLVED_RAM_FUNCTION_POINTER"),
                                      (0x4004, 4, "RESOLVED_RAM_FUNCTION_POINTER"),
                                      (0x2020, 2, "UNRESOLVED")):
        conn.execute(
            "INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, source) "
            "VALUES (1,?,0,'computed-jump-unresolved',0,?,'ghidra-instrscan')",
            (site, fid),
        )
        conn.execute(
            "INSERT INTO indirect_edge_resolutions (firmware_id, from_addr, from_function_id, instr_mnemonic, "
            "instr_shape, classification, source) VALUES (1,?,?,'bx','reg-indirect',?,'t')",
            (site, fid, classification),
        )
    for site, fid, target, cand, confidence in ((0x1004, 1, 0x2000, 2, "STRONG"), (0x4004, 4, 0x5000, 5, "WEAK")):
        conn.execute(
            "INSERT INTO indirect_edge_candidates (firmware_id, from_addr, candidate_addr, candidate_function_id, "
            "confidence, source) VALUES (1,?,?,?,?,'ram-fnptr-constant-store')",
            (site, target, cand, confidence),
        )
        conn.execute(
            "INSERT INTO resolved_function_pointers (firmware_id, consumer_site, consumer_function_id, slot_addr, "
            "store_addr, writer_function_id, derivation, callsite_addr, arg_reg, value_kind, raw_value, thumb_bit, "
            "canonical_target, terminal_target, confidence, source) "
            "VALUES (1,?,?,0x20000010,0x3008,3,'callsite-argument',0x3002,'r0','constant',?,1,?,?,?,"
            "'ram-fnptr-constant-store')",
            (site, fid, target | 1, target, target + 0x10, confidence),
        )
    conn.commit()
    conn.close()
    return db


def test_pointer_edge_is_distinct_with_provenance(tmp_path):
    graph = CensusGraph(firmware_key="fw", db_path=_db(tmp_path), expected_sha256=SHA)

    # The STRONG pointer edge connects the dispatcher to the body and below.
    assert graph.downstream(["FUN_00001000"]) == {"FUN_00001000": 0, "FUN_00002000": 1, "FUN_00003000": 2}

    result = graph.common_paths(["FUN_00001000"], ["FUN_00003000"], left_label="IRQ", right_label="helper")
    assert result.status == PathStatus.KNOWN_COMMON_PATH

    [edge] = result.resolved_indirect_edges
    assert edge.edge_kind == "resolved_indirect"
    assert (edge.site, edge.from_function, edge.to_function) == ("0x00001004", "FUN_00001000", "FUN_00002000")
    assert (edge.slot, edge.raw_value, edge.canonical_target) == ("0x20000010", "0x00002001", "0x00002000")
    assert edge.raw_value != edge.canonical_target
    assert (edge.store, edge.writer, edge.callsite, edge.arg_reg) == ("0x00003008", "FUN_00003000", "0x00003002", "r0")
    assert edge.terminal_target == "0x00002010" and edge.confidence == "STRONG"
    assert "resolved_indirect edges (RAM function pointer, not direct calls)" in result.planner_summary


def test_pointer_edge_does_not_close_other_frontiers(tmp_path):
    graph = CensusGraph(firmware_key="fw", db_path=_db(tmp_path), expected_sha256=SHA)

    # The resolved site leaves the frontier; the body's own unresolved call stays.
    assert graph.unresolved_sites("FUN_00001000") == []
    assert graph.unresolved_sites("FUN_00002000") == [("0x00002020", "unresolved reg-indirect")]

    # A WEAK pointer resolution is neither an edge nor removed from the frontier.
    assert graph.downstream(["FUN_00004000"]) == {"FUN_00004000": 0}
    assert graph.resolved_indirect_edges(["FUN_00004000"]) == []
    assert [site for site, _ in graph.unresolved_sites("FUN_00004000")] == ["0x00004004"]

    result = graph.common_paths(["FUN_00004000"], ["FUN_00003000"])
    assert result.status == PathStatus.NO_KNOWN_PATH
    assert "not proof of unreachability" in result.planner_summary


def _real():
    from aptrace_agent.census import performing_rigs_census
    from aptrace_agent.structural_wiring import performing_rigs_graph, performing_rigs_usb_inventory

    census = performing_rigs_census()

    if not census.db_path.is_file() or not census.firmware_image.is_file():
        pytest.skip("case census or firmware image not present")

    graph = performing_rigs_graph(census)

    if graph.function_entry("FUN_0000c5cc") is None:
        pytest.skip("census predates the fnptr-seeded Ghidra build")

    return graph, performing_rigs_usb_inventory(census, graph)


def test_real_usb_inventory_includes_recovered_callback_body():
    graph, usb = _real()
    inventory = usb.inventory()

    assert "FUN_0000c5cc" in inventory.functions
    assert any(u.function == "FUN_0000c5cc" and u.reachability == "DEFINITELY_REACHABLE" for u in inventory.register_users)

    [edge] = inventory.resolved_indirect_edges
    assert (edge.site, edge.from_function, edge.to_function) == ("0x0000cc1a", "FUN_0000cc14", "FUN_0000c724")
    assert (edge.slot, edge.raw_value, edge.canonical_target, edge.terminal_target) == (
        "0x200052e8", "0x0000c725", "0x0000c724", "0x0000c5cc")
    assert (edge.store, edge.callsite, edge.arg_reg) == ("0x0000ccc6", "0x0000bcda", "r0")

    reachable = graph.downstream(["FUN_0000cc14"])
    assert reachable["FUN_0000c724"] == 1 and reachable["FUN_0000c5cc"] == 2
    assert "FUN_0000c5cc" in inventory.irq_reachable
    assert ("0x0000c6d8", "unresolved reg-indirect") in graph.unresolved_sites("FUN_0000c5cc")
    assert "no function labeled a handler" in inventory.planner_summary
    assert len(inventory.planner_summary) < 1800


def test_real_eic_usb_common_path_stays_conservative():
    graph, usb = _real()
    handlers = usb.vector_handlers()
    eic = [f"FUN_{handlers[irq]:08x}" for irq in range(12, 28) if irq in handlers]
    result = graph.common_paths(eic, ["FUN_0000cc14", "FUN_0000ccb6", "FUN_0000ccba", "FUN_0000ccbe"],
                                left_label="EIC", right_label="USB")

    # The recovered USB body widens the explored region but does not
    # manufacture a convergence; absence stays "no known path".
    assert result.status == PathStatus.NO_KNOWN_PATH and not result.common
    assert result.explored_right > 4
    assert "not proof of unreachability" in result.planner_summary
    sites = {u.site for u in result.frontier} | {
        site for name in eic for site, _ in graph.unresolved_sites(name)
    }
    assert "0x0000cb92" in sites
    assert "0x0000cc1a" not in {u.site for u in result.frontier}
    assert [e.site for e in result.resolved_indirect_edges] == ["0x0000cc1a"]
