import hashlib
import sqlite3
import struct
from pathlib import Path

import pytest

from aptrace_agent.census import (
    MAX_LIMIT,
    CensusReader,
    PeripheralRange,
)
from aptrace_agent.research import (
    LeadDeriver,
    LeadFollower,
    LeadRegistry,
    ResearchSession,
)
from aptrace_agent.schemas import EvidenceObservation


SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "tools"
    / "census"
    / "schema.sql"
)

FLASH_BASE = 0x4000

CATALOG = {
    "SERCOM2": PeripheralRange(0x41012000, 0x400),
    "TC0": PeripheralRange(0x40003800, 0x400),
    "SERCOM5": PeripheralRange(0x43000400, 0x400),
    "EIC": PeripheralRange(0x40002800, 0x400),
}


def _image() -> bytes:
    data = bytearray(0x100)
    struct.pack_into("<I", data, 0x10, 0x41012000)  # SERCOM2 base, referenced
    struct.pack_into("<I", data, 0x14, 0x41012028)  # SERCOM2+0x28, unreferenced
    struct.pack_into("<I", data, 0x18, 0x40003800)  # TC0 base
    struct.pack_into("<I", data, 0x1C, 0x40002804)  # EIC, data table only
    return bytes(data)


def _build_db(
    path: Path,
    image: bytes,
    *,
    reduced: bool,
) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA.read_text())

    conn.execute(
        "INSERT INTO firmware (id, key, path, sha256, flash_base, "
        "size_bytes, ram_base, ram_size, mmio_base, mmio_size, "
        "ghidra_version, built_at) VALUES "
        "(1, 'fw', 'x.bin', ?, ?, ?, 0, 0, 0, 0, '12.1', '2026-01-01T00:00:00')",
        (hashlib.sha256(image).hexdigest(), FLASH_BASE, len(image)),
    )

    conn.executemany(
        "INSERT INTO functions (id, firmware_id, entry, name, size, thunk, "
        "external, source) VALUES (?, 1, ?, ?, ?, 0, 0, 'ghidra')",
        [
            (1, 0x4200, "tc_init__LABEL", 0x40),
            (2, 0x4100, "FUN_00004100", 0x40),
            (3, 0x4300, "FUN_00004300", 0x20),
        ],
    )

    conn.execute(
        "INSERT INTO basic_blocks (firmware_id, start_addr, end_addr, "
        "function_id, source) VALUES (1, 0x4500, 0x450f, NULL, 'ghidra')"
    )

    conn.executemany(
        "INSERT INTO mmio_accesses (firmware_id, from_addr, "
        "from_function_id, to_addr, width, direction, peripheral, "
        "register_name, resolution_note, source) VALUES "
        "(1, ?, ?, ?, 4, ?, ?, ?, NULL, 'ghidra-refmgr')",
        [
            (0x4210, 1, 0x40003800, "WRITE", "TC0", "COUNT16.CTRLA"),
            (0x4110, 2, 0x4000380a, "READ", "TC0", "COUNT16.INTFLAG"),
            (0x4104, 2, 0x40003800, "WRITE", "TC0", "COUNT16.CTRLA"),
            (0x4508, None, 0x40003800, "READ", "TC0", "COUNT16.CTRLA"),
        ],
    )

    conn.executemany(
        "INSERT INTO literal_refs (firmware_id, from_addr, "
        "from_function_id, to_addr, to_label, ref_type, source) VALUES "
        "(1, ?, ?, ?, NULL, 'READ', 'ghidra-refmgr')",
        [
            (0x4302, 3, FLASH_BASE + 0x10),
            (0x4502, None, FLASH_BASE + 0x10),
        ],
    )

    conn.executemany(
        "INSERT INTO scan_warnings (firmware_id, category, addr, detail, "
        "source) VALUES (1, ?, ?, ?, 'capstone')",
        [
            ("inside-function", 0x4108, "near TC0 access"),
            ("inside-block", 0x4504, "near unattributed site"),
            ("elsewhere", 0x9000, "unrelated"),
        ],
    )

    if reduced:
        conn.executemany(
            "INSERT INTO function_reachability (firmware_id, function_id, "
            "status, nearest_root_addr, nearest_root_kind, hops, source) "
            "VALUES (1, ?, ?, 0x4001, 'reset-vector', ?, 'reachability')",
            [
                (1, "DEFINITELY_REACHABLE", 2),
                (2, "DEFINITELY_REACHABLE", 1),
                (3, "NO_KNOWN_PATH", None),
            ],
        )
        conn.execute(
            "INSERT INTO components (id, firmware_id, component_index, "
            "n_functions, source) VALUES (7, 1, 3, 2, 'components')"
        )
        conn.executemany(
            "INSERT INTO component_members (firmware_id, component_id, "
            "function_id) VALUES (1, 7, ?)",
            [(1,), (2,)],
        )
        conn.execute(
            "INSERT INTO hardware_snapshot_runs (firmware_id, boot_method, "
            "completed_init, ran_at) VALUES (1, 'test', 1, '2026-01-02')"
        )

    conn.commit()
    conn.close()


def _reader(
    tmp_path: Path,
    *,
    reduced: bool = True,
    write_image: bool = True,
    build_db: bool = True,
    expected_sha: str | None = None,
    key: str = "fw",
) -> CensusReader:
    image = _image()
    image_path = tmp_path / "fw.bin"
    db_path = tmp_path / "census.sqlite3"

    if write_image:
        image_path.write_bytes(image)

    if build_db:
        _build_db(db_path, image, reduced=reduced)

    return CensusReader(
        firmware_key=key,
        db_path=db_path,
        firmware_image=image_path,
        expected_sha256=(
            expected_sha or hashlib.sha256(image).hexdigest()
        ),
        peripherals=CATALOG,
        resolve_register=lambda value: (
            "SERCOM2.SPIM.DATA/USART_INT.DATA"
            if value == 0x41012028
            else None
        ),
        catalog_identity="test-catalog",
    )


def test_valid_mmio_peripheral_query(tmp_path):
    usage = _reader(tmp_path).peripheral_usage("tc0")

    assert usage.status == "ok"
    assert usage.peripheral == "TC0"
    assert usage.total_mmio_sites == 4
    assert [item.function for item in usage.functions] == [
        "FUN_00004100",
        "FUN_00004200",
    ]
    assert usage.functions[1].census_name == "tc_init__LABEL"

    first = usage.functions[0]
    assert [site.site for site in first.mmio_sites] == [
        "0x00004104",
        "0x00004110",
    ]
    assert first.mmio_sites[0].register_name == "COUNT16.CTRLA"
    assert first.mmio_sites[0].direction == "WRITE"
    assert first.mmio_sites[0].source == "ghidra-refmgr"

    assert [site.site for site in usage.unattributed_sites] == [
        "0x00004508",
    ]
    assert usage.unattributed_sites[0].basic_block == "0x00004500"
    assert usage.address_constants[0].location == "0x00004018"
    assert usage.address_constants[0].referenced is False

    assert [w.category for w in usage.warnings] == [
        "inside-function",
        "inside-block",
    ]
    assert usage.warnings_total == 2
    assert "svd" in usage.provenance.sources


def test_base_register_peripheral_found_through_address_constants(tmp_path):
    usage = _reader(tmp_path).peripheral_usage("SERCOM2")

    assert usage.status == "ok"
    assert usage.total_mmio_sites == 0
    assert usage.total_address_constants == 2
    assert [c.location for c in usage.address_constants] == [
        "0x00004010",
        "0x00004014",
    ]
    assert usage.address_constants[1].register_name == (
        "SERCOM2.SPIM.DATA/USART_INT.DATA"
    )

    (function,) = usage.functions
    assert function.function == "FUN_00004300"
    assert function.constant_loads[0].site == "0x00004302"
    assert function.constant_loads[0].value == "0x41012000"

    (site,) = usage.unattributed_sites
    assert site.kind == "constant_load"
    assert site.basic_block == "0x00004500"
    assert "SERCOM2 base" in site.detail
    assert usage.provenance.flash_word_scan == "sha256-verified"


@pytest.mark.parametrize(
    "name",
    [
        "SPI0",
        "../census.sqlite3",
        "TC0; DROP TABLE functions",
        "SELECT * FROM functions",
        "",
        None,
    ],
)
def test_unknown_or_hostile_peripheral_is_structured_failure(
    tmp_path,
    name,
):
    reader = _reader(tmp_path)
    before = (tmp_path / "census.sqlite3").read_bytes()

    usage = reader.peripheral_usage(name)

    assert usage.status == "unknown_peripheral"
    assert usage.functions == []
    assert (tmp_path / "census.sqlite3").read_bytes() == before


def test_result_limit_is_clamped(tmp_path):
    reader = _reader(tmp_path)

    one = reader.peripheral_usage("TC0", limit=1)
    assert len(one.functions) == 1
    assert one.functions_truncated is True
    assert one.total_functions == 2
    assert len(one.unattributed_sites) == 1
    assert len(one.address_constants) == 1

    huge = reader.peripheral_usage("TC0", limit=10_000)
    assert huge.provenance.limit == MAX_LIMIT

    assert reader.peripheral_usage("TC0", limit=0).provenance.limit == 1
    assert reader.peripheral_usage("TC0", limit="x").provenance.limit == 25


def test_missing_census_database(tmp_path):
    usage = _reader(
        tmp_path,
        build_db=False,
    ).peripheral_usage("TC0")

    assert usage.status == "census_missing"
    assert not (tmp_path / "census.sqlite3").exists()


def test_firmware_absent_from_census(tmp_path):
    usage = _reader(tmp_path, key="other").peripheral_usage("TC0")

    assert usage.status == "census_missing"


def test_census_built_from_different_image_is_stale(tmp_path):
    usage = _reader(
        tmp_path,
        expected_sha="0" * 64,
    ).peripheral_usage("TC0")

    assert usage.status == "census_stale"
    assert usage.functions == []


def test_base_census_without_reduction_degrades(tmp_path):
    usage = _reader(tmp_path, reduced=False).peripheral_usage("TC0")

    assert usage.status == "ok"
    assert usage.provenance.reduction_status == "absent"
    assert all(f.reachability is None for f in usage.functions)
    assert all(f.component is None for f in usage.functions)
    assert "census-reachability" not in usage.provenance.sources


def test_reduced_census_adds_reachability_and_components(tmp_path):
    usage = _reader(tmp_path).peripheral_usage("TC0")

    assert usage.provenance.reduction_status == "present"
    assert usage.provenance.reduced_at == "2026-01-02"

    first = usage.functions[0]
    assert first.reachability.status == "DEFINITELY_REACHABLE"
    assert first.reachability.hops == 1
    assert first.reachability.nearest_root_kind == "reset-vector"
    assert first.component.index == 3
    assert first.component.n_functions == 2


def test_missing_image_still_reports_mmio(tmp_path):
    usage = _reader(tmp_path, write_image=False).peripheral_usage("TC0")

    assert usage.status == "ok"
    assert usage.total_mmio_sites == 4
    assert usage.total_address_constants == 0
    assert usage.provenance.flash_word_scan == "firmware_image_unavailable"


def test_no_matching_accesses(tmp_path):
    usage = _reader(tmp_path).peripheral_usage("SERCOM5")

    assert usage.status == "no_matching_accesses"
    assert usage.functions == []


def test_data_only_addresses_are_not_code_references(tmp_path):
    usage = _reader(tmp_path).peripheral_usage("EIC")

    assert usage.status == "no_code_references"
    assert usage.total_address_constants == 1
    assert usage.unreferenced_address_constants == 1
    assert usage.functions == []


def test_queries_are_deterministic_and_read_only(tmp_path):
    reader = _reader(tmp_path)
    db = tmp_path / "census.sqlite3"
    before = db.read_bytes()

    first = reader.peripheral_usage("TC0").model_dump(mode="json")
    second = reader.peripheral_usage("TC0").model_dump(mode="json")

    assert first == second
    assert db.read_bytes() == before

    conn = reader._connect()
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM functions")
    conn.close()


def test_available_peripherals(tmp_path):
    assert _reader(tmp_path).available_peripherals() == [
        "EIC",
        "SERCOM2",
        "TC0",
    ]
    missing = tmp_path / "missing"
    missing.mkdir()
    assert _reader(
        missing,
        build_db=False,
        write_image=False,
    ).available_peripherals() == []


class _Executor:
    def __init__(self, reader):
        self.reader = reader

    def execute_operation(self, tool, arguments, *, evidence_id):
        assert tool == "census_peripheral_usage"
        return EvidenceObservation(
            id=evidence_id,
            tool=tool,
            arguments=dict(arguments),
            result=self.reader.peripheral_usage(
                arguments["peripheral"],
                limit=arguments.get("limit", 25),
            ).model_dump(mode="json"),
        )


class _Facts:
    def function_facts(self, function):
        if function == "FUN_00004200":
            raise KeyError(f"Function not found: {function}")
        return {"name": function}


class _Callsites:
    def context(self, *args, **kwargs):
        raise AssertionError("census must not expand callsites")


def _session(reader):
    registry = LeadRegistry()

    return ResearchSession(
        objective="peripheral usage",
        registry=registry,
        follower=LeadFollower(
            registry=registry,
            executor=_Executor(reader),
        ),
        deriver=LeadDeriver(
            registry=registry,
            callsite_reader=_Callsites(),
            function_facts_reader=_Facts(),
        ),
    )


def test_provenance_survives_into_research_layer(tmp_path):
    session = _session(_reader(tmp_path))

    lead = session.registry.register(
        kind="census",
        description="Analyze TC0",
        tool="census_peripheral_usage",
        arguments={"peripheral": "TC0", "limit": 25},
    )
    session.state.add_lead(lead)
    observation = session.follow_lead(lead.id)

    stored = session.ledger.get(observation.id)
    provenance = stored.result["provenance"]
    assert provenance["analysis"] == "census_peripheral_usage"
    assert provenance["firmware_key"] == "fw"
    assert provenance["census_firmware_sha256"] == (
        provenance["expected_firmware_sha256"]
    )
    assert provenance["reduction_status"] == "present"
    assert provenance["peripheral_catalog"] == "test-catalog"

    statements = [claim.statement for claim in session.state.claims]
    assert all(
        claim.grade == "PROVEN"
        and claim.evidence_ids == [observation.id]
        for claim in session.state.claims
    )
    assert statements[0].startswith("Census structural usage of TC0")
    assert any(
        s.startswith("FUN_00004100 has 2 statically resolved TC0")
        for s in statements
    )
    assert any("0x00004508" in s for s in statements)

    function_leads = [
        lead
        for lead in session.state.open_leads()
        if lead.kind in {"function", "function-disassembly"}
    ]
    assert {
        session.registry.resolve(lead.id).arguments["function"]
        for lead in function_leads
    } == {"FUN_00004100"}
    assert all(
        lead.source_evidence_ids == [observation.id]
        for lead in function_leads
    )
    assert not any(
        lead.kind == "callsite" for lead in session.state.leads
    )

    kinds = {issue.kind for issue in session.derivation_issues}
    assert kinds == {
        "invalid-census-function",
        "unattributed-census-site",
    }


def test_negative_result_becomes_bounded_claim(tmp_path):
    session = _session(_reader(tmp_path))

    lead = session.registry.register(
        kind="census",
        description="Analyze SERCOM5",
        tool="census_peripheral_usage",
        arguments={"peripheral": "SERCOM5", "limit": 25},
    )
    session.state.add_lead(lead)
    session.follow_lead(lead.id)

    (claim,) = session.state.claims
    assert "no constant-address MMIO site" in claim.statement
    assert "not excluded" in claim.statement
    assert session.state.open_leads() == []


def test_data_only_result_becomes_bounded_claim(tmp_path):
    session = _session(_reader(tmp_path))

    lead = session.registry.register(
        kind="census",
        description="Analyze EIC",
        tool="census_peripheral_usage",
        arguments={"peripheral": "EIC", "limit": 25},
    )
    session.state.add_lead(lead)
    session.follow_lead(lead.id)

    (claim,) = session.state.claims
    assert claim.statement.startswith(
        "EIC addresses appear only in 1 aligned flash data word(s)"
    )
    assert session.state.open_leads() == []


def test_census_failure_produces_no_claims(tmp_path):
    session = _session(_reader(tmp_path, build_db=False))

    lead = session.registry.register(
        kind="census",
        description="Analyze TC0",
        tool="census_peripheral_usage",
        arguments={"peripheral": "TC0", "limit": 25},
    )
    session.state.add_lead(lead)
    observation = session.follow_lead(lead.id)

    assert observation.result["status"] == "census_missing"
    assert session.state.claims == []
