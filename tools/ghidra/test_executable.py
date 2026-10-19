"""Native executable policy/query regression tests; pytest in agent/.venv.

Integration uses an independently specified synthetic PE (no vendor firmware)
and isolated temporary projects. Ghidra, not this fixture writer, parses it.
"""
import io
import json
import struct
import sys
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import aptrace_ghidra as ag
from executable import query


def pe_fixture():
    """Minimal PE32 fixture: odd entry, conditional branch, call, import/string."""
    b = bytearray(0x600)
    def w(off, fmt, *values):
        struct.pack_into("<" + fmt, b, off, *values)
    b[:2] = b"MZ"; w(0x3c, "I", 0x80); b[0x80:0x84] = b"PE\0\0"
    w(0x84, "HHIIIHH", 0x14c, 2, 0, 0, 0, 0xe0, 0x102)
    o = 0x98
    w(o, "H", 0x10b)
    for off, value in {4:0x200, 8:0x200, 16:0x1001, 20:0x1000, 24:0x2000,
                      28:0x400000, 32:0x1000, 36:0x200, 56:0x3000,
                      60:0x200, 72:0x100000, 76:0x1000, 80:0x100000,
                      84:0x1000, 92:16, 104:0x2050, 108:40, 192:0x2090, 196:8}.items():
        w(o+off, "I", value)
    w(o+40, "HH", 6, 0); w(o+48, "HH", 6, 0); w(o+68, "H", 3)
    for off, name, va, raw, flags in [(0x178,b".text",0x1000,0x200,0x60000020),
                                    (0x1a0,b".rdata",0x2000,0x400,0x40000040)]:
        w(off, "8sIIIIIIHHI", name, 0x200, va, 0x200, raw, 0, 0, 0, 0, flags)
    code = bytes.fromhex("90 68 00204000 e8 15000000 3d 00400000 7502 40 c3 31c0 c3")
    b[0x200:0x200+len(code)] = code
    b[0x220:0x226] = bytes.fromhex("b8 00400000 c3")
    b[0x240:0x246] = bytes.fromhex("b8 2a000000 c3")
    s = b"Flash offset fixture\0"; b[0x400:0x400+len(s)] = s
    w(0x450, "IIIII", 0x2080, 0, 0, 0x20a0, 0x2090)
    w(0x480, "II", 0x20c0, 0); w(0x490, "II", 0x20c0, 0)
    b[0x4a0:0x4ad] = b"KERNEL32.dll\0"
    b[0x4c0:0x4ce] = b"\0\0ExitProcess\0"  # slice assignment retains PE padding
    return bytes(b)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(ag, "CACHE_ROOT", tmp_path / "cache")
    image = tmp_path / "fixture.exe"; image.write_bytes(pe_fixture())
    monkeypatch.setattr(ag, "EXECUTABLE_REGISTRY", {"fixture": {"path": str(image), "format": "pe32-x86"}})
    return image


def test_native_inventory_validation(isolated):
    good = {"format":"Portable Executable (PE)", "language":"x86:LE:32:default",
            "input_sha256":ag.sha256_of(isolated)}
    ag._validate_executable_inventory("fixture", good)
    for patch in ({"format":"Raw Binary"}, {"language":"x86:LE:64:default"}, {"input_sha256":"0"*64}):
        with pytest.raises(ValueError): ag._validate_executable_inventory("fixture", good | patch)


def test_raw_queries_refused(isolated):
    with pytest.raises(SystemExit): ag.literal("fixture", "0x401001")
    with pytest.raises(SystemExit): ag.dump("fixture", "0x401001")
    with pytest.raises(ValueError): query(ag, "fixture", "search", limit=0)
    with pytest.raises(ValueError): query(ag, "fixture", "search", limit=1001)


def test_native_pe_integration(isolated):
    with redirect_stdout(io.StringIO()): ag.build("fixture")
    inv = query(ag, "fixture", "inventory")["result"]
    assert inv["language"] == "x86:LE:32:default"
    assert "0x00401001" in inv["entry_points"]
    assert query(ag, "fixture", "imports", pattern="ExitProcess")["result"]["rows"]
    rows = query(ag, "fixture", "search", pattern="offset")["result"]["rows"]
    assert rows[0]["value"] == "Flash offset fixture"
    assert query(ag, "fixture", "xrefs", address=rows[0]["address"])["result"]["rows"]
    f = query(ag, "fixture", "function", address="0x401001")["result"]
    assert f["entry"] == "0x00401001"  # no Thumb-bit stripping
    assert f["decompile_completed"] and f["instructions"]
    assert query(ag, "fixture", "cfg", address="0x401001")["result"]["edges"]
    window = query(ag, "fixture", "data", address="0x402000", limit=5)["result"]
    assert bytes(window["bytes"]) == b"Flash"
    before = query(ag, "fixture", "function", address="0x401040")["result"]["status"]
    discovered = query(ag, "fixture", "entry-function", address="0x401040")["result"]
    assert discovered["entry"] == "0x00401040" and discovered["instructions"]
    assert query(ag, "fixture", "function", address="0x401040")["result"]["status"] == before
    assert query(ag, "fixture", "function", address="0x402000")["result"]["status"] == "function_not_attributed"
    limited = query(ag, "fixture", "functions", limit=1)["result"]
    assert len(limited["rows"]) == 1 and limited["truncated"]
    assert query(ag, "fixture", "search", pattern="not-present-unique")["result"]["matches_total"] == 0
    # Exports are identity-bound, so a tampered artifact cannot serve evidence.
    export = ag.cache_dir("fixture") / "static_export.json"
    export.write_text(export.read_text() + "\n")
    assert ag.cache_status("fixture")[0] == "stale"
    with pytest.raises(SystemExit): query(ag, "fixture", "inventory")


def test_mixed_address_spaces(isolated, monkeypatch):
    monkeypatch.setattr(ag, "ensure_fresh", lambda key: None)
    monkeypatch.setattr(ag, "expected_identity", lambda key: {})
    cdir = ag.cache_dir("fixture"); cdir.mkdir(parents=True)
    (cdir / "executable.json").write_text(json.dumps({
        "format":"Portable Executable (PE)", "language":"x86:LE:32:default",
        "input_sha256":ag.sha256_of(isolated)}))
    rows = [{"from":"0x401001", "to":"0xStack[-0x60]"},
            {"from":"0x401002", "to":"0x00402000"},
            {"from":"0x401003", "to":"0xregister:00000000"}]
    (cdir / "static_export.json").write_text(json.dumps({"dataReferences":rows}))
    result = query(ag, "fixture", "xrefs", address="0x402000")["result"]
    assert result["rows"] == [rows[1]]


def test_routing_and_ambiguity(isolated):
    from aptrace_agent.executable_research import select_target
    assert select_target("Investigate fixture.exe erase", backend=ag) == "fixture"
    assert select_target("Cortex-M FUN_00001234", backend=ag) is None
    with pytest.raises(ValueError): select_target("unknown.exe erase", backend=ag)
    with pytest.raises(ValueError): select_target("query", "unknown", backend=ag)
    ag.EXECUTABLE_REGISTRY["other"] = {"path":"other.exe"}
    with pytest.raises(ValueError): select_target("fixture.exe and other.exe", backend=ag)


def test_malformed_native_import(isolated):
    isolated.write_bytes(b"Not an executable\n")
    with pytest.raises(ValueError, match="no validated executable exports"):
        with redirect_stdout(io.StringIO()): ag.build("fixture")
    assert not (ag.cache_dir("fixture") / "meta.json").exists()


def test_cli_routes_before_arm(monkeypatch, capsys, tmp_path):
    from aptrace_agent import cli, executable_research as host
    monkeypatch.setattr(host, "select_target", lambda question, explicit=None: "fixture")
    payload = {"routing":"native-executable-static", "evidence":[], "claims":[], "stop_reason":"bounded_discovery_finished"}
    monkeypatch.setattr(host, "research", lambda *a, **kw: payload)
    def no_arm(*a, **kw): pytest.fail("host objective reached ARM controller")
    monkeypatch.setattr(cli, "run_autonomous_investigation", no_arm)
    monkeypatch.setattr(cli, "run_investigation", no_arm)
    for command in (["research", "fixture.exe", "--json", "--output", str(tmp_path/'result.json')],
                    ["investigate", "fixture.exe", "--json"]):
        monkeypatch.setattr(sys, "argv", ["aptrace-agent", *command]); cli.main()
        assert json.loads(capsys.readouterr().out) == payload
    monkeypatch.setattr(sys, "argv", ["aptrace-agent", "research", "fixture.exe", "--ledger", str(tmp_path/'ledger')])
    with pytest.raises(SystemExit): cli.main()
    assert not (tmp_path/'ledger').exists()
