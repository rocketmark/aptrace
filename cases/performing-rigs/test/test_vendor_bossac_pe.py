"""Pinned static acceptance case; never executes the Windows process or hardware.
Run with agent/.venv/bin/python -m pytest, after APTrace build vendor_bossac.
These observations are regression anchors, not semantic claim admission.
"""
import sys
import shutil
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'tools' / 'ghidra'))
import aptrace_ghidra as ag
from executable import query


@pytest.fixture(autouse=True)
def isolated_project(tmp_path, monkeypatch):
    ag.ensure_fresh('vendor_bossac')
    shutil.copytree(ag.cache_dir('vendor_bossac'), tmp_path / 'vendor_bossac',
                    ignore=shutil.ignore_patterns('*.lock'))
    monkeypatch.setattr(ag, 'CACHE_ROOT', tmp_path)


def test_vendor_identity_and_virtual_driver_dispatch():
    inventory = query(ag, 'vendor_bossac', 'inventory')
    assert inventory['identity']['input_sha256'] == 'eaebd0b6ef980e464b1a6a5a50eee91f9d6202f51dae7d9f78779d18593121a9'
    assert inventory['result']['language'] == 'x86:LE:32:default'
    vtable = bytes(query(ag, 'vendor_bossac', 'data', address='0x436ae8', limit=112)['result']['bytes'])
    assert int.from_bytes(vtable[0x60:0x64], 'little') == 0x403970
    assert int.from_bytes(vtable[0x68:0x6c], 'little') == 0x403910
    for entry, guard in [('0x403970', 'TEST ESI,0xf'), ('0x403910', 'TEST AL,0xf')]:
        before = ag.expected_identity('vendor_bossac')
        first = query(ag, 'vendor_bossac', 'entry-function', address=entry, limit=500)
        second = query(ag, 'vendor_bossac', 'entry-function', address=entry, limit=500)
        assert first['result_sha256'] == second['result_sha256']
        instructions = [i['text'] for i in first['result']['instructions']]
        assert guard in instructions and 'CALL 0x00403800' in instructions
        assert not first['result']['truncated'] and first['result']['decompile_completed']
        assert ag.expected_identity('vendor_bossac') == before


def test_main_and_offset_parser_anchors():
    main = query(ag, 'vendor_bossac', 'function', address='0x42ae60', limit=1000)['result']
    instructions = [i['text'] for i in main['instructions']]
    for address in ('0x00407470', '0x004074c0', '0x004079d0'):
        assert 'CALL ' + address in instructions
    parser = query(ag, 'vendor_bossac', 'function', address='0x40e570', limit=500)['result']
    assert parser['decompile_completed'] and 'strtol' in parser['decompiled_c']
    assert query(ag, 'vendor_bossac', 'search', pattern='BOSSA) Version 1.9')['result']['rows']
