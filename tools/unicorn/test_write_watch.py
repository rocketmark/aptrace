#!/usr/bin/env python3
"""Memory-observer noninterference tests, including Thumb IT/flag changes.

Run: tools/unicorn/.venv/bin/python3 tools/unicorn/test_write_watch.py
Emit the identical synthetic CLI fixtures without native execution:
    python3 tools/unicorn/test_write_watch.py --emit-fixtures DIRECTORY
These are test images, never patched target firmware.
"""
import argparse
import struct
import tempfile
from pathlib import Path


def image(condition=0x98, store=0x700a):
    # cmp r2,#5; it <cond>; str[b/h] r2,[r1]; movs r0,#1;
    # bl thunk; b done. Thunk branches to the real callee; falling through
    # the thunk writes99 instead of42. This detects stale conditional state
    # beyond the IT block, not merely whether the watched store happened.
    code = bytearray(0x48)
    code[:8] = struct.pack('<HHHH', 0x2a05, 0xbf00 | condition, store, 0x2001)
    code[8:14] = bytes.fromhex('00f00af810e0')
    code[0x20:0x2a] = bytes.fromhex('00f00eb863234b607047')
    code[0x30:0x32] = bytes.fromhex('00bf')
    code[0x40:0x46] = bytes.fromhex('2a234b607047')
    return bytes(code)


def emit_fixtures(directory):
    directory.mkdir(parents=True, exist_ok=True)
    for name, condition in [('ls', 0x98), ('eq', 0x08), ('ne', 0x18)]:
        for width, store in [(1, 0x700a), (2, 0x800a), (4, 0x600a)]:
            (directory / f'{name}-{width}.bin').write_bytes(image(condition, store))


def run_regressions():
    from concrete import ConcreteMachine
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        emit_fixtures(directory)
        count = 0
        for condition in ('ls', 'eq', 'ne'):
            for width in (1, 2, 4):
                path = directory / f'{condition}-{width}.bin'
                decoded = list(md.disasm(path.read_bytes()[:14], 0x4000))
                assert decoded[1].mnemonic == 'it' and decoded[1].op_str == condition
                for value in (4, 5, 6):
                    address = 0x20000069 if width == 1 else 0x20000100
                    options = dict(reg_seed=[('r1', address), ('r2', value)],
                                   stop_at=[0x4030], dump_mem=[(address, 8)],
                                   collect_coverage=True, max_instructions=100)
                    baseline = ConcreteMachine(path, track_dirty=False).run(0x4000, **options)
                    predicate = {'ls': value <= 5, 'eq': value == 5, 'ne': value != 5}[condition]
                    expected = (value if predicate else 0).to_bytes(4, 'little') + (42).to_bytes(4, 'little')
                    assert baseline.completed and baseline.mem(address, 8) == expected
                    for tracked, observers in [
                        (False, {'watch_mem_write': [(address, width)]}),
                        (False, {'watch_mem_write': [(address, 8)], 'max_mem_write_log': 1}),
                        (False, {'log_ram': True}),
                        (True, {}),
                        (True, {'watch_mem_write': [(address, 8)], 'trace_last': 0}),
                    ]:
                        machine = ConcreteMachine(path, track_dirty=tracked)
                        observed = machine.run(0x4000, **options, **observers)
                        assert observed.completed
                        assert observed.registers == baseline.registers
                        assert observed.mem(address, 8) == expected
                        assert observed.visited_pcs == baseline.visited_pcs
                        assert observed.execution_mode == 'memory-hook-single-step'
                        if 'watch_mem_write' in observers:
                            hits = observed.mem_write_hits
                            broad = observers['watch_mem_write'][0][1] == 8
                            expected_hits = int(predicate) + int(broad)
                            capacity = observers.get('max_mem_write_log', 1000)
                            assert len(hits) == min(capacity, expected_hits)
                            assert observed.mem_write_dropped == max(0, expected_hits - capacity)
                            if predicate:
                                first = hits[0]
                                assert int(first['pc'], 16) == 0x4004
                                assert int(first['address'], 16) == address
                                assert first['size'] == width
                                assert int(first['value'], 16) == value
                                assert first['previous'] == '00' * width
                        if tracked:
                            repeated = machine.run(0x4000, **options, **observers)
                            assert repeated.registers == observed.registers
                            assert repeated.mem(address, 8) == expected
                        count += 1
        # Same IT fixture in MMIO exercises both passive MMIO logging and
        # read-hook stand-ins (mask0 leaves the actual data unchanged).
        path = directory / 'ls-1.bin'
        for observers in ({'log_mmio': True}, {'mmio_force_bits': [(0x40000000, 0)]}):
            result = ConcreteMachine(path, track_dirty=False).run(
                0x4000, reg_seed=[('r1', 0x40000000), ('r2', 5)],
                stop_at=[0x4030], dump_mem=[(0x40000000, 8)], **observers)
            assert result.completed and result.mem(0x40000000, 8) == bytes.fromhex('050000002a000000')
        print(f'write-watch noninterference: {count} observer cases + reset/MMIO controls passed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--emit-fixtures', type=Path)
    args = parser.parse_args()
    if args.emit_fixtures:
        emit_fixtures(args.emit_fixtures)
    else:
        run_regressions()
