#!/usr/bin/env python3
"""APTrace: regression coverage for tools/unicorn/concrete.py and the CLI
numeric-parsing fix in tools/unicorn/run_concrete.py.

Deliberately not pytest-based (no new dependency for this project) --
plain assertions, run as a script. Exit code 0 means everything passed.

Run after touching concrete.py/run_concrete.py, in addition to (not
instead of) tools/doctor.sh and tools/unicorn/virtual_link.py all/plus,
which remain the acceptance tests for firmware-behavior-facing changes.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
REPO_ROOT = HERE.parent.parent
MANDO_FW = REPO_ROOT / "research/firmware/originals/firmware_mando868.bin"

from concrete import ConcreteMachine, ConcreteExecutionError  # noqa: E402
import run_concrete  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def test_numeric_cli_semantics():
    print("test_numeric_cli_semantics (28 != 0x28)")
    check("parse_value('28') == 28 (decimal)", run_concrete.parse_value("28") == 28)
    check("parse_value('0x28') == 40 (hex)", run_concrete.parse_value("0x28") == 0x28)
    check("28 != 0x28", run_concrete.parse_value("28") != run_concrete.parse_value("0x28"))
    # And end-to-end through the actual CLI argv parser + a real Unicorn run,
    # not just the parsing function in isolation -- this is the exact
    # regression for the false investigative path documented in
    # docs/investigations/plus-target-distance-roundtrip.md.
    import tempfile
    import json
    with tempfile.TemporaryDirectory() as d:
        out_dec = Path(d) / "dec.json"
        out_hex = Path(d) / "hex.json"
        rc1 = run_concrete.main(["--firmware", str(MANDO_FW), "--entry", "0x4998",
                                  "--reg", "r0=28", "--stop-at", "0x4998",
                                  "--max-instructions", "1", "--out", str(out_dec)])
        rc2 = run_concrete.main(["--firmware", str(MANDO_FW), "--entry", "0x4998",
                                  "--reg", "r0=0x28", "--stop-at", "0x4998",
                                  "--max-instructions", "1", "--out", str(out_hex)])
        r0_dec = json.load(open(out_dec))["registers"]["r0"]
        r0_hex = json.load(open(out_hex))["registers"]["r0"]
        check("CLI --reg r0=28 -> r0=0x1c", r0_dec == "0x0000001c", r0_dec)
        check("CLI --reg r0=0x28 -> r0=0x28", r0_hex == "0x00000028", r0_hex)


def test_direct_call_with_stack_args():
    print("test_direct_call_with_stack_args (FUN_000049c4, a known Remote function)")
    machine = ConcreteMachine(MANDO_FW, mmio_size=0x4000000)
    # FUN_000049c4('+' frame builder): 5 AAPCS args, the 5th (mode) goes
    # on the stack -- exactly the case that used to require hand-picking
    # SP/LR. confirm1=confirm2=1, channel=0, param_4=0, mode=0x62.
    result = machine.call(
        0x49c4, args=[1, 1, 0, 0, 0x62],
        seed_mem=[(0x20000b20, b"\xf4\x01\x00\x00")],  # record0 delta = 500
        dump_mem=[(0x2000183c, 64)],
        max_instructions=5000,
    )
    check("call returned cleanly (no fabricated-return crash)", result.returned,
          result.result.stop_reason)
    check("instructions executed is small/bounded", 0 < result.result.instructions_executed < 2000,
          str(result.result.instructions_executed))
    frame = result.result.mem(0x2000183c, 64).split(b"\x00", 1)[0]
    check("real frame bytes match the known-good result",
          frame == b"+1,1,1,0,98,1,0,0,0,500,0,0|", frame)

    # Calling again on the SAME machine object (reuse, not a fresh
    # process) must not leak state from the first call.
    result2 = machine.call(0x49c4, args=[1, 1, 1, 0, 0x62],
                            seed_mem=[(0x20000b20 + 0x120, b"\x0a\x00\x00\x00")],  # channel 1's own delta = 10
                            dump_mem=[(0x2000183c, 64)])
    check("second call on the same machine also returns cleanly", result2.returned)
    frame2 = result2.result.mem(0x2000183c, 64).split(b"\x00", 1)[0]
    check("second call reflects channel=1's own seed, not leaked state from call 1",
          frame2 == b"+1,1,1,1,98,1,0,0,0,10,0,0|", frame2)


def test_structured_failure_snapshot():
    print("test_structured_failure_snapshot (a failed run is still fully analyzable)")
    machine = ConcreteMachine(MANDO_FW)
    # Force a real failure: jump PC into the unmapped region above RAM.
    result = machine.run(0x20030000 | 1, max_instructions=10)
    check("failed run reports success=False", result.success is False)
    check("failed run has a non-None stop_reason", result.stop_reason is not None, result.stop_reason)
    check("failed run has a non-None error", result.error is not None)
    check("failed run still has full registers", "pc" in result.registers)
    check("failed run still has recent_pcs (no second run needed to see the tail)",
          isinstance(result.recent_pcs, list))

    # raise_on_error=True attaches the same structured result to the exception.
    try:
        machine.run(0x20030000 | 1, max_instructions=10, raise_on_error=True)
        check("raise_on_error=True raised ConcreteExecutionError", False)
    except ConcreteExecutionError as e:
        check("raise_on_error=True raised ConcreteExecutionError", True)
        check("exception carries the full RunResult", e.result.stop_reason is not None)


def test_carry_forward_is_explicit_and_tagged():
    print("test_carry_forward_is_explicit_and_tagged (priority 8)")
    machine = ConcreteMachine(MANDO_FW)
    r1 = machine.run(0x49c4, sp=0x2002ff00, max_instructions=1)  # cheap, just to get a RunResult
    result = machine.run(0x49c4, reg_seed=[("r0", 0)], seed_mem=[(0x20000000, b"\x01\x02\x03\x04")],
                          dump_mem=[(0x20000000, 4)], max_instructions=1)
    carried = result.carry(0x20000000, 4, label="test")
    check("carry() returns bytes matching the prior run's own output", carried.data == b"\x01\x02\x03\x04")
    # Feed it into a second run and confirm the applied_seeds log tags it
    # distinctly from an ordinary seed.
    result2 = machine.run(0x49c4, seed_mem=[carried, (0x20000004, b"\xff\xff\xff\xff", "synthetic")],
                           max_instructions=1)
    tags = {s["tag"] for s in result2.applied_seeds}
    check("carried state is tagged 'carried:...', distinct from a synthetic seed",
          any(t.startswith("carried:") for t in tags) and "synthetic" in tags, tags)


def main():
    test_numeric_cli_semantics()
    test_direct_call_with_stack_args()
    test_structured_failure_snapshot()
    test_carry_forward_is_explicit_and_tagged()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s): {FAILURES}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
