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

from concrete import ConcreteMachine, ConcreteExecutionError, TRAMPOLINE_BYTES  # noqa: E402
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
    check("failed run reports error_free=False", result.error_free is False)
    check("failed run reports completed=False", result.completed is False)
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


def test_fresh_isolation_across_mutable_state():
    print("test_fresh_isolation_across_mutable_state (hardening: fresh=True must restore RAM, flash, MMIO, PPB -- not just RAM/registers)")
    machine = ConcreteMachine(MANDO_FW, mmio_size=0x100000)
    ram_addr = 0x20001000
    flash_addr = 0x4100
    mmio_addr = 0x40001000
    ppb_addr = 0xE000E010  # SysTick CTRL address -- not modeled, but real mapped PPB space this
                            # class must still snapshot/restore like any other mutable region.

    pristine = {
        "ram": bytes(machine.uc.mem_read(ram_addr, 4)),
        "flash": bytes(machine.uc.mem_read(flash_addr, 4)),
        "mmio": bytes(machine.uc.mem_read(mmio_addr, 4)),
        "ppb": bytes(machine.uc.mem_read(ppb_addr, 4)),
    }

    machine.run(0x49c4, seed_mem=[
        (ram_addr, b"\xaa\xbb\xcc\xdd"),
        (flash_addr, b"\x11\x22\x33\x44"),
        (mmio_addr, b"\x55\x66\x77\x88"),
        (ppb_addr, b"\xff\xff\xff\xff"),
    ], max_instructions=5)
    check("dirty-page tracking recorded every mutated region (not just RAM)",
          len(machine._dirty_pages) >= 4, len(machine._dirty_pages))

    # A second run with fresh=True (the default) must see the SAME
    # pristine bytes a brand-new ConcreteMachine would -- this is the
    # exact guarantee the old subprocess-per-run model gave for free and
    # that reusing one ConcreteMachine must now provide explicitly.
    r2 = machine.run(0x49c4, dump_mem=[
        (ram_addr, 4), (flash_addr, 4), (mmio_addr, 4), (ppb_addr, 4),
    ], max_instructions=1)
    check("RAM restored to pristine on fresh=True", r2.mem(ram_addr, 4) == pristine["ram"], r2.mem(ram_addr, 4))
    check("flash restored to pristine on fresh=True", r2.mem(flash_addr, 4) == pristine["flash"], r2.mem(flash_addr, 4))
    check("MMIO restored to pristine on fresh=True", r2.mem(mmio_addr, 4) == pristine["mmio"], r2.mem(mmio_addr, 4))
    check("PPB restored to pristine on fresh=True", r2.mem(ppb_addr, 4) == pristine["ppb"], r2.mem(ppb_addr, 4))

    # fresh=False must NOT restore -- continuation stays explicit/opt-in.
    machine.run(0x49c4, seed_mem=[(ram_addr, b"\x01\x02\x03\x04")], max_instructions=1)
    r3 = machine.run(0x49c4, dump_mem=[(ram_addr, 4)], max_instructions=1, fresh=False)
    check("fresh=False intentionally carries state forward (not isolated)",
          r3.mem(ram_addr, 4) == b"\x01\x02\x03\x04", r3.mem(ram_addr, 4))


def test_real_default_sp_and_no_trampoline_in_ram():
    print("test_real_default_sp_and_no_trampoline_in_ram (hardening: run() must use the real SAMD51 SP; call()'s trampoline must live outside real RAM)")
    machine = ConcreteMachine(MANDO_FW)
    check("ram_top is the real SAMD51 RAM top (0x20030000)",
          machine.ram_top == 0x20030000, hex(machine.ram_top))
    check("trampoline_addr is outside real device RAM",
          not (machine.ram_base <= machine.trampoline_addr < machine.ram_top), hex(machine.trampoline_addr))

    machine.run(0x49c4, max_instructions=1)
    ram_bytes = bytes(machine.uc.mem_read(machine.ram_base, machine.ram_size))
    check("no injected trampoline bytes (0xfe 0xe7) appear anywhere in real device RAM",
          TRAMPOLINE_BYTES not in ram_bytes)

    result = machine.call(0x49c4, args=[1, 1, 0, 0, 0x62], max_instructions=5000)
    check("call() still returns cleanly with its trampoline moved out of real RAM", result.returned)
    ram_bytes_after_call = bytes(machine.uc.mem_read(machine.ram_base, machine.ram_size))
    check("real RAM still carries no trampoline bytes after a call()",
          TRAMPOLINE_BYTES not in ram_bytes_after_call)


def test_error_free_vs_completed_semantics():
    print("test_error_free_vs_completed_semantics (hardening: error_free != completed -- an instruction-limit result is not a completed one)")
    machine = ConcreteMachine(MANDO_FW, mmio_size=0x4000000)

    r_stop = machine.run(0x49c4, stop_at=[0x49c4], max_instructions=5)
    check("expected-stop run: error_free", r_stop.error_free)
    check("expected-stop run: completed", r_stop.completed)
    check("expected-stop run: stop_reason names the stop address",
          r_stop.stop_reason.startswith("reached stop address"), r_stop.stop_reason)

    r_limit = machine.run(0x49c4, max_instructions=3)
    check("instruction-limit run (no stop requested): error_free", r_limit.error_free)
    check("instruction-limit run (no stop requested): NOT completed", r_limit.completed is False)
    check("instruction-limit run: stop_reason is the instruction-limit message",
          r_limit.stop_reason == "instruction limit reached", r_limit.stop_reason)

    r_err = machine.run(0x20030000 | 1, max_instructions=10)
    check("Unicorn-error run: NOT error_free", r_err.error_free is False)
    check("Unicorn-error run: NOT completed", r_err.completed is False)

    call_result = machine.call(0x49c4, args=[1, 1, 0, 0, 0x62], max_instructions=5000)
    check("clean call() return: error_free", call_result.result.error_free)
    check("clean call() return: completed", call_result.result.completed)
    check("clean call() return: returned", call_result.returned)


def test_virtual_link_scenario_order_independence():
    print("test_virtual_link_scenario_order_independence (hardening: reused ConcreteMachine instances must not leak state across scenario order)")
    import virtual_link

    scenarios = {
        "plus": virtual_link.run_plus_target_distance_roundtrip,
        "g": virtual_link.run_g_ack_roundtrip,
        "s": virtual_link.run_s_roundtrip,
        "ampersand": virtual_link.run_ampersand_roundtrip,
    }
    # The same firmware-keyed ConcreteMachine cache (virtual_link._machines)
    # persists across both orders below, in the same process -- exactly
    # the reuse the old subprocess-per-run model made impossible to get
    # wrong. Each scenario function already asserts its own known-good
    # values internally; passing in both orders means no leftover state
    # from one scenario's legs altered another's observed output.
    for order in (["plus", "g", "s", "ampersand"], ["ampersand", "s", "g", "plus"]):
        for name in order:
            try:
                # Scenarios don't share a return-type contract (most
                # return True; run_s_roundtrip deliberately returns a
                # descriptive dict, per its own docstring) -- truthiness
                # plus "no assertion raised" is the real pass/fail signal.
                ok = bool(scenarios[name](verbose=False))
                detail = ""
            except AssertionError as e:
                ok = False
                detail = str(e)
            check(f"scenario '{name}' passes in order {order}", ok, detail)


def main():
    test_numeric_cli_semantics()
    test_direct_call_with_stack_args()
    test_structured_failure_snapshot()
    test_carry_forward_is_explicit_and_tagged()
    test_fresh_isolation_across_mutable_state()
    test_real_default_sp_and_no_trampoline_in_ram()
    test_error_free_vs_completed_semantics()
    test_virtual_link_scenario_order_independence()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s): {FAILURES}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
