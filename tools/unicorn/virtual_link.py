#!/usr/bin/env python3
"""APTrace: a virtual RF link between the AutoPilot and Remote firmware.

Wires the four already-independently-proven concrete scenarios
(docs/investigations/dispatcher-loop-concrete-trace.md,
docs/investigations/tx-hook-verification.md,
docs/investigations/mando-first-execution.md) into one harness-driven
round trip, per docs/harness/roadmap.md's M3 step 8. See
docs/investigations/virtual-rf-link.md for the full write-up.

This does NOT model LoRa/SPI hardware. Per the already-established
"boundary found" in mando-first-execution.md, both firmwares' real radio
drivers are unreachable without either running full startup or building
real peripheral behavior -- both explicitly out of scope. Instead, this
hooks *above* the radio driver on both ends, exactly where
research/autopilot_static_inventory/rf-boundaries.md originally
recommended: capture the exact bytes a real, unmodified TX call is about
to hand to the (unmodeled) radio, and deliver those exact bytes into the
other firmware's real RX state (a packet buffer, or a ring buffer plus its
pointers), then let that firmware's own real, unmodified code consume
them. Every step below is a real `tools/unicorn/run_concrete.py`
invocation (the project's existing, sole concrete-execution backend) --
this module only orchestrates them; it adds no new Unicorn/emulation
logic.

Two reusable primitives fall out of doing this for real, not a
transaction-specific script:

  capture_tx_bytes(...)   -- run a firmware's real code until it calls a
                             string-argument TX wrapper (the same `void
                             wrapper(char *s)` convention both firmwares'
                             TX wrappers use: AutoPilot's 0x8c10, Remote's
                             0x58a8), and return exactly the bytes it is
                             about to hand that wrapper. Two real Unicorn
                             runs (not one): the first discovers what
                             address the firmware itself computed as the
                             argument (R0) at the wrapper's entry, without
                             assuming it; the second dumps memory there.
                             This is what makes the technique reusable for
                             a transaction whose output isn't already
                             known in advance (unlike this module's own
                             "&|" demo, where the output happens to be
                             already-proven).

  deliver_and_observe(...) -- seed a firmware's real RX state with bytes
                             already captured from the other side, run its
                             real, unmodified code, and return whatever
                             memory range the caller wants to observe
                             (a pending-event byte, a response buffer).

Usage:
    tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
RUN_CONCRETE = HERE / "run_concrete.py"
VENV_PYTHON = HERE / ".venv" / "bin" / "python3"
REPO_ROOT = HERE.parent.parent

AUTOPILOT_FW = REPO_ROOT / "research/firmware/originals/firmware_autopilot868.bin"
MANDO_FW = REPO_ROOT / "research/firmware/originals/firmware_mando868.bin"

# Default MMIO window: covers the SAMD51 peripheral bridge (0x40000000+)
# used by both firmwares' startup/driver code paths -- see
# docs/investigations/mando-first-execution.md ("New harness capability").
MMIO_BASE = "0x40000000"
MMIO_SIZE = "0x4000000"


def _hexaddr(addr):
    return addr if isinstance(addr, str) else f"0x{addr:x}"


def _norm(addr):
    """Match run_concrete.py's own JSON key formatting (f"0x{addr:08x}")."""
    if isinstance(addr, str):
        addr = int(addr, 0)
    return f"0x{addr:08x}"


def run_concrete(firmware, entry, seed_mem=(), stub_calls=(), stop_at=None,
                  dump_mem=(), max_instructions=5000,
                  mmio_base=MMIO_BASE, mmio_size=MMIO_SIZE):
    """Invoke the existing tools/unicorn/run_concrete.py CLI -- the same
    command a human would type -- and return its parsed JSON snapshot.
    This is the only place this module talks to Unicorn; every other
    function here just chooses arguments for this one."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name
    args = [str(VENV_PYTHON), str(RUN_CONCRETE),
            "--firmware", str(firmware),
            "--entry", _hexaddr(entry),
            "--mmio-base", mmio_base, "--mmio-size", mmio_size,
            "--max-instructions", str(max_instructions),
            "--out", out_path]
    for addr, data in seed_mem:
        args += ["--seed-mem", f"{_hexaddr(addr)}:{data}"]
    for addr in stub_calls:
        args += ["--stub-call", _hexaddr(addr)]
    if stop_at is not None:
        args += ["--stop-at", _hexaddr(stop_at)]
    for addr, length in dump_mem:
        args += ["--dump-mem", f"{_hexaddr(addr)}:{length}"]
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"run_concrete.py failed:\n{result.stderr}")
    with open(out_path) as f:
        snapshot = json.load(f)
    Path(out_path).unlink(missing_ok=True)
    return snapshot


def capture_tx_bytes(firmware, entry, tx_wrapper_entry, seed_mem=(),
                      max_instructions=5000, max_len=64):
    """Run the real firmware from 'entry' until it reaches 'tx_wrapper_entry'
    (a `void wrapper(char *s)`-convention TX call, entered fresh -- not
    stepped into, so none of its own not-yet-modeled body runs), and
    return exactly the NUL-terminated bytes it is about to hand that
    wrapper. Does not assume or hardcode the content -- only the calling
    convention, which is independently confirmed for both of this
    project's TX wrappers (AutoPilot's 0x8c10: tx-hook-verification.md;
    Remote's 0x58a8: mando-first-execution.md)."""
    probe = run_concrete(firmware, entry, seed_mem=seed_mem,
                          stop_at=tx_wrapper_entry, max_instructions=max_instructions)
    expected_stop = f"reached stop address {_norm(tx_wrapper_entry)}"
    if probe["stop_reason"] != expected_stop:
        raise RuntimeError(
            f"never reached TX wrapper {_hexaddr(tx_wrapper_entry)}: {probe['stop_reason']}")
    arg_ptr = int(probe["registers"]["r0"], 0)
    dump = run_concrete(firmware, entry, seed_mem=seed_mem,
                         stop_at=tx_wrapper_entry, max_instructions=max_instructions,
                         dump_mem=[(arg_ptr, str(max_len))])
    raw = bytes.fromhex(dump["memory"][_norm(arg_ptr)])
    return raw.split(b"\x00", 1)[0] + b"\x00", arg_ptr


def deliver_and_observe(firmware, entry, seed_mem, observe_addr, observe_len,
                         stub_calls=(), stop_at=None, max_instructions=5000):
    """Seed the real firmware's own RX state with bytes already captured
    from the other side, run its real, unmodified code, and return the
    requested memory range."""
    snap = run_concrete(firmware, entry, seed_mem=seed_mem, stub_calls=stub_calls,
                         stop_at=stop_at, dump_mem=[(observe_addr, str(observe_len))],
                         max_instructions=max_instructions)
    if stop_at is not None:
        expected_stop = f"reached stop address {_norm(stop_at)}"
        if snap["stop_reason"] != expected_stop:
            raise RuntimeError(f"unexpected stop: {snap['stop_reason']}")
    return bytes.fromhex(snap["memory"][_norm(observe_addr)])


# --- Known anchors (all independently confirmed by execution in the docs
# cited above; nothing here is a new claim) ---------------------------------

AUTOPILOT_RX_ENTRY = 0x8a34          # real dispatcher call site (RX)
AUTOPILOT_RX_BUFFER = 0x2000232a     # real packet buffer
AUTOPILOT_RX_EXIT = 0x83ec           # confirmed post-dispatch exit block
AUTOPILOT_PENDING5 = 0x200025c1      # pending[5], the firmware-version event
AUTOPILOT_TX_ENTRY = 0x9268          # outbound event dispatcher
AUTOPILOT_TX_WRAPPER = 0x8c10        # string TX wrapper
AUTOPILOT_VERSION_BUF = 0x20003134   # "V01R39\0", written by real startup (FUN_00004328)
AUTOPILOT_SCAN_SLOT0 = 0x20000100    # scan-table simplification (see tx-hook-verification.md)
AUTOPILOT_SCAN_COUNT = 0x200000d9
AUTOPILOT_LAST_TS = 0x20002520       # rate-limit-gate bypass

REMOTE_TX_ENTRY = 0xbaaa             # real "&|" query, past the not-yet-modeled drain loop
REMOTE_TX_WRAPPER = 0x58a8           # string TX wrapper
REMOTE_RX_ENTRY = 0xbaa6             # past the drain loop, at the preamble call
REMOTE_RX_STOP = 0xbacc              # confirmed end of the 7-byte collection loop
REMOTE_RX_RINGBUF = 0x20001773
REMOTE_RX_READPTR = 0x200017d7
REMOTE_RX_WRITEPTR = 0x200017d8
REMOTE_RESULT_BUF = 0x200002fc
REMOTE_STUB_CALLS = (0x58a8, 0xb440, 0x168c0)  # radio poll + TX wrapper + SysTick delay


def run_ampersand_roundtrip(verbose=True):
    """The acceptance scenario: Remote sends "&|" -> AutoPilot parses it and
    produces "V01R39" -> Remote captures it. Returns True and prints a
    step-by-step transcript; raises on any unexpected divergence (nothing
    is silently tolerated)."""
    def log(msg):
        if verbose:
            print(msg)

    log("=== Leg 1: Remote constructs its real query ===")
    wire1, arg_ptr = capture_tx_bytes(MANDO_FW, REMOTE_TX_ENTRY, REMOTE_TX_WRAPPER)
    log(f"  Remote's real, unmodified 0xba98 calls 0x58a8 with a pointer to"
        f" flash 0x{arg_ptr:x}, bytes = {wire1!r}")
    assert wire1 == b"&|\x00", f"unexpected Remote TX bytes: {wire1!r}"

    log("=== Leg 2a: AutoPilot receives it and schedules event 5 ===")
    wire1_bytes = wire1[:-1]  # drop the capture-side NUL -- not part of the wire frame
    packet = wire1_bytes.ljust(4, b"\x00")  # pad to the buffer size dispatcher-loop-concrete-trace.md exercised
    pending5 = deliver_and_observe(
        AUTOPILOT_FW, AUTOPILOT_RX_ENTRY,
        seed_mem=[(AUTOPILOT_RX_BUFFER, packet.hex())],
        stop_at=AUTOPILOT_RX_EXIT,
        observe_addr=AUTOPILOT_PENDING5, observe_len=1)
    log(f"  AutoPilot's real, unmodified 0x8258 dispatcher, given the real"
        f" wire bytes {wire1_bytes!r}, sets pending[5] = 0x{pending5.hex()}")
    assert pending5 == b"\x01", f"event 5 not scheduled: pending[5]={pending5!r}"

    log("=== Leg 2b: AutoPilot's outbound dispatcher builds its real response ===")
    wire2, resp_ptr = capture_tx_bytes(
        AUTOPILOT_FW, AUTOPILOT_TX_ENTRY, AUTOPILOT_TX_WRAPPER,
        seed_mem=[
            (AUTOPILOT_PENDING5, pending5.hex()),  # carried forward from leg 2a, not hardcoded
            (AUTOPILOT_VERSION_BUF, "5630315233390000"),
            (AUTOPILOT_SCAN_SLOT0, "05"),
            (AUTOPILOT_SCAN_COUNT, "01"),
            (AUTOPILOT_LAST_TS, "0000ffff"),
        ])
    log(f"  AutoPilot's real, unmodified 0x9268 dispatcher calls 0x8c10 with"
        f" a pointer to RAM 0x{resp_ptr:x}, bytes = {wire2!r}")
    assert wire2 == b"V01R39\x00", f"unexpected AutoPilot TX bytes: {wire2!r}"

    log("=== Leg 3: Remote receives it ===")
    captured = deliver_and_observe(
        MANDO_FW, REMOTE_RX_ENTRY,
        seed_mem=[
            (REMOTE_RX_RINGBUF, wire2.hex()),
            (REMOTE_RX_READPTR, "00"),
            (REMOTE_RX_WRITEPTR, f"{len(wire2):02x}"),
        ],
        stub_calls=REMOTE_STUB_CALLS,
        stop_at=REMOTE_RX_STOP,
        observe_addr=REMOTE_RESULT_BUF, observe_len=len(wire2))
    log(f"  Remote's real, unmodified 0xba98 collection loop, given the real"
        f" wire bytes {wire2!r}, captures {captured!r} at 0x{REMOTE_RESULT_BUF:x}")
    assert captured == b"V01R39\x00", f"Remote did not capture the real response: {captured!r}"

    log("\nRound trip PASSED: Remote \"&|\" -> AutoPilot event 5 -> Remote \"V01R39\\0\"")
    return True


if __name__ == "__main__":
    ok = run_ampersand_roundtrip()
    sys.exit(0 if ok else 1)
