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

  capture_tx_byte(...)   -- like capture_tx_bytes, for AutoPilot's *other*
                             TX-wrapper convention (0x7f84: a single byte
                             passed by value in R0, not a `char *`) --
                             added for the G -> # transaction, whose
                             AutoPilot-side response is one byte ('#'),
                             not a string.

Three transactions are implemented on top of these primitives:
  run_ampersand_roundtrip() -- "&|" -> "V01R39" (roadmap M3's own scenario)
  run_g_ack_roundtrip()     -- G<d><d><seq>| -> "#" (roadmap M4's first
                               transaction; see
                               docs/investigations/g-ack-roundtrip.md for
                               what this one needed beyond M3 -- register-
                               seeded call arguments, a Remote-side retry
                               loop, and two additional AutoPilot-side
                               `--stub-call`s for real-but-irrelevant
                               driver-touching helpers).
  run_s_roundtrip()         -- "S|" -> "P..." (roadmap M4's second
                               transaction; run twice, at two different
                               concrete device-state values, to exercise
                               both the short and extended response forms
                               for real -- see
                               docs/investigations/s-p-roundtrip.md,
                               including a real "don't downgrade" guard in
                               the Remote's own parser found by running
                               it, not by reading the decompile alone).

Usage:
    tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py          # all transactions
    tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py g        # G -> # only
    tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py s        # S -> P... only
    tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py ampersand  # "&|" -> "V01R39" only
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


def run_concrete(firmware, entry, seed_mem=(), reg_seed=(), stub_calls=(), stop_at=None,
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
    for name, value in reg_seed:
        args += ["--reg", f"{name}={_hexaddr(value)}"]
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


def _expect_stop(snap, stop_at):
    expected_stop = f"reached stop address {_norm(stop_at)}"
    if snap["stop_reason"] != expected_stop:
        raise RuntimeError(f"expected to stop at {_hexaddr(stop_at)}, got: {snap['stop_reason']}")


def capture_tx_bytes(firmware, entry, tx_wrapper_entry, seed_mem=(), reg_seed=(),
                      stub_calls=(), max_instructions=5000, max_len=64):
    """Run the real firmware from 'entry' until it reaches 'tx_wrapper_entry'
    (a `void wrapper(char *s)`-convention TX call, entered fresh -- not
    stepped into, so none of its own not-yet-modeled body runs), and
    return exactly the NUL-terminated bytes it is about to hand that
    wrapper. Does not assume or hardcode the content -- only the calling
    convention, which is independently confirmed for both of this
    project's string-argument TX wrappers (AutoPilot's 0x8c10:
    tx-hook-verification.md; Remote's 0x58a8: mando-first-execution.md).

    'stub_calls' lets a caller skip real-but-irrelevant driver-touching
    helpers encountered *before* reaching the wrapper (see
    docs/investigations/g-ack-roundtrip.md for a real case: the Remote's
    G-request builder calls a wake-up preamble, and the AutoPilot's G
    handler calls two logging/config helpers that dereference an
    uninitialized driver object -- neither affects the bytes handed to
    the TX wrapper, so both are safe to stub)."""
    probe = run_concrete(firmware, entry, seed_mem=seed_mem, reg_seed=reg_seed,
                          stub_calls=stub_calls,
                          stop_at=tx_wrapper_entry, max_instructions=max_instructions)
    _expect_stop(probe, tx_wrapper_entry)
    arg_ptr = int(probe["registers"]["r0"], 0)
    dump = run_concrete(firmware, entry, seed_mem=seed_mem, reg_seed=reg_seed,
                         stub_calls=stub_calls,
                         stop_at=tx_wrapper_entry, max_instructions=max_instructions,
                         dump_mem=[(arg_ptr, str(max_len))])
    raw = bytes.fromhex(dump["memory"][_norm(arg_ptr)])
    return raw.split(b"\x00", 1)[0] + b"\x00", arg_ptr


def capture_tx_byte(firmware, entry, tx_wrapper_entry, seed_mem=(), reg_seed=(),
                     stub_calls=(), max_instructions=5000):
    """Like 'capture_tx_bytes', but for the *other* TX-wrapper calling
    convention this project's firmware uses: `void wrapper(char b)` (a
    single byte passed by value in R0 -- AutoPilot's 0x7f84), rather than
    a `char *s` pointer. One real Unicorn run is enough here: the payload
    *is* R0, not something R0 points at."""
    probe = run_concrete(firmware, entry, seed_mem=seed_mem, reg_seed=reg_seed,
                          stub_calls=stub_calls,
                          stop_at=tx_wrapper_entry, max_instructions=max_instructions)
    _expect_stop(probe, tx_wrapper_entry)
    return int(probe["registers"]["r0"], 0) & 0xFF


def deliver_and_observe(firmware, entry, seed_mem, observe_addr, observe_len,
                         reg_seed=(), stub_calls=(), stop_at=None, max_instructions=5000):
    """Seed the real firmware's own RX state with bytes already captured
    from the other side, run its real, unmodified code, and return the
    requested memory range."""
    snap = run_concrete(firmware, entry, seed_mem=seed_mem, reg_seed=reg_seed, stub_calls=stub_calls,
                         stop_at=stop_at, dump_mem=[(observe_addr, str(observe_len))],
                         max_instructions=max_instructions)
    if stop_at is not None:
        _expect_stop(snap, stop_at)
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

# --- G -> # anchors (all independently confirmed by execution this pass;
# see docs/investigations/g-ack-roundtrip.md) --------------------------------

AUTOPILOT_PENDING17 = 0x200025cd     # pending[17], the G-acknowledgement event
AUTOPILOT_TX_BYTE_WRAPPER = 0x7f84   # single-byte TX wrapper (event 17's real path, not 0x8c10)
# Two real-but-irrelevant driver-touching helpers the G handler (0x83b2)
# calls before writing pending[17]: 0xb258 dereferences an uninitialized
# object pointer through a vtable (only valid after real startup, same
# class of boundary as the RF driver itself); 0x4b64 refreshes persistent
# motor-config-derived state via a loop whose length depends on
# not-yet-modeled data and spins far past any reasonable instruction
# budget in cold RAM. Neither's return value is used by the G handler.
AUTOPILOT_G_HANDLER_STUB_CALLS = (0xb258, 0x4b64)

REMOTE_G_BUILD_ENTRY = 0xb680        # real G<d><d><seq>| builder
REMOTE_G_WAKE_FLAG = 0x20000fc8      # "has ever sent" flag; seeded nonzero to skip a one-time wake preamble (see below)
REMOTE_ACK_ENTRY = 0xb5ca            # past 0xb59c's own drain+preamble, right before the real send
REMOTE_ACK_STOP = 0xb60e             # reached only once the '#' has been recognized (R4 becomes 1) or retries exhaust (R4 stays 0)
# 0xb59c's own prologue (skipped by entering at REMOTE_ACK_ENTRY) sets
# these four registers before the retry loop's body runs; resolved from
# the same literal pool 0xb59c itself reads (0x2000276c = the last-
# activity timestamp cell, shared with the "&|" transaction's own timing
# state; 0x2000183c = the G-request buffer 0xb680 just built).
REMOTE_ACK_REG_SEED = (("r4", 5), ("r5", 0x2000276c), ("r6", 0x2000276c), ("r7", 0x2000183c))

# --- S -> P... anchors (all independently confirmed by execution this
# pass; see docs/investigations/s-p-roundtrip.md) ---------------------------

REMOTE_S_ENTRY = 0xc440              # real S|/!0|/!1| routine; param_1 (R0) selects phase
REMOTE_S_PREAMBLE_STUB = 0x5a14      # real but irrelevant "wake" call, unconditional here (unlike G's)
REMOTE_S_PARSE_ENTRY = 0xc4dc        # past the drain+send+200-tick wait, right at the P-response parse loop
REMOTE_S_PARSE_STOP = 0xc4b2         # loop-exit check, reached once the response is fully parsed (both forms)
# 0xc4dc's own immediately-following instructions set R10/R11/R6/R4 from
# the literal pool (ring buffer, read ptr, stored-state address, retry
# flag) -- entering there skips them, so they're seeded here instead. R8
# (the function's own param_1, preserved across the whole call) also
# needs seeding since we bypass the real entry that received it in R0.
REMOTE_S_PARSE_REG_SEED = (("r8", 0),)
# R9 (the value1-store pointer) is set once, far earlier (0xc474, well
# before the send), and never reloaded -- only needed at all on the
# *extended*-response path (mode 4 below); the short-response path never
# touches it (confirmed by first omitting it and getting a clean run, not
# assumed).
REMOTE_S_VALUE1_REG_SEED = ("r9", 0x20002688)

AUTOPILOT_PENDING6 = 0x200025c2      # pending[6], the S/P event
AUTOPILOT_S_MODE = 0x20002524        # device state/mode selector (0-4); read by BOTH the S handler's
                                      # switch and (separately, later) the event-6 builder's short/extended check
AUTOPILOT_S_VALUE0 = 0x200025ad      # value0 -- computed and stored by the S handler itself from AUTOPILOT_S_MODE
AUTOPILOT_S_VALUE1 = 0x20002530      # value1 -- only read by the builder when AUTOPILOT_S_MODE == 4
AUTOPILOT_S_BOOL = 0x20003100        # bool source -- only read when AUTOPILOT_S_MODE == 4

REMOTE_S_STORED_STATE = 0x200018e7   # Remote's own copy of value0, after its "don't downgrade" guard
REMOTE_S_VALUE1_STORE = 0x20002688   # Remote's stored value1 (only written on the extended path)
REMOTE_S_BOOL_STORE = 0x20002671     # Remote's stored bool (only written on the extended path)


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


def run_g_ack_roundtrip(verbose=True):
    """The second acceptance scenario: Remote sends a real G<d><d><seq>|
    request -> AutoPilot schedules event 17 -> AutoPilot sends "#" ->
    Remote's real retry/ack path accepts it. Tests whether the M3
    primitives generalize to a transaction with request fields and
    Remote-side retry/ack behavior, not just a fixed string. See
    docs/investigations/g-ack-roundtrip.md."""
    def log(msg):
        if verbose:
            print(msg)

    log("=== Leg 1: Remote constructs its real G request ===")
    # param_1=0, param_2=0: the two "<d><d>" fields 0xb680 takes as
    # arguments -- seeded, not captured, since 0xb680 is entered directly
    # rather than through its real (large, UI-state-machine) caller
    # 0xe670. 0/0 matches 2 of 0xe670's 3 real call sites in the common
    # case (the third computes a small nonzero channel index) -- see
    # g-ack-roundtrip.md for why this is a representative seed, not an
    # arbitrary one. REMOTE_G_WAKE_FLAG is seeded nonzero to skip a real
    # but irrelevant one-time "wake up the radio" preamble inside 0xb59c
    # (mirrors the same preamble already documented for 0xba98).
    wire1, arg_ptr = capture_tx_bytes(
        MANDO_FW, REMOTE_G_BUILD_ENTRY, REMOTE_TX_WRAPPER,
        seed_mem=[(REMOTE_G_WAKE_FLAG, "01")],
        reg_seed=[("r0", 0), ("r1", 0)],
        stub_calls=[0xb440])
    log(f"  Remote's real, unmodified 0xb680/0xb59c calls 0x58a8 with a pointer to"
        f" RAM 0x{arg_ptr:x}, bytes = {wire1!r}")
    assert wire1[:1] == b"G" and wire1[-2:] == b"|\x00", f"unexpected Remote G bytes: {wire1!r}"

    log("=== Leg 2a: AutoPilot receives it and schedules event 17 ===")
    wire1_bytes = wire1[:-1]  # drop the capture-side NUL -- not part of the wire frame
    packet = wire1_bytes.ljust(8, b"\x00")
    pending17 = deliver_and_observe(
        AUTOPILOT_FW, AUTOPILOT_RX_ENTRY,
        seed_mem=[(AUTOPILOT_RX_BUFFER, packet.hex())],
        stub_calls=AUTOPILOT_G_HANDLER_STUB_CALLS,
        stop_at=AUTOPILOT_RX_EXIT,
        observe_addr=AUTOPILOT_PENDING17, observe_len=1)
    log(f"  AutoPilot's real, unmodified 0x8258 dispatcher, given the real"
        f" wire bytes {wire1_bytes!r}, sets pending[17] = 0x{pending17.hex()}")
    assert pending17 == b"\x01", f"event 17 not scheduled: pending[17]={pending17!r}"

    log("=== Leg 2b: AutoPilot's outbound dispatcher builds its real \"#\" response ===")
    ack_byte = capture_tx_byte(
        AUTOPILOT_FW, AUTOPILOT_TX_ENTRY, AUTOPILOT_TX_BYTE_WRAPPER,
        seed_mem=[
            (AUTOPILOT_PENDING17, pending17.hex()),  # carried forward from leg 2a, not hardcoded
            (AUTOPILOT_SCAN_SLOT0, "11"),             # event 17, not event 5 -- same scan-table simplification
            (AUTOPILOT_SCAN_COUNT, "01"),
            (AUTOPILOT_LAST_TS, "0000ffff"),
        ])
    log(f"  AutoPilot's real, unmodified 0x9268 dispatcher calls 0x7f84 with"
        f" R0 = 0x{ack_byte:02x} ({bytes([ack_byte])!r})")
    assert ack_byte == 0x23, f"unexpected AutoPilot ack byte: 0x{ack_byte:02x}"

    log("=== Leg 3: Remote's real retry/ack path accepts it ===")
    # Unlike the other legs, success here is a *register* outcome (R4, the
    # retry function's own C-level `int` return value), not a memory
    # range -- deliver_and_observe's contract is memory-based, so this
    # calls run_concrete directly. R4 == 1 only on the path that recognized
    # the seeded '#' byte as a real acknowledgement (0xb602-0xb60c in the
    # disassembly); R4 == 0 is what the same stop address sees if retries
    # exhaust instead -- both are real, reachable outcomes of the same
    # code, not a value this script forces.
    snap = run_concrete(
        MANDO_FW, REMOTE_ACK_ENTRY,
        seed_mem=[
            (REMOTE_RX_RINGBUF, f"{ack_byte:02x}"),
            (REMOTE_RX_READPTR, "00"),
            (REMOTE_RX_WRITEPTR, "01"),
        ],
        reg_seed=REMOTE_ACK_REG_SEED,
        stub_calls=REMOTE_STUB_CALLS,
        stop_at=REMOTE_ACK_STOP)
    _expect_stop(snap, REMOTE_ACK_STOP)
    accepted = int(snap["registers"]["r4"], 0)
    log(f"  Remote's real, unmodified 0xb59c retry/ack loop, given the real"
        f" ack byte 0x{ack_byte:02x}, returns {accepted} (1 = accepted)")
    assert accepted == 1, f"Remote did not accept the real acknowledgement: R4={accepted}"

    log("\nRound trip PASSED: Remote \"G\" request -> AutoPilot event 17 -> Remote accepts \"#\"")
    return True


def run_s_roundtrip(verbose=True):
    """The third acceptance scenario: Remote sends a real "S|" query ->
    AutoPilot schedules event 6 and builds a real "P..." response from its
    own concrete state -> Remote's real parser consumes and stores it. Run
    twice, at two different concrete AUTOPILOT_S_MODE values, to exercise
    both the short and extended response forms for real rather than
    asserting one and reading the other off the decompile. See
    docs/investigations/s-p-roundtrip.md.

    Returns a dict describing what was observed in each case (not just
    True/False) -- this transaction has no single pass/fail byte string to
    check against, and the point of the slice is the description, not a
    binary result."""
    def log(msg):
        if verbose:
            print(msg)

    log("=== Leg 1: Remote constructs its real S query ===")
    wire1, arg_ptr = capture_tx_bytes(
        MANDO_FW, REMOTE_S_ENTRY, REMOTE_TX_WRAPPER,
        reg_seed=[("r0", 0)],  # param_1=0: "do the full S-then-! sequence" (see s-p-roundtrip.md)
        stub_calls=[REMOTE_S_PREAMBLE_STUB, 0xb440])
    log(f"  Remote's real, unmodified 0xc440(0) calls 0x58a8 with a pointer to"
        f" flash 0x{arg_ptr:x}, bytes = {wire1!r}")
    assert wire1 == b"S|\x00", f"unexpected Remote S bytes: {wire1!r}"
    wire1_bytes = wire1[:-1]

    results = {}
    for mode, label in ((0, "short"), (4, "extended")):
        log(f"\n--- AUTOPILOT_S_MODE = {mode} ({label} response) ---")
        log("=== Leg 2a: AutoPilot receives it and schedules event 6 ===")
        packet = wire1_bytes.ljust(4, b"\x00")
        seed2a = [(AUTOPILOT_RX_BUFFER, packet.hex())]
        if mode:
            seed2a.append((AUTOPILOT_S_MODE, f"{mode:02x}"))
        snap2a = run_concrete(AUTOPILOT_FW, AUTOPILOT_RX_ENTRY, seed_mem=seed2a,
                               stop_at=AUTOPILOT_RX_EXIT,
                               dump_mem=[(AUTOPILOT_PENDING6, "1"), (AUTOPILOT_S_VALUE0, "1")])
        _expect_stop(snap2a, AUTOPILOT_RX_EXIT)
        pending6 = bytes.fromhex(snap2a["memory"][_norm(AUTOPILOT_PENDING6)])
        value0 = bytes.fromhex(snap2a["memory"][_norm(AUTOPILOT_S_VALUE0)])
        log(f"  AutoPilot's real, unmodified 0x8258 dispatcher (mode={mode}) sets"
            f" pending[6] = 0x{pending6.hex()}, value0 = 0x{value0.hex()}")
        assert pending6 == b"\x01", f"event 6 not scheduled: pending[6]={pending6!r}"

        log("=== Leg 2b: AutoPilot's outbound dispatcher builds its real \"P...\" response ===")
        seed2b = [
            (AUTOPILOT_PENDING6, pending6.hex()),
            (AUTOPILOT_S_VALUE0, value0.hex()),  # carried forward from leg 2a, not hardcoded
            (AUTOPILOT_SCAN_SLOT0, "06"),
            (AUTOPILOT_SCAN_COUNT, "01"),
            (AUTOPILOT_LAST_TS, "0000ffff"),
        ]
        if mode:
            seed2b.append((AUTOPILOT_S_MODE, f"{mode:02x}"))
        wire2, resp_ptr = capture_tx_bytes(AUTOPILOT_FW, AUTOPILOT_TX_ENTRY, AUTOPILOT_TX_WRAPPER,
                                            seed_mem=seed2b)
        log(f"  AutoPilot's real, unmodified 0x9268 dispatcher calls 0x8c10 with"
            f" a pointer to RAM 0x{resp_ptr:x}, bytes = {wire2!r}")
        wire2_bytes = wire2[:-1]  # the P-response is comma-self-terminating; the capture-side NUL never crosses the wire

        log("=== Leg 3: Remote's real parser consumes and stores it ===")
        reg_seed = [REMOTE_S_PARSE_REG_SEED[0]]
        if mode == 4:
            reg_seed.append(REMOTE_S_VALUE1_REG_SEED)  # only touched on the extended path -- see anchor comment above
        snap3 = run_concrete(
            MANDO_FW, REMOTE_S_PARSE_ENTRY, reg_seed=reg_seed,
            seed_mem=[
                (REMOTE_RX_RINGBUF, wire2_bytes.hex()),
                (REMOTE_RX_READPTR, "00"),
                (REMOTE_RX_WRITEPTR, f"{len(wire2_bytes):02x}"),
            ],
            stub_calls=[0xb440],
            stop_at=REMOTE_S_PARSE_STOP,
            dump_mem=[(REMOTE_S_STORED_STATE, "1"), (REMOTE_S_VALUE1_STORE, "4"), (REMOTE_S_BOOL_STORE, "1")])
        _expect_stop(snap3, REMOTE_S_PARSE_STOP)
        stored = bytes.fromhex(snap3["memory"][_norm(REMOTE_S_STORED_STATE)])
        stored_value1 = bytes.fromhex(snap3["memory"][_norm(REMOTE_S_VALUE1_STORE)])
        stored_bool = bytes.fromhex(snap3["memory"][_norm(REMOTE_S_BOOL_STORE)])
        log(f"  Remote's real, unmodified 0xc440 parser, given the real wire bytes"
            f" {wire2_bytes!r}, stores state=0x{stored.hex()}"
            f" value1={int.from_bytes(stored_value1, 'little', signed=True)}"
            f" bool=0x{stored_bool.hex()}")

        results[label] = {
            "mode": mode, "value0": value0.hex(), "response": wire2_bytes,
            "remote_stored_state": stored.hex(),
            "remote_stored_value1": int.from_bytes(stored_value1, "little", signed=True),
            "remote_stored_bool": stored_bool.hex(),
        }

    log("\nBoth response forms observed:")
    log(f"  short:    mode=0 -> value0=0x{results['short']['value0']} ->"
        f" response={results['short']['response']!r} -> Remote stores"
        f" state=0x{results['short']['remote_stored_state']}"
        f" (see s-p-roundtrip.md for why this value, from cold RAM, does not"
        f" change the Remote's own stored state)")
    log(f"  extended: mode=4 -> value0=0x{results['extended']['value0']} ->"
        f" response={results['extended']['response']!r} -> Remote stores"
        f" state=0x{results['extended']['remote_stored_state']},"
        f" value1={results['extended']['remote_stored_value1']},"
        f" bool=0x{results['extended']['remote_stored_bool']}")
    return results


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which == "ampersand":
        ok = run_ampersand_roundtrip()
    elif which == "g":
        ok = run_g_ack_roundtrip()
    elif which == "s":
        ok = bool(run_s_roundtrip())
    elif which == "all":
        ok = run_ampersand_roundtrip()
        print()
        ok = run_g_ack_roundtrip() and ok
        print()
        ok = bool(run_s_roundtrip()) and ok
    else:
        sys.exit(f"usage: {sys.argv[0]} [ampersand|g|s|all]")
    sys.exit(0 if ok else 1)
