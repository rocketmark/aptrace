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
them. Every step below runs on `tools/unicorn/concrete.py`'s
`ConcreteMachine` (the project's existing, sole concrete-execution
backend, now used as a reusable Python object -- one machine per
firmware image, reset between legs -- rather than a fresh
`run_concrete.py` subprocess per call; see concrete.py's own module
docstring for why). This module only orchestrates it; it adds no new
Unicorn/emulation logic.

Reusable primitives fall out of doing this for real, not a
transaction-specific script:

  capture_tx_bytes(...)   -- run a firmware's real code until it calls a
                             string-argument TX wrapper (the same `void
                             wrapper(char *s)` convention both firmwares'
                             TX wrappers use: AutoPilot's 0x8c10, Remote's
                             0x58a8), and return exactly the bytes it is
                             about to hand that wrapper -- in ONE real
                             Unicorn run (`dump_reg_pointee`: the register
                             the firmware computed as the argument is
                             read, and memory at that address dumped, in
                             the same stop). The pointer is still always
                             whatever the real firmware computed, never
                             pre-supplied; only the old "one run to learn
                             R0, a second to dump *R0" duplication is
                             gone (see concrete.py's module docstring,
                             point 2).

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

  call(...)/carry(...)   -- (used by run_plus_target_distance_roundtrip)
                             thin re-exports of concrete.py's ABI-correct
                             direct-function-call helper and its explicit,
                             logged state-carry-forward mechanism -- see
                             that scenario's own comments for what they
                             replaced (hand-picked SP/LR/trampoline
                             addresses, manual hex round-tripping between
                             runs).

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
    tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py bang     # !0|/!1| -> 11-field CSV only (the 11-vs-10 mismatch)
    tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py i        # I<channel><mode>| -> event-15 signed number only
    tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py i9i1     # I9|/I1| short forms -- distinct from I<channel><mode>| and each other
    tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py plus     # '+' -> motor target -> G mode-1 distance only
    tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py pb05     # PB05-low reload -> does it reach motor_move_commit__CUSTOM?
    tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py t-status # T-status frame -> does the Remote ever send anything back?
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from concrete import ConcreteMachine  # noqa: E402

REPO_ROOT = HERE.parent.parent

AUTOPILOT_FW = REPO_ROOT / "research/firmware/originals/firmware_autopilot868.bin"
MANDO_FW = REPO_ROOT / "research/firmware/originals/firmware_mando868.bin"

# Default MMIO window: covers the SAMD51 peripheral bridge (0x40000000+)
# used by both firmwares' startup/driver code paths -- see
# docs/investigations/mando-first-execution.md ("New harness capability").
MMIO_BASE = 0x40000000
MMIO_SIZE = 0x4000000

# One ConcreteMachine per firmware image, built once and reused across
# every leg of every transaction in this module -- see concrete.py's own
# module docstring for why (this used to be a fresh `run_concrete.py`
# subprocess -- fresh Uc instance, fresh firmware read, fresh memory map
# -- per single call). `run_concrete()` below always calls `.run(...)`
# with its default fresh=True, so this reuse is safe: every mapped
# mutable region a prior leg could have touched -- RAM, flash, the MMIO
# window, PPB -- is restored to pristine before every one of these calls
# (via ConcreteMachine's dirty-page tracking, not a blind re-zero),
# exactly replicating the old subprocess-per-call isolation, just
# without rebuilding the flash/RAM/MMIO mapping and re-reading the
# firmware file every time.
_machines = {}


def _machine_for(firmware):
    key = str(firmware)
    if key not in _machines:
        _machines[key] = ConcreteMachine(firmware, mmio_base=MMIO_BASE, mmio_size=MMIO_SIZE)
    return _machines[key]


def _norm(addr):
    """Match the JSON-snapshot key formatting this module's callers were
    already written against (f"0x{addr:08x}")."""
    if isinstance(addr, str):
        addr = int(addr, 0)
    return f"0x{addr:08x}"


def run_concrete(firmware, entry, seed_mem=(), reg_seed=(), stub_calls=(), stop_at=None,
                  dump_mem=(), max_instructions=5000,
                  mmio_base=MMIO_BASE, mmio_size=MMIO_SIZE, sp=None, dump_reg_pointee=()):
    """Run concretely on this firmware's shared, reusable ConcreteMachine
    (see `_machine_for`) and return a JSON-snapshot-shaped dict -- the
    same shape `tools/unicorn/run_concrete.py`'s CLI has always produced,
    so every scenario function below that does `probe["registers"]["r0"]`-
    style dict access is unaffected by this now talking to a Python
    library instead of a subprocess.

    'sp' overrides the default initial stack pointer (top of RAM, minus a
    small reserved trampoline page -- fine for ordinary entry points,
    which push before they read their own stack, but wrong for entering
    directly at a function that reads a 5th-or-later AAPCS stack argument
    at [sp+0] before any push of its own has run; `call()` below handles
    that case properly instead)."""
    machine = _machine_for(firmware)
    seed_mem_ints = [(a if isinstance(a, int) else int(a, 0), bytes.fromhex(d) if isinstance(d, str) else d)
                      for a, d in seed_mem]
    reg_seed_ints = [(name, v if isinstance(v, int) else int(v, 0)) for name, v in reg_seed]
    stub_calls_ints = [a if isinstance(a, int) else int(a, 0) for a in stub_calls]
    dump_mem_ints = [(a if isinstance(a, int) else int(a, 0), int(n)) for a, n in dump_mem]
    result = machine.run(
        entry if isinstance(entry, int) else int(entry, 0),
        sp=sp if sp is None or isinstance(sp, int) else int(sp, 0),
        reg_seed=reg_seed_ints, seed_mem=seed_mem_ints, stub_calls=stub_calls_ints,
        stop_at=[stop_at if isinstance(stop_at, int) else int(stop_at, 0)] if stop_at is not None else [],
        dump_mem=dump_mem_ints, dump_reg_pointee=dump_reg_pointee,
        max_instructions=max_instructions,
    )
    return result.to_dict()


class UnexpectedStopError(RuntimeError):
    """A scenario leg didn't stop/return the way it expected. Carries the
    full structured snapshot (a run_concrete()-style to_dict() snapshot,
    or a real RunResult for a call()-based leg) as `.snapshot`, so a
    caller can inspect stop reason, error, registers, recent PCs,
    requested memory, and watch/mmio/stub logs without rerunning the
    experiment by hand -- a failed leg here should be exactly as
    analyzable as a failed ConcreteMachine.run()/call() is on its own."""

    def __init__(self, message, snapshot):
        super().__init__(message)
        self.snapshot = snapshot


def _expect_stop(snap, stop_at):
    expected_stop = f"reached stop address {_norm(stop_at)}"
    if snap["stop_reason"] != expected_stop:
        raise UnexpectedStopError(
            f"expected to stop at 0x{int(stop_at):x}, got: {snap['stop_reason']}", snap)


def capture_tx_bytes(firmware, entry, tx_wrapper_entry, seed_mem=(), reg_seed=(),
                      stub_calls=(), max_instructions=5000, max_len=64, sp=None):
    """Run the real firmware from 'entry' until it reaches 'tx_wrapper_entry'
    (a `void wrapper(char *s)`-convention TX call, entered fresh -- not
    stepped into, so none of its own not-yet-modeled body runs), and
    return exactly the NUL-terminated bytes it is about to hand that
    wrapper -- in ONE real concrete run (`dump_reg_pointee`, see
    concrete.py's module docstring point 2): the register the firmware
    computed as the argument is read, and memory at that address dumped,
    at the same stop, instead of one run to learn R0 and a second to
    dump *R0. Does not assume or hardcode the content -- only the
    calling convention, which is independently confirmed for both of
    this project's string-argument TX wrappers (AutoPilot's 0x8c10:
    tx-hook-verification.md; Remote's 0x58a8: mando-first-execution.md).

    'stub_calls' lets a caller skip real-but-irrelevant driver-touching
    helpers encountered *before* reaching the wrapper (see
    docs/investigations/g-ack-roundtrip.md for a real case: the Remote's
    G-request builder calls a wake-up preamble, and the AutoPilot's G
    handler calls two logging/config helpers that dereference an
    uninitialized driver object -- neither affects the bytes handed to
    the TX wrapper, so both are safe to stub)."""
    probe = run_concrete(firmware, entry, seed_mem=seed_mem, reg_seed=reg_seed,
                          stub_calls=stub_calls, sp=sp,
                          stop_at=tx_wrapper_entry, max_instructions=max_instructions,
                          dump_reg_pointee=[("r0", max_len)])
    _expect_stop(probe, tx_wrapper_entry)
    arg_ptr = int(probe["reg_pointee"]["r0"]["pointer"], 0)
    raw = bytes.fromhex(probe["reg_pointee"]["r0"]["data"])
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


# --- '!' -> 11-field bulk CSV anchors (all independently confirmed by
# execution this pass; !0|/!1| are sent by the SAME 0xc440(0) routine as
# 'S', immediately after its own real "P..." response is fully drained --
# see docs/investigations/protocol-pipeline.md) -----------------------------

REMOTE_BANG_MODE_SELECTOR = 0x2000109b  # Remote's own !0|/!1| choice: 0 -> "!0|" (0xc63e's
                                          # literal 0x1c870), nonzero -> "!1|" (0xc566's own
                                          # fallthrough literal 0x1c86c) -- confirmed by reading
                                          # both literal-pool strings directly, not inferred from
                                          # the address names
REMOTE_BANG_PARSE_ENTRY = 0xc584         # past 0xc440's own S-response-wait timeout prologue
                                          # (0xc57c's first bytes-available check + its 199-tick
                                          # retry), right at the SAME real bytes-available
                                          # recheck (0xb4f8) whose result (0xc596: bne 0xc6b4)
                                          # is what actually branches into the real 10-field
                                          # parse loop -- entering here lets THAT real check
                                          # decide the branch, rather than this module picking it
REMOTE_BANG_FIELD10_DONE = 0xc87c        # reached immediately after the Remote's OWN 10th (and
                                          # final) `bl 0xb51c` call (0xc872) -- the exact point at
                                          # which "field 11" (AutoPilot's 11th emitted field) is,
                                          # if present, still sitting entirely unconsumed in the
                                          # RX ring buffer
REMOTE_BANG_DONE_FLAG = 0x2000195b       # set =1 by the Remote immediately after its 10th parse
                                          # call (0xc876-0xc87a) -- confirms the Remote considers
                                          # its own parse "done" at exactly 10 fields, not 11

AUTOPILOT_PENDING7 = 0x200025c3          # pending[7], the '!' bulk-CSV event (0x200025bc + 7,
                                          # same base every other pending[] constant in this
                                          # module uses)

AUTOPILOT_FIELD1_SOURCE = 0x200000ec     # event 7's field 1 = i32[here]/10, narrowed to u8
                                          # (research/autopilot_static_inventory/event7-schema.md).
                                          # From cold RAM this is 0, so field1=0 -- confirmed by
                                          # disassembly of the Remote's OWN field-1 consumer
                                          # (0xc6b4-0xc6cc: `bl 0xb51c; muls r0,#10; subs
                                          # r0,#0x65; movw r3,#0x74ca; cmp r0,r3; bhi 0xc9dc`) to
                                          # be OUTSIDE the Remote's own accepted range for that
                                          # field ([101,29999] on the *10 value, i.e. raw field1
                                          # must be >= 11) -- field1=0 sends the Remote down its
                                          # own real "value out of range" branch (0xc9dc), which
                                          # this harness cannot follow to completion (it calls,
                                          # among other things, into a formatting helper whose
                                          # state depends on C++ runtime global constructors this
                                          # harness never runs, since it never boots from
                                          # Reset_Handler -- see docs/harness/execution-model.md).
                                          # Seeded below to a representative in-range value so the
                                          # Remote's real 10-field happy-path parse is what gets
                                          # exercised; this is AutoPilot's own real 0x8c70 builder
                                          # computing field1 from this input, same as every other
                                          # already-seeded field in this scenario (scan slot,
                                          # last-timestamp) -- not a hardcoded response byte.

# The AutoPilot's REAL short "S" response ("P1,\0") that 0xc440(0) has
# already, for real, drained by the time it reaches REMOTE_BANG_PARSE_ENTRY
# -- see run_s_roundtrip's own "short" leg (mode=0, value0=1). Captured
# once here as a named constant, not re-derived per call, since re-running
# that leg adds nothing new to the '!' transaction itself.
REMOTE_BANG_PRIOR_S_RESPONSE = b"P1,"


def run_bang_bulk_csv_roundtrip(verbose=True):
    """The fifth acceptance scenario: Remote's real 0xc440(0) routine,
    having just drained a real AutoPilot "S"->"P1," response, sends a real
    "!0|"/"!1|" request -> AutoPilot schedules event 7 and builds its real
    11-field numeric CSV response from its own concrete state -> Remote's
    real parser consumes it. Directly resolves the previously-open "11-vs-10
    field mismatch" (docs/protocol/open-questions.md #2): confirms exactly
    what AutoPilot emits, exactly how many fields the Remote parses, and
    what state the Remote is left in afterward -- via real execution on
    both sides, not by re-reading the disassembly. Run for BOTH `!0|` and
    `!1|`: the AutoPilot-side dispatch check (0x87b2) never inspects the
    mode digit at all (confirmed by disassembly and by this scenario
    getting an IDENTICAL AutoPilot-side pending[7]/response for both), so
    any distinction is entirely Remote-side."""
    def log(msg):
        if verbose:
            print(msg)

    mando = _machine_for(MANDO_FW)
    results = {}
    for mode, label in ((0, "!0|"), (1, "!1|")):
        log(f"\n--- Remote mode selector (0x2000109b) = {mode} ({label}) ---")
        log("=== Leg 1a: Remote's real 0xc440(0) sends its own real \"S|\" request ===")
        # A real, full 0xc440 call (true entry, real prologue/SP) -- stopped
        # (never stubbed/skipped) at the FIRST real 0x58a8 call, exactly the
        # same "S|" send run_s_roundtrip's own leg 1 already independently
        # confirmed. Continuing from THIS real stop -- rather than re-
        # entering fresh mid-function at REMOTE_S_PARSE_ENTRY, which was
        # tried first and found to corrupt an unrelated real local-stack
        # write a few hundred instructions later (0xc568's `str r3,[sp,
        # #0x14]`, landing just past mapped RAM under the entry point's
        # default fresh stack pointer) -- keeps the SAME real, compiler-
        # allocated stack frame for the whole leg, not a fabricated one.
        leg1a = mando.run(
            REMOTE_S_ENTRY, reg_seed=[("r0", 0)],
            stub_calls=[REMOTE_S_PREAMBLE_STUB, 0xb440],
            stop_at=[REMOTE_TX_WRAPPER], dump_reg_pointee=[("r0", 8)],
            max_instructions=2000, label=f"bang-{label}-leg1a-s-send",
        ).expect_stop(REMOTE_TX_WRAPPER)
        _s_ptr, s_raw = leg1a.reg_pointee("r0")
        wire_s = s_raw.split(b"\x00", 1)[0] + b"\x00"
        log(f"  Remote's real, unmodified 0xc440 calls 0x58a8 with bytes = {wire_s!r}")
        assert wire_s == b"S|\x00", f"unexpected Remote S bytes: {wire_s!r}"

        log("\n=== Leg 1b: continuing the SAME real call, past its own real \"S\"->\"P1,\""
            " drain, Remote sends the real !<mode>| request ===")
        # Continuing (fresh=False) from the real LR/SP this SAME call's own
        # `bl 0x58a8` left behind -- never a fabricated resume point. The
        # ring buffer is seeded with AutoPilot's own real short-form "P1,"
        # response (run_s_roundtrip's own already-established finding for
        # AUTOPILOT_S_MODE=0), standing in for that response having really
        # arrived over the (unmodeled) radio link.
        leg1b = mando.run(
            leg1a.registers["lr"], fresh=False, sp=leg1a.registers["sp"],
            seed_mem=[
                (REMOTE_RX_RINGBUF, REMOTE_BANG_PRIOR_S_RESPONSE),
                (REMOTE_RX_READPTR, bytes([0])),
                (REMOTE_RX_WRITEPTR, bytes([len(REMOTE_BANG_PRIOR_S_RESPONSE)])),
                (REMOTE_BANG_MODE_SELECTOR, bytes([mode])),
            ],
            stub_calls=[0xb440], stop_at=[REMOTE_TX_WRAPPER], dump_reg_pointee=[("r0", 8)],
            max_instructions=5000, label=f"bang-{label}-leg1b-bang-send",
        ).expect_stop(REMOTE_TX_WRAPPER)
        _bang_ptr, bang_raw = leg1b.reg_pointee("r0")
        wire1 = bang_raw.split(b"\x00", 1)[0] + b"\x00"
        log(f"  Remote's real, unmodified 0xc440 calls 0x58a8 with bytes = {wire1!r}")
        assert wire1[:1] == b"!" and wire1[1:2] == str(mode).encode() and wire1[-2:] == b"|\x00", \
            f"unexpected Remote ! bytes for mode={mode}: {wire1!r}"
        wire1_bytes = wire1[:-1]

        log("\n=== Leg 2a: AutoPilot receives it and schedules event 7 ===")
        packet = wire1_bytes.ljust(4, b"\x00")
        pending7 = deliver_and_observe(
            AUTOPILOT_FW, AUTOPILOT_RX_ENTRY,
            seed_mem=[(AUTOPILOT_RX_BUFFER, packet.hex())],
            stop_at=AUTOPILOT_RX_EXIT,
            observe_addr=AUTOPILOT_PENDING7, observe_len=1)
        log(f"  AutoPilot's real, unmodified 0x8258 dispatcher (mode digit {mode!r} in the"
            f" wire packet, never inspected by the check at 0x87b2) sets pending[7] = 0x{pending7.hex()}")
        assert pending7 == b"\x01", f"event 7 not scheduled: pending[7]={pending7!r}"

        log("\n=== Leg 2b: AutoPilot's outbound dispatcher builds its real 11-field CSV ===")
        # 0x8c70 (the event-7 builder) re-reads AUTOPILOT_RX_BUFFER[1] itself
        # (a real, separate mode-digit re-read -- confirmed by disassembly at
        # 0x8c72-0x8c80 -- distinct from, and NOT gating, any of the 11
        # emitted fields) -- carried forward from leg 2a's own real packet,
        # not re-derived.
        wire2, resp_ptr = capture_tx_bytes(
            AUTOPILOT_FW, AUTOPILOT_TX_ENTRY, AUTOPILOT_TX_WRAPPER,
            seed_mem=[
                (AUTOPILOT_RX_BUFFER, packet.hex()),
                (AUTOPILOT_PENDING7, pending7.hex()),
                (AUTOPILOT_SCAN_SLOT0, "07"),
                (AUTOPILOT_SCAN_COUNT, "01"),
                (AUTOPILOT_LAST_TS, "0000ffff"),
                (AUTOPILOT_FIELD1_SOURCE, "c8000000"),  # 200 (LE) -> field1 = 200/10 = 20
            ])
        wire2_bytes = wire2[:-1]
        n_fields = wire2_bytes.count(b",")
        log(f"  AutoPilot's real, unmodified 0x9268 dispatcher calls 0x8c10 with a pointer to"
            f" RAM 0x{resp_ptr:x}, bytes = {wire2_bytes!r} ({n_fields} comma-terminated fields)")
        assert n_fields == 11, f"expected AutoPilot's real event-7 builder to emit 11 fields, got {n_fields}: {wire2_bytes!r}"

        log("\n=== Leg 3: continuing the SAME real call once more -- Remote's real parser"
            " consumes it. Does it drop, misalign, or ignore field 11? ===")
        # Same principle as Leg 1b: continuing (fresh=False) from leg1b's own
        # real LR/SP (right where its own `bl 0x58a8` -- the "!<mode>|" send
        # -- left off) keeps the ONE real, continuously-executing 0xc440
        # call/stack frame intact for the whole transaction. A fresh
        # re-entry at REMOTE_BANG_PARSE_ENTRY was tried first and hung; so
        # did this same real-LR/SP continuation, at first, in the identical
        # place -- the stack-continuity fix alone was NOT sufficient. The
        # actual cause was AUTOPILOT_FIELD1_SOURCE defaulting to cold-RAM 0:
        # the Remote's own field-1 range check (0xc6c0-0xc6cc) rejects it
        # and branches to its own real "out of range" handler (0xc9dc),
        # which this harness cannot run to completion (see
        # AUTOPILOT_FIELD1_SOURCE's own comment above). Seeding a
        # representative in-range field 1 (leg 2b, above) keeps the Remote
        # on its real 10-field happy-path parse, which is what this leg
        # actually needs to exercise. Even on that happy path, the real
        # call is genuinely expensive: it internally runs a large but
        # FINITE shared memset-style helper (0x196f8's byte-fill loop,
        # confirmed by raising the instruction budget until the run
        # completed on its own at ~34.7k instructions rather than hitting
        # the limit) -- a real, one-time buffer-clear cost, not a bug or
        # an infinite loop, analogous to the already-documented finite
        # SERCOM device-probe cost noted in docs/harness/roadmap.md.
        # max_instructions below is sized with headroom over that
        # measured real cost.
        leg3 = mando.run(
            leg1b.registers["lr"], fresh=False, sp=leg1b.registers["sp"],
            seed_mem=[
                (REMOTE_RX_RINGBUF, wire2_bytes),
                (REMOTE_RX_READPTR, bytes([0])),
                (REMOTE_RX_WRITEPTR, bytes([len(wire2_bytes)])),
            ],
            stub_calls=[0xb440], stop_at=[REMOTE_BANG_FIELD10_DONE],
            dump_mem=[(REMOTE_RX_READPTR, 1), (REMOTE_RX_WRITEPTR, 1), (REMOTE_BANG_DONE_FLAG, 1)],
            max_instructions=100000, label=f"bang-{label}-leg3-parse",
        ).expect_stop(REMOTE_BANG_FIELD10_DONE)
        readptr = leg3.mem(REMOTE_RX_READPTR, 1)[0]
        writeptr = leg3.mem(REMOTE_RX_WRITEPTR, 1)[0]
        done_flag = leg3.mem(REMOTE_BANG_DONE_FLAG, 1)[0]
        leftover = wire2_bytes[readptr:writeptr]
        log(f"  Remote's real, unmodified 0xc440 parser calls its decimal-field parser"
            f" (0xb51c) exactly 10 times, then sets its own \"parse done\" flag"
            f" (0x2000195b) = 0x{done_flag:02x}")
        log(f"  Real RX ring-buffer pointers at that instant: read=0x{readptr:x} write=0x{writeptr:x}"
            f" -- {writeptr - readptr} byte(s) left UNCONSUMED in the ring buffer: {leftover!r}")
        assert done_flag == 1, f"expected the Remote's own done-flag to be set, got 0x{done_flag:02x}"
        eleventh_field = wire2_bytes.split(b",")[10]
        assert leftover == eleventh_field + b",", \
            f"expected exactly field 11 ({eleventh_field!r}+',') left unconsumed, got {leftover!r}"

        results[label] = {
            "mode": mode, "request": wire1_bytes, "response": wire2_bytes,
            "n_fields_emitted": n_fields, "leftover_unconsumed": leftover,
        }

    log("\nBoth mode forms observed:")
    for label, r in results.items():
        log(f"  {label}: request={r['request']!r} -> response={r['response']!r}"
            f" ({r['n_fields_emitted']} fields) -> Remote leaves {r['leftover_unconsumed']!r} unconsumed")
    log("\nRESULT (the 11-vs-10 field mismatch, definitively resolved by real execution):")
    log("  AutoPilot's real 0x8c70 ALWAYS emits exactly 11 comma-terminated fields.")
    log("  The Remote's real 0xc440 parser calls its field parser (0xb51c) EXACTLY 10")
    log("  times, then unconditionally marks itself done (0x2000195b=1) and moves on --")
    log("  it never even attempts to read field 11. Field 11 + its trailing comma are")
    log("  NEITHER an error NOR silently discarded: they are left, byte-for-byte,")
    log("  sitting UNCONSUMED in the real RX ring buffer (write pointer stays ahead of")
    log("  read pointer by exactly len(field11)+1 bytes) -- real, persistent buffer")
    log("  state, not a crash and not a clean drop. Whether a LATER, unrelated read")
    log("  eventually treats these leftover bytes as the start of a different message")
    log("  (a real misalignment risk) depends on what the Remote does with the ring")
    log("  buffer between cycles -- not re-traced here (out of this scenario's scope,")
    log("  see docs/investigations/protocol-pipeline.md's Open items); what IS now")
    log("  concretely settled is that the byte-count mismatch is real, silent (no")
    log("  error/assert on either side), and identical for both !0| and !1|.")
    return results


# --- 'I<channel><mode>|' -> per-channel async state machine -> event 15
# signed-number response anchors (all independently confirmed by execution
# this pass; see docs/investigations/protocol-pipeline.md) -----------------

REMOTE_I_ENTRY = 0xb958                  # Remote's real, self-contained I<channel><mode>|
                                          # builder + response-wait loop (params: r0=channel
                                          # 0-3, r1=mode_param 0/1) -- unlike 0xc440 this is a
                                          # standalone routine with its own real prologue, so a
                                          # normal fresh entry is sufficient (no two-phase
                                          # resume needed for leg 1)
REMOTE_I_VALUE_STORE = 0x20001908        # Remote's real per-channel signed-value storage
                                          # (int32 array, index = channel*4) -- where 0xb958
                                          # writes the parsed event-15 response; confirmed by
                                          # decompile, distinct from I9|/I1|'s own 0x200027f0

AUTOPILOT_CHANNEL_MONITOR_ENTRY = 0x8a80 # channel_event_monitor__CUSTOM -- takes NO
                                          # parameters, internally scans all 4 channels'
                                          # 0x20002524[ch] state byte every call (this is the
                                          # real main-loop tick that notices state==5 and
                                          # completes the transaction; the RX dispatcher itself
                                          # only sets state=5, it does not schedule event 15)
AUTOPILOT_PENDING15 = 0x200025cb         # pending[15], the event-15 numeric-response event
                                          # (0x200025bc + 15, same pending[] base as every
                                          # other AUTOPILOT_PENDING* constant in this module)
AUTOPILOT_SELECTOR = 0x20002328          # "which channel is this response for" -- written
                                          # channel+1 by BOTH the RX handler (0x874a) and the
                                          # monitor (0x8a80's case 5, redundantly, same value)
                                          # -- read back (channel = SELECTOR-1) by the event-15
                                          # builder (0x8ddc) to index AUTOPILOT_LIVE_POSITION
AUTOPILOT_MODE_ARRAY = 0x200029d8        # per-channel mode byte -- written verbatim from the
                                          # wire's mode digit by the RX handler (0x8778-0x877a);
                                          # NOT re-inverted on the AutoPilot side, so it ends up
                                          # holding the OPPOSITE of the Remote's own mode_param
                                          # (see REMOTE_I_ENTRY's mode-digit inversion, below)

# Confirmed by decompiling 0xb958 (Remote's I builder): mode_param==0 sends
# wire digit '1', mode_param==1 sends wire digit '0' -- an intentional
# inversion on the SEND side only. The AutoPilot then stores that wire
# digit as-is into AUTOPILOT_MODE_ARRAY[channel] (0x8778-0x877a): no
# second inversion there. Net effect: AUTOPILOT_MODE_ARRAY[channel] ends
# up EQUAL to (1 - mode_param), not mode_param itself.


def run_i_channel_mode_roundtrip(verbose=True):
    """The sixth acceptance scenario: Remote's real 0xb958 builds and sends
    a real "I<channel><mode>|" request -> AutoPilot's real ASCII dispatcher
    (0x872e-0x877c) sets the per-channel state machine -> AutoPilot's real
    main-loop monitor (channel_event_monitor__CUSTOM, 0x8a80) notices state
    5, schedules event 15, and (mode-dependent) caches the live position ->
    AutoPilot's real event-15 builder (0x8ddc) emits a signed-decimal
    response sourced directly from AUTOPILOT_LIVE_POSITION[channel] ->
    Remote's real 0xb958 parses it and stores it in REMOTE_I_VALUE_STORE.
    Run for two representative (channel, mode) pairs -- not exhaustive
    (the task does not require all 8) -- chosen to cover both mode values
    and a non-zero channel."""
    def log(msg):
        if verbose:
            print(msg)

    mando = _machine_for(MANDO_FW)
    results = {}
    # (channel, mode_param, representative live-position value to seed)
    cases = [(0, 0, 12345), (2, 1, -777)]
    for channel, mode_param, live_pos in cases:
        label = f"I ch={channel} mode={mode_param}"
        log(f"\n--- {label} ---")
        log("=== Leg 1a: Remote's real 0xb958 sends its own real I<channel><mode>| request ===")
        leg1a = mando.run(
            REMOTE_I_ENTRY, reg_seed=[("r0", channel), ("r1", mode_param)],
            stub_calls=[0xb440],
            stop_at=[REMOTE_TX_WRAPPER], dump_reg_pointee=[("r0", 8)],
            max_instructions=3000, label=f"i-{label}-leg1a-send",
        ).expect_stop(REMOTE_TX_WRAPPER)
        _i_ptr, i_raw = leg1a.reg_pointee("r0")
        wire1 = i_raw.split(b"\x00", 1)[0] + b"\x00"
        log(f"  Remote's real, unmodified 0xb958 calls 0x58a8 with bytes = {wire1!r}")
        wire_mode_digit = chr(ord("1") if mode_param == 0 else ord("0"))
        assert wire1 == f"I{channel + 1}{wire_mode_digit}|".encode() + b"\x00", \
            f"unexpected Remote I bytes for channel={channel} mode={mode_param}: {wire1!r}"
        wire1_bytes = wire1[:-1]

        log("\n=== Leg 2a: AutoPilot receives it -- sets per-channel state, NOT the"
            " response itself (that's the monitor's job, leg 2b) ===")
        packet = wire1_bytes.ljust(4, b"\x00")
        result_2a = deliver_and_observe(
            AUTOPILOT_FW, AUTOPILOT_RX_ENTRY,
            seed_mem=[(AUTOPILOT_RX_BUFFER, packet.hex())],
            stop_at=AUTOPILOT_RX_EXIT,
            observe_addr=AUTOPILOT_S_MODE + channel, observe_len=1)
        state_val = result_2a
        log(f"  AutoPilot's real, unmodified 0x872e-0x877c handler sets"
            f" 0x20002524[{channel}] (per-channel state) = 0x{state_val.hex()}")
        assert state_val == b"\x05", f"expected state=5, got {state_val!r}"

        log("\n=== Leg 2b: AutoPilot's real main-loop monitor (0x8a80) notices state 5"
            " and schedules event 15 ===")
        # The dead gate (0x20001b14[channel], see docs/investigations/
        # motor-subsystem-unlock.md -- exhaustively confirmed never set
        # nonzero anywhere in this firmware image) is left at its real
        # cold-RAM value of 0, so the monitor's state-5 branch completes
        # immediately, exactly as it would on real hardware from a fresh
        # per-channel state. AUTOPILOT_LIVE_POSITION[channel] is seeded to
        # a representative real-looking value -- the monitor/builder only
        # READ it here, never compute it, so this stands in for whatever
        # the real position-tracking code has left there by the time a
        # user actually issues 'I' (out of scope for this transaction).
        live_pos_bytes = int(live_pos).to_bytes(4, "little", signed=True)
        result_2b = run_concrete(
            AUTOPILOT_FW, AUTOPILOT_CHANNEL_MONITOR_ENTRY,
            seed_mem=[
                (AUTOPILOT_S_MODE + channel, "05"),
                (AUTOPILOT_MODE_ARRAY + channel, f"{wire_mode_digit_to_int(wire_mode_digit):02x}"),
                (AUTOPILOT_LIVE_POSITION + channel * 4, live_pos_bytes.hex()),
            ],
            stop_at=0x8bc4,  # channel_event_monitor__CUSTOM's own real return point
            dump_mem=[
                (AUTOPILOT_PENDING15, 1), (AUTOPILOT_SELECTOR, 1),
                (AUTOPILOT_S_MODE + channel, 1),
                (AUTOPILOT_CH0_STRUCT + channel * 0x120 + 0x10, 4),
            ],
        )
        autopilot_mode_val = wire_mode_digit_to_int(wire_mode_digit)
        pending15 = bytes.fromhex(result_2b["memory"][_norm(AUTOPILOT_PENDING15)])
        selector = bytes.fromhex(result_2b["memory"][_norm(AUTOPILOT_SELECTOR)])
        state_after = bytes.fromhex(result_2b["memory"][_norm(AUTOPILOT_S_MODE + channel)])
        log(f"  AutoPilot's real, unmodified 0x8a80 monitor sets pending[15] = 0x{pending15.hex()},"
            f" selector (0x20002328) = 0x{selector.hex()} (channel+1), and resets its own"
            f" state byte back to 0x{state_after.hex()}")
        assert pending15 == b"\x01", f"event 15 not scheduled: pending[15]={pending15!r}"
        assert selector == bytes([channel + 1]), f"unexpected selector: {selector!r}"
        assert state_after == b"\x00", f"expected monitor to reset state to 0, got {state_after!r}"
        if autopilot_mode_val == 1:
            cached = bytes.fromhex(result_2b["memory"][
                _norm(AUTOPILOT_CH0_STRUCT + channel * 0x120 + 0x10)])
            log(f"  AutoPilot-side mode byte=1 (wire mode digit {wire_mode_digit!r}, from"
                f" Remote mode_param={mode_param} via the send-side inversion documented"
                f" above) -- monitor ALSO cached LIVE_POSITION[{channel}] into"
                f" CH0_STRUCT+0x10: {cached!r}")
        else:
            log(f"  AutoPilot-side mode byte=0 (wire mode digit {wire_mode_digit!r}, from"
                f" Remote mode_param={mode_param}) -- monitor does NOT cache into"
                f" CH0_STRUCT (mode-gated side effect only, does not affect the response)")

        log("\n=== Leg 2c: AutoPilot's outbound dispatcher builds its real signed-decimal"
            " event-15 response, sourced directly from AUTOPILOT_LIVE_POSITION[channel] ===")
        wire2, resp_ptr = capture_tx_bytes(
            AUTOPILOT_FW, AUTOPILOT_TX_ENTRY, AUTOPILOT_TX_WRAPPER,
            seed_mem=[
                (AUTOPILOT_PENDING15, pending15.hex()),
                (AUTOPILOT_SELECTOR, selector.hex()),
                (AUTOPILOT_LIVE_POSITION + channel * 4, live_pos_bytes.hex()),
                # Same real pending-event scan table the '!' scenario needed
                # (see AUTOPILOT_SCAN_SLOT0's own comment above) -- here
                # populated with event 15 instead of event 7.
                (AUTOPILOT_SCAN_SLOT0, "0f"),
                (AUTOPILOT_SCAN_COUNT, "01"),
                (AUTOPILOT_LAST_TS, "0000ffff"),
            ])
        wire2_bytes = wire2[:-1]
        log(f"  AutoPilot's real, unmodified 0x9268 dispatcher calls 0x8ddc, which calls"
            f" 0x8c10 with a pointer to RAM 0x{resp_ptr:x}, bytes = {wire2_bytes!r}")
        assert wire2_bytes == f"{live_pos},".encode(), \
            f"expected the response to be exactly LIVE_POSITION[{channel}]={live_pos} + ','," \
            f" got {wire2_bytes!r}"

        log("\n=== Leg 3: continuing the SAME real 0xb958 call -- Remote's real response"
            " parser consumes it and stores the signed value ===")
        leg3 = mando.run(
            leg1a.registers["lr"], fresh=False, sp=leg1a.registers["sp"],
            seed_mem=[
                (REMOTE_RX_RINGBUF, wire2_bytes),
                (REMOTE_RX_READPTR, bytes([0])),
                (REMOTE_RX_WRITEPTR, bytes([len(wire2_bytes)])),
            ],
            stub_calls=[0xb440],
            stop_at=[0xba52],  # 0xb958's own real, single shared epilogue --
                                # confirmed by disassembly to be reached by
                                # every response branch (literal '0', '-'
                                # signed, and generic multi-digit positive)
            dump_mem=[(REMOTE_I_VALUE_STORE + channel * 4, 4)],
            max_instructions=20000, label=f"i-{label}-leg3-parse",
        ).expect_stop(0xba52)
        stored = int.from_bytes(leg3.mem(REMOTE_I_VALUE_STORE + channel * 4, 4), "little", signed=True)
        ret_val = leg3.registers["r0"]
        log(f"  Remote's real, unmodified 0xb958 parser stores REMOTE_I_VALUE_STORE[{channel}]"
            f" = {stored} (r0 return code = {ret_val})")
        assert stored == live_pos, f"expected Remote to store {live_pos}, got {stored}"

        results[label] = {
            "channel": channel, "mode_param": mode_param,
            "request": wire1_bytes, "response": wire2_bytes, "stored_value": stored,
        }

    log("\nAll (channel, mode) cases observed:")
    for label, r in results.items():
        log(f"  {label}: request={r['request']!r} -> response={r['response']!r}"
            f" -> Remote stores REMOTE_I_VALUE_STORE[{r['channel']}]={r['stored_value']}")
    log("\nRESULT: the I<channel><mode>| response value is, in every case, exactly")
    log("  AutoPilot's real AUTOPILOT_LIVE_POSITION[channel] at the moment the real")
    log("  main-loop monitor (0x8a80) observes state==5 -- read directly, unmodified,")
    log("  by both the monitor's cache write (mode-gated) and the event-15 builder's")
    log("  own read (unconditional on mode). mode_param only controls whether the")
    log("  monitor ALSO caches that same value into CH0_STRUCT+0x10 as a side effect;")
    log("  it never changes WHICH value is reported back to the Remote.")
    return results


def wire_mode_digit_to_int(digit_char):
    return 1 if digit_char == "1" else 0


REMOTE_I9_I1_ENTRY = 0xb834              # Remote's OTHER, separate I-family sender -- fixed
                                          # "I9|" or "I1|" (no channel/mode digits at all),
                                          # chosen by comparing REMOTE_S_STORED_STATE (the
                                          # SAME cell the 'S' transaction stores value0 into,
                                          # see REMOTE_S_STORED_STATE's own comment above) to
                                          # 26: !=26 sends "I1|", ==26 sends "I9|". Structurally
                                          # near-identical to 0xb958 (same retry/timeout
                                          # shape, same shared decimal-parser 0xb51c), but a
                                          # genuinely distinct function with its own storage
                                          # (REMOTE_I9_I1_VALUE_STORE, below) -- confirmed by
                                          # decompile, not assumed from the naming alone.
REMOTE_I9_I1_VALUE_STORE = 0x200027f0     # single (non-per-channel) int -- matches
                                          # command-inventory.md's prior static finding


def run_i9_i1_short_form_check(verbose=True):
    """Resolves the previously-open I9|/I1| question (docs/protocol/
    command-inventory.md): are these the same protocol path as
    I<channel><mode>|, or genuinely different? Traces both real wire
    forms through the SAME real AutoPilot dispatcher used by the main
    'I' scenario above, with no assumptions about channel validity.

    Real finding: neither form carries a real mode digit (byte offset 2
    is the literal '|' in both, decoding to a garbage mode value of 76);
    "I1|" decodes to channel index 0 (in range) and completes exactly
    like I<channel=0><mode!=1>| -- but through 0xb834's own separate
    send/retry/storage code, not 0xb958's. "I9|" decodes to channel
    index 8 -- out of the monitor's real 4-channel (0-3) scan range --
    so AutoPilot's real 0x872e handler still writes STATE[8]/MODE[8]/
    SELECTOR=9 (a real, silent out-of-bounds array write into adjacent
    scratch RAM), but channel_event_monitor__CUSTOM's real loop never
    inspects index 8, so pending[15] is NEVER set: "I9|" is a genuine,
    silent protocol dead end on this firmware image -- the Remote's own
    0xb834 retries six times, times out, and gives up without ever
    storing a value into REMOTE_I9_I1_VALUE_STORE."""
    def log(msg):
        if verbose:
            print(msg)

    mando = _machine_for(MANDO_FW)
    results = {}
    for stored_state, label, expect_wire in ((26, "I9|", b"I9|\x00"), (0, "I1|", b"I1|\x00")):
        log(f"\n--- {label} (REMOTE_S_STORED_STATE={stored_state}) ---")
        leg1 = mando.run(
            REMOTE_I9_I1_ENTRY, seed_mem=[(REMOTE_S_STORED_STATE, bytes([stored_state]))],
            stub_calls=[0xb440], stop_at=[REMOTE_TX_WRAPPER], dump_reg_pointee=[("r0", 8)],
            max_instructions=3000, label=f"i9i1-{label}-send",
        ).expect_stop(REMOTE_TX_WRAPPER)
        _ptr, raw = leg1.reg_pointee("r0")
        wire = raw.split(b"\x00", 1)[0] + b"\x00"
        log(f"  Remote's real, unmodified 0xb834 calls 0x58a8 with bytes = {wire!r}")
        assert wire == expect_wire, f"unexpected {label} wire bytes: {wire!r}"

        packet = wire[:-1].ljust(4, b"\x00")
        snap = run_concrete(
            AUTOPILOT_FW, AUTOPILOT_RX_ENTRY,
            seed_mem=[(AUTOPILOT_RX_BUFFER, packet.hex())], stop_at=AUTOPILOT_RX_EXIT,
            dump_mem=[(AUTOPILOT_SELECTOR, 1), (0x20002524, 12), (AUTOPILOT_MODE_ARRAY, 12)],
            max_instructions=3000)
        selector = bytes.fromhex(snap["memory"][_norm(AUTOPILOT_SELECTOR)])
        channel_idx = selector[0] - 1
        log(f"  AutoPilot's real, unmodified 0x872e handler decodes this as channel index"
            f" {channel_idx} (SELECTOR={selector[0]}), a mode byte of 76 (from the literal"
            f" '|' at the position a real mode digit would occupy), and sets"
            f" 0x20002524[{channel_idx}] = 5 -- {'IN' if 0 <= channel_idx <= 3 else 'OUT OF'}"
            f" the monitor's real 0-3 channel range")

        monitor_snap = run_concrete(
            AUTOPILOT_FW, AUTOPILOT_CHANNEL_MONITOR_ENTRY,
            seed_mem=[(0x20002524 + channel_idx, "05"), (AUTOPILOT_SELECTOR, selector.hex())],
            stop_at=0x8bc4, dump_mem=[(AUTOPILOT_PENDING15, 1), (0x20002524 + channel_idx, 1)])
        pending15 = bytes.fromhex(monitor_snap["memory"][_norm(AUTOPILOT_PENDING15)])
        outcome = "scheduled" if pending15 == b"\x01" else "NEVER scheduled -- dead end"
        log(f"  AutoPilot's real, unmodified 0x8a80 monitor: pending[15] = 0x{pending15.hex()}"
            f" ({outcome})")

        results[label] = {"wire": wire[:-1], "channel_idx": channel_idx, "pending15": pending15}

    assert results["I9|"]["pending15"] == b"\x00", "expected I9| to be a real dead end"
    assert results["I1|"]["pending15"] == b"\x01", "expected I1| to complete (channel 0)"
    log("\nRESULT: I9| and I1| are genuinely DISTINCT from I<channel><mode>| (different")
    log("  sender/storage) AND from each other (I1| silently aliases channel 0's real")
    log("  dispatch path; I9| is a real, silent dead end -- SELECTOR=9 decodes to an")
    log("  out-of-bounds channel index the monitor's real 4-channel scan never visits,")
    log("  so pending[15] is never set and the Remote's own retry loop just times out).")
    return results


# --- '+' (Auto-Mode segment) -> motor target -> G mode-1 -> FUN_00006fd8
# distance anchors (all independently confirmed by execution this pass;
# see docs/investigations/plus-target-distance-roundtrip.md) -------------

REMOTE_PLUS_BUILD_ENTRY = 0x000049c4   # real '+' frame builder -- called
                                         # directly through concrete.py's
                                         # ConcreteMachine.call (ARM AAPCS:
                                         # its 5th argument, mode, is
                                         # placed on the stack automatically;
                                         # no hand-picked SP, no fabricated
                                         # LR -- see that helper's own
                                         # docstring for what this replaced).
                                         # UNLIKE every other Remote sender
                                         # this module captures,
                                         # FUN_000049c4 does NOT itself call
                                         # the TX wrapper (0x58a8); it only
                                         # builds the frame into the shared
                                         # buffer and returns, leaving its
                                         # real caller (FUN_0000e670/
                                         # FUN_0000c440) to hand it to 0x58a8
                                         # via a separate ack/retry call
                                         # (FUN_0000b59c) -- confirmed by
                                         # disassembly, not assumed.
REMOTE_PLUS_TX_BUFFER = 0x2000183c     # the shared outgoing-packet buffer
                                         # (also used by the G builder)
REMOTE_PLUS_RECORD0_DELTA = 0x20000b20  # Remote's own local per-channel
                                         # per-mode mirror struct, channel 0
                                         # record 0 (the A->B segment), +0x0
                                         # (delta) -- seeding this to a
                                         # nonzero value stands in for "the
                                         # user has already recorded a real
                                         # A->B segment," the same evidence
                                         # tier as REMOTE_G_WAKE_FLAG's own
                                         # precedent of seeding representative
                                         # prior state rather than tracing the
                                         # full jog-wheel chain from cold boot

AUTOPILOT_CH0_STRUCT = 0x20001b40      # the per-channel-per-mode motor
                                         # config struct, channel 0 (see
                                         # docs/investigations/
                                         # persistent-record-motor-target-mapping.md)
AUTOPILOT_PLUS_DISPLAY_STUB = 0xb216   # a real but irrelevant uninitialized-
                                         # display-object dereference inside
                                         # the '+' handler's own unconditional
                                         # display-refresh tail
AUTOPILOT_DIRTY_AREA = 0x20004144      # +0x1002 (dirty flag) sits at byte 3
                                         # of this 8-byte window -- see
                                         # docs/investigations/
                                         # dirty-flag-persistence.md

AUTOPILOT_G_MODE1_TARGET_STAGE = 0x2000201c  # FUN_00007e2c's own "this
                                               # cycle's resolved target"
                                               # staging array (mc4-transition.md)
AUTOPILOT_G_STATE_MACHINE_ENTRY = 0x00007e2c  # the real state machine that
                                                # reads a G request's real
                                                # channel/type digits and,
                                                # two calls later, calls the
                                                # real move-commit function
AUTOPILOT_G_STATE_MACHINE_STATE = 0x200025e0  # its own state byte (0/1/2)
AUTOPILOT_G_STATE_MACHINE_ARM = 0x200025e1    # the real arm byte a G
                                                # dispatch sets to 2 (confirmed
                                                # by disassembly at 0x83de,
                                                # part of the same real 'G'
                                                # handler g-ack-roundtrip.md
                                                # already exercises) --
                                                # seeded directly here to
                                                # avoid needing the real
                                                # MC4-unlocked main loop this
                                                # state machine is normally
                                                # driven from (a disclosed,
                                                # precisely-scoped harness
                                                # boundary, not a fabricated
                                                # distance -- see the
                                                # investigation doc's "what
                                                # this boundary discloses"
                                                # section)
AUTOPILOT_LIVE_POSITION = 0x20002064   # per-channel live position array
AUTOPILOT_MOVE_COMMITTED_FLAG = 0x20002524  # FUN_00006fd8's own "=1, on
                                              # committing a real move" flag
                                              # (i-command-motor-chain.md)
AUTOPILOT_FUN_00006fd8 = 0x00006fd8    # the real move-commit call
AUTOPILOT_G_DISPLAY_STUBS = (0xb23a, 0xb2fe)  # the state machine's own
                                                # unconditional display-
                                                # refresh calls -- same class
                                                # of stub as
                                                # AUTOPILOT_PLUS_DISPLAY_STUB


def run_plus_target_distance_roundtrip(verbose=True):
    """The fourth acceptance scenario, and the one this project's M6
    behavior-to-hardware provenance work has been building toward: a real
    Remote Auto-Mode '+' send drives a real AutoPilot motor target update
    that a real subsequent G-mode-1 request turns into a real, nonzero
    FUN_00006fd8 move-commit distance -- with every byte on the '+' side
    traced back to the Remote's own real frame builder (FUN_000049c4),
    not hand-constructed. See
    docs/investigations/plus-target-distance-roundtrip.md for the full
    write-up, including exactly which two steps are harness-seeded state
    (disclosed below) rather than observed real firmware output.

    Two disclosed, minimal harness boundaries (neither fabricates the
    resulting distance -- both are documented, narrowly-scoped inputs the
    real code then computes from):
      1. The Remote's own local per-channel record (REMOTE_PLUS_RECORD0_DELTA)
         is seeded with a representative prior "recorded A->B segment"
         value (500) -- standing in for jog-wheel-entered UI state this
         investigation did not re-derive from scratch (the same evidence
         tier as REMOTE_G_WAKE_FLAG elsewhere in this module).
      2. FUN_00007e2c (the G-mode-1 state machine) is entered directly and
         its own arm byte is seeded to the exact value (2) a real G
         dispatch is independently confirmed (by disassembly, at 0x83de)
         to set -- bypassing the real MC4-unlocked main loop this state
         machine is normally driven from, which costs far more
         instructions than this project's boot-recipe calibration budgets
         for (see docs/investigations/persistent-record-motor-target-mapping.md's
         own "exact remaining gap"). This does not affect the distance
         value itself, which is computed entirely from the real '+'-
         written AUTOPILOT_CH0_STRUCT state.
    """
    def log(msg):
        if verbose:
            print(msg)

    mando = _machine_for(MANDO_FW)
    autopilot = _machine_for(AUTOPILOT_FW)

    log("=== Leg 1: Remote's real '+' frame builder (FUN_000049c4) ===")
    # Reproduces FUN_0000c440's own real call exactly: confirm1=confirm2=1
    # (the universal invariant every real caller satisfies), channel=0,
    # param_4=0 (the real "loop over FUN_00004998(channel) segments"
    # branch), mode=0x62 (the only mode value confirmed, by AutoPilot-side
    # disassembly, to cross the ">50" threshold into FUN_00004ca8/
    # FUN_000043f0's compute+persist path). Called through
    # ConcreteMachine.call: no hand-picked SP, no manual [sp+0] write for
    # the 5th argument (mode) -- the ABI helper places it.
    call1 = mando.call(
        REMOTE_PLUS_BUILD_ENTRY,
        args=[1, 1, 0, 0, 0x62],
        seed_mem=[(REMOTE_PLUS_RECORD0_DELTA, b"\xf4\x01\x00\x00")],  # record0 (+0x0, delta) = 500
        dump_mem=[(REMOTE_PLUS_TX_BUFFER, 64)],
        label="leg1-plus-build",
    )
    if not call1.returned:
        raise UnexpectedStopError(
            f"FUN_000049c4 did not return cleanly: {call1.result.stop_reason}\n"
            f"recent PCs: {[hex(pc) for pc in call1.result.recent_pcs]}", call1.result)
    raw = call1.result.mem(REMOTE_PLUS_TX_BUFFER, 64)
    wire_plus = raw.split(b"\x00", 1)[0]
    log(f"  Remote's real, unmodified FUN_000049c4 builds: {wire_plus!r}")
    assert wire_plus.startswith(b"+") and wire_plus.endswith(b"|")
    assert b",500," in wire_plus, f"expected the seeded delta (500) in the real frame: {wire_plus!r}"

    log("\n=== Leg 2: AutoPilot's real '+' handler updates the real motor-config struct ===")
    # AUTOPILOT_RX_ENTRY (0x8a34) is the same already-established boundary
    # run_ampersand_roundtrip/run_g_ack_roundtrip/run_s_roundtrip all use --
    # no Reset_Handler boot needed. R0 (the dispatcher's own param_1) must
    # be seeded to the packet's real length -- '+'`s handler reads
    # packet[param_1-1] as part of a real retransmission-dedup guard that
    # the real receive loop would normally have set up.
    packet_plus = wire_plus.ljust(32, b"\x00")
    result_plus = autopilot.run(
        AUTOPILOT_RX_ENTRY,
        reg_seed=[("r0", len(wire_plus))],
        seed_mem=[(AUTOPILOT_RX_BUFFER, packet_plus)],
        stub_calls=[AUTOPILOT_PLUS_DISPLAY_STUB],
        stop_at=[0x8a38],
        dump_mem=[(AUTOPILOT_CH0_STRUCT, 0x120), (AUTOPILOT_DIRTY_AREA, 8)],
        max_instructions=200000,
        label="leg2-plus-deliver",
    ).expect_stop(0x8a38)
    ch0_struct = result_plus.mem(AUTOPILOT_CH0_STRUCT, 0x120)
    dirty_area = result_plus.mem(AUTOPILOT_DIRTY_AREA, 8)
    delta = int.from_bytes(ch0_struct[0x0:0x4], "little", signed=True)
    target = int.from_bytes(ch0_struct[0xc:0x10], "little", signed=True)
    dirty_flag = dirty_area[3]
    log(f"  AutoPilot's real, unmodified '+' handler computes: channel0 record0"
        f" delta(+0x0)={delta}, target(+0xc)={target}, dirty flag={dirty_flag}")
    assert delta == 500, f"expected the real wire delta (500), got {delta}"
    assert target == 500, f"expected the real computed target (500), got {target}"
    assert dirty_flag == 1, "expected the real '+' handler to dirty the persisted buffer"

    log("\n=== Leg 3: Remote's real G-request builder (channel=0, type=1) ===")
    wire_g, _ = capture_tx_bytes(
        MANDO_FW, REMOTE_G_BUILD_ENTRY, REMOTE_TX_WRAPPER,
        seed_mem=[(REMOTE_G_WAKE_FLAG, "01")],
        reg_seed=[("r0", 1), ("r1", 0)],  # (type=1, channel=0) -- confirmed by
                                            # the real wire byte order this
                                            # produces, opposite of
                                            # g-ack-roundtrip.md's own
                                            # unlabeled (0,0) baseline
        stub_calls=[0xb440],
    )
    wire_g = wire_g[:-1]
    log(f"  Remote's real, unmodified 0xb680 builds: {wire_g!r}")
    assert wire_g[:1] == b"G" and wire_g[-1:] == b"|"

    log("\n=== Leg 4: AutoPilot's real G-mode-1 state machine reaches FUN_00006fd8 ===")
    # FUN_00007e2c is a real, plain (non-loop-resident) function: called
    # once, it advances its own state 0->1 (resolving the real target from
    # AUTOPILOT_CH0_STRUCT into its staging array); called again, it
    # advances 1->2 and calls FUN_00006fd8 with that real, resolved
    # distance. Both calls read the G request's channel/type digits
    # directly from AUTOPILOT_RX_BUFFER, which Leg 3's real bytes are
    # seeded into once, before either call. Both are `.call()`s with no
    # arguments (this state machine takes none -- it reads its state from
    # RAM), so what's actually being exercised is `.call()`'s clean-
    # return/trampoline machinery on a *zero-argument* real function,
    # plus the explicit state-carry-forward below.
    #
    # ch0_struct_carried is explicit, visible state carry-forward
    # (priority 8): exactly the bytes Leg 2's own real execution produced
    # for AUTOPILOT_CH0_STRUCT, tagged 'carried:...' in every run's
    # applied_seeds log below -- never hand-picked, never re-derived.
    ch0_struct_carried = result_plus.carry(AUTOPILOT_CH0_STRUCT, 0x120, label="leg2-plus-deliver")
    packet_g = wire_g.ljust(16, b"\x00")
    common_seed = [
        (AUTOPILOT_RX_BUFFER, packet_g),
        (AUTOPILOT_G_STATE_MACHINE_ARM, b"\x02"),
        ch0_struct_carried,
        (AUTOPILOT_LIVE_POSITION, b"\x00\x00\x00\x00"),
    ]
    call_state0 = autopilot.call(
        AUTOPILOT_G_STATE_MACHINE_ENTRY,
        seed_mem=common_seed + [(AUTOPILOT_G_STATE_MACHINE_STATE, b"\x00")],
        stub_calls=list(AUTOPILOT_G_DISPLAY_STUBS),
        dump_mem=[(AUTOPILOT_G_MODE1_TARGET_STAGE, 4), (AUTOPILOT_G_STATE_MACHINE_STATE, 1)],
        max_instructions=5000,
        label="leg4-call1-state0",
    )
    if not call_state0.returned:
        raise UnexpectedStopError(
            f"FUN_00007e2c (state 0->1) did not return cleanly: {call_state0.result.stop_reason}\n"
            f"recent PCs: {[hex(pc) for pc in call_state0.result.recent_pcs]}", call_state0.result)
    staged_target = int.from_bytes(
        call_state0.result.mem(AUTOPILOT_G_MODE1_TARGET_STAGE, 4), "little", signed=True)
    state_after = call_state0.result.mem(AUTOPILOT_G_STATE_MACHINE_STATE, 1)[0]
    log(f"  Call 1 (state 0->1): resolves target={staged_target} from the real channel-0"
        f" struct, state -> {state_after}")
    assert staged_target == 500, f"expected the real resolved target (500), got {staged_target}"
    assert state_after == 1

    # The staging-array value call 1 itself just produced is carried
    # forward the same explicit way, not re-typed as a literal.
    staged_target_carried = call_state0.result.carry(AUTOPILOT_G_MODE1_TARGET_STAGE, 4, label="leg4-call1-state0")
    # This second call's real path reaches FUN_00006fd8 but does not
    # itself return from FUN_00007e2c until well after -- use `.run()`
    # with an explicit stop_at right at that call, rather than `.call()`'s
    # own wait-for-clean-return (which would run past the point this leg
    # actually wants to inspect).
    result_state1 = autopilot.run(
        AUTOPILOT_G_STATE_MACHINE_ENTRY,
        reg_seed=[("lr", autopilot.trampoline_addr | 1)],
        seed_mem=common_seed + [(AUTOPILOT_G_STATE_MACHINE_STATE, b"\x01"), staged_target_carried],
        stub_calls=list(AUTOPILOT_G_DISPLAY_STUBS),
        stop_at=[AUTOPILOT_FUN_00006fd8],
        max_instructions=5000,
        label="leg4-call2-state1-to-6fd8",
    ).expect_stop(AUTOPILOT_FUN_00006fd8)
    r = result_state1.registers
    channel, const_arg, distance, rate = r["r0"], r["r1"], r["r2"], r["r3"]
    if distance & 0x80000000:
        distance -= 1 << 32
    log(f"  Call 2 (state 1->2): FUN_00006fd8(channel={channel}, const=0x{const_arg:x},"
        f" distance={distance}, rate=0x{rate:x})")
    assert channel == 0
    assert distance == 500, f"expected FUN_00006fd8's real distance to equal the real '+' delta (500), got {distance}"
    assert abs(distance) > 8, "expected the real move-commit threshold to be crossed"

    log("\n=== Leg 5: FUN_00006fd8 itself takes the real move branch (not the <=8 no-op) ===")
    call_committed = autopilot.call(
        AUTOPILOT_FUN_00006fd8,
        args=[channel, const_arg, distance & 0xFFFFFFFF, rate],
        seed_mem=common_seed,
        stub_calls=list(AUTOPILOT_G_DISPLAY_STUBS),
        dump_mem=[(AUTOPILOT_MOVE_COMMITTED_FLAG, 1)],
        max_instructions=10000,
        label="leg5-fun6fd8",
    )
    if not call_committed.returned:
        raise UnexpectedStopError(
            f"FUN_00006fd8 did not return cleanly: {call_committed.result.stop_reason}\n"
            f"recent PCs: {[hex(pc) for pc in call_committed.result.recent_pcs]}", call_committed.result)
    committed = call_committed.result.mem(AUTOPILOT_MOVE_COMMITTED_FLAG, 1)[0]
    log(f"  FUN_00006fd8's own real distance-threshold check sets the move-committed"
        f" flag (0x20002524[0]) = {committed}")
    assert committed == 1, "expected the real move branch (not the documented <=8 no-op) to fire"

    log("\nEND-TO-END PATH CONFIRMED: real Remote '+' (delta=500) -> real AutoPilot"
        " target write -> real G mode-1 -> FUN_00006fd8 distance=500 (>8) -> real"
        " move-committed flag set. The subsequent phase-machine/timer/ISR/GPIO chain"
        " is the already independently concretely-proven path from"
        " motor-timer-survey.md and i-command-motor-chain.md, not re-verified this pass.")
    return True


def run_plus_interactive_no_commit_check(verbose=True):
    """Gap Resolution A (docs/replacement/autopilot-gap-audit.md): the
    interactive Auto-Mode '+' call sites (mode=0/0x14, action-command-
    map.md Part 3 / auto-mode-and-plus-command.md's sites A-D) were, until
    now, only disassembly-confirmed NOT to cross AutoPilot's '>50'
    compute+persist threshold -- never carried through a complete concrete
    execution to the resulting AutoPilot state, the way the mode=0x62
    bulk-push path already was (run_plus_target_distance_roundtrip, above).
    This closes that gap for the representative screen-5 call site (A/B),
    args (confirm1,confirm2,channel,param_4,mode) = (1,1,0,1,0x00).

    Reuses the SAME two disclosed harness boundaries as the bulk-push
    scenario above (same evidence tier, not a new shortcut):
      1. REMOTE_PLUS_RECORD0_DELTA seeded to 500 -- the identical,
         already-disclosed "a real Auto-Mode UI session already recorded
         this segment" stand-in run_plus_target_distance_roundtrip uses.
      2. AUTOPILOT_RX_ENTRY entered directly -- the same already-
         established boundary every command in this module uses (no
         Reset_Handler boot needed). This sidesteps the real, separately-
         documented blocker (motor-config-persistence.md's Open items):
         '+' 's own dispatch was never reached from a fresh boot in 250M+/
         80M+ instruction attempts, bottlenecked by an uncharacterized
         upstream hardware-probe cost -- entering directly at this
         boundary is the same technique that already avoided that
         blocker for the bulk-push leg, and is reused unchanged here.
    """
    def log(msg):
        if verbose:
            print(msg)

    mando = _machine_for(MANDO_FW)
    autopilot = _machine_for(AUTOPILOT_FW)

    log("=== Leg 1: Remote's real '+' frame builder, INTERACTIVE args (screen-5 site A/B) ===")
    # param_4==1's branch (unlike the bulk-push's param_4==0 branch) makes
    # two real calls to FUN_00014bb6 -> FUN_00014b92 -> a vtable dispatch
    # through *DAT_000053a0 (a real, uninitialized-in-this-scenario Remote
    # display/print object -- the identical shape and role as
    # AUTOPILOT_PLUS_DISPLAY_STUB on the AutoPilot side, below): a live
    # boot would have constructed this object; direct-entry (no
    # Reset_Handler) does not. Traced by disassembly before stubbing, not
    # guessed: FUN_00014b92's own body is `(**(code**)(*param_1+4))(...)`
    # -- a real virtual call whose vtable pointer is null here, crashing
    # at address 0x4 exactly as observed on the first unstubbed attempt.
    # Stubbing it is the same disclosed technique this project already
    # uses for the equivalent AutoPilot-side call, not a new shortcut.
    # FUN_00014c7a (a second, real display number-formatter -- traced the
    # same way: FUN_00014c7a -> FUN_00014c24/FUN_00014bc4, the latter
    # continuing into the same null-vtable print chain) is called right
    # after FUN_00014bb6 in this same branch and needs the identical
    # treatment, discovered by re-running after the first stub moved the
    # crash forward rather than resolving it -- not guessed in advance.
    REMOTE_PLUS_DISPLAY_STUBS = [0x14bb6, 0x14c7a]
    # param_4==1's own real wire-delta computation is
    # target_start(record+0x10) - target_computed(record+0xc) -- traced
    # directly from FUN_000049c4's disassembly, NOT REMOTE_PLUS_RECORD0_
    # DELTA's (+0x0) offset the bulk-push (param_4==0) branch uses; the
    # two branches read different fields of the same record. The record
    # base itself is further offset by a real, currently-cold Remote
    # "current segment index" byte (0x20001904, *pbVar5 in the
    # decompile) -- seeded to 1 (segment 1, the real value a first
    # recording naturally starts at) so the record resolves to
    # REMOTE_PLUS_RECORD0_DELTA's own base with zero offset, keeping
    # every seed address anchored to that one already-disclosed constant
    # rather than a second, freestanding one.
    REMOTE_PLUS_SEGMENT_INDEX = 0x20001904
    REMOTE_PLUS_RECORD0_TARGET_START = REMOTE_PLUS_RECORD0_DELTA + 0x10  # 0x20000b30
    call1 = mando.call(
        REMOTE_PLUS_BUILD_ENTRY,
        args=[1, 1, 0, 1, 0x00],
        seed_mem=[
            (REMOTE_PLUS_SEGMENT_INDEX, b"\x01"),
            (REMOTE_PLUS_RECORD0_TARGET_START, (500).to_bytes(4, "little")),  # target_start(+0x10) = 500; target_computed(+0xc) stays cold/0 -> delta = 500-0 = 500
        ],
        stub_calls=REMOTE_PLUS_DISPLAY_STUBS,
        dump_mem=[(REMOTE_PLUS_TX_BUFFER, 64)],
        label="gapA-leg1-plus-build-interactive",
    )
    if not call1.returned:
        raise UnexpectedStopError(
            f"FUN_000049c4 (interactive args) did not return cleanly: {call1.result.stop_reason}\n"
            f"recent PCs: {[hex(pc) for pc in call1.result.recent_pcs]}", call1.result)
    raw = call1.result.mem(REMOTE_PLUS_TX_BUFFER, 64)
    wire_plus = raw.split(b"\x00", 1)[0]
    log(f"  Remote's real, unmodified FUN_000049c4 (interactive args) builds: {wire_plus!r}")
    assert wire_plus.startswith(b"+") and wire_plus.endswith(b"|")

    log("\n=== Leg 2: AutoPilot's real '+' handler processes the interactive-mode frame ===")
    packet_plus = wire_plus.ljust(32, b"\x00")
    result_plus = autopilot.run(
        AUTOPILOT_RX_ENTRY,
        reg_seed=[("r0", len(wire_plus))],
        seed_mem=[(AUTOPILOT_RX_BUFFER, packet_plus)],
        stub_calls=[AUTOPILOT_PLUS_DISPLAY_STUB],
        stop_at=[0x8a38],
        dump_mem=[(AUTOPILOT_CH0_STRUCT, 0x120), (AUTOPILOT_DIRTY_AREA, 8)],
        max_instructions=200000,
        label="gapA-leg2-plus-deliver-interactive",
    ).expect_stop(0x8a38)
    ch0_struct = result_plus.mem(AUTOPILOT_CH0_STRUCT, 0x120)
    dirty_area = result_plus.mem(AUTOPILOT_DIRTY_AREA, 8)
    delta = int.from_bytes(ch0_struct[0x0:0x4], "little", signed=True)
    target = int.from_bytes(ch0_struct[0xc:0x10], "little", signed=True)
    valid = ch0_struct[0x44]
    dirty_flag = dirty_area[3]
    log(f"  AutoPilot's real, unmodified interactive '+' handler computes: channel0 record0"
        f" delta(+0x0)={delta}, target(+0xc)={target}, valid(+0x44)={valid}, dirty flag={dirty_flag}")

    # The load-bearing check this scenario exists to make concrete: the
    # wire-supplied delta IS written (the field-write path is
    # mode-independent), but the compute+persist threshold ('mode>50')
    # is NOT crossed by mode=0x00 -- so target and the dirty flag must
    # stay at their pre-'+' (cold, zeroed) state, unlike the mode=0x62
    # leg above (run_plus_target_distance_roundtrip) where target became
    # 500 and dirty became 1 for the identical delta.
    assert delta == 500, f"expected the real wire delta (500) to be written regardless of mode, got {delta}"
    assert target == 0, (
        f"interactive '+' (mode=0x00) computed a nonzero target ({target}) -- "
        f"this would mean the interactive path DOES cross the persist threshold, "
        f"contradicting the documented '>50' gate")
    assert dirty_flag == 0, (
        f"interactive '+' (mode=0x00) dirtied the persisted buffer (flag={dirty_flag}) -- "
        f"this would mean the interactive path DOES persist, contradicting the "
        f"documented '>50' gate")

    log("\nRESULT: the interactive '+' path (mode=0x00, screen-5 site A/B) writes the")
    log("wire-supplied delta into the real per-channel record but, confirmed now by")
    log("real execution (not just disassembly), does NOT compute a live target and")
    log("does NOT dirty the persisted buffer -- it cannot arm or commit a move by")
    log("itself. The one real path that does cross this threshold is the mode=0x62")
    log("bulk-push (see run_plus_target_distance_roundtrip, above), whose real")
    log("trigger is the Remote's own boot sequence or a post-reconnect re-arm")
    log("(FUN_0000c440) -- not any interactive Auto-Mode confirm click.")
    return True


# --- Manual Mode 0xF0/0xE0 binary jog frame: field layout and latch behavior
# (Gap Resolution B, docs/replacement/autopilot-gap-audit.md). Addresses
# resolved from ascii_dispatcher__CUSTOM's (0x8258) own literal pool via
# `tools/ghidra/aptrace_ghidra.py literal` (existing cached-project query,
# not a new whole-firmware analysis): -----------------------------------
AUTOPILOT_F0E0_THRESHOLD_TABLE = 0x20000180  # per-channel clamp ceiling,
                                               # same array motor-subsystem-
                                               # unlock.md already names
AUTOPILOT_F0E0_BUSY_GATE = 0x20001b14         # the already-documented,
                                               # "exhaustively dead" busy
                                               # gate -- 0xE0's handler reads
                                               # it (not a new writer) as its
                                               # own "first time" check
AUTOPILOT_F0E0_LATCH = 0x20001fdd             # 0xE0-only: per-channel byte,
                                               # 1 once a value has been
                                               # cached for this channel
AUTOPILOT_F0E0_CACHED_VALUE = 0x20001fe4      # 0xE0-only: per-channel int,
                                               # last value seen while latched
AUTOPILOT_F0E0_TIMESTAMP = 0x20001ff4         # 0xE0-only: per-channel int,
                                               # millis() at first-latch time
AUTOPILOT_JOG_HANDLER = 0x00005448            # under-threshold branch (both
                                               # 0xF0 and 0xE0)
AUTOPILOT_LIMIT_HANDLER = 0x00005274          # at/over-threshold branch
                                               # (both 0xF0 and 0xE0; mode=4)


def _f0e0_record(marker, channel, value, seq=1):
    """Builds one real-shaped 0xF0/0xE0 frame, N=1 record, matching the
    already-documented grammar exactly (manual-mode-and-limits.md /
    command-inventory.md): <marker><len=0x0B><FFx4><chan><sign+23bit><'|'><seq>.
    """
    sign = 1 if value < 0 else 0
    mag = abs(value) & 0x7FFFFF
    b7 = (sign << 7) | ((mag >> 16) & 0x7F)
    b8 = (mag >> 8) & 0xFF
    b9 = mag & 0xFF
    return bytes([marker, 0x0B, 0xFF, 0xFF, 0xFF, 0xFF, channel & 0xF, b7, b8, b9, 0x7C, seq])


def run_manual_mode_f0_e0_check(verbose=True):
    """Gap Resolution B (docs/replacement/autopilot-gap-audit.md). Answers,
    using AutoPilot's own real code (disassembly of the already-known
    dispatch entry, ascii_dispatcher__CUSTOM/0x8258, plus concrete
    delivery through the same AUTOPILOT_RX_ENTRY boundary every other
    command in this module uses):

      1. 0xE0's exact field layout: IDENTICAL to 0xF0's -- both read the
         same per-record 4-byte shape (channel nibble @ byte6, sign+23-bit
         magnitude @ bytes 7-9) from the same packet buffer, via the same
         loop-count formula off the packet's own length byte. Confirmed
         below by delivering byte-identical record payloads under each
         marker and observing identical (channel, value) decode.
      2. The state transition 0xE0 causes, beyond 0xF0: 0xE0 additionally
         maintains AUTOPILOT_F0E0_LATCH/_CACHED_VALUE/_TIMESTAMP per
         channel and uses them to SUPPRESS a repeat at-limit
         (FUN_00005274, mode=4) call once a channel is already latched --
         0xF0 has no such memory and calls one handler or the other on
         every record, every delivery, unconditionally.
      3/4/5. Dead-man/timeout: AUTOPILOT_F0E0_TIMESTAMP is written
         (millis() at first-latch time) but this module's existing cached
         xref data (tools/ghidra/aptrace_ghidra.py xrefs, same query this
         project already relies on for AUTOPILOT_F0E0_BUSY_GATE elsewhere)
         finds NO consumer of it anywhere in the image -- no other read of
         AUTOPILOT_F0E0_TIMESTAMP, AUTOPILOT_F0E0_LATCH, or
         AUTOPILOT_F0E0_CACHED_VALUE exists outside this same handler.
         Per the same evidentiary standard this project already applies
         to AUTOPILOT_F0E0_BUSY_GATE ("exhaustively dead, no other
         writer/reader found"), no dead-man/timeout mechanism is present
         in current evidence for either 0xF0 or 0xE0: once a frame stops
         arriving, the RX-driven handler simply does not run again -- there
         is no separate polling/decay logic to time out. This is a
         negative finding from the existing evidence base, not a new
         broad search.
    """
    def log(msg):
        if verbose:
            print(msg)

    autopilot = _machine_for(AUTOPILOT_FW)
    THRESHOLD = 100  # disclosed infrastructure seed: the real .data value
                       # of AUTOPILOT_F0E0_THRESHOLD_TABLE[0] is only
                       # established by Reset_Handler's .data copy, which
                       # this module's direct-RX-entry boundary (shared by
                       # every scenario in this file) does not run; seeding
                       # a concrete, disclosed value here only lets the
                       # ALREADY-REAL comparison instruction at 0x82a6/
                       # 0x830a take a deterministic, observable branch --
                       # it does not fabricate what either branch DOES.
    threshold_seed = (AUTOPILOT_F0E0_THRESHOLD_TABLE, THRESHOLD.to_bytes(4, "little"))

    log("=== Check 1: 0xF0, under-threshold value -> real FUN_00005448 (jog) call ===")
    frame = _f0e0_record(0xF0, channel=0, value=10)
    r = autopilot.run(
        AUTOPILOT_RX_ENTRY,
        reg_seed=[("r0", len(frame))],
        seed_mem=[(AUTOPILOT_RX_BUFFER, frame.ljust(32, b"\x00")), threshold_seed],
        stop_at=[AUTOPILOT_JOG_HANDLER, AUTOPILOT_LIMIT_HANDLER],
        max_instructions=5000,
        label="gapB-f0-under",
    )
    assert r.stopped_at(AUTOPILOT_JOG_HANDLER), f"expected 0xF0 under threshold to reach the jog handler, got {r.stop_reason}"
    log(f"  0xF0 value=10 (< {THRESHOLD}): FUN_00005448(channel={r.registers['r0']}, value={r.registers['r1']}) -- as predicted")
    assert (r.registers["r0"], r.registers["r1"]) == (0, 10)

    log("\n=== Check 2: 0xF0, over-threshold value -> real FUN_00005274(chan,4) (at-limit) call ===")
    frame = _f0e0_record(0xF0, channel=0, value=200)
    r = autopilot.run(
        AUTOPILOT_RX_ENTRY,
        reg_seed=[("r0", len(frame))],
        seed_mem=[(AUTOPILOT_RX_BUFFER, frame.ljust(32, b"\x00")), threshold_seed],
        stop_at=[AUTOPILOT_JOG_HANDLER, AUTOPILOT_LIMIT_HANDLER],
        max_instructions=5000,
        label="gapB-f0-over",
    )
    assert r.stopped_at(AUTOPILOT_LIMIT_HANDLER), f"expected 0xF0 over threshold to reach the at-limit handler, got {r.stop_reason}"
    log(f"  0xF0 value=200 (> {THRESHOLD}): FUN_00005274(channel={r.registers['r0']}, mode={r.registers['r1']}) -- as predicted")
    assert (r.registers["r0"], r.registers["r1"]) == (0, 4)

    log("\n=== Check 3: 0xE0, SAME under-threshold record bytes (marker swapped) -> SAME decode ===")
    frame_f0 = _f0e0_record(0xF0, channel=0, value=10)
    frame_e0 = _f0e0_record(0xE0, channel=0, value=10)
    assert frame_e0[1:] == frame_f0[1:], "0xE0's per-record bytes must be byte-identical to 0xF0's (only marker differs)"
    r = autopilot.run(
        AUTOPILOT_RX_ENTRY,
        reg_seed=[("r0", len(frame_e0))],
        seed_mem=[(AUTOPILOT_RX_BUFFER, frame_e0.ljust(32, b"\x00")), threshold_seed],
        stop_at=[AUTOPILOT_JOG_HANDLER, AUTOPILOT_LIMIT_HANDLER],
        max_instructions=5000,
        label="gapB-e0-under-cold",
    )
    assert r.stopped_at(AUTOPILOT_JOG_HANDLER), f"expected 0xE0 under threshold to also reach the jog handler, got {r.stop_reason}"
    log(f"  0xE0 value=10 (< {THRESHOLD}), byte-identical record to Check 1: FUN_00005448(channel={r.registers['r0']}, value={r.registers['r1']})")
    assert (r.registers["r0"], r.registers["r1"]) == (0, 10), "0xE0 decoded a different (channel, value) than 0xF0 from identical record bytes"
    log("  CONFIRMED: 0xE0's per-record field layout is byte-identical to 0xF0's.")

    log("\n=== Check 4: 0xE0, over-threshold value, cold latch -> FUN_00005274 fires once ===")
    frame_e0_over = _f0e0_record(0xE0, channel=0, value=200)
    r1 = autopilot.run(
        AUTOPILOT_RX_ENTRY,
        reg_seed=[("r0", len(frame_e0_over))],
        seed_mem=[(AUTOPILOT_RX_BUFFER, frame_e0_over.ljust(32, b"\x00")), threshold_seed],
        stop_at=[AUTOPILOT_JOG_HANDLER, AUTOPILOT_LIMIT_HANDLER, AUTOPILOT_RX_EXIT],
        dump_mem=[(AUTOPILOT_F0E0_LATCH, 1)],
        max_instructions=5000,
        label="gapB-e0-over-cold",
    )
    assert r1.stopped_at(AUTOPILOT_LIMIT_HANDLER), f"expected cold-latch 0xE0 over threshold to reach the at-limit handler, got {r1.stop_reason}"
    log(f"  Delivery 1 (cold latch): FUN_00005274(channel={r1.registers['r0']}, mode={r1.registers['r1']}) reached, as predicted.")
    latch_after_1 = r1.mem(AUTOPILOT_F0E0_LATCH, 1)[0]
    log(f"  AUTOPILOT_F0E0_LATCH[0] after delivery 1 = {latch_after_1} (unchanged by the at-limit branch itself -- see docstring)")

    log("\n=== Check 5: 0xE0, SAME over-threshold value, WITH latch pre-set -> FUN_00005274 suppressed ===")
    # Directly exercises the latch's real documented effect (0x831a's
    # `cbnz r2,0x8324`, skip-the-call branch) rather than relying on
    # delivery 1 alone to have set it -- a disclosed infrastructure seed
    # standing in for "a prior under-threshold record already latched
    # this channel," the real, documented way AUTOPILOT_F0E0_LATCH
    # becomes nonzero (0x834c, reached only from the under-threshold arm).
    r2 = autopilot.run(
        AUTOPILOT_RX_ENTRY,
        reg_seed=[("r0", len(frame_e0_over))],
        seed_mem=[(AUTOPILOT_RX_BUFFER, frame_e0_over.ljust(32, b"\x00")), threshold_seed,
                  (AUTOPILOT_F0E0_LATCH, b"\x01")],
        stop_at=[AUTOPILOT_JOG_HANDLER, AUTOPILOT_LIMIT_HANDLER, AUTOPILOT_RX_EXIT],
        max_instructions=5000,
        label="gapB-e0-over-latched",
    )
    assert r2.stopped_at(AUTOPILOT_RX_EXIT), (
        f"expected a pre-latched 0xE0 over-threshold record to skip BOTH handlers and "
        f"reach the loop's own exit, got {r2.stop_reason}")
    log("  With AUTOPILOT_F0E0_LATCH[0] pre-set to 1: NEITHER FUN_00005448 NOR")
    log("  FUN_00005274 is reached -- the record is silently skipped. CONFIRMED:")
    log("  0xE0's latch suppresses repeat at-limit calls; 0xF0 has no such memory")
    log("  (Check 2 re-fires FUN_00005274 unconditionally, every delivery).")

    log("\n=== Check 6: dead-man/timeout -- existing cached xref evidence, no new scan ===")
    for name, addr in (("AUTOPILOT_F0E0_TIMESTAMP", AUTOPILOT_F0E0_TIMESTAMP),
                        ("AUTOPILOT_F0E0_LATCH", AUTOPILOT_F0E0_LATCH),
                        ("AUTOPILOT_F0E0_CACHED_VALUE", AUTOPILOT_F0E0_CACHED_VALUE)):
        log(f"  {name} (0x{addr:x}): no consumer found in the existing cached static"
            f" export outside ascii_dispatcher__CUSTOM's own 0xE0 arm (per"
            f" `tools/ghidra/aptrace_ghidra.py xrefs autopilot868 0x{addr:x}`).")
    log("  CONCLUSION: no dead-man/timeout mechanism is present in current evidence.")
    log("  AUTOPILOT_F0E0_TIMESTAMP is written (millis() at first-latch time) but")
    log("  never read anywhere else -- motion is not automatically stopped or decayed")
    log("  when 0xF0/0xE0 frames stop arriving; the RX-driven handler simply does not")
    log("  run again until another frame is delivered.")
    return True


# --- PB05 config-reload -> motion-causality anchors (all independently
# confirmed by execution this pass; see
# docs/investigations/trigger-input-motion-causality.md) --------------------

AUTOPILOT_GATE1 = 0x20001b38          # already known: the '+' mode=0x62
                                        # finalize path's own real side effect
                                        # (trigger-input-symbolic-
                                        # reachability.md)
AUTOPILOT_GATE2 = 0x200000d8          # all-4-idle status; provenance-closed
                                        # value 9 (trigger-input-symbolic-
                                        # reachability.md Part 3) -- disclosed
                                        # here per that same precedent, not
                                        # re-derived live this pass (this
                                        # function's own idle-check is a
                                        # separate, not yet re-traced, branch)
AUTOPILOT_PERSIST_BUF = 0x20003145    # RAM staging buffer FUN_00004b64's
                                        # bulk-load (config_loader__CUSTOM)
                                        # reads from -- the SAME buffer
                                        # FUN_000043f0's real persist writes
                                        # through to (dirty-flag-
                                        # persistence.md), confirmed this
                                        # pass to carry a real '+' push's
                                        # target/delta forward into a later
                                        # reload with no NVM flush needed
PERSIST_LEN = 1660                     # covers persisted logical offsets
                                        # 0..1659 (Step A needs up to 1652)

AUTOPILOT_PHASE_RAMP_ENTRY = 0x00008e18  # phase_ramp_state_machine__CUSTOM's
                                           # own sound entry point (trigger-
                                           # input-concrete-path.md Part 9/10)
AUTOPILOT_MODE_FLAG = 0x20001fc0       # PA02 boot-time mode flag (2 = PA02 low)
AUTOPILOT_TR_ENABLE = 0x20003120       # trigger-status reporting enable (0 = default)
AUTOPILOT_PER_CHAN_DEVICE_STATE = 0x20002524  # 4 bytes; also the 0x8f98
                                                # path's own idle precondition
AUTOPILOT_PHASE_MODE = 0x20002318      # 4 bytes -- phase_ramp's OWN per-
                                         # channel arm/state byte (0=idle,
                                         # 1=armed, 2=compute+commit, ...).
                                         # Exhaustive xref found exactly 3
                                         # writers in the whole image: the
                                         # reload itself (writes 0), this
                                         # function's own internal self-
                                         # transitions (once already armed),
                                         # and exactly one OTHER command
                                         # handler (0x865a, part of the 'W'
                                         # command family, gated on GATE2 --
                                         # not GATE1/PB05) that is the SOLE
                                         # producer of the 0->1 (armed)
                                         # transition anywhere in this image.
AUTOPILOT_FLAG_2014 = 0x20002014       # 4 bytes; the reload's own real
                                         # writer, closing trigger-input-
                                         # concrete-path.md's own open
                                         # "0x20002014[channel]" question --
                                         # it CLEARS this to 0 for a valid
                                         # channel, it never sets it
AUTOPILOT_FLAG_310C = 0x2000310c       # 4 bytes -- a previously-uncharacterized
                                         # per-channel "has a nonzero delta"
                                         # flag the reload's own per-record
                                         # loop sets to 1; its only other
                                         # reference anywhere in the image is
                                         # a read inside motor_move_commit__
                                         # CUSTOM itself -- but since
                                         # AUTOPILOT_PHASE_MODE never reaches
                                         # 2 from this path, that reader is
                                         # never reached either
AUTOPILOT_STATUS_BYTE = 0x200025bc     # +1 becomes 3 at 0x8f98 (already known)
AUTOPILOT_TICK_VAR = 0x200052ec
AUTOPILOT_RATE_LAST_CHECK = 0x20002410
AUTOPILOT_PB05_MMIO = 0x410080a0       # PORT.GROUP1.IN
AUTOPILOT_PB05_BIT = 0x20              # bit 5
AUTOPILOT_PB3031_PULSE_MMIO = 0x41008094  # PORT.GROUP1.OUTCLR(+0)/OUTSET(+4);
                                            # the reload's own shared epilogue
                                            # (FUN_00006952, also called from
                                            # motor_move_commit__CUSTOM itself)
                                            # unconditionally pulses PB30
                                            # high / PB31 low here -- a real,
                                            # confirmed GPIO side effect,
                                            # distinct from any per-channel
                                            # step/DIR pin (motor-timer-
                                            # survey.md/pin-index-
                                            # provenance.md already named
                                            # those separately) and not
                                            # itself investigated further
                                            # this pass

WIRE_PLUS_500 = b"+1,1,1,0,98,1,0,0,0,500,0,0|"  # byte-identical to the
                                                    # already-proven real
                                                    # Remote frame (plus-
                                                    # target-distance-
                                                    # roundtrip.md)


def _hexb(b):
    return " ".join(f"{x:02x}" for x in b)


def run_pb05_reload_motion_check(verbose=True):
    """Does the PB05-low config-reload (trigger-input-symbolic-
    reachability.md's own confirmed 0x8f98 path) naturally cause motor
    motion, given a real, already-proven, non-blank persisted target
    sitting in the config it reloads from?

    Builds the SAME real predecessor state run_plus_target_distance_
    roundtrip's own Leg 1/2 already establishes (a real '+' mode=0x62
    bulk-push, delta=target=500 for channel 0) -- which, per trigger-
    input-symbolic-reachability.md, is *also* the real, already-proven
    producer of GATE1 (0x20001b38=0x7b), one of the two preconditions
    the PB05-low path itself needs. GATE2 (0x200000d8=9) is the OTHER
    precondition; its own provenance was closed by disassembly in that
    same investigation (an all-4-channels-idle check inside this same
    function) and is disclosed-seeded here rather than re-derived live,
    exactly as that investigation's own Unicorn replay did.

    Then runs phase_ramp_state_machine__CUSTOM (0x8e18, the already-
    established sound entry point) from that one real predecessor state
    twice, varying ONLY the genuinely external input (PB05's live level),
    and continues into a follow-up call simulating the next main-loop
    iteration -- looking, throughout, for whether execution ever reaches
    motor_move_commit__CUSTOM (0x00006fd8). A final, clearly-separated,
    explicitly-disclosed control (NOT part of the PB05 chain) confirms
    the state machine's own commit path is real and reachable in general
    by independently forcing the one byte this investigation found is
    missing -- so a negative result above is not mistaken for "the
    harness can't reach FUN_00006fd8 at all."
    """
    def log(msg):
        if verbose:
            print(msg)

    autopilot = _machine_for(AUTOPILOT_FW)

    log("=== Leg 1: real '+' delivery (byte-identical to plus-target-distance-roundtrip.md) ===")
    packet_plus = WIRE_PLUS_500.ljust(32, b"\x00")
    result_plus = autopilot.run(
        AUTOPILOT_RX_ENTRY,
        reg_seed=[("r0", len(WIRE_PLUS_500))],
        seed_mem=[(AUTOPILOT_RX_BUFFER, packet_plus)],
        stub_calls=[AUTOPILOT_PLUS_DISPLAY_STUB],
        stop_at=[0x8a38],
        dump_mem=[(AUTOPILOT_CH0_STRUCT, 0x120), (AUTOPILOT_DIRTY_AREA, 8),
                  (AUTOPILOT_GATE1, 4), (AUTOPILOT_PERSIST_BUF, PERSIST_LEN)],
        max_instructions=200000,
        label="pb05-leg1-plus-deliver",
    ).expect_stop(0x8a38)

    ch0 = result_plus.mem(AUTOPILOT_CH0_STRUCT, 0x120)
    delta = int.from_bytes(ch0[0x0:0x4], "little", signed=True)
    target = int.from_bytes(ch0[0xc:0x10], "little", signed=True)
    gate1 = result_plus.mem(AUTOPILOT_GATE1, 4)
    dirty = result_plus.mem(AUTOPILOT_DIRTY_AREA, 8)[3]
    log(f"  channel0 record0: delta={delta} target={target} dirty={dirty}; gate1={_hexb(gate1)}")
    assert delta == 500 and target == 500 and dirty == 1
    assert gate1[0] == 0x7b, f"expected the real '+' side effect gate1==0x7b, got {gate1.hex()}"

    ch0_carried = result_plus.carry(AUTOPILOT_CH0_STRUCT, 0x120, label="pb05-leg1-plus-deliver")
    gate1_carried = result_plus.carry(AUTOPILOT_GATE1, 4, label="pb05-leg1-plus-deliver")
    persist_carried = result_plus.carry(AUTOPILOT_PERSIST_BUF, PERSIST_LEN, label="pb05-leg1-plus-deliver")

    def base_seed(ch0=None):
        return [
            ch0 or ch0_carried, gate1_carried, persist_carried,
            (AUTOPILOT_PERSIST_BUF, b"\x01"),  # disclosed: config-loader
                                                 # already initialized this
                                                 # session (the lazy-init
                                                 # marker byte) -- a boot-
                                                 # completion fact every
                                                 # scenario reaching this
                                                 # deep into firmware
                                                 # operation implies, not a
                                                 # motion value
            (AUTOPILOT_MODE_FLAG, bytes([2])),
            (AUTOPILOT_TR_ENABLE, bytes([0])),
            (AUTOPILOT_PER_CHAN_DEVICE_STATE, bytes(4)),
            (AUTOPILOT_STATUS_BYTE, bytes(2)),
            (AUTOPILOT_RATE_LAST_CHECK, b"\x00\x00\x00\x00"),
        ]

    def run_phase_ramp(tag, pb05_high, tick, extra_seed, ch0=None):
        mmio_kw = {"mmio_force_bits": [(AUTOPILOT_PB05_MMIO, AUTOPILOT_PB05_BIT)]} if pb05_high \
            else {"mmio_clear_bits": [(AUTOPILOT_PB05_MMIO, AUTOPILOT_PB05_BIT)]}
        return autopilot.run(
            AUTOPILOT_PHASE_RAMP_ENTRY,
            seed_mem=base_seed(ch0) + [(AUTOPILOT_TICK_VAR, tick.to_bytes(4, "little"))] + list(extra_seed),
            reg_seed=[("lr", autopilot.trampoline_addr | 1)],
            stop_at=[autopilot.trampoline_addr, AUTOPILOT_FUN_00006fd8],
            watch_mem_write=[(AUTOPILOT_GATE2, 1), (AUTOPILOT_PHASE_MODE, 4),
                              (AUTOPILOT_FLAG_2014, 4), (AUTOPILOT_FLAG_310C, 4),
                              (AUTOPILOT_STATUS_BYTE, 2), (AUTOPILOT_PB3031_PULSE_MMIO, 8)],
            dump_mem=[(AUTOPILOT_PHASE_MODE, 4), (AUTOPILOT_FLAG_2014, 4),
                      (AUTOPILOT_FLAG_310C, 4), (AUTOPILOT_STATUS_BYTE, 2),
                      (AUTOPILOT_GATE2, 1), (AUTOPILOT_CH0_STRUCT, 0x120)],
            max_instructions=400000,
            label=f"pb05-{tag}",
            **mmio_kw,
        )

    def gpio_pulse_hits(r):
        return [h for h in r.mem_write_hits if h["range"].startswith(f"0x{AUTOPILOT_PB3031_PULSE_MMIO:08x}")]

    log("\n=== Leg 2: PB05 LOW -- the reload should fire ===")
    idle_seed = [(AUTOPILOT_PHASE_MODE, bytes(4)), (AUTOPILOT_FLAG_2014, bytes(4)),
                 (AUTOPILOT_FLAG_310C, bytes(4)), (AUTOPILOT_GATE2, bytes([9]))]
    r_low = run_phase_ramp("leg2-pb05-low", pb05_high=False, tick=10_000, extra_seed=idle_seed)
    status_low = r_low.mem(AUTOPILOT_STATUS_BYTE, 2)
    phase_mode_low = r_low.mem(AUTOPILOT_PHASE_MODE, 4)
    flag310c_low = r_low.mem(AUTOPILOT_FLAG_310C, 4)
    log(f"  stop_reason: {r_low.stop_reason}")
    log(f"  status bytes = {_hexb(status_low)} (+1==3 means 0x8f98/the reload really ran)")
    log(f"  PHASE_MODE after = {_hexb(phase_mode_low)}  0x2000310c after = {_hexb(flag310c_low)}")
    log(f"  GPIO (PB30/PB31) pulse hits: {len(gpio_pulse_hits(r_low))}")
    assert status_low[1] == 3, "expected the real 0x8f98 write (status byte -> 3) -- reload did not fire"
    assert not r_low.stopped_at(AUTOPILOT_FUN_00006fd8), \
        "unexpected: PB05-low reload alone reached motor_move_commit__CUSTOM"
    assert phase_mode_low[0] == 0, "expected PHASE_MODE to stay/return to idle (the reload never arms it)"
    assert flag310c_low[0] == 1, "expected the reload to flag channel0's cached nonzero delta"
    assert len(gpio_pulse_hits(r_low)) == 2, "expected the reload's own real PB30/PB31 pulse"

    log("\n=== Leg 3: PB05 HIGH -- same predecessor state, the control ===")
    r_high = run_phase_ramp("leg3-pb05-high", pb05_high=True, tick=10_000, extra_seed=idle_seed)
    status_high = r_high.mem(AUTOPILOT_STATUS_BYTE, 2)
    log(f"  stop_reason: {r_high.stop_reason}")
    log(f"  status bytes = {_hexb(status_high)}  mem_write_hits = {len(r_high.mem_write_hits)}")
    assert status_high[1] == 0, "expected PB05-high to NOT reach 0x8f98 (control failed)"
    assert not r_high.stopped_at(AUTOPILOT_FUN_00006fd8)
    assert len(gpio_pulse_hits(r_high)) == 0, "expected NO GPIO pulse when the reload doesn't fire"

    log("\n=== Leg 4: a second call, continuing from Leg 2's own post-reload state")
    log("    (simulating the next real main-loop iteration) ===")
    ch0_after_carried = r_low.carry(AUTOPILOT_CH0_STRUCT, 0x120, label="pb05-leg2-pb05-low")
    followup_seed = [
        r_low.carry(AUTOPILOT_PHASE_MODE, 4, label="pb05-leg2-pb05-low"),
        r_low.carry(AUTOPILOT_FLAG_2014, 4, label="pb05-leg2-pb05-low"),
        r_low.carry(AUTOPILOT_FLAG_310C, 4, label="pb05-leg2-pb05-low"),
        r_low.carry(AUTOPILOT_GATE2, 1, label="pb05-leg2-pb05-low"),
    ]
    r_followup = run_phase_ramp("leg4-followup", pb05_high=True, tick=20_000,
                                 extra_seed=followup_seed, ch0=ch0_after_carried)
    log(f"  stop_reason: {r_followup.stop_reason}")
    assert not r_followup.stopped_at(AUTOPILOT_FUN_00006fd8), \
        "unexpected: a follow-up call reached motor_move_commit__CUSTOM"

    log("\n=== Control (NOT part of the PB05 chain): the SAME post-reload state DOES")
    log("    reach motor_move_commit__CUSTOM once PHASE_MODE[0] is independently")
    log("    forced to 1 -- confirming arming is the only missing ingredient ===")
    armed_seed = [followup_seed[1], followup_seed[2], followup_seed[3],  # 0x20002014/0x2000310c/GATE2 carried
                  (AUTOPILOT_PHASE_MODE, bytes([1, 0, 0, 0]))]           # the ONE disclosed change
    r_arm1 = run_phase_ramp("control-call1", pb05_high=True, tick=20_000,
                             extra_seed=armed_seed, ch0=ch0_after_carried)
    phase_mode_armed = r_arm1.mem(AUTOPILOT_PHASE_MODE, 4)
    log(f"  call1 (mode 1->2): PHASE_MODE after = {_hexb(phase_mode_armed)}")
    assert phase_mode_armed[0] == 2, "expected the real mode 1->2 self-transition"
    r_arm2 = run_phase_ramp(
        "control-call2", pb05_high=True, tick=30_000,
        extra_seed=[followup_seed[1], followup_seed[2], followup_seed[3],
                    r_arm1.carry(AUTOPILOT_PHASE_MODE, 4, label="pb05-control-call1")],
        ch0=ch0_after_carried,
    ).expect_stop(AUTOPILOT_FUN_00006fd8)
    r = r_arm2.registers
    log(f"  call2 reached FUN_00006fd8(channel={r['r0']}, const=0x{r['r1']:x},"
        f" distance={r['r2'] - (1 << 32) if r['r2'] & 0x80000000 else r['r2']}, rate=0x{r['r3']:x})")

    log("\nRESULT: the PB05-low reload (real gate1, disclosed-provenance gate2, a real")
    log("non-blank persisted target) reaches 0x8f98 and reruns config_loader__CUSTOM +")
    log("its motion-profile compute for real -- but never arms PHASE_MODE, so neither")
    log("that call nor a follow-up ever reaches motor_move_commit__CUSTOM. The control")
    log("above confirms the ONLY missing ingredient is PHASE_MODE's own arm byte, whose")
    log("sole producer in this image (0x865a) is an unrelated command, not PB05.")
    return True


# --- T-status (AutoPilot -> Remote) feedback-loop anchors (all
# independently confirmed by execution this pass; see
# docs/investigations/trigger-status-remote-feedback.md) -------------------

REMOTE_T_DISPATCH_ENTRY = 0x00010ce4   # FUN_00010ce4, the Remote's real
                                         # per-byte inbound dispatcher --
                                         # same function already established
                                         # (mt-quick-setup-trigger.md /
                                         # bulk-push-trigger-provenance.md)
                                         # for MT/'a'-'x'/'B' handling; this
                                         # pass finds and closes its plain
                                         # 'T' branch (0x10f0a-0x10f32)
REMOTE_T_RADIO_REFILL_STUB = 0xb440    # the real radio-driver ring-buffer
                                         # refill step (called from the peek
                                         # helper FUN_0000b4f8) -- touches an
                                         # uninitialized driver object, the
                                         # same already-documented boundary
                                         # this project always stubs
                                         # (mando-first-execution.md);
                                         # irrelevant once the frame is
                                         # already placed in the ring buffer
REMOTE_T_FIELD1 = 0x200002e8           # T's first field (0 or 1023), stored
REMOTE_T_FIELD2 = 0x200027f8           # T's second field (0 or 1), stored
REMOTE_T_FLAG = 0x200027f9             # "a T frame was received" flag --
                                         # exhaustive xref: its only OTHER
                                         # reference anywhere in the image is
                                         # a read inside FUN_0000fa10 (a real
                                         # UI screen's own render loop, which
                                         # converts field1 into a scaled
                                         # display value -- field1*3300/1023
                                         # -- and redraws it in a color
                                         # selected by field2; no other
                                         # consumer exists)


def run_t_status_feedback_check(verbose=True):
    """Does the Remote's real handling of AutoPilot's T-status frame
    (`"T<0 or 1023>,<1 or 0>,|"`, trigger-input-concrete-path.md) ever send
    anything back -- the one thing that could close a firmware-only
    feedback loop back into the W-command family / phase_ramp_arm_byte /
    motor_move_commit__CUSTOM (trigger-input-motion-causality.md)?

    Delivers both real frame shapes the AutoPilot is confirmed to send
    directly into the Remote's real inbound ring buffer, entering at the
    real per-byte dispatcher (FUN_00010ce4) that already handles MT/'a'-
    'x'/'B' elsewhere in this project -- not a new entry convention.
    Watches for the Remote's own real string TX wrapper (0x58a8): if
    reached, the Remote sent something in response; if the function
    instead returns cleanly with nothing sent, the frame's whole effect
    is confined to the two storage cells (+ a UI redraw) this investigation
    found are its only real consumers anywhere in the image.
    """
    def log(msg):
        if verbose:
            print(msg)

    mando = _machine_for(MANDO_FW)

    def deliver(frame, tag):
        log(f"=== Delivering real frame {frame!r} into the Remote's real inbound dispatcher ===")
        seed = [
            (REMOTE_RX_RINGBUF, frame),
            (REMOTE_RX_READPTR, bytes([0])),
            (REMOTE_RX_WRITEPTR, bytes([len(frame)])),
            (REMOTE_T_FIELD1, (0xdeadbeef).to_bytes(4, "little")),  # sentinel
            (REMOTE_T_FIELD2, bytes([0xAA])),                        # so a
            (REMOTE_T_FLAG, bytes([0xAA])),                          # real write is unmistakable
        ]
        r = mando.run(
            REMOTE_T_DISPATCH_ENTRY,
            seed_mem=seed,
            reg_seed=[("lr", mando.trampoline_addr | 1)],
            stub_calls=[REMOTE_T_RADIO_REFILL_STUB],
            stop_at=[mando.trampoline_addr, REMOTE_TX_WRAPPER],
            dump_mem=[(REMOTE_T_FIELD1, 4), (REMOTE_T_FIELD2, 1),
                      (REMOTE_T_FLAG, 1), (REMOTE_RX_READPTR, 1)],
            max_instructions=20000,
            label=f"t-status-{tag}",
        )
        assert not r.stopped_at(REMOTE_TX_WRAPPER), \
            f"unexpected: the Remote sent something in response to a real T frame ({frame!r})"
        assert r.stopped_at(mando.trampoline_addr), \
            f"expected a clean return, got: {r.stop_reason}"
        field1 = int.from_bytes(r.mem(REMOTE_T_FIELD1, 4), "little", signed=True)
        field2 = r.mem(REMOTE_T_FIELD2, 1)[0]
        flag = r.mem(REMOTE_T_FLAG, 1)[0]
        readptr = r.mem(REMOTE_RX_READPTR, 1)[0]
        log(f"  field1={field1} field2={field2} flag={flag} readptr_after={readptr}"
            f" (frame len={len(frame)}, clean return, TX wrapper NOT reached)")
        return field1, field2, flag

    f1, f2, flag = deliver(b"T1023,0,|", "high")
    assert (f1, f2, flag) == (1023, 0, 1), f"expected (1023, 0, 1), got {(f1, f2, flag)}"
    f1, f2, flag = deliver(b"T0,1,|", "low")
    assert (f1, f2, flag) == (0, 1, 1), f"expected (0, 1, 1), got {(f1, f2, flag)}"

    log("\nRESULT: both real T-status frame shapes are parsed and stored for real,")
    log("with the real radio-driver refill (irrelevant once the frame is already")
    log("queued) stubbed -- and NEITHER delivery reaches the Remote's own TX")
    log("wrapper. The T-status path cannot be the missing motion-arm bridge: it")
    log("has no outbound consequence at all, firmware-confirmed, not inferred")
    log("from a timeout or absence.")
    return True


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which == "ampersand":
        ok = run_ampersand_roundtrip()
    elif which == "g":
        ok = run_g_ack_roundtrip()
    elif which == "s":
        ok = bool(run_s_roundtrip())
    elif which == "bang":
        ok = bool(run_bang_bulk_csv_roundtrip())
    elif which == "i":
        ok = bool(run_i_channel_mode_roundtrip())
    elif which == "i9i1":
        ok = bool(run_i9_i1_short_form_check())
    elif which == "plus":
        ok = run_plus_target_distance_roundtrip()
    elif which == "plus-interactive":
        ok = run_plus_interactive_no_commit_check()
    elif which == "manual-f0e0":
        ok = run_manual_mode_f0_e0_check()
    elif which == "pb05":
        ok = run_pb05_reload_motion_check()
    elif which == "t-status":
        ok = run_t_status_feedback_check()
    elif which == "all":
        ok = run_ampersand_roundtrip()
        print()
        ok = run_g_ack_roundtrip() and ok
        print()
        ok = bool(run_s_roundtrip()) and ok
        print()
        ok = bool(run_bang_bulk_csv_roundtrip()) and ok
        print()
        ok = bool(run_i_channel_mode_roundtrip()) and ok
        print()
        ok = bool(run_i9_i1_short_form_check()) and ok
        print()
        ok = run_plus_target_distance_roundtrip() and ok
        print()
        ok = run_plus_interactive_no_commit_check() and ok
        print()
        ok = run_manual_mode_f0_e0_check() and ok
        print()
        ok = run_pb05_reload_motion_check() and ok
        print()
        ok = run_t_status_feedback_check() and ok
    else:
        sys.exit(f"usage: {sys.argv[0]} [ampersand|g|s|bang|i|i9i1|plus|plus-interactive|manual-f0e0|pb05|t-status|all]")
    sys.exit(0 if ok else 1)
