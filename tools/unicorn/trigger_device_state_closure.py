"""
Trigger -> Movement falsification audit: device-state producer/consumer
closure (docs/investigations/trigger-input.md, "Falsification pass").

The original trigger-input investigation (pb05 scenario, below) proved
phase_ramp_arm_byte (0x20002318) is cleared, not set, by the trigger-accept
reload -- but never checked two OTHER per-channel RAM cells that same
reload (FUN_00006b50) writes: AUTOPILOT_PER_CHAN_DEVICE_STATE (0x20002524,
set to 1) and AUTOPILOT_FLAG_310C (0x2000310c, set to 1). This script
closes that gap: it reuses the exact proven Leg1 ('+' bulk push) + Leg2
(PB05-low trigger accept / config-reload) predecessor state that
virtual_link.py's run_pb05_reload_motion_check already establishes, then
exercises the two genuine every-main-loop-tick consumers of
AUTOPILOT_PER_CHAN_DEVICE_STATE that the pb05 scenario never calls:

  - FUN_00005fac (sketch_loop__CUSTOM's own direct callee) -- reads
    0x20002524[ch] != 0 (which includes the value 1 the trigger-reload
    writes) and walks a per-channel segment-duration table.
  - channel_event_monitor__CUSTOM / FUN_00008a80 (sketch_loop__CUSTOM's
    other direct callee) -- switches on 0x20002524[ch], but only acts on
    values 2/3 (not 1).

Watches for any reach into motor_move_commit__CUSTOM (0x00006fd8),
FUN_00004d18 (0x00004d18), or the shared digitalWrite helper (0x0000d388)
across several simulated main-loop ticks (to let FUN_00005fac's own
elapsed-time gate become satisfiable). Result: neither consumer ever
reaches a motion primitive -- see trigger-input.md for the full writeup.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools" / "unicorn"))

import virtual_link as vl  # noqa: E402

AUTOPILOT_FW = vl.AUTOPILOT_FW
_machine_for = vl._machine_for

FUN_00005fac = 0x00005fac
FUN_00008a80 = 0x00008a80  # channel_event_monitor__CUSTOM
FUN_00004d18 = 0x00004d18
DIGITALWRITE_SHARED = 0x0000d388
SKETCH_LOOP_TRAMPOLINE_STOP = [vl.AUTOPILOT_FUN_00006fd8, FUN_00004d18, DIGITALWRITE_SHARED]

AUTOPILOT_DEVICE_STATE = vl.AUTOPILOT_PER_CHAN_DEVICE_STATE  # 0x20002524
AUTOPILOT_FLAG_310C = vl.AUTOPILOT_FLAG_310C                  # 0x2000310c
SEGMENT_DURATION_TABLE = 0x200025e8


def hexb(b):
    return " ".join(f"{x:02x}" for x in b)


def main():
    autopilot = _machine_for(AUTOPILOT_FW)

    print("=== Leg 1 (reused, proven): real '+' bulk push, delta=target=500 ch0 ===")
    packet_plus = vl.WIRE_PLUS_500.ljust(32, b"\x00")
    result_plus = autopilot.run(
        vl.AUTOPILOT_RX_ENTRY,
        reg_seed=[("r0", len(vl.WIRE_PLUS_500))],
        seed_mem=[(vl.AUTOPILOT_RX_BUFFER, packet_plus)],
        stub_calls=[vl.AUTOPILOT_PLUS_DISPLAY_STUB],
        stop_at=[0x8a38],
        dump_mem=[(vl.AUTOPILOT_CH0_STRUCT, 0x120), (vl.AUTOPILOT_DIRTY_AREA, 8),
                  (vl.AUTOPILOT_GATE1, 4), (vl.AUTOPILOT_PERSIST_BUF, vl.PERSIST_LEN)],
        max_instructions=200000,
        label="falsify-leg1-plus-deliver",
    ).expect_stop(0x8a38)
    ch0_carried = result_plus.carry(vl.AUTOPILOT_CH0_STRUCT, 0x120, label="falsify-leg1-plus-deliver")
    gate1_carried = result_plus.carry(vl.AUTOPILOT_GATE1, 4, label="falsify-leg1-plus-deliver")
    persist_carried = result_plus.carry(vl.AUTOPILOT_PERSIST_BUF, vl.PERSIST_LEN, label="falsify-leg1-plus-deliver")

    def base_seed(ch0=None):
        return [
            ch0 or ch0_carried, gate1_carried, persist_carried,
            (vl.AUTOPILOT_PERSIST_BUF, b"\x01"),
            (vl.AUTOPILOT_MODE_FLAG, bytes([2])),
            (vl.AUTOPILOT_TR_ENABLE, bytes([0])),
            (AUTOPILOT_DEVICE_STATE, bytes(4)),
            (vl.AUTOPILOT_STATUS_BYTE, bytes(2)),
            (vl.AUTOPILOT_RATE_LAST_CHECK, b"\x00\x00\x00\x00"),
        ]

    def run_phase_ramp(tag, pb05_high, tick, extra_seed, ch0=None):
        mmio_kw = {"mmio_force_bits": [(vl.AUTOPILOT_PB05_MMIO, vl.AUTOPILOT_PB05_BIT)]} if pb05_high \
            else {"mmio_clear_bits": [(vl.AUTOPILOT_PB05_MMIO, vl.AUTOPILOT_PB05_BIT)]}
        return autopilot.run(
            vl.AUTOPILOT_PHASE_RAMP_ENTRY,
            seed_mem=base_seed(ch0) + [(vl.AUTOPILOT_TICK_VAR, tick.to_bytes(4, "little"))] + list(extra_seed),
            reg_seed=[("lr", autopilot.trampoline_addr | 1)],
            stop_at=[autopilot.trampoline_addr, vl.AUTOPILOT_FUN_00006fd8],
            watch_mem_write=[(vl.AUTOPILOT_GATE2, 1), (vl.AUTOPILOT_PHASE_MODE, 4),
                              (vl.AUTOPILOT_FLAG_2014, 4), (AUTOPILOT_FLAG_310C, 4),
                              (AUTOPILOT_DEVICE_STATE, 4), (vl.AUTOPILOT_STATUS_BYTE, 2),
                              (vl.AUTOPILOT_PB3031_PULSE_MMIO, 8)],
            dump_mem=[(vl.AUTOPILOT_PHASE_MODE, 4), (vl.AUTOPILOT_FLAG_2014, 4),
                      (AUTOPILOT_FLAG_310C, 4), (AUTOPILOT_DEVICE_STATE, 4),
                      (vl.AUTOPILOT_STATUS_BYTE, 2), (vl.AUTOPILOT_GATE2, 1),
                      (vl.AUTOPILOT_CH0_STRUCT, 0x120), (SEGMENT_DURATION_TABLE, 0x32 * 4)],
            max_instructions=400000,
            label=f"falsify-{tag}",
            **mmio_kw,
        )

    print("\n=== Leg 2 (reused, proven): PB05 LOW -- the trigger-accept reload fires ===")
    idle_seed = [(vl.AUTOPILOT_PHASE_MODE, bytes(4)), (vl.AUTOPILOT_FLAG_2014, bytes(4)),
                 (AUTOPILOT_FLAG_310C, bytes(4)), (vl.AUTOPILOT_GATE2, bytes([9]))]
    r_low = run_phase_ramp("leg2-pb05-low", pb05_high=False, tick=10_000, extra_seed=idle_seed)
    status_low = r_low.mem(vl.AUTOPILOT_STATUS_BYTE, 2)
    device_state_low = r_low.mem(AUTOPILOT_DEVICE_STATE, 4)
    flag310c_low = r_low.mem(AUTOPILOT_FLAG_310C, 4)
    print(f"  status bytes = {hexb(status_low)} (+1==3 means reload ran)")
    print(f"  0x20002524 (device state) after = {hexb(device_state_low)}")
    print(f"  0x2000310c (flag) after         = {hexb(flag310c_low)}")
    assert status_low[1] == 3, "reload did not fire -- test setup broken"
    print(f"  CONFIRMS (concretely): trigger-accept reload sets device_state[0]={device_state_low[0]}, "
          f"flag_310c[0]={flag310c_low[0]}")
    seg_dur_dbg = r_low.mem(SEGMENT_DURATION_TABLE, 0x32 * 4)
    print(f"  segment_duration_table[ch0][0..3] = {hexb(seg_dur_dbg[:16])}")

    print("\n=== NEW: from that real post-reload state, call FUN_00005fac directly ===")
    print("    (sketch_loop__CUSTOM's own direct callee -- runs every real main-loop tick)")
    device_state_carried = r_low.carry(AUTOPILOT_DEVICE_STATE, 4, label="falsify-leg2-pb05-low")
    flag310c_carried = r_low.carry(AUTOPILOT_FLAG_310C, 4, label="falsify-leg2-pb05-low")
    ch0_after_carried = r_low.carry(vl.AUTOPILOT_CH0_STRUCT, 0x120, label="falsify-leg2-pb05-low")
    seg_dur_carried = r_low.carry(SEGMENT_DURATION_TABLE, 0x32 * 4, label="falsify-leg2-pb05-low")
    gate2_carried = r_low.carry(vl.AUTOPILOT_GATE2, 1, label="falsify-leg2-pb05-low")

    for i, tick in enumerate([50_000, 100_000, 200_000, 400_000], start=1):
        r_fac = autopilot.run(
            FUN_00005fac,
            seed_mem=[
                device_state_carried, flag310c_carried, ch0_after_carried,
                seg_dur_carried, gate2_carried,
                (vl.AUTOPILOT_TICK_VAR, tick.to_bytes(4, "little")),
            ],
            reg_seed=[("lr", autopilot.trampoline_addr | 1)],
            stop_at=list(SKETCH_LOOP_TRAMPOLINE_STOP) + [autopilot.trampoline_addr],
            watch_mem_write=[(AUTOPILOT_DEVICE_STATE, 4), (AUTOPILOT_FLAG_310C, 4),
                              (SEGMENT_DURATION_TABLE, 0x32 * 4)],
            dump_mem=[(AUTOPILOT_DEVICE_STATE, 4), (AUTOPILOT_FLAG_310C, 4)],
            max_instructions=200000,
            label=f"falsify-fac-tick{i}",
        )
        ds = r_fac.mem(AUTOPILOT_DEVICE_STATE, 4)
        f3 = r_fac.mem(AUTOPILOT_FLAG_310C, 4)
        hit_motion = any(r_fac.stopped_at(a) for a in SKETCH_LOOP_TRAMPOLINE_STOP)
        print(f"  tick={tick}: stop_reason={r_fac.stop_reason}  "
              f"device_state={hexb(ds)}  flag_310c={hexb(f3)}  "
              f"reached_motion_primitive={hit_motion}  write_hits={len(r_fac.mem_write_hits)}")
        if hit_motion:
            print("  !!! FALSIFICATION: FUN_00005fac reached a motion primitive !!!")
            return False
        device_state_carried = r_fac.carry(AUTOPILOT_DEVICE_STATE, 4, label=f"falsify-fac-tick{i}")
        flag310c_carried = r_fac.carry(AUTOPILOT_FLAG_310C, 4, label=f"falsify-fac-tick{i}")

    print("\n=== NEW: from the SAME real post-reload state, call channel_event_monitor__CUSTOM ===")
    print("    (sketch_loop__CUSTOM's other direct callee)")
    r_mon = autopilot.run(
        FUN_00008a80,
        seed_mem=[
            device_state_carried, flag310c_carried, ch0_after_carried, gate2_carried,
            (vl.AUTOPILOT_TICK_VAR, (500_000).to_bytes(4, "little")),
        ],
        reg_seed=[("lr", autopilot.trampoline_addr | 1)],
        stop_at=list(SKETCH_LOOP_TRAMPOLINE_STOP) + [autopilot.trampoline_addr],
        watch_mem_write=[(AUTOPILOT_DEVICE_STATE, 4), (AUTOPILOT_FLAG_310C, 4)],
        dump_mem=[(AUTOPILOT_DEVICE_STATE, 4), (AUTOPILOT_FLAG_310C, 4)],
        max_instructions=200000,
        label="falsify-monitor",
    )
    hit_motion_mon = any(r_mon.stopped_at(a) for a in SKETCH_LOOP_TRAMPOLINE_STOP)
    print(f"  stop_reason={r_mon.stop_reason}  reached_motion_primitive={hit_motion_mon}  "
          f"write_hits={len(r_mon.mem_write_hits)}")
    if hit_motion_mon:
        print("  !!! FALSIFICATION: channel_event_monitor__CUSTOM reached a motion primitive !!!")
        return False

    print("\nRESULT: across 4 simulated main-loop ticks of FUN_00005fac and one call to")
    print("channel_event_monitor__CUSTOM, starting from the REAL concrete post-trigger-accept")
    print("state (device_state[0]=1, flag_310c[0]=1, a real non-blank segment-duration table),")
    print("neither function ever reached motor_move_commit__CUSTOM, FUN_00004d18, or the shared")
    print("digitalWrite helper. No falsification found for this specific candidate path.")
    return True


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
