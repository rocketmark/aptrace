#!/usr/bin/env python3
"""Concrete Unicorn experiments for the trigger-input transient-propagation
investigation (docs/investigations/trigger-input-transient-propagation.md).

Three experiments against the REAL, UNMODIFIED firmware (no patch -- this
is observation, not the mitigation-patchability slice's candidate patch):

1. adc_baseline_experiment(): synthetic ADC sample streams fed into the
   already-known DEAD 128-sample boot-time baseline routine
   (FUN_00005d44 -> analogRead_wrapper -> FUN_0000d1b4), to check whether
   any transient shape reaches anything beyond the already-documented
   dead RAM (trigger-input-concrete-path.md Part 4).

2. analog_live_gate_experiment(): the SAME synthetic streams fed into a
   real, previously-uncharacterized LIVE consumer this investigation
   found: phase_ramp_state_machine__CUSTOM's "analog arm" (0x8e68-0x8f98),
   reached on every poll when *0x20001fc0 (mode_flag) == 1 (PA02 read
   HIGH at boot). Every poll calls analogRead(PB05) fresh (no averaging,
   no rate limit on the read itself) and:
     - compares the live raw ADC value against two RAM threshold cells
       (0x200000a8 upper, 0x200000c0 lower) to decide a real accept/
       reject outcome into the SAME config-reload target (0x8f98) the
       digital arm's second gate reaches, when TR-reporting is disarmed
       (0x20003120==0, TR0|, the default);
     - OR, when TR-reporting is armed (TR1|), builds and sends a real
       "T<raw ADC decimal>,<0 or 1>,|" frame via the real TX wrapper
       (0x8c10), rate-limited to ~500 ticks -- structurally the analog
       counterpart of the already-documented digital T-status frame.

3. digital_matrix_experiment(): the task's required H/L sequences injected
   into the digital arm (mode_flag==2), under both TR0 (accept-gate) and
   TR1 (T-status-send) contexts, in "startup" (rate limit pre-satisfied)
   and "runtime" (rate limit freshly consumed, cannot re-fire within the
   same sequence) framings.

All three share one poll_once() helper, entering at the function's own
real, already-established sound entry point (0x8e18 --
trigger-input-concrete-path.md Part 9/10: r4,r5,r8,r9 are freshly loaded
in the real prologue, no fabricated registers needed) with an explicit SP
reset every poll (this script does NOT rely on stack state surviving
across separate main-loop-iteration-equivalent calls, matching how the
real main loop calls this function fresh each iteration -- FUN_000093fc,
g-command-motor-subsystem-unlock.md).

Every patch/seed is delivered through run()'s own seed_mem (never a
direct pre-run mem_write), per this project's own documented lesson
(trigger-input-mitigation-patchability.md's "a real bug this prototype's
own first attempt hit").
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from concrete import ConcreteMachine  # noqa: E402
from unicorn import UC_HOOK_CODE  # noqa: E402

FIRMWARE = Path(__file__).parent.parent.parent / "research/firmware/originals/firmware_autopilot868.bin"

# -- real, already-confirmed addresses -------------------------------------
FUNC_ENTRY = 0x8e18          # phase_ramp_state_machine__CUSTOM's own real start
TX_WRAPPER = 0x8c10          # already-proven TX wrapper (stop here, don't model its body)
ACCEPT_TARGET = 0x8f98       # config-reload tail-jump (shared by BOTH digital and analog arms)
REJECT_TARGET = 0x9232       # shared "no-op" epilogue

MODE_FLAG = 0x20001fc0       # 1 = PA02 HIGH at boot (analog arm), 2 = PA02 LOW (digital arm)
TR_ENABLE = 0x20003120       # TR0|/TR1|
R5_BASE = 0x20002524         # per-channel device-state array (must be 0,0,0,0 -- idle)
GATE_CELL_1 = 0x20001b38     # must == 0x7b
GATE_CELL_2 = 0x200000d8     # must == 9
RATE_LIMIT_LAST_CHECK = 0x20002410   # shared by BOTH arms' T-status send gate

# -- NEW this slice: the live analog arm's own RAM -------------------------
LIVE_ADC_VALUE = 0x20000190       # raw analogRead(PB05) result, every poll
SENSITIVITY_SELECTOR = 0x20000194  # 0=custom(unchanged)/1=preset A/2=preset B; default (blank
                                    # persisted config) resolves to 1 via boot_config_reader__CUSTOM
THRESHOLD_UPPER = 0x200000a8       # preset A: 0x244=580, preset B: 0x2ee=750
THRESHOLD_LOWER = 0x200000c0       # preset A: 0xc8=200,  preset B: 0xfa=250

PB05_MMIO = 0x410080a0       # PORT.GROUP1.IN, bit 5
PB05_BIT = 5
ADC1_RESULT = 0x43002040     # confirmed this slice: analogRead(PB05) reads ADC1.RESULT (16-bit)
ADC1_RESULT_READ_PC = 0xd2a2  # ldrh.w r0,[r3,#0x40] inside FUN_0000d1b4 -- fixed PC regardless of caller

MMIO_BASE = 0x40000000
MMIO_SIZE = 0x4000000
SP_TOP = 0x20030000          # fixed SP every poll -- no cross-poll stack drift


def pb05_digital_seed(level_high):
    value = (1 << PB05_BIT) if level_high else 0
    return (PB05_MMIO, value.to_bytes(4, "little"))


def adc_result_seed(value):
    return (ADC1_RESULT, (value & 0xFFFF).to_bytes(2, "little"))


def poll_once(machine, mode_flag, tr_enable, external_seed, first, rate_limit_fresh=True,
              threshold_upper=580, threshold_lower=200, sensitivity_selector=0):
    """One real, concrete pass through phase_ramp_state_machine__CUSTOM's
    own real entry (0x8e18), stopping at the first of: the real TX wrapper
    (a send happened), the real accept target, or the real reject target.
    `first=True` (re-)seeds every background cell this investigation's own
    prior slices already disclosed and confirmed; later polls in the same
    scenario reuse fresh=False so RAM state (rate-limit timestamps, the
    live ADC/threshold cells) persists across polls exactly like real
    consecutive main-loop iterations."""
    seed_mem = [external_seed]
    if first:
        seed_mem += [
            (MODE_FLAG, bytes([mode_flag])),
            (TR_ENABLE, bytes([tr_enable])),
            (R5_BASE + 0, b"\x00"), (R5_BASE + 1, b"\x00"),
            (R5_BASE + 2, b"\x00"), (R5_BASE + 3, b"\x00"),
            (GATE_CELL_1, (0x7b).to_bytes(4, "little")),
            (GATE_CELL_2, bytes([9])),
            (SENSITIVITY_SELECTOR, bytes([sensitivity_selector])),
            (THRESHOLD_UPPER, threshold_upper.to_bytes(4, "little")),
            (THRESHOLD_LOWER, threshold_lower.to_bytes(4, "little")),
        ]
        # rate-limit timestamp: "fresh" (startup) => elapsed already >=500
        # (last-check far in the past, via unsigned wraparound, matching
        # this project's own established seeding idiom); "not fresh"
        # (runtime, just sent) => last-check == current tick (0), so
        # elapsed==0 and a re-send cannot fire until real time this
        # harness does not model would elapse (--fake-tick, unused here
        # per instruction -- poll count, not milliseconds).
        last_check = 0 if rate_limit_fresh else 0
        seed_mem.append((RATE_LIMIT_LAST_CHECK,
                          ((0xFFFFFFFF - 600) if rate_limit_fresh else 0).to_bytes(4, "little")))
    result = machine.run(
        entry=FUNC_ENTRY,
        sp=SP_TOP,
        seed_mem=seed_mem,
        stop_at=[TX_WRAPPER, ACCEPT_TARGET, REJECT_TARGET],
        max_instructions=5000,
        fresh=first,
    )
    pc = result.reg("pc") & ~1
    if pc == TX_WRAPPER:
        outcome = "SEND(0x8c10)"
    elif pc == ACCEPT_TARGET:
        outcome = "ACCEPT(0x8f98)"
    elif pc == REJECT_TARGET:
        outcome = "reject(0x9232)"
    else:
        outcome = f"UNEXPECTED(0x{pc:x}, {result.stop_reason})"
    live_adc = int.from_bytes(machine.uc.mem_read(LIVE_ADC_VALUE, 4), "little")
    return outcome, live_adc, result.instructions_executed


# ---------------------------------------------------------------------------
# Experiment 1: synthetic ADC streams into the DEAD 128-sample baseline
# ---------------------------------------------------------------------------

STREAMS = {
    "steady": lambda n: [512] * n,
    "single_spike": lambda n: [512] * (n // 2) + [4095] + [512] * (n - n // 2 - 1),
    "several_spikes": lambda n: [(0 if (i // 17) % 2 else 4095) if i % 17 == 0 else 512 for i in range(n)],
    "alternating_extremes": lambda n: [0 if i % 2 == 0 else 4095 for i in range(n)],
    "settling_ramp": lambda n: [int(4095 * (1 - i / (n - 1)) * 0.9 + 512 * (i / (n - 1)) * 1.1) if n > 1 else 512 for i in range(n)],
}
DEAD_RAM = [0x20002098, 0x2000313c, 0x20001fc4, 0x20003128, 0x200023c0]

# Fixed, hand-placed 8-sample sequences for Experiment 2 (the live gate,
# which -- found this slice -- reads through the SAME real ~500-tick-gated
# exponentially-smoothed filter as Experiment 1's dead baseline, and
# whose filter initializes to poll 0's raw sample exactly on the very
# first call ever -- FUN_000042a4 0x42e0-0x42e8). Unlike Experiment 1's
# 128-sample generic streams, these deliberately avoid putting a spike at
# index 0, so a settled in-band baseline is genuinely established before
# the transient -- the realistic "insertion happens after the device has
# already been running/reporting" case. alternating_extremes is the one
# deliberate exception: ringing present from the very first sample,
# modeling an insertion transient landing on the very first poll after
# this subsystem's own subscription starts (no prior settled state to
# damp against).
ANALOG_LIVE_STREAMS = {
    "steady": [512] * 8,
    "single_spike": [512, 512, 512, 4095, 512, 512, 512, 512],
    "several_spikes": [512, 512, 4095, 512, 0, 512, 512, 4095],
    "alternating_extremes": [0, 4095, 0, 4095, 0, 4095, 0, 4095],
    "settling_ramp": [4095, 3527, 2959, 2391, 1823, 1255, 687, 512],
}


def adc_baseline_experiment(n_samples=128):
    print("=== Experiment 1: synthetic ADC streams -> dead 128-sample baseline (FUN_00005d44) ===")
    results = {}
    for name, gen in STREAMS.items():
        samples = gen(n_samples)
        machine = ConcreteMachine(str(FIRMWARE), mmio_base=MMIO_BASE, mmio_size=MMIO_SIZE)
        state = {"i": 0}

        def feed(uc, address, size, user_data):
            i = state["i"]
            v = samples[min(i, len(samples) - 1)]
            uc.mem_write(ADC1_RESULT, (v & 0xFFFF).to_bytes(2, "little"))
            state["i"] += 1

        handle = machine.uc.hook_add(UC_HOOK_CODE, feed, begin=ADC1_RESULT_READ_PC, end=ADC1_RESULT_READ_PC)

        # FUN_000042a4's own ~500-tick gate (its last-check cell,
        # 0x20003124, literal-pool-confirmed) never naturally elapses
        # without real time passing -- forcing it to 0 on every call
        # entry makes every one of the 128 loop iterations genuinely
        # resample (matching what 128 real ~500ms-apart calls would do),
        # rather than sampling once and reusing a cached filtered value
        # for the rest of the loop (real behavior under a stalled clock,
        # not what this experiment needs to test transient propagation
        # through the full averaging window).
        def force_resample(uc, address, size, user_data):
            uc.mem_write(0x20003124, (0).to_bytes(4, "little"))

        handle2 = machine.uc.hook_add(UC_HOOK_CODE, force_resample, begin=0x000042a4, end=0x000042a4)
        # PA02=HIGH at boot (mode_flag=1) is what RUNS the averaging loop
        # (`if (*0x20001fc0 != 2) { ...averaging... }` -- concrete-path.md
        # Part 4). The function's own entry sequence calls a real
        # delay(200)/delay(100) (bl 0xcd50) before the loop; this delay()
        # is backed by a DWT/CYCCNT-shaped double-read hardware cycle
        # counter (0xccdc), NOT the simple millis() tick variable --
        # already-documented elsewhere in this project as "a DWT->CYCCNT
        # -based pulse-width delay, unrelated to control flow" (the same
        # class of boundary named in trigger-input-motion-causality.md's
        # config_reload_gpio_pulse). Stubbed (opaque call, caller-saved
        # registers only), same as that established boundary -- the delay
        # amount has no bearing on which/how many ADC samples get fed.
        # FUN_000042a4 (the per-sample caller) is itself a real, separate
        # ~500-tick-gated exponential filter around the actual ADC read
        # (0xd1b4) -- confirmed this slice (disassembly, 0x42a4-0x42ce):
        # without real elapsed time between the loop's 128 calls it only
        # samples once, then reuses the cached filtered value for the
        # rest of the loop (correct, real firmware behavior, not a
        # harness artifact -- the mismatch is that Unicorn's millis()
        # tick variable does not advance on its own). --fake-tick paces
        # it fast enough that all 128 calls genuinely resample, matching
        # what 128 real ~500ms-apart calls would do on hardware.
        result = machine.run(
            entry=0x00005d44, sp=SP_TOP,
            seed_mem=[(MODE_FLAG, bytes([1]))],
            stop_at=[0x00005db0],  # the function's own single real return point
            stub_calls=[0x0000cd50],
            max_instructions=400000,
            fresh=True,
        )
        machine.uc.hook_del(handle)
        machine.uc.hook_del(handle2)
        dead_ram_after = {hex(a): int.from_bytes(machine.uc.mem_read(a, 4), "little") for a in DEAD_RAM}
        samples_consumed = state["i"]
        print(f"  {name:22s} samples_fed={samples_consumed:4d}  "
              f"stop={result.stop_reason:30s}  dead_ram={dead_ram_after}")
        results[name] = {"samples_consumed": samples_consumed, "dead_ram_after": dead_ram_after,
                          "stop_reason": result.stop_reason}
    print()
    return results


# ---------------------------------------------------------------------------
# Experiment 2: the same synthetic streams into the LIVE per-poll analog gate
# ---------------------------------------------------------------------------

def analog_live_gate_experiment(n_polls=8):
    print("=== Experiment 2: synthetic ADC streams -> LIVE analog accept/T-status gate ===")
    print("    (analogRead(PB05) goes through FUN_000042a4, a real ~500-tick-gated,")
    print("     exponentially-smoothed wrapper -- found this slice. 'burst' mode leaves")
    print("     that gate alone, matching a fast bounce/ringing burst all within one real")
    print("     ~500ms window (only the first poll actually resamples); 'sustained' mode")
    print("     forces a fresh resample every poll, matching a slow-settling condition")
    print("     spanning many real windows.)")
    results = {}
    for name, samples in ANALOG_LIVE_STREAMS.items():
        for tr, label in [(0, "TR0_disarmed_accept_gate"), (1, "TR1_armed_tstatus_send")]:
            for timing, force in [("burst", False), ("sustained", True)]:
                machine = ConcreteMachine(str(FIRMWARE), mmio_base=MMIO_BASE, mmio_size=MMIO_SIZE)
                handle = None
                if force:
                    def force_resample(uc, address, size, user_data):
                        uc.mem_write(0x20003124, (0).to_bytes(4, "little"))
                    handle = machine.uc.hook_add(UC_HOOK_CODE, force_resample, begin=0x000042a4, end=0x000042a4)
                rows = []
                for i, v in enumerate(samples):
                    outcome, live_adc, _ = poll_once(
                        machine, mode_flag=1, tr_enable=tr,
                        external_seed=adc_result_seed(v), first=(i == 0),
                        rate_limit_fresh=True,
                    )
                    rows.append((i, v, live_adc, outcome))
                if handle is not None:
                    machine.uc.hook_del(handle)
                accepts = sum(1 for r in rows if r[3] == "ACCEPT(0x8f98)")
                sends = sum(1 for r in rows if r[3] == "SEND(0x8c10)")
                print(f"  {name:22s} {label:28s} {timing:10s} accepts={accepts} sends={sends}  "
                      f"seq={[(r[1], r[2], r[3]) for r in rows]}")
                results[f"{name}/{label}/{timing}"] = rows
    print()
    return results


# ---------------------------------------------------------------------------
# Experiment 3: the task's digital H/L matrix, both TR contexts, both timing contexts
# ---------------------------------------------------------------------------

DIGITAL_SEQUENCES = {
    "H_L_H": [True, False, True],
    "H_L_L_H": [True, False, False, True],
    "H_L_H_L_H": [True, False, True, False, True],
    "H_L_L_L_H": [True, False, False, False, True],
    "L_L_L_L": [False, False, False, False],
}


def digital_matrix_experiment():
    print("=== Experiment 3: digital H/L transient matrix (mode_flag=2, digital arm) ===")
    results = {}
    for seq_name, seq in DIGITAL_SEQUENCES.items():
        for tr, tr_label in [(0, "TR0_accept_gate"), (1, "TR1_tstatus_send")]:
            for ctx, fresh in [("startup", True), ("runtime", False)]:
                machine = ConcreteMachine(str(FIRMWARE), mmio_base=MMIO_BASE, mmio_size=MMIO_SIZE)
                rows = []
                for i, level in enumerate(seq):
                    outcome, _, _ = poll_once(
                        machine, mode_flag=2, tr_enable=tr,
                        external_seed=pb05_digital_seed(level), first=(i == 0),
                        rate_limit_fresh=fresh,
                    )
                    rows.append((i, "H" if level else "L", outcome))
                accepts = sum(1 for r in rows if r[2] == "ACCEPT(0x8f98)")
                sends = sum(1 for r in rows if r[2] == "SEND(0x8c10)")
                key = f"{seq_name}/{tr_label}/{ctx}"
                print(f"  {seq_name:12s} {tr_label:18s} {ctx:8s} accepts={accepts} sends={sends}  "
                      f"seq={[(r[1], r[2]) for r in rows]}")
                results[key] = rows
    print()
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--only", choices=["adc-dead", "adc-live", "digital", "all"], default="all")
    args = ap.parse_args()

    out = {}
    if args.only in ("adc-dead", "all"):
        out["adc_baseline_dead"] = adc_baseline_experiment()
    if args.only in ("adc-live", "all"):
        out["adc_live_gate"] = analog_live_gate_experiment()
    if args.only in ("digital", "all"):
        out["digital_matrix"] = digital_matrix_experiment()

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(out, f, indent=2, default=str)
        print(f"wrote {args.json_out}")


if __name__ == "__main__":
    main()
