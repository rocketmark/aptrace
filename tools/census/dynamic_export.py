"""APTrace census: capture Unicorn dynamic coverage from the EXISTING
tools/unicorn/virtual_link.py scenario corpus, without rewriting any of
its scenario logic.

How this stays non-invasive: `ConcreteMachine.run` (tools/unicorn/
concrete.py) is monkeypatched, for the duration of one capture call
only, to default `collect_coverage`/`log_ram`/`log_mmio` on and to
record every resulting RunResult -- every scenario function in
virtual_link.py (run_ampersand_roundtrip, run_g_ack_roundtrip, ...)
still calls exactly the same `run_concrete()`/`call()`/`carry()` helpers
it always has; none of virtual_link.py's own code changes or even needs
to know this capture is happening. See concrete.py's `run()` docstring
for what `collect_coverage`/`log_ram` add (both additive, default off,
ConcreteMachine(fresh=True) semantics untouched).

Writes one JSON file per scenario under
research/runs/census/dynamic/<scenario>.json -- tools/census/
dynamic_ingest.py reads those files into the census database (kept as a
separate step so "capture" and "ingest" each have one job, and a capture
can be inspected/reused without a database present).
"""
import datetime
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
UNICORN_DIR = REPO_ROOT / "tools" / "unicorn"
sys.path.insert(0, str(UNICORN_DIR))

DEFAULT_OUT_DIR = REPO_ROOT / "research" / "runs" / "census" / "dynamic"

SCENARIOS = {
    "ampersand": "run_ampersand_roundtrip",
    "g": "run_g_ack_roundtrip",
    "s": "run_s_roundtrip",
    "plus": "run_plus_target_distance_roundtrip",
    "pb05": "run_pb05_reload_motion_check",
    "t-status": "run_t_status_feedback_check",
}

# The TX-wrapper convention this project's own scenarios already use to
# capture outbound bytes (see virtual_link.py's module docstring, point
# 2): a leg that requested dump_reg_pointee on r0 and stopped exactly at
# one of these addresses is, by that established convention, a TX
# capture -- read directly from virtual_link.py's own public anchors,
# not re-guessed here.
def _tx_wrapper_addrs(vl):
    names = ("AUTOPILOT_TX_WRAPPER", "AUTOPILOT_TX_BYTE_WRAPPER", "REMOTE_TX_WRAPPER")
    return {getattr(vl, n) for n in names if hasattr(vl, n)}


def _firmware_key_for_path(path_str):
    stem = Path(path_str).stem  # e.g. "firmware_autopilot868"
    for key in ("autopilot868", "autopilot915", "mando868", "mando915"):
        if key in stem:
            return key
    return stem


def capture(scenario_names, out_dir=None, verbose=True):
    """Run each named scenario (keys of SCENARIOS, or 'all') with
    coverage capture enabled, writing one JSON export file per scenario.
    Returns the list of written file paths."""
    import concrete  # noqa: E402  (tools/unicorn/concrete.py)
    import virtual_link  # noqa: E402

    out_dir = Path(out_dir) if out_dir else DEFAULT_OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    if scenario_names == ["all"] or scenario_names == "all":
        names = list(SCENARIOS)
    else:
        unknown = [n for n in scenario_names if n not in SCENARIOS]
        if unknown:
            raise ValueError(f"unknown scenario(s) {unknown}; known: {sorted(SCENARIOS)}")
        names = list(scenario_names)

    tx_wrapper_addrs = _tx_wrapper_addrs(virtual_link)
    original_run = concrete.ConcreteMachine.run
    written = []

    for scenario_name in names:
        fn_name = SCENARIOS[scenario_name]
        scenario_fn = getattr(virtual_link, fn_name)
        legs = []

        def recording_run(self, *args, **kwargs):
            kwargs.setdefault("collect_coverage", True)
            kwargs.setdefault("log_ram", True)
            kwargs.setdefault("log_mmio", True)
            result = original_run(self, *args, **kwargs)
            snap = result.to_dict()
            tx_rx = []
            if result.stop_reason and result._reg_pointee.get("r0") is not None:
                stopped_addr = None
                if result.stop_reason.startswith("reached stop address "):
                    stopped_addr = int(result.stop_reason.rsplit(" ", 1)[-1], 16)
                if stopped_addr in tx_wrapper_addrs:
                    ptr, data = result._reg_pointee["r0"]
                    if data is not None:
                        payload = data.split(b"\x00", 1)[0]
                        tx_rx.append({"direction": "TX", "data_hex": payload.hex(),
                                      "note": f"r0-pointee at stop 0x{stopped_addr:08x}"})
            legs.append({
                "firmware": result.firmware,
                "label": result.label,
                "snapshot": snap,
                "tx_rx": tx_rx,
            })
            return result

        concrete.ConcreteMachine.run = recording_run
        try:
            if verbose:
                print(f"=== capturing dynamic coverage: {scenario_name} ({fn_name}) ===")
            scenario_fn(verbose=verbose)
        finally:
            concrete.ConcreteMachine.run = original_run

        firmware_keys = sorted({_firmware_key_for_path(leg["firmware"]) for leg in legs})
        export = {
            "scenario": scenario_name,
            "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "firmware_keys": firmware_keys,
            "legs": legs,
        }
        out_path = out_dir / f"{scenario_name}.json"
        out_path.write_text(json.dumps(export, indent=2))
        written.append(out_path)
        if verbose:
            print(f"  wrote {out_path} ({len(legs)} legs)")

    return written


def main(argv):
    which = argv if argv else ["all"]
    capture(which)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
