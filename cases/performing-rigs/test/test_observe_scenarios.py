#!/usr/bin/env python3
"""Performing Rigs: scenario-aware caller observation on the real AutoPilot
image (scripts/observe_call_arguments.py over config/observation_scenarios.json).

Checks that the boot observation is unchanged, that every observation is
deterministic, that observing a virtual-link scenario does not perturb it,
that unsupported and unknown scenarios are refused, and that the watched
SERCOM-object field is reported with its initializing store. Plain
assertions via check(), same convention as test_concrete.py. Run with the
Unicorn venv (needs the gitignored census DB and the firmware originals):

    tools/unicorn/.venv/bin/python3 cases/performing-rigs/test/test_observe_scenarios.py
"""
import contextlib
import io
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE = HERE.parent
REPO_ROOT = CASE.parents[1]
sys.path.insert(0, str(CASE / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "unicorn"))

import observe_call_arguments as oca  # noqa: E402

FAILURES = []
FW = "autopilot868"


def check(name, condition, detail=""):
    print(f"  [{'ok' if condition else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def observe(*args, **kwargs):
    with contextlib.redirect_stderr(io.StringIO()):
        return oca.observe(*args, **kwargs)


def refused(**kwargs):
    try:
        observe(FW, 0xB4B4, **kwargs)
    except SystemExit as exc:
        return str(exc)
    return None


def test_boot_unchanged_and_deterministic():
    print("test_boot_unchanged_and_deterministic")
    doc = observe(FW, 0xB4B4, (0xB4B4, 0xB4FE))
    obs = doc["observation"]
    sites = {s["call_site"]: s for s in obs["call_sites"]}
    r0 = {v["value"] for s in obs["call_sites"] for v in s["arguments"]["r0"]}
    check("278 entries through the four direct call sites",
          obs["observed_entries"] == 278 and set(sites) == {"0x0000a068", "0x0000a088", "0x0000a0ac", "0x0000b5c2"},
          (obs["observed_entries"], sorted(sites)))
    check("only the two RAM SERCOM-object pointers reach r0", r0 == {"0x20004c54", "0x20004c78"}, r0)
    check("no MMIO access from code in the function extent",
          doc["mmio_in_extent"]["access_count"] == 0 and not doc["mmio_in_extent"]["log_truncated"])
    check("boot ran to its recipe budget with every milestone",
          doc["run"]["instructions_executed"] == 450_000 and doc["run"]["budget_exhausted"]
          and doc["run"]["init_status"] == "complete")
    check("scenario identity recorded", doc["scenario"] == "boot" and doc["scenario_config"]["kind"] == "boot-recipe")
    again = observe(FW, 0xB4B4, (0xB4B4, 0xB4FE))
    check("identical document on a second run", json.dumps(doc, sort_keys=True) == json.dumps(again, sort_keys=True))


def test_watched_sercom_field():
    print("test_watched_sercom_field")
    doc = observe(FW, 0xB4B4, watch=["0x20004c54:4", "0x20004c3c:4"])
    fields = {f["name"]: f for f in doc["watched_fields"]["fields"]}
    f54, f3c = fields["0x20004c54+4"], fields["0x20004c3c+4"]
    check("0x20004c54 initialized to the SERCOM2 base by FUN_0000b312",
          f54["initialization"] and f54["initialization"]["new"] == "0x41012000"
          and f54["initialization"]["function"] == "FUN_0000b312", f54["initialization"])
    check("0x20004c3c initialized to the SERCOM0 base (exploratory word reproduced)",
          f3c["initialization"] and f3c["initialization"]["new"] == "0x40003000" and f3c["final_bytes"] == "00300040",
          f3c["initialization"])
    check("watched stores complete", doc["watched_fields"]["complete"])
    groups = [g for g in doc["correlation"] if g["value"] == "0x20004c54"]
    check("every call passing 0x20004c54 saw its initialized value",
          groups and all(g["field_state"] == "initialized value unchanged at every call" for g in groups), groups)
    check("the read through r0 is a RAM read whose content resembles an MMIO base",
          all(g["value_region"] == "RAM" and g["pointee_words"] == [{"word": "0x41012000", "region": "MMIO"}]
              for g in groups))
    check("observation with a write watch is identical without it",
          doc["observation"] == observe(FW, 0xB4B4)["observation"])


def _plain_legs(runner_name):
    """(instructions, stop_reason) of every leg of one scenario, unobserved."""
    import concrete
    import virtual_link

    original = concrete.ConcreteMachine.run
    legs = []

    def recording(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        legs.append((result.instructions_executed, result.stop_reason))
        return result

    concrete.ConcreteMachine.run = recording
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            outcome = getattr(virtual_link, runner_name)(verbose=False)
    finally:
        concrete.ConcreteMachine.run = original
        virtual_link._machines.clear()
    return legs, outcome


def test_virtual_link_scenarios():
    print("test_virtual_link_scenarios (observation does not perturb the scenario)")
    scenarios = oca.load_scenarios()
    for name in ("vl-plus", "vl-pb05", "vl-bang"):
        doc = observe(FW, 0xB4B4, watch=["0x20004c54:4"], scenario=name)
        legs, outcome = _plain_legs(scenarios[name]["runner"])
        check(f"{name}: ran and passed its own assertions", doc["status"] == "ok" and bool(outcome), doc["status"])
        check(f"{name}: same legs, instructions and stops as an unobserved run",
              [(leg["instructions_executed"], leg["stop_reason"]) for leg in doc["legs"]] == legs)
        check(f"{name}: deterministic", json.dumps(doc, sort_keys=True)
              == json.dumps(observe(FW, 0xB4B4, watch=["0x20004c54:4"], scenario=name), sort_keys=True))
        check(f"{name}: harness inputs of target legs recorded",
              all("seeds" in leg and "stub_calls" in leg for leg in doc["legs"]))


def test_refusals():
    print("test_refusals")
    doc = observe(FW, 0xB4B4, scenario="vl-t-status")
    check("a scenario that executes no AutoPilot code is unsupported, not run",
          doc["status"].startswith("unsupported") and doc["observation"]["observed_entries"] == 0, doc["status"])
    check("unknown scenario refused", "unknown scenario" in (refused(scenario="vl-nope") or ""))
    check("non-RAM watch refused", "not inside RAM" in (refused(watch=["0x40003000:4"]) or ""))
    check("oversized watch refused", "size" in (refused(watch=["0x20004c54:32"]) or ""))
    check("too many watches refused", "at most" in (refused(watch=[f"{0x20000000 + 16 * i:#x}:4" for i in range(9)]) or ""))
    check("budget override refused outside boot", "only to the boot" in (refused(scenario="vl-plus", max_instructions=10) or ""))


def main():
    test_boot_unchanged_and_deterministic()
    test_watched_sercom_field()
    test_virtual_link_scenarios()
    test_refusals()
    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURE(S): {FAILURES}")
        sys.exit(1)
    print("\nall observation scenario checks passed")


if __name__ == "__main__":
    main()
