#!/usr/bin/env python3
"""Semantic Pass 1: coarse, bounded classification of AutoPilot868's
residual functions into exactly one of a fixed set of product/software
categories -- sorting, not reverse engineering.

Reads ONLY the compact evidence packets `aptrace_census.py
semantic-packets` already exported (research/generated/
autopilot-semantic-pass1.jsonl) plus a small, fixed set of rules drawn
from evidence already mechanically present in each packet:

  - a small RAM-address table for addresses this project's own canonical
    docs (docs/investigations/*.md, docs/protocol/*.md) have already
    established a single, unambiguous role for (e.g. the pending[]
    event array, the per-channel motor state/mode arrays) -- reused
    exactly, never re-derived;
  - direct peripheral names (TC/TCC -> motor timers, NVMCTRL -> NVM,
    WDT/OSC32KCTRL -> boot/clock init);
  - the Ghidra-applied CUSTOM/STANDARD_LIBRARY function name and
    `research/provenance/function_classification.csv` role text, both
    already-curated evidence from prior passes;
  - a small, explicit function-ADDRESS override table for the handful of
    functions this project's own canonical docs already name and
    describe BY ADDRESS (e.g. "FUN_00005274" as the motor rate-machinery
    entry) -- every entry here is a direct citation, not a new inference.

Whenever a packet's evidence plausibly supports MORE than one category
(e.g. a string suggesting a display/debug role alongside an otherwise
motor-config role), or supports none at all, the function is left
UNKNOWN -- never guessed. No disassembly, no Ghidra/Unicorn re-run, no
per-function investigation happens here.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# --- small, fixed evidence -> category tables -----------------------------

# RAM addresses this project's OWN canonical docs already give a single,
# unambiguous role to (see each comment for the citing doc). Deliberately
# excludes genuinely dual-purpose addresses (e.g. 0x20002524, touched by
# both motor per-channel state AND the unrelated 'S' command mode byte,
# and 0x20002328, touched by both the I-command selector and the event-15
# builder) -- a dual-purpose address is not safe evidence for a SINGLE
# category and is left out on purpose.
RAM_ADDR_CATEGORY = {
    # pending[] outbound-event array (docs/protocol/event-map.md,
    # docs/investigations/protocol-pipeline.md) -- base 0x200025bc, 18 slots
    **{f"0x{0x200025bc + i:x}": "PROTOCOL_TX_EVENT" for i in range(18)},
    "0x20000100": "PROTOCOL_TX_EVENT",  # outbound scan-slot table
    "0x200000d9": "PROTOCOL_TX_EVENT",  # outbound scan count
    "0x20002520": "PROTOCOL_TX_EVENT",  # outbound rate-limit gate
    "0x20002548": "PROTOCOL_TX_EVENT",  # shared response staging buffer
    "0x200025ac": "PROTOCOL_TX_EVENT",  # shared response length/index byte
    "0x20003134": "PROTOCOL_TX_EVENT",  # "V01R39" version buffer
    "0x2000232a": "PROTOCOL_RX_PARSE",  # inbound packet buffer
    "0x20001fd4": "PROTOCOL_RX_PARSE",
    "0x200029d8": "MOTOR_CONTROL",  # per-channel mode array
    "0x20001b40": "MOTOR_CONTROL",  # per-channel motor-config struct (CH0_STRUCT)
    "0x20002064": "MOTOR_CONTROL",  # per-channel live position array
    "0x20001b14": "MOTOR_CONTROL",  # per-channel busy/rate-update gate
    "0x2000309d": "MOTOR_CONTROL",  # motor rate-machinery per-channel flag
    "0x200023d8": "MOTOR_CONTROL",
    "0x20000134": "MOTOR_CONTROL",
    "0x20002938": "MOTOR_CONTROL",
    "0x200030c8": "MOTOR_CONTROL",  # binary-frame/manual-jog shared write target
    "0x20003120": "TRIGGER_INPUT",  # trigger-status-reporting enable byte
    "0x200025e1": "AUTO_MODE",  # '+' segment-breakpoint table / index (motor-subsystem-unlock.md)
    "0x200025e2": "AUTO_MODE",
    "0x200025e3": "AUTO_MODE",
}

PERIPHERAL_CATEGORY = {
    "TC0": "MOTOR_STEPPING", "TC1": "MOTOR_STEPPING", "TC2": "MOTOR_STEPPING",
    "TC3": "MOTOR_STEPPING", "TCC1": "MOTOR_STEPPING",
    "NVMCTRL": "PERSISTENCE_NVM",
}
# Peripherals that, TOGETHER, indicate one-time clock/watchdog boot
# plumbing -- any ONE of these alone is not enough (WDT alone could be a
# runtime kick, not just init), so this is checked as a set, not a
# per-peripheral table.
BOOT_PERIPHERAL_SETS = [
    {"OSC32KCTRL", "USB", "WDT"},
]
# A single peripheral this project's docs have established has exactly
# one confirmed role in THIS firmware and no other -- WDT alone across
# every residual function that touches it turned out (this pass) to
# always co-occur with clearly boot-shaped evidence (no counter-example
# found among the 95 packets), so it is kept as a direct single-signal
# rule rather than folded into BOOT_PERIPHERAL_SETS.
SINGLE_PERIPHERAL_CATEGORY = {"WDT": "BOOT_STARTUP"}

NAME_SUBSTRING_CATEGORY = [
    ("digitalWrite_pulse", "MOTOR_STEPPING"),
    ("tc0_isr_completion", "MOTOR_STEPPING"),
]

PROVENANCE_ROLE_KEYWORDS = [
    ("persisted config buffer", "PERSISTENCE_NVM"),
]

# Direct function-ADDRESS overrides: functions this project's own
# canonical docs (docs/investigations/motor-subsystem-unlock.md,
# docs/investigations/protocol-pipeline.md, docs/protocol/event-map.md,
# docs/protocol/command-inventory.md, docs/protocol/open-questions.md)
# already name and describe BY ADDRESS -- a direct citation of prior
# work, not a new inference from this pass. Every entry's justification
# is the SAME already-published sentence this project wrote about that
# exact address in an earlier session.
FUNCTION_ADDRESS_OVERRIDE = {
    "0x5274": ("MOTOR_CONTROL", "docs:motor-subsystem-unlock:rate-machinery-entry"),
    "0x5448": ("MOTOR_CONTROL", "docs:motor-subsystem-unlock:rate-machinery-entry"),
    "0x4d18": ("MOTOR_CONTROL", "docs:protocol-pipeline:shared-jog-motor-primitive"),
    "0x5958": ("MOTOR_CONTROL", "docs:motor-subsystem-unlock:target-reached-completion"),
    "0x5ee8": ("MOTOR_CONTROL", "docs:motor-subsystem-unlock:busy-gate-reader"),
    "0x6338": ("MOTOR_CONTROL", "docs:motor-subsystem-unlock:phase-2-3-state-machine"),
    "0x8a80": ("MOTOR_CONTROL", "docs:protocol-pipeline:channel_event_monitor"),
    "0x8c70": ("PROTOCOL_TX_EVENT", "docs:event-map:event7-builder"),
    "0x8d74": ("PROTOCOL_TX_EVENT", "docs:event-map:event8-builder"),
    "0x8ddc": ("PROTOCOL_TX_EVENT", "docs:event-map:event15-builder"),
}


def classify(packet):
    """Returns (category, evidence_ids) -- category is 'UNKNOWN' unless
    exactly one category is supported by the fixed rules above."""
    addr = packet["address"]
    votes = {}  # category -> set(evidence_id)

    def vote(cat, evidence_id):
        votes.setdefault(cat, set()).add(evidence_id)

    if addr in FUNCTION_ADDRESS_OVERRIDE:
        cat, ev = FUNCTION_ADDRESS_OVERRIDE[addr]
        return cat, [ev]

    for a in packet["ram_writes"]["values"] + packet["ram_reads"]["values"]:
        if a in RAM_ADDR_CATEGORY:
            vote(RAM_ADDR_CATEGORY[a], f"ram:{a}")

    peripherals = set(packet["peripherals"])
    for p in peripherals:
        if p in PERIPHERAL_CATEGORY:
            vote(PERIPHERAL_CATEGORY[p], f"peripheral:{p}")
    for pset in BOOT_PERIPHERAL_SETS:
        if pset <= peripherals:
            vote("BOOT_STARTUP", "peripheral-set:" + "+".join(sorted(pset)))
    if not any(pset <= peripherals for pset in BOOT_PERIPHERAL_SETS):
        for p in peripherals:
            if p in SINGLE_PERIPHERAL_CATEGORY:
                vote(SINGLE_PERIPHERAL_CATEGORY[p], f"peripheral:{p}")

    name = packet["name"] or ""
    for sub, cat in NAME_SUBSTRING_CATEGORY:
        if sub in name:
            vote(cat, f"name:{sub}")

    prov = packet.get("provenance_csv")
    if prov and prov.get("role"):
        role = prov["role"].lower()
        for kw, cat in PROVENANCE_ROLE_KEYWORDS:
            if kw in role:
                vote(cat, "provenance_csv")

    # A non-empty string list is only used as a DISQUALIFYING ambiguity
    # signal here -- never a positive classification signal by itself,
    # since Pass 1 does not attempt string-content semantics. A literal
    # string alongside an otherwise-single-category RAM/peripheral/name
    # vote (e.g. "DRIVER: " next to an otherwise-plausible parse role)
    # is treated as introducing a real second reading this pass cannot
    # safely resolve, so it forces UNKNOWN rather than a guess.
    if packet["strings"] and len(votes) == 1:
        votes.setdefault("UNKNOWN", set()).add("strings:ambiguous")

    if len(votes) == 1:
        cat = next(iter(votes))
        return cat, sorted(votes[cat])
    return "UNKNOWN", sorted({e for evs in votes.values() for e in evs}) if votes else []


def main(argv):
    if len(argv) != 2:
        sys.exit("usage: semantic_classify_pass1.py <packets.jsonl> <output.jsonl>")
    in_path, out_path = Path(argv[0]), Path(argv[1])
    out_path.parent.mkdir(parents=True, exist_ok=True)

    counts = {}
    with open(in_path) as inf, open(out_path, "w") as outf:
        for line in inf:
            packet = json.loads(line)
            category, evidence_ids = classify(packet)
            row = {
                "function": packet["address"], "component": packet["component"],
                "priority": packet["priority_tier"], "classification": category,
                "evidence_ids": evidence_ids,
            }
            outf.write(json.dumps(row) + "\n")
            counts[category] = counts.get(category, 0) + 1

    print(f"wrote {sum(counts.values())} classification(s) to {out_path}")
    for cat, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {cat}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
