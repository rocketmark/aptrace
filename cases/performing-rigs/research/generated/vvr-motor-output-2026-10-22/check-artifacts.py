"""Document saved native output requests; no firmware semantics or runner."""
import collections
import gzip
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NAMES = ["transient", "intentional", "unacquired",
         "transient-count-observation", "intentional-count-observation"]
def read_native(name):
    p = ROOT / (name + ".json")
    return json.loads(p.read_text() if p.exists() else gzip.decompress(Path(str(p) + ".gz").read_bytes()))


data = {n: read_native(n) for n in NAMES}
checks = []


def check(name, value):
    checks.append({"check": name, "pass": bool(value)})


def hits(d, pc):
    return [x for x in d["watch_hits"] if int(x["address"], 16) == pc]


def io(d, address, mask=None, after=0):
    return [x for x in d["mem_write_hits"] if int(x["address"], 16) == address
            and (mask is None or int(x["value"], 16) & mask)
            and x["instruction"] > after]


def frames(d):
    # Reuses the established case documentary CS-boundary/low-byte method.
    # This groups recorded writes; it does not simulate SPI or device responses.
    selects = [("D0", 0x41008094, 0x100), ("D1", 0x41008014, 0x40000),
               ("D2", 0x41008094, 0x200), ("D3", 0x41008014, 0x80000)]
    active, result, anomalies = {}, [], []
    for x in d["mem_write_hits"]:
        address, value = int(x["address"], 16), int(x["value"], 16)
        for name, clear, mask in selects:
            if address in (clear, clear + 4) and value & mask:
                if address == clear:
                    if active:
                        anomalies.append({"kind": "overlap", "instruction": x["instruction"]})
                    active[name] = {"select": name, "start": x["instruction"], "bytes": []}
                elif name in active:
                    f = active.pop(name)
                    if f["bytes"]:
                        f["end"] = x["instruction"]
                        f["register"] = f["bytes"][0] & 127
                        f["write"] = bool(f["bytes"][0] & 128)
                        f["payload"] = int.from_bytes(bytes(f["bytes"][1:]), "big")
                        result.append(f)
        if address == 0x43000428:
            if len(active) != 1:
                anomalies.append({"kind": "unframed byte", "instruction": x["instruction"]})
            else:
                next(iter(active.values()))["bytes"].append(value & 255)
    return result, anomalies


summary, timeline = {}, {}
for name, d in data.items():
    check(name + ": no native error", d["error"] is None and d["error_free"])
    check(name + ": corrected memory-hook execution", d["execution_mode"] == "memory-hook-single-step")
    check(name + ": full14M bound", d["instructions_executed"] == 14000000 and d["stop_reason"] == "instruction limit reached")
    check(name + ": no output log truncation", d["mem_write_dropped"] == 0)
    check(name + ": no code-watch cap", len(d["watch_hits"]) < 12000)
    check(name + ": no delivered TC0 handler", not hits(d, 0x607c))
    check(name + ": no STEP emitter invocation", not hits(d, 0x5898))
    fs, anomalies = frames(d)
    check(name + ": complete unambiguous SPI framing", not anomalies and all(len(f["bytes"]) == 5 for f in fs))
    accepted = hits(d, 0x8f98)
    boundary = accepted[0]["instruction"] if accepted else 12098773
    step = [x for x in d["mem_write_hits"] if int(x["address"], 16) in (0x41008094, 0x41008098)
            and int(x["value"], 16) & 0x400]
    direction = [x for x in d["mem_write_hits"] if int(x["address"], 16) in (0x41008094, 0x41008098)
                 and int(x["value"], 16) & 0x800]
    setters = [{"pc": h["address"], "instruction": h["instruction"],
                "object": h["registers"]["r0"], "input": int(h["registers"]["r1"], 16)}
               for h in d["watch_hits"] if int(h["address"], 16) in (0xae60, 0xb070)]
    summary[name] = {
        "instructions": d["instructions_executed"], "stop_reason": d["stop_reason"],
        "acceptances": len(accepted), "rate_start_entries": len(hits(d, 0x5f8c)),
        "step_emitter_entries": len(hits(d, 0x5898)), "tc0_handler_entries": len(hits(d, 0x607c)),
        "ch0_step_writes_total": len(step),
        "ch0_step_writes_after_boundary": sum(x["instruction"] > boundary for x in step),
        "ch0_direction_after_boundary": [x for x in direction if x["instruction"] > boundary],
        "driver_setters": setters, "spi_datagrams": len(fs),
        "spi_register_writes_after_boundary": sum(f["write"] and f["start"] > boundary for f in fs),
        "period_arguments": [{"instruction": h["instruction"], "channel": int(h["registers"]["r0"], 16),
                              "period": int(h["registers"]["r1"], 16)} for h in hits(d, 0x5c00)],
        "counter_forces": [x for x in d["force_mem_hits"] if "40003814" in str(x)],
        "final": d["memory"],
    }
    timeline[name] = {"timer_writes": [x for x in d["mem_write_hits"] if x["range"] == "0x40003800:32"],
                      "step_writes": step, "direction_writes": direction, "driver_setters": setters}
    check(name + ": startup STEP requests exist", len(step) == 192)
    check(name + ": no post-boundary ch0 STEP request", not summary[name]["ch0_step_writes_after_boundary"])
    for ch, clear, bit in [(0,0x41008094,0x400),(1,0x41008014,0x100),
                            (2,0x41008094,0x1000),(3,0x41008014,0x400)]:
        writes = io(d,clear,bit) + io(d,clear+4,bit)
        check(name + f": ch{ch} startup96 HIGH/LOW pairs only",
              len(io(d,clear,bit)) == len(io(d,clear+4,bit)) == 96
              and not any(x["instruction"] > boundary for x in writes))
    if name in NAMES[:3]:
        check(name + ": no trigger-specific driver register writes", not summary[name]["spi_register_writes_after_boundary"])
        check(name + ": boot400/16 then MC41600/0", [x["input"] for x in setters] == [400,16]*4 + [1600,0]*4)

a, b, neg = (data[n] for n in NAMES[:3])
check("matched positives: all captured CPU writes identical including ordinal/PC/old value", a["mem_write_hits"] == b["mem_write_hits"])
check("matched positives: all recorded periods identical", summary["transient"]["period_arguments"] == summary["intentional"]["period_arguments"])
check("matched positives: same record bytes", a["memory"]["0x20001b40"] == b["memory"]["0x20001b40"])
check("transient: savedLOW/currentHIGH", hits(a, 0x922c)[0]["registers"]["r0"] == "0x00000000" and hits(a, 0x922c)[0]["memory"]["0x410080a0"] == "20000000")
check("intentional: savedLOW/currentLOW", hits(b, 0x922c)[0]["registers"]["r0"] == "0x00000000" and hits(b, 0x922c)[0]["memory"]["0x410080a0"] == "00000000")
check("different input levels persist at initiation", hits(a,0x5fa6)[0]["memory"]["0x410080a0"] == "20000000" and hits(b,0x5fa6)[0]["memory"]["0x410080a0"] == "00000000")
for name in NAMES[:2]:
    d = data[name]
    check(name + ": one normal acceptance/start", len(hits(d, 0x8f98)) == len(hits(d, 0x5f8c)) == 1)
    check(name + ": positive distance500 start0 end500", bytes.fromhex(d["memory"]["0x20001b40"])[0:4] == (500).to_bytes(4,"little") and bytes.fromhex(d["memory"]["0x20001b40"])[12:20] == (500).to_bytes(4,"little") + bytes(4))
    check(name + ": eleven post-accept DIR HIGH requests", len(io(d,0x41008098,0x800,12098773)) == 11 and not io(d,0x41008094,0x800,12098773))
check("negative: HIGH acquired on every observed read", bool(hits(neg,0x922c)) and all(h["registers"]["r0"] == "0x00000001" for h in hits(neg,0x922c)))
check("negative: no acceptance or profile start", not hits(neg,0x8f98) and not hits(neg,0x5f8c))
check("negative: no post-boundary motor DIR", not summary["unacquired"]["ch0_direction_after_boundary"])
check("negative: no post-boundary TC0 writes", not [x for x in timeline["unacquired"]["timer_writes"] if x["instruction"] > 12098773])
check("counter attempts agree with each other", data[NAMES[3]]["mem_write_hits"] == data[NAMES[4]]["mem_write_hits"])
for name in NAMES[3:]:
    check(name + ": not a valid single counter event", summary[name]["rate_start_entries"] == 38 and len(summary[name]["counter_forces"]) == 38 and len(hits(data[name],0x8f98)) == 1)

fs, anomalies = frames(a)
(ROOT / "driver-transactions.json").write_text(json.dumps({"source":"transient.json; identical captured writes in intentional.json", "method":"existing case CS-bounded DATA low bytes; logical requests only", "anomalies":anomalies,"transactions":fs},indent=2)+"\n")
(ROOT / "comparison.json").write_text(json.dumps(summary,indent=2)+"\n")
(ROOT / "timeline.json").write_text(json.dumps(timeline,indent=2)+"\n")
(ROOT / "checks.json").write_text(json.dumps(checks,indent=2)+"\n")
failed = [x for x in checks if not x["pass"]]
print(f"{len(checks)-len(failed)}/{len(checks)} saved-artifact checks passed")
for x in failed:
    print("FAILED:",x["check"])
raise SystemExit(bool(failed))
