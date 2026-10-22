"""Check saved original-execution evidence; does not emulate or launch firmware."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASE = ROOT.parents[2]
checks = []


def check(label, condition):
    checks.append({"check": label, "pass": bool(condition)})


def read(name):
    return json.loads((ROOT / (name + ".json")).read_text())


def hits(d, address):
    return [h for h in d["watch_hits"] if int(h["address"], 16) == address]


def word(d, address):
    return int.from_bytes(bytes.fromhex(d["memory"][address])[:4], "little")


names = ["digital-acquired-transient", "digital-acquired-transient-915",
         "analog-517-to600-x1-915", "analog-517-to600-x2-915",
         "held-completion", "held-completion-w", "released-completion-w"]
data = {n: read(n) for n in names}
outcomes = {}
for name, d in data.items():
    check(name + ": no native error", d["error"] is None and d["error_free"])
    check(name + ": corrected write-hook path", d["execution_mode"] == "memory-hook-single-step")
    check(name + ": watches below cap", len(d["watch_hits"]) < (12000 if "completion" in name else 2500))
    outcomes[name] = {
        "instructions": d["instructions_executed"], "stop_reason": d["stop_reason"],
        "error": d["error"], "completed": d["completed"],
        "events": {hex(a): [{"instruction": h["instruction"],
                   "r0": h["registers"]["r0"], "r2": h["registers"]["r2"],
                   "input": h["memory"].get("0x410080a0"),
                   "filtered_x": h["memory"].get("0x20000190"),
                   "idle": h["memory"].get("0x200000d8")}
                  for h in hits(d, a)] for a in [0x922c, 0x8f98, 0x5f8c, 0x5810,
                                                    0x5fa4, 0x5fea, 0x6026, 0x6056,
                                                    0x865a, 0x6fd8]},
        "final_state": d["memory"],
        "idle9_store_count": len(hits(d, 0x9088)),
        "first_idle9_store": hits(d, 0x9088)[0]["instruction"] if hits(d, 0x9088) else None,
    }

old = json.loads((ROOT.parent / "powered-trigger-connection-2026-10-21" /
                  "digital-acquired-transient.json").read_text())
check("868 replay byte-for-byte decoded result equals historical witness",
      old == data["digital-acquired-transient"])
for name in names[:2]:
    d = data[name]
    check(name + ": saved LOW / current HIGH", hits(d, 0x922c)[0]["registers"]["r0"] == "0x00000000"
          and hits(d, 0x922c)[0]["memory"]["0x410080a0"] == "20000000")
    check(name + ": acceptance after release", hits(d, 0x8f98)[0]["instruction"] == 12098773)
    check(name + ": native initiation after release", hits(d, 0x5fa4)[0]["instruction"] == 12327152
          and word(d, "0x20001b14") == 1 and word(d, "0x40003800") & 2)
    check(name + ": requested boundary", d["completed"] and d["instructions_executed"] == 12327153)

x1, x2 = data[names[2]], data[names[3]]
check("fault-band X1 starts", len(hits(x1, 0x8f98)) == len(hits(x1, 0x5fa4)) == 1)
check("fault-band X1 filtered581 at acceptance", hits(x1, 0x8f98)[0]["memory"]["0x20000190"].startswith("45020000"))
check("fault-band X2 no acceptance or initiation", not hits(x2, 0x8f98) and not hits(x2, 0x5fa4))
check("fault-band X2 acquired600 selector2", x2["memory"]["0x20000190"] == "5802000002000000")
check("fault-band X2 remains eligible", word(x2, "0x20002524") == 0 and bytes.fromhex(x2["memory"]["0x200000d8"])[0] == 9)

alone, held, released = (data[n] for n in names[4:])
for name, d in [(names[4], alone), (names[5], held), (names[6], released)]:
    check(name + ": natural terminal stage", len(hits(d, 0x6026)) == 1 and len(hits(d, 0x6056)) == 1)
    check(name + ": instruction-bound stop, no watch-cap stop", d["stop_reason"] == "instruction limit reached")
check("no W: one initiation and idle2", len(hits(alone, 0x5fa4)) == 1 and bytes.fromhex(alone["memory"]["0x200000d8"])[0] == 2)
check("no W: stopped channel and timer", word(alone, "0x20002524") == word(alone, "0x20001b14") == 0 and not word(alone, "0x40003800") & 2)
check("stage durations2.5M/5M/2.5M/0", bytes.fromhex(alone["memory"]["0x200025e2"])[6:22] == b"\xa0\x25\x26\x00\x40\x4b\x4c\x00\xa0\x25\x26\x00\x00\x00\x00\x00")
for name, d in [(names[5], held), (names[6], released)]:
    check(name + ": W consumed after completion", hits(d, 0x865a)[0]["instruction"] > hits(d, 0x6056)[0]["instruction"])
    check(name + ": zero-distance return limitation", hits(d, 0x6fd8)[0]["registers"]["r2"] == "0x00000000" and word(d, "0x20002064") == 0)
    check(name + ": native idle9 reached", bool(hits(d, 0x9088)))
check("held with W: two acceptances and native starts", len(hits(held, 0x8f98)) == len(hits(held, 0x5fa4)) == 2)
check("held with W: second start index", hits(held, 0x5fa4)[1]["instruction"] == 52524554)
check("release with W: only one start despite re-arm", len(hits(released, 0x8f98)) == len(hits(released, 0x5fa4)) == 1 and bytes.fromhex(released["memory"]["0x200000d8"])[0] == 9)
check("release with W: inactive final input and stopped", released["memory"]["0x20000190"] == "e100000001000000" and word(released, "0x20001b14") == 0)

vvr = CASE / "research/validation/nathan-vvr"
for item in json.loads((vvr / "manifest.json").read_text())["files"]:
    check(item["file"] + ": preserved hash", hashlib.sha256((vvr / item["file"]).read_bytes()).hexdigest() == item["sha256"])
    check(item["file"] + ": extraction hash", hashlib.sha256((vvr / item["text"]).read_bytes()).hexdigest() == item["text_sha256"])

(ROOT / "outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
(ROOT / "checks.json").write_text(json.dumps(checks, indent=2) + "\n")
failed = [x for x in checks if not x["pass"]]
print(f"{len(checks)-len(failed)}/{len(checks)} saved-artifact checks passed")
for x in failed:
    print("FAILED:", x["check"])
raise SystemExit(bool(failed))
