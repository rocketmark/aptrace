"""Saved binary/execution comparisons, not an emulator or test runner."""
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NAMES = [f"{n}-{s}" for n in ["transient","intentional","unacquired","fresh-intentional"] for s in ["original","patched"]]
NAMES += ["analog-x1-patched","analog-x2-patched"]
NAMES += [f"{n}-{s}" for n in ["B1-full-reset","G-to-enable","W1-nonzero-to-enable"] for s in ["original","patched"]]
NAMES += ["held-w-original","held-w-patched","release-fresh-w-patched","late-release-patched"]


def read(name):
    p = ROOT / (name + ".json")
    return json.loads(p.read_text() if p.exists() else gzip.decompress(Path(str(p)+".gz").read_bytes()))


def hits(d, a):
    return [h for h in d["watch_hits"] if int(h["address"],16) == a]


def project(d):
    return [(x["pc"],x["address"],x["size"],x["value"],x["previous"]) for x in d["mem_write_hits"]]


checks = []
def check(label, value):
    checks.append({"check":label,"pass":bool(value)})


data = {n:read(n) for n in NAMES}
summary = {}
for name,d in data.items():
    check(name+": no native error", d["error"] is None and d["error_free"])
    check(name+": corrected hook mode", d["execution_mode"] == "memory-hook-single-step")
    check(name+": below watch cap", "max watch hits" not in d["stop_reason"])
    if name.split('-')[0] in ["transient","intentional","unacquired","fresh","late"]:
        check(name+": no write-log truncation", d["mem_write_dropped"] == 0)
    addresses = [0x922c,0x15470,0x1547c,0x8f98,0x5f8c,0x571c,0x5810,0x5fa4,0x5fa6,0x5898,0x607c]
    summary[name] = {
        "firmware":d["firmware"],"instructions":d["instructions_executed"],"stop":d["stop_reason"],"error":d["error"],
        "events":{hex(a):[{"instruction":h["instruction"],"r0":h["registers"]["r0"],"input":h["memory"].get("0x410080a0")} for h in hits(d,a)] for a in addresses},
        "captured_writes":len(d["mem_write_hits"]),"dropped_writes":d["mem_write_dropped"],"final":d["memory"],
    }

for name in ["transient","intentional","fresh-intentional"]:
    check(name+": original initiation reproduced", len(hits(data[name+"-original"],0x5f8c)) == 1)
for name in ["transient-patched","unacquired-patched"]:
    d=data[name]
    for a in [0x8f98,0x5f8c,0x571c,0x5810,0x5898,0x607c]:
        check(name+f": no initiation/service at{hex(a)}", not hits(d,a))
    check(name+":14M bound", d["instructions_executed"] == 14000000)
    for clear,mask in [(0x41008094,0x400),(0x41008014,0x100),(0x41008094,0x1000),(0x41008014,0x400)]:
        check(name+f": no post-candidate STEP{hex(mask)}", not [x for x in d["mem_write_hits"] if x["instruction"]>12098771 and int(x["address"],16) in [clear,clear+4] and int(x["value"],16)&mask])

comparisons={}
for name,shift in [("intentional",24),("fresh-intentional",26)]:
    a,b=data[name+"-original"],data[name+"-patched"]
    same=project(a)==project(b)
    check(name+": global write ordering comparison is characterized", same if name=="intentional" else not same)
    for rng in ["0x40003800:32","0x43000428:4"]:
        stream=lambda d:[(x["pc"],x["address"],x["size"],x["value"]) for x in d["mem_write_hits"] if x["range"]==rng]
        check(name+": same peripheral stream "+rng,stream(a)==stream(b))
    for lo,hi,mask in [(0x41008014,0x4100801c,0xc0f00),(0x41008094,0x4100809c,0xc0033fc0)]:
        stream=lambda d:[(x["address"],int(x["value"],16)&mask) for x in d["mem_write_hits"] if lo<=int(x["address"],16)<=hi and int(x["value"],16)&mask]
        check(name+": same motor/control GPIO stream "+hex(lo),stream(a)==stream(b))
    check(name+": one patched acceptance/start",len(hits(b,0x8f98))==len(hits(b,0x5f8c))==1)
    check(name+": expected acceptance instruction cost",hits(b,0x8f98)[0]["instruction"]-hits(a,0x8f98)[0]["instruction"]==shift)
    check(name+": same motor record",a["memory"]["0x20001b40"]==b["memory"]["0x20001b40"])
    check(name+": acceptance registers and SP preserved",all(hits(a,0x8f98)[0]["registers"][reg]==hits(b,0x8f98)[0]["registers"][reg] for reg in ["r"+str(i) for i in range(13)]+["sp","lr"]))
    comparisons[name]={"writes_original":len(a["mem_write_hits"]),"writes_patched":len(b["mem_write_hits"]),"global_write_requests_equal_after_timestamp_removal":same,"peripheral_and_motor_gpio_streams_equal":True,"acceptance_instruction_shift":shift,"ordering_limit":"Fresh-input control changes global interleaving of timer/housekeeping; per-stream equality is not global ordering equivalence" if not same else None}

check("transient:230 observed fresh-HIGH rejections",len(hits(data["transient-patched"],0x1547c))==230 and all(h["registers"]["r0"]=="0x00000001" for h in hits(data["transient-patched"],0x1547c)))
check("late release remains a counterexample",len(hits(data["late-release-patched"],0x8f98))==1 and hits(data["late-release-patched"],0x1547c)[0]["memory"]["0x410080a0"]=="20000000")
for name in ["held-w-original","held-w-patched","release-fresh-w-patched"]:
    check(name+": two starts, release-to-rearm NOT implemented",len(hits(data[name],0x8f98))==len(hits(data[name],0x5fa4))==2)
    check(name+":60M continuation",data[name]["instructions_executed"]==60000000)
for mode,expected in [("x1",1),("x2",0)]:
    d=data["analog-"+mode+"-patched"]
    check("analog"+mode+": unchanged first initiation",len(hits(d,0x5f8c))==expected)
    check("analog"+mode+": digital extension never entered",not hits(d,0x15470))
for route in ["B1-full-reset","G-to-enable","W1-nonzero-to-enable"]:
    a,b=data[route+"-original"],data[route+"-patched"]
    check(route+": both reach live-store boundary",a["completed"] and b["completed"] and a["requested_stop_at"]==b["requested_stop_at"])
    check(route+": same enabled TC0 register state",a["memory"]["0x40003800"]==b["memory"]["0x40003800"])
    check(route+": same final channel/live state",a["memory"]["0x20001b14"]==b["memory"]["0x20001b14"])

m=json.loads((ROOT/"modification-manifest.json").read_text())
source=Path(m["original_path"]).read_bytes();patched=(ROOT/m["patched_file"]).read_bytes()
check("original image hash unchanged",hashlib.sha256(source).hexdigest()==m["original_sha256"])
check("patched image identity",hashlib.sha256(patched).hexdigest()==m["patched_sha256"])
off=0x922c-0x4000
check("only intended six-byte original-region replacement",patched[:off]==source[:off] and patched[off+6:len(source)]==source[off+6:])
check("28-byte extension only",len(patched)==len(source)+28)
check("configuration flash preserved",patched[0xe000:0xf001]==source[0xe000:0xf001])
(ROOT/"outcomes.json").write_text(json.dumps({"runs":summary,"comparisons":comparisons,"qualification_policy_status":"PARTIAL: freshness only; C/analog protection not achieved"},indent=2)+"\n")
(ROOT/"checks.json").write_text(json.dumps(checks,indent=2)+"\n")
failed=[c for c in checks if not c["pass"]]
print(f"{len(checks)-len(failed)}/{len(checks)} artifact checks passed; partial policy status is NOT a full safety pass")
for c in failed:print("FAILED:",c["check"])
raise SystemExit(bool(failed))
