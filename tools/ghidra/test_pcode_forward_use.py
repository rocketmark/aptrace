#!/usr/bin/env python3
"""APTrace: acceptance coverage for tools/ghidra/pcode_forward_use.py.
Plain assertions, same convention as test_aptrace_ghidra.py. Needs Ghidra
(about 3 s per suite); runs no case code and touches no case data.

    python3 tools/ghidra/test_pcode_forward_use.py

Covers: the architecture spike's 11 Thumb and 7 RV32 controls and the
added negative controls (fixtures/pcode_forward_use/controls.json, exact
expectations), byte-identical repeat runs, project mode on a scratch copy
of an analyzed fixture project (the source project is unchanged), request
validation, the engine-unavailable path, the verdict policy, and a static
check that the walker and driver name no instruction set.
"""
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pcode_forward_use as pfu  # noqa: E402
from headless import find_headless  # noqa: E402

FIXTURES = HERE / "fixtures" / "pcode_forward_use"
FAILURES = []


def check(name, condition, detail=""):
    print(f"  [{'ok' if condition else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def _function(spec):
    entry, _, body = spec.partition(":")
    ranges = tuple((int(lo, 0), int(hi, 0)) for lo, hi in (r.split("-") for r in body.split(",") if r))
    return pfu.FunctionSpec(int(entry, 0), ranges)


def _origin(spec):
    addr, _, reg = spec.partition(":")
    return pfu.Origin(int(addr, 0), reg or None)


def suite_target(suite):
    return pfu.Target(
        image=FIXTURES / suite["image"],
        image_sha256=suite["sha256"],
        language_id=suite["language"],
        compiler_spec_id=suite["cspec"],
        base=int(suite["base"], 0),
        functions=tuple(_function(f) for f in suite.get("functions", ())),
        disassemble=tuple(int(a, 0) for a in suite.get("disassemble", ())),
    )


def run_suite(suite):
    doc, m = pfu.run_forward_use(
        suite_target(suite), [_origin(o["origin"]) for o in suite["origins"]],
        max_steps=suite.get("max_steps", pfu.DEFAULT_MAX_STEPS))
    return doc, m


def canonical(doc):
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))


def test_controls(manifest):
    print("controls (controls.json):")
    measurements = []
    docs = {}
    for suite in manifest["suites"]:
        doc, m = run_suite(suite)
        docs[suite["name"]] = doc
        measurements.append((suite["name"], m))
        check(f"{suite['name']}: engine ran", doc["status"] == "ok", doc.get("status"))
        check(f"{suite['name']}: language/cspec recorded",
              doc["engine"]["language_id"] == suite["language"] and doc["engine"]["compiler_spec_id"] == suite["cspec"])
        for expected, got in zip(suite["origins"], doc["results"]):
            name = f"{suite['name']}/{expected['case']}"
            ok = got["verdict"] == expected["verdict"]
            if "escape_kinds" in expected:
                ok &= got["escape_kinds"] == expected["escape_kinds"]
            ok &= sorted(i["code"] for i in got.get("incomplete") or []) == sorted(expected.get("incomplete", []))
            if "unsupported" in expected:
                ok &= (got.get("unsupported") or {}).get("code") == expected["unsupported"]
            for code in expected.get("precision", []):
                ok &= code in [p["code"] for p in got.get("precision", [])]
            # A negative verdict is only ever a complete one.
            ok &= got["verdict"] != pfu.NO_ESCAPE or got["complete"]
            check(name, ok, f"got {got['verdict']} {got.get('escape_kinds')} "
                            f"{[i['code'] for i in got.get('incomplete') or []]} {got.get('unsupported')}")
    return docs, measurements


def test_spike_parity(manifest):
    """Every spike ground-truth escape is found, or the deviation is a labeled imprecision."""

    print("spike ground truth (expected.json escapes):")
    walker_kind = {"CONTROL_TRANSFER": "CONTROL_FLOW_ESCAPE", "STORE": "MEMORY_ESCAPE",
                   "ARGUMENT": "ARGUMENT_ESCAPE", "RETURN_VALUE": "RETURN_ESCAPE"}
    n = 0
    for suite in manifest["suites"]:
        for o in suite["origins"]:
            if "spike_escapes" not in o:
                continue
            n += 1
            spike = {walker_kind[k] for k in o["spike_escapes"]}
            got = set(o["escape_kinds"])
            sound = (not spike and not got) or bool(spike & got) or ("MEMORY_FLOW_NOT_FOLLOWED" in o.get("precision", []) and got)
            check(f"{o['case']}: {sorted(spike) or 'no escape'} -> {o['assessment']}", sound)
    check("18 spike controls covered", n == 18, str(n))


def test_determinism(manifest):
    print("determinism:")
    suite = manifest["suites"][0]
    a, _ = run_suite(suite)
    b, _ = run_suite(suite)
    check("two runs give byte-identical canonical results", canonical(a) == canonical(b))
    check("result carries no wall-clock or path data",
          not re.search(r"/aptrace-pcode-|/tmp/|/var/folders/|wall_seconds|peak_rss", canonical(a)))


def _tree_hashes(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def _build_project(directory, image, suite, analyze):
    directory.mkdir()
    cmd = [str(find_headless()), str(directory), "fixture", "-import", str(image), "-processor", suite["language"],
           "-cspec", suite["cspec"], "-loader", "BinaryLoader", "-loader-baseAddr", suite["base"],
           "-scriptPath", str(FIXTURES), "-preScript", "APTracePcodeForwardUseTestSeed.java", ",".join(suite["functions"])]
    subprocess.run(cmd + ([] if analyze else ["-noanalysis"]), capture_output=True, text=True)
    return pfu.GhidraProject(directory, "fixture", image.name, identity="test")


def test_project_mode(manifest):
    """Project mode reads an analyzed project through a scratch copy; the source is unchanged."""

    print("project mode (fixture projects, scratch copy):")
    suite = manifest["suites"][0]
    expected = [o["verdict"] for o in suite["origins"]]
    origins = [_origin(o["origin"]) for o in suite["origins"]]
    with tempfile.TemporaryDirectory(prefix="aptrace-pfu-test-") as tmp:
        image = Path(tmp) / suite["image"]
        shutil.copy2(FIXTURES / suite["image"], image)
        seeded = _build_project(Path(tmp) / "seeded", image, suite, analyze=False)
        check("seeded fixture project built", (seeded.directory / "fixture.gpr").exists())
        before = _tree_hashes(seeded.directory)
        target = pfu.Target(image, suite["sha256"], suite["language"], suite["cspec"], 0, project=seeded)
        doc, _ = pfu.run_forward_use(target, origins)
        verdicts = [r["verdict"] for r in doc["results"]]
        check("project mode reproduces the import-mode verdicts", verdicts == expected, str(verdicts))
        check("source project unchanged (byte-identical files)", _tree_hashes(seeded.directory) == before)
        check("no lock files left in the source project",
              not any(p.name.endswith((".lock", ".lock~")) for p in seeded.directory.rglob("*")))
        try:
            pfu.run_forward_use(pfu.Target(image, suite["sha256"], suite["language"], suite["cspec"], 0,
                                           project=seeded, functions=(pfu.FunctionSpec(0),)), [pfu.Origin(0)])
            check("project mode refuses function creation", False)
        except pfu.ForwardUseError:
            check("project mode refuses function creation", True)

        # Auto-analysis with the language's defaults changes boundaries (at
        # base 0 the Cortex analyzer reads a vector table and creates
        # functions inside C1). Whatever changes, it must never become a
        # silent negative.
        analyzed = _build_project(Path(tmp) / "analyzed", image, suite, analyze=True)
        doc, _ = pfu.run_forward_use(pfu.Target(image, suite["sha256"], suite["language"], suite["cspec"], 0,
                                                project=analyzed), origins)
        changed = [(o["case"], o["verdict"], r["verdict"]) for o, r in zip(suite["origins"], doc["results"])
                   if o["verdict"] != r["verdict"]]
        print(f"    auto-analyzed project, changed verdicts: {changed or 'none'}")
        check("auto-analyzed boundaries never turn a result into NO_ESCAPE",
              all(new != pfu.NO_ESCAPE for _, _, new in changed))


def test_validation(manifest):
    print("request validation:")
    suite = manifest["suites"][0]
    target = suite_target(suite)
    cases = {
        "origin outside the image": (target, [pfu.Origin(0x10_0000)], {}),
        "no origin": (target, [], {}),
        "image sha256 mismatch": (pfu.Target(target.image, "0" * 64, target.language_id, target.compiler_spec_id, 0), [pfu.Origin(0)], {}),
        "step budget out of range": (target, [pfu.Origin(0)], {"max_steps": 0}),
    }
    for name, (t, origins, kw) in cases.items():
        try:
            pfu.run_forward_use(t, origins, **kw)
            check(f"rejects {name}", False)
        except pfu.ForwardUseError:
            check(f"rejects {name}", True)

    saved = pfu.find_headless
    pfu.find_headless = lambda: None
    try:
        doc, _ = pfu.run_forward_use(target, [pfu.Origin(0)])
    finally:
        pfu.find_headless = saved
    r = doc["results"][0]
    check("missing engine is an explicit UNSUPPORTED result",
          doc["status"] == "engine_unavailable" and r["verdict"] == pfu.UNSUPPORTED
          and r["unsupported"]["code"] == "ENGINE_UNAVAILABLE")


def test_policy():
    print("verdict policy:")
    base = {"status": "analyzed", "uses": [], "incomplete": []}
    store = {"kind": "STORE", "store_target": {"region": "stack"}}
    check("complete, no escaping use -> NO_ESCAPE_WITHIN_SCOPE",
          pfu.classify({**base, "uses": [{"kind": "COMPARE"}]})["verdict"] == pfu.NO_ESCAPE)
    r = pfu.classify({**base, "uses": [{"kind": "COMPARE"}], "incomplete": [{"code": "BUDGET_EXHAUSTED"}]})
    check("incomplete, no escaping use -> INCOMPLETE, never a negative", r["verdict"] == pfu.INCOMPLETE and not r["complete"])
    r = pfu.classify({**base, "uses": [store], "incomplete": [{"code": "FLOW_LEAVES_FUNCTION"}]})
    check("an escape found on an analyzed path stands; completeness stays false",
          r["verdict"] == pfu.ESCAPE and r["escape_kinds"] == ["MEMORY_ESCAPE"] and not r["complete"])
    check("a stack store is labeled MEMORY_FLOW_NOT_FOLLOWED", "MEMORY_FLOW_NOT_FOLLOWED" in [p["code"] for p in r["precision"]])
    try:
        pfu.classify({**base, "uses": [{"kind": "SOMETHING_NEW"}]})
        check("an unclassified walker use kind is an error, not ignored", False)
    except RuntimeError:
        check("an unclassified walker use kind is an error, not ignored", True)
    r = pfu.classify({"status": "unsupported", "unsupported_code": "NO_INSTRUCTION", "unsupported_detail": "x"})
    check("unsupported origin -> UNSUPPORTED", r["verdict"] == pfu.UNSUPPORTED and r["unsupported"]["code"] == "NO_INSTRUCTION")


# Instruction-set vocabulary that must not appear in the generic walker or
# driver code (comments and docstrings excluded): register names, modes,
# mnemonics and architecture names.
ISA_TOKENS = re.compile(
    r"\b(r(?:[0-9]|1[0-5])|sp|lr|ip|a[0-7]|ra|x[0-9]+|thumb|arm|aarch\d*|riscv|rv32|rv64|cortex|tmode|"
    r"isamodeswitch|aapcs|ldr|str|blx|bx|bl|cbz|cbnz|jalr|auipc|mips|x86)\b", re.IGNORECASE)


def _code_only(text, java):
    if java:
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        text = re.sub(r"//[^\n]*", "", text)
    else:
        text = re.sub(r'"""(.*?)"""', "", text, flags=re.S)
        text = re.sub(r"#[^\n]*", "", text)
    return re.sub(r'"(?:[^"\\\n]|\\.)*"', '""', text)


def test_isa_neutral():
    print("ISA neutrality (static):")
    for path, java in ((pfu.WALKER_SCRIPT, True), (Path(pfu.__file__), False)):
        # `str` is a Python builtin, not the mnemonic.
        hits = sorted({m.group(0) for m in ISA_TOKENS.finditer(_code_only(path.read_text(), java))} - (set() if java else {"str"}))
        check(f"{path.name} names no instruction set, register or mnemonic", not hits, str(hits))


def main():
    manifest = json.loads((FIXTURES / "controls.json").read_text())
    for suite in manifest["suites"]:
        actual = hashlib.sha256((FIXTURES / suite["image"]).read_bytes()).hexdigest()
        check(f"fixture {suite['image']} matches its pinned sha256", actual == suite["sha256"])
    test_policy()
    test_isa_neutral()
    if find_headless() is None:
        print("Ghidra not found: engine-backed checks skipped")
        return 1
    test_validation(manifest)
    docs, measurements = test_controls(manifest)
    test_spike_parity(manifest)
    test_determinism(manifest)
    test_project_mode(manifest)
    print("measurements (wall s, peak RSS MiB):")
    for name, m in measurements:
        rss = f"{m.peak_rss_bytes / 2**20:.0f}" if m.peak_rss_bytes else "?"
        print(f"  {name}: {m.wall_seconds:.2f} s, {rss} MiB")
    print(f"\n{'FAILED: ' + ', '.join(FAILURES) if FAILURES else 'all checks passed'}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
