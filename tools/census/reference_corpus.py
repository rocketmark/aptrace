"""APTrace census: a mechanically-fetched, mechanically-built reference
source corpus for the AutoPilot/Mando firmware's confirmed build
toolchain -- Adafruit `ArduinoCore-samd` v1.7.11, named directly by
embedded build-path strings in all four firmware images (see
docs/firmware/firmware-layout.md) and already independently fetched and
spot-checked by hand in docs/investigations/boot-and-hardware-bringup.md.
This module makes that fetch-and-compare process itself mechanical,
reusable, and exhaustive rather than a one-off manual investigation.

Every corpus entry (the core itself, the toolchain, CMSIS, CMSIS-Atmel)
is pinned to an EXACT version with a citable reason it belongs in the
corpus -- see `PACKAGES` below. No package is added because it seems
"likely to help"; each one is either named directly by firmware evidence
(the core itself) or mechanically discovered as a real, versioned
dependency of that SAME core (the toolchain version and CMSIS/CMSIS-
Atmel versions all come from the core's own `platform.txt` and from
Adafruit's own published, versioned board-manager package index --
never guessed, never a "latest").

Downloaded sources/toolchain/build artifacts live under
`research/runs/census/reference_corpus/` -- entirely git-ignored (see
`/research/runs/census/` in .gitignore) -- never committed. This module
(the fetch/build recipe) IS committed; the multi-hundred-MB toolchain/
CMSIS downloads and compiled object files are not.

## Board/build-flag justification

The compiled board profile used (`adafruit_feather_m4`, from the core's
own `boards.txt`) is the ONLY Adafruit SAMD board in this core version
whose `build.extra_flags` defines `__SAMD51J19A__` -- an EXACT match to
this project's own independently-confirmed exact part number
(`ATSAMD51J19A`, from physical board inspection -- see
docs/hardware/hardware-reference.md), not a guess. Its board-specific
`variant.cpp`/pin table is NOT used or compiled (a different physical
board's pin layout) -- only `cores/arduino/*` (shared by every SAMD51
board in this core), the board-independent `platform.txt` compiler
flags, and the directly-evidenced `libraries/SPI/SPI.cpp` (named by the
firmware's own embedded build-path strings) are compiled.

Two build settings are NOT independently confirmed from the firmware
and are used as the board's own DEFAULT, disclosed as an assumption:
`build.f_cpu=120000000L` (`boards.txt`'s `menu.speed.120`, the
unmarked/first-listed option) and `-Os` (`menu.opt.small`, likewise the
default). Both affect only F_CPU-derived constants and code-generation
aggressiveness respectively; a real mismatch would show up as a broad,
uniform drop in match tier (EXACT_BYTES -> RELOCATION_NORMALIZED or
worse) across many core functions, which is exactly the kind of finding
`reference-match`'s summary is built to surface -- see
`docs/tooling/census.md`.
"""
import hashlib
import json
import re
import subprocess
import sys
import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import reference_normalize as rn  # noqa: E402

CORPUS_ROOT = REPO_ROOT / "research" / "runs" / "census" / "reference_corpus"
SOURCES_DIR = CORPUS_ROOT / "sources"
TOOLS_DIR = CORPUS_ROOT / "tools"
BUILD_DIR = CORPUS_ROOT / "build"
INDEX_DIR = CORPUS_ROOT / "index"

ADAFRUIT_INDEX_URL = "https://adafruit.github.io/arduino-board-index/package_adafruit_index.json"

# ---------------------------------------------------------------------------
# Package registry -- every corpus entry, with its provenance.
# ---------------------------------------------------------------------------

CORE_PKG = {
    "pkg_key": "adafruit-arduinocore-samd",
    "name": "adafruit/ArduinoCore-samd",
    "version": "1.7.11",
    "kind": "git",
    "repo_url": "https://github.com/adafruit/ArduinoCore-samd.git",
    "ref": "1.7.11",
    "license": "LGPL-2.1 (cores/arduino; see per-directory LICENSE.md/headers for exceptions)",
    "relevance": "PRIMARY reference target -- named directly by embedded build-path strings in "
                 "all four firmware images: '...packages\\\\adafruit\\\\hardware\\\\samd\\\\1.7.11\\\\"
                 "libraries\\\\SPI\\\\SPI.cpp' (docs/firmware/firmware-layout.md), independently "
                 "fetched and spot-checked in docs/investigations/boot-and-hardware-bringup.md.",
    "discovered_via": "strings scan on the firmware .bin files (docs/firmware/firmware-layout.md)",
}

TOOLCHAIN_PKG = {
    "pkg_key": "arm-none-eabi-gcc",
    "name": "arm-none-eabi-gcc (GNU Tools for Arm Embedded Processors)",
    "version": "9-2019q4",
    "kind": "archive",
    "archive_url": "https://github.com/adafruit/arduino-board-index/releases/download/build-tools/"
                    "gcc-arm-none-eabi-9-2019-q4-major-mac.tar.bz2",
    "license": "Mixed GPL/BSD (GNU Arm Embedded Toolchain distribution terms)",
    "relevance": "The EXACT compiler version Adafruit's own board-manager package index pins for "
                 "samd core v1.7.11 (toolsDependencies: packager=adafruit, name=arm-none-eabi-gcc, "
                 "version=9-2019q4) -- never a generic/latest arm-none-eabi-gcc.",
    "discovered_via": f"{ADAFRUIT_INDEX_URL}, toolsDependencies for architecture=samd version=1.7.11",
}

CMSIS_PKG = {
    "pkg_key": "cmsis-5",
    "name": "ARM-software/CMSIS_5 (CMSIS Core/DSP)",
    "version": "5.4.0",
    "kind": "archive",
    "archive_url": "https://github.com/ARM-software/CMSIS_5/archive/5.4.0.tar.gz",
    "license": "Apache-2.0",
    "relevance": "Header-only (CMSIS/Core/Include, CMSIS/DSP/Include) build dependency named "
                 "directly in the core's own platform.txt (compiler.arm.cmsis.c.flags) at this "
                 "EXACT version -- required to compile cores/arduino at all, not a source of "
                 "compiled application/platform functions itself (no .c/.cpp files built from it).",
    "discovered_via": f"{CORE_PKG['repo_url']} platform.txt (compiler.arm.cmsis.c.flags), tag 1.7.11",
}

ZERODMA_PKG = {
    "pkg_key": "adafruit-zerodma",
    "name": "adafruit/Adafruit_ZeroDMA",
    "version": "655916e (submodule pin)",
    "kind": "git",
    "repo_url": "https://github.com/adafruit/Adafruit_ZeroDMA",
    "ref": "655916e504e24ec92a46dd17c057ead9e2fe402d",
    "license": "MIT",
    "relevance": "A build-time HEADER dependency of libraries/SPI/SPI.cpp (directly evidenced by "
                 "embedded build-path strings) -- SPI.h includes <Adafruit_ZeroDMA.h>. Vendored in "
                 "adafruit-arduinocore-samd-1.7.11 as a git submodule that a shallow --depth 1 clone "
                 "does not fetch; the EXACT pinned commit is read directly from that repo's own "
                 ".gitmodules gitlink, never guessed at 'latest'. Only the header is used (to make "
                 "SPI.cpp compile at all) -- Adafruit_ZeroDMA's own .cpp is NOT compiled into this "
                 "corpus (no firmware evidence names it directly).",
    "discovered_via": f"{CORE_PKG['repo_url']} .gitmodules (libraries/Adafruit_ZeroDMA gitlink), tag 1.7.11",
}

CMSIS_ATMEL_PKG = {
    "pkg_key": "cmsis-atmel",
    "name": "adafruit/ArduinoModule-CMSIS-Atmel",
    "version": "1.2.2",
    "kind": "archive",
    "archive_url": "https://github.com/adafruit/ArduinoModule-CMSIS-Atmel/releases/download/"
                    "v1.2.2/CMSIS-Atmel-1.2.2.tar.bz2",
    "license": "Apache-2.0 (Microchip/Atmel device headers + startup, Adafruit-packaged)",
    "relevance": "ATSAMD51 device headers AND the compiled CMSIS startup/system files "
                 "(startup_samd51.c, system_samd51.c) -- resolves this project's own previously-"
                 "documented 'UNKNOWN, honestly' open item (docs/investigations/boot-and-hardware-"
                 "bringup.md: 'CMSIS SystemInit()'s exact upstream source... a separate, unfetched "
                 "Microchip CMSIS-Atmel package'). Version pinned identically to CMSIS_5 above.",
    "discovered_via": f"{CORE_PKG['repo_url']} platform.txt (compiler.arm.cmsis.c.flags), tag 1.7.11",
}

PACKAGES = [CORE_PKG, TOOLCHAIN_PKG, CMSIS_PKG, CMSIS_ATMEL_PKG, ZERODMA_PKG]

# ---------------------------------------------------------------------------
# Build variant -- see module docstring for the board/flag justification.
# ---------------------------------------------------------------------------

BOARD = "adafruit_feather_m4"
VARIANT_KEY = f"{BOARD}-Os"
BUILD_MCU = "cortex-m4"
BUILD_EXTRA_FLAGS = ("-D__SAMD51J19A__", "-DADAFRUIT_FEATHER_M4_EXPRESS", "-D__SAMD51__",
                     "-D__FPU_PRESENT", "-DARM_MATH_CM4", "-mfloat-abi=hard", "-mfpu=fpv4-sp-d16")
F_CPU = "120000000L"  # boards.txt menu.speed.120 default -- NOT independently confirmed, see module docstring
OPTIMIZE = "-Os"       # boards.txt menu.opt.small default -- NOT independently confirmed, see module docstring

COMMON_DEFINES = (
    f"-DF_CPU={F_CPU}", "-DARDUINO=10812", f"-DARDUINO_{BOARD.upper()}",
    "-DARDUINO_ARCH_SAMD", "-DARDUINO_SAMD_ADAFRUIT",
)

C_FLAGS = (
    f"-mcpu={BUILD_MCU}", "-mthumb", "-c", "-g", OPTIMIZE, "-std=gnu11",
    "-ffunction-sections", "-fdata-sections", "-nostdlib",
    "--param", "max-inline-insns-single=500", '-D__SKETCH_NAME__="reference_corpus"',
) + BUILD_EXTRA_FLAGS

CXX_FLAGS = (
    f"-mcpu={BUILD_MCU}", "-mthumb", "-c", "-g", OPTIMIZE, "-std=gnu++11",
    "-ffunction-sections", "-fdata-sections", "-fno-threadsafe-statics", "-nostdlib",
    "--param", "max-inline-insns-single=500", "-fno-rtti", "-fno-exceptions",
    '-D__SKETCH_NAME__="reference_corpus"',
) + BUILD_EXTRA_FLAGS

# Source files actually compiled -- see module docstring for why this
# set and no more: the full shared core (unconditionally compiled for
# ANY sketch on this core, board-independent) plus the ONE library
# directly named by the firmware's own embedded build-path strings.
# CMSIS-Atmel's startup/system files are attributed to CMSIS_ATMEL_PKG,
# everything under cores/arduino and libraries/SPI to CORE_PKG.
CORE_RELATIVE_FILES = (
    "cores/arduino/IPAddress.cpp", "cores/arduino/Print.cpp", "cores/arduino/Reset.cpp",
    "cores/arduino/SERCOM.cpp", "cores/arduino/Stream.cpp", "cores/arduino/Tone.cpp",
    "cores/arduino/Uart.cpp", "cores/arduino/WInterrupts.c", "cores/arduino/WMath.cpp",
    "cores/arduino/WString.cpp", "cores/arduino/abi.cpp", "cores/arduino/cortex_handlers.c",
    "cores/arduino/delay.c", "cores/arduino/hooks.c", "cores/arduino/itoa.c",
    "cores/arduino/main.cpp", "cores/arduino/math_helper.c", "cores/arduino/new.cpp",
    "cores/arduino/pulse.c", "cores/arduino/startup.c", "cores/arduino/wiring.c",
    "cores/arduino/wiring_analog.c", "cores/arduino/wiring_digital.c",
    "cores/arduino/wiring_private.c", "cores/arduino/wiring_shift.c",
    "libraries/SPI/SPI.cpp",
)
CMSIS_ATMEL_RELATIVE_FILES = (
    "CMSIS/Device/ATMEL/samd51/source/system_samd51.c",
    "CMSIS/Device/ATMEL/samd51/source/as_gcc/startup_samd51.c",
)


def _run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _core_source_dir():
    return SOURCES_DIR / f"{CORE_PKG['pkg_key']}-{CORE_PKG['version']}"


def _zerodma_dir():
    return SOURCES_DIR / f"{ZERODMA_PKG['pkg_key']}-{ZERODMA_PKG['ref'][:7]}"


def _toolchain_dir():
    matches = [m for m in TOOLS_DIR.glob("gcc-arm-none-eabi-*") if m.is_dir()]
    return matches[0] if matches else None


def _cmsis_dir():
    return TOOLS_DIR / f"{CMSIS_PKG['pkg_key']}-{CMSIS_PKG['version']}"


def _cmsis_atmel_dir():
    """Returns the directory that directly CONTAINS `CMSIS/Device/ATMEL`
    (the tarball's own top-level dir varies by release, so this walks
    one level to find it rather than hard-coding a name)."""
    root = TOOLS_DIR / f"{CMSIS_ATMEL_PKG['pkg_key']}-{CMSIS_ATMEL_PKG['version']}"
    if (root / "CMSIS" / "Device" / "ATMEL").is_dir():
        return root
    for m in root.glob("*"):
        if (m / "CMSIS" / "Device" / "ATMEL").is_dir():
            return m
    return None


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def fetch(conn=None, verbose=True):
    """Mechanically fetch every corpus entry -- git-clone a pinned tag
    (recording the RESOLVED commit) or download a versioned release
    archive (recording its sha256) -- never an unpinned 'latest'."""
    SOURCES_DIR.mkdir(parents=True, exist_ok=True)
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    results = []

    # 1. The core itself (git, pinned tag).
    core_dir = _core_source_dir()
    if not core_dir.exists():
        if verbose:
            print(f"  cloning {CORE_PKG['repo_url']} @ {CORE_PKG['ref']} ...")
        r = _run(["git", "clone", "--branch", CORE_PKG["ref"], "--depth", "1",
                   CORE_PKG["repo_url"], str(core_dir)])
        if r.returncode != 0:
            raise RuntimeError(f"git clone failed: {r.stderr}")
    resolved = _run(["git", "rev-parse", "HEAD"], cwd=core_dir).stdout.strip()
    results.append({**CORE_PKG, "resolved_commit": resolved, "archive_sha256": None})
    if verbose:
        print(f"  {CORE_PKG['name']} @ {CORE_PKG['ref']} -> {resolved}")

    # 1b. Adafruit_ZeroDMA (git submodule of the core, pinned by the
    # core's own .gitmodules gitlink -- a shallow clone of the core
    # doesn't fetch submodule content, so this is fetched separately at
    # the EXACT pinned commit).
    zerodma_dir = _zerodma_dir()
    if not zerodma_dir.exists():
        if verbose:
            print(f"  cloning {ZERODMA_PKG['repo_url']} @ {ZERODMA_PKG['ref']} ...")
        r = _run(["git", "clone", ZERODMA_PKG["repo_url"], str(zerodma_dir)])
        if r.returncode != 0:
            raise RuntimeError(f"git clone failed: {r.stderr}")
        r = _run(["git", "checkout", ZERODMA_PKG["ref"]], cwd=zerodma_dir)
        if r.returncode != 0:
            raise RuntimeError(f"git checkout of pinned commit failed: {r.stderr}")
    resolved_zd = _run(["git", "rev-parse", "HEAD"], cwd=zerodma_dir).stdout.strip()
    results.append({**ZERODMA_PKG, "resolved_commit": resolved_zd, "archive_sha256": None})
    if verbose:
        print(f"  {ZERODMA_PKG['name']} @ {ZERODMA_PKG['ref']} -> {resolved_zd}")

    # 2. Toolchain, CMSIS, CMSIS-Atmel (versioned archives).
    for pkg, extract_to, strip in (
            (TOOLCHAIN_PKG, TOOLS_DIR, None),
            (CMSIS_PKG, _cmsis_dir(), "CMSIS_5-5.4.0"),
            (CMSIS_ATMEL_PKG, TOOLS_DIR / f"{CMSIS_ATMEL_PKG['pkg_key']}-{CMSIS_ATMEL_PKG['version']}", None)):
        archive_name = pkg["archive_url"].rsplit("/", 1)[-1]
        archive_path = TOOLS_DIR / archive_name
        if not archive_path.exists():
            if verbose:
                print(f"  downloading {pkg['name']} {pkg['version']} ...")
            r = _run(["curl", "-sL", "-o", str(archive_path), pkg["archive_url"]])
            if r.returncode != 0 or not archive_path.exists():
                raise RuntimeError(f"download failed for {pkg['name']}: {r.stderr}")
        digest = _sha256_file(archive_path)
        if pkg is TOOLCHAIN_PKG and not _toolchain_dir():
            _run(["tar", "xjf", str(archive_path)], cwd=TOOLS_DIR)
        elif pkg is CMSIS_PKG and not (extract_to / "CMSIS").exists():
            extract_to.mkdir(parents=True, exist_ok=True)
            _run(["tar", "xzf", str(archive_path), "-C", str(extract_to), "--strip-components=1",
                   f"{strip}/CMSIS/Core/Include", f"{strip}/CMSIS/DSP/Include", f"{strip}/CMSIS/Lib",
                   f"{strip}/LICENSE.txt"])
        elif pkg is CMSIS_ATMEL_PKG and not extract_to.exists():
            extract_to.mkdir(parents=True, exist_ok=True)
            _run(["tar", "xjf", str(archive_path), "-C", str(extract_to)])
        results.append({**pkg, "resolved_commit": None, "archive_sha256": digest})
        if verbose:
            print(f"  {pkg['name']} {pkg['version']} -> sha256={digest[:16]}...")

    if conn is not None:
        _persist_packages(conn, results)
    return results


def _persist_packages(conn, results):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for r in results:
        conn.execute(
            "INSERT INTO reference_packages (pkg_key, name, version, kind, repo_url, ref, "
            "resolved_commit, archive_url, archive_sha256, license, relevance, discovered_via, "
            "fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(pkg_key) DO UPDATE SET resolved_commit=excluded.resolved_commit, "
            "archive_sha256=excluded.archive_sha256, fetched_at=excluded.fetched_at",
            (r["pkg_key"], r["name"], r["version"], r["kind"], r.get("repo_url"), r.get("ref"),
             r.get("resolved_commit"), r.get("archive_url"), r.get("archive_sha256"), r["license"],
             r["relevance"], r["discovered_via"], now))
    conn.commit()


# ---------------------------------------------------------------------------
# build -- compile every evidenced source file, extract per-symbol facts.
# ---------------------------------------------------------------------------

_INSN_LINE_RE = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f ]+?)\s+(\S+)(?:\s+(.*))?$")


def _objdump_opcode_to_mem_bytes(text):
    """objdump prints a Thumb instruction's opcode field as one or more
    space-separated 16-bit-halfword VALUES (most-significant hex digit
    first, like a normal hex number written down -- e.g. 'f7ff fffe'
    for a 4-byte Thumb-2 BL) -- NOT the raw little-endian memory byte
    sequence. Each halfword must be individually byte-swapped to
    reconstruct the real bytes (confirmed this pass: without this, a
    tool's OWN `millis()` never matched its byte-identical firmware
    counterpart at all -- every hash silently used the wrong byte
    order on the reference side)."""
    out = bytearray()
    for group in text.split():
        out.extend(bytes.fromhex(group)[::-1])
    return bytes(out)
_RELOC_LINE_RE = re.compile(r"^\s+([0-9a-f]+):\s+(R_\S+)\s+(\S+)$")
_DATA_MNEM = {".word", ".short", ".byte"}
_SECTION_RE = re.compile(r"^Disassembly of section \.text\.(\S+):$")


def _parse_objdump(text):
    """Parse `objdump -dr` output for possibly MULTIPLE symbols (one
    per `.text.<symbol>` section, gcc's -ffunction-sections layout).
    Returns {symbol: (instructions, relocated_offsets)} where each
    instruction is (rel_offset, hex_bytes, mnemonic, op_str) --
    excludes any data pseudo-op (a literal pool -- never treated as
    code, see reference_normalize.py's docstring). Callers must ALSO
    apply `reference_normalize.trim_trailing_padding` -- this function
    does not (kept as a single, explicit, shared step both sides of
    the comparison call identically)."""
    out = {}
    current = None
    instrs, relocs = [], set()
    base_off = None

    def flush():
        if current is not None:
            out[current] = (instrs, relocs)

    for line in text.splitlines():
        sec_m = _SECTION_RE.match(line)
        if sec_m:
            flush()
            current = sec_m.group(1)
            instrs, relocs, base_off = [], set(), None
            continue
        reloc_m = _RELOC_LINE_RE.match(line)
        if reloc_m and current is not None:
            off = int(reloc_m.group(1), 16)
            if base_off is not None:
                relocs.add(off - base_off)
            continue
        insn_m = _INSN_LINE_RE.match(line)
        if insn_m and current is not None:
            off_s, hexbytes, mnem, rest = insn_m.groups()
            off = int(off_s, 16)
            if base_off is None:
                base_off = off
            rel_off = off - base_off
            if mnem in _DATA_MNEM:
                # A literal-pool entry (or other data), never real code --
                # excluded from this symbol's instruction stream, matching
                # Ghidra's own function-size convention on the firmware
                # side. gcc's -ffunction-sections already isolates each
                # function in its own .text.<symbol> section, so this
                # never needs to "break" out of the loop -- the next
                # `Disassembly of section .text.<sym>:` header (if any)
                # is handled by `_SECTION_RE` above regardless.
                continue
            op_str = (rest or "").split(";")[0].strip()
            instrs.append((rel_off, _objdump_opcode_to_mem_bytes(hexbytes).hex(), mnem, op_str))
    flush()
    return out


def _compile_one(gcc_path, cxx, flags, includes, src, out_dir, verbose):
    obj = out_dir / (Path(src).stem + ".o")
    cmd = [str(gcc_path)] + list(flags) + list(COMMON_DEFINES) + \
        [f"-I{i}" for i in includes] + [str(src), "-o", str(obj)]
    r = _run(cmd)
    if r.returncode != 0:
        return None, r.stderr
    return obj, None


def build(conn, verbose=True):
    """Compile every evidenced source file with the discovered
    toolchain/flags, extract per-symbol facts (bytes, hashes,
    structural signature) via `objdump -dr`, and persist. Returns
    (n_symbols, n_files_ok, n_files_failed, failures)."""
    toolchain_dir = _toolchain_dir()
    if toolchain_dir is None:
        raise RuntimeError("toolchain not fetched -- run 'reference-corpus fetch' first")
    gcc = toolchain_dir / "bin" / "arm-none-eabi-gcc"
    gxx = toolchain_dir / "bin" / "arm-none-eabi-g++"
    objdump = toolchain_dir / "bin" / "arm-none-eabi-objdump"

    core_dir = _core_source_dir()
    cmsis_atmel_dir = _cmsis_atmel_dir()
    cmsis_dir = _cmsis_dir()
    if not core_dir.exists() or cmsis_atmel_dir is None or not (cmsis_dir / "CMSIS").exists():
        raise RuntimeError("sources not fetched -- run 'reference-corpus fetch' first")

    zerodma_dir = _zerodma_dir()
    if not zerodma_dir.exists():
        raise RuntimeError("Adafruit_ZeroDMA not fetched -- run 'reference-corpus fetch' first")

    includes = [
        core_dir / "cores" / "arduino", core_dir / "variants" / "feather_m4",
        zerodma_dir,  # header-only use by libraries/SPI/SPI.cpp (see ZERODMA_PKG) -- not compiled itself
        cmsis_dir / "CMSIS" / "Core" / "Include", cmsis_dir / "CMSIS" / "DSP" / "Include",
        cmsis_atmel_dir / "CMSIS" / "Device" / "ATMEL",
        cmsis_atmel_dir / "CMSIS" / "Device" / "ATMEL" / "samd51" / "include",  # sam.h -> "samd51.h" needs this directly on the search path
    ]

    build_dir = BUILD_DIR / VARIANT_KEY
    build_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cflags_str = " ".join(C_FLAGS + COMMON_DEFINES)
    cxxflags_str = " ".join(CXX_FLAGS + COMMON_DEFINES)
    conn.execute(
        "INSERT INTO reference_build_variants (variant_key, board, mcu, toolchain_name, "
        "toolchain_version, optimize, f_cpu, cflags, cxxflags, confidence_note, built_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(variant_key) DO UPDATE SET built_at=excluded.built_at",
        (VARIANT_KEY, BOARD, BUILD_MCU, "arm-none-eabi-gcc", TOOLCHAIN_PKG["version"], OPTIMIZE, F_CPU,
         cflags_str, cxxflags_str,
         "F_CPU and optimization level are the board's own DEFAULTS (boards.txt menu.speed.120/"
         "menu.opt.small), NOT independently confirmed from the firmware -- see reference_corpus.py's "
         "module docstring.", now))
    conn.commit()
    variant_id = conn.execute(
        "SELECT id FROM reference_build_variants WHERE variant_key=?", (VARIANT_KEY,)).fetchone()["id"]

    pkg_id_by_key = {r["pkg_key"]: r["id"] for r in conn.execute("SELECT id, pkg_key FROM reference_packages")}

    files_ok, files_failed = [], []
    all_symbols = []

    def process(relative_files, base_dir, package_id):
        for rel in relative_files:
            src = base_dir / rel
            if not src.exists():
                files_failed.append((rel, package_id, "source file not found"))
                continue
            is_cpp = src.suffix == ".cpp"
            flags = CXX_FLAGS if is_cpp else C_FLAGS
            compiler = gxx if is_cpp else gcc
            obj, err = _compile_one(compiler, is_cpp, flags, includes, src, build_dir, verbose)
            if obj is None:
                files_failed.append((rel, package_id, err.strip()[-2000:]))
                if verbose:
                    print(f"  [FAILED] {rel}: {err.strip().splitlines()[-1] if err.strip() else '?'}")
                continue
            files_ok.append((rel, package_id))
            r = _run([str(objdump), "-dr", str(obj)])
            parsed = _parse_objdump(r.stdout)
            for symbol, (raw_instrs, relocs) in parsed.items():
                instrs = rn.trim_trailing_padding(raw_instrs)
                if not instrs:
                    continue
                hexbytes = "".join(i[1] for i in instrs)
                fp = rn.fingerprint_instructions(instrs, relocated_offsets=relocs)
                exact_hash = hashlib.sha256(bytes.fromhex(hexbytes)).hexdigest()
                all_symbols.append({
                    "build_variant_id": variant_id, "package_id": package_id, "source_file": rel,
                    "symbol": symbol, "byte_size": len(hexbytes) // 2, "exact_hash": exact_hash,
                    "exact_instr_hash": fp["exact_instr_hash"], "reloc_norm_hash": fp["reloc_norm_hash"],
                    "pcrel_norm_hash": fp["pcrel_norm_hash"], "n_instructions": fp["n_instructions"],
                    "n_branches": fp["n_branches"], "raw_bytes_hex": hexbytes,
                })
            if verbose:
                print(f"  [ok] {rel} -> {len(parsed)} symbol(s)")

    process(CORE_RELATIVE_FILES, core_dir, pkg_id_by_key[CORE_PKG["pkg_key"]])
    process(CMSIS_ATMEL_RELATIVE_FILES, cmsis_atmel_dir, pkg_id_by_key[CMSIS_ATMEL_PKG["pkg_key"]])

    # A rebuild invalidates every PRIOR reference-match result across
    # EVERY firmware (they reference reference_symbols rows this DELETE
    # is about to replace) -- cleared here rather than leaving a stale
    # FK-referencing row or a foreign-key error; `census reduce`'s own
    # library_matches confirmations degrade gracefully (see
    # reference_match.apply_to_library_matches) until `reference-match`
    # is rerun per firmware.
    conn.execute("DELETE FROM reference_match_candidates WHERE reference_symbol_id IN "
                 "(SELECT id FROM reference_symbols WHERE build_variant_id=?)", (variant_id,))
    conn.execute("DELETE FROM reference_matches WHERE reference_symbol_id IN "
                 "(SELECT id FROM reference_symbols WHERE build_variant_id=?)", (variant_id,))
    conn.execute("DELETE FROM reference_symbols WHERE build_variant_id=?", (variant_id,))
    for s in all_symbols:
        conn.execute(
            "INSERT INTO reference_symbols (build_variant_id, package_id, source_file, symbol, "
            "byte_size, exact_hash, exact_instr_hash, reloc_norm_hash, pcrel_norm_hash, "
            "n_instructions, n_branches, raw_bytes_hex) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (s["build_variant_id"], s["package_id"], s["source_file"], s["symbol"], s["byte_size"],
             s["exact_hash"], s["exact_instr_hash"], s["reloc_norm_hash"], s["pcrel_norm_hash"],
             s["n_instructions"], s["n_branches"], s["raw_bytes_hex"]))
    conn.execute("DELETE FROM reference_build_files WHERE build_variant_id=?", (variant_id,))
    for rel, package_id in files_ok:
        conn.execute("INSERT INTO reference_build_files (build_variant_id, package_id, source_file, "
                     "status, error) VALUES (?,?,?,'ok',NULL)", (variant_id, package_id, rel))
    for rel, package_id, err in files_failed:
        conn.execute("INSERT INTO reference_build_files (build_variant_id, package_id, source_file, "
                     "status, error) VALUES (?,?,?,'failed',?)", (variant_id, package_id, rel, err))
    conn.commit()

    if verbose:
        print(f"\nBuild complete: {len(all_symbols)} symbol(s) from {len(files_ok)} file(s), "
              f"{len(files_failed)} file(s) failed")
        for rel, _pkg, err in files_failed:
            print(f"  FAILED: {rel} -- {err.splitlines()[-1] if err else '?'}")
    return len(all_symbols), len(files_ok), len(files_failed), files_failed
