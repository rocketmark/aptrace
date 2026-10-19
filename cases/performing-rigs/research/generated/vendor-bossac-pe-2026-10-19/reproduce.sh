#!/bin/sh
set -eu
# Run from the repository root. Vendor EXE is data only. Fresh isolated cache/output.
export JAVA_HOME=${JAVA_HOME:-/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home}
export JAVA_TOOL_OPTIONS=${JAVA_TOOL_OPTIONS:--Duser.home=/tmp/aptrace-ghidra-home}
mkdir -p /tmp/aptrace-ghidra-home
out=${1:-$(mktemp -d /tmp/aptrace-vendor-pe-evidence.XXXXXX)}
mkdir -p "$out"
export APTRACE_GHIDRA_CACHE_ROOT=${APTRACE_GHIDRA_CACHE_ROOT:-$(mktemp -d /tmp/aptrace-vendor-pe-cache.XXXXXX)/cache}
python3 tools/ghidra/aptrace_ghidra.py build vendor_bossac
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 500 --address 0x40e100 --out "$out/config-constructor.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 1000 --address 0x42ae40 --out "$out/config-init.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac xrefs --limit 100 --address 0x00438040 --out "$out/config-xrefs.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 1000 --address 0x4032a0 --out "$out/d5-autoerase-toggle.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 1000 --address 0x403740 --out "$out/d5-command.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac function --limit 500 --address 0x4035a0 --out "$out/d5-constructor.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 1000 --address 0x403800 --out "$out/d5-erase.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 1000 --address 0x4038c0 --out "$out/d5-eraseall.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 1000 --address 0x403ac0 --out "$out/d5-options.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 1000 --address 0x4032b0 --out "$out/d5-security-read.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac data --limit 128 --address 0x00436ae8 --out "$out/d5-vtable.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 500 --address 0x403910 --out "$out/d5-writebuffer.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 1000 --address 0x403970 --out "$out/d5-writepage.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac function --limit 1000 --address 0x4089a0 --out "$out/device-function.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac callers --limit 100 --address 0x00407470 --out "$out/erase-callers.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac function --limit 1000 --address 0x00407470 --out "$out/erase-function.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac xrefs --limit 100 --address 0x00432867 --out "$out/erase-xrefs.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 1000 --address 0x402df0 --out "$out/flash-writebuffer.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac cfg --limit 1000 --address 0x42ae60 --out "$out/main-cfg.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac function --limit 1000 --address 0x0042ae60 --out "$out/main-function.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac data --limit 864 --address 0x42d080 --out "$out/options-table.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac function --limit 1000 --address 0x40e570 --out "$out/parser-function.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 1000 --address 0x40d1f0 --out "$out/reset.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 1000 --address 0x402900 --out "$out/samba-chiperase.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac entry-function --limit 1000 --address 0x402a00 --out "$out/samba-writebuffer.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac xrefs --limit 100 --address 0x00438078 --out "$out/usb-default-xrefs.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac function --limit 1000 --address 0x4079d0 --out "$out/verify-function.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac references --limit 1000 --pattern '0x00436b' --out "$out/vtable-references.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac function --limit 1000 --address 0x4074c0 --out "$out/write-function.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac inventory --out "$out/inventory.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac imports --limit 1000 --out "$out/imports.json"
python3 tools/ghidra/aptrace_ghidra.py exe-query vendor_bossac search --pattern flash --limit 1000 --out "$out/flash-strings.json"
agent/.venv/bin/aptrace-agent research 'bossac.exe offset erase write verify reset' --max-steps 12 --output "$out/research.json"
echo "Evidence: $out"
