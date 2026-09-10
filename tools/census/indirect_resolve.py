"""APTrace census reduce: mechanically classify every indirect
call/jump instruction (both the ones Ghidra already resolved and the
ones it didn't) into one of four evidence tiers:

  STATICALLY_RESOLVED    -- Ghidra's own analysis already resolved it
                             (a `edges` row with resolved=1 and a
                             computed-* kind -- e.g. a jump table Ghidra
                             itself recovered).
  DYNAMICALLY_OBSERVED    -- a real Unicorn run actually executed this
                             instruction with a concrete register value,
                             observed via a dedicated `watch` capture
                             pass over the existing scenario corpus (see
                             `dynamic_candidates`) -- the strongest
                             possible evidence for an otherwise-
                             unresolved site.
  FINITE_CANDIDATE_SET     -- no real execution reached it (or reached it
                             with a value this module couldn't attribute
                             to a known function), but a bounded,
                             mechanical flash scan (a TBB/TBH inline
                             table, or a table based at a nearby
                             Ghidra-resolved literal-pool constant)
                             found a plausible, size-bounded set of
                             candidate targets.
  UNRESOLVED                -- none of the above found anything. Left
                             exactly as unresolved as it was -- never
                             silently upgraded.

Every candidate found by every method is kept in
`indirect_edge_candidates` (never deduplicated away, so two methods
disagreeing stays visible); `indirect_edge_resolutions` holds one
summary classification per instruction address, picking the strongest
tier that actually produced evidence.

No LLM interpretation: the instruction-shape classification is a fixed
Capstone operand-type check, the table scans are bounded byte-pattern
walks, and the dynamic pass is a real, unmodified replay of the
existing tools/unicorn/virtual_link.py scenario corpus with one
additional `watch` list.
"""
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm_const import ARM_OP_REG, ARM_REG_PC

HERE = Path(__file__).resolve().parent

MAX_TABLE_ENTRIES = 64


def _md():
    m = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    m.detail = True
    return m


# Capstone's ARM disassembly text uses the ARM EABI's conventional
# aliases for r9/r10/r11/r12 (sb/sl/fp/ip) -- normalized here to the
# canonical r-number names concrete.py's REG_BY_NAME/registers dict
# actually uses (confirmed necessary this pass: Mando868 has a real
# `bx sl` indirect-call site that a raw `insn.reg_name()` result would
# otherwise silently fail to look up downstream).
_CAPSTONE_REG_ALIASES = {"sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12"}


def _canonical_reg_name(name):
    return _CAPSTONE_REG_ALIASES.get(name, name)


def decode_instruction(firmware_bytes, flash_base, addr):
    """Decode the single Thumb instruction at `addr`. Returns
    (mnemonic, shape, target_reg_name) where shape is one of
    'reg-indirect' (BX/BLX/MOV-to-PC with a register operand --
    target_reg_name names the register holding the target),
    'table-branch' (TBB/TBH -- target_reg_name is None, the table
    immediately follows the instruction), 'mem-indirect' (an LDR whose
    destination is PC -- target_reg_name is None; the target comes from
    a memory read this module doesn't try to symbolically evaluate),
    or 'unknown' (decode failed or an unrecognized indirect shape --
    still recorded, never silently dropped)."""
    off = addr - flash_base
    chunk = firmware_bytes[off:off + 4]
    if not chunk:
        return None, "unknown", None
    insns = list(_md().disasm(chunk, addr, count=1))
    if not insns:
        return None, "unknown", None
    insn = insns[0]
    m = insn.mnemonic.lower()

    if m in ("bx", "blx") and insn.operands and insn.operands[0].type == ARM_OP_REG:
        return m, "reg-indirect", _canonical_reg_name(insn.reg_name(insn.operands[0].reg))
    if m in ("mov", "mov.w") and len(insn.operands) == 2 and \
            insn.operands[0].type == ARM_OP_REG and insn.operands[0].reg == ARM_REG_PC and \
            insn.operands[1].type == ARM_OP_REG:
        return m, "reg-indirect", _canonical_reg_name(insn.reg_name(insn.operands[1].reg))
    if m in ("tbb", "tbb.w", "tbh", "tbh.w"):
        return m, "table-branch", None
    if m.startswith("ldr") and insn.operands and insn.operands[0].type == ARM_OP_REG and \
            insn.operands[0].reg == ARM_REG_PC:
        return m, "mem-indirect", None
    return m, "unknown", None


def scan_pointer_table(firmware_bytes, flash_base, table_base, max_entries=MAX_TABLE_ENTRIES):
    """Bounded scan of consecutive 4-byte words starting at `table_base`
    for a plausible Thumb function-pointer table: stop at the first
    word that ISN'T Thumb-bit-set-and-inside-the-flash-image (the
    table's real end has no explicit length available to this scanner,
    so "the pattern stops looking like a pointer table" is the
    mechanical stopping rule -- see module docstring). Returns a list
    of (index, target_addr) for entries that passed."""
    end = flash_base + len(firmware_bytes)
    out = []
    addr = table_base
    for i in range(max_entries):
        off = addr - flash_base
        if off < 0 or off + 4 > len(firmware_bytes):
            break
        (word,) = __import__("struct").unpack_from("<I", firmware_bytes, off)
        if word & 1 == 0:
            break
        target = word & ~1
        if not (flash_base <= target < end):
            break
        out.append((i, target))
        addr += 4
    return out


def scan_halfword_table(firmware_bytes, flash_base, table_base, entry_width, base_for_offset,
                          max_entries=MAX_TABLE_ENTRIES):
    """TBB (entry_width=1, byte offsets) / TBH (entry_width=2, halfword
    offsets) inline tables: each entry is an offset (in halfwords,
    per the ARMv7-M architecture reference's own TBB/TBH definition --
    not a guess) from `base_for_offset` (the address immediately after
    the TBB/TBH instruction). Stops at the first entry whose resulting
    target address falls outside the flash image."""
    end = flash_base + len(firmware_bytes)
    out = []
    for i in range(max_entries):
        off = (table_base - flash_base) + i * entry_width
        if off < 0 or off + entry_width > len(firmware_bytes):
            break
        raw = firmware_bytes[off] if entry_width == 1 else \
            int.from_bytes(firmware_bytes[off:off + 2], "little")
        target = base_for_offset + 2 * raw
        if not (flash_base <= target < end):
            break
        out.append((i, target))
    return out


def nearby_literal_table_base(conn, firmware_id, from_addr):
    """For a 'mem-indirect' (LDR-into-PC) instruction with no direct
    Ghidra resolution, look for the closest PRECEDING literal_refs row
    within the SAME basic block -- a real PC-relative constant load
    Ghidra's own reference manager already resolved -- and treat its
    target as a candidate jump-table base. Returns an int address, or
    None if no such row exists (nothing to scan from)."""
    block = conn.execute(
        "SELECT start_addr, end_addr FROM basic_blocks WHERE firmware_id=? "
        "AND start_addr <= ? AND end_addr >= ? LIMIT 1", (firmware_id, from_addr, from_addr)).fetchone()
    if block is None:
        return None
    row = conn.execute(
        "SELECT to_addr FROM literal_refs WHERE firmware_id=? AND from_addr >= ? AND from_addr < ? "
        "ORDER BY from_addr DESC LIMIT 1", (firmware_id, block["start_addr"], from_addr)).fetchone()
    return row["to_addr"] if row else None


def dynamic_candidates(firmware_key, from_addrs_with_regs, verbose=True):
    """Run the EXISTING tools/unicorn/virtual_link.py scenario corpus
    once more (unmodified -- same monkeypatch discipline as
    tools/census/dynamic_export.py), this time injecting `watch` on
    every `from_addr` in `from_addrs_with_regs` (a dict from_addr ->
    target_reg_name) for the matching firmware image, and reading the
    watched register's value at each hit. Returns a dict
    from_addr -> list of (target_addr, scenario_name) -- the REAL
    concrete values this instruction's target register held at
    runtime, across every scenario leg that actually reached it.

    Only meaningful for 'reg-indirect' shape instructions (a fixed
    register at the watch point holds the whole target) -- callers
    should not pass table-branch/mem-indirect addresses in here."""
    unicorn_dir = HERE.parent / "unicorn"
    sys.path.insert(0, str(unicorn_dir))
    import concrete  # noqa: E402
    import virtual_link  # noqa: E402
    import dynamic_export  # noqa: E402

    watch_addrs = list(from_addrs_with_regs)
    if not watch_addrs:
        return {}

    original_run = concrete.ConcreteMachine.run
    found = {addr: [] for addr in watch_addrs}

    for scenario_name, fn_name in dynamic_export.SCENARIOS.items():
        scenario_fn = getattr(virtual_link, fn_name)

        def recording_run(self, *args, **kwargs):
            existing_watch = list(kwargs.get("watch", ()))
            kwargs["watch"] = existing_watch + watch_addrs
            result = original_run(self, *args, **kwargs)
            fw_key = dynamic_export._firmware_key_for_path(result.firmware)
            if fw_key == firmware_key:
                for hit in result.watch_hits:
                    addr = int(hit["address"], 16)
                    if addr in from_addrs_with_regs:
                        reg = from_addrs_with_regs[addr]
                        val = int(hit["registers"][reg], 16)
                        found[addr].append((val, scenario_name))
            return result

        concrete.ConcreteMachine.run = recording_run
        try:
            if verbose:
                print(f"  [indirect-resolve] replaying scenario '{scenario_name}' with "
                      f"{len(watch_addrs)} watched indirect site(s)...")
            scenario_fn(verbose=False)
        except Exception as e:  # noqa: BLE001 -- a scenario assertion failing here must not abort the whole resolve pass
            if verbose:
                print(f"    (scenario '{scenario_name}' raised {type(e).__name__}: {e} -- "
                      f"partial watch data from it, if any, is still used)")
        finally:
            concrete.ConcreteMachine.run = original_run

    return found
