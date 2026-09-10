"""APTrace census reduce: reusable, provenance-tagged Unicorn boot
recipes for AutoPilot and Mando, mechanically packaged from EXISTING,
CITED investigation evidence -- no new semantic RE work is performed by
this module. Every environmental/model assumption a recipe applies is
recorded (kind, address, detail, citation) so a run's full disclosure
list is always inspectable, never implicit.

Two REFERENCE recipes, each keyed by the firmware image the underlying
investigation actually used:

  AUTOPILOT_RECIPE (reference: autopilot868) -- packages, VERBATIM, the
  disclosed clock/PLL/SERCOM/NVMCTRL completion-bit assumptions, the
  RAM tick counter, the PA22 GPIO-input boundary condition, the
  DWT-delay stub, and the radio-ID handshake stand-in from
  docs/investigations/boot-and-hardware-bringup.md. Reproduces that
  document's own cited milestones exactly (see test_reduce.py) and
  reaches real main-loop steady state (5 confirmed `0x8960` iterations,
  matching that document's own success criterion) -- `init_status`
  'complete'.

  MANDO_RECIPE (reference: mando868) -- built incrementally, by running
  from Reset_Handler with only chip-architecture-level assumptions (the
  clock/PLL bits, which the SVD and this image's own static evidence
  confirm are touched by mando's clock-init function at the SAME
  peripheral addresses as AutoPilot's) and diagnosing each subsequent
  stall with `--watch` register captures, never by skipping PCs or
  forcing a loop exit. Two real SERCOM2 completion-bit waits were found
  and modeled the same documented way (SWRST self-clear, INTFLAG.DRE).
  A later stall at a plain RAM-flag wait (`0x20003b30`) turned out to
  be a REAL DMAC (DMA controller) transfer-complete interrupt,
  confirmed end to end via Ghidra CFG/xrefs + the SVD + Unicorn traces
  (see MANDO_RECIPE['resolved_blockers'] for the full mechanical chain)
  and modeled via `interrupt_bridges` + `ConcreteMachine.
  deliver_interrupt` -- a narrow, evidence-bounded interrupt-delivery
  primitive (real handler execution, real peripheral-pending state,
  no general Cortex-M exception simulator). See MANDO_RECIPE['blocker']
  for whatever the CURRENT furthest blocker is (None if fully resolved
  to steady state).

For a SIBLING image in the same product family (`autopilot915`,
`mando915`) that isn't itself a reference recipe's own firmware,
`resolve_for_firmware` mechanically remaps every CODE address in the
family's reference recipe via an EXACT function-fingerprint match
(byte-identical function -> identical internal offsets, so
`sibling_addr = sibling_function.entry + (ref_addr - ref_function.entry)`
is exact) -- MMIO/peripheral addresses need no remapping (chip-fixed,
confirmed identical via this image's own static evidence, not
assumed). Any address that fails to remap (no EXACT match found) is
DROPPED from the sibling's recipe and reported as a gap -- never
guessed.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from fingerprint import _family  # noqa: E402


def A(kind, addr, detail, citation):
    return {"kind": kind, "addr": addr, "detail": detail, "citation": citation}


_CITATION = "docs/investigations/boot-and-hardware-bringup.md"

AUTOPILOT_RECIPE = {
    "reference_key": "autopilot868",
    "entry": 0xcc24,  # Reset_Handler
    "fake_tick": [(0x200052ec, 20)],
    "mmio_force_bits": [
        (0x4000140c, 0x1), (0x40001010, 0x100), (0x40001040, 0x3), (0x40001054, 0x3),
        (0x43000418, 0x4), (0x41012018, 0x4), (0x41004010, 0x1),
    ],
    "mmio_clear_bits": [(0x43000400, 0x1), (0x41012000, 0x1)],
    "force_reg": [(0x9dd4, "r0", 0x12)],
    "seed_mem": [(0x41008020, (0x400000).to_bytes(4, "little"))],  # PORT.GROUP0.IN bit22 (PA22) held high
    "stub_calls": [0xcd34],  # DWT->CYCCNT busy-wait delay helper
    "map_pages": [(0x800080, 0x40)],  # NVM Software Calibration Row
    "milestones": {
        0x9464: "boot/init entry (setup())", 0x69d8: "startup reference/input routine real timeout exit",
        0x9dd4: "disclosed radio-ID assumption fires", 0x6190: "post-probe init resumes (1/5)",
        0x4c20: "post-probe init resumes (2/5)", 0x4328: "post-probe init resumes (3/5)",
        0x5d44: "post-probe init resumes (4/5)", 0x7770: "post-probe init resumes (5/5)",
        0x8960: "real main loop receive call",
    },
    "steady_state_addr": 0x8960,
    "steady_state_hits": 5,
    "max_instructions": 450_000,
    "blocker": None,
    "resolved_blockers": [],
    "interrupt_bridges": [],
    "assumptions": [
        A("fake_tick", 0x200052ec, "RAM-resident millis/tick counter, advanced on an instruction-count cadence "
          "(not a real SysTick MMIO model) -- diagnosed by disassembling the real tick-reading functions.",
          _CITATION + "#test--repro"),
        A("mmio_force_bits", 0x4000140c, "OSC32KCTRL.STATUS.XOSC32KRDY -- real hardware self-sets after its own "
          "preceding configuration write.", _CITATION + "#evidence"),
        A("mmio_force_bits", 0x40001010, "OSCCTRL.STATUS.DFLLRDY -- same category.", _CITATION + "#evidence"),
        A("mmio_force_bits", 0x40001040, "OSCCTRL.DPLL0.DPLLSTATUS.{LOCK,CLKRDY} -- same category.", _CITATION + "#evidence"),
        A("mmio_force_bits", 0x40001054, "OSCCTRL.DPLL1.DPLLSTATUS.{LOCK,CLKRDY} -- same category.", _CITATION + "#evidence"),
        A("mmio_clear_bits", 0x43000400, "SERCOM5.CTRLA/SYNCBUSY bit0 (SWRST) -- real hardware self-clears.", _CITATION + "#evidence"),
        A("mmio_clear_bits", 0x41012000, "SERCOM2.CTRLA/SYNCBUSY bit0 (SWRST) -- same.", _CITATION + "#evidence"),
        A("mmio_force_bits", 0x43000418, "SERCOM5.INTFLAG.DRE -- set the moment the peripheral is enabled with nothing queued.", _CITATION + "#evidence"),
        A("mmio_force_bits", 0x41012018, "SERCOM2.INTFLAG.DRE -- same.", _CITATION + "#evidence"),
        A("mmio_force_bits", 0x41004010, "NVMCTRL.INTFLAG.DONE -- same completion-bit category.", _CITATION + "#evidence"),
        A("force_reg", 0x9dd4, "Radio chip-ID probe stand-in: r0=0x12 at the post-SPI-read comparison, standing "
          "in for 'a radio module is present and answers with the value real firmware requires' -- a real "
          "external-device dependency, not internal chip state; scoped to exactly this one instruction.",
          _CITATION + "#evidence"),
        A("seed_mem", 0x41008020, "PORT.GROUP0.IN bit22 (PA22) held high -- disclosed GPIO-input boundary "
          "assumption for the startup reference/input routine's wait loop; no physical function claimed.",
          _CITATION + "#test--repro"),
        A("stub_call", 0xcd34, "DWT->CYCCNT-based microsecond busy-wait helper -- Unicorn's zero-behavior MMIO "
          "model never advances DWT->CYCCNT, so this call would spin forever; stubbed to return immediately "
          "(structurally unrelated to the fake-tick mechanism).", _CITATION + "#test--repro"),
        A("map_page", 0x800080, "NVM Software Calibration Row -- a real, factory-programmed per-die area; "
          "mapped as a disclosed zero-filled placeholder, not a claim about true calibration values.",
          _CITATION + "#test--repro"),
    ],
}

MANDO_RECIPE = {
    "reference_key": "mando868",
    "entry": 0x16794,  # Reset_Handler (confirmed via vectors table AND fingerprint match to autopilot868's own)
    "fake_tick": [(0x20005a08, 20)],
    "mmio_force_bits": [
        (0x4000140c, 0x1), (0x40001010, 0x100), (0x40001040, 0x3), (0x40001054, 0x3),
        (0x41012018, 0x4),
    ],
    "mmio_clear_bits": [(0x41012000, 0x1)],
    "force_reg": [],
    "seed_mem": [],
    "stub_calls": [0x168a4],  # DWT->CYCCNT busy-wait delay helper (EXACT byte match to autopilot868's 0xcd34)
    "map_pages": [(0x800080, 0x40)],
    "milestones": {
        0x14f74: "SERCOM2 SWRST self-clear wait (modeled, cited category)",
        0x14fda: "SERCOM2 INTFLAG.DRE wait (modeled, cited category)",
        0x13f92: "DMAC channel-2 transfer-complete wait (modeled via interrupt_bridges -- see 'resolved_blockers')",
    },
    # FUN_00007abc, mando868's own real loop() top (small, application-
    # specific -- cross-product-matches nothing in AutoPilot, same-
    # product-matches mando915 exactly, consistent with real per-product
    # Arduino-core sketch code). Confirmed this pass via `--watch`: 10
    # hits at a PERFECTLY regular 33-instruction period (0 variance) --
    # the same steady-state evidence standard
    # docs/investigations/boot-and-hardware-bringup.md's own AutoPilot
    # criterion uses (there: ~2900-2940-instruction cadence, 5 hits).
    "steady_state_addr": 0x7abc,
    "steady_state_hits": 5,
    "max_instructions": 600_000,
    # RESOLVED this pass -- see `interrupt_bridges` below and
    # docs/tooling/census.md's "Mando interrupt-delivery closure" for
    # the full mechanical chain. Kept here (not deleted) as a record of
    # what the earlier pass found and how it was closed.
    "blocker": None,
    "resolved_blockers": [{
        "addr": 0x20003b30,
        "wait_site": 0x13f92,
        "description": "A plain RAM byte flag (0x20003b30) polled by a tight busy-loop at 0x13f92 "
                        "('ldrb r3,[r5]; cmp r3,#0; bne 0x13f92', r5=0x20003b30). Its only known writer in this "
                        "census's static evidence is a 6-byte code range at 0x13764-0x1376a "
                        "('ldr r3,[0x1376c]; movs r2,#0; strb r2,[r3]; bx lr', target confirmed = 0x20003b30 "
                        "via Ghidra's own reference manager) -- but that range has NO resolved static call/jump "
                        "edge, is not a vector target, and was not dynamically observed as an indirect target "
                        "either.",
        "resolution": "Confirmed a real DMAC (DMA controller) transfer-complete interrupt chain, entirely from "
                       "existing evidence (no new source available, purely Ghidra CFG/xrefs + SVD + Unicorn "
                       "traces): FUN_00013874 (a TC2/CCL/EVSYS driver-setup routine, visited during boot) calls "
                       "FUN_00011fd8(object=0x200026f8, callback=0x13765, index=1) -- a generic 3-slot callback-"
                       "table setter (`*(object+(index+2)*4)=callback`) -- registering our release routine into "
                       "slot 1 ('transfer complete') of a driver object. A later, dynamically-confirmed write "
                       "(Unicorn watch_mem_write, instruction 67257, PC=0x11e2c) stores that SAME object pointer "
                       "into a DMA-channel-to-object lookup table at 0x20003a60, index 2 (address 0x20003a68) -- "
                       "i.e. DMA channel 2. IRQ vectors 47-51 (DMAC_0..DMAC_OTHER, IRQ31-35 per the SVD's own "
                       "<interrupt> elements) all point at the SAME real handler, FUN_00011d20, which reads "
                       "DMAC.INTPEND (0x4100a020) & 0x1f for the pending channel, looks up "
                       "channel_table[channel] (0x20003a60 + channel*4), and if non-null calls "
                       "FUN_00011cb8(object, channel). That function reads DMAC.CHANNELn.CHINTFLAG "
                       "(0x4100a000 + channel*0x10 + 0x4e, confirmed via the SVD) and dispatches to one of three "
                       "registered callbacks by bit: TERR(bit0)->slot0, TCMPL(bit1)->slot1 (OUR callback), "
                       "SUSP(bit2)->slot2. Empirically verified end to end in Unicorn "
                       "(ConcreteMachine.deliver_interrupt): seeding INTPEND=2 and CHANNEL2.CHINTFLAG.TCMPL=1 "
                       "and running the REAL FUN_00011d20 (not a stub) releases the flag exactly as this chain "
                       "predicts.",
    }],
    # A general, reusable, data-driven bridge: "when execution reaches
    # `wait_check_addr` with `flag_addr` still armed, deliver a real
    # NVIC interrupt via `handler_addr` (never a stub) after seeding
    # the minimal, disclosed peripheral-pending condition it needs,
    # then resume exactly where the interrupted code was." See
    # `run_with_interrupt_bridges` for the executor. Deliberately NOT a
    # general Cortex-M exception simulator: no EXC_RETURN, no NVIC
    # priority/masking, no real asynchronous preemption -- delivery is
    # triggered only at this ONE well-defined synchronization point,
    # exactly where the firmware itself already demonstrates it is
    # waiting for this exact completion.
    "interrupt_bridges": [{
        "wait_check_addr": 0x13f92, "flag_addr": 0x20003b30, "flag_released_value": 0,
        "handler_addr": 0x11d20,
        # The channel table (see below) can have MULTIPLE simultaneously-
        # registered channels at once (confirmed empirically: channels 0
        # and 1 are ALSO populated by the time this wait is first
        # reached, with their own, DIFFERENT registered callbacks, e.g.
        # channel 0's own callback is 0x118cd, not ours) -- "any non-null
        # entry" is NOT sufficient evidence for which channel this
        # SPECIFIC wait is for. `release_callback_addr` is the ONE thing
        # that uniquely identifies it: the release routine itself
        # (0x13765, the same address confirmed in 'resolved_blockers' as
        # OUR flag's real writer) -- the channel selected is the one
        # whose own registered object has THIS EXACT callback in its
        # slot-1 ("transfer complete") field, never merely "the first
        # populated slot".
        "release_callback_addr": 0x13765,
        "callback_slot_offset": 0xc,
        # DMAC.INTPEND/DMAC base address are chip-fixed (confirmed via
        # this image's own SVD-resolved static evidence) -- reused as-is,
        # no remapping needed for a sibling image.
        "dmac_base": 0x4100a000, "intpend_offset": 0x20,
        # The DMA channel-to-driver-object lookup table's OWN base
        # address, by contrast, is a firmware-specific RAM global (like
        # the tick counter) -- NOT stored as a fixed constant here.
        # Instead: `channel_table_literal_offset` is the handler
        # function's own literal-pool cell holding that address,
        # relative to `handler_addr` (0x11d48-0x11d20 -- see the
        # disassembly cited in 'resolved_blockers' above). Reading that
        # cell directly from EACH image's own flash bytes at
        # `handler_addr + channel_table_literal_offset` (handler_addr
        # already correctly remapped via EXACT fingerprint match) gives
        # that image's own real table address -- robust across siblings
        # without needing a separate, fragile RAM-address remap.
        "channel_table_literal_offset": 0x28, "channel_table_count": 32,
        "chintflag_channel_stride": 0x10, "chintflag_offset": 0x4e, "chintflag_tcmpl_bit": 0x2,
        # Only 4 real deliveries are actually needed to reach steady
        # state (confirmed this pass); bounded well above that for
        # margin without being unbounded.
        "max_deliveries": 25,
        "citation": "tools/census/boot_recipes.py's MANDO_RECIPE['resolved_blockers'] (this pass) + "
                     "tools/svd/ATSAMD51J19A.svd's DMAC <interrupt> elements and CHANNELn.CHINTFLAG/INTPEND "
                     "register definitions",
    }],
    "assumptions": [
        A("fake_tick", 0x20005a08, "RAM-resident millis/tick counter -- mando868's own equivalent of "
          "autopilot868's 0x200052ec, identified via an EXACT function-fingerprint match to autopilot868's "
          "millis() (FUN_0000ccd0 -> mando868 FUN_00016840) and confirmed directly against this image's own "
          "memory_accesses evidence (not assumed identical to autopilot's address).",
          "tools/census/reduce.py's fingerprint-based remapping (this pass)"),
        A("mmio_force_bits", 0x4000140c, "OSC32KCTRL.STATUS.XOSC32KRDY -- confirmed touched by mando868's own "
          "clock-init function (EXACT match to autopilot868's FUN_0000cdd8), same category as AutoPilot's.",
          "tools/census/reduce.py's fingerprint-based remapping (this pass) + " + _CITATION + "#evidence"),
        A("mmio_force_bits", 0x40001010, "OSCCTRL.STATUS.DFLLRDY -- same.", "as above"),
        A("mmio_force_bits", 0x40001040, "OSCCTRL.DPLL0.DPLLSTATUS -- same.", "as above"),
        A("mmio_force_bits", 0x40001054, "OSCCTRL.DPLL1.DPLLSTATUS -- same.", "as above"),
        A("mmio_clear_bits", 0x41012000, "SERCOM2.CTRLA/SYNCBUSY bit0 (SWRST) -- found THIS pass by watching "
          "mando868's own first boot stall (0x14f74): r3=0x41012000 (SERCOM2), same real-hardware self-clear "
          "category as autopilot868's own SERCOM2/SERCOM5 use.", "tools/census/boot_recipes.py (this pass)"),
        A("mmio_force_bits", 0x41012018, "SERCOM2.INTFLAG.DRE -- found THIS pass by watching mando868's second "
          "boot stall (0x14fda): r3=0x41012000+0x18, same real-hardware DRE-on-enable category.",
          "tools/census/boot_recipes.py (this pass)"),
        A("stub_call", 0x168a4, "DWT->CYCCNT busy-wait helper -- EXACT byte match to autopilot868's own "
          "FUN_0000cd34, confirmed via this image's own literal_refs (0xe0001004 read twice, same pattern).",
          "tools/census/reduce.py's fingerprint-based remapping (this pass)"),
        A("map_page", 0x800080, "NVM Software Calibration Row -- same chip-architecture fact as AutoPilot's.",
          _CITATION + "#test--repro"),
        A("interrupt_bridge", 0x11d20, "DMAC channel-2 transfer-complete interrupt, delivered by running the "
          "REAL FUN_00011d20 handler (never stubbed) after seeding DMAC.INTPEND=2 and "
          "DMAC.CHANNEL2.CHINTFLAG.TCMPL=1 -- the minimal disclosed peripheral-pending condition; see "
          "'resolved_blockers' above for the full evidence chain.",
          "tools/census/boot_recipes.py's MANDO_RECIPE['interrupt_bridges'] (this pass)"),
    ],
}

RECIPES_BY_REFERENCE = {"autopilot868": AUTOPILOT_RECIPE, "mando868": MANDO_RECIPE}


def _remap_code_addr(conn, sibling_fw_id, reference_key, ref_addr, gaps):
    """Remap one CODE address from the reference image to the sibling,
    via an EXACT function-fingerprint match (see module docstring).
    Queries `function_fingerprints` directly (exact_hash equality)
    rather than `library_matches` -- library_matches records only ONE
    "best" cross-image match per function (deliberately preferring a
    cross-PRODUCT match, e.g. autopilot->mando, over a same-product
    sibling match, for library-detection purposes -- see
    fingerprint.py's `_family`), which is often NOT the reference image
    this recipe needs to remap through even when a same-product EXACT
    match also exists. Returns the remapped int address, or None
    (appending a note to `gaps`) if no EXACT match exists to remap
    through."""
    NEARBY_GAP_WINDOW = 0x400  # see the fallback comment below

    ref_row = conn.execute(
        "SELECT f.id, f.entry FROM functions f JOIN firmware fw ON fw.id=f.firmware_id "
        "WHERE fw.key=? AND f.entry <= ? ORDER BY f.entry DESC LIMIT 1", (reference_key, ref_addr)).fetchone()
    ref_size = conn.execute("SELECT size FROM functions WHERE id=?", (ref_row["id"],)).fetchone()[0] \
        if ref_row is not None else 0
    strictly_contained = ref_row is not None and ref_addr < ref_row["entry"] + ref_size
    nearby_gap = ref_row is not None and not strictly_contained and \
        ref_addr < ref_row["entry"] + ref_size + NEARBY_GAP_WINDOW
    if ref_row is None or not (strictly_contained or nearby_gap):
        gaps.append(f"0x{ref_addr:08x}: no containing function found in reference image '{reference_key}'")
        return None
    if not strictly_contained:
        # `ref_addr` falls in a Ghidra-unattributed ("exec-bytes-
        # unowned") gap just past the nearest preceding function's own
        # declared body -- a real, documented census limitation (see
        # scan_warnings' 'exec-bytes-unowned' category), not necessarily
        # an absence of real correspondence. Fall back to the SAME
        # nearest-preceding-function EXACT-match + fixed offset, without
        # the strict size bound -- weaker (not guaranteed exact if the
        # gap itself changed size between images), but still entirely
        # evidence-based (still requires a real EXACT fingerprint match
        # on the enclosing function), and confirmed empirically this
        # pass to correctly track mando915's own uniform code-layout
        # shift relative to mando868 for exactly this situation.
        gaps.append(f"0x{ref_addr:08x}: falls {ref_addr - ref_row['entry']:#x} bytes past reference function "
                     f"0x{ref_row['entry']:08x}'s own declared size -- remapped via that function's nearest-"
                     f"preceding-EXACT-match offset anyway (best-effort, not a guaranteed-exact remap)")
    ref_fp = conn.execute(
        "SELECT exact_hash FROM function_fingerprints WHERE firmware_id="
        "(SELECT id FROM firmware WHERE key=?) AND function_id=?", (reference_key, ref_row["id"])).fetchone()
    if ref_fp is None:
        gaps.append(f"0x{ref_addr:08x}: reference function 0x{ref_row['entry']:08x} has no fingerprint yet "
                     f"(run 'census reduce {reference_key}' first)")
        return None
    sib_row = conn.execute(
        "SELECT f.entry FROM function_fingerprints fp JOIN functions f ON f.id = fp.function_id "
        "WHERE fp.firmware_id=? AND fp.exact_hash=?", (sibling_fw_id, ref_fp["exact_hash"])).fetchone()
    if sib_row is None:
        gaps.append(f"0x{ref_addr:08x} (in reference function 0x{ref_row['entry']:08x}): "
                     f"no EXACT byte-identical function found in the sibling firmware")
        return None
    offset = ref_addr - ref_row["entry"]
    return sib_row["entry"] + offset


def _remap_ram_addr(conn, sibling_fw_id, reference_key, ref_addr, gaps):
    """Remap one RAM DATA address (e.g. a --fake-tick counter) --
    NOT a code address, so `_remap_code_addr`'s "which function
    CONTAINS this address" logic doesn't apply (a RAM address is never
    inside a function's own code range). Instead: find which reference
    function's OWN memory_accesses touches this exact RAM address,
    find that function's EXACT fingerprint match in the sibling, and
    read off the sibling function's own (distinct) memory_accesses
    target -- correct for the small, single-purpose leaf functions
    (millis()-style tick counters) this is used for; would need a more
    careful per-instruction correlation for a function touching
    multiple distinct RAM addresses (not the case for any current
    recipe)."""
    ref_func = conn.execute(
        "SELECT f.id, f.entry FROM memory_accesses m JOIN functions f ON f.id = m.from_function_id "
        "JOIN firmware fw ON fw.id = m.firmware_id WHERE fw.key=? AND m.to_addr=? LIMIT 1",
        (reference_key, ref_addr)).fetchone()
    if ref_func is None:
        gaps.append(f"0x{ref_addr:08x}: no reference function found touching this RAM address")
        return None
    ref_fp = conn.execute(
        "SELECT exact_hash FROM function_fingerprints WHERE firmware_id="
        "(SELECT id FROM firmware WHERE key=?) AND function_id=?", (reference_key, ref_func["id"])).fetchone()
    if ref_fp is None:
        gaps.append(f"0x{ref_addr:08x}: reference function 0x{ref_func['entry']:08x} has no fingerprint yet")
        return None
    sib_func = conn.execute(
        "SELECT f.id FROM function_fingerprints fp JOIN functions f ON f.id = fp.function_id "
        "WHERE fp.firmware_id=? AND fp.exact_hash=?", (sibling_fw_id, ref_fp["exact_hash"])).fetchone()
    if sib_func is None:
        gaps.append(f"0x{ref_addr:08x} (via reference function 0x{ref_func['entry']:08x}): "
                     f"no EXACT byte-identical function found in the sibling firmware")
        return None
    sib_targets = [r["to_addr"] for r in conn.execute(
        "SELECT DISTINCT to_addr FROM memory_accesses WHERE firmware_id=? AND from_function_id=?",
        (sibling_fw_id, sib_func["id"]))]
    if len(sib_targets) != 1:
        gaps.append(f"0x{ref_addr:08x}: sibling's matched function touches {len(sib_targets)} distinct RAM "
                     f"address(es) (expected exactly 1) -- not remapped, ambiguous")
        return None
    return sib_targets[0]


def resolve_for_firmware(conn, firmware_key):
    """Return (recipe_dict, gaps) for `firmware_key` -- the reference
    recipe verbatim if this IS a reference image, else a remapped copy
    for a sibling image in the same product family. `gaps` lists every
    assumption that could NOT be remapped (dropped, not guessed)."""
    if firmware_key in RECIPES_BY_REFERENCE:
        return RECIPES_BY_REFERENCE[firmware_key], []

    family = _family(firmware_key)
    reference_key = next((k for k in RECIPES_BY_REFERENCE if _family(k) == family), None)
    if reference_key is None:
        return None, [f"no reference boot recipe exists for product family '{family}'"]

    ref = RECIPES_BY_REFERENCE[reference_key]
    fw_row = conn.execute("SELECT id FROM firmware WHERE key=?", (firmware_key,)).fetchone()
    if fw_row is None:
        return None, [f"firmware '{firmware_key}' has no base census yet"]
    sibling_fw_id = fw_row["id"]

    gaps = []

    def remap(addr):
        r = _remap_code_addr(conn, sibling_fw_id, reference_key, addr, gaps)
        return r

    entry = remap(ref["entry"])
    if entry is None:
        # Fall back to this image's own Reset vector -- always available,
        # mechanically independent of fingerprint matching.
        row = conn.execute(
            "SELECT target_addr FROM vectors WHERE firmware_id=? AND vector_index=1", (sibling_fw_id,)).fetchone()
        entry = row["target_addr"] if row else ref["entry"]
        gaps.append(f"entry point remapped via this image's own Reset vector instead of fingerprint match")

    remapped = {
        "reference_key": reference_key,
        "entry": entry,
        # MMIO/peripheral addresses are chip-fixed -- no remapping needed
        # (see module docstring); reused as-is.
        "mmio_force_bits": list(ref["mmio_force_bits"]),
        "mmio_clear_bits": list(ref["mmio_clear_bits"]),
        "map_pages": list(ref["map_pages"]),
        "steady_state_addr": remap(ref["steady_state_addr"]) if ref["steady_state_addr"] else None,
        "steady_state_hits": ref["steady_state_hits"],
        "max_instructions": ref["max_instructions"],
        "blocker": ref["blocker"],
        "milestones": {},
    }
    for addr, label in ref["milestones"].items():
        r = remap(addr)
        if r is not None:
            remapped["milestones"][r] = label

    fake_tick = []
    for addr, period in ref["fake_tick"]:
        r = _remap_ram_addr(conn, sibling_fw_id, reference_key, addr, gaps)
        if r is not None:
            fake_tick.append((r, period))
    remapped["fake_tick"] = fake_tick

    force_reg = []
    for addr, reg, val in ref["force_reg"]:
        r = remap(addr)
        if r is not None:
            force_reg.append((r, reg, val))
    remapped["force_reg"] = force_reg

    seed_mem = list(ref["seed_mem"])  # PORT/MMIO addresses -- chip-fixed, no remap
    remapped["seed_mem"] = seed_mem

    stub_calls = []
    for addr in ref["stub_calls"]:
        r = remap(addr)
        if r is not None:
            stub_calls.append(r)
    remapped["stub_calls"] = stub_calls

    remapped["resolved_blockers"] = list(ref.get("resolved_blockers", []))

    bridges = []
    for b in ref.get("interrupt_bridges", []):
        wait_check = remap(b["wait_check_addr"])
        handler = remap(b["handler_addr"])
        flag = _remap_ram_addr(conn, sibling_fw_id, reference_key, b["flag_addr"], gaps)
        release_cb = remap(b["release_callback_addr"])
        if wait_check is None or handler is None or flag is None or release_cb is None:
            gaps.append(f"interrupt bridge at 0x{b['wait_check_addr']:08x} could not be fully remapped "
                         f"(wait_check={wait_check}, handler={handler}, flag={flag}, "
                         f"release_callback={release_cb}) -- dropped, not guessed")
            continue
        nb = dict(b)
        nb["wait_check_addr"], nb["handler_addr"], nb["flag_addr"] = wait_check, handler, flag
        nb["release_callback_addr"] = release_cb
        bridges.append(nb)
    remapped["interrupt_bridges"] = bridges

    def remap_display_addr(a):
        if a["addr"] is None:
            return None
        if a["kind"] == "fake_tick":
            return _remap_ram_addr(conn, sibling_fw_id, reference_key, a["addr"], gaps)
        if a["kind"] in ("force_reg", "stub_call", "interrupt_bridge"):
            return remap(a["addr"])
        return a["addr"]  # mmio_force_bits/mmio_clear_bits/map_page: chip-fixed, no remap

    remapped["assumptions"] = [
        A(a["kind"], remap_display_addr(a),
          a["detail"] + f" (remapped from {reference_key} via EXACT fingerprint match)", a["citation"])
        for a in ref["assumptions"]
    ]

    return remapped, gaps


def build_machine(recipe, firmware_path, flash_base, ram_base, ram_size, mmio_base, mmio_size,
                    track_dirty=False):
    """Construct a ConcreteMachine with this recipe's `map_pages` applied
    as `extra_maps` -- map_pages MUST be set at construction time (see
    ConcreteMachine.__init__), so this is the one correct way to build a
    machine a recipe will run on; do not construct one separately."""
    unicorn_dir = HERE.parent / "unicorn"
    sys.path.insert(0, str(unicorn_dir))
    from concrete import ConcreteMachine  # noqa: E402
    return ConcreteMachine(firmware_path, flash_base=flash_base, ram_base=ram_base, ram_size=ram_size,
                             mmio_base=mmio_base, mmio_size=mmio_size, track_dirty=track_dirty,
                             extra_maps=recipe.get("map_pages", ()))


def apply_recipe(machine, recipe, extra_watch=(), collect_coverage=True, log_ram=False, log_mmio=True,
                   max_watch_hits=None):
    """Run `recipe` on `machine` (a fresh or reset ConcreteMachine),
    returning the RunResult. `extra_watch` is merged into the recipe's
    own milestone/steady-state watch list (e.g. currently-unresolved
    indirect-call sites, for BLX-target observation during boot).

    `log_ram` defaults to False here (unlike the short scenario-corpus
    captures in dynamic_export.py) -- empirically confirmed this pass:
    over a long (~400K-instruction), RAM/stack-heavy boot run,
    `log_ram=True` causes a genuine execution divergence (a control-flow
    change reaching a bogus low-address branch tens of thousands of
    instructions later), not just a passive-logging overhead. Root
    cause is a real cross-hook reentrancy hazard in
    tools/unicorn/concrete.py's Unicorn engine usage -- confirmed for
    the case of hook_code's own direct `--fake-tick`/`--force-mem`
    writes landing inside the hooked range (now excluded automatically,
    see concrete.py's `_ranges_excluding`), but NOT fully root-caused
    beyond that for a run this long/RAM-heavy; `log_mmio` and
    `collect_coverage` were both verified safe (exact milestone-for-
    milestone reproduction of the cited investigation) and remain
    default-on. Pass log_ram=True explicitly only for a short, already-
    validated run -- never for a boot capture without re-verifying
    milestones match first."""
    watch = set(recipe.get("milestones", {}))
    if recipe.get("steady_state_addr") is not None:
        watch.add(recipe["steady_state_addr"])
    watch |= set(extra_watch)

    if max_watch_hits is None:
        if recipe.get("steady_state_addr") is not None and recipe.get("steady_state_hits"):
            max_watch_hits = len(recipe.get("milestones", {})) + recipe["steady_state_hits"] + len(extra_watch) * 50
        else:
            max_watch_hits = 4000

    return machine.run(
        recipe["entry"],
        fake_tick=recipe.get("fake_tick", ()),
        mmio_force_bits=recipe.get("mmio_force_bits", ()),
        mmio_clear_bits=recipe.get("mmio_clear_bits", ()),
        force_reg=recipe.get("force_reg", ()),
        seed_mem=[(a, b, "boot-recipe-seed") for a, b in recipe.get("seed_mem", ())],
        stub_calls=recipe.get("stub_calls", ()),
        watch=sorted(watch), max_watch_hits=max_watch_hits,
        max_instructions=recipe.get("max_instructions", 300_000),
        collect_coverage=collect_coverage, log_ram=log_ram, log_mmio=log_mmio,
        label="boot", fresh=True,
    )


def _merge_snapshots(dicts):
    """Combine multiple RunResult.to_dict()-shaped dicts (one per leg:
    the main thread's runs plus every delivered ISR's own run) into ONE
    snapshot -- union of visited_pcs (so newly-reached functions/BLX
    sites from EITHER the main thread or an ISR body count as real
    coverage), concatenation of ram_log/mmio_log/watch_hits (so MMIO
    touched during interrupt delivery is captured too), sum of
    instructions_executed, and the LAST leg's stop_reason/registers/
    entry (the final outcome)."""
    if not dicts:
        return {}
    merged = dict(dicts[-1])
    visited = set()
    ram_log, mmio_log, watch_hits = [], [], []
    total_instructions = 0
    for d in dicts:
        visited |= {p for p in (d.get("visited_pcs") or [])}
        ram_log.extend(d.get("ram_log") or [])
        mmio_log.extend(d.get("mmio_log") or [])
        watch_hits.extend(d.get("watch_hits") or [])
        total_instructions += d.get("instructions_executed") or 0
    merged["visited_pcs"] = sorted(visited)
    merged["ram_log"] = ram_log
    merged["mmio_log"] = mmio_log
    merged["watch_hits"] = watch_hits
    merged["instructions_executed"] = total_instructions
    merged["entry"] = dicts[0].get("entry")
    return merged


def run_with_interrupt_bridges(machine, recipe, extra_watch=(), collect_coverage=True, log_ram=False,
                                 log_mmio=True, verbose=True):
    """Like `apply_recipe`, but for a recipe with `interrupt_bridges`:
    runs the main thread with `stop_at` set on every bridge's
    `wait_check_addr`; each time execution actually stops there WHILE
    the bridge's flag is still armed, discovers the real pending
    channel by reading the SAME live channel-lookup table the firmware
    itself populated (never guessed), seeds the minimal disclosed
    peripheral-pending condition, delivers the real ISR
    (`ConcreteMachine.deliver_interrupt` -- never a stub), and resumes
    the main thread at the exact address it was stopped at. Stops
    honestly (does not fabricate a channel or force the flag) if no
    live table entry is found, or a bridge's own `max_deliveries` bound
    is reached, or the overall instruction budget runs out.

    Returns (merged_snapshot_dict, delivery_log) -- delivery_log is a
    list of {bridge_wait_addr, channel, table_addr, instruction} for
    every real interrupt actually delivered, kept as part of this
    run's disclosed-assumption trail."""
    sys.path.insert(0, str(HERE.parent / "unicorn"))
    from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_PC  # noqa: E402

    bridges = {b["wait_check_addr"]: b for b in recipe.get("interrupt_bridges", [])}
    milestones = set(recipe.get("milestones", {}))
    if recipe.get("steady_state_addr") is not None:
        milestones.add(recipe["steady_state_addr"])
    watch = milestones | set(extra_watch)

    budget = recipe.get("max_instructions", 300_000)
    delivery_counts = {addr: 0 for addr in bridges}
    legs, delivery_log = [], []
    entry, sp, fresh = recipe["entry"], None, True
    total_instructions = 0

    while total_instructions < budget:
        result = machine.run(
            entry, sp=sp,
            fake_tick=recipe.get("fake_tick", ()),
            mmio_force_bits=recipe.get("mmio_force_bits", ()),
            mmio_clear_bits=recipe.get("mmio_clear_bits", ()),
            force_reg=recipe.get("force_reg", ()),
            seed_mem=[(a, b, "boot-recipe-seed") for a, b in recipe.get("seed_mem", ())] if fresh else (),
            stub_calls=recipe.get("stub_calls", ()),
            stop_at=sorted(bridges), watch=sorted(watch), max_watch_hits=1_000_000,
            max_instructions=budget - total_instructions,
            collect_coverage=collect_coverage, log_ram=log_ram, log_mmio=log_mmio,
            fresh=fresh, label="boot",
        )
        legs.append(result.to_dict())
        total_instructions += result.instructions_executed
        fresh = False

        stopped_addr = None
        if result.stop_reason and result.stop_reason.startswith("reached stop address "):
            stopped_addr = int(result.stop_reason.rsplit(" ", 1)[-1], 16)

        if stopped_addr not in bridges:
            break  # a genuinely different outcome (steady state, budget, crash) -- done

        bridge = bridges[stopped_addr]
        flag_val = machine.uc.mem_read(bridge["flag_addr"], 1)[0]
        entry, sp = stopped_addr, machine.uc.reg_read(UC_ARM_REG_SP)
        if flag_val == bridge["flag_released_value"]:
            # Already released (e.g. re-checked after a prior delivery in
            # the SAME wait loop) -- resuming with `entry == stopped_addr`
            # would immediately re-trigger this SAME stop_at on its very
            # first (about-to-execute) instruction, with zero real
            # progress (confirmed empirically this pass -- a real
            # correctness hazard of resuming exactly ON a `stop_at`
            # address, not specific to this bridge). Step exactly one
            # real instruction with NO stop_at first, to genuinely move
            # past the wait-check instruction, then resume the guarded
            # run from wherever that really left PC.
            step = machine.run(entry, sp=sp, max_instructions=1, fresh=False,
                                 collect_coverage=collect_coverage, log_ram=log_ram, log_mmio=log_mmio,
                                 label="boot-step-over")
            legs.append(step.to_dict())
            total_instructions += step.instructions_executed
            entry, sp = machine.uc.reg_read(UC_ARM_REG_PC) & ~1, machine.uc.reg_read(UC_ARM_REG_SP)
            continue

        if delivery_counts[stopped_addr] >= bridge["max_deliveries"]:
            if verbose:
                print(f"  [boot] bridge at 0x{stopped_addr:08x}: max_deliveries "
                      f"({bridge['max_deliveries']}) reached, stopping honestly")
            break

        table_addr = int.from_bytes(
            machine.uc.mem_read(bridge["handler_addr"] + bridge["channel_table_literal_offset"], 4), "little")
        channel = None
        for ch in range(bridge["channel_table_count"]):
            obj = int.from_bytes(machine.uc.mem_read(table_addr + ch * 4, 4), "little")
            if obj == 0:
                continue
            callback = int.from_bytes(machine.uc.mem_read(obj + bridge["callback_slot_offset"], 4), "little")
            if callback == bridge["release_callback_addr"]:
                channel = ch
                break
        if channel is None:
            if verbose:
                print(f"  [boot] bridge at 0x{stopped_addr:08x}: no live channel-table entry whose registered "
                      f"callback matches this bridge's release routine -- no evidence for which channel is "
                      f"pending, stopping honestly")
            break

        intpend_addr = bridge["dmac_base"] + bridge["intpend_offset"]
        chintflag_addr = bridge["dmac_base"] + channel * bridge["chintflag_channel_stride"] + bridge["chintflag_offset"]
        machine.uc.mem_write(intpend_addr, channel.to_bytes(2, "little"))
        cur = machine.uc.mem_read(chintflag_addr, 1)[0]
        machine.uc.mem_write(chintflag_addr, bytes([cur | bridge["chintflag_tcmpl_bit"]]))

        cr = machine.deliver_interrupt(bridge["handler_addr"], max_instructions=20_000,
                                         label=f"dmac-isr-ch{channel}", collect_coverage=collect_coverage,
                                         log_mmio=log_mmio, log_ram=log_ram)

        # DMAC.CHANNELn.CHINTFLAG (like every other INTFLAG-style
        # register in this chip family's SVD -- SERCOM.INTFLAG etc.) is
        # write-1-to-clear on real hardware; this project's zero-
        # behavior MMIO model doesn't emulate that write semantic
        # automatically, so the bit this delivery just set would
        # otherwise stay stuck "pending" forever, and DMAC.INTPEND would
        # keep reporting this SAME channel to any later, genuinely
        # UNRELATED reader -- confirmed empirically this pass: without
        # clearing, the very same channel re-triggers a spurious
        # "pending" read every ~70 instructions indefinitely (20,000+
        # deliveries with zero sign of terminating), not a real,
        # bounded firmware loop. Clearing both mirrors the one real,
        # documented (not invented) architectural convention this whole
        # SVD already uses everywhere else.
        machine.uc.mem_write(chintflag_addr, bytes([cur & ~bridge["chintflag_tcmpl_bit"] & 0xFF]))
        machine.uc.mem_write(intpend_addr, (0).to_bytes(2, "little"))

        legs.append(cr.result.to_dict())
        total_instructions += cr.result.instructions_executed
        delivery_counts[stopped_addr] += 1
        delivery_log.append({
            "bridge_wait_addr": stopped_addr, "channel": channel, "table_addr": table_addr,
            "instruction": total_instructions, "handler_returned_cleanly": cr.returned,
        })
        if verbose:
            print(f"  [boot] delivered DMAC channel-{channel} interrupt at instruction {total_instructions} "
                  f"(handler returned cleanly: {cr.returned})")

        # Same step-over as above: `entry` is still `stopped_addr` (a
        # `stop_at` address) -- move past it for real before the next
        # guarded run, or it would instantly re-trigger with zero
        # progress.
        step = machine.run(stopped_addr, sp=machine.uc.reg_read(UC_ARM_REG_SP), max_instructions=1, fresh=False,
                             collect_coverage=collect_coverage, log_ram=log_ram, log_mmio=log_mmio,
                             label="boot-step-over")
        legs.append(step.to_dict())
        total_instructions += step.instructions_executed
        entry, sp = machine.uc.reg_read(UC_ARM_REG_PC) & ~1, machine.uc.reg_read(UC_ARM_REG_SP)

    return _merge_snapshots(legs), delivery_log


class SnapshotResult:
    """A minimal RunResult-shaped adapter around a merged snapshot dict
    (see `_merge_snapshots`) -- so downstream code
    (`init_status_for`/`extract_indirect_hits`/`reduce.py`) can treat a
    multi-leg interrupt-bridge capture exactly like a single plain
    RunResult, via the same `.watch_hits`/`.instructions_executed`/
    `.stop_reason`/`.to_dict()` interface."""

    def __init__(self, snapshot):
        self._snapshot = snapshot
        self.watch_hits = snapshot.get("watch_hits", [])
        self.instructions_executed = snapshot.get("instructions_executed", 0)
        self.stop_reason = snapshot.get("stop_reason")
        self.firmware = snapshot.get("firmware")
        self.label = snapshot.get("label")

    def to_dict(self):
        return self._snapshot


def init_status_for(recipe, result):
    """The three-way status this pass introduced (see
    hardware_snapshot_runs.init_status): 'complete' (the recipe's own
    steady-state criterion was met), 'partial-justified' (at least one
    real, cited milestone was reached -- or, for a recipe with no
    milestones at all like MANDO_RECIPE, real forward progress past
    entry was made on cited assumptions -- before stopping at a
    documented, evidence-backed blocker), 'blocked' (no meaningful
    progress, or no recipe exists for this firmware at all)."""
    if recipe is None:
        return "blocked"
    hit_addrs = {int(h["address"], 16) for h in result.watch_hits}
    steady = recipe.get("steady_state_addr")
    if steady is not None and sum(1 for h in result.watch_hits if int(h["address"], 16) == steady) \
            >= (recipe.get("steady_state_hits") or 1):
        return "complete"
    if hit_addrs or result.instructions_executed > 1000:
        return "partial-justified"
    return "blocked"


def capture_boot(conn, firmware_key, fw_path, flash_base, ram_base, ram_size, mmio_base, mmio_size,
                   extra_watch=(), out_dir=None, verbose=True):
    """Run this firmware's boot recipe (reference or fingerprint-
    remapped sibling) -- via `run_with_interrupt_bridges` if the recipe
    has any (delivering real, evidence-bounded interrupts along the
    way), else the plain `apply_recipe` -- capture coverage the same
    way dynamic_export.py's scenario corpus does (reusing its own JSON
    export/ingest format -- scenario name 'boot'), and return
    (out_path_or_None, machine_or_None, result_or_None, recipe_or_None,
    gaps, init_status, delivery_log) for the caller (tools/census/
    reduce.py) to feed into dynamic_ingest, indirect-edge resolution,
    and the hardware snapshot -- all from this SAME execution, not a
    second run. `result` exposes the same `.watch_hits`/
    `.instructions_executed`/`.stop_reason`/`.to_dict()` interface
    either way (see `SnapshotResult` for the interrupt-bridge case).
    `delivery_log` is `[]` when no bridges fired (or none exist)."""
    sys.path.insert(0, str(HERE))
    import dynamic_export  # noqa: E402

    recipe, gaps = resolve_for_firmware(conn, firmware_key)
    if recipe is None:
        if verbose:
            print(f"  [boot] no boot recipe available for '{firmware_key}': {gaps}")
        return None, None, None, None, gaps, "blocked", []

    machine = build_machine(recipe, fw_path, flash_base, ram_base, ram_size, mmio_base, mmio_size)

    delivery_log = []
    if recipe.get("interrupt_bridges"):
        snapshot, delivery_log = run_with_interrupt_bridges(machine, recipe, extra_watch=extra_watch,
                                                                verbose=verbose)
        snapshot["firmware"] = str(fw_path)
        snapshot["label"] = "boot"
        result = SnapshotResult(snapshot)
    else:
        result = apply_recipe(machine, recipe, extra_watch=extra_watch)
    status = init_status_for(recipe, result)

    if verbose:
        hit_summary = {}
        for h in result.watch_hits:
            hit_summary[h["address"]] = hit_summary.get(h["address"], 0) + 1
        print(f"  [boot] {firmware_key}: reference={recipe['reference_key']} status={status} "
              f"instructions={result.instructions_executed} stop_reason={result.stop_reason!r} "
              f"milestones_hit={len(hit_summary)} interrupts_delivered={len(delivery_log)}")
        if gaps:
            print(f"  [boot] {firmware_key}: {len(gaps)} recipe gap(s) (dropped, not guessed): {gaps}")

    leg = {"firmware": str(fw_path), "label": "boot", "snapshot": result.to_dict(), "tx_rx": []}
    out_path = dynamic_export.write_export("boot", [leg], out_dir=out_dir, verbose=verbose)

    return out_path, machine, result, recipe, gaps, status, delivery_log


def extract_indirect_hits(result, from_addrs_with_regs):
    """From a boot capture's RunResult.watch_hits, pull out the register
    value observed at each `from_addrs_with_regs` (from_addr -> target
    register name) address -- same return shape as
    indirect_resolve.dynamic_candidates (from_addr -> [(value,
    'boot'), ...]), so tools/census/reduce.py can merge boot-observed
    and scenario-corpus-observed indirect targets uniformly."""
    found = {addr: [] for addr in from_addrs_with_regs}
    for hit in result.watch_hits:
        addr = int(hit["address"], 16)
        if addr in from_addrs_with_regs:
            reg = from_addrs_with_regs[addr]
            val = int(hit["registers"][reg], 16)
            found[addr].append((val, "boot"))
    return found
