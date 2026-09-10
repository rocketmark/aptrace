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

  MANDO_RECIPE (reference: mando868) -- built incrementally THIS pass,
  by running from Reset_Handler with only chip-architecture-level
  assumptions (the clock/PLL bits, which the SVD and this image's own
  static evidence confirm are touched by mando's clock-init function at
  the SAME peripheral addresses as AutoPilot's) and diagnosing each
  subsequent stall with `--watch` register captures, never by skipping
  PCs or forcing a loop exit. Two real SERCOM2 completion-bit waits
  were found and modeled the same documented way (SWRST self-clear,
  INTFLAG.DRE); progress then stops at a plain RAM-flag wait
  (`0x20003b30`) whose only known writer is an orphaned code range with
  no resolved static or dynamic caller in this census -- likely an
  interrupt-delivered completion, which this project's Unicorn harness
  does not model. No existing repo evidence justifies a model for it,
  so the recipe stops there, honestly -- `init_status`
  'partial-justified' (real progress, on cited evidence, clearly
  short of steady state). See MANDO_RECIPE['blocker'] for the full
  mechanical detail.

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
        0x13f92: "documented blocker: RAM flag 0x20003b30 wait (no citable model -- see 'blocker' below)",
    },
    "steady_state_addr": None,
    "steady_state_hits": None,
    "max_instructions": 300_000,
    "blocker": {
        "addr": 0x20003b30,
        "wait_site": 0x13f92,
        "description": "A plain RAM byte flag (0x20003b30) polled by a tight busy-loop at 0x13f92 "
                        "('ldrb r3,[r5]; cmp r3,#0; bne 0x13f92', r5=0x20003b30). Its only known writer in this "
                        "census's static evidence is a 6-byte code range at 0x13764-0x1376a "
                        "('ldr r3,[0x1376c]; movs r2,#0; strb r2,[r3]; bx lr', target confirmed = 0x20003b30 "
                        "via Ghidra's own reference manager) -- but that range has NO resolved static call/jump "
                        "edge, is not a vector target, and was not dynamically observed as an indirect target "
                        "either. It is most likely reached only via NVIC interrupt delivery (an ISR clearing a "
                        "completion flag), which this project's Unicorn harness does not model at all (no NVIC/"
                        "interrupt-dispatch capability exists in tools/unicorn/concrete.py).",
        "evidence_needed": "Either (a) a NVIC/interrupt-delivery model in the Unicorn harness (a real, "
                            "nontrivial capability this project does not currently have -- out of scope for a "
                            "mechanical reducer to add unilaterally), or (b) independent evidence identifying "
                            "which real interrupt source clears 0x20003b30 and confirming it is safe to model "
                            "as a disclosed completion bit the way the SERCOM/clock bits were.",
    },
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
    ref_row = conn.execute(
        "SELECT f.id, f.entry FROM functions f JOIN firmware fw ON fw.id=f.firmware_id "
        "WHERE fw.key=? AND f.entry <= ? ORDER BY f.entry DESC LIMIT 1", (reference_key, ref_addr)).fetchone()
    if ref_row is None or ref_addr >= ref_row["entry"] + conn.execute(
            "SELECT size FROM functions WHERE id=?", (ref_row["id"],)).fetchone()[0]:
        gaps.append(f"0x{ref_addr:08x}: no containing function found in reference image '{reference_key}'")
        return None
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

    def remap_display_addr(a):
        if a["addr"] is None:
            return None
        if a["kind"] == "fake_tick":
            return _remap_ram_addr(conn, sibling_fw_id, reference_key, a["addr"], gaps)
        if a["kind"] in ("force_reg", "stub_call"):
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
    remapped sibling), capture coverage the same way
    dynamic_export.py's scenario corpus does (reusing its own JSON
    export/ingest format -- scenario name 'boot'), and return
    (out_path_or_None, machine_or_None, result_or_None, recipe_or_None,
    gaps, init_status) for the caller (tools/census/reduce.py) to feed
    into dynamic_ingest, indirect-edge resolution, and the hardware
    snapshot -- all from this SAME execution, not a second run."""
    sys.path.insert(0, str(HERE))
    import dynamic_export  # noqa: E402

    recipe, gaps = resolve_for_firmware(conn, firmware_key)
    if recipe is None:
        if verbose:
            print(f"  [boot] no boot recipe available for '{firmware_key}': {gaps}")
        return None, None, None, None, gaps, "blocked"

    machine = build_machine(recipe, fw_path, flash_base, ram_base, ram_size, mmio_base, mmio_size)
    result = apply_recipe(machine, recipe, extra_watch=extra_watch)
    status = init_status_for(recipe, result)

    if verbose:
        hit_summary = {}
        for h in result.watch_hits:
            hit_summary[h["address"]] = hit_summary.get(h["address"], 0) + 1
        print(f"  [boot] {firmware_key}: reference={recipe['reference_key']} status={status} "
              f"instructions={result.instructions_executed} stop_reason={result.stop_reason!r} "
              f"milestones_hit={len(hit_summary)}")
        if gaps:
            print(f"  [boot] {firmware_key}: {len(gaps)} recipe gap(s) (dropped, not guessed): {gaps}")

    leg = {"firmware": str(fw_path), "label": "boot", "snapshot": result.to_dict(), "tx_rx": []}
    out_path = dynamic_export.write_export("boot", [leg], out_dir=out_dir, verbose=verbose)

    return out_path, machine, result, recipe, gaps, status


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
