"""APTrace census reduce: a deterministic, machine-readable hardware
contract per firmware image -- the mechanical input a later
replacement-firmware specification phase should read, instead of
re-deriving MCU configuration facts from raw census tables by hand.

Built ENTIRELY from evidence this census has already collected in an
earlier stage -- the completed hardware_snapshot/hardware_snapshot_runs
(tools/census/hardware_snapshot.py), static mmio_accesses, the vector
table, pins/pin_snapshot, and components -- never a new Unicorn run, an
SVD bit-field guess, or a semantic label. Every peripheral/register
entry carries its RAW register value (exactly as hardware_snapshot
stored it) alongside whatever MECHANICAL decode is actually available
(PORT direction/output/input/PINCFG/PMUXEN/PMUX-nibble from
pin_snapshot; nothing more -- see hardware_snapshot.py's own docstring
for why per-bit-field decode of e.g. ADC/TC/TCC/SERCOM/DMAC registers
is NOT attempted: this project has no vendored bit-field enumeration
beyond the SVD's own peripheral/register NAMES, which mmio_accesses/
hardware_snapshot already carry). A field that has no evidence is
`null`/omitted, never fabricated.

"MCU pin/peripheral fact" vs "physical connector identity" stays the
same two evidence classes documented throughout this project (see
docs/tooling/census.md's "Limitations" section and pins.py's module
docstring) -- this contract carries ONLY the former; a curated
connector-mapping annotation, if one ever exists, is a separate source
this module does not read.
"""
import datetime
import json

MCU_PART = "ATSAMD51J19A"
MCU_CITATION = "tools/svd/ATSAMD51J19A.svd (vendored Microchip SVD, the same source resolve_mmio.py uses)"

CLOCK_TREE_PREFIXES = ("GCLK", "OSCCTRL", "OSC32KCTRL", "MCLK")
NO_BITFIELD_NOTE = ("raw register value only -- this project has no vendored per-bit-field "
                     "enumeration beyond the SVD's own peripheral/register names; see "
                     "hardware_contract.py's module docstring")


def _owners(conn, firmware_id, peripheral):
    """Functions (and the components they belong to) that statically
    access this peripheral -- 'ownership by function/component',
    mechanical only (a real mmio_accesses.from_function_id row, joined
    against component_members if a components pass has run)."""
    fn_rows = conn.execute(
        "SELECT DISTINCT m.from_function_id, f.entry, f.name FROM mmio_accesses m "
        "JOIN functions f ON f.id = m.from_function_id "
        "WHERE m.firmware_id=? AND m.peripheral=? AND m.from_function_id IS NOT NULL",
        (firmware_id, peripheral)).fetchall()
    functions = [{"function_id": r["from_function_id"], "entry": f"0x{r['entry']:08x}", "name": r["name"]}
                 for r in fn_rows]
    fids = [r["from_function_id"] for r in fn_rows]
    components = set()
    if fids:
        placeholders = ",".join("?" for _ in fids)
        for r in conn.execute(
                f"SELECT DISTINCT c.component_index FROM component_members cm "
                f"JOIN components c ON c.id = cm.component_id "
                f"WHERE cm.firmware_id=? AND cm.function_id IN ({placeholders})",
                (firmware_id, *fids)):
            components.add(r["component_index"])
    return functions, sorted(components)


def _clock_tree(conn, firmware_id):
    rows = conn.execute(
        "SELECT * FROM hardware_snapshot WHERE firmware_id=? AND peripheral IN "
        "('GCLK','OSCCTRL','OSC32KCTRL','MCLK') ORDER BY addr", (firmware_id,)).fetchall()
    out = []
    for r in rows:
        out.append({
            "addr": f"0x{r['addr']:08x}", "peripheral": r["peripheral"], "register": r["register_name"],
            "width": r["width"], "raw_value": r["raw_value"], "source": "hardware_snapshot (post-boot register dump)",
        })
    return out


def _peripheral_block(conn, firmware_id, name_prefixes):
    """Every hardware_snapshot register whose peripheral name starts
    with one of `name_prefixes`, grouped by exact peripheral name, with
    static ownership evidence attached per peripheral."""
    rows = conn.execute(
        "SELECT * FROM hardware_snapshot WHERE firmware_id=? ORDER BY peripheral, addr", (firmware_id,)).fetchall()
    by_peripheral = {}
    for r in rows:
        if r["peripheral"] is None or not any(r["peripheral"].startswith(p) for p in name_prefixes):
            continue
        by_peripheral.setdefault(r["peripheral"], []).append(r)

    out = {}
    for peripheral, regs in sorted(by_peripheral.items()):
        functions, components = _owners(conn, firmware_id, peripheral)
        out[peripheral] = {
            "registers": [{
                "addr": f"0x{r['addr']:08x}", "register": r["register_name"], "width": r["width"],
                "raw_value": r["raw_value"], "decoded": NO_BITFIELD_NOTE,
                "source": "hardware_snapshot (post-boot register dump)",
            } for r in regs],
            "owned_by_functions": functions,
            "owned_by_components": components,
        }
    return out


def _port_block(conn, firmware_id):
    rows = conn.execute(
        "SELECT * FROM pin_snapshot WHERE firmware_id=? ORDER BY group_index, pin_index",
        (firmware_id,)).fetchall()
    pins = []
    for r in rows:
        functions, components = [], []
        pin_rows = conn.execute(
            "SELECT DISTINCT p.from_function_id, f.entry, f.name FROM pins p "
            "JOIN functions f ON f.id = p.from_function_id "
            "WHERE p.firmware_id=? AND p.pin_name=? AND p.from_function_id IS NOT NULL",
            (firmware_id, r["pin_name"])).fetchall()
        if pin_rows:
            functions = [{"function_id": pr["from_function_id"], "entry": f"0x{pr['entry']:08x}", "name": pr["name"]}
                         for pr in pin_rows]
            fids = [pr["from_function_id"] for pr in pin_rows]
            placeholders = ",".join("?" for _ in fids)
            comp_rows = conn.execute(
                f"SELECT DISTINCT c.component_index FROM component_members cm "
                f"JOIN components c ON c.id = cm.component_id "
                f"WHERE cm.firmware_id=? AND cm.function_id IN ({placeholders})",
                (firmware_id, *fids)).fetchall()
            components = sorted({cr["component_index"] for cr in comp_rows})
        pins.append({
            "pin_name": r["pin_name"], "group_index": r["group_index"], "pin_index": r["pin_index"],
            "direction": r["direction"], "output_value": r["output_value"], "input_value": r["input_value"],
            "pincfg_raw": r["pincfg_raw"], "pmuxen": r["pmuxen"], "pmux_nibble": r["pmux_nibble"],
            "owned_by_functions": functions, "owned_by_components": components,
            "source": "pin_snapshot (decoded PORT state, see pin_snapshot table docstring for what "
                       "pmux_nibble does/doesn't mean)",
        })
    return pins


def _irq_vectors(conn, firmware_id):
    rows = conn.execute(
        "SELECT v.*, f.name AS target_name FROM vectors v LEFT JOIN functions f "
        "ON f.firmware_id=v.firmware_id AND f.entry=v.target_addr "
        "WHERE v.firmware_id=? ORDER BY v.vector_index", (firmware_id,)).fetchall()
    out = []
    for r in rows:
        entry = {
            "vector_index": r["vector_index"], "is_irq": bool(r["is_irq"]),
            "irq_number": (r["vector_index"] - 16) if r["is_irq"] else None,
            "name": r["name"], "target_addr": f"0x{r['target_addr']:08x}" if r["target_addr"] is not None else None,
            "target_function": r["target_name"], "landed_in_known_function": bool(r["landed_in_known_function"])
            if r["landed_in_known_function"] is not None else None,
        }
        if r["target_addr"] is not None:
            fid_row = conn.execute("SELECT id FROM functions WHERE firmware_id=? AND entry=?",
                                    (firmware_id, r["target_addr"])).fetchone()
            if fid_row:
                comp_row = conn.execute(
                    "SELECT c.component_index FROM component_members cm JOIN components c ON c.id=cm.component_id "
                    "WHERE cm.firmware_id=? AND cm.function_id=?", (firmware_id, fid_row["id"])).fetchone()
                entry["owned_by_component"] = comp_row["component_index"] if comp_row else None
        out.append(entry)
    return out


def build_contract(conn, firmware_id, firmware_key):
    """Returns (contract_dict, generated_at_iso). Callers persist via
    `compute` below; also callable standalone (e.g. for a test) since
    it performs no writes itself."""
    hw_run = conn.execute("SELECT * FROM hardware_snapshot_runs WHERE firmware_id=?", (firmware_id,)).fetchone()
    n_hw_rows = conn.execute("SELECT COUNT(*) FROM hardware_snapshot WHERE firmware_id=?", (firmware_id,)).fetchone()[0]

    contract = {
        "firmware_key": firmware_key,
        "mcu": {"part": MCU_PART, "architecture": "ARMv7E-M (Cortex-M4F)", "citation": MCU_CITATION},
        "hardware_snapshot_status": {
            "init_status": hw_run["init_status"] if hw_run else None,
            "boot_method": hw_run["boot_method"] if hw_run else None,
            "completed_init": bool(hw_run["completed_init"]) if hw_run else None,
            "n_registers_captured": n_hw_rows,
            "assumptions": json.loads(hw_run["assumptions_json"]) if hw_run and hw_run["assumptions_json"] else [],
        },
        "clock_tree": _clock_tree(conn, firmware_id),
        "port": _port_block(conn, firmware_id),
        "adc": _peripheral_block(conn, firmware_id, ("ADC",)),
        "tc_tcc": _peripheral_block(conn, firmware_id, ("TC",)),
        "sercom": _peripheral_block(conn, firmware_id, ("SERCOM",)),
        "eic": _peripheral_block(conn, firmware_id, ("EIC",)),
        "dmac": _peripheral_block(conn, firmware_id, ("DMAC",)),
        "usb": _peripheral_block(conn, firmware_id, ("USB",)),
        "wdt": _peripheral_block(conn, firmware_id, ("WDT",)),
        "nvmctrl": _peripheral_block(conn, firmware_id, ("NVMCTRL",)),
        "irq_vectors": _irq_vectors(conn, firmware_id),
        "provenance": {
            "note": "Every register value is RAW, exactly as read from hardware_snapshot (a real post-boot "
                    "Unicorn register dump -- see hardware_snapshot_status.init_status/boot_method for how far "
                    "that boot actually got, and .assumptions for every disclosed model assumption applied to "
                    "reach it). 'decoded' fields are limited to what this project mechanically resolves today "
                    "(peripheral/register NAMES via the SVD, plus full PORT/pin decode); no per-bit-field "
                    "semantics are invented for ADC/TC/TCC/SERCOM/EIC/DMAC/USB/WDT/NVMCTRL registers.",
        },
    }
    return contract


def compute(conn, firmware_id, firmware_key):
    contract = build_contract(conn, firmware_id, firmware_key)
    generated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn.execute("DELETE FROM hardware_contract_runs WHERE firmware_id=?", (firmware_id,))
    conn.execute(
        "INSERT INTO hardware_contract_runs (firmware_id, contract_json, generated_at) VALUES (?,?,?)",
        (firmware_id, json.dumps(contract), generated_at))
    conn.commit()
    return contract
