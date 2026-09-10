"""APTrace census reduce: deterministic, evidence-only priority scoring
for the residual function queue (see docs/tooling/census.md's "Residual
prioritization" section). Every point is attached to a named,
independently-inspectable mechanical signal -- the score is never a
single opaque number; each `residual_priority` row's `reasons_json`
lists every signal that actually fired, its point value, the fixed
description of what the signal means, and the concrete per-function
evidence that triggered it.

No semantic naming/classification happens here -- a signal like
`mmio_access` only means "function_features.n_mmio_reads +
n_mmio_writes > 0", never "this looks like a motor driver". Positive
signals bias toward likely-application, externally-interacting code;
negative signals bias toward isolated/leaf/confirmed-platform code. The
resulting score is a PRIORITY ORDERING HINT for a later human/LLM
phase, not a correctness claim -- a LOW-scoring function can still be
real application logic that the mechanical signals available here
simply don't happen to touch (see docs/tooling/census.md's
Limitations). Runs on top of an already-computed `census reduce` pass
(function_features, components, indirect_edge_resolutions,
library_matches, dynamic_coverage/memory/tx_rx must already exist).
"""
import json

# (points, description) -- kept as one fixed table so scoring and
# documentation/CLI headers can never drift apart. Every point value is
# a small, deliberately modest integer (no signal alone should dominate
# the score) chosen once and applied uniformly across every firmware
# image, never tuned per image.
POSITIVE_SIGNALS = {
    "mmio_access": (3, "reads or writes at least one MMIO register"),
    "pin_access": (3, "configures or reads/writes at least one PORT pin"),
    "irq_relationship": (4, "is itself a populated IRQ-vector target, or has a resolved call edge "
                             "to/from one"),
    "nvm_access": (2, "touches the NVMCTRL peripheral (flash/persistence)"),
    "protocol_data_path": (3, "shares a static RAM address with a dynamic run that actually captured "
                               "real TX/RX bytes"),
    "called_from_covered_code": (3, "has a resolved caller that IS dynamically exercised -- one hop "
                                     "downstream of confirmed-live code"),
    "unresolved_indirect_involvement": (2, "is the site of, or a resolved/candidate target of, an "
                                            "UNRESOLVED or FINITE_CANDIDATE_SET indirect call/jump"),
    "shared_ram_with_covered_code": (2, "shares a static RAM address with a function that IS "
                                         "dynamically exercised"),
    "component_partial_dynamic_coverage": (2, "belongs to a components.py resource/graph component "
                                                "that has at least one dynamically-exercised member"),
}
NEGATIVE_SIGNALS = {
    "isolated_leaf_utility": (-2, "no resolved callees, <=2 basic blocks, and zero MMIO/RAM/pin "
                                   "footprint"),
    "no_external_state_interaction": (-2, "touches no MMIO register and no pin at all"),
    "cross_product_platform_match": (-3, "an EXACT or STRONG_MATCH cross-PRODUCT fingerprint match "
                                          "(not a same-product sibling match) -- real shared-platform-"
                                          "code evidence"),
    "only_reached_via_confirmed_library": (-2, "every resolved caller is itself "
                                                 "reference_source_confirmed=1 -- only reachable through "
                                                 "already-confirmed library code"),
}

HIGH_THRESHOLD = 5
MEDIUM_THRESHOLD = 1

TIER_LABELS = {
    "HIGH": "HIGH-PRIORITY APPLICATION RESIDUAL",
    "MEDIUM": "MEDIUM-PRIORITY RESIDUAL",
    "LOW": "LOW / LIKELY PLATFORM-UTILITY",
}


def tier_for(score):
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def residual_function_ids(conn, firmware_id):
    """The residual queue: reachable, not reference-source-confirmed,
    never dynamically exercised -- the SAME definition
    `aptrace_census.py residual` reports (kept in exactly one place so
    the two can never silently drift -- see cmd_residual)."""
    rows = conn.execute(
        "SELECT r.function_id FROM function_reachability r "
        "LEFT JOIN library_matches l ON l.firmware_id=r.firmware_id AND l.function_id=r.function_id "
        "WHERE r.firmware_id=? AND r.status != 'NO_KNOWN_PATH' "
        "AND (l.reference_source_confirmed IS NULL OR l.reference_source_confirmed=0) "
        "AND r.function_id NOT IN (SELECT function_id FROM dynamic_coverage WHERE firmware_id=? "
        "AND function_id IS NOT NULL)", (firmware_id, firmware_id))
    return [r["function_id"] for r in rows]


def compute(conn, firmware_id):
    from db import replace_firmware_rows

    residual_ids = residual_function_ids(conn, firmware_id)
    if not residual_ids:
        replace_firmware_rows(conn, firmware_id, "residual_priority", [])
        conn.commit()
        return []

    residual_set = set(residual_ids)
    features = {r["function_id"]: r for r in conn.execute(
        "SELECT * FROM function_features WHERE firmware_id=?", (firmware_id,))}
    lib = {r["function_id"]: r for r in conn.execute(
        "SELECT * FROM library_matches WHERE firmware_id=?", (firmware_id,))}

    irq_handler_fids = {fid for fid, f in features.items() if f["is_irq_handler"]}
    covered_fids = {fid for fid, f in features.items() if f["n_dynamic_runs"] > 0}

    # Resolved call adjacency, both directions, for the IRQ 1-hop check
    # and the "called from covered code" / "only reached via confirmed
    # library" checks.
    callers_of = {}   # function_id -> set(caller function_id), resolved calls only
    callees_of = {}   # function_id -> set(callee function_id)
    for row in conn.execute(
            "SELECT from_function_id, to_function_id FROM edges WHERE firmware_id=? AND resolved=1 "
            "AND kind LIKE '%call%' AND from_function_id IS NOT NULL AND to_function_id IS NOT NULL",
            (firmware_id,)):
        callers_of.setdefault(row["to_function_id"], set()).add(row["from_function_id"])
        callees_of.setdefault(row["from_function_id"], set()).add(row["to_function_id"])

    # Protocol-relevant RAM addresses: touched during a dynamic run that
    # ACTUALLY captured real TX/RX bytes (dynamic_tx_rx's mere existence
    # is the mechanical fact used -- never a guess about which specific
    # buffer is "the" protocol buffer).
    protocol_runs = [r["dynamic_run_id"] for r in conn.execute(
        "SELECT DISTINCT dynamic_run_id FROM dynamic_tx_rx WHERE firmware_id=?", (firmware_id,))]
    protocol_ram_addrs = set()
    if protocol_runs:
        placeholders = ",".join("?" for _ in protocol_runs)
        for r in conn.execute(
                f"SELECT DISTINCT addr FROM dynamic_memory WHERE firmware_id=? "
                f"AND dynamic_run_id IN ({placeholders})", (firmware_id, *protocol_runs)):
            protocol_ram_addrs.add(r["addr"])

    # RAM addresses statically touched by any dynamically-covered function.
    covered_ram_addrs = set()
    if covered_fids:
        placeholders = ",".join("?" for _ in covered_fids)
        for r in conn.execute(
                f"SELECT DISTINCT to_addr FROM memory_accesses WHERE firmware_id=? "
                f"AND from_function_id IN ({placeholders})", (firmware_id, *covered_fids)):
            covered_ram_addrs.add(r["to_addr"])

    # Indirect-edge involvement: either the SITE (from_function_id) or a
    # CANDIDATE TARGET of an UNRESOLVED/FINITE_CANDIDATE_SET instruction.
    indirect_site_fids = {r["from_function_id"] for r in conn.execute(
        "SELECT DISTINCT from_function_id FROM indirect_edge_resolutions WHERE firmware_id=? "
        "AND classification IN ('UNRESOLVED','FINITE_CANDIDATE_SET') AND from_function_id IS NOT NULL",
        (firmware_id,))}
    unresolved_from_addrs = {r["from_addr"] for r in conn.execute(
        "SELECT from_addr FROM indirect_edge_resolutions WHERE firmware_id=? "
        "AND classification IN ('UNRESOLVED','FINITE_CANDIDATE_SET')", (firmware_id,))}
    indirect_target_fids = set()
    if unresolved_from_addrs:
        placeholders = ",".join("?" for _ in unresolved_from_addrs)
        for r in conn.execute(
                f"SELECT DISTINCT candidate_function_id FROM indirect_edge_candidates WHERE firmware_id=? "
                f"AND from_addr IN ({placeholders}) AND candidate_function_id IS NOT NULL",
                (firmware_id, *unresolved_from_addrs)):
            indirect_target_fids.add(r["candidate_function_id"])

    # Component membership, for the component-level partial-dynamic-
    # coverage signal (components.py already groups every REACHABLE
    # function, residual or not -- see components.py).
    component_of = {r["function_id"]: r["component_id"] for r in conn.execute(
        "SELECT function_id, component_id FROM component_members WHERE firmware_id=?", (firmware_id,))}
    covered_components = {component_of[fid] for fid in covered_fids if fid in component_of}

    def own_ram_addrs(fid):
        return {r["to_addr"] for r in conn.execute(
            "SELECT to_addr FROM memory_accesses WHERE firmware_id=? AND from_function_id=?",
            (firmware_id, fid))}

    out = []
    for fid in residual_ids:
        f = features.get(fid)
        reasons = []

        def fire(table, name, evidence):
            points, desc = table[name]
            reasons.append({"signal": name, "points": points, "description": desc, "evidence": evidence})

        if f is None:
            # No function_features row is only possible if 'reduce' was
            # only partially run -- honest zero score, no fabricated
            # signal.
            out.append({"firmware_id": firmware_id, "function_id": fid, "score": 0, "tier": "LOW",
                        "reasons_json": json.dumps([]), "source": "residual_priority"})
            continue

        n_mmio = f["n_mmio_reads"] + f["n_mmio_writes"]
        n_ram = f["n_ram_reads"] + f["n_ram_writes"]
        my_ram = own_ram_addrs(fid)

        if n_mmio > 0:
            fire(POSITIVE_SIGNALS, "mmio_access",
                 f"n_mmio_reads={f['n_mmio_reads']} n_mmio_writes={f['n_mmio_writes']} "
                 f"peripherals={f['peripherals_json']}")
        if f["n_pins"] > 0:
            fire(POSITIVE_SIGNALS, "pin_access", f"n_pins={f['n_pins']} pins={f['pins_json']}")

        irq_neighbors = (callers_of.get(fid, set()) | callees_of.get(fid, set())) & irq_handler_fids
        if fid in irq_handler_fids or irq_neighbors:
            fire(POSITIVE_SIGNALS, "irq_relationship",
                 "is_irq_handler=True" if fid in irq_handler_fids else
                 f"resolved call edge to/from IRQ handler function_id(s)={sorted(irq_neighbors)}")

        peripherals = json.loads(f["peripherals_json"] or "[]")
        if "NVMCTRL" in peripherals:
            fire(POSITIVE_SIGNALS, "nvm_access", "peripherals includes NVMCTRL")

        protocol_hit = my_ram & protocol_ram_addrs
        if protocol_hit:
            fire(POSITIVE_SIGNALS, "protocol_data_path",
                 f"shares RAM addr(es) {sorted(f'0x{a:08x}' for a in protocol_hit)[:5]} with a run that "
                 f"captured real dynamic_tx_rx bytes")

        covered_callers = callers_of.get(fid, set()) & covered_fids
        if covered_callers:
            fire(POSITIVE_SIGNALS, "called_from_covered_code",
                 f"resolved caller function_id(s) with n_dynamic_runs>0: {sorted(covered_callers)}")

        if fid in indirect_site_fids or fid in indirect_target_fids:
            fire(POSITIVE_SIGNALS, "unresolved_indirect_involvement",
                 f"site={fid in indirect_site_fids} candidate_target={fid in indirect_target_fids}")

        shared_ram = my_ram & covered_ram_addrs
        if shared_ram:
            fire(POSITIVE_SIGNALS, "shared_ram_with_covered_code",
                 f"shares RAM addr(es) {sorted(f'0x{a:08x}' for a in shared_ram)[:5]} with dynamically-"
                 f"exercised code")

        comp_id = component_of.get(fid)
        if comp_id is not None and comp_id in covered_components:
            fire(POSITIVE_SIGNALS, "component_partial_dynamic_coverage",
                 f"component_id={comp_id} has >=1 dynamically-exercised member")

        # --- negative signals ---
        if f["n_callees"] == 0 and f["n_basic_blocks"] <= 2 and n_mmio == 0 and n_ram == 0 \
                and f["n_pins"] == 0:
            fire(NEGATIVE_SIGNALS, "isolated_leaf_utility",
                 f"n_callees=0 n_basic_blocks={f['n_basic_blocks']} n_mmio=0 n_ram=0 n_pins=0")

        if n_mmio == 0 and f["n_pins"] == 0:
            fire(NEGATIVE_SIGNALS, "no_external_state_interaction", "n_mmio=0 n_pins=0")

        lm = lib.get(fid)
        if lm and lm["confidence"] in ("EXACT", "STRONG_MATCH") and \
                not str(lm["method"] or "").endswith("-same-product"):
            fire(NEGATIVE_SIGNALS, "cross_product_platform_match",
                 f"confidence={lm['confidence']} method={lm['method']} "
                 f"matched={lm['matched_firmware_key']}:{lm['matched_function_name']}")

        static_callers = callers_of.get(fid, set())
        if static_callers and all(
                lib.get(c) is not None and lib[c]["reference_source_confirmed"] for c in static_callers):
            fire(NEGATIVE_SIGNALS, "only_reached_via_confirmed_library",
                 f"all resolved caller function_id(s) {sorted(static_callers)} are reference_source_confirmed")

        score = sum(r["points"] for r in reasons)
        out.append({
            "firmware_id": firmware_id, "function_id": fid, "score": score, "tier": tier_for(score),
            "reasons_json": json.dumps(reasons), "source": "residual_priority",
        })

    replace_firmware_rows(conn, firmware_id, "residual_priority", out)
    conn.commit()
    return out
