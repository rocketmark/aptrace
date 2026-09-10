"""APTrace census reduce: the ONLY thing this reducer treats as
confirmed "library truth" -- curated, provenance-tagged confirmation
that a specific function structurally matches REAL, FETCHED upstream
source, reusing docs/investigations/boot-and-hardware-bringup.md's own
CONFIRMED tier verbatim (Adafruit ArduinoCore-samd v1.7.11, fetched and
compared byte-for-byte/structurally against this image). No new
matching work is done here -- this module only tags rows already
proven by that investigation, plus their mechanically-identified
(fingerprint-EXACT) counterparts in sibling/cross-product images.

IMPORTANT EVIDENCE RULE (see docs/tooling/census.md and the task this
was built for): a cross-image fingerprint match in `library_matches`
(EXACT/STRONG_MATCH/POSSIBLE_MATCH), however strong, is NEVER treated
as "library truth" by this reducer -- it only proves "this code is
shared between OUR OWN products," not "this is confirmed external
library/platform code." Only `reference_source_confirmed=1` here
(matched against REAL, FETCHED reference source) counts for residual-
exclusion purposes. A function can be a very strong cross-image match
and still be a genuinely interesting residual function -- shared code
is not automatically uninteresting.
"""
_CITATION = ("docs/investigations/boot-and-hardware-bringup.md's CONFIRMED tier -- "
             "structurally matched, byte-for-byte, against the real, fetched "
             "adafruit/ArduinoCore-samd v1.7.11 tagged source")

# autopilot868's own CONFIRMED-tier functions (entry address -> what was
# matched). Kept to exactly what that document calls CONFIRMED -- NOT
# its LIKELY_STANDARD_LIBRARY/LIKELY_THIRD_PARTY_LIBRARY/UNKNOWN tiers,
# which are explicitly weaker and not "truth" by this reducer's own rule.
AUTOPILOT868_CONFIRMED = {
    0xcc24: "Reset_Handler (CMSIS Cortex-M startup, byte-for-byte)",
    0xcc10: "Dummy_Handler",
    0xcca4: "SysTick_Handler",
    0xccd0: "millis()",
    0xcd90: "main() (ArduinoCore-samd main.cpp call order: init(); __libc_init_array(); "
             "initVariant(); delay(1); [USB init]; setup(); for(;;){loop();yield();serialEventRun();})",
    0x9464: "the sketch's setup() (call-order match)",
    0x93fc: "the sketch's loop() (call-order match)",
}


def apply_reference_confirmations(conn, firmware_id, firmware_key):
    """Tag this firmware's own CONFIRMED-tier functions directly (for
    autopilot868), or mechanically propagate autopilot868's CONFIRMED
    set to any OTHER image via an EXACT function-fingerprint match (no
    new judgment -- if the bytes are identical to a function already
    human-confirmed against real upstream source, the confirmation
    transfers exactly). Returns the number of rows tagged."""
    tagged = 0

    if firmware_key == "autopilot868":
        for entry, detail in AUTOPILOT868_CONFIRMED.items():
            row = conn.execute("SELECT id FROM functions WHERE firmware_id=? AND entry=?",
                                (firmware_id, entry)).fetchone()
            if row is None:
                continue
            cur = conn.execute("SELECT id FROM library_matches WHERE firmware_id=? AND function_id=?",
                                (firmware_id, row["id"])).fetchone()
            if cur is None:
                conn.execute(
                    "INSERT INTO library_matches (firmware_id, function_id, confidence, method, "
                    "matched_firmware_key, matched_function_id, matched_function_name, "
                    "reference_source_confirmed, reference_source_citation, source) "
                    "VALUES (?,?,?,?,?,?,?,1,?,?)",
                    (firmware_id, row["id"], "EXACT", "reference-source-confirmed", None, None, None,
                     f"{_CITATION} -- {detail}", "reference_library"))
            else:
                conn.execute(
                    "UPDATE library_matches SET reference_source_confirmed=1, reference_source_citation=? "
                    "WHERE id=?", (f"{_CITATION} -- {detail}", cur["id"]))
            tagged += 1
        conn.commit()
        return tagged

    # Any other image: propagate via EXACT fingerprint match against
    # autopilot868's own confirmed functions (mechanical, no new work).
    for entry, detail in AUTOPILOT868_CONFIRMED.items():
        ref_func = conn.execute(
            "SELECT f.id FROM functions f JOIN firmware fw ON fw.id=f.firmware_id "
            "WHERE fw.key='autopilot868' AND f.entry=?", (entry,)).fetchone()
        if ref_func is None:
            continue
        ref_fp = conn.execute(
            "SELECT exact_hash FROM function_fingerprints WHERE firmware_id="
            "(SELECT id FROM firmware WHERE key='autopilot868') AND function_id=?", (ref_func["id"],)).fetchone()
        if ref_fp is None:
            continue
        sib_func = conn.execute(
            "SELECT f.id, f.entry FROM function_fingerprints fp JOIN functions f ON f.id=fp.function_id "
            "WHERE fp.firmware_id=? AND fp.exact_hash=?", (firmware_id, ref_fp["exact_hash"])).fetchone()
        if sib_func is None:
            continue
        citation = f"{_CITATION} -- {detail} (propagated via EXACT fingerprint match to autopilot868 0x{entry:08x})"
        cur = conn.execute("SELECT id FROM library_matches WHERE firmware_id=? AND function_id=?",
                            (firmware_id, sib_func["id"])).fetchone()
        if cur is None:
            conn.execute(
                "INSERT INTO library_matches (firmware_id, function_id, confidence, method, "
                "matched_firmware_key, matched_function_id, matched_function_name, "
                "reference_source_confirmed, reference_source_citation, source) "
                "VALUES (?,?,?,?,?,?,?,1,?,?)",
                (firmware_id, sib_func["id"], "EXACT", "reference-source-confirmed",
                 "autopilot868", ref_func["id"], None, citation, "reference_library"))
        else:
            conn.execute(
                "UPDATE library_matches SET reference_source_confirmed=1, reference_source_citation=? "
                "WHERE id=?", (citation, cur["id"]))
        tagged += 1
    conn.commit()
    return tagged
