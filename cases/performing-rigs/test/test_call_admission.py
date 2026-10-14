#!/usr/bin/env python3
"""Performing Rigs: call-relation admission on the indirect-dispatch trials.

research/runs/call-admission-v1/trial-evidence.json holds the session
evidence (E1-E8) and the claim lines of the three live planner trials of
indirect-dispatch-v1. Qwen proposed "FUN_0000c7c0 is called by FUN_0000c5cc"
and "FUN_0000c5cc can call FUN_0000c4b8 or FUN_0000c7c0" citing E7, E8;
E7 is function_facts(FUN_0000c4b8), E8 function_facts(FUN_0000c7c0) with no
callers. Admission admitted both. This replays the exact lines through the
controller's parser and admission, and checks that correctly scoped claims
about the same evidence are still admitted. Plain assertions via check().
Run with the agent venv from the repo root:

    agent/.venv/bin/python cases/performing-rigs/test/test_call_admission.py
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE = HERE.parent
REPO_ROOT = CASE.parents[1]
FIXTURE = CASE / "research" / "runs" / "call-admission-v1" / "trial-evidence.json"
sys.path.insert(0, str(REPO_ROOT / "agent" / "src"))

from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchController, ResearchSession  # noqa: E402
from aptrace_agent.research.admission import admit  # noqa: E402
from aptrace_agent.schemas import EvidenceObservation  # noqa: E402

FAILURES = []
DOC = json.loads(FIXTURE.read_text())
FUNCTIONS = {f"FUN_{v:08x}" for v in (0xC5CC, 0xC4B8, 0xC7C0, 0xBDD4, 0xC724, 0xB890, 0xD388, 0xBC08)}


def check(name, condition, detail=""):
    print(f"  [{'ok' if condition else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def session():
    registry = LeadRegistry()
    s = ResearchSession(objective=DOC["provenance"]["objective"], registry=registry, follower=LeadFollower(registry=registry, executor=None))
    for item in DOC["evidence"]:
        s.record(EvidenceObservation(id=item["alias"], tool=item["tool"], arguments=item["arguments"], result=item["result"] or {}))
    return s


def decide(line, s=None):
    proposals, unparseable = ResearchController._parse_claims([line])
    assert not unparseable and len(proposals) == 1, line
    return admit(proposals[0], s or session(), round=1, function_exists=lambda name: name in FUNCTIONS)


def codes(record, severity="reject"):
    return {d.code for d in record.diagnostics if d.severity == severity}


def main():
    s = session()
    print("original trial proposals")
    originals = {a["raw"]: a for t in DOC["trials"] for a in t["claim_admission"]}
    check("fixture holds the three trials' 3 distinct lines", len(originals) == 3, str(list(originals)))
    check("the trials admitted both call claims", sorted(a["decision"] for a in originals.values()) == ["admitted", "admitted", "rejected"])

    called_by = decide("PROBABLE STRUCTURE E7,E8 FUN_0000c7c0 is called by FUN_0000c5cc", s)
    check("c5cc -> c7c0 (passive) rejected", called_by.decision == "rejected", str(called_by.diagnostics))
    check("  as CALL_RELATION_UNSUPPORTED", codes(called_by) == {"CALL_RELATION_UNSUPPORTED"}, str(codes(called_by)))
    detail = next(d.detail for d in called_by.diagnostics if d.code == "CALL_RELATION_UNSUPPORTED")
    check("  detail names the relation and E8's empty caller list", "FUN_0000c5cc -> FUN_0000c7c0" in detail and "E8 lists no callers of FUN_0000c7c0" in detail, detail)
    check("  detail shows the edge E7 does establish", "E7: FUN_0000c5cc -> 0x0000c4b8 at 0x0000c66a DIRECT_CALL" in detail, detail)

    either = decide("PROBABLE STRUCTURE E7,E8 FUN_0000c5cc can call FUN_0000c4b8 or FUN_0000c7c0", s)
    check("c5cc can call c4b8 or c7c0 rejected", either.decision == "rejected", str(either.diagnostics))
    check("  c4b8 disjunct checked, c7c0 disjunct unsupported",
          {d.value for d in either.diagnostics if d.code == "CALL_RELATION_CHECKED"} == {"FUN_0000c5cc -> FUN_0000c4b8"}
          and {d.value for d in either.diagnostics if d.code == "CALL_RELATION_UNSUPPORTED"} == {"FUN_0000c5cc -> FUN_0000c7c0"})

    malformed = decide("PROBABLE STRUCTURE E7,E8 E0000c5cc can call FUN_0000c7c0 or FUN_0000c4b8", s)
    check("E0000c5cc line still rejected as ENTITY_MALFORMED", "ENTITY_MALFORMED" in codes(malformed))

    every = decide("PROBABLE STRUCTURE E1,E2,E3,E4,E5,E6,E7,E8 FUN_0000c5cc calls FUN_0000c7c0", s)
    check("citing all session evidence: still rejected", every.decision == "rejected")
    check("  E1/E2 enumerate c5cc's direct calls: CALL_TARGET_MISMATCH", "CALL_TARGET_MISMATCH" in codes(every), str(codes(every)))

    print("correctly scoped claims on the same evidence")
    direct = decide("PROBABLE STRUCTURE E7 FUN_0000c5cc calls FUN_0000c4b8 at 0x0000c66a", s)
    check("direct c5cc -> c4b8 at 0xc66a admitted", direct.decision == "admitted", str(direct.diagnostics))
    decoded = decide("PROBABLE STRUCTURE E2 FUN_0000c5cc calls FUN_0000b890 at 0x0000c5ea", s)
    check("decoded BL c5cc -> b890 admitted", decoded.decision == "admitted", str(decoded.diagnostics))
    wrong_site = decide("PROBABLE STRUCTURE E7 FUN_0000c5cc calls FUN_0000c4b8 at 0x0000c6d8", s)
    check("wrong call site: CALL_SITE_MISMATCH", codes(wrong_site) == {"CALL_SITE_MISMATCH"}, str(codes(wrong_site)))

    conditional = decide(
        "PROBABLE RESOLUTION E3 FUN_0000c5cc's indirect call at 0x0000c6d8 may dispatch to 0x0000ca58 if the receiver's vptr is 0x00014900", s
    )
    check("conditional c6d8 -> ca58 with the vptr condition admitted", conditional.decision == "admitted", str(conditional.diagnostics))
    unconditional = decide("PROBABLE RESOLUTION E3 FUN_0000c5cc calls 0x0000ca58", s)
    check("same target stated unconditionally: CALL_CONDITION_OMITTED", codes(unconditional) == {"CALL_CONDITION_OMITTED"}, str(codes(unconditional)))
    wrong_vtable = decide("PROBABLE RESOLUTION E3 FUN_0000c5cc may call 0x0000ca58 if the receiver's vptr is 0x00014050", s)
    check("condition naming another vtable: CALL_CONDITION_OMITTED", codes(wrong_vtable) == {"CALL_CONDITION_OMITTED"}, str(codes(wrong_vtable)))
    not_a_target = decide("PROBABLE RESOLUTION E3 FUN_0000c5cc may call FUN_0000c7c0 if the receiver's vptr is 0x00014900", s)
    check("c7c0 is not a 0xc6d8 candidate under any vptr: rejected", not_a_target.decision == "rejected", str(codes(not_a_target)))

    absent = decide("PROBABLE STRUCTURE E8 FUN_0000c7c0 has no callers", s)
    check("unscoped 'has no callers': CALL_ABSENCE_NOT_ESTABLISHED", codes(absent) == {"CALL_ABSENCE_NOT_ESTABLISHED"}, str(codes(absent)))
    scoped = decide("PROBABLE STRUCTURE E8 FUN_0000c7c0 has no recorded callers in the Ghidra call graph", s)
    check("scoped 'no recorded callers' admitted with CALL_ABSENCE_SCOPED", scoped.decision == "admitted" and "CALL_ABSENCE_SCOPED" in codes(scoped, "note"))

    if FAILURES:
        print(f"\n{len(FAILURES)} failure(s): {FAILURES}")
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
