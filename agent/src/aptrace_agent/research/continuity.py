"""
Execution-state continuity (state-continuity-v1): which state each
separately executed evidence segment started from, and whether two segments
that an investigation relates share state they never passed to each other.

This is a detector of unsupported continuity, not a composition capability.
It never establishes that two executions are continuous; at most it reports
that a record says one segment carried another's state forward.

Each segment's state is classified from execution metadata already in the
evidence:

- ``supplied``: an initial condition the harness wrote (a seeded memory
  range, a register seed, a forced value). Its value is a harness input.
- ``produced``: state the execution itself wrote, only when the result
  records the writes (``ram_log`` write entries, ``mem_write_hits``).
- ``end_state``: addresses whose final value the result records
  (``final_memory``) and that the segment did not supply. A snapshot does not
  say whether execution or the initial image put the value there, so it is
  never reported as produced.
- ``carried``: state taken from another recorded segment, when the result
  names it (``carried_from``). No current scenario runner records this.
- ``unknown``: anything the record does not identify (for example a seeded
  range that is counted but not located, or writes that were not logged).

Sources, in order of preference:

1. ``result.legs`` (registered-scenario results: ``fresh``, ``seeds``,
   ``reg_seed``, ``forced``, ``stub_calls``), as normalized into an
   assessment scope's ``state`` by ``state_from_result``;
2. for a terminal-assessment-v1 scope, which kept only the rendered harness
   assumptions, APTrace's own assumption strings ("seeded N byte(s) at
   ADDR", "N seeded range(s)", "fresh"). This fallback is pattern-matched and
   is disclosed as such (``source: harness_assumption_text``).

Concerns, for each pair of execution segments:

- ``independently_supplied_state``: both segments supply an overlapping
  address range and no record carries one into the other;
- ``supplied_over_prior_state``: the later segment supplies an address the
  earlier one produced or recorded at its end, so its value is a harness
  input, not the earlier segment's output;
- ``prior_state_not_carried``: the earlier segment produced or recorded end
  state and the later one starts fresh without carrying it.

Two observations of the same registered scenario under the same registry
hash replay one harness state; they are reported as ``same_registered_scenario``,
not as a concern. Legs inside one scenario are not compared.

See docs/critic-validation.md.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any


STATE_VERSION = "execution-state-v1"
CONTINUITY_VERSION = "state-continuity-v1"

PRODUCED, SUPPLIED, CARRIED, UNKNOWN = "produced", "supplied", "carried", "unknown"

INDEPENDENTLY_SUPPLIED = "independently_supplied_state"
SUPPLIED_OVER_PRIOR = "supplied_over_prior_state"
PRIOR_NOT_CARRIED = "prior_state_not_carried"
END_STATE = "end_state"
SAME_SCENARIO = "same_registered_scenario"

_SEEDED_AT = re.compile(r"seeded (\d+) byte\(s\) at (0x[0-9a-fA-F]+)")
_SEEDED_COUNT = re.compile(r"(\d+) seeded range\(s\)")
_REGISTER_COUNT = re.compile(r"(\d+) register seed\(s\)")
_FRESH = re.compile(r"\bfresh\b")
MAX_PRODUCED = 32


def _int(text: Any) -> int | None:
    try:
        return int(str(text), 0)
    except (TypeError, ValueError):
        return None


def _range(addr: Any, length: Any) -> dict[str, Any] | None:
    start = _int(addr)

    if start is None:
        return None

    return {"addr": f"0x{start:08x}", "len": max(1, _int(length) or 1)}


def _unique(ranges: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    seen = {(r["addr"], r["len"]) for r in ranges}
    return [{"addr": a, "len": n} for a, n in sorted(seen)]


def state_from_result(result: Mapping[str, Any]) -> dict[str, Any] | None:
    """Normalized execution state of one concrete result, or None when it records none."""

    legs = [leg for leg in result.get("legs") or [] if isinstance(leg, dict)]
    carried = [str(e) for e in result.get("carried_from") or []]
    final = result.get("final_memory") if isinstance(result.get("final_memory"), dict) else None
    log = [e for e in result.get("ram_log") or [] if isinstance(e, dict)]
    writes = [e.get("address") for e in log if e.get("direction") == "write"]
    writes += [h.get("address") for h in result.get("mem_write_hits") or [] if isinstance(h, dict)]
    writes = sorted({a for w in writes if (a := _int(w)) is not None})

    if not (legs or carried or final or log):
        return None

    normalized = []

    for leg in legs:
        supplied = [r for s in leg.get("seeds") or [] if isinstance(s, dict) and (r := _range(s.get("addr"), s.get("len")))]
        normalized.append({
            "leg": leg.get("leg"),
            "entry": leg.get("entry"),
            "fresh": leg.get("fresh"),
            "supplied": _unique(supplied),
            "registers": sorted({str(r[0]) for r in leg.get("reg_seed") or [] if isinstance(r, (list, tuple)) and r}),
            "forced": sorted(str(k) for k in (leg.get("forced") or {})),
            "stubs": len(leg.get("stub_calls") or []),
        })

    fresh = [leg["fresh"] for leg in normalized]

    if carried:
        initial = CARRIED
    elif fresh and all(f is True for f in fresh):
        initial = "fresh"
    else:
        initial = UNKNOWN

    snapshot = sorted(a for k in (final or {}) if (a := _int(k)) is not None)
    return {
        "version": STATE_VERSION,
        "source": "result.legs" if legs else "result",
        "initial": initial,
        "legs": normalized,
        "carried_from": carried,
        "produced": [f"0x{a:08x}" for a in writes[:MAX_PRODUCED]],
        "produced_total": len(writes),
        "produced_recorded": bool(log),
        "final_snapshot": [f"0x{a:08x}" for a in snapshot[:MAX_PRODUCED]],
    }


def segment_state(scope: Mapping[str, Any]) -> dict[str, Any] | None:
    """State summary of one execution scope (v2 structured state, else the v1 text fallback)."""

    if scope.get("instructions_executed") is None and not scope.get("scenario"):
        return None  # not a concrete execution (e.g. a symbolic or static result)

    state = scope.get("state")

    if isinstance(state, Mapping):
        supplied = _unique([r for leg in state.get("legs") or [] for r in leg.get("supplied") or []])
        registers = sorted({r for leg in state.get("legs") or [] for r in leg.get("registers") or []})
        forced = sorted({f for leg in state.get("legs") or [] for f in leg.get("forced") or []})
        produced = list(state.get("produced") or [])
        snapshot = list(state.get("final_snapshot") or [])
        return {
            "source": state.get("source"),
            "initial": state.get("initial", UNKNOWN),
            "supplied": supplied,
            "supplied_unidentified": 0,
            "registers": registers,
            "forced": forced,
            "carried_from": list(state.get("carried_from") or []),
            "produced": produced,
            "produced_recorded": bool(state.get("produced_recorded")),
            # Recorded at the end, not supplied by this segment and not a logged write.
            "end_state": [a for a in snapshot if a not in produced and not _covered([a], supplied)],
        }

    # terminal-assessment-v1 scope: only the rendered assumptions remain.
    texts = [str(a) for a in scope.get("harness_assumptions") or []]
    supplied = [r for t in texts for n, a in _SEEDED_AT.findall(t) if (r := _range(a, n))]
    counted = max([int(n) for t in texts for n in _SEEDED_COUNT.findall(t)] or [0])
    registers = max([int(n) for t in texts for n in _REGISTER_COUNT.findall(t)] or [0])
    hidden = max(0, (scope.get("harness_assumptions_total") or 0) - len(texts))
    return {
        "source": "harness_assumption_text",
        "initial": "fresh" if any(_FRESH.search(t) for t in texts) else UNKNOWN,
        "supplied": _unique(supplied),
        # Seeded ranges counted but not located, plus assumptions the assessment did not keep.
        "supplied_unidentified": max(0, counted - len(supplied)) + hidden,
        "registers": [f"{registers} unnamed"] if registers else [],
        "forced": [],
        "carried_from": [],
        "produced": [],
        "produced_recorded": False,
        "end_state": [],
    }


def _overlap(left: Sequence[Mapping[str, Any]], right: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    shared = []

    for a in left:
        a0 = int(a["addr"], 16)

        for b in right:
            b0 = int(b["addr"], 16)
            start, end = max(a0, b0), min(a0 + a["len"], b0 + b["len"])

            if start < end:
                shared.append({"addr": f"0x{start:08x}", "len": end - start})

    return _unique(shared)


def _covered(addresses: Sequence[str], ranges: Sequence[Mapping[str, Any]]) -> list[str]:
    hits = []

    for text in addresses:
        a = int(text, 16)

        if any(int(r["addr"], 16) <= a < int(r["addr"], 16) + r["len"] for r in ranges):
            hits.append(text)

    return hits


def _ranges(items: Sequence[Mapping[str, Any]]) -> str:
    return ", ".join(f"{r['addr']} ({r['len']} byte(s))" for r in items)


def analyze(relations: Sequence[Mapping[str, Any]], scopes: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Continuity of state between the execution segments an assessment cites."""

    order = {r["id"]: i for i, r in enumerate(relations)}
    cited_by: dict[str, list[str]] = {}

    for relation in relations:
        for item in list(relation.get("evidence") or []) + list(relation.get("blockers") or []):
            cited_by.setdefault(item["evidence_id"], [])

            if relation["id"] not in cited_by[item["evidence_id"]]:
                cited_by[item["evidence_id"]].append(relation["id"])

    segments = []

    for scope in scopes:
        state = segment_state(scope)

        if state is None:
            continue

        segments.append({
            "evidence_id": scope["evidence_id"],
            "scenario": scope.get("scenario"),
            "scenario_registry_sha256": scope.get("scenario_registry_sha256"),
            "relations": cited_by.get(scope["evidence_id"], []),
            **state,
        })

    def rank(segment: Mapping[str, Any]) -> int:
        return min((order[r] for r in segment["relations"] if r in order), default=len(order))

    segments.sort(key=lambda s: (rank(s), s["evidence_id"]))
    concerns, pairs = [], []

    for i, first in enumerate(segments):
        for second in segments[i + 1:]:
            ids = [first["evidence_id"], second["evidence_id"]]
            carried = first["evidence_id"] in second["carried_from"] or second["evidence_id"] in first["carried_from"]

            if (first["scenario"] and first["scenario"] == second["scenario"]
                    and first["scenario_registry_sha256"] == second["scenario_registry_sha256"]):
                pairs.append({"segments": ids, "relation": SAME_SCENARIO})
                continue

            pairs.append({"segments": ids, "relation": CARRIED if carried else "independent"})

            if carried:
                continue

            base = {"segments": ids, "scenarios": [first["scenario"], second["scenario"]],
                    "relations": {first["evidence_id"]: first["relations"], second["evidence_id"]: second["relations"]},
                    "establishes_continuity": False}
            shared = _overlap(first["supplied"], second["supplied"])

            if shared:
                concerns.append(dict(base, kind=INDEPENDENTLY_SUPPLIED, addresses=shared,
                                     state={ids[0]: SUPPLIED, ids[1]: SUPPLIED},
                                     statement=f"{ids[0]} and {ids[1]} each supply {_ranges(shared)} as an initial condition; "
                                               "neither execution produced the other's value, and no record carries state "
                                               "between them",
                                     requirement=f"one execution in which {_ranges(shared)} is produced by the firmware before "
                                                 f"the later segment uses it, or a later segment that starts from {ids[0]}'s "
                                                 "recorded final state instead of a seed"))

            prior = [(a, PRODUCED) for a in first["produced"]] + [(a, END_STATE) for a in first["end_state"]]
            overwritten = [(a, c) for a, c in prior if _covered([a], second["supplied"])]

            if overwritten:
                concerns.append(dict(base, kind=SUPPLIED_OVER_PRIOR,
                                     addresses=[{"addr": a, "len": 1} for a, _ in overwritten],
                                     state={ids[0]: sorted({c for _, c in overwritten}), ids[1]: SUPPLIED},
                                     statement=f"{ids[1]} supplies {', '.join(a for a, _ in overwritten)}, which {ids[0]} "
                                               f"{'produced' if all(c == PRODUCED for _, c in overwritten) else 'recorded at its end'}; "
                                               f"{ids[1]}'s value is a harness input, not {ids[0]}'s output",
                                     requirement=f"{ids[1]} rerun from {ids[0]}'s recorded value (carried forward), not a seed"))

            if prior and second["initial"] == "fresh":
                kinds = sorted({c for _, c in prior})
                concerns.append(dict(base, kind=PRIOR_NOT_CARRIED,
                                     addresses=[{"addr": a, "len": 1} for a, _ in prior],
                                     state={ids[0]: kinds, ids[1]: "fresh"},
                                     statement=f"{ids[0]} ends with {len(prior)} recorded address(es) of state "
                                               f"({' and '.join(kinds)}); {ids[1]} starts from fresh machine state and "
                                               "carries none of it",
                                     requirement=f"an execution of {ids[1]}'s code that starts from {ids[0]}'s end state, "
                                                 "recorded as carried forward"))

    for number, concern in enumerate(concerns, 1):
        concern["id"] = f"C{number}"

    unknown = [
        {"evidence_id": s["evidence_id"],
         "detail": "; ".join(part for part in (
             f"{s['supplied_unidentified']} supplied item(s) not located" if s["supplied_unidentified"] else "",
             "writes not logged (produced state not distinguished)" if not s["produced_recorded"] else "",
             "initial state not identified" if s["initial"] == UNKNOWN else "",
         ) if part)}
        for s in segments
        if s["supplied_unidentified"] or not s["produced_recorded"] or s["initial"] == UNKNOWN
    ]
    return {
        "version": CONTINUITY_VERSION,
        "segments": segments,
        "pairs": pairs,
        "concerns": concerns,
        "unknown": unknown,
        "note": "a concern states that continuity is unsupported; no result here establishes runtime continuity",
    }


__all__ = [
    "STATE_VERSION", "CONTINUITY_VERSION", "PRODUCED", "SUPPLIED", "CARRIED", "UNKNOWN",
    "END_STATE", "INDEPENDENTLY_SUPPLIED", "SUPPLIED_OVER_PRIOR", "PRIOR_NOT_CARRIED", "SAME_SCENARIO",
    "state_from_result", "segment_state", "analyze",
]
