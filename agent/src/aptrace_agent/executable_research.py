"""Deterministic target/capability routing and bounded static host research.

This path deliberately does not create ARM session facts or admitted claims.
Native Ghidra observations are journaled with identity and explicit limits.
"""
from contextlib import redirect_stdout
from collections import deque
import io
import re
from pathlib import Path

from aptrace_agent.ghidra_index import _aptrace_ghidra


def select_target(question, explicit=None, *, backend=None):
    backend = backend or _aptrace_ghidra()
    registry = backend.EXECUTABLE_REGISTRY
    if explicit:
        if explicit not in registry:
            raise ValueError(f"unknown executable target {explicit!r}")
        return explicit
    found = []
    for key, spec in registry.items():
        names = (key, Path(spec["path"]).name)
        if any(re.search(r"(?<![\w.])" + re.escape(n) + r"(?![\w.])", question, re.I) for n in names):
            found.append(key)
    if len(found) > 1:
        raise ValueError("ambiguous executable objective; specify --target")
    if found:
        return found[0]
    if re.search(r"\b[\w-]+\.exe\b", question, re.I):
        raise ValueError("executable objective has no registered target; refusing ARM fallback")
    return None


def research(question, target, *, max_steps=12, backend=None):
    if not 1 <= max_steps <= 100:
        raise ValueError("host research budget must be 1..100")
    if len(question) > 12000:
        raise ValueError("host objective exceeds 12000 characters")
    backend = backend or _aptrace_ghidra()
    from executable import query
    # Build/reuse via the existing lifecycle, before any evidence is returned.
    with redirect_stdout(io.StringIO()):
        backend.build(target)
    data = backend._load_static_export(target)
    words = set(re.findall(r"[a-z0-9_]{4,}", question.lower()))
    candidates = sorted(data["strings"], key=lambda r: (
        -sum(w in r["value"].lower() for w in words), r["address"]))
    candidates = [r for r in candidates if any(w in r["value"].lower() for w in words)][:20]
    jobs = deque([("inventory", {})] + [("xrefs", {"address": r["address"]}) for r in candidates])
    journal, seen = [], set()
    # Report the selected strings separately, so negative xrefs aren't mistaken
    # for absent behavior. Limits apply to discovery and every engine query.
    while jobs and len(journal) < max_steps:
        kind, args = jobs.popleft()
        ident = (kind, tuple(sorted(args.items())))
        if ident in seen:
            continue
        seen.add(ident)
        observation = query(backend, target, kind, limit=100, **args)
        journal.append(observation)
        if kind == "xrefs":
            # Follow concrete Ghidra references before exploring more strings.
            entries = {f["name"]: f["entry"] for f in data["functions"]}
            addresses = list(dict.fromkeys(entries.get(r.get("fromFunction"), r["from"])
                for r in observation["result"]["rows"]))[:3]
            for address in reversed(addresses):
                jobs.appendleft(("function", {"address": address}))
    return {"schema_version": 1, "routing": "native-executable-static",
            "objective": question, "target": target, "budget": max_steps,
            "stop_reason": "budget_exhausted" if jobs else "bounded_discovery_finished",
            "discovered_strings": candidates, "evidence": journal, "claims": [],
            "remaining_queries": [{"kind": k, **a} for k, a in jobs],
            "limitations": ["Static Ghidra evidence only; no claim admission or VERIFIED transition",
                            "Keyword discovery is bounded, not exhaustive behavior analysis"]}
