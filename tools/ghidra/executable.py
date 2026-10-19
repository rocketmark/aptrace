"""Bounded static evidence over native Ghidra executable projects.

No PE parser, instruction semantics, source-identity inference or claim promotion.
Lifecycle and original static exports are owned by aptrace_ghidra.
"""
import hashlib
import json
import tempfile
from pathlib import Path


def query(backend, target, kind, *, pattern="", address=None, limit=100):
    if target not in backend.EXECUTABLE_REGISTRY:
        raise ValueError("executable query requires an explicitly registered executable target")
    if not 1 <= limit <= 1000 or len(pattern) > 256:
        raise ValueError("query limit must be 1..1000; pattern at most 256 characters")
    if kind not in {"inventory", "search", "functions", "imports", "references", "xrefs", "callers", "callees", "function", "entry-function", "cfg", "data"}:
        raise ValueError("unsupported executable query")
    backend.ensure_fresh(target)
    static = backend._load_static_export(target)
    inv = json.loads((backend.cache_dir(target) / "executable.json").read_text())
    backend._validate_executable_inventory(target, inv)
    args = {"kind": kind, "pattern": pattern, "address": address, "limit": limit}
    total = None
    if kind in {"function", "entry-function", "cfg", "data"}:
        if address is None:
            raise ValueError("address required")
        int(address, 0)  # validate before engine invocation; never clear a Thumb bit
        with tempfile.NamedTemporaryFile(dir=backend.cache_dir(target), suffix=".json") as f:
            backend._query_via_process(target, "APTraceExecutableQuery.java",
                [f.name, kind, address, str(limit)], f"{kind} {address}")
            try:
                result = json.loads(Path(f.name).read_text())
            except json.JSONDecodeError as exc:
                raise ValueError(f"native query produced no JSON; inspect {backend.cache_dir(target) / '_last_headless.log'}") from exc
    elif kind == "inventory":
        result = {k: v for k, v in inv.items() if k != "imports"}
        for field in ("memory_blocks", "entry_points"):
            if len(result[field]) > limit:
                result[field] = result[field][:limit]
                result["truncated"] = True
        result["counts"] = {k: len(static[k]) for k in ("functions", "strings", "calls", "dataReferences")}
    else:
        table = {"search": "strings", "functions": "functions", "imports": "imports",
                 "references": "dataReferences", "xrefs": "dataReferences", "callers": "calls", "callees": "calls"}[kind]
        rows = inv[table] if kind == "imports" else static[table]
        if kind in {"xrefs", "callers", "callees"}:
            if address is None:
                raise ValueError("address required")
            addr = int(address, 0)
            def matches(r):
                fields = ("from", "to") if kind == "xrefs" else (("to",) if kind == "callers" else ("from",))
                if kind == "callees":
                    # Callees queried by containing function, not just its entry instruction.
                    funcs = [f for f in static["functions"] if int(f["entry"], 16) == addr]
                    if funcs and sum(f["name"] == funcs[0]["name"] for f in static["functions"]) != 1:
                        raise ValueError("ambiguous exported function name; use the native CFG query")
                    return bool(funcs) and r.get("fromFunction") == funcs[0]["name"]
                def memory_address(value):
                    # Native exports also contain Stack/register/external spaces.
                    try:
                        return int(value, 16)
                    except (ValueError, TypeError):
                        return None
                return any(memory_address(r.get(k)) == addr for k in fields)
            rows = [r for r in rows if matches(r)]
        elif pattern:
            rows = [r for r in rows if pattern.lower() in json.dumps(r, ensure_ascii=False).lower()]
        total = len(rows)
        selected = []
        text_truncated = False
        for row in rows[:limit]:
            clipped = {k: (v[:4096] if isinstance(v, str) else v) for k, v in row.items()}
            text_truncated |= clipped != row
            selected.append(clipped)
        result = {"rows": selected, "matches_total": total, "truncated": total > limit,
                  "text_truncated": text_truncated}
        if kind == "imports" and inv.get("truncated"):
            result.update(source_truncated=True, truncated=True, matches_total_scope="exported_subset")
    meta = backend.expected_identity(target)
    return {"schema_version": 1, "operation": "executable_structure_v1", "target": target,
            "arguments": args, "identity": meta, "evidence_level": "static-ghidra",
            "query_script_sha256": backend.sha256_of(backend.SCRIPTS_DIR / "APTraceExecutableQuery.java"),
            "query_implementation_sha256": backend.sha256_of(Path(__file__)),
            "export_sha256": backend.sha256_of(backend.cache_dir(target) / "static_export.json"),
            "result": result, "limitations": [
                "Ghidra-discovered boundaries/flow are heuristic; unresolved computed edges remain incomplete",
                "No Windows execution, serial-device behavior, physical protection or VERIFIED claim is established",
                "Absence of a defined string/reference does not establish absence of behavior"],
            "result_sha256": hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()}
