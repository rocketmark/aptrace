"""
Deterministic Agent v0 tests: bounded planner projection, structural
actions (graph common paths, USB inventory, function effects), and the
controller's census-first behavior. No live model is used.
"""

import json
import sqlite3
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from aptrace_agent.census_graph import CensusGraph, PathStatus
from aptrace_agent.function_effects import (
    EffectsInputError,
    FunctionEffectsRunner,
    planner_summary,
    validate_request,
)
from aptrace_agent.interface_inventory import scan_usb_descriptors
from aptrace_agent.research import (
    LeadDeriver,
    LeadFollower,
    LeadRegistry,
    ResearchController,
    ResearchSession,
)
from aptrace_agent.research.projection import (
    PlannerProjection,
    ProjectionBudget,
    conclusion,
)
from aptrace_agent.schemas import EvidenceObservation


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA = REPO_ROOT / "tools" / "census" / "schema.sql"
SHA = "ab" * 32
ALL_STRUCTURAL = ("usb_inventory", "common_paths", "function_effects")


# -- fakes ----------------------------------------------------------------------


def _function_facts(name):
    return {
        "name": name,
        "entry": "0x" + name[4:],
        "size": 40,
        "callers": [{"function": "FUN_00009000", "address": "0x00009010"}],
        "callees": [],
        "unique_caller_count": 1,
    }


class FakeFactsReader:
    def function_facts(self, function):
        if not function.startswith("FUN_"):
            raise KeyError(function)

        return _function_facts(function)


class FakeCallsiteReader:
    def context(self, function, address, before=8, after=8):
        return {
            "function": function,
            "address": address,
            "instructions": [
                {"address": address, "mnemonic": "bl", "operands": "0x00002000"},
            ],
        }


class StructuralExecutor:
    """Executes every evidence operation with deterministic synthetic results."""

    def __init__(self):
        self.calls = []

    def execute_operation(self, tool, arguments, *, evidence_id):
        self.calls.append((tool, json.loads(json.dumps(arguments))))

        if tool == "census_peripheral_usage":
            peripheral = arguments["peripheral"]
            base = {"TCC1": 0x3000, "EIC": 0xA000, "PORT": 0xB000, "USB": 0xC000}.get(peripheral, 0xE000)
            result = {
                "status": "ok",
                "peripheral": peripheral,
                "total_mmio_sites": 3,
                "total_address_constants": 1,
                "unreferenced_address_constants": 0,
                "total_functions": 2,
                "functions": [
                    {
                        "function": f"FUN_{base + i * 0x40:08x}",
                        "mmio_site_count": 1,
                        "mmio_sites": [{"register_name": "CTRLA", "direction": "WRITE", "address": "0x0"}],
                        "constant_loads": [],
                        "reachability": {"status": "DEFINITELY_REACHABLE"},
                    }
                    for i in range(2)
                ],
                "unattributed_sites": [],
                "provenance": {"reduction_status": "present"},
            }
        elif tool == "census_usb_inventory":
            result = {
                "status": "ok",
                "register_users": [
                    {"function": "FUN_0000c000", "reachability": "DEFINITELY_REACHABLE", "reads": ["CTRLA"], "writes": []}
                ],
                "irq_vectors": [
                    {
                        "irq": 80,
                        "name": "USB_OTHER",
                        "handler": "FUN_0000cc14",
                        "census_function_at_entry": None,
                        "inside_census_function": None,
                        "in_census_vector_table": False,
                    }
                ],
                "descriptors": [],
                "functions": ["FUN_0000c000"],
                "planner_summary": "USB inventory (synthetic): 1 register user; USB_OTHER(80)->FUN_0000cc14 [no census fn]",
            }
        elif tool == "census_common_paths":
            result = {
                "status": "NO_KNOWN_PATH",
                "left_label": arguments["left_label"],
                "right_label": arguments["right_label"],
                "max_hops": 8,
                "left": [{"function": f, "roots": ["reset"]} for f in arguments["left"]],
                "right": [{"function": f, "roots": ["reset"]} for f in arguments["right"]],
                "explored_left": 3,
                "explored_right": 2,
                "common": [],
                "shared_state": [],
                "frontier_total": 1,
                "frontier": [{"site": "0x0000a012", "function": arguments["left"][0], "side": "left", "kind": "unresolved reg-indirect"}],
                "planner_summary": f"common paths {arguments['left_label']}|{arguments['right_label']}: NO_KNOWN_PATH",
            }
        elif tool == "function_effects":
            result = {
                "status": "complete",
                "function": arguments["function"],
                "inputs_used": ["r0"],
                "reads": 2,
                "writes": 0,
                "calls": [],
                "accesses": [],
                "return_depends_on": ["r0"],
                "return_bit_valued": "proven",
                "specialized": [],
                "planner_summary": f"{arguments['function']} effects [RAW complete]",
            }
        elif tool == "function_facts":
            result = _function_facts(arguments["function"])
        elif tool == "function_disassembly":
            result = {
                "name": arguments["function"],
                "instructions": [
                    {"address": f"0x{0x1000 + 2 * i:08x}", "mnemonic": "movs", "operands": "r0, #1"}
                    for i in range(400)
                ],
            }
        elif tool == "callsite_context":
            result = FakeCallsiteReader().context(arguments["function"], arguments["address"])
        elif tool == "search_case_evidence":
            result = {
                "query": arguments["query"],
                "matches": [
                    {"source": f"docs/notes{i}.md", "line": i, "excerpt": "optocoupler trigger input " * 60}
                    for i in range(8)
                ],
            }
        else:
            result = {"value": "executed"}

        return EvidenceObservation(id=evidence_id, tool=tool, arguments=dict(arguments), result=result)


class ScriptedPlanner:
    """Plays scripted decisions; records every request."""

    def __init__(self, decisions, *, reject_above_bytes=None, reject_as_body=False):
        self.decisions = list(decisions)
        self.requests = []
        self.reject_above_bytes = reject_above_bytes
        self.reject_as_body = reject_as_body

    def create(self, **kwargs):
        self.requests.append(kwargs)
        size = len(json.dumps(kwargs["messages"])) + len(json.dumps(kwargs["tools"]))

        if self.reject_above_bytes is not None and size > self.reject_above_bytes:
            error = {"code": "prefill_memory_exceeded", "message": "oMLX prefill memory guard rejected this prompt"}

            if self.reject_as_body:
                return SimpleNamespace(choices=None, model_extra={"error": error}, usage=None)

            raise RuntimeError(f"Error code: 400 - {error}")

        decision = self.decisions.pop(0) if self.decisions else ("finish", {"reason": "scripted end"})

        if callable(decision):
            decision = decision(kwargs)

        name, arguments = decision
        return SimpleNamespace(
            usage=SimpleNamespace(prompt_tokens=size // 3),
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=None,
                        tool_calls=[SimpleNamespace(function=SimpleNamespace(name=name, arguments=json.dumps(arguments)))],
                    )
                )
            ],
        )


class NoReconciler:
    def __init__(self):
        self.calls = 0

    def run(self, session):
        self.calls += 1


def _session(objective="Which firmware functions configure the TCC1 timer, and are they reachable from reset?"):
    registry = LeadRegistry()
    executor = StructuralExecutor()
    session = ResearchSession(
        objective=objective,
        registry=registry,
        follower=LeadFollower(registry=registry, executor=executor),
        deriver=LeadDeriver(
            registry=registry,
            callsite_reader=FakeCallsiteReader(),
            function_facts_reader=FakeFactsReader(),
        ),
    )
    return session, executor


def _controller(planner, **kwargs):
    kwargs.setdefault("census_peripherals", ("EIC", "PORT", "SERCOM2", "TCC1", "USB"))
    return ResearchController(
        planner_client=SimpleNamespace(chat=SimpleNamespace(completions=planner)),
        planner_model="test",
        reconciler=NoReconciler(),
        prefill_retry_delay=0,
        **kwargs,
    )


def _tool_names(request):
    return [tool["function"]["name"] for tool in request["tools"]]


def _visible_leads(request):
    for tool in request["tools"]:
        if tool["function"]["name"] == "follow_lead":
            return tool["function"]["parameters"]["properties"]["lead_id"]["enum"]

    return []


def _first_lead(request):
    if "follow_lead" in _tool_names(request) and _visible_leads(request):
        return ("follow_lead", {"lead_id": _visible_leads(request)[0]})

    return ("finish", {"reason": "no leads"})


def _keep_going(request):
    """A planner that never finishes while any valid action remains."""

    names = _tool_names(request)

    if "follow_lead" in names and _visible_leads(request):
        return _first_lead(request)

    if "analyze_peripheral" in names:
        tool = next(t for t in request["tools"] if t["function"]["name"] == "analyze_peripheral")
        return ("analyze_peripheral", {"peripheral": tool["function"]["parameters"]["properties"]["peripheral"]["enum"][0]})

    if "search_case_evidence" in names:
        return ("search_case_evidence", {"query": f"angle {len(request['messages'][-1]['content'])}"})

    return ("finish", {"reason": "nothing left"})


def _grow_history(session, executor, count):
    """Record a long mixed evidence history directly through the session."""

    tools = ["search_case_evidence", "function_disassembly", "function_facts", "census_peripheral_usage"]

    for i in range(count):
        tool = tools[i % len(tools)]
        arguments = {
            "search_case_evidence": {"query": f"query {i}", "purpose": "discovery"},
            "function_disassembly": {"function": f"FUN_{0x2000 + i * 4:08x}"},
            "function_facts": {"function": f"FUN_{0x3000 + i * 4:08x}"},
            "census_peripheral_usage": {"peripheral": f"P{i}", "limit": 25},
        }[tool]
        session.record(executor.execute_operation(tool, arguments, evidence_id=session.ledger.next_id()))


# -- 1-3: bounded projection, complete internal evidence, newest facts --------


def test_planner_projection_reaches_a_stable_bound_as_history_grows():
    session, executor = _session()
    controller = _controller(ScriptedPlanner([]), structural_tools=ALL_STRUCTURAL)
    budget = controller.projection.budget
    sizes = {}

    for target in (10, 40, 120, 240):
        _grow_history(session, executor, target - len(session.ledger))
        state = controller.projection.render(session)
        prompt, _ = controller._decision_prompt(session, controller._decision_palette(session))
        tools = json.dumps(controller._decision_palette(session).tools)
        sizes[target] = len(prompt) + len(tools)
        assert len(state) <= budget.total

    # Bounded: no growth between 120 and 240 records beyond a small margin
    # (identifier widths), and absolute size well under the old plateau.
    assert sizes[240] - sizes[120] < 200
    assert sizes[240] < 7000
    assert len(session.ledger) == 240


def test_full_evidence_remains_internal_while_planner_sees_a_projection():
    session, executor = _session()
    _grow_history(session, executor, 80)
    controller = _controller(ScriptedPlanner([]))
    state = controller.projection.render(session)

    # The ledger holds every complete payload; the projection holds none.
    disassembly = [obs for obs in session.ledger.all() if obs.tool == "function_disassembly"]
    assert len(session.ledger) == 80
    assert all(len(obs.result["instructions"]) == 400 for obs in disassembly)
    assert "movs" not in state
    assert len(session.state.claims) > 20
    assert len(state) <= controller.projection.budget.total
    assert "older retained by APTrace" in state


def test_newest_and_high_value_facts_survive_compaction():
    session, executor = _session()
    _grow_history(session, executor, 60)
    newest = session.record(
        executor.execute_operation(
            "census_common_paths",
            {"left": ["FUN_0000a000"], "right": ["FUN_0000c000"], "left_label": "EIC", "right_label": "USB"},
            evidence_id=session.ledger.next_id(),
        )
    )
    state = PlannerProjection().render(session)
    newest_claims = [claim for claim in session.state.claims if newest.id in claim.evidence_ids]

    assert newest_claims
    assert any(claim.id in state for claim in newest_claims)
    assert "NO_KNOWN_PATH" in state
    # Frontier-derived open question survives into the planner view.
    assert "[open]" in state and "unresolved indirect" in state
    # The oldest census claims are compacted away but retained.
    assert session.state.claims[0].id + "[" not in state


def test_compact_budget_is_smaller_than_normal():
    session, executor = _session()
    _grow_history(session, executor, 60)
    normal = PlannerProjection().render(session)
    compact = PlannerProjection(ProjectionBudget(total=1400, facts=520, latest_count=1, latest_first=360, latest=360)).render(session)
    assert len(compact) < len(normal) <= 2800


# -- 4, 12: census-first TCC1 behavior and short objectives complete --------------


def test_tcc1_objective_stays_census_first_and_completes():
    session, executor = _session()
    planner = ScriptedPlanner(
        [
            ("analyze_peripheral", {"peripheral": "TCC1"}),
            _first_lead,
            _first_lead,
            ("finish", {"reason": "TCC1 configuration functions identified", "hypotheses": ["FUN_00003000 sets the TCC1 period"]}),
        ]
    )
    controller = _controller(planner, structural_tools=ALL_STRUCTURAL, max_steps=6)
    result = controller.run(session)

    first = planner.requests[0]
    assert "analyze_peripheral" in _tool_names(first)
    assert "TCC1" in next(
        t for t in first["tools"] if t["function"]["name"] == "analyze_peripheral"
    )["function"]["parameters"]["properties"]["peripheral"]["enum"]
    assert first["max_tokens"] == 512
    assert [step.action for step in result.steps] == ["analyze", "follow_lead", "follow_lead", "finish"]
    assert executor.calls[0] == ("census_peripheral_usage", {"peripheral": "TCC1", "limit": 25})
    # The narrowed census functions are inspected before any callsite crawl.
    assert [call[0] for call in executor.calls[1:3]] == ["function_facts", "function_facts"]
    assert {call[1]["function"] for call in executor.calls[1:3]} == {"FUN_00003000", "FUN_00003040"}
    assert result.stop_reason == "planner_finished"

    answer = conclusion(session.state)
    assert any("TCC1" in line and "[census]" in line for line in answer["proven"])
    assert any("[planner]" in line for line in answer["probable"])


def test_short_sercom2_objective_completes_census_first():
    session, executor = _session("Which functions use SERCOM2 and are they reachable from reset?")
    planner = ScriptedPlanner([("analyze_peripheral", {"peripheral": "SERCOM2"}), ("finish", {"reason": "answered"})])
    result = _controller(planner, structural_tools=ALL_STRUCTURAL).run(session)
    assert [step.action for step in result.steps] == ["analyze", "finish"]
    assert result.stop_reason == "planner_finished"
    assert len(result.planner_requests) == 2


# -- 5, 6: function effects is bounded and summarized --------------------------------


def test_function_effects_tool_rejects_paths_mmio_and_solver_arguments():
    session, executor = _session()
    planner = ScriptedPlanner(
        [
            ("analyze_peripheral", {"peripheral": "EIC"}),
            (
                "analyze_function_effects",
                {"function": "FUN_0000a000", "mmio": "0x40000000:0x1000", "smt": "(assert false)", "path": "/etc/passwd"},
            ),
            ("analyze_function_effects", {"function": "FUN_0000dead"}),
            ("finish", {"reason": "done"}),
        ]
    )
    controller = _controller(planner, structural_tools=ALL_STRUCTURAL, max_steps=3)
    result = controller.run(session)

    effects_tool = next(t for t in planner.requests[1]["tools"] if t["function"]["name"] == "analyze_function_effects")
    assert set(effects_tool["function"]["parameters"]["properties"]) == {"function", "r0", "r1"}
    assert effects_tool["function"]["parameters"]["additionalProperties"] is False
    correction = planner.requests[2]["messages"][-1]["content"]
    assert "rejected mmio, path, smt" in correction
    assert all(call[0] != "function_effects" for call in executor.calls)
    assert result.stop_reason == "planner_contract_exhausted"


def test_effects_runner_validates_and_builds_only_bounded_argv(tmp_path):
    with pytest.raises(EffectsInputError):
        validate_request("../../etc/passwd", None)

    for bad in ({"mmio": 1}, {"r5": 1}, {"r0": -1}, {"r0": "1"}, {"r0": 1, "r1": 2, "r2": 3}, {"r0": True}):
        with pytest.raises(EffectsInputError):
            validate_request("FUN_0000d3dc", bad)

    image = tmp_path / "fw.bin"
    image.write_bytes(b"\x00" * 64)
    import hashlib

    argvs = []

    def fake_run(argv):
        argvs.append(argv)
        prefix = Path(next(a for a in argv if a.startswith("out="))[4:])
        prefix.with_suffix(".raw.json").write_text(json.dumps(_RAW))
        prefix.with_suffix(".enriched.json").write_text(json.dumps(_ENRICHED))
        return subprocess.CompletedProcess(argv, 0, "", "")

    binary = tmp_path / "aptrace"
    binary.write_text("")
    runner = FunctionEffectsRunner(
        binary=binary,
        firmware_image=image,
        expected_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
        mmio_window=(0x40000000, 0x4000000),
        cache_dir=tmp_path / "cache",
        entry_allowed=lambda entry: entry == 0xD3DC,
        resolve_register=lambda value: "PORT.GROUP0.IN (+0x20)" if value == 0x41008020 else None,
        run=fake_run,
    )

    with pytest.raises(EffectsInputError):
        runner.analyze("FUN_00001234")

    result = runner.analyze("FUN_0000d3dc", {"r0": 1})
    argv = argvs[0]
    assert argv[1:4] == ["function-effects", str(image), "0xd3dc"]
    assert argv[4:] == ["r0=0x1", f"out={tmp_path / 'cache' / argv[-1].rsplit('/', 1)[-1]}"]
    assert not any("mmio" in part for part in argv)

    summary = planner_summary(result)
    assert "FUN_0000d3dc effects [RAW complete" in summary
    assert "[SOLVER arg_r0 == 0x1] read @0xd3f8 -> 0x41008020 PORT.GROUP0.IN" in summary
    assert "[SOLVER] return in {0,1}: proven" in summary
    assert len(summary) < 700
    # Full raw and solver artifacts are retained in the evidence result.
    assert result.raw["accesses"][1]["address"]["expr"] == "bvSum (bvShl ...) 0x41008020"
    assert result.solver["query_log"] == [{"n": 1}]

    # Second call is served from the cache without rerunning the engine.
    runner.analyze("FUN_0000d3dc", {"r0": 1})
    assert len(argvs) == 1


_RAW = {
    "status": "complete",
    "macaw_blocks": 3,
    "counts": {"reads": 2, "writes": 0, "calls": 0},
    "inputs_referenced": ["arg_r0", "globalMemoryBytes"],
    "regions": [
        {"region": "FLASH", "base": "0x4000", "size": "0x11470"},
        {"region": "RAM", "base": "0x20000000", "size": "0x30000"},
        {"region": "MMIO", "base": "0x40000000", "size": "0x4000000"},
    ],
    "accesses": [
        {
            "kind": "read", "pc": "0xd3de", "width_bytes": 4, "served_from_concrete_readonly": True,
            "is_stack_block": False, "address": {"concrete": "0xd408", "expr": "0xd408", "free_vars": []},
            "guard": {"concrete": True},
        },
        {
            "kind": "read", "pc": "0xd3f8", "width_bytes": 4, "served_from_concrete_readonly": False,
            "is_stack_block": False,
            "address": {"concrete": None, "expr": "bvSum (bvShl ...) 0x41008020", "free_vars": ["arg_r0", "globalMemoryBytes"]},
            "guard": {"concrete": None},
        },
    ],
    "calls": [],
    "return_r0": {"concrete": None, "free_vars": ["arg_r0", "globalMemoryBytes"]},
    "assumptions": ["read-only segments concrete"],
}

_ENRICHED = {
    "solver_derived_facts": {
        "accesses": [
            {"index": 1, "region_membership_under_guard": [], "guard_status": {"status": "always-true"}, "specializations": []},
            {
                "index": 2,
                "region_membership_under_guard": [{"region": "MMIO", "membership": "proven"}],
                "guard_status": {"status": "conditional"},
                "specializations": [
                    {
                        "additional_assumption": "arg_r0 == 0x1",
                        "address_uniqueness": {"outcome": "unique", "value": "0x41008020"},
                        "guard_status": {"status": "always-true"},
                    }
                ],
            },
        ],
        "return_r0": {"bit_valued": "proven"},
    },
    "query_log": [{"n": 1}],
}


def test_effects_evidence_keeps_raw_and_solver_facts_distinct():
    session, executor = _session()
    session.record(
        EvidenceObservation(
            id="E1",
            tool="function_effects",
            arguments={"function": "FUN_0000d3dc", "specialize": {"r0": 1}},
            result={
                "status": "complete",
                "function": "FUN_0000d3dc",
                "inputs_used": ["r0"],
                "reads": 5,
                "writes": 0,
                "calls": [],
                "accesses": [{"region": "MMIO (solver)"}],
                "return_depends_on": ["r0", "memory"],
                "return_bit_valued": "proven",
                "specialized": [
                    {"assumption": "arg_r0 == 0x1", "pc": "0xd3f8", "kind": "read", "address": "0x41008020",
                     "register_name": "PORT.GROUP0.IN", "guard": "always-true"},
                ],
            },
        )
    )
    bases = {claim.basis for claim in session.state.claims}
    assert bases == {"raw-symbolic", "solver"}
    solver = [c.statement for c in session.state.claims if c.basis == "solver"]
    assert any("Under arg_r0 == 0x1" in s and "0x41008020 (PORT.GROUP0.IN)" in s for s in solver)
    assert "[RAW]" in PlannerProjection().render(session) and "[SOLVER]" in PlannerProjection().render(session)


# -- 7, 8: graph common paths over a synthetic census -------------------------------


def _census_db(tmp_path):
    db = tmp_path / "census.sqlite3"
    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA.read_text())
    conn.execute(
        "INSERT INTO firmware (id, key, path, sha256, flash_base, size_bytes, ram_base, ram_size, mmio_base, "
        "mmio_size, built_at) VALUES (1,'fw','x',?,0x4000,1000,0x20000000,0x1000,0x40000000,0x1000,'now')",
        (SHA,),
    )
    # A: left root (EIC ISR), B: right (USB), C: dispatcher reached by both,
    # D: helper below C, U: utility called by everything, E: isolated left
    # function with an unresolved indirect call.
    functions = {1: 0x1000, 2: 0x2000, 3: 0x3000, 4: 0x4000, 5: 0x5000, 6: 0x6000, 7: 0x7000}
    for fid, entry in functions.items():
        conn.execute(
            "INSERT INTO functions (id, firmware_id, entry, name, size, thunk, external, source) VALUES (?,1,?,?,0x40,0,0,'t')",
            (fid, entry, f"FUN_{entry:08x}"),
        )
        conn.execute(
            "INSERT INTO basic_blocks (firmware_id, start_addr, end_addr, function_id, source) VALUES (1,?,?,?,'t')",
            (entry, entry + 0x3F, fid),
        )
    edges = [(1, 3), (2, 3), (3, 4), (1, 5), (2, 5), (3, 5), (4, 5), (7, 5)]
    for i, (a, b) in enumerate(edges):
        conn.execute(
            "INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, to_function_id, source) "
            "VALUES (1,?,?,'call',1,?,?,'ghidra-basicblockmodel')",
            (functions[a] + 4 + i, functions[b], a, b),
        )
    # Six more callers of the utility to make its fan-in high.
    for i in range(8, 14):
        conn.execute(
            "INSERT INTO functions (id, firmware_id, entry, name, size, thunk, external, source) VALUES (?,1,?,?,4,0,0,'t')",
            (i, 0x8000 + i * 0x10, f"FUN_{0x8000 + i * 0x10:08x}"),
        )
        conn.execute(
            "INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, to_function_id, source) "
            "VALUES (1,?,0x5000,'call',1,?,5,'ghidra-basicblockmodel')",
            (0x8000 + i * 0x10, i),
        )
    conn.execute(
        "INSERT INTO indirect_edge_resolutions (firmware_id, from_addr, from_function_id, instr_mnemonic, instr_shape, "
        "classification, source) VALUES (1,0x6010,6,'blx','reg-indirect','UNRESOLVED','t')"
    )
    conn.execute(
        "INSERT INTO memory_accesses (firmware_id, from_addr, from_function_id, to_addr, width, direction, source) "
        "VALUES (1,0x1008,1,0x20000100,1,'WRITE','t'), (1,0x2008,2,0x20000100,1,'READ','t')"
    )
    conn.execute(
        "INSERT INTO vectors (firmware_id, vector_index, raw_value, target_addr, is_irq, source) VALUES (1,28,0x1001,0x1000,1,'t')"
    )
    conn.execute(
        "INSERT INTO reachability_roots (firmware_id, addr, function_id, root_kind, justification, source) "
        "VALUES (1,0x1000,1,'irq-vector','t','t')"
    )
    conn.commit()
    conn.close()
    return db


def test_common_paths_are_deterministic_and_rank_specific_convergence(tmp_path):
    db = _census_db(tmp_path)
    graph = CensusGraph(firmware_key="fw", db_path=db, expected_sha256=SHA, irq_label=lambda irq: f"EIC_EXTINT_{irq - 12}")

    first = graph.common_paths(["FUN_00001000"], ["FUN_00002000"], left_label="EIC", right_label="USB")
    utilities = graph.common_paths(["FUN_00004000"], ["FUN_00007000"])
    assert utilities.status == PathStatus.SHARED_UTILITIES_ONLY
    again = CensusGraph(firmware_key="fw", db_path=db, expected_sha256=SHA, irq_label=lambda irq: f"EIC_EXTINT_{irq - 12}").common_paths(
        ["FUN_00001000"], ["FUN_00002000"], left_label="EIC", right_label="USB"
    )

    assert first.model_dump() == again.model_dump()
    assert first.status == PathStatus.KNOWN_COMMON_PATH
    assert first.common[0].function == "FUN_00003000"
    assert first.common[0].path_left == ["FUN_00001000", "FUN_00003000"]
    assert first.common[-1].function == "FUN_00005000" and first.common[-1].shared_utility
    assert first.left[0].roots == ["EIC_EXTINT_0"]
    assert first.shared_state[0].address == "0x20000100"
    assert "converge at FUN_00003000" in first.planner_summary


def test_unresolved_indirect_calls_prevent_overclaiming_unreachable(tmp_path):
    graph = CensusGraph(firmware_key="fw", db_path=_census_db(tmp_path), expected_sha256=SHA)
    result = graph.common_paths(["FUN_00006000"], ["FUN_00004000"], left_label="L", right_label="R")

    assert result.status == PathStatus.NO_KNOWN_PATH
    assert result.frontier_total == 1
    assert result.frontier[0].site == "0x00006010"
    assert "paths through them are unknown" in result.planner_summary
    assert "not proof of unreachability" in result.planner_summary
    assert "UNREACHABLE" not in {status.value for status in PathStatus}

    # Unknown names are reported, not guessed.
    missing = graph.common_paths(["FUN_0000ffff"], ["FUN_00004000"])
    assert missing.status == PathStatus.NO_RESOLVABLE_INPUT
    assert missing.unknown_inputs == ["FUN_0000ffff"]


def test_planner_relates_analyzed_sets_without_crawling():
    session, executor = _session("Do EIC and USB paths converge?")
    planner = ScriptedPlanner(
        [
            ("analyze_peripheral", {"peripheral": "EIC"}),
            ("analyze_peripheral", {"peripheral": "USB"}),
            ("find_common_paths", {"left": ["EIC"], "right": ["usb"]}),
            ("finish", {"reason": "done"}),
        ]
    )
    result = _controller(planner, structural_tools=ALL_STRUCTURAL, max_steps=5).run(session)

    assert [s.action for s in result.steps] == ["analyze", "analyze", "common_paths", "finish"]
    tool, arguments = executor.calls[-1]
    assert tool == "census_common_paths"
    assert arguments == {
        "left": ["FUN_0000a000", "FUN_0000a040"],
        "right": ["FUN_0000c000", "FUN_0000c040"],
        "left_label": "EIC",
        "right_label": "USB",
    }
    assert any("NO_KNOWN_PATH" in c.statement for c in session.state.claims)
    assert any("unresolved indirect" in q.question for q in session.state.open_questions)


# -- 9: USB inventory --------------------------------------------------------------


def test_usb_descriptor_scan_finds_standard_layouts_only():
    device = bytes([0x12, 0x01, 0x00, 0x02, 0xEF, 0x02, 0x01, 0x40, 0x9A, 0x23, 0x20, 0x80, 0, 1, 1, 2, 3, 1])
    data = b"\xff" * 16 + device + b"\x12\x01\x00\x07" + b"\x00" * 40
    found = scan_usb_descriptors(data, 0x4000)
    assert found == [("device", 0x4010, "bcdUSB=0x0200 class=miscellaneous/IAD-composite VID=0x239a PID=0x8020")]


def test_usb_inventory_on_real_census_is_bounded():
    from aptrace_agent.census import performing_rigs_census
    from aptrace_agent.structural_wiring import performing_rigs_graph, performing_rigs_usb_inventory

    census = performing_rigs_census()

    if not census.db_path.is_file() or not census.firmware_image.is_file():
        pytest.skip("case census or firmware image not present")

    inventory = performing_rigs_usb_inventory(census, performing_rigs_graph(census)).inventory()

    assert inventory.status == "ok"
    assert len(inventory.planner_summary) < 1400
    assert len(inventory.strings) <= 6 and len(inventory.dispatch_candidates) <= 6
    assert "no function labeled a handler" in inventory.planner_summary
    assert {v.irq for v in inventory.irq_vectors} == {80, 81, 82, 83}


def test_usb_inventory_reflects_full_vector_coverage():
    from aptrace_agent.census import performing_rigs_census
    from aptrace_agent.structural_wiring import performing_rigs_graph, performing_rigs_usb_inventory

    census = performing_rigs_census()

    if not census.db_path.is_file() or not census.firmware_image.is_file():
        pytest.skip("case census or firmware image not present")

    conn = sqlite3.connect(f"{census.db_path.resolve().as_uri()}?mode=ro", uri=True)
    max_vector = conn.execute(
        "SELECT MAX(v.vector_index) FROM vectors v JOIN firmware f ON f.id=v.firmware_id WHERE f.key=?",
        (census.firmware_key,),
    ).fetchone()[0]
    conn.close()

    if (max_vector or 0) < 16 + 83:
        pytest.skip("census predates the target IRQ-count fix; rebuild it")

    graph = performing_rigs_graph(census)
    inventory = performing_rigs_usb_inventory(census, graph).inventory()
    entries = {80: "FUN_0000cc14", 81: "FUN_0000ccb6", 82: "FUN_0000ccba", 83: "FUN_0000ccbe"}

    assert "0 beyond census coverage" in inventory.census_vector_coverage
    for vector in inventory.irq_vectors:
        assert vector.in_census_vector_table
        assert vector.handler == entries[vector.irq]
        assert vector.census_function_at_entry == entries[vector.irq]
        assert vector.census_function_at_entry in inventory.functions
        member = graph.member(entries[vector.irq])
        assert member is not None and member.reachability == "DEFINITELY_REACHABLE"


# -- 10: repeated subsystem analysis is not reissued ------------------------------------


def test_repeated_structural_analysis_is_not_reissued():
    session, executor = _session("USB structure")
    planner = ScriptedPlanner(
        [
            ("analyze_usb_interface", {}),
            ("analyze_peripheral", {"peripheral": "EIC"}),
            ("find_common_paths", {"left": ["EIC"], "right": ["USB"]}),
            ("find_common_paths", {"left": ["USB"], "right": ["EIC"]}),
            ("finish", {"reason": "done"}),
        ]
    )
    controller = _controller(planner, structural_tools=ALL_STRUCTURAL, max_steps=5)
    result = controller.run(session)

    tools = [call[0] for call in executor.calls]
    assert tools.count("census_usb_inventory") == 1
    assert tools.count("census_common_paths") == 1
    # After the inventory ran it is no longer offered.
    assert "analyze_usb_interface" not in _tool_names(planner.requests[1])
    # The duplicate paths request was retried fresh without that tool.
    retry = planner.requests[4]
    assert "find_common_paths" not in _tool_names(retry)
    assert len(retry["messages"]) == 2
    assert result.steps[-1].action == "finish"
    analyses = controller.projection.render(session)
    assert "usb-inventory(E1)" in analyses and "paths EIC|USB(E3)" in analyses


# -- 11: caller/callee crawling remains a later fallback ----------------------------------


def test_decision_prompt_layout():
    session, executor = _session("Trigger convergence")
    planner = ScriptedPlanner([("analyze_peripheral", {"peripheral": "EIC"}), _first_lead])
    _controller(planner, structural_tools=ALL_STRUCTURAL, max_steps=2).run(session)
    prompt = planner.requests[1]["messages"][-1]["content"]

    assert prompt.index("OBJECTIVE:") < prompt.index("STATE (") < prompt.index("\nLEADS") < prompt.index("TASK:")
    assert "(already run: EIC)" in prompt


def test_first_of_several_parallel_calls_is_used():
    session, executor = _session()
    lead = session.registry.register(kind="function", description="x", tool="function_facts", arguments={"function": "FUN_00004444"})
    session.state.add_lead(lead)

    class Parallel(ScriptedPlanner):
        def create(self, **kwargs):
            response = super().create(**kwargs)
            calls = response.choices[0].message.tool_calls
            response.choices[0].message.tool_calls = calls + calls
            return response

    planner = Parallel([("follow_lead", {"lead_id": lead.id})])
    result = _controller(planner, max_steps=1).run(session)
    assert result.steps[0].action == "follow_lead"
    assert len(planner.requests) == 1


def test_structural_leads_rank_before_callsite_crawling():
    session, executor = _session()
    # A function-facts observation yields callsite (crawl) leads first...
    session.record(executor.execute_operation("function_facts", {"function": "FUN_00009000"}, evidence_id="E1"))
    # ...then a census analysis yields structural function leads.
    session.record(executor.execute_operation("census_peripheral_usage", {"peripheral": "TCC1", "limit": 25}, evidence_id="E2"))

    controller = _controller(ScriptedPlanner([]), max_visible_leads=3)
    visible = controller._planner_open_leads(session)
    tools = [session.registry.resolve(lead.id).tool for lead in visible]

    assert tools[0] == "function_facts"
    assert all(session.registry.resolve(lead.id).arguments.get("function", "").startswith("FUN_00003") for lead in visible[:2])
    assert "callsite_context" not in tools
    assert any(session.registry.resolve(lead.id).tool == "callsite_context" for lead in session.state.open_leads())


# -- 13: long runs survive; prefill rejection degrades to a compact projection -------


def test_long_run_request_size_plateaus():
    session, executor = _session(
        "Determine how externally generated trigger events enter and propagate through the firmware, "
        "and whether GPIO/EIC and USB paths converge."
    )
    script = [
        ("search_case_evidence", {"query": "optocoupler trigger"}),
        ("analyze_peripheral", {"peripheral": "PORT"}),
        ("analyze_peripheral", {"peripheral": "EIC"}),
        ("analyze_usb_interface", {}),
        ("find_common_paths", {"left": ["EIC"], "right": ["USB"]}),
        ("analyze_function_effects", {"function": "FUN_0000a000", "r0": 1}),
    ] + [_keep_going] * 24
    planner = ScriptedPlanner(script)
    controller = _controller(planner, structural_tools=ALL_STRUCTURAL, max_steps=30)
    result = controller.run(session)

    sizes = [r["total_bytes"] for r in result.planner_requests]
    assert len(result.steps) >= 25
    assert result.stop_reason in ("planner_finished", "step_budget_exhausted")
    assert max(r["state_chars"] for r in result.planner_requests) <= controller.projection.budget.total
    assert max(sizes[10:]) - min(sizes[10:]) < 1500
    assert max(sizes) < 8000
    assert len(session.ledger) == sum(step.action != "finish" for step in result.steps)


def test_prefill_rejection_retries_with_compact_projection():
    for as_body in (False, True):
        session, executor = _session("Trigger and USB convergence")
        _grow_history(session, executor, 40)
        lead = session.registry.register(kind="function", description="x", tool="function_facts", arguments={"function": "FUN_00004444"})
        session.state.add_lead(lead)
        planner = ScriptedPlanner([("finish", {"reason": "done"})], reject_as_body=as_body)
        controller = _controller(planner, structural_tools=ALL_STRUCTURAL)
        normal_size = len(json.dumps(controller._decision_prompt(session, controller._decision_palette(session))[0]))
        planner.reject_above_bytes = normal_size + 1500

        result = controller.run(session)

        assert result.stop_reason == "planner_finished", as_body
        assert [r.get("compact") for r in result.planner_requests] == [None, True]
        # Compact mode stays on for the following decisions.
        assert controller._compact_decisions == 3
        assert result.planner_requests[0]["error"] == "prefill_memory_exceeded"
        assert result.planner_requests[1]["state_chars"] < result.planner_requests[0]["state_chars"]


def test_persistent_prefill_rejection_stops_cleanly_with_evidence():
    session, executor = _session()
    _grow_history(session, executor, 10)
    lead = session.registry.register(kind="function", description="x", tool="function_facts", arguments={"function": "FUN_00004444"})
    session.state.add_lead(lead)
    planner = ScriptedPlanner([], reject_above_bytes=0)
    result = _controller(planner).run(session)

    assert result.stop_reason == "planner_prefill_exhausted"
    # One normal request, then two compact retries.
    assert [r.get("compact") for r in result.planner_requests] == [None, True, True]
    assert len(session.ledger) == 10


def test_computed_control_transfer_marks_effects_bounded(tmp_path):
    import hashlib

    image = tmp_path / "fw.bin"
    image.write_bytes(b"\x01" * 64)
    raw = dict(_RAW)
    raw["accesses"] = raw["accesses"][:1]
    raw["calls"] = [{"pc": "0x5814", "target_concrete": None, "args_concrete": [None] * 4}]

    def fake_run(argv):
        prefix = Path(next(a for a in argv if a.startswith("out="))[4:])
        prefix.with_suffix(".raw.json").write_text(json.dumps(raw))
        prefix.with_suffix(".enriched.json").write_text(json.dumps({"solver_derived_facts": {"accesses": []}}))
        return subprocess.CompletedProcess(argv, 0, "", "")

    binary = tmp_path / "aptrace"
    binary.write_text("")
    runner = FunctionEffectsRunner(
        binary=binary, firmware_image=image, expected_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
        mmio_window=(0x40000000, 0x4000000), cache_dir=tmp_path / "c", entry_allowed=lambda e: True,
        resolve_register=lambda v: None, run=fake_run,
    )
    result = runner.analyze("FUN_00005810")
    assert result.coverage.startswith("bounded: computed control transfer(s) at 0x5814")
    assert "[RAW bounded:" in planner_summary(result)

    session, _executor = _session()
    session.record(EvidenceObservation(id="E1", tool="function_effects", arguments={"function": "FUN_00005810"},
                                       result=result.model_dump(mode="json")))
    assert any("counts are lower bounds" in c.statement for c in session.state.claims)


def test_duplicate_request_withholds_tool_for_two_decisions():
    session, executor = _session()
    planner = ScriptedPlanner(
        [
            ("analyze_peripheral", {"peripheral": "TCC1"}),
            ("analyze_peripheral", {"peripheral": "TCC1"}),
            _first_lead,
            _first_lead,
            _first_lead,
            _first_lead,
        ]
    )
    _controller(planner, max_steps=5).run(session)
    offered = [("analyze_peripheral" in _tool_names(r)) for r in planner.requests]
    # Request 2 duplicates; its retry and the next two decisions omit the
    # tool, after which it is offered again.
    assert offered == [True, True, False, False, False, True]


def test_consecutive_duplicates_do_not_exhaust_the_contract():
    session, executor = _session()
    planner = ScriptedPlanner(
        [
            ("analyze_peripheral", {"peripheral": "EIC"}),
            ("analyze_function_effects", {"function": "FUN_0000a000"}),
            ("analyze_peripheral", {"peripheral": "EIC"}),
            ("analyze_function_effects", {"function": "FUN_0000a000"}),
            _first_lead,
        ]
    )
    result = _controller(planner, structural_tools=ALL_STRUCTURAL, max_steps=3).run(session)
    assert [s.action for s in result.steps] == ["analyze", "effects", "follow_lead"]


def test_effects_geometry_must_match_census_window(tmp_path):
    import hashlib

    image = tmp_path / "fw.bin"
    image.write_bytes(b"\x02" * 64)
    raw = dict(_RAW)
    raw["regions"] = [{"region": "MMIO", "base": "0x41000000", "size": "0x1000"}]

    def fake_run(argv):
        prefix = Path(next(a for a in argv if a.startswith("out="))[4:])
        prefix.with_suffix(".raw.json").write_text(json.dumps(raw))
        return subprocess.CompletedProcess(argv, 0, "", "")

    binary = tmp_path / "aptrace"
    binary.write_text("")
    runner = FunctionEffectsRunner(
        binary=binary, firmware_image=image, expected_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
        mmio_window=(0x40000000, 0x4000000), cache_dir=tmp_path / "c", entry_allowed=lambda e: True,
        resolve_register=lambda v: None, run=fake_run,
    )

    with pytest.raises(RuntimeError, match="disagrees with census geometry"):
        runner.analyze("FUN_0000d3dc")


def test_effects_timeout_is_bounded_and_cached(tmp_path):
    import hashlib

    image = tmp_path / "fw.bin"
    image.write_bytes(b"\x03" * 64)
    calls = []

    def slow(argv):
        calls.append(argv)
        raise subprocess.TimeoutExpired(argv, 300)

    binary = tmp_path / "aptrace"
    binary.write_text("")
    runner = FunctionEffectsRunner(
        binary=binary, firmware_image=image, expected_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
        mmio_window=(0x40000000, 0x4000000), cache_dir=tmp_path / "c", entry_allowed=lambda e: True,
        resolve_register=lambda v: None, run=slow,
    )
    first = runner.analyze("FUN_0000cbb0")
    second = runner.analyze("FUN_0000cbb0")

    assert first.status.startswith("bounded: timeout")
    assert "nothing concluded" in first.planner_summary
    assert second.planner_summary.endswith("(cached)")
    assert len(calls) == 1
