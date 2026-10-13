"""Shared fakes for research-ledger tests (no census, Ghidra, or model needed)."""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace

from aptrace_agent.ledger.models import ExecutionContext
from aptrace_agent.ledger.operations import LedgerOperationRunner
from aptrace_agent.ledger.store import ResearchLedger
from aptrace_agent.schemas import EvidenceObservation
from aptrace_agent.source_agreement import SourceObservation, source_agreement


FIRMWARE = "6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3"

USB_EDGE = {
    "edge_kind": "resolved_indirect",
    "site": "0x0000cc1a",
    "from_function": "FUN_0000cc14",
    "to_function": "FUN_0000c724",
    "slot": "0x200052e8",
    "raw_value": "0x0000c725",
    "canonical_target": "0x0000c724",
    "terminal_target": "0x0000c5cc",
    "store": "0x0000ccc6",
    "writer": "FUN_0000ccc4",
    "derivation": "callsite-argument",
    "callsite": "0x0000bcda",
    "arg_reg": "r0",
    "confidence": "STRONG",
}

USB_FUNCTIONS = ["FUN_0000954c", "FUN_0000bd94", "FUN_0000c5cc", "FUN_0000cdd8", "FUN_0000cc14", "FUN_0000ccb6"]
EIC_STUBS = ["FUN_0000cbb0", "FUN_0000cbb6", "FUN_0000cbbc"]


def usb_inventory() -> dict:
    return {
        "status": "ok",
        "functions": list(USB_FUNCTIONS),
        "irq_vectors": [{"irq": 80, "name": "USB_OTHER", "handler": "FUN_0000cc14"}],
        "resolved_indirect_edges": [dict(USB_EDGE)],
        "limitations": ["Register users are constant-address MMIO sites."],
        "provenance": {"firmware_sha256": FIRMWARE},
        "planner_summary": "USB inventory: resolved_indirect 0x0000cc1a FUN_0000cc14=>FUN_0000c724 RAM 0x200052e8=0x0000c725 stored at 0x0000ccc6 [STRONG]",
    }


def eic_usage() -> dict:
    return {
        "status": "ok",
        "peripheral": "EIC",
        "total_functions": 3,
        "functions": [{"function": "FUN_0000a000"}, {"function": "FUN_0000a03c"}, {"function": "FUN_0000cbb0"}],
        "limitations": ["Structural usage does not identify the attached device."],
    }


def common_paths(arguments: dict) -> dict:
    vectors = arguments.get("right_label", "").startswith("IRQ:") or arguments.get("left_label", "").startswith("IRQ:")
    status = "NO_KNOWN_PATH" if vectors else "KNOWN_COMMON_PATH"
    return {
        "status": status,
        "left_label": arguments.get("left_label"),
        "right_label": arguments.get("right_label"),
        "common_total": 0 if vectors else 3,
        "frontier_total": 7,
        "resolved_indirect_edges": [dict(USB_EDGE)],
        "limitations": ["NO_KNOWN_PATH means no path this census can construct within the hop bound."],
        "planner_summary": f"common paths {arguments.get('left_label')}|{arguments.get('right_label')}: {status}",
    }


# Fake code layout: function -> (start, end); Macaw lacks the pointer targets.
CODE = {
    "census": {0xCC14: 0xCC1E, 0xC724: 0xC72A, 0xC5CC: 0xC706, 0xCCC4: 0xCCCA, 0xBC44: 0xBD42},
    "ghidra": {0xCC14: 0xCC1E, 0xC724: 0xC72A, 0xC5CC: 0xC706, 0xCCC4: 0xCCCA, 0xBC44: 0xBD42},
    "macaw": {0xCC14: 0xCC1A, 0xCCC4: 0xCCCA, 0xBC44: 0xBD42},
}


# Independence envelope a source may declare. Real sources declare none
# today (the default here, too); tests opt in to model complete metadata.
INDEPENDENT_ENVELOPE = {
    "census": {"lineage": ["ghidra"], "firmware_sha256": FIRMWARE, "engine_version": "census-test"},
    "ghidra": {"lineage": ["ghidra"], "firmware_sha256": FIRMWARE, "engine_version": "ghidra-test"},
    "macaw": {"lineage": ["macaw"], "firmware_sha256": FIRMWARE, "engine_version": "macaw-test"},
}


class FakeCodeSource:
    def __init__(self, name: str, functions: dict[int, int] | None, version: str = "v1", envelope: dict | None = None, non_code: set[int] | None = None):
        self.name = name
        self.functions = functions
        self.version = version
        self.derived_from = "ghidra:v1" if name == "census" else None
        self.non_code = non_code or set()

        for field, value in (envelope or {}).items():
            setattr(self, field, value)

    def observe(self, address: int) -> SourceObservation:
        if self.functions is None:
            return SourceObservation(source=self.name, available=False)

        if address in self.non_code:
            return SourceObservation(source=self.name, available=True, version=self.version, recognizes_code=False, non_code=True)

        for start, end in self.functions.items():
            if start <= address < end:
                return SourceObservation(
                    source=self.name, available=True, version=self.version, recognizes_code=True,
                    function=f"FUN_{start:08x}", start=f"0x{start:08x}", end=f"0x{end:08x}",
                    blocks=[(f"0x{start:08x}", f"0x{end:08x}")],
                )

        return SourceObservation(source=self.name, available=True, version=self.version, recognizes_code=False)


class FakeExecutor:
    """Deterministic typed-operation executor with optional result drift."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.drift: dict[str, dict] = {}
        self.code = copy.deepcopy(CODE)
        # source -> independence envelope; source -> addresses it calls data.
        self.envelope: dict[str, dict] = {}
        self.non_code: dict[str, set[int]] = {}
        self.census = SimpleNamespace(available_peripherals=lambda: ["EIC", "TCC1", "SERCOM2", "USB"])

    def execute_operation(self, tool, arguments, *, evidence_id):
        self.calls.append((tool, copy.deepcopy(arguments)))

        if tool == "census_usb_inventory":
            result = usb_inventory()
        elif tool == "census_peripheral_usage":
            result = eic_usage() if arguments["peripheral"] == "EIC" else {"status": "ok", "peripheral": arguments["peripheral"], "functions": []}
        elif tool == "census_common_paths":
            result = common_paths(arguments)
        elif tool == "function_facts":
            if arguments["function"] == "FUN_0000dead":
                raise KeyError("Function not found: FUN_0000dead")
            result = {"name": arguments["function"], "entry": "0x0", "callers": [], "callees": []}
        elif tool == "function_disassembly":
            result = {"name": arguments["function"], "entry": "0x0", "instructions": [{"address": "0x0", "mnemonic": "bx", "operands": "lr"}]}
        elif tool == "structural_source_agreement":
            sources = [
                FakeCodeSource(name, functions, envelope=self.envelope.get(name), non_code=self.non_code.get(name))
                for name, functions in self.code.items()
            ]
            result = source_agreement(sources, arguments["addresses"])
        else:
            result = {"value": tool}

        result.update(self.drift.get(tool, {}))
        return EvidenceObservation(id=evidence_id, tool=tool, arguments=arguments, result=result)


class MutableContext:
    def __init__(self) -> None:
        self.artifacts = {"census_db": "a" * 64, "ghidra_export": "b" * 64, "svd": "c" * 64}

    def __call__(self) -> ExecutionContext:
        return ExecutionContext(case="performing-rigs", firmware_key="autopilot868", firmware_sha256=FIRMWARE, artifacts=dict(self.artifacts))


def stack(tmp_path):
    ledger = ResearchLedger(tmp_path / "ledger")
    executor = FakeExecutor()
    context = MutableContext()
    runner = LedgerOperationRunner(ledger, executor, context)
    return ledger, executor, context, runner


def irq_handlers(prefix: str) -> list[str]:
    return list(EIC_STUBS) if "EIC".startswith(prefix) or prefix.startswith("EIC") else []


class ScriptedAuditModel:
    """OpenAI-shaped client returning scripted auditor JSON decisions."""

    def __init__(self, decisions):
        self.decisions = list(decisions)
        self.requests: list[list[dict]] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(copy.deepcopy(kwargs["messages"]))
        decision = self.decisions.pop(0) if self.decisions else request("analyze_usb_interface")
        content = decision if isinstance(decision, str) else json.dumps(decision)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=None))],
            usage=SimpleNamespace(prompt_tokens=100, completion_tokens=20),
        )


def request(tool: str, **arguments) -> dict:
    return {"action": "request", "tool": tool, "arguments": arguments, "purpose": "falsify"}


def verdict(value: str, **extra) -> dict:
    payload = {
        "action": "verdict",
        "verdict": value,
        "scope_check": "evidence set matches the assertion",
        "reasoning": f"scripted {value}",
        "challenges": [],
        "evidence_inspected": [],
        "limitations": [],
        "follow_up_requests": [],
    }
    payload.update(extra)
    return payload
