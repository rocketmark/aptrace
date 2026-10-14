from __future__ import annotations

from dataclasses import dataclass

from aptrace_agent.research.state import (
    Claim,
    ClaimGrade,
    ResearchState,
)
from aptrace_agent.research.state_updates import (
    ResearchStateUpdater,
)
from aptrace_agent.schemas import EvidenceObservation


@dataclass(frozen=True)
class FactDerivationResult:
    claims: tuple[Claim, ...]


def _direct_r0_literal(
    observation: EvidenceObservation,
) -> int | None:
    if observation.tool != "callsite_context":
        return None

    result = observation.result
    instructions = result.get(
        "instructions",
        [],
    )
    callsite = result.get("address")

    call_index = None

    for index, instruction in enumerate(
        instructions
    ):
        if (
            instruction.get("address")
            == callsite
        ):
            call_index = index
            break

    if call_index is None:
        return None

    for instruction in reversed(
        instructions[:call_index]
    ):
        operands = str(
            instruction.get(
                "operands",
                "",
            )
        ).strip()

        parts = [
            part.strip()
            for part in operands.split(",")
        ]

        if not parts:
            continue

        if parts[0].lower() != "r0":
            continue

        mnemonic = str(
            instruction.get(
                "mnemonic",
                "",
            )
        ).lower()

        if mnemonic not in {
            "mov",
            "movs",
            "mov.w",
            "movs.w",
        }:
            return None

        if len(parts) < 2:
            return None

        immediate = parts[1]

        if not immediate.startswith("#"):
            return None

        try:
            return int(
                immediate[1:],
                0,
            )
        except ValueError:
            return None

    return None


def _call_target(
    observation: EvidenceObservation,
) -> str | None:
    if observation.tool != "callsite_context":
        return None

    result = observation.result
    callsite = result.get("address")

    for instruction in result.get(
        "instructions",
        [],
    ):
        if (
            instruction.get("address")
            != callsite
        ):
            continue

        mnemonic = str(
            instruction.get(
                "mnemonic",
                "",
            )
        ).lower()

        if not mnemonic.startswith("bl"):
            return None

        target = str(
            instruction.get(
                "operands",
                "",
            )
        ).strip()

        return target or None

    return None


MAX_CENSUS_FUNCTION_CLAIMS = 4
MAX_CENSUS_UNATTRIBUTED_CLAIMS = 2


def _census_location(
    value: str | None,
    register: str | None,
    peripheral: str,
    base: str | None,
) -> str:
    """Short, unambiguous name for a peripheral address."""

    if value is None:
        return peripheral

    try:
        offset = int(value, 16) - int(str(base), 16)
    except (TypeError, ValueError):
        offset = None

    if offset == 0:
        return f"{value} ({peripheral} base)"

    if register and "/" not in register:
        return f"{value} ({register})"

    if offset is not None:
        return f"{value} ({peripheral}+0x{offset:x})"

    return value


def _census_claims(
    observation: EvidenceObservation,
) -> list[str]:
    """
    Atomic structural statements supported by one census peripheral
    analysis. Nothing here names the external device on the bus.
    """

    result = observation.result
    status = result.get("status")
    peripheral = str(result.get("peripheral", ""))
    base = result.get("peripheral_base")
    provenance = result.get("provenance") or {}
    reduction = provenance.get("reduction_status")

    if status == "no_matching_accesses":
        return [
            f"The census contains no constant-address MMIO site and no "
            f"aligned flash address constant for {peripheral} "
            f"(bounded static analysis; runtime-computed addresses "
            f"are not excluded)."
        ]

    if status == "no_code_references":
        return [
            f"{peripheral} addresses appear only in "
            f"{result.get('total_address_constants', 0)} aligned flash "
            f"data word(s) that no census instruction references; the "
            f"census has no constant-address MMIO site for {peripheral} "
            f"(bounded static analysis; indexed table access is not "
            f"excluded)."
        ]

    if status != "ok":
        return []

    statements = [
        f"Census structural usage of {peripheral}: "
        f"{result.get('total_mmio_sites', 0)} constant-address MMIO "
        f"site(s), {result.get('total_address_constants', 0)} flash "
        f"address constant(s) "
        f"({result.get('unreferenced_address_constants', 0)} with no "
        f"code reference), {result.get('total_functions', 0)} "
        f"attributed function(s), "
        f"{len(result.get('unattributed_sites') or [])} unattributed "
        f"reference site(s) (reduction {reduction})."
    ]

    for item in (result.get("functions") or [])[
        :MAX_CENSUS_FUNCTION_CLAIMS
    ]:
        parts: list[str] = []
        sites = item.get("mmio_sites") or []

        if sites:
            accesses = sorted(
                {
                    f"{site.get('register_name') or site.get('address')} "
                    f"{site.get('direction')}"
                    for site in sites
                }
            )

            parts.append(
                f"has {item.get('mmio_site_count')} statically "
                f"resolved {peripheral} MMIO site(s) "
                f"({', '.join(accesses[:4])}"
                f"{', ...' if len(accesses) > 4 else ''})"
            )

        loads = item.get("constant_loads") or []

        if loads:
            first = loads[0]
            parts.append(
                f"loads {peripheral} address constant "
                + _census_location(
                    first.get("value"),
                    first.get("register_name"),
                    peripheral,
                    base,
                )
                + f" at {first.get('site')}"
                + (
                    f" (+{len(loads) - 1} more load site(s))"
                    if len(loads) > 1
                    else ""
                )
            )

        reach = item.get("reachability")

        if reach:
            parts.append(
                f"census reachability {reach.get('status')}"
            )

        if parts:
            statements.append(
                f"{item.get('function')} " + "; ".join(parts) + "."
            )

    for site in (result.get("unattributed_sites") or [])[
        :MAX_CENSUS_UNATTRIBUTED_CLAIMS
    ]:
        statements.append(
            f"Code at {site.get('site')} (basic block "
            f"{site.get('basic_block')}, attributed to no census "
            f"function) references {peripheral}: {site.get('detail')}."
        )

    return statements


def _names(items: list[dict], limit: int = 4) -> str:
    names = [str(item.get("function")) for item in items[:limit]]
    return ",".join(names) + ("..." if len(items) > limit else "")


def _common_path_facts(result: dict) -> tuple[list[tuple[str, str]], list[str]]:
    """Structural statements from one census common-path analysis."""

    status = result.get("status")
    left, right = result.get("left_label"), result.get("right_label")
    hops = result.get("max_hops")
    statements: list[tuple[str, str]] = []
    questions: list[str] = []

    if status not in ("KNOWN_COMMON_PATH", "NO_KNOWN_PATH", "SHARED_UTILITIES_ONLY"):
        return statements, questions

    for label, members in ((left, result.get("left", [])), (right, result.get("right", []))):
        roots = sorted({root for member in members for root in member.get("roots", [])})
        statements.append(
            (
                "census-graph",
                f"{label} set [{_names(members)}] is reached in the census call graph "
                f"from roots: {', '.join(roots) or 'no vector root (census)'}.",
            )
        )

    specific = [c for c in result.get("common", []) if not c.get("shared_utility")]

    if status == "KNOWN_COMMON_PATH":
        statements.append(
            (
                "census-graph",
                f"{left} and {right} sets share {result.get('common_total')} known downstream "
                f"function(s) within {hops} hops ({len(specific)} listed are not shared utilities).",
            )
        )

        for item in specific[:2]:
            statements.append(
                (
                    "census-graph",
                    f"{item['function']} is a known common descendant of {left} "
                    f"(via {' > '.join(item['path_left'])}) and {right} "
                    f"(via {' > '.join(item['path_right'])}).",
                )
            )
    elif status == "SHARED_UTILITIES_ONLY":
        utilities = ", ".join(c["function"] for c in result.get("common", [])[:3])
        statements.append(
            (
                "census-graph",
                f"{left} and {right} sets share only widely called utilities ({utilities}) within "
                f"{hops} hops; no specific convergence is known (not proof of unreachability).",
            )
        )
    else:
        statements.append(
            (
                "census-graph",
                f"NO_KNOWN_PATH: the census strong call graph has no common descendant of the "
                f"{left} and {right} sets within {hops} hops (explored "
                f"{result.get('explored_left')}/{result.get('explored_right')} functions); "
                "this is not proof of unreachability.",
            )
        )

    for item in result.get("shared_state", [])[:2]:
        statements.append(
            (
                "census-graph",
                f"RAM {item['address']} is accessed by {left}-side "
                f"{','.join(item['left_functions'])} ({item['left']}) and {right}-side "
                f"{','.join(item['right_functions'])} ({item['right']}) (constant-address accesses).",
            )
        )

    frontier = result.get("frontier", [])

    if frontier:
        sites = ", ".join(f"{f['site']} in {f['function']}" for f in frontier[:2])
        questions.append(
            f"Do unresolved indirect transfers in the {left}/{right} region "
            f"({result.get('frontier_total')} sites, e.g. {sites}) connect the two paths?"
        )

    return statements, questions


def _usb_inventory_facts(result: dict) -> tuple[list[tuple[str, str]], list[str]]:
    statements: list[tuple[str, str]] = []
    questions: list[str] = []

    if result.get("status") != "ok":
        return statements, questions

    users = result.get("register_users", [])
    statements.append(
        (
            "census",
            f"{len(users)} census function(s) access USB registers at constant addresses: "
            + "; ".join(
                f"{u['function']} (R:{','.join(u['reads']) or '-'} W:{','.join(u['writes']) or '-'}; "
                f"{u.get('reachability') or 'reachability unknown'})"
                for u in users[:4]
            )
            + ".",
        )
    )

    outside = [v for v in result.get("irq_vectors", []) if v.get("handler") and not v.get("in_census_vector_table")]

    vectors = []

    for vector in result.get("irq_vectors", []):
        if not vector.get("handler"):
            continue

        where = (
            "census function"
            if vector.get("census_function_at_entry")
            else f"inside {vector['inside_census_function']}"
            if vector.get("inside_census_function")
            else "not a census function"
        )
        vectors.append(f"{vector['name']}(IRQ{vector['irq']})->{vector['handler']} [{where}]")

    if vectors:
        statements.append(
            (
                "census",
                "Image vector table USB handlers: " + "; ".join(vectors)
                + ("; outside the census vector table, so not census roots" if outside else "")
                + ".",
            )
        )

    for descriptor in result.get("descriptors", [])[:2]:
        statements.append(
            (
                "census",
                f"Flash holds a standard USB {descriptor['kind']} descriptor at {descriptor['address']} "
                f"({descriptor['detail']}), referenced by {descriptor['code_references']} code site(s).",
            )
        )

    if outside:
        handlers = ", ".join(v["handler"] for v in outside[:4])
        questions.append(
            f"What do the USB IRQ handlers ({handlers}) call? They are outside census "
            "vector coverage, so census graph paths from them are unknown."
        )

    return statements, questions


def _observation_facts(result: dict) -> tuple[list[tuple[str, str]], list[str]]:
    """Scoped facts of one caller-grounded observation: what one scenario showed, nothing more."""

    status = str(result.get("status", ""))

    if not (status == "ok" or status.startswith("bounded")):
        return [], []

    function = result.get("function")
    scenario = result.get("scenario") or "boot"
    sites = result.get("call_sites", [])
    unreached = [f"{s.get('call_site')} ({s.get('caller')})" for s in sites if s.get("status") == "UNOBSERVED"]

    if not result.get("observed_entries"):
        return [(
            "concrete-observed",
            f"{function} was not entered under scenario {scenario} "
            f"({(result.get('run') or {}).get('instructions_executed')} instructions); not thereby unreachable.",
        )], []

    values = sorted({(v["value"], v.get("register_name") or v.get("region") or "?") for s in sites
                     for v in (s.get("arguments") or {}).get("r0", [])})
    words = sorted({(v["pointee_word"], v.get("pointee_register_name") or v.get("pointee_word_region") or "?")
                    for s in sites for v in (s.get("arguments") or {}).get("r0", []) if v.get("pointee_word")})
    mmio = result.get("mmio_in_function")
    statement = (
        f"{function} under scenario {scenario}: {result.get('observed_entries')} observed calls passed r0 "
        + ", ".join(f"{v}({r})" for v, r in values[:3])
        + (f"; the word at r0 held {', '.join(f'{w}({r})' for w, r in words[:3])} (content, not an access)" if words else "")
        + (f"; {mmio.get('access_count')} MMIO accesses from its code" if mmio else "")
        + "; other scenarios and values are not excluded."
    )
    questions = [
        f"Unobserved call site {site} of {function}: argument values unknown, not excluded." for site in unreached[:2]
    ]
    return [("concrete-observed", statement)], questions


def _effects_facts(result: dict) -> tuple[list[tuple[str, str]], list[str]]:
    statements: list[tuple[str, str]] = []

    if not str(result.get("status", "")).startswith(("complete", "partial", "bounded: step limit")):
        return statements, []

    function = result.get("function")
    mmio = {
        (a.get("kind"), a.get("pc"))
        for a in result.get("accesses", [])
        if (a.get("region") or "").startswith("MMIO")
    }
    coverage = result.get("coverage", "complete")
    scope = (
        "(Crucible, all inputs symbolic)"
        if coverage == "complete"
        else f"(Crucible, all inputs symbolic; {coverage}; counts are lower bounds)"
    )
    statements.append(
        (
            "raw-symbolic",
            f"{function} {scope}: inputs used "
            f"{','.join(result.get('inputs_used', [])) or 'none'}; {result.get('reads')} reads, "
            f"{result.get('writes')} writes, {len(result.get('calls', []))} calls; "
            f"{len(mmio)} MMIO access site(s); return depends on "
            f"{'+'.join(result.get('return_depends_on', [])) or 'no symbolic input'}.",
        )
    )

    for call in list({(c.get("pc"), c.get("target")): c for c in result.get("calls", [])}.values())[:3]:
        statements.append(
            (
                "raw-symbolic",
                f"{function} calls {call.get('target') or 'a computed target'} at {call.get('pc')}.",
            )
        )

    if result.get("return_bit_valued") == "proven":
        statements.append(("solver", f"{function} return value is always 0 or 1."))

    for item in result.get("specialized", []):
        if item.get("register_name") in (None, "FLASH", "RAM"):
            continue

        statements.append(
            (
                "solver",
                f"Under {item['assumption']}, {function} {item['kind']} at {item['pc']} "
                f"accesses exactly {item['address']} ({item['register_name']}).",
            )
        )

    return statements, []


class StateFactDeriver:
    """
    Convert structurally explicit evidence into atomic PROVEN claims.

    No semantic role interpretation occurs here. Those judgments belong
    to the research reviewer.
    """

    def __init__(
        self,
        *,
        updater: ResearchStateUpdater | None = None,
    ) -> None:
        self.updater = (
            updater
            or ResearchStateUpdater()
        )

    def derive(
        self,
        observation: EvidenceObservation,
        state: ResearchState,
    ) -> FactDerivationResult:
        claims: list[Claim] = []

        if observation.tool == "pin_table_entry":
            result = observation.result

            index = result.get("index")
            gpio = result.get("gpio")
            group = result.get("group")
            bit = result.get("bit")

            if (
                index is not None
                and gpio
                and group is not None
                and bit is not None
            ):
                claim = (
                    self.updater.merge_claim(
                        state,
                        statement=(
                            "Logical pin-table index "
                            f"{index} maps to GPIO "
                            f"{gpio} "
                            f"(group {group}, bit {bit})."
                        ),
                        grade=ClaimGrade.PROVEN,
                        basis="static-table",
                        evidence_ids=[
                            observation.id,
                        ],
                    )
                )

                claims.append(claim)

        if observation.tool == "callsite_context":
            literal = _direct_r0_literal(
                observation
            )

            target = _call_target(
                observation
            )

            result = observation.result
            function = result.get(
                "function"
            )
            address = result.get(
                "address"
            )

            if (
                literal is not None
                and function
                and address
                and target
            ):
                claim = (
                    self.updater.merge_claim(
                        state,
                        statement=(
                            f"{function} calls "
                            f"{target} at "
                            f"{address} with "
                            f"r0 literal {literal} "
                            f"(0x{literal:x})."
                        ),
                        grade=ClaimGrade.PROVEN,
                        basis="disassembly",
                        evidence_ids=[
                            observation.id,
                        ],
                    )
                )

                claims.append(claim)

        if observation.tool == "census_peripheral_usage":
            for statement in _census_claims(
                observation
            ):
                claims.append(
                    self.updater.merge_claim(
                        state,
                        statement=statement,
                        grade=ClaimGrade.PROVEN,
                        evidence_ids=[
                            observation.id,
                        ],
                        basis="census",
                    )
                )

        derived = {
            "census_common_paths": _common_path_facts,
            "census_usb_inventory": _usb_inventory_facts,
            "function_effects": _effects_facts,
            "observed_call_arguments": _observation_facts,
        }.get(observation.tool)

        if derived is not None:
            statements, questions = derived(observation.result)

            for basis, statement in statements:
                claims.append(
                    self.updater.merge_claim(
                        state,
                        statement=statement,
                        grade=ClaimGrade.PROVEN,
                        evidence_ids=[observation.id],
                        basis=basis,
                    )
                )

            for question in questions:
                self.updater.merge_open_question(
                    state,
                    question=question,
                    evidence_ids=[observation.id],
                    source="aptrace",
                )

        return FactDerivationResult(
            claims=tuple(claims)
        )
