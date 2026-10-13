"""
Append-only, content-addressed research ledger.

Layout under the ledger root:

    runs/<run_id>.json                 InvestigationRun (investigations, audits, setups)
    invocations/<invocation_id>.json   ToolInvocation
    evidence/<evidence_id>.json        EvidenceArtifact metadata
    blobs/<sha[:2]>/<sha>.json         structured results, content-addressed
    claims/<claim_id>/v<N>.json        ClaimVersion (immutable)
    audits/<audit_id>.json             AuditRecord (immutable history)
    verifications/<id>.json            VerificationRecord (immutable history)
    events.jsonl                       append-only lifecycle events

Every JSON record is written once; rewriting different content raises.
Current claim and evidence status is folded from events.jsonl, never
stored on the record, so historical records stay immutable.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from aptrace_agent.ledger.hashing import canonical_json, digest
from aptrace_agent.ledger.models import (
    APTRACE_ACTORS,
    AuditRecord,
    ClaimState,
    ClaimType,
    ClaimVersion,
    EvidenceArtifact,
    EvidenceGrade,
    ExecutionContext,
    InvestigationRun,
    LifecycleEvent,
    Limitation,
    ToolInvocation,
    VerificationRecord,
    parse_version_key,
    version_key,
)
from aptrace_agent.ledger.semantics import (
    canonical_result,
    evidence_grade,
    evidence_limitations,
    inherited_limitations,
)


T = TypeVar("T", bound=BaseModel)

# Results above this size go to blobs-large/, which a case may keep out of
# version control (regenerable by replay; still content-addressed).
LARGE_BLOB_BYTES = 4 * 1024 * 1024

EVIDENCE_VALID = "VALID"
EVIDENCE_INVALIDATED = "INVALIDATED"

# States from which a dependency change makes a claim stale.
_STALEABLE = {ClaimState.PROPOSED, ClaimState.VERIFIED}
# Dependency states that make dependents stale.
_STALE_TRIGGERS = {ClaimState.SUPERSEDED, ClaimState.STALE, ClaimState.BLOCKED}


class LedgerError(RuntimeError):
    pass


class LedgerImmutableError(LedgerError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_id(prefix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"{prefix}-{stamp}-{secrets.token_hex(3)}"


class ResearchLedger:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    # -- low-level storage ----------------------------------------------------

    def _path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def _write_once(self, path: Path, record: BaseModel | dict[str, Any]) -> None:
        payload = record.model_dump(mode="json", by_alias=True) if isinstance(record, BaseModel) else record
        text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

        if path.exists():
            if json.loads(path.read_text()) == json.loads(text):
                return

            raise LedgerImmutableError(f"refusing to rewrite immutable ledger record {path}")

        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("x", encoding="utf-8") as f:
            f.write(text)

    def _read(self, path: Path, model: type[T]) -> T:
        if not path.is_file():
            raise KeyError(str(path.relative_to(self.root)))

        return model.model_validate_json(path.read_text())

    def _list(self, directory: str, model: type[T]) -> list[T]:
        base = self._path(directory)

        if not base.is_dir():
            return []

        return [model.model_validate_json(p.read_text()) for p in sorted(base.glob("*.json"))]

    # -- blobs ----------------------------------------------------------------

    def put_blob(self, value: Any) -> tuple[str, int]:
        text = canonical_json(value)
        sha = digest(value)
        tier = "blobs-large" if len(text) > LARGE_BLOB_BYTES else "blobs"
        path = self._path(tier, sha[:2], f"{sha}.json")

        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)

            with path.open("x", encoding="utf-8") as f:
                f.write(text)

        return sha, len(text.encode("utf-8"))

    def blob_path(self, sha: str) -> Path:
        for tier in ("blobs", "blobs-large"):
            path = self._path(tier, sha[:2], f"{sha}.json")

            if path.is_file():
                return path

        return self._path("blobs", sha[:2], f"{sha}.json")

    def has_blob(self, sha: str) -> bool:
        return self.blob_path(sha).is_file()

    def blob_size(self, sha: str) -> int:
        return self.blob_path(sha).stat().st_size if self.has_blob(sha) else 0

    def load_blob(self, sha: str) -> tuple[Any, bool]:
        """(value, integrity ok). Integrity fails if the content hash changed."""

        path = self.blob_path(sha)

        if not path.is_file():
            raise KeyError(f"missing blob {sha}")

        value = json.loads(path.read_text())
        return value, digest(value) == sha

    # -- runs, invocations, evidence ------------------------------------------

    def record_run(self, run: InvestigationRun) -> InvestigationRun:
        self._write_once(self._path("runs", f"{run.run_id}.json"), run)
        return run

    def run(self, run_id: str) -> InvestigationRun:
        return self._read(self._path("runs", f"{run_id}.json"), InvestigationRun)

    def runs(self) -> list[InvestigationRun]:
        return self._list("runs", InvestigationRun)

    @staticmethod
    def operation_key(tool: str, arguments: dict[str, Any], input_artifacts: dict[str, str], firmware_sha256: str) -> str:
        return digest(
            {
                "tool": tool,
                "arguments": arguments,
                "inputs": input_artifacts,
                "firmware_sha256": firmware_sha256,
            }
        )

    def record_invocation(
        self,
        *,
        run_id: str,
        seq: int,
        tool: str,
        arguments: dict[str, Any],
        context: ExecutionContext,
        input_artifacts: dict[str, str],
        started_at: str,
        ended_at: str,
        runtime_ms: float,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        input_evidence_ids: Iterable[str] = (),
        replayable: bool = True,
        replay_of: str | None = None,
        session_evidence_id: str | None = None,
    ) -> tuple[ToolInvocation, EvidenceArtifact | None]:
        operation_key = self.operation_key(tool, arguments, input_artifacts, context.firmware_sha256)
        invocation_id = "TI-" + digest({"run": run_id, "seq": seq, "op": operation_key})[:16]
        artifact: EvidenceArtifact | None = None
        result_sha: str | None = None

        if error is None and result is not None:
            result = canonical_result(tool, result)
            result_sha, size = self.put_blob(result)
            evidence_id = "EV-" + digest({"op": operation_key, "result": result_sha})[:16]
            existing = self._path("evidence", f"{evidence_id}.json")

            if existing.is_file():
                artifact = self._read(existing, EvidenceArtifact)
            else:
                grade, basis = evidence_grade(tool, result)
                artifact = EvidenceArtifact(
                    evidence_id=evidence_id,
                    invocation_id=invocation_id,
                    tool=tool,
                    arguments=arguments,
                    result_sha256=result_sha,
                    result_bytes=size,
                    context_id=context.context_id(),
                    case=context.case,
                    firmware_key=context.firmware_key,
                    firmware_sha256=context.firmware_sha256,
                    grade=grade,
                    grade_basis=basis,
                    limitations=[
                        Limitation(text=text, code=code)
                        for code, text in evidence_limitations(tool, arguments, result)
                    ],
                    path_status=result.get("status") if tool == "census_common_paths" else None,
                    summary=str(result.get("planner_summary") or "")[:600],
                )
                self._write_once(existing, artifact)

        invocation = ToolInvocation(
            invocation_id=invocation_id,
            run_id=run_id,
            tool=tool,
            arguments=arguments,
            operation_key=operation_key,
            context_id=context.context_id(),
            input_artifacts=input_artifacts,
            input_evidence_ids=list(input_evidence_ids),
            status="ok" if error is None else "error",
            evidence_id=None if artifact is None else artifact.evidence_id,
            result_sha256=result_sha,
            started_at=started_at,
            ended_at=ended_at,
            runtime_ms=runtime_ms,
            error=error,
            replayable=replayable,
            replay_of=replay_of,
            session_evidence_id=session_evidence_id,
        )
        self._write_once(self._path("invocations", f"{invocation_id}.json"), invocation)
        return invocation, artifact

    def invocation(self, invocation_id: str) -> ToolInvocation:
        return self._read(self._path("invocations", f"{invocation_id}.json"), ToolInvocation)

    def invocations(self) -> list[ToolInvocation]:
        return self._list("invocations", ToolInvocation)

    def has_evidence(self, evidence_id: str) -> bool:
        return self._path("evidence", f"{evidence_id}.json").is_file()

    def evidence(self, evidence_id: str) -> EvidenceArtifact:
        return self._read(self._path("evidence", f"{evidence_id}.json"), EvidenceArtifact)

    def all_evidence(self) -> list[EvidenceArtifact]:
        return self._list("evidence", EvidenceArtifact)

    def evidence_result(self, evidence_id: str) -> tuple[dict[str, Any], bool]:
        artifact = self.evidence(evidence_id)
        return self.load_blob(artifact.result_sha256)

    # -- claims ---------------------------------------------------------------

    def _claim_path(self, claim_id: str, version: int) -> Path:
        return self._path("claims", claim_id, f"v{version}.json")

    def _next_claim_id(self) -> str:
        base = self._path("claims")
        numbers = [int(p.name[1:]) for p in base.glob("C*") if p.name[1:].isdigit()] if base.is_dir() else []
        return f"C{max(numbers, default=0) + 1}"

    def claim(self, key: str) -> ClaimVersion:
        claim_id, version = parse_version_key(key)

        if version is None:
            return self.latest_version(claim_id)

        return self._read(self._claim_path(claim_id, version), ClaimVersion)

    def has_claim(self, key: str) -> bool:
        try:
            self.claim(key)
        except KeyError:
            return False

        return True

    def claim_versions(self, claim_id: str) -> list[ClaimVersion]:
        base = self._path("claims", claim_id)

        if not base.is_dir():
            raise KeyError(f"unknown claim {claim_id}")

        versions = [ClaimVersion.model_validate_json(p.read_text()) for p in base.glob("v*.json")]
        return sorted(versions, key=lambda c: c.version)

    def latest_version(self, claim_id: str) -> ClaimVersion:
        return self.claim_versions(claim_id)[-1]

    def all_claim_versions(self) -> list[ClaimVersion]:
        base = self._path("claims")

        if not base.is_dir():
            return []

        out: list[ClaimVersion] = []

        for directory in sorted(base.iterdir(), key=lambda p: int(p.name[1:]) if p.name[1:].isdigit() else 0):
            if directory.is_dir():
                out.extend(self.claim_versions(directory.name))

        return out

    def _inherit(self, evidence_ids: Iterable[str], limitations: Iterable[Limitation | str]) -> list[Limitation]:
        stated = [item if isinstance(item, Limitation) else Limitation(text=str(item)) for item in limitations]
        known = [self.evidence(e) for e in evidence_ids if self.has_evidence(e)]
        inherited = inherited_limitations(known)
        codes = {item.code for item in stated if item.code}
        return stated + [item for item in inherited if item.code not in codes]

    def propose_claim(
        self,
        *,
        subject: str,
        assertion: str,
        claim_type: ClaimType | str,
        proposed_grade: EvidenceGrade | str,
        proposed_by: str,
        supporting_evidence_ids: Iterable[str] = (),
        contradictory_evidence_ids: Iterable[str] = (),
        depends_on: Iterable[str] = (),
        scope: str = "",
        assumptions: Iterable[str] = (),
        limitations: Iterable[Limitation | str] = (),
        derivation: str = "",
        run_id: str | None = None,
        semantics: Any = None,
    ) -> ClaimVersion:
        """
        Record a new claim at version 1 in state PROPOSED.

        Limitations the supporting evidence carries are inherited
        mechanically, so they cannot be dropped by the proposer.
        """

        supporting = list(dict.fromkeys(supporting_evidence_ids))
        claim = ClaimVersion(
            claim_id=self._next_claim_id(),
            version=1,
            subject=subject,
            assertion=assertion,
            claim_type=ClaimType(claim_type),
            proposed_grade=EvidenceGrade(proposed_grade),
            scope=scope,
            assumptions=list(assumptions),
            limitations=self._inherit(supporting, limitations),
            supporting_evidence_ids=supporting,
            contradictory_evidence_ids=list(dict.fromkeys(contradictory_evidence_ids)),
            depends_on=list(dict.fromkeys(depends_on)),
            derivation=derivation,
            proposed_by=proposed_by,
            run_id=run_id,
            created_at=now(),
            semantics=semantics,
        )
        self._write_once(self._claim_path(claim.claim_id, 1), claim)
        self.transition(claim.key, ClaimState.PROPOSED, actor="aptrace-ledger", reason=f"proposed by {proposed_by}")
        return claim

    def supersede_claim(self, key: str, *, proposed_by: str, reason: str, **changes: Any) -> ClaimVersion:
        """
        Create the next version of a claim. The prior version is never
        modified; it becomes SUPERSEDED and its dependents become STALE.
        """

        old = self.claim(key)
        latest = self.latest_version(old.claim_id)

        if latest.version != old.version:
            raise LedgerError(f"{old.key} is not the latest version ({latest.key})")

        fields = old.model_dump()
        fields.update(changes)
        supporting = list(dict.fromkeys(fields["supporting_evidence_ids"]))
        stated = [Limitation.model_validate(item) if isinstance(item, dict) else item for item in fields["limitations"]]

        if "limitations" not in changes:
            # Inherited limitations are recomputed from the new evidence set.
            stated = [item for item in stated if not (isinstance(item, Limitation) and item.code)]

        fields.update(
            version=old.version + 1,
            supporting_evidence_ids=supporting,
            limitations=self._inherit(supporting, stated),
            proposed_by=proposed_by,
            supersedes=old.key,
            created_at=now(),
        )
        new = ClaimVersion.model_validate(fields)
        self._write_once(self._claim_path(new.claim_id, new.version), new)
        self.transition(new.key, ClaimState.PROPOSED, actor="aptrace-ledger", reason=f"supersedes {old.key}: {reason}", refs=[old.key])
        self.transition(old.key, ClaimState.SUPERSEDED, actor="aptrace-ledger", reason=f"superseded by {new.key}: {reason}", refs=[new.key])
        self.propagate_staleness([old.key])
        return new

    # -- lifecycle events -----------------------------------------------------

    def events(self) -> list[LifecycleEvent]:
        path = self._path("events.jsonl")

        if not path.is_file():
            return []

        return [LifecycleEvent.model_validate_json(line) for line in path.read_text().splitlines() if line.strip()]

    def _append_event(self, event: LifecycleEvent) -> LifecycleEvent:
        path = self._path("events.jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("a", encoding="utf-8") as f:
            f.write(event.model_dump_json() + "\n")

        return event

    def transition(
        self,
        key: str,
        state: ClaimState,
        *,
        actor: str,
        reason: str,
        refs: Iterable[str] = (),
    ) -> LifecycleEvent:
        """
        Append a claim lifecycle event. Only APTrace actors may do this;
        model verdicts are recorded as audits and never transition a claim.
        """

        if actor not in APTRACE_ACTORS:
            raise PermissionError(f"actor {actor!r} may not change claim lifecycle state")

        if state == ClaimState.VERIFIED and actor != "aptrace-verifier":
            raise PermissionError("only the APTrace verifier may mark a claim VERIFIED")

        if not self.has_claim(key) or parse_version_key(key)[1] is None:
            raise KeyError(f"unknown claim version {key}")

        return self._append_event(
            LifecycleEvent(
                seq=len(self.events()) + 1,
                at=now(),
                subject_kind="claim",
                subject=key,
                state=ClaimState(state).value,
                actor=actor,
                reason=reason,
                refs=list(refs),
            )
        )

    def state(self, key: str) -> ClaimState:
        claim = self.claim(key)
        current: ClaimState | None = None

        for event in self.events():
            if event.subject_kind == "claim" and event.subject == claim.key:
                current = ClaimState(event.state)

        if current is None:
            raise LedgerError(f"claim {claim.key} has no lifecycle events")

        return current

    def history(self, key: str) -> list[LifecycleEvent]:
        claim = self.claim(key)
        return [e for e in self.events() if e.subject_kind == "claim" and e.subject == claim.key]

    def evidence_state(self, evidence_id: str) -> str:
        current = EVIDENCE_VALID

        for event in self.events():
            if event.subject_kind == "evidence" and event.subject == evidence_id:
                current = event.state

        return current

    def invalidate_evidence(self, evidence_id: str, *, reason: str, refs: Iterable[str] = ()) -> list[str]:
        """Mark evidence invalid; claims relying on it (and dependents) become STALE."""

        if self.evidence_state(evidence_id) != EVIDENCE_INVALIDATED:
            self._append_event(
                LifecycleEvent(
                    seq=len(self.events()) + 1,
                    at=now(),
                    subject_kind="evidence",
                    subject=evidence_id,
                    state=EVIDENCE_INVALIDATED,
                    actor="aptrace-staleness",
                    reason=reason,
                    refs=list(refs),
                )
            )

        staled: list[str] = []

        for claim in self.all_claim_versions():
            if evidence_id in claim.supporting_evidence_ids and self.state(claim.key) in _STALEABLE:
                self.transition(claim.key, ClaimState.STALE, actor="aptrace-staleness", reason=f"evidence {evidence_id} invalidated: {reason}", refs=[evidence_id])
                staled.append(claim.key)

        return staled + self.propagate_staleness(staled)

    def dependents(self, key: str) -> list[ClaimVersion]:
        return [c for c in self.all_claim_versions() if key in c.depends_on]

    def propagate_staleness(self, keys: Iterable[str]) -> list[str]:
        """
        Deterministically mark every transitive dependent of the given claim
        versions STALE when the dependency is superseded, stale or blocked.
        Returns the keys newly marked. No repair is attempted.
        """

        staled: list[str] = []
        queue = list(keys)
        seen: set[str] = set()

        while queue:
            key = queue.pop(0)

            if key in seen:
                continue

            seen.add(key)

            if self.state(key) not in _STALE_TRIGGERS:
                continue

            for dependent in self.dependents(key):
                if self.state(dependent.key) in _STALEABLE:
                    self.transition(
                        dependent.key,
                        ClaimState.STALE,
                        actor="aptrace-staleness",
                        reason=f"dependency {key} is {self.state(key).value}",
                        refs=[key],
                    )
                    staled.append(dependent.key)

                queue.append(dependent.key)

        return staled

    # -- audits and verifications ---------------------------------------------

    def record_audit(self, audit: AuditRecord) -> AuditRecord:
        self._write_once(self._path("audits", f"{audit.audit_id}.json"), audit)
        return audit

    def audit(self, audit_id: str) -> AuditRecord:
        return self._read(self._path("audits", f"{audit_id}.json"), AuditRecord)

    def audits_for(self, key: str, *, include_diagnostic: bool = True) -> list[AuditRecord]:
        claim = self.claim(key)
        audits = [
            a
            for a in self._list("audits", AuditRecord)
            if a.claim_version == claim.key and (include_diagnostic or not a.diagnostic)
        ]
        return sorted(audits, key=lambda a: a.ended_at)

    def latest_audit(self, key: str, *, include_diagnostic: bool = True) -> AuditRecord | None:
        audits = self.audits_for(key, include_diagnostic=include_diagnostic)
        return audits[-1] if audits else None

    def record_verification(self, record: VerificationRecord) -> VerificationRecord:
        self._write_once(self._path("verifications", f"{record.verification_id}.json"), record)
        return record

    def verifications_for(self, key: str) -> list[VerificationRecord]:
        claim = self.claim(key)
        records = [v for v in self._list("verifications", VerificationRecord) if v.claim_version == claim.key]
        return sorted(records, key=lambda v: v.at)

    # -- helpers --------------------------------------------------------------

    def fingerprint(self) -> str:
        """Identity of the ledger's claim/event state, for report staleness."""

        path = self._path("events.jsonl")
        events = path.read_text() if path.is_file() else ""
        claims = sorted(c.key for c in self.all_claim_versions())
        audits = sorted(p.name for p in self._path("audits").glob("*.json")) if self._path("audits").is_dir() else []
        return digest({"events": events, "claims": claims, "audits": audits})[:16]

    def iter_current(self) -> Iterator[tuple[ClaimVersion, ClaimState]]:
        for claim in self.all_claim_versions():
            yield claim, self.state(claim.key)


def ensure_key(ledger: ResearchLedger, key: str) -> str:
    """Normalize C7 or C7:v2 to an explicit version key."""

    claim = ledger.claim(key)
    return version_key(claim.claim_id, claim.version)
