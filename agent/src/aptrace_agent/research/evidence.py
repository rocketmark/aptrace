from __future__ import annotations

from aptrace_agent.research.state import ResearchState
from aptrace_agent.schemas import EvidenceObservation


class EvidenceLedger:
    """
    Authoritative APTrace evidence store.

    Evidence IDs are allocated here, never by the research model.
    ResearchState contains references to ledger entries rather than
    inventing or renumbering evidence.
    """

    def __init__(self) -> None:
        self._observations: dict[str, EvidenceObservation] = {}
        self._next_id = 1

    def next_id(self) -> str:
        return f"E{self._next_id}"

    def add(
        self,
        observation: EvidenceObservation,
        *,
        state: ResearchState | None = None,
    ) -> EvidenceObservation:
        expected = self.next_id()

        if observation.id != expected:
            raise ValueError(
                f"expected evidence id {expected}, "
                f"got {observation.id}"
            )

        if observation.id in self._observations:
            raise ValueError(
                f"duplicate evidence id: {observation.id}"
            )

        self._observations[observation.id] = observation
        self._next_id += 1

        if state is not None:
            state.add_evidence(observation.id)

        return observation

    def get(self, evidence_id: str) -> EvidenceObservation:
        try:
            return self._observations[evidence_id]
        except KeyError as exc:
            raise KeyError(
                f"unknown evidence: {evidence_id}"
            ) from exc

    def all(self) -> list[EvidenceObservation]:
        return list(self._observations.values())

    def __len__(self) -> int:
        return len(self._observations)
