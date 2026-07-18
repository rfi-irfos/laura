"""Shared types and severity helpers for the L.A.U.R.A. scanner.

A :class:`Sighting` is one passive observation from a detection module.
It is a *record of what was seen*, never an action taken. Severity is a
coarse triage hint for the human reviewer; nothing here auto-escalates.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

VALID_SENSES = ("lumen", "umbra", "relay", "aegis")
VALID_SEVERITIES = ("low", "medium", "high")


@dataclass
class Sighting:
    """One passive detection observation."""

    sense: str  # lumen | umbra | relay | aegis
    kind: str  # evil_twin | open_ap | arp_spoof | captive_portal | ...
    summary: str  # one-line human text
    severity: str = "low"  # low | medium | high
    evidence: dict[str, Any] = field(default_factory=dict)
    host: str = ""  # operator-side tag for the scanning machine
    sighting_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    observed_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if self.sense not in VALID_SENSES:
            self.sense = "unknown"
        if self.severity not in VALID_SEVERITIES:
            self.severity = "low"

    def to_payload(self) -> dict[str, Any]:
        """Serialise for the backend ``/threat`` endpoint."""
        d = asdict(self)
        d["evidence"] = self.evidence
        return d


def sighting(
    sense: str,
    kind: str,
    summary: str,
    severity: str = "low",
    evidence: dict[str, Any] | None = None,
    host: str = "",
) -> Sighting:
    """Convenience constructor."""
    return Sighting(
        sense=sense,
        kind=kind,
        summary=summary,
        severity=severity,
        evidence=evidence or {},
        host=host,
    )
