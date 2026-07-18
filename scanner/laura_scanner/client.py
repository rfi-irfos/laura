"""Alert — ship passive sightings to a LAURA backend for human review.

The backend ``/threat`` endpoint is open (like ``/beacon``) because the
scanner only *reports what it observed on the operator's own machine*. What
happens with the record is gated behind ``/internal/review`` — a human
looks at every sighting before anything else. No auto-action.
"""

from __future__ import annotations

from typing import Iterable

import requests

from . import Sighting


def report(
    beacon_base: str,
    sightings: Iterable[Sighting],
    timeout: float = 10.0,
) -> tuple[int, int]:
    """POST each sighting to ``{beacon_base}/threat``.

    Returns (sent, failed). Failures are non-fatal — detection still works
    offline; the operator just loses central aggregation.
    """
    base = beacon_base.rstrip("/")
    sent = 0
    failed = 0
    for s in sightings:
        try:
            r = requests.post(
                f"{base}/threat",
                json=s.to_payload(),
                timeout=timeout,
            )
            if r.status_code in (200, 202, 201):
                sent += 1
            else:
                failed += 1
        except Exception:
            failed += 1
    return sent, failed


__all__ = ["report"]
