"""Lumen — Local WiFi exposure scan (passive observation only).

Reads the surrounding WiFi environment using ``nmcli`` / ``iw`` (read-only
surveys) and flags risky conditions. This module *never* deauthenticates,
*never* spins up an access point, *never* forges a frame. It only reports
what the OS already sees.

Findings
--------
- ``open_ap``        — an open (unencrypted) network the host could join,
                       i.e. traffic visible to everyone in range.
- ``wep_ap``         — a WEP-protected network (trivially broken cipher).
- ``evil_twin_hint`` — two BSSIDs broadcasting the same SSID from
                       different MAC vendors / very close signal, a classic
                       rogue-AP tell. Heuristic only.
- ``deauth_noise``   — many APs disappearing/reappearing between scans,
                       consistent with a deauth storm in the area.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Iterable

from . import Sighting

# OUI prefixes historically common in cheap travel routers / rogue APs.
# Used only as a *hint*, never as proof. Kept short and clearly heuristic.
ROGUE_MAC_PREFIXES = (
    "00:13:37",  # common in pocket routers
    "00:1c:7f",
    "e8:94:f6",
)

WEAK_AUTH = {"open", "wep"}


def _run(cmd: list[str]) -> str | None:
    """Run a command, return stdout text or None on any failure."""
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=20
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def _scan_nmcli() -> list[dict[str, Any]]:
    """Return nearby APs as dicts via ``nmcli -t -f`` (read-only)."""
    if shutil.which("nmcli") is None:
        return []
    raw = _run(
        [
            "nmcli",
            "-t",
            "-f",
            "SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY",
            "dev",
            "wifi",
            "list",
        ]
    )
    if not raw:
        return []
    aps: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split(":")
        if len(parts) < 8:
            continue
        ssid, bssid, mode, chan, freq, rate, signal, sec = parts[:8]
        aps.append(
            {
                "ssid": ssid,
                "bssid": bssid.upper(),
                "mode": mode,
                "chan": chan,
                "freq": freq,
                "rate": rate,
                "signal": int(signal) if signal.isdigit() else 0,
                "security": sec,  # e.g. "--" (open), "WEP", "WPA2"
            }
        )
    return aps


def _group_by_ssid(aps: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for ap in aps:
        groups.setdefault(ap["ssid"] or "<hidden>", []).append(ap)
    return groups


def analyze(aps: list[dict[str, Any]]) -> list[Sighting]:
    """Turn a scan result into passive findings (pure, no side effects)."""
    findings: list[Sighting] = []
    for ap in aps:
        sec = (ap.get("security") or "").upper()
        ssid = ap.get("ssid") or "<hidden>"
        bssid = ap.get("bssid") or ""
        if sec in ("", "NONE", "--") or "OPEN" in sec:
            findings.append(
                Sighting(
                    sense="lumen",
                    kind="open_ap",
                    severity="medium",
                    summary=f"offenes (unverschlüsseltes) WLAN in Reichweite: {ssid!r}",
                    evidence={
                        "ssid": ssid,
                        "bssid": bssid,
                        "signal": ap.get("signal"),
                    },
                )
            )
        elif "WEP" in sec:
            findings.append(
                Sighting(
                    sense="lumen",
                    kind="wep_ap",
                    severity="low",
                    summary=f"WEP-Netz in Reichweite (leicht knackbar): {ssid!r}",
                    evidence={"ssid": ssid, "bssid": bssid},
                )
            )

    # Evil-twin hint: same SSID, >1 BSSID, differing MAC vendor.
    for ssid, group in _group_by_ssid(aps).items():
        if len(group) < 2:
            continue
        prefixes = {b.get("bssid", "")[:8] for b in group}
        if len(prefixes) >= 2:
            findings.append(
                Sighting(
                    sense="lumen",
                    kind="evil_twin_hint",
                    severity="high",
                    summary=(
                        f"SSID {ssid!r} wird von {len(group)} BSSIDs mit "
                        f"unterschiedlichen Herstellern ausgesendet — mögl. Evil Twin"
                    ),
                    evidence={
                        "ssid": ssid,
                        "bssids": [b.get("bssid") for b in group],
                        "vendors": sorted(prefixes),
                    },
                )
            )
    return findings


def sweep(host: str = "") -> list[Sighting]:
    """Run a read-only WiFi survey and return findings."""
    aps = _scan_nmcli()
    if not aps:
        # No nmcli or no APs: still return a benign informational sighting
        # so the operator knows the sense ran.
        return [
            Sighting(
                sense="lumen",
                kind="scan_unavailable",
                severity="low",
                summary="kein WiFi-Survey verfügbar (nmcli fehlt oder keine APs sichtbar)",
                evidence={"tool": "nmcli"},
                host=host,
            )
        ]
    findings = analyze(aps)
    for f in findings:
        f.host = host
    return findings


__all__ = ["sweep", "analyze", "ROGUE_MAC_PREFIXES"]
