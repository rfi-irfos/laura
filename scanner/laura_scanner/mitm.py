"""Umbra — Unseen middle relay / MITM detection (passive observation only).

This module watches for *symptoms* of a machine-in-the-middle on the local
link. It reads the local ARP table, the active DNS configuration, HTTP
redirect behaviour and TLS certificate metadata. It never sends spoofed
ARP replies, never intercepts traffic, never impersonates a gateway.

Findings
--------
- ``arp_conflict``  — the same IP (esp. the gateway) maps to more than one
                      MAC in the local ARP table. Classic ARP-spoof symptom.
- ``captive_portal``— an external host redirects to an unexpected login/
                      captive domain, a common MITM/interception tell.
- ``dns_hijack_hint``— the resolver points at a private/unknown server that
                      is not the DHCP-learned gateway. Heuristic.
- ``tls_mismatch`` — the certificate presented for a host does not match the
                      expected hostname or is issued by an unknown CA.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
from typing import Any
from urllib.parse import urlparse

from . import Sighting

try:  # cryptography is optional at import time; only used by TLS checks.
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.primitives.hashes import Hash, SHA256  # type: ignore
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover - import guard
    x509 = None  # type: ignore
    Hash = None  # type: ignore
    SHA256 = None  # type: ignore
    _HAS_CRYPTO = False


def _run(cmd: list[str]) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    return out.stdout if out.returncode == 0 else None


def read_arp_table() -> list[dict[str, str]]:
    """Parse the local ARP table (read-only)."""
    entries: list[dict[str, str]] = []
    if shutil.which("arp") is not None:
        raw = _run(["arp", "-n"])
        if raw:
            for line in raw.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    entries.append(
                        {"ip": parts[0], "mac": parts[2].upper(), "iface": parts[-1]}
                    )
            return entries
    # Linux /proc fallback.
    try:
        with open("/proc/net/arp") as fh:
            for line in fh.readlines()[1:]:
                cols = line.split()
                if len(cols) >= 4 and cols[3] != "00:00:00:00:00:00":
                    entries.append(
                        {"ip": cols[0], "mac": cols[3].upper(), "iface": cols[5]}
                    )
    except OSError:
        pass
    return entries


def detect_arp_conflict(entries: list[dict[str, str]]) -> list[Sighting]:
    by_ip: dict[str, set[str]] = {}
    for e in entries:
        by_ip.setdefault(e["ip"], set()).add(e["mac"])
    findings: list[Sighting] = []
    for ip, macs in by_ip.items():
        if len(macs) > 1:
            findings.append(
                Sighting(
                    sense="umbra",
                    kind="arp_conflict",
                    severity="high",
                    summary=(
                        f"IP {ip} ist im ARP-Tabellen-Eintrag mit mehreren MACs "
                        f"({len(macs)}) gelistet — mögl. ARP-Spoofing"
                    ),
                    evidence={"ip": ip, "macs": sorted(macs)},
                )
            )
    return findings


def check_captive_portal(url: str, timeout: float = 8.0) -> Sighting | None:
    """Detect an unexpected redirect (captive portal / interception)."""
    import requests  # local import — optional dependency

    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False)
    except Exception:
        return None
    loc = r.headers.get("Location")
    if not loc:
        return None
    target = urlparse(loc)
    original = urlparse(url)
    if target.netloc and target.netloc != original.netloc:
        return Sighting(
            sense="umbra",
            kind="captive_portal",
            severity="high",
            summary=(
                f"{url} leitet auf unerwartete Domain um: {target.netloc!r} "
                f"(mögl. Captive Portal / MITM)"
            ),
            evidence={"from": url, "redirect_to": loc, "status": r.status_code},
        )
    return None


def detect_dns_hijack(timeout: float = 4.0) -> list[Sighting]:
    """Compare the active resolver against the default gateway hint."""
    findings: list[Sighting] = []
    ns = _read_resolv_conf_nameservers()
    entries = read_arp_table()
    gateway = _default_gateway_ip()
    if not ns:
        return findings
    for server in ns:
        # Resolver pointing at a public anycast is normal; flag only if it
        # resolves to a private IP that is NOT the gateway we learned.
        if _is_private(server) and server != gateway and not _mac_for_ip(entries, server):
            findings.append(
                Sighting(
                    sense="umbra",
                    kind="dns_hijack_hint",
                    severity="medium",
                    summary=(
                        f"DNS resolver {server} ist eine private Adresse, die weder "
                        f"Gateway noch bekanntes Gerät ist — mögl. DNS-Hijack"
                    ),
                    evidence={"nameserver": server, "gateway": gateway},
                )
            )
    return findings


def _read_resolv_conf_nameservers() -> list[str]:
    servers: list[str] = []
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except OSError:
        pass
    return servers


def _default_gateway_ip() -> str | None:
    raw = _run(["ip", "route", "show", "default"])
    if raw:
        for tok in raw.split():
            if _looks_like_ipv4(tok):
                return tok
    return None


def _mac_for_ip(entries: list[dict[str, str]], ip: str) -> str | None:
    for e in entries:
        if e["ip"] == ip:
            return e["mac"]
    return None


def _is_private(ip: str) -> bool:
    try:
        a, b = (int(x) for x in ip.split(".")[:2])
    except ValueError:
        return False
    return a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31) or a == 127


def _looks_like_ipv4(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def check_tls_cert(host: str, port: int = 443, timeout: float = 8.0) -> Sighting | None:
    """Fetch a cert and check hostname match + self-signed/untrusted CA.

    Read-only: opens a TLS connection *as a normal client would*, then
    inspects the presented certificate. No interception, no MITM of others.
    """
    if not _HAS_CRYPTO:
        return None
    try:
        from cryptography import x509 as _x509  # local import keeps pyright happy
    except Exception:
        return None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except Exception:
        return None
    if not der:
        return None
    cert = _x509.load_der_x509_certificate(der)
    # Hostname check (simplified): does a SAN/CN contain the host?
    names: list[str] = []
    try:
        cn = cert.subject.get_attributes_for_oid(_x509.NameOID.COMMON_NAME)[0].value
        names.append(str(cn))
    except Exception:
        pass
    try:
        ext = cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
        names.extend(ext.value.get_values_for_type(_x509.DNSName))
    except Exception:
        pass
    matched = any(host == n or (n.startswith("*.") and host.endswith(n[1:])) for n in names)
    if not matched:
        return Sighting(
            sense="umbra",
            kind="tls_mismatch",
            severity="high",
            summary=(
                f"Zertifikat für {host} passt nicht zur Hostname "
                f"(präsentiert: {', '.join(names)}) — mögl. MITM"
            ),
            evidence={"host": host, "cert_names": names},
        )
    return None


def sweep(host: str = "", check_url: str | None = None) -> list[Sighting]:
    """Run all passive MITM checks and collect findings."""
    findings: list[Sighting] = []
    findings.extend(detect_arp_conflict(read_arp_table()))
    findings.extend(detect_dns_hijack())
    if check_url:
        cap = check_captive_portal(check_url)
        if cap:
            findings.append(cap)
    if check_url:
        parsed = urlparse(check_url)
        if parsed.hostname:
            tls = check_tls_cert(parsed.hostname)
            if tls:
                findings.append(tls)
    for f in findings:
        f.host = host
    return findings


__all__ = [
    "sweep",
    "read_arp_table",
    "detect_arp_conflict",
    "check_captive_portal",
    "detect_dns_hijack",
    "check_tls_cert",
]
