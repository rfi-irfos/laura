"""Relay — Relay & phishing watch (passive observation only).

Watchers for *social-layer* interception: phishing domains that impersonate
a brand, IDN homoglyph tricks (e.g. wikıpedia.org with a dotless i), and a
crude relay-distance heuristic — if a request to a "local" service suddenly
resolves far away or hops through an unexpected number of AS hops, that is
the kind of thing a relay/proxy MITM leaves behind.

This module never visits a malicious site on the user's behalf, never
submits credentials, never follows a phishing form. It inspects the *name*
and *network path metadata* only.

Findings
--------
- ``homoglyph_domain``  — the domain decodes to a punycode (xn--) form that
                         maps to a look-alike of a known brand. Possible
                         IDN homograph phishing.
- ``brand_impersonation``— a domain (after punycode decode) contains a
                         known brand token plus a filler, e.g. paypa1-secure.
- ``relay_distance``    — a target that should be local resolves to a
                         distant/foreign network with high latency, a relay
                         tell. Heuristic, non-authoritative.
"""

from __future__ import annotations

import socket
import time
from typing import Any

from . import Sighting

# Brand tokens we watch for in look-alike domains. Lower-case, simplified.
BRAND_TOKENS = (
    "paypal",
    "amazon",
    "google",
    "microsoft",
    "outlook",
    "apple",
    "netflix",
    "facebook",
    "instagram",
    "bank",
    "post",
    "gmail",
    "dropbox",
    "github",
)

# Unicode codepoints commonly abused in homoglyph attacks, mapped to the
# ASCII char they imitate. Decoding punycode and replacing these yields the
# "intended" look-alike string for comparison.
HOMOGLYPHS = {
    "а": "a",  # cyrillic a
    "е": "e",  # cyrillic e
    "о": "o",  # cyrillic o
    "р": "p",  # cyrillic er
    "с": "c",  # cyrillic es
    "х": "x",  # cyrillic ha
    "у": "y",  # cyrillic u
    "і": "i",  # cyrillic i
    "ј": "j",  # cyrillic je
    "ԛ": "q",  # cyrillic q
    "ɡ": "g",  # latin small capital g
    "𝟎": "0",
    "𝟏": "1",
    "𝟑": "3",
    "𝟒": "4",
    "𝟓": "5",
    "𝟕": "7",
    "𝟖": "8",
}

# Common "leetspeak" substitutions seen in phishing domains. These are not
# unicode look-alikes but simple character swaps, folded here so brand
# tokens survive normalization.
LEET = {
    "1": "l",
    "0": "o",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
}


def _decode_punycode(domain: str) -> str:
    """Decode any xn-- label to unicode; leave others untouched."""
    out = []
    for label in domain.split("."):
        if label.lower().startswith("xn--"):
            try:
                out.append(label.encode("ascii").decode("idna"))
                continue
            except Exception:
                pass
        out.append(label)
    return ".".join(out)


def _homoglyph_normalize(text: str) -> str:
    text = "".join(HOMOGLYPHS.get(ch, ch) for ch in text)
    # second pass: leetspeak (single-char swaps)
    return "".join(LEET.get(ch, ch) for ch in text)


def analyze_domain(domain: str) -> list[Sighting]:
    """Inspect a single domain name for phishing/relay tells (pure)."""
    findings: list[Sighting] = []
    raw = domain.strip().lower().rstrip(".")
    decoded = _decode_punycode(raw)
    normalized = _homoglyph_normalize(decoded)

    if raw != decoded:
        findings.append(
            Sighting(
                sense="relay",
                kind="homoglyph_domain",
                severity="high",
                summary=(
                    f"Domain {raw!r} ist punycode und decodiert zu {decoded!r} "
                    f"— mögl. IDN-Homoglyph-Phishing"
                ),
                evidence={"raw": raw, "decoded": decoded},
            )
        )

    for brand in BRAND_TOKENS:
        if brand in normalized:
            # A real brand domain ("paypal.com") matches the token too — only
            # flag it as impersonation when it is NOT the canonical brand host.
            if raw in (f"{brand}.com", f"www.{brand}.com", brand):
                continue
            findings.append(
                Sighting(
                    sense="relay",
                    kind="brand_impersonation",
                    severity="high",
                    summary=(
                        f"Domain {decoded!r} enthält Marken-Token {brand!r} "
                        f"— mögl. Phishing/Imitations-Domain"
                    ),
                    evidence={"decoded": decoded, "brand": brand},
                )
            )
            break
    return findings


def check_relay_distance(host: str, threshold_ms: float = 120.0) -> Sighting | None:
    """Heuristic: does a host resolve and respond pathologically far/slow?

    Read-only: a single DNS lookup + one TCP connect-time measurement. The
    latency figure is a crude relay tell, never a verdict.
    """
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return None
    start = time.monotonic()
    try:
        with socket.create_connection((host, 443), timeout=5):
            elapsed = (time.monotonic() - start) * 1000.0
    except Exception:
        try:
            with socket.create_connection((host, 80), timeout=5):
                elapsed = (time.monotonic() - start) * 1000.0
        except Exception:
            return None
    if elapsed > threshold_ms:
        return Sighting(
            sense="relay",
            kind="relay_distance",
            severity="low",
            summary=(
                f"{host} antwortet sehr langsam ({elapsed:.0f} ms) — mögl. "
                f"weit entfernter Relay/Proxy vorgeschaltet (Heuristik)"
            ),
            evidence={"host": host, "ip": ip, "latency_ms": round(elapsed, 1)},
        )
    return None


def sweep(host: str = "", domains: list[str] | None = None) -> list[Sighting]:
    """Inspect a list of domains (and optionally measure relay distance)."""
    findings: list[Sighting] = []
    for d in domains or []:
        findings.extend(analyze_domain(d))
    for f in findings:
        f.host = host
    return findings


__all__ = ["sweep", "analyze_domain", "check_relay_distance", "BRAND_TOKENS"]
