import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laura_scanner import Sighting, sighting, VALID_SENSES
from laura_scanner import wifi, mitm, relay


def test_sighting_validates_sense_and_severity():
    s = sighting("bogus", "x", "summary", severity="critical")
    assert s.sense == "unknown"
    assert s.severity == "low"
    assert s.sense not in VALID_SENSES


def test_sighting_payload_roundtrip():
    s = sighting("lumen", "open_ap", "test", severity="medium",
                 evidence={"ssid": "free"}, host="laptop")
    p = s.to_payload()
    assert p["sense"] == "lumen"
    assert p["severity"] == "medium"
    assert p["evidence"] == {"ssid": "free"}
    assert "sighting_id" in p and "observed_at" in p


def test_wifi_analyzes_open_and_wep():
    aps = [
        {"ssid": "CafeFree", "bssid": "AA:BB:CC:01:02:03", "signal": 70, "security": "--"},
        {"ssid": "OldNet", "bssid": "DD:EE:FF:01:02:03", "signal": 40, "security": "WEP"},
    ]
    f = wifi.analyze(aps)
    kinds = {x.kind for x in f}
    assert "open_ap" in kinds
    assert "wep_ap" in kinds


def test_wifi_detects_evil_twin():
    aps = [
        {"ssid": "HomeNet", "bssid": "AA:BB:CC:11:22:33", "signal": 60, "security": "WPA2"},
        {"ssid": "HomeNet", "bssid": "DD:EE:FF:44:55:66", "signal": 58, "security": "WPA2"},
    ]
    f = wifi.analyze(aps)
    evil = [x for x in f if x.kind == "evil_twin_hint"]
    assert evil, "expected an evil-twin hint"
    assert evil[0].severity == "high"


def test_wifi_no_false_positive_single_ap():
    aps = [{"ssid": "HomeNet", "bssid": "AA:BB:CC:11:22:33",
            "signal": 60, "security": "WPA2"}]
    f = wifi.analyze(aps)
    assert all(x.kind != "evil_twin_hint" for x in f)


def test_mitm_arp_conflict():
    entries = [
        {"ip": "192.168.1.1", "mac": "AA:AA:AA:AA:AA:AA", "iface": "wlan0"},
        {"ip": "192.168.1.1", "mac": "BB:BB:BB:BB:BB:BB", "iface": "wlan0"},
    ]
    f = mitm.detect_arp_conflict(entries)
    assert len(f) == 1
    assert f[0].kind == "arp_conflict"
    assert f[0].severity == "high"


def test_mitm_no_arp_conflict():
    entries = [
        {"ip": "192.168.1.1", "mac": "AA:AA:AA:AA:AA:AA", "iface": "wlan0"},
        {"ip": "192.168.1.2", "mac": "BB:BB:BB:BB:BB:BB", "iface": "wlan0"},
    ]
    assert mitm.detect_arp_conflict(entries) == []


def test_relay_homoglyph():
    f = relay.analyze_domain("xn--wkpedia-3od.org")
    # decoded form contains a cyrillic 'i' -> should flag homoglyph
    assert any(x.kind == "homoglyph_domain" for x in f)


def test_relay_brand_impersonation():
    f = relay.analyze_domain("paypa1-secure-login.com")
    assert any(x.kind == "brand_impersonation" for x in f)


def test_relay_clean_domain():
    f = relay.analyze_domain("wikipedia.org")
    assert not any(x.kind in ("homoglyph_domain", "brand_impersonation") for x in f)


def test_sweep_empty_domains():
    assert relay.sweep(domains=[]) == []
