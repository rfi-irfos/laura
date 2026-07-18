"""L.A.U.R.A. scanner CLI — passive host-side threat sweep.

Usage
-----
    python3 -m laura_scanner.cli sweep [--host NAME] [--beacon-base URL]
    python3 -m laura_scanner.cli wifi  [--host NAME]
    python3 -m laura_scanner.cli mitm  [--host NAME] [--check-url URL]
    python3 -m laura_scanner.cli relay --domain example.com [--domain ...]

Everything is read-only observation. No packets are spoofed, no frames
forged, no third party is touched.
"""

from __future__ import annotations

import argparse
import sys
from typing import Iterable, Sequence

from . import Sighting
from . import mitm, relay, wifi
from .client import report as report_to_backend


def _print(findings: Iterable[Sighting]) -> None:
    rows = list(findings)
    if not rows:
        print("  (keine auffälligen Befunde)")
        return
    for f in rows:
        print(f"  [{f.severity.upper():6}] {f.sense}/{f.kind}: {f.summary}")


def cmd_sweep(args: argparse.Namespace) -> int:
    findings: list[Sighting] = []
    print("== lumen (wifi) ==")
    findings += wifi.sweep(host=args.host)
    print("== umbra (mitm) ==")
    findings += mitm.sweep(host=args.host, check_url=args.check_url)
    print("== relay (phishing) ==")
    findings += relay.sweep(host=args.host, domains=args.domain or [])
    print()
    print("=== Befunde ===")
    _print(findings)
    if args.beacon_base:
        sent, failed = report_to_backend(args.beacon_base, findings)
        print(f"\nbackend: {sent} gesendet, {failed} fehlgeschlagen")
    return 0


def cmd_wifi(args: argparse.Namespace) -> int:
    f = wifi.sweep(host=args.host)
    _print(f)
    return _maybe_send(args, f)


def cmd_mitm(args: argparse.Namespace) -> int:
    f = mitm.sweep(host=args.host, check_url=args.check_url)
    _print(f)
    return _maybe_send(args, f)


def cmd_relay(args: argparse.Namespace) -> int:
    f = relay.sweep(host=args.host, domains=args.domain or [])
    _print(f)
    return _maybe_send(args, f)


def _maybe_send(args: argparse.Namespace, findings: list[Sighting]) -> int:
    if args.beacon_base:
        sent, failed = report_to_backend(args.beacon_base, findings)
        print(f"backend: {sent} gesendet, {failed} fehlgeschlagen")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="laura-scan", description=__doc__)
    p.add_argument("--host", default="", help="tag for the scanning machine")
    p.add_argument("--beacon-base", default="", help="LAURA backend base URL")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("sweep", help="run all passive senses")
    sp.add_argument("--check-url", default=None)
    sp.add_argument("--domain", action="append", default=[])
    sp.set_defaults(func=cmd_sweep)

    sp = sub.add_parser("wifi", help="lumen: wifi exposure scan")
    sp.set_defaults(func=cmd_wifi)

    sp = sub.add_parser("mitm", help="umbra: mitm detection")
    sp.add_argument("--check-url", default=None)
    sp.set_defaults(func=cmd_mitm)

    sp = sub.add_parser("relay", help="relay: phishing/relay watch")
    sp.add_argument("--domain", action="append", default=[])
    sp.set_defaults(func=cmd_relay)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        # default: full sweep
        args.cmd = "sweep"
        args.func = cmd_sweep
        args.check_url = None
        args.domain = []
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
