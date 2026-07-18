# L.A.U.R.A. scanner

Host-side **passive** threat detection for the L.A.U.R.A. framework. The
scanner runs on *your own* machine and only *observes* what is already
happening on your local network / in your browser environment. It never
sends a spoofed packet, never forges a frame, never attacks a third party.

Senses (map to the L.A.U.R.A. backronym):

- **lumen** (Local WiFi exposure) — `wifi.py`
- **umbra** (Unseen middle relay / MITM) — `mitm.py`
- **relay** (Relay & phishing watch) — `relay.py`
- **aegis** (NFC/Bluetooth proximity) — *see the `docs/` canary kit*
- **alert** (human-reviewed reporting) — `client.py` → backend `/threat`

Run:

```bash
python3 -m laura_scanner.cli sweep --host my-laptop
python3 -m laura_scanner.cli wifi
python3 -m laura_scanner.cli mitm
python3 -m laura_scanner.cli relay --url https://example.com
```

Optional: pipe findings to a LAURA backend with `--beacon-base https://laura.rfi-irfos.dev`.

Tests:

```bash
pytest -q
```
