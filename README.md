# LAURA

![status](https://img.shields.io/badge/status-live-4ade80?style=flat&labelColor=0f172a)
![exploit](https://img.shields.io/badge/exploit-none-22d3ee?style=flat&labelColor=0f172a)
![reporting](https://img.shields.io/badge/reporting-human_reviewed_only-a78bfa?style=flat&labelColor=0f172a)
![account](https://img.shields.io/badge/account-none_required-f59e0b?style=flat&labelColor=0f172a)
![license](https://img.shields.io/badge/license-MIT-ef4444?style=flat&labelColor=0f172a)

Digitaler selbstschutz gegen proximity data theft — und jetzt auch gegen
die unsichtbaren mittelsmänner daneben: WiFi-Exposure, MITM und Phishing.

## Human rights are not subject to negotiation.

Proximity-tools (NFC/Bluetooth-basierte geräte, physischer kurzzugriff auf
ein entsperrtes handy, missbrauchte übertragungswege zwischen geräten)
werden zunehmend genutzt, um unbemerkt private fotos von handys zu ziehen
&mdash; oft gefolgt von erpressung.

LAURA erzeugt einen köder-ordner, den du selbst auf dein eigenes handy legst.
Sieht aus wie dein privater fotobereich. Greift jemand ohne deine erlaubnis
darauf zu und öffnet den ordner später irgendwo, bekommt er statt echter
fotos einen köder &mdash; und du bekommst einen beleg, dass es passiert ist.

**Live:** https://rfi-irfos.github.io/laura/

## Was das tool tut

- erzeugt clientseitig ein download-paket mit köder-dateien
- zeichnet auf, wenn der köder-link später irgendwo geöffnet wird (zeitpunkt,
  technische kennung der anfrage)
- gibt dir einen privaten code, mit dem nur du nachsehen kannst, ob/wann
  ausgelöst wurde

## Was das tool bewusst nicht tut

- **kein exploit.** alles, was passiert, passiert dadurch, dass die
  öffnende person selbst eine ganz normale HTTP-anfrage auslöst &mdash;
  exakt das, was jede webseite mit einem besucher-log auch aufzeichnet.
  es läuft kein code auf dem gerät, das den köder öffnet.
- **keine automatische meldung an behörden oder dritte.** ein mensch sieht
  sich jeden treffer an, bevor irgendetwas weiter passiert.
- **keine registrierung, kein klarname, keine app-installation.** alles
  läuft im browser, das einzige, was ihn verlässt, ist der fertige download.

Das ist keine zurückhaltung aus vorsicht, sondern die grenze dessen, was
legal geht: aktiver zugriff auf ein fremdes gerät ("hack back") ist
unabhängig vom anlass strafbar. Der passive ansatz hier folgt dem etablierten
konzept von [canary tokens](https://canarytokens.org/) &mdash; köder, die
beim öffnen ganz normal nach hause funken.

## L.A.U.R.A. — das framework

L.A.U.R.A. steht für **Local Awareness & Unseen Relay Alarm**. Es ist kein
werkzeug, sondern ein passives erkennungs-framework: jede säule *beobachtet*
nur, was bereits auf deinem eigenen gerät / netzwerk passiert. Keine säule
sendet je gefälschte pakete, fälscht frames oder greift dritte an.

| Buchstabe | Säule | Was sie tut | Modul |
|-----------|-------|-------------|-------|
| **L** | **Lumen** — Local WiFi exposure | offene netze, WEP, Evil-Twin-verdacht, deauth-störungen erkennen | `scanner/laura_scanner/wifi.py` |
| **A** | **Aegis** — Aether proximity shield | der bestehende NFC/Bluetooth-köder (canary kit) | `docs/` generator |
| **U** | **Umbra** — Unseen middle relay (MITM) | ARP-spoof, captive portal, DNS-hijack, TLS-mismatch symptom | `scanner/laura_scanner/mitm.py` |
| **R** | **Relay** — Relay & phishing watch | homoglyph/IDN, marken-imitation, relay-latenz-heuristik | `scanner/laura_scanner/relay.py` |
| **A** | **Alert** — Accountable, human-reviewed alarm | alle befunde laufen in ein menschlich geprüftes backend | `backend/` + `scanner/laura_scanner/client.py` |

Das wortspiel hält: **L.A.U.R.A. weckt auf**, bevor etwas passiert &mdash;
sie ist der *alarm*, nicht der angriff.

## Architektur

- `docs/` &mdash; statische seite (GitHub Pages), generiert das
  download-paket vollständig im browser, kein server-roundtrip beim
  erstellen selbst
- `backend/` &mdash; kleiner Rust/Axum-service auf Fly.io, nimmt die
  passiven beacon-treffer **und** die threat-sightings der scanner-säulen
  entgegen und stellt den privaten lookup bereit
- `scanner/` &mdash; Python-paket `laura-scanner` mit den drei neuen
  erkennungs-sinnen (lumen/umbra/relay). Läuft auf dem eigenen rechner,
  nur beobachtung, kein exploit

### Neue backend-endpunkte

- `POST /threat` — nimmt eine passive `Sighting` einer scanner-säule entgegen
  (offen wie `/beacon`, nur ein beobachtungs-beleg, kein trigger)
- `GET /internal/review` — wie bisher token-gated; zeigt jetzt beacon-hits
  **und** threat-sightings gemeinsam zur menschlichen prüfung

## Lokale entwicklung

```bash
# backend
cd backend
cp .env.example .env
cargo run

# frontend (irgendein statischer server, z.b.)
cd docs
python3 -m http.server 8080

# scanner (passive erkennung auf dem eigenen rechner)
cd scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"
pytest -q
python3 -m laura_scanner.cli sweep --host mein-laptop
```
