# VPN über HTTPS – kommt durch jede Firewall

Eigenes VPN, komplett in Rust. Läuft als ganz normales **HTTPS auf Port 443** und kommt dadurch auch durch strenge
Firmen-Firewalls (vor allem **Sophos**) – schon der erste Verbindungsaufbau ist ein gewöhnlicher HTTPS-Aufruf.
Innen Ende-zu-Ende verschlüsselt wie WireGuard. Standardmäßig bis zu **8 Geräte** (einstellbar bis 250: `kvpn-server max 12`): Android, Windows, Linux.
**Name und Bild bestimmst du selbst.**

```
Gerät ── TLS 1.3 :443 ──► (Firewall / Proxy) ──► dein Server ──► Internet
         sieht aus wie eine normale Webseite         Noise IK (X25519, ChaCha20-Poly1305, BLAKE2s)
```

## Installieren – ein Befehl

Auf deinem Linux-Server (als root):

```bash
curl -fsSL https://raw.githubusercontent.com/Krone7891/VPN/main/install.sh | sudo bash
```

Das Setup lädt alles von hier, fragt nach dem **Namen** deines VPN, der **Domain**, einem **Bild** und dem ersten Gerät
und richtet alles ein (Zertifikat, Dienst, Firewall). Ohne Rückfragen:

```bash
curl -fsSL https://raw.githubusercontent.com/Krone7891/VPN/main/install.sh | sudo bash -s -- \
     --name "Potzplitz VPN" --domain vpn.meine-domain.de --bild https://example.org/logo.png --geraet "Mein Handy" --ja
```

Danach:

| Was | Wo |
|---|---|
| Gerät anlegen | `kvpn-server add "Laptop"` – zeigt QR-Code und Verbindungscode |
| Code wieder anzeigen | `kvpn-server code "Laptop"` (oder lokal auf `http://localhost:8180`) |
| Server aktualisieren | `kvpn-update` |
| **Apps aktualisieren** | `kvpn-server update` – neue Version von GitHub, **erst nach deiner Freigabe** an die Geräte |
| Apps mit deinem Namen | `https://<dein-server>/download/` → `Potzplitz VPN.apk`, `Potzplitz VPN.exe`, … |
| Statistik | `https://<dein-server>/stats` (Passwort steht in `/etc/krone-vpn/statistik-passwort.txt`) |
| **Lokal auf dem Server** | **`http://localhost:8180`** – Statistik, Downloads, **eigenes Bild hochladen** (ohne Passwort, nur lokal) |

Als **Docker-Compose**-Container: beim Setup mit `--docker` (oder die Frage mit „j“ beantworten).

Alles Weitere (Domain/ohne Domain, hinter nginx, Docker, Updates, Bild, Wartung): **[SELBST-HOSTEN.md](SELBST-HOSTEN.md)**

## Apps

Fertig gebaut in [`dist/`](dist) – oder von deinem Server unter `/download/` mit deinem Namen:

| Gerät | Datei | |
|---|---|---|
| Android 8+ (arm64, z. B. Galaxy S26) | [`dist/KroneVPN.apk`](dist/KroneVPN.apk) | QR-Code scannen oder Code einfügen, „Immer verbunden" möglich |
| Windows 10/11 | [`dist/KroneVPN.exe`](dist/KroneVPN.exe) | eine Datei, Treiber eingebettet; Programmfenster mit Ein/Aus-Knopf, Live-Werten und Profilen (alte Text-Ansicht umschaltbar, dort Befehlsmenü: `f` Fenster, `p` Profil, `c` Code, `t` aus); das VPN läuft als **Dienst im Hintergrund** (Fenster darf zu, startet mit Windows) |
| Linux x86_64 | [`dist/kronevpn-linux`](dist/kronevpn-linux) | statisch, ohne Abhängigkeiten; `--hintergrund` = systemd-Dienst |
| Server x86_64 | [`dist/kvpn-server`](dist/kvpn-server) | statisch, ohne Abhängigkeiten (das Setup nimmt ihn automatisch) |

**Einstellungen** (bei jedem Lauf von `install.sh` abgefragt – das Skript darf jederzeit erneut laufen – oder
`kvpn-server einstellungen`): Benutzerverwaltung mit SQLite (Standard **an**: Benutzer, sperren, Ablaufdatum, Verlauf –
`kvpn-server benutzer`), AES-256-GCM statt ChaCha20 (Standard aus), Leistungsmodus mit allen CPU-Kernen (Standard aus),
Höchstzahl Geräte. Details: [SELBST-HOSTEN.md](SELBST-HOSTEN.md#einstellungen-benutzerverwaltung-aes-256-leistungsmodus).

**Admin-Seite im VPN:** verbunden `http://10.77.0.1:8180` öffnen – beim ersten Mal Passwort festlegen, dann von jedem
Gerät im VPN anmelden (Update freigeben, Codes, Höchstzahl …). **Update-Stand der Geräte:** `kvpn-server status`.

**Profile:** PC und Handy können mehrere Verbindungscodes speichern (z. B. verschiedene Server) und zwischen ihnen
wechseln – Windows-Fenster „Profile“, Android „Profile …“, Linux `kronevpn --profile` / `--profil <nr>`.

Prüfsummen: [`dist/SHA256SUMS`](dist/SHA256SUMS). Die Apps zeigen den Namen deines VPN an, sobald der
Verbindungscode eingefügt ist, und dürfen beliebig umbenannt werden.

## Warum es durch Firewalls kommt

- Nur TCP 443, normales TLS 1.3 mit echtem Zertifikat, Browser-Header, kein „vpn" in der Adresse, kein UDP.
- **HTTPS-Inspektion** (Sophos „Entschlüsseln und scannen"): wird erkannt und angezeigt – die Verbindung klappt
  trotzdem und bleibt sicher, weil der Server-Schlüssel fest im Verbindungscode steht.
- **Firmen-Proxy** wird automatisch genutzt (Windows-Internetoptionen, Android-WLAN-Proxy) oder per `--proxy`.

## Automatische Updates

Die Apps aktualisieren sich selbst – aber **nur mit Versionen von GitHub, die du auf dem Server freigegeben hast**:
Der Server meldet eine neue Version (`dist/update.json` im Repo), du gibst sie mit `kvpn-server update` frei, er lädt
und prüft sie und schickt sie über die verschlüsselte VPN-Verbindung an die Geräte. Die Update-Liste ist mit Ed25519
signiert (Schlüssel nur beim Bauen, nie auf dem Server); die Apps prüfen Signatur und SHA-256 selbst. Windows/Linux
ersetzen sich und starten neu, Android installiert die neue APK (ab Android 12 ohne Rückfrage).

## Sicherheit

- Innen Noise IK (wie WireGuard): jedes Gerät eigener Schlüssel, fremde Schlüssel bekommen keine Antwort,
  Replay-Schutz, neue Sitzungsschlüssel bei jeder Verbindung, gefälschte Absenderadressen werden verworfen.
- Verbindungscodes sind geheim (enthalten den Geräteschlüssel) – bei Verlust `kvpn-server remove` + neu `add`.
- Die Apps selbst enthalten nichts Geheimes – deshalb ist `/download/` offen. Bild hochladen geht nur lokal.

## Aufbau

| Ordner | Inhalt |
|---|---|
| `install.sh` | Setup (ein Befehl, lädt von GitHub, fragt Name/Domain/Bild) |
| `selfhost.sh` | Einrichtung auf dem Server (wird vom Setup aufgerufen) |
| `kvpn/` | Kern: Protokoll, Noise-Handshake, Verschlüsselung, TLS/WebSocket/Proxy, Client-Logik |
| `kvpn-server/` | Server (Linux): Multi-Queue-TUN (mehrere Kerne), NAT, Geräte, Statistik, Downloads, Bild |
| `kronevpn/` | Client für Windows (Wintun) und Linux |
| `kvpn-android/`, `android/` | JNI-Bibliothek und Android-App (VpnService), Bau ohne Gradle |
| `deploy/` | systemd-Dienst, Docker Compose, nginx-Ausschnitte, `kvpn-update` |
| `tools/set-icon.py` | eigenes Bild als App-Symbol für den eigenen Build |
| `tests/` | End-to-End-Tests mit simulierter Firmen-Firewall |

## Selbst bauen und testen

```bash
bash build-all.sh                 # Tests + alle Dateien nach dist/ (Rust, mingw-w64, musl, Android-SDK/NDK nötig)
sudo bash tests/e2e.sh            # Firewall nur 443, Proxy, TLS-Aufbruch, 8 Geräte, Neustart, Android-Kern …
sudo bash tests/selfhost-test.sh  # Setup: ohne Domain, mit Domain, hinter nginx, Online-Installer
```

Hintergründe und Protokoll: [PLAN.md](PLAN.md). Wintun (Windows-Treiber) © WireGuard LLC, siehe
[`kronevpn/wintun/LICENSE.txt`](kronevpn/wintun/LICENSE.txt).
