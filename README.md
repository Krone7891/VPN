# VPN über HTTPS – kommt durch jede Firewall

Eigenes VPN, komplett in Rust. Läuft als ganz normales **HTTPS auf Port 443** und kommt dadurch auch durch strenge
Firmen-Firewalls (vor allem **Sophos**) – schon der erste Verbindungsaufbau ist ein gewöhnlicher HTTPS-Aufruf.
Innen Ende-zu-Ende verschlüsselt wie WireGuard. Standardmäßig bis zu **8 Geräte** (einstellbar bis 250: `kvpn-server max 12`): Android, Windows, Linux.
**Name und Bild bestimmst du selbst.**

```
Gerät ── TLS 1.3 :443 ──► (Firewall / Proxy) ──► dein Server ──► Internet
         sieht aus wie eine normale Webseite         Noise IK (X25519, BLAKE2s) · Daten AES-256-GCM/ChaCha20 + Tarn-Schicht
```


## Neu in Apps 1.4.0 / Server 1.4.0

**Server**
- **Tägliche Sicherung**: Schlüssel, Geräte, Benutzer, Einstellungen und Statistik als `.tar.gz` (nur root lesbar,
  die letzten 14 bleiben). Wiederherstellen – auch auf einem neuen Server nach der Installation – mit
  `kvpn-server sicherung zurueck <datei>` (der aktuelle Stand wird vorher gesichert, der Dienst startet neu).
  `kvpn-server sicherung [jetzt|an|aus|ordner <pfad>|behalten <n>]`; auf der Admin-Seite: an/aus, „Jetzt sichern“, herunterladen.
- **Ausfall-Alarm** (Benachrichtigung „ausfall“): ausgewählte Geräte länger als N Stunden nicht im VPN (z. B. das
  Kinder-Handy) → Meldung, und Entwarnung, wenn es wieder da ist. Der Server prüft alle 10 Minuten, ob sein Name
  (DynDNS) noch auf den eigenen Anschluss zeigt (eine DNS-Frage an OpenDNS: `myip.opendns.com`) – gemeldet wird nur,
  wenn es vorher schon einmal gepasst hat (kein Fehlalarm bei DS-Lite/Tunnel). Nach einem Ausfall des Servers
  steht die Dauer in der Start-Meldung. Admin-Seite → Einstellungen → Ausfall-Alarm, oder
  `kvpn-server set ausfall_geraete "Handy Lea, PC Büro"` · `set ausfall_stunden 24` · `set ausfall_extern an|aus`.
- **Gäste einladen**: `kvpn-server gast "Oma" [--tage 7]` (oder Admin-Seite → Gäste einladen) zeigt einen Link und
  QR-Code. Über `https://<server>/einladung/…` holt sich der Gast die App und – nur **einmal** – seinen Zugang
  (Messenger-Vorschauen verbrauchen ihn nicht). Danach ist der Link wertlos; nach Ablauf ist der Zugang gesperrt und
  einen Tag später ganz entfernt. `kvpn-server gaeste` zeigt alle. (Mit nginx davor: Bereich `/einladung/` aus
  `deploy/nginx-selfhost.conf` übernehmen.)
- **Geschwindigkeitstest** für die Apps (misst durch den Tunnel zum eigenen Server).

**Apps**
- **Geschwindigkeit testen**: Ping, Download und Upload durch das VPN bis zum eigenen Server (je 5 s).
  Android: Knopf unter den Live-Werten · PC: „Geschwindigkeit testen“ unter den Details, im Symbol neben der Uhr
  oder `kronevpn --geschwindigkeit` (Linux mit sudo).
- **Android: Schnelleinstellungs-Kachel** – VPN an/aus direkt aus der Statusleiste (Kachel einmal über den Stift
  hinzufügen). Fehlt noch der Code oder die VPN-Erlaubnis, öffnet sie die App.
- **Windows: Symbol neben der Uhr** – Farbe zeigt den Zustand (grün verbunden, gelb verbindet, blau pausiert,
  grau aus), Tooltip mit Datenrate und Ping. Klick öffnet das Fenster, Rechtsklick: Verbinden/Trennen, Geschwindigkeit
  testen, beim Anmelden zeigen. Meldet, wenn die Verbindung länger abreißt.

## Neu in Apps 1.3.0 / Server 1.3.0

**Server**
- **Werbe- & Tracker-Blocker** (wie Pi-hole, Standard an): Der Server beantwortet die DNS-Anfragen der Geräte
  selbst und blockt Namen aus einer Sperrliste (StevenBlack, täglich neu). Wirkt auch bei alten Apps (DNS wird
  umgeleitet). Eigene Sperren/Ausnahmen und Listen auf der Admin-Seite; Zähler, meistgeblockte Namen und je Gerät.
  `kvpn-server einstellungen --werbeblocker an|aus`
- **Heimnetz**: Geräte im VPN erreichen Drucker, NAS usw. im Netz des Servers – auch mit Namen (`nas.fritz.box`
  oder kurz `nas`). Abschaltbar: `kvpn-server einstellungen --heimnetz aus` (dann nur Internet).
- **Zweiter Schritt** für die Admin-Seite im VPN: Passwort + Code aus einer Authenticator-App (TOTP, RFC 6238).
  Einrichten auf der Admin-Seite (QR-Code) oder `kvpn-server zwei-faktor an`; Notfall: `kvpn-server zwei-faktor aus`.
- **Benachrichtigungen aufs Handy** über **ntfy** (ntfy.sh oder eigener ntfy-Server, auch mit Zugang/Token) oder Telegram: neues Gerät, falsches Admin-Passwort, Server gestartet, neue App-Version,
  Monatsbericht. `kvpn-server benachrichtigung ntfy https://ntfy.sh/<geheimes-thema>` · `… test`
- **Monatsbericht**: Daten, Online-Zeit und Verbindungen je Gerät, Laufzeit des Servers, geblockte Anfragen – auf
  der Admin-Seite (auch als CSV), mit `kvpn-server bericht [JJJJ-MM]` und am Monatsanfang als Benachrichtigung.
- **Start beim Hochfahren** prüfen/einschalten: `kvpn-server autostart [an]` (auch auf der Admin-Seite); der
  Dienst gibt beim Hochfahren nicht mehr auf, wenn das Netz noch nicht da ist.

**Apps**
- **Notbremse (Kill-Switch)**: Fällt das VPN aus, geht nichts mehr unverschlüsselt ins Internet.
  - PC (Windows): Filter der Windows-Filterplattform (wie WireGuard), Fenster → **Schutz**. Lokales Netz wahlweise erlaubt.
  - Android: über die System-Einstellung „Durchgehend aktives VPN“ + „Verbindungen ohne VPN blockieren“ – die App
    zeigt den Stand und führt dorthin (App → **Schutz**).
  - Linux: iptables (`kronevpn --notbremse an`).
- **Automatisch schützen**: In fremden WLANs und im Mobilfunk verbindet das VPN von selbst, in vertrauten Netzen
  (z. B. zu Hause) pausiert es. Android: WLAN-Name; PC: WLAN-Name oder Router des Netzes.
- **Am VPN vorbei**: Android: einzelne Apps wählen. PC: Ziele (Namen, Adressen, Netze) – einzelne Programme gehen
  unter Windows nur mit eigenem Treiber.
- Nach einem **App-Update** verbindet sich das VPN sicher wieder von selbst (auch wenn Android es beim Austausch kurz entzieht).
- Ändert sich die Adresse des Servers (DynDNS) während einer Unterbrechung, fragt die App sie direkt am Tunnel vorbei nach.

## Neu in Apps 1.2.0 / Server 1.2.1: eigenes Logo überall

- Ein hochgeladenes Logo (Admin-Seite oder `kvpn-server logo bild.png`) erscheint jetzt **auch in den Apps**: Der
  Server macht daraus ein quadratisches PNG (256 × 256) und schickt es beim nächsten Verbinden durch den Tunnel.
  - **PC (Windows):** Logo im Fenster, Fenster- und Taskleisten-Symbol, Symbol der Verknüpfung im Startmenü.
  - **Android:** Logo im Kopf der App und in der Benachrichtigung; „📌 Logo als Symbol auf den Startbildschirm“ legt
    eine Verknüpfung mit dem Logo an, die bei jedem neuen Logo von selbst mitwechselt.
  - Logo entfernen (`kvpn-server logo --entfernen`) → überall wieder die Krone.
- Nicht austauschbar (Grenzen der Systeme): das Symbol der App im Android-App-Menü und das Symbol in der EXE-Datei
  selbst – beide stecken in der signierten Datei; ein Austausch würde die Signatur (und Auto-Updates) brechen.

## Neu: Server 1.2.0 (Apps bleiben 1.1.2)

- **Server und Apps haben getrennte Versionen.** Ändert sich nur der Server, bekommen die Geräte kein Update – und
  jede App (Android, Windows, Linux) steigt nur, wenn sich genau ihr Code oder ihre Abhängigkeiten ändern.
- **Admin-Passwort bei der Einrichtung:** Installer und `kvpn-server einstellungen` fragen danach, solange keins
  festgelegt ist (`kvpn-server admin-passwort`). Es gilt für die Admin-Seite und schützt die Update-Quelle.
- **Update-Quelle ändern** (eigenes GitHub-Repo für die App-Updates): `kvpn-server update-quelle besitzer/name [zweig]`
  oder auf der Admin-Seite unter Einstellungen – nur mit dem Admin-Passwort. Vorher prüft der Server, ob im neuen
  Repo `dist/update.json` mit gültiger Signatur liegt (sonst würden die Apps die Updates von dort ablehnen).
  Neues Repo anlegen: auf GitHub ein Repo erstellen und den Ordner `dist/` (Apps, `update.json`, `update.json.sig`)
  hineinlegen. Admin-Passwort ändern geht auf der Webseite nur mit dem bisherigen.

## Neu in 1.1.2

- **„Sicherheit“ verständlich erklärt** (PC und Android): Verschlüsselt ist immer – man wählt nur das Verfahren
  (Auto / AES-256 / ChaCha20, alle gleich sicher, Unterschied nur Tempo und Akku). Dazu steht, was immer aktiv und nicht
  abschaltbar ist: HTTPS-Hülle (TLS 1.3), Geräte-Schlüssel (Noise) und Tarnung (keine Verschlüsselung, nur Verkleidung).

## Neu in 1.1.1

- **Windows verbindet viel schneller:** Die Route zum Server (am Tunnel vorbei) setzt die App jetzt direkt über die
  Windows-IP-API statt über PowerShell – das hat auf manchen Rechnern pro Verbindungsversuch 20–60 s gedauert.
  Im Protokoll steht jetzt, über welches Gateway die Route läuft und wie lange es gedauert hat.

## Neu in 1.1.0

- **Verschlüsselung wählbar:** Auto (AES-256-GCM, wenn der Prozessor AES-Befehle hat, sonst ChaCha20-Poly1305) oder
  fest – Windows „Sicherheit“, Android „🔒 Verschlüsselung“, Linux `--verschluesselung auto|aes|chacha`. Nur geprüfte
  Standard-Verfahren; Senden/Empfangen/TLS laufen als Fließband auf mehreren Kernen.
- **Tarn-Schicht:** Der Server würfelt bei jeder Verbindung ein neues Profil aus (Paketgrößen, Füllbytes, Takt der
  Lebenszeichen, Länge des Handshakes). Es bleibt normales TLS 1.3 + WebSocket auf 443 – nur ohne erkennbare Muster.
- **Ortung (nur eigene Geräte, nur Admin-Seite):** bester Standort aus GPS des Handys, WLAN-Ortung (Google Geolocation
  API / WiGLE, Schlüssel per `kvpn-server set google_geo_key …` / `wigle_api NAME:TOKEN`) und IP-Adresse;
  **Bewegungs-Karte** je Gerät mit GPX-Export (`kvpn-server orte <gerät>`), **still anpingen** und **„Jetzt orten“**.
- **Absturz-Protokolle** der Apps kommen durch den Tunnel in `<state_dir>/absturz-logs/` (`kvpn-server abstuerze`).
- **Apps:** Power-Knopf jetzt auch auf Android, mehr Animationen, Fehlermeldungen in Klartext mit Tipp, Einrichtung
  beim ersten Start, Benachrichtigung solange das VPN läuft (zeigt auch, ob der Standort geteilt wird), Neustart nach
  Updates von selbst. **Windows** fragt nur noch einmal (beim Einrichten) nach Administratorrechten.
- Die Apps zeigen den Verbindungscode nicht mehr an (nur noch der Server: `kvpn-server add` / `code`).

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
`kvpn-server benutzer`), AES-256-GCM für ältere Apps bis 1.0.13 (ab 1.1.0 wählt jede App selbst), Leistungsmodus mit allen CPU-Kernen (Standard aus),
Höchstzahl Geräte. Details: [SELBST-HOSTEN.md](SELBST-HOSTEN.md#einstellungen-benutzerverwaltung-aes-256-leistungsmodus).

**Admin-Seite im VPN:** verbunden `http://10.77.0.1:8180` öffnen – beim ersten Mal Passwort festlegen, dann von jedem
Gerät im VPN anmelden (Update freigeben, Codes, **Einstellungen** inkl. Neustart, **Benutzer und Geräte sperren/entsperren** …). **Update-Stand der Geräte:** `kvpn-server status`.

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
