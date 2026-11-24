# Eigenes VPN – auf dem eigenen Server betreiben

Ein Programm (`kvpn-server`), ein systemd-Dienst, Port **443/TCP**. Standardmäßig bis zu 8 Geräte – ändern mit `kvpn-server max <anzahl>` (bis 250) oder auf der lokalen Seite
http://localhost:8180 („Höchstens … Geräte erlauben“). Kommt durch Firmen-Firewalls
(Sophos & Co.), weil alles wie normales HTTPS aussieht; innen Ende-zu-Ende verschlüsselt wie WireGuard.

## Voraussetzungen

- Linux-Server mit öffentlicher IP (VPS, Root-Server, Rechner zu Hause mit Portfreigabe 443), root-Zugang
- x86_64: fertiges Programm liegt bei (`dist/kvpn-server`, läuft auf jedem Linux). Andere CPU (ARM): Rust
  installieren (https://rustup.rs), `selfhost.sh` baut dann selbst.
- `iptables`, `iproute2`, `openssl`, systemd (bei Debian/Ubuntu Standard)
- Port **443/TCP** von außen erreichbar (beim Anbieter/Router freigeben)

## Einrichten – ein Befehl

Auf dem Server als root (lädt alles von GitHub, fragt nach **Name**, **Domain**, **Bild** und dem ersten Gerät):

```bash
curl -fsSL https://raw.githubusercontent.com/Krone7891/VPN/main/install.sh | sudo bash
```

Ohne Rückfragen, alles als Angaben:

```bash
curl -fsSL https://raw.githubusercontent.com/Krone7891/VPN/main/install.sh | sudo bash -s -- \
     --name "Potzplitz VPN" --domain vpn.meine-domain.de --bild https://example.org/logo.png --geraet "Mein Handy" --ja
```

| Angabe | Bedeutung |
|---|---|
| `--name "…"` | Name deines VPN: steht in den Apps, auf Download- und Statistik-Seite und in den Dateinamen (`Potzplitz VPN.exe`) |
| `--domain host` | eigene Domain → echtes Let's-Encrypt-Zertifikat (empfohlen, kommt am besten durch Firewalls). Leer = öffentliche IP + eigenes Zertifikat |
| `--bild datei\|url` | eigenes Bild (PNG/JPG/WebP/GIF, max. 2 MB) für die Webseiten |
| `--geraet "…"` | gleich ein Gerät anlegen (mehrfach möglich) |
| `--hinter-nginx` | es läuft schon ein Webserver auf 443 – das VPN lauscht intern, der nginx-Ausschnitt wird angezeigt |
| `--docker` | Server als **Docker-Compose**-Container statt systemd-Dienst (Docker wird bei Bedarf installiert); `--systemd` = zurück |
| `--ja` | keine Rückfragen |

**Privates Repository?** Dann braucht der Download einen GitHub-Zugangsschlüssel (github.com/settings/tokens →
„Fine-grained", nur dieses Repo, Recht „Contents: read"):

```bash
T=github_pat_...   # dein Schlüssel
curl -fsSL -H "Authorization: Bearer $T" https://raw.githubusercontent.com/Krone7891/VPN/main/install.sh | sudo GITHUB_TOKEN=$T bash
```

Erneut ausführen = aktualisieren (Schlüssel und Geräte bleiben). Wer das Repo schon geklont hat: `sudo bash install.sh`
(bzw. direkt `sudo bash selfhost.sh <domain> --name "…"`).

## Aktualisieren

```bash
kvpn-update            # Server auf den neuesten Stand von GitHub bringen (Name, Domain, Geräte, Docker/systemd bleiben)
kvpn-server update     # neue App-Version an Handy/PC verteilen – mit Rückfrage
```

**App-Updates kommen nur von GitHub und erst nach deiner Freigabe:**

1. Der Server schaut alle 6 Stunden im GitHub-Repo nach einer neuen App-Version (`dist/update.json`) und **meldet** sie
   nur (Log und Statistik-Seite) – verteilt wird noch nichts.
2. Du gibst sie frei: `kvpn-server update` (zeigt Version und Größen, fragt nach) oder auf der lokalen Seite
   `http://localhost:8180` mit „Jetzt an die Geräte verteilen“.
3. Der Server lädt die Apps von GitHub, prüft sie gegen die **signierte** Liste und gibt sie an die Geräte weiter –
   über die verschlüsselte VPN-Verbindung. Verbundene Geräte bekommen sie sofort, andere beim nächsten Verbinden.
4. Die Apps prüfen die Signatur noch einmal selbst und spielen das Update ein: Windows/Linux ersetzen sich und starten
   neu, Android installiert es (ab Android 12 ohne Rückfrage, sonst einmal „Installieren“ tippen).
Kommt ein Update an? `kvpn-server status` zeigt je Gerät System, App-Version und Update-Stand („wird angeboten“,
„übertragen – wird installiert“, „aktuell“). Android: Wurde die App von Hand installiert, muss Android das **erste**
Update einmal bestätigen – die App zeigt dafür eine Benachrichtigung „Update bereit“ (antippen → „Installieren“),
ist die App offen, kommt die Rückfrage sofort. Fehlt die Erlaubnis „Unbekannte Apps installieren“, öffnet die App
zuerst diese Einstellung. Wurde die Rückfrage weggeklickt, kommt sie beim nächsten Öffnen der App wieder. Danach
aktualisiert sie sich ab Android 12 ohne Rückfrage. (Bis 1.0.9 konnte die Rückfrage beim erneuten Öffnen der App
„abgebrochen“ werden – ab 1.0.10 nicht mehr.)

5. Bei der Freigabe werden auch die Apps auf der Download-Seite erneuert. Unter Windows bringt der Dienst außerdem
   ältere Kopien von KroneVPN.exe (z. B. im Download-Ordner) auf die neue Version – beim nächsten Start ist dann
   die neue Oberfläche da. Reste davon (`*.exe.old`) räumt er selbst weg, sobald das alte Programm beendet ist.
   (1.0.6–1.0.10 konnten dabei bei einem noch laufenden alten Programm alle 30 s eine weitere Datei
   `KroneVPN.exe.old.old…` anlegen – ab 1.0.11 behoben, die überzähligen Dateien werden automatisch gelöscht.)
   Die Statistik-Seite zeigt oben die Server-Version und an jedem Gerät seine App-Version (gelb = Update ausstehend),
   die Download-Seite die Version der Apps.

Signiert wird beim Bauen mit einem geheimen Schlüssel, der nie auf dem Server liegt – selbst ein übernommener Server
kann den Geräten keine fremden Programme unterschieben. Anderes Repo/Zweig: `kvpn-server set update_repo besitzer/name`,
`kvpn-server set update_branch …`; nur melden abschalten: `kvpn-server set update_check false`.
Apps vor Version 1.0.1 können das noch nicht – sie einmal von Hand aktualisieren (`/download/`).

## Docker

`--docker` beim Installieren (oder `sudo bash selfhost.sh --docker`) richtet den Server als Container ein:
`deploy/docker/docker-compose.yml` (Netz des Servers direkt, `NET_ADMIN`, `/dev/net/tun`, Konfiguration in
`/etc/krone-vpn`, Daten in `/var/lib/krone-vpn`). Verwaltet wird wie gewohnt mit `kvpn-server …` auf dem Server –
der Container übernimmt Änderungen sofort. Protokoll: `docker logs -f krone-vpn`. Zurück: `--systemd`.

## Webseiten

| Adresse | Inhalt | Zugriff |
|---|---|---|
| `https://<adresse>/download/` | Apps mit deinem Namen (`<Name>.apk`, `<Name>.exe`, Linux) | offen – die Apps enthalten nichts Geheimes |
| `https://<adresse>/stats` | Statistik (bei `--hinter-nginx`: `/vpn-statistik`) | Passwort aus `/etc/krone-vpn/statistik-passwort.txt` |
| **`http://localhost:8180`** | Statistik + Downloads **auf dem Server selbst**, ohne Passwort, mit **„Eigenes Bild" hochladen** | nur lokal |

**Admin-Seite im VPN (einfacher):** Mit dem VPN verbunden im Browser **`http://10.77.0.1:8180`** öffnen (Android-App:
„Admin-Seite öffnen“). Beim ersten Aufruf legst du ein Passwort fest (mindestens 8 Zeichen, gespeichert nur als
PBKDF2-Hash); danach meldest du dich damit von jedem Gerät im VPN an, der Browser bleibt ein Jahr angemeldet. Dort geht
alles wie auf der lokalen Seite (Update freigeben, Codes, Höchstzahl, Bild). Nur für verbundene Geräte erreichbar.
Passwort neu: `kvpn-server admin-passwort '<neu>'`, vergessen: `kvpn-server admin-passwort --loeschen`,
abschalten: `kvpn-server einstellungen --admin-vpn aus`. Tipp: gleich nach dem Update selbst das Passwort festlegen –
wer die Seite zuerst öffnet, legt es fest.

Die lokale Seite gibt es **nur auf dem Server selbst** (sie lauscht nur auf 127.0.0.1). Vom eigenen PC aus:
`ssh -L 8180:localhost:8180 root@<server>` und dann im Browser `http://localhost:8180` öffnen (das Fenster mit der
SSH-Verbindung offen lassen). Anderer lokaler Port: `kvpn-server set local_listen 127.0.0.1:<port>`.

### Eigenes Bild

- auf der lokalen Seite `http://localhost:8180` unter „Eigenes Bild" hochladen, oder
- `kvpn-server logo bild.png` (entfernen: `kvpn-server logo --entfernen`), oder beim Installieren `--bild`.

Das Bild erscheint auf Download- und Statistik-Seite und als Browser-Symbol. Hochladen geht nur lokal, nie von außen.
Das **App-Symbol** von EXE/APK ändert man beim eigenen Bauen: `python3 tools/set-icon.py bild.png`, dann
`bash build-all.sh` (braucht Rust, Android-SDK usw.).

## Geräte

```bash
kvpn-server add "Mein Handy"      # zeigt QR-Code + Verbindungscode
kvpn-server add "Laptop"
kvpn-server list                  # Übersicht (mit Benutzer und Status)
kvpn-server code "Laptop"         # Code + QR-Code wieder anzeigen
kvpn-server remove "Laptop"       # sofort gesperrt
```

**Alte Codes wieder anzeigen:** `kvpn-server code "Name"` oder auf der lokalen Seite `http://localhost:8180` beim Gerät
„Verbindungscode anzeigen“ (mit QR-Code, nur lokal). Geht für alle Geräte, die ab Version 1.0.1 angelegt wurden.
Ältere Geräte: Code auf dem Gerät anzeigen (Android-App „Code anzeigen“, Windows `KroneVPN.exe --code`) und auf dem
Server merken: `kvpn-server import '<code>'`.

Die Apps gibt es auf `https://<adresse>/download/` mit deinem Namen (oder in `dist/`). Sie zeigen den Namen deines VPN
an, sobald der Verbindungscode eingefügt ist.

- **Android:** `dist/KroneVPN.apk` installieren, QR-Code mit der Kamera scannen (oder Code einfügen), Verbinden.
  Die App darf danach geschlossen (auch weggewischt) werden – das VPN läuft weiter.
- **Windows:** `dist/KroneVPN.exe` starten (Adminrechte), Code einfügen. Es öffnet sich ein Programmfenster mit großem
  Ein/Aus-Knopf, Live-Werten, Verlauf, „Code“ (QR-Code fürs Handy), „Protokoll“ und „Profile“. Das VPN läuft als
  **Windows-Dienst im Hintergrund** und startet mit Windows – **das Fenster darf geschlossen werden**; wieder öffnen
  über das Startmenü. Lieber die alte Text-Ansicht? Unten „Klassische Ansicht“. Dort per Buchstabe + Enter:
  `f` neues Fenster, `p` Profil wechseln, `c` Code/QR, `t` ausschalten (die Wahl wird gemerkt, auch `--klassisch` / `--fenster`). Per Befehl: `--trennen`, ganz entfernen: `--entfernen`, Textanzeige wie früher: `--vordergrund`,
  Test ohne Netzwerkänderung: `--test`. (Programm: `C:\Program Files\KroneVPN`, Code/Protokoll: `C:\ProgramData\KroneVPN`.)
- **Linux:** `sudo dist/kronevpn-linux 'kronevpn://v1/…'` – im Hintergrund als systemd-Dienst: zusätzlich `--hintergrund`
  (danach darf das Terminal zu; `--trennen` / `--entfernen`).
- **Profile** (mehrere Codes, z. B. verschiedene Server): Windows-Fenster „Profile“ (oder oben auf den Namen klicken),
  Android „Profile …“ (antippen = verwenden, lange drücken = entfernen), Linux `--profile` (Liste) und
  `--profil <nr|name>`. Jeder neu eingegebene Code wird als Profil gemerkt; Wechseln verbindet sofort neu.

Die Dateien dürfen beliebig umbenannt werden (z. B. „Potzplitz VPN.exe").

Statistik-Passwort ändern: `kvpn-server password '…'`. Aus privaten Netzen (192.168.x.x, 10.x.x.x – also auch
übers VPN) geht die Statistik ohne Passwort.

## Einstellungen (Benutzerverwaltung, AES-256, Leistungsmodus)

Das Installationsskript darf **jederzeit erneut laufen** – es fragt jedes Mal nach den Einstellungen (Enter = so
lassen) und behält Schlüssel, Geräte, Domain und Name. Ohne Rückfragen mit Schaltern, oder direkt auf dem Server:

```bash
kvpn-server einstellungen                       # Frage für Frage
kvpn-server einstellungen --benutzer an --aes256 an --leistung aus --max 12
```

| Einstellung | Standard | Was sie tut |
|---|---|---|
| `--benutzer an\|aus` | **an** | **Benutzerverwaltung (SQLite)**: Geräte stehen in `benutzer.db` neben `server.toml` (nur root lesbar). Benutzer anlegen, Geräte zuordnen, sperren, Ablaufdatum, Verlauf. Beim Einschalten werden vorhandene Geräte übernommen, beim Ausschalten zurückgeschrieben. |
| `--aes256 an\|aus` | aus | Daten im Tunnel mit **AES-256-GCM** statt ChaCha20-Poly1305 (beide 256 Bit). Gilt für Apps ab 1.0.6, ältere bleiben automatisch bei ChaCha20. Von außen nicht zu sehen – Sophos & Co. merken davon nichts. |
| `--leistung an\|aus` | aus | **Leistungsmodus**: alle CPU-Kerne (eine TUN-Warteschlange je Kern, mehr Threads) – mehr Durchsatz, mehr Last. Aus = sparsam (1 Warteschlange, 2 Threads; reicht für jeden Internetanschluss). Gilt nach Neustart des Servers. |
| `--admin-vpn an\|aus` | an | Admin-Seite im VPN unter `http://10.77.0.1:8180` mit Passwort (siehe „Webseiten“) |
| `--standort an\|aus` | an | **Standort der Geräte** auf der Admin-/lokalen Seite (nie auf der öffentlichen Statistik): ungefähr aus der IP-Adresse, von der sich ein Gerät verbindet – Stadt, Land, Anbieter, Link zur Karte. Kein GPS: im Mobilfunk oder Firmennetz ist es der Ort des Netzanschlusses. Dafür fragt der Server **ipwho.is** (die IP-Adresse geht dorthin; Ergebnis 7 Tage gemerkt). Auch: `kvpn-server standort <ip>`, `kvpn-server status`. |
| `--max <anzahl>` | 8 | höchstens so viele Geräte (bis 250) |

**Auf der Webseite einstellen:** Alles davon geht auch auf der Admin-Seite (im VPN `http://10.77.0.1:8180` oder lokal
`http://localhost:8180`) im Bereich **„Einstellungen“**: Name des VPN, Höchstzahl, Schalter für Benutzerverwaltung,
AES-256, Leistungsmodus und Admin-Seite im VPN, dazu **Admin-Passwort ändern**. Brauchen Leistungsmodus oder Admin-Seite
einen Neustart, erscheint der Knopf **„Server jetzt neu starten“** (geht, wenn der Server als systemd-Dienst oder in
Docker läuft; die Geräte sind ein paar Sekunden getrennt und verbinden sich von selbst wieder).

Mit Benutzerverwaltung:

```bash
kvpn-server benutzer add "Anna" --notiz "Schwester"
kvpn-server add "Annas Handy" --benutzer Anna --ablauf 2026-12-31   # oder --ablauf 30 (Tage)
kvpn-server benutzer                       # Benutzer mit ihren Geräten
kvpn-server sperren "Annas Handy"          # sofort getrennt, Code geht erst nach 'entsperren' wieder
kvpn-server benutzer sperren "Anna"        # alle Geräte von Anna gesperrt
kvpn-server benutzer max "Anna" 2          # höchstens 2 Geräte für Anna
kvpn-server ablauf "Annas Handy" nie       # Ablaufdatum entfernen
kvpn-server zuordnen "Laptop" "Anna"       # Gerät einem Benutzer zuordnen ('-' = keinem)
kvpn-server verlauf ["Annas Handy"]        # wann verbunden/getrennt (90 Tage)
kvpn-server benutzer remove "Anna" [--mit-geraeten]
```

**Auf der Webseite sperren:** Auf der Admin-Seite im VPN (`http://10.77.0.1:8180`) bzw. lokal (`http://localhost:8180`)
gibt es unter den Geräten den Bereich „Benutzer & Geräte sperren“ – je Benutzer und je Gerät ein Knopf
**Sperren/Entsperren**. Gesperrte Geräte werden sofort getrennt.

Änderungen gelten sofort, ohne Neustart. Die Statistik-Seite zeigt den Benutzer an jedem Gerät, gesperrte/abgelaufene
Geräte unter der Liste und die eingestellte Verschlüsselung.

## Wartung

| Was | Befehl |
|---|---|
| Status / Protokoll | `systemctl status krone-vpn` · `journalctl -u krone-vpn -f` |
| Neu starten | `systemctl restart krone-vpn` |
| Konfiguration | `/etc/krone-vpn/server.toml` (Geräteänderungen wirken sofort, Rest nach Neustart) |
| Zertifikat | Let's Encrypt verlängert sich selbst (certbot), der Dienst startet danach neu |

`private_key` in der Konfiguration ist geheim – wer ihn hat, kann sich als Server ausgeben. Verbindungscodes
ebenfalls geheim halten (sie enthalten den Geräteschlüssel).

## Netz im Tunnel

Geräte bekommen 10.77.0.2–9 (und fd77:6b76::2–9 für IPv6), DNS 1.1.1.1 / 9.9.9.9. Alles änderbar in
`server.toml` (`net4`, `net6`, `dns`, `mtu`). Der Server macht NAT selbst (`nat = true`).
