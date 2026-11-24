# Eigenes VPN – auf dem eigenen Server betreiben

Ein Programm (`kvpn-server`), ein systemd-Dienst, Port **443/TCP**. Bis zu 8 Geräte. Kommt durch Firmen-Firewalls
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
| `--ja` | keine Rückfragen |

**Privates Repository?** Dann braucht der Download einen GitHub-Zugangsschlüssel (github.com/settings/tokens →
„Fine-grained", nur dieses Repo, Recht „Contents: read"):

```bash
T=github_pat_...   # dein Schlüssel
curl -fsSL -H "Authorization: Bearer $T" https://raw.githubusercontent.com/Krone7891/VPN/main/install.sh | sudo GITHUB_TOKEN=$T bash
```

Erneut ausführen = aktualisieren (Schlüssel und Geräte bleiben). Wer das Repo schon geklont hat: `sudo bash install.sh`
(bzw. direkt `sudo bash selfhost.sh <domain> --name "…"`).

## Webseiten

| Adresse | Inhalt | Zugriff |
|---|---|---|
| `https://<adresse>/download/` | Apps mit deinem Namen (`<Name>.apk`, `<Name>.exe`, Linux) | offen – die Apps enthalten nichts Geheimes |
| `https://<adresse>/stats` | Statistik (bei `--hinter-nginx`: `/vpn-statistik`) | Passwort aus `/etc/krone-vpn/statistik-passwort.txt` |
| **`http://localhost:8180`** | Statistik + Downloads **auf dem Server selbst**, ohne Passwort, mit **„Eigenes Bild" hochladen** | nur lokal |

Vom eigenen PC aus über localhost: `ssh -L 8180:localhost:8180 root@<server>` und dann im Browser
`http://localhost:8180` öffnen. Anderer lokaler Port: `kvpn-server set local_listen 127.0.0.1:<port>`.

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
kvpn-server list                  # Übersicht (max. 8)
kvpn-server remove "Laptop"       # sofort gesperrt
```

Die Apps gibt es auf `https://<adresse>/download/` mit deinem Namen (oder in `dist/`). Sie zeigen den Namen deines VPN
an, sobald der Verbindungscode eingefügt ist.

- **Android:** `dist/KroneVPN.apk` installieren, QR-Code mit der Kamera scannen (oder Code einfügen), Verbinden.
- **Windows:** `dist/KroneVPN.exe` starten (Adminrechte), Code einfügen – wird gespeichert. Test ohne
  Netzwerkänderung: `KroneVPN.exe --test`.
- **Linux:** `sudo dist/kronevpn-linux 'kronevpn://v1/…'`

Die Dateien dürfen beliebig umbenannt werden (z. B. „Potzplitz VPN.exe").

Statistik-Passwort ändern: `kvpn-server password '…'`. Aus privaten Netzen (192.168.x.x, 10.x.x.x – also auch
übers VPN) geht die Statistik ohne Passwort.

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
