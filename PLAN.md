# KroneVPN – Plan

## Ziele
| Ziel | Umsetzung |
|---|---|
| kommt durch Firewalls, v. a. **Sophos** | Tunnel sieht aus wie normales HTTPS: **TLS 1.3 auf TCP 443**, echtes Let's-Encrypt-Zertifikat (nginx), danach ein **WebSocket** auf einem unauffälligen Pfad (`/api/v1/stream`, kein „vpn" in der URL). Schon der **erste Handshake** ist ein ganz normaler HTTPS-Aufruf – kein UDP, kein eigenes Protokoll, keine Signatur für Sophos „VPN and Proxy"-Anwendungsfilter. |
| Sophos HTTPS-Inspektion (TLS wird aufgebrochen) | Client akzeptiert auch das Sophos-Zertifikat, weil die **eigentliche Sicherheit innen liegt** (Noise, siehe unten). Sophos sieht dann nur einen WebSocket mit zufällig aussehenden Binärdaten. Erkannte Inspektion wird in der Statistik angezeigt (Aussteller des Zertifikats). |
| Firmen-Proxy (Sophos als expliziter Proxy) | HTTP-`CONNECT`-Proxy wird unterstützt (Windows: Systemproxy automatisch, Android: Systemproxy automatisch, sonst manuell). |
| sicher, alles verschlüsselt | Innen **Noise IK (X25519, ChaCha20-Poly1305, BLAKE2s)** – dasselbe Verfahren wie WireGuard. Server-Schlüssel ist im Client fest hinterlegt (kein Man-in-the-Middle möglich, auch nicht durch Sophos), jeder Client hat einen eigenen Schlüssel. Fremde Schlüssel bekommen keine Antwort. Replay-Schutz per Zeitstempel. Pro Verbindung neue Schlüssel (Forward Secrecy). |
| schnell, multi-core | Rust + tokio (Mehrkern-Laufzeit). Server: TUN mit **Multi-Queue** (eine Warteschlange pro Kern, max. 8). Senden und Empfangen pro Verbindung laufen getrennt auf verschiedenen Kernen (eigene Schlüssel je Richtung). Pakete werden gebündelt (weniger Overhead), TCP_NODELAY, MSS-Clamping. |
| wenig Serveraufwand | ein Programm (`kvpn-server`, ~3 MB), ein systemd-Dienst, läuft hinter dem vorhandenen nginx auf 443. Keine Datenbank. |
| max. 6 Verbindungen, ausgelegt auf 8 | harte Grenze **8 Geräte** (Peers), Adressen 10.77.0.2–.9 und fd77:6b76::2–9 (IPv4 + IPv6). |
| APK + EXE | Android: VpnService (Java) + Rust-Kern per JNI (arm64, 16-KB-Seiten für Android 15+/S26 Ultra). Windows: eine einzige `KroneVPN.exe` (Wintun-Treiber eingebettet, fragt nach Adminrechten). Zusätzlich Linux-Client. |
| Webseite | Download-Seite `/download/` (Apps unter eigenem Namen), Statistik `/stats` (Passwort), lokale Seite `http://localhost:8180` mit eigenem Bild |

## Aufbau
```
Handy/PC ── TLS 1.3 :443 ──► (Sophos) ──► nginx :443 ──► kvpn-server 127.0.0.1:8101 ──► kvpn0 (TUN) ──► NAT ──► Internet
            WebSocket /api/v1/stream                       Noise IK innen
```
- `kvpn` (Bibliothek): Protokoll, Krypto, Verbindungscode, TLS/WebSocket/Proxy, Client-Logik (für alle Plattformen gleich).
- `kvpn-server`: Linux-Server, Befehle `init`, `add <name>`, `remove`, `list`, `run`.
- `kronevpn`: Client für Windows und Linux.
- `kvpn-android`: JNI-Bibliothek für die APK; `android/`: App (ohne Gradle gebaut: aapt2/javac/d8/apksigner).

## Protokoll
1. TLS 1.3 (ALPN http/1.1), WebSocket-Upgrade mit normalen Browser-Headern.
2. Nachricht 1 (Client→Server): Noise IK, Inhalt: Zeitstempel, OS, Version, TLS-Aussteller, Proxy ja/nein.
3. Nachricht 2 (Server→Client): Noise IK, Inhalt: IPv4/IPv6-Adresse, DNS, MTU.
4. Danach: jede WebSocket-Nachricht = ChaCha20-Poly1305-verschlüsseltes Bündel aus Datensätzen
   (`IP-Paket`, `Ping`, `Pong`, `Füllbytes`), Zähler-Nonce je Richtung.
5. Keepalive alle 10 s, Neuverbindung automatisch (Netzwechsel WLAN/Mobil), TUN bleibt dabei bestehen (kein Datenleck).

## Testplan (alles hier vor dem Einspielen)
- Unit-Tests: Handshake, Verschlüsselung, Manipulation/Replay, Verbindungscode.
- End-to-End in Netzwerk-Namespaces mit echtem nginx + TLS:
  - Client-Netz lässt **nur TCP 443** durch (wie eine strenge Sophos-Regel) → WireGuard/UDP ginge nicht, KroneVPN muss gehen.
  - über **HTTP-Proxy** (CONNECT), wie Sophos im Proxy-Modus.
  - über **mitmproxy mit TLS-Aufbruch** (simuliert Sophos HTTPS-Inspektion) → muss verbinden und Inspektion melden.
  - ping, HTTP, Durchsatz (iperf3, beide Richtungen, mehrere Streams), 8 Clients gleichzeitig, 9. wird abgelehnt,
    fremder Schlüssel wird abgelehnt, Server-Neustart → Clients verbinden sich neu.
- Windows-EXE: Cross-Build + Selbsttest unter Wine (Verbindung + Handshake). Android: Build, APK-Prüfung (Signatur, 16-KB-Ausrichtung).

## Grenzen (ehrlich)
- TCP-Tunnel ist bei Paketverlust langsamer als WireGuard/UDP – dafür kommt er überall durch. Zu Hause/unterwegs ohne Sperre bleibt WireGuard die schnellste Wahl.
- Sperrt eine Firewall die Domain per Kategorie („Dynamic DNS"), hilft nur eine andere Domain (in der Server-Konfiguration änderbar).

## Aufgaben 1.1.0

**Krypto & Tarnung**
- [x] Dynamische Cipher-Wahl: AES-256-GCM bei AES-NI/ARMv8-AES, sonst ChaCha20-Poly1305 (nur geprüfte Verfahren)
- [x] Cipher im Client umschaltbar (Auto / AES-256 / ChaCha20) – PC + Android
- [x] Multicore: Senden/Empfangen/Verschlüsseln parallel
- [x] Tarn-Schicht pro Verbindung neu (Paketgrößen, Padding, Timing) – Sophos-Durchgang hat Vorrang

**Auto-Update**
- [x] Nur Geräte im Tunnel bekommen das Update, nur geänderte App
- [x] App startet sich nach dem Patch selbst neu

**Ortung (nur eigene Geräte)**
- [x] GPS-Report + IP-Geo zusammenführen
- [x] SSID/BSSID-Ortung über WiGLE + Google Geolocation API (Schlüssel in server.toml)
- [x] Standort-Verlauf loggen + Bewegungs-Map je Gerät
- [x] Anti-Diebstahl: frischer GPS-Fix auf Abruf

**Webseite**
- [x] Geräte still anpingen (ohne Benachrichtigung)
- [x] Admin-Seite responsiv für jede Größe

**Apps**
- [x] Power-Button der PC-App auch auf Android
- [x] Mehr Animationen
- [x] Verständliche Fehlermeldungen
- [x] Absturz-Logs über den Tunnel in Server-Ordner
- [ ] Absturz-Logs gemeinsam besprechen
- [x] Code-/QR-Anzeige entfernen
- [x] Alle Berechtigungen beim ersten Start abfragen
- [x] PC: nur einmalige Admin-Abfrage (UAC) – gebaut, auf echtem Windows noch zu pruefen
- [x] Google Play Protect „gefährlich“: Benachrichtigung + Erklärung (Standort nie verdeckt); Prüfung/Einspruch bei Google selbst
- [x] Gefundene Bugs beheben

**Abschluss**
- [x] Version 1.1.0, alles bauen, e2e-Tests, Doku, beide Repos pushen (Server: `kvpn-update`, Apps: `kvpn-server update`)
