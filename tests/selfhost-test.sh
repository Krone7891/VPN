#!/bin/bash
# Test fuer selfhost.sh (eigener Server, eigenstaendig) – als root:  bash tests/selfhost-test.sh
#   A) ohne Domain: eigenes Zertifikat, kvpn-server macht TLS selbst auf 443
#   B) mit Domain (Zertifikat selbst erstellt, da im Test kein Let's Encrypt)
#   C) hinter vorhandenem nginx (--hinter-nginx)
# Client-Netz laesst nur TCP 443 hinaus. Je Variante: Verbindungstest, voller Tunnel, Statistik mit Passwort.
set -u
unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy
K=$(cd "$(dirname "$0")/.." && pwd)
BIN=${1:-$K/target/release}
PASS=0; FAIL=0
ok()  { echo "  [OK]     $*"; PASS=$((PASS+1)); }
bad() { echo "  [FEHLER] $*"; FAIL=$((FAIL+1)); }
ns()  { local n=$1; shift; ip netns exec "$n" "$@"; }
cleanup() {
  for p in $(cat /tmp/sh-pids 2>/dev/null); do kill "$p" 2>/dev/null; done; rm -f /tmp/sh-pids
  sleep 0.5; for n in sh-srv sh-cli sh-net; do ip netns del $n 2>/dev/null; done; rm -rf /etc/netns/sh-cli /etc/netns/sh-srv
}
trap cleanup EXIT; cleanup 2>/dev/null
bg() { "$@" >> "$W/log.$2-$(basename "$3")" 2>&1 & echo $! >> /tmp/sh-pids; }

W=$(mktemp -d /tmp/kvpn-sh.XXXX); chmod 755 "$W"
ip netns add sh-srv; ip netns add sh-cli; ip netns add sh-net
for n in sh-srv sh-cli sh-net; do ns $n ip link set lo up; done
ip link add s0 type veth peer name c0; ip link set s0 netns sh-srv; ip link set c0 netns sh-cli
ip link add s1 type veth peer name n0; ip link set s1 netns sh-srv; ip link set n0 netns sh-net
ns sh-srv ip addr add 198.51.100.1/24 dev s0; ns sh-srv ip link set s0 up
ns sh-cli ip addr add 198.51.100.2/24 dev c0; ns sh-cli ip link set c0 up; ns sh-cli ip route add default via 198.51.100.1
ns sh-srv ip addr add 203.0.113.1/24 dev s1; ns sh-srv ip link set s1 up
ns sh-net ip addr add 203.0.113.2/24 dev n0; ns sh-net ip link set n0 up; ns sh-net ip route add default via 203.0.113.1
ns sh-srv sysctl -qw net.ipv4.ip_forward=1; ns sh-srv iptables -P FORWARD DROP
mkdir -p /etc/netns/sh-cli; printf '127.0.0.1 localhost\n198.51.100.1 vpn.example.test\n' > /etc/netns/sh-cli/hosts
ns sh-cli iptables -P OUTPUT DROP
ns sh-cli iptables -A OUTPUT -o lo -j ACCEPT; ns sh-cli iptables -A OUTPUT -o kvpn-c0 -j ACCEPT
ns sh-cli iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; ns sh-cli iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
mkdir -p "$W/www"; echo "internet ok" > "$W/www/index.html"
bg ns sh-net python3 -m http.server 80 --directory "$W/www"

variant() {   # name args...
  local name=$1; shift
  echo "== Variante $name: selfhost.sh $*"
  local C=$W/$name; mkdir -p "$C"
  export KVPN_DOWNLOADS=$C/downloads KVPN_STATE=$C/state
  KVPN_TEST=1 KVPN_CONFIG=$C/server.toml KVPN_BIN=$C/kvpn-server KVPN_PUBLIC_IP=198.51.100.1 bash "$K/selfhost.sh" "$@" > "$C/install.txt" 2>&1 \
    && ok "selfhost.sh lief durch ($(grep -o 'wss://[^ ]*' "$C/install.txt" | head -1), intern $(grep -o 'intern: [^)]*' "$C/install.txt" | head -1 | cut -d' ' -f2))" \
    || { bad "selfhost.sh"; cat "$C/install.txt"; return; }
  sed -i "s#^state_dir = .*#state_dir = \"$C/state\"#" "$C/server.toml"
  # zweiter Lauf: Schluessel bleibt gleich
  local k1; k1=$(grep '^private_key' "$C/server.toml")
  KVPN_TEST=1 KVPN_CONFIG=$C/server.toml KVPN_BIN=$C/kvpn-server KVPN_PUBLIC_IP=198.51.100.1 bash "$K/selfhost.sh" "$@" > /dev/null 2>&1
  [ "$k1" = "$(grep '^private_key' "$C/server.toml")" ] && ok "erneuter Aufruf behaelt den Server-Schluessel" || bad "Schluessel geaendert"
  # Aktualisieren ohne Angaben (wie kvpn-update): Adresse, Domain und "hinter nginx" bleiben
  local before; before=$(grep -E '^(public_url|listen|tls_cert) ' "$C/server.toml")
  KVPN_TEST=1 KVPN_CONFIG=$C/server.toml KVPN_BIN=$C/kvpn-server KVPN_PUBLIC_IP=198.51.100.1 bash "$K/selfhost.sh" > /dev/null 2>&1
  [ "$before" = "$(grep -E '^(public_url|listen|tls_cert) ' "$C/server.toml")" ] && ok "Aktualisieren ohne Angaben behaelt Adresse/Zertifikat/nginx" || bad "Einstellungen beim Aktualisieren geaendert: $(grep -E '^(public_url|listen|tls_cert) ' "$C/server.toml")"
  [ -x "$C/kvpn-update" ] && grep -q 'Krone7891/VPN' "$C/kvpn-update" && ok "Befehl kvpn-update eingerichtet" || bad "kvpn-update fehlt"
  sed -i "s#^state_dir = .*#state_dir = \"$C/state\"#" "$C/server.toml"
  "$C/kvpn-server" --config "$C/server.toml" add "Laptop" | grep '^kronevpn://' > "$C/code"
  bg ns sh-srv "$C/kvpn-server" --config "$C/server.toml" run
  if [ "${NGX:-0}" = 1 ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=vpn.example.test" -addext "subjectAltName=DNS:vpn.example.test" -keyout "$C/k.pem" -out "$C/c.pem" 2>/dev/null
    local L; L=$(sed -n 's/^listen = "\(.*\)"/\1/p' "$C/server.toml")
    cat > "$C/nginx.conf" <<EOF
pid $C/nginx.pid; error_log $C/nginx-error.log; events {}
http { access_log off; client_body_temp_path $C/t1; proxy_temp_path $C/t2; fastcgi_temp_path $C/t3; uwsgi_temp_path $C/t4; scgi_temp_path $C/t5;
  server { listen 443 ssl; server_name vpn.example.test; ssl_certificate $C/c.pem; ssl_certificate_key $C/k.pem;
$(sed "s#127.0.0.1:8101#$L#g" "$K/deploy/nginx-selfhost.conf")
    location / { return 200 "andere Webseite\n"; } } }
EOF
    bg ns sh-srv nginx -c "$C/nginx.conf" -g "daemon off;"
  fi
  sleep 2
  ns sh-cli "$BIN/kronevpn" --config "$C/code" --test > "$C/test.txt" 2>&1 && ok "Verbindungstest: $(grep -o 'Handshake in [0-9]* ms' "$C/test.txt")" || { bad "Verbindungstest"; cat "$C/test.txt"; tail "$C"/log.*; }
  bg ns sh-cli "$BIN/kronevpn" --config "$C/code"
  sleep 3
  [ "$(ns sh-cli curl -s -m 5 http://203.0.113.2/)" = "internet ok" ] && ok "Internet durch den Tunnel (NAT)" || bad "kein Internet durch den Tunnel"
  local SP=/stats; [ "${NGX:-0}" = 1 ] && SP=/vpn-statistik
  local HOSTN; HOSTN=$(grep -o 'wss://[^/]*' "$C/install.txt" | head -1 | cut -c7-)
  local PW; PW=$(cat "$C/statistik-passwort.txt")
  # Statistik von aussen: der Client-PC kommt (nach Trennen) aus einem "fremden" Netz -> nur mit Passwort
  pkill -f "kronevpn --config $C/code$" ; sleep 1
  local R="--resolve vpn.example.test:443:198.51.100.1"
  ns sh-cli curl -sk -m 5 $R "https://$HOSTN$SP/data.json" | grep -q '"login":true' && ok "Statistik ohne Passwort gesperrt" || bad "Statistik offen"
  ns sh-cli curl -sk -m 5 $R -c "$C/jar" -H 'Content-Type: application/json' -d "{\"pw\":\"$PW\"}" "https://$HOSTN$SP/login" | grep -q '"ok":true' && ok "Anmeldung mit Statistik-Passwort" || bad "Anmeldung"
  ns sh-cli curl -sk -m 5 $R -b "$C/jar" "https://$HOSTN$SP/data.json" | grep -q '"Laptop"' && ok "Statistik mit Passwort sichtbar" || bad "Statistik mit Passwort"
  ns sh-cli curl -sk -m 5 $R -H 'X-Krone-Auth: homeserver' "https://$HOSTN$SP/data.json" | grep -q '"login":true' && ok "Kopf X-Krone-Auth von aussen wirkungslos" || bad "Kopf einschleusbar!"
  # alles in Server- und Client-Netz beenden und warten, bis Port 443 wirklich frei ist (Server raeumt NAT-Regeln auf)
  for n in sh-srv sh-cli; do ip netns pids $n | xargs -r kill 2>/dev/null; done
  for i in $(seq 1 40); do ns sh-srv ss -ltnH '( sport = :443 or sport = :18101 )' | grep -q . || break; sleep 0.25; done
}

online() {   # Online-Installer wie von GitHub: Paket als Archiv, Skript ueber eine Pipe
  echo "== Variante D: curl .../install.sh | bash -s -- --name \"Potzplitz VPN\" --bild logo.png --geraet Handy --ja"
  local C=$W/D; mkdir -p "$C"
  local KN; KN=$(basename "$K")
  tar -C "$K/.." --exclude="$KN/target" --exclude="$KN/.git" --transform "s#^$KN#VPN-main#" -czf "$C/main.tar.gz" "$KN"
  cat "$K/install.sh" | env KVPN_TEST=1 KVPN_TARBALL="file://$C/main.tar.gz" KVPN_SRC=$C/src KVPN_CONFIG=$C/server.toml KVPN_BIN=$C/kvpn-server \
      KVPN_DOWNLOADS=$C/downloads KVPN_STATE=$C/state KVPN_PUBLIC_IP=198.51.100.1 \
      bash -s -- --name "Potzplitz VPN" --bild "$K/assets/favicon-64.png" --geraet "Handy" --ja > "$C/install.txt" 2>&1 \
    && ok "Online-Installer lief durch (Quellen nach $(basename "$C")/src geladen)" || { bad "Online-Installer"; cat "$C/install.txt"; return; }
  [ -f "$C/src/selfhost.sh" ] && ok "Paket von 'GitHub' entpackt" || bad "Paket nicht entpackt"
  grep -q '^vpn_name = "Potzplitz VPN"' "$C/server.toml" && ok "Name gesetzt: Potzplitz VPN" || bad "Name fehlt"
  grep -A3 'Geraet: Handy' "$C/install.txt" | head -1 >/dev/null; grep -q '^kronevpn://' "$C/install.txt" && ok "Geraet 'Handy' angelegt (Code ausgegeben)" || bad "Geraet nicht angelegt"
  grep -q 'Apps zum Herunterladen: https://198.51.100.1/download/' "$C/install.txt" && ok "Download-Link wird beim Anlegen angezeigt" || bad "kein Download-Link"
  ls "$C/downloads" | tr '\n' '|' | grep -q 'Potzplitz VPN.apk|Potzplitz VPN.exe|potzplitz-vpn-linux|' && ok "Apps mit eigenem Namen: $(ls "$C/downloads" | tr '\n' ',' )" || bad "Downloads: $(ls "$C/downloads")"
  grep '^kronevpn://' "$C/install.txt" | head -1 > "$C/code"
  python3 -c "import sys,json,base64;c=open(sys.argv[1]).read().strip().split('/v1/')[1];j=json.loads(base64.urlsafe_b64decode(c+'='*(-len(c)%4)));sys.exit(0 if j.get('t')=='Potzplitz VPN' else 1)" "$C/code" \
    && ok "Name steckt im Verbindungscode (Apps zeigen ihn an)" || bad "Name nicht im Code"
  bg ns sh-srv "$C/kvpn-server" --config "$C/server.toml" run
  sleep 2
  local R="--resolve 198.51.100.1:443:198.51.100.1"
  ns sh-cli curl -sk -m 5 "https://198.51.100.1/download/" | grep -q 'Potzplitz VPN.exe' && ok "Download-Seite zeigt die Apps" || bad "Download-Seite"
  ns sh-cli curl -sk -m 10 -o "$C/dl.exe" "https://198.51.100.1/download/Potzplitz%20VPN.exe"; cmp -s "$C/dl.exe" "$K/dist/KroneVPN.exe" && ok "EXE-Download bitgenau ($(stat -c%s "$C/dl.exe") Bytes)" || bad "EXE-Download"
  ns sh-cli curl -sk -m 5 -D - -o /dev/null "https://198.51.100.1/download/Potzplitz%20VPN.apk" | grep -qi "filename\*=UTF-8''Potzplitz%20VPN.apk" && ok "APK kommt als 'Potzplitz VPN.apk'" || bad "APK-Dateiname"
  [ "$(ns sh-cli curl -sk -m 5 -o /dev/null -w '%{http_code}' "https://198.51.100.1/download/..%2Fserver.toml")" = 404 ] && ok "kein Zugriff auf andere Dateien (../)" || bad "Pfad-Ausbruch!"
  cmp -s <(ns sh-cli curl -sk -m 5 "https://198.51.100.1/logo") "$K/assets/favicon-64.png" && ok "eigenes Bild wird ausgeliefert" || bad "Bild"
  ns sh-cli curl -sk -m 5 "https://198.51.100.1/download/" | grep -q '<img class="lg" src="logo' && ok "Bild auf der Download-Seite" || bad "Bild fehlt auf Download-Seite"
  [ "$(ns sh-cli curl -sk -m 5 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: image/png' --data-binary @"$K/assets/icon-256.png" https://198.51.100.1/logo)" = 403 ] && ok "Bild-Upload von aussen gesperrt (403)" || bad "Upload von aussen moeglich!"
  # lokale Webseite auf dem Server
  ns sh-srv curl -s -m 5 http://localhost:8180/data.json | grep -q '"name":"Potzplitz VPN"' && ok "lokal http://localhost:8180 ohne Passwort (Name: Potzplitz VPN)" || bad "lokale Seite"
  ns sh-srv curl -s -m 5 http://localhost:8180/ | grep -q 'Eigenes Bild' && ok "lokale Seite hat 'Eigenes Bild'" || bad "Upload-Bereich fehlt"
  ns sh-srv curl -s -m 5 -X POST -H 'Content-Type: image/png' --data-binary @"$K/assets/icon-256.png" http://localhost:8180/logo | grep -q '"ok":true' \
    && cmp -s <(ns sh-srv curl -s -m 5 http://localhost:8180/logo) "$K/assets/icon-256.png" && ok "Bild-Upload lokal: neues Bild aktiv" || bad "lokaler Upload"
  ns sh-srv curl -s -m 5 -X POST -H 'Content-Type: image/svg+xml' --data-binary '<svg onload="alert(1)"/>' http://localhost:8180/logo | grep -q '"ok":false' && ok "SVG/Fremdes wird abgelehnt" || bad "SVG angenommen!"
  [ "$(ns sh-srv curl -s -m 5 -o /dev/null -w '%{http_code}' -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' http://localhost:8180/api/v1/stream)" = 404 ] && ok "kein Tunnel ueber den lokalen Port" || bad "Tunnel lokal offen"
  ns sh-cli "$BIN/kronevpn" --config "$C/code" --test > "$C/test.txt" 2>&1 && grep -q '^Potzplitz VPN – Verbindungstest' "$C/test.txt" && ok "App zeigt den Namen: $(head -1 "$C/test.txt" | cut -c1-60)" || { bad "App/Name"; cat "$C/test.txt"; }
  for n in sh-srv sh-cli; do ip netns pids $n | xargs -r kill 2>/dev/null; done
  for i in $(seq 1 40); do ns sh-srv ss -ltnH '( sport = :443 )' | grep -q . || break; sleep 0.25; done
}

variant A
variant B vpn.example.test
NGX=1 variant C vpn.example.test --hinter-nginx
online
echo
echo "Ergebnis: $PASS bestanden, $FAIL fehlgeschlagen"
[ $FAIL -eq 0 ]
