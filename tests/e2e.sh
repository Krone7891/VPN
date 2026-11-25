#!/bin/bash
# KroneVPN – End-to-End-Test mit simulierter Firmen-Firewall (Netzwerk-Namespaces, echtes nginx mit TLS).
#
#   Client-Netze lassen NUR TCP 443 hinaus (wie eine strenge Sophos-Regel; UDP/WireGuard ist blockiert).
#   Ein Netz erlaubt nur den Firmen-Proxy (HTTP CONNECT), eines geht ueber mitmproxy mit TLS-Aufbruch
#   (simuliert Sophos HTTPS-Inspektion).
#
# Aufruf als root:  bash tests/e2e.sh [pfad/zu/target/release]
set -u
unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy
# WLAN-Ortung: Google Geolocation API und WiGLE werden im Server-Netz nachgebildet (Port 8997)
export KVPN_GOOGLE_URL=http://127.0.0.1:8997/geolocate KVPN_WIGLE_URL=http://127.0.0.1:8997/wigle
# Standard: die ausgelieferten statischen Builds (musl), sonst target/release
R=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "${1:-}" ] && [ -x "$R/target/x86_64-unknown-linux-musl/release/kronevpn" ] && [ -x "$R/target/x86_64-unknown-linux-musl/release/kvpn-server" ]; then
  BIN=$R/target/x86_64-unknown-linux-musl/release
else
  BIN=${1:-$R/target/release}
fi
W=$(mktemp -d /tmp/kvpn-e2e.XXXX)
MITM=${MITM:-/opt/mitm/bin/mitmdump}
NCLI=8
PASS=0; FAIL=0
ok()   { echo "  [OK]     $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FEHLER] $*"; FAIL=$((FAIL+1)); }
ns()   { local n=$1; shift; ip netns exec "$n" "$@"; }

cleanup() {
  for p in $(cat "$W"/pids 2>/dev/null); do kill "$p" 2>/dev/null; done
  sleep 0.5
  for n in kv-srv kv-net $(seq -f "kv-cli%g" 1 9) kv-px kv-mitm; do ip netns del "$n" 2>/dev/null; done
  rm -rf /etc/netns/kv-cli* /etc/netns/kv-px /etc/netns/kv-mitm /etc/netns/kv-srv
}
trap cleanup EXIT
cleanup 2>/dev/null
bg() { local n; if [ "$1" = ns ]; then n="$2-$(basename "$3")"; else n=$(basename "$1"); fi; "$@" >>"$W/log.$n" 2>&1 & echo $! >> "$W/pids"; }

mkdir -p /etc/netns/kv-srv; printf '127.0.0.1 localhost vpn.test\n' > /etc/netns/kv-srv/hosts
echo "== Aufbau: Server, Internet, $NCLI Clients + Proxy-Netz + MITM-Netz  (Arbeitsordner $W)"
ip netns add kv-srv; ip netns add kv-net
ns kv-srv ip link set lo up; ns kv-net ip link set lo up
ip link add s-net type veth peer name n0
ip link set s-net netns kv-srv; ip link set n0 netns kv-net
ns kv-srv ip addr add 10.201.0.1/24 dev s-net; ns kv-srv ip link set s-net up
ns kv-net ip addr add 10.201.0.2/24 dev n0; ns kv-net ip link set n0 up
ns kv-net ip route add default via 10.201.0.1
ns kv-net ip -6 addr add fd00:201::2/64 dev n0 nodad
ns kv-srv ip -6 addr add fd00:201::1/64 dev s-net nodad
ns kv-net ip -6 route add default via fd00:201::1

mkclient() { # name idx
  local n=$1 i=$2
  ip netns add "$n"; ns "$n" ip link set lo up
  ip link add "s$i" type veth peer name c0
  ip link set "s$i" netns kv-srv; ip link set c0 netns "$n"
  ns kv-srv ip addr add "10.200.$i.1/24" dev "s$i"; ns kv-srv ip link set "s$i" up
  ns "$n" ip addr add "10.200.$i.2/24" dev c0; ns "$n" ip link set c0 up
  ns "$n" ip route add default via "10.200.$i.1"
  mkdir -p "/etc/netns/$n"; echo "10.200.$i.1 vpn.test" > "/etc/netns/$n/hosts"; echo "127.0.0.1 localhost" >> "/etc/netns/$n/hosts"
  # Firewall wie Sophos: hinaus nur TCP 443 (+ was durch den Tunnel geht), alles andere verworfen
  local port=${3:-443}
  ns "$n" iptables -P OUTPUT DROP
  ns "$n" iptables -A OUTPUT -o lo -j ACCEPT
  ns "$n" iptables -A OUTPUT -o kvpn-c0 -j ACCEPT
  ns "$n" iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ns "$n" iptables -A OUTPUT -p tcp --dport "$port" -j ACCEPT
  ns "$n" ip6tables -P OUTPUT DROP
  ns "$n" ip6tables -A OUTPUT -o lo -j ACCEPT
  ns "$n" ip6tables -A OUTPUT -o kvpn-c0 -j ACCEPT
  ns "$n" ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}
for i in $(seq 1 9); do mkclient "kv-cli$i" "$i"; done
# Geraet 1 wie ein echter PC: Servername per DNS (nicht hosts-Datei), DNS-Server steht im "Internet". Bei vollem
# Tunnel geht DNS nur durch den Tunnel - beim (Neu-)Verbinden steht der aber nicht (so trat der Windows-Fehler auf).
printf '127.0.0.1 localhost\n' > /etc/netns/kv-cli1/hosts
printf 'nameserver 10.201.0.2\n' > /etc/netns/kv-cli1/resolv.conf
ns kv-cli1 iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
ns kv-srv iptables -A FORWARD -p udp --dport 53 -j ACCEPT
ns kv-srv iptables -A FORWARD -p udp --sport 53 -j ACCEPT
mkclient kv-px 20 3128      # nur der Firmen-Proxy ist erlaubt
mkclient kv-mitm 21 8080    # nur der TLS-aufbrechende Proxy ist erlaubt
ns kv-srv sysctl -qw net.ipv4.ip_forward=1
# Server leitet zwischen Client-Netzen und "Internet" NICHT direkt weiter (nur ueber den Tunnel)
ns kv-srv iptables -P FORWARD DROP

echo "== Dienste: Internet (HTTP, iperf3), nginx TLS 443, kvpn-server, tinyproxy, mitmproxy"
mkdir -p "$W/www"; echo "hallo aus dem internet" > "$W/www/index.html"
bg ns kv-net python3 -m http.server 80 --directory "$W/www"
bg ns kv-net iperf3 -s
bg ns kv-net dnsmasq --no-daemon --no-resolv --no-hosts --listen-address=10.201.0.2 --bind-interfaces --address=/vpn.test/10.200.1.1 --user=root
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=vpn.test" -addext "subjectAltName=DNS:vpn.test" \
  -keyout "$W/key.pem" -out "$W/cert.pem" 2>/dev/null
cat > "$W/nginx.conf" <<EOF
worker_processes 2; pid $W/nginx.pid; error_log $W/nginx-error.log;
events { worker_connections 1024; }
http {
  access_log off;
  client_body_temp_path $W/nb; proxy_temp_path $W/np; fastcgi_temp_path $W/nf; uwsgi_temp_path $W/nu; scgi_temp_path $W/ns;
  server {
    listen 443 ssl; server_name vpn.test;
    ssl_certificate $W/cert.pem; ssl_certificate_key $W/key.pem; ssl_protocols TLSv1.2 TLSv1.3;
$(cat "$(dirname "$0")/../deploy/nginx-selfhost.conf")
    location / { return 200 "normale Webseite\n"; }
  }
}
EOF
ROOTD=$(cd "$(dirname "$0")/.." && pwd)
bg ns kv-srv nginx -c "$W/nginx.conf" -g "daemon off;"

export KVPN_CONFIG=$W/server.toml
"$BIN/kvpn-server" init --url wss://vpn.test/api/v1/stream >/dev/null
sed -i "s#^state_dir = .*#state_dir = \"$W/state\"#" "$W/server.toml"
grep -q '^state_dir' "$W/server.toml" || sed -i "1a state_dir = \"$W/state\"" "$W/server.toml"
for i in $(seq 1 8); do "$BIN/kvpn-server" add "geraet$i" | grep '^kronevpn://' > "$W/code$i"; done
"$BIN/kvpn-server" add "neun" > "$W/add9.txt" 2>&1 && bad "9. Geraet haette abgelehnt werden muessen" || ok "9. Geraet wird abgelehnt (max. 8): $(tail -1 "$W/add9.txt")"
"$BIN/kvpn-server" list | head -3
bg ns kv-srv "$BIN/kvpn-server" run
cat > "$W/tinyproxy.conf" <<EOF
Port 3128
Listen 10.200.20.1
Timeout 600
Allow 10.200.20.0/24
ConnectPort 443
LogLevel Error
PidFile "$W/tinyproxy.pid"
EOF
bg ns kv-srv tinyproxy -d -c "$W/tinyproxy.conf"
# mitmproxy: bricht TLS auf wie Sophos HTTPS-Scanning (eigene CA), Upstream-Zertifikat wird nicht geprueft
bg ns kv-srv env HOME="$W" "$MITM" --mode regular --listen-host 10.200.21.1 --listen-port 8080 --ssl-insecure --set confdir="$W/mitm" -q
sleep 3

echo "== Test 1: ohne VPN ist das Internet gesperrt (Firewall aktiv)"
ns kv-cli1 curl -s -m 3 http://10.201.0.2/ >/dev/null && bad "Firewall laesst HTTP durch" || ok "HTTP ohne VPN blockiert"
ns kv-cli1 curl -sk -m 3 https://vpn.test/ | grep -q "normale Webseite" && ok "HTTPS 443 zum Server erlaubt (normale Webseite)" || bad "HTTPS zum Server geht nicht"

echo "== Test 2: Verbindungstest (--test) und voller Tunnel"
ns kv-cli1 "$BIN/kronevpn" --config "$W/code1" --test > "$W/test1.txt" 2>&1 && ok "Handshake ueber TLS/443: $(grep -o 'Handshake in [0-9]* ms' "$W/test1.txt")" || { bad "Verbindungstest"; cat "$W/test1.txt"; }
# ein Absturz-Protokoll von "frueher" liegt bereit -> geht beim Verbinden an den Server
mkdir -p "$W/absturz"; printf 'KroneVPN PC – Absturz (Rust)\npanicked at Test-Panik\n' > "$W/absturz/1764000001-rust.txt"
bg ns kv-cli1 "$BIN/kronevpn" --config "$W/code1" --kein-update
sleep 6   # Test-DNS beantwortet IPv6-Abfragen nicht -> Client wartet je Abfrage 1,5 s und nimmt dann nur IPv4
ns kv-cli1 ping -c 3 -W 2 10.201.0.2 > "$W/ping1.txt" 2>&1 && ok "ping durch den Tunnel: $(tail -1 "$W/ping1.txt" | cut -d= -f2)" || { bad "ping durch den Tunnel"; cat "$W/ping1.txt"; tail -20 "$W"/log.*; }
[ "$(ns kv-cli1 curl -s -m 5 http://10.201.0.2/)" = "hallo aus dem internet" ] && ok "HTTP durch den Tunnel" || bad "HTTP durch den Tunnel"
if ns kv-cli1 ip -6 addr show dev kvpn-c0 2>/dev/null | grep -q fd77; then
  ns kv-cli1 curl -s -m 5 -g "http://[fd00:201::2]/" | grep -q hallo && ok "IPv6 durch den Tunnel" || bad "IPv6 durch den Tunnel"
else echo "  [--]     IPv6 auf TUN wird von diesem Test-Kernel nicht unterstuetzt (uebersprungen)"; fi
ns kv-cli1 ping -c 1 -W 2 10.77.0.1 >/dev/null && ok "Server im Tunnel erreichbar (10.77.0.1)" || bad "10.77.0.1 nicht erreichbar"

echo "== Test 3: Durchsatz (iperf3, 5 s)"
D=$(ns kv-cli1 iperf3 -c 10.201.0.2 -t 5 -R -J 2>/dev/null | python3 -c 'import json,sys;print(round(json.load(sys.stdin)["end"]["sum_received"]["bits_per_second"]/1e6))' 2>/dev/null)
U=$(ns kv-cli1 iperf3 -c 10.201.0.2 -t 5 -J 2>/dev/null | python3 -c 'import json,sys;print(round(json.load(sys.stdin)["end"]["sum_received"]["bits_per_second"]/1e6))' 2>/dev/null)
P=$(ns kv-cli1 iperf3 -c 10.201.0.2 -t 5 -R -P 4 -J 2>/dev/null | python3 -c 'import json,sys;print(round(json.load(sys.stdin)["end"]["sum_received"]["bits_per_second"]/1e6))' 2>/dev/null)
[ -n "$D" ] && [ -n "$U" ] && ok "Download $D Mbit/s, Upload $U Mbit/s, 4 Streams $P Mbit/s" || bad "iperf3 fehlgeschlagen"

echo "== Test 6: nur Firmen-Proxy erlaubt (HTTP CONNECT, wie Sophos im Proxy-Modus)"
ns kv-px curl -sk -m 3 https://vpn.test/ >/dev/null && bad "direkter Weg im Proxy-Netz offen" || ok "direkter Weg gesperrt"
ns kv-px "$BIN/kronevpn" --config "$W/code2" --proxy 10.200.20.1:3128 --test > "$W/testpx.txt" 2>&1 && ok "ueber Proxy: $(grep -o 'OK .*' "$W/testpx.txt")" || { bad "ueber Proxy"; cat "$W/testpx.txt"; }

echo "== Test 7: TLS-Aufbruch (mitmproxy = Sophos HTTPS-Inspektion)"
ns kv-mitm "$BIN/kronevpn" --config "$W/code3" --proxy 10.200.21.1:8080 --test > "$W/testmitm.txt" 2>&1 && ok "durch TLS-Inspektion: $(grep -o 'TLS-Zertifikat: [^–]*' "$W/testmitm.txt")" || { bad "durch TLS-Inspektion"; cat "$W/testmitm.txt"; tail "$W"/log.kv-srv-env 2>/dev/null; }

echo "== Test 7c: Verschluesselung waehlbar (Auto/AES-256/ChaCha20) + Tarn-Schicht je Verbindung"
CPU_AES=$(grep -qw aes /proc/cpuinfo && echo "AES-256-GCM" || echo "ChaCha20-Poly1305")
# durch den TLS-Aufbruch (Sophos-Inspektion) mit fest gewaehltem ChaCha20
ns kv-mitm "$BIN/kronevpn" --config "$W/code3" --verschluesselung chacha --proxy 10.200.21.1:8080 --test > "$W/testmitm-c.txt" 2>&1 \
  && grep -q "ChaCha20-Poly1305" "$W/testmitm-c.txt" && ok "ChaCha20 + Tarnung durch TLS-Inspektion" || { bad "ChaCha20 durch TLS-Inspektion"; cat "$W/testmitm-c.txt"; }
for wahl in chacha aes auto; do
  case $wahl in chacha) want="ChaCha20-Poly1305";; aes) want="AES-256-GCM";; auto) want=$CPU_AES;; esac
  ns kv-cli1 "$BIN/kronevpn" --config "$W/code1" --verschluesselung $wahl --test > "$W/test-$wahl.txt" 2>&1
  grep -q "Verschluesselung: $want" "$W/test-$wahl.txt" && grep -q "Tarn-Schicht aktiv" "$W/test-$wahl.txt" \
    && ok "Wahl '$wahl' -> $want, Tarn-Schicht aktiv" || { bad "Wahl '$wahl' (erwartet $want)"; cat "$W/test-$wahl.txt"; }
done
[ "$(cat "$W/verschluesselung.txt" 2>/dev/null)" = auto ] && ok "Wahl wird gemerkt (verschluesselung.txt)" || bad "Wahl nicht gespeichert"
# aeltere App (z. B. 1.0.13 ohne Wunschliste/Tarn) muss weiter verbinden koennen, bis sie ihr Update hat
if [ -n "${OLD_CLIENT:-}" ] && [ -x "$OLD_CLIENT" ]; then
  ns kv-cli1 "$OLD_CLIENT" --config "$W/code1" --test > "$W/test-alt.txt" 2>&1 && ok "alte App $("$OLD_CLIENT" --version 2>/dev/null) verbindet weiterhin" || { bad "alte App verbindet nicht mehr"; cat "$W/test-alt.txt"; }
fi

# Nachbildung von Google Geolocation API + WiGLE (protokolliert, was ankommt)
cat > "$W/wlanmock.py" <<'PY'
import http.server, json, sys, base64, urllib.parse
LOG = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def out(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        aps = body.get("wifiAccessPoints", [])
        open(LOG, "a").write("google key=%s aps=%d\n" % (q.get("key", [""])[0], len(aps)))
        if q.get("key", [""])[0] != "TESTKEY" or len(aps) < 2: return self.out(403, {"error": {"code": 403}})
        self.out(200, {"location": {"lat": 52.5163, "lng": 13.3777}, "accuracy": 500})
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        auth = base64.b64decode(self.headers.get("Authorization", "Basic ").split(" ", 1)[1] or b"").decode()
        open(LOG, "a").write("wigle auth=%s netid=%s\n" % (auth, q.get("netid", [""])[0]))
        if auth != "testname:testtoken": return self.out(401, {"success": False})
        self.out(200, {"success": True, "totalResults": 1, "results": [{"trilat": 52.5200, "trilong": 13.4050, "ssid": "Test-WLAN"}]})
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 8997), H).serve_forever()
PY
bg ns kv-srv python3 "$W/wlanmock.py" "$W/wlanmock.log"
"$BIN/kvpn-server" set google_geo_key TESTKEY | grep -q "(eingetragen)" && ! "$BIN/kvpn-server" set wigle_api testname:testtoken | grep -q testtoken \
  && ok "WLAN-Ortung: Zugangsdaten eingetragen (Werte werden nicht ausgegeben)" || bad "Zugangsdaten eintragen"
sleep 2

echo "== Test 7b: Android-Kern (JNI-Bibliothek der APK, Host-Build) mit uebergebenem TUN-fd wie VpnService"
ROOTD=$(cd "$(dirname "$0")/.." && pwd)
# aktuellen Stand des Android-Kerns bauen (sonst wuerde ein alter Build getestet)
export PATH="$PATH:$HOME/.cargo/bin:/root/.cargo/bin${SUDO_USER:+:$(getent passwd "$SUDO_USER" | cut -d: -f6)/.cargo/bin}"
command -v javac >/dev/null && command -v cargo >/dev/null && { bash "$ROOTD/tests/jni/build.sh" >/dev/null 2>&1 || echo "  (JNI-Build fehlgeschlagen)"; }
if [ -f "$ROOTD/target/release/libkronevpn.so" ] && [ -d "$ROOTD/target/jni" ]; then
  ns kv-cli9 python3 "$ROOTD/tests/jni/run_with_tun.py" kvpn-c0 10.77.0.5/24 10.201.0.0/24 \
    java -Djava.library.path="$ROOTD/target/release" -cp "$ROOTD/target/jni" de.krone.vpn.JniTest {fd} "$W/code4" 6 > "$W/jni.txt" 2>&1 &
  for i in $(seq 1 60); do grep -q READY "$W/jni.txt" 2>/dev/null && break; sleep 0.5; done
  grep -q '"state":"connected"' "$W/jni.txt" && ok "JNI: parse/start/status ok, Tunnel verbunden" || { bad "JNI-Start"; cat "$W/jni.txt"; }
  # Admin-Seite: Handy still anpingen und orten (waehrend es verbunden ist)
  R1=$(ns kv-srv curl -s -m 8 -X POST http://127.0.0.1:8180/ping/geraet4)
  echo "$R1" | grep -q '"ok":true' && ok "Handy still angepingt: $R1 (Kern antwortet, keine Anzeige)" || bad "Anpingen: $R1"
  R2=$(ns kv-srv curl -s -m 8 -X POST http://127.0.0.1:8180/orten/geraet4)
  echo "$R2" | grep -q '"ok":true' && ok "Ortung angefordert" || bad "Orten: $R2"
  R3=$(ns kv-srv curl -s -m 8 -X POST http://127.0.0.1:8180/ping/gibtsnicht)
  echo "$R3" | grep -q 'nicht verbunden' && ok "Anpingen eines nicht verbundenen Geraets: klare Meldung" || bad "Anpingen offline: $R3"
  [ "$(ns kv-srv curl -s -m 3 -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8101/ping/geraet4)" = 403 ] && ok "Anpingen/Orten von aussen gesperrt (403)" || bad "Anpingen von aussen moeglich!"
  grep -q 'nach reconnect=.*"connects":2' "$W/jni.txt" && ok "JNI: Netzwechsel -> sofort neu verbunden" || bad "JNI reconnect: $(grep 'nach reconnect' "$W/jni.txt")"
  grep -q '^status=.*"cipher":"ChaCha20-Poly1305"' "$W/jni.txt" && grep -q 'nach reconnect=.*"cipher":"AES-256-GCM"' "$W/jni.txt" \
    && ok "JNI: Verschluesselung in der App umschaltbar (ChaCha20 -> AES-256 beim Neuverbinden)" || bad "JNI Verschluesselung: $(grep -o '"cipher":"[^"]*"' "$W/jni.txt" | tr '\n' ' ')"
  ns kv-cli9 ping -c 3 -W 2 10.201.0.2 > "$W/jniping.txt" 2>&1 && ok "ping durch den Android-Kern: $(tail -1 "$W/jniping.txt" | cut -d= -f2)" || bad "ping durch den Android-Kern"
  for i in $(seq 1 30); do grep -q STOPPED "$W/jni.txt" && break; sleep 0.5; done
  grep -q STOPPED "$W/jni.txt" && ! ns kv-cli9 ip link show kvpn-c0 >/dev/null 2>&1 && ok "JNI: stop schliesst das TUN sauber" || bad "JNI stop: $(tail -3 "$W/jni.txt")"
  grep -q 'parse(falsch)={"error"' "$W/jni.txt" && ok "JNI: ungueltiger Code wird erkannt" || bad "JNI parse"
  grep -q 'vor stop=.*"crash_ok":\["1764000000-java.txt"\]' "$W/jni.txt" && "$BIN/kvpn-server" abstuerze geraet4 | grep -q "Test-Absturz" \
    && ok "Android-Absturz-Protokoll durch den Tunnel im Server-Ordner, App bekam die Bestaetigung" || bad "Absturz-Protokoll (Android): $("$BIN/kvpn-server" abstuerze 2>&1 | tail -3)"
  grep -q 'vor stop=.*"locate":1' "$W/jni.txt" && ok "JNI: Orten-Anfrage kommt in der App an (locate=1 -> frischer GPS-Standort)" || bad "Orten kam nicht an: $(grep -o '"locate":[0-9]*' "$W/jni.txt" | tail -1)"
  ns kv-srv curl -s -m 3 http://127.0.0.1:8180/data.json | python3 -c 'import json,sys;d=json.load(sys.stdin);p=[x for x in d["peers"] if x["name"]=="geraet4"][0];v=p.get("dev") or {};print(v);sys.exit(0 if v.get("ssid")=="Test-WLAN" and abs(v.get("lat",0)-48.1351)<1e-6 and v.get("acc")==18 else 1)' >/dev/null \
    && ok "App meldet WLAN-Name und Standort (freigegeben) -> Admin-Seite zeigt sie" || bad "Standort-Meldung der App fehlt auf der Admin-Seite"
  ns kv-srv curl -s -m 3 http://127.0.0.1:8101/stats/data.json | grep -q 'Test-WLAN' && bad "WLAN/Standort auf der oeffentlichen Statistik!" || ok "oeffentliche Statistik ohne WLAN/Standort"
  ns kv-srv curl -s -m 3 http://127.0.0.1:8180/data.json | python3 -c 'import json,sys;d=json.load(sys.stdin);p=[x for x in d["peers"] if x["name"]=="geraet4"][0];b=p.get("pos") or {};v=p.get("dev") or {};print(b);sys.exit(0 if b.get("src")=="gps" and b.get("acc")==18 and len(v.get("aps",[]))==2 else 1)' > "$W/pos.txt" 2>&1 \
    && ok "bester Standort: GPS des Handys ±18 m (vor IP-Ortung), WLAN-Liste angekommen" || bad "bester Standort: $(cat "$W/pos.txt")"
  ns kv-srv curl -s -m 3 http://127.0.0.1:8101/stats/data.json | grep -q '"pos"' && bad "Standort auf der oeffentlichen Statistik!" || ok "oeffentliche Statistik ohne besten Standort"
  for i in $(seq 1 20); do grep -q "^wigle" "$W/wlanmock.log" 2>/dev/null && break; sleep 0.5; done; sleep 1
  grep -q "^google key=TESTKEY aps=2" "$W/wlanmock.log" && ok "Google Geolocation: Schluessel + 2 WLAN-Netze gesendet" || bad "Google-Abfrage: $(cat "$W/wlanmock.log" 2>/dev/null)"
  grep -q "^wigle auth=testname:testtoken netid=aa:bb:cc:dd:ee:ff" "$W/wlanmock.log" && ok "WiGLE: BSSID mit Zugangsdaten abgefragt (Google war ungenauer)" || bad "WiGLE-Abfrage: $(cat "$W/wlanmock.log" 2>/dev/null)"
  ns kv-srv curl -s -m 3 http://127.0.0.1:8180/data.json | python3 -c 'import json,sys;d=json.load(sys.stdin);p=[x for x in d["peers"] if x["name"]=="geraet4"][0];w=p.get("wlan") or {};print(w);sys.exit(0 if w.get("via")=="WiGLE" and w.get("acc")==120 and abs(w.get("lat",0)-52.52)<1e-6 else 1)' > "$W/wlan.txt" 2>&1 \
    && ok "Admin-Seite: WLAN-Ortung über WiGLE ±120 m" || bad "WLAN-Ortung: $(cat "$W/wlan.txt")"
  ns kv-srv curl -s -m 3 http://127.0.0.1:8180/data.json http://127.0.0.1:8180/settings.json | grep -q -e TESTKEY -e testtoken && bad "Zugangsdaten auf der Webseite sichtbar!" || ok "Zugangsdaten nicht auf der Webseite"
  ns kv-srv curl -s -m 3 http://127.0.0.1:8180/settings.json | grep -q '"google_geo_key":true' && ok "Einstellungen zeigen: Google eingetragen" || bad "settings.json ohne google_geo_key"
  ns kv-srv curl -s -m 3 http://127.0.0.1:8101/stats/data.json | grep -q '"wlan"' && bad "WLAN-Ortung auf der oeffentlichen Statistik!" || ok "oeffentliche Statistik ohne WLAN-Ortung"
  # Bewegungs-Karte: GPS-Meldung + WLAN-Ortung landen im Verlauf
  ns kv-srv curl -s -m 3 "http://127.0.0.1:8180/verlauf.json?geraet=geraet4&tage=1" | python3 -c 'import json,sys;d=json.load(sys.stdin);s=sorted(p["src"] for p in d["punkte"]);print(s);sys.exit(0 if d["ok"] and "gps" in s and "wlan" in s else 1)' > "$W/verlauf.txt" 2>&1 \
    && ok "Standort-Verlauf: $(cat "$W/verlauf.txt") (GPS + WLAN-Ortung)" || bad "Standort-Verlauf: $(cat "$W/verlauf.txt")"
  ns kv-srv curl -s -m 3 "http://127.0.0.1:8180/verlauf.gpx?geraet=geraet4&tage=0" | python3 -c 'import sys,xml.dom.minidom as m;d=m.parseString(sys.stdin.read());sys.exit(0 if len(d.getElementsByTagName("trkpt"))>=2 else 1)' \
    && ok "Verlauf als GPX (gueltiges XML mit Wegpunkten)" || bad "GPX-Export"
  [ "$(ns kv-srv curl -s -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8101/verlauf.json?geraet=geraet4")" = 403 ] && ok "Verlauf von aussen gesperrt (403)" || bad "Verlauf von aussen abrufbar!"
  ns kv-srv curl -s -m 3 http://127.0.0.1:8180/leaflet.js | grep -q 't.version="1.9.4"' && ok "Karten-Bibliothek kommt vom Server selbst (keine fremden Skripte)" || bad "leaflet.js fehlt"
  "$BIN/kvpn-server" orte geraet4 1 | grep -q "Punkte" && ok "kvpn-server orte: $("$BIN/kvpn-server" orte geraet4 1 | tail -1)" || bad "kvpn-server orte"
  if [ -n "${SHOT_DIR:-}" ] && command -v node >/dev/null; then
    mkdir -p "$SHOT_DIR"; cp "$R/tests/shot.js" "$W/shot.js" 2>/dev/null
    ns kv-srv node "$W/shot.js" http://127.0.0.1:8180/ "$SHOT_DIR" geraet4 > "$W/shot.txt" 2>&1 && ok "Bildschirmfotos der Admin-Seite: $SHOT_DIR" || echo "  [--]     Bildschirmfotos: $(tail -2 "$W/shot.txt")"
  fi
else echo "  [--]     JNI-Test uebersprungen (cargo build --release -p kvpn-android und javac fehlen)"; fi

echo "== Test 4: alle 8 Geraete gleichzeitig"
for i in $(seq 2 8); do bg ns "kv-cli$i" "$BIN/kronevpn" --config "$W/code$i" --kein-update; done
sleep 4
n=0; for i in $(seq 1 8); do ns "kv-cli$i" ping -c 2 -W 2 10.201.0.2 >/dev/null 2>&1 && n=$((n+1)); done
[ $n -eq 8 ] && ok "8 von 8 Geraeten gleichzeitig online" || bad "nur $n von 8 Geraeten online"
ns kv-cli2 ping -c 1 -W 2 10.77.0.3 >/dev/null 2>&1 && ok "Geraete erreichen sich untereinander (10.77.0.x)" || bad "Geraete untereinander"
"$BIN/kvpn-server" abstuerze geraet1 | grep -q "Test-Panik" && [ ! -e "$W/absturz/1764000001-rust.txt" ] \
  && ok "PC/Linux-Absturz-Protokoll uebertragen und danach auf dem Geraet geloescht" || bad "Absturz-Protokoll (Linux): $(ls "$W/absturz" 2>&1) / $("$BIN/kvpn-server" abstuerze 2>&1 | tail -2)"
R1=$(ns kv-srv curl -s -m 8 -X POST http://127.0.0.1:8180/ping/geraet2)
echo "$R1" | grep -q '"ok":true' && ok "Linux-App still angepingt: $R1" || bad "Anpingen Linux: $R1"

echo "== Test 5: fremdes Geraet (Schluessel nicht eingetragen) wird abgelehnt"
python3 - "$W/code1" > "$W/code-fremd" <<'PY'
import sys,json,base64,os
c=open(sys.argv[1]).read().strip(); b=c.split("/v1/")[1]; j=json.loads(base64.urlsafe_b64decode(b+"="*(-len(b)%4)))
j["k"]=base64.b64encode(os.urandom(32)).decode()
print("kronevpn://v1/"+base64.urlsafe_b64encode(json.dumps(j).encode()).decode().rstrip("="))
PY
ns kv-cli9 "$BIN/kronevpn" --config "$W/code-fremd" --test > "$W/test9.txt" 2>&1 && bad "fremder Schluessel wurde angenommen" || ok "fremder Schluessel abgelehnt: $(grep -o 'FEHLER.*' "$W/test9.txt" | head -1 | cut -c1-90)"
python3 - "$W/code1" > "$W/code-falsch" <<'PY'
import sys,json,base64,os
c=open(sys.argv[1]).read().strip(); b=c.split("/v1/")[1]; j=json.loads(base64.urlsafe_b64decode(b+"="*(-len(b)%4)))
j["s"]=base64.b64encode(os.urandom(32)).decode()
print("kronevpn://v1/"+base64.urlsafe_b64encode(json.dumps(j).encode()).decode().rstrip("="))
PY
ns kv-cli9 "$BIN/kronevpn" --config "$W/code-falsch" --test > "$W/test9b.txt" 2>&1 && bad "falscher Server-Schluessel angenommen (MITM moeglich!)" || ok "falscher Server-Schluessel (MITM) abgelehnt"
grep -q "kennt dieses Gerät nicht" "$W/test9.txt" && ok "Klartext: $(grep -o 'Der Server kennt[^.]*' "$W/test9.txt" | head -1)" || bad "Klartext fuer abgelehntes Geraet fehlt: $(cat "$W/test9.txt")"
grep -qE "passt nicht zu diesem Server|Schlüssel passen nicht" "$W/test9b.txt" && ok "Klartext bei falschem Server-Schluessel: $(grep -o '\-> .*' "$W/test9b.txt" | head -1 | cut -c1-80)" || bad "Klartext MITM fehlt: $(cat "$W/test9b.txt")"

echo "== Test 8: Statistik"
J=$(ns kv-srv curl -s -m 3 http://127.0.0.1:8101/stats/data.json)
echo "$J" | python3 -c 'import json,sys;d=json.load(sys.stdin);on=[p["name"] for p in d["peers"] if p["online"]];print(len(on),"online:",", ".join(on));m=[p for p in d["peers"] if p["info"]["tls_issuer"] and not p["info"]["tls_trusted"]];sys.exit(0 if len(on)>=8 else 1)' && ok "Statistik zeigt alle Geraete online" || bad "Statistik: $J"
ns kv-srv curl -s -m 3 http://127.0.0.1:8101/gibts/nicht | grep -q "Not Found" && ok "unbekannte Pfade -> 404" || bad "404"
ns kv-srv curl -s -m 3 -H "X-Real-IP: 8.8.8.8" http://127.0.0.1:8101/stats/data.json | grep -q '"login":true' && ok "Statistik von aussen nur mit Passwort" || bad "Statistik von aussen offen"
[ "$(ns kv-cli1 curl -sk -m 3 -o /dev/null -w '%{http_code} %{redirect_url}' https://vpn.test/stats)" = "302 https://vpn.test/vpn-statistik" ] && ok "/stats leitet auf die Statistik (wie die App)" || bad "/stats"
ns kv-cli1 curl -sk -m 3 https://vpn.test/vpn-statistik | grep -q "Statistik" && ok "Statistik-Seite ueber nginx" || bad "Statistik-Seite ueber nginx"
ns kv-cli1 curl -sk -m 3 -H "X-Krone-Auth: homeserver" -H "X-Real-IP: 8.8.8.8" https://vpn.test/vpn-statistik/data.json | grep -q '"peers"' && ok "Statistik ueber nginx (Heimnetz-Client ohne Passwort)" || bad "Statistik-Daten ueber nginx"
ns kv-srv curl -s -m 3 -H "X-Krone-Auth: homeserver" -H "X-Real-IP: 8.8.8.8" http://127.0.0.1:8101/stats/data.json >/dev/null; \
ns kv-cli1 curl -sk -m 3 -H "X-Krone-Auth: homeserver" https://vpn.test/api/v1/stream | grep -q '"peers"' && bad "Kopf ueber Tunnel-Pfad einschleusbar" || ok "Auth-Kopf von aussen nicht einschleusbar"

echo "== Test 9: Server-Neustart -> Geraete verbinden sich selbst neu"
[ "$(ns kv-cli1 ip route get 10.201.0.2 | grep -o 'dev [^ ]*')" = "dev kvpn-c0" ] && ok "Geraet 1: DNS laeuft durch den Tunnel (wie unter Windows)" || bad "Geraet 1: DNS nicht im Tunnel"
# dabei AES-256 und Leistungsmodus einschalten (Standard: beide aus)
"$BIN/kvpn-server" einstellungen --aes256 an --leistung an | grep -q "AES-256 an · Leistungsmodus an" && ok "einstellungen: AES-256 und Leistungsmodus an" || bad "einstellungen"
SL=$(wc -l < "$W/log.kv-srv-kvpn-server")
pkill -f "kvpn-server run"; for i in $(seq 1 20); do pgrep -f "kvpn-server run" >/dev/null || break; sleep 0.5; done
pgrep -f "kvpn-server run" >/dev/null && bad "Server laesst sich nicht beenden" || ok "Server beendet"
bg ns kv-srv "$BIN/kvpn-server" run
sleep 14
n=0; for i in $(seq 1 8); do ns "kv-cli$i" ping -c 2 -W 2 10.201.0.2 >/dev/null 2>&1 && n=$((n+1)); done
[ $n -eq 8 ] && ok "nach Neustart wieder 8 von 8 online" || bad "nach Neustart nur $n von 8"
tail -n +"$SL" "$W/log.kv-srv-kvpn-server" | grep -q "Leistungsmodus an" && ok "Server: $(tail -n +"$SL" "$W/log.kv-srv-kvpn-server" | grep -o '[0-9]* TUN-Queues, [0-9]* Kerne, Leistungsmodus an' | head -1)" || bad "Leistungsmodus nicht aktiv"
# Apps ab 1.1.0 waehlen selbst (Auto = nach Prozessor); hier haben alle denselben Prozessor
A=$(tail -n +"$SL" "$W/log.kv-srv-kvpn-server" | grep -c "verbunden von.*${CPU_AES%%-GCM*}")
[ "$A" -ge 8 ] && ok "alle Geraete mit $CPU_AES verbunden (Auto, $A Verbindungen)" || bad "$CPU_AES: nur $A Verbindungen"
D=$(ns kv-cli1 iperf3 -c 10.201.0.2 -t 4 -R -P 4 -J 2>/dev/null | python3 -c 'import json,sys;print(round(json.load(sys.stdin)["end"]["sum_received"]["bits_per_second"]/1e6))' 2>/dev/null)
[ -n "$D" ] && ok "Durchsatz mit AES-256 + Leistungsmodus: $D Mbit/s (4 Streams)" || bad "iperf3 mit AES-256"

echo "== Test 10: Geraet entfernen -> sofort getrennt"
"$BIN/kvpn-server" remove geraet8 >/dev/null; sleep 5
ns kv-cli8 ping -c 2 -W 2 10.201.0.2 >/dev/null 2>&1 && bad "entferntes Geraet noch verbunden" || ok "entferntes Geraet getrennt"

echo "== Test 10b: Benutzerverwaltung (SQLite): sperren, Benutzer, Ablaufdatum, Verlauf"
waitping() { for i in $(seq 1 "$2"); do ns "$1" ping -c 1 -W 1 10.201.0.2 >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
"$BIN/kvpn-server" benutzer add Tester >/dev/null && "$BIN/kvpn-server" zuordnen geraet7 Tester >/dev/null && "$BIN/kvpn-server" benutzer | grep -q "Tester.*geraet7" && ok "Benutzer angelegt und Geraet zugeordnet" || bad "Benutzer/zuordnen: $("$BIN/kvpn-server" benutzer 2>&1)"
"$BIN/kvpn-server" sperren geraet7 >/dev/null; sleep 4
ns kv-cli7 ping -c 2 -W 2 10.201.0.2 >/dev/null 2>&1 && bad "gesperrtes Geraet noch verbunden" || ok "Geraet gesperrt -> sofort getrennt"
"$BIN/kvpn-server" list | grep -q "geraet7.*gesperrt" && ok "list zeigt 'gesperrt'" || bad "list ohne Sperre"
"$BIN/kvpn-server" entsperren geraet7 >/dev/null
waitping kv-cli7 60 && ok "entsperrt -> verbindet sich wieder" || bad "nach Entsperren nicht wieder verbunden"
"$BIN/kvpn-server" benutzer sperren Tester >/dev/null; sleep 4
ns kv-cli7 ping -c 2 -W 2 10.201.0.2 >/dev/null 2>&1 && bad "Geraet eines gesperrten Benutzers noch verbunden" || ok "Benutzer gesperrt -> seine Geraete getrennt"
"$BIN/kvpn-server" benutzer entsperren Tester >/dev/null
"$BIN/kvpn-server" ablauf geraet7 2001-01-01 >/dev/null; sleep 4
"$BIN/kvpn-server" list | grep -q "geraet7.*abgelaufen" && ok "Ablaufdatum in der Vergangenheit -> abgelaufen" || bad "Ablauf: $("$BIN/kvpn-server" list | grep geraet7)"
"$BIN/kvpn-server" ablauf geraet7 nie >/dev/null
waitping kv-cli7 60 && ok "Ablauf entfernt -> wieder verbunden" || bad "nach Ablauf 'nie' nicht verbunden"
"$BIN/kvpn-server" verlauf geraet7 | grep -q "verbunden von" && "$BIN/kvpn-server" verlauf geraet7 | grep -q "getrennt" && ok "Verlauf: $("$BIN/kvpn-server" verlauf geraet7 | wc -l) Eintraege fuer geraet7" || bad "Verlauf leer"
[ -f "$W/benutzer.db" ] && ! grep -q '^\[\[peer\]\]' "$W/server.toml" && ok "Geraete stehen in benutzer.db (nicht mehr in server.toml)" || bad "benutzer.db fehlt oder Geraete noch in server.toml"

echo "== Test 10c: Admin-Seite im VPN (http://10.77.0.1:8180, Passwort beim ersten Aufruf)"
A=http://10.77.0.1:8180
ns kv-cli1 curl -s -m 5 "$A/" | grep -q "showLogin" && ok "Admin-Seite im VPN erreichbar" || bad "Admin-Seite im VPN nicht erreichbar"
ns kv-cli1 curl -s -m 5 "$A/data.json" | grep -q '"setup":true' && ok "erster Aufruf: Passwort festlegen" || bad "kein Einrichten: $(ns kv-cli1 curl -s -m 5 "$A/data.json")"
ns kv-cli1 curl -s -m 5 "$A/codes" | grep -q '"codes"' && bad "Codes ohne Anmeldung abrufbar!" || ok "ohne Anmeldung keine Codes"
ns kv-cli1 curl -s -m 5 -H 'Content-Type: application/json' -d '{"pw":"kurz"}' "$A/admin-setup" | grep -q '"ok":false' && ok "zu kurzes Passwort abgelehnt" || bad "kurzes Passwort angenommen"
ns kv-cli1 curl -s -m 5 -c "$W/adm1" -H 'Content-Type: application/json' -d '{"pw":"Geheim-1234"}' "$A/admin-setup" | grep -q '"ok":true' && ok "Passwort festgelegt (Browser bleibt angemeldet)" || bad "admin-setup"
grep -q '^admin_password = "pbkdf2-sha256\$' "$W/server.toml" && ! grep -q 'Geheim-1234' "$W/server.toml" && ok "gespeichert nur als PBKDF2-Hash" || bad "Passwort nicht als Hash gespeichert"
ns kv-cli1 curl -s -m 5 -b "$W/adm1" "$A/data.json" | grep -q '"local":true' && ok "angemeldet: volle Admin-Seite (wie localhost)" || bad "nach Festlegen nicht angemeldet"
ns kv-cli2 curl -s -m 5 -H 'Content-Type: application/json' -d '{"pw":"Boese-0000"}' "$A/admin-setup" | grep -q '"ok":true' && bad "Passwort ein zweites Mal festlegbar!" || ok "zweites Festlegen abgelehnt"
ns kv-cli2 curl -s -m 5 -H 'Content-Type: application/json' -d '{"pw":"falsch-123"}' "$A/login" | grep -q '"ok":false' && ok "falsches Passwort abgelehnt" || bad "falsches Passwort angenommen"
ns kv-cli2 curl -s -m 5 -c "$W/adm2" -H 'Content-Type: application/json' -d '{"pw":"Geheim-1234"}' "$A/login" | grep -q '"ok":true' && ns kv-cli2 curl -s -m 5 -b "$W/adm2" "$A/codes" | grep -q '"codes"' \
  && ok "anderes Geraet: mit dem Passwort angemeldet, Codes sichtbar" || bad "Anmeldung vom zweiten Geraet"
ns kv-cli2 curl -s -m 5 -b "$W/adm2" -X POST "$A/max/8" | grep -q '"ok":true' && ok "Admin im VPN darf Einstellungen aendern (Hoechstzahl)" || bad "Admin /max"
ns kv-cli2 curl -s -m 5 -b "$W/adm2" "$A/users.json" | grep -q '"name":"geraet6"' && ok "Webseite: Benutzer- und Geraeteliste" || bad "users.json: $(ns kv-cli2 curl -s -m 5 -b "$W/adm2" "$A/users.json" | head -c 200)"
ns kv-cli2 curl -s -m 5 -H 'Content-Type: application/json' -d '{"kind":"device","name":"geraet6","action":"sperren"}' "$A/manage" | grep -q '"ok":true' && bad "Sperren ohne Anmeldung moeglich!" || ok "Sperren ohne Anmeldung abgelehnt"
ns kv-cli1 curl -sk -m 5 -H 'Content-Type: application/json' -d '{"kind":"device","name":"geraet6","action":"sperren"}' https://vpn.test/manage | grep -q '"ok":true' && bad "Sperren von aussen moeglich!" || ok "Sperren ueber die oeffentliche Seite abgelehnt"
ns kv-cli2 curl -s -m 5 -b "$W/adm2" -H 'Content-Type: application/json' -d '{"kind":"device","name":"geraet6","action":"sperren"}' "$A/manage" | grep -q '"msg":"Gerät .geraet6. gesperrt' && sleep 2 \
  && ! ns kv-cli6 ping -c 2 -W 2 10.201.0.2 >/dev/null 2>&1 && ok "Webseite: Geraet gesperrt -> sofort getrennt" || bad "Webseite sperren"
ns kv-cli2 curl -s -m 5 -b "$W/adm2" -H 'Content-Type: application/json' -d '{"kind":"device","name":"geraet6","action":"entsperren"}' "$A/manage" | grep -q '"ok":true' \
  && waitping kv-cli6 60 && ok "Webseite: entsperrt -> wieder verbunden" || bad "Webseite entsperren"
ns kv-cli2 curl -s -m 5 -b "$W/adm2" -H 'Content-Type: application/json' -d '{"kind":"user","name":"Tester","action":"sperren"}' "$A/manage" | grep -q '"disabled":true' \
  && ns kv-cli2 curl -s -m 5 -b "$W/adm2" -H 'Content-Type: application/json' -d '{"kind":"user","name":"Tester","action":"entsperren"}' "$A/manage" | grep -q '"ok":true' \
  && ok "Webseite: Benutzer sperren und entsperren" || bad "Webseite Benutzer sperren"
# Einstellungen auf der Webseite
SJ() { ns kv-cli2 curl -s -m 8 -b "$W/adm2" -c "$W/adm2" -H 'Content-Type: application/json' -d "$1" "$A/settings"; }
ns kv-cli2 curl -s -m 5 -b "$W/adm2" "$A/settings.json" | grep -q '"users":true' && ok "Webseite: Einstellungen abrufbar" || bad "settings.json: $(ns kv-cli2 curl -s -m 5 -b "$W/adm2" "$A/settings.json" | head -c 200)"
ns kv-cli1 curl -s -m 5 "$A/settings.json" | grep -q '"ok":true' && bad "Einstellungen ohne Anmeldung abrufbar!" || ok "Einstellungen ohne Anmeldung nicht abrufbar"
ns kv-cli1 curl -sk -m 5 -H 'Content-Type: application/json' -d '{"vpn_name":"Boese"}' https://vpn.test/settings | grep -q '"ok":true' && bad "Einstellungen von aussen aenderbar!" || ok "Einstellungen ueber die oeffentliche Seite abgelehnt"
SJ '{"vpn_name":"Test VPN","max_devices":12}' | grep -q '"msg":"Gespeichert: höchstens 12 Geräte · Name' && grep -q '^vpn_name = "Test VPN"' "$W/server.toml" && grep -q '^max_devices = 12' "$W/server.toml" \
  && ok "Webseite: Name und Hoechstzahl gespeichert" || bad "Webseite Name/Hoechstzahl: $(SJ '{}' | head -c 300)"
SJ '{"max_devices":2}' | grep -q '"ok":false' && ok "Webseite: zu kleine Hoechstzahl abgelehnt" || bad "max 2 angenommen"
P0=$(grep -q '^performance = true' "$W/server.toml" && echo true || echo false); P1=$([ $P0 = true ] && echo false || echo true)
SJ "{\"performance\":$P1}" | grep -q '"restart_needed":true' && SJ "{\"performance\":$P0}" | grep -q '"restart_needed":false' \
  && ok "Webseite: Leistungsmodus umgeschaltet -> 'Neustart noetig' wird angezeigt (und wieder weg)" || bad "Webseite Leistungsmodus/Neustart"
ns kv-cli2 curl -s -m 5 -b "$W/adm2" -X POST "$A/restart" | grep -q 'nicht als Dienst' && ok "Neustart ohne systemd/Docker abgelehnt (wuerde nicht wieder starten)" || bad "restart ohne Dienst"
SJ '{"users":false}' | grep -q '"users":false' && grep -q '^\[\[peer\]\]' "$W/server.toml" && sleep 2 && ns kv-cli6 ping -c 2 -W 2 10.201.0.2 >/dev/null 2>&1 \
  && ok "Webseite: Benutzerverwaltung aus -> Geraete wieder in server.toml, bleiben verbunden" || bad "Webseite Benutzerverwaltung aus"
SJ '{"users":true}' | grep -q '"users":true' && ! grep -q '^\[\[peer\]\]' "$W/server.toml" && "$BIN/kvpn-server" benutzer | grep -q Tester \
  && ok "Webseite: Benutzerverwaltung wieder an (Benutzer bleiben erhalten)" || bad "Webseite Benutzerverwaltung an"
SJ '{"admin_password":"kurz"}' | grep -q '"ok":false' && ok "Webseite: zu kurzes Admin-Passwort abgelehnt" || bad "kurzes Admin-Passwort angenommen"
SJ '{"admin_password":"Neues-Geheim-99"}' | grep -q 'bisherige Admin-Passwort' && SJ '{"admin_password":"Neues-Geheim-99","admin_password_old":"falsch-0000"}' | grep -q '"ok":false' \
  && ok "Webseite: Admin-Passwort aendern nur mit dem bisherigen" || bad "Admin-Passwort ohne bisheriges aenderbar!"
# Update-Quelle: nur mit Admin-Passwort
SJ '{"update_repo":"boese/repo"}' | grep -q 'Admin-Passwort falsch' && SJ '{"update_repo":"boese/repo","password":"falsch-0000"}' | grep -q '"ok":false' \
  && grep -q '^update_repo = "Krone7891/VPN"' "$W/server.toml" && ok "Webseite: Update-Quelle ohne/mit falschem Passwort nicht aenderbar" || bad "Update-Quelle ohne Passwort geaendert!"
SJ '{"update_repo":"kein repo","password":"Geheim-1234"}' | grep -q 'kein GitHub-Repo' && ok "Webseite: ungueltiger Repo-Name abgelehnt" || bad "ungueltiges Repo angenommen"
ns kv-cli2 curl -s -m 5 -b "$W/adm2" "$A/settings.json" | grep -q '"update_repo":"Krone7891/VPN"' && ok "Webseite: Update-Quelle wird angezeigt" || bad "settings.json ohne update_repo"
SJ '{"admin_password":"Neues-Geheim-99","admin_password_old":"Geheim-1234"}' | grep -q 'Admin-Passwort geändert' && ns kv-cli2 curl -s -m 5 -b "$W/adm2" "$A/data.json" | grep -q '"local":true' \
  && ! ns kv-cli1 curl -s -m 5 -b "$W/adm1" "$A/data.json" | grep -q '"local":true' && ns kv-cli1 curl -s -m 5 -H 'Content-Type: application/json' -d '{"pw":"Neues-Geheim-99"}' "$A/login" | grep -q '"ok":true' \
  && ok "Webseite: Admin-Passwort geaendert (dieser Browser bleibt angemeldet, andere muessen neu anmelden)" || bad "Webseite Admin-Passwort aendern"
SJ '{"vpn_name":"","max_devices":8}' >/dev/null
# Version auf der Webseite
VER=$(grep -m1 '^version' "$R/Cargo.toml" | cut -d'"' -f2)
SVER=$(grep -m1 '^version' "$R/kvpn-server/Cargo.toml" | cut -d'"' -f2)
[ "$("$BIN/kvpn-server" version)" = "$SVER" ] && ns kv-cli2 curl -s -m 5 -b "$W/adm2" "$A/data.json" | grep -q "\"version\":\"$SVER\"" \
  && ok "Server hat eigene Version $SVER (Apps $VER)" || bad "Server-Version: $("$BIN/kvpn-server" version) statt $SVER"
ns kv-cli2 curl -s -m 5 -b "$W/adm2" "$A/data.json" | grep -q "\"apps\":\"$VER\"" && ok "Webseite: App-Version $VER angezeigt" || bad "data.json ohne App-Version"
ns kv-cli2 curl -s -m 5 -b "$W/adm2" "$A/data.json" | grep -q "\"ver\":\"$VER\"" && ok "Webseite: App-Version je Geraet" || bad "data.json ohne Geraete-Version"
# Standort der Geraete (ungefaehr, aus der IP) – nur auf der Admin-Seite
ns kv-cli2 curl -s -m 5 -b "$W/adm2" "$A/data.json" | grep -q '"geo":{[^}]*"local":true' && ok "Admin-Seite: Standort je Geraet (Testnetz = lokales Netz, ohne Abfrage)" || bad "Admin-Seite ohne Standort"
ns kv-srv curl -s -m 3 http://127.0.0.1:8101/stats/data.json | grep -q '"geo"' && bad "Standort auf der oeffentlichen Statistik!" || ok "oeffentliche Statistik ohne Standort"
SJ '{"geo":false}' | grep -q '"geo":false' && ! ns kv-cli2 curl -s -m 5 -b "$W/adm2" "$A/data.json" | grep -q '"geo":{' && ok "Standort abschaltbar" || bad "Standort aus"
SJ '{"geo":true}' >/dev/null
cat > "$W/geo.py" <<'PY'
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ip = self.path.strip('/').split('?')[0]
        b = json.dumps({"ip": ip, "success": True, "country": "Deutschland", "country_code": "DE", "region": "Bayern", "city": "München",
                        "latitude": 48.1351, "longitude": 11.582, "connection": {"isp": "Deutsche Telekom AG"}}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 8998), H).serve_forever()
PY
bg python3 "$W/geo.py"; sleep 1
KVPN_GEO_URL=http://127.0.0.1:8998 "$BIN/kvpn-server" standort 91.12.3.4 | grep -q "München, Bayern, Deutschland · Deutsche Telekom AG" && ok "kvpn-server standort: $(KVPN_GEO_URL=http://127.0.0.1:8998 "$BIN/kvpn-server" standort 91.12.3.4)" || bad "standort-Abfrage"
"$BIN/kvpn-server" standort 192.168.1.5 | grep -q "lokales" && ok "private Adressen werden nicht nachgefragt" || bad "standort privat"
mkdir -p "$W/dlpage"; echo test > "$W/dlpage/KroneVPN.apk"
"$BIN/kvpn-server" set downloads_dir "$W/dlpage" >/dev/null; sleep 3
ns kv-srv curl -s -m 3 http://127.0.0.1:8180/download/ | grep -q "Version $VER" && ok "Download-Seite zeigt Version $VER" || bad "Download-Seite ohne Version"
"$BIN/kvpn-server" set downloads_dir "" >/dev/null
ns kv-net curl -s -m 3 "http://10.201.0.1:8180/" >/dev/null 2>&1 && bad "Admin-Seite ausserhalb des VPN erreichbar!" || ok "ausserhalb des Tunnels nicht erreichbar"
"$BIN/kvpn-server" admin-passwort --loeschen >/dev/null; sleep 4
ns kv-cli2 curl -s -m 5 -b "$W/adm2" "$A/data.json" | grep -q '"setup":true' && ok "admin-passwort --loeschen: abgemeldet, neu festlegen moeglich" || bad "loeschen"

echo "== Test 11: Verbindungscodes wieder anzeigen"
[ "$("$BIN/kvpn-server" code geraet1 | grep '^kronevpn://')" = "$(cat "$W/code1")" ] && ok "kvpn-server code zeigt den Code wieder (mit QR-Code)" || bad "kvpn-server code"
ns kv-srv curl -s -m 3 http://127.0.0.1:8180/codes > "$W/codes.json"
grep -qF "$(cat "$W/code2")" "$W/codes.json" && grep -q '<svg' "$W/codes.json" && ok "lokale Seite: Codes mit QR-Code" || bad "lokale Seite /codes: $(head -c 200 "$W/codes.json")"
[ "$(ns kv-srv curl -s -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:8101/codes)" = 403 ] && ok "Codes von aussen gesperrt (403)" || bad "Codes von aussen abrufbar"
rm -f "$W"/codes/*.key
"$BIN/kvpn-server" code geraet2 >/dev/null 2>&1 && bad "Code ohne gespeicherten Schluessel?" || ok "alte Geraete ohne gespeicherten Code werden erkannt"
"$BIN/kvpn-server" import "$(cat "$W/code2")" >/dev/null && [ "$("$BIN/kvpn-server" code geraet2 | grep '^kronevpn://')" = "$(cat "$W/code2")" ] && ok "Code vom Geraet uebernommen (import) und wieder anzeigbar" || bad "import"
"$BIN/kvpn-server" import "$(cat "$W/code-fremd")" >/dev/null 2>&1 && bad "fremder Code importiert" || ok "fremder Code wird beim Import abgelehnt"

echo "== Test 11b: Hoechstzahl der Geraete einstellbar"
"$BIN/kvpn-server" max 3 > "$W/max3.txt" 2>&1 && bad "max 3 bei 7 Geraeten haette abgelehnt werden muessen" || ok "max unter Geraeteanzahl abgelehnt: $(tail -1 "$W/max3.txt")"
[ "$(ns kv-srv curl -s -m 3 -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8101/max/20)" = 403 ] && ok "Hoechstzahl von aussen nicht aenderbar (403)" || bad "Hoechstzahl von aussen aenderbar"
ns kv-srv curl -s -m 3 -X POST http://127.0.0.1:8180/max/9 | grep -q '"ok":true' && ok "lokale Seite: Hoechstzahl auf 9 gesetzt" || bad "lokale Seite /max/9"
"$BIN/kvpn-server" add "neun" >/dev/null 2>&1 && "$BIN/kvpn-server" add "zehn" >/dev/null 2>&1 && ok "mit max 9: weitere Geraete angelegt (9 von 9)" || bad "Geraete trotz max 9 abgelehnt"
"$BIN/kvpn-server" add "elf" > "$W/add11.txt" 2>&1 && bad "10. Geraet trotz max 9 angelegt" || ok "10. Geraet abgelehnt: $(tail -1 "$W/add11.txt")"
"$BIN/kvpn-server" max 300 >/dev/null 2>&1 && bad "max 300 angenommen" || ok "max ueber der Grenze abgelehnt"
"$BIN/kvpn-server" remove neun >/dev/null; "$BIN/kvpn-server" remove zehn >/dev/null
"$BIN/kvpn-server" max 8 | grep -q "hoechstens 8" && ok "zurueck auf max 8" || bad "max 8"
# ab 1.1.0 zeigen die Apps den Code nicht mehr an (nur noch der Server bei "add"/"code")
"$BIN/kronevpn" --config "$W/code3" --code < /dev/null > "$W/code-app.txt" 2>&1; rc=$?
[ $rc -ne 0 ] && ! grep -q '^kronevpn://' "$W/code-app.txt" && ok "PC-App zeigt keinen Code mehr an (--code unbekannt)" || bad "PC-App zeigt den Code noch an"

echo "== Test 12: App-Update nur von GitHub und erst nach Freigabe auf dem Server"
KEY=${KVPN_UPDATE_KEY:-$HOME/.kronevpn/update-ed25519.pk8}
if [ -f "$KEY" ]; then
  G=$W/gh; mkdir -p "$G/dist" "$W/upd"
  printf '#!/bin/sh\necho "NEUE VERSION $*" > %s/updated.txt\nexec sleep 600\n' "$W" > "$G/dist/kronevpn-linux"; chmod +x "$G/dist/kronevpn-linux"
  KVPN_UPDATE_VERSION=99.0.0 "$BIN/kvpn-server" update-sign "$KEY" "$G/dist" >/dev/null
  bg python3 -m http.server 8999 --bind 127.0.0.1 --directory "$G"      # steht hier fuer raw.githubusercontent.com
  export KVPN_UPDATE_URL=http://127.0.0.1:8999
  sleep 1
  pkill -f "code7 --kein-update"; sleep 1
  cp "$BIN/kronevpn" "$W/upd/kronevpn"
  bg ns kv-cli7 "$W/upd/kronevpn" --config "$W/code7"
  sleep 5
  ns kv-cli7 ping -c 1 -W 2 10.201.0.2 >/dev/null 2>&1 && [ ! -f "$W/updated.txt" ] && ok "Geraet verbunden, ohne Freigabe kein Update" || bad "Update ohne Freigabe?"
  echo n | "$BIN/kvpn-server" update > "$W/upd-n.txt" 2>&1
  grep -q "Version 99.0.0" "$W/upd-n.txt" && grep -q "Nicht verteilt" "$W/upd-n.txt" && ok "kvpn-server update zeigt 99.0.0 und wartet auf Bestaetigung" || bad "update (nein): $(cat "$W/upd-n.txt")"
  sleep 4; [ ! -f "$W/updated.txt" ] && ok "abgelehnt -> nichts verteilt" || bad "trotz Ablehnung verteilt"
  cp "$G/dist/update.json" "$W/uj"; sed -i 's/99.0.0/99.0.1/' "$G/dist/update.json"
  "$BIN/kvpn-server" update --ja > "$W/upd-f.txt" 2>&1 && bad "gefaelschte Liste angenommen" || ok "gefaelschte Liste abgelehnt: $(grep -o 'Signatur[^–]*' "$W/upd-f.txt" | head -1)"
  echo Neues-Geheim-99 | "$BIN/kvpn-server" update-quelle test/neu main > "$W/quelle-f.txt" 2>&1 && bad "Update-Quelle mit gefaelschter Liste angenommen" \
    || { grep -q "nicht mit dem Update-Schlüssel" "$W/quelle-f.txt" && ok "Update-Quelle: Repo ohne gueltige Signatur abgelehnt" || bad "quelle-f: $(cat "$W/quelle-f.txt")"; }
  cp "$W/uj" "$G/dist/update.json"
  # Update-Quelle aendern: nur mit Admin-Passwort, das neue Repo muss eine gueltig signierte Liste haben
  # (ohne festgelegtes Passwort geht es auf der Kommandozeile – Einrichtung; Test 10c hat es geloescht)
  "$BIN/kvpn-server" admin-passwort Neues-Geheim-99 >/dev/null
  echo falsch-0000 | "$BIN/kvpn-server" update-quelle test/neu main > "$W/quelle1.txt" 2>&1 && bad "Update-Quelle mit falschem Passwort geaendert!" \
    || { grep -q '^update_repo = "Krone7891/VPN"' "$W/server.toml" && ok "Update-Quelle: falsches Passwort abgelehnt" || bad "quelle1: $(cat "$W/quelle1.txt")"; }
  echo falsch-0000 | "$BIN/kvpn-server" set update_repo test/neu > /dev/null 2>&1 && bad "set update_repo ohne Passwort!" || ok "set update_repo braucht ebenfalls das Passwort"
  echo Neues-Geheim-99 | "$BIN/kvpn-server" update-quelle test/neu main > "$W/quelle2.txt" 2>&1 && grep -q '^update_repo = "test/neu"' "$W/server.toml" && grep -q "gültig signiert" "$W/quelle2.txt" \
    && ok "Update-Quelle geaendert: $(grep -o 'Update-Quelle jetzt[^–]*' "$W/quelle2.txt")" || bad "quelle2: $(cat "$W/quelle2.txt")"
  "$BIN/kvpn-server" update-quelle | grep -q "github.com/test/neu" && ok "kvpn-server update-quelle zeigt die neue Quelle" || bad "update-quelle Anzeige"
  echo Neues-Geheim-99 | "$BIN/kvpn-server" update-quelle Krone7891/VPN main >/dev/null 2>&1 && grep -q '^update_repo = "Krone7891/VPN"' "$W/server.toml" && ok "Update-Quelle zurueckgestellt" || bad "Update-Quelle zurueck"
  mkdir -p "$W/mirror/dl"; echo alt > "$W/mirror/dl/Mein VPN-linux"; echo '{}' > "$W/mirror/files.json"
  "$BIN/kvpn-server" set download_mirror "$W/mirror/dl" >/dev/null
  "$BIN/kvpn-server" update --ja > "$W/upd-y.txt" 2>&1 && ok "Freigabe: $(grep -o 'Version 99.0.0 ist freigegeben' "$W/upd-y.txt")" || bad "Freigabe: $(cat "$W/upd-y.txt")"
  for i in $(seq 1 30); do [ -f "$W/updated.txt" ] && break; sleep 1; done
  [ -f "$W/updated.txt" ] && ok "Geraet hat das Update ueber den Tunnel geladen, geprueft und sich neu gestartet ($(cat "$W/updated.txt"))" || { bad "Update kam nicht an"; tail -5 "$W/log.kv-cli7-kronevpn"; grep -i update "$W/log.kv-srv-kvpn-server" | tail -5; }
  cmp -s "$W/upd/kronevpn" "$G/dist/kronevpn-linux" && ok "Programmdatei ersetzt" || bad "Programmdatei nicht ersetzt"
  cmp -s "$W/mirror/dl/Mein VPN-linux" "$G/dist/kronevpn-linux" && grep -q '"version": "99.0.0"' "$W/mirror/files.json" && ok "Download-Seite bei der Freigabe mit erneuert (auch umbenannte Datei, files.json)" || bad "Download-Seite nicht erneuert: $(ls "$W/mirror/dl") $(cat "$W/mirror/files.json")"
  grep -q "Update 99.0.0 uebertragen" "$W/log.kv-srv-kvpn-server" && ok "Server: $(grep -o 'App-Update 99.0.0 freigegeben.*' "$W/log.kv-srv-kvpn-server" | head -1)" || bad "Server-Log ohne Uebertragung"
  ! grep -q "NEUE VERSION" "$W"/log.kv-cli1-kronevpn 2>/dev/null && ok "Geraete mit --kein-update bleiben unveraendert" || bad "--kein-update ignoriert"
  # Android-Kern (wie die App): Update ueber den Tunnel laden und als update.apk ablegen
  if [ -f "$ROOTD/target/release/libkronevpn.so" ] && [ -d "$ROOTD/target/jni" ]; then
    "$BIN/kvpn-server" add "jni-handy" | grep '^kronevpn://' > "$W/code-jni"
    sleep 4   # Server uebernimmt das neue Geraet
    mkdir -p "$W/jniupd"
    ns kv-cli9 python3 "$ROOTD/tests/jni/run_with_tun.py" kvpn-c0 10.77.0.20/24 10.201.0.0/24 \
      java -Djava.library.path="$ROOTD/target/release" -cp "$ROOTD/target/jni" de.krone.vpn.JniTest {fd} "$W/code-jni" 2 "$W/jniupd" > "$W/jniupd.txt" 2>&1
    grep -q '"update_version":"99.0.0"' "$W/jniupd.txt" && cmp -s "$W/jniupd/update.apk" "$G/dist/kronevpn-linux" \
      && ok "Android-Kern: Update 99.0.0 ueber den Tunnel geladen, geprueft und als update.apk abgelegt (wie in der App)" \
      || bad "Android-Kern Update: $(grep -o 'UPDATE=.*' "$W/jniupd.txt" | cut -c1-300)"
    ns kv-srv "$BIN/kvpn-server" status > "$W/status.txt" 2>&1
    grep -q "jni-handy.*99.0.0 uebertragen" "$W/status.txt" && ok "kvpn-server status zeigt: $(grep jni-handy "$W/status.txt" | sed 's/  */ /g')" || bad "status: $(cat "$W/status.txt")"
    "$BIN/kvpn-server" remove jni-handy >/dev/null
  fi
  unset KVPN_UPDATE_URL
else
  echo "  (uebersprungen: kein Signier-Schluessel $KEY)"
fi

echo "== Test 13: eigenes Logo vom Server in den Apps (kommt durch den Tunnel)"
python3 - "$W/logo-test.png" <<'PY'
import struct, sys, zlib
w, h = 300, 180
raw = b"".join(b"\x00" + b"".join(bytes([(x * 255) // w, (y * 255) // h, 160, 255]) for x in range(w)) for y in range(h))
chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
open(sys.argv[1], "wb").write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
PY
"$BIN/kvpn-server" logo "$W/logo-test.png" > "$W/logo.txt" 2>&1 && [ -s "$W/state/app-logo/logo.id" ] && python3 -c "import struct,sys;d=open(sys.argv[1],'rb').read();sys.exit(0 if struct.unpack('>II',d[16:24])==(256,256) else 1)" "$W/state/app-logo/logo.png" \
  && ok "Logo hochgeladen -> App-Logo 256x256 erzeugt" || bad "App-Logo: $(cat "$W/logo.txt")"
mkdir -p "$W/lg"; "$BIN/kvpn-server" add "logo-geraet" | grep '^kronevpn://' > "$W/lg/code"; sleep 4
bg ns kv-cli9 "$BIN/kronevpn" --config "$W/lg/code" --kein-update
for i in $(seq 1 25); do [ "$(cat "$W/lg/logo/logo.id" 2>/dev/null)" = "$(cat "$W/state/app-logo/logo.id")" ] && break; sleep 1; done
[ "$(cat "$W/lg/logo/logo.id" 2>/dev/null)" = "$(cat "$W/state/app-logo/logo.id")" ] && cmp -s "$W/lg/logo/logo.png" "$W/state/app-logo/logo.png" \
  && ok "Geraet hat das Logo durch den Tunnel geholt ($(stat -c %s "$W/lg/logo/logo.png") Bytes, Kennung passt)" || bad "Logo kam nicht an: $(ls -la "$W/lg" "$W/lg/logo" 2>&1 | tail -4)"
grep -q "logo-geraet: Logo uebertragen" "$W/log.kv-srv-kvpn-server" && ok "Server: Logo uebertragen" || bad "Server-Log ohne Logo"
"$BIN/kvpn-server" logo --entfernen >/dev/null; pkill -f "lg/code --kein-update"; sleep 1
bg ns kv-cli9 "$BIN/kronevpn" --config "$W/lg/code" --kein-update
for i in $(seq 1 20); do [ ! -f "$W/lg/logo/logo.id" ] && break; sleep 1; done
[ ! -f "$W/lg/logo/logo.id" ] && [ ! -f "$W/lg/logo/logo.png" ] && ok "Logo auf dem Server entfernt -> App nimmt wieder die Krone" || bad "Logo nicht entfernt"
pkill -f "lg/code --kein-update"; "$BIN/kvpn-server" remove logo-geraet >/dev/null

echo
grep -h "verbunden von\|abgelehnt\|Inspektion" "$W"/log.kv-srv-kvpn-server 2>/dev/null | tail -5
[ -n "${HOOK:-}" ] && W="$W" bash -c "$HOOK"
echo
echo "Ergebnis: $PASS bestanden, $FAIL fehlgeschlagen"
[ $FAIL -eq 0 ]
