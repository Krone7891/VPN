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
BIN=${1:-$(cd "$(dirname "$0")/.." && pwd)/target/release}
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
bg ns kv-cli1 "$BIN/kronevpn" --config "$W/code1"
sleep 3
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

echo "== Test 7b: Android-Kern (JNI-Bibliothek der APK, Host-Build) mit uebergebenem TUN-fd wie VpnService"
ROOTD=$(cd "$(dirname "$0")/.." && pwd)
if [ -f "$ROOTD/target/release/libkronevpn.so" ] && [ -d "$ROOTD/target/jni" ]; then
  ns kv-cli9 python3 "$ROOTD/tests/jni/run_with_tun.py" kvpn-c0 10.77.0.5/24 10.201.0.0/24 \
    java -Djava.library.path="$ROOTD/target/release" -cp "$ROOTD/target/jni" de.krone.vpn.JniTest {fd} "$W/code4" 6 > "$W/jni.txt" 2>&1 &
  for i in $(seq 1 60); do grep -q READY "$W/jni.txt" 2>/dev/null && break; sleep 0.5; done
  grep -q '"state":"connected"' "$W/jni.txt" && ok "JNI: parse/start/status ok, Tunnel verbunden" || { bad "JNI-Start"; cat "$W/jni.txt"; }
  grep -q 'nach reconnect=.*"connects":2' "$W/jni.txt" && ok "JNI: Netzwechsel -> sofort neu verbunden" || bad "JNI reconnect: $(grep 'nach reconnect' "$W/jni.txt")"
  ns kv-cli9 ping -c 3 -W 2 10.201.0.2 > "$W/jniping.txt" 2>&1 && ok "ping durch den Android-Kern: $(tail -1 "$W/jniping.txt" | cut -d= -f2)" || bad "ping durch den Android-Kern"
  for i in $(seq 1 30); do grep -q STOPPED "$W/jni.txt" && break; sleep 0.5; done
  grep -q STOPPED "$W/jni.txt" && ! ns kv-cli9 ip link show kvpn-c0 >/dev/null 2>&1 && ok "JNI: stop schliesst das TUN sauber" || bad "JNI stop: $(tail -3 "$W/jni.txt")"
  grep -q 'parse(falsch)={"error"' "$W/jni.txt" && ok "JNI: ungueltiger Code wird erkannt" || bad "JNI parse"
else echo "  [--]     JNI-Test uebersprungen (cargo build --release -p kvpn-android und javac fehlen)"; fi

echo "== Test 4: alle 8 Geraete gleichzeitig"
for i in $(seq 2 8); do bg ns "kv-cli$i" "$BIN/kronevpn" --config "$W/code$i"; done
sleep 4
n=0; for i in $(seq 1 8); do ns "kv-cli$i" ping -c 2 -W 2 10.201.0.2 >/dev/null 2>&1 && n=$((n+1)); done
[ $n -eq 8 ] && ok "8 von 8 Geraeten gleichzeitig online" || bad "nur $n von 8 Geraeten online"
ns kv-cli2 ping -c 1 -W 2 10.77.0.3 >/dev/null 2>&1 && ok "Geraete erreichen sich untereinander (10.77.0.x)" || bad "Geraete untereinander"

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
kill "$(pgrep -f "kvpn-server run" | head -1)"; sleep 1
bg ns kv-srv "$BIN/kvpn-server" run
sleep 14
n=0; for i in $(seq 1 8); do ns "kv-cli$i" ping -c 2 -W 2 10.201.0.2 >/dev/null 2>&1 && n=$((n+1)); done
[ $n -eq 8 ] && ok "nach Neustart wieder 8 von 8 online" || bad "nach Neustart nur $n von 8"

echo "== Test 10: Geraet entfernen -> sofort getrennt"
"$BIN/kvpn-server" remove geraet8 >/dev/null; sleep 5
ns kv-cli8 ping -c 2 -W 2 10.201.0.2 >/dev/null 2>&1 && bad "entferntes Geraet noch verbunden" || ok "entferntes Geraet getrennt"

echo
grep -h "verbunden von\|abgelehnt\|Inspektion" "$W"/log.kv-srv-kvpn-server 2>/dev/null | tail -5
[ -n "${HOOK:-}" ] && W="$W" bash -c "$HOOK"
echo
echo "Ergebnis: $PASS bestanden, $FAIL fehlgeschlagen"
[ $FAIL -eq 0 ]
