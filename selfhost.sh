#!/bin/bash
# VPN-Server (KroneVPN) auf einem eigenen Linux-Server einrichten oder aktualisieren (als root).
# Einfacher geht es mit install.sh (laedt alles von GitHub und fragt nach Name und Domain).
#
#   bash selfhost.sh vpn.meine-domain.de --name "Potzplitz VPN"
#                                            mit Domain: Let's-Encrypt-Zertifikat, Server direkt auf Port 443
#   bash selfhost.sh --name "Potzplitz VPN"  ohne Domain: eigenes Zertifikat, Adresse = oeffentliche IP
#   ... --bild logo.png                     eigenes Bild (Datei oder https-Adresse) fuer Download- und Statistik-Seite
#   bash selfhost.sh vpn.meine-domain.de --hinter-nginx
#                                            es laeuft schon ein Webserver auf 443: VPN lauscht intern,
#                                            der nginx-Ausschnitt wird angezeigt
#   ... --docker                             Server als Docker-Compose-Container statt systemd-Dienst
#   ... --systemd                            zurueck von Docker zum systemd-Dienst
#   ... --benutzer an|aus  --aes256 an|aus  --leistung an|aus  --max <anzahl>
#                                            Einstellungen (Standard: Benutzerverwaltung an, AES-256 aus,
#                                            Leistungsmodus aus, 8 Geraete). Ohne diese Schalter wird im Terminal
#                                            jedes Mal gefragt (Enter = so lassen); --ja = nicht fragen.
#                                            Spaeter auch einzeln: kvpn-server einstellungen
#
# Danach Geraete anlegen:  kvpn-server add "Mein Handy"   (zeigt QR-Code und Verbindungscode)
# Lokale Webseite (Statistik, Downloads) auf dem Server:  http://localhost:8180
# Mehrfach aufrufen = aktualisieren (Schluessel und Geraete bleiben erhalten).
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
DOMAIN=""; NGINX=0; NAME=""; BILD=""; MODE=""; SETS=(); ASK=""; YES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --hinter-nginx|--behind-nginx) NGINX=1 ;;
    --docker) MODE=docker ;;
    --systemd) MODE=systemd ;;
    --name) NAME=${2:-}; shift ;;
    --name=*) NAME=${1#--name=} ;;
    --bild|--logo) BILD=${2:-}; shift ;;
    --bild=*|--logo=*) BILD=${1#*=} ;;
    --benutzer|--aes256|--leistung|--admin-vpn|--max) SETS+=("$1" "${2:-}"); shift ;;
    --einstellungen) ASK=1 ;;
    --ja|-y|--yes) YES=1 ;;
    -h|--help) sed -n 2,22p "$0"; exit 0 ;;
    -*) echo "Unbekannte Option: $1"; exit 2 ;;
    *) DOMAIN=$1 ;;
  esac
  shift
done
CFG=${KVPN_CONFIG:-/etc/krone-vpn/server.toml}
DL=${KVPN_DOWNLOADS:-/var/lib/krone-vpn/downloads}
TEST=${KVPN_TEST:-}                          # nur fuer automatische Tests: kein systemd/certbot/Firewall
[ -n "$TEST" ] || [ "$(id -u)" = 0 ] || { echo "Bitte als root starten (sudo bash selfhost.sh ...)"; exit 1; }
say() { echo; echo "== $*"; }
# kurze Erklaerung zu jedem Schritt (grau)
erkl() { printf '   \033[2m%s\033[0m\n' "$@"; }
ETC=$(dirname "$CFG")
# Aktualisieren: bisherige Einrichtung beibehalten (Domain, hinter nginx, Docker), wenn nichts anderes angegeben ist
if [ -f "$CFG" ]; then
  OLDHOST=$(sed -n 's#^public_url = "wss://\[\{0,1\}\([^]/"]*\)\]\{0,1\}/.*#\1#p' "$CFG")
  if [ -z "$DOMAIN" ] && [ -n "$OLDHOST" ] && ! [[ "$OLDHOST" =~ ^[0-9.:]+$ ]]; then DOMAIN=$OLDHOST; fi
  if [ "$NGINX" = 0 ] && grep -q '^listen = "127\.0\.0\.1:' "$CFG" && grep -q '^tls_cert = ""' "$CFG"; then NGINX=1; fi
fi
if [ -z "$MODE" ]; then [ -f "$ETC/.docker" ] && MODE=docker || MODE=systemd; fi
RESTART="systemctl restart krone-vpn"; [ "$MODE" = docker ] && RESTART="docker restart krone-vpn"

say "1/6 Programm kvpn-server"
erkl "Der VPN-Server selbst (ein einziges Programm, nach /usr/local/bin). Dazu kvpn-update zum Aktualisieren."
ARCH=$(uname -m)
if [ "$ARCH" = x86_64 ] && [ -x dist/kvpn-server ] && [ -z "${KVPN_BUILD:-}" ]; then
  BIN=dist/kvpn-server; echo "   fertige Datei (statisch, laeuft auf jedem x86_64-Linux)"
else
  export PATH="$HOME/.cargo/bin:$PATH"
  command -v cargo >/dev/null || { echo "   $ARCH: bitte Rust installieren (https://rustup.rs), dann erneut starten"; exit 1; }
  nice -n 19 cargo build --release -p kvpn-server; BIN=target/release/kvpn-server
fi
DEST=${KVPN_BIN:-/usr/local/bin/kvpn-server}
install -m 755 "$BIN" "$DEST.new" && mv -f "$DEST.new" "$DEST"
K() { "$DEST" --config "$CFG" "$@"; }
sed "s#@REPO@#${KVPN_REPO:-Krone7891/VPN}#" deploy/kvpn-update > "$(dirname "$DEST")/kvpn-update"; chmod 755 "$(dirname "$DEST")/kvpn-update"
echo "   $DEST $("$DEST" version)"

say "2/6 Adresse und Zertifikat"
erkl "Unter dieser Adresse finden die Apps den Server. Das Zertifikat macht die Verbindung zu normalem HTTPS;" "zusaetzlich pruefen die Apps den Server ueber seinen eigenen Schluessel (sicher auch ohne Let's Encrypt)."
if [ -z "$DOMAIN" ]; then
  if [ -f "$CFG" ] && [ -z "${KVPN_PUBLIC_IP:-}" ]; then
    HOST=$(sed -n 's#^public_url = "wss://\[\{0,1\}\([^]/"]*\)\]\{0,1\}/.*#\1#p' "$CFG")
  fi
  HOST=${HOST:-${KVPN_PUBLIC_IP:-$(curl -4 -s -m 8 https://api.ipify.org || true)}}
  [ -n "$HOST" ] || { echo "   Oeffentliche IP nicht ermittelbar – bitte Domain oder IP angeben: bash selfhost.sh <adresse>"; exit 1; }
  echo "   keine Domain angegeben -> $HOST"
else
  HOST=$DOMAIN
fi
CERTDIR=$(dirname "$CFG")/tls
CERT=""; KEY=""
if [ "$NGINX" = 0 ]; then
  if [ -n "$DOMAIN" ] && ! [[ "$DOMAIN" =~ ^[0-9.:]+$ ]] && [ -z "$TEST" ]; then
    command -v certbot >/dev/null || { apt-get update -qq && apt-get install -y -qq certbot >/dev/null; } || true
    if command -v certbot >/dev/null && certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email \
         --keep-until-expiring -d "$DOMAIN" --deploy-hook "$RESTART" >/dev/null 2>&1; then
      CERT=/etc/letsencrypt/live/$DOMAIN/fullchain.pem; KEY=/etc/letsencrypt/live/$DOMAIN/privkey.pem
      echo "   Let's-Encrypt-Zertifikat fuer $DOMAIN (verlaengert sich automatisch)"
    else
      echo "   Let's Encrypt ging nicht (Port 80 frei? Domain zeigt auf diesen Server?) – nehme eigenes Zertifikat"
    fi
  fi
  if [ -z "$CERT" ]; then
    mkdir -p "$CERTDIR"; chmod 700 "$CERTDIR"
    CERT=$CERTDIR/cert.pem; KEY=$CERTDIR/key.pem
    if [ ! -f "$CERT" ] || ! openssl x509 -in "$CERT" -noout -ext subjectAltName 2>/dev/null | grep -q "$HOST"; then
      SAN="DNS:$HOST"; [[ "$HOST" =~ ^[0-9.]+$|: ]] && SAN="IP:$HOST"
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 -subj "/CN=$HOST" \
        -addext "subjectAltName=$SAN" -keyout "$KEY" -out "$CERT" 2>/dev/null
      chmod 600 "$KEY"
    fi
    echo "   eigenes Zertifikat ($CERT) – sicher, weil die Apps den Server per Schluessel pruefen."
    echo "   Hinweis: Firewalls, die ungueltige Zertifikate sperren, lassen nur ein echtes Zertifikat durch (Domain angeben)."
  fi
fi

say "3/6 Konfiguration $CFG"
erkl "Schluessel des Servers, Name, Adressen und Einstellungen (nur fuer root lesbar). Bei einem Update bleibt alles."
URLHOST=$HOST; [[ "$HOST" == *:* ]] && URLHOST="[$HOST]"
URL="wss://$URLHOST/api/v1/stream"
if [ -f "$CFG" ]; then
  echo "   vorhanden – Schluessel und Geraete bleiben"
else
  K init --url "$URL" >/dev/null
fi
if [ "$NGINX" = 1 ]; then
  PORT=18101
  while ss -ltnH "( sport = :$PORT )" 2>/dev/null | grep -q .; do PORT=$((PORT+1)); done
  LISTEN="127.0.0.1:$PORT"; CERT=""; KEY=""
else
  LISTEN=${KVPN_LISTEN:-0.0.0.0:443}
fi
K set public_url "$URL" >/dev/null
K set listen "$LISTEN" >/dev/null
K set tls_cert "$CERT" >/dev/null
K set tls_key "$KEY" >/dev/null
[ -n "$NAME" ] && K set vpn_name "$NAME" >/dev/null
# eigenes Update-Repo (Einrichtung; ist schon ein Admin-Passwort festgelegt, geht das nur mit: kvpn-server update-quelle)
[ -n "${KVPN_REPO:-}" ] && { K update-quelle "$KVPN_REPO" "${KVPN_REPO_BRANCH:-main}" --ohne-pruefung </dev/null >/dev/null 2>&1 || echo "   Update-Repo nicht geaendert (Admin-Passwort noetig): kvpn-server update-quelle $KVPN_REPO"; }
NAME=$(sed -n 's/^vpn_name = "\(.*\)"/\1/p' "$CFG"); NAME=${NAME:-KroneVPN}
PWF=$(dirname "$CFG")/statistik-passwort.txt
if ! grep -q '^stats_password = "..*"' "$CFG"; then
  PW=$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 14)
  K set stats_password "$PW" >/dev/null
  echo "$PW" > "$PWF"; chmod 600 "$PWF"
fi
LOCAL=$(sed -n 's/^local_listen = "\(.*\)"/\1/p' "$CFG")
chmod 600 "$CFG"
echo "   Name: $NAME · Adresse fuer die Geraete: $URL · intern: $LISTEN"
# Einstellungen: Schalter von der Kommandozeile, sonst im Terminal fragen (bei jedem Lauf; Enter = so lassen)
if [ ${#SETS[@]} -gt 0 ]; then
  K einstellungen "${SETS[@]}" | sed 's/^/   /'
elif [ -z "$YES" ] && [ -z "$TEST" ] && { [ -n "$ASK" ] || [ -t 0 ]; } && (: </dev/tty) 2>/dev/null; then
  K einstellungen </dev/tty
else
  K einstellungen --ja | sed 's/^/   /'
  # Admin-Passwort (Admin-Seite + Update-Quelle): einmal fragen, solange keins festgelegt ist
  [ -z "$TEST" ] && (: </dev/tty) 2>/dev/null && K admin-passwort --falls-fehlt </dev/tty || true
fi

say "4/6 Apps zum Herunterladen ($DL)"
erkl "Android-, Windows- und Linux-App mit deinem Namen – fuer die Download-Seite. Neue App-Versionen kommen" "spaeter signiert durch den Tunnel auf die Geraete (nach Freigabe: kvpn-server update)."
SLUG=$(echo "$NAME" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-*//; s/-*$//'); SLUG=${SLUG:-vpn}
mkdir -p "$DL"; find "$DL" -maxdepth 1 -type f -delete
[ -f dist/KroneVPN.apk ] && install -m 644 dist/KroneVPN.apk "$DL/$NAME.apk"
[ -f dist/KroneVPN.exe ] && install -m 644 dist/KroneVPN.exe "$DL/$NAME.exe"
[ -f dist/kronevpn-linux ] && install -m 644 dist/kronevpn-linux "$DL/$SLUG-linux"
K set downloads_dir "$DL" >/dev/null
[ -n "${KVPN_STATE:-}" ] && K set state_dir "$KVPN_STATE" >/dev/null
ls "$DL" | sed 's/^/   /'
STATE=$(sed -n 's/^state_dir = "\(.*\)"/\1/p' "$CFG"); STATE=${STATE:-/var/lib/krone-vpn}
if [ -n "$BILD" ]; then
  if [[ "$BILD" =~ ^https?:// ]]; then
    TMPB=$(mktemp); curl -fsSL -m 30 --max-filesize 2097152 -o "$TMPB" "$BILD" || { echo "   Bild nicht ladbar: $BILD"; TMPB=""; }
  else TMPB=$BILD; fi
  [ -n "$TMPB" ] && { K logo "$TMPB" | sed 's/^/   /' || echo "   Bild nicht uebernommen (nur PNG/JPG/WebP/GIF bis 2 MB)"; }
  [[ "$BILD" =~ ^https?:// ]] && rm -f "$TMPB"
fi

if [ -n "$TEST" ]; then echo "== Testmodus: kein systemd/Firewall"; exit 0; fi

if [ "$MODE" = docker ]; then
  say "5/6 Docker Compose (Container krone-vpn)"
  erkl "Der Server laeuft im Container krone-vpn und startet mit dem Rechner neu."
  if ! docker compose version >/dev/null 2>&1; then
    echo "   installiere Docker (offizielles Skript get.docker.com) ..."
    curl -fsSL https://get.docker.com | sh >/dev/null
  fi
  [ "$CFG" = /etc/krone-vpn/server.toml ] || { echo "   Docker geht nur mit /etc/krone-vpn/server.toml"; exit 1; }
  # Weiterleitung auf dem Server selbst einschalten (aus dem Container heraus nicht erlaubt)
  {
    echo "net.ipv4.ip_forward = 1"; echo "net.ipv6.conf.all.forwarding = 1"
    for f in /proc/sys/net/ipv6/conf/*/accept_ra; do
      n=$(basename "$(dirname "$f")"); [ "$n" = all ] || [ "$n" = default ] || [ "$n" = lo ] && continue
      [ "$(cat "$f")" = 1 ] && echo "net.ipv6.conf.$n.accept_ra = 2"
    done
  } > /etc/sysctl.d/90-krone-vpn.conf
  sysctl -q -p /etc/sysctl.d/90-krone-vpn.conf || true
  if systemctl is-enabled --quiet krone-vpn 2>/dev/null; then systemctl disable --now krone-vpn >/dev/null 2>&1; echo "   systemd-Dienst abgeschaltet (laeuft jetzt im Container)"; fi
  CTX=$STATE/docker; mkdir -p "$CTX"
  install -m 644 deploy/docker/Dockerfile deploy/docker/docker-compose.yml "$CTX/"
  install -m 755 "$DEST" "$CTX/kvpn-server"
  mkdir -p /etc/letsencrypt
  docker compose -f "$CTX/docker-compose.yml" -p krone-vpn up -d --build --force-recreate 2>&1 | tail -3 | sed 's/^/   /'
  sleep 2
  docker ps --filter name=^krone-vpn$ --filter status=running -q | grep -q . && echo "   laeuft (docker logs -f krone-vpn)" || { docker logs --tail 20 krone-vpn; exit 1; }
  touch "$ETC/.docker"
else
  say "5/6 Dienst krone-vpn (systemd)"
  erkl "Der Server laeuft als Dienst im Hintergrund, startet mit dem Rechner und nach Fehlern von selbst neu."
  if [ -f "$ETC/.docker" ]; then
    docker compose -f "$STATE/docker/docker-compose.yml" -p krone-vpn down >/dev/null 2>&1 || docker rm -f krone-vpn >/dev/null 2>&1 || true
    rm -f "$ETC/.docker"; echo "   Docker-Container entfernt (laeuft jetzt als systemd-Dienst)"
  fi
  sed "s#/usr/local/bin/kvpn-server run#$DEST --config $CFG run#; s#^Description=.*#Description=$NAME (VPN ueber HTTPS/443)#" deploy/krone-vpn.service > /etc/systemd/system/krone-vpn.service
  systemctl daemon-reload
  systemctl enable krone-vpn >/dev/null 2>&1
  systemctl restart krone-vpn; sleep 1
  systemctl is-active --quiet krone-vpn && echo "   laeuft" || { journalctl -u krone-vpn -n 20 --no-pager; exit 1; }
fi

say "6/6 Firewall"
erkl "Port 443 (TCP) muss von aussen erreichbar sein – zu Hause zusaetzlich im Router freigeben (Portfreigabe)."
if [ "$NGINX" = 0 ]; then
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then ufw allow 443/tcp >/dev/null && echo "   ufw: 443/tcp offen"
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then firewall-cmd -q --permanent --add-service=https && firewall-cmd -q --reload && echo "   firewalld: https offen"
  else echo "   keine aktive ufw/firewalld gefunden – beim Anbieter/Router TCP 443 auf diesen Server freigeben"; fi
else
  echo "   (hinter nginx: nichts zu tun)"
fi

echo
echo "== fertig: $NAME"
if [ "$NGINX" = 1 ]; then
  echo "In den server-Block (443) von $HOST in nginx einfuegen, dann: nginx -t && systemctl reload nginx"
  echo "-----------------------------------------------------------------------------"
  sed "s#127.0.0.1:8101#$LISTEN#g" deploy/nginx-selfhost.conf
  echo "-----------------------------------------------------------------------------"
fi
[ "$NGINX" = 1 ] && SP=/vpn-statistik || SP=/stats
echo "Geraet anlegen:     kvpn-server add \"Mein Handy\"     (QR-Code scannen bzw. Code in die PC-App einfuegen)"
echo "Apps fuer Geraete:  https://$URLHOST/download/"
echo "Statistik:          https://$URLHOST$SP   (Passwort: $(cat "$PWF" 2>/dev/null || echo "siehe stats_password in $CFG"))"
[ -n "$LOCAL" ] && echo "Lokal auf dem Server (ohne Passwort):  http://localhost:${LOCAL##*:}/   ·   vom PC aus: ssh -L ${LOCAL##*:}:localhost:${LOCAL##*:} root@$HOST  und dann  http://localhost:${LOCAL##*:}/"
echo "Pruefen am PC:      \"$NAME.exe\" --test"
[ "$MODE" = docker ] && echo "Docker:             docker logs -f krone-vpn   ·   docker restart krone-vpn"
echo "Aktualisieren:      kvpn-update   (Server von GitHub)  ·  Apps an die Geraete verteilen: kvpn-server update (mit Freigabe)"
echo "Alle Funktionen:    kvpn-server anleitung   (gespeichert in $ETC/ANLEITUNG.txt)"
K anleitung --datei "$ETC/ANLEITUNG.txt" --still 2>/dev/null || true
