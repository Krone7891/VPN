#!/bin/bash
# VPN-Server einrichten – direkt von GitHub, ein Befehl (als root auf einem Linux-Server):
#
#   curl -fsSL https://raw.githubusercontent.com/Krone7891/VPN/main/install.sh | sudo bash
#
# Fragt nach Name, Domain, Bild und erstem Geraet. Ohne Rueckfragen (z. B. fuer Skripte):
#
#   curl -fsSL https://raw.githubusercontent.com/Krone7891/VPN/main/install.sh | sudo bash -s -- \
#        --name "Potzplitz VPN" --domain vpn.meine-domain.de --bild https://.../logo.png --geraet "Mein Handy" --ja
#
# Optionen:
#   --name "Name"        Name deines VPN (erscheint in den Apps, auf Download- und Statistik-Seite, in den Dateinamen)
#   --domain host        eigene Domain (empfohlen, echtes Zertifikat); leer = oeffentliche IP
#   --bild datei|url     eigenes Bild (PNG/JPG/WebP/GIF) fuer die Webseiten
#   --geraet "Name"      gleich ein Geraet anlegen (mehrfach moeglich)
#   --hinter-nginx       es laeuft schon ein Webserver auf 443
#   --docker             Server als Docker-Compose-Container (statt systemd-Dienst); --systemd = zurueck
#   --ja                 keine Rueckfragen (Standardwerte)
# Erneut ausfuehren = aktualisieren (Schluessel und Geraete bleiben erhalten), kurz:  kvpn-update
#
# Privates GitHub-Repo: mit einem Zugangsschluessel (github.com/settings/tokens, Recht "Contents: read"):
#   T=github_pat_...; curl -fsSL -H "Authorization: Bearer $T" https://raw.githubusercontent.com/Krone7891/VPN/main/install.sh \
#     | sudo GITHUB_TOKEN=$T bash
set -euo pipefail
# Alles steckt in main(): bei "curl | bash" liest bash so erst das ganze Skript, bevor etwas laeuft
main() {
REPO=${KVPN_REPO:-Krone7891/VPN}
BRANCH=${KVPN_BRANCH:-main}
TOKEN=${GITHUB_TOKEN:-${KVPN_GITHUB_TOKEN:-}}
if [ -n "$TOKEN" ]; then
  TARBALL=${KVPN_TARBALL:-https://api.github.com/repos/$REPO/tarball/$BRANCH}   # privates Repo: ueber die API
else
  TARBALL=${KVPN_TARBALL:-https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz}
fi
SRC=${KVPN_SRC:-/opt/kronevpn}
NAME=""; DOMAIN=""; BILD=""; NGINX=""; MODE=""; YES=""; DEVICES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=${2:-}; shift ;;
    --domain) DOMAIN=${2:-}; shift ;;
    --bild|--logo) BILD=${2:-}; shift ;;
    --geraet|--device) DEVICES+=("${2:-}"); shift ;;
    --hinter-nginx|--behind-nginx) NGINX=--hinter-nginx ;;
    --docker) MODE=--docker ;;
    --systemd) MODE=--systemd ;;
    --ja|-y|--yes) YES=1 ;;
    -h|--help) sed -n 2,20p "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "Unbekannte Option: $1 (Hilfe: --help)"; exit 2 ;;
  esac
  shift
done
[ -n "${KVPN_TEST:-}" ] || [ "$(id -u)" = 0 ] || { echo "Bitte als root starten:  curl -fsSL ... | sudo bash"; exit 1; }
B=$'\033[1m'; N=$'\033[0m'

# ---- Quellen: lokaler Ordner (git clone / ZIP) oder frisch von GitHub
SELF=${BASH_SOURCE[0]:-}
if [ -n "$SELF" ] && [ -f "$SELF" ] && [ -f "$(dirname "$(readlink -f "$SELF")")/selfhost.sh" ]; then
  D=$(dirname "$(readlink -f "$SELF")")
else
  echo "${B}Lade das VPN von GitHub ($REPO) ...${N}"
  for t in curl tar; do command -v $t >/dev/null || { apt-get update -qq && apt-get install -y -qq $t >/dev/null; }; done
  mkdir -p "$SRC"
  TMP=$(mktemp -d)
  CH=(); [ -n "$TOKEN" ] && CH=(-H "Authorization: Bearer $TOKEN")
  curl -fsSL "${CH[@]}" "$TARBALL" | tar -xz -C "$TMP" || {
    echo "Download fehlgeschlagen: $TARBALL"
    [ -z "$TOKEN" ] && echo "Ist das Repo privat? Dann mit GITHUB_TOKEN starten (siehe Anfang von install.sh) oder das Repo auf oeffentlich stellen."
    exit 1; }
  rm -rf "$SRC.new"; mv "$TMP"/* "$SRC.new"; rm -rf "$TMP"
  rm -rf "$SRC.old"; [ -d "$SRC" ] && mv "$SRC" "$SRC.old"; mv "$SRC.new" "$SRC"; rm -rf "$SRC.old"
  D=$SRC
  echo "   nach $D"
fi
cd "$D"


# ---- Werkzeuge
if [ -z "${KVPN_TEST:-}" ]; then
  miss=(); for t in curl openssl ip iptables ss; do command -v $t >/dev/null || miss+=($t); done
  if [ ${#miss[@]} -gt 0 ] && command -v apt-get >/dev/null; then
    echo "Installiere: iproute2 iptables openssl curl"; apt-get update -qq && apt-get install -y -qq iproute2 iptables openssl curl >/dev/null
  fi
fi

# ---- Fragen (auch bei "curl | bash": gelesen wird vom Terminal)
ask() {   # variable frage standard
  local v=${!1}; [ -n "$v" ] || [ -n "$YES" ] && { [ -n "$v" ] || printf -v "$1" '%s' "$3"; return; }
  if [ -r /dev/tty ] && [ -w /dev/tty ]; then
    printf '%s%s%s [%s]: ' "$B" "$2" "$N" "$3" > /dev/tty
    IFS= read -r v < /dev/tty || v=""
  fi
  printf -v "$1" '%s' "${v:-$3}"
}
CUR=$(sed -n 's/^vpn_name = "\(.*\)"/\1/p' "${KVPN_CONFIG:-/etc/krone-vpn/server.toml}" 2>/dev/null || true)
CURD=$(sed -n 's#^public_url = "wss://\([^]/":]*\)/.*#\1#p' "${KVPN_CONFIG:-/etc/krone-vpn/server.toml}" 2>/dev/null || true)
[[ "$CURD" =~ ^[0-9.]+$ ]] && CURD=""
ask NAME "Wie soll dein VPN heissen?" "${CUR:-Mein VPN}"
ask DOMAIN "Domain fuer den Server (leer = oeffentliche IP)" "$CURD"
ask BILD "Eigenes Bild (Datei oder https-Adresse, leer = keins)" ""
if [ -z "$MODE" ] && [ -z "$YES" ] && [ ! -f "${KVPN_CONFIG:-/etc/krone-vpn/server.toml}" ]; then
  DK=""; ask DK "Als Docker-Compose-Container betreiben statt als systemd-Dienst? (j/n)" "n"
  [[ "$DK" =~ ^[jJyY] ]] && MODE=--docker
fi
if [ ${#DEVICES[@]} -eq 0 ] && [ -z "$YES" ]; then
  G=""; ask G "Gleich ein Geraet anlegen? Name (leer = spaeter)" ""; [ -n "$G" ] && DEVICES+=("$G")
fi

# ---- einrichten
ARGS=(--name "$NAME"); [ -n "$DOMAIN" ] && ARGS+=("$DOMAIN"); [ -n "$BILD" ] && ARGS+=(--bild "$BILD"); [ -n "$NGINX" ] && ARGS+=("$NGINX"); [ -n "$MODE" ] && ARGS+=("$MODE")
bash selfhost.sh "${ARGS[@]}"

KS=${KVPN_BIN:-/usr/local/bin/kvpn-server}
for g in "${DEVICES[@]}"; do
  echo; echo "${B}== Geraet: $g${N}"
  LIST=$("$KS" --config "${KVPN_CONFIG:-/etc/krone-vpn/server.toml}" list)
  if printf '%s\n' "$LIST" | grep -qiF "  $g "; then echo "   gibt es schon"
  else "$KS" --config "${KVPN_CONFIG:-/etc/krone-vpn/server.toml}" add "$g"; fi
done
echo
echo "${B}$NAME ist eingerichtet.${N}  Weitere Geraete:  kvpn-server add \"Name\""
}

main "$@"
