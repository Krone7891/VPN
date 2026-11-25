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
#   --benutzer an|aus    Benutzerverwaltung (SQLite; Standard an)
#   --aes256 an|aus      AES-256-GCM statt ChaCha20 fuer die Daten (Standard aus)
#   --leistung an|aus    Leistungsmodus: alle CPU-Kerne (Standard aus)
#   --max <anzahl>       hoechstens so viele Geraete (Standard 8)
#   --ja                 keine Rueckfragen (Standardwerte bzw. bisherige Einstellungen)
# Waehrend der Installation steht zu jeder Frage kurz, was sie bedeutet; am Ende kommt eine Anleitung mit allen
# Funktionen (spaeter nochmal: kvpn-server anleitung, gespeichert in /etc/krone-vpn/ANLEITUNG.txt).
# Ohne --ja wird bei jedem Lauf nach den Einstellungen gefragt (Enter = so lassen) – das Skript kann also jederzeit
# erneut laufen, um etwas umzustellen.
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
NAME=""; DOMAIN=""; BILD=""; NGINX=""; MODE=""; YES=""; DEVICES=(); SETS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=${2:-}; shift ;;
    --domain) DOMAIN=${2:-}; shift ;;
    --bild|--logo) BILD=${2:-}; shift ;;
    --geraet|--device) DEVICES+=("${2:-}"); shift ;;
    --hinter-nginx|--behind-nginx) NGINX=--hinter-nginx ;;
    --docker) MODE=--docker ;;
    --systemd) MODE=--systemd ;;
    --benutzer|--aes256|--leistung|--admin-vpn|--max) SETS+=("$1" "${2:-}"); shift ;;
    --ja|-y|--yes) YES=1 ;;
    -h|--help) sed -n 2,27p "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "Unbekannte Option: $1 (Hilfe: --help)"; exit 2 ;;
  esac
  shift
done
[ -n "${KVPN_TEST:-}" ] || [ "$(id -u)" = 0 ] || { echo "Bitte als root starten:  curl -fsSL ... | sudo bash"; exit 1; }
B=$'\033[1m'; N=$'\033[0m'; G=$'\033[2m'
# Erklaerung (grau, eingerueckt) – nur wenn gefragt wird
info() { [ -n "$YES" ] && return 0; printf '%s\n' "$@" | sed "s/^/   ${G}/; s/$/${N}/"; }
if [ -z "$YES" ]; then
  cat <<TXT

${B}Willkommen! Hier richtest du dein eigenes VPN ein.${N}

   Was du bekommst:
   • ein VPN über HTTPS (Port 443) – kommt auch durch strenge Firmen-Firewalls, Hotel- und Schul-WLANs
   • Apps für Android, Windows und Linux mit deinem Namen und Logo, Updates kommen von selbst
   • Werbe-Blocker, Zugriff aufs Heimnetz, Admin-Seite, Benachrichtigungen aufs Handy, tägliche Sicherung,
     Gäste-Einladungen, Zeitfenster (z. B. nur Mo-Fr 7-16 Uhr) – eine Liste aller Funktionen kommt am Ende

   Was jetzt passiert (dauert 1–3 Minuten):
   1. Programm laden (von GitHub: $REPO)        4. Apps zum Herunterladen bereitlegen
   2. ein paar Fragen (Enter = Vorschlag)        5. Dienst starten (startet auch nach einem Neustart)
   3. Zertifikat und Schlüssel erzeugen          6. Firewall: Port 443 öffnen

   Voraussetzung: dieser Server ist aus dem Internet auf Port 443 (TCP) erreichbar – bei einem Server zu Hause
   im Router eine Portfreigabe 443 auf diesen Rechner einrichten.

TXT
fi

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
[ -z "$YES" ] && echo "${B}Ein paar Fragen${N} (Enter übernimmt den Vorschlag in [Klammern]; alles lässt sich später ändern)"; [ -z "$YES" ] && echo
[ -z "$NAME" ] && info "Der Name erscheint in den Apps, auf der Download- und Statistik-Seite und in den Dateinamen" "der Apps (z. B. „Familie Müller VPN“)."
ask NAME "Wie soll dein VPN heißen?" "${CUR:-Mein VPN}"
[ -z "$DOMAIN" ] && info "" "Unter dieser Adresse finden die Apps deinen Server. Mit eigener Domain (z. B. vpn.meine-domain.de," "auch DynDNS wie DuckDNS/deSEC) gibt es ein echtes Let's-Encrypt-Zertifikat – damit kommt das VPN auch durch" "Firewalls, die ungültige Zertifikate sperren. Die Domain muss schon auf diesen Server zeigen." "Leer lassen = die öffentliche IP-Adresse wird genommen (geht auch, aber ändert sie sich, müssen alle Codes neu)."
ask DOMAIN "Domain für den Server (leer = öffentliche IP)" "$CURD"
[ -z "$BILD" ] && info "" "Optional: dein eigenes Logo (PNG/JPG/WebP/GIF, höchstens 2 MB) – erscheint in den Apps (Kopf, Symbol," "Benachrichtigung) und auf den Webseiten. Als Datei auf diesem Server oder als https-Adresse."
ask BILD "Eigenes Bild (Datei oder https-Adresse, leer = keins)" ""
if [ -z "$MODE" ] && [ -z "$YES" ] && [ ! -f "${KVPN_CONFIG:-/etc/krone-vpn/server.toml}" ]; then
  info "" "Wie soll der Server laufen? Normal (empfohlen) als systemd-Dienst direkt auf dem Rechner." "Docker nur, wenn du hier alles in Containern betreibst (Docker wird dann bei Bedarf installiert)."
  DK=""; ask DK "Als Docker-Container betreiben statt als systemd-Dienst? (j/n)" "n"
  [[ "$DK" =~ ^[jJyY] ]] && MODE=--docker
fi
if [ ${#DEVICES[@]} -eq 0 ] && [ -z "$YES" ]; then
  info "" "Jedes Handy und jeder PC bekommt einen eigenen Zugang (Verbindungscode/QR-Code). Den ersten kannst du" "gleich anlegen – weitere später mit:  kvpn-server add \"Name\""
  GER=""; ask GER "Gleich ein Gerät anlegen? Name (z. B. Mein Handy, leer = später)" ""; [ -n "$GER" ] && DEVICES+=("$GER")
fi
[ -z "$YES" ] && { echo; info "Jetzt geht es los. Gleich folgen noch die Einstellungen (Werbe-Blocker, Heimnetz, Sicherung …)" "und das Admin-Passwort – zu jeder steht kurz dabei, was sie bedeutet."; echo; }

# ---- einrichten
ARGS=(--name "$NAME"); [ -n "$DOMAIN" ] && ARGS+=("$DOMAIN"); [ -n "$BILD" ] && ARGS+=(--bild "$BILD"); [ -n "$NGINX" ] && ARGS+=("$NGINX"); [ -n "$MODE" ] && ARGS+=("$MODE")
ARGS+=("${SETS[@]}"); if [ -n "$YES" ]; then ARGS+=(--ja); else ARGS+=(--einstellungen); fi
bash selfhost.sh "${ARGS[@]}"

KS=${KVPN_BIN:-/usr/local/bin/kvpn-server}
CF=${KVPN_CONFIG:-/etc/krone-vpn/server.toml}
for g in "${DEVICES[@]}"; do
  echo; echo "${B}== Gerät: $g${N}"
  info "Mit dem Handy: App installieren (Link unten), dann diesen QR-Code mit der Kamera scannen." "Am PC: App starten und den Verbindungscode (kronevpn://…) einfügen. Den Code geheim halten."
  LIST=$("$KS" --config "$CF" list)
  if printf '%s\n' "$LIST" | grep -qiF "  $g "; then echo "   gibt es schon (Code nochmal: kvpn-server code \"$g\")"
  else "$KS" --config "$CF" add "$g"; fi
done
# Anleitung mit allen Funktionen: anzeigen und zum Nachlesen speichern
AN=$(dirname "$CF")/ANLEITUNG.txt
"$KS" --config "$CF" anleitung --datei "$AN" --still 2>/dev/null || true
echo
echo "${B}═══════════════════════════════════════════════════════════════════════════════${N}"
echo "${B}$NAME ist eingerichtet und läuft.${N}"
echo "${B}═══════════════════════════════════════════════════════════════════════════════${N}"
echo
if [ -f "$AN" ]; then
  sed -n '/^SO GEHT ES LOS/,/^ALLE FUNKTIONEN/p' "$AN" | sed '$d'
  echo "ALLE FUNKTIONEN (mit Befehl):  kvpn-server anleitung   ·   gespeichert in $AN"
  if [ -z "$YES" ] && [ -r /dev/tty ]; then
    A=""; printf '\n%sAlle Funktionen jetzt anzeigen? (j/n)%s [j]: ' "$B" "$N" > /dev/tty; IFS= read -r A < /dev/tty || A=n
    [[ "${A:-j}" =~ ^[jJyY] ]] && sed -n '/^ALLE FUNKTIONEN/,$p' "$AN"
  fi
else
  echo "Weitere Geräte:  kvpn-server add \"Name\"   ·   Hilfe: kvpn-server"
fi
}

main "$@"
