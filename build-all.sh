#!/bin/bash
# Baut alles und legt es in dist/: KroneVPN.apk, KroneVPN.exe, kronevpn-linux, kvpn-server (statisch), files.json
# Voraussetzungen: Rust mit Zielen x86_64-pc-windows-gnu, x86_64-unknown-linux-musl, aarch64-linux-android,
# mingw-w64, musl-tools, Android-SDK (siehe android/build-apk.sh). Tests: cargo test && sudo bash tests/e2e.sh
set -euo pipefail
cd "$(dirname "$0")"
# Signier-Schluessel fuer App-Updates (geheim, nur hier beim Bauen). Fehlt er, wird ein neuer erzeugt und sein
# oeffentlicher Teil nach kvpn/update-key.pub geschrieben (die Apps nehmen dann nur noch damit signierte Updates an).
KEY=${KVPN_UPDATE_KEY:-$HOME/.kronevpn/update-ed25519.pk8}
if [ ! -f "$KEY" ]; then
  cargo build --release -p kvpn-server
  target/release/kvpn-server update-keygen "$KEY" kvpn/update-key.pub
fi
cargo test --release --workspace --exclude kvpn-android
cargo build --release --target x86_64-unknown-linux-musl -p kvpn-server -p kronevpn
cargo build --release --target x86_64-pc-windows-gnu -p kronevpn
OUT=target/apk bash android/build-apk.sh
mkdir -p dist
cp target/x86_64-unknown-linux-musl/release/kvpn-server dist/kvpn-server
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
# Apps nur dann mit neuer Version nach dist/, wenn sich ihr Code geaendert hat (sonst bekommen die Geraete kein Update)
echo "== App-Versionen"
python3 tools/app-versions.py "$VERSION" android=target/apk/KroneVPN.apk \
  windows=target/x86_64-pc-windows-gnu/release/kronevpn.exe linux=target/x86_64-unknown-linux-musl/release/kronevpn
python3 - "$VERSION" <<'PY'
import hashlib, json, os, sys, time
av = json.load(open("dist/app-versions.json"))
files = []
for os_, n in [("android", "KroneVPN.apk"), ("windows", "KroneVPN.exe"), ("linux", "kronevpn-linux")]:
    p = os.path.join("dist", n)
    files.append({"name": n, "size": os.path.getsize(p), "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest(), "version": av[os_]["version"]})
newest = max((f["version"] for f in files), key=lambda v: [int(x) for x in v.split(".")])
json.dump({"version": newest, "date": time.strftime("%d.%m.%Y"), "files": files}, open("dist/files.json", "w"), indent=1)
with open("dist/SHA256SUMS", "w") as f:
    for n in ["KroneVPN.apk", "KroneVPN.exe", "kronevpn-linux", "kvpn-server"]:
        f.write(hashlib.sha256(open("dist/" + n, "rb").read()).hexdigest() + "  " + n + "\n")
PY
# signierte Liste der Apps (Server holen sie von GitHub, verteilt wird erst nach Freigabe: kvpn-server update)
target/x86_64-unknown-linux-musl/release/kvpn-server update-sign "$KEY" dist
ls -la dist
