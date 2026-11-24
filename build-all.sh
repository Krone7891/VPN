#!/bin/bash
# Baut alles und legt es in dist/: KroneVPN.apk, KroneVPN.exe, kronevpn-linux, kvpn-server (statisch), SHA256SUMS, update.json (signiert)
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
bash android/build-apk.sh
mkdir -p dist
cp target/x86_64-pc-windows-gnu/release/kronevpn.exe dist/KroneVPN.exe
cp target/x86_64-unknown-linux-musl/release/kronevpn dist/kronevpn-linux
cp target/x86_64-unknown-linux-musl/release/kvpn-server dist/kvpn-server
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
python3 - "$VERSION" <<'PY'
import hashlib, json, os, sys, time
with open("dist/SHA256SUMS", "w") as f:
    for n in ["KroneVPN.apk", "KroneVPN.exe", "kronevpn-linux", "kvpn-server"]:
        f.write(hashlib.sha256(open("dist/" + n, "rb").read()).hexdigest() + "  " + n + "\n")
PY
# signierte Liste der Apps (Server holen sie von GitHub, verteilt wird erst nach Freigabe: kvpn-server update)
target/x86_64-unknown-linux-musl/release/kvpn-server update-sign "$KEY" dist
ls -la dist
