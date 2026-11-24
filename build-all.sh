#!/bin/bash
# Baut alles und legt es in dist/: KroneVPN.apk, KroneVPN.exe, kronevpn-linux, kvpn-server (statisch), SHA256SUMS
# Voraussetzungen: Rust mit Zielen x86_64-pc-windows-gnu, x86_64-unknown-linux-musl, aarch64-linux-android,
# mingw-w64, musl-tools, Android-SDK (siehe android/build-apk.sh). Tests: cargo test && sudo bash tests/e2e.sh
set -euo pipefail
cd "$(dirname "$0")"
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
ls -la dist
