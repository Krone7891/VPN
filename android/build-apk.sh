#!/bin/bash
# KroneVPN-APK ohne Gradle bauen: Rust (arm64, 16-KB-Seiten) -> aapt2 -> javac -> d8 -> zipalign -> apksigner
#   ANDROID_SDK (Standard /opt/android-sdk) mit platforms;android-36, build-tools;36.0.0, ndk;29.x
#   KEYSTORE   Signaturschluessel (Standard ~/.kronevpn/release.jks; wird beim ersten Mal erzeugt –
#              AUFHEBEN, sonst lassen sich Updates nur nach Deinstallation installieren)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
SDK=${ANDROID_SDK:-/opt/android-sdk}
BT=$SDK/build-tools/36.0.0
JAR=$SDK/platforms/android-36/android.jar
NDK=$(ls -d "$SDK"/ndk/* | sort -V | tail -1)/toolchains/llvm/prebuilt/linux-x86_64/bin
KEYSTORE=${KEYSTORE:-$HOME/.kronevpn/release.jks}
KSPASS=${KSPASS:-kronevpn}
VERSION=$(grep -m1 '^version' "$ROOT/Cargo.toml" | cut -d'"' -f2)
VCODE=${VCODE:-$(echo "$VERSION" | awk -F. '{print $1*10000+$2*100+$3}')}
OUT=${OUT:-$ROOT/dist}
B=$(mktemp -d)
trap 'rm -rf "$B"' EXIT

echo "== Rust-Kern fuer arm64-v8a"
export CC_aarch64_linux_android=$NDK/aarch64-linux-android26-clang
export AR_aarch64_linux_android=$NDK/llvm-ar
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$NDK/aarch64-linux-android26-clang
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384"
(cd "$ROOT" && cargo build --release -p kvpn-android --target aarch64-linux-android)

echo "== Ressourcen + Manifest"
"$BT/aapt2" compile --dir "$HERE/res" -o "$B/res.zip"
"$BT/aapt2" link -o "$B/base.apk" -I "$JAR" --manifest "$HERE/AndroidManifest.xml" "$B/res.zip" \
  --min-sdk-version 26 --target-sdk-version 36 --version-code "$VCODE" --version-name "$VERSION" --auto-add-overlay

echo "== Java -> dex"
mkdir -p "$B/classes" "$B/dex"
javac -nowarn -Xlint:-options --release 11 -cp "$JAR" -d "$B/classes" $(find "$HERE/src" -name '*.java')
"$BT/d8" --release --min-api 26 --lib "$JAR" --output "$B/dex" $(find "$B/classes" -name '*.class')

echo "== APK packen (native Bibliothek unkomprimiert, 16-KB-ausgerichtet)"
python3 - "$B/base.apk" "$B/dex/classes.dex" "$ROOT/target/aarch64-linux-android/release/libkronevpn.so" "$B/unaligned.apk" <<'PY'
import sys, zipfile
src, dex, so, out = sys.argv[1:]
with zipfile.ZipFile(src) as zi, zipfile.ZipFile(out, "w") as zo:
    for it in zi.infolist():
        zo.writestr(it, zi.read(it.filename))
    zo.write(dex, "classes.dex", compress_type=zipfile.ZIP_DEFLATED)
    zo.write(so, "lib/arm64-v8a/libkronevpn.so", compress_type=zipfile.ZIP_STORED)
PY
"$BT/zipalign" -f -P 16 4 "$B/unaligned.apk" "$B/aligned.apk"

if [ ! -f "$KEYSTORE" ]; then
  echo "== Neuer Signaturschluessel: $KEYSTORE  (aufheben!)"
  mkdir -p "$(dirname "$KEYSTORE")"
  keytool -genkeypair -keystore "$KEYSTORE" -storepass "$KSPASS" -keypass "$KSPASS" -alias kronevpn \
    -keyalg EC -groupname secp256r1 -validity 10000 -dname "CN=KroneVPN, O=KroneVPN" >/dev/null 2>&1
fi
mkdir -p "$OUT"
"$BT/apksigner" sign --ks "$KEYSTORE" --ks-pass "pass:$KSPASS" --ks-key-alias kronevpn \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true --out "$OUT/KroneVPN.apk" "$B/aligned.apk"
rm -f "$OUT/KroneVPN.apk.idsig"
"$BT/apksigner" verify --verbose "$OUT/KroneVPN.apk" | grep -E "Verified|v2|v3" | head -4
"$BT/zipalign" -c -P 16 -v 4 "$OUT/KroneVPN.apk" | grep -E "libkronevpn|Verification" 
ls -la "$OUT/KroneVPN.apk"
