#!/bin/bash
# Android-Kern fuer den Test auf dem PC bauen (gleicher Rust-Code wie in der APK, nur fuer Linux statt Android)
# und die Java-Testklasse uebersetzen. Wird von tests/e2e.sh aufgerufen.
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo build --release -p kvpn-android
mkdir -p target/jni
javac -d target/jni android/src/de/krone/vpn/Native.java tests/jni/JniTest.java
