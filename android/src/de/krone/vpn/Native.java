package de.krone.vpn;

/** Rust-Kern (libkronevpn.so): TLS, WebSocket, Noise-Verschluesselung, Paketweiterleitung. */
final class Native {
    static { System.loadLibrary("kronevpn"); }
    private Native() {}

    /** Code pruefen; JSON mit name/url/ip4/ip6/dns/mtu oder {"error": ...} */
    static native String parse(String code);
    /** Tunnel starten; fd gehoert danach Rust. Liefert Handle (0 = Fehler). */
    static native long start(int fd, String code, String systemProxy);
    static native void stop(long handle);
    static native void reconnect(long handle);
    static native String status(long handle);
    static native String version();
}
