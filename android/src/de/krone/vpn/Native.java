package de.krone.vpn;

/** Rust-Kern (libkronevpn.so): TLS, WebSocket, Noise-Verschluesselung, Paketweiterleitung. */
final class Native {
    static { System.loadLibrary("kronevpn"); }
    private Native() {}

    /** Code pruefen; JSON mit name/url/ip4/ip6/dns/mtu oder {"error": ...} */
    static native String parse(String code);
    /** Tunnel starten; fd gehoert danach Rust. Liefert Handle (0 = Fehler). */
    static native long start(int fd, String code, String systemProxy, String updateDir);
    static native void stop(long handle);
    static native void reconnect(long handle);
    static native String status(long handle);
    /** Angaben fuer den Server (WLAN-Name, Standort) als JSON – nur wenn in der App freigegeben */
    static native void report(long handle, String json);
    static native String version();
    /** Verschluesselung waehlen: "auto", "aes" oder "chacha" (gilt ab dem naechsten Verbindungsaufbau) */
    static native void cipher(String choice);
    /** Prozessor hat AES-Befehle (dann nimmt "auto" AES-256-GCM) */
    static native boolean aesHw();
    /** Ordner fuer Absturz-Protokolle des Rust-Kerns (einmal beim Start) */
    static native void crashDir(String dir);

    /** Ordner fuer das eigene Logo des Servers (vor start) */
    static native void logoDir(String dir);
    /** Absturz-Protokoll an den Server schicken (Status "crash_ok" meldet, was angekommen ist) */
    static native void crash(long handle, String name, String text);

    /** Schutz-Regeln (JSON wie am PC): soll das VPN in diesem Netz laufen? (kvpn::regeln) */
    static native boolean schuetzen(String regeln, String wlan, boolean online);
}
