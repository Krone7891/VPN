//! `kvpn-server anleitung`: alles Wichtige auf einen Blick – erste Schritte und ALLE Funktionen mit Befehl.
//! Mit den Adressen dieses Servers. Der Installer zeigt sie am Ende an und legt sie als ANLEITUNG.txt neben
//! server.toml (zum spaeteren Nachlesen: kvpn-server anleitung).

use crate::config::Config;

fn an(b: bool) -> &'static str {
    if b {
        "an"
    } else {
        "aus"
    }
}

/// Funktionen: (Bereich, [(Name, Erklaerung, Befehl/Ort)])
pub fn funktionen() -> Vec<(&'static str, Vec<(&'static str, &'static str, &'static str)>)> {
    vec![
        (
            "Verbindung & Sicherheit",
            vec![
                ("VPN über HTTPS (Port 443)", "sieht für Firewalls wie eine normale Webseite aus – kommt auch durch strenge Firmen-Firewalls (Sophos) und Firmen-Proxys", "immer an"),
                ("Ende-zu-Ende-Verschlüsselung", "Noise (wie WireGuard) + AES-256-GCM oder ChaCha20 – auch wenn eine Firewall HTTPS aufbricht, liest niemand mit", "App → Sicherheit"),
                ("Tarnung", "Paketgrößen und Takt ändern sich bei jeder Verbindung, keine typischen VPN-Muster", "immer an"),
                ("Notbremse (Kill-Switch)", "fällt das VPN aus, geht nichts unverschlüsselt ins Internet", "App → Schutz"),
                ("Automatisch schützen", "in fremden WLANs/Mobilfunk verbinden, im eigenen WLAN pausieren", "App → Schutz"),
                ("Am VPN vorbei", "einzelne Apps (Android) bzw. Ziele (PC) gehen direkt ins Internet", "App → Schutz"),
                ("Zweiter Schritt (2FA)", "Admin-Seite nur mit Passwort + Code aus einer Authenticator-App", "kvpn-server zwei-faktor an"),
            ],
        ),
        (
            "Geräte & Benutzer",
            vec![
                ("Gerät anlegen", "zeigt QR-Code und Verbindungscode für die App", "kvpn-server add \"Mein Handy\""),
                ("Liste / Code nochmal zeigen", "alle Geräte mit Status; Code und QR erneut", "kvpn-server list  ·  kvpn-server code \"Name\""),
                ("Benutzer", "Personen mit mehreren Geräten, Höchstzahl je Benutzer", "kvpn-server benutzer add \"Anna\"  ·  add \"Annas Handy\" --benutzer Anna"),
                ("Sperren / Ablaufdatum", "Gerät oder Benutzer sofort sperren, Zugang bis zu einem Datum", "kvpn-server sperren \"Name\"  ·  ablauf \"Name\" 2026-12-31"),
                ("Zeitfenster", "VPN nur zu bestimmten Zeiten, z. B. Mo-Fr 07:00-16:00 (je Gerät oder Benutzer)", "kvpn-server zeiten \"Name\" \"Mo-Fr 7-16\""),
                ("Gäste einladen", "Link/QR mit Ablauf, Zugang nur einmal abholbar, danach automatisch weg", "kvpn-server gast \"Oma\" --tage 7"),
                ("Verlauf", "wann sich welches Gerät verbunden hat (90 Tage)", "kvpn-server verlauf [Gerät]"),
                ("Höchstzahl Geräte", "wie viele Geräte gleichzeitig angelegt sein dürfen", "kvpn-server max 20"),
            ],
        ),
        (
            "Netz & Werbe-Blocker",
            vec![
                ("Werbe- & Tracker-Blocker", "wie Pi-hole für alle Geräte im VPN, Listen täglich neu", "kvpn-server einstellungen --werbeblocker an"),
                ("Eigene Sperren/Ausnahmen", "einzelne Seiten sperren oder freigeben", "Admin-Seite → Einstellungen"),
                ("Heimnetz", "Geräte im VPN erreichen Drucker/NAS daheim, auch mit Namen", "kvpn-server einstellungen --heimnetz an"),
                ("Geschwindigkeitstest", "Ping, Download, Upload durch das VPN bis zum Server", "App → Geschwindigkeit testen"),
            ],
        ),
        (
            "Überblick & Meldungen",
            vec![
                ("Admin-Seite", "Live-Datenrate, Geräte, Verlauf, Einstellungen, sperren, Gäste, Sicherung", "im VPN: http://<server-im-vpn>:8180"),
                ("Monatsbericht", "Daten, Online-Zeit, Verbindungen je Gerät; auch als CSV", "kvpn-server bericht [JJJJ-MM]"),
                ("Benachrichtigungen", "aufs Handy über ntfy oder Telegram: neues Gerät, falsches Passwort, Start, Update, Bericht, Ausfall", "kvpn-server benachrichtigung ntfy https://ntfy.sh/<thema>"),
                ("Ausfall-Alarm", "Gerät zu lange offline; Server von außen nicht erreichbar (DynDNS)", "kvpn-server set ausfall_geraete \"Handy Lea\""),
                ("Standort & Orten", "Standort der Geräte (wenn in der App erlaubt), Karte mit Verlauf, Gerät orten", "Admin-Seite → Geräte"),
                ("Gerät anpingen", "prüfen, ob ein Gerät gerade erreichbar ist", "Admin-Seite → Geräte"),
                ("Absturz-Protokolle", "Fehlerberichte der Apps landen auf dem Server", "kvpn-server abstuerze"),
            ],
        ),
        (
            "Wartung",
            vec![
                ("Tägliche Sicherung", "Schlüssel, Geräte, Benutzer, Einstellungen; die letzten 14 bleiben", "kvpn-server sicherung  ·  sicherung jetzt"),
                ("Wiederherstellen", "auch auf einem neuen Server nach der Installation", "kvpn-server sicherung zurueck <datei>"),
                ("Server aktualisieren", "neueste Version von GitHub, Schlüssel und Geräte bleiben", "kvpn-update"),
                ("App-Updates verteilen", "neue App-Version (signiert) geht nach Freigabe durch den Tunnel an die Geräte", "kvpn-server update"),
                ("Eigener Name & Logo", "erscheinen in den Apps und auf den Webseiten", "kvpn-server set vpn_name \"…\"  ·  kvpn-server logo bild.png"),
                ("Start beim Hochfahren", "prüfen bzw. einschalten", "kvpn-server autostart an"),
                ("Status", "Geräte mit App-Version und Update-Stand", "kvpn-server status"),
            ],
        ),
        (
            "Apps",
            vec![
                ("Android", "Ein/Aus-Knopf, Schnelleinstellungs-Kachel, Schutz, Geschwindigkeit, Logo des Servers", "App"),
                ("Windows", "Programmfenster, Symbol neben der Uhr, läuft als Dienst im Hintergrund", "KroneVPN.exe"),
                ("Linux", "als Dienst (systemd) oder im Terminal", "sudo kronevpn-linux 'kronevpn://…' --hintergrund"),
            ],
        ),
    ]
}

/// Basisadresse (https://host[:port]) aus der Server-Adresse
fn web(c: &Config) -> String {
    crate::gast::base_url(c)
}

pub fn text(c: &Config) -> String {
    let mut o = String::new();
    let w = web(c);
    let name = c.display_name();
    o += &format!("{name} – Anleitung\n{}\n\n", "=".repeat(name.chars().count() + 12));
    o += "SO GEHT ES LOS\n\n";
    o += "  1. Gerät anlegen (für jedes Handy/jeden PC einmal):\n         kvpn-server add \"Mein Handy\"\n";
    o += "     Es erscheint ein QR-Code und ein Verbindungscode (kronevpn://…). Den Code geheim halten:\n     wer ihn hat, kann sich verbinden.\n\n";
    o += "  2. App installieren:\n";
    if !c.downloads_dir.is_empty() && !w.is_empty() {
        o += &format!("         {w}/download/      (Android, Windows, Linux)\n");
    }
    o += "     Android: App installieren, dann den QR-Code mit der Kamera scannen – die App öffnet sich mit dem Code.\n";
    o += "     Windows: Programm starten und den Verbindungscode einfügen (einmal Admin-Rechte bestätigen).\n";
    o += "     Linux:   sudo ./kronevpn-linux 'kronevpn://…' --hintergrund\n\n";
    o += "  3. Verbinden: auf den großen Knopf tippen. Fertig – alles läuft verschlüsselt über deinen Server.\n\n";
    o += "  4. Admin-Seite (Live-Werte, Geräte, Einstellungen):\n";
    match c.admin_addr() {
        Some(a) => o += &format!("         im VPN: http://{a}   (Admin-Passwort{})\n", if c.admin_password.is_empty() { " – wird beim ersten Aufruf festgelegt" } else { "" }),
        None => o += "         im VPN: aus (einschalten: kvpn-server einstellungen --admin-vpn an)\n",
    }
    if !c.local_listen.is_empty() {
        o += &format!("         auf dem Server selbst: http://{}\n", c.local_listen.replace("127.0.0.1", "localhost"));
    }
    o += "\n";
    o += &format!(
        "JETZT EINGESTELLT\n\n  Benutzerverwaltung {} · Werbe-Blocker {} · Heimnetz {} · tägliche Sicherung {} · Benachrichtigungen {}\n  Höchstens {} Geräte ({} angelegt)   ·   ändern: kvpn-server einstellungen  oder Admin-Seite\n\n",
        an(c.users),
        an(c.adblock),
        an(c.lan_access),
        an(c.backup),
        if crate::notify::configured(c) { "an" } else { "aus (einrichten: kvpn-server benachrichtigung …)" },
        c.max_devices,
        c.device_count()
    );
    o += "ALLE FUNKTIONEN\n";
    for (bereich, list) in funktionen() {
        o += &format!("\n  {bereich}\n");
        for (n, e, b) in list {
            o += &format!("    • {n}: {e}\n        → {b}\n");
        }
    }
    o += "\nHILFE\n\n  kvpn-server             alle Befehle\n  kvpn-server anleitung   diese Anleitung\n";
    if !w.is_empty() {
        o += &format!("  Server-Adresse für die Apps: {}\n", c.public_url);
    }
    o
}

#[cfg(test)]
mod tests {
    #[test]
    fn anleitung_vollstaendig() {
        let (k, _) = kvpn::crypto::generate_keypair();
        let mut c = crate::config::Config::new("wss://vpn.example.org/api/v1/stream".into(), kvpn::code::key_to_b64(&k));
        c.downloads_dir = "/tmp/x".into();
        let t = super::text(&c);
        assert!(t.contains("https://vpn.example.org/download/"));
        for w in ["kvpn-server add", "zeiten", "gast", "sicherung", "Werbe", "Notbremse", "Geschwindigkeit", "Benachrichtigung", "Kachel", "Symbol neben der Uhr"] {
            assert!(t.contains(w), "fehlt: {w}");
        }
    }
}
