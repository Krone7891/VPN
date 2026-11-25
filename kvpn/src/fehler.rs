//! Fehlermeldungen in Klartext: was ist los und was kann man tun.
//!
//! Die technischen Meldungen (DNS, TCP, TLS, WebSocket, Noise …) bleiben im Protokoll; Apps zeigen den Klartext.

/// technische Meldung -> verstaendliche Erklaerung mit Tipp. Unbekanntes bleibt wie es ist.
pub fn klartext(roh: &str) -> String {
    let r = roh.to_lowercase();
    let hat = |w: &[&str]| w.iter().any(|x| r.contains(x));
    let k = |t: &str| t.to_string();

    // vom Server abgelehnt – mit Grund (Zeitfenster, gesperrt, abgelaufen): der Text des Servers ist schon Klartext
    if let Some(g) = roh.strip_prefix("Server lehnt ab: ") {
        return g.to_string();
    }
    // vom Server abgelehnt / Schluessel
    if hat(&["handshake abgelehnt"]) {
        return k("Der Server kennt dieses Gerät nicht (mehr) – entfernt, gesperrt, abgelaufen oder alle Plätze belegt. Beim Admin melden bzw. einen neuen Verbindungscode holen.");
    }
    if !hat(&["tls-handshake"]) && hat(&["handshake fehlgeschlagen", "entschluesselung fehlgeschlagen", "falscher schluessel"]) {
        return k("Die Schlüssel passen nicht – der Verbindungscode gehört zu einem anderen Server oder ist veraltet. Bitte den aktuellen Code einfügen.");
    }
    if hat(&["handshake abgebrochen"]) {
        return k("Der Server hat die Anmeldung abgebrochen – der Verbindungscode passt nicht zu diesem Server (anderer Server oder veralteter Code). Bitte den aktuellen Code einfügen.");
    }
    if hat(&["unbekannte verschluesselung"]) {
        return k("Der Server verlangt eine neuere App-Version. Bitte die App aktualisieren.");
    }
    // Proxy
    if hat(&["proxy lehnt ab: 407"]) {
        return k("Der Firmen-Proxy verlangt eine Anmeldung (407). Proxy mit Benutzer:Passwort eintragen (user:pass@proxy:port).");
    }
    if hat(&["proxy lehnt ab: 403", "proxy lehnt ab: 405"]) {
        return k("Der Proxy blockiert die Verbindung zum Server. Ohne Proxy probieren oder beim Netz-Admin nachfragen.");
    }
    if hat(&["proxy"]) && hat(&["nicht erreichbar", "antwortet nicht", "lehnt ab"]) {
        return k("Der eingetragene Proxy ist nicht erreichbar. Proxy-Adresse prüfen – oder ohne Proxy verbinden.");
    }
    // kein Netz / DNS
    if hat(&["network is unreachable", "os error 101", "netzwerk ist nicht erreichbar", "no route to host", "os error 113"]) {
        return k("Kein Netzwerk. WLAN oder mobile Daten einschalten – das VPN verbindet sich dann von selbst.");
    }
    if hat(&["nicht gefunden", "getaddrinfo", "dns-abfrage", "keine adresse fuer"]) {
        return k("Die Server-Adresse wird nicht gefunden – kein Internet oder DNS gesperrt. Internetverbindung prüfen; das VPN versucht es weiter.");
    }
    // Server nicht erreichbar
    if hat(&["connection refused", "os error 111", "verbindung verweigert", "os error 10061"]) {
        return k("Der Server lehnt die Verbindung ab – er startet vermutlich gerade neu oder ist aus. Das VPN versucht es weiter.");
    }
    if hat(&["keine antwort (firewall?)", "zeitueberschreitung", "timed out", "os error 110", "os error 10060"]) {
        return k("Der Server antwortet nicht. Ist er an? Blockiert das Netz die Verbindung? Das VPN versucht es weiter.");
    }
    // TLS / HTTPS
    if hat(&["certificate", "zertifikat"]) && hat(&["expired", "notvalidyet", "not valid", "abgelaufen"]) {
        return k("Das Zertifikat passt zeitlich nicht – stimmen Datum und Uhrzeit dieses Geräts? Sonst ist das Server-Zertifikat abgelaufen (Admin).");
    }
    if hat(&["tls-handshake dauert"]) {
        return k("Die sichere Verbindung (HTTPS) kommt nicht zustande – das Netz bremst oder filtert. Neuer Versuch läuft.");
    }
    if hat(&["tls-handshake fehlgeschlagen", "tls", "handshakefailure"]) {
        return k("Die sichere Verbindung (HTTPS) wurde gestört. Öffentliches WLAN (Hotel, Zug)? Erst im Browser eine Webseite öffnen und dort anmelden.");
    }
    // HTTP-Antworten beim WebSocket-Aufbau
    if hat(&["websocket"]) {
        if hat(&["404", "not found"]) {
            return k("Der Server ist erreichbar, aber der VPN-Zugang fehlt dort (404) – Adresse im Code oder nginx-Einrichtung prüfen (Admin).");
        }
        if hat(&["502", "503", "504", "bad gateway", "service unavailable"]) {
            return k("Der Webserver läuft, aber der VPN-Dienst dahinter nicht (502/503). Server-Admin: kvpn-server prüfen. Neuer Versuch läuft.");
        }
        if hat(&["403", "forbidden", "401"]) {
            return k("Der Zugang wurde vom Netz oder Server verweigert (403). Firmen-Firewall? Über einen anderen Weg (Proxy/Mobilfunk) probieren.");
        }
        if hat(&["antwortet nicht"]) {
            return k("Der Server antwortet nicht auf den Verbindungsaufbau. Neuer Versuch läuft.");
        }
    }
    // laufende Verbindung
    if hat(&["keine antwort vom server seit"]) {
        return k("Die Verbindung ist eingeschlafen (das Netz hat sie wohl getrennt) – verbinde neu …");
    }
    if hat(&["server hat die verbindung beendet"]) {
        return k("Der Server hat die Verbindung beendet (Neustart, Update oder Gerät gesperrt) – verbinde neu …");
    }
    if hat(&["netzwerk gewechselt"]) {
        return k("Netzwerk gewechselt – verbinde neu …");
    }
    if hat(&["verbindung abgebrochen", "connection reset", "broken pipe", "os error 104", "os error 32", "unterbrochen", "senden fehlgeschlagen"]) {
        return k("Die Verbindung ist abgebrochen (Netzwechsel oder Firewall) – verbinde neu …");
    }
    if hat(&["tun geschlossen"]) {
        return k("Der VPN-Adapter wurde vom System geschlossen. Bitte neu verbinden.");
    }
    // Windows / System
    if hat(&["os error 5)", "zugriff verweigert", "access is denied", "permission denied", "os error 13)"]) {
        return format!("Keine Berechtigung – KroneVPN braucht dafür Administratorrechte (bzw. root). ({roh})");
    }
    if hat(&["os error 1060", "dienst ist nicht installiert", "does not exist as an installed service"]) {
        return k("Der VPN-Dienst ist nicht eingerichtet. Einmal auf Verbinden klicken – KroneVPN richtet ihn dann ein.");
    }
    if hat(&["no space left", "os error 28", "speicher"]) && hat(&["voll", "no space", "os error 28"]) {
        return k("Der Speicher ist voll – bitte etwas Platz schaffen.");
    }
    roh.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn klartext_fuer_typische_fehler() {
        let f = |s: &str| klartext(s);
        assert!(f("Adresse vpn.example.de nicht gefunden (getaddrinfo -2)").contains("nicht gefunden"));
        assert!(f("203.0.113.1:443: keine Antwort (Firewall?)").contains("antwortet nicht"));
        assert!(f("203.0.113.1:443: Connection refused (os error 111)").contains("lehnt die Verbindung ab"));
        assert!(f("TLS-Handshake fehlgeschlagen: invalid peer certificate: Expired").contains("Uhrzeit"));
        assert!(f("TLS-Handshake fehlgeschlagen: received fatal alert: HandshakeFailure").contains("WLAN"));
        assert!(f("WebSocket-Aufbau fehlgeschlagen: HTTP error: 502 Bad Gateway").contains("502"));
        assert!(f("WebSocket-Aufbau fehlgeschlagen: HTTP error: 404 Not Found").contains("404"));
        assert!(f("Server hat den Handshake abgelehnt (Geraet entfernt, Code veraltet oder alle 8 Plaetze belegt)").contains("kennt dieses Gerät nicht"));
        assert_eq!(f("Server lehnt ab: VPN nur Mo-Fr 07:00-16:00 – wieder ab Mo 07:00"), "VPN nur Mo-Fr 07:00-16:00 – wieder ab Mo 07:00");
        assert!(f("Proxy lehnt ab: 407 Proxy Authentication Required").contains("Anmeldung"));
        assert!(f("connect: Network is unreachable (os error 101)").contains("Kein Netzwerk"));
        assert!(f("keine Antwort vom Server seit 35 s – verbinde neu").contains("eingeschlafen"));
        assert!(f("Verbindung abgebrochen: Connection reset by peer (os error 104)").contains("abgebrochen"));
        assert!(f("Dienstverwaltung: Zugriff verweigert (os error 5)").contains("Administratorrechte"));
        assert!(f("Server hat den Handshake abgebrochen: WebSocket protocol error: Connection reset without closing handshake").contains("passt nicht zu diesem Server"));
        assert_eq!(f("etwas ganz Neues"), "etwas ganz Neues");
    }
}

// ------------------------------------------------------------------ Absturz-Protokolle

/// Bei einem Absturz (panic) ein Protokoll in `dir` schreiben: "<zeit>-rust.txt" mit Version, System, Meldung, Ort
/// und Aufrufkette. `extra` liefert Zusatzinfos (z. B. die letzten Zeilen des Protokolls). Die App schickt die Datei
/// beim naechsten Verbinden durch den Tunnel an den Server.
pub fn absturz_haken(dir: std::path::PathBuf, app: &'static str, extra: fn() -> String) {
    let vorher = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let bt = std::backtrace::Backtrace::force_capture();
        let thread = std::thread::current().name().unwrap_or("?").to_string();
        let text = format!(
            "KroneVPN {app} {} – Absturz (Rust)\nSystem: {} {}\nThread: {thread}\n{info}\n\nAufrufkette:\n{bt}\n\n{}",
            crate::VERSION,
            std::env::consts::OS,
            std::env::consts::ARCH,
            extra()
        );
        let _ = std::fs::create_dir_all(&dir);
        let name = format!("{}-rust.txt", crate::util::now_secs());
        let _ = std::fs::write(dir.join(name), &text.as_bytes()[..text.len().min(crate::proto::MAX_CRASH - 64)]);
        vorher(info);
    }));
}

/// gespeicherte Absturz-Protokolle (Name, Inhalt), aelteste zuerst; hoechstens 20
pub fn absturz_dateien(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut v: Vec<(String, Vec<u8>)> = rd
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "txt").unwrap_or(false))
        .filter_map(|e| Some((e.file_name().to_string_lossy().to_string(), std::fs::read(e.path()).ok()?)))
        .collect();
    v.sort();
    v.truncate(20);
    v
}

#[cfg(test)]
mod absturz_tests {
    #[test]
    fn haken_schreibt_protokoll() {
        let d = std::env::temp_dir().join(format!("kvpn-haken-{}", std::process::id()));
        super::absturz_haken(d.clone(), "test", || "letzte Zeilen: xyz".into());
        let r = std::thread::Builder::new().name("vpn-test".into()).spawn(|| panic!("absichtlich")).unwrap().join();
        assert!(r.is_err());
        let _ = std::panic::take_hook();
        let f = super::absturz_dateien(&d);
        assert_eq!(f.len(), 1);
        let t = String::from_utf8_lossy(&f[0].1);
        assert!(f[0].0.ends_with("-rust.txt") && t.contains("absichtlich") && t.contains("vpn-test") && t.contains("letzte Zeilen: xyz") && t.contains("fehler.rs"), "{t}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
