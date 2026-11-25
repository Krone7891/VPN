//! Schutz-Regeln der Apps (ab Apps 1.3.0), fuer alle Plattformen gleich:
//!   * Notbremse (Kill-Switch): faellt das VPN aus, geht gar nichts mehr ins Internet – nichts unverschluesselt
//!   * automatisch schuetzen: in fremden WLANs und im Mobilfunk verbinden, im eigenen (vertrauten) WLAN pausieren
//!   * Ausnahmen: Android = Apps, PC = Ziele (Namen, Adressen, Netze), die am VPN vorbei direkt ins Internet gehen
//! Gespeichert als JSON (Android in den App-Einstellungen, PC in regeln.json neben dem Verbindungscode).

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Regeln {
    /// Notbremse: ohne VPN kein Internet (PC: Windows-Firewall-Filter bzw. iptables; Android: System-Einstellung
    /// "Durchgehend aktives VPN" + "Verbindungen ohne VPN blockieren")
    pub notbremse: bool,
    /// trotz Notbremse ins lokale Netz (Drucker, Router-Seite, Anmeldeseite im Hotel-WLAN nicht!)
    pub lokal_erlaubt: bool,
    /// automatisch schuetzen: in fremden Netzen verbinden, in vertrauten pausieren
    pub auto: bool,
    /// vertraute Netze: WLAN-Name oder "router:<MAC>" (PC: erkennt das Heimnetz auch ohne WLAN-Namen)
    pub vertraut: Vec<String>,
    /// Android: Apps (Paketnamen), die am VPN vorbei gehen
    pub apps: Vec<String>,
    /// PC: Ziele, die am VPN vorbei gehen: Namen ("bank.de"), Adressen ("203.0.113.5") oder Netze ("198.51.100.0/24")
    pub ziele: Vec<String>,
}

impl Default for Regeln {
    fn default() -> Self {
        Regeln { notbremse: false, lokal_erlaubt: true, auto: false, vertraut: Vec::new(), apps: Vec::new(), ziele: Vec::new() }
    }
}

/// das Netz, in dem das Geraet gerade ist
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Netz {
    /// irgendeine Verbindung ins Netz da?
    pub online: bool,
    /// WLAN-Name (leer = kein WLAN oder Name unbekannt)
    pub wlan: String,
    /// MAC-Adresse des Routers (Standard-Gateway), klein mit ':' (leer = unbekannt)
    pub router: String,
}

impl Netz {
    /// Kennungen dieses Netzes, wie sie in `vertraut` stehen
    pub fn kennungen(&self) -> Vec<String> {
        let mut v = Vec::new();
        if !self.wlan.is_empty() {
            v.push(self.wlan.clone());
        }
        if !self.router.is_empty() {
            v.push(format!("router:{}", self.router));
        }
        v
    }

    /// Anzeige ("WLAN „Heimnetz“" / "Netz mit Router aa:bb:…" / "Mobilfunk/Kabel")
    pub fn anzeige(&self) -> String {
        if !self.wlan.is_empty() {
            format!("WLAN „{}“", self.wlan)
        } else if !self.router.is_empty() {
            format!("Netz mit Router {}", self.router)
        } else if self.online {
            "unbekanntes Netz".into()
        } else {
            "kein Netz".into()
        }
    }
}

impl Regeln {
    pub fn from_json(s: &str) -> Regeln {
        serde_json::from_str(s).unwrap_or_default()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    pub fn load(path: &std::path::Path) -> Regeln {
        std::fs::read_to_string(path).map(|s| Regeln::from_json(&s)).unwrap_or_default()
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.to_json()).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// ist dieses Netz vertraut?
    pub fn ist_vertraut(&self, n: &Netz) -> bool {
        let k = n.kennungen();
        self.vertraut.iter().any(|v| k.iter().any(|x| x.eq_ignore_ascii_case(v.trim())))
    }

    /// soll das VPN in diesem Netz laufen? (ohne "automatisch schuetzen" immer ja)
    pub fn soll_schuetzen(&self, n: &Netz) -> bool {
        !self.auto || !self.ist_vertraut(n)
    }

    /// Netz als vertraut merken (alle Kennungen) – true = etwas hinzugefuegt
    pub fn vertrauen(&mut self, n: &Netz) -> bool {
        let mut neu = false;
        for k in n.kennungen() {
            if !self.vertraut.iter().any(|v| v.eq_ignore_ascii_case(&k)) {
                self.vertraut.push(k);
                neu = true;
            }
        }
        neu
    }

    /// Ziele aufteilen: (Netze als (Adresse, Praefix), Namen). Ungueltiges wird uebergangen.
    pub fn ziele_aufteilen(&self) -> (Vec<(IpAddr, u8)>, Vec<String>) {
        let mut nets = Vec::new();
        let mut names = Vec::new();
        for z in &self.ziele {
            let z = z.trim().trim_start_matches("https://").trim_start_matches("http://");
            if z.is_empty() {
                continue;
            }
            if let Ok((a, p)) = crate::util::parse_cidr(z) {
                nets.push((a, p));
            } else if let Ok(a) = z.parse::<IpAddr>() {
                nets.push((a, if a.is_ipv4() { 32 } else { 128 }));
            } else {
                let host = z.split('/').next().unwrap_or("").split(':').next().unwrap_or("").to_ascii_lowercase();
                if host.contains('.') && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') && !names.contains(&host) {
                    names.push(host);
                }
            }
        }
        (nets, names)
    }
}

/// Ziel-Liste aus Text (eine Zeile/Komma je Eintrag) pruefen – Fehlertext fuer die Anzeige
pub fn ziele_pruefen(text: &str) -> Result<Vec<String>, String> {
    let mut v = Vec::new();
    for z in text.split([',', '\n', ';', ' ']).map(str::trim).filter(|z| !z.is_empty()) {
        let r = Regeln { ziele: vec![z.to_string()], ..Default::default() };
        let (n, h) = r.ziele_aufteilen();
        if n.is_empty() && h.is_empty() {
            return Err(format!("„{z}“ ist weder Name (bank.de) noch Adresse (203.0.113.5) noch Netz (198.51.100.0/24)"));
        }
        if n.iter().any(|(a, p)| *p == 0 || a.is_unspecified()) {
            return Err(format!("„{z}“ wuerde alles am VPN vorbei schicken"));
        }
        v.push(z.to_string());
    }
    if v.len() > 100 {
        return Err("hoechstens 100 Ausnahmen".into());
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_schutz() {
        let mut r = Regeln { auto: true, ..Default::default() };
        let heim = Netz { online: true, wlan: "FRITZ!Box 7590".into(), router: "aa:bb:cc:dd:ee:ff".into() };
        let hotel = Netz { online: true, wlan: "Hotel-Gast".into(), router: "11:22:33:44:55:66".into() };
        let mobil = Netz { online: true, ..Default::default() };
        assert!(r.soll_schuetzen(&heim));
        assert!(r.vertrauen(&heim));
        assert!(!r.vertrauen(&heim), "nicht doppelt");
        assert_eq!(r.vertraut, vec!["FRITZ!Box 7590".to_string(), "router:aa:bb:cc:dd:ee:ff".to_string()]);
        assert!(!r.soll_schuetzen(&heim));
        assert!(r.soll_schuetzen(&hotel));
        assert!(r.soll_schuetzen(&mobil));
        // Heimnetz per Kabel (kein WLAN-Name), gleicher Router -> vertraut
        assert!(!r.soll_schuetzen(&Netz { online: true, wlan: String::new(), router: "AA:BB:CC:DD:EE:FF".into() }));
        r.auto = false;
        assert!(r.soll_schuetzen(&heim), "ohne Automatik immer schuetzen");
        // alte/kaputte Datei -> Standard
        assert_eq!(Regeln::from_json("{\"notbremse\":true}"), Regeln { notbremse: true, ..Default::default() });
        assert_eq!(Regeln::from_json("kaputt"), Regeln::default());
    }

    #[test]
    fn ziele() {
        let r = Regeln { ziele: vec!["bank.de".into(), "https://www.Sparkasse.de/login".into(), "203.0.113.5".into(), "198.51.100.0/24".into(), "2001:db8::/32".into(), "quatsch".into()], ..Default::default() };
        let (n, h) = r.ziele_aufteilen();
        assert_eq!(h, vec!["bank.de".to_string(), "www.sparkasse.de".to_string()]);
        assert_eq!(n.len(), 3);
        assert_eq!(n[0], ("203.0.113.5".parse().unwrap(), 32));
        assert_eq!(n[1].1, 24);
        assert!(ziele_pruefen("bank.de, 10.0.0.0/8\n").is_ok());
        assert!(ziele_pruefen("0.0.0.0/0").is_err());
        assert!(ziele_pruefen("kein ziel").is_err());
    }
}
