//! Ausfall-Alarm (ab Server 1.4.0) – meldet ueber die Benachrichtigungen (Ereignis "ausfall"):
//!   * ein ueberwachtes Geraet (Einstellung `ausfall_geraete`) war laenger als `ausfall_stunden` nicht verbunden –
//!     z. B. das Handy der Kinder oder ein PC, der immer im VPN sein sollte. Kommt es wieder: Entwarnung.
//!   * der Server ist von aussen vermutlich nicht erreichbar: der Name in der Server-Adresse (DynDNS) zeigt nicht
//!     mehr auf die oeffentliche Adresse des Anschlusses (z. B. nach einer Zwangstrennung). Gemeldet wird nur, wenn es
//!     vorher schon einmal gepasst hat – Anschluesse ohne eigene IPv4 (DS-Lite, Tunnel) bekommen keinen Fehlalarm.
//!   * eine Sicherung ging schief (sicherung.rs)
//!   * nach einem Ausfall des Servers selbst steht die Dauer in der Start-Meldung ("lief 3 h nicht")
//!
//! Die oeffentliche Adresse kommt per DNS-Abfrage "myip.opendns.com" bei OpenDNS (nur eine DNS-Frage, keine Daten).

use crate::config::Config;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Zustand zwischen den Pruefungen
#[derive(Default)]
pub struct Waechter {
    /// schon gemeldete Geraete (bis sie wieder da sind)
    gemeldet: HashSet<String>,
    /// Name zeigte schon einmal auf die eigene Adresse (sonst kein Alarm)
    pub extern_passte: bool,
    extern_fehler: u32,
    extern_gemeldet: bool,
}

/// Meldung: (Titel, Text)
pub type Meldung = (String, String);

fn dauer(s: u64) -> String {
    if s < 3600 {
        format!("{} min", s / 60)
    } else if s < 2 * 86400 {
        format!("{} h", s / 3600)
    } else {
        format!("{} Tagen", s / 86400)
    }
}

impl Waechter {
    /// Geraete pruefen. `letzte`: Name -> (verbunden?, zuletzt gesehen (0 = seit Serverstart nicht))
    pub fn geraete(&mut self, c: &Config, letzte: &HashMap<String, (bool, u64)>, started: u64, now: u64) -> Vec<Meldung> {
        let mut out = Vec::new();
        // (Tests: Grenze in Sekunden ueber KVPN_AUSFALL_S)
        let grenze = std::env::var("KVPN_AUSFALL_S").ok().and_then(|x| x.parse().ok()).unwrap_or(c.ausfall_stunden.max(1) as u64 * 3600);
        let ueberwacht: Vec<String> = c.ausfall_geraete.iter().map(|x| x.to_lowercase()).collect();
        for (name, (online, seen)) in letzte {
            let key = name.to_lowercase();
            if !ueberwacht.contains(&key) {
                self.gemeldet.remove(&key);
                continue;
            }
            if *online {
                if self.gemeldet.remove(&key) {
                    out.push((format!("„{name}“ ist wieder da"), format!("„{name}“ ist wieder mit dem VPN verbunden.")));
                }
                continue;
            }
            let seit = if *seen > 0 { *seen } else { started };
            if now.saturating_sub(seit) >= grenze && self.gemeldet.insert(key) {
                let wann = if *seen > 0 { format!("zuletzt verbunden am {} (UTC)", crate::users::datetime(*seen as i64)) } else { "seit dem Start des Servers nicht verbunden".to_string() };
                out.push((
                    format!("„{name}“ seit {} offline", dauer(now.saturating_sub(seit))),
                    format!("„{name}“ war seit {} nicht mehr im VPN – {wann}. Akku leer, ausgeschaltet oder VPN aus?", dauer(now.saturating_sub(seit))),
                ));
            }
        }
        out
    }

    /// Ergebnis der Erreichbarkeits-Pruefung verarbeiten: Some(true) = passt, Some(false) = zeigt woanders hin,
    /// None = nicht pruefbar. Gemeldet wird nach zwei Fehlern hintereinander (also nach ca. 20 min).
    pub fn extern_ergebnis(&mut self, r: Option<(bool, String)>) -> Option<Meldung> {
        match r {
            Some((true, _)) => {
                self.extern_passte = true;
                self.extern_fehler = 0;
                if std::mem::take(&mut self.extern_gemeldet) {
                    return Some(("wieder erreichbar".into(), "Die Server-Adresse zeigt wieder auf deinen Anschluss – die Geräte kommen von unterwegs wieder rein.".into()));
                }
                None
            }
            Some((false, text)) if self.extern_passte => {
                self.extern_fehler += 1;
                if self.extern_fehler >= 2 && !self.extern_gemeldet {
                    self.extern_gemeldet = true;
                    return Some(("von außen nicht erreichbar?".into(), text));
                }
                None
            }
            _ => None,
        }
    }
}

/// Host aus der Server-Adresse – None, wenn er nicht oeffentlich pruefbar ist (IP-Adresse, lokaler Name)
pub fn pruef_host(c: &Config) -> Option<String> {
    let t = kvpn::transport::parse_url(&c.public_url).ok()?;
    let h = t.host.trim_end_matches('.').to_lowercase();
    if h.parse::<IpAddr>().is_ok() || !h.contains('.') {
        return None;
    }
    let lokal = [".local", ".lan", ".home", ".internal", ".test", ".localhost", ".fritz.box", ".home.arpa"];
    // (Tests geben einen eigenen DNS-Server vor und duerfen dann auch Test-Namen pruefen)
    if lokal.iter().any(|x| h.ends_with(x)) && std::env::var_os("KVPN_EXTERN_DNS").is_none() {
        return None;
    }
    Some(h)
}

fn dns_server() -> SocketAddr {
    std::env::var("KVPN_EXTERN_DNS").ok().and_then(|s| s.parse().ok()).unwrap_or_else(|| "208.67.222.222:53".parse().unwrap())
}

/// A-Eintraege eines Namens bei einem bestimmten DNS-Server
fn a_records(server: SocketAddr, host: &str) -> Result<Vec<IpAddr>, String> {
    let mut q = vec![0u8, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    let id: u16 = rand::random();
    q[..2].copy_from_slice(&id.to_be_bytes());
    for l in host.split('.') {
        if l.is_empty() || l.len() > 63 {
            return Err(format!("ungueltiger Name {host}"));
        }
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let s = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok();
    for _ in 0..2 {
        if s.send_to(&q, server).is_err() {
            continue;
        }
        let mut buf = [0u8; 1500];
        if let Ok((n, from)) = s.recv_from(&mut buf) {
            if from == server && n >= 12 && buf[..2] == q[..2] {
                return Ok(kvpn::transport::parse_a_records(&buf[..n], 0).into_iter().map(|a| a.ip()).collect());
            }
        }
    }
    Err(format!("keine Antwort von {server}"))
}

/// Erreichbarkeit pruefen (blockiert bis ca. 12 s): Some((passt, Text)) oder None (nicht pruefbar)
pub fn extern_pruefen(c: &Config) -> Option<(bool, String)> {
    let host = pruef_host(c)?;
    let srv = dns_server();
    let ich = a_records(srv, "myip.opendns.com").ok()?.into_iter().next()?;
    let ziel = a_records(srv, &host).ok()?;
    if ziel.is_empty() {
        return Some((false, format!("{host} hat keine IPv4-Adresse mehr (DynDNS?). Dein Anschluss hat {ich}.")));
    }
    if ziel.contains(&ich) {
        return Some((true, String::new()));
    }
    let z: Vec<String> = ziel.iter().map(|a| a.to_string()).collect();
    Some((
        false,
        format!("{host} zeigt auf {}, dein Anschluss hat aber {ich}. Wahrscheinlich hat sich die Adresse geändert und DynDNS hängt – von unterwegs kommt dann niemand ins VPN.", z.join(", ")),
    ))
}

/// Server lebt: Zeitpunkt jede Minute in <state_dir>/lebt.txt; beim Start daraus die Dauer eines Ausfalls
pub fn lebt_datei(c: &Config) -> std::path::PathBuf {
    std::path::Path::new(&c.state_dir).join("lebt.txt")
}

pub fn lebt(c: &Config, now: u64) {
    let p = lebt_datei(c);
    let _ = std::fs::write(&p, now.to_string());
}

/// Name hat schon einmal gepasst (bleibt ueber Neustarts erhalten)
fn passte_datei(c: &Config) -> std::path::PathBuf {
    std::path::Path::new(&c.state_dir).join("erreichbar.txt")
}

pub fn passte_laden(c: &Config) -> bool {
    std::fs::read_to_string(passte_datei(c)).map(|s| s.trim() == "1").unwrap_or(false)
}

pub fn passte_merken(c: &Config) {
    let _ = std::fs::write(passte_datei(c), "1");
}

/// wie lange war der Server weg? (None = unbekannt oder unter 10 Minuten)
pub fn ausfall_dauer(c: &Config, now: u64) -> Option<String> {
    let t: u64 = std::fs::read_to_string(lebt_datei(c)).ok()?.trim().parse().ok()?;
    let d = now.saturating_sub(t);
    (d >= 600).then(|| dauer(d))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        let (k, _) = kvpn::crypto::generate_keypair();
        let mut c = Config::new("wss://vpn.example.org/api/v1/stream".into(), kvpn::code::key_to_b64(&k));
        c.ausfall_geraete = vec!["Handy Lea".into()];
        c.ausfall_stunden = 24;
        c
    }

    #[test]
    fn geraete_melden() {
        let c = cfg();
        let mut w = Waechter::default();
        let start = 1_000_000u64;
        let mut m = HashMap::new();
        m.insert("Handy Lea".to_string(), (false, start + 100));
        m.insert("PC".to_string(), (false, 0));
        assert!(w.geraete(&c, &m, start, start + 3600).is_empty());
        let r = w.geraete(&c, &m, start, start + 100 + 25 * 3600);
        assert_eq!(r.len(), 1, "nur das ueberwachte Geraet");
        assert!(r[0].0.contains("seit 25 h offline"), "{:?}", r);
        assert!(w.geraete(&c, &m, start, start + 100 + 26 * 3600).is_empty(), "nur einmal");
        m.insert("Handy Lea".to_string(), (true, start + 30 * 3600));
        let r = w.geraete(&c, &m, start, start + 30 * 3600);
        assert_eq!(r.len(), 1);
        assert!(r[0].0.contains("wieder da"));
        assert!(w.geraete(&c, &m, start, start + 31 * 3600).is_empty());
    }

    #[test]
    fn erreichbarkeit() {
        let mut w = Waechter::default();
        // hat nie gepasst (z. B. DS-Lite) -> kein Alarm
        assert!(w.extern_ergebnis(Some((false, "x".into()))).is_none());
        assert!(w.extern_ergebnis(Some((false, "x".into()))).is_none());
        assert!(w.extern_ergebnis(Some((true, String::new()))).is_none());
        assert!(w.extern_ergebnis(Some((false, "zeigt woanders hin".into()))).is_none(), "erst beim zweiten Mal");
        assert!(w.extern_ergebnis(None).is_none());
        let m = w.extern_ergebnis(Some((false, "zeigt woanders hin".into()))).unwrap();
        assert!(m.1.contains("woanders"));
        assert!(w.extern_ergebnis(Some((false, "x".into()))).is_none(), "nur einmal");
        assert!(w.extern_ergebnis(Some((true, String::new()))).unwrap().0.contains("wieder"));
    }

    #[test]
    fn hosts() {
        let mut c = cfg();
        assert_eq!(pruef_host(&c).as_deref(), Some("vpn.example.org"));
        c.public_url = "wss://203.0.113.5/api/v1/stream".into();
        assert!(pruef_host(&c).is_none());
        c.public_url = "wss://vpn.test/api/v1/stream".into();
        assert!(pruef_host(&c).is_none());
        c.public_url = "wss://nas.fritz.box/api/v1/stream".into();
        assert!(pruef_host(&c).is_none());
    }
}
