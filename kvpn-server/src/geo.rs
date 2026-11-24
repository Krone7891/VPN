//! Ungefaehrer Standort der Geraete fuer die lokale Seite bzw. Admin-Seite (nie auf der oeffentlichen Statistik).
//!
//! Aus der oeffentlichen IP-Adresse, von der sich ein Geraet verbindet: Stadt, Region, Land, Anbieter. Das ist
//! KEIN GPS – im Mobilfunk oder hinter einer Firmen-Firewall ist es der Ort des Netzanschlusses (oft nur die
//! naechste groessere Stadt). Abgefragt wird ipwho.is (HTTPS, ohne Konto); dafuer geht die IP-Adresse dorthin.
//! Abschalten: kvpn-server einstellungen --standort aus (oder auf der Webseite).
//! Ergebnisse werden 7 Tage in <state_dir>/standorte.json gemerkt; jede Adresse wird hoechstens einmal je
//! 10 Minuten nachgefragt, die Seite wartet nie darauf.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Geo {
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub cc: String,
    #[serde(default)]
    pub lat: f64,
    #[serde(default)]
    pub lon: f64,
    #[serde(default)]
    pub isp: String,
    /// Adresse aus einem privaten/lokalen Netz (keine Abfrage)
    #[serde(default)]
    pub local: bool,
    #[serde(default)]
    pub ts: u64,
}

const FRESH: u64 = 7 * 86400;
const RETRY: u64 = 600;

struct Cache {
    path: String,
    map: HashMap<String, Geo>,
    tried: HashMap<String, u64>,
    busy: HashSet<String>,
}

fn cache() -> &'static Mutex<Option<Cache>> {
    static C: OnceLock<Mutex<Option<Cache>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// private, lokale und reservierte Adressen: nicht nachfragen
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_private() || a.is_loopback() || a.is_link_local() || a.is_unspecified() || (o[0] == 100 && (64..128).contains(&o[1])) || o[0] >= 224
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_private(IpAddr::V4(v4));
            }
            let s = a.segments();
            a.is_loopback() || a.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xff00) == 0xff00
        }
    }
}

fn url(ip: &str) -> String {
    match std::env::var("KVPN_GEO_URL") {
        Ok(u) => format!("{}/{ip}", u.trim_end_matches('/')),
        Err(_) => format!("https://ipwho.is/{ip}?lang=de"),
    }
}

/// Antwort von ipwho.is (oder einem aehnlichen Dienst) lesen
pub fn parse(body: &[u8]) -> Option<Geo> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    if v.get("success").and_then(|x| x.as_bool()) == Some(false) || v.get("error").map(|e| !e.is_null() && e != false).unwrap_or(false) {
        return None;
    }
    let s = |keys: &[&str]| -> String {
        keys.iter()
            .find_map(|k| {
                let mut cur = &v;
                for part in k.split('.') {
                    cur = cur.get(part)?;
                }
                cur.as_str().map(|x| x.trim().to_string()).filter(|x| !x.is_empty())
            })
            .unwrap_or_default()
    };
    let f = |keys: &[&str]| keys.iter().find_map(|k| v.get(*k).and_then(|x| x.as_f64())).unwrap_or(0.0);
    let g = Geo {
        city: s(&["city"]),
        region: s(&["region", "regionName"]),
        country: s(&["country", "country_name"]),
        cc: s(&["country_code", "countryCode"]),
        lat: f(&["latitude", "lat"]),
        lon: f(&["longitude", "lon"]),
        isp: s(&["connection.isp", "connection.org", "isp", "org"]),
        local: false,
        ts: kvpn::util::now_secs(),
    };
    (!g.country.is_empty() || !g.city.is_empty()).then_some(g)
}

fn fetch(ip: &str) -> Option<Geo> {
    let test = std::env::var("KVPN_GEO_URL").is_ok();
    let out = std::process::Command::new("curl")
        .args(["-fsS", "--proto", if test { "=https,http" } else { "=https" }, "--max-time", "8", "--max-filesize", "65536"])
        .args(["-A", "kvpn-server"])
        .arg(url(ip))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse(&out.stdout)
}

/// sofort nachfragen (fuer kvpn-server standort <ip>)
pub fn lookup_now(ip: &str) -> Result<Geo, String> {
    let addr: IpAddr = ip.trim().parse().map_err(|_| format!("'{ip}' ist keine IP-Adresse"))?;
    if is_private(addr) {
        return Ok(Geo { local: true, ..Default::default() });
    }
    fetch(&addr.to_string()).ok_or_else(|| "keine Antwort von ipwho.is (Netz, Limit oder unbekannte Adresse)".to_string())
}

pub fn describe(g: &Geo) -> String {
    if g.local {
        return "lokales/privates Netz".into();
    }
    let mut parts: Vec<&str> = vec![&g.city];
    if g.region != g.city {
        parts.push(&g.region);
    }
    parts.push(&g.country);
    let place = parts.into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(", ");
    format!("{place}{}{}", if g.isp.is_empty() { String::new() } else { format!(" · {}", g.isp) }, if g.lat != 0.0 || g.lon != 0.0 { format!(" · {:.3}, {:.3}", g.lat, g.lon) } else { String::new() })
}

fn save(c: &Cache) {
    let tmp = format!("{}.neu", c.path);
    if std::fs::write(&tmp, serde_json::to_string(&c.map).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&tmp, &c.path);
    }
}

/// Standort zu einer Adresse – sofort aus dem Speicher; fehlt er, wird er im Hintergrund nachgefragt
/// (beim naechsten Aufruf der Seite ist er dann da).
pub fn get(state_dir: &str, ip: &str) -> Option<Geo> {
    let addr: IpAddr = ip.trim().trim_start_matches('[').trim_end_matches(']').parse().ok()?;
    if is_private(addr) {
        return Some(Geo { local: true, ..Default::default() });
    }
    let key = addr.to_string();
    let now = kvpn::util::now_secs();
    let mut guard = cache().lock().unwrap();
    let path = format!("{state_dir}/standorte.json");
    if guard.as_ref().map(|c| c.path != path).unwrap_or(true) {
        let map = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        *guard = Some(Cache { path, map, tried: HashMap::new(), busy: HashSet::new() });
    }
    let c = guard.as_mut().unwrap();
    let have = c.map.get(&key).cloned();
    let fresh = have.as_ref().map(|g| now.saturating_sub(g.ts) < FRESH).unwrap_or(false);
    let may = !c.busy.contains(&key) && c.tried.get(&key).map(|t| now.saturating_sub(*t) >= RETRY).unwrap_or(true);
    if !fresh && may {
        c.busy.insert(key.clone());
        c.tried.insert(key.clone(), now);
        std::thread::spawn(move || {
            let r = fetch(&key);
            let mut guard = cache().lock().unwrap();
            if let Some(c) = guard.as_mut() {
                c.busy.remove(&key);
                if let Some(g) = r {
                    c.map.insert(key, g);
                    // alte Eintraege nicht ewig aufheben
                    let now = kvpn::util::now_secs();
                    c.map.retain(|_, g| now.saturating_sub(g.ts) < 90 * 86400);
                    save(c);
                }
            }
        });
    }
    have
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_adressen() {
        for a in ["10.1.2.3", "192.168.0.1", "172.16.5.5", "127.0.0.1", "100.64.1.1", "fd00::1", "fe80::1", "::1", "::ffff:192.168.1.1"] {
            assert!(is_private(a.parse().unwrap()), "{a}");
        }
        for a in ["8.8.8.8", "91.12.3.4", "2a02:8070::1", "100.128.0.1"] {
            assert!(!is_private(a.parse().unwrap()), "{a}");
        }
    }

    #[test]
    fn antwort_lesen() {
        let ipwho = r#"{"ip":"91.12.3.4","success":true,"type":"IPv4","continent":"Europa","country":"Deutschland","country_code":"DE",
            "region":"Bayern","city":"München","latitude":48.1351,"longitude":11.582,"connection":{"asn":3320,"org":"Telekom","isp":"Deutsche Telekom AG"}}"#.as_bytes();
        let g = parse(ipwho).unwrap();
        assert_eq!((g.city.as_str(), g.region.as_str(), g.country.as_str(), g.cc.as_str(), g.isp.as_str()), ("München", "Bayern", "Deutschland", "DE", "Deutsche Telekom AG"));
        assert!((g.lat - 48.1351).abs() < 1e-6);
        assert!(parse(br#"{"success":false,"message":"Reserved range"}"#).is_none());
        let ipapi = br#"{"ip":"1.2.3.4","city":"Wien","region":"Wien","country_name":"Austria","country_code":"AT","latitude":48.2,"longitude":16.37,"org":"A1"}"#;
        let g = parse(ipapi).unwrap();
        assert_eq!((g.city.as_str(), g.country.as_str(), g.isp.as_str()), ("Wien", "Austria", "A1"));
        assert!(parse(b"kein json").is_none());
    }
}
