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

// ------------------------------------------------------------------ vom Geraet selbst gemeldet (Android-App, freiwillig)

/// Angaben, die ein Geraet selbst schickt – nur wenn der Nutzer in der App „Standort teilen“ einschaltet:
/// WLAN-Name (SSID/BSSID) und Standort des Handys (GPS/WLAN/Mobilfunk, mit Genauigkeit). Viel genauer als die IP.
/// Gespeichert in <state_dir>/standorte-geraete.json (letzter Stand je Geraet).
fn reports() -> &'static Mutex<Option<(String, HashMap<String, serde_json::Value>)>> {
    static R: OnceLock<Mutex<Option<(String, HashMap<String, serde_json::Value>)>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(None))
}

fn with_reports<T>(state_dir: &str, f: impl FnOnce(&mut HashMap<String, serde_json::Value>, &str) -> T) -> T {
    let path = format!("{state_dir}/standorte-geraete.json");
    let mut g = reports().lock().unwrap();
    if g.as_ref().map(|x| x.0 != path).unwrap_or(true) {
        let map = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        *g = Some((path.clone(), map));
    }
    let (p, m) = g.as_mut().unwrap();
    f(m, p)
}

/// "aa:bb:cc:dd:ee:ff" (keine zufaellige/leere Adresse)
fn mac(s: &str) -> bool {
    let p: Vec<&str> = s.split(':').collect();
    p.len() == 6 && p.iter().all(|x| x.len() == 2 && x.chars().all(|c| c.is_ascii_hexdigit())) && s != "02:00:00:00:00:00" && s != "00:00:00:00:00:00"
}

/// Meldung pruefen und nur bekannte Felder mit sinnvollen Werten uebernehmen.
/// Some(None) = Geraet hat das Teilen ausgeschaltet (loeschen); None = unbrauchbar.
pub fn clean_report(raw: &[u8]) -> Option<Option<serde_json::Value>> {
    if raw.len() > kvpn::proto::MAX_INFO {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let o = v.as_object()?;
    if o.get("off").and_then(|x| x.as_bool()) == Some(true) {
        return Some(None);
    }
    let mut out = serde_json::Map::new();
    let txt = |k: &str, max: usize| o.get(k).and_then(|x| x.as_str()).map(|x| x.chars().filter(|c| !c.is_control()).take(max).collect::<String>()).filter(|x| !x.is_empty());
    let num = |k: &str, lo: f64, hi: f64| o.get(k).and_then(|x| x.as_f64()).filter(|x| x.is_finite() && *x >= lo && *x <= hi);
    if let Some(x) = txt("ssid", 64) {
        out.insert("ssid".into(), x.into());
    }
    if let Some(x) = txt("bssid", 32).filter(|b| mac(b)) {
        out.insert("bssid".into(), x.to_ascii_lowercase().into());
    }
    // WLAN-Netze in der Naehe (fuer die Ortung ueber Google/WiGLE): [{"b": BSSID, "s": Signal dBm}]
    if let Some(list) = o.get("aps").and_then(|x| x.as_array()) {
        let aps: Vec<serde_json::Value> = list
            .iter()
            .filter_map(|a| {
                let b = a.get("b")?.as_str()?.to_ascii_lowercase();
                let sig = a.get("s").and_then(|x| x.as_i64()).unwrap_or(-80).clamp(-120, 0);
                mac(&b).then(|| serde_json::json!({"b": b, "s": sig}))
            })
            .take(16)
            .collect();
        if !aps.is_empty() {
            out.insert("aps".into(), aps.into());
        }
    }
    if let (Some(lat), Some(lon)) = (num("lat", -90.0, 90.0), num("lon", -180.0, 180.0)) {
        out.insert("lat".into(), lat.into());
        out.insert("lon".into(), lon.into());
        if let Some(a) = num("acc", 0.0, 1e6) {
            out.insert("acc".into(), a.into());
        }
        if let Some(t) = o.get("t").and_then(|x| x.as_u64()) {
            out.insert("t".into(), t.into());
        }
        if let Some(x) = txt("src", 16) {
            out.insert("src".into(), x.into());
        }
    }
    if out.is_empty() {
        return None;
    }
    out.insert("got".into(), kvpn::util::now_secs().into());
    Some(Some(serde_json::Value::Object(out)))
}

/// Meldung eines Geraets speichern (bzw. loeschen, wenn es das Teilen ausgeschaltet hat) und – wenn Zugangsdaten
/// eingetragen sind – im Hintergrund ueber die WLAN-Netze orten
pub fn device_report(state_dir: &str, device: &str, raw: &[u8], keys: &WlanKeys) {
    let Some(r) = clean_report(raw) else { return };
    if let Some(v) = &r {
        if keys.verlauf {
            verlauf_add(state_dir, device, v, "gps");
        }
        wlan_lookup(state_dir, device, v, keys);
    } else {
        with_wlan(state_dir, |c| {
            if c.stand.geraete.remove(device).is_some() {
                wlan_save(c);
            }
        });
    }
    with_reports(state_dir, |m, path| {
        match r {
            Some(v) => m.insert(device.to_string(), v),
            None => m.remove(device),
        };
        let tmp = format!("{path}.neu");
        if std::fs::write(&tmp, serde_json::to_string(&*m).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    });
}

/// letzte Meldung eines Geraets (WLAN, Standort)
pub fn device_info(state_dir: &str, device: &str) -> Option<serde_json::Value> {
    with_reports(state_dir, |m, _| m.get(device).cloned())
}

// ------------------------------------------------------------------ Ortung ueber WLAN (Google Geolocation API, WiGLE)
//
// Das Handy meldet (wenn "Standort teilen" an ist) das verbundene WLAN (BSSID) und die WLAN-Netze in der Naehe.
// Daraus ermittelt der Server den Ort – auch wenn GPS aus ist oder das Handy in einem Gebaeude liegt:
//   * Google Geolocation API: aus mehreren WLAN-Netzen (sehr genau, oft ±20–50 m). Schluessel: google_geo_key.
//   * WiGLE (wigle.net, weltweite WLAN-Karte): Ort des verbundenen WLANs (BSSID). Zugang: wigle_api.
// Beide nur, wenn auf dem Server eingetragen. Ergebnisse je BSSID werden gemerkt (WiGLE erlaubt nur wenige
// Abfragen am Tag, Google kostet ab einer gewissen Menge Geld): je Geraet hoechstens alle 5 Minuten und nur,
// wenn sich die WLAN-Umgebung geaendert hat (sonst stuendlich).

/// Zugangsdaten fuer die WLAN-Ortung (aus server.toml)
#[derive(Clone, Default)]
pub struct WlanKeys {
    pub google: String,
    pub wigle: String,
    /// Standort-Verlauf schreiben (Standort auf der Admin-Seite eingeschaltet)
    pub verlauf: bool,
}

impl WlanKeys {
    pub fn from_cfg(c: &crate::config::Config) -> Self {
        WlanKeys { google: c.google_geo_key.trim().into(), wigle: c.wigle_api.trim().into(), verlauf: c.geo }
    }
    pub fn any(&self) -> bool {
        !self.google.is_empty() || !self.wigle.is_empty()
    }
}

/// Genauigkeit, wenn WiGLE nur den Ort eines WLANs liefert (Reichweite eines Routers)
const WIGLE_ACC: f64 = 120.0;
const WLAN_MERKEN: u64 = 30 * 86400;
const WLAN_NICHTS: u64 = 86400;

#[derive(Default, Serialize, Deserialize)]
struct WlanStand {
    /// letzte WLAN-Ortung je Geraet
    #[serde(default)]
    geraete: HashMap<String, serde_json::Value>,
    /// gemerkte WiGLE-Antworten je BSSID ({lat, lon, ts} oder {none: true, ts})
    #[serde(default)]
    bssid: HashMap<String, serde_json::Value>,
}

struct WlanCache {
    path: String,
    stand: WlanStand,
    /// je Geraet: (Zeit, Fingerabdruck der WLAN-Umgebung) der letzten Abfrage
    zuletzt: HashMap<String, (u64, String)>,
    busy: HashSet<String>,
}

fn wlan_cache() -> &'static Mutex<Option<WlanCache>> {
    static C: OnceLock<Mutex<Option<WlanCache>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

fn with_wlan<T>(state_dir: &str, f: impl FnOnce(&mut WlanCache) -> T) -> T {
    let path = format!("{state_dir}/standorte-wlan.json");
    let mut g = wlan_cache().lock().unwrap();
    if g.as_ref().map(|c| c.path != path).unwrap_or(true) {
        let stand = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        *g = Some(WlanCache { path, stand, zuletzt: HashMap::new(), busy: HashSet::new() });
    }
    f(g.as_mut().unwrap())
}

fn wlan_save(c: &WlanCache) {
    let tmp = format!("{}.neu", c.path);
    if std::fs::write(&tmp, serde_json::to_string(&c.stand).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&tmp, &c.path);
    }
}

/// letzte Ortung ueber WLAN-Datenbanken fuer ein Geraet: {lat, lon, acc, t, via, ssid, bssid}
pub fn wlan_info(state_dir: &str, device: &str) -> Option<serde_json::Value> {
    with_wlan(state_dir, |c| c.stand.geraete.get(device).cloned())
}

/// curl mit Einstellungen ueber stdin (Schluessel tauchen so nicht in der Prozessliste auf)
fn curl_cfg(lines: &[(&str, &str)]) -> Option<Vec<u8>> {
    use std::io::Write;
    let test = std::env::var("KVPN_GOOGLE_URL").is_ok() || std::env::var("KVPN_WIGLE_URL").is_ok();
    let mut cfg = String::new();
    for (k, v) in lines {
        cfg.push_str(&format!("{k} = \"{}\"\n", v.replace('\\', "\\\\").replace('"', "\\\"")));
    }
    let mut child = std::process::Command::new("curl")
        .args(["-fsS", "--proto", if test { "=https,http" } else { "=https" }, "--max-time", "10", "--max-filesize", "262144", "-A", "kvpn-server", "-K", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(cfg.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(out.stdout)
}

/// Antwort der Google Geolocation API: (lat, lon, Genauigkeit in m)
pub fn parse_google(body: &[u8]) -> Option<(f64, f64, f64)> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let lat = v.get("location")?.get("lat")?.as_f64()?;
    let lon = v.get("location")?.get("lng")?.as_f64()?;
    let acc = v.get("accuracy").and_then(|x| x.as_f64()).unwrap_or(100.0);
    ((-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)).then_some((lat, lon, acc))
}

/// Antwort von WiGLE (network/search?netid=…): (lat, lon) des ersten Treffers
pub fn parse_wigle(body: &[u8]) -> Option<(f64, f64)> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    if v.get("success").and_then(|x| x.as_bool()) != Some(true) {
        return None;
    }
    let r = v.get("results")?.as_array()?.first()?;
    let lat = r.get("trilat")?.as_f64()?;
    let lon = r.get("trilong")?.as_f64()?;
    ((-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon) && (lat != 0.0 || lon != 0.0)).then_some((lat, lon))
}

fn google(key: &str, aps: &[serde_json::Value]) -> Option<(f64, f64, f64)> {
    let base = std::env::var("KVPN_GOOGLE_URL").unwrap_or_else(|_| "https://www.googleapis.com/geolocation/v1/geolocate".into());
    let wifi: Vec<serde_json::Value> = aps.iter().map(|a| serde_json::json!({"macAddress": a["b"], "signalStrength": a["s"]})).collect();
    let body = serde_json::json!({"considerIp": false, "wifiAccessPoints": wifi}).to_string();
    let url = format!("{base}?key={key}");
    parse_google(&curl_cfg(&[("url", &url), ("header", "Content-Type: application/json"), ("data-binary", &body)])?)
}

fn wigle(api: &str, bssid: &str) -> Option<(f64, f64)> {
    let base = std::env::var("KVPN_WIGLE_URL").unwrap_or_else(|_| "https://api.wigle.net/api/v2/network/search".into());
    let url = format!("{base}?netid={}", bssid.replace(':', "%3A"));
    parse_wigle(&curl_cfg(&[("url", &url), ("user", api)])?)
}

/// Fingerabdruck der WLAN-Umgebung: die drei staerksten BSSIDs (sortiert)
fn fingerabdruck(r: &serde_json::Value) -> String {
    let mut b: Vec<String> = r.get("aps").and_then(|x| x.as_array()).map(|l| l.iter().take(3).filter_map(|a| a["b"].as_str().map(String::from)).collect()).unwrap_or_default();
    if let Some(x) = r.get("bssid").and_then(|x| x.as_str()) {
        b.push(x.into());
    }
    b.sort();
    b.dedup();
    b.join(",")
}

/// WLAN-Ortung fuer eine Meldung (laeuft im Hintergrund; nur mit eingetragenen Zugangsdaten)
pub fn wlan_lookup(state_dir: &str, device: &str, r: &serde_json::Value, keys: &WlanKeys) {
    if !keys.any() {
        return;
    }
    let fp = fingerabdruck(r);
    if fp.is_empty() {
        return;
    }
    let now = kvpn::util::now_secs();
    let ok = with_wlan(state_dir, |c| {
        if c.busy.contains(device) {
            return false;
        }
        if let Some((t, alt)) = c.zuletzt.get(device) {
            let alter = now.saturating_sub(*t);
            if alter < 300 || (*alt == fp && alter < 3600) {
                return false;
            }
        }
        c.busy.insert(device.to_string());
        c.zuletzt.insert(device.to_string(), (now, fp.clone()));
        true
    });
    if !ok {
        return;
    }
    let (sd, dev, r, keys) = (state_dir.to_string(), device.to_string(), r.clone(), keys.clone());
    std::thread::spawn(move || {
        let aps: Vec<serde_json::Value> = r.get("aps").and_then(|x| x.as_array()).cloned().unwrap_or_default();
        let bssid = r.get("bssid").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let ssid = r.get("ssid").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let mut best: Option<(f64, f64, f64, &str)> = None;
        if !keys.google.is_empty() && aps.len() >= 2 {
            if let Some((lat, lon, acc)) = google(&keys.google, &aps) {
                best = Some((lat, lon, acc, "Google"));
            }
        }
        if !keys.wigle.is_empty() && !bssid.is_empty() && best.map(|b| b.2 > WIGLE_ACC).unwrap_or(true) {
            // gemerkt? (Treffer 30 Tage, "nicht gefunden" 1 Tag)
            let now = kvpn::util::now_secs();
            let gemerkt = with_wlan(&sd, |c| c.stand.bssid.get(&bssid).cloned()).filter(|v| {
                let t = v.get("ts").and_then(|x| x.as_u64()).unwrap_or(0);
                now.saturating_sub(t) < if v.get("none").is_some() { WLAN_NICHTS } else { WLAN_MERKEN }
            });
            let treffer = match gemerkt {
                Some(v) => v.get("lat").and_then(|x| x.as_f64()).zip(v.get("lon").and_then(|x| x.as_f64())),
                None => {
                    let t = wigle(&keys.wigle, &bssid);
                    let v = match t {
                        Some((lat, lon)) => serde_json::json!({"lat": lat, "lon": lon, "ts": now}),
                        None => serde_json::json!({"none": true, "ts": now}),
                    };
                    with_wlan(&sd, |c| {
                        c.stand.bssid.insert(bssid.clone(), v);
                        c.stand.bssid.retain(|_, v| now.saturating_sub(v.get("ts").and_then(|x| x.as_u64()).unwrap_or(0)) < WLAN_MERKEN);
                    });
                    t
                }
            };
            if let Some((lat, lon)) = treffer {
                best = Some((lat, lon, WIGLE_ACC, "WiGLE"));
            }
        }
        with_wlan(&sd, |c| {
            c.busy.remove(&dev);
            if let Some((lat, lon, acc, via)) = best {
                let v = serde_json::json!({"lat": lat, "lon": lon, "acc": acc.round(), "t": kvpn::util::now_secs(), "via": via, "ssid": ssid, "bssid": bssid});
                if keys.verlauf {
                    crate::geo::verlauf_add(&sd, &dev, &v, "wlan");
                }
                c.stand.geraete.insert(dev.clone(), v);
            }
            wlan_save(c);
        });
    });
}

// ------------------------------------------------------------------ Standort-Verlauf (Bewegungs-Karte)
//
// Jeder neue Standort eines Geraets (GPS des Handys, WLAN-Ortung, Ort der IP-Adresse) kommt als eine Zeile JSON in
// <state_dir>/standort-verlauf/<geraet>.jsonl: {"t", "lat", "lon", "acc", "src", …}. Steht das Geraet still, wird
// nicht jede Meldung neu geschrieben (erst nach 15 Minuten bzw. bei IP nach 6 Stunden). Aufgehoben werden die
// letzten 50 000 Punkte (bei Meldungen alle 5 Minuten weit ueber ein Jahr).

const VERLAUF_MAX: usize = 50_000;

fn verlauf_letzte() -> &'static Mutex<HashMap<String, serde_json::Value>> {
    static L: OnceLock<Mutex<HashMap<String, serde_json::Value>>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Dateiname fuer ein Geraet (nur sichere Zeichen; Kennung haengt am vollen Namen, damit es keine Verwechslung gibt)
pub fn verlauf_datei(state_dir: &str, device: &str) -> std::path::PathBuf {
    let sicher: String = device.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).take(40).collect();
    let mut h: u32 = 0x811c9dc5;
    for b in device.bytes() {
        h = (h ^ b as u32).wrapping_mul(0x01000193);
    }
    std::path::Path::new(state_dir).join("standort-verlauf").join(format!("{sicher}-{h:08x}.jsonl"))
}

/// Entfernung in Metern (Haversine)
pub fn dist_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6_371_000.0;
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let (dp, dl) = ((lat2 - lat1).to_radians(), (lon2 - lon1).to_radians());
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * r * a.sqrt().asin()
}

fn letzte_zeile(path: &std::path::Path) -> Option<serde_json::Value> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    f.seek(SeekFrom::Start(len.saturating_sub(4096))).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    s.lines().rev().find_map(|l| serde_json::from_str(l).ok())
}

/// Standort in den Verlauf schreiben (`src`: "gps", "wlan", "ip"). Doppelte Punkte (Geraet steht still) entfallen.
pub fn verlauf_add(state_dir: &str, device: &str, v: &serde_json::Value, src: &str) {
    let (Some(lat), Some(lon)) = (v.get("lat").and_then(|x| x.as_f64()), v.get("lon").and_then(|x| x.as_f64())) else { return };
    let now = kvpn::util::now_secs();
    let t = v.get("t").and_then(|x| x.as_u64()).filter(|t| *t > 0 && *t <= now + 60).unwrap_or(now);
    let acc = v.get("acc").and_then(|x| x.as_f64()).unwrap_or(if src == "ip" { IP_ACC } else { 50.0 });
    let path = verlauf_datei(state_dir, device);
    let mut letzte = verlauf_letzte().lock().unwrap();
    let key = format!("{}|{device}", path.display());
    let vorher = letzte.get(&key).cloned().or_else(|| letzte_zeile(&path));
    if let Some(l) = &vorher {
        let (lt, llat, llon) = (l["t"].as_u64().unwrap_or(0), l["lat"].as_f64().unwrap_or(0.0), l["lon"].as_f64().unwrap_or(0.0));
        let lsrc = l["src"].as_str().unwrap_or("");
        let d = dist_m(lat, lon, llat, llon);
        if t < lt {
            return; // aelter als der letzte Punkt (z. B. verspaetete Meldung)
        }
        let gleich = d < (acc / 4.0).max(25.0);
        let pause = if src == "ip" { 6 * 3600 } else { 900 };
        if gleich && lsrc == src && t - lt < pause {
            return;
        }
        // grobe IP-Ortung nicht zwischen genaue Punkte streuen, solange das Handy frische genaue Punkte liefert
        if src == "ip" && lsrc != "ip" && now.saturating_sub(lt) < 1800 {
            return;
        }
    }
    let mut z = serde_json::json!({"t": t, "lat": (lat * 1e6).round() / 1e6, "lon": (lon * 1e6).round() / 1e6, "acc": acc.round(), "src": src});
    for k in ["ssid", "via", "city", "label"] {
        if let Some(x) = v.get(k).and_then(|x| x.as_str()).filter(|x| !x.is_empty()) {
            z[k] = x.chars().take(64).collect::<String>().into();
        }
    }
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{z}");
    }
    // zu gross? aeltere Punkte abschneiden
    if std::fs::metadata(&path).map(|m| m.len() > 8 * 1024 * 1024).unwrap_or(false) {
        if let Ok(alle) = std::fs::read_to_string(&path) {
            let zeilen: Vec<&str> = alle.lines().collect();
            let rest = zeilen[zeilen.len().saturating_sub(VERLAUF_MAX)..].join("\n") + "\n";
            let tmp = path.with_extension("neu");
            if std::fs::write(&tmp, rest).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }
    letzte.insert(key, z);
}

/// Verlauf eines Geraets ab `seit` (Unix-Zeit); hoechstens `max` Punkte (bei mehr wird gleichmaessig ausgeduennt,
/// der neueste ist immer dabei)
pub fn verlauf(state_dir: &str, device: &str, seit: u64, max: usize) -> Vec<serde_json::Value> {
    let Ok(alle) = std::fs::read_to_string(verlauf_datei(state_dir, device)) else { return vec![] };
    let p: Vec<serde_json::Value> = alle.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|v| v["t"].as_u64().unwrap_or(0) >= seit).collect();
    if p.len() <= max || max < 2 {
        return p;
    }
    let schritt = p.len() as f64 / (max - 1) as f64;
    let mut out: Vec<serde_json::Value> = (0..max - 1).map(|i| p[(i as f64 * schritt) as usize].clone()).collect();
    out.push(p[p.len() - 1].clone());
    out
}

/// Verlauf als GPX (fuer Google Earth, OsmAnd, Komoot …)
pub fn gpx(device: &str, punkte: &[serde_json::Value]) -> String {
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
    let zeit = |t: u64| {
        let (d, s) = ((t / 86400) as i64, t % 86400);
        // Tage seit 1970 -> Datum (Howard Hinnant)
        let z = d + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
        format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
    };
    let mut g = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<gpx version=\"1.1\" creator=\"KroneVPN\" xmlns=\"http://www.topografix.com/GPX/1/1\">\n<trk><name>{}</name><trkseg>\n",
        esc(device)
    );
    for p in punkte {
        let (Some(lat), Some(lon)) = (p["lat"].as_f64(), p["lon"].as_f64()) else { continue };
        let desc = format!("{} ±{} m{}", p["src"].as_str().unwrap_or(""), p["acc"].as_f64().unwrap_or(0.0), p["ssid"].as_str().map(|s| format!(" WLAN {s}")).unwrap_or_default());
        g.push_str(&format!("<trkpt lat=\"{lat}\" lon=\"{lon}\"><time>{}</time><desc>{}</desc></trkpt>\n", zeit(p["t"].as_u64().unwrap_or(0)), esc(&desc)));
    }
    g.push_str("</trkseg></trk>\n</gpx>\n");
    g
}

/// Ort der IP-Adresse beim Verbinden in den Verlauf (wartet kurz auf die Abfrage bei ipwho.is)
pub fn verlauf_ip(state_dir: &str, device: &str, ip: &str) {
    let (sd, dev, ip) = (state_dir.to_string(), device.to_string(), ip.to_string());
    std::thread::spawn(move || {
        for _ in 0..15 {
            match get(&sd, &ip) {
                Some(g) if g.local || (g.lat == 0.0 && g.lon == 0.0) => return,
                Some(g) => {
                    let v = serde_json::json!({"lat": g.lat, "lon": g.lon, "acc": IP_ACC, "t": kvpn::util::now_secs(), "city": g.city});
                    verlauf_add(&sd, &dev, &v, "ip");
                    return;
                }
                None => std::thread::sleep(std::time::Duration::from_secs(1)),
            }
        }
    });
}

// ------------------------------------------------------------------ bester Standort aus allen Quellen

/// Ein Standort gilt so lange als aktuell (danach zaehlt der neueste)
const AKTUELL: u64 = 30 * 60;
/// Genauigkeit einer IP-Ortung (Ort des Netzanschlusses, oft nur die Stadt)
pub const IP_ACC: f64 = 25_000.0;

/// Bester Standort eines Geraets: {lat, lon, acc (Meter), t, src: "gps"|"wlan"|"ip", label}.
/// Unter den aktuellen (juenger als 30 Minuten) gewinnt der genaueste, sonst der neueste.
///   dev  = Meldung des Handys (GPS/Netz-Ortung), wlan = Ortung ueber WLAN-Datenbanken, ip = Ort der IP-Adresse
pub fn best(dev: Option<&serde_json::Value>, wlan: Option<&serde_json::Value>, ip: Option<&Geo>, ip_t: u64, now: u64) -> Option<serde_json::Value> {
    struct K {
        lat: f64,
        lon: f64,
        acc: f64,
        t: u64,
        src: &'static str,
        label: String,
    }
    let mut k: Vec<K> = Vec::new();
    let f = |v: &serde_json::Value, key: &str| v.get(key).and_then(|x| x.as_f64());
    if let Some(d) = dev {
        if let (Some(lat), Some(lon)) = (f(d, "lat"), f(d, "lon")) {
            let t = d.get("t").and_then(|x| x.as_u64()).or_else(|| d.get("got").and_then(|x| x.as_u64())).unwrap_or(0).min(now);
            let quelle = d.get("src").and_then(|x| x.as_str()).unwrap_or("");
            let label = match quelle {
                "gps" => "GPS des Handys".to_string(),
                "passive" => "GPS des Handys (von einer anderen App angefragt)".to_string(),
                "" => "Ortung des Handys".to_string(),
                q => format!("Ortung des Handys ({q})"),
            };
            k.push(K { lat, lon, acc: f(d, "acc").unwrap_or(50.0), t, src: "gps", label });
        }
    }
    if let Some(w) = wlan {
        if let (Some(lat), Some(lon)) = (f(w, "lat"), f(w, "lon")) {
            let t = w.get("t").and_then(|x| x.as_u64()).unwrap_or(0).min(now);
            let wer = w.get("via").and_then(|x| x.as_str()).unwrap_or("WLAN-Datenbank");
            let ssid = w.get("ssid").and_then(|x| x.as_str()).filter(|x| !x.is_empty()).map(|x| format!(" „{x}“")).unwrap_or_default();
            k.push(K { lat, lon, acc: f(w, "acc").unwrap_or(150.0), t, src: "wlan", label: format!("WLAN{ssid} über {wer}") });
        }
    }
    if let Some(g) = ip.filter(|g| !g.local && (g.lat != 0.0 || g.lon != 0.0)) {
        k.push(K { lat: g.lat, lon: g.lon, acc: IP_ACC, t: ip_t.min(now), src: "ip", label: "IP-Adresse (Ort des Internet-Anschlusses)".into() });
    }
    let aktuell: Vec<&K> = k.iter().filter(|x| now.saturating_sub(x.t) < AKTUELL).collect();
    let b = if aktuell.is_empty() {
        k.iter().max_by(|a, b| a.t.cmp(&b.t).then(b.acc.total_cmp(&a.acc)))?
    } else {
        *aktuell.iter().min_by(|a, b| a.acc.total_cmp(&b.acc))?
    };
    Some(serde_json::json!({"lat": b.lat, "lon": b.lon, "acc": b.acc.round(), "t": b.t, "src": b.src, "label": b.label}))
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
    fn meldung_pruefen() {
        let r = clean_report(br#"{"ssid":"FritzBox 7590","bssid":"aa:bb:cc:dd:ee:ff","lat":48.1,"lon":11.5,"acc":12.5,"src":"gps","t":1700000000,"boese":"x"}"#).unwrap().unwrap();
        assert_eq!(r["ssid"], "FritzBox 7590");
        assert_eq!(r["acc"], 12.5);
        assert!(r.get("boese").is_none() && r.get("got").is_some());
        assert!(clean_report(br#"{"off":true}"#).unwrap().is_none());
        assert!(clean_report(br#"{"lat":200,"lon":1}"#).is_none());
        assert!(clean_report(b"kaputt").is_none());
        let d = std::env::temp_dir().join(format!("kvpn-geo-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let sd = d.to_str().unwrap();
        device_report(sd, "Handy", br#"{"ssid":"Zuhause"}"#, &WlanKeys::default());
        assert_eq!(device_info(sd, "Handy").unwrap()["ssid"], "Zuhause");
        device_report(sd, "Handy", br#"{"off":true}"#, &WlanKeys::default());
        assert!(device_info(sd, "Handy").is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn bester_standort() {
        let now = 1_800_000_000u64;
        let gps = serde_json::json!({"lat": 48.1, "lon": 11.5, "acc": 12.0, "t": now - 60, "src": "gps"});
        let alt = serde_json::json!({"lat": 48.1, "lon": 11.5, "acc": 12.0, "t": now - 7200, "src": "gps"});
        let wlan = serde_json::json!({"lat": 48.2, "lon": 11.6, "acc": 80.0, "t": now - 30, "via": "WiGLE", "ssid": "FritzBox"});
        let ip = Geo { city: "München".into(), lat: 48.13, lon: 11.58, ts: now, ..Default::default() };
        // frisches GPS ist am genauesten
        assert_eq!(best(Some(&gps), Some(&wlan), Some(&ip), now, now).unwrap()["src"], "gps");
        // GPS 2 h alt: WLAN-Ortung von gerade eben gewinnt
        let b = best(Some(&alt), Some(&wlan), Some(&ip), now, now).unwrap();
        assert_eq!(b["src"], "wlan");
        assert!(b["label"].as_str().unwrap().contains("FritzBox") && b["label"].as_str().unwrap().contains("WiGLE"));
        // nur IP
        let b = best(None, None, Some(&ip), now, now).unwrap();
        assert_eq!((b["src"].as_str().unwrap(), b["acc"].as_f64().unwrap()), ("ip", IP_ACC));
        // alles alt: das neueste zaehlt (IP von vor 1 h statt GPS von vor 2 h)
        assert_eq!(best(Some(&alt), None, Some(&ip), now - 3600, now).unwrap()["src"], "ip");
        // lokales Netz / nichts
        assert!(best(None, None, Some(&Geo { local: true, ..Default::default() }), now, now).is_none());
        // WLAN-Liste aus der App wird geprueft
        let r = clean_report(br#"{"ssid":"X","bssid":"AA:BB:CC:DD:EE:FF","aps":[{"b":"11:22:33:44:55:66","s":-50},{"b":"kaputt","s":1},{"b":"02:00:00:00:00:00"}]}"#).unwrap().unwrap();
        assert_eq!(r["bssid"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(r["aps"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn bewegungs_verlauf() {
        let d = std::env::temp_dir().join(format!("kvpn-verlauf-{}", std::process::id()));
        let sd = d.to_str().unwrap();
        let t0 = kvpn::util::now_secs() - 100_000;
        let p = |t: u64, lat: f64, lon: f64| serde_json::json!({"t": t, "lat": lat, "lon": lon, "acc": 10.0, "ssid": "Café <&>"});
        verlauf_add(sd, "Mein Handy", &p(t0, 48.0, 11.0), "gps");
        verlauf_add(sd, "Mein Handy", &p(t0 + 60, 48.00001, 11.0), "gps"); // steht still -> entfaellt
        verlauf_add(sd, "Mein Handy", &p(t0 + 120, 48.01, 11.0), "gps"); // ~1,1 km weiter
        verlauf_add(sd, "Mein Handy", &p(t0 + 1100, 48.01, 11.0), "gps"); // still, aber 15 min um -> Lebenszeichen
        verlauf_add(sd, "Mein Handy", &p(t0 + 50, 47.0, 10.0), "gps"); // aelter als der letzte -> entfaellt
        verlauf_add(sd, "Mein Handy", &serde_json::json!({"lat": 1.0}), "gps"); // unvollstaendig
        let v = verlauf(sd, "Mein Handy", 0, 1000);
        assert_eq!(v.len(), 3, "{v:?}");
        assert!((dist_m(48.0, 11.0, 48.01, 11.0) - 1112.0).abs() < 5.0);
        assert_eq!(verlauf(sd, "Mein Handy", t0 + 100, 1000).len(), 2);
        assert!(verlauf(sd, "anderes", 0, 10).is_empty());
        // ausduennen: der neueste bleibt
        for i in 0..50 {
            verlauf_add(sd, "Laptop", &p(t0 + i * 1000, 48.0 + i as f64 * 0.01, 11.0), "wlan");
        }
        let v = verlauf(sd, "Laptop", 0, 10);
        assert_eq!(v.len(), 10);
        assert_eq!(v[9]["t"], t0 + 49_000);
        let g = gpx("Mein <Handy>", &verlauf(sd, "Mein Handy", 0, 1000));
        assert!(g.contains("<name>Mein &lt;Handy&gt;</name>") && g.matches("<trkpt").count() == 3 && g.contains("Café &lt;&amp;&gt;"));
        assert!(gpx("x", &[serde_json::json!({"t": 1_700_000_000u64, "lat": 1.0, "lon": 2.0})]).contains("<time>2023-11-14T22:13:20Z</time>"));
        assert_ne!(verlauf_datei(sd, "a/b"), verlauf_datei(sd, "a_b"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn wlan_antworten() {
        let g = parse_google(br#"{"location":{"lat":48.137,"lng":11.575},"accuracy":23.5}"#).unwrap();
        assert_eq!(g, (48.137, 11.575, 23.5));
        assert!(parse_google(br#"{"error":{"code":404,"message":"Not Found"}}"#).is_none());
        let w = parse_wigle(br#"{"success":true,"totalResults":1,"results":[{"trilat":52.52,"trilong":13.405,"ssid":"FRITZ!Box","netid":"AA:BB:CC:DD:EE:FF"}]}"#).unwrap();
        assert_eq!(w, (52.52, 13.405));
        assert!(parse_wigle(br#"{"success":true,"totalResults":0,"results":[]}"#).is_none());
        assert!(parse_wigle(br#"{"success":false,"message":"too many queries today"}"#).is_none());
        let fp = fingerabdruck(&serde_json::json!({"bssid":"aa:aa:aa:aa:aa:aa","aps":[{"b":"cc:cc:cc:cc:cc:cc"},{"b":"aa:aa:aa:aa:aa:aa"}]}));
        assert_eq!(fp, "aa:aa:aa:aa:aa:aa,cc:cc:cc:cc:cc:cc");
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
