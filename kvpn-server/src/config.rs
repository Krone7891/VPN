//! Server-Konfiguration (/etc/krone-vpn/server.toml)

use kvpn::crypto::Key32;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Adresse, auf der der Server lauscht (hinter nginx: 127.0.0.1:8101)
    #[serde(default = "d_listen")]
    pub listen: String,
    /// Adresse fuer die Clients (landet im Verbindungscode)
    pub public_url: String,
    /// privater Server-Schluessel (Base64) – geheim halten!
    pub private_key: String,
    #[serde(default = "d_tun")]
    pub tun: String,
    /// IPv4-Netz im Tunnel; Server = .1, Geraete = .2 bis .9
    #[serde(default = "d_net4")]
    pub net4: String,
    /// IPv6-Netz im Tunnel (leer = kein IPv6 im Tunnel; IPv6 der Geraete wird dann blockiert statt durchgelassen)
    #[serde(default = "d_net6")]
    pub net6: String,
    #[serde(default = "d_dns")]
    pub dns: Vec<String>,
    #[serde(default = "d_mtu")]
    pub mtu: u16,
    /// NAT, Weiterleitung und MSS-Anpassung selbst einrichten (iptables/ip6tables)
    #[serde(default = "d_true")]
    pub nat: bool,
    /// TUN-Warteschlangen (0 = eine je CPU-Kern, hoechstens 8)
    #[serde(default)]
    pub queues: usize,
    /// Passwort fuer die Statistik-Seite von aussen (leer = nur aus Heimnetz/VPN)
    #[serde(default)]
    pub stats_password: String,
    #[serde(default = "d_state")]
    pub state_dir: String,
    /// Name des VPN (erscheint in den Apps, auf der Statistik- und Download-Seite)
    #[serde(default)]
    pub vpn_name: String,
    /// lokale Webseite (Statistik + Downloads) nur auf diesem Rechner, ohne TLS und ohne Passwort:
    /// http://localhost:8180 (leer = aus). Der VPN-Tunnel laeuft hier nicht.
    #[serde(default = "d_local")]
    pub local_listen: String,
    /// Ordner mit den Apps fuer /download/ (leer = keine Download-Seite)
    #[serde(default)]
    pub downloads_dir: String,
    /// weiterer Ordner mit den Apps (z. B. Download-Seite einer anderen Webseite), wird bei der Update-Freigabe
    /// ebenfalls aktualisiert (liegt daneben eine files.json, wird sie neu geschrieben). Wird nicht ausgeliefert.
    #[serde(default)]
    pub download_mirror: String,
    /// optional: TLS selbst machen (ohne nginx davor), Pfade zu PEM-Dateien
    #[serde(default)]
    pub tls_cert: String,
    #[serde(default)]
    pub tls_key: String,
    /// App-Updates kommen nur von diesem GitHub-Repo (dist/update.json, signiert) und erst nach Freigabe
    #[serde(default = "d_repo")]
    pub update_repo: String,
    #[serde(default = "d_branch")]
    pub update_branch: String,
    /// regelmaessig bei GitHub nach neuen App-Versionen schauen (nur melden, verteilt wird erst nach Freigabe)
    #[serde(default = "d_true")]
    pub update_check: bool,
    /// Daten mit AES-256-GCM statt ChaCha20-Poly1305 verschluesseln (nur Apps ab 1.0.6, aeltere bleiben bei ChaCha20)
    #[serde(default)]
    pub aes256: bool,
    /// Leistungsmodus: alle CPU-Kerne (eine TUN-Warteschlange je Kern, mehr Threads). Aus = sparsam (1 Warteschlange)
    #[serde(default)]
    pub performance: bool,
    /// Benutzerverwaltung (SQLite, benutzer.db neben server.toml): Benutzer, Geraete sperren, Ablaufdatum, Verlauf.
    /// Die Geraete stehen dann in der Datenbank statt hier.
    #[serde(default = "d_true")]
    pub users: bool,
    /// Admin-Seite auch im VPN: http://<Server im Tunnel>:<Port der lokalen Seite>, z. B. http://10.77.0.1:8180
    #[serde(default = "d_true")]
    pub admin_vpn: bool,
    /// ungefaehren Standort der Geraete (aus der IP-Adresse, ueber ipwho.is) auf der lokalen/Admin-Seite zeigen
    #[serde(default = "d_true")]
    pub geo: bool,
    /// Ortung ueber WLAN-Netze (nur Admin-Seite): Google Geolocation API – Schluessel aus der Google Cloud Console
    /// (API "Geolocation API" aktivieren). Leer = aus. Geht nur an Google, nie auf die Webseite.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub google_geo_key: String,
    /// Ortung ueber WLAN-Netze: WiGLE (wigle.net -> Account -> "Show my token"): "API-Name:API-Token". Leer = aus.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub wigle_api: String,
    /// Passwort dafuer als PBKDF2-Hash (leer = wird beim ersten Aufruf im VPN festgelegt)
    #[serde(default)]
    pub admin_password: String,
    /// zweiter Schritt fuer die Admin-Seite im VPN: TOTP-Geheimnis (Base32) der Authenticator-App, leer = aus
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub admin_totp: String,
    /// eigener DNS im Tunnel (Server 1.3.0): beantwortet die DNS-Anfragen der Geraete selbst – Grundlage fuer den
    /// Werbe-Blocker und fuer Namen im Heimnetz (z. B. nas.fritz.box)
    #[serde(default = "d_true")]
    pub dns_proxy: bool,
    /// Werbe- und Tracker-Blocker (nur mit dns_proxy)
    #[serde(default = "d_true")]
    pub adblock: bool,
    /// Sperrlisten (Hosts-Format oder reine Namensliste), werden taeglich neu geladen
    #[serde(default = "d_lists")]
    pub adblock_lists: Vec<String>,
    /// eigene Sperren (gelten auch fuer Unter-Namen, z. B. "tiktok.com")
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_block: Vec<String>,
    /// Ausnahmen vom Blocker (gehen immer, auch wenn sie auf einer Sperrliste stehen)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_allow: Vec<String>,
    /// Geraete im VPN duerfen ins Heimnetz des Servers (Drucker, NAS, ...). Aus = nur Internet
    #[serde(default = "d_true")]
    pub lan_access: bool,
    /// Benachrichtigungen ueber ntfy: Adresse des Themas, z. B. https://ntfy.sh/mein-geheimes-thema (leer = aus)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notify_ntfy: String,
    /// Zugang zum eigenen ntfy-Server (Bearer-Token, z. B. vom HomeServer aus /etc/hs-notify.conf), leer = ohne
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notify_ntfy_token: String,
    /// Benachrichtigungen ueber Telegram: Bot-Schluessel (von @BotFather) und Chat-ID (leer = aus)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notify_telegram_token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notify_telegram_chat: String,
    /// was gemeldet wird: geraet, passwort, start, update, bericht
    #[serde(default = "d_notify_on")]
    pub notify_on: Vec<String>,
    /// gesperrte/abgelaufene Geraete (nur Benutzerverwaltung; belegen Plaetze und Adressen)
    #[serde(skip)]
    pub inactive: Vec<Peer>,
    /// hoechstens so viele Geraete (einstellbar: kvpn-server max <n>, bis zu LIMIT bzw. so viele, wie in net4 passen)
    #[serde(default = "d_max")]
    pub max_devices: usize,
    #[serde(default, rename = "peer")]
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Peer {
    pub name: String,
    pub public_key: String,
    /// letzte Stelle der Adresse (ab 2)
    pub index: u8,
    /// Benutzer, dem das Geraet gehoert (nur Benutzerverwaltung)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
}

fn d_listen() -> String {
    "127.0.0.1:8101".into()
}
fn d_local() -> String {
    "127.0.0.1:8180".into()
}
fn d_tun() -> String {
    "kvpn0".into()
}
fn d_net4() -> String {
    "10.77.0.0/24".into()
}
fn d_net6() -> String {
    "fd77:6b76::/64".into()
}
fn d_dns() -> Vec<String> {
    vec!["1.1.1.1".into(), "9.9.9.9".into(), "2606:4700:4700::1111".into()]
}
fn d_mtu() -> u16 {
    1400
}
fn d_notify_on() -> Vec<String> {
    crate::notify::ALLE.iter().map(|s| s.to_string()).collect()
}
fn d_lists() -> Vec<String> {
    vec![crate::dns::DEFAULT_LIST.into()]
}
fn d_true() -> bool {
    true
}
fn d_repo() -> String {
    "Krone7891/VPN".into()
}
fn d_branch() -> String {
    "main".into()
}
fn d_max() -> usize {
    kvpn::proto::MAX_PEERS
}
fn d_state() -> String {
    "/var/lib/krone-vpn".into()
}

pub const FIRST_INDEX: u8 = 2;

/// "an"/"aus" (auch ja/nein, true/false, 1/0, on/off)
pub fn on_off(v: &str) -> Result<bool, String> {
    match v.trim().to_lowercase().as_str() {
        "an" | "ja" | "j" | "true" | "1" | "on" | "yes" | "y" | "ein" => Ok(true),
        "aus" | "nein" | "n" | "false" | "0" | "off" | "no" => Ok(false),
        _ => Err(format!("'{v}': bitte an oder aus")),
    }
}
/// Liste von Namen (Komma, Leerzeichen oder Zeilen) fuer dns_block/dns_allow
pub fn name_list(val: &str) -> Result<Vec<String>, String> {
    let mut v: Vec<String> = Vec::new();
    for x in val.split([',', ' ', '\n', ';']) {
        let n = crate::dns::norm(x.trim_start_matches("*.").trim_start_matches("http://").trim_start_matches("https://").split('/').next().unwrap_or(""));
        if n.is_empty() {
            continue;
        }
        if n.len() > 253 || !n.contains('.') || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_') {
            return Err(format!("'{x}' ist kein Name wie werbung.example.com"));
        }
        if !v.contains(&n) {
            v.push(n);
        }
    }
    if v.len() > 500 {
        return Err("hoechstens 500 Namen".into());
    }
    Ok(v)
}

/// absolute Obergrenze fuer max_devices (Adressen .2 bis .251)
pub const LIMIT: usize = 250;

impl Config {
    pub fn new(public_url: String, private_key: String) -> Self {
        let mut c: Config = toml::from_str(&format!("public_url = {:?}\nprivate_key = {:?}\n", public_url, private_key)).unwrap();
        c.public_url = public_url;
        c
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e} (zuerst 'kvpn-server init' ausfuehren)"))?;
        let mut c: Config = toml::from_str(&s).map_err(|e| format!("{path}: {e}"))?;
        if c.users {
            // Geraete aus der Datenbank; noch in server.toml stehende (z. B. nach dem Einschalten) werden uebernommen
            let db = crate::users::open(path)?;
            let old = std::mem::take(&mut c.peers);
            if !old.is_empty() {
                crate::users::import(&db, &old)?;
                c.save(path)?;
            }
            (c.peers, c.inactive) = crate::users::peers(&db)?;
        }
        c.check()?;
        Ok(c)
    }

    /// Adresse der Admin-Seite im VPN (Server-Adresse im Tunnel, Port wie die lokale Seite)
    pub fn admin_addr(&self) -> Option<std::net::SocketAddr> {
        if !self.admin_vpn {
            return None;
        }
        let port = self.local_listen.parse::<std::net::SocketAddr>().map(|a| a.port()).unwrap_or(8180);
        Some(std::net::SocketAddr::from((self.ip4(1), port)))
    }

    /// alle Geraete (auch gesperrte)
    pub fn device_count(&self) -> usize {
        self.peers.len() + self.inactive.len()
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        // mit Benutzerverwaltung stehen die Geraete in benutzer.db, nicht in server.toml
        let mut c = self.clone();
        if c.users {
            c.peers.clear();
        }
        let body = toml::to_string_pretty(&c).map_err(|e| e.to_string())?;
        let text = format!(
            "# KroneVPN Server – Konfiguration\n# Geraete verwalten: kvpn-server add <name> | remove <name> | list   (Aenderungen gelten sofort)\n# private_key ist geheim!\n\n{body}"
        );
        if let Some(dir) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("{tmp}: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("{path}: {e}"))
    }

    pub fn check(&self) -> Result<(), String> {
        self.server_key()?;
        self.net4()?;
        self.net6()?;
        kvpn::transport::parse_url(&self.public_url)?;
        let cap = self.capacity()?;
        if !(1..=cap).contains(&self.max_devices) {
            return Err(format!("max_devices muss zwischen 1 und {cap} liegen (Grenze: {LIMIT} bzw. Groesse von net4 {})", self.net4));
        }
        if self.device_count() > self.max_devices {
            return Err(format!(
                "{} Geraete eingetragen, aber hoechstens {} erlaubt – erst Geraete entfernen (kvpn-server remove <name>) oder max_devices erhoehen",
                self.device_count(),
                self.max_devices
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for p in self.peers.iter().chain(&self.inactive) {
            kvpn::code::key_from_b64(&p.public_key).map_err(|e| format!("Geraet {}: {e}", p.name))?;
            if !(FIRST_INDEX as usize..FIRST_INDEX as usize + cap).contains(&(p.index as usize)) {
                return Err(format!("Geraet {}: index muss {}..{} sein", p.name, FIRST_INDEX, FIRST_INDEX as usize + cap - 1));
            }
            if !seen.insert(p.index) {
                return Err(format!("index {} doppelt vergeben", p.index));
            }
        }
        if !(1280..=9000).contains(&self.mtu) {
            return Err("mtu muss zwischen 1280 und 9000 liegen".into());
        }
        Ok(())
    }

    pub fn display_name(&self) -> &str {
        if self.vpn_name.trim().is_empty() { "KroneVPN" } else { self.vpn_name.trim() }
    }

    /// einzelnen Wert setzen (fuer Installer): kvpn-server set <schluessel> <wert>
    pub fn set(&mut self, key: &str, val: &str) -> Result<(), String> {
        match key {
            "listen" => self.listen = val.into(),
            "local_listen" => self.local_listen = val.into(),
            "public_url" => self.public_url = val.into(),
            "vpn_name" | "name" => {
                if val.chars().count() > 40 || val.contains(['"', '\n', '/', '\\']) {
                    return Err("Name: hoechstens 40 Zeichen, ohne \" / \\".into());
                }
                self.vpn_name = val.trim().into()
            }
            "downloads_dir" => self.downloads_dir = val.into(),
            "download_mirror" => self.download_mirror = val.into(),
            "tls_cert" => self.tls_cert = val.into(),
            "tls_key" => self.tls_key = val.into(),
            "stats_password" => self.stats_password = val.into(),
            "state_dir" => self.state_dir = val.into(),
            "dns" => self.dns = val.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
            "mtu" => self.mtu = val.parse().map_err(|_| "mtu: Zahl erwartet".to_string())?,
            "nat" => self.nat = matches!(val, "true" | "1" | "ja" | "an"),
            "net4" => self.net4 = val.into(),
            "net6" => self.net6 = val.into(),
            "update_repo" => {
                if val.split('/').count() != 2 || val.contains(char::is_whitespace) {
                    return Err("update_repo: GitHub-Repo als besitzer/name".into());
                }
                self.update_repo = val.into()
            }
            "update_branch" => self.update_branch = val.into(),
            "update_check" => self.update_check = matches!(val, "true" | "1" | "ja" | "an"),
            "aes256" | "aes" => self.aes256 = on_off(val)?,
            "performance" | "leistung" | "leistungsmodus" => self.performance = on_off(val)?,
            "users" | "benutzer" | "benutzerverwaltung" => self.users = on_off(val)?,
            "admin_vpn" | "admin" => self.admin_vpn = on_off(val)?,
            "geo" | "standort" => self.geo = on_off(val)?,
            "google_geo_key" | "google" => {
                let v = val.trim();
                if v.contains(char::is_whitespace) || v.contains('"') {
                    return Err("google_geo_key: Schluessel ohne Leerzeichen (leer oder \"aus\" = abschalten)".into());
                }
                self.google_geo_key = if matches!(v, "aus" | "off" | "-") { String::new() } else { v.into() }
            }
            "wigle_api" | "wigle" => {
                let v = val.trim();
                let aus = v.is_empty() || matches!(v, "aus" | "off" | "-");
                if !aus && (!v.contains(':') || v.contains(char::is_whitespace) || v.contains('"')) {
                    return Err("wigle_api: als API-Name:API-Token (von wigle.net -> Account), leer oder \"aus\" = abschalten".into());
                }
                self.wigle_api = if aus { String::new() } else { v.into() }
            }
            "notify_ntfy" | "ntfy" => {
                let v = val.trim();
                if v.is_empty() || matches!(v, "aus" | "off" | "-") {
                    self.notify_ntfy.clear()
                } else if (v.starts_with("https://") || v.starts_with("http://")) && v.len() > 10 && !v.contains(char::is_whitespace) && !v.contains('"') {
                    self.notify_ntfy = v.into()
                } else {
                    return Err("ntfy: Adresse wie https://ntfy.sh/mein-geheimes-thema (\"aus\" = abschalten)".into());
                }
            }
            "notify_ntfy_token" | "ntfy_token" => {
                let v = val.trim();
                if v.is_empty() || matches!(v, "aus" | "off" | "-") {
                    self.notify_ntfy_token.clear()
                } else if v.len() >= 8 && v.bytes().all(|b| b.is_ascii_graphic() && b != b'"') {
                    self.notify_ntfy_token = v.into()
                } else {
                    return Err("ntfy-Zugang: Token ohne Leerzeichen".into());
                }
            }
            "notify_telegram_token" | "telegram_token" => {
                let v = val.trim();
                if v.is_empty() || matches!(v, "aus" | "off" | "-") {
                    self.notify_telegram_token.clear()
                } else if v.contains(':') && v.len() > 20 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'_' || b == b'-') {
                    self.notify_telegram_token = v.into()
                } else {
                    return Err("Telegram: Bot-Schluessel wie 123456789:AAH... (von @BotFather)".into());
                }
            }
            "notify_telegram_chat" | "telegram_chat" => {
                let v = val.trim();
                if v.is_empty() || matches!(v, "aus" | "off" | "-") {
                    self.notify_telegram_chat.clear()
                } else if v.trim_start_matches('-').bytes().all(|b| b.is_ascii_digit()) || (v.starts_with('@') && v.len() > 2) {
                    self.notify_telegram_chat = v.into()
                } else {
                    return Err("Telegram: Chat-ID ist eine Zahl (z. B. von @userinfobot)".into());
                }
            }
            "notify_on" | "melden" => {
                let v: Vec<String> = val.split([',', ' ']).map(|x| x.trim().to_lowercase()).filter(|x| !x.is_empty()).collect();
                if let Some(x) = v.iter().find(|x| !crate::notify::ALLE.contains(&x.as_str()) && x.as_str() != "nichts") {
                    return Err(format!("melden: '{x}' unbekannt (geraet, passwort, start, update, bericht oder nichts)"));
                }
                self.notify_on = v.into_iter().filter(|x| x != "nichts").collect();
            }
            "dns_proxy" | "dns_server" | "eigener_dns" => self.dns_proxy = on_off(val)?,
            "adblock" | "werbeblocker" | "blocker" => self.adblock = on_off(val)?,
            "lan_access" | "heimnetz" => self.lan_access = on_off(val)?,
            "adblock_lists" | "sperrlisten" => {
                let v: Vec<String> = val.split([',', ' ', '\n']).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
                if v.iter().any(|u| !u.starts_with("https://") && !u.starts_with("http://")) {
                    return Err("adblock_lists: Adressen (https://...) mit Komma getrennt".into());
                }
                self.adblock_lists = if v.is_empty() { d_lists() } else { v }
            }
            "dns_block" | "sperren" => self.dns_block = name_list(val)?,
            "dns_allow" | "ausnahmen" => self.dns_allow = name_list(val)?,
            "max_devices" | "max_geraete" | "max" => self.max_devices = val.trim().parse().map_err(|_| "max_devices: Zahl erwartet")?,
            _ => return Err(format!("unbekannter Schluessel '{key}' (listen, local_listen, public_url, vpn_name, downloads_dir, download_mirror, tls_cert, tls_key, stats_password, state_dir, dns, mtu, nat, net4, net6, update_repo, update_branch, update_check, max_devices, aes256, performance, users, admin_vpn, geo, google_geo_key, wigle_api, dns_proxy, adblock, adblock_lists, dns_block, dns_allow, lan_access, notify_ntfy, notify_ntfy_token, notify_telegram_token, notify_telegram_chat, notify_on)")),
        }
        self.check()
    }

    pub fn server_key(&self) -> Result<Key32, String> {
        kvpn::code::key_from_b64(&self.private_key)
    }

    /// (Netzadresse, Praefix)
    pub fn net4(&self) -> Result<(Ipv4Addr, u8), String> {
        match kvpn::util::parse_cidr(&self.net4)? {
            (std::net::IpAddr::V4(a), p) if p <= 28 => Ok((Ipv4Addr::from(u32::from(a) & (!0u32 << (32 - p))), p)),
            _ => Err("net4 muss ein IPv4-Netz bis /28 sein".into()),
        }
    }

    pub fn net6(&self) -> Result<Option<(Ipv6Addr, u8)>, String> {
        if self.net6.trim().is_empty() {
            return Ok(None);
        }
        match kvpn::util::parse_cidr(&self.net6)? {
            (std::net::IpAddr::V6(a), p) if p <= 120 => Ok(Some((Ipv6Addr::from(u128::from(a) & (!0u128 << (128 - p))), p))),
            _ => Err("net6 muss ein IPv6-Netz bis /120 sein".into()),
        }
    }

    pub fn ip4(&self, index: u8) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.net4().unwrap().0) + index as u32)
    }

    pub fn ip6(&self, index: u8) -> Option<Ipv6Addr> {
        self.net6().unwrap().map(|(n, _)| Ipv6Addr::from(u128::from(n) + index as u128))
    }

    /// wie viele Geraete hoechstens moeglich sind (Adressen im net4 ohne Netz, Server und Broadcast; hoechstens LIMIT)
    pub fn capacity(&self) -> Result<usize, String> {
        let (_, p4) = self.net4()?;
        let hosts = if p4 >= 31 { 0 } else { (1usize << (32 - p4 as u32).min(16)) - 3 };
        Ok(hosts.min(LIMIT))
    }

    pub fn free_index(&self) -> Option<u8> {
        if self.device_count() >= self.max_devices {
            return None;
        }
        let cap = self.capacity().ok()?;
        (FIRST_INDEX as usize..FIRST_INDEX as usize + cap).map(|i| i as u8).find(|i| !self.peers.iter().chain(&self.inactive).any(|p| p.index == *i))
    }

    pub fn welcome(&self, p: &Peer) -> kvpn::proto::Welcome {
        let (_, p4) = self.net4().unwrap();
        kvpn::proto::Welcome {
            name: p.name.clone(),
            ip4: format!("{}/{}", self.ip4(p.index), p4),
            ip6: match (self.ip6(p.index), self.net6().unwrap()) {
                (Some(a), Some((_, p6))) => format!("{a}/{p6}"),
                _ => String::new(),
            },
            dns: self.dns.clone(),
            mtu: self.mtu,
            upd: None,
            cipher: String::new(),
            tarn: None,
            pad: String::new(),
            logo: Some(crate::web::logo_app_id(&self.state_dir)),
        }
    }

    pub fn client_config(&self, p: &Peer, private_key: &Key32) -> kvpn::code::ClientConfig {
        let w = self.welcome(p);
        kvpn::code::ClientConfig {
            name: p.name.clone(),
            url: self.public_url.clone(),
            server_pub: kvpn::code::key_to_b64(&kvpn::crypto::public_from_private(&self.server_key().unwrap())),
            private_key: kvpn::code::key_to_b64(private_key),
            ip4: w.ip4,
            ip6: w.ip6,
            dns: w.dns,
            mtu: w.mtu,
            title: self.vpn_name.clone(),
            proxy: String::new(),
        }
    }
}

// ------------------------------------------------------------------------------------------------ gespeicherte Codes

/// Ordner mit den Geraete-Schluesseln (neben server.toml, nur root lesbar) – damit man Codes spaeter wieder anzeigen kann
pub fn codes_dir(cfg_path: &str) -> std::path::PathBuf {
    std::path::Path::new(cfg_path).parent().unwrap_or(std::path::Path::new(".")).join("codes")
}

fn key_file(cfg_path: &str, public_key_b64: &str) -> Option<std::path::PathBuf> {
    let k = kvpn::code::key_from_b64(public_key_b64).ok()?;
    let name: String = k.iter().map(|b| format!("{b:02x}")).collect();
    Some(codes_dir(cfg_path).join(format!("{name}.key")))
}

/// privaten Schluessel eines Geraets merken
pub fn store_key(cfg_path: &str, p: &Peer, private_key: &Key32) -> Result<(), String> {
    let f = key_file(cfg_path, &p.public_key).ok_or("Schluessel ungueltig")?;
    let dir = codes_dir(cfg_path);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let tmp = f.with_extension("tmp");
    std::fs::write(&tmp, kvpn::code::key_to_b64(private_key)).map_err(|e| format!("{}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &f).map_err(|e| format!("{}: {e}", f.display()))
}

pub fn remove_key(cfg_path: &str, p: &Peer) {
    if let Some(f) = key_file(cfg_path, &p.public_key) {
        let _ = std::fs::remove_file(f);
    }
}

/// aktueller Verbindungscode eines Geraets (None = Schluessel nicht gespeichert, z. B. vor Version 1.0.1 angelegt)
pub fn stored_code(cfg_path: &str, cfg: &Config, p: &Peer) -> Option<String> {
    let f = key_file(cfg_path, &p.public_key)?;
    let k = kvpn::code::key_from_b64(&std::fs::read_to_string(f).ok()?).ok()?;
    // passt der gespeicherte Schluessel noch zum Geraet?
    if kvpn::code::key_to_b64(&kvpn::crypto::public_from_private(&k)) != p.public_key {
        return None;
    }
    Some(cfg.client_config(p, &k).to_code())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_limits() {
        let (k, _) = kvpn::crypto::generate_keypair();
        let mut c = Config::new("wss://vpn.example.de/api/v1/stream".into(), kvpn::code::key_to_b64(&k));
        c.check().unwrap();
        assert_eq!(c.listen, "127.0.0.1:8101");
        assert_eq!(c.local_listen, "127.0.0.1:8180");
        for n in 0..8 {
            let i = c.free_index().unwrap();
            let (_, pubk) = kvpn::crypto::generate_keypair();
            c.peers.push(Peer { name: format!("g{n}"), public_key: kvpn::code::key_to_b64(&pubk), index: i, user: String::new() });
        }
        assert!(c.free_index().is_none());
        c.check().unwrap();
        assert_eq!(c.ip4(2).to_string(), "10.77.0.2");
        assert_eq!(c.ip6(9).unwrap().to_string(), "fd77:6b76::9");
        let w = c.welcome(&c.peers[0]);
        assert_eq!(w.ip4, "10.77.0.2/24");
        assert_eq!(w.ip6, "fd77:6b76::2/64");
        let (_, pubk) = kvpn::crypto::generate_keypair();
        c.peers.push(Peer { name: "zuviel".into(), public_key: kvpn::code::key_to_b64(&pubk), index: 5, user: String::new() });
        assert!(c.check().is_err());
        c.peers.pop();
        c.set("vpn_name", "Potzplitz VPN").unwrap();
        c.set("listen", "0.0.0.0:443").unwrap();
        assert!(c.set("vpn_name", "a/b").is_err());
        assert!(c.set("gibtsnicht", "x").is_err());
        assert_eq!(c.client_config(&c.peers[0], &[7; 32]).display_name(), "Potzplitz VPN");
        let (_, pubk) = kvpn::crypto::generate_keypair();
        c.peers.push(Peer { name: "zuviel".into(), public_key: kvpn::code::key_to_b64(&pubk), index: 5, user: String::new() });
        // speichern/laden
        let dir = std::env::temp_dir().join(format!("kvpn-test-{}", std::process::id()));
        let p = dir.join("server.toml");
        c.peers.pop();
        c.users = false;
        c.save(p.to_str().unwrap()).unwrap();
        let d = Config::load(p.to_str().unwrap()).unwrap();
        assert_eq!(d.peers, c.peers);
        // Benutzerverwaltung an: Geraete aus server.toml wandern in benutzer.db
        let t = std::fs::read_to_string(&p).unwrap().replace("users = false", "users = true");
        std::fs::write(&p, t).unwrap();
        let d = Config::load(p.to_str().unwrap()).unwrap();
        assert!(d.users);
        assert_eq!(d.peers, c.peers);
        assert!(!std::fs::read_to_string(&p).unwrap().contains("[[peer]]"), "Geraete stehen jetzt nur noch in der Datenbank");
        assert_eq!(Config::load(p.to_str().unwrap()).unwrap().peers, c.peers);
        let _ = std::fs::remove_dir_all(dir);
    }
}
