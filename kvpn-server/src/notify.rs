//! Benachrichtigungen aufs Handy (ab Server 1.3.0): ntfy (App "ntfy", eigener oder oeffentlicher Server) und/oder
//! Telegram (eigener Bot).
//!
//! Gemeldet wird (einzeln abschaltbar):
//!   * "geraet":   ein Geraet verbindet sich zum allerersten Mal
//!   * "passwort": falsches Passwort / falscher Code auf der Admin-Seite (hoechstens alle 10 Minuten)
//!   * "start":    der VPN-Server ist (neu) gestartet, z. B. nach Stromausfall oder Update
//!   * "update":   neue App-Version auf GitHub, wartet auf Freigabe
//!   * "bericht":  am Monatsanfang der Bericht fuer den letzten Monat
//!   * "ausfall":  ein ueberwachtes Geraet ist zu lange offline, der Server ist von aussen nicht erreichbar,
//!                 eine Sicherung ging schief (ab 1.4.0) – und jeweils Entwarnung
//! Gesendet wird im Hintergrund mit curl; Zugangsdaten stehen nur in server.toml (nur root lesbar).

use crate::config::Config;
use crate::log;
use crate::server::Shared;
use std::sync::Mutex;

pub enum Ereignis {
    NeuesGeraet { name: String, os: String, von: String },
    FalschesPasswort,
    Start { version: String, pause: Option<String> },
    Update { version: String },
    Bericht { text: String },
    Ausfall { titel: String, text: String },
}

pub const ALLE: &[&str] = &["geraet", "passwort", "start", "update", "bericht", "ausfall"];

impl Ereignis {
    fn art(&self) -> &'static str {
        match self {
            Ereignis::NeuesGeraet { .. } => "geraet",
            Ereignis::FalschesPasswort => "passwort",
            Ereignis::Start { .. } => "start",
            Ereignis::Update { .. } => "update",
            Ereignis::Bericht { .. } => "bericht",
            Ereignis::Ausfall { .. } => "ausfall",
        }
    }

    fn text(&self, vpn: &str) -> (String, String, &'static str) {
        match self {
            Ereignis::NeuesGeraet { name, os, von } => (
                format!("{vpn}: neues Gerät verbunden"),
                format!("„{name}“ ({os}) hat sich zum ersten Mal verbunden{}.", if von.is_empty() { String::new() } else { format!(" – von {von}") }),
                "iphone",
            ),
            Ereignis::FalschesPasswort => (
                format!("{vpn}: falsches Admin-Passwort"),
                "Auf der Admin-Seite wurde ein falsches Passwort oder ein falscher Code eingegeben. Warst du das nicht, Admin-Passwort ändern.".into(),
                "warning",
            ),
            Ereignis::Start { version, pause } => (
                format!("{vpn}: Server gestartet"),
                match pause {
                    Some(p) => format!("Der VPN-Server läuft wieder (Version {version}) – er war {p} nicht erreichbar (Stromausfall, Neustart oder Update?)."),
                    None => format!("Der VPN-Server läuft wieder (Version {version})."),
                },
                "rocket",
            ),
            Ereignis::Bericht { text } => (format!("{vpn}: Monatsbericht"), text.clone(), "bar_chart"),
            Ereignis::Ausfall { titel, text } => (format!("{vpn}: {titel}"), text.clone(), "rotating_light"),
            Ereignis::Update { version } => (
                format!("{vpn}: neue App-Version {version}"),
                format!("Version {version} liegt auf GitHub bereit. Verteilen an die Geräte: kvpn-server update (oder auf der Admin-Seite)."),
                "package",
            ),
        }
    }
}

/// irgendein Weg eingerichtet?
pub fn configured(c: &Config) -> bool {
    !c.notify_ntfy.is_empty() || (!c.notify_telegram_token.is_empty() && !c.notify_telegram_chat.is_empty())
}

static LAST_PW: Mutex<u64> = Mutex::new(0);

/// Ereignis melden (wenn eingerichtet und nicht abgeschaltet) – kehrt sofort zurueck
pub fn event(sh: &Shared, e: Ereignis) {
    let c = sh.cfg();
    event_cfg(&c, e);
}

pub fn event_cfg(c: &Config, e: Ereignis) {
    if !configured(c) || !c.notify_on.iter().any(|x| x == e.art()) {
        return;
    }
    if let Ereignis::FalschesPasswort = e {
        let now = kvpn::util::now_secs();
        let mut l = LAST_PW.lock().unwrap();
        if now.saturating_sub(*l) < 600 {
            return;
        }
        *l = now;
    }
    let (title, text, tag) = e.text(c.display_name());
    let c = c.clone();
    std::thread::spawn(move || {
        if let Err(err) = send(&c, &title, &text, tag) {
            log!("Benachrichtigung nicht gesendet: {err}");
        }
    });
}

/// URL-Kodierung fuer Abfrage-Parameter
fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// curl mit Adresse (und Zugang) ueber stdin – Zugangsdaten tauchen so nicht in der Prozessliste auf
fn curl(url: &str, bearer: &str, args: &[String]) -> Result<String, String> {
    use std::io::Write;
    let mut ch = std::process::Command::new("curl")
        .args(["-sS", "--fail-with-body", "-m", "15", "--proto", "=https,http", "-K", "-"])
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl nicht gefunden ({e})"))?;
    let mut k = format!("url = \"{}\"\n", url.replace('"', "%22"));
    if !bearer.is_empty() {
        k += &format!("header = \"Authorization: Bearer {}\"\n", bearer.replace(['"', '\\', '\n'], ""));
    }
    ch.stdin.take().unwrap().write_all(k.as_bytes()).map_err(|e| e.to_string())?;
    let o = ch.wait_with_output().map_err(|e| e.to_string())?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        let mut m = format!("{} {}", String::from_utf8_lossy(&o.stderr).trim(), String::from_utf8_lossy(&o.stdout).trim());
        // Bot-Schluessel nie im Protokoll
        if let Some(i) = m.find("/bot") {
            m.replace_range(i.., "/bot…");
        }
        Err(m.trim().chars().take(200).collect())
    }
}

/// an alle eingerichteten Wege senden. Ok = mindestens einer hat geklappt
pub fn send(c: &Config, title: &str, text: &str, tag: &str) -> Result<String, String> {
    let mut ok = Vec::new();
    let mut err = Vec::new();
    if !c.notify_ntfy.is_empty() {
        let sep = if c.notify_ntfy.contains('?') { '&' } else { '?' };
        let url = format!("{}{sep}title={}&tags={}", c.notify_ntfy, enc(title), enc(tag));
        match curl(&url, &c.notify_ntfy_token, &["--data-binary".into(), text.into()]) {
            Ok(_) => ok.push("ntfy"),
            Err(e) => err.push(format!("ntfy: {e}")),
        }
    }
    if !c.notify_telegram_token.is_empty() && !c.notify_telegram_chat.is_empty() {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", c.notify_telegram_token);
        let url = std::env::var("KVPN_TELEGRAM_URL").unwrap_or(url);
        let args = vec!["--data-urlencode".into(), format!("chat_id={}", c.notify_telegram_chat), "--data-urlencode".into(), format!("text={title}\n{text}")];
        match curl(&url, "", &args) {
            Ok(_) => ok.push("Telegram"),
            Err(e) => err.push(format!("Telegram: {e}")),
        }
    }
    if ok.is_empty() && err.is_empty() {
        return Err("keine Benachrichtigung eingerichtet (ntfy-Adresse oder Telegram-Bot)".into());
    }
    if ok.is_empty() {
        Err(err.join("; "))
    } else if err.is_empty() {
        Ok(format!("gesendet an {}", ok.join(" + ")))
    } else {
        Ok(format!("gesendet an {} – {}", ok.join(" + "), err.join("; ")))
    }
}

/// Probe-Nachricht (Admin-Seite, kvpn-server benachrichtigung test)
pub fn test(c: &Config) -> Result<String, String> {
    send(c, &format!("{}: Test", c.display_name()), "Benachrichtigungen funktionieren ✓", "white_check_mark")
}

// ------------------------------------------------------------------------------------------------ HomeServer

/// ntfy-Server des HomeServers (/etc/hs-notify.conf: URL, TOKEN): (Adresse des Themas, Token)
pub fn homeserver(thema: &str) -> Result<(String, String), String> {
    let f = std::env::var("KVPN_HS_NOTIFY").unwrap_or_else(|_| "/etc/hs-notify.conf".into());
    let text = std::fs::read_to_string(&f).map_err(|e| format!("{f}: {e} (kein HomeServer mit ntfy?)"))?;
    let get = |k: &str| {
        text.lines().find_map(|l| {
            let (a, b) = l.trim().split_once('=')?;
            (a.trim() == k && !l.trim_start().starts_with('#')).then(|| b.trim().trim_matches('"').to_string())
        })
    };
    let url = get("URL").filter(|u| !u.is_empty()).ok_or(format!("{f}: URL fehlt"))?;
    let token = get("TOKEN").unwrap_or_default();
    Ok((format!("{}/{thema}", url.trim_end_matches('/')), token))
}

// ------------------------------------------------------------------------------------------------ neue Geraete

fn seen_file(c: &Config) -> std::path::PathBuf {
    std::path::Path::new(&c.state_dir).join("bekannte-geraete.txt")
}

/// beim Start: Liste der bekannten Geraete anlegen, falls es sie noch nicht gibt (alle eingetragenen gelten als bekannt)
pub fn init_seen(c: &Config) {
    let f = seen_file(c);
    if !f.exists() {
        let all: String = c.peers.iter().map(|p| format!("{}\t{}\n", p.name, &p.public_key[..p.public_key.len().min(12)])).collect();
        let _ = std::fs::write(&f, all);
    }
}

/// beim ersten Verbinden eines Geraets (Name + Schluessel) melden. Beim allerersten Aufruf ueberhaupt werden alle
/// schon eingetragenen Geraete still als bekannt uebernommen (keine Flut nach dem Update).
pub fn device_connected(sh: &Shared, name: &str, key: &str, os: &str, von: &str) {
    let c = sh.cfg();
    let f = seen_file(&c);
    let id = format!("{name}\t{}", &key[..key.len().min(12)]);
    let text = match std::fs::read_to_string(&f) {
        Ok(t) => t,
        Err(_) => {
            let all: String = c.peers.iter().map(|p| format!("{}\t{}\n", p.name, &p.public_key[..p.public_key.len().min(12)])).collect();
            let _ = std::fs::write(&f, &all);
            all
        }
    };
    if text.lines().any(|l| l == id) {
        return;
    }
    let _ = std::fs::write(&f, format!("{text}{id}\n"));
    event(sh, Ereignis::NeuesGeraet { name: name.into(), os: os.into(), von: von.into() });
}

#[cfg(test)]
mod tests {
    #[test]
    fn kodierung() {
        assert_eq!(super::enc("Krone VPN: Test ✓"), "Krone%20VPN%3A%20Test%20%E2%9C%93");
    }
}
