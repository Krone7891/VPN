//! Gaeste einladen (ab Server 1.4.0): ein Link (oder QR-Code) fuer Besuch, der nach ein paar Tagen von selbst
//! ungueltig wird.
//!
//!   kvpn-server gast "Oma" [--tage 7]      legt das Geraet "Gast Oma" an (laeuft nach 7 Tagen ab) und zeigt den Link
//!   kvpn-server gaeste                     Liste
//!
//! Der Link https://<server>/einladung/<geheim> zeigt eine Seite mit den Apps zum Herunterladen und einem Knopf
//! "Zugang anzeigen". Erst dieser Knopf zeigt den Verbindungscode (QR + "In der App oeffnen") – und nur EINMAL:
//! Vorschauen in Messengern (die den Link selbst aufrufen) verbrauchen ihn also nicht. Danach zeigt der Link nur
//! noch "schon abgeholt". Nach Ablauf ist das Geraet gesperrt und wird einen Tag spaeter ganz entfernt (Platz frei).
//! Gespeichert wird nur eine Pruefsumme des Links (benutzer.db) – wer die Datenbank liest, kann ihn nicht nachbauen.

use crate::config::{Config, Peer};
use crate::users;
use sha2::{Digest, Sha256};

/// Ergebnis beim Anlegen
pub struct Neu {
    pub device: String,
    pub link: String,
    pub expires: i64,
}

pub fn hash(token: &str) -> String {
    Sha256::digest(token.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn new_token() -> String {
    let b: [u8; 18] = rand::random();
    // URL-sicher (Base64url ohne Fuellzeichen)
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (c[1] as u32) << 8 | c[2] as u32;
        for i in (0..4).rev() {
            s.push(A[(n >> (6 * i) & 63) as usize] as char);
        }
    }
    s
}

/// Grundadresse des Servers fuer Links (https://host[:port])
pub fn base_url(c: &Config) -> String {
    match kvpn::transport::parse_url(&c.public_url) {
        Ok(t) => {
            let host = if t.host.contains(':') { format!("[{}]", t.host) } else { t.host.clone() };
            let port = if (t.tls && t.port == 443) || (!t.tls && t.port == 80) { String::new() } else { format!(":{}", t.port) };
            format!("{}://{host}{port}", if t.tls { "https" } else { "http" })
        }
        Err(_) => String::new(),
    }
}

/// Gast anlegen: Geraet "Gast <name>" mit Ablauf in `tage` Tagen und Einladungs-Link
pub fn anlegen(cfg_path: &str, name: &str, tage: u32) -> Result<Neu, String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 34 || name.contains(['"', '\n', '/', '\\']) {
        return Err("Name fehlt oder ungueltig (hoechstens 34 Zeichen)".into());
    }
    if !(1..=90).contains(&tage) {
        return Err("Gaeste: 1 bis 90 Tage".into());
    }
    let mut cfg = Config::load(cfg_path)?;
    if !cfg.users {
        return Err("Gaeste brauchen die Benutzerverwaltung (einschalten: kvpn-server einstellungen --benutzer an)".into());
    }
    let device = format!("Gast {name}");
    if cfg.peers.iter().chain(&cfg.inactive).any(|p| p.name.eq_ignore_ascii_case(&device)) {
        return Err(format!("„{device}“ gibt es schon – anderen Namen nehmen oder erst entfernen"));
    }
    let index = cfg.free_index().ok_or(format!("alle {} Plätze belegt – erst ein Gerät entfernen oder mehr erlauben", cfg.max_devices))?;
    let (cpriv, cpub) = kvpn::crypto::generate_keypair();
    let peer = Peer { name: device.clone(), public_key: kvpn::code::key_to_b64(&cpub), index, user: String::new() };
    cfg.peers.push(peer.clone());
    cfg.check()?;
    // der Code muss beim Abholen wieder erzeugt werden koennen -> Schluessel wie bei "add" ablegen (nur root)
    crate::config::store_key(cfg_path, &peer, &cpriv)?;
    let db = users::open(cfg_path)?;
    if let Err(e) = users::add_device(&db, &peer) {
        crate::config::remove_key(cfg_path, &peer);
        return Err(e);
    }
    // gilt bis Tagesende des letzten Tages
    let now = kvpn::util::now_secs() as i64;
    let expires = (now / 86400 + tage as i64 + 1) * 86400 - 1;
    users::set_expires(&db, &device, expires)?;
    let token = new_token();
    users::gast_add(&db, &device, &hash(&token), expires)?;
    users::log_event(cfg_path, &device, &format!("als Gast eingeladen (bis {})", users::date(expires)));
    Ok(Neu { device, link: format!("{}/einladung/{token}", base_url(&cfg)), expires })
}

/// Zustand eines Links
pub enum Stand {
    /// gibt es nicht (oder entfernt)
    Unbekannt,
    /// abgelaufen
    Abgelaufen,
    /// schon abgeholt (Zeitpunkt)
    Abgeholt(i64),
    /// gueltig: (Geraet, Ablauf)
    Offen(String, i64),
}

fn token_ok(token: &str) -> bool {
    token.len() == 24 && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn stand(cfg_path: &str, token: &str) -> Stand {
    if !token_ok(token) {
        return Stand::Unbekannt;
    }
    let Ok(db) = users::open(cfg_path) else { return Stand::Unbekannt };
    let Ok(Some(e)) = users::gast_by_token(&db, &hash(token)) else { return Stand::Unbekannt };
    if e.expires <= kvpn::util::now_secs() as i64 {
        return Stand::Abgelaufen;
    }
    if e.used > 0 {
        return Stand::Abgeholt(e.used);
    }
    Stand::Offen(e.device, e.expires)
}

/// Code abholen (nur einmal): Verbindungscode
pub fn abholen(cfg_path: &str, token: &str) -> Result<(String, i64), String> {
    let Stand::Offen(device, expires) = stand(cfg_path, token) else { return Err("Diese Einladung gilt nicht mehr".into()) };
    let cfg = Config::load(cfg_path)?;
    let p = cfg.peers.iter().find(|p| p.name.eq_ignore_ascii_case(&device)).ok_or("Gast-Zugang ist gesperrt")?;
    let code = crate::config::stored_code(cfg_path, &cfg, p).ok_or("Verbindungscode nicht gefunden")?;
    let db = users::open(cfg_path)?;
    users::gast_used(&db, &device)?;
    users::log_event(cfg_path, &device, "Einladung abgeholt");
    crate::log!("{device}: Einladung abgeholt");
    Ok((code, expires))
}

/// abgelaufene Gaeste einen Tag nach Ablauf ganz entfernen. Ergebnis: entfernte Geraete
pub fn aufraeumen(cfg_path: &str) -> Vec<String> {
    let Ok(db) = users::open(cfg_path) else { return Vec::new() };
    let now = kvpn::util::now_secs() as i64;
    let mut out = Vec::new();
    for g in users::gaeste(&db).unwrap_or_default() {
        if g.expires + 86400 < now {
            if let Ok(Some(p)) = users::remove_device(&db, &g.device) {
                crate::config::remove_key(cfg_path, &p);
            }
            let _ = users::gast_remove(&db, &g.device);
            out.push(g.device);
        }
    }
    out
}

// ------------------------------------------------------------------------------------------------ Seite

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn seite(titel: &str, logo: &str, inhalt: &str) -> String {
    format!(
        r#"<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer"><title>{t}</title>
<style>:root{{--bg:#f4f5f8;--card:#fff;--ink:#16181d;--mute:#5d6472;--line:#e3e6ec;--acc:#3b6cf6;--ok:#1f9d55;color-scheme:light}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0f1115;--card:#171a21;--ink:#e8eaf0;--mute:#9aa3b2;--line:#262b35;--acc:#6f95ff;--ok:#3ccf7a;color-scheme:dark}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
.w{{max-width:560px;margin:0 auto;padding:28px 16px 50px}}h1{{font-size:26px;margin:0 0 4px}}.sub{{color:var(--mute);margin:0 0 18px}}
.c{{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;margin-top:14px}}.c h2{{font-size:17px;margin:0 0 6px}}
.b{{display:block;width:100%;text-align:center;font:inherit;font-weight:600;font-size:16px;padding:13px;border-radius:12px;border:0;background:var(--acc);color:#fff;text-decoration:none;cursor:pointer;margin-top:10px}}
.b2{{background:transparent;color:var(--ink);border:1px solid var(--line)}}.m{{color:var(--mute);font-size:13.5px}}ol{{padding-left:20px;margin:6px 0}}li{{margin:4px 0}}
.qr{{background:#fff;border-radius:12px;padding:10px;max-width:300px;margin:8px auto}}.qr svg{{width:100%;height:auto;display:block}}
code{{display:block;word-break:break-all;font-size:12px;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px;margin-top:8px}}.lg{{width:40px;height:40px;border-radius:9px;object-fit:cover;vertical-align:-9px;margin-right:8px}}
.ok{{color:var(--ok);font-weight:600}}</style></head><body><div class="w"><h1>{logo}{t}</h1>{inhalt}</div></body></html>"#,
        t = esc(titel)
    )
}

/// Seite fuer GET (Willkommen + Apps + Knopf) bzw. nach dem Abholen (Code)
pub fn html(cfg: &Config, token: &str, st: &Stand, code: Option<(&str, i64)>, apps: &[(String, u64)], logo_v: u64) -> String {
    let name = cfg.display_name();
    let logo = if logo_v > 0 { format!("<img class=\"lg\" src=\"/einladung/{token}/logo?v={logo_v}\" alt=\"\">") } else { "🛡️ ".into() };
    let apps_html = |hinweis: &str| -> String {
        if apps.is_empty() {
            return String::new();
        }
        let links: String = apps
            .iter()
            .map(|(n, sz)| {
                let l = n.to_lowercase();
                let os = if l.ends_with(".apk") { "🤖 Android" } else if l.ends_with(".exe") { "🪟 Windows" } else if l.contains("linux") { "🐧 Linux" } else { "📦 Datei" };
                format!("<a class=\"b b2\" href=\"/einladung/{token}/app/{}\" download>{os} – {} ({:.1} MB)</a>", crate::web::pct_encode(n), esc(n), *sz as f64 / 1048576.0)
            })
            .collect();
        format!("<div class=\"c\"><h2>1. App installieren</h2><div class=\"m\">{hinweis}</div>{links}</div>")
    };
    let inhalt = match (st, code) {
        (_, Some((code, bis))) => {
            let svg = qrcode::QrCode::with_error_correction_level(code.as_bytes(), qrcode::EcLevel::L)
                .map(|q| q.render::<qrcode::render::svg::Color>().min_dimensions(260, 260).quiet_zone(true).build())
                .unwrap_or_default();
            format!(
                "<p class=\"sub\">Dein Gast-Zugang gilt bis {} (UTC). <span class=\"ok\">Abgeholt ✓</span></p>\
                 <div class=\"c\"><h2>Mit dem VPN verbinden</h2>\
                 <a class=\"b\" href=\"{c}\">In der App öffnen</a>\
                 <div class=\"m\" style=\"margin-top:12px\">Oder: App öffnen und diesen QR-Code scannen bzw. den Code einfügen. Am PC: Code kopieren und beim Start der App einfügen.</div>\
                 <div class=\"qr\">{svg}</div><code id=\"k\">{c}</code>\
                 <button class=\"b b2\" onclick=\"navigator.clipboard.writeText(document.getElementById('k').textContent).then(()=>this.textContent='Kopiert ✓')\">Code kopieren</button></div>\
                 <div class=\"c m\"><b>Wichtig:</b> Diese Seite lässt sich nicht noch einmal öffnen – den Code jetzt in die App übernehmen. Gib ihn nicht weiter: er gehört zu deinem Gast-Zugang.</div>{}",
                users::datetime(bis),
                apps_html("Falls noch nicht geschehen – danach oben „In der App öffnen“."),
                c = esc(code)
            )
        }
        (Stand::Offen(_, bis), None) => format!(
            "<p class=\"sub\">Du bist als Gast eingeladen – der Zugang gilt bis {} (UTC) und endet dann von selbst.</p>{}\
             <div class=\"c\"><h2>2. Zugang abholen</h2><div class=\"m\">Den Knopf erst drücken, wenn die App installiert ist: der Zugang wird nur <b>einmal</b> angezeigt.</div>\
             <form method=\"post\"><button class=\"b\" type=\"submit\">Zugang anzeigen</button></form></div>",
            users::datetime(*bis),
            apps_html("Für dein Gerät herunterladen und installieren.")
        ),
        (Stand::Abgeholt(t), None) => format!("<p class=\"sub\">Diese Einladung wurde schon am {} (UTC) abgeholt. Brauchst du sie nochmal, frag bitte nach einer neuen.</p>", users::datetime(*t)),
        (Stand::Abgelaufen, None) => "<p class=\"sub\">Diese Einladung ist abgelaufen. Frag bitte nach einer neuen.</p>".into(),
        (Stand::Unbekannt, None) => "<p class=\"sub\">Diese Einladung gibt es nicht (mehr).</p>".into(),
    };
    seite(&format!("{name} – Einladung"), &logo, &inhalt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn einladen_abholen_aufraeumen() {
        let base = std::env::temp_dir().join(format!("kvpn-gast-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let cfg_path = base.join("server.toml").to_string_lossy().to_string();
        let (k, _) = kvpn::crypto::generate_keypair();
        let mut c = Config::new("wss://vpn.example.org:8443/api/v1/stream".into(), kvpn::code::key_to_b64(&k));
        c.state_dir = base.join("state").to_string_lossy().to_string();
        c.users = true;
        c.save(&cfg_path).unwrap();
        let n = anlegen(&cfg_path, "Oma", 7).unwrap();
        assert_eq!(n.device, "Gast Oma");
        assert!(n.link.starts_with("https://vpn.example.org:8443/einladung/"), "{}", n.link);
        let token = n.link.rsplit('/').next().unwrap().to_string();
        assert!(token_ok(&token));
        assert!(anlegen(&cfg_path, "Oma", 7).is_err(), "doppelt");
        assert!(matches!(stand(&cfg_path, &token), Stand::Offen(..)));
        assert!(matches!(stand(&cfg_path, "x"), Stand::Unbekannt));
        assert!(matches!(stand(&cfg_path, &"A".repeat(24)), Stand::Unbekannt));
        let (code, bis) = abholen(&cfg_path, &token).unwrap();
        assert!(code.starts_with("kronevpn://"));
        assert!(bis > kvpn::util::now_secs() as i64 + 6 * 86400);
        assert!(abholen(&cfg_path, &token).is_err(), "nur einmal");
        assert!(matches!(stand(&cfg_path, &token), Stand::Abgeholt(_)));
        // abgelaufen (Datum zurueckdrehen) -> gesperrt, einen Tag spaeter entfernt
        let db = users::open(&cfg_path).unwrap();
        db.execute("UPDATE gaeste SET expires = 1000", []).unwrap();
        assert!(matches!(stand(&cfg_path, &token), Stand::Abgelaufen));
        assert_eq!(aufraeumen(&cfg_path), vec!["Gast Oma".to_string()]);
        assert!(Config::load(&cfg_path).unwrap().peers.iter().all(|p| p.name != "Gast Oma"));
        assert!(matches!(stand(&cfg_path, &token), Stand::Unbekannt));
        let _ = std::fs::remove_dir_all(&base);
    }
}
