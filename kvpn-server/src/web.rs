//! Statistik-Webseite (HTML + JSON) und schlichte 404-Antwort fuer alles andere.

use crate::server::{is_home, login_allowed, login_failed, stats_token, Shared};
use kvpn::util::now_secs;
use serde_json::json;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const PAGE: &str = include_str!("stats.html");

async fn respond<S: AsyncWrite + Unpin>(s: &mut S, code: &str, ctype: &str, extra: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: same-origin\r\n{extra}Connection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes()).await;
    let _ = s.write_all(body).await;
    let _ = s.flush().await;
}

fn cookie(headers: &HashMap<String, String>, name: &str) -> Option<String> {
    headers.get("cookie")?.split(';').find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

fn authorized(sh: &Shared, headers: &HashMap<String, String>, remote: IpAddr, via_nginx: bool) -> bool {
    // ein vorgeschalteter nginx hat die Anmeldung schon geprueft (auth_request) und setzt diesen Kopf selbst
    if via_nginx && headers.get("x-krone-auth").map(|v| v == "homeserver").unwrap_or(false) {
        return true;
    }
    if is_home(remote) {
        return true;
    }
    let cfg = sh.cfg();
    !cfg.stats_password.is_empty() && cookie(headers, "kvpn_stats").map(|c| c == stats_token(&cfg)).unwrap_or(false)
}

pub async fn handle<S>(
    sh: &Arc<Shared>,
    s: &mut S,
    method: &str,
    path: &str,
    query: &str,
    headers: &HashMap<String, String>,
    remote: IpAddr,
    via_nginx: bool,
    local: bool,
    vpn_admin: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let p = path.trim_end_matches('/');
    // Admin-Seite im VPN: erst nach Anmeldung (Passwort wird beim ersten Aufruf festgelegt), dann wie die lokale Seite
    let local = if vpn_admin {
        let cfg = sh.cfg();
        let authed = !cfg.admin_password.is_empty() && cookie(headers, "kvpn_admin").map(|c| c == crate::admin::token(&cfg)).unwrap_or(false);
        if !authed {
            return admin_gate(sh, s, method, p, headers).await;
        }
        true
    } else {
        local
    };
    if p == "/logo" || p.ends_with("/logo") {
        return logo(sh, s, method, headers, local).await;
    }
    // App-Update von GitHub freigeben – nur auf der lokalen Seite
    if p.ends_with("/update") && method == "POST" {
        if !local {
            return respond(s, "403 Forbidden", "application/json", "", br#"{"ok":false,"err":"Freigabe nur lokal auf dem Server (http://localhost:8180) oder mit: kvpn-server update"}"#).await;
        }
        let cfg = sh.cfg();
        let r = tokio::task::spawn_blocking(move || crate::updates::approve(&cfg, &|m| crate::log!("Update: {m}"))).await;
        let b = match r {
            Ok(Ok(v)) => {
                crate::log!("App-Update {v} auf der lokalen Seite freigegeben");
                json!({"ok": true, "version": v})
            }
            Ok(Err(e)) => json!({"ok": false, "err": e}),
            Err(e) => json!({"ok": false, "err": e.to_string()}),
        };
        return respond(s, "200 OK", "application/json; charset=utf-8", "", b.to_string().as_bytes()).await;
    }
    // hoechste Anzahl Geraete einstellen – nur auf der lokalen Seite
    if p.contains("/max/") && method == "POST" {
        if !local {
            return respond(s, "403 Forbidden", "application/json", "", br#"{"ok":false,"err":"Nur lokal auf dem Server (http://localhost:8180) oder mit: kvpn-server max <anzahl>"}"#).await;
        }
        let want = p.rsplit('/').next().unwrap_or("").to_string();
        let r = crate::config::Config::load(&sh.cfg_path).and_then(|mut c| {
            c.set("max_devices", &want)?;
            c.save(&sh.cfg_path)?;
            Ok(c.max_devices)
        });
        let b = match r {
            Ok(n) => {
                crate::log!("Hoechstzahl der Geraete auf {n} gesetzt (lokale Seite)");
                json!({"ok": true, "max": n})
            }
            Err(e) => json!({"ok": false, "err": e}),
        };
        return respond(s, "200 OK", "application/json; charset=utf-8", "", b.to_string().as_bytes()).await;
    }
    // Geraet still anpingen / jetzt orten – nur Admin-Seite (lokal bzw. im VPN mit Passwort)
    if method == "POST" && (p.contains("/ping/") || p.starts_with("ping/") || p.contains("/orten/") || p.starts_with("orten/")) {
        if !local {
            return respond(s, "403 Forbidden", "application/json", "", br#"{"ok":false,"err":"Nur auf der Admin-Seite"}"#).await;
        }
        let name = pct_decode(p.rsplit('/').next().unwrap_or(""));
        let b = if p.contains("ping/") {
            match sh.ping_device(&name).await {
                Ok(ms) => json!({"ok": true, "ms": (ms * 10.0).round() / 10.0}),
                Err(e) => json!({"ok": false, "err": e}),
            }
        } else {
            match sh.locate_device(&name) {
                Ok(()) => {
                    crate::log!("{name}: Ortung von der Admin-Seite angefordert");
                    json!({"ok": true})
                }
                Err(e) => json!({"ok": false, "err": e}),
            }
        };
        return respond(s, "200 OK", "application/json; charset=utf-8", "", b.to_string().as_bytes()).await;
    }
    // Karten-Bibliothek (Leaflet, im Server eingebaut – die Seite laedt keine fremden Skripte)
    if p.ends_with("/leaflet.js") || p == "leaflet.js" || p.ends_with("/leaflet.css") || p == "leaflet.css" {
        let (ct, b): (&str, &[u8]) = if p.ends_with(".js") {
            ("application/javascript; charset=utf-8", include_bytes!("vendor/leaflet/leaflet.js"))
        } else {
            ("text/css; charset=utf-8", include_bytes!("vendor/leaflet/leaflet.css"))
        };
        return respond(s, "200 OK", ct, "", b).await;
    }
    // Standort-Verlauf eines Geraets (Bewegungs-Karte) – nur Admin-Seite, nur mit eingeschaltetem Standort
    let pfad = p;
    if pfad.ends_with("/verlauf.json") || pfad == "verlauf.json" || pfad.ends_with("/verlauf.gpx") || pfad == "verlauf.gpx" {
        let cfg = sh.cfg();
        if !local || !cfg.geo {
            return respond(s, "403 Forbidden", "application/json", "", br#"{"ok":false,"err":"Nur auf der Admin-Seite mit eingeschaltetem Standort"}"#).await;
        }
        let arg = |k: &str| query.split('&').find_map(|kv| kv.split_once('=').filter(|(a, _)| *a == k).map(|(_, v)| pct_decode(v)));
        let geraet = arg("geraet").unwrap_or_default();
        let tage: u64 = arg("tage").and_then(|t| t.parse().ok()).unwrap_or(7).min(3650);
        let seit = if tage == 0 { 0 } else { kvpn::util::now_secs().saturating_sub(tage * 86400) };
        let gpx = pfad.ends_with(".gpx");
        let sd = cfg.state_dir.clone();
        let g2 = geraet.clone();
        let punkte = tokio::task::spawn_blocking(move || crate::geo::verlauf(&sd, &g2, seit, if gpx { 50_000 } else { 5_000 })).await.unwrap_or_default();
        if gpx {
            let datei: String = geraet.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
            let extra = format!("Content-Disposition: attachment; filename=\"standorte-{datei}.gpx\"\r\n");
            return respond(s, "200 OK", "application/gpx+xml; charset=utf-8", &extra, crate::geo::gpx(&geraet, &punkte).as_bytes()).await;
        }
        let b = json!({"ok": true, "geraet": geraet, "tage": tage, "punkte": punkte}).to_string();
        return respond(s, "200 OK", "application/json; charset=utf-8", "", b.as_bytes()).await;
    }
    // Einstellungen auf der Webseite (wie kvpn-server einstellungen) – nur lokal bzw. Admin im VPN
    if p.ends_with("/settings.json") || (method == "POST" && (p.ends_with("/settings") || p.ends_with("/restart"))) {
        if !local {
            return respond(s, "403 Forbidden", "application/json", "", br#"{"ok":false,"err":"Nur auf der Admin-Seite (im VPN oder lokal)"}"#).await;
        }
        if p.ends_with("/restart") {
            if !can_restart() {
                return respond(s, "200 OK", "application/json; charset=utf-8", "", r#"{"ok":false,"err":"Der Server läuft nicht als Dienst (systemd/Docker) und würde nicht von selbst wieder starten – bitte von Hand neu starten."}"#.as_bytes()).await;
            }
            crate::log!("Neustart ueber die Webseite angefordert");
            respond(s, "200 OK", "application/json", "", br#"{"ok":true}"#).await;
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(600)).await;
                // normales Beenden (raeumt Firewall-Regeln auf); systemd (Restart=always) bzw. Docker startet neu
                unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
            });
            return;
        }
        let body = if method == "POST" { read_json(s, headers).await } else { serde_json::Value::Null };
        let sh2 = sh.clone();
        let r = tokio::task::spawn_blocking(move || settings(&sh2, &body)).await.unwrap_or_else(|e| Err(e.to_string()));
        let (b, extra) = match r {
            Ok((v, pw_changed)) => {
                // neues Admin-Passwort: Anmeldung im VPN gleich auf das neue Passwort umstellen
                let extra = if pw_changed && vpn_admin { admin_cookie(&sh.cfg()) } else { String::new() };
                (v, extra)
            }
            Err(e) => (json!({"ok": false, "err": e}), String::new()),
        };
        return respond(s, "200 OK", "application/json; charset=utf-8", &extra, b.to_string().as_bytes()).await;
    }
    // gespeicherte Verbindungscodes mit QR-Code – nur auf der lokalen Seite (http://localhost:8180), nie von aussen
    // Benutzerverwaltung auf der Webseite: Benutzer und Geraete sperren/entsperren (nur lokal bzw. Admin im VPN)
    if p.ends_with("/users.json") || (p.ends_with("/manage") && method == "POST") {
        if !local {
            return respond(s, "403 Forbidden", "application/json", "", br#"{"ok":false,"err":"Nur auf der Admin-Seite (im VPN oder lokal)"}"#).await;
        }
        if !sh.cfg().users {
            return respond(s, "200 OK", "application/json", "", br#"{"ok":false,"enabled":false,"err":"Benutzerverwaltung ist aus (kvpn-server einstellungen --benutzer an)"}"#).await;
        }
        let body = if method == "POST" { read_json(s, headers).await } else { serde_json::Value::Null };
        let (path, sh2) = (sh.cfg_path.clone(), sh.clone());
        let r = tokio::task::spawn_blocking(move || manage(&sh2, &path, &body)).await.unwrap_or_else(|e| Err(e.to_string()));
        let b = match r {
            Ok(v) => v,
            Err(e) => json!({"ok": false, "err": e}),
        };
        return respond(s, "200 OK", "application/json; charset=utf-8", "", b.to_string().as_bytes()).await;
    }
    if p.ends_with("/codes") {
        if !local {
            return respond(s, "403 Forbidden", "application/json", "", br#"{"err":"Nur lokal auf dem Server"}"#).await;
        }
        let cfg = sh.cfg();
        let list: Vec<serde_json::Value> = cfg
            .peers
            .iter()
            .map(|pe| {
                let code = crate::config::stored_code(&sh.cfg_path, &cfg, pe);
                let svg = code.as_ref().and_then(|c| qrcode::QrCode::with_error_correction_level(c.as_bytes(), qrcode::EcLevel::L).ok()).map(|q| {
                    q.render::<qrcode::render::svg::Color>().min_dimensions(260, 260).quiet_zone(true).build()
                });
                json!({"name": pe.name, "code": code, "svg": svg})
            })
            .collect();
        let b = json!({"codes": list}).to_string();
        return respond(s, "200 OK", "application/json; charset=utf-8", "", b.as_bytes()).await;
    }
    if p.ends_with("/data.json") || p == "data.json" {
        if !authorized(sh, headers, remote, via_nginx) {
            let b = json!({"login": true, "password_set": !sh.cfg().stats_password.is_empty()}).to_string();
            return respond(s, "401 Unauthorized", "application/json; charset=utf-8", "", b.as_bytes()).await;
        }
        let mut j = data_json(sh);
        j["local"] = json!(local);
        // ungefaehrer Standort nur auf der lokalen bzw. Admin-Seite
        let cfg = sh.cfg();
        if local && cfg.geo {
            if let Some(list) = j["peers"].as_array_mut() {
                let now = kvpn::util::now_secs();
                for p in list {
                    let ip = p["info"]["remote"].as_str().unwrap_or("").to_string();
                    let name = p["name"].as_str().unwrap_or("").to_string();
                    let g = crate::geo::get(&cfg.state_dir, &ip);
                    if let Some(g) = &g {
                        p["geo"] = json!(g);
                    }
                    // vom Geraet selbst gemeldet (WLAN-Name, Standort des Handys) – nur wenn dort freigegeben
                    let d = crate::geo::device_info(&cfg.state_dir, &name);
                    if let Some(d) = &d {
                        p["dev"] = d.clone();
                    }
                    // bester Standort aus allen Quellen (GPS, WLAN-Datenbanken, IP)
                    let ip_t = if p["online"].as_bool().unwrap_or(false) { now } else { p["last_seen"].as_u64().unwrap_or(0) };
                    let w = crate::geo::wlan_info(&cfg.state_dir, &name);
                    if let Some(w) = &w {
                        p["wlan"] = w.clone();
                    }
                    if let Some(b) = crate::geo::best(d.as_ref(), w.as_ref(), g.as_ref(), ip_t, now) {
                        p["pos"] = b;
                    }
                }
            }
        }
        let b = j.to_string();
        return respond(s, "200 OK", "application/json; charset=utf-8", "", b.as_bytes()).await;
    }
    if p.ends_with("/login") && method == "POST" {
        let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0).min(2048);
        let mut body = vec![0u8; len];
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), s.read_exact(&mut body)).await;
        let pw = serde_json::from_slice::<serde_json::Value>(&body).ok().and_then(|v| v["pw"].as_str().map(String::from)).unwrap_or_default();
        let cfg = sh.cfg();
        if !login_allowed(sh) {
            return respond(s, "429 Too Many Requests", "application/json", "", br#"{"ok":false,"err":"Zu viele Versuche - bitte 1 Minute warten"}"#).await;
        }
        if cfg.stats_password.is_empty() || pw.as_bytes() != cfg.stats_password.as_bytes() {
            login_failed(sh);
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            return respond(s, "200 OK", "application/json", "", br#"{"ok":false,"err":"Falsches Passwort"}"#).await;
        }
        let c = format!("Set-Cookie: kvpn_stats={}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Strict\r\n", stats_token(&cfg));
        return respond(s, "200 OK", "application/json", &c, br#"{"ok":true}"#).await;
    }
    if p.ends_with("/logout") && method == "POST" {
        let c = if vpn_admin { "Set-Cookie: kvpn_admin=; Path=/; Max-Age=0\r\n" } else { "Set-Cookie: kvpn_stats=; Path=/; Max-Age=0\r\n" };
        return respond(s, "200 OK", "application/json", c, br#"{"ok":true}"#).await;
    }
    if (method == "GET" || method == "HEAD") && (p == "/download" || p.starts_with("/download/")) {
        return downloads(sh, s, &p["/download".len()..], method == "HEAD").await;
    }
    if method == "GET" && (p.is_empty() || p.starts_with("/stats") || p.starts_with("/statistik")) {
        return respond(s, "200 OK", "text/html; charset=utf-8", "", PAGE.as_bytes()).await;
    }
    respond(s, "404 Not Found", "text/html; charset=utf-8", "", b"<!doctype html><title>404 Not Found</title><h1>Not Found</h1>").await;
}

// ------------------------------------------------------------------ Benutzerverwaltung (Webseite)

async fn read_json<S: AsyncRead + Unpin>(s: &mut S, headers: &HashMap<String, String>) -> serde_json::Value {
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0).min(4096);
    let mut body = vec![0u8; len];
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), s.read_exact(&mut body)).await;
    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
}

/// Liste (GET) bzw. Aktion (POST {"kind":"device"|"user","name":"…","action":"sperren"|"entsperren"})
fn manage(sh: &Shared, cfg_path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    use crate::users;
    let db = users::open(cfg_path)?;
    let mut done = String::new();
    if let Some(kind) = body["kind"].as_str() {
        let name = body["name"].as_str().unwrap_or("").trim().to_string();
        let off = match body["action"].as_str() {
            Some("sperren") => true,
            Some("entsperren") => false,
            _ => return Err("unbekannte Aktion".into()),
        };
        let found = match kind {
            "device" => users::set_disabled(&db, &name, off)?,
            "user" => users::set_user_disabled(&db, &name, off)?,
            _ => return Err("unbekannte Art".into()),
        };
        if !found {
            return Err(format!("'{name}' nicht gefunden"));
        }
        drop(db);
        sh.reload();
        let what = if kind == "device" { "Geraet" } else { "Benutzer" };
        crate::log!("Webseite: {what} '{name}' {}", if off { "gesperrt" } else { "entsperrt" });
        done = format!("{} '{name}' {}", if kind == "device" { "Gerät" } else { "Benutzer" }, if off { "gesperrt – sofort getrennt" } else { "entsperrt" });
        return manage(sh, cfg_path, &serde_json::Value::Null).map(|mut v| {
            v["msg"] = json!(done);
            v
        });
    }
    let cfg = sh.cfg();
    let online: std::collections::HashSet<String> =
        sh.peers.read().unwrap().values().filter(|p| p.stats.connected_since.load(Relaxed) > 0).map(|p| p.peer.name.clone()).collect();
    let devices: Vec<_> = users::devices(&db)?
        .into_iter()
        .map(|d| {
            json!({"name": d.peer.name, "user": d.peer.user, "ip4": cfg.ip4(d.peer.index).to_string(), "status": d.status(),
                   "active": d.active(), "disabled": d.disabled, "online": online.contains(&d.peer.name)})
        })
        .collect();
    let users: Vec<_> = users::users(&db)?
        .into_iter()
        .map(|u| json!({"name": u.name, "note": u.note, "disabled": u.disabled, "devices": u.devices, "max": u.max_devices}))
        .collect();
    Ok(json!({"ok": true, "enabled": true, "users": users, "devices": devices, "msg": done}))
}

// ------------------------------------------------------------------ Einstellungen (Webseite)

/// laeuft der Server unter systemd oder in Docker (startet nach dem Beenden von selbst wieder)?
fn can_restart() -> bool {
    std::env::var_os("INVOCATION_ID").is_some() || std::path::Path::new("/.dockerenv").exists() || std::env::var_os("KVPN_RESTART_OK").is_some()
}

fn settings_json(sh: &Shared) -> serde_json::Value {
    let c = sh.cfg();
    json!({
        "ok": true,
        "users": c.users, "aes256": c.aes256, "performance": c.performance, "admin_vpn": c.admin_vpn, "geo": c.geo,
        "admin_url": c.admin_addr().map(|a| format!("http://{a}")).unwrap_or_default(),
        "admin_password_set": !c.admin_password.is_empty(),
        // Zugangsdaten fuer die WLAN-Ortung: nur ob gesetzt, nie der Wert
        "google_geo_key": !c.google_geo_key.is_empty(), "wigle_api": !c.wigle_api.is_empty(),
        "max_devices": c.max_devices, "max_possible": c.capacity().unwrap_or(0), "devices": c.device_count(),
        "vpn_name": c.display_name(),
        "restart_needed": (c.performance, c.admin_addr().is_some()) != sh.boot,
        "can_restart": can_restart(),
        "msg": "",
    })
}

/// GET: aktuelle Einstellungen; POST {users?, aes256?, performance?, admin_vpn?, geo?, max_devices?, vpn_name?, admin_password?,
/// google_geo_key?, wigle_api?}
/// Rueckgabe: (Einstellungen + Meldung, Admin-Passwort geaendert)
fn settings(sh: &Shared, body: &serde_json::Value) -> Result<(serde_json::Value, bool), String> {
    if !body.is_object() {
        return Ok((settings_json(sh), false));
    }
    let path = &sh.cfg_path;
    let mut msgs: Vec<String> = Vec::new();
    let flag = |k: &str| body.get(k).and_then(|v| v.as_bool());
    if let Some(on) = flag("users") {
        if let Some(m) = crate::users::switch(path, on)? {
            crate::log!("Webseite: {m}");
            msgs.push(if on { "Benutzerverwaltung an".into() } else { "Benutzerverwaltung aus".into() });
        }
    }
    let mut c = crate::config::Config::load(path)?;
    let before = c.clone();
    let mut pw_changed = false;
    for (k, v) in [("aes256", flag("aes256")), ("performance", flag("performance")), ("admin_vpn", flag("admin_vpn")), ("geo", flag("geo"))] {
        if let Some(v) = v {
            c.set(k, if v { "an" } else { "aus" })?;
        }
    }
    if let Some(n) = body.get("max_devices") {
        let n = n.as_u64().map(|n| n.to_string()).or_else(|| n.as_str().map(|s| s.trim().to_string())).unwrap_or_default();
        c.set("max_devices", &n)?;
    }
    if let Some(n) = body.get("vpn_name").and_then(|v| v.as_str()) {
        if n.trim() != c.display_name() {
            c.set("vpn_name", n)?;
        }
    }
    // Zugangsdaten fuer die WLAN-Ortung: "" = so lassen, "aus" = entfernen
    for k in ["google_geo_key", "wigle_api"] {
        if let Some(v) = body.get(k).and_then(|v| v.as_str()).map(str::trim).filter(|v| !v.is_empty()) {
            c.set(k, v)?;
        }
    }
    if let Some(pw) = body.get("admin_password").and_then(|v| v.as_str()).filter(|p| !p.is_empty()) {
        crate::admin::check_new(pw)?;
        c.admin_password = crate::admin::hash(pw);
        pw_changed = true;
    }
    let onoff = |b: bool| if b { "an" } else { "aus" };
    if c.aes256 != before.aes256 {
        msgs.push(format!("AES-256 {} (gilt für neue Verbindungen)", onoff(c.aes256)));
    }
    if c.performance != before.performance {
        msgs.push(format!("Leistungsmodus {}", onoff(c.performance)));
    }
    if c.admin_vpn != before.admin_vpn {
        msgs.push(format!("Admin-Seite im VPN {}", onoff(c.admin_vpn)));
    }
    if c.geo != before.geo {
        msgs.push(format!("Standort {}", onoff(c.geo)));
    }
    if c.google_geo_key != before.google_geo_key {
        msgs.push(format!("Google-Ortung {}", if c.google_geo_key.is_empty() { "entfernt" } else { "eingetragen" }));
    }
    if c.wigle_api != before.wigle_api {
        msgs.push(format!("WiGLE {}", if c.wigle_api.is_empty() { "entfernt" } else { "eingetragen" }));
    }
    if c.max_devices != before.max_devices {
        msgs.push(format!("höchstens {} Geräte", c.max_devices));
    }
    if c.vpn_name != before.vpn_name {
        msgs.push(format!("Name \"{}\"", c.display_name()));
    }
    if pw_changed {
        msgs.push("Admin-Passwort geändert".into());
    }
    c.save(path)?;
    sh.reload();
    if !msgs.is_empty() {
        crate::log!("Webseite: Einstellungen geändert – {}", msgs.join(", "));
    }
    let mut v = settings_json(sh);
    v["msg"] = json!(if msgs.is_empty() { "Nichts geändert".to_string() } else { format!("Gespeichert: {}", msgs.join(" · ")) });
    Ok((v, pw_changed))
}

// ------------------------------------------------------------------ Admin-Seite im VPN (noch nicht angemeldet)

async fn read_pw<S: AsyncRead + Unpin>(s: &mut S, headers: &HashMap<String, String>) -> String {
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0).min(2048);
    let mut body = vec![0u8; len];
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), s.read_exact(&mut body)).await;
    serde_json::from_slice::<serde_json::Value>(&body).ok().and_then(|v| v["pw"].as_str().map(String::from)).unwrap_or_default()
}

fn admin_cookie(cfg: &crate::config::Config) -> String {
    format!("Set-Cookie: kvpn_admin={}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Strict\r\n", crate::admin::token(cfg))
}

async fn admin_gate<S: AsyncRead + AsyncWrite + Unpin>(sh: &Arc<Shared>, s: &mut S, method: &str, p: &str, headers: &HashMap<String, String>) {
    let cfg = sh.cfg();
    if p.ends_with("/data.json") || p == "data.json" {
        let b = json!({"login": true, "admin": true, "setup": cfg.admin_password.is_empty(), "password_set": !cfg.admin_password.is_empty()}).to_string();
        return respond(s, "401 Unauthorized", "application/json; charset=utf-8", "", b.as_bytes()).await;
    }
    if p.ends_with("/login") && method == "POST" {
        let pw = read_pw(s, headers).await;
        if !login_allowed(sh) {
            return respond(s, "429 Too Many Requests", "application/json", "", br#"{"ok":false,"err":"Zu viele Versuche - bitte 1 Minute warten"}"#).await;
        }
        let ok = !cfg.admin_password.is_empty() && {
            let (h, pw2) = (cfg.admin_password.clone(), pw.clone());
            tokio::task::spawn_blocking(move || crate::admin::verify(&h, &pw2)).await.unwrap_or(false)
        };
        if !ok {
            login_failed(sh);
            crate::log!("Admin-Seite im VPN: falsches Passwort");
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            return respond(s, "200 OK", "application/json", "", br#"{"ok":false,"err":"Falsches Passwort"}"#).await;
        }
        return respond(s, "200 OK", "application/json", &admin_cookie(&cfg), br#"{"ok":true}"#).await;
    }
    if p.ends_with("/admin-setup") && method == "POST" {
        let pw = read_pw(s, headers).await;
        if !cfg.admin_password.is_empty() {
            return respond(s, "200 OK", "application/json", "", br#"{"ok":false,"err":"Es ist schon ein Passwort festgelegt - bitte anmelden"}"#).await;
        }
        if let Err(e) = crate::admin::check_new(&pw) {
            return respond(s, "200 OK", "application/json", "", json!({"ok": false, "err": e}).to_string().as_bytes()).await;
        }
        let path = sh.cfg_path.clone();
        let r = tokio::task::spawn_blocking(move || -> Result<(), String> {
            let mut c = crate::config::Config::load(&path)?;
            if !c.admin_password.is_empty() {
                return Err("Es ist schon ein Passwort festgelegt - bitte anmelden".into());
            }
            c.admin_password = crate::admin::hash(&pw);
            c.save(&path)
        })
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
        if let Err(e) = r {
            return respond(s, "200 OK", "application/json", "", json!({"ok": false, "err": e}).to_string().as_bytes()).await;
        }
        sh.reload();
        crate::log!("Admin-Seite im VPN: Passwort festgelegt");
        return respond(s, "200 OK", "application/json", &admin_cookie(&sh.cfg()), br#"{"ok":true}"#).await;
    }
    if (method == "GET" || method == "HEAD") && (p == "/logo" || p.ends_with("/logo")) {
        return logo(sh, s, method, headers, false).await;
    }
    if method == "GET" && (p.is_empty() || p == "/" || p.starts_with("/stats") || p.starts_with("/statistik")) {
        return respond(s, "200 OK", "text/html; charset=utf-8", "", PAGE.as_bytes()).await;
    }
    respond(s, "401 Unauthorized", "application/json", "", br#"{"ok":false,"err":"Bitte zuerst anmelden"}"#).await
}

// ------------------------------------------------------------------ eigenes Bild (Logo)
const LOGO_MAX: usize = 2 * 1024 * 1024;

fn logo_paths(sh: &Shared) -> (std::path::PathBuf, std::path::PathBuf) {
    let d = std::path::PathBuf::from(&sh.cfg().state_dir);
    (d.join("logo.bin"), d.join("logo.type"))
}

/// Bild + Typ, falls eines hochgeladen wurde
pub fn logo_get(sh: &Shared) -> Option<(Vec<u8>, String)> {
    let (b, t) = logo_paths(sh);
    Some((std::fs::read(b).ok()?, std::fs::read_to_string(t).ok()?.trim().to_string()))
}

/// Version fuer den Browser-Zwischenspeicher (Aenderungszeit), 0 = kein Bild
pub fn logo_version(sh: &Shared) -> u64 {
    std::fs::metadata(logo_paths(sh).0)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Bildtyp an den ersten Bytes erkennen (nur PNG, JPEG, WebP, GIF – kein SVG, das koennte Skripte enthalten)
pub fn image_type(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        Some("image/png")
    } else if b.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        Some("image/webp")
    } else if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        Some("image/gif")
    } else {
        None
    }
}

/// Bild speichern (auch fuer den Installer: kvpn-server logo <datei>)
pub fn logo_store(state_dir: &str, data: &[u8]) -> Result<&'static str, String> {
    if data.len() > LOGO_MAX {
        return Err("Bild zu gross (hoechstens 2 MB)".into());
    }
    let t = image_type(data).ok_or("Nur PNG, JPG, WebP oder GIF")?;
    let d = std::path::Path::new(state_dir);
    std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    std::fs::write(d.join("logo.bin.tmp"), data).map_err(|e| e.to_string())?;
    std::fs::write(d.join("logo.type"), t).map_err(|e| e.to_string())?;
    std::fs::rename(d.join("logo.bin.tmp"), d.join("logo.bin")).map_err(|e| e.to_string())?;
    Ok(t)
}

async fn logo<S: AsyncRead + AsyncWrite + Unpin>(sh: &Shared, s: &mut S, method: &str, headers: &HashMap<String, String>, local: bool) {
    match method {
        "GET" | "HEAD" => match logo_get(sh) {
            Some((b, t)) => {
                let ct = if image_type(&b).is_some() { t } else { "application/octet-stream".into() };
                respond(s, "200 OK", &ct, "Content-Security-Policy: default-src 'none'\r\n", if method == "HEAD" { b"" } else { &b }).await
            }
            None => respond(s, "404 Not Found", "text/plain", "", b"kein Bild").await,
        },
        // Aendern nur ueber die lokale Seite (http://localhost:8180) – von aussen nie
        "POST" | "DELETE" if !local => respond(s, "403 Forbidden", "application/json", "", br#"{"ok":false,"err":"Nur lokal auf dem Server (http://localhost:8180)"}"#).await,
        "POST" => {
            let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
            if len == 0 || len > LOGO_MAX {
                return respond(s, "413 Payload Too Large", "application/json", "", br#"{"ok":false,"err":"Bild fehlt oder ist groesser als 2 MB"}"#).await;
            }
            let mut body = vec![0u8; len];
            if tokio::time::timeout(std::time::Duration::from_secs(30), s.read_exact(&mut body)).await.map(|r| r.is_err()).unwrap_or(true) {
                return respond(s, "400 Bad Request", "application/json", "", br#"{"ok":false,"err":"Upload abgebrochen"}"#).await;
            }
            match logo_store(&sh.cfg().state_dir, &body) {
                Ok(_) => respond(s, "200 OK", "application/json", "", br#"{"ok":true}"#).await,
                Err(e) => respond(s, "415 Unsupported Media Type", "application/json", "", json!({"ok": false, "err": e}).to_string().as_bytes()).await,
            }
        }
        "DELETE" => {
            let (b, t) = logo_paths(sh);
            let _ = std::fs::remove_file(b);
            let _ = std::fs::remove_file(t);
            respond(s, "200 OK", "application/json", "", br#"{"ok":true}"#).await
        }
        _ => respond(s, "405 Method Not Allowed", "text/plain", "", b"").await,
    }
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn pct_encode(s: &str) -> String {
    s.bytes().map(|c| if c.is_ascii_alphanumeric() || b"-._~".contains(&c) { (c as char).to_string() } else { format!("%{c:02X}") }).collect()
}

fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Apps im Download-Ordner: (Dateiname, Groesse)
fn download_files(dir: &str) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                .filter_map(|e| Some((e.file_name().into_string().ok()?, e.metadata().ok()?.len())))
                .filter(|(n, _)| !n.starts_with('.'))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// /download/ – Seite mit den Apps, /download/<datei> – die Datei selbst (ohne Anmeldung: die Apps enthalten nichts
/// Geheimes, verbinden kann sich nur, wer einen Verbindungscode hat)
async fn downloads<S: AsyncWrite + Unpin>(sh: &Shared, s: &mut S, rest: &str, head: bool) {
    let cfg = sh.cfg();
    if cfg.downloads_dir.is_empty() {
        return respond(s, "404 Not Found", "text/html; charset=utf-8", "", b"<!doctype html><title>404 Not Found</title><h1>Not Found</h1>").await;
    }
    let files = download_files(&cfg.downloads_dir);
    let want = pct_decode(rest.trim_start_matches('/'));
    if want.is_empty() {
        let name = html_esc(cfg.display_name());
        let ver = html_esc(&apps_version(&cfg));
        let vers = app_versions(&cfg);
        let lv = logo_version(sh);
        let (logo_img, icon) = if lv > 0 {
            (format!("<img class=\"lg\" src=\"logo?v={lv}\" alt=\"\">"), format!("<link rel=\"icon\" href=\"logo?v={lv}\">"))
        } else {
            ("🛡️ ".to_string(), String::new())
        };
        let kind = |n: &str| {
            let l = n.to_lowercase();
            if l.ends_with(".apk") { ("🤖", "Android", "Installieren, dann den QR-Code vom Server mit der Kamera scannen – die App öffnet sich mit dem Code.") }
            else if l.ends_with(".exe") { ("🪟", "Windows 10/11", "Starten (Adminrechte bestätigen), Verbindungscode einfügen – er wird gespeichert. Windows SmartScreen: „Weitere Informationen“ → „Trotzdem ausführen“.") }
            else if l.contains("linux") { ("🐧", "Linux", "chmod +x, dann sudo ./datei 'kronevpn://v1/…'") }
            else { ("📦", "Datei", "") }
        };
        let cards: String = files.iter().map(|(n, sz)| {
            let (ic, os, how) = kind(n);
            let l = n.to_lowercase();
            let key = if l.ends_with(".apk") { "android" } else if l.ends_with(".exe") { "windows" } else { "linux" };
            let ver = vers.get(key).and_then(|v| v.as_str()).map(html_esc).unwrap_or_else(|| ver.clone());
            format!("<a class=\"dl\" href=\"{}\" download><span class=\"ic\">{ic}</span><span><b>{}</b><span class=\"m\">{os} · Version {ver} · {:.1} MB</span><span class=\"h\">{}</span></span></a>",
                pct_encode(n), html_esc(n), *sz as f64 / 1048576.0, html_esc(how))
        }).collect();
        let body = format!(r#"<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>{name} – Apps</title>{icon}
<style>:root{{--bg:#f4f5f8;--card:#fff;--ink:#16181d;--mute:#5d6472;--line:#e3e6ec;--acc:#3b6cf6;color-scheme:light}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0f1115;--card:#171a21;--ink:#e8eaf0;--mute:#9aa3b2;--line:#262b35;--acc:#6f95ff;color-scheme:dark}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
.w{{max-width:760px;margin:0 auto;padding:28px 16px 50px}}h1{{font-size:28px;margin:0}}.sub{{color:var(--mute);margin:4px 0 20px}}
.dl{{display:flex;gap:14px;align-items:flex-start;text-decoration:none;color:var(--ink);background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px;margin-top:12px}}
.dl:hover{{border-color:var(--acc)}}.ic{{font-size:30px;line-height:1}}.dl b{{display:block;font-size:17px}}.m{{display:block;color:var(--mute);font-size:13.5px}}.h{{display:block;font-size:14px;margin-top:6px}}
.n{{color:var(--mute);font-size:13.5px;margin-top:22px}}.v{{display:inline-block;font-size:12.5px;font-weight:600;padding:1px 9px;border-radius:99px;border:1px solid var(--line);background:var(--card);color:var(--ink);margin-right:6px}}.lg{{width:44px;height:44px;border-radius:10px;object-fit:cover;vertical-align:-10px;margin-right:10px}}</style></head><body><div class="w"><h1>{logo_img}{name}</h1>
<div class="sub"><span class="v">Version {ver}</span> Apps zum Herunterladen. Den persönlichen Verbindungscode bekommst du vom Betreiber dieses Servers.</div>{cards}
<div class="n">Verbinden kann sich nur, wer einen Verbindungscode hat – die Apps allein enthalten nichts Geheimes.</div></div></body></html>"#);
        return respond(s, "200 OK", "text/html; charset=utf-8", "", body.as_bytes()).await;
    }
    // nur Dateien, die wirklich im Ordner liegen (kein ../ moeglich)
    let Some((fname, _)) = files.iter().find(|(n, _)| *n == want) else {
        return respond(s, "404 Not Found", "text/html; charset=utf-8", "", b"<!doctype html><title>404 Not Found</title><h1>Not Found</h1>").await;
    };
    let data = match tokio::fs::read(std::path::Path::new(&cfg.downloads_dir).join(fname)).await {
        Ok(d) => d,
        Err(_) => return respond(s, "404 Not Found", "text/plain", "", b"nicht gefunden").await,
    };
    let ctype = if fname.to_lowercase().ends_with(".apk") { "application/vnd.android.package-archive" } else { "application/octet-stream" };
    let ascii: String = fname.chars().map(|c| if c.is_ascii_alphanumeric() || ".-_ ".contains(c) { c } else { '_' }).collect();
    let extra = format!("Content-Disposition: attachment; filename=\"{ascii}\"; filename*=UTF-8''{}\r\n", pct_encode(fname));
    if head {
        let h = format!("HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n", data.len());
        let _ = s.write_all(h.as_bytes()).await;
        return;
    }
    respond(s, "200 OK", ctype, &extra, &data).await
}

/// aktuelle App-Version: die neueste freigegebene, sonst die des Servers
pub fn apps_version(cfg: &crate::config::Config) -> String {
    match crate::updates::offered(cfg) {
        Some(m) => m.version,
        None => kvpn::VERSION.to_string(),
    }
}

/// Version je App ("android", "windows", "linux") – jede App hat ihre eigene; leer, solange nichts freigegeben ist
pub fn app_versions(cfg: &crate::config::Config) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    if let Some(m) = crate::updates::offered(cfg) {
        for os in m.files.keys() {
            if let Some(v) = m.version_for(os) {
                out.insert(os.clone(), json!(v));
            }
        }
    }
    out
}

fn proc_cpu_seconds() -> f64 {
    // utime + stime aus /proc/self/stat (Ticks)
    std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| {
            let r = s.rsplit_once(')')?.1.split_whitespace().collect::<Vec<_>>();
            let u: f64 = r.get(11)?.parse().ok()?;
            let st: f64 = r.get(12)?.parse().ok()?;
            Some((u + st) / unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64)
        })
        .unwrap_or(0.0)
}

fn rss_mb() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)?.parse::<f64>().ok()))
        .map(|kb| kb / 1024.0)
        .unwrap_or(0.0)
}

pub fn data_json(sh: &Shared) -> serde_json::Value {
    let cfg = sh.cfg();
    let now = now_secs();
    let h = sh.hist.lock().unwrap();
    let mut peers: Vec<_> = sh.peers.read().unwrap().values().cloned().collect();
    peers.sort_by_key(|p| p.peer.index);
    let list: Vec<_> = peers
        .iter()
        .map(|p| {
            let st = &p.stats;
            let since = st.connected_since.load(Relaxed);
            let info = st.info.lock().unwrap().clone();
            let (today, month) = h.sums(&p.peer.name, now);
            let total = h.persist.total.get(&p.peer.name).copied().unwrap_or([0, 0]);
            let spark: Vec<u64> = st.spark.lock().unwrap().iter().map(|(r, t)| r + t).collect();
            json!({
                "name": p.peer.name, "index": p.peer.index, "user": p.peer.user,
                "ip4": cfg.ip4(p.peer.index).to_string(),
                "ip6": cfg.ip6(p.peer.index).map(|a| a.to_string()).unwrap_or_default(),
                "online": since > 0, "since": since,
                "last_seen": st.last_seen.load(Relaxed),
                "handshakes": st.handshakes.load(Relaxed),
                "rx": st.rx_bytes.load(Relaxed), "tx": st.tx_bytes.load(Relaxed),
                "rx_packets": st.rx_packets.load(Relaxed), "tx_packets": st.tx_packets.load(Relaxed),
                "rate_rx": st.rate_rx.load(Relaxed), "rate_tx": st.rate_tx.load(Relaxed),
                "rtt_ms": st.rtt_us.load(Relaxed) as f64 / 1000.0,
                "spoofed": st.spoofed.load(Relaxed),
                "today": today, "month": month, "total": total,
                "spark": spark,
                "info": info,
            })
        })
        .collect();
    let days: Vec<_> = h
        .persist
        .days
        .iter()
        .rev()
        .take(31)
        .map(|(d, m)| {
            let (r, t) = m.values().fold((0u64, 0u64), |a, v| (a.0 + v[0], a.1 + v[1]));
            json!({"date": d, "rx": r, "tx": t, "per": m})
        })
        .collect();
    let up = now.saturating_sub(sh.started).max(1);
    json!({
        "now": now,
        "server": {
            "version": kvpn::VERSION, "name": cfg.display_name(), "logo": logo_version(sh), "downloads": !cfg.downloads_dir.is_empty(), "started": sh.started, "queues": sh.queues,
            "cores": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
            "admin_url": cfg.admin_addr().map(|a| format!("http://{a}/")).unwrap_or_default(),
            "url": cfg.public_url, "tun": cfg.tun, "net4": cfg.net4, "net6": cfg.net6, "mtu": cfg.mtu,
            "cpu_pct": proc_cpu_seconds() / up as f64 * 100.0, "rss_mb": rss_mb(),
            "tun_drops": sh.tun_drops.load(Relaxed),
            "load": std::fs::read_to_string("/proc/loadavg").ok().and_then(|s| s.split_whitespace().next().map(String::from)).unwrap_or_default(),
        },
        "inactive": cfg.inactive.iter().map(|p| json!({"name": p.name, "user": p.user, "ip4": cfg.ip4(p.index).to_string()})).collect::<Vec<_>>(),
        "settings": {"users": cfg.users, "aes256": cfg.aes256, "performance": cfg.performance},
        "max_peers": cfg.max_devices,
        "max_possible": cfg.capacity().unwrap_or(0),
        "update": {
            "offered": crate::updates::offered(&cfg).map(|m| m.version).unwrap_or_default(),
            "pending": crate::updates::pending(&cfg).map(|m| m.version).unwrap_or_default(),
            "apps": apps_version(&cfg),
            "app_versions": app_versions(&cfg),
            "repo": cfg.update_repo,
        },
        "peers": list,
        "sec": h.sec.iter().map(|(r, t)| [*r, *t]).collect::<Vec<_>>(),
        "min": h.min.iter().map(|(r, t)| [*r, *t]).collect::<Vec<_>>(),
        "days": days,
    })
}
