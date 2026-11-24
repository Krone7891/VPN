//! Statistik-Webseite (HTML + JSON) und schlichte 404-Antwort fuer alles andere.

use crate::server::{is_home, login_allowed, login_failed, stats_token, Shared};
use kvpn::proto::MAX_PEERS;
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
    headers: &HashMap<String, String>,
    remote: IpAddr,
    via_nginx: bool,
    local: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let p = path.trim_end_matches('/');
    if p == "/logo" || p.ends_with("/logo") {
        return logo(sh, s, method, headers, local).await;
    }
    if p.ends_with("/data.json") || p == "data.json" {
        if !authorized(sh, headers, remote, via_nginx) {
            let b = json!({"login": true, "password_set": !sh.cfg().stats_password.is_empty()}).to_string();
            return respond(s, "401 Unauthorized", "application/json; charset=utf-8", "", b.as_bytes()).await;
        }
        let mut j = data_json(sh);
        j["local"] = json!(local);
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
        return respond(s, "200 OK", "application/json", "Set-Cookie: kvpn_stats=; Path=/; Max-Age=0\r\n", br#"{"ok":true}"#).await;
    }
    if (method == "GET" || method == "HEAD") && (p == "/download" || p.starts_with("/download/")) {
        return downloads(sh, s, &p["/download".len()..], method == "HEAD").await;
    }
    if method == "GET" && (p.is_empty() || p.starts_with("/stats") || p.starts_with("/statistik")) {
        return respond(s, "200 OK", "text/html; charset=utf-8", "", PAGE.as_bytes()).await;
    }
    respond(s, "404 Not Found", "text/html; charset=utf-8", "", b"<!doctype html><title>404 Not Found</title><h1>Not Found</h1>").await;
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
            format!("<a class=\"dl\" href=\"{}\" download><span class=\"ic\">{ic}</span><span><b>{}</b><span class=\"m\">{os} · {:.1} MB</span><span class=\"h\">{}</span></span></a>",
                pct_encode(n), html_esc(n), *sz as f64 / 1048576.0, html_esc(how))
        }).collect();
        let body = format!(r#"<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>{name} – Apps</title>{icon}
<style>:root{{--bg:#f4f5f8;--card:#fff;--ink:#16181d;--mute:#5d6472;--line:#e3e6ec;--acc:#3b6cf6;color-scheme:light}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0f1115;--card:#171a21;--ink:#e8eaf0;--mute:#9aa3b2;--line:#262b35;--acc:#6f95ff;color-scheme:dark}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
.w{{max-width:760px;margin:0 auto;padding:28px 16px 50px}}h1{{font-size:28px;margin:0}}.sub{{color:var(--mute);margin:4px 0 20px}}
.dl{{display:flex;gap:14px;align-items:flex-start;text-decoration:none;color:var(--ink);background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px;margin-top:12px}}
.dl:hover{{border-color:var(--acc)}}.ic{{font-size:30px;line-height:1}}.dl b{{display:block;font-size:17px}}.m{{display:block;color:var(--mute);font-size:13.5px}}.h{{display:block;font-size:14px;margin-top:6px}}
.n{{color:var(--mute);font-size:13.5px;margin-top:22px}}.lg{{width:44px;height:44px;border-radius:10px;object-fit:cover;vertical-align:-10px;margin-right:10px}}</style></head><body><div class="w"><h1>{logo_img}{name}</h1>
<div class="sub">Apps zum Herunterladen. Den persönlichen Verbindungscode bekommst du vom Betreiber dieses Servers.</div>{cards}
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
                "name": p.peer.name, "index": p.peer.index,
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
            "url": cfg.public_url, "tun": cfg.tun, "net4": cfg.net4, "net6": cfg.net6, "mtu": cfg.mtu,
            "cpu_pct": proc_cpu_seconds() / up as f64 * 100.0, "rss_mb": rss_mb(),
            "tun_drops": sh.tun_drops.load(Relaxed),
            "load": std::fs::read_to_string("/proc/loadavg").ok().and_then(|s| s.split_whitespace().next().map(String::from)).unwrap_or_default(),
        },
        "max_peers": MAX_PEERS,
        "peers": list,
        "sec": h.sec.iter().map(|(r, t)| [*r, *t]).collect::<Vec<_>>(),
        "min": h.min.iter().map(|(r, t)| [*r, *t]).collect::<Vec<_>>(),
        "days": days,
    })
}
