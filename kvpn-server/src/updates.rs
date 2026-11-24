//! App-Updates fuer die Geraete – nur von GitHub und erst nach Freigabe auf dem Server.
//!
//! 1. Der Server schaut regelmaessig (alle 6 Stunden) im GitHub-Repo nach `dist/update.json` (+ Signatur).
//!    Ist dort eine neuere App-Version, wird sie nur VORGEMERKT und gemeldet (Log, Statistik-Seite).
//! 2. Freigabe auf dem Server: `kvpn-server update` oder Knopf auf der lokalen Seite (http://localhost:8180).
//!    Erst dann werden die Apps von GitHub geladen, gegen die signierte Liste geprueft (Groesse, SHA-256)
//!    und nach <state_dir>/update gelegt.
//! 3. Von dort bekommen die Geraete sie beim Verbinden ueber den verschluesselten Tunnel (siehe server.rs);
//!    die Apps pruefen die Signatur noch einmal selbst.
//!
//! Quelle ist immer https://raw.githubusercontent.com/<update_repo>/<update_branch>/dist/ (nur HTTPS, Zertifikat
//! wird geprueft). Nur fuer automatische Tests laesst sich die Adresse mit KVPN_UPDATE_URL umstellen.

use crate::config::Config;
use kvpn::update::{newer, verify, Manifest};
use std::path::{Path, PathBuf};

pub fn base_url(cfg: &Config) -> String {
    if let Ok(u) = std::env::var("KVPN_UPDATE_URL") {
        return u.trim_end_matches('/').to_string();
    }
    format!("https://raw.githubusercontent.com/{}/{}", cfg.update_repo.trim_matches('/'), cfg.update_branch)
}

/// Datei laden (curl: Proxy, Weiterleitungen, Zertifikatspruefung)
fn fetch(url: &str, max: u64) -> Result<Vec<u8>, String> {
    let test = std::env::var("KVPN_UPDATE_URL").is_ok();
    let out = std::process::Command::new("curl")
        .args(["-fsSL", "--proto", if test { "=https,http" } else { "=https" }, "--max-time", "300", "--max-filesize"])
        .arg(max.to_string())
        .arg(url)
        .output()
        .map_err(|e| format!("curl nicht gefunden ({e}) – bitte installieren"))?;
    if !out.status.success() {
        return Err(format!("{url}: Download fehlgeschlagen ({})", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(out.stdout)
}

pub fn dir(cfg: &Config) -> PathBuf {
    Path::new(&cfg.state_dir).join("update")
}

fn read_signed(dir: &Path, name: &str) -> Option<(Manifest, String, String)> {
    let text = std::fs::read_to_string(dir.join(name)).ok()?;
    let sig = std::fs::read_to_string(dir.join(format!("{name}.sig"))).ok()?;
    let m = verify(&text, &sig).ok()?;
    Some((m, text, sig))
}

/// Version, die an die Geraete verteilt wird (freigegeben)
pub fn offered(cfg: &Config) -> Option<Manifest> {
    read_signed(&dir(cfg), "update.json").map(|x| x.0)
}

/// auf GitHub gefunden, aber noch nicht freigegeben
pub fn pending(cfg: &Config) -> Option<Manifest> {
    let (m, _, _) = read_signed(Path::new(&cfg.state_dir), "update-pending.json")?;
    match offered(cfg) {
        Some(o) if !newer(&m.version, &o.version) => None,
        _ => Some(m),
    }
}

/// bei GitHub nachsehen. Some = neuere Version als die freigegebene (Liste, Text, Signatur)
pub fn check(cfg: &Config) -> Result<Option<(Manifest, String, String)>, String> {
    let base = base_url(cfg);
    let text = String::from_utf8(fetch(&format!("{base}/dist/update.json"), 64 * 1024)?).map_err(|_| "update.json ist kein Text")?;
    let sig = String::from_utf8(fetch(&format!("{base}/dist/update.json.sig"), 4096)?).map_err(|_| "Signatur ist kein Text")?;
    let m = verify(&text, &sig)?;
    if let Some(o) = offered(cfg) {
        if !newer(&m.version, &o.version) {
            return Ok(None);
        }
    }
    Ok(Some((m, text, sig)))
}

/// gefundene Version vormerken (ohne sie zu verteilen)
pub fn remember(cfg: &Config, text: &str, sig: &str) {
    let d = Path::new(&cfg.state_dir);
    let _ = std::fs::create_dir_all(d);
    let _ = std::fs::write(d.join("update-pending.json"), text);
    let _ = std::fs::write(d.join("update-pending.json.sig"), sig);
}

/// Freigabe: neueste Version von GitHub laden, pruefen und an die Geraete verteilen. Liefert die Version.
pub fn approve(cfg: &Config, say: &dyn Fn(&str)) -> Result<String, String> {
    let Some((m, text, sig)) = check(cfg)? else {
        return Err(format!(
            "auf GitHub ({}) gibt es keine neuere App-Version als die verteilte ({})",
            base_url(cfg),
            offered(cfg).map(|o| o.version).unwrap_or_else(|| "keine".into())
        ));
    };
    let base = base_url(cfg);
    let root = dir(cfg);
    let new = root.with_file_name("update.neu");
    let _ = std::fs::remove_dir_all(&new);
    std::fs::create_dir_all(&new).map_err(|e| format!("{}: {e}", new.display()))?;
    for (os, f) in &m.files {
        if f.name.contains(['/', '\\']) || f.name.starts_with('.') || f.size > kvpn::update::MAX_SIZE {
            return Err(format!("ungueltiger Eintrag fuer {os} in update.json"));
        }
        say(&format!("lade {} ({} KB) ...", f.name, f.size / 1024));
        let data = fetch(&format!("{base}/dist/{}", f.name), f.size)?;
        if data.len() as u64 != f.size || kvpn::update::sha256_hex(&data) != f.sha256.to_ascii_lowercase() {
            let _ = std::fs::remove_dir_all(&new);
            return Err(format!("{}: Pruefsumme stimmt nicht mit der signierten Liste ueberein – abgebrochen", f.name));
        }
        std::fs::write(new.join(&f.name), &data).map_err(|e| e.to_string())?;
    }
    std::fs::write(new.join("update.json.sig"), &sig).map_err(|e| e.to_string())?;
    // update.json zuletzt: der Server liest die Liste erst, wenn alles da ist
    std::fs::write(new.join("update.json"), &text).map_err(|e| e.to_string())?;
    let old = root.with_file_name("update.alt");
    let _ = std::fs::remove_dir_all(&old);
    if root.exists() {
        std::fs::rename(&root, &old).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&new, &root).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&old);
    let d = Path::new(&cfg.state_dir);
    let _ = std::fs::remove_file(d.join("update-pending.json"));
    let _ = std::fs::remove_file(d.join("update-pending.json.sig"));
    Ok(m.version)
}
