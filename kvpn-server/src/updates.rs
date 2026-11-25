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
    source_url(&cfg.update_repo, &cfg.update_branch)
}

fn source_url(repo: &str, branch: &str) -> String {
    if let Ok(u) = std::env::var("KVPN_UPDATE_URL") {
        return u.trim_end_matches('/').to_string();
    }
    format!("https://raw.githubusercontent.com/{}/{}", repo.trim_matches('/'), branch)
}

// ------------------------------------------------------------------ Update-Quelle (GitHub-Repo) aendern

/// "besitzer/name" wie auf GitHub
pub fn check_repo(repo: &str) -> Result<(), String> {
    let ok_part = |p: &str| !p.is_empty() && p.len() <= 100 && p.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) && !p.starts_with('.');
    match repo.split('/').collect::<Vec<_>>().as_slice() {
        [a, b] if ok_part(a) && ok_part(b) => Ok(()),
        _ => Err(format!("„{repo}“ ist kein GitHub-Repo – bitte als besitzer/name, z. B. Krone7891/VPN")),
    }
}

pub fn check_branch(b: &str) -> Result<(), String> {
    if !b.is_empty() && b.len() <= 200 && b.chars().all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c)) && !b.contains("..") && !b.starts_with('/') {
        Ok(())
    } else {
        Err(format!("„{b}“ ist kein gültiger Zweig"))
    }
}

/// Liegt im Repo eine Update-Liste, die mit dem Schluessel dieser Apps signiert ist? (sonst wuerden die Geraete
/// die Apps von dort ablehnen) Liefert die Liste.
pub fn probe(repo: &str, branch: &str) -> Result<Manifest, String> {
    let base = source_url(repo, branch);
    let get = |f: &str, max: u64| -> Result<String, String> {
        let b = fetch(&format!("{base}/dist/{f}"), max).map_err(|_| format!("im Repo {repo} (Zweig {branch}) gibt es keine dist/{f} – Repo öffentlich? Name und Zweig richtig?"))?;
        String::from_utf8(b).map_err(|_| format!("dist/{f} ist kein Text"))
    };
    let text = get("update.json", 64 * 1024)?;
    let sig = get("update.json.sig", 4096)?;
    verify(&text, &sig).map_err(|e| {
        format!("dist/update.json in {repo} ist nicht mit dem Update-Schlüssel dieser Apps signiert ({e}) – die Geräte würden Apps von dort ablehnen")
    })
}

/// Update-Quelle aendern. Ist ein Admin-Passwort festgelegt, muss `pw` stimmen. Ohne Passwort geht es nur, wenn
/// `ohne_pw_erlaubt` (Einrichtung auf der Kommandozeile, solange noch keins festgelegt ist). `pruefen`: vorher im
/// neuen Repo nach einer gueltig signierten Update-Liste sehen.
pub fn set_source(path: &str, repo: &str, branch: &str, pw: Option<&str>, ohne_pw_erlaubt: bool, pruefen: bool) -> Result<String, String> {
    let repo = repo.trim().trim_matches('/');
    let branch = branch.trim();
    check_repo(repo)?;
    check_branch(branch)?;
    let mut c = Config::load(path)?;
    if !c.admin_password.is_empty() {
        let ok = pw.map(|p| crate::admin::verify(&c.admin_password, p)).unwrap_or(false);
        if !ok {
            std::thread::sleep(std::time::Duration::from_secs(1));
            return Err("Admin-Passwort falsch – Update-Quelle bleibt unverändert".into());
        }
    } else if !ohne_pw_erlaubt {
        return Err("Zuerst ein Admin-Passwort festlegen (Einstellungen oder kvpn-server admin-passwort) – damit wird das Ändern der Update-Quelle geschützt".into());
    }
    if c.update_repo == repo && c.update_branch == branch {
        return Ok(format!("Update-Quelle ist schon {repo} (Zweig {branch})"));
    }
    let gefunden = if pruefen { Some(probe(repo, branch)?) } else { None };
    let (alt_repo, alt_zweig) = (c.update_repo.clone(), c.update_branch.clone());
    c.update_repo = repo.into();
    c.update_branch = branch.into();
    c.save(path)?;
    // von der alten Quelle vorgemerkte Version verwerfen
    let d = Path::new(&c.state_dir);
    let _ = std::fs::remove_file(d.join("update-pending.json"));
    let _ = std::fs::remove_file(d.join("update-pending.json.sig"));
    crate::log!("Update-Quelle geaendert: {alt_repo} ({alt_zweig}) -> {repo} ({branch})");
    Ok(match gefunden {
        Some(m) => format!("Update-Quelle jetzt {repo} (Zweig {branch}) – dort gefunden: Apps {} (gültig signiert). Verteilen weiterhin erst nach Freigabe.", m.version),
        None => format!("Update-Quelle jetzt {repo} (Zweig {branch}) – nicht geprüft"),
    })
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
    // auch die Download-Seite bekommt die neuen Apps (wer sie neu herunterlaedt, hat gleich die neue Version)
    // auch die Download-Seite(n) bekommen die neuen Apps (wer neu herunterlaedt, hat gleich die neue Version)
    for dir in [&cfg.downloads_dir, &cfg.download_mirror] {
        if !dir.is_empty() {
            refresh_downloads(Path::new(dir), &root, &m, say);
        }
    }
    let d = Path::new(&cfg.state_dir);
    let _ = std::fs::remove_file(d.join("update-pending.json"));
    let _ = std::fs::remove_file(d.join("update-pending.json.sig"));
    Ok(m.version)
}

/// Apps in einem Download-Ordner ersetzen. Dateien dort koennen nach dem VPN benannt sein
/// (z. B. "Potzplitz VPN.exe"): Zuordnung nach Art (.apk, .exe, -linux)
fn refresh_downloads(dl: &Path, root: &Path, m: &Manifest, say: &dyn Fn(&str)) {
    let names: Vec<String> = std::fs::read_dir(dl)
        .map(|rd| rd.flatten().filter_map(|e| e.file_name().into_string().ok()).filter(|n| !n.starts_with('.')).collect())
        .unwrap_or_default();
    let kind = |n: &str| {
        let l = n.to_ascii_lowercase();
        if l.ends_with(".apk") {
            "android"
        } else if l.ends_with(".exe") {
            "windows"
        } else if l.ends_with("-linux") {
            "linux"
        } else {
            ""
        }
    };
    for (os, f) in &m.files {
        let mut targets: Vec<String> = names.iter().filter(|n| kind(n) == os.as_str()).cloned().collect();
        if targets.is_empty() {
            targets.push(f.name.clone());
        }
        for t in targets {
            let tmp = dl.join(format!(".{t}.neu"));
            match std::fs::copy(root.join(&f.name), &tmp).and_then(|_| std::fs::rename(&tmp, dl.join(&t))) {
                Ok(()) => say(&format!("Download-Seite: {t} aktualisiert")),
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    say(&format!("Download-Seite: {t} nicht aktualisiert ({e})"))
                }
            }
        }
    }
    // files.json daneben (Download-Seite mit Version und Pruefsummen) neu schreiben
    let fj = dl.parent().map(|p| p.join("files.json"));
    if let Some(fj) = fj.filter(|f| f.exists()) {
        let mut files = Vec::new();
        for f in m.files.values() {
            let v = if f.version.is_empty() { &m.version } else { &f.version };
            files.push(serde_json::json!({"name": f.name, "size": f.size, "sha256": f.sha256, "version": v}));
        }
        let j = serde_json::json!({"version": m.version, "date": date_de(kvpn::util::now_secs()), "files": files});
        let _ = std::fs::write(&fj, serde_json::to_string_pretty(&j).unwrap_or_default());
    }
}

/// "24.11.2026" (UTC)
fn date_de(t: u64) -> String {
    let z = (t / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + (month <= 2) as i64;
    format!("{day:02}.{month:02}.{year}")
}
