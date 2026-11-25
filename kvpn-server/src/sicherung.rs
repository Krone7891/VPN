//! Sicherung und Wiederherstellung (ab Server 1.4.0).
//!
//! Eine Sicherung ist eine normale .tar.gz-Datei (mit `tar -tzf` lesbar) mit allem, was man fuer einen neuen Server
//! braucht: Server-Schluessel, Geraete, Benutzer, Einstellungen (Ordner der server.toml, unter "config/") und dem
//! Zustand (Statistik, Logo, Standort-Verlauf, Absturz-Protokolle ... unter "state/"). Nicht dabei: App-Updates und
//! die Sperrlisten des Werbe-Blockers (kommen von selbst wieder) und die Sicherungen selbst.
//!
//! Automatisch einmal am Tag (Einstellung `backup`), aufbewahrt werden die letzten `backup_keep`. Die Dateien sind
//! nur fuer root lesbar – sie enthalten den geheimen Server-Schluessel.
//!
//!   kvpn-server sicherung                 Liste
//!   kvpn-server sicherung jetzt           neue Sicherung anlegen
//!   kvpn-server sicherung zurueck <datei> wiederherstellen (vorher wird der aktuelle Stand gesichert)

use crate::config::Config;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Kennung am Anfang des Dateinamens
const PREFIX: &str = "kronevpn-sicherung-";
/// Dateien ueber dieser Groesse kommen nicht in die Sicherung
const MAX_FILE: u64 = 50 << 20;
/// Ordner im Zustand, die nicht gesichert werden (kommen von selbst wieder bzw. sind die Sicherungen selbst)
const SKIP_STATE: &[&str] = &["update", "dns", "sicherungen", "update-neu", "update-alt"];

pub fn dir(c: &Config) -> PathBuf {
    if c.backup_dir.trim().is_empty() {
        Path::new(&c.state_dir).join("sicherungen")
    } else {
        PathBuf::from(c.backup_dir.trim())
    }
}

/// vorhandene Sicherungen, neueste zuerst: (Dateiname, Groesse, Zeitpunkt)
pub fn list(c: &Config) -> Vec<(String, u64, u64)> {
    let mut v: Vec<(String, u64, u64)> = std::fs::read_dir(dir(c))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            if !n.starts_with(PREFIX) || !n.ends_with(".tar.gz") {
                return None;
            }
            let m = e.metadata().ok()?;
            let t = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
            Some((n, m.len(), t))
        })
        .collect();
    v.sort_by(|a, b| b.2.cmp(&a.2).then(b.0.cmp(&a.0)));
    v
}

/// Pfad einer Sicherung nach Name (nur Dateien aus dem Sicherungs-Ordner, kein ../)
pub fn path_of(c: &Config, name: &str) -> Option<PathBuf> {
    if name.contains(['/', '\\']) || !name.starts_with(PREFIX) || !name.ends_with(".tar.gz") {
        return None;
    }
    let p = dir(c).join(name);
    p.is_file().then_some(p)
}

fn stamp() -> String {
    // Datum und Uhrzeit (UTC) fuer den Dateinamen
    let t = kvpn::util::now_secs();
    let d = crate::users::date(t as i64);
    let s = t % 86400;
    format!("{d}-{:02}{:02}{:02}", s / 3600, s / 60 % 60, s % 60)
}

fn add_dir<W: Write>(tb: &mut tar::Builder<W>, base: &Path, rel: &Path, prefix: &str, skip: &[&str], skip_files: &[PathBuf]) -> Result<usize, String> {
    let mut n = 0;
    let rd = match std::fs::read_dir(base.join(rel)) {
        Ok(r) => r,
        Err(_) => return Ok(0),
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().to_string();
        let r = rel.join(&name);
        let full = base.join(&r);
        if skip_files.iter().any(|s| std::fs::canonicalize(s).ok() == std::fs::canonicalize(&full).ok()) {
            continue;
        }
        let Ok(md) = std::fs::symlink_metadata(&full) else { continue };
        if md.is_dir() {
            if rel.as_os_str().is_empty() && skip.contains(&name.as_str()) {
                continue;
            }
            n += add_dir(tb, base, &r, prefix, skip, skip_files)?;
        } else if md.is_file() && md.len() <= MAX_FILE && !name.ends_with(".tmp") && !name.ends_with("-journal") && !name.ends_with("-wal") && !name.ends_with("-shm") {
            let data = std::fs::read(&full).map_err(|e| format!("{}: {e}", full.display()))?;
            append(tb, &format!("{prefix}/{}", r.to_string_lossy()), &data, mode_of(&md))?;
            n += 1;
        }
    }
    Ok(n)
}

#[cfg(unix)]
fn mode_of(md: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o777
}
#[cfg(not(unix))]
fn mode_of(_: &std::fs::Metadata) -> u32 {
    0o600
}

fn append<W: Write>(tb: &mut tar::Builder<W>, name: &str, data: &[u8], mode: u32) -> Result<(), String> {
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(mode);
    h.set_mtime(kvpn::util::now_secs());
    h.set_entry_type(tar::EntryType::Regular);
    tb.append_data(&mut h, name, data).map_err(|e| format!("{name}: {e}"))
}

/// konsistente Kopie der Benutzer-Datenbank (laeuft der Server gerade, waere die Datei mitten im Schreiben)
fn db_copy(cfg_path: &str) -> Option<Vec<u8>> {
    let src = crate::users::db_path(cfg_path);
    if !src.is_file() {
        return None;
    }
    let tmp = std::env::temp_dir().join(format!("kvpn-sicherung-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let ok = rusqlite::Connection::open(&src).and_then(|c| c.execute("VACUUM INTO ?1", [tmp.to_string_lossy().to_string()])).is_ok();
    let data = if ok { std::fs::read(&tmp).ok() } else { std::fs::read(&src).ok() };
    let _ = std::fs::remove_file(&tmp);
    data
}

/// Sicherung anlegen; `art` steht im Dateinamen ("" = taeglich/von Hand, z. B. "vor-wiederherstellung").
/// Ergebnis: Pfad der neuen Datei
pub fn create(cfg_path: &str, c: &Config, art: &str) -> Result<PathBuf, String> {
    let d = dir(c);
    std::fs::create_dir_all(&d).map_err(|e| format!("{}: {e}", d.display()))?;
    restrict(&d, 0o700);
    let name = format!("{PREFIX}{}{}.tar.gz", stamp(), if art.is_empty() { String::new() } else { format!("-{art}") });
    let path = d.join(&name);
    let tmp = d.join(format!(".{name}.tmp"));
    let res = (|| -> Result<usize, String> {
        let f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        restrict(&tmp, 0o600);
        let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        let mut tb = tar::Builder::new(gz);
        let info = serde_json::json!({
            "art": "KroneVPN-Sicherung",
            "server_version": crate::VERSION,
            "name": c.display_name(),
            "zeit": kvpn::util::now_secs(),
            "config_datei": Path::new(cfg_path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        });
        append(&mut tb, "sicherung.json", serde_json::to_string_pretty(&info).unwrap().as_bytes(), 0o600)?;
        let cdir = Path::new(cfg_path).parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_path_buf();
        let db = crate::users::db_path(cfg_path);
        let mut n = 0;
        // aus dem Konfig-Ordner nur, was dem Server gehoert: server.toml, Ordner codes/ (Geraete-Schluessel fuer
        // "kvpn-server code"), benutzer.db (als konsistente Kopie) – nicht, was sonst noch dort liegt
        let cfg_name = Path::new(cfg_path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "server.toml".into());
        let data = std::fs::read(cfg_path).map_err(|e| format!("{cfg_path}: {e}"))?;
        append(&mut tb, &format!("config/{cfg_name}"), &data, 0o600)?;
        n += 1;
        let codes = crate::config::codes_dir(cfg_path);
        if codes.is_dir() {
            n += add_dir(&mut tb, &cdir, Path::new(codes.file_name().unwrap()), "config", &[], &[d.clone()])?;
        }
        if let Some(b) = db_copy(cfg_path) {
            append(&mut tb, &format!("config/{}", db.file_name().unwrap().to_string_lossy()), &b, 0o600)?;
            n += 1;
        }
        n += add_dir(&mut tb, Path::new(&c.state_dir), Path::new(""), "state", SKIP_STATE, &[d.clone()])?;
        let gz = tb.into_inner().map_err(|e| e.to_string())?;
        let f = gz.finish().map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        Ok(n)
    })();
    match res {
        Ok(_) => {
            std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
            Ok(path)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(unix)]
fn restrict(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
}
#[cfg(not(unix))]
fn restrict(_: &Path, _: u32) {}

/// alte automatische Sicherungen loeschen (behaelt die neuesten `keep`; besondere wie "vor-wiederherstellung" auch)
pub fn prune(c: &Config) -> usize {
    let keep = c.backup_keep.max(1) as usize;
    let mut n = 0;
    for (i, (name, _, _)) in list(c).into_iter().filter(|(n, _, _)| n.matches('-').count() == 5).enumerate() {
        if i >= keep && std::fs::remove_file(dir(c).join(&name)).is_ok() {
            n += 1;
        }
    }
    n
}

/// ist heute schon gesichert worden? (neueste Sicherung juenger als 23 h)
pub fn due(c: &Config) -> bool {
    c.backup && list(c).first().map(|x| kvpn::util::now_secs().saturating_sub(x.2) > 23 * 3600).unwrap_or(true)
}

/// Inhalt einer Sicherung lesen: (Name im Archiv, Daten)
fn read_all(file: &Path) -> Result<Vec<(String, Vec<u8>, u32)>, String> {
    let f = std::fs::File::open(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(f));
    let mut out = Vec::new();
    for e in ar.entries().map_err(|e| format!("keine gueltige Sicherung: {e}"))? {
        let mut e = e.map_err(|e| format!("keine gueltige Sicherung: {e}"))?;
        if e.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let name = e.path().map_err(|e| e.to_string())?.to_string_lossy().to_string();
        let mode = e.header().mode().unwrap_or(0o600);
        let mut b = Vec::new();
        e.read_to_end(&mut b).map_err(|e| format!("{name}: {e}"))?;
        out.push((name, b, mode));
    }
    Ok(out)
}

/// sicherer Teilpfad (kein absoluter Pfad, kein ..)
fn safe_rel(p: &str) -> Option<PathBuf> {
    let pb = PathBuf::from(p);
    if p.is_empty() || pb.is_absolute() || pb.components().any(|c| !matches!(c, std::path::Component::Normal(_))) {
        return None;
    }
    Some(pb)
}

/// Kurzinfo einer Sicherung (fuer die Rueckfrage): (Name des VPNs, Zeit, Server-Version, Dateien)
pub fn info(file: &Path) -> Result<(String, u64, String, usize), String> {
    let all = read_all(file)?;
    let j: serde_json::Value = all
        .iter()
        .find(|(n, _, _)| n == "sicherung.json")
        .and_then(|(_, b, _)| serde_json::from_slice(b).ok())
        .ok_or("keine KroneVPN-Sicherung (sicherung.json fehlt)")?;
    if j["art"] != "KroneVPN-Sicherung" {
        return Err("keine KroneVPN-Sicherung".into());
    }
    Ok((j["name"].as_str().unwrap_or("").into(), j["zeit"].as_u64().unwrap_or(0), j["server_version"].as_str().unwrap_or("").into(), all.len() - 1))
}

/// Sicherung zurueckspielen. Vorher wird der aktuelle Stand gesichert (Ergebnis: Pfad dieser Sicherung, falls es
/// schon einen Server gab). Dateien, die es in der Sicherung nicht gibt, bleiben liegen.
pub fn restore(cfg_path: &str, file: &Path) -> Result<(Option<PathBuf>, usize), String> {
    let all = read_all(file)?;
    let j: serde_json::Value = all
        .iter()
        .find(|(n, _, _)| n == "sicherung.json")
        .and_then(|(_, b, _)| serde_json::from_slice(b).ok())
        .ok_or("keine KroneVPN-Sicherung (sicherung.json fehlt)")?;
    if j["art"] != "KroneVPN-Sicherung" {
        return Err("keine KroneVPN-Sicherung".into());
    }
    let cfg_name = j["config_datei"].as_str().unwrap_or("server.toml").to_string();
    if !all.iter().any(|(n, _, _)| *n == format!("config/{cfg_name}")) {
        return Err(format!("{cfg_name} fehlt in der Sicherung"));
    }
    // aktueller Stand zuerst in Sicherheit
    let before = match Config::load(cfg_path) {
        Ok(c) => Some(create(cfg_path, &c, "vor-wiederherstellung")?),
        Err(_) => None,
    };
    let cdir = Path::new(cfg_path).parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_path_buf();
    let mut n = 0;
    let write = |base: &Path, rel: &Path, data: &[u8], mode: u32| -> Result<(), String> {
        let p = base.join(rel);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        let tmp = p.with_file_name(format!(".{}.neu", p.file_name().unwrap().to_string_lossy()));
        std::fs::write(&tmp, data).map_err(|e| format!("{}: {e}", tmp.display()))?;
        restrict(&tmp, mode & 0o777);
        std::fs::rename(&tmp, &p).map_err(|e| format!("{}: {e}", p.display()))
    };
    // 1. Konfiguration (server.toml unter dem Namen, den dieser Server benutzt)
    for (name, data, mode) in all.iter().filter(|(n, _, _)| n.starts_with("config/")) {
        let Some(rel) = safe_rel(&name["config/".len()..]) else { continue };
        let rel = if rel == Path::new(&cfg_name) { PathBuf::from(Path::new(cfg_path).file_name().unwrap()) } else { rel };
        write(&cdir, &rel, data, *mode)?;
        n += 1;
    }
    // alte Datenbank-Reste (Journal) der ersetzten Datenbank weg
    let db = crate::users::db_path(cfg_path);
    for x in ["-journal", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{x}", db.display()));
    }
    // 2. Zustand in den Ordner, den die zurueckgespielte Konfiguration nennt
    let c = Config::load(cfg_path).map_err(|e| format!("zurueckgespielte Konfiguration: {e}"))?;
    let sdir = PathBuf::from(&c.state_dir);
    for (name, data, mode) in all.iter().filter(|(n, _, _)| n.starts_with("state/")) {
        let Some(rel) = safe_rel(&name["state/".len()..]) else { continue };
        write(&sdir, &rel, data, *mode)?;
        n += 1;
    }
    Ok((before, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sichern_und_zurueck() {
        let base = std::env::temp_dir().join(format!("kvpn-sich-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cdir = base.join("etc");
        std::fs::create_dir_all(cdir.join("codes")).unwrap();
        let cfg_path = cdir.join("server.toml").to_string_lossy().to_string();
        let (k, _) = kvpn::crypto::generate_keypair();
        let mut c = Config::new("wss://vpn.example.org/api/v1/stream".into(), kvpn::code::key_to_b64(&k));
        c.state_dir = base.join("state").to_string_lossy().to_string();
        c.users = false;
        c.save(&cfg_path).unwrap();
        std::fs::write(cdir.join("codes/handy.key"), "geheim").unwrap();
        std::fs::create_dir_all(base.join("state/update")).unwrap();
        std::fs::write(base.join("state/update/gross.apk"), "x").unwrap();
        std::fs::write(base.join("state/bekannte-geraete.txt"), "abc\n").unwrap();
        let p = create(&cfg_path, &c, "").unwrap();
        assert_eq!(list(&c).len(), 1);
        assert!(path_of(&c, p.file_name().unwrap().to_str().unwrap()).is_some());
        assert!(path_of(&c, "../server.toml").is_none());
        let (_, _, ver, files) = info(&p).unwrap();
        assert_eq!(ver, crate::VERSION);
        assert_eq!(files, 3, "server.toml, codes/handy.key, bekannte-geraete.txt (ohne update/)");
        // alles weg -> zurueck
        std::fs::remove_file(cdir.join("codes/handy.key")).unwrap();
        std::fs::write(base.join("state/bekannte-geraete.txt"), "").unwrap();
        let mut c2 = c.clone();
        c2.vpn_name = "Anders".into();
        c2.save(&cfg_path).unwrap();
        let (vorher, n) = restore(&cfg_path, &p).unwrap();
        assert!(vorher.is_some());
        assert_eq!(n, 3);
        assert_eq!(std::fs::read_to_string(cdir.join("codes/handy.key")).unwrap(), "geheim");
        assert_eq!(std::fs::read_to_string(base.join("state/bekannte-geraete.txt")).unwrap(), "abc\n");
        assert_eq!(Config::load(&cfg_path).unwrap().vpn_name, c.vpn_name);
        // kaputte Datei
        std::fs::write(base.join("kaputt.tar.gz"), "nix").unwrap();
        assert!(restore(&cfg_path, &base.join("kaputt.tar.gz")).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn pfade() {
        assert!(safe_rel("a/b.txt").is_some());
        assert!(safe_rel("../x").is_none());
        assert!(safe_rel("/etc/passwd").is_none());
        assert!(safe_rel("a/../../x").is_none());
    }
}
