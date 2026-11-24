//! Benutzerverwaltung (SQLite): Datei benutzer.db neben server.toml (nur root lesbar).
//!
//! - Benutzer (Personen) mit beliebig vielen Geraeten, sperren/entsperren, Hoechstzahl Geraete je Benutzer
//! - Geraete einzeln sperren, mit Ablaufdatum versehen, einem Benutzer zuordnen
//! - Verlauf: wann sich welches Geraet verbunden bzw. getrennt hat (90 Tage)
//!
//! Gesperrte oder abgelaufene Geraete (oder Geraete gesperrter Benutzer) werden beim Verbinden abgelehnt und – wenn
//! gerade verbunden – sofort getrennt. Sie behalten ihren Platz und ihre Adresse (Entsperren = gleicher Code geht wieder).
//! Eingeschaltet mit `users = true` in server.toml (Standard; `kvpn-server einstellungen`).

use crate::config::Peer;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

pub fn db_path(cfg_path: &str) -> PathBuf {
    Path::new(cfg_path).parent().unwrap_or(Path::new(".")).join("benutzer.db")
}

fn now() -> i64 {
    kvpn::util::now_secs() as i64
}

fn e(x: rusqlite::Error) -> String {
    format!("Benutzer-Datenbank: {x}")
}

pub fn open(cfg_path: &str) -> Result<Connection, String> {
    let p = db_path(cfg_path);
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let new = !p.exists();
    let db = Connection::open(&p).map_err(|x| format!("{}: {x}", p.display()))?;
    #[cfg(unix)]
    if new {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    let _ = new;
    db.busy_timeout(std::time::Duration::from_secs(5)).map_err(e)?;
    db.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS users(
             id INTEGER PRIMARY KEY,
             name TEXT NOT NULL UNIQUE COLLATE NOCASE,
             note TEXT NOT NULL DEFAULT '',
             created INTEGER NOT NULL,
             disabled INTEGER NOT NULL DEFAULT 0,
             max_devices INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE IF NOT EXISTS devices(
             id INTEGER PRIMARY KEY,
             name TEXT NOT NULL UNIQUE COLLATE NOCASE,
             public_key TEXT NOT NULL UNIQUE,
             idx INTEGER NOT NULL UNIQUE,
             user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
             created INTEGER NOT NULL,
             disabled INTEGER NOT NULL DEFAULT 0,
             expires INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE IF NOT EXISTS events(
             ts INTEGER NOT NULL,
             device TEXT NOT NULL,
             event TEXT NOT NULL);
         CREATE INDEX IF NOT EXISTS events_ts ON events(ts);",
    )
    .map_err(e)?;
    Ok(db)
}

#[derive(Debug, Clone)]
pub struct Device {
    pub peer: Peer,
    pub disabled: bool,
    pub user_disabled: bool,
    pub expires: i64,
    #[allow(dead_code)]
    pub created: i64,
}

impl Device {
    pub fn active(&self) -> bool {
        !self.disabled && !self.user_disabled && (self.expires == 0 || self.expires > now())
    }
    pub fn status(&self) -> String {
        if self.disabled {
            "gesperrt".into()
        } else if self.user_disabled {
            "Benutzer gesperrt".into()
        } else if self.expires != 0 && self.expires <= now() {
            format!("abgelaufen am {}", date(self.expires))
        } else if self.expires != 0 {
            format!("aktiv bis {}", date(self.expires))
        } else {
            "aktiv".into()
        }
    }
}

pub fn devices(db: &Connection) -> Result<Vec<Device>, String> {
    let mut st = db
        .prepare(
            "SELECT d.name, d.public_key, d.idx, COALESCE(u.name, ''), d.disabled, COALESCE(u.disabled, 0), d.expires, d.created
             FROM devices d LEFT JOIN users u ON u.id = d.user_id ORDER BY d.idx",
        )
        .map_err(e)?;
    let rows = st
        .query_map([], |r| {
            Ok(Device {
                peer: Peer { name: r.get(0)?, public_key: r.get(1)?, index: r.get::<_, i64>(2)? as u8, user: r.get(3)? },
                disabled: r.get::<_, i64>(4)? != 0,
                user_disabled: r.get::<_, i64>(5)? != 0,
                expires: r.get(6)?,
                created: r.get(7)?,
            })
        })
        .map_err(e)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(e)
}

/// (aktive, gesperrte/abgelaufene) Geraete
pub fn peers(db: &Connection) -> Result<(Vec<Peer>, Vec<Peer>), String> {
    let (a, b): (Vec<Device>, Vec<Device>) = devices(db)?.into_iter().partition(|d| d.active());
    Ok((a.into_iter().map(|d| d.peer).collect(), b.into_iter().map(|d| d.peer).collect()))
}

fn user_id(db: &Connection, name: &str, create: bool) -> Result<Option<i64>, String> {
    let name = name.trim();
    if name.is_empty() {
        return Ok(None);
    }
    let id: Option<i64> = db.query_row("SELECT id FROM users WHERE name = ?1", [name], |r| r.get(0)).optional().map_err(e)?;
    match (id, create) {
        (Some(i), _) => Ok(Some(i)),
        (None, true) => {
            add_user(db, name, "")?;
            user_id(db, name, false)
        }
        (None, false) => Err(format!("kein Benutzer '{name}' (anlegen: kvpn-server benutzer add \"{name}\")")),
    }
}

/// Geraete aus server.toml uebernehmen (schon vorhandene bleiben). Liefert die Anzahl neuer.
pub fn import(db: &Connection, list: &[Peer]) -> Result<usize, String> {
    let mut n = 0;
    for p in list {
        let uid = user_id(db, &p.user, true)?;
        n += db
            .execute(
                "INSERT OR IGNORE INTO devices(name, public_key, idx, user_id, created) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![p.name, p.public_key, p.index as i64, uid, now()],
            )
            .map_err(e)?;
    }
    Ok(n)
}

/// Benutzerverwaltung wieder eingeschaltet: server.toml ist der aktuelle Stand der aktiven Geraete.
/// Neue uebernehmen, aktive, die dort fehlen (inzwischen entfernt), loeschen. Gesperrte bleiben.
pub fn sync(db: &Connection, list: &[Peer]) -> Result<(usize, usize), String> {
    let mut removed = 0;
    // inzwischen neu angelegte Geraete auf dem Platz/mit dem Namen eines nur noch hier stehenden (gesperrten) Geraets:
    // das neue gewinnt
    for p in list {
        removed += db
            .execute("DELETE FROM devices WHERE (idx = ?1 OR name = ?2) AND public_key != ?3", params![p.index as i64, p.name, p.public_key])
            .map_err(e)?;
    }
    let added = import(db, list)?;
    for d in devices(db)? {
        if d.active() && !list.iter().any(|p| p.public_key == d.peer.public_key) {
            removed += db.execute("DELETE FROM devices WHERE public_key = ?1", [&d.peer.public_key]).map_err(e)?;
        }
    }
    Ok((added, removed))
}

pub fn add_device(db: &Connection, p: &Peer) -> Result<(), String> {
    let uid = user_id(db, &p.user, true)?;
    if let Some(u) = uid {
        let (max, n): (i64, i64) = db
            .query_row("SELECT max_devices, (SELECT COUNT(*) FROM devices WHERE user_id = ?1) FROM users WHERE id = ?1", [u], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(e)?;
        if max > 0 && n >= max {
            return Err(format!("Benutzer '{}' hat schon {n} von hoechstens {max} Geraeten (aendern: kvpn-server benutzer max \"{}\" <anzahl>)", p.user, p.user));
        }
    }
    db.execute(
        "INSERT INTO devices(name, public_key, idx, user_id, created) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![p.name, p.public_key, p.index as i64, uid, now()],
    )
    .map_err(e)?;
    Ok(())
}

pub fn remove_device(db: &Connection, name: &str) -> Result<Option<Peer>, String> {
    let d = devices(db)?.into_iter().find(|d| d.peer.name.eq_ignore_ascii_case(name.trim()));
    if let Some(d) = &d {
        db.execute("DELETE FROM devices WHERE public_key = ?1", [&d.peer.public_key]).map_err(e)?;
    }
    Ok(d.map(|d| d.peer))
}

fn set_device(db: &Connection, name: &str, sql: &str, v: i64) -> Result<bool, String> {
    Ok(db.execute(sql, params![v, name.trim()]).map_err(e)? > 0)
}

pub fn set_disabled(db: &Connection, name: &str, disabled: bool) -> Result<bool, String> {
    set_device(db, name, "UPDATE devices SET disabled = ?1 WHERE name = ?2", disabled as i64)
}

pub fn set_expires(db: &Connection, name: &str, ts: i64) -> Result<bool, String> {
    set_device(db, name, "UPDATE devices SET expires = ?1 WHERE name = ?2", ts)
}

pub fn assign(db: &Connection, device: &str, user: &str) -> Result<bool, String> {
    let uid = user_id(db, user, false)?;
    Ok(db.execute("UPDATE devices SET user_id = ?1 WHERE name = ?2", params![uid, device.trim()]).map_err(e)? > 0)
}

#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub note: String,
    pub created: i64,
    pub disabled: bool,
    pub max_devices: i64,
    pub devices: Vec<String>,
}

pub fn users(db: &Connection) -> Result<Vec<User>, String> {
    let mut st = db.prepare("SELECT id, name, note, created, disabled, max_devices FROM users ORDER BY name").map_err(e)?;
    let rows: Vec<(i64, User)> = st
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                User { name: r.get(1)?, note: r.get(2)?, created: r.get(3)?, disabled: r.get::<_, i64>(4)? != 0, max_devices: r.get(5)?, devices: vec![] },
            ))
        })
        .map_err(e)?
        .collect::<Result<_, _>>()
        .map_err(e)?;
    let mut out = Vec::new();
    for (id, mut u) in rows {
        let mut st = db.prepare("SELECT name FROM devices WHERE user_id = ?1 ORDER BY idx").map_err(e)?;
        u.devices = st.query_map([id], |r| r.get(0)).map_err(e)?.collect::<Result<_, _>>().map_err(e)?;
        out.push(u);
    }
    Ok(out)
}

pub fn add_user(db: &Connection, name: &str, note: &str) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() || name.len() > 40 || name.contains(['"', '\n']) {
        return Err("Benutzername fehlt oder ungueltig (hoechstens 40 Zeichen)".into());
    }
    db.execute("INSERT INTO users(name, note, created) VALUES (?1, ?2, ?3)", params![name, note, now()]).map_err(|x| match x {
        rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => format!("Benutzer '{name}' gibt es schon"),
        x => e(x),
    })?;
    Ok(())
}

/// Benutzer loeschen; seine Geraete bleiben (ohne Benutzer) – ausser `with_devices`. Liefert die entfernten Geraete.
pub fn remove_user(db: &Connection, name: &str, with_devices: bool) -> Result<Option<Vec<Peer>>, String> {
    let Some(id) = db.query_row("SELECT id FROM users WHERE name = ?1", [name.trim()], |r| r.get::<_, i64>(0)).optional().map_err(e)? else {
        return Ok(None);
    };
    let mut gone = Vec::new();
    if with_devices {
        gone = devices(db)?.into_iter().filter(|d| d.peer.user.eq_ignore_ascii_case(name.trim())).map(|d| d.peer).collect();
        db.execute("DELETE FROM devices WHERE user_id = ?1", [id]).map_err(e)?;
    }
    db.execute("DELETE FROM users WHERE id = ?1", [id]).map_err(e)?;
    Ok(Some(gone))
}

pub fn set_user_disabled(db: &Connection, name: &str, disabled: bool) -> Result<bool, String> {
    Ok(db.execute("UPDATE users SET disabled = ?1 WHERE name = ?2", params![disabled as i64, name.trim()]).map_err(e)? > 0)
}

pub fn set_user_max(db: &Connection, name: &str, max: i64) -> Result<bool, String> {
    Ok(db.execute("UPDATE users SET max_devices = ?1 WHERE name = ?2", params![max.max(0), name.trim()]).map_err(e)? > 0)
}

/// Eintrag im Verlauf (Fehler werden ignoriert – der Verlauf ist nur Zusatz). Aeltere als 90 Tage fliegen raus.
pub fn log_event(cfg_path: &str, device: &str, event: &str) {
    if let Ok(db) = open(cfg_path) {
        let _ = db.execute("INSERT INTO events(ts, device, event) VALUES (?1, ?2, ?3)", params![now(), device, event]);
        if rand::random::<u8>() == 0 {
            let _ = db.execute("DELETE FROM events WHERE ts < ?1", [now() - 90 * 86400]);
        }
    }
}

pub fn events(db: &Connection, limit: usize, device: Option<&str>) -> Result<Vec<(i64, String, String)>, String> {
    let mut st = db
        .prepare("SELECT ts, device, event FROM events WHERE (?1 = '' OR device = ?1 COLLATE NOCASE) ORDER BY ts DESC, rowid DESC LIMIT ?2")
        .map_err(e)?;
    let mut v: Vec<(i64, String, String)> = st
        .query_map(params![device.unwrap_or(""), limit as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(e)?
        .collect::<Result<_, _>>()
        .map_err(e)?;
    v.reverse();
    Ok(v)
}

// ------------------------------------------------------------------------------------------------ Datum

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// "2026-12-31" (UTC)
pub fn date(ts: i64) -> String {
    let z = ts.div_euclid(86400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + (month <= 2) as i64;
    format!("{year:04}-{month:02}-{day:02}")
}

pub fn datetime(ts: i64) -> String {
    let s = ts.rem_euclid(86400);
    format!("{} {:02}:{:02}:{:02}", date(ts), s / 3600, s / 60 % 60, s % 60)
}

/// Ablauf: "2026-12-31" oder "31.12.2026" (gilt bis Tagesende), "30" bzw. "30d" (Tage ab jetzt), "nie"/"0" (kein Ablauf)
pub fn parse_expiry(s: &str) -> Result<i64, String> {
    let s = s.trim().to_lowercase();
    if matches!(s.as_str(), "nie" | "never" | "0" | "kein" | "") {
        return Ok(0);
    }
    if let Ok(d) = s.trim_end_matches(['d', 't']).parse::<i64>() {
        if d > 0 && d < 100_000 {
            return Ok(now() + d * 86400);
        }
    }
    let parts: Vec<i64> = s.split(['-', '.']).filter_map(|x| x.parse().ok()).collect();
    let (y, m, d) = match (parts.as_slice(), s.contains('.')) {
        ([d, m, y], true) => (*y, *m, *d),
        ([y, m, d], false) => (*y, *m, *d),
        _ => return Err(format!("'{s}': Datum als 2026-12-31 oder 31.12.2026, Tage als 30, oder 'nie'")),
    };
    if !(2000..3000).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(format!("'{s}': ungueltiges Datum"));
    }
    Ok(days_from_civil(y, m, d) * 86400 + 86399)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str, i: u8, user: &str) -> Peer {
        let (_, p) = kvpn::crypto::generate_keypair();
        Peer { name: name.into(), public_key: kvpn::code::key_to_b64(&p), index: i, user: user.into() }
    }

    #[test]
    fn datenbank() {
        let dir = std::env::temp_dir().join(format!("kvpn-users-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("server.toml").to_string_lossy().to_string();
        let db = open(&cfg).unwrap();
        assert_eq!(import(&db, &[peer("Handy", 2, ""), peer("PC", 3, "Anna")]).unwrap(), 2);
        assert_eq!(import(&db, &[peer("Handy", 2, "")]).unwrap(), 0, "gleicher Name/Adresse wird nicht doppelt angelegt");
        add_device(&db, &peer("Laptop", 4, "Anna")).unwrap();
        assert!(add_device(&db, &peer("laptop", 5, "")).is_err(), "Name doppelt");
        let (a, b) = peers(&db).unwrap();
        assert_eq!((a.len(), b.len()), (3, 0));
        assert_eq!(users(&db).unwrap()[0].devices, vec!["PC".to_string(), "Laptop".to_string()]);
        // sperren / Benutzer sperren / Ablauf
        assert!(set_disabled(&db, "Handy", true).unwrap());
        assert_eq!(peers(&db).unwrap().0.len(), 2);
        assert!(set_user_disabled(&db, "anna", true).unwrap());
        assert_eq!(peers(&db).unwrap().0.len(), 0);
        set_user_disabled(&db, "Anna", false).unwrap();
        set_expires(&db, "PC", now() - 10).unwrap();
        let (a, b) = peers(&db).unwrap();
        assert_eq!((a.len(), b.len()), (1, 2));
        // Hoechstzahl je Benutzer
        set_user_max(&db, "Anna", 2).unwrap();
        assert!(add_device(&db, &peer("Tablet", 6, "Anna")).is_err());
        // Benutzer loeschen: Geraete bleiben ohne Benutzer
        remove_user(&db, "Anna", false).unwrap();
        assert!(devices(&db).unwrap().iter().all(|d| d.peer.user.is_empty()));
        // sync: aktive, die in der Liste fehlen, werden geloescht; gesperrte bleiben
        let (added, removed) = sync(&db, &[]).unwrap();
        assert_eq!((added, removed), (0, 1));
        assert_eq!(devices(&db).unwrap().len(), 2);
        // neues Geraet auf dem Platz eines gesperrten (waehrend die Benutzerverwaltung aus war): das neue gewinnt
        let handy_idx = devices(&db).unwrap().iter().find(|d| d.peer.name == "Handy").unwrap().peer.index;
        let neu = peer("Neu", handy_idx, "");
        let (added, removed) = sync(&db, &[neu.clone()]).unwrap();
        assert_eq!((added, removed), (1, 1));
        assert!(devices(&db).unwrap().iter().any(|d| d.peer == neu));
        log_event(&cfg, "Handy", "verbunden");
        assert_eq!(events(&db, 10, Some("handy")).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn datum() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(parse_expiry("2026-12-31").unwrap()), "2026-12-31");
        assert_eq!(date(parse_expiry("31.12.2026").unwrap()), "2026-12-31");
        assert_eq!(parse_expiry("nie").unwrap(), 0);
        assert!(parse_expiry("30").unwrap() > now());
        assert!(parse_expiry("morgen").is_err());
    }
}
