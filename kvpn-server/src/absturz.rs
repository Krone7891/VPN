//! Absturz-Protokolle der Apps: kommen verschluesselt durch den Tunnel (REC_CRASH) und landen als Textdatei in
//! <state_dir>/absturz-logs/<geraet>/<zeit>-<name>.txt. Ansehen: kvpn-server abstuerze [geraet]

use std::path::{Path, PathBuf};

/// hoechstens so viele Protokolle je Geraet (aeltere werden geloescht)
const MAX_JE_GERAET: usize = 200;

fn sicher(s: &str, max: usize) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' }).take(max).collect::<String>().trim_matches('.').to_string()
}

pub fn ordner(state_dir: &str) -> PathBuf {
    Path::new(state_dir).join("absturz-logs")
}

/// Datensatz [Namenslaenge][Name][Text] speichern; liefert den Namen fuer die Bestaetigung
pub fn speichern(state_dir: &str, geraet: &str, data: &[u8]) -> Option<String> {
    let n = *data.first()? as usize;
    if data.len() < 1 + n || n == 0 {
        return None;
    }
    let name = String::from_utf8_lossy(&data[1..1 + n]).to_string();
    let text = &data[1 + n..];
    if text.len() > kvpn::proto::MAX_CRASH {
        return None;
    }
    let dir = ordner(state_dir).join(sicher(geraet, 60));
    std::fs::create_dir_all(&dir).ok()?;
    let mut datei = sicher(&name, 80);
    if datei.is_empty() {
        return None;
    }
    if !datei.ends_with(".txt") {
        datei.push_str(".txt");
    }
    let ziel = dir.join(&datei);
    // gleiches Protokoll nochmal (Bestaetigung verloren gegangen): nur bestaetigen
    if !ziel.exists() {
        let kopf = format!("Geraet: {geraet}\nEmpfangen: {} UTC\n\n", crate::users::datetime(kvpn::util::now_secs() as i64));
        let mut b = kopf.into_bytes();
        b.extend_from_slice(text);
        std::fs::write(&ziel, b).ok()?;
        aufraeumen(&dir);
        crate::log!("{geraet}: Absturz-Protokoll empfangen -> {}", ziel.display());
    }
    Some(name)
}

fn aufraeumen(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut f: Vec<(std::time::SystemTime, PathBuf)> = rd.flatten().filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path()))).collect();
    if f.len() <= MAX_JE_GERAET {
        return;
    }
    f.sort();
    for (_, p) in &f[..f.len() - MAX_JE_GERAET] {
        let _ = std::fs::remove_file(p);
    }
}

/// alle Protokolle: (Geraet, Datei, Groesse, Zeit)
pub fn liste(state_dir: &str) -> Vec<(String, PathBuf, u64, u64)> {
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir(ordner(state_dir)) else { return out };
    for g in rd.flatten().filter(|e| e.path().is_dir()) {
        let name = g.file_name().to_string_lossy().to_string();
        if let Ok(fs) = std::fs::read_dir(g.path()) {
            for f in fs.flatten() {
                let m = f.metadata().ok();
                let t = m.as_ref().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
                out.push((name.clone(), f.path(), m.map(|m| m.len()).unwrap_or(0), t));
            }
        }
    }
    out.sort_by_key(|x| x.3);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speichern_und_aufraeumen() {
        let d = std::env::temp_dir().join(format!("kvpn-absturz-{}", std::process::id()));
        let sd = d.to_str().unwrap();
        let rec = |name: &str, text: &str| {
            let mut v = vec![name.len() as u8];
            v.extend_from_slice(name.as_bytes());
            v.extend_from_slice(text.as_bytes());
            v
        };
        assert_eq!(speichern(sd, "Mein Handy", &rec("1764000000-java.txt", "java.lang.NullPointerException")).as_deref(), Some("1764000000-java.txt"));
        // doppelt: nur bestaetigt, nicht neu
        assert!(speichern(sd, "Mein Handy", &rec("1764000000-java.txt", "anders")).is_some());
        let l = liste(sd);
        assert_eq!(l.len(), 1);
        let t = std::fs::read_to_string(&l[0].1).unwrap();
        assert!(t.contains("Geraet: Mein Handy") && t.contains("NullPointerException") && !t.contains("anders"));
        // boese Namen bleiben im Ordner
        speichern(sd, "../x", &rec("../../etc/passwd", "x")).unwrap();
        assert!(liste(sd).iter().all(|(_, p, _, _)| p.starts_with(ordner(sd))));
        assert!(speichern(sd, "x", &[5, b'a']).is_none());
        for i in 0..MAX_JE_GERAET + 5 {
            speichern(sd, "viel", &rec(&format!("{i}-rust.txt"), "panic")).unwrap();
        }
        assert_eq!(liste(sd).iter().filter(|x| x.0 == "viel").count(), MAX_JE_GERAET);
        let _ = std::fs::remove_dir_all(&d);
    }
}
