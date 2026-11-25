//! Automatische Aktualisierung der Apps (Android, Windows, Linux).
//!
//! Ablauf: Der Server legt `update.json` (Version, Dateien mit Groesse und SHA-256) und deren Ed25519-Signatur
//! bereit. Beim Verbinden meldet die App ihre Version; ist auf dem Server eine neuere, steht das Angebot in der
//! Antwort des Handshakes. Die App prueft die Signatur gegen den fest eingebauten Schluessel
//! (`kvpn/update-key.pub`), laedt die Datei stueckweise UEBER DIE BESTEHENDE VERSCHLUESSELTE VERBINDUNG
//! (kommt also durch jede Firewall, durch die auch das VPN kommt, und nur eigene Geraete bekommen sie),
//! prueft die SHA-256-Pruefsumme und uebergibt sie der Plattform zum Einspielen.
//!
//! Selbst ein uebernommener Server kann so keine fremden Programme verteilen: ohne den geheimen
//! Signier-Schluessel (liegt nur beim Bauen vor, nie auf dem Server) wird nichts angenommen.

use crate::proto::UpdateOffer;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// oeffentlicher Schluessel, mit dem Updates signiert sein muessen (Hex, 32 Bytes)
pub const PUBLIC_KEY_HEX: &str = include_str!("../update-key.pub");
/// groesste angenommene Update-Datei
pub const MAX_SIZE: u64 = 64 << 20;
/// Stueckgroesse beim Uebertragen
pub const CHUNK: usize = 30_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    /// Version dieser App (jede App hat ihre eigene; leer = `Manifest::version`). So bekommt ein Geraet nur dann
    /// ein Update, wenn sich SEINE App geaendert hat.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
}

/// Inhalt von update.json; `files` nach Plattform: "android", "windows", "linux"
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: String,
    pub files: BTreeMap<String, FileEntry>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

/// "1.2.10" > "1.2.9"
pub fn newer(a: &str, b: &str) -> bool {
    let p = |s: &str| -> Vec<u64> { s.trim().split('.').map(|x| x.parse().unwrap_or(0)).collect() };
    let (a, b) = (p(a), p(b));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    false
}

impl Manifest {
    /// Version der App fuer diese Plattform
    pub fn version_for(&self, os: &str) -> Option<&str> {
        self.files.get(os).map(|f| if f.version.is_empty() { self.version.as_str() } else { f.version.as_str() })
    }
}

/// Signatur pruefen und Liste lesen
pub fn verify(manifest: &str, sig_b64: &str) -> Result<Manifest, String> {
    verify_with(PUBLIC_KEY_HEX, manifest, sig_b64)
}

pub fn verify_with(pub_hex: &str, manifest: &str, sig_b64: &str) -> Result<Manifest, String> {
    let pk = unhex(pub_hex).filter(|k| k.len() == 32).ok_or("eingebauter Update-Schluessel ungueltig")?;
    let sig = base64::engine::general_purpose::STANDARD.decode(sig_b64.trim()).map_err(|_| "Signatur ist kein Base64")?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pk)
        .verify(manifest.as_bytes(), &sig)
        .map_err(|_| "Update-Signatur ungueltig – wird nicht installiert".to_string())?;
    serde_json::from_str(manifest).map_err(|e| format!("update.json fehlerhaft: {e}"))
}

/// neuen Signier-Schluessel erzeugen: (geheimer Schluessel PKCS#8, oeffentlicher Schluessel Hex)
pub fn keygen() -> Result<(Vec<u8>, String), String> {
    use ring::signature::KeyPair;
    let rng = ring::rand::SystemRandom::new();
    let pk8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| e.to_string())?;
    let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pk8.as_ref()).map_err(|e| e.to_string())?;
    Ok((pk8.as_ref().to_vec(), hex(kp.public_key().as_ref())))
}

/// signieren: (Signatur Base64, oeffentlicher Schluessel Hex)
pub fn sign(pk8: &[u8], manifest: &str) -> Result<(String, String), String> {
    use ring::signature::KeyPair;
    let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pk8).map_err(|_| "Signier-Schluessel ungueltig")?;
    Ok((base64::engine::general_purpose::STANDARD.encode(kp.sign(manifest.as_bytes()).as_ref()), hex(kp.public_key().as_ref())))
}

/// fertig geladenes und geprueftes Update
pub struct Ready {
    pub version: String,
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Default)]
struct St {
    target: Option<(String, FileEntry)>,
    buf: Vec<u8>,
    done: bool,
    error: String,
}

/// Zustand fuer die Anzeige
#[derive(Debug, Clone, Default, Serialize)]
pub struct UpdateStatus {
    /// angebotene Version (leer = keine)
    pub version: String,
    pub got: u64,
    pub size: u64,
    pub done: bool,
    pub error: String,
}

/// Update-Logik auf Client-Seite (bleibt ueber Neuverbindungen erhalten: abgebrochene Downloads gehen weiter)
pub struct Updater {
    os: String,
    current: String,
    st: Mutex<St>,
    on_ready: Box<dyn Fn(Ready) + Send + Sync>,
}

impl Updater {
    pub fn new(on_ready: impl Fn(Ready) + Send + Sync + 'static) -> Self {
        Self::with(std::env::consts::OS, crate::VERSION, on_ready)
    }

    pub fn with(os: &str, current: &str, on_ready: impl Fn(Ready) + Send + Sync + 'static) -> Self {
        Updater { os: os.to_string(), current: current.to_string(), st: Mutex::new(St::default()), on_ready: Box::new(on_ready) }
    }

    /// Angebot aus dem Handshake pruefen. true = es gibt etwas zu laden
    pub fn offer(&self, o: &UpdateOffer) -> bool {
        let mut st = self.st.lock().unwrap();
        let m = match verify(&o.manifest, &o.sig) {
            Ok(m) => m,
            Err(e) => {
                st.error = e;
                return false;
            }
        };
        let Some(ver) = m.version_for(&self.os).map(String::from) else { return false };
        if !newer(&ver, &self.current) {
            return false;
        }
        let Some(f) = m.files.get(&self.os).cloned() else { return false };
        if f.size == 0 || f.size > MAX_SIZE {
            st.error = "Update-Datei hat eine unzulaessige Groesse".into();
            return false;
        }
        let t = Some((ver, f));
        if st.target != t {
            *st = St { target: t, ..Default::default() };
        }
        !st.done
    }

    /// naechste Anforderung an den Server: ab welcher Position (None = nichts zu laden)
    pub fn request(&self) -> Option<u32> {
        let st = self.st.lock().unwrap();
        match &st.target {
            Some(_) if !st.done => Some(st.buf.len() as u32),
            _ => None,
        }
    }

    /// Datensatz REC_UPD_DATA verarbeiten
    pub fn data(&self, rec: &[u8]) {
        if rec.len() < 4 {
            return;
        }
        let off = u32::from_be_bytes(rec[..4].try_into().unwrap()) as usize;
        let ready = {
            let mut st = self.st.lock().unwrap();
            let Some((ver, f)) = st.target.clone() else { return };
            if st.done || off != st.buf.len() || (st.buf.len() + rec.len() - 4) as u64 > f.size {
                return;
            }
            st.buf.extend_from_slice(&rec[4..]);
            if (st.buf.len() as u64) < f.size {
                return;
            }
            if sha256_hex(&st.buf) != f.sha256.to_ascii_lowercase() {
                st.buf.clear();
                st.error = "Pruefsumme des Updates falsch – lade neu".into();
                return;
            }
            st.done = true;
            st.error.clear();
            Ready { version: ver, name: f.name, data: std::mem::take(&mut st.buf) }
        };
        (self.on_ready)(ready);
    }

    pub fn status(&self) -> UpdateStatus {
        let st = self.st.lock().unwrap();
        match &st.target {
            Some((v, f)) => UpdateStatus { version: v.clone(), got: if st.done { f.size } else { st.buf.len() as u64 }, size: f.size, done: st.done, error: st.error.clone() },
            None => UpdateStatus { error: st.error.clone(), ..Default::default() },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn manifest(ver: &str, data: &[u8]) -> String {
        let mut files = BTreeMap::new();
        files.insert("linux".to_string(), FileEntry { name: "x".into(), size: data.len() as u64, sha256: sha256_hex(data), version: String::new() });
        serde_json::to_string(&Manifest { version: ver.into(), files }).unwrap()
    }

    #[test]
    fn versionen() {
        assert!(newer("1.0.10", "1.0.9"));
        assert!(newer("2", "1.9.9"));
        assert!(!newer("1.0.1", "1.0.1"));
        assert!(!newer("1.0.0", "1.0.1"));
    }

    #[test]
    fn signatur_und_download() {
        let (pk8, pubhex) = keygen().unwrap();
        let data: Vec<u8> = (0..70_000u32).map(|i| (i * 7) as u8).collect();
        let m = manifest("9.9.9", &data);
        let (sig, ph) = sign(&pk8, &m).unwrap();
        assert_eq!(ph, pubhex);
        assert!(verify_with(&pubhex, &m, &sig).is_ok());
        // veraenderte Liste wird abgelehnt
        assert!(verify_with(&pubhex, &m.replace("9.9.9", "9.9.8"), &sig).is_err());
        // fremder Schluessel wird abgelehnt
        let (_, other) = keygen().unwrap();
        assert!(verify_with(&other, &m, &sig).is_err());
    }

    #[test]
    fn stueckweise_mit_pruefsumme() {
        let data: Vec<u8> = (0..70_000u32).map(|i| (i * 13) as u8).collect();
        let got = Arc::new(Mutex::new(None));
        let g = got.clone();
        let u = Updater::with("linux", "1.0.0", move |r| *g.lock().unwrap() = Some(r.data));
        // ohne gueltige Signatur passiert nichts
        assert!(!u.offer(&UpdateOffer { manifest: manifest("9.9.9", &data), sig: "AAAA".into() }));
        assert_eq!(u.request(), None);
        // Ziel direkt setzen (Signatur ist oben getestet)
        u.st.lock().unwrap().target = Some(("9.9.9".into(), FileEntry { name: "x".into(), size: data.len() as u64, sha256: sha256_hex(&data), version: String::new() }));
        let mut off = 0usize;
        for c in data.chunks(CHUNK) {
            assert_eq!(u.request(), Some(off as u32));
            let mut rec = (off as u32).to_be_bytes().to_vec();
            rec.extend_from_slice(c);
            u.data(&rec);
            u.data(&rec); // doppelt: wird ignoriert
            off += c.len();
        }
        assert_eq!(got.lock().unwrap().as_deref(), Some(&data[..]));
        assert_eq!(u.request(), None);
        assert!(u.status().done);
    }
}
