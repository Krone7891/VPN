//! Eigenes Logo des Servers in den Apps (ab Apps 1.2.0).
//!
//! Wird auf dem Server ein Bild hochgeladen, macht er daraus ein quadratisches PNG (256 x 256) und nennt dessen
//! Kennung im Welcome (`logo`). Hat die App ein anderes (oder keins), holt sie es durch den Tunnel
//! (REC_LOGO_GET -> REC_LOGO in Stuecken) und legt es in ihren Logo-Ordner: `logo.png` + `logo.id`.
//! Die Apps zeigen es dann ueberall an, wo sonst die Krone steht (Kopf, Fenster/Taskleiste, Verknuepfung,
//! Benachrichtigung). Loescht der Server das Bild, kommt `logo: ""` – die App nimmt wieder die Krone.

use std::path::Path;

/// hoechste Groesse des Logos (PNG 256 x 256)
pub const MAX_LOGO: usize = 768 * 1024;

/// Kennung eines Logos: Anfang der SHA-256 der PNG-Datei
pub fn id_of(png: &[u8]) -> String {
    crate::update::sha256_hex(png)[..16].to_string()
}

/// Kennung des gespeicherten Logos ("" = keins)
pub fn id_in(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("logo.id")).map(|s| s.trim().to_string()).unwrap_or_default()
}

/// PNG?
pub fn is_png(b: &[u8]) -> bool {
    b.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a])
}

/// neues Logo speichern (erst die Datei, dann die Kennung – wer liest, sieht nie ein halbes Bild)
pub fn save(dir: &Path, png: &[u8]) -> Result<String, String> {
    if !is_png(png) || png.len() > MAX_LOGO {
        return Err("Logo ist kein PNG oder zu gross".into());
    }
    let id = id_of(png);
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp = dir.join("logo.png.neu");
    std::fs::write(&tmp, png).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, dir.join("logo.png")).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("logo.id"), &id).map_err(|e| e.to_string())?;
    Ok(id)
}

/// Logo entfernen (Server hat keins mehr) – die App zeigt wieder die Krone
pub fn remove(dir: &Path) {
    for f in ["logo.id", "logo.png", "logo.ico"] {
        let _ = std::fs::remove_file(dir.join(f));
    }
}

/// Windows-Symbol (.ico) mit dem PNG darin (geht ab Windows Vista; PNG muss 256 x 256 sein)
pub fn ico_from_png(png: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(png.len() + 22);
    o.extend_from_slice(&[0, 0, 1, 0, 1, 0]); // reserviert, Typ 1 (Symbol), 1 Bild
    o.extend_from_slice(&[0, 0, 0, 0]); // Breite/Hoehe 0 = 256, keine Palette, reserviert
    o.extend_from_slice(&1u16.to_le_bytes()); // Ebenen
    o.extend_from_slice(&32u16.to_le_bytes()); // Bit je Pixel
    o.extend_from_slice(&(png.len() as u32).to_le_bytes());
    o.extend_from_slice(&22u32.to_le_bytes()); // Beginn der Bilddaten
    o.extend_from_slice(png);
    o
}

/// Empfang eines Logos in Stuecken (REC_LOGO: [Gesamtgroesse u32][Position u32][Daten])
#[derive(Default)]
pub struct Empfang {
    buf: Vec<u8>,
    total: usize,
}

impl Empfang {
    /// Stueck verarbeiten; fertig und Kennung passt -> Some(PNG)
    pub fn stueck(&mut self, want_id: &str, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 8 {
            return None;
        }
        let total = u32::from_be_bytes(data[..4].try_into().ok()?) as usize;
        let off = u32::from_be_bytes(data[4..8].try_into().ok()?) as usize;
        let d = &data[8..];
        if total == 0 || total > MAX_LOGO || off != self.buf.len() || off + d.len() > total {
            // unerwartet (z. B. neu angefangen): von vorn
            if off == 0 && total > 0 && total <= MAX_LOGO && d.len() <= total {
                self.buf.clear();
            } else {
                return None;
            }
        }
        self.total = total;
        self.buf.extend_from_slice(d);
        if self.buf.len() < self.total {
            return None;
        }
        let png = std::mem::take(&mut self.buf);
        (id_of(&png) == want_id && is_png(&png)).then_some(png)
    }
}

/// Logo in Stuecke fuer REC_LOGO teilen
pub fn stuecke(png: &[u8]) -> Vec<Vec<u8>> {
    let total = (png.len() as u32).to_be_bytes();
    png.chunks(crate::update::CHUNK)
        .enumerate()
        .map(|(i, c)| {
            let mut r = Vec::with_capacity(c.len() + 8);
            r.extend_from_slice(&total);
            r.extend_from_slice(&((i * crate::update::CHUNK) as u32).to_be_bytes());
            r.extend_from_slice(c);
            r
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stueckweise_und_speichern() {
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        png.extend((0..100_000u32).map(|i| (i * 7 % 251) as u8));
        let id = id_of(&png);
        let mut e = Empfang::default();
        let teile = stuecke(&png);
        assert!(teile.len() > 1);
        let mut fertig = None;
        for t in &teile {
            fertig = e.stueck(&id, t);
        }
        assert_eq!(fertig.as_deref(), Some(&png[..]));
        // falsche Kennung -> verworfen
        let mut e = Empfang::default();
        let mut r = None;
        for t in &teile {
            r = e.stueck("falsch", t);
        }
        assert!(r.is_none());
        let d = std::env::temp_dir().join(format!("kvpn-logo-{}", std::process::id()));
        assert_eq!(save(&d, &png).unwrap(), id);
        assert_eq!(id_in(&d), id);
        let ico = ico_from_png(&png);
        assert_eq!(&ico[..6], &[0, 0, 1, 0, 1, 0]);
        assert_eq!(&ico[22..30], &png[..8]);
        remove(&d);
        assert_eq!(id_in(&d), "");
        let _ = std::fs::remove_dir_all(&d);
    }
}
