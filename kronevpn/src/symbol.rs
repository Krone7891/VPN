//! Bild fuer das Symbol im Infobereich (Windows, neben der Uhr): das Logo klein, mit farbigem Punkt fuer den Zustand.
//! Plattformunabhaengig, damit es auch unter Linux getestet werden kann.

/// Zustand fuer das Symbol
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lage {
    /// verbunden (gruen)
    An,
    /// verbindet / wartet auf Netz (gelb)
    Verbinde,
    /// pausiert im vertrauten Netz (blau)
    Pause,
    /// aus (grau)
    Aus,
}

impl Lage {
    pub fn text(self) -> &'static str {
        match self {
            Lage::An => "Verbunden",
            Lage::Verbinde => "Verbinde …",
            Lage::Pause => "Pausiert (vertrautes Netz)",
            Lage::Aus => "Aus",
        }
    }

    fn farbe(self) -> [u8; 3] {
        match self {
            Lage::An => [0x22, 0xc5, 0x5e],
            Lage::Verbinde => [0xf5, 0xa5, 0x24],
            Lage::Pause => [0x4f, 0x7c, 0xf7],
            Lage::Aus => [0x8a, 0x91, 0x9e],
        }
    }

    /// aus dem Zustand des Dienstes (status.json): state = "connected", "connecting", "waiting", "paused", ...
    pub fn aus_status(state: Option<&str>) -> Lage {
        match state {
            Some("connected") => Lage::An,
            Some("paused") => Lage::Pause,
            Some("connecting") | Some("waiting") => Lage::Verbinde,
            _ => Lage::Aus,
        }
    }
}

pub const GROESSE: usize = 32;

/// RGBA-Bild GROESSE x GROESSE: Logo (128x128 RGBA, verkleinert), unten rechts ein Punkt in der Farbe des Zustands.
/// Aus = Logo blasser, damit man es auf einen Blick sieht.
pub fn bild(logo128: &[u8], lage: Lage) -> Vec<u8> {
    let n = GROESSE;
    let f = 128 / n;
    let mut out = vec![0u8; n * n * 4];
    for y in 0..n {
        for x in 0..n {
            // Mittelwert eines f x f-Feldes (mit Alpha gewichtet)
            let (mut r, mut g, mut b, mut a) = (0u32, 0u32, 0u32, 0u32);
            for dy in 0..f {
                for dx in 0..f {
                    let i = ((y * f + dy) * 128 + (x * f + dx)) * 4;
                    if i + 3 >= logo128.len() {
                        continue;
                    }
                    let al = logo128[i + 3] as u32;
                    r += logo128[i] as u32 * al;
                    g += logo128[i + 1] as u32 * al;
                    b += logo128[i + 2] as u32 * al;
                    a += al;
                }
            }
            let o = (y * n + x) * 4;
            if a > 0 {
                out[o] = (r / a) as u8;
                out[o + 1] = (g / a) as u8;
                out[o + 2] = (b / a) as u8;
                let mut al = a / (f * f) as u32;
                if lage == Lage::Aus {
                    al = al * 55 / 100;
                }
                out[o + 3] = al as u8;
            }
        }
    }
    // Punkt unten rechts: weisser Rand, darin die Farbe
    let (cx, cy, r_in, r_out) = (n as f32 - 7.5, n as f32 - 7.5, 5.6f32, 7.4f32);
    let c = lage.farbe();
    for y in 0..n {
        for x in 0..n {
            let d = ((x as f32 + 0.5 - cx).powi(2) + (y as f32 + 0.5 - cy).powi(2)).sqrt();
            let o = (y * n + x) * 4;
            if d <= r_in {
                let k = (r_in - d).clamp(0.0, 1.0);
                for j in 0..3 {
                    out[o + j] = (c[j] as f32 * k + 255.0 * (1.0 - k)) as u8;
                }
                out[o + 3] = 255;
            } else if d <= r_out {
                let k = (r_out - d).clamp(0.0, 1.0);
                out[o] = 255;
                out[o + 1] = 255;
                out[o + 2] = 255;
                out[o + 3] = (255.0 * k).max(out[o + 3] as f32) as u8;
            }
        }
    }
    out
}

/// Tooltip des Symbols (Windows: hoechstens 127 Zeichen)
pub fn tipp(titel: &str, lage: Lage, rate_rx: u64, rate_tx: u64, rtt_ms: f64) -> String {
    let mut t = format!("{titel}: {}", lage.text());
    if lage == Lage::An {
        t += &format!("\n↓ {}  ↑ {}", kvpn::util::human_rate(rate_rx as f64), kvpn::util::human_rate(rate_tx as f64));
        if rtt_ms > 0.0 {
            t += &format!("  · Ping {rtt_ms:.0} ms");
        }
    }
    t.chars().take(127).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bild_und_tipp() {
        let logo = vec![200u8; 128 * 128 * 4];
        let an = bild(&logo, Lage::An);
        let aus = bild(&logo, Lage::Aus);
        assert_eq!(an.len(), GROESSE * GROESSE * 4);
        // Punkt unten rechts gruen bzw. grau, Logo oben links bei "aus" blasser
        let p = ((GROESSE - 8) * GROESSE + (GROESSE - 8)) * 4;
        assert_eq!(&an[p..p + 4], &[0x22, 0xc5, 0x5e, 255]);
        assert_eq!(&aus[p..p + 3], &[0x8a, 0x91, 0x9e]);
        assert!(aus[3] < an[3]);
        assert_eq!(Lage::aus_status(Some("waiting")), Lage::Verbinde);
        assert_eq!(Lage::aus_status(None), Lage::Aus);
        let t = tipp("KroneVPN", Lage::An, 2_000_000, 100_000, 23.4);
        assert!(t.starts_with("KroneVPN: Verbunden\n↓ "), "{t}");
        assert!(t.ends_with("Ping 23 ms"), "{t}");
        assert!(tipp(&"x".repeat(300), Lage::Aus, 0, 0, 0.0).chars().count() <= 127);
    }
}
