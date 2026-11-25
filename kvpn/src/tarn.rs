//! Tarn-Schicht: formt den sichtbaren Verkehr bei jeder Verbindung anders.
//!
//! Was eine Firewall (auch Sophos mit HTTPS-Inspektion) von KroneVPN sieht, ist eine normale TLS-1.3-Verbindung
//! auf Port 443 mit einem WebSocket – wie bei Chat-, Office- oder Videoseiten. Erkennen liesse sich ein VPN darin
//! hoechstens an Mustern: immer gleich grosse Datenpakete, Lebenszeichen im festen 10-Sekunden-Takt, ein Handshake
//! mit immer derselben Laenge.
//!
//! Genau diese Muster wuerfelt der Server bei jeder Verbindung neu aus (Tarn-Profil, verschluesselt im Welcome):
//!   * Buendel werden auf ein zufaelliges Vielfaches (Block) aufgefuellt – Paketgroessen verraten nichts mehr,
//!   * manche Buendel bekommen zufaellig zusaetzliche Fuellbytes,
//!   * Lebenszeichen kommen in zufaelligen Abstaenden (innerhalb eines Bereichs, der unter den Leerlauf-Zeitlimits
//!     von Firewalls und Proxys bleibt – die Verbindung wird also nicht als "tot" getrennt),
//!   * Hello/Welcome haben zufaellige Laengen.
//!
//! Wichtig: Die Tarn-Schicht ist KEINE Verschluesselung und ersetzt keine. Die Sicherheit kommt allein von
//! TLS + Noise + AES-256-GCM/ChaCha20-Poly1305. Die Fuellbytes liegen innerhalb der Verschluesselung.

use crate::proto::{push_record, Tarn, MAX_BUNDLE, REC_PAD};
use rand::Rng;
use std::time::Duration;

/// laengste Pause zwischen Lebenszeichen: deutlich unter den ueblichen Leerlauf-Grenzen (Sophos/Proxys ab 60 s)
/// und unter der Wartezeit der Gegenseite (Client 35 s, Server 60 s)
pub const KA_MAX_MS: u32 = 17_000;
pub const KA_MIN_MS: u32 = 3_000;

impl Tarn {
    /// neues zufaelliges Profil (Server, bei jeder Verbindung). `leicht` = Leistungsmodus: kaum Fuellbytes.
    pub fn random(leicht: bool) -> Tarn {
        let mut r = rand::rng();
        let bloecke: &[u16] = if leicht { &[0, 16, 32, 64] } else { &[64, 96, 128, 192, 256, 320, 384, 512] };
        let block = bloecke[r.random_range(0..bloecke.len())];
        let ka_min = r.random_range(4_000..9_000);
        let ka_max = (ka_min + r.random_range(2_000..8_000)).min(KA_MAX_MS);
        Tarn {
            block,
            extra: if leicht { r.random_range(0..64) } else { r.random_range(32..640) },
            chance: if leicht { r.random_range(0..16) } else { r.random_range(8..96) },
            ka_min,
            ka_max,
        }
    }

    /// aelterer Server ohne Tarn-Profil: wie bis 1.0.13 (Lebenszeichen alle 10 s)
    pub fn alt() -> Tarn {
        Tarn { block: 0, extra: 0, chance: 0, ka_min: 10_000, ka_max: 10_000 }
    }

    /// Werte von der Gegenseite in sichere Grenzen bringen
    pub fn sicher(self) -> Tarn {
        let ka_min = self.ka_min.clamp(KA_MIN_MS, KA_MAX_MS);
        Tarn { block: self.block.min(1024), extra: self.extra.min(1024), chance: self.chance, ka_min, ka_max: self.ka_max.clamp(ka_min, KA_MAX_MS) }
    }

    /// Wartezeit bis zum naechsten Lebenszeichen
    pub fn lebenszeichen(&self) -> Duration {
        let ms = if self.ka_max > self.ka_min { rand::rng().random_range(self.ka_min..=self.ka_max) } else { self.ka_min };
        Duration::from_millis(ms as u64)
    }

    /// Klartext-Buendel vor dem Verschluesseln auffuellen (REC_PAD, wird beim Empfang ignoriert)
    pub fn fuellen(&self, buf: &mut Vec<u8>) {
        let len = buf.len();
        let mut ziel = if self.block > 0 { (len + 3).div_ceil(self.block as usize) * self.block as usize } else { len };
        if self.extra > 0 && self.chance > 0 {
            let mut r = rand::rng();
            if r.random::<u8>() < self.chance {
                ziel += r.random_range(0..=self.extra as usize);
            }
        }
        if ziel < len + 3 || ziel > MAX_BUNDLE {
            return;
        }
        let n = ziel - len - 3;
        buf.reserve(ziel - len);
        push_record(buf, REC_PAD, &[]);
        let l = buf.len();
        buf[l - 2..].copy_from_slice(&(n as u16).to_be_bytes());
        buf.resize(ziel, 0);
    }
}

/// Fuellzeichen fuer Hello/Welcome: zufaellige Laenge 0..=max
pub fn fuellzeichen(max: usize) -> String {
    let n = rand::rng().random_range(0..=max);
    " ".repeat(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{for_each_record, REC_PACKET};

    #[test]
    fn fuellen_auf_block() {
        for _ in 0..200 {
            let t = Tarn::random(false);
            for groesse in [0usize, 1, 60, 1400, 4000, 32 * 1024] {
                let mut b = Vec::new();
                push_record(&mut b, REC_PACKET, &vec![7u8; groesse]);
                let vorher = b.len();
                t.fuellen(&mut b);
                assert!(b.len() >= vorher);
                assert!(b.len() <= vorher + 3 + t.block as usize + t.extra as usize);
                if t.block > 0 && (t.chance == 0 || t.extra == 0) {
                    assert_eq!(b.len() % t.block as usize, 0);
                }
                // Empfaenger sieht genau ein Paket, der Rest ist Fuellung
                let mut pakete = vec![];
                for_each_record(&b, |k, d| {
                    if k == REC_PACKET {
                        pakete.push(d.len())
                    }
                })
                .unwrap();
                assert_eq!(pakete, vec![groesse]);
            }
            let ka = t.lebenszeichen();
            assert!(ka >= Duration::from_millis(KA_MIN_MS as u64) && ka <= Duration::from_millis(KA_MAX_MS as u64));
        }
    }

    #[test]
    fn profile_verschieden_und_sicher() {
        let a: Vec<Tarn> = (0..20).map(|_| Tarn::random(false)).collect();
        assert!(a.windows(2).any(|w| w[0] != w[1]));
        let boese = Tarn { block: 60_000, extra: 60_000, chance: 255, ka_min: 1, ka_max: 999_999 }.sicher();
        assert!(boese.block <= 1024 && boese.ka_min >= KA_MIN_MS && boese.ka_max <= KA_MAX_MS);
        // ohne Block und ohne Extra bleibt alles wie es ist
        let mut b = vec![1, 0, 1, 9];
        Tarn::alt().fuellen(&mut b);
        assert_eq!(b, vec![1, 0, 1, 9]);
    }
}
