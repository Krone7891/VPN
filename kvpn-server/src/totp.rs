//! Zweiter Schritt fuer die Admin-Seite (ab Server 1.3.0): Einmal-Code aus einer Authenticator-App
//! (Google Authenticator, Microsoft Authenticator, Aegis, 2FAS, ...).
//!
//! Standardverfahren TOTP nach RFC 6238 (HMAC-SHA1, 6 Ziffern, 30 Sekunden) – nichts Eigenes. Das Geheimnis liegt als
//! Base32 in server.toml (nur root lesbar). Ein Code gilt einmal (kein zweites Anmelden mit demselben Code) und
//! 30 Sekunden davor/danach (Uhren gehen nicht genau gleich).

use std::sync::Mutex;

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub const STEP: u64 = 30;

pub fn b32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn b32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=' && *c != '-') {
        let v = B32.iter().position(|&x| x as char == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buf >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/// neues Geheimnis (160 Bit, wie von RFC 4226 empfohlen)
pub fn new_secret() -> String {
    b32_encode(&rand::random::<[u8; 20]>())
}

/// 6-stelliger Code fuer einen Zeitschritt
pub fn code_at(key: &[u8], step: u64) -> u32 {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let h = ring::hmac::sign(&k, &step.to_be_bytes());
    let h = h.as_ref();
    let o = (h[19] & 0x0f) as usize;
    (u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]])) % 1_000_000
}

/// Code pruefen (aktueller Schritt +-1). Ergebnis: der passende Zeitschritt
pub fn check(secret: &str, code: &str, now: u64) -> Option<u64> {
    let key = b32_decode(secret)?;
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let t = now / STEP;
    [t, t.saturating_sub(1), t + 1].into_iter().find(|&s| code_at(&key, s) == want)
}

/// zuletzt benutzter Zeitschritt – derselbe Code geht nur einmal
static LAST: Mutex<u64> = Mutex::new(0);

/// Code pruefen und verbrauchen
pub fn verify_once(secret: &str, code: &str) -> bool {
    let Some(step) = check(secret, code, kvpn::util::now_secs()) else { return false };
    let mut last = LAST.lock().unwrap();
    if step <= *last {
        return false;
    }
    *last = step;
    true
}

/// Adresse fuer die Authenticator-App (als QR-Code)
pub fn uri(secret: &str, vpn_name: &str) -> String {
    let enc = |s: &str| -> String {
        s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
    };
    format!("otpauth://totp/{}:admin?secret={secret}&issuer={}&algorithm=SHA1&digits=6&period=30", enc(vpn_name), enc(vpn_name))
}

/// Einrichtung auf der Admin-Seite: neues Geheimnis, das erst mit dem ersten richtigen Code gilt (Zeit der Erzeugung)
pub static PENDING: Mutex<Option<(String, u64)>> = Mutex::new(None);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238() {
        // Testvektoren aus RFC 6238 (SHA1, Schluessel "12345678901234567890"), letzte 6 Ziffern
        let key = b"12345678901234567890";
        assert_eq!(code_at(key, 59 / 30), 287082);
        assert_eq!(code_at(key, 1111111109 / 30), 81804);
        assert_eq!(code_at(key, 1234567890 / 30), 5924);
        assert_eq!(code_at(key, 2000000000 / 30), 279037);
        let s = b32_encode(key);
        assert_eq!(s, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(b32_decode(&s.to_lowercase()).unwrap(), key);
        assert_eq!(check(&s, "081804", 1111111109), Some(1111111109 / 30));
        assert_eq!(check(&s, "081804", 1111111109 + 30), Some(1111111109 / 30), "30 s Spielraum");
        assert_eq!(check(&s, "081804", 1111111109 + 90), None);
        assert_eq!(check(&s, "81804", 1111111109), None);
        assert!(uri(&s, "Krone VPN").starts_with("otpauth://totp/Krone%20VPN:admin?secret=GEZD"));
    }

    #[test]
    fn nur_einmal() {
        let s = new_secret();
        let k = b32_decode(&s).unwrap();
        let c = format!("{:06}", code_at(&k, kvpn::util::now_secs() / STEP));
        assert!(verify_once(&s, &c));
        assert!(!verify_once(&s, &c), "derselbe Code darf nicht zweimal gehen");
    }
}
