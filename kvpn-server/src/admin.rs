//! Admin-Seite im VPN: http://<Server im Tunnel>:<Port> (Standard http://10.77.0.1:8180).
//!
//! Erreichbar nur fuer verbundene Geraete (der Server lauscht dafuer nur auf seiner Tunnel-Adresse). Beim ersten
//! Aufruf wird ein Passwort festgelegt; gespeichert wird nur ein PBKDF2-Hash in server.toml. Danach kann man sich von
//! jedem Geraet im VPN damit anmelden – der Browser bleibt ein Jahr angemeldet. Neu setzen/vergessen:
//! `kvpn-server admin-passwort <neu>` bzw. `kvpn-server admin-passwort --loeschen`.

use crate::config::Config;
use sha2::Digest;
use std::num::NonZeroU32;

const ITER: u32 = 100_000;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (s.len() % 2 == 0).then_some(())?;
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// "pbkdf2-sha256$<runden>$<salz hex>$<hash hex>"
pub fn hash(pw: &str) -> String {
    let salt: [u8; 16] = rand::random();
    let mut out = [0u8; 32];
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(ITER).unwrap(), &salt, pw.as_bytes(), &mut out);
    format!("pbkdf2-sha256${ITER}${}${}", hex(&salt), hex(&out))
}

pub fn verify(stored: &str, pw: &str) -> bool {
    let p: Vec<&str> = stored.split('$').collect();
    let ["pbkdf2-sha256", it, salt, h] = p.as_slice() else { return false };
    let (Some(salt), Some(h)) = (unhex(salt), unhex(h)) else { return false };
    let Some(it) = it.parse::<u32>().ok().and_then(NonZeroU32::new) else { return false };
    ring::pbkdf2::verify(ring::pbkdf2::PBKDF2_HMAC_SHA256, it, &salt, pw.as_bytes(), &h).is_ok()
}

/// Inhalt des Anmelde-Cookies (aendert sich mit dem Passwort -> alte Anmeldungen werden ungueltig)
pub fn token(cfg: &Config) -> String {
    let mut h = sha2::Sha256::new();
    h.update(b"krone-vpn-admin\0");
    h.update(cfg.admin_password.as_bytes());
    h.update(b"\0");
    // zweiten Schritt ein-/ausschalten meldet ebenfalls alle Browser ab
    h.update(cfg.admin_totp.as_bytes());
    h.update(b"\0");
    h.update(cfg.private_key.as_bytes());
    hex(&h.finalize())
}

pub fn check_new(pw: &str) -> Result<(), String> {
    if pw.chars().count() < 8 {
        return Err("Passwort bitte mit mindestens 8 Zeichen".into());
    }
    if pw.len() > 200 {
        return Err("Passwort zu lang".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn passwort() {
        let h = super::hash("geheim123");
        assert!(super::verify(&h, "geheim123"));
        assert!(!super::verify(&h, "geheim124"));
        assert!(!super::verify("", "x"));
        assert_ne!(super::hash("geheim123"), h, "mit Salz");
        assert!(super::check_new("kurz").is_err());
    }
}
