//! Schluessel, Noise-IK-Handshake und Transport-Verschluesselung.
//!
//! Nach dem Handshake werden die beiden Noise-Schluessel (je Richtung einer) herausgeloest. Senden und Empfangen
//! haben damit getrennte Zustaende und laufen parallel auf verschiedenen Kernen. Die Nonce ist ein Zaehler je
//! Richtung – der Transport (TCP/WebSocket) liefert in Reihenfolge, jede Luecke, Wiederholung oder Aenderung fuehrt
//! zum Abbruch der Verbindung.
//!
//! Verschluesselung der Daten (ab 1.1.0 dynamisch): die App waehlt "Auto" (AES-256-GCM, wenn der Prozessor
//! AES-Befehle hat, sonst ChaCha20-Poly1305) oder fest eins von beiden. Nur gepruefte Standard-Verfahren (ring),
//! beide mit 256-Bit-Schluesseln aus dem Noise-Handshake.

use crate::proto::{Hello, Welcome, NOISE_PARAMS, PROLOGUE};
use std::fmt;

#[derive(Debug)]
pub struct CryptoError(pub String);
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for CryptoError {}
impl From<snow::Error> for CryptoError {
    fn from(e: snow::Error) -> Self {
        CryptoError(format!("Noise: {e}"))
    }
}
fn err(s: impl Into<String>) -> CryptoError {
    CryptoError(s.into())
}

pub type Key32 = [u8; 32];

fn params() -> snow::params::NoiseParams {
    NOISE_PARAMS.parse().expect("gueltige Noise-Parameter")
}

/// neues Schluesselpaar (privat, oeffentlich)
pub fn generate_keypair() -> (Key32, Key32) {
    let kp = snow::Builder::new(params()).generate_keypair().expect("Schluessel erzeugen");
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&kp.private);
    b.copy_from_slice(&kp.public);
    (a, b)
}

/// oeffentlichen Schluessel aus dem privaten berechnen (X25519)
pub fn public_from_private(private: &Key32) -> Key32 {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private)).to_bytes()
}

struct Aead(ring::aead::LessSafeKey);

impl Aead {
    fn new(key: &Key32, cipher: &str) -> Self {
        // beides ring (handoptimiert: AES-NI/ARMv8-AES bzw. SIMD/NEON fuer ChaCha20), Ergebnis wie RFC 8439 / NIST
        let alg = if cipher == crate::proto::CIPHER_AES256 { &ring::aead::AES_256_GCM } else { &ring::aead::CHACHA20_POLY1305 };
        Aead(ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(alg, key).expect("Schluessel")))
    }
    fn seal(&self, n: u64, buf: &mut Vec<u8>) -> Result<(), ()> {
        self.0.seal_in_place_append_tag(ring_nonce(n), ring::aead::Aad::empty(), buf).map_err(|_| ())
    }
    fn open(&self, n: u64, buf: &mut Vec<u8>) -> Result<(), ()> {
        let len = self.0.open_in_place(ring_nonce(n), ring::aead::Aad::empty(), buf).map_err(|_| ())?.len();
        buf.truncate(len);
        Ok(())
    }
}

/// Nonce = Zaehler der Richtung (Bytes 4..12, little endian), wie bei Noise/WireGuard
fn ring_nonce(n: u64) -> ring::aead::Nonce {
    let mut b = [0u8; 12];
    b[4..].copy_from_slice(&n.to_le_bytes());
    ring::aead::Nonce::assume_unique_for_key(b)
}

/// hat dieser Prozessor AES-Befehle (x86: AES-NI + PCLMULQDQ, ARM: ARMv8-Crypto)? Dann ist AES-256-GCM am
/// schnellsten, sonst ChaCha20-Poly1305 (ohne AES-Hardware deutlich schneller und trotzdem gleich sicher).
pub fn aes_hw() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("pclmulqdq")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes") && std::arch::is_aarch64_feature_detected!("pmull")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        false
    }
}

/// Einstellung der App ("auto", "aes", "chacha") -> Wunschliste fuer den Server
pub fn cipher_wish(choice: &str) -> Vec<String> {
    use crate::proto::{CIPHER_AES256 as A, CIPHER_CHACHA as C};
    match normalize_choice(choice) {
        "aes" => vec![A.into()],
        "chacha" => vec![C.into()],
        _ if aes_hw() => vec![A.into(), C.into()],
        _ => vec![C.into(), A.into()],
    }
}

/// "AES-256", "aes256gcm", "ChaCha20" … -> "auto" | "aes" | "chacha"
pub fn normalize_choice(choice: &str) -> &'static str {
    let c = choice.trim().to_ascii_lowercase();
    if c.starts_with("aes") {
        "aes"
    } else if c.starts_with("chacha") {
        "chacha"
    } else {
        "auto"
    }
}

/// Server: Verschluesselung fuer diese Verbindung waehlen ("" = ChaCha20, sonst "aes256gcm").
/// Apps ab 1.1.0 schicken eine Wunschliste – die gilt (dort entscheidet die App bzw. ihre Hardware).
/// Aeltere Apps nur ["aes256gcm"]: dann wie bisher die Server-Einstellung `aes256`.
pub fn choose_cipher(hello: &Hello, server_aes: bool) -> String {
    use crate::proto::{CIPHER_AES256 as A, CIPHER_CHACHA as C};
    if hello.pick {
        for c in &hello.ciphers {
            if c == A {
                return A.into();
            }
            if c == C {
                return String::new();
            }
        }
        return String::new();
    }
    if server_aes && hello.ciphers.iter().any(|c| c == A) {
        A.into()
    } else {
        String::new()
    }
}

/// Anzeigename ("" bzw. "chacha20" = ChaCha20-Poly1305)
pub fn cipher_label(c: &str) -> &'static str {
    if c == crate::proto::CIPHER_AES256 {
        "AES-256-GCM"
    } else {
        "ChaCha20-Poly1305"
    }
}

/// Verschluesseln einer Richtung
pub struct Sealer {
    aead: Aead,
    n: u64,
}
/// Entschluesseln einer Richtung
pub struct Opener {
    aead: Aead,
    n: u64,
}

impl Sealer {
    pub fn new(key: &Key32) -> Self {
        Self::with(key, "")
    }
    pub fn with(key: &Key32, cipher: &str) -> Self {
        Sealer { aead: Aead::new(key, cipher), n: 0 }
    }
    /// verschluesselt `buf` an Ort und Stelle (haengt 16 Byte Tag an)
    pub fn seal(&mut self, buf: &mut Vec<u8>) -> Result<(), CryptoError> {
        if self.n == u64::MAX {
            return Err(err("Nonce erschoepft"));
        }
        self.aead.seal(self.n, buf).map_err(|_| err("Verschluesselung fehlgeschlagen"))?;
        self.n += 1;
        Ok(())
    }
}

impl Opener {
    pub fn new(key: &Key32) -> Self {
        Self::with(key, "")
    }
    pub fn with(key: &Key32, cipher: &str) -> Self {
        Opener { aead: Aead::new(key, cipher), n: 0 }
    }
    /// entschluesselt `buf` an Ort und Stelle; Fehler = manipuliert/falsche Reihenfolge
    pub fn open(&mut self, buf: &mut Vec<u8>) -> Result<(), CryptoError> {
        if buf.len() < 16 {
            return Err(err("Nachricht zu kurz"));
        }
        self.aead.open(self.n, buf).map_err(|_| err("Entschluesselung fehlgeschlagen (manipuliert oder falscher Schluessel)"))?;
        self.n += 1;
        Ok(())
    }
}

fn split(hs: &mut snow::HandshakeState, initiator: bool, cipher: &str) -> (Sealer, Opener) {
    // Noise Split(): erster Schluessel = Initiator -> Responder
    let (i2r, r2i) = hs.dangerously_get_raw_split();
    if initiator {
        (Sealer::with(&i2r, cipher), Opener::with(&r2i, cipher))
    } else {
        (Sealer::with(&r2i, cipher), Opener::with(&i2r, cipher))
    }
}

/// Client: Handshake beginnen. Liefert Zustand und Nachricht 1.
pub fn client_init(client_priv: &Key32, server_pub: &Key32, hello: &Hello) -> Result<(snow::HandshakeState, Vec<u8>), CryptoError> {
    let mut hs = snow::Builder::new(params())
        .local_private_key(client_priv)?
        .remote_public_key(server_pub)?
        .prologue(PROLOGUE)?
        .build_initiator()?;
    let payload = serde_json::to_vec(hello).map_err(|e| err(e.to_string()))?;
    let mut out = vec![0u8; payload.len() + 256];
    let n = hs.write_message(&payload, &mut out)?;
    out.truncate(n);
    Ok((hs, out))
}

/// Client: Nachricht 2 verarbeiten.
pub fn client_finish(mut hs: snow::HandshakeState, msg2: &[u8]) -> Result<(Welcome, Sealer, Opener), CryptoError> {
    let mut payload = vec![0u8; msg2.len()];
    let n = hs.read_message(msg2, &mut payload)?;
    let w: Welcome = serde_json::from_slice(&payload[..n]).map_err(|e| err(format!("Antwort des Servers ungueltig: {e}")))?;
    if !hs.is_handshake_finished() {
        return Err(err("Handshake unvollstaendig"));
    }
    if !w.cipher.is_empty() && w.cipher != crate::proto::CIPHER_AES256 && w.cipher != crate::proto::CIPHER_CHACHA {
        return Err(err(format!("Server will unbekannte Verschluesselung '{}' – App aktualisieren", w.cipher)));
    }
    let (s, o) = split(&mut hs, true, &w.cipher);
    Ok((w, s, o))
}

/// Server: Nachricht 1 lesen. Liefert Zustand, oeffentlichen Schluessel des Clients und dessen Hello.
pub fn server_read(server_priv: &Key32, msg1: &[u8]) -> Result<(snow::HandshakeState, Key32, Hello), CryptoError> {
    let mut hs = snow::Builder::new(params()).local_private_key(server_priv)?.prologue(PROLOGUE)?.build_responder()?;
    let mut payload = vec![0u8; msg1.len()];
    let n = hs.read_message(msg1, &mut payload)?;
    let rs = hs.get_remote_static().ok_or_else(|| err("kein Client-Schluessel"))?;
    let mut k = [0u8; 32];
    k.copy_from_slice(rs);
    let hello: Hello = serde_json::from_slice(&payload[..n]).map_err(|e| err(format!("Hello ungueltig: {e}")))?;
    Ok((hs, k, hello))
}

/// Server: Nachricht 2 schreiben und Transportschluessel ableiten.
pub fn server_reply(mut hs: snow::HandshakeState, welcome: &Welcome) -> Result<(Vec<u8>, Sealer, Opener), CryptoError> {
    let payload = serde_json::to_vec(welcome).map_err(|e| err(e.to_string()))?;
    let mut out = vec![0u8; payload.len() + 256];
    let n = hs.write_message(&payload, &mut out)?;
    out.truncate(n);
    if !hs.is_handshake_finished() {
        return Err(err("Handshake unvollstaendig"));
    }
    let (s, o) = split(&mut hs, false, &welcome.cipher);
    Ok((out, s, o))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn welcome() -> Welcome {
        Welcome { name: "Test".into(), ip4: "10.77.0.2/24".into(), ip6: "fd77:6b76::2/64".into(), dns: vec!["1.1.1.1".into()], mtu: 1400, upd: None, cipher: String::new(), tarn: None, pad: String::new() }
    }

    #[test]
    fn handshake_and_transport() {
        let (spriv, spub) = generate_keypair();
        let (cpriv, cpub) = generate_keypair();
        assert_eq!(public_from_private(&spriv), spub);
        let hello = Hello { ts: 42, os: "test".into(), ..Default::default() };
        let (chs, m1) = client_init(&cpriv, &spub, &hello).unwrap();
        let (shs, got_cpub, got_hello) = server_read(&spriv, &m1).unwrap();
        assert_eq!(got_cpub, cpub);
        assert_eq!(got_hello.ts, 42);
        let (m2, mut ss, mut so) = server_reply(shs, &welcome()).unwrap();
        let (w, mut cs, mut co) = client_finish(chs, &m2).unwrap();
        assert_eq!(w, welcome());

        for i in 0..100u32 {
            let mut b = format!("Paket {i} vom Client").into_bytes();
            cs.seal(&mut b).unwrap();
            so.open(&mut b).unwrap();
            assert_eq!(b, format!("Paket {i} vom Client").into_bytes());
            let mut b = vec![i as u8; 1500];
            ss.seal(&mut b).unwrap();
            co.open(&mut b).unwrap();
            assert_eq!(b, vec![i as u8; 1500]);
        }
    }

    #[test]
    fn aes256_transport() {
        let (spriv, spub) = generate_keypair();
        let (cpriv, _) = generate_keypair();
        let hello = Hello { ts: 1, ciphers: vec![crate::proto::CIPHER_AES256.into()], ..Default::default() };
        let (chs, m1) = client_init(&cpriv, &spub, &hello).unwrap();
        let (shs, _, h) = server_read(&spriv, &m1).unwrap();
        assert_eq!(h.ciphers, vec![crate::proto::CIPHER_AES256.to_string()]);
        let mut w = welcome();
        w.cipher = crate::proto::CIPHER_AES256.into();
        let (m2, mut ss, mut so) = server_reply(shs, &w).unwrap();
        let (_, mut cs, mut co) = client_finish(chs, &m2).unwrap();
        for i in 0..50u32 {
            let mut b = vec![i as u8; 1400];
            cs.seal(&mut b).unwrap();
            assert_eq!(b.len(), 1416);
            so.open(&mut b).unwrap();
            assert_eq!(b, vec![i as u8; 1400]);
            let mut b = format!("zurueck {i}").into_bytes();
            ss.seal(&mut b).unwrap();
            co.open(&mut b).unwrap();
            assert_eq!(b, format!("zurueck {i}").into_bytes());
        }
        // manipuliert -> Fehler
        let mut b = b"x".to_vec();
        cs.seal(&mut b).unwrap();
        b[0] ^= 1;
        assert!(so.open(&mut b).is_err());
        // AES-Daten lassen sich nicht mit ChaCha oeffnen
        let key = [7u8; 32];
        let mut b = b"hallo".to_vec();
        Sealer::with(&key, crate::proto::CIPHER_AES256).seal(&mut b).unwrap();
        assert!(Opener::new(&key).open(&mut b).is_err());
    }

    #[test]
    fn tamper_replay_and_wrong_server_fail() {
        let (spriv, spub) = generate_keypair();
        let (cpriv, _) = generate_keypair();
        let (chs, m1) = client_init(&cpriv, &spub, &Hello::default()).unwrap();
        let (shs, _, _) = server_read(&spriv, &m1).unwrap();
        let (m2, mut ss, _) = server_reply(shs, &welcome()).unwrap();
        let (_, _, mut co) = client_finish(chs, &m2).unwrap();

        // manipuliert
        let mut b = b"geheim".to_vec();
        ss.seal(&mut b).unwrap();
        let mut bad = b.clone();
        bad[0] ^= 1;
        assert!(co.open(&mut bad).is_err());
        // richtige Nachricht geht (Zaehler wurde durch Fehlversuch nicht erhoeht)
        co.open(&mut b).unwrap();
        // Wiederholung derselben Nachricht schlaegt fehl
        let mut again = Vec::new();
        let mut c = b"x".to_vec();
        ss.seal(&mut c).unwrap();
        again.extend_from_slice(&c);
        co.open(&mut c).unwrap();
        assert!(co.open(&mut again).is_err());

        // falscher Server-Schluessel (z. B. Sophos-MITM mit eigenem Schluessel): Server kann Nachricht 1 nicht lesen
        let (other_priv, _) = generate_keypair();
        let (_, m1) = client_init(&cpriv, &spub, &Hello::default()).unwrap();
        assert!(server_read(&other_priv, &m1).is_err());
    }

    /// ring-ChaCha20 (ab 1.1.0) muss genau wie die bisherige Umsetzung (RustCrypto) verschluesseln,
    /// sonst koennten alte Apps nicht mehr mit neuem Server (und umgekehrt)
    #[test]
    fn chacha_wie_bisher() {
        use chacha20poly1305::aead::{AeadInPlace, KeyInit};
        let key = [0x42u8; 32];
        let alt = chacha20poly1305::ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
        let mut s = Sealer::new(&key);
        let mut o = Opener::new(&key);
        for n in 0..20u64 {
            let msg = vec![n as u8; 100 + n as usize * 37];
            let mut a = msg.clone();
            let mut nb = [0u8; 12];
            nb[4..].copy_from_slice(&n.to_le_bytes());
            alt.encrypt_in_place(chacha20poly1305::Nonce::from_slice(&nb), b"", &mut a).unwrap();
            let mut b = msg.clone();
            s.seal(&mut b).unwrap();
            assert_eq!(a, b, "Nachricht {n}");
            o.open(&mut a).unwrap();
            assert_eq!(a, msg);
        }
    }

    #[test]
    fn wahl_der_verschluesselung() {
        use crate::proto::{CIPHER_AES256 as A, CIPHER_CHACHA as C};
        let h = |c: &[&str], pick: bool| Hello { ciphers: c.iter().map(|s| s.to_string()).collect(), pick, ..Default::default() };
        // alte App (bis 1.0.13): Server-Einstellung entscheidet
        assert_eq!(choose_cipher(&h(&[A], false), false), "");
        assert_eq!(choose_cipher(&h(&[A], false), true), A);
        assert_eq!(choose_cipher(&h(&[], false), true), "");
        // neue App: ihre Wahl gilt, egal wie der Server steht
        assert_eq!(choose_cipher(&h(&[A], true), false), A);
        assert_eq!(choose_cipher(&h(&[C], true), true), "");
        assert_eq!(choose_cipher(&h(&[C, A], true), true), "");
        assert_eq!(choose_cipher(&h(&["neu-unbekannt", A], true), false), A);
        // Einstellung der App
        assert_eq!(cipher_wish("aes"), vec![A.to_string()]);
        assert_eq!(cipher_wish("ChaCha20"), vec![C.to_string()]);
        let auto = cipher_wish("auto");
        assert_eq!(auto.len(), 2);
        assert_eq!(auto[0] == A, aes_hw());
        // Antwort "chacha20" vom Server wird verstanden
        let (spriv, spub) = generate_keypair();
        let (cpriv, _) = generate_keypair();
        let (chs, m1) = client_init(&cpriv, &spub, &h(&[C], true)).unwrap();
        let (shs, _, _) = server_read(&spriv, &m1).unwrap();
        let mut w = welcome();
        w.cipher = C.into();
        let (m2, mut ss, _) = server_reply(shs, &w).unwrap();
        let (_, _, mut co) = client_finish(chs, &m2).unwrap();
        let mut b = b"ok".to_vec();
        ss.seal(&mut b).unwrap();
        co.open(&mut b).unwrap();
    }
}
