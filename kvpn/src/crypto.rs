//! Schluessel, Noise-IK-Handshake und Transport-Verschluesselung.
//!
//! Nach dem Handshake werden die beiden Noise-Schluessel (je Richtung einer) herausgeloest. Senden und Empfangen
//! haben damit getrennte Zustaende und laufen parallel auf verschiedenen Kernen. Die Nonce ist ein Zaehler je
//! Richtung – der Transport (TCP/WebSocket) liefert in Reihenfolge, jede Luecke, Wiederholung oder Aenderung fuehrt
//! zum Abbruch der Verbindung.
//!
//! Verschluesselung der Daten: ChaCha20-Poly1305 (Standard) oder – wenn der Server es so eingestellt hat und die App
//! es kann – AES-256-GCM (mit Hardware-Beschleunigung, ring). Beide mit 256-Bit-Schluesseln aus dem Noise-Handshake.

use crate::proto::{Hello, Welcome, NOISE_PARAMS, PROLOGUE};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
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

enum Aead {
    ChaCha(ChaCha20Poly1305),
    Aes(ring::aead::LessSafeKey),
}

impl Aead {
    fn new(key: &Key32, cipher: &str) -> Self {
        if cipher == crate::proto::CIPHER_AES256 {
            Aead::Aes(ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key).expect("AES-Schluessel")))
        } else {
            Aead::ChaCha(ChaCha20Poly1305::new(Key::from_slice(key)))
        }
    }
    fn seal(&self, n: u64, buf: &mut Vec<u8>) -> Result<(), ()> {
        match self {
            Aead::ChaCha(a) => a.encrypt_in_place(&nonce(n), b"", buf).map_err(|_| ()),
            Aead::Aes(k) => k.seal_in_place_append_tag(ring_nonce(n), ring::aead::Aad::empty(), buf).map_err(|_| ()),
        }
    }
    fn open(&self, n: u64, buf: &mut Vec<u8>) -> Result<(), ()> {
        match self {
            Aead::ChaCha(a) => a.decrypt_in_place(&nonce(n), b"", buf).map_err(|_| ()),
            Aead::Aes(k) => {
                let len = k.open_in_place(ring_nonce(n), ring::aead::Aad::empty(), buf).map_err(|_| ())?.len();
                buf.truncate(len);
                Ok(())
            }
        }
    }
}

fn ring_nonce(n: u64) -> ring::aead::Nonce {
    let mut b = [0u8; 12];
    b[4..].copy_from_slice(&n.to_le_bytes());
    ring::aead::Nonce::assume_unique_for_key(b)
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

fn nonce(n: u64) -> Nonce {
    let mut b = [0u8; 12];
    b[4..].copy_from_slice(&n.to_le_bytes());
    *Nonce::from_slice(&b)
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
    if !w.cipher.is_empty() && w.cipher != crate::proto::CIPHER_AES256 {
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
        Welcome { name: "Test".into(), ip4: "10.77.0.2/24".into(), ip6: "fd77:6b76::2/64".into(), dns: vec!["1.1.1.1".into()], mtu: 1400, upd: None, cipher: String::new() }
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
}
