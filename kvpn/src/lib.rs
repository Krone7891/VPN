//! KroneVPN – gemeinsamer Kern fuer Server und alle Clients.
//!
//! Aussen: TLS 1.3 + WebSocket auf Port 443 (sieht aus wie normales HTTPS, kommt durch Sophos & Co.).
//! Innen:  Noise IK (X25519, ChaCha20-Poly1305, BLAKE2s) – Sicherheit haengt NICHT am TLS-Zertifikat.
//! Daten:  AES-256-GCM oder ChaCha20-Poly1305 (dynamisch nach Hardware bzw. Wahl in der App) + Tarn-Schicht.

pub mod client;
pub mod code;
pub mod crypto;
pub mod fehler;
pub mod logo;
pub mod pipe;
pub mod proto;
pub mod tarn;
pub mod transport;
pub mod update;
pub mod util;

#[cfg(unix)]
pub mod fdtun;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
