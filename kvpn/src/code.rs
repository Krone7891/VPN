//! Verbindungscode: alles, was ein Geraet zum Verbinden braucht, in einer Zeile (auch als QR-Code).
//! Format: `kronevpn://v1/<base64url(JSON)>`

use crate::crypto::Key32;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};

pub const PREFIX: &str = "kronevpn://v1/";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientConfig {
    /// Geraetename
    #[serde(rename = "n")]
    pub name: String,
    /// Server-Adresse, z. B. wss://vpn.example.de/api/v1/stream
    #[serde(rename = "u")]
    pub url: String,
    /// oeffentlicher Server-Schluessel (Base64)
    #[serde(rename = "s")]
    pub server_pub: String,
    /// privater Schluessel dieses Geraets (Base64)
    #[serde(rename = "k")]
    pub private_key: String,
    #[serde(rename = "a4")]
    pub ip4: String,
    #[serde(rename = "a6", default)]
    pub ip6: String,
    #[serde(rename = "d", default)]
    pub dns: Vec<String>,
    #[serde(rename = "m", default = "default_mtu")]
    pub mtu: u16,
    /// Name des VPN fuer die Anzeige in den Apps (leer = "KroneVPN")
    #[serde(rename = "t", default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    /// optionaler HTTP-Proxy "host:port" oder "user:pass@host:port" (leer = direkt bzw. Systemproxy)
    #[serde(rename = "p", default, skip_serializing_if = "String::is_empty")]
    pub proxy: String,
}

fn default_mtu() -> u16 {
    1400
}

pub fn key_to_b64(k: &Key32) -> String {
    STANDARD.encode(k)
}

pub fn key_from_b64(s: &str) -> Result<Key32, String> {
    let v = STANDARD.decode(s.trim()).map_err(|e| format!("Schluessel ungueltig: {e}"))?;
    v.try_into().map_err(|_| "Schluessel muss 32 Byte lang sein".to_string())
}

impl ClientConfig {
    /// Anzeigename des VPN
    pub fn display_name(&self) -> &str {
        if self.title.trim().is_empty() { "KroneVPN" } else { self.title.trim() }
    }

    pub fn to_code(&self) -> String {
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).unwrap()))
    }

    /// Code einlesen; Leerzeichen/Zeilenumbrueche (z. B. aus Messenger kopiert) werden ignoriert
    pub fn from_code(code: &str) -> Result<Self, String> {
        let c: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        let body = c
            .strip_prefix(PREFIX)
            .ok_or_else(|| "Das ist kein KroneVPN-Verbindungscode (muss mit kronevpn://v1/ beginnen)".to_string())?;
        let raw = URL_SAFE_NO_PAD.decode(body.trim_end_matches('=')).map_err(|e| format!("Code beschaedigt: {e}"))?;
        let cfg: ClientConfig = serde_json::from_slice(&raw).map_err(|e| format!("Code beschaedigt: {e}"))?;
        cfg.server_key()?;
        cfg.client_key()?;
        if !(cfg.url.starts_with("wss://") || cfg.url.starts_with("ws://")) {
            return Err("Server-Adresse muss mit wss:// beginnen".into());
        }
        Ok(cfg)
    }

    pub fn server_key(&self) -> Result<Key32, String> {
        key_from_b64(&self.server_pub)
    }
    pub fn client_key(&self) -> Result<Key32, String> {
        key_from_b64(&self.private_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_roundtrip() {
        let (k, _) = crate::crypto::generate_keypair();
        let (_, s) = crate::crypto::generate_keypair();
        let c = ClientConfig {
            name: "Galaxy S26 Ultra".into(),
            url: "wss://vpn.example.de/api/v1/stream".into(),
            server_pub: key_to_b64(&s),
            private_key: key_to_b64(&k),
            ip4: "10.77.0.2/24".into(),
            ip6: "fd77:6b76::2/64".into(),
            dns: vec!["1.1.1.1".into(), "9.9.9.9".into()],
            mtu: 1400,
            title: "Potzplitz VPN".into(),
            proxy: String::new(),
        };
        let code = c.to_code();
        assert!(code.starts_with(PREFIX));
        // mit Zeilenumbruechen (Messenger)
        let broken = format!("  {}\n{} ", &code[..30], &code[30..]);
        assert_eq!(ClientConfig::from_code(&broken).unwrap(), c);
        assert!(ClientConfig::from_code("hallo").is_err());
        assert_eq!(ClientConfig::from_code(&code).unwrap().display_name(), "Potzplitz VPN");
        // alte Codes ohne Namen bleiben gueltig
        let mut old = c.clone();
        old.title.clear();
        assert_eq!(ClientConfig::from_code(&old.to_code()).unwrap().display_name(), "KroneVPN");
        assert!(ClientConfig::from_code(&code[..code.len() - 5]).is_err());
    }
}
