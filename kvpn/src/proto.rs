//! Protokoll-Konstanten und Nachrichten.

use serde::{Deserialize, Serialize};

/// Noise-Muster: wie WireGuard (IK = Client kennt den Server-Schluessel vorher).
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const PROLOGUE: &[u8] = b"KroneVPN/1";
/// harte Obergrenze fuer Geraete (Peers)
pub const MAX_PEERS: usize = 8;
/// Standard-Pfad des Tunnels (unauffaellig, kein "vpn" in der URL)
pub const DEFAULT_PATH: &str = "/api/v1/stream";

/// Datensatz-Arten innerhalb eines verschluesselten Buendels
pub const REC_PACKET: u8 = 1;
pub const REC_PING: u8 = 2;
pub const REC_PONG: u8 = 3;
pub const REC_PAD: u8 = 4;

/// maximale Groesse eines Klartext-Buendels
pub const MAX_BUNDLE: usize = 60 * 1024;
/// Buendel werden bis zu dieser Groesse mit weiteren wartenden Paketen gefuellt
pub const BUNDLE_TARGET: usize = 32 * 1024;

/// Nutzdaten der ersten Handshake-Nachricht (Client -> Server)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Hello {
    /// Zeitstempel in Nanosekunden (Replay-Schutz)
    pub ts: u64,
    pub os: String,
    pub ver: String,
    /// Aussteller des TLS-Zertifikats, das der Client gesehen hat (z. B. "Sophos ..." bei HTTPS-Inspektion)
    #[serde(default)]
    pub tls_issuer: String,
    /// war das Zertifikat oeffentlich vertrauenswuerdig?
    #[serde(default)]
    pub tls_trusted: bool,
    #[serde(default)]
    pub via_proxy: bool,
}

/// Nutzdaten der zweiten Handshake-Nachricht (Server -> Client)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Welcome {
    pub name: String,
    /// z. B. "10.77.0.2/24"
    pub ip4: String,
    /// z. B. "fd77:6b76::2/64" (leer = kein IPv6)
    #[serde(default)]
    pub ip6: String,
    pub dns: Vec<String>,
    pub mtu: u16,
}

/// Datensatz an ein Buendel anhaengen: [art u8][laenge u16 BE][daten]
pub fn push_record(buf: &mut Vec<u8>, kind: u8, data: &[u8]) {
    debug_assert!(data.len() <= u16::MAX as usize);
    buf.push(kind);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Datensaetze eines Buendels durchlaufen. Fehlerhafte Laenge -> Err.
pub fn for_each_record(mut buf: &[u8], mut f: impl FnMut(u8, &[u8])) -> Result<(), &'static str> {
    while !buf.is_empty() {
        if buf.len() < 3 {
            return Err("abgeschnittener Datensatz");
        }
        let kind = buf[0];
        let len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        if buf.len() < 3 + len {
            return Err("Datensatz zu lang");
        }
        f(kind, &buf[3..3 + len]);
        buf = &buf[3 + len..];
    }
    Ok(())
}

/// Ziel-IP eines IP-Pakets (v4 oder v6)
pub fn dst_ip(pkt: &[u8]) -> Option<std::net::IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(std::net::IpAddr::from([pkt[16], pkt[17], pkt[18], pkt[19]])),
        6 if pkt.len() >= 40 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[24..40]);
            Some(std::net::IpAddr::from(a))
        }
        _ => None,
    }
}

/// Quell-IP eines IP-Pakets (v4 oder v6)
pub fn src_ip(pkt: &[u8]) -> Option<std::net::IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(std::net::IpAddr::from([pkt[12], pkt[13], pkt[14], pkt[15]])),
        6 if pkt.len() >= 40 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[8..24]);
            Some(std::net::IpAddr::from(a))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_roundtrip() {
        let mut b = Vec::new();
        push_record(&mut b, REC_PACKET, b"hallo");
        push_record(&mut b, REC_PING, &[1, 2, 3]);
        push_record(&mut b, REC_PAD, &[]);
        let mut seen = Vec::new();
        for_each_record(&b, |k, d| seen.push((k, d.to_vec()))).unwrap();
        assert_eq!(seen, vec![(1, b"hallo".to_vec()), (2, vec![1, 2, 3]), (4, vec![])]);
        assert!(for_each_record(&b[..b.len() - 1 - 3], |_, _| {}).is_err());
    }

    #[test]
    fn ip_parse() {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&[10, 77, 0, 2]);
        p[16..20].copy_from_slice(&[1, 1, 1, 1]);
        assert_eq!(dst_ip(&p).unwrap().to_string(), "1.1.1.1");
        assert_eq!(src_ip(&p).unwrap().to_string(), "10.77.0.2");
        let mut q = vec![0u8; 40];
        q[0] = 0x60;
        q[8] = 0xfd;
        q[24] = 0x20;
        q[25] = 0x01;
        assert_eq!(src_ip(&q).unwrap().to_string(), "fd00::");
        assert_eq!(dst_ip(&q).unwrap().to_string(), "2001::");
        assert!(dst_ip(&[0x45]).is_none());
    }
}
