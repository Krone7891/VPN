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
/// Client -> Server: Update-Datei ab Position senden ([position u32 BE])
pub const REC_UPD_GET: u8 = 5;
/// Server -> Client: Stueck der Update-Datei ([position u32 BE][daten])
pub const REC_UPD_DATA: u8 = 6;
/// Client -> Server: Angaben des Geraets als JSON (WLAN-Name, Standort) – nur, wenn auf dem Geraet freigegeben
pub const REC_INFO: u8 = 7;
/// hoechste Groesse von REC_INFO
pub const MAX_INFO: usize = 2048;
/// Server -> Client: stilles Anpingen von der Admin-Seite ([id u32 BE]); der VPN-Kern antwortet selbst mit
/// REC_SPONG (gleiche Daten) – ohne App, ohne Benachrichtigung (ab 1.1.0, aeltere Apps ignorieren es)
pub const REC_SPING: u8 = 8;
pub const REC_SPONG: u8 = 9;
/// Server -> Client: "jetzt orten" ([id u32 BE]) – die App holt einen frischen Standort und meldet ihn per REC_INFO
pub const REC_LOCATE: u8 = 10;
/// Client -> Server: Absturz-Protokoll ([Namenslaenge u8][Name][Text]); der Server legt es in einen Ordner ab
pub const REC_CRASH: u8 = 11;
/// Server -> Client: Absturz-Protokoll gespeichert ([Name]) – erst dann loescht die App ihre Kopie
pub const REC_CRASH_OK: u8 = 12;
/// Client -> Server: eigenes Logo des Servers schicken (leer) – ab Apps 1.2.0
pub const REC_LOGO_GET: u8 = 13;
/// Server -> Client: Stueck des Logos ([Gesamtgroesse u32 BE][Position u32 BE][Daten], siehe logo.rs)
pub const REC_LOGO: u8 = 14;
/// Geschwindigkeitstest (ab Apps/Server 1.4.0) – misst genau die Strecke Geraet <-> eigener Server durch den Tunnel:
/// Client -> Server: Download fuer so viele Millisekunden schicken ([ms u16 BE], hoechstens SPEED_MAX_MS)
pub const REC_SPEED_GET: u8 = 15;
/// beide Richtungen: Fuelldaten des Tests (werden verworfen)
pub const REC_SPEED_DATA: u8 = 16;
/// Client -> Server: Upload fertig (leer) – der Server antwortet mit REC_SPEED_RES Art 2
pub const REC_SPEED_UP_END: u8 = 17;
/// Server -> Client: [Art u8 (1 = Download fertig, 2 = Upload-Ergebnis)][Bytes u64 BE][Mikrosekunden u64 BE]
pub const REC_SPEED_RES: u8 = 18;
/// Laenge des Tests je Richtung (Millisekunden) und Obergrenze
pub const SPEED_MS: u16 = 5000;
pub const SPEED_MAX_MS: u16 = 10000;
/// Groesse eines Fuell-Datensatzes (zwei passen in ein Buendel)
pub const SPEED_CHUNK: usize = 15 * 1024;

/// Ergebnis eines Geschwindigkeitstests als Datensatz-Inhalt
pub fn speed_res(kind: u8, bytes: u64, us: u64) -> Vec<u8> {
    let mut d = Vec::with_capacity(17);
    d.push(kind);
    d.extend_from_slice(&bytes.to_be_bytes());
    d.extend_from_slice(&us.to_be_bytes());
    d
}

/// Datensatz-Inhalt von REC_SPEED_RES lesen: (Art, Bytes, Mikrosekunden)
pub fn speed_res_parse(d: &[u8]) -> Option<(u8, u64, u64)> {
    (d.len() >= 17).then(|| (d[0], u64::from_be_bytes(d[1..9].try_into().unwrap()), u64::from_be_bytes(d[9..17].try_into().unwrap())))
}

/// Mbit/s aus Bytes und Mikrosekunden
pub fn mbit(bytes: u64, us: u64) -> f64 {
    if us == 0 {
        return 0.0;
    }
    (bytes as f64 * 8.0) / us as f64
}

/// hoechste Groesse eines Absturz-Protokolls (Rest wird abgeschnitten)
pub const MAX_CRASH: usize = 48 * 1024;

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
    /// Client kann sich selbst aktualisieren (ab 1.0.1)
    #[serde(default)]
    pub upd: bool,
    /// unterstuetzte Verschluesselungen fuer die Daten. Bis 1.0.13: nur ["aes256gcm"] (ChaCha20 geht immer).
    /// Ab 1.1.0 mit `pick`: Wunschliste in Reihenfolge, der Server nimmt die erste, die er kann.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ciphers: Vec<String>,
    /// `ciphers` ist eine Wunschliste (ab 1.1.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub pick: bool,
    /// Fuellzeichen zufaelliger Laenge: der Handshake hat bei jeder Verbindung eine andere Groesse (Tarnung)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pad: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// AES-256-GCM statt ChaCha20-Poly1305 fuer die Daten (Name im Handshake)
pub const CIPHER_AES256: &str = "aes256gcm";
/// ChaCha20-Poly1305 (Standard, im Handshake leer oder "chacha20")
pub const CIPHER_CHACHA: &str = "chacha20";

/// Tarn-Profil einer Verbindung: wird vom Server bei jeder Verbindung neu ausgewuerfelt und verschluesselt im
/// Welcome mitgeschickt. Beide Seiten formen damit ihre Datenpakete (Groessen, Fuellbytes, Takt der Lebenszeichen),
/// damit keine zwei Verbindungen gleich aussehen. Aendert nichts an der Verschluesselung und bleibt normales
/// TLS 1.3 + WebSocket – genau das, was Firewalls wie Sophos als HTTPS durchlassen.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tarn {
    /// Buendel werden auf ein Vielfaches davon aufgefuellt (Bytes, 0 = aus)
    pub block: u16,
    /// zusaetzliche zufaellige Fuellbytes bis zu dieser Zahl ...
    pub extra: u16,
    /// ... bei so vielen von 256 Buendeln
    pub chance: u8,
    /// Lebenszeichen zufaellig alle ka_min..ka_max Millisekunden
    pub ka_min: u32,
    pub ka_max: u32,
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
    /// neuere App-Version liegt auf dem Server bereit (signierte Liste, siehe update.rs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upd: Option<UpdateOffer>,
    /// gewaehlte Verschluesselung fuer die Daten (leer = ChaCha20-Poly1305, "aes256gcm" = AES-256-GCM)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cipher: String,
    /// Tarn-Profil dieser Verbindung (ab 1.1.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tarn: Option<Tarn>,
    /// Fuellzeichen zufaelliger Laenge (siehe Hello::pad)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pad: String,
    /// eigenes Logo des Servers: Kennung (siehe logo.rs); Some("") = keins (Krone), None = Server zu alt
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,
}

/// Update-Angebot: Inhalt von update.json und dessen Ed25519-Signatur (Base64)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateOffer {
    pub manifest: String,
    pub sig: String,
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
    fn speed() {
        let d = speed_res(2, 12_500_000, 1_000_000);
        assert_eq!(speed_res_parse(&d), Some((2, 12_500_000, 1_000_000)));
        assert_eq!(mbit(12_500_000, 1_000_000), 100.0);
        assert!(speed_res_parse(&d[..16]).is_none());
        let mut b = Vec::new();
        push_record(&mut b, REC_SPEED_DATA, &[0u8; SPEED_CHUNK]);
        push_record(&mut b, REC_SPEED_DATA, &[0u8; SPEED_CHUNK]);
        assert!(b.len() < MAX_BUNDLE - 1024, "zwei Stuecke passen mit Tarn-Fuellung ins Buendel");
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
