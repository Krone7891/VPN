//! Aeusserer Transport des Clients: TCP -> (optional HTTP-CONNECT-Proxy) -> TLS 1.3 -> WebSocket.
//!
//! Fuer Firewalls (Sophos, Fortinet, ...) sieht das aus wie ein Browser, der eine Webseite mit Live-Verbindung oeffnet.
//! Das TLS-Zertifikat wird geprueft und das Ergebnis gemeldet, eine Verbindung kommt aber auch mit einem
//! Inspektions-Zertifikat (Sophos HTTPS-Scanning) zustande: die Sicherheit liefert der innere Noise-Handshake,
//! dessen Server-Schluessel fest im Client steht.

use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::WebSocketStream;

pub const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";

/// TCP oder TLS ueber TCP
pub enum Conn {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_flush(cx),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

pub type Ws = WebSocketStream<Conn>;

#[derive(Debug, Clone, Default)]
pub struct TransportInfo {
    /// Adresse, mit der wirklich verbunden wurde (Server oder Proxy)
    pub peer: Option<SocketAddr>,
    pub tls_issuer: String,
    pub tls_trusted: bool,
    pub via_proxy: bool,
}

/// Wird vor jedem Verbindungsaufbau mit der Ziel-IP aufgerufen (z. B. Windows: Umgehungsroute am Tunnel vorbei).
pub type ProtectFn = Arc<dyn Fn(IpAddr) + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_url(url: &str) -> Result<Target, String> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("wss://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("ws://") {
        (false, r)
    } else {
        return Err(format!("'{url}': muss mit wss:// beginnen"));
    };
    let (hp, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = split_host_port(hp, if tls { 443 } else { 80 })?;
    Ok(Target { tls, host, port, path })
}

fn split_host_port(hp: &str, default: u16) -> Result<(String, u16), String> {
    if let Some(r) = hp.strip_prefix('[') {
        // [IPv6]:port
        let (h, after) = r.split_once(']').ok_or("']' fehlt")?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| format!("Port '{p}' ungueltig"))?,
            None => default,
        };
        return Ok((h.to_string(), port));
    }
    match hp.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Ok((h.to_string(), p.parse().map_err(|_| format!("Port '{p}' ungueltig"))?)),
        _ => Ok((hp.to_string(), default)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub host: String,
    pub port: u16,
    pub auth: Option<String>,
}

/// "host:port", "http://host:port", "user:pass@host:port"
pub fn parse_proxy(s: &str) -> Result<Option<Proxy>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let s = s.strip_prefix("http://").unwrap_or(s).trim_end_matches('/');
    let (auth, hp) = match s.rsplit_once('@') {
        Some((a, hp)) => (Some(a.to_string()), hp),
        None => (None, s),
    };
    let (host, port) = split_host_port(hp, 8080)?;
    if host.is_empty() {
        return Err("Proxy-Adresse leer".into());
    }
    Ok(Some(Proxy { host, port, auth }))
}

/// Gemerkte Server-Adressen (Name -> IPs). Wichtig, wenn der Tunnel alles umleitet: dann geht DNS nur durch den
/// Tunnel - der beim (Neu-)Verbinden aber gerade nicht steht. Die Clients loesen den Namen deshalb vor dem Einrichten
/// der Routen auf und nehmen bei DNS-Fehlern die gemerkte Adresse.
pub type DnsCache = Arc<Mutex<std::collections::HashMap<String, Vec<SocketAddr>>>>;

pub fn new_dns_cache() -> DnsCache {
    Arc::new(Mutex::new(std::collections::HashMap::new()))
}

/// Namen jetzt (blockierend) aufloesen und merken - vor dem Einrichten des Tunnels aufrufen
pub fn preresolve(cache: &DnsCache, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    use std::net::ToSocketAddrs;
    let v: Vec<SocketAddr> = (host, port).to_socket_addrs().map_err(|e| format!("Adresse {host} nicht gefunden: {e} (Internet da? DNS gesperrt?)"))?.collect();
    if v.is_empty() {
        return Err(format!("Adresse {host} nicht gefunden"));
    }
    cache.lock().unwrap().insert(format!("{host}:{port}"), v.clone());
    Ok(v)
}

async fn resolve(host: &str, port: u16, cache: &DnsCache) -> io::Result<Vec<SocketAddr>> {
    let key = format!("{host}:{port}");
    let err = match tokio::time::timeout(Duration::from_secs(4), tokio::net::lookup_host((host, port))).await {
        Ok(Ok(it)) => {
            let v: Vec<SocketAddr> = it.collect();
            if !v.is_empty() {
                cache.lock().unwrap().insert(key, v.clone());
                return Ok(v);
            }
            io::Error::new(io::ErrorKind::NotFound, format!("Adresse {host} nicht gefunden"))
        }
        Ok(Err(e)) => io::Error::new(e.kind(), format!("Adresse {host} nicht gefunden: {e}")),
        Err(_) => io::Error::new(io::ErrorKind::TimedOut, format!("DNS-Abfrage fuer {host} dauert zu lange")),
    };
    // DNS geht gerade nicht (z. B. laeuft es durch den noch nicht verbundenen Tunnel): gemerkte Adresse nehmen
    match cache.lock().unwrap().get(&key).cloned() {
        Some(v) => Ok(v),
        None => Err(err),
    }
}

async fn tcp_connect(host: &str, port: u16, protect: &Option<ProtectFn>, cache: &DnsCache) -> io::Result<TcpStream> {
    let mut addrs: Vec<SocketAddr> = resolve(host, port, cache).await?;
    // IPv4 zuerst: Firmennetze (Sophos) haben oft kein oder gefiltertes IPv6
    addrs.sort_by_key(|a| a.is_ipv6());
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("keine Adresse fuer {host}"));
    for a in addrs {
        if let Some(p) = protect {
            p(a.ip());
        }
        match tokio::time::timeout(Duration::from_secs(7), TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => last = io::Error::new(e.kind(), format!("{a}: {e}")),
            Err(_) => last = io::Error::new(io::ErrorKind::TimedOut, format!("{a}: keine Antwort (Firewall?)")),
        }
    }
    Err(last)
}

async fn proxy_connect(s: &mut TcpStream, proxy: &Proxy, host: &str, port: u16) -> io::Result<()> {
    let hp = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let mut req = format!("CONNECT {hp} HTTP/1.1\r\nHost: {hp}\r\nUser-Agent: {USER_AGENT}\r\nProxy-Connection: keep-alive\r\n");
    if let Some(a) = &proxy.auth {
        req += &format!("Proxy-Authorization: Basic {}\r\n", base64::engine::general_purpose::STANDARD.encode(a));
    }
    req += "\r\n";
    s.write_all(req.as_bytes()).await?;
    let head = read_head(s, 16 * 1024).await?;
    let status = head.lines().next().unwrap_or("");
    let code = status.split_whitespace().nth(1).unwrap_or("");
    if code != "200" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Proxy lehnt ab: {status}{}", if code == "407" { " (Anmeldung am Proxy noetig)" } else { "" }),
        ));
    }
    Ok(())
}

/// HTTP-Kopf bis zur Leerzeile lesen (byteweise, damit nichts Folgendes verschluckt wird)
pub async fn read_head<S: AsyncRead + Unpin>(s: &mut S, max: usize) -> io::Result<String> {
    let mut buf = Vec::with_capacity(512);
    let mut b = [0u8; 1];
    loop {
        let n = s.read(&mut b).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Verbindung waehrend HTTP-Kopf geschlossen"));
        }
        buf.push(b[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP-Kopf zu gross"));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// ---------------------------------------------------------------- TLS

#[derive(Debug)]
struct ReportingVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    seen: Arc<Mutex<(String, bool)>>,
}

impl ServerCertVerifier for ReportingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let trusted = self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp, now).is_ok();
        *self.seen.lock().unwrap() = (issuer_name(end_entity.as_ref()), trusted);
        // absichtlich immer akzeptiert – die Echtheit des Servers prueft der Noise-Handshake (fester Server-Schluessel)
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config(seen: Arc<Mutex<(String, bool)>>) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| e.to_string())?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ReportingVerifier { inner, provider, seen }))
        .with_no_client_auth();
    // wie ein Browser, der per WebSocket spricht (HTTP/1.1-Upgrade)
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Aussteller (CN bzw. O) aus einem DER-Zertifikat lesen – nur fuer die Anzeige
pub fn issuer_name(der: &[u8]) -> String {
    fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let tag = *b.first()?;
        let l0 = *b.get(1)? as usize;
        let (len, hdr) = if l0 < 0x80 {
            (l0, 2)
        } else {
            let n = l0 & 0x7f;
            if n == 0 || n > 4 || b.len() < 2 + n {
                return None;
            }
            (b[2..2 + n].iter().fold(0usize, |a, &x| (a << 8) | x as usize), 2 + n)
        };
        if b.len() < hdr + len {
            return None;
        }
        Some((tag, &b[hdr..hdr + len], &b[hdr + len..]))
    }
    let f = || -> Option<String> {
        let (_, cert, _) = tlv(der)?;
        let (_, tbs, _) = tlv(cert)?;
        let mut r = tbs;
        let (t, _, rest) = tlv(r)?;
        if t == 0xa0 {
            r = rest; // Version
        }
        let (_, _, r) = tlv(r)?; // Seriennummer
        let (_, _, r) = tlv(r)?; // Signaturalgorithmus
        let (_, issuer, _) = tlv(r)?;
        let (mut cn, mut o) = (String::new(), String::new());
        let mut sets = issuer;
        while let Some((_, set, rest)) = tlv(sets) {
            if let Some((_, seq, _)) = tlv(set) {
                if let Some((_, oid, val)) = tlv(seq) {
                    if let Some((_, v, _)) = tlv(val) {
                        let v = String::from_utf8_lossy(v).into_owned();
                        match oid {
                            [0x55, 0x04, 0x03] => cn = v,
                            [0x55, 0x04, 0x0a] => o = v,
                            _ => {}
                        }
                    }
                }
            }
            sets = rest;
        }
        Some(match (cn.is_empty(), o.is_empty()) {
            (false, false) if !cn.contains(&o) => format!("{cn} ({o})"),
            (false, _) => cn,
            (true, false) => o,
            _ => "unbekannt".into(),
        })
    };
    f().unwrap_or_else(|| "unbekannt".into())
}

/// Verbindung aufbauen bis einschliesslich WebSocket-Upgrade.
pub async fn connect(url: &str, proxy: Option<&Proxy>, protect: &Option<ProtectFn>, cache: &DnsCache) -> Result<(Ws, TransportInfo), String> {
    let t = parse_url(url)?;
    let mut info = TransportInfo::default();
    let mut tcp = match proxy {
        Some(p) => {
            let mut s = tcp_connect(&p.host, p.port, protect, cache).await.map_err(|e| format!("Proxy {}:{} nicht erreichbar: {e}", p.host, p.port))?;
            info.peer = s.peer_addr().ok();
            tokio::time::timeout(Duration::from_secs(15), proxy_connect(&mut s, p, &t.host, t.port))
                .await
                .map_err(|_| "Proxy antwortet nicht".to_string())?
                .map_err(|e| e.to_string())?;
            info.via_proxy = true;
            s
        }
        None => {
            let s = tcp_connect(&t.host, t.port, protect, cache).await.map_err(|e| e.to_string())?;
            info.peer = s.peer_addr().ok();
            s
        }
    };
    let _ = tcp.set_nodelay(true);
    let conn = if t.tls {
        let seen = Arc::new(Mutex::new((String::new(), false)));
        let cfg = tls_config(seen.clone())?;
        let name = ServerName::try_from(t.host.clone()).map_err(|e| format!("Servername ungueltig: {e}"))?;
        let tls = tokio::time::timeout(Duration::from_secs(15), tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp))
            .await
            .map_err(|_| "TLS-Handshake dauert zu lange".to_string())?
            .map_err(|e| format!("TLS-Handshake fehlgeschlagen: {e}"))?;
        let (issuer, trusted) = seen.lock().unwrap().clone();
        info.tls_issuer = issuer;
        info.tls_trusted = trusted;
        Conn::Tls(Box::new(tls))
    } else {
        tcp.flush().await.ok();
        Conn::Plain(tcp)
    };

    let mut req = url.into_client_request().map_err(|e| format!("URL ungueltig: {e}"))?;
    {
        let h = req.headers_mut();
        let origin = format!("{}://{}", if t.tls { "https" } else { "http" }, t.host);
        h.insert("User-Agent", USER_AGENT.parse().unwrap());
        h.insert("Origin", origin.parse().map_err(|_| "Origin ungueltig")?);
        h.insert("Accept-Language", "de-DE,de;q=0.9,en;q=0.8".parse().unwrap());
        h.insert("Cache-Control", "no-cache".parse().unwrap());
        h.insert("Pragma", "no-cache".parse().unwrap());
    }
    let wcfg = WebSocketConfig::default().max_message_size(Some(1 << 20)).max_frame_size(Some(1 << 20));
    let (ws, resp) = tokio::time::timeout(Duration::from_secs(15), tokio_tungstenite::client_async_with_config(req, conn, Some(wcfg)))
        .await
        .map_err(|_| "Server antwortet nicht auf den WebSocket-Aufbau".to_string())?
        .map_err(|e| format!("WebSocket-Aufbau fehlgeschlagen: {e}"))?;
    let _ = resp;
    Ok((ws, info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(
            parse_url("wss://vpn.example.de/api/v1/stream").unwrap(),
            Target { tls: true, host: "vpn.example.de".into(), port: 443, path: "/api/v1/stream".into() }
        );
        assert_eq!(parse_url("ws://10.0.0.1:8101/x").unwrap().port, 8101);
        assert_eq!(parse_url("wss://[2001:db8::1]:8443/x").unwrap().host, "2001:db8::1");
        assert!(parse_url("https://x").is_err());
        assert_eq!(parse_proxy("").unwrap(), None);
        assert_eq!(parse_proxy("http://proxy.firma.de:3128/").unwrap().unwrap().port, 3128);
        let p = parse_proxy("max:geheim@10.1.1.1:8080").unwrap().unwrap();
        assert_eq!(p.auth.as_deref(), Some("max:geheim"));
        assert_eq!(p.host, "10.1.1.1");
    }
}
