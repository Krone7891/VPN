//! Der eigentliche Server: HTTP/WebSocket annehmen, Handshake, Pakete zwischen Geraeten und TUN vermitteln.

use crate::config::{Config, Peer};
use crate::log;
use crate::stats::{Hist, PeerStats, SessInfo};
use futures_util::{SinkExt, StreamExt};
use kvpn::crypto::{self, Key32};
use kvpn::fdtun::FdTun;
use kvpn::proto::*;
use kvpn::util::now_secs;
use sha2::Digest;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

pub struct PeerRt {
    pub peer: Peer,
    pub stats: Arc<PeerStats>,
}

struct Route {
    tx: mpsc::Sender<Vec<u8>>,
    sid: u64,
}

pub struct Shared {
    pub cfg_path: String,
    pub cfg: RwLock<Arc<Config>>,
    pub server_priv: Key32,
    /// oeffentlicher Schluessel -> Geraet
    pub peers: RwLock<HashMap<Key32, Arc<PeerRt>>>,
    routes: RwLock<HashMap<IpAddr, Route>>,
    sessions: Mutex<HashMap<Key32, (u64, Arc<Notify>)>>,
    last_ts: Mutex<HashMap<Key32, u64>>,
    tuns: Vec<Arc<FdTun>>,
    next_sid: AtomicU64,
    pub hist: Mutex<Hist>,
    pub started: u64,
    pub queues: usize,
    pub tun_drops: AtomicU64,
    handshake_slots: Semaphore,
    login_fail: Mutex<(u64, u32)>,
}

impl Shared {
    pub fn new(cfg_path: String, cfg: Config, tuns: Vec<Arc<FdTun>>) -> Arc<Self> {
        let hist = Hist::new(Hist::load(&format!("{}/stats.json", cfg.state_dir)));
        let sh = Arc::new(Shared {
            cfg_path,
            server_priv: cfg.server_key().unwrap(),
            cfg: RwLock::new(Arc::new(cfg.clone())),
            peers: RwLock::new(HashMap::new()),
            routes: RwLock::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            last_ts: Mutex::new(HashMap::new()),
            queues: tuns.len(),
            tuns,
            next_sid: AtomicU64::new(1),
            hist: Mutex::new(hist),
            started: now_secs(),
            tun_drops: AtomicU64::new(0),
            handshake_slots: Semaphore::new(32),
            login_fail: Mutex::new((0, 0)),
        });
        sh.apply_peers(&cfg);
        sh
    }

    pub fn cfg(&self) -> Arc<Config> {
        self.cfg.read().unwrap().clone()
    }

    /// Geraeteliste uebernehmen; Zaehler bekannter Geraete bleiben erhalten, entfernte Geraete werden getrennt
    pub fn apply_peers(&self, cfg: &Config) {
        let mut map = self.peers.write().unwrap();
        let mut new = HashMap::new();
        for p in &cfg.peers {
            let Ok(k) = kvpn::code::key_from_b64(&p.public_key) else { continue };
            let stats = map.get(&k).filter(|o| o.peer.index == p.index).map(|o| o.stats.clone()).unwrap_or_default();
            new.insert(k, Arc::new(PeerRt { peer: p.clone(), stats }));
        }
        let removed: Vec<Key32> = map.keys().filter(|k| !new.contains_key(*k)).cloned().collect();
        *map = new;
        drop(map);
        let s = self.sessions.lock().unwrap();
        for k in removed {
            if let Some((_, n)) = s.get(&k) {
                n.notify_one();
            }
        }
    }

    pub fn reload(&self) {
        match Config::load(&self.cfg_path) {
            Ok(c) => {
                if c.private_key != self.cfg().private_key || c.net4 != self.cfg().net4 || c.net6 != self.cfg().net6 {
                    log!("Hinweis: Schluessel/Netz geaendert – das gilt erst nach einem Neustart des Dienstes");
                }
                self.apply_peers(&c);
                *self.cfg.write().unwrap() = Arc::new(c);
                log!("Konfiguration neu geladen: {} Geraet(e)", self.peers.read().unwrap().len());
            }
            Err(e) => log!("Konfiguration fehlerhaft, behalte die alte: {e}"),
        }
    }
}

// ------------------------------------------------------------------------------------------------ TUN -> Geraete

pub fn spawn_tun_readers(sh: &Arc<Shared>) {
    for (qi, tun) in sh.tuns.iter().enumerate() {
        let tun = tun.clone();
        let sh = sh.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let n = match tun.read(&mut buf).await {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        log!("TUN-Queue {qi}: Lesefehler {e}");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                };
                let Some(dst) = dst_ip(&buf[..n]) else { continue };
                let r = sh.routes.read().unwrap();
                match r.get(&dst) {
                    Some(route) => {
                        if route.tx.try_send(buf[..n].to_vec()).is_err() {
                            sh.tun_drops.fetch_add(1, Relaxed);
                        }
                    }
                    None => {}
                }
            }
        });
    }
}

// ------------------------------------------------------------------------------------------------ HTTP

pub async fn handle_conn<S>(sh: Arc<Shared>, s: S, peer: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_http(sh, s, peer, true).await
}

/// lokale Webseite (http://localhost:8180): nur Statistik und Downloads, kein Tunnel, keine fremden Absender
pub async fn handle_local<S>(sh: Arc<Shared>, s: S, peer: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_http(sh, s, peer, false).await
}

async fn handle_http<S>(sh: Arc<Shared>, mut s: S, peer: SocketAddr, tunnel_ok: bool)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let head = match tokio::time::timeout(Duration::from_secs(15), kvpn::transport::read_head(&mut s, 16 * 1024)).await {
        Ok(Ok(h)) => h,
        _ => return,
    };
    let mut lines = head.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut headers: HashMap<String, String> = HashMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    // lokal: X-Real-IP wird ignoriert (es gibt keinen Proxy davor) - der Absender ist dieser Rechner
    let remote: IpAddr = if peer.ip().is_loopback() && tunnel_ok {
        headers.get("x-real-ip").and_then(|v| v.parse().ok()).unwrap_or(peer.ip())
    } else {
        peer.ip()
    };
    let path = target.split('?').next().unwrap_or("/").to_string();
    let cfg = sh.cfg();
    let tunnel_path = kvpn::transport::parse_url(&cfg.public_url).map(|t| t.path).unwrap_or_else(|_| DEFAULT_PATH.into());

    let is_ws = headers.get("upgrade").map(|v| v.eq_ignore_ascii_case("websocket")).unwrap_or(false);
    if tunnel_ok && path == tunnel_path && is_ws && method == "GET" {
        let Some(key) = headers.get("sec-websocket-key") else { return };
        let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
        let resp = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n");
        if s.write_all(resp.as_bytes()).await.is_err() {
            return;
        }
        let wcfg = WebSocketConfig::default().max_message_size(Some(1 << 20)).max_frame_size(Some(1 << 20));
        let ws = WebSocketStream::from_raw_socket(s, Role::Server, Some(wcfg)).await;
        tunnel(sh, ws, remote).await;
        return;
    }
    crate::web::handle(&sh, &mut s, &method, &path, &headers, remote, tunnel_ok && peer.ip().is_loopback(), !tunnel_ok).await;
}

// ------------------------------------------------------------------------------------------------ Tunnel

async fn tunnel<S>(sh: Arc<Shared>, mut ws: WebSocketStream<S>, remote: IpAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Handshake (hoechstens 32 gleichzeitig, damit Scanner den Server nicht beschaeftigen)
    let Ok(_permit) = sh.handshake_slots.try_acquire() else { return };
    let m1 = match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
        Ok(Some(Ok(Message::Binary(b)))) => b,
        _ => return,
    };
    let (hs, cpub, hello) = match crypto::server_read(&sh.server_priv, &m1) {
        Ok(v) => v,
        Err(_) => {
            log!("{remote}: ungueltiger Handshake (kein KroneVPN-Client oder falscher Server-Schluessel)");
            return;
        }
    };
    let Some(prt) = sh.peers.read().unwrap().get(&cpub).cloned() else {
        log!("{remote}: unbekannter Geraete-Schluessel {} – abgelehnt", kvpn::code::key_to_b64(&cpub));
        let _ = ws.close(None).await;
        return;
    };
    {
        let mut lt = sh.last_ts.lock().unwrap();
        let last = lt.get(&cpub).copied().unwrap_or(0);
        if hello.ts <= last {
            log!("{remote}: {} – wiederholter Handshake (Replay) abgelehnt", prt.peer.name);
            return;
        }
        lt.insert(cpub, hello.ts);
    }
    let cfg = sh.cfg();
    let welcome = cfg.welcome(&prt.peer);
    let (m2, mut sealer, mut opener) = match crypto::server_reply(hs, &welcome) {
        Ok(v) => v,
        Err(e) => {
            log!("{remote}: Handshake-Fehler {e}");
            return;
        }
    };
    if ws.send(Message::Binary(m2.into())).await.is_err() {
        return;
    }
    drop(_permit);

    let ip4: IpAddr = cfg.ip4(prt.peer.index).into();
    let ip6: Option<IpAddr> = cfg.ip6(prt.peer.index).map(Into::into);
    let sid = sh.next_sid.fetch_add(1, Relaxed);
    let kick = Arc::new(Notify::new());
    if let Some((_, old)) = sh.sessions.lock().unwrap().insert(cpub, (sid, kick.clone())) {
        old.notify_one(); // alte Verbindung desselben Geraets (z. B. nach WLAN->Mobil) beenden
    }
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(2048);
    {
        let mut r = sh.routes.write().unwrap();
        r.insert(ip4, Route { tx: tx.clone(), sid });
        if let Some(a) = ip6 {
            r.insert(a, Route { tx: tx.clone(), sid });
        }
    }
    drop(tx);
    let st = prt.stats.clone();
    st.handshakes.fetch_add(1, Relaxed);
    st.connected_since.store(now_secs(), Relaxed);
    st.last_seen.store(now_secs(), Relaxed);
    *st.info.lock().unwrap() = SessInfo {
        remote: remote.to_string(),
        os: hello.os.clone(),
        ver: hello.ver.clone(),
        tls_issuer: hello.tls_issuer.clone(),
        tls_trusted: hello.tls_trusted,
        via_proxy: hello.via_proxy,
    };
    let inspect = if !hello.tls_issuer.is_empty() && !hello.tls_trusted {
        format!(" – TLS-Zertifikat nicht oeffentlich vertrauenswuerdig (Aussteller: {}) – HTTPS-Inspektion?", hello.tls_issuer)
    } else {
        String::new()
    };
    log!(
        "{}: verbunden von {remote} ({} {}){}{}",
        prt.peer.name,
        hello.os,
        hello.ver,
        if hello.via_proxy { " ueber Proxy" } else { "" },
        inspect
    );

    let (mut sink, mut stream) = ws.split();
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Vec<u8>>(16);

    let st_tx = st.clone();
    let mut sender = tokio::spawn(async move {
        loop {
            let mut buf = Vec::with_capacity(BUNDLE_TARGET + 2048);
            tokio::select! {
                c = ctrl_rx.recv() => {
                    let Some(c) = c else { return };
                    buf = c;
                }
                p = rx.recv() => {
                    let Some(p) = p else { return };
                    let (mut n, mut bytes) = (1u64, p.len() as u64);
                    push_record(&mut buf, REC_PACKET, &p);
                    while buf.len() < BUNDLE_TARGET {
                        match rx.try_recv() {
                            Ok(p) => { n += 1; bytes += p.len() as u64; push_record(&mut buf, REC_PACKET, &p); }
                            Err(_) => break,
                        }
                    }
                    st_tx.tx_packets.fetch_add(n, Relaxed);
                    st_tx.tx_bytes.fetch_add(bytes, Relaxed);
                }
            }
            if sealer.seal(&mut buf).is_err() {
                return;
            }
            if sink.send(Message::Binary(buf.into())).await.is_err() {
                return;
            }
        }
    });

    let st_rx = st.clone();
    let tun = sh.tuns[(sid as usize) % sh.tuns.len()].clone();
    let mut receiver = tokio::spawn(async move {
        loop {
            let msg = match tokio::time::timeout(Duration::from_secs(60), stream.next()).await {
                Ok(Some(Ok(m))) => m,
                _ => return,
            };
            let mut buf: Vec<u8> = match msg {
                Message::Binary(b) => b.into(),
                Message::Close(_) => return,
                _ => continue,
            };
            if opener.open(&mut buf).is_err() {
                return;
            }
            st_rx.last_seen.store(now_secs(), Relaxed);
            let (mut n, mut bytes) = (0u64, 0u64);
            let ok = for_each_record(&buf, |kind, data| match kind {
                REC_PACKET => {
                    // nur Pakete mit der eigenen Absender-Adresse (kein Faelschen fremder Adressen)
                    let src = src_ip(data);
                    if src == Some(ip4) || (src.is_some() && src == ip6) {
                        n += 1;
                        bytes += data.len() as u64;
                        let _ = tun.write_now(data);
                    } else {
                        st_rx.spoofed.fetch_add(1, Relaxed);
                    }
                }
                REC_PING if data.len() >= 8 => {
                    if data.len() >= 12 {
                        let rtt = u32::from_be_bytes(data[8..12].try_into().unwrap());
                        st_rx.rtt_us.store(rtt as u64, Relaxed);
                    }
                    let mut b = Vec::with_capacity(64);
                    push_record(&mut b, REC_PONG, &data[..8]);
                    let _ = ctrl_tx.try_send(b);
                }
                _ => {}
            });
            if ok.is_err() {
                return;
            }
            st_rx.rx_packets.fetch_add(n, Relaxed);
            st_rx.rx_bytes.fetch_add(bytes, Relaxed);
        }
    });

    let started = Instant::now();
    let why = tokio::select! {
        _ = &mut sender => "Senden beendet",
        _ = &mut receiver => "Verbindung beendet",
        _ = kick.notified() => "ersetzt/entfernt",
    };
    sender.abort();
    receiver.abort();
    {
        let mut r = sh.routes.write().unwrap();
        for a in [Some(ip4), ip6].into_iter().flatten() {
            if r.get(&a).map(|x| x.sid == sid).unwrap_or(false) {
                r.remove(&a);
            }
        }
    }
    let mut s = sh.sessions.lock().unwrap();
    if s.get(&cpub).map(|x| x.0 == sid).unwrap_or(false) {
        s.remove(&cpub);
        st.connected_since.store(0, Relaxed);
    }
    drop(s);
    log!("{}: getrennt ({why}) nach {} s", prt.peer.name, started.elapsed().as_secs());
}

// ------------------------------------------------------------------------------------------------ Hintergrund

/// jede Sekunde: Raten und Verlauf; jede Minute speichern; alle 3 s Konfiguration auf Aenderungen pruefen
pub fn spawn_background(sh: &Arc<Shared>) {
    let s = sh.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut n = 0u64;
        let mut mtime = std::fs::metadata(&s.cfg_path).and_then(|m| m.modified()).ok();
        loop {
            tick.tick().await;
            n += 1;
            let now = now_secs();
            let per: Vec<(String, u64, u64)> = s
                .peers
                .read()
                .unwrap()
                .values()
                .map(|p| {
                    let (r, t) = p.stats.tick();
                    (p.peer.name.clone(), r, t)
                })
                .collect();
            let path = format!("{}/stats.json", s.cfg().state_dir);
            let mut h = s.hist.lock().unwrap();
            h.add_second(now, &per);
            if n % 60 == 0 {
                h.save(&path);
            }
            drop(h);
            if n % 3 == 0 {
                let m = std::fs::metadata(&s.cfg_path).and_then(|m| m.modified()).ok();
                if m != mtime {
                    mtime = m;
                    s.reload();
                }
            }
        }
    });
}

pub fn save_stats(sh: &Shared) {
    let path = format!("{}/stats.json", sh.cfg().state_dir);
    sh.hist.lock().unwrap().save(&path);
}

// ------------------------------------------------------------------------------------------------ Zugriff Statistik

/// Heimnetz, VPN, Loopback und das eigene IPv6-Netz duerfen ohne Passwort
pub fn is_home(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        x => x,
    };
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local(),
        IpAddr::V6(a) => {
            let seg = a.segments();
            a.is_loopback() || (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80 || own_v6_nets().iter().any(|(n, p)| in_net6(a, *n, *p))
        }
    }
}

fn in_net6(a: std::net::Ipv6Addr, n: std::net::Ipv6Addr, p: u8) -> bool {
    if p == 0 {
        return true;
    }
    let m = !0u128 << (128 - p as u32);
    (u128::from(a) & m) == (u128::from(n) & m)
}

fn own_v6_nets() -> Vec<(std::net::Ipv6Addr, u8)> {
    let mut v = Vec::new();
    if let Ok(s) = std::fs::read_to_string("/proc/net/if_inet6") {
        for l in s.lines() {
            let p: Vec<&str> = l.split_whitespace().collect();
            if p.len() >= 6 && p[3] == "00" && !p[5].starts_with("wg") && !p[5].starts_with("kvpn") && !p[5].starts_with("docker") {
                if let (Ok(a), Ok(pl)) = (u128::from_str_radix(p[0], 16), u8::from_str_radix(p[2], 16)) {
                    v.push((std::net::Ipv6Addr::from(a), pl.min(64)));
                }
            }
        }
    }
    v
}

pub fn stats_token(cfg: &Config) -> String {
    let mut h = sha2::Sha256::new();
    h.update(b"krone-vpn-stats\0");
    h.update(cfg.stats_password.as_bytes());
    h.update(b"\0");
    h.update(cfg.private_key.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Brute-Force-Bremse: nach 5 Fehlversuchen pro Minute wird gesperrt
pub fn login_allowed(sh: &Shared) -> bool {
    let mut f = sh.login_fail.lock().unwrap();
    let now = now_secs();
    if now / 60 != f.0 {
        *f = (now / 60, 0);
    }
    f.1 < 5
}
pub fn login_failed(sh: &Shared) {
    sh.login_fail.lock().unwrap().1 += 1;
}
