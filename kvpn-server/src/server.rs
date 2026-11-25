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
    /// (Leistungsmodus, Admin-Seite im VPN) wie beim Start – Aenderungen daran gelten erst nach einem Neustart
    pub boot: (bool, bool),
    pub tun_drops: AtomicU64,
    handshake_slots: Semaphore,
    login_fail: Mutex<(u64, u32)>,
    /// Steuer-Kanal je verbundenem Geraet (Name -> (Sitzung, Sender)) fuer Anpingen und Orten von der Admin-Seite
    ctrl: Mutex<HashMap<String, (u64, mpsc::Sender<Vec<u8>>)>>,
    /// offene stille Pings: id -> Antwort
    pings: Mutex<HashMap<u32, tokio::sync::oneshot::Sender<()>>>,
    next_ping: std::sync::atomic::AtomicU32,
    /// eigener DNS im Tunnel (Werbe-Blocker, Heimnetz-Namen)
    pub dns: crate::dns::Shared,
    /// eigener DNS beim Start an? (Aenderung gilt erst nach Neustart)
    pub dns_boot: bool,
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
            boot: (cfg.performance, cfg.admin_addr().is_some()),
            tuns,
            next_sid: AtomicU64::new(1),
            hist: Mutex::new(hist),
            started: now_secs(),
            tun_drops: AtomicU64::new(0),
            handshake_slots: Semaphore::new(32),
            login_fail: Mutex::new((0, 0)),
            ctrl: Mutex::new(HashMap::new()),
            pings: Mutex::new(HashMap::new()),
            next_ping: std::sync::atomic::AtomicU32::new(1),
            dns: crate::dns::Dns::new(cfg.adblock),
            dns_boot: cfg.dns_proxy,
        });
        sh.dns.set_own(&cfg.dns_block, &cfg.dns_allow);
        sh.apply_peers(&cfg);
        sh
    }

    /// verbundene Geraete mit aelterer App neu verbinden lassen (bekommen dabei das Update angeboten)
    pub fn kick_outdated(&self, m: &kvpn::update::Manifest) -> usize {
        let peers = self.peers.read().unwrap();
        let sessions = self.sessions.lock().unwrap();
        let mut n = 0;
        for (k, p) in peers.iter() {
            let i = p.stats.info.lock().unwrap().clone();
            if i.upd && m.version_for(&i.os).map(|v| kvpn::update::newer(v, &i.ver)).unwrap_or(false) {
                if let Some((_, kick)) = sessions.get(k) {
                    kick.notify_one();
                    n += 1;
                }
            }
        }
        n
    }

    /// Geraet still anpingen (Admin-Seite): Antwortzeit in Millisekunden. Der VPN-Kern im Geraet antwortet selbst –
    /// auf dem Geraet erscheint nichts.
    pub async fn ping_device(&self, name: &str) -> Result<f64, String> {
        let tx = self.ctrl.lock().unwrap().get(name).map(|x| x.1.clone()).ok_or("nicht verbunden")?;
        let id = self.next_ping.fetch_add(1, Relaxed);
        let (otx, orx) = tokio::sync::oneshot::channel();
        self.pings.lock().unwrap().insert(id, otx);
        let mut b = Vec::with_capacity(16);
        push_record(&mut b, REC_SPING, &id.to_be_bytes());
        let t = Instant::now();
        let r = match tx.send(b).await {
            Err(_) => Err("Verbindung wurde gerade beendet".to_string()),
            Ok(()) => match tokio::time::timeout(Duration::from_secs(6), orx).await {
                Ok(Ok(())) => Ok(t.elapsed().as_secs_f64() * 1000.0),
                _ => Err("keine Antwort in 6 s (App älter als 1.1.0 oder Verbindung hängt)".to_string()),
            },
        };
        self.pings.lock().unwrap().remove(&id);
        r
    }

    /// "Jetzt orten": Geraet soll einen frischen Standort holen und melden
    pub fn locate_device(&self, name: &str) -> Result<(), String> {
        let tx = self.ctrl.lock().unwrap().get(name).map(|x| x.1.clone()).ok_or("nicht verbunden")?;
        let mut b = Vec::with_capacity(16);
        push_record(&mut b, REC_LOCATE, &self.next_ping.fetch_add(1, Relaxed).to_be_bytes());
        tx.try_send(b).map_err(|_| "Verbindung ausgelastet – gleich nochmal".to_string())
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
        self.reload_quiet(false)
    }

    /// `quiet`: nur melden, wenn sich an den Geraeten etwas geaendert hat (regelmaessige Pruefung auf Ablaufdatum)
    pub fn reload_quiet(&self, quiet: bool) {
        match Config::load(&self.cfg_path) {
            Ok(c) => {
                let old = self.cfg();
                if c.private_key != old.private_key || c.net4 != old.net4 || c.net6 != old.net6 {
                    log!("Hinweis: Schluessel/Netz geaendert – das gilt erst nach einem Neustart des Dienstes");
                }
                if c.performance != old.performance || c.queues != old.queues {
                    log!("Hinweis: Leistungsmodus geaendert – das gilt erst nach einem Neustart des Dienstes");
                }
                let changed = c.peers != old.peers || c.inactive != old.inactive;
                self.apply_peers(&c);
                self.dns.on.store(c.adblock, Relaxed);
                self.dns.set_own(&c.dns_block, &c.dns_allow);
                if c.adblock != old.adblock {
                    log!("Werbe-Blocker {}", if c.adblock { "an" } else { "aus" });
                }
                if c.lan_access != old.lan_access && c.nat {
                    crate::netsetup::lan_block(&c, !c.lan_access);
                    log!("Heimnetz fuer die Geraete {}", if c.lan_access { "freigegeben" } else { "gesperrt (nur Internet)" });
                }
                if c.dns_proxy != old.dns_proxy {
                    log!("Hinweis: eigener DNS geaendert – das gilt erst nach einem Neustart des Dienstes");
                }
                *self.cfg.write().unwrap() = Arc::new(c);
                if !quiet || changed {
                    let cfg = self.cfg();
                    log!(
                        "Konfiguration neu geladen: {} Geraet(e){}",
                        cfg.peers.len(),
                        if cfg.inactive.is_empty() { String::new() } else { format!(", {} gesperrt/abgelaufen", cfg.inactive.len()) }
                    );
                }
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
    handle_http(sh, s, peer, true, false).await
}

/// lokale Webseite (http://localhost:8180): nur Statistik und Downloads, kein Tunnel, keine fremden Absender
pub async fn handle_local<S>(sh: Arc<Shared>, s: S, peer: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_http(sh, s, peer, false, false).await
}

/// Admin-Seite im VPN (nur fuer verbundene Geraete, mit Passwort)
pub async fn handle_admin<S>(sh: Arc<Shared>, s: S, peer: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_http(sh, s, peer, false, true).await
}

async fn handle_http<S>(sh: Arc<Shared>, mut s: S, peer: SocketAddr, tunnel_ok: bool, vpn_admin: bool)
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
    if vpn_admin {
        // nur aus dem Tunnel-Netz
        let inside = match (remote, cfg.net4()) {
            (IpAddr::V4(a), Ok((n, p))) => p == 0 || (u32::from(a) ^ u32::from(n)) >> (32 - p as u32) == 0,
            _ => false,
        };
        if !inside {
            return;
        }
    }
    let query = target.split_once('?').map(|x| x.1).unwrap_or("");
    crate::web::handle(&sh, &mut s, &method, &path, query, &headers, remote, tunnel_ok && peer.ip().is_loopback(), !tunnel_ok && !vpn_admin, vpn_admin).await;
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
    let mut welcome = cfg.welcome(&prt.peer);
    let upd = if hello.upd { update_offer(&cfg, &hello.os, &hello.ver) } else { None };
    welcome.upd = upd.as_ref().map(|u| u.offer.clone());
    // Verschluesselung: Apps ab 1.1.0 waehlen selbst (Auto = nach Prozessor), aeltere nach Einstellung `aes256`
    welcome.cipher = crypto::choose_cipher(&hello, cfg.aes256);
    // Tarn-Profil fuer genau diese Verbindung (bei jeder neu ausgewuerfelt) – nur Apps, die es verstehen
    let tarn = if hello.pick { kvpn::proto::Tarn::random(cfg.performance) } else { kvpn::proto::Tarn::alt() };
    if hello.pick {
        welcome.tarn = Some(tarn);
        welcome.pad = kvpn::tarn::fuellzeichen(160);
    }
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
    sh.hist.lock().unwrap().add_connect(now_secs(), &prt.peer.name);
    st.connected_since.store(now_secs(), Relaxed);
    st.last_seen.store(now_secs(), Relaxed);
    // schon uebertragenes Update merken, bis das Geraet mit der neuen Version kommt
    let prev_sent = st.info.lock().unwrap().upd_sent.clone();
    let upd_sent = if !prev_sent.is_empty() && kvpn::update::newer(&prev_sent, &hello.ver) { prev_sent } else { String::new() };
    *st.info.lock().unwrap() = SessInfo {
        remote: remote.to_string(),
        os: hello.os.clone(),
        ver: hello.ver.clone(),
        tls_issuer: hello.tls_issuer.clone(),
        tls_trusted: hello.tls_trusted,
        via_proxy: hello.via_proxy,
        upd: hello.upd,
        cipher: if welcome.cipher.is_empty() { kvpn::proto::CIPHER_CHACHA.into() } else { welcome.cipher.clone() },
        upd_sent,
    };
    let inspect = if !hello.tls_issuer.is_empty() && !hello.tls_trusted {
        format!(" – TLS-Zertifikat nicht oeffentlich vertrauenswuerdig (Aussteller: {}) – HTTPS-Inspektion?", hello.tls_issuer)
    } else {
        String::new()
    };
    log!(
        "{}: verbunden von {remote} ({} {}){}{}{}",
        prt.peer.name,
        hello.os,
        hello.ver,
        if hello.via_proxy { " ueber Proxy" } else { "" },
        if hello.pick { format!(", {}", crypto::cipher_label(&welcome.cipher)) } else if welcome.cipher.is_empty() { String::new() } else { ", AES-256".into() },
        inspect
    );
    // Ort der IP-Adresse in den Standort-Verlauf (Bewegungs-Karte)
    if cfg.geo {
        crate::geo::verlauf_ip(&cfg.state_dir, &prt.peer.name, &remote.to_string());
    }
    {
        // erstes Verbinden eines Geraets -> Benachrichtigung (falls eingerichtet)
        let (sh2, n, k, os, von) = (sh.clone(), prt.peer.name.clone(), prt.peer.public_key.clone(), hello.os.clone(), remote.to_string());
        tokio::task::spawn_blocking(move || crate::notify::device_connected(&sh2, &n, &k, &os, &von));
    }
    if cfg.users {
        let (p, n, ev) = (sh.cfg_path.clone(), prt.peer.name.clone(), format!("verbunden von {remote} ({} {}){}", hello.os, hello.ver, if hello.via_proxy { " ueber Proxy" } else { "" }));
        tokio::task::spawn_blocking(move || crate::users::log_event(&p, &n, &ev));
    }

    // Fliessband: TLS/WebSocket senden und empfangen laufen in eigenen Tasks (weitere Kerne)
    let (sink, stream) = ws.split();
    let (out, _, _w) = kvpn::pipe::writer(sink, 64);
    let (mut inc, _r) = kvpn::pipe::reader(stream, 64);
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Vec<u8>>(16);
    sh.ctrl.lock().unwrap().insert(prt.peer.name.clone(), (sid, ctrl_tx.clone()));

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
            tarn.fuellen(&mut buf);
            if sealer.seal(&mut buf).is_err() {
                return;
            }
            if out.send(buf).await.is_err() {
                return;
            }
        }
    });

    if let Some(u) = &upd {
        log!("{}: Update {} -> {} angeboten", prt.peer.name, hello.ver, u.version);
    }
    let st_rx = st.clone();
    let tun = sh.tuns[(sid as usize) % sh.tuns.len()].clone();
    let upd_sending = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let peer_name = prt.peer.name.clone();
    let st_upd = st.clone();
    let sh_rx = sh.clone();
    // Geschwindigkeitstest: hoechstens einer je Verbindung gleichzeitig; Upload-Messung (Bytes, erstes/letztes Stueck)
    let speed_busy = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut up_meas: (u64, Option<Instant>, Option<Instant>) = (0, None, None);
    let mut receiver = tokio::spawn(async move {
        loop {
            let mut buf = match tokio::time::timeout(Duration::from_secs(60), inc.recv()).await {
                Ok(Some(kvpn::pipe::Rein::Daten(b))) => b,
                _ => return,
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
                // Absturz-Protokoll der App -> Ordner auf dem Server, dann bestaetigen
                REC_CRASH => {
                    let c = sh_rx.cfg();
                    if let Some(n) = crate::absturz::speichern(&c.state_dir, &peer_name, data) {
                        let mut b = Vec::with_capacity(n.len() + 3);
                        push_record(&mut b, REC_CRASH_OK, n.as_bytes());
                        let _ = ctrl_tx.try_send(b);
                    }
                }
                REC_SPONG if data.len() >= 4 => {
                    let id = u32::from_be_bytes(data[..4].try_into().unwrap());
                    if let Some(t) = sh_rx.pings.lock().unwrap().remove(&id) {
                        let _ = t.send(());
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
                // vom Geraet freigegebene Angaben (WLAN-Name, Standort) – nur fuer die Admin-Seite
                REC_INFO if data.len() <= kvpn::proto::MAX_INFO => {
                    // WLAN-Ortung (Google/WiGLE) nur mit eingeschaltetem Standort; Zugangsdaten gelten sofort
                    let c = sh_rx.cfg();
                    let keys = if c.geo { crate::geo::WlanKeys::from_cfg(&c) } else { Default::default() };
                    // (Default: keine WLAN-Ortung, kein Verlauf)
                    crate::geo::device_report(&c.state_dir, &peer_name, data, &keys)
                }
                // eigenes Logo fuer die App (Stuecke ueber den Steuer-Kanal)
                kvpn::proto::REC_LOGO_GET => {
                    let c = sh_rx.cfg();
                    if let Some(png) = crate::web::logo_app_data(&c.state_dir) {
                        let ctrl = ctrl_tx.clone();
                        let name = peer_name.clone();
                        tokio::spawn(async move {
                            for st in kvpn::logo::stuecke(&png) {
                                let mut b = Vec::with_capacity(st.len() + 8);
                                push_record(&mut b, kvpn::proto::REC_LOGO, &st);
                                if ctrl.send(b).await.is_err() {
                                    return;
                                }
                            }
                            log!("{name}: Logo uebertragen ({} KB)", png.len() / 1024);
                        });
                    }
                }
                kvpn::proto::REC_SPEED_GET if data.len() >= 2 => {
                    if !speed_busy.swap(true, Relaxed) {
                        let ms = u16::from_be_bytes([data[0], data[1]]).clamp(500, kvpn::proto::SPEED_MAX_MS);
                        up_meas = (0, None, None);
                        tokio::spawn(speed_down(ms, ctrl_tx.clone(), speed_busy.clone(), peer_name.clone()));
                    }
                }
                kvpn::proto::REC_SPEED_DATA => {
                    let now = Instant::now();
                    up_meas.0 += data.len() as u64;
                    up_meas.1.get_or_insert(now);
                    up_meas.2 = Some(now);
                }
                kvpn::proto::REC_SPEED_UP_END => {
                    let us = match up_meas {
                        (_, Some(a), Some(b)) => b.duration_since(a).as_micros() as u64,
                        _ => 0,
                    };
                    let mut b = Vec::with_capacity(24);
                    push_record(&mut b, kvpn::proto::REC_SPEED_RES, &kvpn::proto::speed_res(2, up_meas.0, us));
                    let _ = ctrl_tx.try_send(b);
                    log!("{peer_name}: Geschwindigkeitstest Upload {:.1} Mbit/s", kvpn::proto::mbit(up_meas.0, us));
                    up_meas = (0, None, None);
                }
                REC_UPD_GET if data.len() >= 4 => {
                    if let Some(u) = &upd {
                        if !upd_sending.swap(true, Relaxed) {
                            let from = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
                            tokio::spawn(send_update(u.path.clone(), u.version.clone(), from, ctrl_tx.clone(), peer_name.clone(), st_upd.clone()));
                        }
                    }
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
    {
        let mut c = sh.ctrl.lock().unwrap();
        if c.get(&prt.peer.name).map(|x| x.0 == sid).unwrap_or(false) {
            c.remove(&prt.peer.name);
        }
    }
    let mut s = sh.sessions.lock().unwrap();
    if s.get(&cpub).map(|x| x.0 == sid).unwrap_or(false) {
        s.remove(&cpub);
        st.connected_since.store(0, Relaxed);
    }
    drop(s);
    log!("{}: getrennt ({why}) nach {} s", prt.peer.name, started.elapsed().as_secs());
    if sh.cfg().users {
        let (p, n, ev) = (sh.cfg_path.clone(), prt.peer.name.clone(), format!("getrennt ({why}) nach {} s", started.elapsed().as_secs()));
        tokio::task::spawn_blocking(move || crate::users::log_event(&p, &n, &ev));
    }
}

// ------------------------------------------------------------------------------------------------ Updates

struct UpdFile {
    offer: kvpn::proto::UpdateOffer,
    path: std::path::PathBuf,
    version: String,
}

/// neuere App fuer dieses Geraet? Liegt in <state_dir>/update (update.json + update.json.sig + Dateien)
fn update_offer(cfg: &Config, os: &str, ver: &str) -> Option<UpdFile> {
    let dir = std::path::Path::new(&cfg.state_dir).join("update");
    let manifest = std::fs::read_to_string(dir.join("update.json")).ok()?;
    let sig = std::fs::read_to_string(dir.join("update.json.sig")).ok()?;
    let m = match kvpn::update::verify(&manifest, &sig) {
        Ok(m) => m,
        Err(e) => {
            log!("Update in {}: {e}", dir.display());
            return None;
        }
    };
    // nur wenn sich die App DIESES Geraets geaendert hat (jede App hat ihre eigene Version)
    let fver = m.version_for(os)?.to_string();
    if !kvpn::update::newer(&fver, ver) {
        return None;
    }
    let f = m.files.get(os)?;
    if f.name.contains(['/', '\\']) || f.name.starts_with('.') {
        return None;
    }
    let path = dir.join(&f.name);
    match std::fs::metadata(&path) {
        Ok(md) if md.len() == f.size => {}
        _ => {
            log!("Update {fver}: {} fehlt oder hat die falsche Groesse", path.display());
            return None;
        }
    }
    Some(UpdFile { offer: kvpn::proto::UpdateOffer { manifest, sig }, path, version: fver })
}

/// Update-Datei stueckweise ueber die Verbindung senden (Gegendruck ueber den Steuer-Kanal; endet mit der Verbindung)
async fn send_update(path: std::path::PathBuf, version: String, from: usize, ctrl: mpsc::Sender<Vec<u8>>, name: String, st: Arc<PeerStats>) {
    let Ok(data) = tokio::fs::read(&path).await else { return };
    let mut off = from.min(data.len());
    while off < data.len() {
        let end = (off + kvpn::update::CHUNK).min(data.len());
        let mut rec = Vec::with_capacity(end - off + 4);
        rec.extend_from_slice(&(off as u32).to_be_bytes());
        rec.extend_from_slice(&data[off..end]);
        let mut b = Vec::with_capacity(rec.len() + 16);
        push_record(&mut b, REC_UPD_DATA, &rec);
        if ctrl.send(b).await.is_err() {
            return;
        }
        off = end;
    }
    log!("{name}: Update {version} uebertragen ({} KB)", (data.len() - from.min(data.len())) / 1024);
    st.info.lock().unwrap().upd_sent = version;
}

/// Geschwindigkeitstest Download: Fuelldaten ueber den Steuer-Kanal (Gegendruck = so schnell wie die Verbindung)
async fn speed_down(ms: u16, ctrl: mpsc::Sender<Vec<u8>>, busy: Arc<std::sync::atomic::AtomicBool>, name: String) {
    let filler = vec![0u8; kvpn::proto::SPEED_CHUNK];
    let t0 = Instant::now();
    let end = t0 + Duration::from_millis(ms as u64);
    let mut bytes = 0u64;
    while Instant::now() < end {
        let mut b = Vec::with_capacity(2 * filler.len() + 16);
        push_record(&mut b, kvpn::proto::REC_SPEED_DATA, &filler);
        push_record(&mut b, kvpn::proto::REC_SPEED_DATA, &filler);
        if ctrl.send(b).await.is_err() {
            busy.store(false, Relaxed);
            return;
        }
        bytes += 2 * filler.len() as u64;
    }
    let us = t0.elapsed().as_micros() as u64;
    let mut b = Vec::with_capacity(24);
    push_record(&mut b, kvpn::proto::REC_SPEED_RES, &kvpn::proto::speed_res(1, bytes, us));
    let _ = ctrl.send(b).await;
    log!("{name}: Geschwindigkeitstest Download {:.1} Mbit/s (gesendet)", kvpn::proto::mbit(bytes, us));
    // naechster Test fruehestens nach dem Upload
    tokio::time::sleep(Duration::from_secs(8)).await;
    busy.store(false, Relaxed);
}

// ------------------------------------------------------------------------------------------------ Hintergrund

/// jede Sekunde: Raten und Verlauf; jede Minute speichern; alle 3 s Konfiguration auf Aenderungen pruefen
pub fn spawn_background(sh: &Arc<Shared>) {
    // alle 6 Stunden bei GitHub nach einer neuen App-Version schauen – nur vormerken und melden, nicht verteilen
    let s2 = sh.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(20)).await;
        let mut told = String::new();
        loop {
            let cfg = s2.cfg();
            if cfg.update_check {
                let c = cfg.clone();
                match tokio::task::spawn_blocking(move || crate::updates::check(&c)).await {
                    Ok(Ok(Some((m, text, sig)))) => {
                        crate::updates::remember(&cfg, &text, &sig);
                        if told != m.version {
                            log!("Neue App-Version {} auf GitHub ({}) – an die Geraete verteilen mit: kvpn-server update", m.version, cfg.update_repo);
                            crate::notify::event_cfg(&cfg, crate::notify::Ereignis::Update { version: m.version.clone() });
                            told = m.version;
                        }
                    }
                    Ok(Err(e)) => log!("Update-Pruefung bei GitHub: {e}"),
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        }
    });
    let s = sh.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut n = 0u64;
        let mut mtime = std::fs::metadata(&s.cfg_path).and_then(|m| m.modified()).ok();
        let db_file = crate::users::db_path(&s.cfg_path);
        let mut db_mtime = std::fs::metadata(&db_file).and_then(|m| m.modified()).ok();
        let upd_file = |s: &Shared| crate::updates::dir(&s.cfg()).join("update.json");
        let mut upd_mtime = std::fs::metadata(upd_file(&s)).and_then(|m| m.modified()).ok();
        let mut dns_last = (0u64, 0u64);
        let mut month_seen = String::new();
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
            let online: Vec<String> =
                s.peers.read().unwrap().values().filter(|p| p.stats.connected_since.load(Relaxed) > 0).map(|p| p.peer.name.clone()).collect();
            let (dq, db) = (s.dns.total.queries.load(Relaxed), s.dns.total.blocked.load(Relaxed));
            let mut h = s.hist.lock().unwrap();
            h.add_second(now, &per);
            h.add_online(now, &online);
            h.add_dns(now, dq.saturating_sub(dns_last.0), db.saturating_sub(dns_last.1));
            dns_last = (dq, db);
            // Monatswechsel: Bericht des letzten Monats als Benachrichtigung
            let month = crate::stats::local_date(now)[..7].to_string();
            if month_seen.is_empty() {
                month_seen = month.clone();
            } else if month != month_seen {
                let b = h.bericht(&month_seen, now);
                crate::notify::event(&s, crate::notify::Ereignis::Bericht { text: crate::stats::bericht_text(&b, s.cfg().display_name()) });
                month_seen = month;
            }
            if n % 60 == 0 {
                h.save(&path);
            }
            drop(h);
            if n % 3 == 0 {
                let m = std::fs::metadata(&s.cfg_path).and_then(|m| m.modified()).ok();
                // Benutzerverwaltung: Aenderungen in benutzer.db (sperren, entfernen, ...) sofort uebernehmen
                let dm = std::fs::metadata(&db_file).and_then(|m| m.modified()).ok();
                if m != mtime {
                    mtime = m;
                    db_mtime = dm;
                    s.reload();
                } else if dm != db_mtime && s.cfg().users {
                    db_mtime = dm;
                    s.reload();
                } else if n % 60 == 0 && s.cfg().users {
                    // Ablaufdaten pruefen
                    s.reload_quiet(true);
                }
                // neue App-Version freigegeben: Geraete mit aelterer Version kurz neu verbinden lassen -> Angebot
                let um = std::fs::metadata(upd_file(&s)).and_then(|m| m.modified()).ok();
                if um != upd_mtime {
                    upd_mtime = um;
                    if let Some(m) = crate::updates::offered(&s.cfg()) {
                        let n = s.kick_outdated(&m);
                        log!("App-Update {} freigegeben – {n} Geraet(e) bekommen es jetzt", m.version);
                    }
                }
            }
        }
    });
}

/// jede Minute: "lebt" merken, ueberwachte Geraete pruefen; alle 10 Minuten Erreichbarkeit und taegliche Sicherung
pub fn spawn_waechter(sh: &Arc<Shared>) {
    let s = sh.clone();
    tokio::spawn(async move {
        let mut w = crate::ausfall::Waechter::default();
        w.extern_passte = crate::ausfall::passte_laden(&s.cfg());
        let mut n = 0u64;
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            let c = s.cfg();
            let now = now_secs();
            crate::ausfall::lebt(&c, now);
            // ueberwachte Geraete
            if !c.ausfall_geraete.is_empty() {
                let mut letzte: HashMap<String, (bool, u64)> = HashMap::new();
                for p in s.peers.read().unwrap().values() {
                    letzte.insert(p.peer.name.clone(), (p.stats.connected_since.load(Relaxed) > 0, p.stats.last_seen.load(Relaxed)));
                }
                for (t, x) in w.geraete(&c, &letzte, s.started, now) {
                    log!("Ausfall-Alarm: {t}");
                    crate::notify::event_cfg(&c, crate::notify::Ereignis::Ausfall { titel: t, text: x });
                }
            }
            if n % 10 == 0 {
                // von aussen erreichbar? (DynDNS zeigt auf den eigenen Anschluss)
                if c.ausfall_extern {
                    let c2 = c.clone();
                    if let Ok(r) = tokio::task::spawn_blocking(move || crate::ausfall::extern_pruefen(&c2)).await {
                        let vorher = w.extern_passte;
                        if let Some((ok, t)) = &r {
                            if !ok {
                                log!("Erreichbarkeit: {t}");
                            }
                        }
                        if let Some((t, x)) = w.extern_ergebnis(r) {
                            log!("Ausfall-Alarm: {t}");
                            crate::notify::event_cfg(&c, crate::notify::Ereignis::Ausfall { titel: t, text: x });
                        }
                        if w.extern_passte && !vorher {
                            crate::ausfall::passte_merken(&c);
                        }
                    }
                }
                // abgelaufene Gaeste entfernen
                if c.users {
                    let p = s.cfg_path.clone();
                    if let Ok(weg) = tokio::task::spawn_blocking(move || crate::gast::aufraeumen(&p)).await {
                        for d in &weg {
                            log!("{d}: Gast-Zugang abgelaufen – entfernt");
                        }
                        if !weg.is_empty() {
                            s.reload();
                        }
                    }
                }
                // taegliche Sicherung
                if crate::sicherung::due(&c) {
                    let (c2, p) = (c.clone(), s.cfg_path.clone());
                    match tokio::task::spawn_blocking(move || crate::sicherung::create(&p, &c2, "").map(|f| (f, crate::sicherung::prune(&c2)))).await {
                        Ok(Ok((f, alt))) => log!("Sicherung angelegt: {}{}", f.display(), if alt > 0 { format!(" ({alt} alte entfernt)") } else { String::new() }),
                        Ok(Err(e)) => {
                            log!("Sicherung fehlgeschlagen: {e}");
                            crate::notify::event_cfg(&c, crate::notify::Ereignis::Ausfall { titel: "Sicherung fehlgeschlagen".into(), text: format!("Die tägliche Sicherung ging schief: {e}") });
                        }
                        Err(_) => {}
                    }
                }
            }
            n += 1;
            tokio::time::sleep(Duration::from_secs(std::env::var("KVPN_WAECHTER_S").ok().and_then(|x| x.parse().ok()).unwrap_or(60))).await;
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
