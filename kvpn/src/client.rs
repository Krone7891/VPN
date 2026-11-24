//! Client-Logik fuer alle Plattformen: Verbinden, Handshake, Pakete tunneln, automatisch neu verbinden.
//!
//! Die Plattform liefert nur zwei Dinge: einen Kanal mit Paketen vom Betriebssystem (`tun_in`) und einen
//! `TunWriter`, der Pakete an das Betriebssystem zurueckgibt. Das TUN-Geraet bleibt beim Neuverbinden bestehen –
//! waehrend einer Unterbrechung geht also nichts unverschluesselt am Tunnel vorbei.

use crate::code::ClientConfig;
use crate::crypto::{self, Opener, Sealer};
use crate::proto::*;
use crate::transport::{self, ProtectFn, Proxy, TransportInfo};
use crate::util::now_nanos;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;

pub trait TunWriter: Send + Sync + 'static {
    /// ein IP-Paket an das Betriebssystem geben (darf nicht blockieren; bei Ueberlast verwerfen)
    fn write_packet(&self, pkt: &[u8]);
}

pub const ST_STOPPED: u8 = 0;
pub const ST_CONNECTING: u8 = 1;
pub const ST_CONNECTED: u8 = 2;
pub const ST_WAITING: u8 = 3;

#[derive(Default, Clone, Serialize)]
pub struct StatusInfo {
    pub last_error: String,
    pub tls_issuer: String,
    pub tls_trusted: bool,
    pub via_proxy: bool,
    pub server: String,
}

/// Zustand fuer die Anzeige (Konsole, Android-App)
#[derive(Default)]
pub struct Status {
    pub state: AtomicU8,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rtt_us: AtomicU64,
    pub connected_since: AtomicU64,
    pub connects: AtomicU64,
    pub info: Mutex<StatusInfo>,
}

#[derive(Serialize)]
struct StatusJson<'a> {
    state: &'a str,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rtt_ms: f64,
    connected_since: u64,
    connects: u64,
    #[serde(flatten)]
    info: StatusInfo,
}

impl Status {
    pub fn state_name(&self) -> &'static str {
        match self.state.load(Relaxed) {
            ST_CONNECTING => "connecting",
            ST_CONNECTED => "connected",
            ST_WAITING => "waiting",
            _ => "stopped",
        }
    }
    pub fn to_json(&self) -> String {
        serde_json::to_string(&StatusJson {
            state: self.state_name(),
            rx_bytes: self.rx_bytes.load(Relaxed),
            tx_bytes: self.tx_bytes.load(Relaxed),
            rx_packets: self.rx_packets.load(Relaxed),
            tx_packets: self.tx_packets.load(Relaxed),
            rtt_ms: self.rtt_us.load(Relaxed) as f64 / 1000.0,
            connected_since: self.connected_since.load(Relaxed),
            connects: self.connects.load(Relaxed),
            info: self.info.lock().unwrap().clone(),
        })
        .unwrap()
    }
    fn error(&self, e: &str) {
        self.info.lock().unwrap().last_error = e.to_string();
    }
}

pub struct ClientOptions {
    /// Wege zum Server, werden der Reihe nach probiert (None = direkt). Der zuletzt erfolgreiche bleibt vorn.
    pub routes: Vec<Option<Proxy>>,
    /// vor jedem Verbindungsaufbau mit der Ziel-IP aufgerufen
    pub protect: Option<ProtectFn>,
    /// gemerkte Server-Adressen (falls DNS waehrend des Neuverbindens nicht geht)
    pub dns: transport::DnsCache,
    /// von aussen ausgeloest (z. B. Android: Netzwechsel WLAN <-> Mobil): laufende Verbindung sofort neu aufbauen
    pub reconnect: Option<Arc<tokio::sync::Notify>>,
    /// wird nach jedem erfolgreichen Handshake aufgerufen
    pub on_connected: Option<Arc<dyn Fn(&crate::proto::Welcome, &TransportInfo) + Send + Sync>>,
    /// automatische Aktualisierung (None = aus)
    pub update: Option<Arc<crate::update::Updater>>,
}

static LAST_TS: AtomicU64 = AtomicU64::new(0);
fn hello_ts() -> u64 {
    // streng steigend, auch bei mehreren Verbindungen pro Sekunde
    let now = now_nanos();
    let mut prev = LAST_TS.load(Relaxed);
    loop {
        let next = now.max(prev + 1);
        match LAST_TS.compare_exchange(prev, next, Relaxed, Relaxed) {
            Ok(_) => return next,
            Err(p) => prev = p,
        }
    }
}

/// Verbinden und Handshake. Liefert WebSocket, Schluessel, Antwort des Servers und Transport-Infos.
pub async fn connect_once(
    cfg: &ClientConfig,
    proxy: Option<&Proxy>,
    protect: &Option<ProtectFn>,
    dns: &transport::DnsCache,
) -> Result<(transport::Ws, Sealer, Opener, Welcome, TransportInfo), String> {
    connect_once_with(cfg, proxy, protect, dns, false).await
}

/// wie `connect_once`; `upd` = dem Server melden, dass sich diese App selbst aktualisieren kann
pub async fn connect_once_with(
    cfg: &ClientConfig,
    proxy: Option<&Proxy>,
    protect: &Option<ProtectFn>,
    dns: &transport::DnsCache,
    upd: bool,
) -> Result<(transport::Ws, Sealer, Opener, Welcome, TransportInfo), String> {
    let (mut ws, info) = transport::connect(&cfg.url, proxy, protect, dns).await?;
    let hello = Hello {
        ts: hello_ts(),
        os: std::env::consts::OS.to_string(),
        ver: crate::VERSION.to_string(),
        tls_issuer: info.tls_issuer.clone(),
        tls_trusted: info.tls_trusted,
        via_proxy: info.via_proxy,
        upd,
        ciphers: vec![crate::proto::CIPHER_AES256.to_string()],
    };
    let (hs, m1) = crypto::client_init(&cfg.client_key()?, &cfg.server_key()?, &hello).map_err(|e| e.to_string())?;
    ws.send(Message::Binary(m1.into())).await.map_err(|e| format!("Senden fehlgeschlagen: {e}"))?;
    let m2 = loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
            Err(_) => return Err("Server antwortet nicht auf den Handshake".into()),
            Ok(None) | Ok(Some(Ok(Message::Close(_)))) => {
                return Err("Server hat den Handshake abgelehnt (Geraet entfernt, Code veraltet oder alle 8 Plaetze belegt)".into())
            }
            Ok(Some(Err(e))) => return Err(format!("Verbindung abgebrochen: {e}")),
            Ok(Some(Ok(Message::Binary(b)))) => break b,
            Ok(Some(Ok(_))) => continue,
        }
    };
    let (welcome, s, o) = crypto::client_finish(hs, &m2).map_err(|e| format!("Handshake fehlgeschlagen: {e}"))?;
    Ok((ws, s, o, welcome, info))
}

/// Hauptschleife: verbindet, haelt die Verbindung und verbindet bei Abbruch neu, bis `stop` auf true geht.
pub async fn run(
    cfg: ClientConfig,
    opts: ClientOptions,
    tun_in: mpsc::Receiver<Vec<u8>>,
    tun_out: Arc<dyn TunWriter>,
    status: Arc<Status>,
    mut stop: watch::Receiver<bool>,
) {
    let tun_in = Arc::new(tokio::sync::Mutex::new(tun_in));
    let mut backoff = 1u64;
    let mut routes = if opts.routes.is_empty() { vec![None] } else { opts.routes.clone() };
    while !*stop.borrow() {
        status.state.store(ST_CONNECTING, Relaxed);
        let attempt = tokio::select! {
            r = connect_once_with(&cfg, routes[0].as_ref(), &opts.protect, &opts.dns, opts.update.is_some()) => r,
            _ = stop.changed() => break,
        };
        if attempt.is_err() && routes.len() > 1 {
            routes.rotate_left(1); // naechster Weg (direkt <-> Proxy)
        }
        match attempt {
            Ok((ws, sealer, opener, welcome, info)) => {
                {
                    let mut i = status.info.lock().unwrap();
                    i.tls_issuer = info.tls_issuer.clone();
                    i.tls_trusted = info.tls_trusted;
                    i.via_proxy = info.via_proxy;
                    i.server = info.peer.map(|p| p.to_string()).unwrap_or_default();
                    i.last_error.clear();
                }
                if let (Some(u), Some(o)) = (&opts.update, &welcome.upd) {
                    u.offer(o);
                }
                if let Some(cb) = &opts.on_connected {
                    cb(&welcome, &info);
                }
                status.connects.fetch_add(1, Relaxed);
                status.connected_since.store(crate::util::now_secs(), Relaxed);
                status.state.store(ST_CONNECTED, Relaxed);
                let started = Instant::now();
                let kick = opts.reconnect.clone();
                // Netzwechsel-Signal, das schon waehrend des Verbindungsaufbaus kam, ist erledigt:
                // die neue Verbindung laeuft bereits ueber das aktuelle Netz (sonst sofort wieder getrennt)
                if let Some(k) = &kick {
                    let _ = futures_util::FutureExt::now_or_never(k.notified());
                }
                let r = tokio::select! {
                    r = session(ws, sealer, opener, tun_in.clone(), tun_out.clone(), status.clone(), stop.clone(), opts.update.clone()) => r,
                    _ = async { match &kick { Some(k) => k.notified().await, None => std::future::pending().await } } => {
                        backoff = 0;
                        Err("Netzwerk gewechselt – verbinde neu".to_string())
                    }
                };
                status.connected_since.store(0, Relaxed);
                if let Err(e) = r {
                    status.error(&e);
                }
                if started.elapsed() > Duration::from_secs(30) {
                    backoff = 1;
                }
            }
            Err(e) => {
                // vom Server abgelehnt (Geraet entfernt): nicht im Sekundentakt anklopfen
                if e.contains("abgelehnt") {
                    backoff = 30;
                }
                status.error(&e);
            }
        }
        if *stop.borrow() {
            break;
        }
        status.state.store(ST_WAITING, Relaxed);
        let kick = opts.reconnect.clone();
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(backoff * 1000 + 200)) => {}
            _ = stop.changed() => break,
            _ = async { match &kick { Some(k) => k.notified().await, None => std::future::pending().await } } => { backoff = 0; }
        }
        backoff = if backoff >= 30 { 10 } else { (backoff * 2).clamp(1, 10) };
    }
    status.state.store(ST_STOPPED, Relaxed);
}

/// eine bestehende Verbindung bedienen; Senden und Empfangen laufen als eigene Tasks (mehrere Kerne)
pub async fn session(
    ws: transport::Ws,
    mut sealer: Sealer,
    mut opener: Opener,
    tun_in: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
    tun_out: Arc<dyn TunWriter>,
    status: Arc<Status>,
    mut stop: watch::Receiver<bool>,
    update: Option<Arc<crate::update::Updater>>,
) -> Result<(), String> {
    let (mut sink, mut stream) = ws.split();
    let t0 = Instant::now();
    let st_tx = status.clone();
    let upd_rx = update.clone();

    let mut sender = tokio::spawn(async move {
        // neuere Version angeboten: Datei (weiter) anfordern
        if let Some(off) = update.as_ref().and_then(|u| u.request()) {
            let mut buf = Vec::with_capacity(64);
            push_record(&mut buf, REC_UPD_GET, &off.to_be_bytes());
            sealer.seal(&mut buf).map_err(|e| e.to_string())?;
            sink.send(Message::Binary(buf.into())).await.map_err(|e| format!("Senden fehlgeschlagen: {e}"))?;
        }
        let mut rx = tun_in.lock().await;
        let mut ping = tokio::time::interval(Duration::from_secs(10));
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let mut buf = Vec::with_capacity(BUNDLE_TARGET + 2048);
            tokio::select! {
                p = rx.recv() => {
                    let Some(p) = p else { return Err("TUN geschlossen".to_string()) };
                    let mut n = 0u64;
                    let mut bytes = 0u64;
                    if p.len() <= u16::MAX as usize { bytes += p.len() as u64; n += 1; push_record(&mut buf, REC_PACKET, &p); }
                    while buf.len() < BUNDLE_TARGET {
                        match rx.try_recv() {
                            Ok(p) if p.len() <= u16::MAX as usize => { bytes += p.len() as u64; n += 1; push_record(&mut buf, REC_PACKET, &p); }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                    st_tx.tx_packets.fetch_add(n, Relaxed);
                    st_tx.tx_bytes.fetch_add(bytes, Relaxed);
                }
                _ = ping.tick() => {
                    let mut d = [0u8; 12];
                    d[..8].copy_from_slice(&(t0.elapsed().as_micros() as u64).to_be_bytes());
                    d[8..].copy_from_slice(&(st_tx.rtt_us.load(Relaxed).min(u32::MAX as u64) as u32).to_be_bytes());
                    push_record(&mut buf, REC_PING, &d);
                    // Fuellbytes: Keepalives haben keine feste Groesse
                    let pad = vec![0u8; (rand::random::<u8>() % 96) as usize];
                    push_record(&mut buf, REC_PAD, &pad);
                }
            }
            sealer.seal(&mut buf).map_err(|e| e.to_string())?;
            sink.send(Message::Binary(buf.into())).await.map_err(|e| format!("Senden fehlgeschlagen: {e}"))?;
        }
    });

    let st_rx = status.clone();
    let mut receiver = tokio::spawn(async move {
        loop {
            let msg = match tokio::time::timeout(Duration::from_secs(35), stream.next()).await {
                Err(_) => return Err("keine Antwort vom Server seit 35 s – verbinde neu".to_string()),
                Ok(None) => return Err("Server hat die Verbindung beendet".to_string()),
                Ok(Some(Err(e))) => return Err(format!("Verbindung abgebrochen: {e}")),
                Ok(Some(Ok(m))) => m,
            };
            let mut buf: Vec<u8> = match msg {
                Message::Binary(b) => b.into(),
                Message::Close(_) => return Err("Server hat die Verbindung beendet".to_string()),
                _ => continue,
            };
            opener.open(&mut buf).map_err(|e| e.to_string())?;
            let (mut n, mut bytes) = (0u64, 0u64);
            for_each_record(&buf, |kind, data| match kind {
                REC_PACKET => {
                    n += 1;
                    bytes += data.len() as u64;
                    tun_out.write_packet(data);
                }
                REC_PONG if data.len() >= 8 => {
                    let sent = u64::from_be_bytes(data[..8].try_into().unwrap());
                    let now = t0.elapsed().as_micros() as u64;
                    st_rx.rtt_us.store(now.saturating_sub(sent), Relaxed);
                }
                REC_UPD_DATA => {
                    if let Some(u) = &upd_rx {
                        u.data(data);
                    }
                }
                _ => {}
            })?;
            st_rx.rx_packets.fetch_add(n, Relaxed);
            st_rx.rx_bytes.fetch_add(bytes, Relaxed);
        }
    });

    let r = tokio::select! {
        r = &mut sender => r.unwrap_or_else(|e| Err(e.to_string())),
        r = &mut receiver => r.unwrap_or_else(|e| Err(e.to_string())),
        _ = stop.changed() => Ok(()),
    };
    sender.abort();
    receiver.abort();
    r
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    /// ein Netzwechsel-Signal aus der Aufbauphase darf die neue Verbindung nicht sofort beenden
    #[tokio::test]
    async fn altes_netzwechsel_signal_wird_verworfen() {
        let k = std::sync::Arc::new(tokio::sync::Notify::new());
        k.notify_one(); // kam waehrend connect_once
        let _ = futures_util::FutureExt::now_or_never(k.notified());
        let r = tokio::time::timeout(Duration::from_millis(50), k.notified()).await;
        assert!(r.is_err(), "altes Signal haette die Verbindung sofort getrennt");
        // ein neues Signal wirkt weiterhin
        let k2 = k.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            k2.notify_one();
        });
        assert!(tokio::time::timeout(Duration::from_millis(500), k.notified()).await.is_ok());
    }
}
