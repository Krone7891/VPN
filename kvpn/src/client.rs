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
use serde::{Deserialize, Serialize};
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
    /// letzter Fehler in Klartext (fuer die Anzeige)
    pub last_error: String,
    /// derselbe Fehler technisch (fuers Protokoll / "Details")
    pub last_error_detail: String,
    pub tls_issuer: String,
    pub tls_trusted: bool,
    pub via_proxy: bool,
    pub server: String,
    /// Verschluesselung der laufenden Verbindung ("AES-256-GCM" / "ChaCha20-Poly1305")
    pub cipher: String,
    /// eingestellte Wahl in der App ("auto", "aes", "chacha")
    pub cipher_choice: String,
    /// Prozessor hat AES-Befehle
    pub aes_hw: bool,
}

/// Geschwindigkeitstest (Anzeige in den Apps). Zustand: "" (nie), "laeuft", "fertig", "fehler"
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Speed {
    pub state: String,
    /// gerade gemessen: "ping", "down", "up"
    pub phase: String,
    pub ping_ms: f64,
    pub down_mbps: f64,
    pub up_mbps: f64,
    pub error: String,
    /// Zeitpunkt des Ergebnisses (Unix-Sekunden)
    pub at: u64,
    #[serde(skip)]
    #[doc(hidden)]
    pub t_start: Option<Instant>,
    #[serde(skip)]
    #[doc(hidden)]
    pub t_phase: Option<Instant>,
    #[serde(skip)]
    #[doc(hidden)]
    pub down_first: Option<Instant>,
    #[serde(skip)]
    #[doc(hidden)]
    pub down_bytes: u64,
}

impl Speed {
    pub fn laeuft(&self) -> bool {
        self.state == "laeuft"
    }
    pub fn fehler(&mut self, e: &str) {
        self.state = "fehler".into();
        self.phase.clear();
        self.error = e.into();
        self.at = crate::util::now_secs();
    }
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
    /// Angaben fuer den Server (REC_INFO): (Zaehler, JSON) – wird bei jeder Aenderung und nach jedem Verbinden gesendet
    pub report: Mutex<(u64, Vec<u8>)>,
    /// Zaehler der Orten-Anfragen von der Admin-Seite (REC_LOCATE); die App holt dann einen frischen Standort
    pub locate: AtomicU64,
    /// Absturz-Protokolle fuer den Server: (Name, Text); gehen nach dem Verbinden hinaus
    pub crash_out: Mutex<Vec<(String, Vec<u8>)>>,
    /// vom Server bestaetigt (Name) – die App darf ihre Kopie loeschen
    pub crash_ok: Mutex<Vec<String>>,
    /// Ordner fuer das Logo des Servers (logo.png + logo.id); None = App will keins
    pub logo_dir: Mutex<Option<std::path::PathBuf>>,
    /// zaehlt hoch, wenn sich das Logo geaendert hat (neu oder entfernt) – die App zeigt es dann an
    pub logo_seq: AtomicU64,
    /// Geschwindigkeitstest: Zustand und Ergebnis
    pub speed: Mutex<Speed>,
    /// Geschwindigkeitstest starten (von der App)
    pub speed_go: tokio::sync::Notify,
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
    locate: u64,
    crash_ok: Vec<String>,
    speed: Speed,
    #[serde(flatten)]
    info: StatusInfo,
}

impl Status {
    /// Angaben des Geraets an den Server melden (z. B. {"ssid":…,"lat":…,"lon":…}); leer = nichts
    pub fn set_report(&self, json: &[u8]) {
        if json.len() > crate::proto::MAX_INFO {
            return;
        }
        let mut r = self.report.lock().unwrap();
        r.0 += 1;
        r.1 = json.to_vec();
    }

    /// Absturz-Protokoll zum Senden vormerken (Name = Dateiname, z. B. "1764000000-java.txt")
    pub fn add_crash(&self, name: &str, text: &[u8]) {
        let name: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')).take(80).collect();
        if name.is_empty() {
            return;
        }
        let mut q = self.crash_out.lock().unwrap();
        if q.iter().any(|(n, _)| *n == name) || q.len() >= 20 {
            return;
        }
        q.push((name, text[..text.len().min(crate::proto::MAX_CRASH)].to_vec()));
    }

    /// bestaetigte Absturz-Protokolle abholen (die App loescht sie dann)
    pub fn take_crash_ok(&self) -> Vec<String> {
        std::mem::take(&mut *self.crash_ok.lock().unwrap())
    }

    /// Geschwindigkeitstest starten (nur mit Verbindung; laeuft schon einer, passiert nichts)
    pub fn speedtest(&self) -> Result<(), String> {
        if self.state.load(Relaxed) != ST_CONNECTED {
            return Err("Nicht verbunden – erst verbinden, dann testen".into());
        }
        let mut s = self.speed.lock().unwrap();
        if s.laeuft() && s.t_start.map(|t| t.elapsed() < Duration::from_secs(30)).unwrap_or(false) {
            return Ok(());
        }
        *s = Speed { state: "laeuft".into(), phase: "ping".into(), t_start: Some(Instant::now()), ..Default::default() };
        drop(s);
        self.speed_go.notify_one();
        Ok(())
    }

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
            locate: self.locate.load(Relaxed),
            crash_ok: self.crash_ok.lock().unwrap().clone(),
            speed: self.speed.lock().unwrap().clone(),
            info: self.info.lock().unwrap().clone(),
        })
        .unwrap()
    }
    fn error(&self, e: &str) {
        let mut i = self.info.lock().unwrap();
        i.last_error = crate::fehler::klartext(e);
        i.last_error_detail = e.to_string();
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
    /// gewaehlte Verschluesselung ("auto", "aes", "chacha"), wird vor jedem Verbindungsaufbau gefragt (None = auto)
    pub cipher: Option<Arc<dyn Fn() -> String + Send + Sync>>,
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
    connect_once_with(cfg, proxy, protect, dns, false, "auto").await
}

/// wie `connect_once`; `upd` = dem Server melden, dass sich diese App selbst aktualisieren kann,
/// `cipher` = Wahl der Verschluesselung ("auto", "aes", "chacha")
pub async fn connect_once_with(
    cfg: &ClientConfig,
    proxy: Option<&Proxy>,
    protect: &Option<ProtectFn>,
    dns: &transport::DnsCache,
    upd: bool,
    cipher: &str,
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
        ciphers: crypto::cipher_wish(cipher),
        pick: true,
        pad: crate::tarn::fuellzeichen(160),
    };
    let (hs, m1) = crypto::client_init(&cfg.client_key()?, &cfg.server_key()?, &hello).map_err(|e| e.to_string())?;
    ws.send(Message::Binary(m1.into())).await.map_err(|e| format!("Senden fehlgeschlagen: {e}"))?;
    let m2 = loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
            Err(_) => return Err("Server antwortet nicht auf den Handshake".into()),
            // ab Server 1.5.0 mit Grund (gesperrt, abgelaufen, ausserhalb des Zeitfensters)
            Ok(Some(Ok(Message::Close(Some(f))))) if !f.reason.trim().is_empty() => {
                return Err(format!("Server lehnt ab: {}", f.reason.trim()))
            }
            Ok(None) | Ok(Some(Ok(Message::Close(_)))) => {
                return Err("Server hat den Handshake abgelehnt (Geraet entfernt, Code veraltet oder alle 8 Plaetze belegt)".into())
            }
            Ok(Some(Err(e))) => return Err(format!("Server hat den Handshake abgebrochen: {e}")),
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
        let choice = crypto::normalize_choice(&opts.cipher.as_ref().map(|f| f()).unwrap_or_default());
        {
            let mut i = status.info.lock().unwrap();
            i.cipher_choice = choice.into();
            i.aes_hw = crypto::aes_hw();
        }
        let attempt = tokio::select! {
            r = connect_once_with(&cfg, routes[0].as_ref(), &opts.protect, &opts.dns, opts.update.is_some(), choice) => r,
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
                    i.cipher = crypto::cipher_label(&welcome.cipher).into();
                    i.last_error.clear();
                    i.last_error_detail.clear();
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
                let tarn = welcome.tarn.map(|t| t.sicher()).unwrap_or_else(crate::proto::Tarn::alt);
                // eigenes Logo des Servers: anderes als gespeichert -> holen; keins mehr -> entfernen
                let logo_dir = status.logo_dir.lock().unwrap().clone();
                let logo_want = match (&logo_dir, &welcome.logo) {
                    (Some(d), Some(id)) if id.is_empty() => {
                        if !crate::logo::id_in(d).is_empty() {
                            crate::logo::remove(d);
                            status.logo_seq.fetch_add(1, Relaxed);
                        }
                        None
                    }
                    (Some(d), Some(id)) if *id != crate::logo::id_in(d) => Some(id.clone()),
                    _ => None,
                };
                let r = tokio::select! {
                    r = session(ws, sealer, opener, tarn, tun_in.clone(), tun_out.clone(), status.clone(), stop.clone(), opts.update.clone(), logo_want) => r,
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
                if e.contains("abgelehnt") || e.contains("lehnt ab") {
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

/// eine bestehende Verbindung bedienen. Fliessband ueber mehrere Kerne:
///   TUN lesen + buendeln + verschluesseln  ->  TLS/WebSocket senden        (je ein Task)
///   TLS/WebSocket empfangen                ->  entschluesseln + TUN schreiben (je ein Task)
#[allow(clippy::too_many_arguments)]
pub async fn session(
    ws: transport::Ws,
    mut sealer: Sealer,
    mut opener: Opener,
    tarn: crate::proto::Tarn,
    tun_in: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
    tun_out: Arc<dyn TunWriter>,
    status: Arc<Status>,
    mut stop: watch::Receiver<bool>,
    update: Option<Arc<crate::update::Updater>>,
    logo_want: Option<String>,
) -> Result<(), String> {
    let (sink, stream) = ws.split();
    let (out, out_err, _w) = crate::pipe::writer(sink, 64);
    let (mut inc, _r) = crate::pipe::reader(stream, 64);
    let t0 = Instant::now();
    let st_tx = status.clone();
    let upd_rx = update.clone();
    // Antworten des Empfangs-Tasks (z. B. auf stilles Anpingen), gehen mit dem naechsten Buendel hinaus
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Vec<u8>>(16);
    let logo_get = logo_want.is_some();
    let mut logo_rx = crate::logo::Empfang::default();
    {
        let mut sp = status.speed.lock().unwrap();
        if sp.laeuft() {
            sp.fehler("Verbindung wurde waehrend des Tests neu aufgebaut – bitte nochmal");
        }
    }
    // Geschwindigkeitstest: Upload laeuft bis zu diesem Zeitpunkt (vom Empfangs-Task nach dem Download gesetzt)
    let (up_tx, mut up_rx) = mpsc::channel::<()>(1);

    let mut sender = tokio::spawn(async move {
        let send_fail = |out_err: &Arc<Mutex<String>>| {
            let e = out_err.lock().unwrap().clone();
            if e.is_empty() { "Verbindung zum Server unterbrochen".to_string() } else { format!("Senden fehlgeschlagen: {e}") }
        };
        // verschluesseln (mit Tarn-Fuellung) und an die Sende-Stufe geben
        macro_rules! senden {
            ($buf:expr) => {{
                let mut b = $buf;
                tarn.fuellen(&mut b);
                sealer.seal(&mut b).map_err(|e| e.to_string())?;
                if out.send(b).await.is_err() {
                    return Err(send_fail(&out_err));
                }
            }};
        }
        // neuere Version angeboten: Datei (weiter) anfordern
        if let Some(off) = update.as_ref().and_then(|u| u.request()) {
            let mut buf = Vec::with_capacity(64);
            push_record(&mut buf, REC_UPD_GET, &off.to_be_bytes());
            senden!(buf);
        }
        // eigenes Logo des Servers anfordern
        if logo_get {
            let mut buf = Vec::with_capacity(16);
            push_record(&mut buf, crate::proto::REC_LOGO_GET, &[]);
            senden!(buf);
        }
        let mut rx = tun_in.lock().await;
        // Angaben des Geraets (falls freigegeben) gleich nach dem Verbinden und danach bei jeder Aenderung
        let mut report_seq = 0u64;
        let take_report = |seq: &mut u64| -> Option<Vec<u8>> {
            let r = st_tx.report.lock().unwrap();
            (r.0 != *seq && !r.1.is_empty()).then(|| {
                *seq = r.0;
                r.1.clone()
            })
        };
        if let Some(r) = take_report(&mut report_seq) {
            let mut buf = Vec::with_capacity(r.len() + 32);
            push_record(&mut buf, REC_INFO, &r);
            senden!(buf);
        }
        // Absturz-Protokolle (bleiben vorgemerkt, bis der Server sie bestaetigt)
        let mut crash_sent: std::collections::HashSet<String> = Default::default();
        let take_crash = |sent: &mut std::collections::HashSet<String>| -> Vec<Vec<u8>> {
            let q = st_tx.crash_out.lock().unwrap();
            q.iter()
                .filter(|(n, _)| sent.insert(n.clone()))
                .map(|(n, t)| {
                    let mut d = Vec::with_capacity(n.len() + 1 + t.len());
                    d.push(n.len() as u8);
                    d.extend_from_slice(n.as_bytes());
                    d.extend_from_slice(t);
                    let mut b = Vec::with_capacity(d.len() + 3);
                    push_record(&mut b, REC_CRASH, &d);
                    b
                })
                .collect()
        };
        for b in take_crash(&mut crash_sent) {
            senden!(b);
        }
        // Lebenszeichen in zufaelligen Abstaenden (Tarn-Profil), erstes gleich zu Beginn (Ping-Messung)
        let ka = tokio::time::sleep(Duration::from_millis(300));
        tokio::pin!(ka);
        let mut report_tick = tokio::time::interval(Duration::from_secs(2));
        report_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut up_until: Option<Instant> = None;
        let filler = vec![0u8; SPEED_CHUNK];
        loop {
            let mut buf = Vec::with_capacity(BUNDLE_TARGET + 2048);
            tokio::select! {
                // Geschwindigkeitstest: erst Ping (letzte Messung des Lebenszeichens), dann Download anfordern
                _ = st_tx.speed_go.notified() => {
                    {
                        let mut sp = st_tx.speed.lock().unwrap();
                        if !sp.laeuft() { continue; }
                        sp.ping_ms = (st_tx.rtt_us.load(Relaxed) as f64 / 100.0).round() / 10.0;
                        sp.phase = "down".into();
                        sp.t_phase = Some(Instant::now());
                        sp.down_first = None;
                        sp.down_bytes = 0;
                    }
                    push_record(&mut buf, REC_SPEED_GET, &SPEED_MS.to_be_bytes());
                }
                // Download fertig -> Upload fuer dieselbe Dauer
                Some(()) = up_rx.recv() => {
                    up_until = Some(Instant::now() + Duration::from_millis(SPEED_MS as u64));
                    continue;
                }
                // Upload: Fuelldaten so schnell, wie die Verbindung sie abnimmt (Pakete gehen weiter mit)
                _ = std::future::ready(()), if up_until.is_some() => {
                    if up_until.map(|t| Instant::now() >= t).unwrap_or(true) {
                        up_until = None;
                        push_record(&mut buf, REC_SPEED_UP_END, &[]);
                    } else {
                        push_record(&mut buf, REC_SPEED_DATA, &filler);
                        push_record(&mut buf, REC_SPEED_DATA, &filler);
                    }
                }
                c = ctrl_rx.recv() => {
                    let Some(c) = c else { continue };
                    buf.extend_from_slice(&c);
                }
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
                _ = report_tick.tick() => {
                    // Geschwindigkeitstest haengt (Server zu alt oder Verbindung bricht ein)
                    {
                        let mut sp = st_tx.speed.lock().unwrap();
                        if sp.laeuft() && sp.t_phase.map(|t| t.elapsed() > Duration::from_secs(SPEED_MS as u64 / 1000 + 12)).unwrap_or(false) {
                            let e = if sp.phase == "down" && sp.down_bytes == 0 { "Der Server kann den Geschwindigkeitstest noch nicht (ab Server 1.4.0)" } else { "Keine Antwort vom Server – bitte nochmal" };
                            sp.fehler(e);
                        }
                    }
                    for b in take_crash(&mut crash_sent) {
                        senden!(b);
                    }
                    // neue Angaben des Geraets (WLAN, Standort)? sonst nichts senden
                    let Some(r) = take_report(&mut report_seq) else { continue };
                    push_record(&mut buf, REC_INFO, &r);
                }
                _ = &mut ka => {
                    ka.as_mut().reset(tokio::time::Instant::now() + tarn.lebenszeichen());
                    let mut d = [0u8; 12];
                    d[..8].copy_from_slice(&(t0.elapsed().as_micros() as u64).to_be_bytes());
                    d[8..].copy_from_slice(&(st_tx.rtt_us.load(Relaxed).min(u32::MAX as u64) as u32).to_be_bytes());
                    push_record(&mut buf, REC_PING, &d);
                    // Fuellbytes: Lebenszeichen haben keine feste Groesse
                    let pad = vec![0u8; (rand::random::<u8>() % 96) as usize];
                    push_record(&mut buf, REC_PAD, &pad);
                }
            }
            senden!(buf);
        }
    });

    let st_rx = status.clone();
    let mut receiver = tokio::spawn(async move {
        loop {
            let mut buf = match tokio::time::timeout(Duration::from_secs(35), inc.recv()).await {
                Err(_) => return Err("keine Antwort vom Server seit 35 s – verbinde neu".to_string()),
                Ok(None) | Ok(Some(crate::pipe::Rein::Ende)) => return Err("Server hat die Verbindung beendet".to_string()),
                Ok(Some(crate::pipe::Rein::Fehler(e))) => return Err(format!("Verbindung abgebrochen: {e}")),
                Ok(Some(crate::pipe::Rein::Daten(b))) => b,
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
                // stilles Anpingen von der Admin-Seite: der Kern antwortet selbst (keine Anzeige in der App)
                REC_SPING if data.len() <= 16 => {
                    let mut b = Vec::with_capacity(24);
                    push_record(&mut b, REC_SPONG, data);
                    let _ = ctrl_tx.try_send(b);
                }
                REC_LOCATE => {
                    st_rx.locate.fetch_add(1, Relaxed);
                }
                crate::proto::REC_LOGO => {
                    if let Some(id) = &logo_want {
                        if let Some(png) = logo_rx.stueck(id, data) {
                            let dir = st_rx.logo_dir.lock().unwrap().clone();
                            if let Some(d) = dir {
                                if crate::logo::save(&d, &png).is_ok() {
                                    st_rx.logo_seq.fetch_add(1, Relaxed);
                                }
                            }
                        }
                    }
                }
                REC_SPEED_DATA => {
                    let mut sp = st_rx.speed.lock().unwrap();
                    if sp.laeuft() && sp.phase == "down" {
                        sp.down_first.get_or_insert_with(Instant::now);
                        sp.down_bytes += data.len() as u64;
                    }
                }
                REC_SPEED_RES => {
                    let Some((art, b, us)) = speed_res_parse(data) else { return };
                    let mut sp = st_rx.speed.lock().unwrap();
                    if !sp.laeuft() {
                        return;
                    }
                    if art == 1 && sp.phase == "down" {
                        // eigene Messung (ab dem ersten Stueck) – sonst die des Servers
                        let eigen = sp.down_first.map(|t| t.elapsed().as_micros() as u64).unwrap_or(0);
                        sp.down_mbps = if eigen > 50_000 && sp.down_bytes > 0 { mbit(sp.down_bytes, eigen) } else { mbit(b, us) };
                        sp.down_mbps = (sp.down_mbps * 10.0).round() / 10.0;
                        sp.phase = "up".into();
                        sp.t_phase = Some(Instant::now());
                        let _ = up_tx.try_send(());
                    } else if art == 2 && sp.phase == "up" {
                        sp.up_mbps = (mbit(b, us) * 10.0).round() / 10.0;
                        sp.state = "fertig".into();
                        sp.phase.clear();
                        sp.at = crate::util::now_secs();
                    }
                }
                REC_CRASH_OK => {
                    let n = String::from_utf8_lossy(data).to_string();
                    st_rx.crash_out.lock().unwrap().retain(|(x, _)| *x != n);
                    let mut ok = st_rx.crash_ok.lock().unwrap();
                    if !ok.contains(&n) {
                        ok.push(n);
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
