//! Statistik: Zaehler je Geraet, Verlauf (Sekunden/Minuten), Tages- und Monatssummen (gespeichert).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;

#[derive(Default, Clone, Serialize)]
pub struct SessInfo {
    pub remote: String,
    pub os: String,
    pub ver: String,
    pub tls_issuer: String,
    pub tls_trusted: bool,
    pub via_proxy: bool,
    /// App kann sich selbst aktualisieren
    pub upd: bool,
    /// Verschluesselung der Daten ("chacha20" oder "aes256gcm")
    pub cipher: String,
    /// an das Geraet vollstaendig uebertragene App-Version (Update)
    pub upd_sent: String,
}

/// Zaehler eines Geraets (bleiben ueber Neuverbindungen erhalten). rx = vom Geraet, tx = zum Geraet.
#[derive(Default)]
pub struct PeerStats {
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub spoofed: AtomicU64,
    pub rtt_us: AtomicU64,
    pub connected_since: AtomicU64,
    pub handshakes: AtomicU64,
    pub last_seen: AtomicU64,
    pub rate_rx: AtomicU64,
    pub rate_tx: AtomicU64,
    pub info: Mutex<SessInfo>,
    pub spark: Mutex<VecDeque<(u64, u64)>>,
    last: Mutex<(u64, u64)>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Persist {
    /// "JJJJ-MM-TT" -> Geraet -> [rx, tx]
    pub days: BTreeMap<String, BTreeMap<String, [u64; 2]>>,
    /// Geraet -> [rx, tx] seit Beginn
    pub total: BTreeMap<String, [u64; 2]>,
    /// fuer den Monatsbericht (ab Server 1.3.0): "JJJJ-MM-TT" -> Geraet -> Sekunden verbunden
    #[serde(default)]
    pub online: BTreeMap<String, BTreeMap<String, u64>>,
    /// "JJJJ-MM-TT" -> Geraet -> Anzahl Verbindungen
    #[serde(default)]
    pub connects: BTreeMap<String, BTreeMap<String, u64>>,
    /// "JJJJ-MM-TT" -> Sekunden, die der Server lief
    #[serde(default)]
    pub uptime: BTreeMap<String, u64>,
    /// "JJJJ-MM-TT" -> [DNS-Anfragen, davon geblockt]
    #[serde(default)]
    pub dns: BTreeMap<String, [u64; 2]>,
}

/// Monatsbericht: Summen eines Monats
#[derive(Default, Serialize, Clone, Debug)]
pub struct Bericht {
    pub month: String,
    /// Geraet -> (rx, tx, Sekunden online, Verbindungen)
    pub per: BTreeMap<String, [u64; 4]>,
    pub rx: u64,
    pub tx: u64,
    pub uptime: u64,
    /// Sekunden des Monats bis jetzt (bzw. ganzer Monat)
    pub span: u64,
    pub dns: [u64; 2],
    pub days: usize,
}

pub struct Hist {
    pub sec: VecDeque<(u64, u64)>,
    pub min: VecDeque<(u64, u64)>,
    min_acc: (u64, u64, u32),
    pub persist: Persist,
    pub dirty: bool,
}

pub const SEC_KEEP: usize = 600;
pub const MIN_KEEP: usize = 1440;
pub const SPARK_KEEP: usize = 120;

impl Hist {
    pub fn new(persist: Persist) -> Self {
        Hist { sec: VecDeque::new(), min: VecDeque::new(), min_acc: (0, 0, 0), persist, dirty: false }
    }
}

impl PeerStats {
    /// einmal pro Sekunde: Rate berechnen; liefert Zuwachs (rx, tx) seit dem letzten Aufruf
    pub fn tick(&self) -> (u64, u64) {
        let rx = self.rx_bytes.load(Relaxed);
        let tx = self.tx_bytes.load(Relaxed);
        let mut l = self.last.lock().unwrap();
        let d = (rx.saturating_sub(l.0), tx.saturating_sub(l.1));
        *l = (rx, tx);
        self.rate_rx.store(d.0, Relaxed);
        self.rate_tx.store(d.1, Relaxed);
        let mut s = self.spark.lock().unwrap();
        s.push_back(d);
        while s.len() > SPARK_KEEP {
            s.pop_front();
        }
        d
    }
}

/// Bytes lesbar
pub fn fmt_bytes(b: u64) -> String {
    let u = ["B", "KB", "MB", "GB", "TB"];
    let (mut v, mut i) = (b as f64, 0);
    while v >= 1024.0 && i < u.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b} B") } else { format!("{v:.1} {}", u[i]).replace('.', ",") }
}

/// Stunden lesbar ("12,5 h")
pub fn fmt_hours(s: u64) -> String {
    format!("{:.1} h", s as f64 / 3600.0).replace('.', ",")
}

/// Monatsbericht als Text (Benachrichtigung, kvpn-server bericht)
pub fn bericht_text(b: &Bericht, vpn: &str) -> String {
    let mut t = format!("{vpn} – {}\n", b.month);
    t += &format!("Daten gesamt: {} (↓ {} · ↑ {})\n", fmt_bytes(b.rx + b.tx), fmt_bytes(b.tx), fmt_bytes(b.rx));
    if b.span > 0 {
        t += &format!("Server lief: {:.1} % ({} von {})\n", (b.uptime as f64 / b.span as f64 * 100.0).min(100.0), fmt_hours(b.uptime), fmt_hours(b.span)).replace('.', ",");
    }
    if b.dns[0] > 0 {
        t += &format!("Werbe-Blocker: {} von {} Anfragen geblockt\n", b.dns[1], b.dns[0]);
    }
    let mut per: Vec<(&String, &[u64; 4])> = b.per.iter().collect();
    per.sort_by(|a, b| (b.1[0] + b.1[1]).cmp(&(a.1[0] + a.1[1])));
    for (n, v) in per {
        t += &format!("• {n}: {} · online {} · {} Verbindungen\n", fmt_bytes(v[0] + v[1]), fmt_hours(v[2]), v[3]);
    }
    t.trim_end().to_string()
}

/// Sekunden eines Monats ("JJJJ-MM"): ganzer Monat, beim laufenden Monat nur bis jetzt
pub fn month_span(month: &str, now: u64) -> u64 {
    let (Some(y), Some(m)) = (month.get(..4).and_then(|x| x.parse::<i32>().ok()), month.get(5..7).and_then(|x| x.parse::<i32>().ok())) else { return 0 };
    let start = |y: i32, m: i32| -> u64 {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_year = y - 1900;
        tm.tm_mon = m - 1;
        tm.tm_mday = 1;
        tm.tm_isdst = -1;
        unsafe { libc::mktime(&mut tm) }.max(0) as u64
    };
    let a = start(y, m);
    let e = if m == 12 { start(y + 1, 1) } else { start(y, m + 1) };
    e.min(now.max(a)).saturating_sub(a)
}

/// lokales Datum "JJJJ-MM-TT"
#[allow(deprecated)]
pub fn local_date(ts: u64) -> String {
    let t = ts as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    format!("{:04}-{:02}-{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday)
}

impl Hist {
    /// Sekundenwerte aller Geraete eintragen
    pub fn add_second(&mut self, now: u64, per_peer: &[(String, u64, u64)]) {
        let (mut rx, mut tx) = (0, 0);
        let day = local_date(now);
        for (name, r, t) in per_peer {
            rx += r;
            tx += t;
            if r + t > 0 {
                let e = self.persist.days.entry(day.clone()).or_default().entry(name.clone()).or_insert([0, 0]);
                e[0] += r;
                e[1] += t;
                let e = self.persist.total.entry(name.clone()).or_insert([0, 0]);
                e[0] += r;
                e[1] += t;
                self.dirty = true;
            }
        }
        self.sec.push_back((rx, tx));
        while self.sec.len() > SEC_KEEP {
            self.sec.pop_front();
        }
        self.min_acc.0 += rx;
        self.min_acc.1 += tx;
        self.min_acc.2 += 1;
        if self.min_acc.2 >= 60 {
            self.min.push_back((self.min_acc.0 / 60, self.min_acc.1 / 60));
            while self.min.len() > MIN_KEEP {
                self.min.pop_front();
            }
            self.min_acc = (0, 0, 0);
        }
        // hoechstens 400 Tage aufheben
        while self.persist.days.len() > 400 {
            let k = self.persist.days.keys().next().cloned().unwrap();
            self.persist.days.remove(&k);
        }
    }

    /// jede Sekunde: welche Geraete verbunden sind (Online-Zeit) und dass der Server laeuft
    pub fn add_online(&mut self, now: u64, online: &[String]) {
        let day = local_date(now);
        *self.persist.uptime.entry(day.clone()).or_default() += 1;
        if !online.is_empty() {
            let m = self.persist.online.entry(day).or_default();
            for n in online {
                *m.entry(n.clone()).or_default() += 1;
            }
        }
        self.dirty = true;
        for map in [&mut self.persist.online, &mut self.persist.connects] {
            while map.len() > 400 {
                let k = map.keys().next().cloned().unwrap();
                map.remove(&k);
            }
        }
        for map in [&mut self.persist.uptime] {
            while map.len() > 400 {
                let k = map.keys().next().cloned().unwrap();
                map.remove(&k);
            }
        }
        while self.persist.dns.len() > 400 {
            let k = self.persist.dns.keys().next().cloned().unwrap();
            self.persist.dns.remove(&k);
        }
    }

    pub fn add_connect(&mut self, now: u64, name: &str) {
        *self.persist.connects.entry(local_date(now)).or_default().entry(name.to_string()).or_default() += 1;
        self.dirty = true;
    }

    pub fn add_dns(&mut self, now: u64, queries: u64, blocked: u64) {
        if queries + blocked > 0 {
            let e = self.persist.dns.entry(local_date(now)).or_default();
            e[0] += queries;
            e[1] += blocked;
            self.dirty = true;
        }
    }

    /// Monate mit Daten, neueste zuerst ("JJJJ-MM")
    pub fn months(&self) -> Vec<String> {
        let mut v: Vec<String> =
            self.persist.days.keys().chain(self.persist.uptime.keys()).chain(self.persist.online.keys()).map(|d| d[..7].to_string()).collect();
        v.sort();
        v.dedup();
        v.reverse();
        v
    }

    /// Summen eines Monats ("JJJJ-MM"); `now` fuer den laufenden Monat
    pub fn bericht(&self, month: &str, now: u64) -> Bericht {
        let mut b = Bericht { month: month.to_string(), ..Default::default() };
        let from = format!("{month}-00");
        let to = format!("{month}-99");
        let mut days = std::collections::BTreeSet::new();
        for (d, m) in self.persist.days.range(from.clone()..to.clone()) {
            days.insert(d.clone());
            for (n, v) in m {
                let e = b.per.entry(n.clone()).or_default();
                e[0] += v[0];
                e[1] += v[1];
                b.rx += v[0];
                b.tx += v[1];
            }
        }
        for (d, m) in self.persist.online.range(from.clone()..to.clone()) {
            days.insert(d.clone());
            for (n, v) in m {
                b.per.entry(n.clone()).or_default()[2] += v;
            }
        }
        for (_, m) in self.persist.connects.range(from.clone()..to.clone()) {
            for (n, v) in m {
                b.per.entry(n.clone()).or_default()[3] += v;
            }
        }
        for (d, v) in self.persist.uptime.range(from.clone()..to.clone()) {
            days.insert(d.clone());
            b.uptime += v;
        }
        for (_, v) in self.persist.dns.range(from..to) {
            b.dns[0] += v[0];
            b.dns[1] += v[1];
        }
        b.days = days.len();
        b.span = month_span(month, now);
        b
    }

    pub fn load(path: &str) -> Persist {
        std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn save(&mut self, path: &str) {
        if !self.dirty {
            return;
        }
        let tmp = format!("{path}.tmp");
        if std::fs::write(&tmp, serde_json::to_vec(&self.persist).unwrap()).is_ok() && std::fs::rename(&tmp, path).is_ok() {
            self.dirty = false;
        }
    }

    /// Summen fuer ein Geraet: (heute, dieser Monat)
    pub fn sums(&self, name: &str, now: u64) -> ([u64; 2], [u64; 2]) {
        let today = local_date(now);
        let month = &today[..7];
        let mut t = [0, 0];
        let mut m = [0, 0];
        for (d, map) in self.persist.days.range(format!("{month}-00")..) {
            if let Some(v) = map.get(name) {
                if d.starts_with(month) {
                    m[0] += v[0];
                    m[1] += v[1];
                }
                if *d == today {
                    t = *v;
                }
            }
        }
        (t, m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hist_sums() {
        let mut h = Hist::new(Persist::default());
        let now = 1_795_000_000;
        for _ in 0..120 {
            h.add_second(now, &[("handy".into(), 100, 1000), ("pc".into(), 0, 0)]);
        }
        assert_eq!(h.sec.len(), 120);
        assert_eq!(h.min.len(), 2);
        assert_eq!(h.min[0], (100, 1000));
        let (t, m) = h.sums("handy", now);
        assert_eq!(t, [12000, 120000]);
        assert_eq!(m, [12000, 120000]);
        assert_eq!(h.sums("pc", now).0, [0, 0]);
        assert_eq!(h.persist.total["handy"], [12000, 120000]);
        // Monatsbericht
        for _ in 0..30 {
            h.add_online(now, &["handy".into()]);
        }
        h.add_connect(now, "handy");
        h.add_connect(now, "handy");
        h.add_dns(now, 100, 7);
        let mo = local_date(now)[..7].to_string();
        assert_eq!(h.months(), vec![mo.clone()]);
        let b = h.bericht(&mo, now);
        assert_eq!(b.per["handy"], [12000, 120000, 30, 2]);
        assert_eq!(b.uptime, 30);
        assert_eq!(b.dns, [100, 7]);
        assert!(b.span > 0 && b.span <= 31 * 86400);
        assert_eq!(month_span("2026-02", 4_000_000_000), 28 * 86400);
        let p = PeerStats::default();
        p.rx_bytes.store(500, Relaxed);
        assert_eq!(p.tick(), (500, 0));
        p.rx_bytes.store(800, Relaxed);
        assert_eq!(p.tick(), (300, 0));
    }
}
