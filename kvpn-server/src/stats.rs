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
        let p = PeerStats::default();
        p.rx_bytes.store(500, Relaxed);
        assert_eq!(p.tick(), (500, 0));
        p.rx_bytes.store(800, Relaxed);
        assert_eq!(p.tick(), (300, 0));
    }
}
