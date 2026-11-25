//! Eigener DNS im Tunnel (ab Server 1.3.0): Werbe- und Tracker-Blocker + Namen im Heimnetz.
//!
//! Der Server beantwortet DNS-Anfragen der Geraete selbst (auf seiner Tunnel-Adresse, Port 53). Anfragen an andere
//! DNS-Server (z. B. 1.1.1.1 aus dem Verbindungscode) leitet die Firewall dorthin um – so wirkt es auch bei alten Apps,
//! ohne dass dort etwas geaendert werden muss.
//!   * Werbe-/Tracker-Blocker: Namen aus einer Sperrliste (wie Pi-hole, Standard: StevenBlack-Hosts) bekommen 0.0.0.0
//!     bzw. :: als Antwort – die Werbung laedt dann einfach nicht. Eigene Ausnahmen/Sperren auf der Admin-Seite.
//!   * Heimnetz: alles andere fragt der Server bei seinem eigenen DNS nach (meist der Router), damit gehen auch Namen
//!     wie "nas.fritz.box". Kurze Namen ("nas") bekommen die Such-Domaene des Servers angehaengt.
//! Die Anfragen werden nicht gespeichert – es gibt nur Zaehler (gesamt, geblockt, je Geraet) und die meistgeblockten
//! Namen fuer die Admin-Seite.

use crate::log;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Standard-Sperrliste (Werbung + Tracker + Schadseiten, ~80 000 Namen)
pub const DEFAULT_LIST: &str = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";
/// so gross darf eine Sperrliste hoechstens sein
const MAX_LIST: u64 = 40 * 1024 * 1024;
/// bekannte DNS-ueber-HTTPS/TLS-Server: Browser/Android wuerden sonst daran vorbei fragen (dann ohne Blocker)
pub const DOH_IPS: &[&str] = &[
    "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "8.8.8.8", "8.8.4.4", "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
];
pub const DOH_IPS6: &[&str] =
    &["2606:4700:4700::1111", "2606:4700:4700::1001", "2620:fe::fe", "2620:fe::9", "2001:4860:4860::8888", "2001:4860:4860::8844"];

#[derive(Default)]
pub struct Counters {
    pub queries: AtomicU64,
    pub blocked: AtomicU64,
}

pub struct Dns {
    /// Sperrliste (genaue Namen)
    list: RwLock<HashSet<String>>,
    /// eigene Sperren / Ausnahmen (gelten auch fuer Unter-Namen)
    own_block: RwLock<HashSet<String>>,
    own_allow: RwLock<HashSet<String>>,
    pub on: AtomicBool,
    upstream: RwLock<Vec<SocketAddr>>,
    search: RwLock<Vec<String>>,
    pub total: Counters,
    /// Geraete-Adresse im Tunnel -> (Anfragen, geblockt)
    per_ip: Mutex<HashMap<IpAddr, (u64, u64)>>,
    /// meistgeblockte Namen (gekappt)
    top: Mutex<HashMap<String, u64>>,
    pub list_info: Mutex<String>,
    pub listening: Mutex<Vec<SocketAddr>>,
}

pub type Shared = Arc<Dns>;

impl Dns {
    pub fn new(on: bool) -> Shared {
        Arc::new(Dns {
            list: RwLock::new(HashSet::new()),
            own_block: RwLock::new(HashSet::new()),
            own_allow: RwLock::new(HashSet::new()),
            on: AtomicBool::new(on),
            upstream: RwLock::new(Vec::new()),
            search: RwLock::new(Vec::new()),
            total: Counters::default(),
            per_ip: Mutex::new(HashMap::new()),
            top: Mutex::new(HashMap::new()),
            list_info: Mutex::new(String::new()),
            listening: Mutex::new(Vec::new()),
        })
    }

    pub fn set_own(&self, block: &[String], allow: &[String]) {
        *self.own_block.write().unwrap() = block.iter().map(|s| norm(s)).filter(|s| !s.is_empty()).collect();
        *self.own_allow.write().unwrap() = allow.iter().map(|s| norm(s)).filter(|s| !s.is_empty()).collect();
    }

    pub fn list_len(&self) -> usize {
        self.list.read().unwrap().len()
    }

    /// soll dieser Name geblockt werden?
    pub fn is_blocked(&self, name: &str) -> bool {
        if !self.on.load(Relaxed) {
            return false;
        }
        let name = norm(name);
        let allow = self.own_allow.read().unwrap();
        if suffixes(&name).any(|s| allow.contains(s)) {
            return false;
        }
        if suffixes(&name).any(|s| self.own_block.read().unwrap().contains(s)) {
            return true;
        }
        self.list.read().unwrap().contains(&name)
    }

    /// Zaehler je Geraet: (Anfragen, geblockt)
    pub fn per_ip(&self) -> HashMap<IpAddr, (u64, u64)> {
        self.per_ip.lock().unwrap().clone()
    }

    /// meistgeblockte Namen
    pub fn top(&self, n: usize) -> Vec<(String, u64)> {
        let t = self.top.lock().unwrap();
        let mut v: Vec<(String, u64)> = t.iter().map(|(a, b)| (a.clone(), *b)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    fn count(&self, ip: IpAddr, name: &str, blocked: bool) {
        self.total.queries.fetch_add(1, Relaxed);
        let mut p = self.per_ip.lock().unwrap();
        let e = p.entry(ip).or_default();
        e.0 += 1;
        if blocked {
            e.1 += 1;
            self.total.blocked.fetch_add(1, Relaxed);
            let mut t = self.top.lock().unwrap();
            if t.len() < 2000 || t.contains_key(name) {
                *t.entry(name.to_string()).or_default() += 1;
            }
        }
    }
}

/// Kleinbuchstaben, ohne Punkt am Ende
pub fn norm(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// "a.b.c" -> "a.b.c", "b.c", "c"
fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(name), |s| s.find('.').map(|i| &s[i + 1..])).filter(|s| !s.is_empty())
}

/// Sperrliste lesen: Hosts-Format ("0.0.0.0 name"), reine Namensliste oder Adblock-Stil ("||name^")
pub fn parse_list(text: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            continue;
        }
        let mut it = line.split_whitespace();
        let first = it.next().unwrap_or("");
        let name = if first.parse::<IpAddr>().is_ok() {
            match it.next() {
                Some(n) => n,
                None => continue,
            }
        } else if let Some(r) = first.strip_prefix("||") {
            r.trim_end_matches('^')
        } else {
            first
        };
        let n = norm(name);
        if n.contains('.') && !matches!(n.as_str(), "localhost" | "localhost.localdomain" | "local" | "broadcasthost" | "0.0.0.0") && n.len() < 254 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_') {
            set.insert(n);
        }
    }
    set
}

/// DNS-Server und Such-Domaenen des Servers selbst (/etc/resolv.conf); Ersatz: `fallback`
pub fn system_upstream(fallback: &[String]) -> (Vec<SocketAddr>, Vec<String>) {
    let text = std::fs::read_to_string(std::env::var("KVPN_RESOLV_CONF").unwrap_or_else(|_| "/etc/resolv.conf".into())).unwrap_or_default();
    let mut ns = Vec::new();
    let mut search = Vec::new();
    for l in text.lines() {
        let mut it = l.split_whitespace();
        match it.next() {
            Some("nameserver") => {
                if let Some(ip) = it.next().and_then(|a| a.split('%').next()).and_then(|a| a.parse::<IpAddr>().ok()) {
                    ns.push(SocketAddr::new(ip, 53));
                }
            }
            Some("search") | Some("domain") => {
                for d in it {
                    let d = norm(d);
                    if !d.is_empty() && !search.contains(&d) {
                        search.push(d);
                    }
                }
            }
            _ => {}
        }
    }
    if ns.is_empty() {
        ns = fallback.iter().filter_map(|a| a.parse::<IpAddr>().ok()).map(|ip| SocketAddr::new(ip, 53)).collect();
    }
    (ns, search)
}

// ------------------------------------------------------------------------------------------------ DNS-Nachrichten

/// Frage einer Anfrage: (Name, Typ, Ende der Frage im Paket)
pub fn question(q: &[u8]) -> Option<(String, u16, usize)> {
    if q.len() < 12 || u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    let mut i = 12;
    let mut name = String::new();
    loop {
        let l = *q.get(i)? as usize;
        if l == 0 {
            i += 1;
            break;
        }
        if l & 0xc0 != 0 || i + 1 + l > q.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&q[i + 1..i + 1 + l]).to_ascii_lowercase());
        i += 1 + l;
        if name.len() > 253 {
            return None;
        }
    }
    let t = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    Some((name, t, i + 4))
}

/// Antwort fuer einen geblockten Namen: A -> 0.0.0.0, AAAA -> ::, sonst leer (NOERROR)
pub fn blocked_reply(q: &[u8], qtype: u16, qend: usize) -> Vec<u8> {
    let mut r = q[..qend].to_vec();
    r[2] = 0x80 | (q[2] & 0x01); // Antwort, RD uebernehmen
    r[3] = 0x80; // RA, NOERROR
    r[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
    let rdata: &[u8] = match qtype {
        1 => &[0, 0, 0, 0],
        28 => &[0; 16],
        _ => return r,
    };
    r[7] = 1;
    r.extend_from_slice(&[0xc0, 0x0c]);
    r.extend_from_slice(&qtype.to_be_bytes());
    r.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    r.extend_from_slice(rdata);
    r
}

/// Fehler-Antwort (z. B. SERVFAIL = 2)
fn error_reply(q: &[u8], qend: usize, rcode: u8) -> Vec<u8> {
    let mut r = q[..qend.min(q.len())].to_vec();
    if r.len() < 12 {
        return Vec::new();
    }
    r[2] = 0x80 | (q[2] & 0x01);
    r[3] = 0x80 | rcode;
    r[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
    r
}

/// Anfrage mit anderem Namen (fuer kurze Namen + Such-Domaene)
fn with_name(q: &[u8], qend: usize, name: &str) -> Vec<u8> {
    let mut r = q[..12].to_vec();
    r[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for l in name.split('.') {
        r.push(l.len() as u8);
        r.extend_from_slice(l.as_bytes());
    }
    r.push(0);
    r.extend_from_slice(&q[qend - 4..qend]);
    r
}

/// Antwort auf eine umgeschriebene Anfrage zurueck auf den urspruenglichen Namen bringen: die Frage wird ersetzt,
/// die Antworten zeigen per Verweis (0xC00C) auf sie. Nur A/AAAA/CNAME-Antworten werden uebernommen.
fn rename_reply(orig: &[u8], orig_qend: usize, reply: &[u8]) -> Option<Vec<u8>> {
    let (_, _, rq) = question(&{
        // question() erwartet QDCOUNT=1 – Antworten haben das auch
        reply.to_vec()
    })?;
    let an = u16::from_be_bytes([reply[6], reply[7]]) as usize;
    let mut out = orig[..orig_qend].to_vec();
    out[2] = reply[2];
    out[3] = reply[3];
    out[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
    let mut i = rq;
    let mut n = 0u16;
    for _ in 0..an {
        i = skip_name(reply, i)?;
        let t = u16::from_be_bytes([*reply.get(i)?, *reply.get(i + 1)?]);
        let len = u16::from_be_bytes([*reply.get(i + 8)?, *reply.get(i + 9)?]) as usize;
        let rd = reply.get(i + 10..i + 10 + len)?;
        if t == 1 || t == 28 {
            out.extend_from_slice(&[0xc0, 0x0c]);
            out.extend_from_slice(&reply[i..i + 8]);
            out.extend_from_slice(&(len as u16).to_be_bytes());
            out.extend_from_slice(rd);
            n += 1;
        }
        i += 10 + len;
    }
    out[6..8].copy_from_slice(&n.to_be_bytes());
    Some(out)
}

fn skip_name(p: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let l = *p.get(i)? as usize;
        if l == 0 {
            return Some(i + 1);
        }
        if l & 0xc0 == 0xc0 {
            return Some(i + 2);
        }
        i += 1 + l;
    }
}

fn rcode(r: &[u8]) -> u8 {
    r.get(3).map(|b| b & 0x0f).unwrap_or(2)
}

fn ancount(r: &[u8]) -> u16 {
    if r.len() < 12 { 0 } else { u16::from_be_bytes([r[6], r[7]]) }
}

/// eine Anfrage beim eigentlichen DNS stellen (UDP, bei abgeschnittener Antwort ueber TCP)
async fn ask_upstream(up: &[SocketAddr], q: &[u8]) -> Option<Vec<u8>> {
    for a in up {
        let bind: SocketAddr = if a.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
        let Ok(s) = UdpSocket::bind(bind).await else { continue };
        if s.send_to(q, a).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; 4096];
        let Ok(Ok((n, from))) = tokio::time::timeout(Duration::from_millis(2500), s.recv_from(&mut buf)).await else { continue };
        if from.ip() != a.ip() || n < 12 || buf[..2] != q[..2] {
            continue;
        }
        buf.truncate(n);
        if buf[2] & 0x02 != 0 {
            // abgeschnitten: ueber TCP nochmal
            if let Some(r) = ask_tcp(*a, q).await {
                return Some(r);
            }
        }
        return Some(buf);
    }
    None
}

async fn ask_tcp(a: SocketAddr, q: &[u8]) -> Option<Vec<u8>> {
    let f = async {
        let mut s = TcpStream::connect(a).await.ok()?;
        let mut m = (q.len() as u16).to_be_bytes().to_vec();
        m.extend_from_slice(q);
        s.write_all(&m).await.ok()?;
        let mut l = [0u8; 2];
        s.read_exact(&mut l).await.ok()?;
        let mut r = vec![0u8; u16::from_be_bytes(l) as usize];
        s.read_exact(&mut r).await.ok()?;
        Some(r)
    };
    tokio::time::timeout(Duration::from_secs(4), f).await.ok().flatten()
}

/// Anfrage eines Geraets beantworten
pub async fn answer(d: &Dns, from: IpAddr, q: &[u8]) -> Vec<u8> {
    let Some((name, qtype, qend)) = question(q) else {
        return if q.len() >= 12 { error_reply(q, 12, 1) } else { Vec::new() };
    };
    let blocked = d.is_blocked(&name);
    d.count(from, &name, blocked);
    if blocked {
        return blocked_reply(q, qtype, qend);
    }
    let up = d.upstream.read().unwrap().clone();
    let reply = ask_upstream(&up, q).await;
    // kurzer Name ("nas"), nichts gefunden: mit der Such-Domaene des Servers (z. B. "nas.fritz.box") versuchen
    let short = !name.contains('.') && !name.is_empty() && matches!(qtype, 1 | 28);
    if short && reply.as_ref().map(|r| rcode(r) != 0 || ancount(r) == 0).unwrap_or(true) {
        let search = d.search.read().unwrap().clone();
        for s in search {
            let full = format!("{name}.{s}");
            if let Some(r) = ask_upstream(&up, &with_name(q, qend, &full)).await {
                if rcode(&r) == 0 && ancount(&r) > 0 {
                    if let Some(x) = rename_reply(q, qend, &r) {
                        if ancount(&x) > 0 {
                            return x;
                        }
                    }
                }
            }
        }
    }
    reply.unwrap_or_else(|| error_reply(q, qend, 2))
}

// ------------------------------------------------------------------------------------------------ Dienst

/// auf den Tunnel-Adressen des Servers lauschen (UDP + TCP Port 53). Ergebnis: Adressen, auf denen es geklappt hat
pub async fn start(d: Shared, addrs: Vec<IpAddr>, fallback: Vec<String>) -> Vec<SocketAddr> {
    let (up, search) = system_upstream(&fallback);
    log!(
        "DNS im Tunnel: fragt weiter bei {} {}",
        up.iter().map(|a| a.ip().to_string()).collect::<Vec<_>>().join(", "),
        if search.is_empty() { String::new() } else { format!("(kurze Namen + .{})", search.join(" / .")) }
    );
    *d.upstream.write().unwrap() = up;
    *d.search.write().unwrap() = search;
    let port: u16 = std::env::var("KVPN_DNS_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(53);
    let mut ok = Vec::new();
    for ip in addrs {
        let a = SocketAddr::new(ip, port);
        // die Adresse am TUN ist evtl. erst einen Moment spaeter da (IPv6 ohne DAD ist sofort da, sicher ist sicher)
        let mut udp = None;
        for _ in 0..10 {
            match UdpSocket::bind(a).await {
                Ok(s) => {
                    udp = Some(s);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(300)).await,
            }
        }
        let Some(udp) = udp else {
            log!("DNS im Tunnel: {a} nicht moeglich (Port belegt? z. B. dnsmasq/Pi-hole) – Geraete fragen weiter direkt");
            continue;
        };
        let tcp = TcpListener::bind(a).await.ok();
        let udp = Arc::new(udp);
        let (d1, u1) = (d.clone(), udp.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            loop {
                let Ok((n, from)) = u1.recv_from(&mut buf).await else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let q = buf[..n].to_vec();
                let (d, u) = (d1.clone(), u1.clone());
                tokio::spawn(async move {
                    let r = answer(&d, from.ip(), &q).await;
                    if !r.is_empty() {
                        let _ = u.send_to(&r, from).await;
                    }
                });
            }
        });
        if let Some(l) = tcp {
            let d2 = d.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((mut s, from)) = l.accept().await else {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    };
                    let d = d2.clone();
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(Duration::from_secs(30), async {
                            loop {
                                let mut l = [0u8; 2];
                                s.read_exact(&mut l).await.ok()?;
                                let mut q = vec![0u8; u16::from_be_bytes(l) as usize];
                                s.read_exact(&mut q).await.ok()?;
                                let r = answer(&d, from.ip(), &q).await;
                                let mut m = (r.len() as u16).to_be_bytes().to_vec();
                                m.extend_from_slice(&r);
                                s.write_all(&m).await.ok()?;
                            }
                            #[allow(unreachable_code)]
                            Some(())
                        })
                        .await;
                    });
                }
            });
        }
        ok.push(a);
    }
    *d.listening.lock().unwrap() = ok.clone();
    ok
}

fn list_file(state_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(state_dir).join("dns").join("sperrliste.txt")
}

/// gespeicherte Sperrliste laden (schnell, beim Start)
pub fn load_cached(d: &Dns, state_dir: &str) {
    if let Ok(t) = std::fs::read_to_string(list_file(state_dir)) {
        let set = parse_list(&t);
        let n = set.len();
        *d.list.write().unwrap() = set;
        *d.list_info.lock().unwrap() = format!("{n} Namen (gespeichert)");
    }
}

/// Sperrliste(n) neu laden (Internet) und speichern. Ergebnis: Anzahl Namen
pub fn refresh(d: &Dns, state_dir: &str, urls: &[String]) -> Result<usize, String> {
    let mut all = String::new();
    let mut errs = Vec::new();
    for u in urls {
        match crate::updates::fetch_url(u, MAX_LIST) {
            Ok(b) => {
                all.push_str(&String::from_utf8_lossy(&b));
                all.push('\n');
            }
            Err(e) => errs.push(e),
        }
    }
    if all.is_empty() {
        return Err(errs.join("; "));
    }
    let set = parse_list(&all);
    if set.len() < 10 {
        return Err("Sperrliste ist leer oder kein bekanntes Format".into());
    }
    let f = list_file(state_dir);
    let _ = std::fs::create_dir_all(f.parent().unwrap());
    let mut sorted: Vec<&String> = set.iter().collect();
    sorted.sort();
    let text: String = sorted.iter().map(|s| format!("{s}\n")).collect();
    let tmp = f.with_extension("neu");
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(&tmp, &f);
    }
    let n = set.len();
    *d.list.write().unwrap() = set;
    *d.list_info.lock().unwrap() = format!("{n} Namen, Stand {}", crate::stats::local_date(kvpn::util::now_secs()));
    if !errs.is_empty() {
        log!("DNS-Sperrliste: {}", errs.join("; "));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, t: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&t.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    #[test]
    fn liste_und_blocken() {
        let set = parse_list("# Kommentar\n0.0.0.0 ads.example.com\n127.0.0.1 localhost\n||tracker.example.net^\nplain.example.org # x\n0.0.0.0 0.0.0.0\n");
        assert!(set.contains("ads.example.com") && set.contains("tracker.example.net") && set.contains("plain.example.org"));
        assert_eq!(set.len(), 3);
        let d = Dns::new(true);
        *d.list.write().unwrap() = set;
        assert!(d.is_blocked("ADS.example.com."));
        assert!(!d.is_blocked("example.com"));
        assert!(!d.is_blocked("sub.ads.example.com"), "Liste: nur genaue Namen");
        d.set_own(&["doubleclick.net".into()], &["ads.example.com".into()]);
        assert!(d.is_blocked("x.y.doubleclick.net"), "eigene Sperren gelten fuer Unter-Namen");
        assert!(!d.is_blocked("ads.example.com"), "Ausnahme geht vor");
        d.on.store(false, Relaxed);
        assert!(!d.is_blocked("x.doubleclick.net"));
    }

    #[test]
    fn antworten() {
        let q = query("ads.example.com", 1);
        let (n, t, e) = question(&q).unwrap();
        assert_eq!((n.as_str(), t, e), ("ads.example.com", 1, q.len()));
        let r = blocked_reply(&q, t, e);
        assert_eq!(&r[..2], &[0x12, 0x34]);
        assert_eq!(r[2] & 0x80, 0x80);
        assert_eq!(ancount(&r), 1);
        assert_eq!(&r[r.len() - 4..], &[0, 0, 0, 0]);
        let r6 = blocked_reply(&query("x.y", 28), 28, query("x.y", 28).len());
        assert_eq!(&r6[r6.len() - 16..], &[0; 16]);
        let rt = blocked_reply(&query("x.y", 16), 16, query("x.y", 16).len());
        assert_eq!(ancount(&rt), 0);
        // kurzer Name -> mit Such-Domaene, Antwort zurueck auf den kurzen Namen
        let q = query("nas", 1);
        let (_, _, e) = question(&q).unwrap();
        let q2 = with_name(&q, e, "nas.fritz.box");
        assert_eq!(question(&q2).unwrap().0, "nas.fritz.box");
        let mut rep = q2.clone();
        rep[2] = 0x81;
        rep[3] = 0x80;
        rep[7] = 1;
        rep.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 192, 168, 178, 20]);
        let x = rename_reply(&q, e, &rep).unwrap();
        assert_eq!(question(&x).unwrap().0, "nas");
        assert_eq!(ancount(&x), 1);
        assert_eq!(&x[x.len() - 4..], &[192, 168, 178, 20]);
    }

    #[test]
    fn resolv_conf() {
        let dir = std::env::temp_dir().join(format!("kvpn-dns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("resolv.conf");
        std::fs::write(&f, "nameserver 127.0.0.53\noptions edns0\nsearch fritz.box\n").unwrap();
        std::env::set_var("KVPN_RESOLV_CONF", &f);
        let (ns, s) = system_upstream(&["1.1.1.1".into()]);
        std::env::remove_var("KVPN_RESOLV_CONF");
        assert_eq!(ns, vec!["127.0.0.53:53".parse::<SocketAddr>().unwrap()]);
        assert_eq!(s, vec!["fritz.box".to_string()]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
