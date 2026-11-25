//! Netzwerk einrichten: Adressen am TUN, Weiterleitung, NAT, MSS-Anpassung. Wird beim Beenden wieder entfernt.

use crate::config::Config;
use crate::log;
use std::process::Command;

fn run(args: &[&str]) -> bool {
    match Command::new(args[0]).args(&args[1..]).output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            let e = String::from_utf8_lossy(&o.stderr);
            if !e.trim().is_empty() {
                log!("  ({}: {})", args.join(" "), e.trim());
            }
            false
        }
        Err(e) => {
            log!("  ({}: {e})", args[0]);
            false
        }
    }
}

fn quiet(args: &[&str]) -> bool {
    Command::new(args[0]).args(&args[1..]).output().map(|o| o.status.success()).unwrap_or(false)
}

/// Regel nur anlegen, wenn sie noch nicht existiert (-C pruefen)
fn ensure(tool: &str, table: &str, chain: &str, insert: bool, rule: &[&str]) {
    let mut chk = vec![tool, "-w", "-t", table, "-C", chain];
    chk.extend_from_slice(rule);
    if quiet(&chk) {
        return;
    }
    let mut add = vec![tool, "-w", "-t", table, if insert { "-I" } else { "-A" }, chain];
    if insert {
        add.push("1");
    }
    add.extend_from_slice(rule);
    run(&add);
}

fn remove(tool: &str, table: &str, chain: &str, rule: &[&str]) {
    let mut del = vec![tool, "-w", "-t", table, "-D", chain];
    del.extend_from_slice(rule);
    for _ in 0..4 {
        if !quiet(&del) {
            break;
        }
    }
}

fn write_sysctl(path: &str, v: &str) {
    if std::fs::write(path, v).is_err() {
        log!("  konnte {path} nicht setzen");
    }
}

struct Rules {
    tool: &'static str,
    net: String,
}

fn rules(cfg: &Config) -> Vec<Rules> {
    let (n4, p4) = cfg.net4().unwrap();
    let mut v = vec![Rules { tool: "iptables", net: format!("{n4}/{p4}") }];
    if let Some((n6, p6)) = cfg.net6().unwrap() {
        v.push(Rules { tool: "ip6tables", net: format!("{n6}/{p6}") });
    }
    v
}

pub fn setup(cfg: &Config) {
    let tun = cfg.tun.as_str();
    let (_, p4) = cfg.net4().unwrap();
    let mtu = cfg.mtu.to_string();
    run(&["ip", "link", "set", "dev", tun, "mtu", &mtu, "up"]);
    let a4 = format!("{}/{}", cfg.ip4(1), p4);
    run(&["ip", "addr", "replace", &a4, "dev", tun]);
    if let (Some(a6), Some((_, p6))) = (cfg.ip6(1), cfg.net6().unwrap()) {
        let a6 = format!("{a6}/{p6}");
        run(&["ip", "-6", "addr", "replace", &a6, "dev", tun, "nodad"]);
    }
    // Admin-Seite im VPN: Zugriff aus dem Tunnel erlauben (falls eine Firewall eingehend sperrt)
    if let Some(a) = cfg.admin_addr() {
        let (ip, port) = (a.ip().to_string(), a.port().to_string());
        ensure("iptables", "filter", "INPUT", true, &["-i", tun, "-d", &ip, "-p", "tcp", "--dport", &port, "-j", "ACCEPT", "-m", "comment", "--comment", "krone-vpn"]);
    }
    if !cfg.nat {
        log!("NAT/Weiterleitung: ausgeschaltet (nat = false)");
        return;
    }
    write_sysctl("/proc/sys/net/ipv4/ip_forward", "1");
    if cfg.net6().unwrap().is_some() {
        // Achtung: mit forwarding=1 nimmt Linux keine Router-Advertisements mehr an (accept_ra=1) – die eigene
        // IPv6-Adresse (DynDNS!) ginge verloren. Daher vorher accept_ra=2 auf allen Schnittstellen, die RAs nutzen.
        if let Ok(rd) = std::fs::read_dir("/proc/sys/net/ipv6/conf") {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n == "all" || n == "lo" || n == tun {
                    continue;
                }
                let p = format!("/proc/sys/net/ipv6/conf/{n}/accept_ra");
                if std::fs::read_to_string(&p).map(|s| s.trim() == "1").unwrap_or(false) {
                    write_sysctl(&p, "2");
                    log!("  {n}: accept_ra=2 (IPv6-Adresse bleibt trotz Weiterleitung erhalten)");
                }
            }
        }
        write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
    }
    for r in rules(cfg) {
        let net = r.net.as_str();
        ensure(r.tool, "nat", "POSTROUTING", false, &["-s", net, "!", "-o", tun, "-j", "MASQUERADE", "-m", "comment", "--comment", "krone-vpn"]);
        ensure(r.tool, "filter", "FORWARD", true, &["-i", tun, "-j", "ACCEPT", "-m", "comment", "--comment", "krone-vpn"]);
        ensure(
            r.tool,
            "filter",
            "FORWARD",
            true,
            &["-o", tun, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT", "-m", "comment", "--comment", "krone-vpn"],
        );
        for dir in ["-i", "-o"] {
            ensure(
                r.tool,
                "mangle",
                "FORWARD",
                false,
                &[dir, tun, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu", "-m", "comment", "--comment", "krone-vpn"],
            );
        }
    }
    if !cfg.lan_access {
        lan_block(cfg, true);
    }
    log!("Netz eingerichtet: {tun} {a4}{}, NAT an", cfg.ip6(1).map(|a| format!(" + {a}")).unwrap_or_default());
}

pub fn teardown(cfg: &Config) {
    let tun = cfg.tun.as_str();
    if let Some(a) = cfg.admin_addr() {
        let (ip, port) = (a.ip().to_string(), a.port().to_string());
        remove("iptables", "filter", "INPUT", &["-i", tun, "-d", &ip, "-p", "tcp", "--dport", &port, "-j", "ACCEPT", "-m", "comment", "--comment", "krone-vpn"]);
    }
    if !cfg.nat {
        return;
    }
    for r in rules(cfg) {
        let net = r.net.as_str();
        remove(r.tool, "nat", "POSTROUTING", &["-s", net, "!", "-o", tun, "-j", "MASQUERADE", "-m", "comment", "--comment", "krone-vpn"]);
        remove(r.tool, "filter", "FORWARD", &["-i", tun, "-j", "ACCEPT", "-m", "comment", "--comment", "krone-vpn"]);
        remove(
            r.tool,
            "filter",
            "FORWARD",
            &["-o", tun, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT", "-m", "comment", "--comment", "krone-vpn"],
        );
        for dir in ["-i", "-o"] {
            remove(
                r.tool,
                "mangle",
                "FORWARD",
                &[dir, tun, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu", "-m", "comment", "--comment", "krone-vpn"],
            );
        }
    }
    lan_block(cfg, false);
    log!("NAT-Regeln entfernt");
}

// ------------------------------------------------------------------------------------------------ DNS im Tunnel

/// Regeln fuer den eigenen DNS: alle DNS-Anfragen der Geraete (egal an welchen Server) gehen an den Server selbst;
/// DNS ueber TLS/QUIC (853) und die bekannten DNS-ueber-HTTPS-Server sind aus dem Tunnel gesperrt – Browser und
/// Android fallen dann auf normales DNS zurueck (sonst wuerden sie am Blocker vorbei fragen).
fn dns_rules(cfg: &Config, listen: &[std::net::SocketAddr]) -> Vec<(&'static str, &'static str, &'static str, Vec<String>)> {
    let tun = cfg.tun.clone();
    let mut v = Vec::new();
    for a in listen {
        let (tool, doh): (&str, &[&str]) = if a.is_ipv4() { ("iptables", crate::dns::DOH_IPS) } else { ("ip6tables", crate::dns::DOH_IPS6) };
        let to = if a.is_ipv4() { format!("{}:{}", a.ip(), a.port()) } else { format!("[{}]:{}", a.ip(), a.port()) };
        let c = |mut r: Vec<String>| {
            r.extend(["-m", "comment", "--comment", "krone-vpn"].map(String::from));
            r
        };
        for p in ["udp", "tcp"] {
            let s = |x: &[&str]| x.iter().map(|y| y.to_string()).collect::<Vec<_>>();
            v.push((tool, "nat", "PREROUTING", c(s(&["-i", &tun, "-p", p, "--dport", "53", "-j", "DNAT", "--to-destination", &to]))));
            v.push((tool, "filter", "INPUT", c(s(&["-i", &tun, "-d", &a.ip().to_string(), "-p", p, "--dport", &a.port().to_string(), "-j", "ACCEPT"]))));
            v.push((tool, "filter", "FORWARD", c(s(&["-i", &tun, "-p", p, "--dport", "853", "-j", "REJECT"]))));
            for ip in doh {
                let rej = if p == "tcp" { vec!["-j", "REJECT", "--reject-with", "tcp-reset"] } else { vec!["-j", "REJECT"] };
                let mut r = s(&["-i", &tun, "-d", ip, "-p", p, "--dport", "443"]);
                r.extend(s(&rej));
                v.push((tool, "filter", "FORWARD", c(r)));
            }
        }
    }
    v
}

/// DNS-Umleitung einrichten (`on`) oder entfernen
pub fn dns_redirect(cfg: &Config, listen: &[std::net::SocketAddr], on: bool) {
    for (tool, table, chain, rule) in dns_rules(cfg, listen) {
        let r: Vec<&str> = rule.iter().map(|s| s.as_str()).collect();
        if on {
            ensure(tool, table, chain, true, &r);
        } else {
            remove(tool, table, chain, &r);
        }
    }
    if on && !listen.is_empty() {
        log!("DNS der Geraete laeuft ueber den Server ({})", listen.iter().map(|a| a.ip().to_string()).collect::<Vec<_>>().join(", "));
    }
}

// ------------------------------------------------------------------------------------------------ Heimnetz

/// wie `lan_nets`, aber hoechstens jede Minute neu ermittelt (fuer die Admin-Seite)
pub fn lan_nets_cached(cfg: &Config) -> Vec<String> {
    static C: std::sync::Mutex<(u64, Vec<String>)> = std::sync::Mutex::new((0, Vec::new()));
    let now = kvpn::util::now_secs();
    let mut c = C.lock().unwrap();
    if now.saturating_sub(c.0) > 60 {
        *c = (now, lan_nets(cfg));
    }
    c.1.clone()
}

/// Netze, die der Server direkt erreicht (Heimnetz, ohne den Tunnel selbst): z. B. ["192.168.178.0/24"]
pub fn lan_nets(cfg: &Config) -> Vec<String> {
    let mut v = Vec::new();
    for fam in ["-4", "-6"] {
        let Ok(o) = Command::new("ip").args([fam, "-o", "route", "show", "scope", "link"]).output() else { continue };
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            let mut it = l.split_whitespace();
            let Some(net) = it.next() else { continue };
            let dev = l.split_whitespace().skip_while(|w| *w != "dev").nth(1).unwrap_or("");
            if dev == cfg.tun || dev == "lo" || dev.starts_with("veth") || net.starts_with("fe80") || net.starts_with("ff") || net == "default" {
                continue;
            }
            let ok = match kvpn::util::parse_cidr(net) {
                Ok((std::net::IpAddr::V4(a), _)) => a.is_private(),
                Ok((std::net::IpAddr::V6(a), _)) => (a.segments()[0] & 0xfe00) == 0xfc00,
                Err(_) => false,
            };
            if ok && !v.contains(&net.to_string()) {
                v.push(net.to_string());
            }
        }
    }
    v
}

fn lan_rules(cfg: &Config) -> Vec<(&'static str, Vec<String>)> {
    let tun = cfg.tun.clone();
    let mut v = Vec::new();
    for (tool, nets) in [("iptables", vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]), ("ip6tables", vec!["fc00::/7"])] {
        for n in nets {
            v.push((tool, ["-i", &tun, "!", "-o", &tun, "-d", n, "-j", "REJECT", "-m", "comment", "--comment", "krone-vpn"].iter().map(|s| s.to_string()).collect()));
        }
    }
    v
}

/// Heimnetz fuer die Geraete sperren (`block`) oder wieder freigeben. Der Server selbst (Admin-Seite, DNS) bleibt
/// erreichbar (laeuft nicht ueber FORWARD), Geraete untereinander auch (-o Tunnel ist ausgenommen).
pub fn lan_block(cfg: &Config, block: bool) {
    for (tool, rule) in lan_rules(cfg) {
        let r: Vec<&str> = rule.iter().map(|s| s.as_str()).collect();
        if block {
            ensure(tool, "filter", "FORWARD", true, &r);
        } else {
            remove(tool, "filter", "FORWARD", &r);
        }
    }
}
