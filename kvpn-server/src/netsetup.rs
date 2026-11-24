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
    log!("Netz eingerichtet: {tun} {a4}{}, NAT an", cfg.ip6(1).map(|a| format!(" + {a}")).unwrap_or_default());
}

pub fn teardown(cfg: &Config) {
    if !cfg.nat {
        return;
    }
    let tun = cfg.tun.as_str();
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
    log!("NAT-Regeln entfernt");
}
