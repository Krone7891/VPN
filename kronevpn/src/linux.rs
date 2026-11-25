//! Linux: TUN-Geraet, Adressen und Routen mit `ip`.

use crate::Args;
use kvpn::client::TunWriter;
use kvpn::code::ClientConfig;
use kvpn::fdtun::{self, FdTun};
use kvpn::transport::ProtectFn;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[path = "dienst_linux.rs"]
pub mod dienst;

fn ip(args: &[&str]) -> Result<String, String> {
    let o = Command::new("ip").args(args).output().map_err(|e| format!("ip: {e}"))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        Err(format!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim()))
    }
}

pub fn config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("/etc"))
        .join("kronevpn")
}

pub fn restrict_file(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}

pub fn system_proxy() -> Option<String> {
    ["https_proxy", "HTTPS_PROXY"].iter().find_map(|k| std::env::var(k).ok()).filter(|s| !s.is_empty())
}

/// Weg zum Internet vor dem Tunnel: (via, dev) fuer IPv4 bzw. IPv6
fn uplink(v6: bool) -> Option<(Option<String>, String)> {
    let probe = if v6 { "2606:4700:4700::1111" } else { "1.1.1.1" };
    let out = ip(&[if v6 { "-6" } else { "-4" }, "route", "get", probe]).ok()?;
    let w: Vec<&str> = out.split_whitespace().collect();
    let via = w.iter().position(|x| *x == "via").and_then(|i| w.get(i + 1)).map(|s| s.to_string());
    let dev = w.iter().position(|x| *x == "dev").and_then(|i| w.get(i + 1))?.to_string();
    Some((via, dev))
}

// ------------------------------------------------------------------------------------------------ Notbremse

const NB: &str = "KVPN-NB";

fn ipt(tool: &str, args: &[&str]) -> bool {
    Command::new(tool).arg("-w").args(args).output().map(|o| o.status.success()).unwrap_or(false)
}

/// Notbremse (Kill-Switch) unter Linux: eigene iptables-Kette vor allem anderen. Hinaus darf nur, was durch den
/// Tunnel geht, zum Server, localhost, DHCP/IPv6-Nachbarsuche, auf Wunsch das lokale Netz (ohne DNS) und die
/// Ausnahmen. Bleibt bei einem Absturz bestehen (dann kommt nichts unverschluesselt hinaus) – loesen:
/// kronevpn --notbremse aus
pub fn notbremse_an(tun: &str, lokal: bool, ziele: &[(std::net::IpAddr, u8)]) -> bool {
    let mut ok = true;
    for (tool, v6) in [("iptables", false), ("ip6tables", true)] {
        if !ipt(tool, &["-N", NB]) {
            ipt(tool, &["-F", NB]);
        }
        let mut r: Vec<Vec<String>> = vec![
            vec!["-o".into(), "lo".into()],
            vec!["-o".into(), tun.into()],
        ];
        if v6 {
            r.push(vec!["-p".into(), "ipv6-icmp".into()]);
            r.push(vec!["-p".into(), "udp".into(), "--sport".into(), "546".into(), "--dport".into(), "547".into()]);
        } else {
            r.push(vec!["-p".into(), "udp".into(), "--sport".into(), "68".into(), "--dport".into(), "67".into()]);
            // eigene Rueckfrage nach der Server-Adresse (kvpn::transport::direct_lookup)
            for d in ["1.1.1.1", "9.9.9.9", "8.8.8.8"] {
                r.push(vec!["-d".into(), d.into(), "-p".into(), "udp".into(), "--dport".into(), "53".into()]);
            }
        }
        for x in &r {
            let mut a: Vec<&str> = vec!["-A", NB];
            a.extend(x.iter().map(|s| s.as_str()));
            a.extend(["-j", "RETURN"]);
            ok &= ipt(tool, &a);
        }
        // DNS nie am Tunnel vorbei (auch nicht an den Router im lokalen Netz)
        for p in ["udp", "tcp"] {
            ipt(tool, &["-A", NB, "-p", p, "--dport", "53", "-j", "REJECT"]);
        }
        if lokal {
            let nets: &[&str] = if v6 { &["fe80::/10", "fc00::/7", "ff00::/8"] } else { &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"] };
            for n in nets {
                ipt(tool, &["-A", NB, "-d", n, "-j", "RETURN"]);
            }
        }
        for (a, p) in ziele.iter().filter(|(a, _)| a.is_ipv6() == v6) {
            ipt(tool, &["-A", NB, "-d", &format!("{a}/{p}"), "-j", "RETURN"]);
        }
        ok &= ipt(tool, &["-A", NB, "-j", "REJECT", "--reject-with", if v6 { "icmp6-adm-prohibited" } else { "icmp-admin-prohibited" }]);
        if !ipt(tool, &["-C", "OUTPUT", "-j", NB]) {
            ok &= ipt(tool, &["-I", "OUTPUT", "1", "-j", NB]);
        }
    }
    ok
}

/// Server-Adresse durch die Notbremse lassen
fn notbremse_server(a: std::net::IpAddr) {
    let tool = if a.is_ipv4() { "iptables" } else { "ip6tables" };
    let d = a.to_string();
    if !ipt(tool, &["-C", NB, "-d", &d, "-j", "RETURN"]) {
        ipt(tool, &["-I", NB, "1", "-d", &d, "-j", "RETURN"]);
    }
}

/// Notbremse loesen (VPN beendet oder Notbremse ausgeschaltet)
pub fn notbremse_aus() {
    for tool in ["iptables", "ip6tables"] {
        while ipt(tool, &["-D", "OUTPUT", "-j", NB]) {}
        ipt(tool, &["-F", NB]);
        ipt(tool, &["-X", NB]);
    }
}

/// Namen der Ausnahmen aufloesen (vor dem Einrichten der Routen)
fn ziele_aufloesen(names: &[String]) -> Vec<(std::net::IpAddr, u8)> {
    use std::net::ToSocketAddrs;
    let mut v = Vec::new();
    for n in names {
        match (n.as_str(), 443).to_socket_addrs() {
            Ok(it) => {
                for x in it {
                    let e = (x.ip(), if x.is_ipv4() { 32 } else { 128 });
                    if !v.contains(&e) {
                        v.push(e);
                    }
                }
            }
            Err(e) => crate::say(&format!("Ausnahme {n}: {e}")),
        }
    }
    v
}

pub struct Platform {
    tun: Arc<FdTun>,
    reader: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    name: String,
    full: bool,
    up4: Option<(Option<String>, String)>,
    up6: Option<(Option<String>, String)>,
    bypass: Arc<Mutex<Vec<String>>>,
    notbremse: bool,
}

impl Platform {
    pub fn setup(cfg: &ClientConfig, a: &Args) -> Result<Self, String> {
        let name = a.tun.clone();
        // Weg ins Internet merken, bevor der Tunnel die Standardroute uebernimmt
        let up4 = uplink(false);
        let up6 = uplink(true);
        let regeln = crate::regeln(a);
        let (mut ziele, namen) = regeln.ziele_aufteilen();
        ziele.extend(ziele_aufloesen(&namen));
        let fd = fdtun::open_linux_tun(&name, false).map_err(|e| format!("TUN anlegen: {e} (als root starten)"))?;
        let tun = Arc::new(FdTun::new(fd).map_err(|e| e.to_string())?);
        ip(&["link", "set", "dev", &name, "mtu", &cfg.mtu.to_string(), "up"])?;
        ip(&["addr", "replace", &cfg.ip4, "dev", &name])?;
        let mut v6 = false;
        if !cfg.ip6.is_empty() {
            match ip(&["-6", "addr", "replace", &cfg.ip6, "dev", &name, "nodad"]) {
                Ok(_) => v6 = true,
                Err(e) => crate::say(&format!("Hinweis: IPv6 im Tunnel nicht moeglich ({e}) – nur IPv4")),
            }
        }
        let full = a.routes.is_none();
        let routes: Vec<String> = match &a.routes {
            Some(r) => r.clone(),
            None => {
                let mut r = vec!["0.0.0.0/1".to_string(), "128.0.0.0/1".to_string()];
                if v6 {
                    r.push("::/1".into());
                    r.push("8000::/1".into());
                }
                r
            }
        };
        for r in &routes {
            if r.contains(':') {
                if let Err(e) = ip(&["-6", "route", "replace", r, "dev", &name]) {
                    crate::say(&format!("Hinweis: {e}"));
                }
            } else {
                ip(&["-4", "route", "replace", r, "dev", &name])?;
            }
        }
        if full && which("resolvectl") {
            let mut args = vec!["dns".to_string(), name.clone()];
            args.extend(cfg.dns.iter().cloned());
            let _ = Command::new("resolvectl").args(&args).output();
            let _ = Command::new("resolvectl").args(["domain", &name, "~."]).output();
        }
        crate::say(&format!("Tunnel {name}: {} {} – Routen: {}", cfg.ip4, cfg.ip6, routes.join(", ")));
        // Ausnahmen: am Tunnel vorbei ueber den bisherigen Weg
        let bypass = Arc::new(Mutex::new(Vec::new()));
        if full {
            for (a, p) in &ziele {
                let (up, fam) = if a.is_ipv4() { (&up4, "-4") } else { (&up6, "-6") };
                let Some((via, dev)) = up else { continue };
                let net = format!("{a}/{p}");
                let mut args = vec![fam, "route", "replace", net.as_str()];
                if let Some(v) = via {
                    args.extend(["via", v.as_str()]);
                }
                args.extend(["dev", dev.as_str()]);
                match ip(&args) {
                    Ok(_) => {
                        crate::say(&format!("Ausnahme am VPN vorbei: {net}"));
                        bypass.lock().unwrap().push(net);
                    }
                    Err(e) => crate::say(&format!("Ausnahme {net}: {e}")),
                }
            }
        }
        let notbremse = regeln.notbremse && full;
        if notbremse {
            if notbremse_an(&name, regeln.lokal_erlaubt, &ziele) {
                crate::say(&format!("Notbremse an: ohne VPN kein Internet{}", if regeln.lokal_erlaubt { " (lokales Netz erlaubt)" } else { "" }));
            } else {
                crate::say("Notbremse: iptables-Regeln nicht vollstaendig gesetzt (iptables/ip6tables installiert?)");
            }
        } else {
            notbremse_aus();
        }
        let (tx, rx) = mpsc::channel(4096);
        fdtun::spawn_reader(tun.clone(), tx);
        Ok(Platform { tun, reader: Mutex::new(Some(rx)), name, full, up4, up6, bypass, notbremse })
    }

    pub fn writer(&self) -> Arc<dyn TunWriter> {
        self.tun.clone()
    }

    pub fn take_reader(&self) -> mpsc::Receiver<Vec<u8>> {
        self.reader.lock().unwrap().take().expect("Reader schon vergeben")
    }

    /// Bei vollem Tunnel: Route zum Server am Tunnel vorbei (sonst liefe der Tunnel durch sich selbst)
    pub fn protect(&self) -> Option<ProtectFn> {
        if !self.full {
            return None;
        }
        let (up4, up6, bypass, nb) = (self.up4.clone(), self.up6.clone(), self.bypass.clone(), self.notbremse);
        Some(Arc::new(move |addr: std::net::IpAddr| {
            if nb {
                notbremse_server(addr);
            }
            let (up, host, fam) = if addr.is_ipv4() { (&up4, format!("{addr}/32"), "-4") } else { (&up6, format!("{addr}/128"), "-6") };
            let Some((via, dev)) = up else { return };
            let mut args = vec![fam, "route", "replace", host.as_str()];
            if let Some(v) = via {
                args.push("via");
                args.push(v);
            }
            args.push("dev");
            args.push(dev);
            if ip(&args).is_ok() {
                let mut b = bypass.lock().unwrap();
                if !b.contains(&host) {
                    b.push(host);
                }
            }
        }))
    }

    pub fn cleanup(&self) {
        for h in self.bypass.lock().unwrap().iter() {
            let _ = ip(&[if h.contains(':') { "-6" } else { "-4" }, "route", "del", h]);
        }
        // VPN bewusst beendet: Internet wieder frei
        if self.notbremse {
            notbremse_aus();
            crate::say("Notbremse geloest");
        }
        let _ = ip(&["link", "set", "dev", &self.name, "down"]);
    }
}

fn which(cmd: &str) -> bool {
    Command::new("sh").args(["-c", &format!("command -v {cmd}")]).output().map(|o| o.status.success()).unwrap_or(false)
}

pub async fn wait_for_exit() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
