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

pub struct Platform {
    tun: Arc<FdTun>,
    reader: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    name: String,
    full: bool,
    up4: Option<(Option<String>, String)>,
    up6: Option<(Option<String>, String)>,
    bypass: Arc<Mutex<Vec<String>>>,
}

impl Platform {
    pub fn setup(cfg: &ClientConfig, a: &Args) -> Result<Self, String> {
        let name = a.tun.clone();
        // Weg ins Internet merken, bevor der Tunnel die Standardroute uebernimmt
        let up4 = uplink(false);
        let up6 = uplink(true);
        let fd = fdtun::open_linux_tun(&name, false).map_err(|e| format!("TUN anlegen: {e} (als root starten)"))?;
        let tun = Arc::new(FdTun::new(fd).map_err(|e| e.to_string())?);
        ip(&["link", "set", "dev", &name, "mtu", &cfg.mtu.to_string(), "up"])?;
        ip(&["addr", "replace", &cfg.ip4, "dev", &name])?;
        let mut v6 = false;
        if !cfg.ip6.is_empty() {
            match ip(&["-6", "addr", "replace", &cfg.ip6, "dev", &name, "nodad"]) {
                Ok(_) => v6 = true,
                Err(e) => println!("Hinweis: IPv6 im Tunnel nicht moeglich ({e}) – nur IPv4"),
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
                    println!("Hinweis: {e}");
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
        println!("Tunnel {name}: {} {} – Routen: {}", cfg.ip4, cfg.ip6, routes.join(", "));
        let (tx, rx) = mpsc::channel(4096);
        fdtun::spawn_reader(tun.clone(), tx);
        Ok(Platform { tun, reader: Mutex::new(Some(rx)), name, full, up4, up6, bypass: Arc::new(Mutex::new(Vec::new())) })
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
        let (up4, up6, bypass) = (self.up4.clone(), self.up6.clone(), self.bypass.clone());
        Some(Arc::new(move |addr: std::net::IpAddr| {
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
