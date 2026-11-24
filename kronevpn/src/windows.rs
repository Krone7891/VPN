//! Windows: Wintun-Adapter (Treiber steckt in der EXE), Adressen/Routen/DNS mit netsh, Umgehungsroute zum Server.

use crate::Args;
use kvpn::client::TunWriter;
use kvpn::code::ClientConfig;
use kvpn::transport::ProtectFn;
use std::net::IpAddr;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[path = "dienst_windows.rs"]
pub mod dienst;

const WINTUN_DLL: &[u8] = include_bytes!("../wintun/wintun.dll");
const ADAPTER: &str = "KroneVPN";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// feste GUID, damit Windows den Adapter wiedererkennt (kein neues "Netzwerk 2, 3, ..." bei jedem Start)
const GUID: u128 = 0x6b726f6e_6576_706e_8a1c_2d3e4f506172;

pub fn config_dir() -> PathBuf {
    std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(".")).join("KroneVPN")
}

pub fn restrict_file(_p: &Path) {}

fn cmd(prog: &str, args: &[&str]) -> Result<String, String> {
    let o = Command::new(prog).args(args).creation_flags(CREATE_NO_WINDOW).output().map_err(|e| format!("{prog}: {e}"))?;
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    if o.status.success() {
        Ok(out)
    } else {
        Err(format!("{prog} {}: {}{}", args.join(" "), out.trim(), String::from_utf8_lossy(&o.stderr).trim()))
    }
}

fn netsh(args: &[&str]) -> Result<String, String> {
    cmd("netsh", args)
}

/// Systemproxy aus den Internetoptionen (wie Edge/Chrome); bei Firmen-PCs oft der Sophos-Proxy
pub fn system_proxy() -> Option<String> {
    let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    let en = cmd("reg", &["query", key, "/v", "ProxyEnable"]).ok()?;
    if !en.contains("0x1") {
        return None;
    }
    let srv = cmd("reg", &["query", key, "/v", "ProxyServer"]).ok()?;
    let val = srv.lines().find(|l| l.contains("ProxyServer"))?.split_whitespace().last()?.to_string();
    // "host:port" oder "http=host:port;https=host:port"
    if val.contains('=') {
        val.split(';').find_map(|p| p.strip_prefix("https=").or_else(|| p.strip_prefix("http=")).map(String::from))
    } else {
        Some(val)
    }
}

struct WinTun(Arc<wintun::Session>);

impl TunWriter for WinTun {
    fn write_packet(&self, pkt: &[u8]) {
        if let Ok(mut p) = self.0.allocate_send_packet(pkt.len() as u16) {
            p.bytes_mut().copy_from_slice(pkt);
            self.0.send_packet(p);
        }
    }
}

pub struct Platform {
    session: Arc<wintun::Session>,
    _adapter: Arc<wintun::Adapter>,
    reader: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    idx: u32,
    bypass: Arc<Mutex<Vec<IpAddr>>>,
    full: bool,
}

fn load_wintun() -> Result<wintun::Wintun, String> {
    let dir = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData")).join("KroneVPN");
    let _ = std::fs::create_dir_all(&dir);
    let dll = dir.join("wintun.dll");
    if std::fs::read(&dll).map(|b| b != WINTUN_DLL).unwrap_or(true) {
        std::fs::write(&dll, WINTUN_DLL).map_err(|e| format!("{}: {e} (als Administrator starten)", dll.display()))?;
    }
    unsafe { wintun::load_from_path(&dll) }.map_err(|e| format!("Wintun laden: {e}"))
}

fn mask(prefix: u8) -> String {
    let m: u32 = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    std::net::Ipv4Addr::from(m).to_string()
}

impl Platform {
    pub fn setup(cfg: &ClientConfig, a: &Args) -> Result<Self, String> {
        let w = load_wintun()?;
        let adapter = match wintun::Adapter::open(&w, ADAPTER) {
            Ok(ad) => ad,
            Err(_) => wintun::Adapter::create(&w, ADAPTER, ADAPTER, Some(GUID)).map_err(|e| format!("Netzwerkadapter anlegen: {e} (als Administrator starten)"))?,
        };
        let idx = adapter.get_adapter_index().map_err(|e| format!("Adapter-Index: {e}"))?;
        let i = idx.to_string();
        let (ip4, p4) = kvpn::util::parse_cidr(&cfg.ip4)?;
        let gw4 = match ip4 {
            IpAddr::V4(a) => std::net::Ipv4Addr::from((u32::from(a) & (!0u32 << (32 - p4))) + 1).to_string(),
            _ => return Err("ip4 ist keine IPv4-Adresse".into()),
        };
        // ein frisch angelegter Adapter ist manchmal erst nach einem Moment bereit
        let mut tries = 0;
        loop {
            match netsh(&["interface", "ipv4", "set", "address", &format!("name={i}"), "source=static", &format!("address={ip4}"), &format!("mask={}", mask(p4)), "gateway=none"]) {
                Ok(_) => break,
                Err(e) if tries >= 5 => return Err(e),
                Err(_) => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(800));
                }
            }
        }
        let _ = netsh(&["interface", "ipv4", "set", "subinterface", &i, &format!("mtu={}", cfg.mtu), "store=active"]);
        let _ = netsh(&["interface", "ipv6", "set", "subinterface", &i, &format!("mtu={}", cfg.mtu.max(1280)), "store=active"]);
        let _ = netsh(&["interface", "ipv4", "set", "interface", &i, "metric=1"]);
        let _ = netsh(&["interface", "ipv6", "set", "interface", &i, "metric=1"]);
        let mut gw6 = String::new();
        if !cfg.ip6.is_empty() {
            let (a6, p6) = kvpn::util::parse_cidr(&cfg.ip6)?;
            if let IpAddr::V6(a) = a6 {
                gw6 = std::net::Ipv6Addr::from((u128::from(a) & (!0u128 << (128 - p6))) + 1).to_string();
            }
            let _ = netsh(&["interface", "ipv6", "add", "address", &format!("interface={i}"), &format!("address={}", cfg.ip6), "store=active"]);
        }
        let full = a.routes.is_none();
        let routes: Vec<String> = a.routes.clone().unwrap_or_else(|| vec!["0.0.0.0/1".into(), "128.0.0.0/1".into(), "::/1".into(), "8000::/1".into()]);
        for r in &routes {
            if r.contains(':') {
                // auch ohne IPv6 im Tunnel: IPv6 laeuft in den Tunnel (und wird dort verworfen) statt daran vorbei
                let mut args = vec!["interface", "ipv6", "add", "route", r.as_str(), i.as_str()];
                if !gw6.is_empty() {
                    args.push(gw6.as_str());
                }
                args.extend(["metric=1", "store=active"]);
                netsh(&args).ok();
            } else {
                netsh(&["interface", "ipv4", "add", "route", r, &i, &gw4, "metric=1", "store=active"])?;
            }
        }
        if full {
            let v4: Vec<&String> = cfg.dns.iter().filter(|d| !d.contains(':')).collect();
            let v6: Vec<&String> = cfg.dns.iter().filter(|d| d.contains(':')).collect();
            for (fam, list) in [("ipv4", v4), ("ipv6", v6)] {
                for (n, d) in list.iter().enumerate() {
                    if n == 0 {
                        let _ = netsh(&["interface", fam, "set", "dnsservers", &format!("name={i}"), "source=static", &format!("address={d}"), "register=none", "validate=no"]);
                    } else {
                        let _ = netsh(&["interface", fam, "add", "dnsservers", &format!("name={i}"), &format!("address={d}"), &format!("index={}", n + 1), "validate=no"]);
                    }
                }
            }
            let _ = cmd("ipconfig", &["/flushdns"]);
        }
        crate::say(&format!("Adapter {ADAPTER} (Index {idx}): {} {} – Routen: {}", cfg.ip4, cfg.ip6, routes.join(", ")));

        let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).map_err(|e| format!("Wintun-Sitzung: {e}"))?);
        let (tx, rx) = mpsc::channel(4096);
        let s = session.clone();
        std::thread::Builder::new()
            .name("wintun-lesen".into())
            .spawn(move || {
                while let Ok(p) = s.receive_blocking() {
                    if tx.blocking_send(p.bytes().to_vec()).is_err() {
                        break;
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Platform { session, _adapter: adapter, reader: Mutex::new(Some(rx)), idx, bypass: Arc::new(Mutex::new(Vec::new())), full })
    }

    pub fn writer(&self) -> Arc<dyn TunWriter> {
        Arc::new(WinTun(self.session.clone()))
    }

    pub fn take_reader(&self) -> mpsc::Receiver<Vec<u8>> {
        self.reader.lock().unwrap().take().expect("Reader schon vergeben")
    }

    /// Route zum Server ueber das normale Netz (WLAN/LAN) statt durch den Tunnel
    pub fn protect(&self) -> Option<ProtectFn> {
        if !self.full {
            return None;
        }
        let idx = self.idx;
        let bypass = self.bypass.clone();
        Some(Arc::new(move |addr: IpAddr| {
            let fam = if addr.is_ipv4() { "IPv4" } else { "IPv6" };
            let dflt = if addr.is_ipv4() { "0.0.0.0/0" } else { "::/0" };
            let ps = format!(
                "$r = Get-NetRoute -AddressFamily {fam} -DestinationPrefix '{dflt}' -ErrorAction SilentlyContinue | Where-Object {{ $_.InterfaceIndex -ne {idx} }} | \
                 Sort-Object {{ $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily {fam}).InterfaceMetric }} | Select-Object -First 1; \
                 if ($r) {{ \"$($r.NextHop) $($r.InterfaceIndex)\" }}"
            );
            let Ok(out) = cmd("powershell", &["-NoProfile", "-NonInteractive", "-Command", &ps]) else { return };
            let mut it = out.split_whitespace();
            let (Some(nh), Some(ifi)) = (it.next(), it.next()) else { return };
            let host = if addr.is_ipv4() { format!("{addr}/32") } else { format!("{addr}/128") };
            let fam_l = if addr.is_ipv4() { "ipv4" } else { "ipv6" };
            let _ = netsh(&["interface", fam_l, "delete", "route", &host, ifi]);
            if netsh(&["interface", fam_l, "add", "route", &host, ifi, nh, "metric=1", "store=active"]).is_ok() {
                let mut b = bypass.lock().unwrap();
                if !b.contains(&addr) {
                    b.push(addr);
                }
            }
        }))
    }

    pub fn cleanup(&self) {
        for a in self.bypass.lock().unwrap().iter() {
            let (fam, host) = if a.is_ipv4() { ("ipv4", format!("{a}/32")) } else { ("ipv6", format!("{a}/128")) };
            // Route auf allen Schnittstellen entfernen (der Weg kann sich geaendert haben)
            let _ = cmd("powershell", &["-NoProfile", "-NonInteractive", "-Command", &format!("Remove-NetRoute -DestinationPrefix '{host}' -Confirm:$false -ErrorAction SilentlyContinue")]);
            let _ = fam;
        }
        let _ = self.session.shutdown();
        let _ = cmd("ipconfig", &["/flushdns"]);
    }
}

pub async fn wait_for_exit() {
    let mut close = tokio::signal::windows::ctrl_close().ok();
    let mut brk = tokio::signal::windows::ctrl_break().ok();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = async { match close.as_mut() { Some(c) => { c.recv().await; } None => std::future::pending::<()>().await } } => {}
        _ = async { match brk.as_mut() { Some(c) => { c.recv().await; } None => std::future::pending::<()>().await } } => {}
    }
}
