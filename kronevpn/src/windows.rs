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

#[link(name = "kernel32")]
extern "system" {
    fn AttachConsole(pid: u32) -> i32;
    fn AllocConsole() -> i32;
    fn GetStdHandle(n: u32) -> isize;
    fn GetFileType(h: isize) -> u32;
}

/// Konsole fuer die Textanzeige holen (das Programm ist ein Fenster-Programm und hat sonst keine).
/// Ausgabe in eine Datei/Pipe umgeleitet (z. B. `--version` aus einem anderen Programm): nichts tun.
pub fn konsole(anhaengen: bool) {
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const FILE_TYPE_DISK: u32 = 1;
    const FILE_TYPE_PIPE: u32 = 3;
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if h != 0 && h != -1 && matches!(GetFileType(h), FILE_TYPE_DISK | FILE_TYPE_PIPE) {
            return;
        }
        if anhaengen && AttachConsole(ATTACH_PARENT_PROCESS) != 0 {
            return;
        }
        AllocConsole();
    }
}

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
    /// gesetzte Umgehungsrouten: (Server, Gateway, Schnittstelle)
    bypass: Arc<Mutex<Vec<(IpAddr, IpAddr, u32)>>>,
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
            let t = std::time::Instant::now();
            match route::bypass(addr, idx) {
                Ok((nh, ifi)) => {
                    let mut b = bypass.lock().unwrap();
                    let neu = (addr, nh, ifi);
                    if !b.contains(&neu) {
                        b.retain(|x| x.0 != addr);
                        b.push(neu);
                        crate::say(&format!("Umgehungsroute zum Server {addr} ueber {nh} (Schnittstelle {ifi}, {} ms)", t.elapsed().as_millis()));
                    }
                }
                Err(e) => crate::say(&format!("Umgehungsroute zum Server {addr}: {e}")),
            }
        }))
    }

    pub fn cleanup(&self) {
        for (a, _, _) in self.bypass.lock().unwrap().drain(..) {
            route::remove_host(a);
        }
        let _ = self.session.shutdown();
        let _ = cmd("ipconfig", &["/flushdns"]);
    }
}

/// Routen ueber die IP-Hilfs-API von Windows (iphlpapi) – frueher PowerShell (Get-NetRoute), das auf manchen
/// Rechnern 20-60 s pro Aufruf brauchte und den Verbindungsaufbau entsprechend verzoegerte.
mod route {
    use std::net::IpAddr;
    use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2, GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
        MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};

    fn family(a: IpAddr) -> u16 {
        if a.is_ipv4() { AF_INET } else { AF_INET6 }
    }

    fn to_sockaddr(a: IpAddr) -> SOCKADDR_INET {
        let mut s: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        match a {
            IpAddr::V4(v) => {
                s.Ipv4.sin_family = AF_INET;
                s.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v.octets());
            }
            IpAddr::V6(v) => {
                s.Ipv6.sin6_family = AF_INET6;
                s.Ipv6.sin6_addr.u.Byte = v.octets();
            }
        }
        s
    }

    fn from_sockaddr(s: &SOCKADDR_INET) -> Option<IpAddr> {
        unsafe {
            match s.si_family {
                AF_INET => Some(IpAddr::from(s.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes())),
                AF_INET6 => Some(IpAddr::from(s.Ipv6.sin6_addr.u.Byte)),
                _ => None,
            }
        }
    }

    /// alle Routen einer Adressfamilie (Kopie der Tabelle)
    fn table(fam: u16) -> Result<Vec<MIB_IPFORWARD_ROW2>, String> {
        let mut t: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        let rc = unsafe { GetIpForwardTable2(fam, &mut t) };
        if rc != NO_ERROR || t.is_null() {
            return Err(format!("Routentabelle nicht lesbar (Fehler {rc})"));
        }
        let rows = unsafe {
            let n = (*t).NumEntries as usize;
            let first = std::ptr::addr_of!((*t).Table) as *const MIB_IPFORWARD_ROW2;
            (0..n).map(|i| std::ptr::read(first.add(i))).collect()
        };
        unsafe { FreeMibTable(t as *const _) };
        Ok(rows)
    }

    /// Metrik der Schnittstelle; None = Schnittstelle nicht verbunden
    fn if_metric(fam: u16, idx: u32) -> Option<u32> {
        let mut r: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpInterfaceEntry(&mut r) };
        r.Family = fam;
        r.InterfaceIndex = idx;
        if unsafe { GetIpInterfaceEntry(&mut r) } != NO_ERROR {
            return Some(0);
        }
        (r.Connected != 0).then_some(r.Metric)
    }

    fn is_host(r: &MIB_IPFORWARD_ROW2, a: IpAddr) -> bool {
        let len = if a.is_ipv4() { 32 } else { 128 };
        r.DestinationPrefix.PrefixLength == len && from_sockaddr(&r.DestinationPrefix.Prefix) == Some(a)
    }

    /// Host-Route zu `a` ueber das beste normale Standard-Gateway (nicht den Tunnel `tun`) setzen.
    /// Ergebnis: (Gateway, Schnittstellen-Index)
    pub fn bypass(a: IpAddr, tun: u32) -> Result<(IpAddr, u32), String> {
        let fam = family(a);
        let rows = table(fam)?;
        let best = rows
            .iter()
            .filter(|r| r.DestinationPrefix.PrefixLength == 0 && r.InterfaceIndex != tun)
            .filter_map(|r| if_metric(fam, r.InterfaceIndex).map(|m| (r.Metric.saturating_add(m), r)))
            .min_by_key(|(m, _)| *m)
            .map(|(_, r)| r)
            .ok_or_else(|| format!("kein normales Standard-Gateway fuer {} gefunden", if a.is_ipv4() { "IPv4" } else { "IPv6" }))?;
        let nh = from_sockaddr(&best.NextHop).unwrap_or(IpAddr::from([0u8, 0, 0, 0]));
        // alte Host-Routen zum Server (z. B. ueber ein frueheres WLAN) entfernen
        for r in rows.iter().filter(|r| is_host(r, a)) {
            if r.InterfaceIndex == best.InterfaceIndex && from_sockaddr(&r.NextHop) == Some(nh) {
                return Ok((nh, best.InterfaceIndex));
            }
            unsafe { DeleteIpForwardEntry2(r) };
        }
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid = best.InterfaceLuid;
        row.InterfaceIndex = best.InterfaceIndex;
        row.DestinationPrefix.Prefix = to_sockaddr(a);
        row.DestinationPrefix.PrefixLength = if a.is_ipv4() { 32 } else { 128 };
        row.NextHop = best.NextHop;
        row.Metric = 1;
        match unsafe { CreateIpForwardEntry2(&row) } {
            NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => Ok((nh, best.InterfaceIndex)),
            rc => Err(format!("Route setzen fehlgeschlagen (Fehler {rc})")),
        }
    }

    /// Host-Routen zu `a` auf allen Schnittstellen entfernen
    pub fn remove_host(a: IpAddr) {
        if let Ok(rows) = table(family(a)) {
            for r in rows.iter().filter(|r| is_host(r, a)) {
                unsafe { DeleteIpForwardEntry2(r) };
            }
        }
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
