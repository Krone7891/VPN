//! Notbremse (Kill-Switch) fuer Windows: Filter der Windows-Filterplattform (WFP), wie bei WireGuard fuer Windows.
//!
//! Solange die Notbremse an ist und der VPN-Dienst laeuft, darf ins Netz nur:
//!   * was durch den Tunnel (KroneVPN-Adapter) geht,
//!   * KroneVPN selbst (die verschluesselte Verbindung zum Server),
//!   * localhost, DHCP und IPv6-Nachbarsuche (sonst gaebe es gar keine Adresse im WLAN),
//!   * auf Wunsch das lokale Netz (Drucker, Router) – aber nie DNS daran vorbei,
//!   * die Ausnahmen (Ziele am VPN vorbei).
//! Alles andere wird blockiert – faellt die Verbindung zum Server aus, geht also nichts unverschluesselt hinaus.
//!
//! Die Filter gehoeren zu einer "dynamischen Sitzung": Windows entfernt sie von selbst, sobald der Dienst endet
//! (VPN getrennt, Dienst beendet). Ein Fehler beim Einrichten laesst gar keine Filter zurueck (alles in einer
//! Transaktion), dann laeuft das VPN ohne Notbremse weiter.

use std::net::IpAddr;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

const RPC_C_AUTHN_WINNT: u32 = 10;
/// eigene Unterebene (fest, damit man sie in "netsh wfp show filters" wiederfindet)
const SUBLAYER: GUID = GUID::from_u128(0x6b726f6e_6e62_7265_6d73_650000000001);

pub struct Notbremse {
    engine: HANDLE,
}

// der Engine-Handle darf zwischen Threads wandern (nur geschlossen wird er)
unsafe impl Send for Notbremse {}
unsafe impl Sync for Notbremse {}

impl Drop for Notbremse {
    fn drop(&mut self) {
        // schliessen = dynamische Sitzung endet = alle Filter weg
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// eine Bedingung (die Werte muessen bis zum FwpmFilterAdd0 leben – daher die Zeiger auf `Halter`)
struct Bed {
    field: GUID,
    matcht: FWP_MATCH_TYPE,
    typ: FWP_DATA_TYPE,
    val: FWP_CONDITION_VALUE0_0,
}

/// haelt Werte, auf die Bedingungen zeigen
#[derive(Default)]
struct Halter {
    u64s: Vec<Box<u64>>,
    v4: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    v6: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
}

impl Halter {
    fn luid(&mut self, l: u64) -> Bed {
        let mut b = Box::new(l);
        let p: *mut u64 = &mut *b;
        self.u64s.push(b);
        Bed { field: FWPM_CONDITION_IP_LOCAL_INTERFACE, matcht: FWP_MATCH_EQUAL, typ: FWP_UINT64, val: FWP_CONDITION_VALUE0_0 { uint64: p } }
    }
    fn netz(&mut self, a: IpAddr, prefix: u8) -> Bed {
        match a {
            IpAddr::V4(v) => {
                let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32) as u32) };
                let mut b = Box::new(FWP_V4_ADDR_AND_MASK { addr: u32::from(v) & mask, mask });
                let p: *mut FWP_V4_ADDR_AND_MASK = &mut *b;
                self.v4.push(b);
                Bed { field: FWPM_CONDITION_IP_REMOTE_ADDRESS, matcht: FWP_MATCH_EQUAL, typ: FWP_V4_ADDR_MASK, val: FWP_CONDITION_VALUE0_0 { v4AddrMask: p } }
            }
            IpAddr::V6(v) => {
                let mut b = Box::new(FWP_V6_ADDR_AND_MASK { addr: v.octets(), prefixLength: prefix.min(128) });
                let p: *mut FWP_V6_ADDR_AND_MASK = &mut *b;
                self.v6.push(b);
                Bed { field: FWPM_CONDITION_IP_REMOTE_ADDRESS, matcht: FWP_MATCH_EQUAL, typ: FWP_V6_ADDR_MASK, val: FWP_CONDITION_VALUE0_0 { v6AddrMask: p } }
            }
        }
    }
}

fn proto(p: u8) -> Bed {
    Bed { field: FWPM_CONDITION_IP_PROTOCOL, matcht: FWP_MATCH_EQUAL, typ: FWP_UINT8, val: FWP_CONDITION_VALUE0_0 { uint8: p } }
}
fn lport(p: u16) -> Bed {
    Bed { field: FWPM_CONDITION_IP_LOCAL_PORT, matcht: FWP_MATCH_EQUAL, typ: FWP_UINT16, val: FWP_CONDITION_VALUE0_0 { uint16: p } }
}
fn rport(p: u16) -> Bed {
    Bed { field: FWPM_CONDITION_IP_REMOTE_PORT, matcht: FWP_MATCH_EQUAL, typ: FWP_UINT16, val: FWP_CONDITION_VALUE0_0 { uint16: p } }
}
fn loopback() -> Bed {
    Bed { field: FWPM_CONDITION_FLAGS, matcht: FWP_MATCH_FLAGS_ALL_SET, typ: FWP_UINT32, val: FWP_CONDITION_VALUE0_0 { uint32: FWP_CONDITION_FLAG_IS_LOOPBACK } }
}

const V4: [GUID; 2] = [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4];
const V6: [GUID; 2] = [FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6];

impl Notbremse {
    fn add(&self, name: &str, layer: GUID, weight: u8, permit: bool, conds: &[Bed]) -> Result<(), String> {
        let mut c: Vec<FWPM_FILTER_CONDITION0> = conds
            .iter()
            .map(|b| FWPM_FILTER_CONDITION0 { fieldKey: b.field, matchType: b.matcht, conditionValue: FWP_CONDITION_VALUE0 { r#type: b.typ, Anonymous: b.val } })
            .collect();
        let mut n = wide(&format!("KroneVPN Notbremse: {name}"));
        let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        f.displayData.name = n.as_mut_ptr();
        f.subLayerKey = SUBLAYER;
        f.layerKey = layer;
        f.weight = FWP_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_VALUE0_0 { uint8: weight } };
        f.numFilterConditions = c.len() as u32;
        f.filterCondition = if c.is_empty() { std::ptr::null_mut() } else { c.as_mut_ptr() };
        f.action.r#type = if permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK };
        // Erlaubnis/Sperre nicht von anderen Unterebenen (z. B. Fremd-Firewalls) ueberstimmbar machen
        f.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        let mut id = 0u64;
        let rc = unsafe { FwpmFilterAdd0(self.engine, &f, std::ptr::null_mut(), &mut id) };
        if rc != 0 {
            return Err(format!("Filter „{name}“: Fehler 0x{rc:08x}"));
        }
        Ok(())
    }

    fn both(&self, name: &str, layers: &[GUID], weight: u8, permit: bool, conds: &[Bed]) -> Result<(), String> {
        for l in layers {
            self.add(name, *l, weight, permit, conds)?;
        }
        Ok(())
    }

    /// Notbremse einschalten. `tun_luid` = KroneVPN-Adapter, `lokal` = lokales Netz erlauben,
    /// `ausnahmen` = Ziele am VPN vorbei (Netze)
    pub fn an(tun_luid: u64, lokal: bool, ausnahmen: &[(IpAddr, u8)]) -> Result<Notbremse, String> {
        let mut name = wide("KroneVPN Notbremse");
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.displayData.name = name.as_mut_ptr();
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.txnWaitTimeoutInMSec = 10_000;
        let mut engine: HANDLE = std::ptr::null_mut();
        let rc = unsafe { FwpmEngineOpen0(std::ptr::null(), RPC_C_AUTHN_WINNT, std::ptr::null(), &session, &mut engine) };
        if rc != 0 {
            return Err(format!("Windows-Filterplattform nicht erreichbar (Fehler 0x{rc:08x})"));
        }
        let nb = Notbremse { engine };
        if unsafe { FwpmTransactionBegin0(engine, 0) } != 0 {
            return Err("Windows-Filterplattform: Transaktion nicht moeglich".into());
        }
        match nb.filter(tun_luid, lokal, ausnahmen) {
            Ok(()) => {
                let rc = unsafe { FwpmTransactionCommit0(engine) };
                if rc != 0 {
                    return Err(format!("Notbremse: Filter nicht uebernommen (Fehler 0x{rc:08x})"));
                }
                Ok(nb)
            }
            Err(e) => {
                unsafe { FwpmTransactionAbort0(engine) };
                Err(e)
            }
        }
    }

    /// spaeter dazugekommene Ausnahmen erlauben (neue Adressen eines Namens)
    pub fn erlauben(&self, netze: &[(IpAddr, u8)]) {
        let mut h = Halter::default();
        for (a, p) in netze {
            let b = h.netz(*a, *p);
            let _ = self.both("Ausnahme", if a.is_ipv4() { &V4 } else { &V6 }, 12, true, &[b]);
        }
    }

    fn filter(&self, tun_luid: u64, lokal: bool, ausnahmen: &[(IpAddr, u8)]) -> Result<(), String> {
        let mut sl: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        let mut n = wide("KroneVPN Notbremse");
        sl.subLayerKey = SUBLAYER;
        sl.displayData.name = n.as_mut_ptr();
        sl.weight = u16::MAX;
        let rc = unsafe { FwpmSubLayerAdd0(self.engine, &sl, std::ptr::null_mut()) };
        if rc != 0 {
            return Err(format!("Unterebene anlegen: Fehler 0x{rc:08x}"));
        }
        let mut h = Halter::default();
        let all: Vec<GUID> = V4.iter().chain(V6.iter()).cloned().collect();
        // 1. alles durch den Tunnel
        let tun = h.luid(tun_luid);
        self.both("Tunnel", &all, 15, true, &[tun])?;
        // 2. KroneVPN selbst (Verbindung zum Server, eigene DNS-Abfrage am Tunnel vorbei)
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        let w = wide(&exe.to_string_lossy());
        let rc = unsafe { FwpmGetAppIdFromFileName0(w.as_ptr(), &mut blob) };
        if rc != 0 || blob.is_null() {
            return Err(format!("Programm-Kennung fuer {}: Fehler 0x{rc:08x}", exe.display()));
        }
        let app = Bed { field: FWPM_CONDITION_ALE_APP_ID, matcht: FWP_MATCH_EQUAL, typ: FWP_BYTE_BLOB_TYPE, val: FWP_CONDITION_VALUE0_0 { byteBlob: blob } };
        let r = self.both("KroneVPN", &all, 15, true, &[app]);
        unsafe { FwpmFreeMemory0(&mut (blob as *mut core::ffi::c_void)) };
        r?;
        // 3. localhost
        self.both("localhost", &all, 15, true, &[loopback()])?;
        // 4. DHCP (IPv4: 68 -> 67, IPv6: 546 -> 547) und IPv6-Nachbarsuche (ICMPv6 133-137)
        self.both("DHCP", &V4, 15, true, &[proto(17), lport(68), rport(67)])?;
        self.both("DHCPv6", &V6, 15, true, &[proto(17), lport(546), rport(547)])?;
        for t in 133..=137u16 {
            // bei ICMP steht der Typ in "lokaler Port"
            self.both("IPv6-Nachbarsuche", &V6, 15, true, &[proto(58), lport(t)])?;
        }
        // 5. DNS (Port 53) nie am Tunnel vorbei – auch nicht an den Router im lokalen Netz (Datenleck)
        for p in [17u8, 6] {
            self.both("DNS nur durch den Tunnel", &all, 14, false, &[proto(p), rport(53)])?;
        }
        // 6. lokales Netz (auf Wunsch)
        if lokal {
            for (a, p) in [("10.0.0.0", 8), ("172.16.0.0", 12), ("192.168.0.0", 16), ("169.254.0.0", 16), ("224.0.0.0", 4), ("255.255.255.255", 32)] {
                let b = h.netz(a.parse().unwrap(), p);
                self.both("lokales Netz", &V4, 12, true, &[b])?;
            }
            for (a, p) in [("fe80::", 10), ("fc00::", 7), ("ff00::", 8)] {
                let b = h.netz(a.parse().unwrap(), p);
                self.both("lokales Netz", &V6, 12, true, &[b])?;
            }
        }
        // 7. Ausnahmen (Ziele am VPN vorbei)
        for (a, p) in ausnahmen {
            let b = h.netz(*a, *p);
            self.both("Ausnahme", if a.is_ipv4() { &V4 } else { &V6 }, 12, true, &[b])?;
        }
        // 8. alles andere sperren
        self.both("alles andere sperren", &all, 0, false, &[])?;
        drop(h);
        Ok(())
    }
}
