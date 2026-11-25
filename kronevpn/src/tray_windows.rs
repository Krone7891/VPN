//! Windows: Symbol im Infobereich (neben der Uhr) – "KroneVPN.exe --symbol".
//!
//!   * Farbe zeigt den Zustand (gruen verbunden, gelb verbindet, blau pausiert, grau aus), Tooltip mit Datenrate
//!   * Linksklick: Programmfenster oeffnen
//!   * Rechtsklick: Verbinden/Trennen, Geschwindigkeit testen, Fenster oeffnen, beim Anmelden starten, schliessen
//!   * Meldung (Sprechblase), wenn die Verbindung abreisst bzw. ein Geschwindigkeitstest fertig ist
//!
//! Laeuft als normaler Benutzer (ohne Admin), liest nur status.json des Dienstes und steuert ihn wie das Fenster.
//! Startet beim Anmelden (HKCU\...\Run, wird vom Programmfenster eingetragen; im Menue abschaltbar) und nur einmal.

use crate::gui::Steuerung;
use crate::symbol::{self, Lage};
use crate::Args;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::{CreateMutexW, OpenMutexW};
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIIF_WARNING, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MUTEX: &str = "Local\\KroneVPN-Symbol";
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_NAME: &str = "KroneVPN-Symbol";
const WM_TRAY: u32 = WM_APP + 1;
const TIMER: usize = 1;

const ID_OEFFNEN: usize = 1;
const ID_VERBINDEN: usize = 2;
const ID_TRENNEN: usize = 3;
const ID_TEMPO: usize = 4;
const ID_AUTOSTART: usize = 5;
const ID_SCHLIESSEN: usize = 6;

const LOGO: &[u8] = include_bytes!("../res/logo128.rgba");

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn copy_w(dst: &mut [u16], s: &str) {
    let w: Vec<u16> = s.encode_utf16().take(dst.len() - 1).collect();
    dst[..w.len()].copy_from_slice(&w);
    dst[w.len()] = 0;
}

/// Zustand des Symbols (nur im Fenster-Thread benutzt)
struct Sym {
    hwnd: HWND,
    st: Arc<crate::plat::dienst::Fenster>,
    titel: String,
    lage: Lage,
    icon: HICON,
    tipp: String,
    /// seit wann die Verbindung weg ist (fuer die Meldung erst nach ein paar Sekunden)
    weg_seit: Option<std::time::Instant>,
    weg_gemeldet: bool,
    /// Zeitpunkt des letzten gemeldeten Geschwindigkeitstests
    tempo_at: u64,
    tempo_warten: bool,
    taskbar_created: u32,
    ticks: u64,
}

// Fenster-Prozedur und Hauptschleife laufen im selben Thread; Zugriff nur dort
static SYM: Mutex<Option<SymPtr>> = Mutex::new(None);
struct SymPtr(*mut Sym);
unsafe impl Send for SymPtr {}

fn icon_aus(lage: Lage) -> HICON {
    let mut rgba = symbol::bild(LOGO, lage);
    let n = symbol::GROESSE;
    // wie winit: Maske = invertiertes Alpha (wird bei 32 Bit mit Alpha ohnehin ignoriert), Farben als BGRA
    let mut and_mask = Vec::with_capacity(n * n);
    for p in rgba.chunks_mut(4) {
        and_mask.push(p[3].wrapping_sub(u8::MAX));
        p.swap(0, 2);
    }
    unsafe { CreateIcon(std::ptr::null_mut(), n as i32, n as i32, 1, 32, and_mask.as_ptr(), rgba.as_ptr()) }
}

fn nid(hwnd: HWND) -> NOTIFYICONDATAW {
    let mut d: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    d.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    d.hWnd = hwnd;
    d.uID = 1;
    d
}

impl Sym {
    fn hinzufuegen(&self) {
        let mut d = nid(self.hwnd);
        d.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        d.uCallbackMessage = WM_TRAY;
        d.hIcon = self.icon;
        copy_w(&mut d.szTip, &self.tipp);
        unsafe { Shell_NotifyIconW(NIM_ADD, &d) };
    }

    fn sprechblase(&self, titel: &str, text: &str, warnung: bool) {
        let mut d = nid(self.hwnd);
        d.uFlags = NIF_INFO;
        copy_w(&mut d.szInfoTitle, titel);
        copy_w(&mut d.szInfo, text);
        d.dwInfoFlags = if warnung { NIIF_WARNING } else { NIIF_INFO };
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
    }

    /// Zustand lesen und Symbol/Tooltip anpassen (alle 2 s)
    fn aktualisieren(&mut self) {
        self.ticks += 1;
        let z = self.st.zustand();
        let lage = match (&z, self.st.lage()) {
            (Some(z), _) => Lage::aus_status(Some(z.state.as_str())),
            (None, crate::gui::Lage::Startet) => Lage::Verbinde,
            _ => Lage::Aus,
        };
        let tipp = match &z {
            Some(z) => symbol::tipp(&self.titel, lage, z.rate_rx, z.rate_tx, z.rtt_ms),
            None => symbol::tipp(&self.titel, lage, 0, 0, 0.0),
        };
        if lage != self.lage {
            let neu = icon_aus(lage);
            let mut d = nid(self.hwnd);
            d.uFlags = NIF_ICON;
            d.hIcon = neu;
            unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
            unsafe { DestroyIcon(self.icon) };
            self.icon = neu;
            // Verbindung abgerissen (Dienst laeuft weiter und verbindet neu) – erst nach 10 s melden
            if self.lage == Lage::An && lage == Lage::Verbinde {
                self.weg_seit = Some(std::time::Instant::now());
            }
            if lage == Lage::An {
                if self.weg_gemeldet {
                    self.sprechblase(&self.titel.clone(), "Wieder verbunden.", false);
                }
                self.weg_seit = None;
                self.weg_gemeldet = false;
            }
            if lage == Lage::Aus || lage == Lage::Pause {
                self.weg_seit = None;
            }
            self.lage = lage;
        }
        if let Some(t) = self.weg_seit {
            if !self.weg_gemeldet && t.elapsed().as_secs() >= 10 {
                let e = z.as_ref().map(|z| z.error.clone()).filter(|e| !e.is_empty()).unwrap_or_else(|| "Verbindet neu …".into());
                self.sprechblase(&format!("{}: Verbindung unterbrochen", self.titel), &e, true);
                self.weg_gemeldet = true;
            }
        }
        if tipp != self.tipp {
            let mut d = nid(self.hwnd);
            d.uFlags = NIF_TIP;
            copy_w(&mut d.szTip, &tipp);
            unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
            self.tipp = tipp;
        }
        // Ergebnis eines Geschwindigkeitstests (vom Symbol angestossen) als Sprechblase
        if let Some(z) = &z {
            if self.tempo_warten && z.speed.at > self.tempo_at && z.speed.state != "laeuft" {
                self.tempo_warten = false;
                self.tempo_at = z.speed.at;
                self.sprechblase(&format!("{}: Geschwindigkeit", self.titel), &crate::speed_text(&z.speed), z.speed.state == "fehler");
            }
        }
        // neue Programmversion installiert (Auto-Update): Symbol mit der neuen Version neu starten
        if self.ticks % 30 == 0 {
            if let Some(neu) = crate::plat::dienst::newer_installed() {
                if std::process::Command::new(neu).arg("--symbol").arg("--neu").creation_flags(CREATE_NO_WINDOW).spawn().is_ok() {
                    unsafe { DestroyWindow(self.hwnd) };
                }
            }
        }
    }

    fn menue(&mut self) {
        let an = matches!(self.lage, Lage::An | Lage::Verbinde | Lage::Pause);
        unsafe {
            let m = CreatePopupMenu();
            AppendMenuW(m, MF_STRING, ID_OEFFNEN, wide(&format!("{} öffnen", self.titel)).as_ptr());
            SetMenuDefaultItem(m, ID_OEFFNEN as u32, 0);
            AppendMenuW(m, MF_SEPARATOR, 0, std::ptr::null());
            if an {
                AppendMenuW(m, MF_STRING, ID_TRENNEN, wide("Trennen").as_ptr());
            } else {
                AppendMenuW(m, MF_STRING, ID_VERBINDEN, wide("Verbinden").as_ptr());
            }
            AppendMenuW(m, MF_STRING | if self.lage == Lage::An { 0 } else { MF_GRAYED }, ID_TEMPO, wide("Geschwindigkeit testen").as_ptr());
            AppendMenuW(m, MF_SEPARATOR, 0, std::ptr::null());
            AppendMenuW(m, MF_STRING | if autostart_an() { MF_CHECKED } else { 0 }, ID_AUTOSTART, wide("Symbol beim Anmelden zeigen").as_ptr());
            AppendMenuW(m, MF_STRING, ID_SCHLIESSEN, wide("Symbol schließen").as_ptr());
            let mut p = POINT { x: 0, y: 0 };
            GetCursorPos(&mut p);
            SetForegroundWindow(self.hwnd);
            let cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, p.x, p.y, 0, self.hwnd, std::ptr::null());
            PostMessageW(self.hwnd, WM_NULL, 0, 0);
            DestroyMenu(m);
            self.befehl(cmd as usize);
        }
    }

    fn befehl(&mut self, id: usize) {
        match id {
            ID_OEFFNEN => fenster_oeffnen(),
            ID_VERBINDEN => {
                let st = self.st.clone();
                let a = st.args();
                std::thread::spawn(move || match crate::known_code(&a).and_then(|c| kvpn::code::ClientConfig::from_code(&c).ok()) {
                    Some(cfg) => {
                        if st.verbinden(&cfg).is_err() {
                            fenster_oeffnen();
                        }
                    }
                    None => fenster_oeffnen(),
                });
                self.lage_vorab(Lage::Verbinde);
            }
            ID_TRENNEN => {
                let st = self.st.clone();
                std::thread::spawn(move || {
                    if st.trennen().is_err() {
                        fenster_oeffnen();
                    }
                });
            }
            ID_TEMPO => match self.st.geschwindigkeit() {
                Ok(()) => {
                    self.tempo_warten = true;
                    self.tempo_at = self.st.zustand().map(|z| z.speed.at).unwrap_or(0);
                    self.sprechblase(&format!("{}: Geschwindigkeit", self.titel), "Test läuft (ca. 10 Sekunden) …", false);
                }
                Err(e) => self.sprechblase(&self.titel.clone(), &e, true),
            },
            ID_AUTOSTART => {
                let neu = !autostart_an();
                autostart(neu);
                merk_aus(!neu);
            }
            ID_SCHLIESSEN => unsafe {
                DestroyWindow(self.hwnd);
            },
            _ => {}
        }
    }

    /// sofort anzeigen, was gleich passiert (der Dienst braucht ein paar Sekunden)
    fn lage_vorab(&mut self, l: Lage) {
        if l != self.lage {
            let neu = icon_aus(l);
            let mut d = nid(self.hwnd);
            d.uFlags = NIF_ICON;
            d.hIcon = neu;
            unsafe {
                Shell_NotifyIconW(NIM_MODIFY, &d);
                DestroyIcon(self.icon);
            }
            self.icon = neu;
            self.lage = l;
        }
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let p = SYM.lock().unwrap().as_ref().map(|p| p.0);
    let Some(p) = p else { return DefWindowProcW(hwnd, msg, wp, lp) };
    let s = &mut *p;
    match msg {
        WM_TIMER => {
            s.aktualisieren();
            0
        }
        WM_TRAY => {
            match lp as u32 {
                WM_LBUTTONUP => fenster_oeffnen(),
                WM_RBUTTONUP | WM_CONTEXTMENU => s.menue(),
                _ => {}
            }
            0
        }
        WM_DESTROY => {
            let d = nid(hwnd);
            Shell_NotifyIconW(NIM_DELETE, &d);
            PostQuitMessage(0);
            0
        }
        // Explorer neu gestartet: Symbol wieder eintragen
        m if m == s.taskbar_created && m != 0 => {
            s.hinzufuegen();
            0
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

/// laeuft das Symbol schon?
pub fn laeuft() -> bool {
    const SYNCHRONIZE: u32 = 0x0010_0000;
    let h = unsafe { OpenMutexW(SYNCHRONIZE, 0, wide(MUTEX).as_ptr()) };
    if h.is_null() {
        return false;
    }
    unsafe { windows_sys::Win32::Foundation::CloseHandle(h) };
    true
}

fn exe() -> PathBuf {
    crate::plat::dienst::installed_exe().filter(|p| p.exists()).or_else(|| std::env::current_exe().ok()).unwrap_or_else(|| PathBuf::from("KroneVPN.exe"))
}

fn fenster_oeffnen() {
    let _ = std::process::Command::new(exe()).spawn();
}

fn reg(args: &[&str]) -> Option<String> {
    let o = std::process::Command::new("reg").args(args).creation_flags(CREATE_NO_WINDOW).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

fn autostart_an() -> bool {
    reg(&["query", RUN_KEY, "/v", RUN_NAME]).is_some()
}

fn autostart(an: bool) {
    if an {
        let cmd = format!("\"{}\" --symbol", exe().display());
        let _ = reg(&["add", RUN_KEY, "/v", RUN_NAME, "/t", "REG_SZ", "/d", &cmd, "/f"]);
    } else {
        let _ = reg(&["delete", RUN_KEY, "/v", RUN_NAME, "/f"]);
    }
}

/// "nicht mehr beim Anmelden starten" merken (sonst traegt das Fenster es wieder ein)
fn merk_datei() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("KroneVPN").join("symbol-aus.txt"))
}

fn merk_aus(aus: bool) {
    let Some(f) = merk_datei() else { return };
    if aus {
        let _ = std::fs::create_dir_all(f.parent().unwrap());
        let _ = std::fs::write(&f, "aus");
    } else {
        let _ = std::fs::remove_file(&f);
    }
}

/// vom Programmfenster beim Start: Symbol beim Anmelden eintragen (ausser abgewaehlt) und starten, falls es fehlt
pub fn sicherstellen() {
    if merk_datei().map(|f| f.exists()).unwrap_or(false) {
        return;
    }
    let soll = format!("\"{}\" --symbol", exe().display());
    let ist = reg(&["query", RUN_KEY, "/v", RUN_NAME]).unwrap_or_default();
    if !ist.contains(&soll) {
        autostart(true);
    }
    if !laeuft() {
        let _ = std::process::Command::new(exe()).arg("--symbol").creation_flags(CREATE_NO_WINDOW).spawn();
    }
}

/// --symbol: Symbol im Infobereich (blockiert bis "Symbol schliessen")
pub fn run(a: &Args) -> ! {
    unsafe {
        // nur einmal je Anmeldung (nach einem Update startet die neue Version, die alte beendet sich gleich danach)
        let mut m = CreateMutexW(std::ptr::null(), 0, wide(MUTEX).as_ptr());
        if GetLastError() == ERROR_ALREADY_EXISTS {
            if !std::env::args().any(|x| x == "--neu") {
                std::process::exit(0);
            }
            // die alte Version beendet sich: kurz warten, dann uebernehmen
            for _ in 0..20 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                windows_sys::Win32::Foundation::CloseHandle(m);
                m = CreateMutexW(std::ptr::null(), 0, wide(MUTEX).as_ptr());
                if GetLastError() != ERROR_ALREADY_EXISTS {
                    break;
                }
            }
        }
        let _keep = m;
        let hinst = GetModuleHandleW(std::ptr::null());
        let cls = wide("KroneVPNSymbol");
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = hinst;
        wc.lpszClassName = cls.as_ptr();
        RegisterClassW(&wc);
        // unsichtbares Fenster (kein Nur-Nachrichten-Fenster: das bekaeme "TaskbarCreated" nicht)
        let hwnd = CreateWindowExW(0, cls.as_ptr(), wide("KroneVPN").as_ptr(), WS_OVERLAPPED, 0, 0, 0, 0, std::ptr::null_mut(), std::ptr::null_mut(), hinst, std::ptr::null());
        if hwnd.is_null() {
            std::process::exit(1);
        }
        let titel = crate::known_code(a).and_then(|c| kvpn::code::ClientConfig::from_code(&c).ok()).map(|c| c.display_name().to_string()).unwrap_or_else(|| "KroneVPN".into());
        let st = Arc::new(crate::plat::dienst::Fenster::new(a.clone()));
        let lage = Lage::aus_status(st.zustand().as_ref().map(|z| z.state.as_str()));
        let sym = Box::new(Sym {
            hwnd,
            st,
            tipp: symbol::tipp(&titel, lage, 0, 0, 0.0),
            titel,
            lage,
            icon: icon_aus(lage),
            weg_seit: None,
            weg_gemeldet: false,
            tempo_at: 0,
            tempo_warten: false,
            taskbar_created: RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()),
            ticks: 0,
        });
        let p = Box::into_raw(sym);
        *SYM.lock().unwrap() = Some(SymPtr(p));
        (*p).hinzufuegen();
        SetTimer(hwnd, TIMER, 2000, None);
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        *SYM.lock().unwrap() = None;
        DestroyIcon((*p).icon);
        drop(Box::from_raw(p));
    }
    std::process::exit(0)
}
