//! Windows: das VPN laeuft als Dienst im Hintergrund – das Fenster ist nur noch eine Anzeige und darf zu.
//!
//! Beim Start richtet KroneVPN.exe den Dienst "KroneVPN" ein (bzw. aktualisiert ihn) und startet ihn:
//!   Programm      C:\Program Files\KroneVPN\KroneVPN.exe   (dort spielt auch das Auto-Update neue Versionen ein)
//!   Code/Daten    C:\ProgramData\KroneVPN\                 (verbindung.txt nur fuer SYSTEM/Administratoren lesbar,
//!                                                           status.json = Live-Werte fuers Fenster, protokoll.txt)
//! Der Dienst startet mit Windows, verbindet sich bei Abbruechen selbst neu und wird nach einem Update von
//! Windows automatisch neu gestartet.
//!
//!   KroneVPN.exe --trennen      VPN aus (Dienst gestoppt, startet nicht mehr mit Windows)
//!   KroneVPN.exe --entfernen    Dienst und gespeicherten Code entfernen
//!   KroneVPN.exe --vordergrund  wie frueher nur im Fenster (Fenster zu = VPN aus)
//!
//! Das Programmfenster (gui.rs) steuert den Dienst ueber `Fenster`; im Startmenue liegt eine Verknuepfung.
//!
//! Alte Kopien: Startet man KroneVPN.exe von woanders (z. B. aus dem Download-Ordner), merkt sich das Programm den Ort.
//! Der Dienst bringt solche Kopien – und laufende aeltere KroneVPN-Programme – automatisch auf seine Version
//! (umbenennen nach *.old + neue Datei hinlegen; das geht auch, waehrend die alte noch laeuft). Beim naechsten Start
//! ist dann die neue Version mit dem neuen Fenster da.

use crate::{say, Args, Ende, Ui, Zustand};
use kvpn::code::ClientConfig;
use std::ffi::OsString;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const NAME: &str = "KroneVPN";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Dienst-Ende "Update eingespielt": Windows startet den Dienst dann mit der neuen Datei neu
const EXIT_UPDATE: u32 = 3;

fn env_dir(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(fallback)).join("KroneVPN")
}
fn data_dir() -> PathBuf {
    env_dir("ProgramData", r"C:\ProgramData")
}
fn prog_dir() -> PathBuf {
    env_dir("ProgramFiles", r"C:\Program Files")
}
fn code_file() -> PathBuf {
    data_dir().join("verbindung.txt")
}
fn proxy_file() -> PathBuf {
    data_dir().join("systemproxy.txt")
}
fn status_file() -> PathBuf {
    data_dir().join("status.json")
}
fn log_file() -> PathBuf {
    data_dir().join("protokoll.txt")
}

fn sc(args: &[&str]) -> bool {
    Command::new("sc").args(args).creation_flags(CREATE_NO_WINDOW).output().map(|o| o.status.success()).unwrap_or(false)
}

/// Datei nur fuer SYSTEM und Administratoren (SIDs, damit es auf jeder Sprache geht)
fn restrict(p: &Path) {
    let _ = Command::new("icacls")
        .arg(p)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

// ------------------------------------------------------------------------------------------------ Dienst

define_windows_service!(ffi_service_main, service_main);

/// vom Dienststeuerungs-Manager gestartet (KroneVPN.exe --service ...)
pub fn run_service() {
    let _ = std::fs::create_dir_all(data_dir());
    let _ = crate::LOGFILE.set(log_file());
    if let Err(e) = service_dispatcher::start(NAME, ffi_service_main) {
        say(&format!("Dienst konnte nicht starten: {e} (KroneVPN.exe ohne --service starten)"));
    }
}

fn service_main(_args: Vec<OsString>) {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let handler = move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            let _ = stop_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(h) = service_control_handler::register(NAME, handler) else { return };
    let set = |state: ServiceState, exit: ServiceExitCode| {
        let _ = h.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running { ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN } else { ServiceControlAccept::empty() },
            exit_code: exit,
            checkpoint: 0,
            wait_hint: Duration::from_secs(15),
            process_id: None,
        });
    };
    set(ServiceState::Running, ServiceExitCode::NO_ERROR);
    let exit = serve(stop_rx);
    set(ServiceState::Stopped, exit);
}

async fn stopped(mut rx: tokio::sync::watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

fn serve(stop_rx: tokio::sync::watch::Receiver<bool>) -> ServiceExitCode {
    let a = crate::parse_args();
    say(&format!("Dienst startet (Version {})", kvpn::VERSION));
    let path = a.config.clone().unwrap_or_else(code_file);
    let cfg = match std::fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|c| ClientConfig::from_code(&c)) {
        Ok(c) => c,
        Err(e) => {
            say(&format!("Kein gueltiger Verbindungscode in {}: {e}", path.display()));
            return ServiceExitCode::ServiceSpecific(1);
        }
    };
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread().worker_threads(cores.clamp(2, 8)).enable_all().build() else {
        return ServiceExitCode::ServiceSpecific(2);
    };
    // alte Kopien des Programms auf diese Version bringen (alle 30 s nachsehen)
    if !a.no_update {
        std::thread::spawn(|| {
            let mut seen = std::collections::HashMap::new();
            loop {
                update_copies(&mut seen);
                std::thread::sleep(Duration::from_secs(30));
            }
        });
    }
    loop {
        // Wege: Proxy aus Code/Aufruf fest – sonst Systemproxy des Benutzers (beim Einrichten gemerkt) zuerst, dann direkt
        let forced = a.proxy.clone().or_else(|| (!cfg.proxy.is_empty()).then(|| cfg.proxy.clone()));
        let ways = match forced {
            Some(p) => vec![kvpn::transport::parse_proxy(&p).ok().flatten()],
            None => match std::fs::read_to_string(proxy_file()).ok().and_then(|p| kvpn::transport::parse_proxy(p.trim()).ok().flatten()) {
                Some(p) => vec![Some(p), None],
                None => vec![None],
            },
        };
        let r = rt.block_on(crate::run_vpn(cfg.clone(), &a, ways, Ui::Datei(status_file()), stopped(stop_rx.clone())));
        match r {
            Ok(Ende::Stopp) => {
                say("Dienst beendet");
                return ServiceExitCode::NO_ERROR;
            }
            Ok(Ende::Update(f)) => match crate::apply_update(&f, false) {
                Ok(()) => {
                    say("Update eingespielt – Windows startet den Dienst mit der neuen Version neu");
                    return ServiceExitCode::ServiceSpecific(EXIT_UPDATE);
                }
                Err(e) => say(&format!("Update konnte nicht eingespielt werden: {e}")),
            },
            Err(e) => say(&format!("Fehler: {e} – neuer Versuch in 10 s")),
        }
        if rt.block_on(async { tokio::time::timeout(Duration::from_secs(10), stopped(stop_rx.clone())).await.is_ok() }) {
            return ServiceExitCode::NO_ERROR;
        }
    }
}

// ------------------------------------------------------------------------------------------------ Einrichten

fn installed_version(exe: &Path) -> Option<String> {
    let o = Command::new(exe).arg("--version").creation_flags(CREATE_NO_WINDOW).output().ok()?;
    let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
    (o.status.success() && !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.')).then_some(v)
}

fn wait_state(svc: &windows_service::service::Service, want: ServiceState, secs: u64) -> bool {
    for _ in 0..secs * 4 {
        if svc.query_status().map(|s| s.current_state == want).unwrap_or(false) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

fn stop_and_wait(svc: &windows_service::service::Service) {
    if svc.query_status().map(|s| s.current_state != ServiceState::Stopped).unwrap_or(false) {
        let _ = svc.stop();
        wait_state(svc, ServiceState::Stopped, 20);
    }
}

fn install(cfg: &ClientConfig, a: &Args) -> Result<(), String> {
    let data = data_dir();
    std::fs::create_dir_all(&data).map_err(|e| format!("{}: {e}", data.display()))?;
    // Code fuer den Dienst
    let code = cfg.to_code();
    let cf = code_file();
    let code_changed = std::fs::read_to_string(&cf).ok().as_deref() != Some(code.as_str());
    if code_changed {
        std::fs::write(&cf, &code).map_err(|e| format!("{}: {e}", cf.display()))?;
        restrict(&cf);
    }
    // Systemproxy des angemeldeten Benutzers merken (der Dienst laeuft als SYSTEM und sieht ihn sonst nicht)
    let sp = super::system_proxy().unwrap_or_default();
    let proxy_changed = std::fs::read_to_string(proxy_file()).unwrap_or_default().trim() != sp;
    if proxy_changed {
        let _ = std::fs::write(proxy_file(), &sp);
    }
    if !sp.is_empty() {
        say(&format!("Systemproxy gefunden: {sp} (wird zuerst probiert, sonst direkt)"));
    }

    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .map_err(|e| format!("Dienstverwaltung: {e} (als Administrator starten)"))?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP | ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_CONFIG;
    let existing = mgr.open_service(NAME, access).ok();

    // Programm nach "C:\Program Files\KroneVPN" (eine neuere, schon per Auto-Update eingespielte Version bleibt)
    let pdir = prog_dir();
    std::fs::create_dir_all(&pdir).map_err(|e| format!("{}: {e}", pdir.display()))?;
    let dst = pdir.join("KroneVPN.exe");
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let same = std::fs::canonicalize(&me).ok() == std::fs::canonicalize(&dst).ok();
    let mut copied = false;
    if !same {
        let copy = match installed_version(&dst) {
            None => true,
            Some(v) if kvpn::update::newer(kvpn::VERSION, &v) => true,
            Some(v) if v == kvpn::VERSION => std::fs::read(&me).ok() != std::fs::read(&dst).ok(),
            Some(v) => {
                say(&format!("Installiert ist schon die neuere Version {v} – die bleibt."));
                false
            }
        };
        if copy {
            if let Some(s) = &existing {
                stop_and_wait(s);
            }
            let mut ok = false;
            for _ in 0..10 {
                if std::fs::copy(&me, &dst).is_ok() {
                    ok = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            if !ok {
                return Err(format!("{} konnte nicht geschrieben werden", dst.display()));
            }
            copied = true;
        }
    }

    let mut args: Vec<OsString> = vec!["--service".into(), "--config".into(), cf.clone().into_os_string()];
    if let Some(r) = &a.routes {
        args.push("--routes".into());
        args.push(r.join(",").into());
    }
    if let Some(p) = &a.proxy {
        args.push("--proxy".into());
        args.push(p.into());
    }
    if a.no_update {
        args.push("--kein-update".into());
    }
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: format!("{} (VPN)", cfg.display_name()).into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: dst.clone(),
        launch_arguments: args,
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let svc = match existing {
        Some(s) => {
            s.change_config(&info).map_err(|e| format!("Dienst aendern: {e}"))?;
            s
        }
        None => mgr.create_service(&info, access).map_err(|e| format!("Dienst anlegen: {e}"))?,
    };
    let _ = svc.set_description(format!("{} – VPN ueber HTTPS/443. Laeuft im Hintergrund; Fenster darf geschlossen werden.", cfg.display_name()));
    let restart = |secs| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(secs) };
    let _ = svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart(2), restart(5), restart(15)]),
    });
    let _ = svc.set_failure_actions_on_non_crash_failures(true);

    shortcut(cfg.display_name(), &dst);

    let running = svc.query_status().map(|s| s.current_state == ServiceState::Running).unwrap_or(false);
    if running && (code_changed || proxy_changed || copied) {
        stop_and_wait(&svc);
    }
    if !svc.query_status().map(|s| s.current_state == ServiceState::Running).unwrap_or(false) {
        let _ = std::fs::remove_file(status_file());
        svc.start::<&str>(&[]).map_err(|e| format!("Dienst starten: {e}"))?;
        wait_state(&svc, ServiceState::Running, 15);
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ Fenster

/// Dienst einrichten/starten und danach nur noch anzeigen. Das Fenster darf jederzeit zu.
fn menu() {
    println!("Befehle (Buchstabe eintippen, dann Enter):");
    println!("  f  neue Ansicht (Programmfenster)");
    println!("  p  Profil wechseln");
    println!("  c  Verbindungscode + QR-Code anzeigen");
    println!("  t  VPN ausschalten");
    println!("  h  diese Hilfe\n");
}

/// alte Ansicht: Profil waehlen (Nummer eintippen)
fn choose_profile(cfg: &mut ClientConfig, a: &Args, rx: &std::sync::mpsc::Receiver<String>) {
    let list = crate::profiles(a);
    println!("\r{:90}\nProfile:", "");
    for (i, p) in list.iter().enumerate() {
        let mark = if crate::same_profile(p, cfg) { "*" } else { " " };
        println!("  {mark} {}  {}", i + 1, crate::profile_label(p));
    }
    println!("  + {}  neues Profil (Verbindungscode einfuegen)", list.len() + 1);
    println!("Nummer eintippen und Enter (nur Enter = abbrechen):");
    let Ok(l) = rx.recv() else { return };
    let new = match l.trim().parse::<usize>() {
        Ok(n) if n >= 1 && n <= list.len() => list[n - 1].clone(),
        Ok(n) if n == list.len() + 1 => {
            println!("Code einfuegen (beginnt mit kronevpn://v1/) und Enter:");
            let Ok(c) = rx.recv() else { return };
            match ClientConfig::from_code(&c) {
                Ok(c) => c,
                Err(e) => {
                    println!("{e}");
                    return;
                }
            }
        }
        _ => {
            println!("Abgebrochen.");
            return;
        }
    };
    crate::save_code(a, &new);
    if crate::same_profile(&new, cfg) && new == *cfg {
        println!("Profil ist schon aktiv.");
        return;
    }
    println!("Wechsle zu {} ...", crate::profile_label(&new));
    match install(&new, a) {
        Ok(()) => {
            *cfg = new;
            crate::set_title(&format!("{} – {}", cfg.display_name(), cfg.name));
        }
        Err(e) => println!("Fehler: {e}"),
    }
}

pub fn background(cfg: &ClientConfig, a: &Args) -> ! {
    let mut cfg = cfg.clone();
    let cfg = &mut cfg;
    let title = cfg.display_name().to_string();
    crate::set_title(&format!("{title} – {}", cfg.name));
    println!("{title} {} – Geraet '{}' – Server {}", kvpn::VERSION, cfg.name, cfg.url);
    if let Err(e) = install(cfg, a) {
        crate::die(format!("{e}\nNotfalls ohne Dienst im Fenster starten:  \"{title}.exe\" --vordergrund"));
    }
    println!();
    println!("Laeuft im Hintergrund (Windows-Dienst) und startet auch automatisch mit Windows.");
    println!("Du kannst dieses Fenster jederzeit schliessen – das VPN bleibt an.");
    menu();
    println!("Verbinde ...");

    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut l = String::new();
        while std::io::stdin().read_line(&mut l).map(|n| n > 0).unwrap_or(false) {
            let _ = tx.send(std::mem::take(&mut l));
        }
    });
    let mut last_state = String::new();
    let mut last_err = String::new();
    let mut upd_shown = String::new();
    let mut waited = 0u32;
    loop {
        if let Ok(line) = rx.try_recv() {
            if line.trim().eq_ignore_ascii_case("t") {
                disconnect();
                println!("\nVPN getrennt. Wieder verbinden: Programm erneut starten.\nEnter druecken zum Schliessen ...");
                let _ = rx.recv();
                std::process::exit(0);
            }
            match line.trim().to_ascii_lowercase().as_str() {
                "f" => {
                    crate::set_classic_view(a, false);
                    match crate::restart_in_view(false) {
                        Ok(()) => std::process::exit(0),
                        Err(e) => println!("\rProgrammfenster konnte nicht gestartet werden: {e}"),
                    }
                }
                "p" => {
                    choose_profile(cfg, a, &rx);
                    last_state.clear();
                }
                "c" => {
                    let code = cfg.to_code();
                    println!("\r{:90}\n{}", "", crate::qr(&code));
                    println!("Verbindungscode fuer '{}' (geheim halten):\n{code}\n", cfg.name);
                }
                "h" | "?" | "hilfe" => {
                    println!("\r{:90}", "");
                    menu();
                }
                "" => {}
                x => println!("\rUnbekannter Befehl '{x}' – h + Enter zeigt die Hilfe"),
            }
        }
        let z: Option<Zustand> = std::fs::read(status_file()).ok().and_then(|b| serde_json::from_slice(&b).ok());
        match z {
            Some(z) if kvpn::util::now_secs().saturating_sub(z.ts) < 5 => {
                waited = 0;
                if !z.update_version.is_empty() && z.update_version != upd_shown {
                    println!("\rNeue Version {} wird geladen ({} KB) – der Dienst startet danach kurz neu          ", z.update_version, z.update_size / 1024);
                    upd_shown = z.update_version.clone();
                }
                if z.state != last_state {
                    if z.state == "connected" {
                        println!("\rVerbunden mit {}{} – {}                    ", z.server, if z.via_proxy { " ueber Proxy" } else { "" }, crate::tls_text(&z));
                    } else if z.state == "connecting" && last_state == "connected" {
                        println!("\rVerbindung unterbrochen – verbinde neu ...                              ");
                    }
                    last_state = z.state.clone();
                }
                if !z.error.is_empty() && z.error != last_err && z.state != "connected" {
                    println!("\r{}                                        ", z.error);
                }
                last_err = z.error.clone();
                if z.state == "connected" {
                    print!("\r{}      ", crate::live_line(&z));
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
            }
            _ => {
                waited += 1;
                if waited == 15 {
                    println!("\rDer Dienst meldet sich nicht. Letzte Eintraege aus {}:", log_file().display());
                    let log = std::fs::read_to_string(log_file()).unwrap_or_default();
                    let lines: Vec<&str> = log.lines().collect();
                    for l in &lines[lines.len().saturating_sub(8)..] {
                        println!("  {l}");
                    }
                    last_state.clear();
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Verknuepfung im Startmenue (fuer alle Benutzer), damit man das Fenster wiederfindet
fn shortcut_file(title: &str) -> PathBuf {
    let name: String = title.chars().map(|c| if r#"\/:*?"<>|"#.contains(c) { '_' } else { c }).collect();
    env_dir("ProgramData", r"C:\ProgramData")
        .with_file_name("Microsoft")
        .join(r"Windows\Start Menu\Programs")
        .join(format!("{}.lnk", name.trim()))
}

fn shortcut(title: &str, target: &Path) {
    // schon angelegt (auch unter anderem Namen, z. B. anderes Profil)? Dann bleibt sie
    if let Ok(l) = std::fs::read_to_string(data_dir().join("verknuepfung.txt")) {
        if Path::new(l.trim()).exists() {
            return;
        }
    }
    let lnk = shortcut_file(title);
    if lnk.exists() {
        return;
    }
    let q = |p: &Path| p.display().to_string().replace('\'', "''");
    let ps = format!(
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{}'); $s.TargetPath='{}'; $s.WorkingDirectory='{}'; $s.Description='VPN'; $s.Save()",
        q(&lnk),
        q(target),
        q(target.parent().unwrap_or(target))
    );
    let ok = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &ps])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ok {
        let _ = std::fs::write(data_dir().join("verknuepfung.txt"), lnk.display().to_string());
    }
}

/// laeuft hier nicht die installierte Version und ist die installierte neuer (Auto-Update)? Dann deren Pfad
pub fn newer_installed() -> Option<PathBuf> {
    let dst = prog_dir().join("KroneVPN.exe");
    let me = std::env::current_exe().ok()?;
    if std::fs::canonicalize(&me).ok() == std::fs::canonicalize(&dst).ok() {
        return None;
    }
    let v = installed_version(&dst)?;
    kvpn::update::newer(&v, kvpn::VERSION).then_some(dst)
}

// ------------------------------------------------------------------------------------------------ alte Kopien

mod ffi {
    use std::ffi::c_void;
    #[repr(C)]
    pub struct ProcessEntry32W {
        pub size: u32,
        pub usage: u32,
        pub pid: u32,
        pub heap: usize,
        pub module: u32,
        pub threads: u32,
        pub parent: u32,
        pub prio: i32,
        pub flags: u32,
        pub exe: [u16; 260],
    }
    #[link(name = "kernel32")]
    extern "system" {
        pub fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> isize;
        pub fn Process32FirstW(snap: isize, e: *mut ProcessEntry32W) -> i32;
        pub fn Process32NextW(snap: isize, e: *mut ProcessEntry32W) -> i32;
        pub fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
        pub fn QueryFullProcessImageNameW(h: isize, flags: u32, buf: *mut u16, size: *mut u32) -> i32;
        pub fn CloseHandle(h: isize) -> i32;
    }
    #[link(name = "version")]
    extern "system" {
        pub fn GetFileVersionInfoSizeW(name: *const u16, handle: *mut u32) -> u32;
        pub fn GetFileVersionInfoW(name: *const u16, handle: u32, len: u32, data: *mut c_void) -> i32;
        pub fn VerQueryValueW(block: *const c_void, sub: *const u16, buf: *mut *mut c_void, len: *mut u32) -> i32;
    }
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Programme aller laufenden Prozesse
fn running_exes() -> Vec<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut out = Vec::new();
    unsafe {
        let snap = ffi::CreateToolhelp32Snapshot(2, 0);
        if snap == -1 || snap == 0 {
            return out;
        }
        let mut e: ffi::ProcessEntry32W = std::mem::zeroed();
        e.size = std::mem::size_of::<ffi::ProcessEntry32W>() as u32;
        let mut ok = ffi::Process32FirstW(snap, &mut e);
        while ok != 0 {
            let h = ffi::OpenProcess(0x1000, 0, e.pid); // PROCESS_QUERY_LIMITED_INFORMATION
            if h != 0 {
                let mut buf = [0u16; 1024];
                let mut n = buf.len() as u32;
                if ffi::QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut n) != 0 {
                    out.push(PathBuf::from(std::ffi::OsString::from_wide(&buf[..n as usize])));
                }
                ffi::CloseHandle(h);
            }
            ok = ffi::Process32NextW(snap, &mut e);
        }
        ffi::CloseHandle(snap);
    }
    out.sort();
    out.dedup();
    out
}

/// Versions-Angaben einer EXE: (Produkt, Original-Dateiname, Version)
fn version_info(p: &Path) -> Option<(String, String, String)> {
    let name = wide(p.as_os_str());
    unsafe {
        let mut h = 0u32;
        let len = ffi::GetFileVersionInfoSizeW(name.as_ptr(), &mut h);
        if len == 0 || len > 1 << 20 {
            return None;
        }
        let mut data = vec![0u8; len as usize];
        if ffi::GetFileVersionInfoW(name.as_ptr(), 0, len, data.as_mut_ptr().cast()) == 0 {
            return None;
        }
        let get = |key: &str| -> Option<String> {
            let sub = wide(std::ffi::OsStr::new(&format!(r"\StringFileInfo\040704B0\{key}")));
            let mut ptr: *mut std::ffi::c_void = std::ptr::null_mut();
            let mut n = 0u32;
            if ffi::VerQueryValueW(data.as_ptr().cast(), sub.as_ptr(), &mut ptr, &mut n) == 0 || ptr.is_null() || n == 0 {
                return None;
            }
            let s = std::slice::from_raw_parts(ptr as *const u16, n as usize);
            Some(String::from_utf16_lossy(s).trim_end_matches('\0').trim().to_string())
        };
        Some((get("ProductName")?, get("OriginalFilename")?, get("FileVersion")?))
    }
}

fn copies_file() -> PathBuf {
    data_dir().join("kopien.txt")
}

/// Ort dieses Programms merken, wenn es nicht das installierte ist (der Dienst haelt es dann aktuell)
pub fn record_copy() {
    let Ok(me) = std::env::current_exe() else { return };
    let me = std::fs::canonicalize(&me).unwrap_or(me);
    if std::fs::canonicalize(prog_dir().join("KroneVPN.exe")).ok().as_ref() == Some(&me) {
        return;
    }
    let text = std::fs::read_to_string(copies_file()).unwrap_or_default();
    let line = me.display().to_string();
    if text.lines().any(|l| l.trim().eq_ignore_ascii_case(&line)) {
        return;
    }
    let _ = std::fs::create_dir_all(data_dir());
    let mut lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines.push(&line);
    let keep = &lines[lines.len().saturating_sub(20)..];
    let _ = std::fs::write(copies_file(), keep.join("\r\n") + "\r\n");
}

fn is_exe(p: &Path) -> bool {
    p.extension().map(|e| e.eq_ignore_ascii_case("exe")).unwrap_or(false)
}

/// "KroneVPN (1).exe.old", "KroneVPN.exe.old.old.old" … – Reste vom Ersetzen bzw. Aktualisieren
fn is_old_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    match l.find(".exe.old") {
        Some(i) => l[i + 4..].split('.').skip(1).all(|x| x == "old"),
        None => false,
    }
}

/// alte Reste in einem Ordner loeschen – nur eigene (KroneVPN-Versionsangaben). Laeuft das alte Programm noch, ist die
/// Datei gesperrt und bleibt bis zum naechsten Durchgang liegen.
fn remove_old_files(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut n = 0;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !is_old_name(&name) {
            continue;
        }
        let p = e.path();
        if !matches!(version_info(&p), Some((product, _, _)) if product == "KroneVPN") {
            continue;
        }
        if std::fs::remove_file(&p).is_ok() {
            n += 1;
        }
    }
    if n > 0 {
        say(&format!("{n} alte KroneVPN-Datei(en) (*.old) in {} geloescht", dir.display()));
    }
}

/// aeltere KroneVPN-Programme (laufende und gemerkte Kopien) durch diese Version ersetzen
fn update_copies(seen: &mut std::collections::HashMap<PathBuf, std::time::SystemTime>) {
    let Ok(me) = std::env::current_exe() else { return };
    let me = std::fs::canonicalize(&me).unwrap_or(me);
    let mut cands = running_exes();
    cands.extend(std::fs::read_to_string(copies_file()).unwrap_or_default().lines().filter(|l| !l.trim().is_empty()).map(|l| PathBuf::from(l.trim())));
    // Reste frueherer Ersetzungen wegraeumen (*.exe.old, auch die Ketten *.exe.old.old… aus 1.0.6–1.0.10)
    let mut dirs: Vec<PathBuf> = cands.iter().filter_map(|p| p.parent().map(Path::to_path_buf)).collect();
    dirs.push(prog_dir());
    dirs.sort();
    dirs.dedup();
    for d in &dirs {
        remove_old_files(d);
    }
    for p in cands {
        // nur echte Programme: ein laufendes Programm, das umbenannt wurde, meldet Windows unter dem neuen Namen
        // (KroneVPN.exe.old) – das ist der Rest einer Ersetzung, keine weitere Kopie
        if !is_exe(&p) {
            continue;
        }
        let Ok(m) = std::fs::metadata(&p) else { continue };
        let Ok(mtime) = m.modified() else { continue };
        if seen.get(&p) == Some(&mtime) {
            continue;
        }
        seen.insert(p.clone(), mtime);
        if std::fs::canonicalize(&p).ok().as_ref() == Some(&me) || m.len() > kvpn::update::MAX_SIZE {
            continue;
        }
        let Some((product, original, ver)) = version_info(&p) else { continue };
        if product != "KroneVPN" || !original.eq_ignore_ascii_case("KroneVPN.exe") || !kvpn::update::newer(kvpn::VERSION, &ver) {
            continue;
        }
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let old = p.with_file_name(format!("{name}.old"));
        let _ = std::fs::remove_file(&old);
        if let Err(e) = std::fs::rename(&p, &old) {
            say(&format!("Alte Kopie {} ({ver}) konnte nicht ersetzt werden: {e}", p.display()));
            continue;
        }
        match std::fs::copy(&me, &p) {
            Ok(_) => {
                say(&format!("Alte Kopie {} von {ver} auf {} aktualisiert", p.display(), kvpn::VERSION));
                if let Ok(t) = std::fs::metadata(&p).and_then(|m| m.modified()) {
                    seen.insert(p.clone(), t);
                }
            }
            Err(e) => {
                let _ = std::fs::rename(&old, &p);
                say(&format!("Alte Kopie {} ({ver}) konnte nicht ersetzt werden: {e}", p.display()));
            }
        }
    }
}

/// Steuerung fuer das Programmfenster
pub struct Fenster {
    a: Args,
}

impl Fenster {
    pub fn new(a: Args) -> Self {
        Fenster { a }
    }
}

fn open_service(access: ServiceAccess) -> Option<windows_service::service::Service> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    mgr.open_service(NAME, access).ok()
}

impl crate::gui::Steuerung for Fenster {
    fn lage(&self) -> crate::gui::Lage {
        use crate::gui::Lage;
        let Some(s) = open_service(ServiceAccess::QUERY_STATUS) else { return Lage::Fehlt };
        match s.query_status().map(|s| s.current_state) {
            Ok(ServiceState::Running) => Lage::Laeuft,
            Ok(ServiceState::StartPending | ServiceState::ContinuePending) => Lage::Startet,
            Ok(ServiceState::StopPending | ServiceState::PausePending) => Lage::Stoppt,
            _ => Lage::Aus,
        }
    }

    fn zustand(&self) -> Option<Zustand> {
        let z: Zustand = serde_json::from_slice(&std::fs::read(status_file()).ok()?).ok()?;
        (kvpn::util::now_secs().saturating_sub(z.ts) < 5).then_some(z)
    }

    fn gewollt(&self) -> bool {
        match open_service(ServiceAccess::QUERY_CONFIG) {
            None => true,
            Some(s) => s.query_config().map(|c| c.start_type == ServiceStartType::AutoStart).unwrap_or(true),
        }
    }

    fn verbinden(&self, cfg: &ClientConfig) -> Result<(), String> {
        install(cfg, &self.a)
    }

    fn trennen(&self) -> Result<(), String> {
        disconnect();
        Ok(())
    }

    fn code_speichern(&self, cfg: &ClientConfig) {
        crate::save_code(&self.a, cfg);
    }

    fn profile(&self) -> Vec<ClientConfig> {
        crate::profiles(&self.a)
    }

    fn profile_speichern(&self, list: &[ClientConfig]) {
        crate::save_profiles(&self.a, list);
    }

    fn protokoll(&self) -> String {
        let log = std::fs::read_to_string(log_file()).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        lines[lines.len().saturating_sub(300)..].join("\n")
    }

    fn protokoll_oeffnen(&self) {
        let _ = Command::new("notepad.exe").arg(log_file()).spawn();
    }

    fn klassisch(&self) -> Result<(), String> {
        crate::set_classic_view(&self.a, true);
        crate::restart_in_view(true)
    }
}

fn disconnect() {
    if let Ok(mgr) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
        if let Ok(s) = mgr.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP) {
            stop_and_wait(&s);
        }
    }
    // nicht mehr mit Windows starten, bis das Programm wieder geoeffnet wird
    sc(&["config", NAME, "start=", "demand"]);
}

/// --trennen / --entfernen
pub fn control(a: &Args) -> ! {
    disconnect();
    if a.uninstall {
        let ok = sc(&["delete", NAME]);
        if let Ok(l) = std::fs::read_to_string(data_dir().join("verknuepfung.txt")) {
            let _ = std::fs::remove_file(l.trim());
        }
        for f in [code_file(), proxy_file(), status_file(), data_dir().join("verknuepfung.txt")] {
            let _ = std::fs::remove_file(f);
        }
        let me = std::env::current_exe().ok().and_then(|p| std::fs::canonicalize(p).ok());
        let pdir = prog_dir();
        if me.map(|m| !m.starts_with(std::fs::canonicalize(&pdir).unwrap_or(pdir.clone()))).unwrap_or(true) {
            let _ = std::fs::remove_dir_all(&pdir);
        }
        println!("{}", if ok { "Dienst und gespeicherter Code entfernt." } else { "Kein Dienst eingerichtet (oder schon entfernt)." });
    } else {
        println!("VPN getrennt – der Dienst startet nicht mehr mit Windows. Wieder verbinden: Programm starten.");
    }
    crate::pause_and_exit(0)
}

/// Code des eingerichteten Dienstes (falls vorhanden)
pub fn stored_code() -> Option<String> {
    std::fs::read_to_string(code_file()).ok().filter(|c| c.trim().starts_with("kronevpn://"))
}
