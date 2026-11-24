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
pub fn background(cfg: &ClientConfig, a: &Args) -> ! {
    let title = cfg.display_name().to_string();
    crate::set_title(&format!("{title} – {}", cfg.name));
    println!("{title} {} – Geraet '{}' – Server {}", kvpn::VERSION, cfg.name, cfg.url);
    if let Err(e) = install(cfg, a) {
        crate::die(format!("{e}\nNotfalls ohne Dienst im Fenster starten:  \"{title}.exe\" --vordergrund"));
    }
    println!();
    println!("Laeuft im Hintergrund (Windows-Dienst) und startet auch automatisch mit Windows.");
    println!("Du kannst dieses Fenster jederzeit schliessen – das VPN bleibt an.");
    println!("VPN ausschalten: hier  t  eintippen und Enter  (oder Programm mit --trennen starten).");
    println!("Neue Ansicht (Programmfenster): hier  f  eintippen und Enter.\n");
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
            if line.trim().eq_ignore_ascii_case("f") {
                crate::set_classic_view(a, false);
                match crate::restart_in_view(false) {
                    Ok(()) => std::process::exit(0),
                    Err(e) => println!("\rProgrammfenster konnte nicht gestartet werden: {e}"),
                }
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
