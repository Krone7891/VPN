//! KroneVPN Client fuer Windows und Linux.
//!
//!   KroneVPN.exe                      startet mit dem gespeicherten Code (beim ersten Mal wird er abgefragt)
//!   KroneVPN.exe <code>               neuen Verbindungscode speichern und verbinden
//!   --test                            nur Verbindung + Handshake pruefen (kein Netzwerkadapter, z. B. "geht es durch die Firewall?")
//!   --proxy host:port                 HTTP-Proxy erzwingen (sonst: Systemproxy, dann direkt)
//!   --routes 10.0.0.0/8,...           nur diese Netze durch den Tunnel (Standard: alles)
//!   --reset                           gespeicherten Code loeschen
//!   --verschluesselung auto|aes|chacha  Verschluesselung waehlen (Auto = nach Prozessor, wird gemerkt)
//!   --kein-update                     nicht automatisch aktualisieren
//!   --profile                         gespeicherte Profile (Verbindungscodes) auflisten
//!   --profil <nr|name>                mit diesem Profil verbinden (wird das aktive Profil)
//!   --klassisch / --fenster           Windows: alte Text-Ansicht bzw. neues Programmfenster (wird gemerkt)
//!
//! Unter Windows oeffnet sich ein Programmfenster (gui.rs); das VPN selbst laeuft als Dienst im Hintergrund.
//! Mit --vordergrund, --test usw. gibt es wie frueher die Textanzeige in einer Konsole.
//!
//! Neue Versionen kommen automatisch ueber die VPN-Verbindung (signiert, siehe kvpn::update): das Programm
//! ersetzt sich selbst und startet neu.

// Windows: Fenster-Programm (keine Konsole beim Doppelklick); Textmodi holen sich eine Konsole (konsole())
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(any(windows, feature = "vorschau"))]
mod gui;

#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(windows, path = "windows.rs")]
mod plat;

// statische Linux-Builds (musl): schneller Speicher-Allokator
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use kvpn::client::{self, ClientOptions, Status};
use kvpn::code::ClientConfig;
use kvpn::transport::{parse_proxy, Proxy};
use kvpn::util::{human_bytes, human_rate};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct Args {
    pub code: Option<String>,
    pub proxy: Option<String>,
    pub routes: Option<Vec<String>>,
    pub test: bool,
    pub reset: bool,
    /// --verschluesselung: neue Wahl (wird gemerkt)
    pub cipher: Option<String>,
    /// Windows: --einrichten (vom Fenster mit Admin-Abfrage gestartet) und wohin das Ergebnis geschrieben wird
    pub setup: bool,
    pub result_file: Option<PathBuf>,
    /// --still: ohne Rueckfragen/Pause beenden
    pub quiet: bool,
    pub no_update: bool,
    /// Windows: im Fenster laufen statt als Dienst
    pub foreground: bool,
    /// Linux: als systemd-Dienst einrichten
    pub background: bool,
    /// vom Windows-Dienststeuerungs-Manager gestartet
    pub service: bool,
    pub disconnect: bool,
    pub uninstall: bool,
    pub config: Option<PathBuf>,
    pub tun: String,
    pub list_profiles: bool,
    pub profile: Option<String>,
    /// Windows: Some(true) = alte Text-Ansicht, Some(false) = Programmfenster, None = wie zuletzt gewaehlt
    pub classic: Option<bool>,
}

pub fn parse_args() -> Args {
    let mut a = Args { code: None, proxy: None, routes: None, test: false, reset: false, cipher: None, setup: false, result_file: None, quiet: false, no_update: false, foreground: false, background: false, service: false, disconnect: false, uninstall: false, config: None, tun: "kvpn-c0".into(), list_profiles: false, profile: None, classic: None };
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--test" | "--selftest" => a.test = true,
            "--reset" => a.reset = true,
            "--verschluesselung" | "--cipher" => a.cipher = it.next(),
            "--einrichten" => a.setup = true,
            "--ergebnis" => a.result_file = it.next().map(PathBuf::from),
            "--still" => a.quiet = true,
            "--kein-update" | "--no-update" => a.no_update = true,
            "--vordergrund" | "--foreground" => a.foreground = true,
            "--hintergrund" | "--background" => a.background = true,
            "--service" => a.service = true,
            "--trennen" | "--stop" => a.disconnect = true,
            "--entfernen" | "--uninstall" => a.uninstall = true,
            "--version" | "-V" => {
                konsole(true);
                println!("{}", kvpn::VERSION);
                std::process::exit(0);
            }
            "--profile" | "--profiles" => a.list_profiles = true,
            "--profil" => a.profile = it.next(),
            "--klassisch" | "--classic" | "--konsole" => a.classic = Some(true),
            "--fenster" | "--gui" => a.classic = Some(false),
            "--proxy" => a.proxy = it.next(),
            "--routes" => a.routes = it.next().map(|r| r.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()),
            "--config" => a.config = it.next().map(PathBuf::from),
            "--tun" => a.tun = it.next().unwrap_or(a.tun),
            "-h" | "--help" => {
                konsole(true);
                println!("KroneVPN {} – Aufruf: kronevpn [code] [--test] [--proxy host:port] [--routes netz,...] [--reset] [--verschluesselung auto|aes|chacha] [--kein-update] [--vordergrund|--hintergrund] [--trennen] [--entfernen] [--profile] [--profil nr|name] [--klassisch|--fenster] [--config datei]", kvpn::VERSION);
                std::process::exit(0);
            }
            c if c.starts_with("kronevpn://") => a.code = Some(c.to_string()),
            other => {
                konsole(true);
                eprintln!("Unbekannte Option: {other}");
                std::process::exit(2);
            }
        }
    }
    a
}

/// Windows: Konsole fuer die Textanzeige (das Programm selbst ist ein Fenster-Programm).
/// `anhaengen`: zuerst die Konsole des Aufrufers nehmen (z. B. --version in cmd)
pub fn konsole(_anhaengen: bool) {
    #[cfg(windows)]
    plat::konsole(_anhaengen);
}

/// Datei mit dem aktiven Verbindungscode (fuer --einrichten)
#[cfg_attr(not(windows), allow(dead_code))]
pub fn config_file(a: &Args) -> PathBuf {
    config_path(a)
}

fn config_path(a: &Args) -> PathBuf {
    if let Some(p) = &a.config {
        return p.clone();
    }
    plat::config_dir().join("verbindung.txt")
}

/// Fenstertitel (Windows-Konsole bzw. Terminal)
pub fn set_title(t: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("cmd").args(["/C", &format!("title {}", t.replace(['&', '|', '<', '>', '^'], " "))]).creation_flags(0).status();
    }
    #[cfg(not(windows))]
    {
        print!("\x1b]0;{t}\x07");
    }
}

pub fn pause_and_exit(code: i32) -> ! {
    #[cfg(windows)]
    {
        println!("\nEnter druecken zum Schliessen ...");
        let _ = std::io::stdin().lock().read_line(&mut String::new());
    }
    std::process::exit(code)
}

pub fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("\nFehler: {msg}");
    pause_and_exit(1)
}

pub fn load_config(a: &Args) -> ClientConfig {
    let path = config_path(a);
    if a.reset {
        let _ = std::fs::remove_file(&path);
        println!("Gespeicherter Code geloescht.");
    }
    let code = if let Some(c) = known_code(a) {
        c
    } else {
        println!("KroneVPN {} – erster Start\n", kvpn::VERSION);
        println!("Bitte den Verbindungscode einfuegen (beginnt mit kronevpn://v1/ ...) und Enter druecken.");
        println!("Den Code bekommst du auf dem Server mit:  kvpn-server add \"Mein PC\"\n");
        print!("> ");
        let _ = std::io::stdout().flush();
        let mut s = String::new();
        let _ = std::io::stdin().lock().read_line(&mut s);
        s
    };
    let cfg = ClientConfig::from_code(&code).unwrap_or_else(|e| die(e));
    if a.code.is_some() || !path.exists() {
        save_code(a, &cfg);
    }
    cfg
}

/// gespeicherter bzw. uebergebener Code (ohne Rueckfrage)
pub fn known_code(a: &Args) -> Option<String> {
    if let Some(c) = &a.code {
        return Some(c.clone());
    }
    if let Ok(c) = std::fs::read_to_string(config_path(a)) {
        return Some(c);
    }
    // Code des eingerichteten Hintergrund-Dienstes (z. B. Programm von woanders gestartet)
    plat::dienst::stored_code().filter(|_| !a.reset)
}

// ------------------------------------------------------------------------------------------------ Profile
// Mehrere Verbindungscodes (z. B. verschiedene Server oder Geraete) in profile.txt neben verbindung.txt,
// einer pro Zeile. verbindung.txt ist das aktive Profil.

fn profiles_path(a: &Args) -> PathBuf {
    config_path(a).with_file_name("profile.txt")
}

/// gleiches Profil = gleicher Server und gleicher Geraetename (ein neuer Code dafuer ersetzt den alten)
pub fn same_profile(x: &ClientConfig, y: &ClientConfig) -> bool {
    x.url == y.url && x.name == y.name
}

pub fn profiles(a: &Args) -> Vec<ClientConfig> {
    let mut v: Vec<ClientConfig> = Vec::new();
    for l in std::fs::read_to_string(profiles_path(a)).unwrap_or_default().lines() {
        if let Ok(c) = ClientConfig::from_code(l) {
            if !v.iter().any(|x| same_profile(x, &c)) {
                v.push(c);
            }
        }
    }
    v
}

pub fn save_profiles(a: &Args, list: &[ClientConfig]) {
    let path = profiles_path(a);
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let text: String = list.iter().map(|c| c.to_code() + "\n").collect();
    if std::fs::write(&path, text).is_ok() {
        plat::restrict_file(&path);
    }
}

pub fn profile_label(c: &ClientConfig) -> String {
    let host = c.url.split("://").nth(1).unwrap_or(&c.url).split('/').next().unwrap_or("").to_string();
    format!("{} – {} ({host})", c.display_name(), c.name)
}

// ------------------------------------------------------------------------------------------------ Ansicht (Windows)

fn view_path(a: &Args) -> PathBuf {
    config_path(a).with_file_name("ansicht.txt")
}

/// alte Text-Ansicht statt Programmfenster? (--klassisch/--fenster wird gemerkt)
#[cfg_attr(not(windows), allow(dead_code))]
pub fn classic_view(a: &Args) -> bool {
    match a.classic {
        Some(c) => {
            set_classic_view(a, c);
            c
        }
        None => std::fs::read_to_string(view_path(a)).map(|s| s.trim() == "klassisch").unwrap_or(false),
    }
}

pub fn set_classic_view(a: &Args, classic: bool) {
    let p = view_path(a);
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(p, if classic { "klassisch" } else { "fenster" });
}

/// Programm in der anderen Ansicht neu starten (dieses beendet sich danach)
#[cfg_attr(not(windows), allow(dead_code))]
pub fn restart_in_view(classic: bool) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    restart_exe(&exe, classic)
}

/// `exe` mit denselben Argumenten (ohne Code) in der gewuenschten Ansicht starten
#[cfg_attr(not(windows), allow(dead_code))]
pub fn restart_exe(exe: &std::path::Path, classic: bool) -> Result<(), String> {
    let mut args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|x| !x.starts_with("kronevpn://") && !matches!(x.as_str(), "--klassisch" | "--classic" | "--konsole" | "--fenster" | "--gui"))
        .collect();
    args.push(if classic { "--klassisch" } else { "--fenster" }.into());
    std::process::Command::new(exe).args(args).spawn().map_err(|e| e.to_string())?;
    Ok(())
}

/// --profile / --profil
fn profile_cli(a: &mut Args) {
    let list = profiles(a);
    let active = known_code(a).and_then(|c| ClientConfig::from_code(&c).ok());
    if a.list_profiles {
        if list.is_empty() {
            println!("Noch keine Profile gespeichert.");
        }
        for (i, c) in list.iter().enumerate() {
            let mark = if active.as_ref().is_some_and(|x| same_profile(x, c)) { "*" } else { " " };
            println!("{mark} {}  {}", i + 1, profile_label(c));
        }
        println!("\nWechseln: kronevpn --profil <nr>   Neues Profil: kronevpn <code>");
        pause_and_exit(0);
    }
    if let Some(want) = a.profile.clone() {
        let w = want.to_lowercase();
        let found = match want.parse::<usize>() {
            Ok(n) if n >= 1 && n <= list.len() => Some(&list[n - 1]),
            _ => list.iter().find(|c| c.name.to_lowercase() == w).or_else(|| list.iter().find(|c| profile_label(c).to_lowercase().contains(&w))),
        };
        match found {
            Some(c) => a.code = Some(c.to_code()),
            None => {
                konsole(false);
                die(format!("Profil '{want}' nicht gefunden (Liste: kronevpn --profile)"))
            }
        }
    }
}

pub fn save_code(a: &Args, cfg: &ClientConfig) {
    // auch in die Profil-Liste (gleiches Profil wird ersetzt)
    let mut list = profiles(a);
    match list.iter().position(|x| same_profile(x, cfg)) {
        Some(i) => list[i] = cfg.clone(),
        None => list.push(cfg.clone()),
    }
    save_profiles(a, &list);
    let path = config_path(a);
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if std::fs::write(&path, cfg.to_code()).is_ok() {
        plat::restrict_file(&path);
        say(&format!("Code gespeichert: {}", path.display()));
    }
}

/// Wege zum Server: erzwungener Proxy, Proxy aus dem Code, Systemproxy (zuerst) + direkt
pub fn ways(a: &Args, cfg: &ClientConfig) -> Vec<Option<Proxy>> {
    let forced = a.proxy.clone().or_else(|| (!cfg.proxy.is_empty()).then(|| cfg.proxy.clone()));
    if let Some(p) = forced {
        return vec![Some(parse_proxy(&p).unwrap_or_else(|e| die(e)).unwrap_or_else(|| die("Proxy leer")))];
    }
    match plat::system_proxy().and_then(|p| parse_proxy(&p).ok().flatten()) {
        Some(p) => {
            println!("Systemproxy gefunden: {}:{} (wird zuerst probiert, sonst direkt)", p.host, p.port);
            vec![Some(p), None]
        }
        None => vec![None],
    }
}

fn cipher_path(a: &Args) -> PathBuf {
    // Windows: beim Dienst (laeuft als SYSTEM) in C:\ProgramData\KroneVPN, damit Fenster und Dienst dieselbe sehen
    #[cfg(windows)]
    if a.config.is_none() {
        return plat::dienst::data_dir().join("verschluesselung.txt");
    }
    config_path(a).with_file_name("verschluesselung.txt")
}

/// Ordner fuer Absturz-Protokolle (Windows: C:\ProgramData\KroneVPN\absturz, wie beim Dienst)
pub fn crash_dir(a: &Args) -> PathBuf {
    #[cfg(windows)]
    if a.config.is_none() {
        return plat::dienst::data_dir().join("absturz");
    }
    config_path(a).with_file_name("absturz")
}

/// Ordner fuer das Logo des Servers (logo.png, logo.id, Windows auch logo.ico)
pub fn logo_dir(a: &Args) -> PathBuf {
    #[cfg(windows)]
    if a.config.is_none() {
        return plat::dienst::data_dir().join("logo");
    }
    config_path(a).with_file_name("logo")
}

/// letzte Zeilen des Protokolls fuer ein Absturz-Protokoll
fn log_tail() -> String {
    #[cfg(windows)]
    {
        let t = std::fs::read_to_string(plat::dienst::log_file()).unwrap_or_default();
        let z: Vec<&str> = t.lines().collect();
        format!("Letzte Zeilen des Protokolls:\n{}", z[z.len().saturating_sub(40)..].join("\n"))
    }
    #[cfg(not(windows))]
    String::new()
}

/// gewaehlte Verschluesselung: "auto" (Standard), "aes" oder "chacha"
pub fn cipher_choice(a: &Args) -> String {
    let s = std::fs::read_to_string(cipher_path(a)).unwrap_or_default();
    kvpn::crypto::normalize_choice(&s).to_string()
}

pub fn set_cipher_choice(a: &Args, choice: &str) -> Result<(), String> {
    let p = cipher_path(a);
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    std::fs::write(&p, kvpn::crypto::normalize_choice(choice)).map_err(|e| format!("{}: {e}", p.display()))
}

/// Anzeige der Wahl, z. B. "Auto (AES-256-GCM, Prozessor hat AES-Befehle)"
pub fn cipher_text(choice: &str) -> String {
    match kvpn::crypto::normalize_choice(choice) {
        "aes" => "AES-256-GCM (fest)".into(),
        "chacha" => "ChaCha20-Poly1305 (fest)".into(),
        _ if kvpn::crypto::aes_hw() => "Auto – AES-256-GCM (Prozessor hat AES-Befehle)".into(),
        _ => "Auto – ChaCha20-Poly1305 (schneller ohne AES-Befehle)".into(),
    }
}

/// Datei neben dem Programm: "<programm>.<endung>"
pub fn beside_exe(ext: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let name = exe.file_name()?.to_string_lossy().to_string();
    Some(exe.with_file_name(format!("{name}.{ext}")))
}

/// heruntergeladene neue Version an die Stelle des Programms setzen und neu starten
/// `restart`: Programm danach neu starten (im Dienst startet Windows es selbst neu)
pub fn apply_update(new: &std::path::Path, restart: bool) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let old = beside_exe("old").ok_or("Programmpfad unbekannt")?;
    let _ = std::fs::remove_file(&old);
    // ein laufendes Programm darf umbenannt (aber nicht ueberschrieben) werden – auch unter Windows
    std::fs::rename(&exe, &old).map_err(|e| format!("{}: {e}", exe.display()))?;
    if let Err(e) = std::fs::rename(new, &exe) {
        let _ = std::fs::rename(&old, &exe);
        return Err(format!("{}: {e}", exe.display()));
    }
    if !restart {
        return Ok(());
    }
    let args: Vec<String> = std::env::args().skip(1).filter(|a| !a.starts_with("kronevpn://")).collect();
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let e = std::process::Command::new(&exe).args(&args).exec();
        Err(format!("Neustart: {e}"))
    }
    #[cfg(not(unix))]
    {
        std::process::Command::new(&exe).args(&args).spawn().map_err(|e| format!("Neustart: {e}"))?;
        std::process::exit(0)
    }
}

fn main() {
    let mut a = parse_args();
    // Abstuerze protokollieren (die Datei geht beim naechsten Verbinden an den Server)
    kvpn::fehler::absturz_haken(crash_dir(&a), "PC", log_tail);
    // Rest eines Updates aufraeumen
    if let Some(old) = beside_exe("old") {
        let _ = std::fs::remove_file(old);
    }
    // Windows-Dienst (vom System gestartet) bzw. Dienst steuern – ohne Rueckfragen
    #[cfg(windows)]
    if a.service {
        plat::dienst::run_service();
        return;
    }
    // Windows: vom Fenster mit Admin-Abfrage gestartet, um den Dienst einzurichten
    #[cfg(windows)]
    if a.setup {
        plat::dienst::setup_cli(&a);
    }
    // Vorschau des Programmfensters (Linux, nur zum Entwickeln)
    #[cfg(feature = "vorschau")]
    if let Ok(m) = std::env::var("KVPN_VORSCHAU") {
        gui::vorschau(&m);
        return;
    }
    if a.list_profiles {
        konsole(false);
    }
    if a.list_profiles || a.profile.is_some() {
        profile_cli(&mut a);
    }
    // Windows: Programmfenster (ausser fuer die Textmodi)
    #[cfg(windows)]
    {
        // eine aeltere Kopie (z. B. im Download-Ordner) gestartet, installiert ist schon eine neuere? Dann die nehmen
        if !(a.disconnect || a.uninstall) {
            plat::dienst::record_copy();
            if let Some(neu) = plat::dienst::newer_installed() {
                let args: Vec<String> = std::env::args().skip(1).collect();
                if std::process::Command::new(neu).args(args).spawn().is_ok() {
                    std::process::exit(0);
                }
            }
        }
        if !(a.foreground || a.test || a.disconnect || a.uninstall || a.reset) && !classic_view(&a) {
            fenster(&a);
        }
        // Text-Modi richten den Dienst bzw. den Adapter selbst ein: dafuer Admin (einmal Abfrage, wie frueher)
        if !a.test && !a.list_profiles {
            plat::dienst::ensure_admin();
        }
        if !a.quiet {
            konsole(false);
        }
    }
    if a.disconnect || a.uninstall {
        plat::dienst::control(&a);
    }
    let cfg = load_config(&a);
    if let Some(c) = &a.cipher {
        match set_cipher_choice(&a, c) {
            Ok(()) => say(&format!(
                "Verschluesselung: {} (gilt ab der naechsten Verbindung)\n  Verschluesselt ist immer – hier wird nur das Verfahren gewaehlt, alle sind gleich sicher. Auto nimmt das schnellste fuer dieses Geraet.\n  Immer aktiv: HTTPS-Huelle (TLS 1.3, sieht aus wie eine Webseite), Geraete-Schluessel (Noise, nur Server und Geraete koennen lesen), Tarnung (keine VPN-Muster).",
                cipher_text(c)
            )),
            Err(e) => say(&format!("Verschluesselung konnte nicht gespeichert werden: {e}")),
        }
    }
    let ways = ways(&a, &cfg);
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(cores.clamp(2, 8)).enable_all().build().unwrap();

    if a.test {
        rt.block_on(async {
            println!("{} – Verbindungstest zu {} ...", cfg.display_name(), cfg.url);
            let mut ok = false;
            for w in &ways {
                let via = w.as_ref().map(|p| format!("ueber Proxy {}:{}", p.host, p.port)).unwrap_or_else(|| "direkt".into());
                let t = std::time::Instant::now();
                match client::connect_once_with(&cfg, w.as_ref(), &None, &kvpn::transport::new_dns_cache(), false, &cipher_choice(&a)).await {
                    Ok((_ws, _s, _o, welcome, info)) => {
                        println!("  OK {via}: Handshake in {} ms", t.elapsed().as_millis());
                        println!("     Verschluesselung: {} (Einstellung: {}){}", kvpn::crypto::cipher_label(&welcome.cipher), cipher_text(&cipher_choice(&a)), if welcome.tarn.is_some() { ", Tarn-Schicht aktiv" } else { "" });
                        println!("     Server: {}", info.peer.map(|p| p.to_string()).unwrap_or_default());
                        println!(
                            "     TLS-Zertifikat: {} – {}",
                            info.tls_issuer,
                            if info.tls_trusted { "oeffentlich vertrauenswuerdig" } else { "NICHT oeffentlich (HTTPS-Inspektion der Firewall?) – trotzdem sicher, Noise prueft den Server" }
                        );
                        println!("     Tunnel-Adresse: {} {}  DNS: {}", welcome.ip4, welcome.ip6, welcome.dns.join(", "));
                        ok = true;
                        break;
                    }
                    Err(e) => {
                        let k = kvpn::fehler::klartext(&e);
                        if k == e {
                            println!("  FEHLER {via}: {e}");
                        } else {
                            println!("  FEHLER {via}: {e}\n         -> {k}");
                        }
                    }
                }
            }
            if ok {
                println!("\nVerbindungstest erfolgreich.");
                pause_and_exit(0)
            } else {
                println!("\nVerbindungstest fehlgeschlagen.");
                pause_and_exit(1)
            }
        });
    }

    // Windows: als Hintergrund-Dienst (das Fenster darf zu) – ausser mit --vordergrund
    #[cfg(windows)]
    if !a.foreground {
        drop(rt);
        plat::dienst::background(&cfg, &a);
    }
    // Linux: --hintergrund richtet einen systemd-Dienst ein
    #[cfg(target_os = "linux")]
    if a.background {
        plat::dienst::install(&cfg, &a);
    }

    let title = cfg.display_name().to_string();
    set_title(&format!("{title} – {}", cfg.name));
    println!("{title} {} – Geraet '{}' – Server {}", kvpn::VERSION, cfg.name, cfg.url);
    #[cfg(windows)]
    println!("(Vordergrund: Fenster schliessen beendet das VPN. Ohne --vordergrund laeuft es als Dienst im Hintergrund.)");
    match rt.block_on(run_vpn(cfg, &a, ways, Ui::Console, plat::wait_for_exit())) {
        Ok(Ende::Stopp) => {}
        Ok(Ende::Update(f)) => {
            if let Err(e) = apply_update(&f, true) {
                println!("Update konnte nicht eingespielt werden: {e} – bitte Programm neu starten");
                pause_and_exit(1);
            }
        }
        Err(e) => die(e),
    }
}

/// Windows: Programmfenster oeffnen. Kehrt nur zurueck, wenn es nicht geht (dann Textanzeige wie frueher).
#[cfg(windows)]
fn fenster(a: &Args) {
    let cfg = known_code(a).and_then(|c| ClientConfig::from_code(&c).ok());
    if let (Some(c), true) = (&cfg, a.code.is_some()) {
        save_code(a, c);
    }
    let st = std::sync::Arc::new(plat::dienst::Fenster::new(a.clone()));
    if let Err(e) = gui::run(st, cfg, a.code.is_some()) {
        konsole(false);
        println!("Das Programmfenster konnte nicht geoeffnet werden ({e}) – Textanzeige.\n");
        return;
    }
    std::process::exit(0)
}

// ------------------------------------------------------------------------------------------------ Tunnel

pub enum Ende {
    /// beendet (Strg+C, Fenster zu, Dienst gestoppt)
    Stopp,
    /// neue Version liegt neben dem Programm (.new) – einspielen und neu starten
    Update(PathBuf),
}

pub enum Ui {
    /// Live-Werte im Fenster
    Console,
    /// Dienst: Zustand jede Sekunde in diese Datei (das Fenster liest sie)
    Datei(PathBuf),
}

/// Protokoll: im Fenster ausgeben bzw. (Dienst) in die Protokolldatei schreiben
pub static LOGFILE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

pub fn say(msg: &str) {
    let Some(p) = LOGFILE.get() else {
        println!("{msg}");
        return;
    };
    if std::fs::metadata(p).map(|m| m.len() > 1 << 20).unwrap_or(false) {
        let _ = std::fs::rename(p, p.with_extension("alt.txt"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
        let _ = writeln!(f, "{} {}", timestamp(), msg.trim_matches(|c: char| c == '\r' || c == '\n').trim_end());
    }
}

/// "2026-11-24 10:15:00" (UTC)
pub fn timestamp() -> String {
    let t = kvpn::util::now_secs();
    let (d, s) = ((t / 86400) as i64, t % 86400);
    // Tage seit 1970 -> Datum (Howard Hinnant)
    let z = d + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + (month <= 2) as i64;
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC", s / 3600, s / 60 % 60, s % 60)
}

/// Zustand fuer Fenster und Status-Datei
#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
#[serde(default)]
pub struct Zustand {
    pub state: String,
    pub title: String,
    pub name: String,
    pub version: String,
    pub server: String,
    pub via_proxy: bool,
    pub tls_trusted: bool,
    pub tls_issuer: String,
    pub rx: u64,
    pub tx: u64,
    pub rate_rx: u64,
    pub rate_tx: u64,
    pub rtt_ms: f64,
    pub since: u64,
    pub error: String,
    /// technische Fassung des Fehlers
    pub error_detail: String,
    pub update_version: String,
    pub update_got: u64,
    pub update_size: u64,
    pub ts: u64,
    /// Verschluesselung der laufenden Verbindung ("AES-256-GCM" / "ChaCha20-Poly1305")
    pub cipher: String,
    /// Wahl ("auto", "aes", "chacha")
    pub cipher_choice: String,
    pub aes_hw: bool,
}

/// eine Zeile Live-Werte
pub fn live_line(z: &Zustand) -> String {
    format!(
        "  Download {:>13}  Upload {:>13}  Ping {:>5.0} ms  gesamt {} / {}",
        human_rate(z.rate_rx as f64),
        human_rate(z.rate_tx as f64),
        z.rtt_ms,
        human_bytes(z.rx),
        human_bytes(z.tx)
    )
}

pub fn tls_text(z: &Zustand) -> String {
    if z.tls_trusted {
        "TLS ok".to_string()
    } else {
        format!("TLS-Inspektion erkannt ({}) – Daten bleiben verschluesselt", z.tls_issuer)
    }
}

/// Tunnel aufbauen und betreiben, bis `stop` eintritt oder ein Update bereitliegt
pub async fn run_vpn<F: std::future::Future<Output = ()>>(cfg: ClientConfig, a: &Args, ways: Vec<Option<Proxy>>, ui: Ui, stop: F) -> Result<Ende, String> {
    let console = matches!(ui, Ui::Console);
    tokio::pin!(stop);
    let status = Arc::new(Status::default());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    // Server (und Proxy) JETZT aufloesen – nach dem Einrichten laeuft DNS durch den Tunnel, der dann noch nicht steht
    let dns = kvpn::transport::new_dns_cache();
    let t = kvpn::transport::parse_url(&cfg.url)?;
    loop {
        match kvpn::transport::preresolve(&dns, &t.host, t.port) {
            Ok(v) => {
                say(&format!("Server {} -> {}", t.host, v.iter().map(|a| a.ip().to_string()).collect::<Vec<_>>().join(", ")));
                break;
            }
            Err(e) if ways.iter().any(|w| w.is_some()) => {
                say(&format!("Hinweis: {e} (geht evtl. ueber den Proxy)"));
                break;
            }
            Err(e) if console => {
                return Err(format!("{e}\nOhne Internet bzw. DNS kann das VPN den Server nicht finden. Bitte Netzwerk pruefen und neu starten."));
            }
            Err(e) => {
                // Dienst (z. B. direkt nach dem Hochfahren): warten, bis das Netz da ist
                say(&format!("{e} – warte auf Netz ..."));
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    _ = &mut stop => return Ok(Ende::Stopp),
                }
            }
        }
    }
    for w in ways.iter().flatten() {
        let _ = kvpn::transport::preresolve(&dns, &w.host, w.port);
    }
    let p = plat::Platform::setup(&cfg, a)?;
    // automatische Updates: neue Version kommt signiert ueber die Verbindung, wird neben das Programm gelegt
    let (upd_tx, mut upd_rx) = tokio::sync::mpsc::unbounded_channel::<PathBuf>();
    let updater = match (a.no_update, beside_exe("new")) {
        (false, Some(target)) => Some(Arc::new(kvpn::update::Updater::new(move |r: kvpn::update::Ready| {
            let tmp = target.with_extension("part");
            let res = std::fs::write(&tmp, &r.data).and_then(|_| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
                }
                std::fs::rename(&tmp, &target)
            });
            match res {
                Ok(()) => {
                    say(&format!("\rUpdate auf Version {} geladen und geprueft – starte neu ...                    ", r.version));
                    let _ = upd_tx.send(target.clone());
                }
                Err(e) => say(&format!("\rUpdate {} konnte nicht gespeichert werden: {e}", r.version)),
            }
        }))),
        _ => None,
    };
    let ca = a.clone();
    let cipher: Arc<dyn Fn() -> String + Send + Sync> = Arc::new(move || cipher_choice(&ca));
    let opts = ClientOptions { routes: ways, protect: p.protect(), dns, reconnect: None, on_connected: None, update: updater.clone(), cipher: Some(cipher) };
    let task = tokio::spawn(client::run(cfg.clone(), opts, p.take_reader(), p.writer(), status.clone(), stop_rx));
    if console {
        println!("Beenden mit Strg+C (oder Fenster schliessen).\n");
    }

    // Absturz-Protokolle von frueher: gehen beim Verbinden an den Server, nach Bestaetigung wird geloescht
    let crashes = crash_dir(a);
    for (n, b) in kvpn::fehler::absturz_dateien(&crashes) {
        status.add_crash(&n, &b);
    }
    // eigenes Logo des Servers: kommt beim Verbinden, wenn es neu ist (Windows: Symbol der Verknuepfung)
    let logos = logo_dir(a);
    *status.logo_dir.lock().unwrap() = Some(logos.clone());
    let mut logo_seq = 0u64;
    let st = status.clone();
    let title = cfg.display_name().to_string();
    let name = cfg.name.clone();
    let status_path = match &ui {
        Ui::Datei(f) => Some(f.clone()),
        Ui::Console => None,
    };
    let show = tokio::spawn(async move {
        let (mut lrx, mut ltx) = (0u64, 0u64);
        let mut last_state = String::new();
        let mut last_err = String::new();
        let mut upd_shown = String::new();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let ls = st.logo_seq.load(Relaxed);
            if ls != logo_seq {
                logo_seq = ls;
                let neu = !kvpn::logo::id_in(&logos).is_empty();
                say(&format!("\r{}                              ", if neu { "Neues Logo vom Server uebernommen" } else { "Logo entfernt – wieder die Krone" }));
                #[cfg(windows)]
                plat::dienst::logo_geaendert(&logos);
            }
            for n in st.take_crash_ok() {
                if std::fs::remove_file(crashes.join(&n)).is_ok() {
                    say(&format!("\rAbsturz-Protokoll {n} an den Server uebertragen                    "));
                }
            }
            let info = st.info.lock().unwrap().clone();
            let (rx, tx) = (st.rx_bytes.load(Relaxed), st.tx_bytes.load(Relaxed));
            let us = updater.as_ref().map(|u| u.status()).unwrap_or_default();
            let z = Zustand {
                state: st.state_name().to_string(),
                title: title.clone(),
                name: name.clone(),
                version: kvpn::VERSION.to_string(),
                server: info.server.clone(),
                via_proxy: info.via_proxy,
                tls_trusted: info.tls_trusted,
                tls_issuer: info.tls_issuer.clone(),
                rx,
                tx,
                rate_rx: rx.saturating_sub(lrx),
                rate_tx: tx.saturating_sub(ltx),
                rtt_ms: st.rtt_us.load(Relaxed) as f64 / 1000.0,
                since: st.connected_since.load(Relaxed),
                error: info.last_error.clone(),
                error_detail: info.last_error_detail.clone(),
                update_version: if us.done { String::new() } else { us.version.clone() },
                update_got: us.got,
                update_size: us.size,
                ts: kvpn::util::now_secs(),
                cipher: info.cipher.clone(),
                cipher_choice: info.cipher_choice.clone(),
                aes_hw: info.aes_hw,
            };
            (lrx, ltx) = (rx, tx);
            if !z.update_version.is_empty() && z.update_version != upd_shown {
                say(&format!("\rNeue Version {} verfuegbar – wird im Hintergrund geladen ({} KB)          ", z.update_version, z.update_size / 1024));
                upd_shown = z.update_version.clone();
            }
            if z.state != last_state {
                if z.state == "connected" {
                    say(&format!("\rVerbunden mit {}{} – {}                    ", z.server, if z.via_proxy { " ueber Proxy" } else { "" }, tls_text(&z)));
                } else if z.state == "connecting" && last_state == "connected" {
                    say("\rVerbindung unterbrochen – verbinde neu ...                              ");
                }
                last_state = z.state.clone();
            }
            if !z.error.is_empty() && z.error != last_err && z.state != "connected" {
                // Klartext und – fuers Protokoll – die technische Meldung
                if z.error_detail.is_empty() || z.error_detail == z.error {
                    say(&format!("\r{}                                        ", z.error));
                } else {
                    say(&format!("\r{} [{}]                    ", z.error, z.error_detail));
                }
            }
            last_err = z.error.clone();
            match &ui {
                Ui::Console => {
                    // Live-Zeile nur im Terminal (unter systemd nicht jede Sekunde ins Protokoll)
                    if z.state == "connected" && std::io::IsTerminal::is_terminal(&std::io::stdout()) {
                        print!("\r{}      ", live_line(&z));
                        let _ = std::io::stdout().flush();
                    }
                }
                Ui::Datei(f) => {
                    let tmp = f.with_extension("tmp");
                    if std::fs::write(&tmp, serde_json::to_vec(&z).unwrap_or_default()).is_ok() {
                        let _ = std::fs::rename(&tmp, f);
                    }
                }
            }
        }
    });

    let ende = tokio::select! {
        _ = &mut stop => Ende::Stopp,
        f = upd_rx.recv() => f.map(Ende::Update).unwrap_or(Ende::Stopp),
    };
    say("\nTrenne ...");
    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    show.abort();
    p.cleanup();
    say("Getrennt.");
    if let Some(f) = &status_path {
        let _ = std::fs::remove_file(f);
    }
    Ok(ende)
}
