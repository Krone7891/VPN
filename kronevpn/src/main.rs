//! KroneVPN Client fuer Windows und Linux.
//!
//!   KroneVPN.exe                      startet mit dem gespeicherten Code (beim ersten Mal wird er abgefragt)
//!   KroneVPN.exe <code>               neuen Verbindungscode speichern und verbinden
//!   --test                            nur Verbindung + Handshake pruefen (kein Netzwerkadapter, z. B. "geht es durch die Firewall?")
//!   --proxy host:port                 HTTP-Proxy erzwingen (sonst: Systemproxy, dann direkt)
//!   --routes 10.0.0.0/8,...           nur diese Netze durch den Tunnel (Standard: alles)
//!   --reset                           gespeicherten Code loeschen
//!   --code                            gespeicherten Verbindungscode + QR-Code anzeigen (z. B. fuers Handy)
//!   --kein-update                     nicht automatisch aktualisieren
//!
//! Neue Versionen kommen automatisch ueber die VPN-Verbindung (signiert, siehe kvpn::update): das Programm
//! ersetzt sich selbst und startet neu.

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

pub struct Args {
    pub code: Option<String>,
    pub proxy: Option<String>,
    pub routes: Option<Vec<String>>,
    pub test: bool,
    pub reset: bool,
    pub show_code: bool,
    pub no_update: bool,
    pub config: Option<PathBuf>,
    pub tun: String,
}

fn parse_args() -> Args {
    let mut a = Args { code: None, proxy: None, routes: None, test: false, reset: false, show_code: false, no_update: false, config: None, tun: "kvpn-c0".into() };
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--test" | "--selftest" => a.test = true,
            "--reset" => a.reset = true,
            "--code" | "--zeige-code" => a.show_code = true,
            "--kein-update" | "--no-update" => a.no_update = true,
            "--proxy" => a.proxy = it.next(),
            "--routes" => a.routes = it.next().map(|r| r.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()),
            "--config" => a.config = it.next().map(PathBuf::from),
            "--tun" => a.tun = it.next().unwrap_or(a.tun),
            "-h" | "--help" => {
                println!("KroneVPN {} – Aufruf: kronevpn [code] [--test] [--proxy host:port] [--routes netz,...] [--reset] [--code] [--kein-update] [--config datei]", kvpn::VERSION);
                std::process::exit(0);
            }
            c if c.starts_with("kronevpn://") => a.code = Some(c.to_string()),
            other => {
                eprintln!("Unbekannte Option: {other}");
                std::process::exit(2);
            }
        }
    }
    a
}

fn config_path(a: &Args) -> PathBuf {
    if let Some(p) = &a.config {
        return p.clone();
    }
    plat::config_dir().join("verbindung.txt")
}

/// Fenstertitel (Windows-Konsole bzw. Terminal)
fn set_title(t: &str) {
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

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("\nFehler: {msg}");
    pause_and_exit(1)
}

fn load_config(a: &Args) -> ClientConfig {
    let path = config_path(a);
    if a.reset {
        let _ = std::fs::remove_file(&path);
        println!("Gespeicherter Code geloescht.");
    }
    let code = if let Some(c) = &a.code {
        c.clone()
    } else if let Ok(c) = std::fs::read_to_string(&path) {
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
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        if std::fs::write(&path, cfg.to_code()).is_ok() {
            plat::restrict_file(&path);
            println!("Code gespeichert: {}", path.display());
        }
    }
    cfg
}

/// Wege zum Server: erzwungener Proxy, Proxy aus dem Code, Systemproxy (zuerst) + direkt
fn ways(a: &Args, cfg: &ClientConfig) -> Vec<Option<Proxy>> {
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

fn qr(text: &str) -> String {
    match qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::L) {
        Ok(c) => c
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .quiet_zone(true)
            .build(),
        Err(_) => "(QR-Code zu gross)".into(),
    }
}

/// Datei neben dem Programm: "<programm>.<endung>"
fn beside_exe(ext: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let name = exe.file_name()?.to_string_lossy().to_string();
    Some(exe.with_file_name(format!("{name}.{ext}")))
}

/// heruntergeladene neue Version an die Stelle des Programms setzen und neu starten
fn apply_update(new: &std::path::Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let old = beside_exe("old").ok_or("Programmpfad unbekannt")?;
    let _ = std::fs::remove_file(&old);
    // ein laufendes Programm darf umbenannt (aber nicht ueberschrieben) werden – auch unter Windows
    std::fs::rename(&exe, &old).map_err(|e| format!("{}: {e}", exe.display()))?;
    if let Err(e) = std::fs::rename(new, &exe) {
        let _ = std::fs::rename(&old, &exe);
        return Err(format!("{}: {e}", exe.display()));
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
    let a = parse_args();
    // Rest eines Updates aufraeumen
    if let Some(old) = beside_exe("old") {
        let _ = std::fs::remove_file(old);
    }
    let cfg = load_config(&a);
    if a.show_code {
        let code = cfg.to_code();
        println!("{}", qr(&code));
        println!("{} – Verbindungscode fuer '{}' (geheim halten):\n\n{code}\n", cfg.display_name(), cfg.name);
        println!("Auf dem Server merken (dann geht dort 'kvpn-server code'):  kvpn-server import '<code>'");
        pause_and_exit(0);
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
                match client::connect_once(&cfg, w.as_ref(), &None, &kvpn::transport::new_dns_cache()).await {
                    Ok((_ws, _s, _o, welcome, info)) => {
                        println!("  OK {via}: Handshake in {} ms", t.elapsed().as_millis());
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
                    Err(e) => println!("  FEHLER {via}: {e}"),
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

    rt.block_on(async move {
        let title = cfg.display_name().to_string();
        set_title(&format!("{title} – {}", cfg.name));
        println!("{title} {} – Geraet '{}' – Server {}", kvpn::VERSION, cfg.name, cfg.url);
        let status = Arc::new(Status::default());
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        // Server (und Proxy) JETZT aufloesen - nach dem Einrichten laeuft DNS durch den Tunnel, der dann noch nicht steht
        let dns = kvpn::transport::new_dns_cache();
        let t = kvpn::transport::parse_url(&cfg.url).unwrap_or_else(|e| die(e));
        match kvpn::transport::preresolve(&dns, &t.host, t.port) {
            Ok(v) => println!("Server {} -> {}", t.host, v.iter().map(|a| a.ip().to_string()).collect::<Vec<_>>().join(", ")),
            Err(e) => {
                if ways.iter().all(|w| w.is_none()) {
                    die(format!("{e}\nOhne Internet bzw. DNS kann KroneVPN den Server nicht finden. Bitte Netzwerk pruefen und neu starten."));
                }
                println!("Hinweis: {e} (geht evtl. ueber den Proxy)");
            }
        }
        for w in ways.iter().flatten() {
            let _ = kvpn::transport::preresolve(&dns, &w.host, w.port);
        }
        let p = plat::Platform::setup(&cfg, &a).unwrap_or_else(|e| die(e));
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
                        println!("\rUpdate auf Version {} geladen und geprueft – starte neu ...                    ", r.version);
                        let _ = upd_tx.send(target.clone());
                    }
                    Err(e) => println!("\rUpdate {} konnte nicht gespeichert werden: {e}", r.version),
                }
            }))),
            _ => None,
        };
        let opts = ClientOptions { routes: ways, protect: p.protect(), dns, reconnect: None, on_connected: None, update: updater.clone() };
        let tun_out = p.writer();
        let tun_in = p.take_reader();
        let st = status.clone();
        let cfg2 = cfg.clone();
        let task = tokio::spawn(client::run(cfg2, opts, tun_in, tun_out, st, stop_rx));
        println!("Beenden mit Strg+C (oder Fenster schliessen).\n");

        let st = status.clone();
        let show = tokio::spawn(async move {
            let (mut lrx, mut ltx) = (0u64, 0u64);
            let mut last_state = String::new();
            let mut last_err = String::new();
            let mut upd_shown = String::new();
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if let Some(u) = &updater {
                    let us = u.status();
                    if !us.version.is_empty() && us.version != upd_shown && !us.done {
                        println!("\rNeue Version {} verfuegbar – wird im Hintergrund geladen ({} KB)          ", us.version, us.size / 1024);
                        upd_shown = us.version.clone();
                    }
                }
                let rx = st.rx_bytes.load(Relaxed);
                let tx = st.tx_bytes.load(Relaxed);
                let state = st.state_name();
                let info = st.info.lock().unwrap().clone();
                if state != last_state {
                    if state == "connected" {
                        let tls = if info.tls_trusted {
                            "TLS ok".to_string()
                        } else {
                            format!("TLS-Inspektion erkannt ({}) – Daten bleiben verschluesselt", info.tls_issuer)
                        };
                        println!("\rVerbunden mit {}{} – {}                    ", info.server, if info.via_proxy { " ueber Proxy" } else { "" }, tls);
                    } else if state == "connecting" && last_state == "connected" {
                        println!("\rVerbindung unterbrochen – verbinde neu ...                              ");
                    }
                    last_state = state.to_string();
                }
                if !info.last_error.is_empty() && info.last_error != last_err && state != "connected" {
                    println!("\r{}                                        ", info.last_error);
                }
                last_err = info.last_error.clone();
                if state == "connected" {
                    print!(
                        "\r  Download {:>13}  Upload {:>13}  Ping {:>5.0} ms  gesamt {} / {}      ",
                        human_rate(rx.saturating_sub(lrx) as f64),
                        human_rate(tx.saturating_sub(ltx) as f64),
                        st.rtt_us.load(Relaxed) as f64 / 1000.0,
                        human_bytes(rx),
                        human_bytes(tx)
                    );
                    let _ = std::io::stdout().flush();
                }
                lrx = rx;
                ltx = tx;
            }
        });

        let update = tokio::select! {
            _ = plat::wait_for_exit() => None,
            f = upd_rx.recv() => f,
        };
        println!("\nTrenne ...");
        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
        show.abort();
        p.cleanup();
        println!("Getrennt.");
        if let Some(f) = update {
            if let Err(e) = apply_update(&f) {
                println!("Update konnte nicht eingespielt werden: {e} – bitte Programm neu starten");
                pause_and_exit(1);
            }
        }
    });
}
