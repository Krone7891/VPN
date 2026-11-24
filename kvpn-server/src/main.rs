//! kvpn-server – KroneVPN Server
//!
//!   kvpn-server init --url wss://vpn.deine-domain.de/api/v1/stream   Konfiguration mit neuem Schluessel anlegen
//!   kvpn-server add <name>                                          Geraet anlegen, Verbindungscode + QR-Code ausgeben
//!   kvpn-server remove <name>                                       Geraet entfernen (wird sofort getrennt)
//!   kvpn-server list                                                Geraete anzeigen
//!   kvpn-server code <name>                                         Verbindungscode + QR-Code erneut anzeigen
//!   kvpn-server import <code>                                       Code eines Geraets uebernehmen (fuer 'code')
//!   kvpn-server update [--ja]                                       neue App-Version von GitHub freigeben und verteilen
//!   kvpn-server update-sign <schluessel.pk8> <dist>                 update.json fuer die Apps signieren (beim Bauen)
//!   kvpn-server password <passwort>                                 Passwort fuer die Statistik von aussen
//!   kvpn-server set <schluessel> <wert>                             einzelnen Wert setzen (z. B. vpn_name, listen)
//!   kvpn-server run                                                 Server starten (systemd: krone-vpn.service)
//!
//! Konfiguration: /etc/krone-vpn/server.toml (anderer Ort: --config <datei> oder KVPN_CONFIG)

mod config;
mod netsetup;
mod server;
mod stats;
mod updates;
mod web;

// statische Linux-Builds (musl): schneller Speicher-Allokator
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use config::{Config, Peer};
use std::sync::Arc;

#[macro_export]
macro_rules! log {
    ($($t:tt)*) => {{ eprintln!($($t)*); }};
}

const DEFAULT_CONFIG: &str = "/etc/krone-vpn/server.toml";

fn usage() -> ! {
    eprintln!(
        "KroneVPN Server {}\n\n  kvpn-server init --url wss://HOST/api/v1/stream\n  kvpn-server add <name>\n  kvpn-server remove <name>\n  kvpn-server list\n  kvpn-server code <name>               Code + QR-Code erneut anzeigen\n  kvpn-server import <code>             Code eines Geraets merken (fuer 'code')\n  kvpn-server update [--ja]             neue App-Version von GitHub an die Geraete verteilen\n  kvpn-server password <passwort>\n  kvpn-server set <schluessel> <wert>   (z. B. vpn_name \"Potzplitz VPN\")\n  kvpn-server logo <bild.png>           eigenes Bild fuer die Webseiten\n  kvpn-server run\n\n  Optionen: --config <datei> (Standard {DEFAULT_CONFIG})",
        kvpn::VERSION
    );
    std::process::exit(2)
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("Fehler: {msg}");
    std::process::exit(1)
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut cfg_path = std::env::var("KVPN_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());
    if let Some(i) = args.iter().position(|a| a == "--config") {
        if i + 1 >= args.len() {
            usage();
        }
        cfg_path = args.remove(i + 1);
        args.remove(i);
    }
    let cmd = args.first().cloned().unwrap_or_default();
    match cmd.as_str() {
        "init" => cmd_init(&cfg_path, &args[1..]),
        "add" => cmd_add(&cfg_path, &args[1..].join(" ")),
        "remove" | "rm" => cmd_remove(&cfg_path, &args[1..].join(" ")),
        "list" | "ls" => cmd_list(&cfg_path),
        "code" | "codes" | "show" | "zeigen" => cmd_code(&cfg_path, &args[1..].join(" ")),
        "import" => cmd_import(&cfg_path, &args[1..].join(" ")),
        "update" | "updates" => cmd_update(&cfg_path, &args[1..]),
        "update-keygen" => cmd_update_keygen(&args[1..]),
        "update-sign" => cmd_update_sign(&args[1..]),
        "password" => cmd_password(&cfg_path, &args[1..].join(" ")),
        "set" => cmd_set(&cfg_path, &args[1..]),
        "logo" | "bild" => cmd_logo(&cfg_path, &args[1..]),
        "run" => cmd_run(cfg_path),
        "version" | "--version" => println!("{}", kvpn::VERSION),
        _ => usage(),
    }
}

fn cmd_init(path: &str, args: &[String]) {
    if std::path::Path::new(path).exists() {
        die(format!("{path} gibt es schon (zum Neuanlegen erst loeschen – dann sind alle Verbindungscodes ungueltig)"));
    }
    let url = match args.iter().position(|a| a == "--url") {
        Some(i) => args.get(i + 1).cloned().unwrap_or_else(|| usage()),
        None => die(format!("Adresse fehlt: kvpn-server init --url wss://<deine-domain-oder-ip>{}", kvpn::proto::DEFAULT_PATH)),
    };
    let (k, _) = kvpn::crypto::generate_keypair();
    let cfg = Config::new(url, kvpn::code::key_to_b64(&k));
    cfg.check().unwrap_or_else(|e| die(e));
    cfg.save(path).unwrap_or_else(|e| die(e));
    println!("Angelegt: {path}\nServer-Adresse fuer Clients: {}\nJetzt Geraete anlegen: kvpn-server add \"Galaxy S26 Ultra\"", cfg.public_url);
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

fn cmd_add(path: &str, name: &str) {
    let name = name.trim();
    if name.is_empty() || name.len() > 40 || name.contains(['"', '\n']) {
        die("Name fehlt oder ungueltig (hoechstens 40 Zeichen)");
    }
    let mut cfg = Config::load(path).unwrap_or_else(|e| die(e));
    if cfg.peers.iter().any(|p| p.name.eq_ignore_ascii_case(name)) {
        die(format!("'{name}' gibt es schon – neuer Code: erst 'kvpn-server remove \"{name}\"', dann wieder add"));
    }
    let Some(index) = cfg.free_index() else {
        die(format!("alle {} Plaetze belegt – erst ein Geraet entfernen", kvpn::proto::MAX_PEERS))
    };
    let (cpriv, cpub) = kvpn::crypto::generate_keypair();
    let peer = Peer { name: name.to_string(), public_key: kvpn::code::key_to_b64(&cpub), index };
    let code = cfg.client_config(&peer, &cpriv).to_code();
    cfg.peers.push(peer.clone());
    cfg.check().unwrap_or_else(|e| die(e));
    if let Err(e) = config::store_key(path, &peer, &cpriv) {
        eprintln!("Hinweis: Code konnte nicht gespeichert werden ({e}) – 'kvpn-server code' geht dann fuer dieses Geraet nicht");
    }
    cfg.save(path).unwrap_or_else(|e| die(e));
    println!("{}", qr(&code));
    println!("{}: Geraet '{name}' angelegt (Adresse {}, Platz {} von {}).", cfg.display_name(), cfg.ip4(index), cfg.peers.len(), kvpn::proto::MAX_PEERS);
    println!("\nVerbindungscode (geheim halten – wer ihn hat, kann sich verbinden):\n\n{code}\n");
    if !cfg.downloads_dir.is_empty() {
        if let Ok(t) = kvpn::transport::parse_url(&cfg.public_url) {
            let host = if t.host.contains(':') { format!("[{}]", t.host) } else { t.host.clone() };
            let port = if (t.tls && t.port == 443) || (!t.tls && t.port == 80) { String::new() } else { format!(":{}", t.port) };
            println!("Apps zum Herunterladen: {}://{host}{port}/download/", if t.tls { "https" } else { "http" });
        }
    }
    println!("Handy: QR-Code mit der Kamera scannen oder Code in der App einfuegen. PC: App starten und Code einfuegen.");
    println!("Der laufende Server uebernimmt das Geraet automatisch (ohne Neustart).");
}

fn cmd_remove(path: &str, name: &str) {
    let mut cfg = Config::load(path).unwrap_or_else(|e| die(e));
    let Some(peer) = find_peer(&cfg, name) else { die(format!("kein Geraet '{name}'")) };
    cfg.peers.retain(|p| p != &peer);
    cfg.save(path).unwrap_or_else(|e| die(e));
    config::remove_key(path, &peer);
    println!("'{name}' entfernt – sein Verbindungscode funktioniert nicht mehr.");
}

fn cmd_list(path: &str) {
    let cfg = Config::load(path).unwrap_or_else(|e| die(e));
    println!("Server: {}   ({} von {} Plaetzen belegt)", cfg.public_url, cfg.peers.len(), kvpn::proto::MAX_PEERS);
    let mut missing = 0;
    for p in &cfg.peers {
        let has = config::stored_code(path, &cfg, p).is_some();
        missing += (!has) as usize;
        println!(
            "  {:<28} {:<12} {:<16} {}",
            p.name,
            cfg.ip4(p.index),
            cfg.ip6(p.index).map(|a| a.to_string()).unwrap_or_default(),
            if has { "Code: kvpn-server code \"…\"" } else { "Code nur auf dem Geraet" }
        );
    }
    if missing > 0 {
        println!("\nCode wieder anzeigen geht fuer Geraete, die vor Version 1.0.1 angelegt wurden, nur vom Geraet aus:");
        println!("  Android-App: \"Code anzeigen\" · Windows: KroneVPN.exe --code · danach hier: kvpn-server import '<code>'");
    }
}

fn find_peer(cfg: &Config, name: &str) -> Option<Peer> {
    let n = name.trim().trim_matches('"');
    cfg.peers.iter().find(|p| p.name.eq_ignore_ascii_case(n)).cloned()
}

fn cmd_code(path: &str, name: &str) {
    let cfg = Config::load(path).unwrap_or_else(|e| die(e));
    if name.trim().is_empty() {
        println!("Aufruf: kvpn-server code \"<name>\"\n");
        cmd_list(path);
        return;
    }
    let Some(p) = find_peer(&cfg, name) else { die(format!("kein Geraet '{name}' (siehe kvpn-server list)")) };
    match config::stored_code(path, &cfg, &p) {
        Some(code) => {
            println!("{}", qr(&code));
            println!("{}: Verbindungscode fuer '{}' (geheim halten):\n\n{code}\n", cfg.display_name(), p.name);
        }
        None => die(format!(
            "fuer '{}' ist kein Code gespeichert (vor Version 1.0.1 angelegt).\n\
             Den Code gibt es noch auf dem Geraet: Android-App \"Code anzeigen\", Windows: KroneVPN.exe --code\n\
             Dann hier merken: kvpn-server import '<code>'   – oder neu anlegen: remove + add",
            p.name
        )),
    }
}

fn cmd_import(path: &str, code: &str) {
    let cfg = Config::load(path).unwrap_or_else(|e| die(e));
    let c = kvpn::code::ClientConfig::from_code(code.trim()).unwrap_or_else(|e| die(e));
    let k = c.client_key().unwrap_or_else(|e| die(e));
    let pubk = kvpn::code::key_to_b64(&kvpn::crypto::public_from_private(&k));
    let Some(p) = cfg.peers.iter().find(|p| p.public_key == pubk) else {
        die("dieser Code gehoert zu keinem Geraet dieses Servers (entfernt oder anderer Server)")
    };
    config::store_key(path, p, &k).unwrap_or_else(|e| die(e));
    println!("Code fuer '{}' gemerkt – anzeigen mit: kvpn-server code \"{}\"", p.name, p.name);
}

/// App-Update von GitHub freigeben: erst zeigen, dann (nach Bestaetigung) laden, pruefen und verteilen
fn cmd_update(path: &str, args: &[String]) {
    let cfg = Config::load(path).unwrap_or_else(|e| die(e));
    let yes = args.iter().any(|a| a == "--ja" || a == "-y" || a == "--yes");
    let off = updates::offered(&cfg).map(|m| m.version);
    println!("{}: Apps fuer die Geraete kommen von GitHub ({}, Zweig {})", cfg.display_name(), cfg.update_repo, cfg.update_branch);
    println!("  an die Geraete verteilt: {}", off.clone().unwrap_or_else(|| "noch keine".into()));
    let found = match updates::check(&cfg) {
        Ok(f) => f,
        Err(e) => die(e),
    };
    let Some((m, text, sig)) = found else {
        println!("  auf GitHub: nichts Neueres – alles aktuell.");
        return;
    };
    updates::remember(&cfg, &text, &sig);
    let files: Vec<String> = m.files.iter().map(|(os, f)| format!("{os} {} KB", f.size / 1024)).collect();
    println!("  auf GitHub: Version {} ({}) – Signatur gueltig", m.version, files.join(", "));
    if !yes {
        print!("\nVersion {} jetzt an die Geraete verteilen? (j/n) ", m.version);
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut a = String::new();
        let _ = std::io::stdin().read_line(&mut a);
        if !a.trim().to_lowercase().starts_with(['j', 'y']) {
            println!("Nicht verteilt. Spaeter: kvpn-server update");
            return;
        }
    }
    match updates::approve(&cfg, &|m| println!("  {m}")) {
        Ok(v) => println!(
            "\nVersion {v} ist freigegeben. Verbundene Geraete (ab App-Version 1.0.1) bekommen sie in den naechsten Sekunden,\n\
             alle anderen beim naechsten Verbinden. Aeltere Apps (1.0.0) einmal von Hand aktualisieren."
        ),
        Err(e) => die(e),
    }
}

/// neuen Signier-Schluessel fuer Updates (nur beim Bauen noetig, gehoert NICHT auf den Server)
fn cmd_update_keygen(args: &[String]) {
    let (Some(k), Some(p)) = (args.first(), args.get(1)) else { die("Aufruf: kvpn-server update-keygen <schluessel.pk8> <update-key.pub>") };
    if std::path::Path::new(k).exists() {
        die(format!("{k} gibt es schon"));
    }
    let (pk8, pubhex) = kvpn::update::keygen().unwrap_or_else(|e| die(e));
    if let Some(d) = std::path::Path::new(k).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    std::fs::write(k, &pk8).unwrap_or_else(|e| die(format!("{k}: {e}")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(k, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::write(p, &pubhex).unwrap_or_else(|e| die(format!("{p}: {e}")));
    println!("Signier-Schluessel: {k} (geheim, sicher aufbewahren)\noeffentlicher Schluessel: {p} = {pubhex}");
}

/// update.json fuer die gebauten Apps in <dist> erzeugen und signieren
fn cmd_update_sign(args: &[String]) {
    let (Some(k), Some(dist)) = (args.first(), args.get(1)) else { die("Aufruf: kvpn-server update-sign <schluessel.pk8> <dist-ordner>") };
    let pk8 = std::fs::read(k).unwrap_or_else(|e| die(format!("{k}: {e}")));
    let mut files = std::collections::BTreeMap::new();
    for (os, name) in [("android", "KroneVPN.apk"), ("windows", "KroneVPN.exe"), ("linux", "kronevpn-linux")] {
        let f = std::path::Path::new(dist).join(name);
        if let Ok(data) = std::fs::read(&f) {
            files.insert(os.to_string(), kvpn::update::FileEntry { name: name.into(), size: data.len() as u64, sha256: kvpn::update::sha256_hex(&data) });
        }
    }
    if files.is_empty() {
        die(format!("keine Apps in {dist}"));
    }
    let version = std::env::var("KVPN_UPDATE_VERSION").unwrap_or_else(|_| kvpn::VERSION.to_string());
    let manifest = serde_json::to_string_pretty(&kvpn::update::Manifest { version, files }).unwrap();
    let (sig, pubhex) = kvpn::update::sign(&pk8, &manifest).unwrap_or_else(|e| die(e));
    if pubhex != kvpn::update::PUBLIC_KEY_HEX.trim() {
        die("Schluessel passt nicht zu kvpn/update-key.pub – die Apps wuerden das Update ablehnen (neu bauen?)");
    }
    kvpn::update::verify(&manifest, &sig).unwrap_or_else(|e| die(e));
    let d = std::path::Path::new(dist);
    std::fs::write(d.join("update.json"), &manifest).unwrap_or_else(|e| die(e));
    std::fs::write(d.join("update.json.sig"), &sig).unwrap_or_else(|e| die(e));
    println!("{}/update.json signiert", dist);
}

fn cmd_set(path: &str, args: &[String]) {
    if args.len() < 2 {
        die("Aufruf: kvpn-server set <schluessel> <wert>");
    }
    let mut cfg = Config::load(path).unwrap_or_else(|e| die(e));
    cfg.set(&args[0], &args[1..].join(" ")).unwrap_or_else(|e| die(e));
    cfg.save(path).unwrap_or_else(|e| die(e));
    println!("{} = {}", args[0], args[1..].join(" "));
}

fn cmd_logo(path: &str, args: &[String]) {
    let cfg = Config::load(path).unwrap_or_else(|e| die(e));
    match args.first().map(|s| s.as_str()) {
        Some("--entfernen") | Some("--remove") => {
            let d = std::path::Path::new(&cfg.state_dir);
            let _ = std::fs::remove_file(d.join("logo.bin"));
            let _ = std::fs::remove_file(d.join("logo.type"));
            println!("Bild entfernt");
        }
        Some(f) => {
            let data = std::fs::read(f).unwrap_or_else(|e| die(format!("{f}: {e}")));
            let t = web::logo_store(&cfg.state_dir, &data).unwrap_or_else(|e| die(e));
            println!("Bild gespeichert ({t}, {} KB) – erscheint auf Download- und Statistik-Seite", data.len() / 1024);
        }
        None => die("Aufruf: kvpn-server logo <bild.png|jpg|webp>   oder   kvpn-server logo --entfernen"),
    }
}

fn cmd_password(path: &str, pw: &str) {
    let mut cfg = Config::load(path).unwrap_or_else(|e| die(e));
    cfg.stats_password = pw.to_string();
    cfg.save(path).unwrap_or_else(|e| die(e));
    println!("{}", if pw.is_empty() { "Passwort entfernt – Statistik nur noch aus Heimnetz/VPN" } else { "Passwort gesetzt" });
}

fn cmd_run(cfg_path: String) {
    let cfg = Config::load(&cfg_path).unwrap_or_else(|e| die(e));
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let queues = if cfg.queues == 0 { cores.min(8) } else { cfg.queues.min(8) }.max(1);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(cores.clamp(2, 8)).enable_all().build().unwrap();
    rt.block_on(async move {
        let _ = std::fs::create_dir_all(&cfg.state_dir);
        // zuerst den Port belegen: ist er besetzt, wird gar nichts am Netz veraendert
        let listener = tokio::net::TcpListener::bind(&cfg.listen).await.unwrap_or_else(|e| {
            die(format!("{}: {e} – anderer Port: listen in /etc/krone-vpn/server.toml und nginx anpassen (install.sh macht das selbst)", cfg.listen))
        });
        // TUN mit mehreren Warteschlangen: jede wird von einer eigenen Task gelesen -> mehrere Kerne
        let mut tuns = Vec::new();
        for _ in 0..queues {
            let fd = kvpn::fdtun::open_linux_tun(&cfg.tun, queues > 1).unwrap_or_else(|e| die(format!("TUN {} anlegen: {e} (als root starten?)", cfg.tun)));
            tuns.push(Arc::new(kvpn::fdtun::FdTun::new(fd).unwrap_or_else(|e| die(e))));
        }
        netsetup::setup(&cfg);
        let sh = server::Shared::new(cfg_path.clone(), cfg.clone(), tuns);
        server::spawn_tun_readers(&sh);
        server::spawn_background(&sh);

        let tls = if !cfg.tls_cert.is_empty() {
            Some(load_tls(&cfg.tls_cert, &cfg.tls_key).unwrap_or_else(|e| die(e)))
        } else {
            None
        };
        log!(
            "KroneVPN Server {} laeuft: {} ({}), {} Geraet(e), {} TUN-Queues, {} Kerne – Clients: {}",
            kvpn::VERSION,
            cfg.listen,
            if tls.is_some() { "TLS selbst" } else { "hinter nginx" },
            cfg.peers.len(),
            queues,
            cores,
            cfg.public_url
        );
        // lokale Webseite: http://localhost:8180 (Statistik + Downloads, nur von diesem Rechner, ohne Passwort)
        if !cfg.local_listen.trim().is_empty() {
            match tokio::net::TcpListener::bind(&cfg.local_listen).await {
                Ok(l) => {
                    let ip_ok = l.local_addr().map(|a| a.ip().is_loopback()).unwrap_or(false);
                    if !ip_ok {
                        log!("Hinweis: local_listen {} ist keine localhost-Adresse – dort ist die Statistik OHNE Passwort sichtbar", cfg.local_listen);
                    }
                    let port = l.local_addr().map(|a| a.port()).unwrap_or(0);
                    log!("Lokale Webseite: http://localhost:{port}/  (Statistik)  und  http://localhost:{port}/download/");
                    let shl = sh.clone();
                    tokio::spawn(async move {
                        loop {
                            let Ok((sock, peer)) = l.accept().await else {
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                continue;
                            };
                            let sh = shl.clone();
                            tokio::spawn(server::handle_local(sh, sock, peer));
                        }
                    });
                }
                Err(e) => log!("Hinweis: lokale Webseite {} nicht moeglich ({e}) – anderen Port: kvpn-server set local_listen 127.0.0.1:<port>", cfg.local_listen),
            }
        }
        let sh2 = sh.clone();
        let accept = async move {
            loop {
                let (sock, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        log!("accept: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let _ = sock.set_nodelay(true);
                let sh = sh2.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    match tls {
                        Some(acc) => {
                            if let Ok(Ok(s)) = tokio::time::timeout(std::time::Duration::from_secs(15), acc.accept(sock)).await {
                                server::handle_conn(sh, s, peer).await;
                            }
                        }
                        None => server::handle_conn(sh, sock, peer).await,
                    }
                });
            }
        };
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = accept => {}
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        log!("beende ...");
        server::save_stats(&sh);
        netsetup::teardown(&sh.cfg());
    });
}

fn load_tls(cert: &str, key: &str) -> Result<tokio_rustls::TlsAcceptor, String> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert).map_err(|e| format!("{cert}: {e}"))?))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{cert}: {e}"))?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key).map_err(|e| format!("{key}: {e}"))?))
        .map_err(|e| format!("{key}: {e}"))?
        .ok_or_else(|| format!("{key}: kein Schluessel gefunden"))?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
}
