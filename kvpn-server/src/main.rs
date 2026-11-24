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

mod admin;
mod config;
mod geo;
mod netsetup;
mod server;
mod stats;
mod updates;
mod users;
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
        "KroneVPN Server {}\n\n  kvpn-server init --url wss://HOST/api/v1/stream\n  kvpn-server add <name> [--benutzer <name>] [--ablauf <datum|tage>]\n  kvpn-server remove <name>\n  kvpn-server list\n  kvpn-server benutzer [add|remove|sperren|entsperren|max] ...   Benutzerverwaltung (SQLite)\n  kvpn-server sperren|entsperren <geraet>   kvpn-server ablauf <geraet> <datum|tage|nie>\n  kvpn-server zuordnen <geraet> <benutzer>  kvpn-server verlauf [geraet]\n  kvpn-server einstellungen [--benutzer an|aus] [--aes256 an|aus] [--leistung an|aus] [--admin-vpn an|aus] [--standort an|aus] [--max N]\n  kvpn-server admin-passwort [<neu> | --loeschen]   Admin-Seite im VPN (http://10.77.0.1:8180)\n  kvpn-server status                    Geraete mit App-Version und Update-Stand\n  kvpn-server standort <ip>             ungefaehrer Ort einer IP-Adresse (ipwho.is)\n  kvpn-server code <name>               Code + QR-Code erneut anzeigen\n  kvpn-server import <code>             Code eines Geraets merken (fuer 'code')\n  kvpn-server update [--ja]             neue App-Version von GitHub an die Geraete verteilen\n  kvpn-server password <passwort>\n  kvpn-server set <schluessel> <wert>   (z. B. vpn_name \"Potzplitz VPN\")\n  kvpn-server logo <bild.png>           eigenes Bild fuer die Webseiten\n  kvpn-server run\n\n  Optionen: --config <datei> (Standard {DEFAULT_CONFIG})",
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
        "add" => cmd_add(&cfg_path, &args[1..]),
        "benutzer" | "users" | "user" => cmd_users(&cfg_path, &args[1..]),
        "sperren" | "disable" => cmd_device_flag(&cfg_path, &args[1..].join(" "), true),
        "entsperren" | "enable" => cmd_device_flag(&cfg_path, &args[1..].join(" "), false),
        "ablauf" | "expire" => cmd_expire(&cfg_path, &args[1..]),
        "zuordnen" | "assign" => cmd_assign(&cfg_path, &args[1..]),
        "verlauf" | "log" | "events" => cmd_events(&cfg_path, &args[1..]),
        "einstellungen" | "settings" => cmd_settings(&cfg_path, &args[1..]),
        "standort" | "geo" => match args.get(1) {
            Some(ip) => match geo::lookup_now(ip) {
                Ok(g) => println!("{ip}: {}", geo::describe(&g)),
                Err(e) => die(e),
            },
            None => die("Aufruf: kvpn-server standort <ip-adresse>"),
        },
        "admin-passwort" | "admin-password" => cmd_admin_pw(&cfg_path, &args[1..]),
        "status" => cmd_status(&cfg_path),
        "remove" | "rm" => cmd_remove(&cfg_path, &args[1..].join(" ")),
        "list" | "ls" => cmd_list(&cfg_path),
        "code" | "codes" | "show" | "zeigen" => cmd_code(&cfg_path, &args[1..].join(" ")),
        "import" => cmd_import(&cfg_path, &args[1..].join(" ")),
        "update" | "updates" => cmd_update(&cfg_path, &args[1..]),
        "update-keygen" => cmd_update_keygen(&args[1..]),
        "update-sign" => cmd_update_sign(&args[1..]),
        "password" => cmd_password(&cfg_path, &args[1..].join(" ")),
        "set" => cmd_set(&cfg_path, &args[1..]),
        "max" | "max-geraete" | "max_devices" => cmd_max(&cfg_path, args.get(1).map(|s| s.as_str())),
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

/// --schalter <wert> aus der Argumentliste holen
fn take_opt(args: &mut Vec<String>, names: &[&str]) -> Option<String> {
    let i = args.iter().position(|a| names.contains(&a.as_str()))?;
    if i + 1 >= args.len() {
        die(format!("{} braucht einen Wert", args[i]));
    }
    let v = args.remove(i + 1);
    args.remove(i);
    Some(v)
}

fn cmd_add(path: &str, args: &[String]) {
    let mut args = args.to_vec();
    let user = take_opt(&mut args, &["--benutzer", "--user", "-b"]).unwrap_or_default();
    let expiry = take_opt(&mut args, &["--ablauf", "--expires", "--bis"]).map(|x| users::parse_expiry(&x).unwrap_or_else(|e| die(e)));
    let name = args.join(" ");
    let name = name.trim();
    if name.is_empty() || name.len() > 40 || name.contains(['"', '\n']) {
        die("Name fehlt oder ungueltig (hoechstens 40 Zeichen)");
    }
    let mut cfg = Config::load(path).unwrap_or_else(|e| die(e));
    if (!user.is_empty() || expiry.is_some()) && !cfg.users {
        die("--benutzer/--ablauf gehen nur mit Benutzerverwaltung (einschalten: kvpn-server einstellungen --benutzer an)");
    }
    if cfg.peers.iter().chain(&cfg.inactive).any(|p| p.name.eq_ignore_ascii_case(name)) {
        die(format!("'{name}' gibt es schon – neuer Code: erst 'kvpn-server remove \"{name}\"', dann wieder add"));
    }
    let Some(index) = cfg.free_index() else {
        die(format!("alle {} Plaetze belegt – erst ein Geraet entfernen oder mehr erlauben: kvpn-server max <anzahl>", cfg.max_devices))
    };
    let (cpriv, cpub) = kvpn::crypto::generate_keypair();
    let peer = Peer { name: name.to_string(), public_key: kvpn::code::key_to_b64(&cpub), index, user: user.trim().to_string() };
    let code = cfg.client_config(&peer, &cpriv).to_code();
    cfg.peers.push(peer.clone());
    cfg.check().unwrap_or_else(|e| die(e));
    if let Err(e) = config::store_key(path, &peer, &cpriv) {
        eprintln!("Hinweis: Code konnte nicht gespeichert werden ({e}) – 'kvpn-server code' geht dann fuer dieses Geraet nicht");
    }
    if cfg.users {
        let db = users::open(path).unwrap_or_else(|e| die(e));
        users::add_device(&db, &peer).unwrap_or_else(|e| {
            config::remove_key(path, &peer);
            die(e)
        });
        if let Some(t) = expiry {
            users::set_expires(&db, &peer.name, t).unwrap_or_else(|e| die(e));
            println!("Gueltig bis {}", users::date(t));
        }
    } else {
        cfg.save(path).unwrap_or_else(|e| die(e));
    }
    println!("{}", qr(&code));
    println!("{}: Geraet '{name}' angelegt (Adresse {}, Platz {} von {}){}.", cfg.display_name(), cfg.ip4(index), cfg.device_count(), cfg.max_devices, if peer.user.is_empty() { String::new() } else { format!(", Benutzer '{}'", peer.user) });
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

/// hoechste Anzahl Geraete anzeigen bzw. setzen
fn cmd_max(path: &str, val: Option<&str>) {
    let mut cfg = Config::load(path).unwrap_or_else(|e| die(e));
    let cap = cfg.capacity().unwrap_or(0);
    match val {
        None => println!("Hoechstens {} Geraete erlaubt ({} angelegt, moeglich bis {cap}). Aendern: kvpn-server max <anzahl>", cfg.max_devices, cfg.peers.len()),
        Some(v) => {
            cfg.set("max_devices", v).unwrap_or_else(|e| die(e));
            cfg.save(path).unwrap_or_else(|e| die(e));
            println!("Jetzt hoechstens {} Geraete erlaubt ({} angelegt). Gilt sofort, ohne Neustart.", cfg.max_devices, cfg.peers.len());
        }
    }
}

fn cmd_remove(path: &str, name: &str) {
    let mut cfg = Config::load(path).unwrap_or_else(|e| die(e));
    let Some(peer) = find_peer(&cfg, name) else { die(format!("kein Geraet '{name}'")) };
    if cfg.users {
        users::remove_device(&users::open(path).unwrap_or_else(|e| die(e)), &peer.name).unwrap_or_else(|e| die(e));
    } else {
        cfg.peers.retain(|p| p != &peer);
        cfg.save(path).unwrap_or_else(|e| die(e));
    }
    config::remove_key(path, &peer);
    println!("'{name}' entfernt – sein Verbindungscode funktioniert nicht mehr.");
}

fn cmd_list(path: &str) {
    let cfg = Config::load(path).unwrap_or_else(|e| die(e));
    println!("Server: {}   ({} von {} Plaetzen belegt – aendern: kvpn-server max <anzahl>)", cfg.public_url, cfg.device_count(), cfg.max_devices);
    let mut missing = 0;
    if cfg.users {
        let db = users::open(path).unwrap_or_else(|e| die(e));
        let list = users::devices(&db).unwrap_or_else(|e| die(e));
        println!("  {:<24} {:<14} {:<12} {:<22} Code", "Geraet", "Benutzer", "Adresse", "Status");
        for d in &list {
            let has = config::stored_code(path, &cfg, &d.peer).is_some();
            missing += (!has) as usize;
            println!(
                "  {:<24} {:<14} {:<12} {:<22} {}",
                d.peer.name,
                if d.peer.user.is_empty() { "–" } else { &d.peer.user },
                cfg.ip4(d.peer.index).to_string(),
                d.status(),
                if has { "kvpn-server code \"…\"" } else { "nur auf dem Geraet" }
            );
        }
        println!("\nBenutzer: kvpn-server benutzer   ·   sperren/entsperren/ablauf/zuordnen <geraet> …   ·   Verlauf: kvpn-server verlauf");
    } else {
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
    }
    if missing > 0 {
        println!("\nCode wieder anzeigen geht fuer Geraete, die vor Version 1.0.1 angelegt wurden, nur vom Geraet aus:");
        println!("  Android-App: \"Code anzeigen\" · Windows: KroneVPN.exe --code · danach hier: kvpn-server import '<code>'");
    }
}

fn find_peer(cfg: &Config, name: &str) -> Option<Peer> {
    let n = name.trim().trim_matches('"');
    cfg.peers.iter().chain(&cfg.inactive).find(|p| p.name.eq_ignore_ascii_case(n)).cloned()
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
    let Some(p) = cfg.peers.iter().chain(&cfg.inactive).find(|p| p.public_key == pubk) else {
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
    if matches!(args[0].as_str(), "users" | "benutzer" | "benutzerverwaltung") {
        switch_users(path, config::on_off(&args[1]).unwrap_or_else(|e| die(e)));
        return;
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
    // Leistungsmodus: eine TUN-Warteschlange je Kern und mehr Threads; sonst sparsam (1 Warteschlange, 2 Threads)
    let queues = match (cfg.queues, cfg.performance) {
        (0, true) => cores.min(8),
        (0, false) => 1,
        (q, _) => q.min(8),
    }
    .max(1);
    let threads = if cfg.performance { cores.clamp(2, 8) } else { 2 };
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(threads).enable_all().build().unwrap();
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
            "KroneVPN Server {} laeuft: {} ({}), {} Geraet(e), {} TUN-Queues, {} Kerne, Leistungsmodus {}, Verschluesselung {}, Benutzerverwaltung {} – Clients: {}",
            kvpn::VERSION,
            cfg.listen,
            if tls.is_some() { "TLS selbst" } else { "hinter nginx" },
            cfg.peers.len(),
            queues,
            cores,
            if cfg.performance { "an" } else { "aus" },
            if cfg.aes256 { "AES-256-GCM" } else { "ChaCha20-Poly1305" },
            if cfg.users { "an (SQLite)" } else { "aus" },
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
        // Admin-Seite im VPN (nur fuer verbundene Geraete, mit Passwort)
        if let Some(addr) = cfg.admin_addr() {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => {
                    log!(
                        "Admin-Seite im VPN: http://{addr}/  ({})",
                        if cfg.admin_password.is_empty() { "Passwort wird beim ersten Aufruf festgelegt" } else { "mit Passwort" }
                    );
                    let sha = sh.clone();
                    tokio::spawn(async move {
                        loop {
                            let Ok((sock, peer)) = l.accept().await else {
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                continue;
                            };
                            tokio::spawn(server::handle_admin(sha.clone(), sock, peer));
                        }
                    });
                }
                Err(e) => log!("Hinweis: Admin-Seite im VPN ({addr}) nicht moeglich: {e}"),
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

// ------------------------------------------------------------------------------------------------ Benutzerverwaltung

fn db_or_die(path: &str) -> (Config, rusqlite::Connection) {
    let cfg = Config::load(path).unwrap_or_else(|e| die(e));
    if !cfg.users {
        die("Die Benutzerverwaltung ist aus – einschalten: kvpn-server einstellungen --benutzer an");
    }
    let db = users::open(path).unwrap_or_else(|e| die(e));
    (cfg, db)
}

/// Benutzerverwaltung ein-/ausschalten (Geraete wandern zwischen server.toml und benutzer.db)
fn switch_users(path: &str, on: bool) -> bool {
    match users::switch(path, on).unwrap_or_else(|e| die(e)) {
        Some(m) => {
            println!("{m}");
            true
        }
        None => false,
    }
}

fn cmd_users(path: &str, args: &[String]) {
    let sub = args.first().map(|s| s.to_lowercase()).unwrap_or_default();
    let rest = args.get(1..).unwrap_or(&[]).to_vec();
    let (_cfg, db) = db_or_die(path);
    match sub.as_str() {
        "" | "list" | "liste" | "ls" => {
            let list = users::users(&db).unwrap_or_else(|e| die(e));
            if list.is_empty() {
                println!("Noch keine Benutzer. Anlegen: kvpn-server benutzer add \"Anna\"   ·   Geraet dazu: kvpn-server add \"Annas Handy\" --benutzer Anna");
            }
            for u in &list {
                println!(
                    "  {:<20} {:<10} seit {}  {} Geraet(e){}{}  {}",
                    u.name,
                    if u.disabled { "GESPERRT" } else { "aktiv" },
                    users::date(u.created),
                    u.devices.len(),
                    if u.max_devices > 0 { format!(" (max. {})", u.max_devices) } else { String::new() },
                    if u.devices.is_empty() { String::new() } else { format!(": {}", u.devices.join(", ")) },
                    if u.note.is_empty() { String::new() } else { format!("– {}", u.note) }
                );
            }
            let free: Vec<String> = users::devices(&db).unwrap_or_default().into_iter().filter(|d| d.peer.user.is_empty()).map(|d| d.peer.name).collect();
            if !free.is_empty() {
                println!("  ohne Benutzer: {}", free.join(", "));
            }
        }
        "add" | "neu" | "anlegen" => {
            let mut rest = rest;
            let note = take_opt(&mut rest, &["--notiz", "--note"]).unwrap_or_default();
            let name = rest.join(" ");
            users::add_user(&db, &name, &note).unwrap_or_else(|e| die(e));
            println!("Benutzer '{}' angelegt. Geraet dazu: kvpn-server add \"<geraet>\" --benutzer \"{}\"", name.trim(), name.trim());
        }
        "remove" | "rm" | "loeschen" | "entfernen" => {
            let mut rest = rest;
            let all = rest.iter().any(|a| a == "--mit-geraeten" || a == "--with-devices");
            rest.retain(|a| a != "--mit-geraeten" && a != "--with-devices");
            let name = rest.join(" ");
            match users::remove_user(&db, &name, all).unwrap_or_else(|e| die(e)) {
                None => die(format!("kein Benutzer '{name}'")),
                Some(gone) => {
                    for p in &gone {
                        config::remove_key(path, p);
                    }
                    println!(
                        "Benutzer '{}' entfernt{}",
                        name.trim(),
                        if all { format!(" mit {} Geraet(en) – deren Codes gehen nicht mehr", gone.len()) } else { " – seine Geraete bleiben (ohne Benutzer)".into() }
                    );
                }
            }
        }
        "sperren" | "disable" | "entsperren" | "enable" => {
            let off = matches!(sub.as_str(), "sperren" | "disable");
            let name = rest.join(" ");
            if !users::set_user_disabled(&db, &name, off).unwrap_or_else(|e| die(e)) {
                die(format!("kein Benutzer '{name}'"));
            }
            println!("Benutzer '{}' {}", name.trim(), if off { "gesperrt – alle seine Geraete sind sofort getrennt" } else { "entsperrt" });
        }
        "max" => {
            let (Some(n), true) = (rest.last().and_then(|x| x.parse::<i64>().ok()), rest.len() >= 2) else {
                die("Aufruf: kvpn-server benutzer max \"<name>\" <anzahl>   (0 = keine Grenze)")
            };
            let name = rest[..rest.len() - 1].join(" ");
            if !users::set_user_max(&db, &name, n).unwrap_or_else(|e| die(e)) {
                die(format!("kein Benutzer '{name}'"));
            }
            println!("Benutzer '{}': {}", name.trim(), if n > 0 { format!("hoechstens {n} Geraete") } else { "keine Grenze".into() });
        }
        _ => die("Aufruf: kvpn-server benutzer [list | add <name> [--notiz …] | remove <name> [--mit-geraeten] | sperren <name> | entsperren <name> | max <name> <anzahl>]"),
    }
}

fn cmd_device_flag(path: &str, name: &str, off: bool) {
    let (_cfg, db) = db_or_die(path);
    if !users::set_disabled(&db, name, off).unwrap_or_else(|e| die(e)) {
        die(format!("kein Geraet '{}' (siehe kvpn-server list)", name.trim()));
    }
    println!("'{}' {}", name.trim(), if off { "gesperrt – sofort getrennt, der Code geht erst nach 'entsperren' wieder" } else { "entsperrt – der Code geht wieder" });
}

fn cmd_expire(path: &str, args: &[String]) {
    if args.len() < 2 {
        die("Aufruf: kvpn-server ablauf \"<geraet>\" <2026-12-31 | 31.12.2026 | 30 (Tage) | nie>");
    }
    let (_cfg, db) = db_or_die(path);
    let t = users::parse_expiry(&args[args.len() - 1]).unwrap_or_else(|e| die(e));
    let name = args[..args.len() - 1].join(" ");
    if !users::set_expires(&db, &name, t).unwrap_or_else(|e| die(e)) {
        die(format!("kein Geraet '{}'", name.trim()));
    }
    println!("'{}': {}", name.trim(), if t == 0 { "kein Ablaufdatum".to_string() } else { format!("gueltig bis {}", users::date(t)) });
}

fn cmd_assign(path: &str, args: &[String]) {
    if args.len() < 2 {
        die("Aufruf: kvpn-server zuordnen \"<geraet>\" \"<benutzer>\"   (Benutzer '-' = keinem zuordnen)");
    }
    let (_cfg, db) = db_or_die(path);
    let user = if args[1] == "-" { "" } else { args[1].as_str() };
    if !users::assign(&db, &args[0], user).unwrap_or_else(|e| die(e)) {
        die(format!("kein Geraet '{}'", args[0]));
    }
    println!("'{}' gehoert jetzt {}", args[0], if user.is_empty() { "keinem Benutzer".to_string() } else { format!("'{user}'") });
}

fn cmd_events(path: &str, args: &[String]) {
    let (_cfg, db) = db_or_die(path);
    let mut args = args.to_vec();
    let n = take_opt(&mut args, &["--anzahl", "-n"]).and_then(|x| x.parse().ok()).unwrap_or(50);
    let dev = args.join(" ");
    let list = users::events(&db, n, (!dev.trim().is_empty()).then_some(dev.trim())).unwrap_or_else(|e| die(e));
    if list.is_empty() {
        println!("Noch nichts im Verlauf.");
    }
    for (ts, d, ev) in list {
        println!("  {} UTC  {:<24} {ev}", users::datetime(ts), d);
    }
}

// ------------------------------------------------------------------------------------------------ Einstellungen

fn ask(q: &str, cur: &str) -> String {
    print!("  {q} [{cur}]: ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let mut a = String::new();
    if std::io::stdin().read_line(&mut a).unwrap_or(0) == 0 {
        return String::new();
    }
    a.trim().to_string()
}

/// Einstellungen anzeigen und aendern: mit Schaltern direkt, sonst (im Terminal) Frage fuer Frage
fn cmd_settings(path: &str, args: &[String]) {
    let mut args = args.to_vec();
    let quiet = args.iter().any(|a| a == "--ja" || a == "-y" || a == "--nicht-fragen");
    args.retain(|a| a != "--ja" && a != "-y" && a != "--nicht-fragen");
    let mut want: Vec<(&str, String)> = Vec::new();
    for (keys, k) in [
        (&["--benutzer", "--benutzerverwaltung", "--users"][..], "users"),
        (&["--aes256", "--aes"][..], "aes256"),
        (&["--leistung", "--leistungsmodus", "--performance"][..], "performance"),
        (&["--admin-vpn", "--admin"][..], "admin_vpn"),
        (&["--standort", "--geo"][..], "geo"),
        (&["--max", "--max-geraete"][..], "max_devices"),
    ] {
        if let Some(v) = take_opt(&mut args, keys) {
            want.push((k, v));
        }
    }
    if let Some(x) = args.first() {
        die(format!("unbekannt: {x} – Aufruf: kvpn-server einstellungen [--benutzer an|aus] [--aes256 an|aus] [--leistung an|aus] [--max N]"));
    }
    let cfg = Config::load(path).unwrap_or_else(|e| die(e));
    let onoff = |b: bool| if b { "an" } else { "aus" };
    let interactive = want.is_empty() && !quiet && std::io::IsTerminal::is_terminal(&std::io::stdin());
    if interactive {
        println!("{} – Einstellungen (Enter = so lassen, sonst an/aus bzw. Zahl):", cfg.display_name());
        for (k, q, cur) in [
            ("users", "Benutzerverwaltung (SQLite: Benutzer, sperren, Ablaufdatum, Verlauf)", onoff(cfg.users).to_string()),
            ("aes256", "AES-256-GCM statt ChaCha20 fuer die Daten (Apps ab 1.0.6)", onoff(cfg.aes256).to_string()),
            ("performance", "Leistungsmodus (alle CPU-Kerne, mehr Durchsatz, mehr Last)", onoff(cfg.performance).to_string()),
            (
                "admin_vpn",
                "Admin-Seite im VPN (http://<server-im-vpn>:8180, mit Passwort)",
                onoff(cfg.admin_vpn).to_string(),
            ),
            ("geo", "Standort der Geraete auf der Admin-Seite (ungefaehr aus der IP, Abfrage bei ipwho.is)", onoff(cfg.geo).to_string()),
            ("max_devices", "Hoechstzahl Geraete", cfg.max_devices.to_string()),
        ] {
            loop {
                let a = ask(q, &cur);
                if a.is_empty() {
                    break;
                }
                let ok = if k == "max_devices" { a.parse::<usize>().is_ok() } else { config::on_off(&a).is_ok() };
                if ok {
                    want.push((k, a));
                    break;
                }
                println!("    bitte {}", if k == "max_devices" { "eine Zahl" } else { "an oder aus" });
            }
        }
    }
    let mut restart = false;
    for (k, v) in &want {
        if *k == "users" {
            switch_users(path, config::on_off(v).unwrap_or_else(|e| die(e)));
            continue;
        }
        let mut c = Config::load(path).unwrap_or_else(|e| die(e));
        let before = (c.performance, c.admin_vpn);
        c.set(k, v).unwrap_or_else(|e| die(e));
        c.save(path).unwrap_or_else(|e| die(e));
        restart |= (c.performance, c.admin_vpn) != before;
    }
    let c = Config::load(path).unwrap_or_else(|e| die(e));
    println!(
        "Einstellungen: Benutzerverwaltung {} · AES-256 {} · Leistungsmodus {} · Admin-Seite im VPN {} · Standort {} · hoechstens {} Geraete ({} angelegt)",
        onoff(c.users),
        onoff(c.aes256),
        onoff(c.performance),
        c.admin_addr().map(|a| format!("http://{a}")).unwrap_or_else(|| "aus".into()),
        onoff(c.geo),
        c.max_devices,
        c.device_count()
    );
    if restart {
        println!("Leistungsmodus/Admin-Seite gelten nach einem Neustart des Servers: systemctl restart krone-vpn   (Docker: docker restart krone-vpn)");
    }
}

// ------------------------------------------------------------------------------------------------ Admin-Seite, Status

fn cmd_admin_pw(path: &str, args: &[String]) {
    let mut cfg = Config::load(path).unwrap_or_else(|e| die(e));
    let addr = cfg.admin_addr().map(|a| format!("http://{a}")).unwrap_or_else(|| "aus (einschalten: kvpn-server einstellungen --admin-vpn an)".into());
    match args.first().map(|s| s.as_str()) {
        None => {
            println!("Admin-Seite im VPN: {addr}");
            println!("Passwort: {}", if cfg.admin_password.is_empty() { "noch keins – wird beim ersten Aufruf im VPN festgelegt" } else { "festgelegt" });
            println!("Neu setzen: kvpn-server admin-passwort '<neues>'   ·   vergessen: kvpn-server admin-passwort --loeschen");
        }
        Some("--loeschen") | Some("--delete") | Some("--reset") => {
            cfg.admin_password.clear();
            cfg.save(path).unwrap_or_else(|e| die(e));
            println!("Admin-Passwort geloescht – beim naechsten Aufruf von {addr} wird ein neues festgelegt. Alle Anmeldungen sind abgemeldet.");
        }
        Some(_) => {
            let pw = args.join(" ");
            admin::check_new(&pw).unwrap_or_else(|e| die(e));
            cfg.admin_password = admin::hash(&pw);
            cfg.save(path).unwrap_or_else(|e| die(e));
            println!("Admin-Passwort gesetzt ({addr}). Alle bisherigen Anmeldungen sind abgemeldet.");
        }
    }
}

/// Geraete mit App-Version und Update-Stand (fragt den laufenden Server ueber die lokale Seite)
fn cmd_status(path: &str) {
    let cfg = Config::load(path).unwrap_or_else(|e| die(e));
    let addr = cfg.local_listen.trim().to_string();
    let get = || -> Result<serde_json::Value, String> {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect_timeout(&addr.parse().map_err(|e| format!("{addr}: {e}"))?, std::time::Duration::from_secs(3)).map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
        write!(s, "GET /data.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").map_err(|e| e.to_string())?;
        let mut b = Vec::new();
        s.read_to_end(&mut b).map_err(|e| e.to_string())?;
        let t = String::from_utf8_lossy(&b);
        let body = t.split_once("\r\n\r\n").map(|x| x.1).unwrap_or("");
        serde_json::from_str(body).map_err(|e| e.to_string())
    };
    let d = get().unwrap_or_else(|e| die(format!("Server laeuft nicht oder lokale Seite nicht erreichbar ({addr}): {e}")));
    let offered = d["update"]["offered"].as_str().unwrap_or("").to_string();
    let pending = d["update"]["pending"].as_str().unwrap_or("");
    println!("{} {} · App-Updates: verteilt {}{}", cfg.display_name(), d["server"]["version"].as_str().unwrap_or(""),
        if offered.is_empty() { "noch keine".to_string() } else { offered.clone() },
        if pending.is_empty() { String::new() } else { format!(" · auf GitHub wartet {pending} auf Freigabe (kvpn-server update)") });
    println!("  {:<24} {:<8} {:<10} {:<9} {}", "Geraet", "online", "System", "Version", "Update");
    for p in d["peers"].as_array().cloned().unwrap_or_default() {
        let i = &p["info"];
        let ver = i["ver"].as_str().unwrap_or("");
        let os = i["os"].as_str().unwrap_or("");
        let upd = if ver.is_empty() {
            "seit Server-Start nicht verbunden".to_string()
        } else if !i["upd_sent"].as_str().unwrap_or("").is_empty() {
            format!("{} uebertragen – wird installiert", i["upd_sent"].as_str().unwrap_or(""))
        } else if !offered.is_empty() && kvpn::update::newer(&offered, ver) && !i["upd"].as_bool().unwrap_or(false) {
            "kein Auto-Update (abgeschaltet oder App vor 1.0.1 – dann einmal von Hand installieren)".to_string()
        } else if !offered.is_empty() && kvpn::update::newer(&offered, ver) {
            format!("{offered} wird beim Verbinden angeboten")
        } else {
            "aktuell".to_string()
        };
        println!(
            "  {:<24} {:<8} {:<10} {:<9} {}",
            p["name"].as_str().unwrap_or(""),
            if p["online"].as_bool().unwrap_or(false) { "ja" } else { "nein" },
            os,
            ver,
            upd
        );
        if let Ok(g) = serde_json::from_value::<geo::Geo>(p["geo"].clone()) {
            if p["geo"].is_object() {
                println!("  {:<24} {}{} (von {})", "", if p["online"].as_bool().unwrap_or(false) { "Standort: " } else { "zuletzt: " }, geo::describe(&g), i["remote"].as_str().unwrap_or(""));
            }
        }
    }
}
