//! JNI-Schnittstelle fuer die Android-App (Klasse de.krone.vpn.Native).
//!
//! Java baut mit VpnService das TUN-Interface und reicht den Datei-Deskriptor hierher; alles weitere (TLS,
//! WebSocket, Noise, Pakete, Neuverbinden) macht der gemeinsame Rust-Kern – derselbe Code wie unter Windows/Linux.

#![cfg(unix)]

use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;
use kvpn::client::{self, ClientOptions, Status};
use kvpn::code::ClientConfig;
use kvpn::fdtun::{self, FdTun};
use kvpn::transport::parse_proxy;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::{mpsc, watch, Notify};

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(cores.clamp(2, 8))
            .thread_name("kronevpn")
            .enable_all()
            .build()
            .expect("tokio")
    })
}

struct Handle {
    stop: watch::Sender<bool>,
    status: Arc<Status>,
    kick: Arc<Notify>,
    updater: Arc<kvpn::update::Updater>,
    /// fertig geladene und gepruefte APK (Pfad, Version) – die App installiert sie
    update_file: Arc<Mutex<(String, String)>>,
    task: tokio::task::JoinHandle<()>,
    reader: tokio::task::JoinHandle<()>,
}

fn jstr(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(|s| s.into()).unwrap_or_default()
}

fn out(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// Code pruefen; liefert JSON mit den Einstellungen (fuer VpnService.Builder) oder {"error": "..."}
#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_parse<'l>(mut env: JNIEnv<'l>, _c: JClass<'l>, code: JString<'l>) -> jstring {
    let code = jstr(&mut env, &code);
    let j = match ClientConfig::from_code(&code) {
        Ok(c) => serde_json::json!({"name": c.name, "title": c.display_name(), "url": c.url, "ip4": c.ip4, "ip6": c.ip6, "dns": c.dns, "mtu": c.mtu, "proxy": c.proxy, "code": c.to_code()}),
        Err(e) => serde_json::json!({"error": e}),
    };
    out(&mut env, &j.to_string())
}

/// Tunnel starten. `fd` gehoert ab jetzt Rust (detachFd). Liefert Handle (0 = Fehler).
#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_start<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    fd: jint,
    code: JString<'l>,
    sys_proxy: JString<'l>,
    update_dir: JString<'l>,
) -> jlong {
    let code = jstr(&mut env, &code);
    let sys_proxy = jstr(&mut env, &sys_proxy);
    let update_dir = jstr(&mut env, &update_dir);
    let Ok(cfg) = ClientConfig::from_code(&code) else {
        unsafe { libc_close(fd) };
        return 0;
    };
    let rt = runtime();
    let _g = rt.enter();
    let tun = match unsafe { FdTun::from_raw(fd) } {
        Ok(t) => Arc::new(t),
        Err(_) => return 0,
    };
    // Wege: Proxy aus dem Code (fest) – sonst Systemproxy zuerst, dann direkt
    let ways = if !cfg.proxy.is_empty() {
        vec![parse_proxy(&cfg.proxy).ok().flatten()]
    } else {
        match parse_proxy(&sys_proxy).ok().flatten() {
            Some(p) => vec![Some(p), None],
            None => vec![None],
        }
    };
    let (tx, rx) = mpsc::channel(4096);
    let reader = fdtun::spawn_reader(tun.clone(), tx);
    let status = Arc::new(Status::default());
    // eigenes Logo des Servers landet in diesem Ordner (logo.png + logo.id); die App zeigt es dann an
    let ld = LOGO_DIR.lock().unwrap().clone();
    if !ld.is_empty() {
        *status.logo_dir.lock().unwrap() = Some(std::path::PathBuf::from(ld));
    }
    let (stop, stop_rx) = watch::channel(false);
    let kick = Arc::new(Notify::new());
    // Updates: signierte APK kommt ueber die VPN-Verbindung und wird hier abgelegt
    let update_file = Arc::new(Mutex::new((String::new(), String::new())));
    let uf = update_file.clone();
    let updater = Arc::new(kvpn::update::Updater::new(move |r: kvpn::update::Ready| {
        if update_dir.is_empty() {
            return;
        }
        let dir = std::path::Path::new(&update_dir);
        let _ = std::fs::create_dir_all(dir);
        let tmp = dir.join("update.part");
        let dst = dir.join("update.apk");
        if std::fs::write(&tmp, &r.data).and_then(|_| std::fs::rename(&tmp, &dst)).is_ok() {
            *uf.lock().unwrap() = (dst.to_string_lossy().to_string(), r.version);
        }
    }));
    let opts = ClientOptions {
        routes: ways,
        protect: None,
        dns: kvpn::transport::new_dns_cache(),
        reconnect: Some(kick.clone()),
        on_connected: None,
        update: Some(updater.clone()),
        cipher: Some(Arc::new(|| CIPHER.lock().unwrap().clone())),
    };
    let task = rt.spawn(client::run(cfg, opts, rx, tun, status.clone(), stop_rx));
    Box::into_raw(Box::new(Handle { stop, status, kick, updater, update_file, task, reader })) as jlong
}

unsafe fn libc_close(fd: jint) {
    extern "C" {
        fn close(fd: i32) -> i32;
    }
    close(fd);
}

/// Tunnel beenden; schliesst das TUN (Android baut das VPN dann ab)
#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_stop<'l>(_env: JNIEnv<'l>, _c: JClass<'l>, h: jlong) {
    if h == 0 {
        return;
    }
    let h = unsafe { Box::from_raw(h as *mut Handle) };
    let _ = h.stop.send(true);
    h.reader.abort();
    let task = h.task;
    let _ = runtime().block_on(async { tokio::time::timeout(Duration::from_secs(3), task).await });
}

/// Netz hat gewechselt: sofort neu verbinden statt auf das Zeitlimit zu warten
#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_reconnect<'l>(_env: JNIEnv<'l>, _c: JClass<'l>, h: jlong) {
    if h == 0 {
        return;
    }
    let h = unsafe { &*(h as *const Handle) };
    h.kick.notify_one();
}

/// Geschwindigkeitstest im laufenden Tunnel starten; Rueckgabe: "" = gestartet, sonst Fehlertext.
/// Das Ergebnis steht danach in status() unter "speed".
#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_speedtest<'l>(env: JNIEnv<'l>, _c: JClass<'l>, h: jlong) -> JString<'l> {
    let r = if h == 0 {
        "Nicht verbunden – erst verbinden, dann testen".to_string()
    } else {
        let h = unsafe { &*(h as *const Handle) };
        h.status.speedtest().err().unwrap_or_default()
    };
    env.new_string(r).unwrap_or_default()
}

/// Angaben des Geraets fuer den Server (JSON: WLAN-Name, Standort) – nur wenn der Nutzer es in der App freigibt
#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_report<'l>(mut env: JNIEnv<'l>, _c: JClass<'l>, h: jlong, json: JString<'l>) {
    if h == 0 {
        return;
    }
    let h = unsafe { &*(h as *const Handle) };
    let j = jstr(&mut env, &json);
    h.status.set_report(j.as_bytes());
}

/// Zustand als JSON (Zustand, Bytes, Ping, TLS-Infos, letzter Fehler)
#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_status<'l>(mut env: JNIEnv<'l>, _c: JClass<'l>, h: jlong) -> jstring {
    if h == 0 {
        return out(&mut env, "{\"state\":\"stopped\"}");
    }
    let h = unsafe { &*(h as *const Handle) };
    let mut j: serde_json::Value = serde_json::from_str(&h.status.to_json()).unwrap_or_default();
    let (file, ver) = h.update_file.lock().unwrap().clone();
    if let Some(o) = j.as_object_mut() {
        o.insert("update".into(), serde_json::to_value(h.updater.status()).unwrap_or_default());
        o.insert("update_file".into(), file.into());
        o.insert("update_version".into(), ver.into());
    }
    out(&mut env, &j.to_string())
}

/// Ordner fuer Absturz-Protokolle setzen (einmal beim Start): Abstuerze im Rust-Kern landen dort als Textdatei
#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_crashDir<'l>(mut env: JNIEnv<'l>, _c: JClass<'l>, dir: JString<'l>) {
    static GESETZT: OnceLock<()> = OnceLock::new();
    let d = jstr(&mut env, &dir);
    if d.is_empty() {
        return;
    }
    GESETZT.get_or_init(|| kvpn::fehler::absturz_haken(std::path::PathBuf::from(d), "Android", String::new));
}

/// Absturz-Protokoll zum Senden an den Server vormerken (geht beim Verbinden durch den Tunnel)
#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_crash<'l>(mut env: JNIEnv<'l>, _c: JClass<'l>, h: jlong, name: JString<'l>, text: JString<'l>) {
    if h == 0 {
        return;
    }
    let h = unsafe { &*(h as *const Handle) };
    let (n, t) = (jstr(&mut env, &name), jstr(&mut env, &text));
    h.status.add_crash(&n, t.as_bytes());
}

/// gewaehlte Verschluesselung ("auto", "aes", "chacha") – gilt ab dem naechsten Verbindungsaufbau
static CIPHER: Mutex<String> = Mutex::new(String::new());

/// Ordner fuer das Logo des Servers (vor start setzen)
static LOGO_DIR: Mutex<String> = Mutex::new(String::new());

#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_logoDir<'l>(mut env: JNIEnv<'l>, _c: JClass<'l>, dir: JString<'l>) {
    *LOGO_DIR.lock().unwrap() = jstr(&mut env, &dir);
}

#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_cipher<'l>(mut env: JNIEnv<'l>, _c: JClass<'l>, choice: JString<'l>) {
    let c = jstr(&mut env, &choice);
    *CIPHER.lock().unwrap() = kvpn::crypto::normalize_choice(&c).to_string();
}

/// hat der Prozessor AES-Befehle? (fuer die Anzeige "Auto nimmt …")
#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_aesHw<'l>(_env: JNIEnv<'l>, _c: JClass<'l>) -> jni::sys::jboolean {
    kvpn::crypto::aes_hw() as jni::sys::jboolean
}

#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_version<'l>(mut env: JNIEnv<'l>, _c: JClass<'l>) -> jstring {
    out(&mut env, kvpn::VERSION)
}

/// Schutz-Regeln: soll das VPN in diesem Netz laufen? (automatisch schuetzen, gleiche Regeln wie am PC)
#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_schuetzen<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    regeln: JString<'l>,
    wlan: JString<'l>,
    online: jni::sys::jboolean,
) -> jni::sys::jboolean {
    let r = kvpn::regeln::Regeln::from_json(&jstr(&mut env, &regeln));
    let n = kvpn::regeln::Netz { online: online != 0, wlan: jstr(&mut env, &wlan), router: String::new() };
    (!n.online || r.soll_schuetzen(&n)) as jni::sys::jboolean
}
