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
use std::sync::{Arc, OnceLock};
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
pub extern "system" fn Java_de_krone_vpn_Native_start<'l>(mut env: JNIEnv<'l>, _c: JClass<'l>, fd: jint, code: JString<'l>, sys_proxy: JString<'l>) -> jlong {
    let code = jstr(&mut env, &code);
    let sys_proxy = jstr(&mut env, &sys_proxy);
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
    let (stop, stop_rx) = watch::channel(false);
    let kick = Arc::new(Notify::new());
    let opts = ClientOptions { routes: ways, protect: None, dns: kvpn::transport::new_dns_cache(), reconnect: Some(kick.clone()), on_connected: None };
    let task = rt.spawn(client::run(cfg, opts, rx, tun, status.clone(), stop_rx));
    Box::into_raw(Box::new(Handle { stop, status, kick, task, reader })) as jlong
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

/// Zustand als JSON (Zustand, Bytes, Ping, TLS-Infos, letzter Fehler)
#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_status<'l>(mut env: JNIEnv<'l>, _c: JClass<'l>, h: jlong) -> jstring {
    if h == 0 {
        return out(&mut env, "{\"state\":\"stopped\"}");
    }
    let h = unsafe { &*(h as *const Handle) };
    let s = h.status.to_json();
    out(&mut env, &s)
}

#[no_mangle]
pub extern "system" fn Java_de_krone_vpn_Native_version<'l>(mut env: JNIEnv<'l>, _c: JClass<'l>) -> jstring {
    out(&mut env, kvpn::VERSION)
}
