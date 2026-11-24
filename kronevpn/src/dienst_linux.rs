//! Linux: als systemd-Dienst im Hintergrund (kronevpn --hintergrund). Terminal darf danach zu.
//!   Programm /usr/local/bin/kronevpn, Code /etc/kronevpn/verbindung.txt (nur root), Dienst kronevpn.service
//!   kronevpn --trennen  (stoppen, nicht mehr beim Start)   ·   kronevpn --entfernen

use crate::Args;
use kvpn::code::ClientConfig;
use std::process::Command;

const UNIT: &str = "/etc/systemd/system/kronevpn.service";
const BIN: &str = "/usr/local/bin/kronevpn";
const CODE: &str = "/etc/kronevpn/verbindung.txt";

fn systemctl(args: &[&str]) -> bool {
    Command::new("systemctl").args(args).status().map(|s| s.success()).unwrap_or(false)
}

fn root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn install(cfg: &ClientConfig, a: &Args) -> ! {
    if !root() {
        crate::die("Bitte mit sudo starten (richtet einen systemd-Dienst ein)");
    }
    let res = (|| -> Result<(), String> {
        let me = std::env::current_exe().map_err(|e| e.to_string())?;
        if std::fs::canonicalize(&me).ok() != std::fs::canonicalize(BIN).ok() {
            let tmp = format!("{BIN}.neu");
            std::fs::copy(&me, &tmp).map_err(|e| format!("{BIN}: {e}"))?;
            std::fs::rename(&tmp, BIN).map_err(|e| format!("{BIN}: {e}"))?;
        }
        std::fs::create_dir_all("/etc/kronevpn").map_err(|e| e.to_string())?;
        std::fs::write(CODE, cfg.to_code()).map_err(|e| format!("{CODE}: {e}"))?;
        super::restrict_file(std::path::Path::new(CODE));
        let mut extra = String::new();
        if let Some(r) = &a.routes {
            extra += &format!(" --routes {}", r.join(","));
        }
        if let Some(p) = &a.proxy {
            extra += &format!(" --proxy {p}");
        }
        if a.no_update {
            extra += " --kein-update";
        }
        let unit = format!(
            "[Unit]\nDescription={} (VPN)\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\n\
             ExecStart={BIN} --config {CODE} --tun {}{extra}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
            cfg.display_name().replace(['\n', '%'], " "),
            a.tun
        );
        std::fs::write(UNIT, unit).map_err(|e| format!("{UNIT}: {e}"))?;
        systemctl(&["daemon-reload"]);
        if !systemctl(&["enable", "kronevpn"]) || !systemctl(&["restart", "kronevpn"]) {
            return Err("systemctl enable/restart kronevpn fehlgeschlagen".into());
        }
        Ok(())
    })();
    match res {
        Ok(()) => {
            println!("{} laeuft jetzt im Hintergrund (systemd-Dienst kronevpn, startet mit dem Rechner).", cfg.display_name());
            println!("Das Terminal darf zu.  Status: systemctl status kronevpn  ·  Protokoll: journalctl -u kronevpn -f");
            println!("Ausschalten: sudo kronevpn --trennen   ·   ganz entfernen: sudo kronevpn --entfernen");
            std::process::exit(0)
        }
        Err(e) => crate::die(e),
    }
}

pub fn control(a: &Args) -> ! {
    if !root() {
        crate::die("Bitte mit sudo starten");
    }
    systemctl(&["disable", "--now", "kronevpn"]);
    if a.uninstall {
        let _ = std::fs::remove_file(UNIT);
        let _ = std::fs::remove_file(CODE);
        systemctl(&["daemon-reload"]);
        println!("Dienst kronevpn und gespeicherter Code entfernt.");
    } else {
        println!("VPN getrennt (Dienst gestoppt, startet nicht mehr mit dem Rechner). Wieder an: sudo systemctl enable --now kronevpn");
    }
    std::process::exit(0)
}

/// Code des eingerichteten Dienstes (falls vorhanden)
pub fn stored_code() -> Option<String> {
    std::fs::read_to_string(CODE).ok().filter(|c| c.trim().starts_with("kronevpn://"))
}
