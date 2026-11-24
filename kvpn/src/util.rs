//! kleine Helfer

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_nanos() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

pub fn now_secs() -> u64 {
    now_nanos() / 1_000_000_000
}

/// "10.77.0.2/24" -> (Adresse, Praefix)
pub fn parse_cidr(s: &str) -> Result<(std::net::IpAddr, u8), String> {
    let (a, p) = s.split_once('/').ok_or_else(|| format!("'{s}': Praefix fehlt (z. B. /24)"))?;
    let ip: std::net::IpAddr = a.parse().map_err(|_| format!("'{a}' ist keine IP-Adresse"))?;
    let p: u8 = p.parse().map_err(|_| format!("'{p}' ist kein Praefix"))?;
    if (ip.is_ipv4() && p > 32) || p > 128 {
        return Err(format!("Praefix /{p} zu gross"));
    }
    Ok((ip, p))
}

/// lesbare Datenmenge (1024er Schritte)
pub fn human_bytes(b: u64) -> String {
    let u = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < u.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", u[i])
    }
}

/// lesbare Datenrate aus Byte/s
pub fn human_rate(bps: f64) -> String {
    let bits = bps * 8.0;
    if bits >= 1e9 {
        format!("{:.2} Gbit/s", bits / 1e9)
    } else if bits >= 1e6 {
        format!("{:.1} Mbit/s", bits / 1e6)
    } else {
        format!("{:.0} kbit/s", bits / 1e3)
    }
}
