//! Zeitfenster (ab Server 1.5.0): ein Geraet (oder alle Geraete eines Benutzers) darf nur zu bestimmten Zeiten ins VPN,
//! z. B. "Mo-Fr 07:00-16:00". Ausserhalb wird es getrennt bzw. abgelehnt und verbindet sich zur naechsten erlaubten
//! Zeit von selbst wieder (die App versucht es weiter).
//!
//! Schreibweise (mehrere Regeln mit ";" oder neuer Zeile):
//!   Mo-Fr 07:00-16:00          Montag bis Freitag
//!   Sa,So 9-12                 Samstag und Sonntag, volle Stunden duerfen ohne :00
//!   taeglich 06:30-21:00       jeden Tag (auch "jeden Tag", "Mo-So")
//!   Fr 22:00-02:00             ueber Mitternacht: Freitag 22 Uhr bis Samstag 2 Uhr
//! Es gilt die Uhrzeit des Servers (Zeitzone des Systems bzw. Einstellung `zeitzone`).

const TAGE: [&str; 7] = ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Regel {
    /// Bit 0 = Montag ... Bit 6 = Sonntag
    pub tage: u8,
    /// Minuten seit Mitternacht; bis < von = ueber Mitternacht
    pub von: u16,
    pub bis: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Zeitplan {
    pub regeln: Vec<Regel>,
}

fn tag(s: &str) -> Option<u8> {
    let s = s.trim().to_lowercase();
    let s = s.trim_end_matches('.');
    let namen: [&[&str]; 7] = [
        &["mo", "mon", "montag", "monday"],
        &["di", "die", "dienstag", "tu", "tue", "tuesday"],
        &["mi", "mit", "mittwoch", "we", "wed", "wednesday"],
        &["do", "don", "donnerstag", "th", "thu", "thursday"],
        &["fr", "fre", "freitag", "fri", "friday"],
        &["sa", "sam", "samstag", "sat", "saturday"],
        &["so", "son", "sonntag", "su", "sun", "sunday"],
    ];
    namen.iter().position(|n| n.contains(&s)).map(|i| i as u8)
}

fn tage(s: &str) -> Result<u8, String> {
    let l = s.trim().to_lowercase();
    if matches!(l.as_str(), "täglich" | "taeglich" | "jeden tag" | "immer" | "alle" | "daily") {
        return Ok(0x7f);
    }
    if matches!(l.as_str(), "werktags" | "wochentags") {
        return Ok(0x1f);
    }
    if l == "wochenende" {
        return Ok(0x60);
    }
    let mut m = 0u8;
    for teil in l.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if let Some((a, b)) = teil.split_once('-') {
            let (a, b) = (tag(a).ok_or(format!("„{a}“ ist kein Wochentag"))?, tag(b).ok_or(format!("„{b}“ ist kein Wochentag"))?);
            let mut i = a;
            loop {
                m |= 1 << i;
                if i == b {
                    break;
                }
                i = (i + 1) % 7;
            }
        } else {
            m |= 1 << tag(teil).ok_or(format!("„{teil}“ ist kein Wochentag (Mo, Di, Mi, Do, Fr, Sa, So)"))?;
        }
    }
    if m == 0 {
        return Err("Wochentage fehlen, z. B. Mo-Fr".into());
    }
    Ok(m)
}

fn uhrzeit(s: &str) -> Result<u16, String> {
    let t = s.trim().trim_end_matches("uhr").trim_end_matches("Uhr").trim();
    let (h, m) = match t.split_once([':', '.']) {
        Some((h, m)) => (h.trim(), m.trim()),
        None => (t, "0"),
    };
    let (h, m): (u16, u16) = (h.parse().map_err(|_| format!("„{s}“ ist keine Uhrzeit"))?, m.parse().map_err(|_| format!("„{s}“ ist keine Uhrzeit"))?);
    if m > 59 || h > 24 || (h == 24 && m > 0) {
        return Err(format!("„{s}“ ist keine Uhrzeit"));
    }
    Ok(h * 60 + m)
}

impl Zeitplan {
    /// leer, "-", "aus", "immer" = keine Einschraenkung
    pub fn parse(s: &str) -> Result<Zeitplan, String> {
        let mut regeln = Vec::new();
        for r in s.split([';', '\n']).map(str::trim).filter(|r| !r.is_empty()) {
            if matches!(r.to_lowercase().as_str(), "-" | "aus" | "immer" | "keine" | "nie") {
                continue;
            }
            // "Mo-Fr 7 Uhr bis 16 Uhr" -> "Mo-Fr 7-16"
            let r = r.replace(" Uhr", "").replace(" uhr", "").replace("Uhr", "").replace(" bis ", "-").replace(" - ", "-").replace("–", "-");
            let r = r.trim();
            // "<Tage> <von>-<bis>": die Uhrzeit ist das letzte Wort
            let (t, z) = r.rsplit_once(char::is_whitespace).ok_or(format!("„{r}“: so schreiben: Mo-Fr 07:00-16:00"))?;
            let (von, bis) = z.split_once('-').ok_or(format!("„{r}“: Uhrzeit als von-bis, z. B. 07:00-16:00"))?;
            let (von, bis) = (uhrzeit(von)?, uhrzeit(bis)?);
            if von == bis {
                return Err(format!("„{r}“: Anfang und Ende sind gleich"));
            }
            regeln.push(Regel { tage: tage(t)?, von, bis });
        }
        if regeln.len() > 20 {
            return Err("höchstens 20 Zeitfenster".into());
        }
        Ok(Zeitplan { regeln })
    }

    pub fn leer(&self) -> bool {
        self.regeln.is_empty()
    }

    /// erlaubt an Wochentag `wt` (0 = Montag) um `min` Minuten nach Mitternacht?
    pub fn erlaubt_um(&self, wt: u8, min: u16) -> bool {
        if self.leer() {
            return true;
        }
        let gestern = (wt + 6) % 7;
        self.regeln.iter().any(|r| {
            if r.von < r.bis {
                r.tage & (1 << wt) != 0 && min >= r.von && min < r.bis
            } else {
                // ueber Mitternacht: abends am Tag selbst, morgens am Folgetag
                (r.tage & (1 << wt) != 0 && min >= r.von) || (r.tage & (1 << gestern) != 0 && min < r.bis)
            }
        })
    }

    /// erlaubt jetzt (Ortszeit des Servers)?
    pub fn erlaubt(&self, ts: u64) -> bool {
        let (wt, min) = jetzt(ts);
        self.erlaubt_um(wt, min)
    }

    /// naechster erlaubter Zeitpunkt als Text ("Mo 07:00"), None = gerade erlaubt oder nie
    pub fn naechster(&self, ts: u64) -> Option<String> {
        if self.leer() || self.erlaubt(ts) {
            return None;
        }
        let (wt, min) = jetzt(ts);
        // in Minutenschritten bis zu einer Woche voraus (hoechstens 10080 Pruefungen)
        for d in 1..=7 * 24 * 60u32 {
            let m = min as u32 + d;
            let (w, mm) = (((wt as u32 + m / 1440) % 7) as u8, (m % 1440) as u16);
            if self.erlaubt_um(w, mm) {
                let heute = m / 1440 == 0;
                let tag = if heute { "heute".to_string() } else if m / 1440 == 1 { "morgen".to_string() } else { TAGE[w as usize].to_string() };
                return Some(format!("{tag} {:02}:{:02}", mm / 60, mm % 60));
            }
        }
        None
    }

    /// einheitliche Schreibweise ("Mo-Fr 07:00-16:00; Sa 09:00-12:00")
    pub fn text(&self) -> String {
        self.regeln
            .iter()
            .map(|r| {
                let t = if r.tage == 0x7f { "täglich".to_string() } else { tage_text(r.tage) };
                format!("{t} {:02}:{:02}-{:02}:{:02}", r.von / 60, r.von % 60, r.bis / 60, r.bis % 60)
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Wochentage als kurzer Text: zusammenhaengende Tage als Bereich ("Mo-Fr", "Mo,Mi,Fr", "Sa-So")
fn tage_text(m: u8) -> String {
    let mut teile = Vec::new();
    let mut i = 0;
    while i < 7 {
        if m & (1 << i) == 0 {
            i += 1;
            continue;
        }
        let a = i;
        while i + 1 < 7 && m & (1 << (i + 1)) != 0 {
            i += 1;
        }
        teile.push(if i > a + 1 { format!("{}-{}", TAGE[a], TAGE[i]) } else if i == a + 1 { format!("{},{}", TAGE[a], TAGE[i]) } else { TAGE[a].to_string() });
        i += 1;
    }
    teile.join(",")
}

/// (Wochentag 0 = Montag, Minute des Tages) in Ortszeit
pub fn jetzt(ts: u64) -> (u8, u16) {
    let t = ts as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    (((tm.tm_wday + 6) % 7) as u8, (tm.tm_hour * 60 + tm.tm_min) as u16)
}

/// Zeitzone des Servers setzen (Einstellung `zeitzone`, z. B. "Europe/Berlin"; leer = System)
pub fn zeitzone(tz: &str) {
    if tz.trim().is_empty() {
        return;
    }
    std::env::set_var("TZ", tz.trim());
    extern "C" {
        fn tzset();
    }
    unsafe { tzset() };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lesen_und_pruefen() {
        let z = Zeitplan::parse("Mo-Fr 7-16").unwrap();
        assert_eq!(z.text(), "Mo-Fr 07:00-16:00");
        assert!(z.erlaubt_um(0, 7 * 60));
        assert!(z.erlaubt_um(4, 15 * 60 + 59));
        assert!(!z.erlaubt_um(4, 16 * 60), "16:00 ist schon draussen");
        assert!(!z.erlaubt_um(0, 6 * 60 + 59));
        assert!(!z.erlaubt_um(5, 10 * 60), "Samstag nicht");
        let z = Zeitplan::parse("Fr 22:00-02:00; Sa,So 9:30-12 Uhr").unwrap();
        assert_eq!(z.text(), "Fr 22:00-02:00; Sa,So 09:30-12:00");
        assert!(z.erlaubt_um(4, 23 * 60), "Freitag spaet");
        assert!(z.erlaubt_um(5, 60), "Samstag frueh (von Freitag)");
        assert!(!z.erlaubt_um(5, 3 * 60));
        assert!(!z.erlaubt_um(3, 23 * 60), "Donnerstag nicht");
        assert!(z.erlaubt_um(6, 10 * 60));
        assert_eq!(Zeitplan::parse("täglich 06:30-21:00").unwrap().text(), "täglich 06:30-21:00");
        assert_eq!(Zeitplan::parse("Sa-Mo 8-9").unwrap().text(), "Mo,Sa,So 08:00-09:00");
        assert_eq!(Zeitplan::parse("werktags 8-18").unwrap().text(), "Mo-Fr 08:00-18:00");
        assert!(Zeitplan::parse("").unwrap().leer());
        assert!(Zeitplan::parse("aus").unwrap().leer());
        assert!(Zeitplan::parse("").unwrap().erlaubt_um(6, 0));
        assert_eq!(Zeitplan::parse("Mo-Fr 7 Uhr bis 16:30 Uhr").unwrap().text(), "Mo-Fr 07:00-16:30");
        for falsch in ["Mo-Fr", "Xy 7-16", "Mo 25-26", "Mo 7-7", "Mo 7:61-8"] {
            assert!(Zeitplan::parse(falsch).is_err(), "{falsch}");
        }
    }

    #[test]
    fn naechster_zeitpunkt() {
        zeitzone("UTC");
        let fr17 = 1_795_798_800u64; // Freitag, 27.11.2026, 17:00 UTC
        assert_eq!(jetzt(fr17), (4, 17 * 60));
        let z = Zeitplan::parse("Mo-Fr 7-16").unwrap();
        assert!(!z.erlaubt(fr17));
        assert_eq!(z.naechster(fr17).as_deref(), Some("Mo 07:00"));
        assert_eq!(Zeitplan::parse("Fr 18-20").unwrap().naechster(fr17).as_deref(), Some("heute 18:00"));
        assert_eq!(Zeitplan::parse("Sa 8-9").unwrap().naechster(fr17).as_deref(), Some("morgen 08:00"));
        assert!(Zeitplan::parse("").unwrap().naechster(fr17).is_none());
    }
}
