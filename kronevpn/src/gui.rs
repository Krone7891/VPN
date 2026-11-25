//! Programmfenster (Windows): grosser Ein/Aus-Knopf (mit Wirbel, wenn das Fenster den Fokus hat), Live-Werte, Verlauf, Verschluesselung, Protokoll.
//!
//! Das Fenster ist nur die Oberflaeche – das VPN selbst laeuft als Windows-Dienst (siehe dienst_windows.rs) und
//! meldet seinen Zustand jede Sekunde in status.json. Das Fenster darf deshalb jederzeit zu.
//! Zum Ansehen ohne Windows: `cargo run -p kronevpn --features vorschau` mit KVPN_VORSCHAU=an|aus|verbinde|neu|update|fehler

use crate::Zustand;
use eframe::egui::{self, pos2, vec2, Color32, CornerRadius, FontFamily, FontId, Margin, Pos2, Rect, RichText, Sense, Stroke};
use kvpn::code::ClientConfig;
use kvpn::util::{human_bytes, human_rate};
use std::collections::VecDeque;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

// Farben wie auf der Statistik-Seite
const BG: Color32 = Color32::from_rgb(0x0f, 0x11, 0x15);
const CARD: Color32 = Color32::from_rgb(0x17, 0x1a, 0x21);
const SOFT: Color32 = Color32::from_rgb(0x1e, 0x22, 0x2b);
const LINE: Color32 = Color32::from_rgb(0x26, 0x2b, 0x35);
const INK: Color32 = Color32::from_rgb(0xe8, 0xea, 0xf0);
const MUTE: Color32 = Color32::from_rgb(0x9a, 0xa3, 0xb2);
const ACC: Color32 = Color32::from_rgb(0x6f, 0x95, 0xff);
const OK: Color32 = Color32::from_rgb(0x36, 0xc2, 0x7a);
const WARN: Color32 = Color32::from_rgb(0xf0, 0xa7, 0x2a);
const BAD: Color32 = Color32::from_rgb(0xff, 0x5c, 0x7a);
const DOWN: Color32 = Color32::from_rgb(0x39, 0x87, 0xe5);
const UP: Color32 = Color32::from_rgb(0xd9, 0x59, 0x26);

const LOGO: &[u8] = include_bytes!("../res/logo128.rgba");
/// Sekunden im Verlauf
const VERLAUF: usize = 90;

/// Zustand des Hintergrund-Dienstes
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
pub enum Lage {
    Fehlt,
    Aus,
    Startet,
    Laeuft,
    Stoppt,
}

/// was das Fenster vom Dienst braucht (Windows: dienst_windows::Fenster, Vorschau: Demo)
pub trait Steuerung: Send + Sync + 'static {
    fn lage(&self) -> Lage;
    /// aktueller Zustand aus status.json (None = keiner bzw. veraltet)
    fn zustand(&self) -> Option<Zustand>;
    /// soll das VPN laufen (Dienst startet mit Windows)? Beim Oeffnen des Fensters wird dann verbunden.
    fn gewollt(&self) -> bool;
    /// Dienst einrichten bzw. aktualisieren und starten (dauert ein paar Sekunden)
    fn verbinden(&self, cfg: &ClientConfig) -> Result<(), String>;
    fn trennen(&self) -> Result<(), String>;
    /// Code als aktives Profil speichern (kommt auch in die Profil-Liste)
    fn code_speichern(&self, cfg: &ClientConfig);
    /// gewaehlte Verschluesselung ("auto", "aes", "chacha")
    fn verschluesselung(&self) -> String;
    /// Verschluesselung waehlen; eine laufende Verbindung wird damit neu aufgebaut
    fn verschluesselung_setzen(&self, wahl: &str) -> Result<(), String>;
    /// gespeicherte Profile (Verbindungscodes)
    fn profile(&self) -> Vec<ClientConfig>;
    fn profile_speichern(&self, list: &[ClientConfig]);
    /// Protokoll (letzte Zeilen)
    fn protokoll(&self) -> String;
    fn protokoll_oeffnen(&self);
    /// zur alten Text-Ansicht wechseln (startet sie; das Fenster schliesst sich danach)
    fn klassisch(&self) -> Result<(), String>;
    /// Dienst laeuft schon mit einer neueren Version (Auto-Update): Fenster in der neuen Version neu starten.
    /// true = neues Fenster gestartet, dieses schliesst sich
    fn neue_version_starten(&self) -> bool {
        false
    }
    /// Ordner mit dem eigenen Logo des Servers (logo.png + logo.id), None = immer die Krone
    fn logo_ordner(&self) -> Option<std::path::PathBuf> {
        None
    }
    /// Schutz-Regeln (Notbremse, automatisch schuetzen, Ausnahmen)
    fn regeln(&self) -> kvpn::regeln::Regeln {
        kvpn::regeln::Regeln::default()
    }
    /// Regeln speichern; ein laufendes VPN uebernimmt sie (verbindet kurz neu)
    fn regeln_speichern(&self, _r: &kvpn::regeln::Regeln) -> Result<(), String> {
        Err("hier nicht moeglich".into())
    }
    /// das Netz, in dem der PC gerade ist
    fn netz(&self) -> kvpn::regeln::Netz {
        kvpn::regeln::Netz::default()
    }
    /// Geschwindigkeitstest im laufenden VPN anstossen (Ergebnis kommt ueber `zustand().speed`)
    fn geschwindigkeit(&self) -> Result<(), String> {
        crate::speedtest_anstossen()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Anzeige {
    Aus,
    Verbinde,
    Verbunden,
    Trenne,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Aktion {
    Verbinden,
    Trennen,
}

struct App {
    st: Arc<dyn Steuerung>,
    cfg: Option<ClientConfig>,
    lage: Lage,
    z: Option<Zustand>,
    abgefragt: Option<Instant>,
    verlauf: VecDeque<(f32, f32)>,
    letzter_ts: u64,
    laeuft_ohne_status: Option<Instant>,
    arbeit: Option<(Aktion, mpsc::Receiver<Result<(), String>>)>,
    gewollt: bool,
    fehler: String,
    eingabe: String,
    eingabe_fehler: String,
    code_aendern: bool,
    zeige_sicherheit: bool,
    /// gewaehlte Verschluesselung und laufende Uebernahme
    wahl: String,
    wahl_arbeit: Option<mpsc::Receiver<Result<(), String>>>,
    zeige_profile: bool,
    profile: Vec<ClientConfig>,
    /// Schutz-Dialog: Regeln in Bearbeitung, Ausnahmen als Text, aktuelles Netz, Meldung
    schutz: Option<(kvpn::regeln::Regeln, String, kvpn::regeln::Netz, String)>,
    titel_setzen: bool,
    danach_verbinden: bool,
    log: Option<String>,
    logo: egui::TextureHandle,
    /// Kennung des angezeigten Logos ("" = Krone) und wann zuletzt nachgesehen wurde
    logo_id: String,
    logo_geprueft: Option<Instant>,
    start: Instant,
    /// Version, fuer die der Neustart des Fensters schon versucht wurde
    neu_versucht: String,
    schliessen: bool,
    /// Animation: Farbe des Knopfs blendet weich um (von, zu, seit), "Plopp" beim Verbinden
    farbe: (Color32, Color32, Instant),
    plopp: Option<Instant>,
    letzte_anz: Option<Anzeige>,
    /// Fenster hat den Fokus: Knopf lebhafter animieren (Wellen, kreisendes Licht, ...)
    lebhaft: bool,
    /// letzter Klick auf den Knopf (Welle) und letzter Wechsel der Anzeige
    klick: Option<Instant>,
    wechsel: Instant,
    /// Wirbel (Tornado) um den Knopf: Drehung, Sog, aktuelle Drehzahl, Staerke, Sog-Tempo; Zeit des letzten Bilds
    wirbel: [f32; 5],
    wirbel_t: Instant,
}

/// weiches Ein-/Ausblenden (0..1 -> 0..1)

/// Sicherheit-Dialog: was man waehlen kann und was immer an ist (gleiche Texte wie in der Android-App)
const SICHER_INTRO: &str = "Deine Daten sind immer verschlüsselt – ausschalten kann man das nicht. Hier wählst du nur das Verfahren. Alle drei Möglichkeiten sind gleich sicher (geprüfte Standards, 256-Bit-Schlüssel); sie unterscheiden sich nur in Tempo und Akku.";
const IMMER_AKTIV: [(&str, &str); 3] = [
    ("HTTPS-Hülle (TLS 1.3, Port 443)", "Für Firewalls wie Sophos sieht das VPN aus wie eine normale Webseite. Deshalb kommt es durch."),
    ("Geräte-Schlüssel (Noise)", "Nur dein Server und deine Geräte können die Daten lesen – auch wenn eine Firmen-Firewall HTTPS aufbricht und hineinschaut."),
    ("Tarnung", "Paketgrößen und Takt ändern sich bei jeder Verbindung, damit keine typischen VPN-Muster entstehen. Das ist keine Verschlüsselung, nur eine Verkleidung – die Sicherheit kommt von den beiden Punkten oben."),
];

fn sanft(x: f32) -> f32 {
    let x = x.clamp(0.0, 1.0);
    1.0 - (1.0 - x).powi(3)
}

pub fn run(st: Arc<dyn Steuerung>, cfg: Option<ClientConfig>, sofort: bool) -> Result<(), String> {
    let title = cfg.as_ref().map(|c| c.display_name().to_string()).unwrap_or_else(|| "KroneVPN".into());
    let icon = egui::IconData { rgba: LOGO.to_vec(), width: 128, height: 128 };
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(&title)
            .with_inner_size([420.0, 740.0])
            .with_min_inner_size([380.0, 520.0])
            .with_icon(Arc::new(icon)),
        renderer: eframe::Renderer::Glow,
        centered: true,
        vsync: true,
        ..Default::default()
    };
    eframe::run_native(&title, opts, Box::new(move |cc| Ok(Box::new(App::new(cc, st, cfg, sofort))))).map_err(|e| e.to_string())
}

// ------------------------------------------------------------------------------------------------ Aussehen

fn schrift(pfade: &[String]) -> Option<Vec<u8>> {
    pfade.iter().find_map(|p| std::fs::read(p).ok())
}

fn stil(ctx: &egui::Context) {
    let win = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
    let f = |n: &str| format!(r"{win}\Fonts\{n}");
    let normal = schrift(&[f("segoeui.ttf"), "/usr/share/fonts/opentype/inter/Inter-Regular.otf".into(), "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf".into()]);
    let fett = schrift(&[f("segoeuisb.ttf"), f("segoeuib.ttf"), "/usr/share/fonts/opentype/inter/Inter-SemiBold.otf".into(), "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf".into()]);
    let mono = schrift(&[f("consola.ttf"), "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf".into()]);

    let mut fonts = egui::FontDefinitions::default();
    let standard = fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    let mut fett_familie = standard.clone();
    if let Some(b) = normal {
        fonts.font_data.insert("text".into(), Arc::new(egui::FontData::from_owned(b)));
        fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "text".into());
        fett_familie.insert(0, "text".into());
    }
    if let Some(b) = fett {
        fonts.font_data.insert("fett".into(), Arc::new(egui::FontData::from_owned(b)));
        fett_familie.insert(0, "fett".into());
    }
    if let Some(b) = mono {
        fonts.font_data.insert("mono".into(), Arc::new(egui::FontData::from_owned(b)));
        fonts.families.entry(FontFamily::Monospace).or_default().insert(0, "mono".into());
    }
    fonts.families.insert(FontFamily::Name("fett".into()), fett_familie);
    ctx.set_fonts(fonts);

    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = CARD;
    v.window_stroke = linie(1.0, LINE);
    v.window_corner_radius = CornerRadius::same(16);
    v.extreme_bg_color = Color32::from_rgb(0x0b, 0x0d, 0x11);
    v.faint_bg_color = SOFT;
    v.hyperlink_color = ACC;
    v.selection.bg_fill = ACC.gamma_multiply(0.45);
    v.selection.stroke = linie(1.0, ACC);
    v.override_text_color = Some(INK);
    let w = &mut v.widgets;
    for (s, bg) in [(&mut w.inactive, SOFT), (&mut w.hovered, LINE), (&mut w.active, Color32::from_rgb(0x30, 0x36, 0x43))] {
        s.bg_fill = bg;
        s.weak_bg_fill = bg;
        s.bg_stroke = linie(1.0, LINE);
        s.fg_stroke = linie(1.5, INK);
        s.corner_radius = CornerRadius::same(10);
        s.expansion = 0.0;
    }
    w.hovered.bg_stroke = linie(1.0, Color32::from_rgb(0x3a, 0x41, 0x50));
    w.noninteractive.bg_stroke = linie(1.0, LINE);
    w.noninteractive.fg_stroke = linie(1.0, INK);
    w.noninteractive.corner_radius = CornerRadius::same(10);
    ctx.set_visuals(v);
    ctx.style_mut(|s| {
        use egui::TextStyle::*;
        s.text_styles = [
            (Small, FontId::proportional(12.5)),
            (Body, FontId::proportional(15.0)),
            (Button, FontId::proportional(15.0)),
            (Heading, FontId::new(22.0, FontFamily::Name("fett".into()))),
            (Monospace, FontId::monospace(13.0)),
        ]
        .into();
        s.spacing.item_spacing = vec2(8.0, 8.0);
        s.spacing.button_padding = vec2(14.0, 8.0);
        s.spacing.interact_size.y = 34.0;
        s.interaction.selectable_labels = false;
    });
}

fn linie(breite: f32, farbe: Color32) -> Stroke {
    Stroke::new(breite, farbe)
}

fn fett(t: impl Into<String>, size: f32) -> RichText {
    RichText::new(t).family(FontFamily::Name("fett".into())).size(size)
}

fn karte() -> egui::Frame {
    egui::Frame::new().fill(CARD).stroke(linie(1.0, LINE)).corner_radius(14).inner_margin(Margin::same(14))
}

fn knopf(text: &str, haupt: bool) -> egui::Button<'static> {
    let b = egui::Button::new(if haupt { fett(text, 15.5).color(Color32::WHITE) } else { RichText::new(text.to_string()) });
    if haupt {
        b.fill(ACC.linear_multiply(0.85)).stroke(Stroke::NONE)
    } else {
        b
    }
}

/// 1:02:03 bzw. 4:05
fn dauer(s: u64) -> String {
    if s >= 86400 {
        format!("{} T {}:{:02} Std", s / 86400, s / 3600 % 24, s / 60 % 60)
    } else if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

fn host(url: &str) -> String {
    let u = url.split("://").nth(1).unwrap_or(url);
    u.split('/').next().unwrap_or(u).to_string()
}

// ------------------------------------------------------------------------------------------------ Logik

impl App {
    fn new(cc: &eframe::CreationContext<'_>, st: Arc<dyn Steuerung>, cfg: Option<ClientConfig>, sofort: bool) -> Self {
        let schutz_vorschau = if cfg!(feature = "vorschau") && std::env::var_os("KVPN_VORSCHAU_SCHUTZ").is_some() {
            let r = st.regeln();
            let t = r.ziele.join("\n");
            Some((r, t, st.netz(), String::new()))
        } else {
            None
        };
        stil(&cc.egui_ctx);
        let logo = cc.egui_ctx.load_texture("logo", egui::ColorImage::from_rgba_unmultiplied([128, 128], LOGO), egui::TextureOptions::LINEAR);
        let gewollt = st.gewollt();
        let mut app = App {
            st,
            cfg,
            lage: Lage::Fehlt,
            z: None,
            abgefragt: None,
            verlauf: VecDeque::new(),
            letzter_ts: 0,
            laeuft_ohne_status: None,
            arbeit: None,
            gewollt,
            fehler: String::new(),
            eingabe: String::new(),
            eingabe_fehler: String::new(),
            code_aendern: false,
            zeige_sicherheit: false,
            wahl: String::new(),
            wahl_arbeit: None,
            zeige_profile: false,
            profile: Vec::new(),
            schutz: schutz_vorschau,
            titel_setzen: false,
            danach_verbinden: false,
            log: None,
            logo,
            logo_id: String::new(),
            logo_geprueft: None,
            start: Instant::now(),
            neu_versucht: String::new(),
            schliessen: false,
            farbe: (MUTE, MUTE, Instant::now()),
            plopp: None,
            letzte_anz: None,
            lebhaft: false,
            klick: None,
            wechsel: Instant::now(),
            wirbel: [0.0; 5],
            wirbel_t: Instant::now(),
        };
        app.wahl = app.st.verschluesselung();
        // Profile: das aktive gehoert immer dazu (z. B. Code aus einer aelteren Version)
        app.profile = app.st.profile();
        if let Some(c) = app.cfg.clone() {
            if !app.profile.iter().any(|p| crate::same_profile(p, &c)) {
                app.st.code_speichern(&c);
                app.profile = app.st.profile();
            }
        }
        // wie bisher: Programm oeffnen = verbinden (ausser man hat vorher bewusst getrennt)
        if app.cfg.is_some() && (sofort || gewollt) {
            app.ausfuehren(Aktion::Verbinden);
        }
        app
    }

    fn ausfuehren(&mut self, a: Aktion) {
        if self.arbeit.is_some() {
            return;
        }
        let cfg = match (a, &self.cfg) {
            (Aktion::Verbinden, None) => return,
            (_, c) => c.clone(),
        };
        self.fehler.clear();
        self.gewollt = a == Aktion::Verbinden;
        let st = self.st.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let r = match a {
                Aktion::Verbinden => st.verbinden(cfg.as_ref().unwrap()),
                Aktion::Trennen => st.trennen(),
            };
            let _ = tx.send(r);
        });
        self.arbeit = Some((a, rx));
        self.abgefragt = None;
    }

    fn abfragen(&mut self) {
        if let Some(rx) = &self.wahl_arbeit {
            match rx.try_recv() {
                Ok(r) => {
                    if let Err(e) = r {
                        self.fehler = format!("Verschlüsselung: {e}");
                    }
                    self.wahl_arbeit = None;
                    self.abgefragt = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => self.wahl_arbeit = None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some((_, rx)) = &self.arbeit {
            match rx.try_recv() {
                Ok(r) => {
                    if let Err(e) = r {
                        self.fehler = e;
                    }
                    self.arbeit = None;
                    self.abgefragt = None;
                    if std::mem::take(&mut self.danach_verbinden) {
                        self.ausfuehren(Aktion::Verbinden);
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => self.arbeit = None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if self.abgefragt.is_some_and(|t| t.elapsed() < Duration::from_millis(500)) {
            return;
        }
        self.abgefragt = Some(Instant::now());
        self.lage = self.st.lage();
        self.z = self.st.zustand();
        // Auto-Update: der Dienst laeuft schon mit der neuen Version -> Fenster startet sich mit dem Patch neu
        if let Some(v) = self.z.as_ref().map(|z| z.version.clone()) {
            if kvpn::update::newer(&v, kvpn::VERSION) && self.neu_versucht != v {
                self.neu_versucht = v;
                self.schliessen = self.st.neue_version_starten();
            }
        }
        if let Some(z) = &self.z {
            if z.ts != self.letzter_ts {
                self.letzter_ts = z.ts;
                let w = if z.state == "connected" { (z.rate_rx as f32, z.rate_tx as f32) } else { (0.0, 0.0) };
                self.verlauf.push_back(w);
                while self.verlauf.len() > VERLAUF {
                    self.verlauf.pop_front();
                }
            }
        }
        if self.lage == Lage::Laeuft && self.z.is_none() {
            self.laeuft_ohne_status.get_or_insert_with(Instant::now);
        } else {
            self.laeuft_ohne_status = None;
        }
        if self.lage == Lage::Aus || self.lage == Lage::Fehlt {
            self.verlauf.clear();
        }
    }

    fn anzeige(&self) -> Anzeige {
        if let Some((a, _)) = &self.arbeit {
            return if *a == Aktion::Trennen { Anzeige::Trenne } else { Anzeige::Verbinde };
        }
        match self.lage {
            Lage::Laeuft if self.z.as_ref().is_some_and(|z| z.state == "connected") => Anzeige::Verbunden,
            Lage::Laeuft | Lage::Startet => Anzeige::Verbinde,
            Lage::Stoppt => Anzeige::Trenne,
            Lage::Aus | Lage::Fehlt => Anzeige::Aus,
        }
    }

    fn code_uebernehmen(&mut self) {
        match ClientConfig::from_code(self.eingabe.trim()) {
            Ok(c) => {
                self.eingabe.clear();
                self.eingabe_fehler.clear();
                self.code_aendern = false;
                self.profil_waehlen(c, true);
            }
            Err(e) => self.eingabe_fehler = e.to_string(),
        }
    }

    /// Profil aktiv machen. Lief das VPN (oder `verbinden`), wird mit dem neuen Profil (neu) verbunden.
    fn profil_waehlen(&mut self, c: ClientConfig, verbinden: bool) {
        let an = self.anzeige() != Anzeige::Aus || self.gewollt;
        self.st.code_speichern(&c);
        self.profile = self.st.profile();
        self.cfg = Some(c);
        self.titel_setzen = true;
        if verbinden || an {
            if self.arbeit.is_some() {
                // laeuft gerade noch etwas: danach mit dem neuen Profil verbinden
                self.danach_verbinden = true;
            } else {
                self.ausfuehren(Aktion::Verbinden);
            }
        }
    }

    /// Verschluesselung wechseln (im Hintergrund: Dienst startet dafuer kurz neu)
    fn wahl_setzen(&mut self, w: &str) {
        if self.wahl_arbeit.is_some() || self.wahl == w {
            return;
        }
        self.wahl = w.to_string();
        self.fehler.clear();
        let (st, w, (tx, rx)) = (self.st.clone(), w.to_string(), mpsc::channel());
        std::thread::spawn(move || {
            let _ = tx.send(st.verschluesselung_setzen(&w));
        });
        self.wahl_arbeit = Some(rx);
    }

    fn ist_aktiv(&self, c: &ClientConfig) -> bool {
        self.cfg.as_ref().is_some_and(|x| crate::same_profile(x, c))
    }
}

// ------------------------------------------------------------------------------------------------ Zeichnen

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.abfragen();
        self.logo_pruefen(ctx);
        if self.schliessen {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if std::mem::take(&mut self.titel_setzen) {
            if let Some(c) = &self.cfg {
                ctx.send_viewport_cmd(egui::ViewportCommand::Title(c.display_name().to_string()));
            }
        }
        let anz = self.anzeige();
        let eingabe = self.cfg.is_none() || self.code_aendern;
        // Fenster im Fokus (und Hauptansicht): Knopf lebhafter animieren; sonst ruhig, spart Strom
        let fokus = ctx.input(|i| i.viewport().focused.unwrap_or(false)) || (cfg!(feature = "vorschau") && std::env::var_os("KVPN_VORSCHAU_FOKUS").is_some());
        self.lebhaft = fokus && !eingabe;

        if !eingabe {
            egui::TopBottomPanel::bottom("fuss")
                .frame(egui::Frame::new().fill(BG).inner_margin(Margin { left: 18, right: 18, top: 10, bottom: 14 }))
                .show_separator_line(false)
                .show(ctx, |ui| self.fuss(ui));
        }
        // beim Oeffnen sanft einblenden
        let ein = sanft(self.start.elapsed().as_secs_f32() / 0.45);
        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG).inner_margin(Margin { left: 18, right: 18, top: 16, bottom: 4 })).show(ctx, |ui| {
            ui.multiply_opacity(ein);
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                self.kopf(ui);
                ui.add_space(6.0);
                if eingabe {
                    self.code_eingabe(ui);
                } else {
                    self.haupt(ui, anz);
                }
            });
        });
        self.dialoge(ctx);

        let animiert = ein < 1.0 || self.farbe.2.elapsed() < Duration::from_millis(400) || self.plopp.is_some_and(|t| t.elapsed() < Duration::from_millis(700)) || self.klick.is_some_and(|t| t.elapsed() < Duration::from_millis(700)) || self.wirbel[3] > 0.01;
        if animiert || self.lebhaft || matches!(anz, Anzeige::Verbinde | Anzeige::Trenne) {
            ctx.request_repaint_after(Duration::from_millis(16));
        } else if anz == Anzeige::Verbunden {
            // ruhiges "Atmen" des Leuchtens
            ctx.request_repaint_after(Duration::from_millis(40));
        } else {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }
}

impl App {
    /// eigenes Logo des Servers: neu (oder entfernt)? Dann im Fenster und als Fenster-/Taskleisten-Symbol tauschen
    fn logo_pruefen(&mut self, ctx: &egui::Context) {
        if self.logo_geprueft.is_some_and(|t| t.elapsed() < Duration::from_secs(2)) {
            return;
        }
        self.logo_geprueft = Some(Instant::now());
        let Some(dir) = self.st.logo_ordner() else { return };
        let id = kvpn::logo::id_in(&dir);
        if id == self.logo_id {
            return;
        }
        let icon = if id.is_empty() {
            Some(egui::IconData { rgba: LOGO.to_vec(), width: 128, height: 128 })
        } else {
            std::fs::read(dir.join("logo.png")).ok().and_then(|b| eframe::icon_data::from_png_bytes(&b).ok())
        };
        let Some(icon) = icon else { return };
        self.logo = ctx.load_texture("logo", egui::ColorImage::from_rgba_unmultiplied([icon.width as usize, icon.height as usize], &icon.rgba), egui::TextureOptions::LINEAR);
        ctx.send_viewport_cmd(egui::ViewportCommand::Icon(Some(Arc::new(icon))));
        self.logo_id = id;
    }

    fn kopf(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(vec2(44.0, 44.0), Sense::hover());
            ui.painter().image(self.logo.id(), r, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
            ui.add_space(4.0);
            let r = ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.add_space(2.0);
                let name = self.cfg.as_ref().map(|c| c.display_name().to_string()).unwrap_or_else(|| "KroneVPN".into());
                ui.label(fett(name, 21.0));
                let geraet = match &self.cfg {
                    Some(c) if self.profile.len() > 1 => format!("Gerät „{}“  ·  Profil wechseln ›", c.name),
                    Some(c) => format!("Gerät „{}“", c.name),
                    None => "Noch nicht eingerichtet".into(),
                };
                ui.label(RichText::new(geraet).color(MUTE).size(13.5));
            });
            if self.cfg.is_some() && !self.code_aendern {
                let resp = ui.interact(r.response.rect, egui::Id::new("profilwahl"), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Profile");
                if resp.clicked() {
                    self.zeige_profile = true;
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let v = self.z.as_ref().map(|z| z.version.clone()).filter(|v| !v.is_empty()).unwrap_or_else(|| kvpn::VERSION.to_string());
                let g = ui.painter().layout_no_wrap(format!("v{v}"), FontId::proportional(12.0), MUTE);
                let (r, _) = ui.allocate_exact_size(g.size() + vec2(18.0, 8.0), Sense::hover());
                ui.painter().rect_filled(r, 20, SOFT);
                ui.painter().galley(r.center() - g.size() / 2.0, g, MUTE);
            });
        });
    }

    fn haupt(&mut self, ui: &mut egui::Ui, anz: Anzeige) {
        let ziel = match anz {
            Anzeige::Verbunden => OK,
            Anzeige::Verbinde => ACC,
            Anzeige::Trenne => WARN,
            Anzeige::Aus => MUTE,
        };
        // Farbe weich umblenden, beim Verbinden kurz "ploppen"
        let jetzt_farbe = self.farbe.0.lerp_to_gamma(self.farbe.1, sanft(self.farbe.2.elapsed().as_secs_f32() / 0.35));
        if ziel != self.farbe.1 {
            self.farbe = (jetzt_farbe, ziel, Instant::now());
        }
        if anz == Anzeige::Verbunden && self.letzte_anz.is_some_and(|a| a != Anzeige::Verbunden) {
            self.plopp = Some(Instant::now());
        }
        if self.letzte_anz != Some(anz) {
            self.wechsel = Instant::now();
        }
        self.letzte_anz = Some(anz);
        self.wirbel_weiter(anz);
        let farbe = self.farbe.0.lerp_to_gamma(self.farbe.1, sanft(self.farbe.2.elapsed().as_secs_f32() / 0.35));
        ui.add_space(8.0);
        ui.vertical_centered(|ui| {
            if self.schalter(ui, anz, farbe) {
                self.klick = Some(Instant::now());
                match anz {
                    Anzeige::Aus => self.ausfuehren(Aktion::Verbinden),
                    Anzeige::Verbunden | Anzeige::Verbinde => self.ausfuehren(Aktion::Trennen),
                    Anzeige::Trenne => {}
                }
            }
            ui.add_space(4.0);
            let (titel, unter) = self.statustext(anz);
            ui.label(fett(titel, 26.0).color(if anz == Anzeige::Aus { INK } else { farbe }));
            ui.label(RichText::new(unter).color(MUTE).size(14.0));
        });
        ui.add_space(12.0);

        let z = self.z.clone().filter(|_| anz == Anzeige::Verbunden);
        // Download / Upload
        ui.columns(3, |c| {
            let rate = |r: u64, t: u64| (human_rate(r as f64), format!("ges. {}", human_bytes(t)));
            wert_karte(&mut c[0], "Download", DOWN, z.as_ref().map(|z| rate(z.rate_rx, z.rx)));
            wert_karte(&mut c[1], "Upload", UP, z.as_ref().map(|z| rate(z.rate_tx, z.tx)));
            let ping = z.as_ref().filter(|z| z.rtt_ms > 0.0).map(|z| (format!("{:.0} ms", z.rtt_ms), if z.via_proxy { "über Proxy".into() } else { "direkt".into() }));
            wert_karte(&mut c[2], "Ping", OK, ping);
        });
        ui.add_space(4.0);
        karte().inner_margin(Margin::same(10)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            self.graph(ui);
        });
        ui.add_space(4.0);

        if let Some(z) = self.z.as_ref().filter(|z| !z.update_version.is_empty() && z.update_size > 0) {
            let f = z.update_got as f32 / z.update_size as f32;
            karte().stroke(linie(1.0, ACC.gamma_multiply(0.6))).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.spacing_mut().item_spacing.y = 6.0;
                ui.label(fett(format!("Neue Version {} wird geladen", z.update_version), 15.0));
                ui.add(egui::ProgressBar::new(f).fill(ACC).desired_height(6.0).corner_radius(3));
                ui.label(RichText::new(format!("{} von {} – danach startet das VPN kurz neu", human_bytes(z.update_got), human_bytes(z.update_size))).color(MUTE).size(12.5));
            });
            ui.add_space(4.0);
        }

        if let Some(f) = self.problem(anz) {
            karte().fill(Color32::from_rgb(0x2a, 0x16, 0x1c)).stroke(linie(1.0, BAD.gamma_multiply(0.5))).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(fett("Problem", 15.0).color(BAD));
                ui.label(RichText::new(kvpn::fehler::klartext(&f)).size(13.5));
                if kvpn::fehler::klartext(&f) != f {
                    ui.label(RichText::new(format!("Technisch: {f}")).color(MUTE).size(11.5));
                }
                if ui.link("Protokoll ansehen").clicked() {
                    self.log = Some(self.st.protokoll());
                }
            });
            ui.add_space(4.0);
        }

        karte().inner_margin(Margin::symmetric(14, 10)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            self.details(ui, z.as_ref());
            if let Some(z) = z.as_ref().filter(|z| z.state == "connected") {
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    let sp = &z.speed;
                    let txt = crate::speed_text(sp);
                    let farbe = match sp.state.as_str() {
                        "fehler" => WARN,
                        "fertig" => INK,
                        _ => MUTE,
                    };
                    ui.label(RichText::new("Tempo").color(MUTE).size(13.5));
                    ui.add_space(10.0);
                    if sp.laeuft() {
                        ui.add(egui::Spinner::new().size(13.0).color(ACC));
                    }
                    if !txt.is_empty() {
                        ui.add(egui::Label::new(RichText::new(txt).color(farbe).size(13.5)).wrap());
                    }
                    if !sp.laeuft() {
                        let l = ui.add(egui::Label::new(RichText::new(if sp.state.is_empty() { "Geschwindigkeit testen" } else { "nochmal" }).color(ACC).size(13.5)).sense(Sense::click()));
                        if l.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Misst Ping, Download und Upload durch das VPN zu deinem Server (je 5 Sekunden)").clicked() {
                            if let Err(e) = self.st.geschwindigkeit() {
                                self.fehler = e;
                            }
                        }
                    }
                });
            }
        });
    }

    /// Wirbel weiterdrehen: Drehzahl, Sog und Staerke gleiten weich zum Ziel (kein Ruckeln beim Zustandswechsel).
    /// Verbinden: schneller Tornado nach innen, Trennen: dreht rueckwaerts nach aussen, verbunden: ruhiger Wirbel,
    /// aus: ganz leise. Ohne Fokus blendet er aus.
    fn wirbel_weiter(&mut self, anz: Anzeige) {
        let dt = self.wirbel_t.elapsed().as_secs_f32().min(0.1);
        self.wirbel_t = Instant::now();
        let (st, w, zug) = match anz {
            Anzeige::Verbinde => (1.0, 4.5, 0.9),
            Anzeige::Trenne => (0.8, -3.5, -0.7),
            Anzeige::Verbunden => (0.6, 1.1, 0.22),
            Anzeige::Aus => (0.3, 0.7, 0.15),
        };
        let st = if self.lebhaft { st } else { 0.0 };
        let f = (dt * 2.5).min(1.0);
        let v = &mut self.wirbel;
        v[2] += (w - v[2]) * f;
        v[3] += (st - v[3]) * f;
        v[4] += (zug - v[4]) * f;
        v[0] = (v[0] + v[2] * dt) % (2.0 * std::f32::consts::PI);
        v[1] = (v[1] + v[4] * dt).rem_euclid(1.0);
    }

    /// grosser runder Ein/Aus-Knopf. true = angeklickt
    fn schalter(&self, ui: &mut egui::Ui, anz: Anzeige, farbe: Color32) -> bool {
        // Flaeche 184 (Platz fuer den Wirbel), klickbar ist nur der Knopf (Radius 60)
        let (rect, _) = ui.allocate_exact_size(vec2(184.0, 184.0), Sense::hover());
        let resp = ui.interact(Rect::from_center_size(rect.center(), vec2(130.0, 130.0)), egui::Id::new("knopf"), Sense::click());
        let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(match anz {
            Anzeige::Aus => "Verbinden",
            Anzeige::Trenne => "Wird getrennt …",
            _ => "Trennen",
        });
        let p = ui.painter();
        let c = rect.center();
        let t = self.start.elapsed().as_secs_f32();
        let hover = resp.hovered() && anz != Anzeige::Trenne;
        // Druecken federt ein, beim Verbinden ploppt der Knopf kurz auf
        let gedrueckt = resp.is_pointer_button_down_on() && anz != Anzeige::Trenne;
        let druck = ui.ctx().animate_value_with_time(egui::Id::new("knopf-druck"), if gedrueckt { 0.93 } else { 1.0 }, 0.12);
        let plopp = self.plopp.map(|s| s.elapsed().as_secs_f32() / 0.6).filter(|x| *x < 1.0).map(|x| 1.0 + 0.07 * (x * std::f32::consts::PI).sin() * (1.0 - x)).unwrap_or(1.0);
        let hv = ui.ctx().animate_bool_with_time(egui::Id::new("knopf-hover"), hover, 0.15);
        // Fenster im Fokus: mehr Bewegung. Aus: laedt sanft zum Klicken ein (leichtes Atmen, alle 4 s eine leise Welle)
        let lebhaft = self.lebhaft;
        let pi = std::f32::consts::PI;
        let einladen = if lebhaft && anz == Anzeige::Aus { 0.5 - 0.5 * (t * 2.0 * pi / 4.0).cos() } else { 0.0 };
        let k = druck * plopp * (1.0 + 0.012 * einladen);
        // Wellen, die vom Knopf weglaufen
        let welle = |x: f32, f: Color32, a: f32, b: f32| {
            let e = 1.0 - (1.0 - x) * (1.0 - x);
            p.circle_stroke(c, (60.0 + 17.0 * e) * k, linie(b * (1.0 - 0.5 * x), f.gamma_multiply(a * (1.0 - x) * (1.0 - x))));
        };
        if lebhaft {
            match anz {
                Anzeige::Verbunden => (0..2).for_each(|i| welle(((t + i as f32 * 1.4) % 2.8) / 2.8, farbe, 0.4, 2.5)),
                Anzeige::Verbinde | Anzeige::Trenne => {} // dort dreht sich der Wirbel
                Anzeige::Aus => {
                    let x = ((t + 2.0) % 4.0) / 1.8;
                    if x < 1.0 {
                        welle(x, ACC, 0.16, 2.0);
                    }
                }
            }
        }
        if let Some(x) = self.klick.map(|s| s.elapsed().as_secs_f32() / 0.6).filter(|x| *x < 1.0) {
            welle(x, if anz == Anzeige::Aus { ACC } else { farbe }, 0.55, 3.5);
        }
        // Leuchten (verbinden: pulsiert, verbunden: atmet ruhig)
        let an = anz != Anzeige::Aus;
        if an {
            let puls = if anz == Anzeige::Verbunden { 0.55 + 0.25 * (t * 1.7).sin() } else { 0.5 + 0.5 * (t * 3.0).sin() };
            for (r, a) in [(77.0, 0.05), (71.0, 0.08), (65.0, 0.12)] {
                p.circle_filled(c, r * k, farbe.gamma_multiply(a * (0.6 + 0.4 * puls)));
            }
        }
        // Wirbel (Tornado): Spiralarme drehen sich um den Knopf, Teilchen werden hineingezogen
        let [dreh, sog, _, st, _] = self.wirbel;
        if st > 0.01 {
            let wf = if anz == Anzeige::Aus { MUTE.lerp_to_gamma(ACC, 0.5) } else { farbe };
            let hell = wf.lerp_to_gamma(Color32::WHITE, 0.3);
            let punkt = |r: f32, a: f32| c + vec2(a.cos(), a.sin()) * r * k;
            for arm in 0..3 {
                let a0 = dreh + arm as f32 * 2.0 * pi / 3.0;
                let n = 16;
                for j in 0..n {
                    let (s0, s1) = (j as f32 / n as f32, (j + 1) as f32 / n as f32);
                    let sm = (s0 + s1) / 2.0;
                    let fluss = 0.6 + 0.4 * (2.0 * pi * (sm * 2.0 + sog * 3.0)).sin();
                    let a = st * 0.7 * (pi * sm).sin() * fluss;
                    p.line_segment([punkt(62.0 + 29.0 * s0, a0 - s0 * 2.6), punkt(62.0 + 29.0 * s1, a0 - s1 * 2.6)], linie(2.5 - s0, wf.gamma_multiply(a)));
                }
            }
            for i in 0..34 {
                let q = (sog + i as f32 * 0.618_034).rem_euclid(1.0);
                let a = i as f32 * 2.399_963 + dreh + q * 2.5;
                p.circle_filled(punkt(91.0 - 29.0 * q, a), (1.0 + 1.5 * (1.0 - q)) * k, hell.gamma_multiply(st * 0.9 * (pi * q).sin()));
            }
        }
        let innen = CARD.lerp_to_gamma(Color32::from_rgb(0x1f, 0x23, 0x2c), hv);
        p.circle_filled(c, 60.0 * k, innen);
        p.circle_stroke(c, 60.0 * k, linie(1.0, LINE));
        // Ring
        match anz {
            Anzeige::Verbunden => {
                p.circle_stroke(c, 60.0 * k, linie(5.0, farbe));
                if lebhaft {
                    // Lichtpunkt mit Schweif kreist langsam um den Ring
                    let hell = farbe.lerp_to_gamma(Color32::WHITE, 0.65);
                    let kopf = t * 1.3;
                    // uebereinander gelegte Boegen, die alle am Kopf enden: vorne hell, hinten weich auslaufend
                    for i in 1..=10 {
                        bogen(p, c, 60.0 * k, kopf - i as f32 * 0.11, kopf, linie(5.0, hell.gamma_multiply(0.16)));
                    }
                }
            }
            Anzeige::Verbinde | Anzeige::Trenne => {
                p.circle_stroke(c, 60.0 * k, linie(5.0, farbe.gamma_multiply(0.18)));
                let a0 = t * 4.0;
                // lebhaft: Bogen wird laenger und kuerzer (wie ein Ladekreis)
                let lang = if lebhaft { 0.52 + 3.3 * (0.5 - 0.5 * (t * 2.4).cos()) } else { 1.6 };
                bogen(p, c, 60.0 * k, a0, a0 + lang, linie(5.0, farbe));
            }
            Anzeige::Aus => {
                let ring = LINE.lerp_to_gamma(ACC, 0.35 * einladen);
                p.circle_stroke(c, 60.0 * k, linie(5.0, ring.lerp_to_gamma(ACC.gamma_multiply(0.7), hv)));
            }
        }
        // Symbol (Ein/Aus)
        let sym = match anz {
            Anzeige::Aus => MUTE.lerp_to_gamma(ACC, hv),
            _ => farbe,
        };
        let s = linie(5.5, sym);
        // lebhaft: nach dem Verbinden zeichnet sich das Zeichen neu (Strich von oben, Bogen von beiden Seiten)
        let neu = if lebhaft && anz == Anzeige::Verbunden { (self.wechsel.elapsed().as_secs_f32() / 0.7).min(1.0) } else { 1.0 };
        let neu = 1.0 - (1.0 - neu).powi(3);
        let m = c + vec2(0.0, 3.0 * k);
        let (b0, b1) = (-pi / 2.0 + 0.75, -pi / 2.0 + 2.0 * pi - 0.75);
        if neu >= 1.0 {
            bogen(p, m, 24.0 * k, b0, b1, s);
        } else if neu > 0.0 {
            let halb = (b1 - b0) / 2.0 * neu;
            bogen(p, m, 24.0 * k, b0, b0 + halb, s);
            bogen(p, m, 24.0 * k, b1 - halb, b1, s);
        }
        let unten = -26.0 + 22.0 * (neu * 1.6).clamp(0.05, 1.0);
        p.line_segment([c + vec2(0.0, -26.0 * k), c + vec2(0.0, unten * k)], s);
        p.circle_filled(c + vec2(0.0, -26.0 * k), 2.6, sym);
        p.circle_filled(c + vec2(0.0, unten * k), 2.6, sym);
        resp.clicked() && anz != Anzeige::Trenne
    }

    fn statustext(&self, anz: Anzeige) -> (String, String) {
        let z = self.z.as_ref();
        // automatisch schuetzen: im vertrauten Netz pausiert
        if let (Lage::Laeuft, Some(z)) = (self.lage, z) {
            if z.state == "paused" && self.arbeit.is_none() {
                return ("Pausiert".into(), z.error.clone());
            }
        }
        match anz {
            Anzeige::Verbunden => {
                let z = z.unwrap();
                let seit = kvpn::util::now_secs().saturating_sub(z.since);
                let weg = if z.via_proxy { " · über Proxy" } else { "" };
                ("Verbunden".into(), format!("seit {}{weg}", dauer(seit)))
            }
            Anzeige::Verbinde => {
                let unter = match (&self.arbeit, z) {
                    (Some(_), _) if self.lage != Lage::Laeuft => "VPN-Dienst wird gestartet …".to_string(),
                    (_, Some(z)) if !z.error.is_empty() => z.error.clone(),
                    (_, Some(z)) if z.state == "waiting" => "Neuer Versuch gleich …".into(),
                    _ => "Verbindung wird aufgebaut …".into(),
                };
                ("Verbinde …".into(), unter)
            }
            Anzeige::Trenne => ("Trenne …".into(), "Verbindung wird beendet".into()),
            Anzeige::Aus => ("Nicht verbunden".into(), "Zum Verbinden auf den Knopf klicken".into()),
        }
    }

    fn problem(&self, anz: Anzeige) -> Option<String> {
        if !self.fehler.is_empty() {
            return Some(self.fehler.clone());
        }
        if self.arbeit.is_some() {
            return None;
        }
        if self.laeuft_ohne_status.is_some_and(|t| t.elapsed() > Duration::from_secs(15)) {
            return Some("Der VPN-Dienst läuft, meldet sich aber nicht. Details stehen im Protokoll.".into());
        }
        if anz == Anzeige::Aus && self.gewollt && self.lage == Lage::Aus {
            let log = self.st.protokoll();
            let letzte = log.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").to_string();
            let letzte = letzte.split_once(" UTC ").map(|x| x.1.to_string()).unwrap_or(letzte);
            return Some(if letzte.is_empty() { "Der VPN-Dienst wurde beendet.".into() } else { format!("Der VPN-Dienst wurde beendet: {letzte}") });
        }
        None
    }

    fn graph(&self, ui: &mut egui::Ui) {
        let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 70.0), Sense::hover());
        let p = ui.painter_at(rect.expand(2.0));
        for i in 0..=3 {
            let y = rect.top() + rect.height() * i as f32 / 3.0;
            p.line_segment([pos2(rect.left(), y), pos2(rect.right(), y)], linie(1.0, Color32::from_rgb(0x20, 0x24, 0x2d)));
        }
        let max = self.verlauf.iter().map(|(a, b)| a.max(*b)).fold(16.0 * 1024.0, f32::max) * 1.15;
        let n = self.verlauf.len();
        if n >= 2 {
            let x = |i: usize| rect.right() - (n - 1 - i) as f32 * rect.width() / (VERLAUF - 1) as f32;
            let y = |v: f32| rect.bottom() - (v / max).min(1.0) * rect.height();
            for (sel, col) in [(0usize, DOWN), (1, UP)] {
                let pts: Vec<Pos2> = self.verlauf.iter().enumerate().map(|(i, v)| pos2(x(i), y(if sel == 0 { v.0 } else { v.1 }))).collect();
                // Flaeche unter der Kurve (Streifen, damit sie auch bei Spitzen korrekt gefuellt ist)
                let fill = col.gamma_multiply(0.16);
                for w in pts.windows(2) {
                    let poly = vec![w[0], w[1], pos2(w[1].x, rect.bottom()), pos2(w[0].x, rect.bottom())];
                    p.add(egui::Shape::convex_polygon(poly, fill, Stroke::NONE));
                }
                p.add(egui::Shape::line(pts, linie(2.0, col)));
            }
        } else {
            p.text(rect.center(), egui::Align2::CENTER_CENTER, "noch keine Daten", FontId::proportional(13.0), MUTE.gamma_multiply(0.7));
        }
        p.text(rect.left_top() + vec2(2.0, 2.0), egui::Align2::LEFT_TOP, human_rate(max as f64 / 1.15), FontId::proportional(11.0), MUTE.gamma_multiply(0.8));
        p.text(rect.right_top() + vec2(-2.0, 2.0), egui::Align2::RIGHT_TOP, format!("letzte {VERLAUF} s"), FontId::proportional(11.0), MUTE.gamma_multiply(0.8));
    }

    fn details(&self, ui: &mut egui::Ui, z: Option<&Zustand>) {
        let server = z.map(|z| z.server.clone()).filter(|s| !s.is_empty()).or_else(|| self.cfg.as_ref().map(|c| host(&c.url))).unwrap_or_default();
        let zeilen: Vec<(&str, String, Color32)> = match z {
            Some(z) => vec![
                ("Server", server, INK),
                (
                    "Schutz",
                    if z.tls_trusted { "TLS 1.3 + Noise – verschlüsselt".into() } else { format!("Firewall prüft HTTPS ({}) – Daten bleiben trotzdem verschlüsselt", z.tls_issuer) },
                    if z.tls_trusted { OK } else { WARN },
                ),
                (
                    "Daten",
                    if z.cipher.is_empty() { "–".into() } else { format!("{} · Tarnung aktiv", z.cipher) },
                    INK,
                ),
            ],
            None => vec![("Server", server, INK), ("Schutz", "nicht aktiv – Datenverkehr geht direkt ins Internet".into(), MUTE)],
        };
        egui::Grid::new("details").num_columns(2).spacing(vec2(16.0, 6.0)).min_row_height(20.0).show(ui, |ui| {
            for (k, v, c) in zeilen {
                let tipp = match k {
                    "Schutz" => "HTTPS-Hülle (TLS 1.3) + Geräte-Schlüssel (Noise): nur dein Server und deine Geräte können die Daten lesen.",
                    "Daten" => "Verfahren, mit dem deine Daten verschlüsselt werden (änderbar unter „Sicherheit“). Tarnung = Paketgrößen und Takt wechseln, damit Firewalls kein VPN-Muster erkennen.",
                    _ => "",
                };
                let a = ui.label(RichText::new(k).color(MUTE).size(13.5));
                let b = ui.add(egui::Label::new(RichText::new(v).color(c).size(13.5)).wrap());
                if !tipp.is_empty() {
                    a.on_hover_text(tipp);
                    b.on_hover_text(tipp);
                }
                ui.end_row();
            }
        });
    }

    fn fuss(&mut self, ui: &mut egui::Ui) {
        ui.spacing_mut().button_padding.x = 6.0;
        ui.columns(4, |c| {
            if c[1].add_sized([c[1].available_width(), 36.0], knopf("Schutz", false))
                .on_hover_text("Notbremse (ohne VPN kein Internet), automatisch schützen in fremden WLANs, Ausnahmen am VPN vorbei")
                .clicked()
            {
                let r = self.st.regeln();
                let t = r.ziele.join("\n");
                self.schutz = Some((r, t, self.st.netz(), String::new()));
            }
            if c[0].add_sized([c[0].available_width(), 36.0], knopf("Sicherheit", false)).on_hover_text("Was deine Daten schützt – und Verschlüsselung wählen (Auto, AES-256, ChaCha20)").clicked() {
                self.wahl = self.st.verschluesselung();
                self.zeige_sicherheit = true;
            }
            if c[2].add_sized([c[2].available_width(), 36.0], knopf("Protokoll", false)).clicked() {
                self.log = Some(self.st.protokoll());
            }
            let t = if self.profile.len() > 1 { format!("Profile ({})", self.profile.len()) } else { "Profile".into() };
            if c[3].add_sized([c[3].available_width(), 36.0], knopf(&t, false)).on_hover_text("Zwischen Verbindungen wechseln oder eine neue hinzufügen").clicked() {
                self.zeige_profile = true;
            }
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Fenster darf zu – VPN läuft weiter.").color(MUTE).size(12.5));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let l = ui.add(egui::Label::new(RichText::new("Klassische Ansicht").color(ACC).size(12.5)).sense(Sense::click()));
                if l.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Zur alten Text-Ansicht wechseln (zurück mit  f + Enter)").clicked() {
                    match self.st.klassisch() {
                        Ok(()) => ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close),
                        Err(e) => self.fehler = format!("Klassische Ansicht: {e}"),
                    }
                }
            });
        });
    }

    fn code_eingabe(&mut self, ui: &mut egui::Ui) {
        ui.add_space(26.0);
        karte().inner_margin(Margin::same(20)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(fett(if self.cfg.is_none() { "Willkommen!" } else { "Profil hinzufügen" }, 22.0));
            ui.add_space(2.0);
            ui.label(RichText::new("Füge deinen Verbindungscode ein. Er beginnt mit kronevpn://v1/ …").color(MUTE));
            ui.label(RichText::new("Den Code bekommst du vom Server-Admin (kvpn-server add \"Mein PC\").").color(MUTE).size(13.0));
            ui.add_space(8.0);
            let r = ui.add(
                egui::TextEdit::multiline(&mut self.eingabe)
                    .hint_text("kronevpn://v1/…   (Strg+V zum Einfügen)")
                    .font(FontId::monospace(12.5))
                    .desired_rows(5)
                    .desired_width(f32::INFINITY)
                    .margin(Margin::same(10)),
            );
            if self.start.elapsed() < Duration::from_millis(300) {
                r.request_focus();
            }
            if !self.eingabe_fehler.is_empty() {
                ui.label(RichText::new(&self.eingabe_fehler).color(BAD).size(13.5));
            }
            ui.add_space(6.0);
            let leer = self.eingabe.trim().is_empty();
            if ui.add_enabled(!leer, knopf(if self.cfg.is_none() { "Verbinden" } else { "Hinzufügen und verbinden" }, true).min_size(vec2(ui.available_width(), 42.0))).clicked() {
                self.code_uebernehmen();
            }
            if self.cfg.is_some() && ui.add(knopf("Abbrechen", false).min_size(vec2(ui.available_width(), 38.0))).clicked() {
                self.code_aendern = false;
                self.eingabe.clear();
                self.eingabe_fehler.clear();
            }
        });
        ui.add_space(10.0);
        ui.vertical_centered(|ui| {
            let t = if self.cfg.is_none() {
                "Danach läuft das VPN als Windows-Dienst im Hintergrund\nund startet automatisch mit Windows."
            } else {
                "Ein Profil pro Code – z. B. für verschiedene Server.\nWechseln jederzeit über „Profile“."
            };
            ui.label(RichText::new(t).color(MUTE).size(12.5));
        });
    }

    fn schutz_dialog(&mut self, ctx: &egui::Context, breite: f32) {
        let hoehe = (ctx.screen_rect().height() - 110.0).max(240.0);
        let mut zu = false;
        let mut speichern = false;
        let Some((r, ziele, netz, msg)) = self.schutz.as_mut() else { return };
        let schalter = |ui: &mut egui::Ui, an: &mut bool, titel: &str, text: &str, aktiv: bool| {
            ui.add_enabled_ui(aktiv, |ui| {
                ui.horizontal_top(|ui| {
                    ui.checkbox(an, "");
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 1.0;
                        ui.label(fett(titel, 14.5));
                        ui.add(egui::Label::new(RichText::new(text).color(MUTE).size(12.5)).wrap());
                    });
                });
            });
            ui.add_space(6.0);
        };
        let modal = egui::Modal::new(egui::Id::new("schutz")).show(ctx, |ui| {
            ui.set_width(breite.min(460.0));
            egui::ScrollArea::vertical().max_height(hoehe).min_scrolled_height(hoehe.min(520.0)).show(ui, |ui| {
                ui.label(fett("Schutz", 19.0));
                ui.label(RichText::new("Wann das VPN läuft und was ohne VPN passieren darf.").color(MUTE).size(13.0));
                ui.add_space(8.0);
                schalter(ui, &mut r.notbremse, "Notbremse (Kill-Switch)",
                    "Fällt das VPN aus (Funkloch, Server weg), geht gar nichts mehr ins Internet – nichts läuft unverschlüsselt daran vorbei. Hotel-/Zug-WLAN mit Anmeldeseite: kurz ausschalten, anmelden, wieder an.", true);
                let nb = r.notbremse;
                ui.indent("lokal", |ui| {
                    schalter(ui, &mut r.lokal_erlaubt, "Lokales Netz erlauben", "Drucker, Router-Seite, Fernseher im selben WLAN bleiben trotz Notbremse erreichbar. Namen (DNS) gehen trotzdem nur durchs VPN.", nb);
                });
                schalter(ui, &mut r.auto, "Automatisch schützen",
                    "In fremden WLANs und im Mobilfunk verbindet sich das VPN von selbst. In deinen vertrauten Netzen (z. B. zu Hause) pausiert es – dort bist du ja schon sicher.", true);
                ui.indent("vertraut", |ui| {
                    ui.add_enabled_ui(r.auto, |ui| {
                        ui.label(RichText::new("Vertraute Netze").color(INK).size(13.0).strong());
                        let mut weg = None;
                        if r.vertraut.is_empty() {
                            ui.label(RichText::new("noch keine").color(MUTE).size(12.5));
                        }
                        for (i, v) in r.vertraut.iter().enumerate() {
                            ui.horizontal(|ui| {
                                let t = v.strip_prefix("router:").map(|m| format!("Netz mit Router {m}")).unwrap_or_else(|| format!("WLAN „{v}“"));
                                ui.label(RichText::new(t).size(12.5));
                                if ui.small_button("entfernen").on_hover_text("nicht mehr vertrauen").clicked() {
                                    weg = Some(i);
                                }
                            });
                        }
                        if let Some(i) = weg {
                            r.vertraut.remove(i);
                        }
                        let schon = r.ist_vertraut(netz);
                        let t = if !netz.online { "Kein Netz erkannt".to_string() } else if schon { format!("{} ist vertraut ✓", netz.anzeige()) } else { format!("Diesem Netz vertrauen: {}", netz.anzeige()) };
                        if ui.add_enabled(netz.online && !schon && !netz.kennungen().is_empty(), egui::Button::new(RichText::new(t).size(12.5))).clicked() {
                            r.vertrauen(netz);
                        }
                    });
                });
                ui.add_space(8.0);
                ui.label(fett("Am VPN vorbei (Ausnahmen)", 14.5));
                ui.add(egui::Label::new(RichText::new("Diese Ziele gehen direkt ins Internet, nicht durchs VPN – z. B. eine Bank, die VPN-Verbindungen sperrt. Ein Eintrag pro Zeile: Name (bank.de), Adresse (203.0.113.5) oder Netz (198.51.100.0/24). Einzelne Programme lassen sich unter Windows nicht ausnehmen (das ginge nur mit einem eigenen Treiber); auf dem Handy geht das pro App.").color(MUTE).size(12.5)).wrap());
                ui.add(egui::TextEdit::multiline(ziele).desired_rows(3).desired_width(f32::INFINITY).hint_text("bank.de"));
                if !msg.is_empty() {
                    ui.label(RichText::new(msg.as_str()).color(BAD).size(12.5));
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let w = (ui.available_width() - 8.0) / 2.0;
                    if ui.add(knopf("Speichern", true).min_size(vec2(w, 38.0))).clicked() {
                        speichern = true;
                    }
                    if ui.add(knopf("Abbrechen", false).min_size(vec2(w, 38.0))).clicked() {
                        zu = true;
                    }
                });
            });
        });
        if speichern {
            match kvpn::regeln::ziele_pruefen(ziele) {
                Ok(z) => {
                    r.ziele = z;
                    match self.st.regeln_speichern(r) {
                        Ok(()) => zu = true,
                        Err(e) => *msg = e,
                    }
                }
                Err(e) => *msg = e,
            }
        }
        if zu || modal.should_close() {
            self.schutz = None;
        }
    }

    fn dialoge(&mut self, ctx: &egui::Context) {
        let breite = (ctx.screen_rect().width() - 48.0).clamp(280.0, 560.0);
        if self.zeige_sicherheit {
            let mut zu = false;
            let mut neu = None;
            let aes_hw = self.z.as_ref().map(|z| z.aes_hw).unwrap_or_else(kvpn::crypto::aes_hw);
            let laeuft = self.z.as_ref().filter(|z| z.state == "connected").map(|z| z.cipher.clone()).filter(|c| !c.is_empty());
            let hoehe = (ctx.screen_rect().height() - 110.0).max(240.0);
            let r = egui::Modal::new(egui::Id::new("sicherheit")).show(ctx, |ui| {
                ui.set_width(breite.min(440.0));
                egui::ScrollArea::vertical().max_height(hoehe).min_scrolled_height(hoehe).show(ui, |ui| {
                ui.label(fett("Sicherheit", 19.0));
                ui.label(RichText::new(SICHER_INTRO).color(MUTE).size(13.0));
                ui.add_space(8.0);
                ui.label(fett("Verschlüsselung wählen", 14.5));
                ui.add_space(2.0);
                let auto_txt = if aes_hw { "Die App nimmt automatisch das schnellste Verfahren für dieses Gerät – hier AES-256-GCM, weil der Prozessor AES-Befehle hat. Passt fast immer." } else { "Die App nimmt automatisch das schnellste Verfahren für dieses Gerät – hier ChaCha20, weil der Prozessor keine AES-Befehle hat. Passt fast immer." };
                let aes_txt = if aes_hw { "Weltweiter Standard (Banken, Behörden, HTTPS). Auf diesem PC sehr schnell, weil der Prozessor AES direkt beherrscht." } else { "Weltweiter Standard (Banken, Behörden, HTTPS). Auf diesem PC langsamer, weil dem Prozessor die AES-Befehle fehlen." };
                for (w, titel, unter) in [
                    ("auto", "Auto (empfohlen)", auto_txt),
                    ("aes", "AES-256-GCM", aes_txt),
                    ("chacha", "ChaCha20-Poly1305", "Moderner Standard (auch in WireGuard). Auf jedem Gerät schnell, auch auf älteren ohne AES-Befehle."),
                ] {
                    let an = self.wahl == w;
                    let resp = egui::Frame::new()
                        .fill(if an { Color32::from_rgb(0x18, 0x20, 0x33) } else { SOFT })
                        .stroke(linie(1.0, if an { ACC.gamma_multiply(0.8) } else { LINE }))
                        .corner_radius(12)
                        .inner_margin(Margin::symmetric(12, 10))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                let (r, _) = ui.allocate_exact_size(vec2(18.0, 18.0), Sense::hover());
                                ui.painter().circle_stroke(r.center(), 8.0, linie(1.5, if an { ACC } else { MUTE }));
                                if an {
                                    ui.painter().circle_filled(r.center(), 4.5, ACC);
                                }
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = 1.0;
                                    ui.label(fett(titel, 15.0));
                                    ui.add(egui::Label::new(RichText::new(unter).color(MUTE).size(12.5)).wrap());
                                });
                            });
                        })
                        .response;
                    if ui.interact(resp.rect, egui::Id::new(("wahl", w)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                        neu = Some(w);
                    }
                    ui.add_space(2.0);
                }
                let info = if self.wahl_arbeit.is_some() {
                    "Wird übernommen – das VPN verbindet sich kurz neu …".to_string()
                } else if let Some(c) = &laeuft {
                    format!("Jetzt aktiv: {c}. Ein Wechsel verbindet das VPN kurz neu (1–2 s).")
                } else {
                    "Gilt ab der nächsten Verbindung.".to_string()
                };
                ui.label(RichText::new(info).color(if laeuft.is_some() { OK } else { MUTE }).size(12.5));
                ui.label(RichText::new("Wann umstellen? Eigentlich nie – nur zum Ausprobieren, falls die Verbindung langsam ist.").color(MUTE).size(12.5));
                ui.add_space(10.0);
                ui.label(fett("Immer aktiv (nicht abschaltbar)", 14.5));
                ui.add_space(2.0);
                for (titel, text) in IMMER_AKTIV {
                    ui.horizontal_top(|ui| {
                        ui.label(RichText::new("✔").color(OK).size(13.0));
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            ui.label(RichText::new(titel).color(INK).size(13.0).strong());
                            ui.add(egui::Label::new(RichText::new(text).color(MUTE).size(12.5)).wrap());
                        });
                    });
                    ui.add_space(3.0);
                }
                ui.add_space(6.0);
                if ui.add(knopf("Schließen", false).min_size(vec2(ui.available_width(), 38.0))).clicked() {
                    zu = true;
                }
                });
            });
            if let Some(w) = neu {
                self.wahl_setzen(w);
            }
            if zu || r.should_close() {
                self.zeige_sicherheit = false;
            }
        }
        if self.schutz.is_some() {
            self.schutz_dialog(ctx, breite);
        }
        if self.zeige_profile {
            let mut zu = false;
            let mut waehlen = None;
            let mut loeschen = None;
            let r = egui::Modal::new(egui::Id::new("profile")).show(ctx, |ui| {
                ui.set_width(breite.min(420.0));
                ui.label(fett("Profile", 19.0));
                ui.label(RichText::new("Jedes Profil ist ein eigener Verbindungscode (z. B. anderer Server oder anderes Gerät).").color(MUTE).size(13.0));
                ui.add_space(4.0);
                egui::ScrollArea::vertical().max_height((ctx.screen_rect().height() - 260.0).clamp(140.0, 420.0)).show(ui, |ui| {
                    for (i, p) in self.profile.iter().enumerate() {
                        let aktiv = self.ist_aktiv(p);
                        let rahmen = if aktiv { linie(1.0, OK.gamma_multiply(0.6)) } else { linie(1.0, LINE) };
                        egui::Frame::new().fill(if aktiv { Color32::from_rgb(0x15, 0x22, 0x1c) } else { SOFT }).stroke(rahmen).corner_radius(12).inner_margin(Margin::symmetric(12, 10)).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = 1.0;
                                    ui.label(fett(p.display_name(), 15.5));
                                    ui.label(RichText::new(format!("„{}“ · {}", p.name, host(&p.url))).color(MUTE).size(12.5));
                                });
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if aktiv {
                                        ui.label(RichText::new("aktiv").color(OK).size(13.0));
                                        let (r, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
                                        ui.painter().circle_filled(r.center(), 4.0, OK);
                                    } else {
                                        let x = ui.add(knopf("", false).min_size(vec2(34.0, 32.0))).on_hover_text("Profil entfernen");
                                        let (m, d) = (x.rect.center(), 5.0);
                                        let st = linie(1.8, if x.hovered() { BAD } else { MUTE });
                                        ui.painter().line_segment([m + vec2(-d, -d), m + vec2(d, d)], st);
                                        ui.painter().line_segment([m + vec2(-d, d), m + vec2(d, -d)], st);
                                        if x.clicked() {
                                            loeschen = Some(i);
                                        }
                                        if ui.add(knopf("Verwenden", true).min_size(vec2(0.0, 32.0))).clicked() {
                                            waehlen = Some(p.clone());
                                        }
                                    }
                                });
                            });
                        });
                        ui.add_space(2.0);
                    }
                });
                ui.add_space(4.0);
                ui.columns(2, |c| {
                    if c[0].add_sized([c[0].available_width(), 38.0], knopf("+ Hinzufügen", false)).clicked() {
                        self.code_aendern = true;
                        self.eingabe_fehler.clear();
                        zu = true;
                    }
                    if c[1].add_sized([c[1].available_width(), 38.0], knopf("Schließen", false)).clicked() {
                        zu = true;
                    }
                });
            });
            if let Some(i) = loeschen {
                self.profile.remove(i);
                self.st.profile_speichern(&self.profile);
            }
            if let Some(c) = waehlen {
                self.profil_waehlen(c, false);
                zu = true;
            }
            if zu || r.should_close() {
                self.zeige_profile = false;
            }
        }
        if let Some(log) = &self.log {
            let mut zu = false;
            let mut neu = false;
            let r = egui::Modal::new(egui::Id::new("log")).show(ctx, |ui| {
                ui.set_width(breite);
                ui.label(fett("Protokoll", 19.0));
                ui.add_space(4.0);
                egui::Frame::new().fill(Color32::from_rgb(0x0b, 0x0d, 0x11)).corner_radius(8).inner_margin(Margin::same(10)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::ScrollArea::vertical().max_height((ctx.screen_rect().height() - 220.0).clamp(160.0, 460.0)).stick_to_bottom(true).show(ui, |ui| {
                        let text = if log.trim().is_empty() { "(noch leer)" } else { log.as_str() };
                        ui.add(egui::Label::new(RichText::new(text).monospace().size(11.5).color(MUTE)).wrap().selectable(true));
                    });
                });
                ui.add_space(4.0);
                ui.columns(3, |c| {
                    if c[0].add_sized([c[0].available_width(), 36.0], knopf("Neu laden", false)).clicked() {
                        neu = true;
                    }
                    if c[1].add_sized([c[1].available_width(), 36.0], knopf("Im Editor", false)).clicked() {
                        self.st.protokoll_oeffnen();
                    }
                    if c[2].add_sized([c[2].available_width(), 36.0], knopf("Schließen", true)).clicked() {
                        zu = true;
                    }
                });
            });
            if neu {
                self.log = Some(self.st.protokoll());
            }
            if zu || r.should_close() {
                self.log = None;
            }
        }
    }
}

fn wert_karte(ui: &mut egui::Ui, titel: &str, farbe: Color32, w: Option<(String, String)>) {
    karte().inner_margin(Margin::symmetric(12, 12)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.spacing_mut().item_spacing.y = 2.0;
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
            ui.painter().circle_filled(r.center(), 4.0, farbe);
            ui.label(RichText::new(titel).color(MUTE).size(13.0));
        });
        ui.add_space(2.0);
        match w {
            Some((gross, klein)) => {
                // Zahl gross, Einheit klein daneben ("36.8 Mbit/s")
                let (zahl, einheit) = gross.split_once(' ').unwrap_or((gross.as_str(), ""));
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 3.0;
                    ui.add(egui::Label::new(fett(zahl, 19.0)).extend());
                    ui.add(egui::Label::new(RichText::new(einheit).color(MUTE).size(12.0)).extend());
                });
                ui.add(egui::Label::new(RichText::new(klein).color(MUTE).size(12.0)).truncate());
            }
            None => {
                ui.label(fett("–", 19.0).color(MUTE));
                ui.label(RichText::new(" ").size(12.0));
            }
        }
    });
}

fn bogen(p: &egui::Painter, c: Pos2, r: f32, a0: f32, a1: f32, s: Stroke) {
    let n = ((a1 - a0).abs() * r / 3.0).ceil().max(4.0) as usize;
    let pts: Vec<Pos2> = (0..=n).map(|i| {
        let a = a0 + (a1 - a0) * i as f32 / n as f32;
        c + vec2(a.cos(), a.sin()) * r
    }).collect();
    p.add(egui::Shape::line(pts, s));
}

// ------------------------------------------------------------------------------------------------ Vorschau (Linux)

#[cfg(feature = "vorschau")]
pub fn vorschau(modus: &str) {
    use std::sync::Mutex;
    struct Demo {
        modus: String,
        t0: Instant,
        an: Mutex<bool>,
        profile: Mutex<Vec<ClientConfig>>,
        wahl: Mutex<String>,
        regeln: Mutex<kvpn::regeln::Regeln>,
        tempo: Mutex<Option<Instant>>,
    }
    impl Steuerung for Demo {
        fn geschwindigkeit(&self) -> Result<(), String> {
            *self.tempo.lock().unwrap() = Some(Instant::now());
            Ok(())
        }
        fn regeln(&self) -> kvpn::regeln::Regeln {
            self.regeln.lock().unwrap().clone()
        }
        fn regeln_speichern(&self, r: &kvpn::regeln::Regeln) -> Result<(), String> {
            *self.regeln.lock().unwrap() = r.clone();
            Ok(())
        }
        fn netz(&self) -> kvpn::regeln::Netz {
            kvpn::regeln::Netz { online: true, wlan: "FRITZ!Box 7590".into(), router: "3c:a6:2f:12:34:56".into() }
        }
        fn logo_ordner(&self) -> Option<std::path::PathBuf> {
            std::env::var_os("KVPN_VORSCHAU_LOGO").map(std::path::PathBuf::from)
        }
        fn lage(&self) -> Lage {
            match (self.modus.as_str(), *self.an.lock().unwrap()) {
                (_, false) => Lage::Aus,
                _ => Lage::Laeuft,
            }
        }
        fn zustand(&self) -> Option<Zustand> {
            if !*self.an.lock().unwrap() {
                return None;
            }
            let t = self.t0.elapsed().as_secs_f64();
            let state = match self.modus.as_str() {
                "verbinde" => "waiting",
                "pause" => "paused",
                _ => "connected",
            };
            let rx = (2.5e6 * (1.2 + (t * 0.7).sin()) + 4e5 * (t * 3.1).sin().abs()) as u64;
            let tx = (2.4e5 * (1.1 + (t * 0.5).cos())) as u64;
            Some(Zustand {
                state: state.into(),
                title: "KroneVPN".into(),
                name: "Mein PC".into(),
                version: if self.modus == "neustart" { "99.0.0".into() } else { kvpn::VERSION.into() },
                server: "203.0.113.10:443".into(),
                via_proxy: self.modus == "fehler",
                tls_trusted: self.modus != "fehler",
                tls_issuer: "Sophos SSL CA_ABC123".into(),
                rx: 1_843_000_000 + (t * 2e6) as u64,
                tx: 211_000_000 + (t * 2e5) as u64,
                rate_rx: rx,
                rate_tx: tx,
                rtt_ms: 23.0 + (t * 2.0).sin() * 3.0,
                since: kvpn::util::now_secs() - 4_391,
                error: if state == "waiting" {
                    kvpn::fehler::klartext("203.0.113.10:443: keine Antwort (Firewall?)")
                } else if state == "paused" {
                    "Vertrautes Netz: WLAN „FRITZ!Box 7590“ – in fremden Netzen verbindet es sich von selbst".into()
                } else {
                    String::new()
                },
                error_detail: if state == "waiting" { "203.0.113.10:443: keine Antwort (Firewall?)".into() } else { String::new() },
                update_version: if self.modus == "update" { "1.0.4".into() } else { String::new() },
                update_got: 3_100_000,
                update_size: 7_400_000,
                ts: (t * 4.0) as u64 + 1,
                cipher: "AES-256-GCM".into(),
                cipher_choice: "auto".into(),
                aes_hw: true,
                speed: match *self.tempo.lock().unwrap() {
                    None if self.modus == "tempo" => kvpn::client::Speed { state: "fertig".into(), ping_ms: 21.0, down_mbps: 94.6, up_mbps: 38.2, at: 1, ..Default::default() },
                    None => Default::default(),
                    Some(t) => {
                        let e = t.elapsed().as_secs_f64();
                        let mut s = kvpn::client::Speed { state: "laeuft".into(), phase: "down".into(), ping_ms: 21.0, ..Default::default() };
                        if e > 3.0 { s.phase = "up".into(); s.down_mbps = 94.6; }
                        if e > 6.0 { s.state = "fertig".into(); s.phase.clear(); s.up_mbps = 38.2; s.at = 1; }
                        s
                    }
                },
            })
        }
        fn gewollt(&self) -> bool {
            self.modus != "aus"
        }
        fn verbinden(&self, _cfg: &ClientConfig) -> Result<(), String> {
            std::thread::sleep(Duration::from_millis(1500));
            *self.an.lock().unwrap() = true;
            Ok(())
        }
        fn trennen(&self) -> Result<(), String> {
            std::thread::sleep(Duration::from_millis(800));
            *self.an.lock().unwrap() = false;
            Ok(())
        }
        fn code_speichern(&self, cfg: &ClientConfig) {
            let mut p = self.profile.lock().unwrap();
            match p.iter().position(|x| crate::same_profile(x, cfg)) {
                Some(i) => p[i] = cfg.clone(),
                None => p.push(cfg.clone()),
            }
        }
        fn verschluesselung(&self) -> String {
            self.wahl.lock().unwrap().clone()
        }
        fn verschluesselung_setzen(&self, wahl: &str) -> Result<(), String> {
            std::thread::sleep(Duration::from_millis(900));
            *self.wahl.lock().unwrap() = wahl.to_string();
            Ok(())
        }
        fn profile(&self) -> Vec<ClientConfig> {
            self.profile.lock().unwrap().clone()
        }
        fn profile_speichern(&self, list: &[ClientConfig]) {
            *self.profile.lock().unwrap() = list.to_vec();
        }
        fn protokoll(&self) -> String {
            "2026-11-24 10:00:01 UTC Dienst startet (Version 1.0.3)\n2026-11-24 10:00:01 UTC Server krone.example -> 203.0.113.10\n2026-11-24 10:00:02 UTC Verbunden mit 203.0.113.10:443 – TLS ok\n".into()
        }
        fn protokoll_oeffnen(&self) {}
        fn klassisch(&self) -> Result<(), String> {
            Err("in der Vorschau nicht verfügbar".into())
        }
        fn neue_version_starten(&self) -> bool {
            println!("NEUSTART in neuer Version");
            true
        }
    }
    let an = !matches!(modus, "aus" | "neu");
    let demo = |title: &str, name: &str, url: &str| {
        use kvpn::code::key_to_b64;
        let (sp, _) = kvpn::crypto::generate_keypair();
        let (cp, _) = kvpn::crypto::generate_keypair();
        ClientConfig {
            name: name.into(),
            url: url.into(),
            server_pub: key_to_b64(&kvpn::crypto::public_from_private(&sp)),
            private_key: key_to_b64(&cp),
            ip4: "10.77.0.2".into(),
            ip6: String::new(),
            dns: vec![],
            mtu: 1400,
            title: title.into(),
            proxy: String::new(),
        }
    };
    let cfg = (modus != "neu").then(|| demo("", "Mein PC", "wss://vpn.example.org/api/v1/stream"));
    let mut profile: Vec<ClientConfig> = cfg.iter().cloned().collect();
    if modus == "profile" {
        profile.push(demo("Büro-VPN", "Laptop", "wss://buero.example.com/api/v1/stream"));
        profile.push(demo("Eltern", "Mein PC", "wss://eltern.example.net/api/v1/stream"));
    }
    let st = Arc::new(Demo { modus: modus.to_string(), t0: Instant::now(), an: Mutex::new(an), profile: Mutex::new(profile), wahl: Mutex::new("auto".into()), tempo: Mutex::new(None),
        regeln: Mutex::new(kvpn::regeln::Regeln { notbremse: true, auto: true, vertraut: vec!["FRITZ!Box 7590".into()], ziele: vec!["bank.de".into()], ..Default::default() }) });
    if let Err(e) = run(st, cfg, false) {
        eprintln!("{e}");
    }
}
