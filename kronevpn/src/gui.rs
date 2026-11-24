//! Programmfenster (Windows): grosser Ein/Aus-Knopf, Live-Werte, Verlauf, Code anzeigen, Protokoll.
//!
//! Das Fenster ist nur die Oberflaeche – das VPN selbst laeuft als Windows-Dienst (siehe dienst_windows.rs) und
//! meldet seinen Zustand jede Sekunde in status.json. Das Fenster darf deshalb jederzeit zu.
//! Zum Ansehen ohne Windows: `cargo run -p kronevpn --features vorschau` mit KVPN_VORSCHAU=an|aus|verbinde|neu|update|fehler

use crate::Zustand;
use eframe::egui::{self, pos2, vec2, Color32, CornerRadius, FontFamily, FontId, Margin, Pos2, Rect, RichText, Sense, Stroke, StrokeKind};
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
    /// gespeicherte Profile (Verbindungscodes)
    fn profile(&self) -> Vec<ClientConfig>;
    fn profile_speichern(&self, list: &[ClientConfig]);
    /// Protokoll (letzte Zeilen)
    fn protokoll(&self) -> String;
    fn protokoll_oeffnen(&self);
    /// zur alten Text-Ansicht wechseln (startet sie; das Fenster schliesst sich danach)
    fn klassisch(&self) -> Result<(), String>;
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
    zeige_code: bool,
    zeige_profile: bool,
    profile: Vec<ClientConfig>,
    titel_setzen: bool,
    danach_verbinden: bool,
    kopiert: Option<Instant>,
    log: Option<String>,
    logo: egui::TextureHandle,
    start: Instant,
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
            zeige_code: false,
            zeige_profile: false,
            profile: Vec::new(),
            titel_setzen: false,
            danach_verbinden: false,
            kopiert: None,
            log: None,
            logo,
            start: Instant::now(),
        };
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

    fn ist_aktiv(&self, c: &ClientConfig) -> bool {
        self.cfg.as_ref().is_some_and(|x| crate::same_profile(x, c))
    }
}

// ------------------------------------------------------------------------------------------------ Zeichnen

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.abfragen();
        if std::mem::take(&mut self.titel_setzen) {
            if let Some(c) = &self.cfg {
                ctx.send_viewport_cmd(egui::ViewportCommand::Title(c.display_name().to_string()));
            }
        }
        let anz = self.anzeige();
        let eingabe = self.cfg.is_none() || self.code_aendern;

        if !eingabe {
            egui::TopBottomPanel::bottom("fuss")
                .frame(egui::Frame::new().fill(BG).inner_margin(Margin { left: 18, right: 18, top: 10, bottom: 14 }))
                .show_separator_line(false)
                .show(ctx, |ui| self.fuss(ui));
        }
        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG).inner_margin(Margin { left: 18, right: 18, top: 16, bottom: 4 })).show(ctx, |ui| {
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

        if matches!(anz, Anzeige::Verbinde | Anzeige::Trenne) {
            ctx.request_repaint_after(Duration::from_millis(16));
        } else {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }
}

impl App {
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
        let farbe = match anz {
            Anzeige::Verbunden => OK,
            Anzeige::Verbinde => ACC,
            Anzeige::Trenne => WARN,
            Anzeige::Aus => MUTE,
        };
        ui.add_space(8.0);
        ui.vertical_centered(|ui| {
            if self.schalter(ui, anz, farbe) {
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
                ui.label(RichText::new(f).size(13.5));
                if ui.link("Protokoll ansehen").clicked() {
                    self.log = Some(self.st.protokoll());
                }
            });
            ui.add_space(4.0);
        }

        karte().inner_margin(Margin::symmetric(14, 10)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            self.details(ui, z.as_ref());
        });
    }

    /// grosser runder Ein/Aus-Knopf. true = angeklickt
    fn schalter(&self, ui: &mut egui::Ui, anz: Anzeige, farbe: Color32) -> bool {
        let (rect, resp) = ui.allocate_exact_size(vec2(156.0, 156.0), Sense::click());
        let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(match anz {
            Anzeige::Aus => "Verbinden",
            Anzeige::Trenne => "Wird getrennt …",
            _ => "Trennen",
        });
        let p = ui.painter();
        let c = rect.center();
        let t = self.start.elapsed().as_secs_f32();
        let hover = resp.hovered() && anz != Anzeige::Trenne;
        // Leuchten
        let an = anz != Anzeige::Aus;
        if an {
            let puls = if anz == Anzeige::Verbunden { 0.5 } else { 0.5 + 0.5 * (t * 3.0).sin() };
            for (r, a) in [(77.0, 0.05), (71.0, 0.08), (65.0, 0.12)] {
                p.circle_filled(c, r, farbe.gamma_multiply(a * (0.6 + 0.4 * puls)));
            }
        }
        let innen = if hover { Color32::from_rgb(0x1f, 0x23, 0x2c) } else { CARD };
        p.circle_filled(c, 60.0, innen);
        p.circle_stroke(c, 60.0, linie(1.0, LINE));
        // Ring
        match anz {
            Anzeige::Verbunden => {
                p.circle_stroke(c, 60.0, linie(5.0, farbe));
            }
            Anzeige::Verbinde | Anzeige::Trenne => {
                p.circle_stroke(c, 60.0, linie(5.0, farbe.gamma_multiply(0.18)));
                let a0 = t * 4.0;
                bogen(p, c, 60.0, a0, a0 + 1.6, linie(5.0, farbe));
            }
            Anzeige::Aus => {
                p.circle_stroke(c, 60.0, linie(5.0, if hover { ACC.gamma_multiply(0.7) } else { LINE }));
            }
        }
        // Symbol (Ein/Aus)
        let sym = match anz {
            Anzeige::Aus if hover => ACC,
            Anzeige::Aus => MUTE,
            _ => farbe,
        };
        let s = linie(5.5, sym);
        let pi = std::f32::consts::PI;
        bogen(p, c + vec2(0.0, 3.0), 24.0, -pi / 2.0 + 0.75, -pi / 2.0 + 2.0 * pi - 0.75, s);
        p.line_segment([c + vec2(0.0, -26.0), c + vec2(0.0, -4.0)], s);
        p.circle_filled(c + vec2(0.0, -26.0), 2.6, sym);
        p.circle_filled(c + vec2(0.0, -4.0), 2.6, sym);
        resp.clicked() && anz != Anzeige::Trenne
    }

    fn statustext(&self, anz: Anzeige) -> (String, String) {
        let z = self.z.as_ref();
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
            ],
            None => vec![("Server", server, INK), ("Schutz", "nicht aktiv – Datenverkehr geht direkt ins Internet".into(), MUTE)],
        };
        egui::Grid::new("details").num_columns(2).spacing(vec2(16.0, 6.0)).min_row_height(20.0).show(ui, |ui| {
            for (k, v, c) in zeilen {
                ui.label(RichText::new(k).color(MUTE).size(13.5));
                ui.add(egui::Label::new(RichText::new(v).color(c).size(13.5)).wrap());
                ui.end_row();
            }
        });
    }

    fn fuss(&mut self, ui: &mut egui::Ui) {
        ui.spacing_mut().button_padding.x = 6.0;
        ui.columns(3, |c| {
            if c[0].add_sized([c[0].available_width(), 36.0], knopf("Code", false)).on_hover_text("Verbindungscode + QR-Code anzeigen (z. B. fürs Handy)").clicked() {
                self.zeige_code = true;
            }
            if c[1].add_sized([c[1].available_width(), 36.0], knopf("Protokoll", false)).clicked() {
                self.log = Some(self.st.protokoll());
            }
            let t = if self.profile.len() > 1 { format!("Profile ({})", self.profile.len()) } else { "Profile".into() };
            if c[2].add_sized([c[2].available_width(), 36.0], knopf(&t, false)).on_hover_text("Zwischen Verbindungen wechseln oder eine neue hinzufügen").clicked() {
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

    fn dialoge(&mut self, ctx: &egui::Context) {
        let breite = (ctx.screen_rect().width() - 48.0).clamp(280.0, 560.0);
        if self.zeige_code {
            if let Some(cfg) = self.cfg.clone() {
                let code = cfg.to_code();
                let r = egui::Modal::new(egui::Id::new("code")).show(ctx, |ui| {
                    ui.set_width(breite.min(400.0));
                    ui.label(fett("Verbindungscode", 19.0));
                    ui.label(RichText::new("Zum Einrichten auf einem anderen Gerät (z. B. QR-Code in der Handy-App scannen). Geheim halten – wer den Code hat, kann sich als dieses Gerät verbinden.").color(MUTE).size(13.0));
                    ui.add_space(6.0);
                    ui.vertical_centered(|ui| qr_zeichnen(ui, &code, ui.available_width().min(260.0)));
                    ui.add_space(6.0);
                    egui::Frame::new().fill(Color32::from_rgb(0x0b, 0x0d, 0x11)).corner_radius(8).inner_margin(Margin::same(8)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        egui::ScrollArea::vertical().max_height(70.0).show(ui, |ui| {
                            ui.add(egui::Label::new(RichText::new(&code).monospace().size(11.0).color(MUTE)).wrap().selectable(true));
                        });
                    });
                    ui.add_space(4.0);
                    let mut zu = false;
                    ui.columns(2, |c| {
                        let kopiert = self.kopiert.is_some_and(|t| t.elapsed() < Duration::from_secs(2));
                        if c[0].add_sized([c[0].available_width(), 38.0], knopf(if kopiert { "Kopiert!" } else { "Kopieren" }, true)).clicked() {
                            c[0].ctx().copy_text(code.clone());
                            self.kopiert = Some(Instant::now());
                        }
                        if c[1].add_sized([c[1].available_width(), 38.0], knopf("Schließen", false)).clicked() {
                            zu = true;
                        }
                    });
                    zu
                });
                if r.inner || r.should_close() {
                    self.zeige_code = false;
                }
            } else {
                self.zeige_code = false;
            }
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

fn qr_zeichnen(ui: &mut egui::Ui, text: &str, groesse: f32) {
    let (rect, _) = ui.allocate_exact_size(vec2(groesse, groesse), Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, 12, Color32::WHITE);
    let Ok(code) = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::L) else {
        p.text(rect.center(), egui::Align2::CENTER_CENTER, "QR-Code zu groß", FontId::proportional(14.0), Color32::BLACK);
        return;
    };
    let w = code.width();
    let farben = code.to_colors();
    let rand = 4.0;
    let m = ((groesse / (w as f32 + 2.0 * rand)) * 2.0).floor() / 2.0; // Modulgroesse (halbe Pixel genau)
    let start = rect.center() - vec2(m * w as f32, m * w as f32) / 2.0;
    for (i, f) in farben.iter().enumerate() {
        if *f == qrcode::Color::Dark {
            let (x, y) = ((i % w) as f32, (i / w) as f32);
            p.rect_filled(Rect::from_min_size(start + vec2(x * m, y * m), vec2(m + 0.3, m + 0.3)), 0, Color32::BLACK);
        }
    }
    let _ = StrokeKind::Inside;
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
    }
    impl Steuerung for Demo {
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
                _ => "connected",
            };
            let rx = (2.5e6 * (1.2 + (t * 0.7).sin()) + 4e5 * (t * 3.1).sin().abs()) as u64;
            let tx = (2.4e5 * (1.1 + (t * 0.5).cos())) as u64;
            Some(Zustand {
                state: state.into(),
                title: "KroneVPN".into(),
                name: "Mein PC".into(),
                version: kvpn::VERSION.into(),
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
                error: if state == "waiting" { "Server nicht erreichbar (Zeitüberschreitung) – neuer Versuch in 4 s".into() } else { String::new() },
                update_version: if self.modus == "update" { "1.0.4".into() } else { String::new() },
                update_got: 3_100_000,
                update_size: 7_400_000,
                ts: (t * 4.0) as u64 + 1,
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
    let st = Arc::new(Demo { modus: modus.to_string(), t0: Instant::now(), an: Mutex::new(an), profile: Mutex::new(profile) });
    if let Err(e) = run(st, cfg, false) {
        eprintln!("{e}");
    }
}
