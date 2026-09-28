//! Ventana principal (spec §4): cabecera con navegación (Inicio, Sesiones,
//! Contactos, Invitaciones), banner con la dirección propia, barra de
//! conexión, tarjetas de acción, sesiones recientes con miniaturas, pie de
//! estado y las ventanas flotantes de Ajustes, Seguridad y equipos cercanos.

use cleandesk_proto::{id::CleanDeskId, quality::QualityProfile};

use crate::app::{CleanDeskApp, HostStatus, Page};
use crate::i18n::{self, tr, trf, Lang};
use crate::theme;

/// Perfiles de calidad para el selector de ajustes (mismo orden que el visor).
pub const QUALITY_PROFILES: &[QualityProfile] = &[
    QualityProfile::Auto,
    QualityProfile::Max,
    QualityProfile::Balanced,
    QualityProfile::Performance,
];

/// Etiqueta (traducida) de un perfil de calidad.
pub fn quality_label(profile: QualityProfile) -> &'static str {
    match profile {
        QualityProfile::Auto => tr("Automatic"),
        QualityProfile::Max => tr("Best quality"),
        QualityProfile::Balanced => tr("Balanced"),
        QualityProfile::Performance => tr("Best performance"),
    }
}

/// Ancho de una tarjeta de sesión reciente.
const CARD_W: f32 = 250.0;
/// Alto de la miniatura de una tarjeta.
const THUMB_H: f32 = 130.0;

/// Una tarjeta de la rejilla de sesiones recientes / contactos.
struct DeviceCard {
    id: CleanDeskId,
    name: String,
    subtitle: String,
    favorite: bool,
    /// Hay una contraseña desatendida recordada para este equipo.
    has_key: bool,
    /// Dirección MAC conocida (para Wake-on-LAN).
    mac: Option<String>,
}

/// Acciones diferidas de una tarjeta (se aplican tras soltar los préstamos).
#[derive(Default)]
struct CardActions {
    connect: Option<CleanDeskId>,
    toggle_fav: Option<(CleanDeskId, String, bool)>,
    forget_key: Option<CleanDeskId>,
    wake: Option<String>,
}

/// Dibuja la ventana principal completa.
pub fn show(app: &mut CleanDeskApp, ctx: &egui::Context) {
    // Rastreo automático de la red local al arrancar y cada minuto: alimenta
    // el punto verde de "en línea" de las tarjetas.
    let due = app
        .last_scan
        .is_none_or(|t| t.elapsed() > std::time::Duration::from_secs(60));
    if due {
        app.discover_nearby(ctx);
    }

    header(app, ctx);
    footer(app, ctx);

    egui::CentralPanel::default()
        .frame(egui::Frame::new().fill(theme::BG).inner_margin(egui::Margin::symmetric(24, 18)))
        .show(ctx, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                if let Some(session) = app.host_session.clone() {
                    active_session_banner(app, ui, &session);
                    ui.add_space(12.0);
                }
                notices(app, ui);
                match app.page {
                    Page::Home => home_page(app, ui, ctx),
                    Page::Sessions => sessions_page(app, ui, ctx),
                    Page::Contacts => contacts_page(app, ui, ctx),
                    Page::Invitations => invitations_page(app, ui),
                }
            });
        });

    settings_window(app, ctx);
    security_window(app, ctx);
    add_device_window(app, ctx);
    nearby_window(app, ctx);
}

/// Avisos (errores de conexión, confirmaciones) con cierre y, si procede, el
/// botón para confiar en una identidad cambiada.
fn notices(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    let Some(notice) = app.notice.clone() else { return };
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(255, 247, 230))
        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(250, 214, 150)))
        .corner_radius(egui::CornerRadius::same(theme::RADIUS_SM))
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(notice).color(egui::Color32::from_rgb(120, 70, 10)));
                if let Some(id) = app.identity_alarm {
                    if ui
                        .add(theme::danger_button(tr("Trust the new identity")))
                        .on_hover_text(tr("Only if you verified the device fingerprint through another channel"))
                        .clicked()
                    {
                        app.unpin_key(id);
                        app.identity_alarm = None;
                        app.notice = Some(tr("Previous key forgotten; connect again.").into());
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(egui::Button::new("✕").frame(false)).clicked() {
                        app.notice = None;
                        app.identity_alarm = None;
                    }
                });
            });
        });
    ui.add_space(10.0);
}

// ---------------------------------------------------------------------------
// Cabecera y pie
// ---------------------------------------------------------------------------

/// Cabecera: logo, navegación por páginas y acciones (ajustes, identidad).
fn header(app: &mut CleanDeskApp, ctx: &egui::Context) {
    egui::TopBottomPanel::top("cd-header")
        .frame(
            egui::Frame::new()
                .fill(theme::PANEL)
                .inner_margin(egui::Margin::symmetric(20, 0))
                .stroke(egui::Stroke::new(1.0_f32, theme::BORDER)),
        )
        .show(ctx, |ui| {
            ui.set_height(52.0);
            ui.horizontal_centered(|ui| {
                // Logo: hoja verde + nombre.
                let (rect, _) = ui.allocate_exact_size(egui::vec2(30.0, 30.0), egui::Sense::hover());
                theme::leaf(ui.painter(), rect.center(), 24.0, 230);
                theme::leaf(ui.painter(), egui::pos2(rect.center().x + 3.0, rect.center().y - 4.0), 16.0, 120);
                ui.label(egui::RichText::new("CleanDesk").strong().size(21.0).color(theme::ACCENT_STRONG));
                ui.add_space(28.0);

                for (page, icon, label) in [
                    (Page::Home, "⌂", tr("Home")),
                    (Page::Sessions, "🖥", tr("Sessions")),
                    (Page::Contacts, "👤", tr("Contacts")),
                    (Page::Invitations, "✉", tr("Invitations")),
                ] {
                    nav_tab(app, ui, page, icon, label);
                    ui.add_space(14.0);
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add(egui::Button::new(egui::RichText::new("👤").size(16.0)).frame(false))
                        .on_hover_text(tr("Device identity and fingerprint"))
                        .clicked()
                    {
                        app.show_security = !app.show_security;
                    }
                    if ui
                        .add(egui::Button::new(egui::RichText::new("⚙").size(16.0)).frame(false))
                        .on_hover_text(tr("Settings"))
                        .clicked()
                    {
                        app.show_settings = !app.show_settings;
                    }
                });
            });
        });
}

/// Una pestaña de navegación con subrayado verde cuando está activa.
fn nav_tab(app: &mut CleanDeskApp, ui: &mut egui::Ui, page: Page, icon: &str, label: &str) {
    let selected = app.page == page;
    let color = if selected { theme::ACCENT_STRONG } else { theme::TEXT_DIM };
    let text = egui::RichText::new(format!("{icon}  {label}")).size(14.0).color(color);
    let text = if selected { text.strong() } else { text };
    let resp = ui.add(egui::Button::new(text).frame(false));
    if resp.clicked() {
        app.page = page;
    }
    if selected {
        let r = resp.rect;
        ui.painter().hline(
            r.x_range(),
            ui.max_rect().bottom() - 1.0,
            egui::Stroke::new(3.0_f32, theme::ACCENT),
        );
    }
}

/// Barra de estado inferior.
fn footer(app: &CleanDeskApp, ctx: &egui::Context) {
    egui::TopBottomPanel::bottom("cd-footer")
        .frame(
            egui::Frame::new()
                .fill(theme::PANEL)
                .inner_margin(egui::Margin::symmetric(24, 8))
                .stroke(egui::Stroke::new(1.0_f32, theme::BORDER)),
        )
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                let community = app.network_mode().is_community();
                let (text, color) = match (app.host_status(), community) {
                    (HostStatus::Online, true) => (tr("Ready to connect (community network)"), theme::ONLINE),
                    (HostStatus::Online, false) => (tr("Ready to connect (private server)"), theme::ONLINE),
                    (HostStatus::Connecting, true) => (tr("Announcing on the community network…"), theme::WARN),
                    (HostStatus::Connecting, false) => (tr("Connecting to the server…"), theme::WARN),
                    (HostStatus::Offline, _) => (tr("Offline; retrying"), theme::DANGER),
                };
                theme::status_dot(ui, color, text);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(format!("v{}", crate::VERSION)).size(11.0).color(theme::TEXT_MUTED));
                    ui.label(egui::RichText::new(tr("Secure connections. Your privacy first.")).size(12.0).color(theme::TEXT_DIM));
                    ui.label(egui::RichText::new("🔒").size(12.0).color(theme::ACCENT));
                });
            });
        });
}

/// Aviso de sesión entrante activa (spec §18) con botón para finalizarla.
fn active_session_banner(app: &CleanDeskApp, ui: &mut egui::Ui, session: &crate::app::HostSession) {
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(255, 244, 229))
        .stroke(egui::Stroke::new(1.0_f32, theme::WARN))
        .corner_radius(egui::CornerRadius::same(theme::RADIUS))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                theme::status_dot(ui, theme::WARN, "");
                let who = session.peer.alias.clone().unwrap_or_else(|| session.peer.hostname.clone());
                ui.label(
                    egui::RichText::new(trf(
                        "{who} ({id}) is viewing your screen",
                        &[("who", &who), ("id", &session.peer.id.to_string())],
                    ))
                    .strong(),
                );
                let perms: Vec<&str> = crate::approval::PERMISSION_ITEMS
                    .iter()
                    .filter(|(p, _)| session.granted.contains(*p))
                    .map(|(_, l)| tr(l))
                    .collect();
                ui.label(egui::RichText::new(perms.join(" · ")).size(11.0).color(theme::TEXT_DIM));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(theme::danger_button(tr("End session"))).clicked() {
                        app.terminate_host_session();
                    }
                });
            });
        });
}

// ---------------------------------------------------------------------------
// Página de inicio
// ---------------------------------------------------------------------------

fn home_page(app: &mut CleanDeskApp, ui: &mut egui::Ui, ctx: &egui::Context) {
    hero(app, ui);
    ui.add_space(14.0);
    connect_bar(app, ui, ctx);
    ui.add_space(14.0);
    action_cards(app, ui, ctx);
    ui.add_space(18.0);

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(tr("Recent sessions")).size(16.0).strong());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.link(egui::RichText::new(format!("{} ›", tr("See all"))).color(theme::ACCENT)).clicked() {
                app.page = Page::Sessions;
            }
        });
    });
    ui.add_space(8.0);
    let cards = recent_cards(app, 7);
    device_grid(app, ui, ctx, &cards, true);
}

/// Banner: título, dirección propia con copiar / bloquear / invitar, y hojas.
fn hero(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    let width = ui.available_width();
    let height = 170.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    theme::gradient_rect(ui.painter(), rect, theme::HERO_A, theme::HERO_B, theme::RADIUS as f32);
    ui.painter().rect_stroke(
        rect,
        theme::RADIUS as f32,
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(200, 228, 210)),
        egui::StrokeKind::Inside,
    );
    // Hojas decorativas en ambos extremos.
    theme::leaf(ui.painter(), egui::pos2(rect.left() + 60.0, rect.bottom() - 18.0), 110.0, 40);
    theme::leaf(ui.painter(), egui::pos2(rect.left() + 130.0, rect.bottom() - 6.0), 70.0, 30);
    theme::leaf(ui.painter(), egui::pos2(rect.right() - 70.0, rect.top() + 40.0), 120.0, 35);
    theme::leaf(ui.painter(), egui::pos2(rect.right() - 40.0, rect.bottom() - 30.0), 90.0, 45);
    theme::monitor_icon(ui.painter(), egui::pos2(rect.right() - 90.0, rect.center().y), 70.0, egui::Color32::from_rgba_unmultiplied(31, 138, 74, 70));

    let inner = rect.shrink2(egui::vec2(28.0, 22.0));
    ui.scope_builder(egui::UiBuilder::new().max_rect(inner), |ui| {
        ui.horizontal_centered(|ui| {
            ui.vertical(|ui| {
                ui.set_width(250.0);
                ui.label(egui::RichText::new(tr("Your desktop,\nanywhere")).size(24.0).strong().color(theme::TEXT));
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(tr("Connect securely, quickly and simply with CleanDesk."))
                        .size(13.0)
                        .color(theme::TEXT_DIM),
                );
            });
            ui.add_space(24.0);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(tr("Your CleanDesk address")).size(14.0).strong());
                    ui.label(egui::RichText::new("ⓘ").color(theme::TEXT_MUTED))
                        .on_hover_text(tr("Share this identifier so others can connect to your screen with your permission."));
                });
                ui.add_space(6.0);
                egui::Frame::new()
                    .fill(egui::Color32::from_rgba_unmultiplied(255, 255, 255, 220))
                    .corner_radius(egui::CornerRadius::same(theme::RADIUS))
                    .inner_margin(egui::Margin::symmetric(16, 10))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            theme::big_id(ui, app.id);
                            ui.add_space(10.0);
                            if ui.add(theme::icon_button("⧉")).on_hover_text(tr("Copy")).clicked() {
                                ui.ctx().copy_text(app.id.to_string());
                                app.notice = Some(tr("ID copied to the clipboard.").into());
                            }
                            if ui.add(theme::icon_button("🔒")).on_hover_text(tr("Unattended access")).clicked() {
                                app.show_settings = true;
                            }
                            if ui.add(theme::primary_button(&format!("👤  {}", tr("Invite")))).clicked() {
                                app.page = Page::Invitations;
                            }
                        });
                    });
            });
        });
    });
}

/// Barra "Conectar a escritorio remoto".
fn connect_bar(app: &mut CleanDeskApp, ui: &mut egui::Ui, ctx: &egui::Context) {
    theme::card().inner_margin(egui::Margin::symmetric(18, 12)).show(ui, |ui| {
        let connecting = app.is_connecting();
        let mut go = false;
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(tr("Connect to remote desktop")).size(14.0).strong());
            ui.add_space(10.0);
            let (icon_rect, _) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::hover());
            theme::monitor_icon(ui.painter(), icon_rect.center(), 18.0, theme::TEXT_DIM);
            ui.add_enabled_ui(!connecting, |ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut app.connect_input)
                        .hint_text(tr("Enter a CleanDesk address or device alias"))
                        .desired_width((ui.available_width() - 150.0).max(120.0)),
                );
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    go = true;
                }
            });
            if connecting {
                ui.spinner();
            } else if ui.add(theme::primary_button(tr("Connect"))).clicked() {
                go = true;
            }
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.checkbox(&mut app.show_connect_password, tr("Unattended access (with password)"));
            if app.show_connect_password {
                ui.add(
                    egui::TextEdit::singleline(&mut app.connect_password)
                        .password(true)
                        .hint_text(tr("Password:"))
                        .desired_width(160.0),
                );
                ui.checkbox(&mut app.remember_password, tr("Remember"))
                    .on_hover_text(tr("Saves the device to favorites with its derived key (never the plaintext password)"));
            } else {
                app.connect_password.clear();
            }
            if connecting {
                let target = app.connecting_target().map(|t| t.to_string()).unwrap_or_default();
                ui.label(egui::RichText::new(trf("Waiting for {target}…", &[("target", &target)])).size(12.0).color(theme::TEXT_DIM));
            }
        });
        if go && !connecting {
            start_from_input(app, ctx);
        }
    });
}

/// Interpreta el campo de conexión: un ID numérico o un alias/nombre de la
/// agenda o de la red local.
fn start_from_input(app: &mut CleanDeskApp, ctx: &egui::Context) {
    let text = app.connect_input.trim().to_string();
    if let Ok(id) = CleanDeskId::parse(&text) {
        app.start_connection(id, ctx);
        return;
    }
    let needle = text.to_lowercase();
    let by_alias = app
        .state
        .addressbook
        .read()
        .entries
        .iter()
        .find(|e| {
            e.name.to_lowercase() == needle
                || e.alias.as_deref().is_some_and(|a| a.to_lowercase() == needle)
        })
        .map(|e| e.id)
        .or_else(|| {
            app.nearby
                .lock()
                .ok()
                .and_then(|n| n.iter().find(|d| d.alias.as_deref().is_some_and(|a| a.to_lowercase() == needle)).map(|d| d.id))
        });
    match by_alias {
        Some(id) => app.start_connection(id, ctx),
        None => app.notice = Some(tr("Invalid CleanDesk ID. Check the number.").into()),
    }
}

/// Las cuatro tarjetas de acción del inicio.
fn action_cards(app: &mut CleanDeskApp, ui: &mut egui::Ui, ctx: &egui::Context) {
    let mut open_settings = false;
    let mut discover = false;
    let mut page: Option<Page> = None;
    let mut url: Option<&str> = None;
    ui.columns(4, |cols| {
        action_card(&mut cols[0], true, "✦", tr("What's new in CleanDesk?"), tr("Discover the latest features and improvements."), tr("See what's new"), || {
            url = Some("https://github.com/EnriqueGF/CleanDesk/releases");
        });
        action_card(&mut cols[1], false, "⇩", tr("Unattended access"), tr("Set a password so you can reach this device without anyone accepting."), tr("Set up now"), || {
            open_settings = true;
        });
        action_card(&mut cols[2], false, "◎", tr("Discover"), tr("Find and connect to devices on your local network automatically."), tr("Find devices"), || {
            discover = true;
        });
        action_card(&mut cols[3], true, "👥", tr("Work better as a team"), tr("Share access, manage devices and keep everything secure."), tr("Contacts"), || {
            page = Some(Page::Contacts);
        });
    });
    if open_settings {
        app.show_settings = true;
    }
    if discover {
        app.show_nearby = true;
        app.last_scan = None;
        app.discover_nearby(ctx);
    }
    if let Some(p) = page {
        app.page = p;
    }
    if let Some(u) = url {
        ctx.open_url(egui::OpenUrl::new_tab(u));
    }
}

fn action_card(ui: &mut egui::Ui, tinted: bool, icon: &str, title: &str, text: &str, button: &str, mut on_click: impl FnMut()) {
    let frame = if tinted { theme::card_tinted() } else { theme::card() };
    frame.show(ui, |ui| {
        ui.set_min_height(190.0);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(44.0, 44.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, theme::RADIUS_SM as f32, theme::ACCENT_DIM);
        ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, icon, egui::FontId::proportional(20.0), theme::ACCENT);
        ui.add_space(8.0);
        ui.label(egui::RichText::new(title).size(16.0).strong());
        ui.add_space(4.0);
        ui.label(egui::RichText::new(text).size(12.0).color(theme::TEXT_DIM));
        ui.add_space(10.0);
        if ui.add(theme::pill_button(&format!("{button}  ›"))).clicked() {
            on_click();
        }
    });
}

// ---------------------------------------------------------------------------
// Tarjetas de equipos (recientes y contactos)
// ---------------------------------------------------------------------------

/// Tarjetas de las sesiones recientes (una por equipo, la más nueva primero).
fn recent_cards(app: &CleanDeskApp, max: usize) -> Vec<DeviceCard> {
    let book = app.state.addressbook.read();
    let history = app.state.history.read();
    let mut seen = std::collections::HashSet::new();
    history
        .recent(200)
        .into_iter()
        .filter(|r| r.device != app.id && seen.insert(r.device))
        .take(max)
        .map(|r| {
            let entry = book.find_by_id(r.device);
            DeviceCard {
                id: r.device,
                name: entry.map(|e| e.name.clone()).unwrap_or_else(|| r.user.clone()),
                subtitle: trf("Connected {when}", &[("when", &format_when(r.started_at))]),
                favorite: entry.is_some(),
                has_key: entry.is_some_and(|e| e.unattended_key.is_some()),
                mac: entry.and_then(|e| e.mac.clone()),
            }
        })
        .collect()
}

/// Tarjetas de la agenda (contactos / favoritos).
fn contact_cards(app: &CleanDeskApp) -> Vec<DeviceCard> {
    let book = app.state.addressbook.read();
    book.entries
        .iter()
        .map(|e| DeviceCard {
            id: e.id,
            name: e.name.clone(),
            subtitle: e
                .last_connection
                .map(|t| trf("Connected {when}", &[("when", &format_when(t))]))
                .unwrap_or_else(|| tr("no connections").into()),
            favorite: true,
            has_key: e.unattended_key.is_some(),
            mac: e.mac.clone(),
        })
        .collect()
}

/// Rejilla de tarjetas con miniatura; `with_new_card` añade la tarjeta
/// punteada "Conectar a un nuevo dispositivo" al final.
fn device_grid(app: &mut CleanDeskApp, ui: &mut egui::Ui, ctx: &egui::Context, cards: &[DeviceCard], with_new_card: bool) {
    if cards.is_empty() && !with_new_card {
        ui.label(egui::RichText::new(tr("You have not saved any device yet.")).color(theme::TEXT_MUTED));
        return;
    }
    let mut actions = CardActions::default();
    let total = cards.len() + usize::from(with_new_card);
    let cols = ((ui.available_width() + 14.0) / (CARD_W + 14.0)).floor().clamp(1.0, 5.0) as usize;
    egui::Grid::new(("cd-device-grid", ui.id())).num_columns(cols).spacing([14.0, 14.0]).show(ui, |ui| {
        for (i, card) in cards.iter().enumerate() {
            device_card(app, ui, ctx, card, &mut actions);
            if (i + 1) % cols == 0 {
                ui.end_row();
            }
        }
        if with_new_card {
            new_device_card(app, ui);
            if total % cols == 0 {
                ui.end_row();
            }
        }
    });

    if let Some((id, name, was_fav)) = actions.toggle_fav {
        if was_fav {
            app.remove_favorite(id);
        } else {
            app.add_favorite(id, name);
        }
    }
    if let Some(id) = actions.forget_key {
        app.forget_key(id);
        app.notice = Some(tr("Password forgotten.").into());
    }
    if let Some(mac) = actions.wake {
        match cleandesk_discovery::wol::send_magic_packet(&mac, None) {
            Ok(()) => app.notice = Some(tr("Wake-up packet sent.").into()),
            Err(e) => app.notice = Some(trf("Could not send the wake-up packet: {err}", &[("err", &e.to_string())])),
        }
    }
    if let Some(id) = actions.connect {
        app.start_connection(id, ctx);
    }
}

/// Una tarjeta de equipo: miniatura (última sesión), estado, estrella y pie
/// con nombre, "conectado hace…" y menú de acciones.
fn device_card(app: &mut CleanDeskApp, ui: &mut egui::Ui, ctx: &egui::Context, card: &DeviceCard, actions: &mut CardActions) {
    let online = app.is_nearby(card.id);
    let thumb = app.thumbnail(ctx, card.id);
    let hovered = ui.rect_contains_pointer(egui::Rect::from_min_size(ui.cursor().min, egui::vec2(CARD_W, THUMB_H + 64.0)));
    theme::device_card(hovered).show(ui, |ui| {
        ui.set_width(CARD_W);
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
        // Miniatura (clic = conectar).
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(CARD_W, THUMB_H), egui::Sense::click());
        let radius = egui::CornerRadius { nw: theme::RADIUS, ne: theme::RADIUS, sw: 0, se: 0 };
        match &thumb {
            Some(tex) => {
                ui.painter().add(egui::Shape::image(
                    tex.id(),
                    rect,
                    egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                    egui::Color32::WHITE,
                ));
            }
            None => {
                ui.painter().rect_filled(rect, radius, theme::CARD_TINT);
                theme::leaf(ui.painter(), egui::pos2(rect.right() - 40.0, rect.bottom() - 20.0), 80.0, 40);
                theme::monitor_icon(ui.painter(), rect.center(), 40.0, theme::ACCENT_LIGHT);
            }
        }
        ui.painter().rect_stroke(rect, radius, egui::Stroke::new(1.0_f32, theme::BORDER), egui::StrokeKind::Inside);
        if resp.clicked() {
            actions.connect = Some(card.id);
        }
        resp.on_hover_text(tr("Connect"));

        // Punto de estado (arriba-izquierda) y estrella (arriba-derecha).
        let dot = egui::pos2(rect.left() + 16.0, rect.top() + 16.0);
        ui.painter().circle_filled(dot, 8.0, egui::Color32::WHITE);
        ui.painter().circle_filled(dot, 5.5, if online { theme::ONLINE } else { theme::OFFLINE });
        let star_rect = egui::Rect::from_center_size(egui::pos2(rect.right() - 18.0, rect.top() + 18.0), egui::vec2(24.0, 24.0));
        ui.painter().circle_filled(star_rect.center(), 12.0, egui::Color32::from_rgba_unmultiplied(255, 255, 255, 210));
        let star = ui.put(
            star_rect,
            egui::Button::new(
                egui::RichText::new(if card.favorite { "★" } else { "☆" })
                    .size(15.0)
                    .color(if card.favorite { theme::STAR } else { theme::TEXT_DIM }),
            )
            .frame(false),
        );
        if star.on_hover_text(tr("Add to / remove from favorites")).clicked() {
            actions.toggle_fav = Some((card.id, card.name.clone(), card.favorite));
        }
        ui.advance_cursor_after_rect(rect);

        // Pie.
        egui::Frame::new().inner_margin(egui::Margin::symmetric(12, 10)).show(ui, |ui| {
            ui.spacing_mut().item_spacing = egui::vec2(8.0, 2.0);
            ui.horizontal(|ui| {
                let (ir, _) = ui.allocate_exact_size(egui::vec2(24.0, 24.0), egui::Sense::hover());
                theme::monitor_icon(ui.painter(), ir.center(), 18.0, theme::TEXT_DIM);
                ui.vertical(|ui| {
                    ui.set_width(CARD_W - 24.0 - 12.0 - 40.0);
                    ui.add(egui::Label::new(egui::RichText::new(&card.name).strong().size(14.0)).truncate());
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(format!("{}{}", card.subtitle, if card.has_key { "  🔑" } else { "" }))
                                .size(11.0)
                                .color(theme::TEXT_MUTED),
                        )
                        .truncate(),
                    )
                    .on_hover_text(card.id.to_string());
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.menu_button(egui::RichText::new("⋮").size(18.0), |ui| {
                        ui.set_min_width(180.0);
                        if ui.button(tr("Connect")).clicked() {
                            actions.connect = Some(card.id);
                            ui.close();
                        }
                        if ui.button(tr("Copy ID")).clicked() {
                            ui.ctx().copy_text(card.id.to_string());
                            ui.close();
                        }
                        let fav_label = if card.favorite { tr("Remove from favorites") } else { tr("Add to favorites") };
                        if ui.button(fav_label).clicked() {
                            actions.toggle_fav = Some((card.id, card.name.clone(), card.favorite));
                            ui.close();
                        }
                        if let Some(mac) = &card.mac {
                            if ui.button(tr("Wake up (Wake-on-LAN)")).clicked() {
                                actions.wake = Some(mac.clone());
                                ui.close();
                            }
                        }
                        if card.has_key && ui.button(tr("Forget remembered password")).clicked() {
                            actions.forget_key = Some(card.id);
                            ui.close();
                        }
                    });
                });
            });
        });
    });
}

/// Tarjeta punteada "Conectar a un nuevo dispositivo".
fn new_device_card(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(CARD_W, THUMB_H + 64.0), egui::Sense::click());
    let color = if resp.hovered() { theme::ACCENT_LIGHT } else { theme::BORDER_SOFT };
    dashed_rect(ui.painter(), rect, color);
    let c = rect.center();
    ui.painter().circle_stroke(egui::pos2(c.x, c.y - 26.0), 16.0, egui::Stroke::new(2.0_f32, theme::ACCENT));
    ui.painter().text(egui::pos2(c.x, c.y - 26.0), egui::Align2::CENTER_CENTER, "+", egui::FontId::proportional(24.0), theme::ACCENT);
    ui.painter().text(egui::pos2(c.x, c.y + 8.0), egui::Align2::CENTER_CENTER, tr("Connect"), egui::FontId::proportional(15.0), theme::TEXT);
    ui.painter().text(egui::pos2(c.x, c.y + 28.0), egui::Align2::CENTER_CENTER, tr("to a new device"), egui::FontId::proportional(13.0), theme::TEXT_DIM);
    if resp.clicked() {
        app.show_add_device = true;
    }
}

/// Borde discontinuo (aproximado con los cuatro lados).
fn dashed_rect(painter: &egui::Painter, rect: egui::Rect, color: egui::Color32) {
    let s = egui::Stroke::new(1.5_f32, color);
    let r = rect.shrink(1.0);
    painter.add(egui::Shape::dashed_line(&[r.left_top(), r.right_top()], s, 6.0, 5.0));
    painter.add(egui::Shape::dashed_line(&[r.right_top(), r.right_bottom()], s, 6.0, 5.0));
    painter.add(egui::Shape::dashed_line(&[r.right_bottom(), r.left_bottom()], s, 6.0, 5.0));
    painter.add(egui::Shape::dashed_line(&[r.left_bottom(), r.left_top()], s, 6.0, 5.0));
}

// ---------------------------------------------------------------------------
// Páginas: Sesiones, Contactos, Invitaciones
// ---------------------------------------------------------------------------

fn sessions_page(app: &mut CleanDeskApp, ui: &mut egui::Ui, ctx: &egui::Context) {
    ui.label(egui::RichText::new(tr("Sessions")).size(20.0).strong());
    ui.label(egui::RichText::new(tr("Every connection made from or to this device.")).color(theme::TEXT_DIM));
    ui.add_space(12.0);

    let records: Vec<_> = app.state.history.read().recent(200).into_iter().cloned().collect();
    if records.is_empty() {
        ui.label(egui::RichText::new(tr("No connections yet. Connect to an ID to see it here.")).color(theme::TEXT_MUTED));
        return;
    }
    let book_names: std::collections::HashMap<u64, String> = app
        .state
        .addressbook
        .read()
        .entries
        .iter()
        .map(|e| (e.id.value(), e.name.clone()))
        .collect();
    let mut connect: Option<CleanDeskId> = None;
    theme::card().inner_margin(egui::Margin::same(8)).show(ui, |ui| {
        egui::Grid::new("cd-sessions-table").num_columns(7).striped(true).spacing([18.0, 8.0]).show(ui, |ui| {
            for h in [tr("Device"), tr("User"), tr("When"), tr("Duration"), tr("Type"), tr("State"), ""] {
                ui.label(egui::RichText::new(h).strong().color(theme::TEXT_DIM));
            }
            ui.end_row();
            for r in &records {
                let name = book_names.get(&r.device.value()).cloned().unwrap_or_else(|| r.device.to_string());
                ui.label(egui::RichText::new(name).strong()).on_hover_text(r.device.to_string());
                ui.label(&r.user);
                ui.label(format_when(r.started_at));
                ui.label(r.duration_secs.map(format_duration).unwrap_or_else(|| "—".into()));
                ui.label(&r.connection_kind);
                ui.label(session_state_label(&r.state));
                if r.device != app.id && ui.add(theme::ghost_button(tr("Connect"))).clicked() {
                    connect = Some(r.device);
                }
                ui.end_row();
            }
        });
    });
    if let Some(id) = connect {
        app.start_connection(id, ctx);
    }
}

fn session_state_label(state: &str) -> &'static str {
    match state {
        "active" => tr("active"),
        "closed" => tr("closed"),
        "rejected" => tr("rejected"),
        "failed" => tr("failed"),
        _ => tr("unknown"),
    }
}

fn format_duration(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

fn contacts_page(app: &mut CleanDeskApp, ui: &mut egui::Ui, ctx: &egui::Context) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(tr("Contacts")).size(20.0).strong());
            ui.label(egui::RichText::new(tr("Saved devices. Star a recent session to add it here.")).color(theme::TEXT_DIM));
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(theme::primary_button(&format!("+ {}", tr("Add device")))).clicked() {
                app.show_add_device = true;
            }
            if ui.add(theme::ghost_button(tr("Find devices"))).clicked() {
                app.show_nearby = true;
                app.last_scan = None;
                app.discover_nearby(ctx);
            }
        });
    });
    ui.add_space(12.0);
    let cards = contact_cards(app);
    device_grid(app, ui, ctx, &cards, false);
}

fn invitations_page(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    ui.label(egui::RichText::new(tr("Invitations")).size(20.0).strong());
    ui.label(egui::RichText::new(tr("Invite someone to connect to this device, or check requests waiting for your approval.")).color(theme::TEXT_DIM));
    ui.add_space(12.0);

    ui.columns(2, |cols| {
        theme::card().show(&mut cols[0], |ui| {
            theme::section_label(ui, tr("Invite"), true);
            ui.add_space(6.0);
            ui.label(tr("Send this text to the person who should connect to you:"));
            ui.add_space(6.0);
            let text = app.invitation_text();
            egui::Frame::new()
                .fill(theme::WIDGET)
                .corner_radius(egui::CornerRadius::same(theme::RADIUS_SM))
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(&text).monospace().size(12.0));
                });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add(theme::primary_button(tr("Copy invitation"))).clicked() {
                    ui.ctx().copy_text(text.clone());
                    app.notice = Some(tr("Invitation copied to the clipboard.").into());
                }
                if ui.add(theme::ghost_button(tr("Copy ID"))).clicked() {
                    ui.ctx().copy_text(app.id.to_string());
                    app.notice = Some(tr("ID copied to the clipboard.").into());
                }
            });
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(tr("They will need your approval unless unattended access is enabled with a password (Settings)."))
                    .size(11.0)
                    .color(theme::TEXT_MUTED),
            );
        });
        theme::card().show(&mut cols[1], |ui| {
            theme::section_label(ui, tr("Pending requests"), true);
            ui.add_space(6.0);
            match &app.host_session {
                Some(s) => {
                    let who = s.peer.alias.clone().unwrap_or_else(|| s.peer.hostname.clone());
                    ui.label(trf("{who} ({id}) is viewing your screen", &[("who", &who), ("id", &s.peer.id.to_string())]));
                }
                None => {
                    ui.label(egui::RichText::new(tr("No pending requests. Incoming requests appear as a dialog you can accept or reject.")).color(theme::TEXT_DIM));
                }
            }
            ui.add_space(10.0);
            theme::section_label(ui, tr("Identity fingerprint"), false);
            ui.label(egui::RichText::new(app.state.identity.fingerprint()).monospace().size(12.0));
        });
    });
}

// ---------------------------------------------------------------------------
// Ventanas flotantes
// ---------------------------------------------------------------------------

/// Ventana "Equipos cercanos" (resultado del rastreo mDNS).
fn nearby_window(app: &mut CleanDeskApp, ctx: &egui::Context) {
    if !app.show_nearby {
        return;
    }
    let mut open = true;
    let mut connect: Option<CleanDeskId> = None;
    let mut rescan = false;
    egui::Window::new(tr("Nearby devices"))
        .id(egui::Id::new("cd-nearby-window"))
        .open(&mut open)
        .collapsible(false)
        .default_width(360.0)
        .show(ctx, |ui| {
            let scanning = app.discovering.load(std::sync::atomic::Ordering::Relaxed);
            ui.horizontal(|ui| {
                if scanning {
                    ui.spinner();
                    ui.label(tr("Scanning the local network…"));
                } else if ui.add(theme::ghost_button(tr("Scan again"))).clicked() {
                    rescan = true;
                }
            });
            ui.add_space(6.0);
            let list = app.nearby.lock().map(|n| n.clone()).unwrap_or_default();
            if list.is_empty() && !scanning {
                ui.label(egui::RichText::new(tr("No CleanDesk devices found on this network.")).color(theme::TEXT_MUTED));
            }
            for d in &list {
                ui.horizontal(|ui| {
                    theme::status_dot(ui, theme::ONLINE, "");
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(d.alias.clone().unwrap_or_else(|| d.id.to_string())).strong());
                        ui.label(egui::RichText::new(d.id.to_string()).size(11.0).color(theme::TEXT_MUTED));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(theme::primary_button(tr("Connect"))).clicked() {
                            connect = Some(d.id);
                        }
                    });
                });
                ui.separator();
            }
        });
    app.show_nearby = open;
    if rescan {
        app.last_scan = None;
        app.discover_nearby(ctx);
    }
    if let Some(id) = connect {
        app.show_nearby = false;
        app.start_connection(id, ctx);
    }
}

/// Ventana flotante "Añadir dispositivo".
fn add_device_window(app: &mut CleanDeskApp, ctx: &egui::Context) {
    if !app.show_add_device {
        return;
    }
    let mut open = true;
    let mut done = false;
    egui::Window::new(tr("Add device"))
        .id(egui::Id::new("cd-add-device-window"))
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .show(ctx, |ui| {
            ui.label(egui::RichText::new(tr("Save a permanent host to favorites")).color(theme::TEXT_DIM));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(tr("CleanDesk ID:"));
                ui.add(
                    egui::TextEdit::singleline(&mut app.add_device_id)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("548 291 743"),
                );
            });
            ui.horizontal(|ui| {
                ui.label(tr("Name:"));
                ui.add(egui::TextEdit::singleline(&mut app.add_device_name).hint_text(tr("Office laptop")));
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add(theme::primary_button(tr("Save"))).clicked() {
                    match CleanDeskId::parse(&app.add_device_id) {
                        Ok(id) => {
                            app.add_favorite(id, app.add_device_name.trim().to_string());
                            app.page = Page::Contacts;
                            done = true;
                        }
                        Err(_) => app.notice = Some(tr("Invalid CleanDesk ID.").into()),
                    }
                }
                if ui.add(theme::ghost_button(tr("Connect"))).clicked() {
                    match CleanDeskId::parse(&app.add_device_id) {
                        Ok(id) => {
                            app.connect_input = id.to_string();
                            app.start_connection(id, ctx);
                            done = true;
                        }
                        Err(_) => app.notice = Some(tr("Invalid CleanDesk ID.").into()),
                    }
                }
            });
        });
    if done || !open {
        app.show_add_device = false;
        app.add_device_id.clear();
        app.add_device_name.clear();
    }
}

/// Ventana flotante de seguridad: huella e identidad.
fn security_window(app: &mut CleanDeskApp, ctx: &egui::Context) {
    if !app.show_security {
        return;
    }
    let mut open = true;
    egui::Window::new(tr("Security"))
        .id(egui::Id::new("cd-security-window"))
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .show(ctx, |ui| {
            ui.label(
                egui::RichText::new(tr("This device's identity is an Ed25519 key pair. Your CleanDesk ID is derived from the public key and the server requires a signature to register it: nobody can impersonate your ID without the private key."))
                    .color(theme::TEXT_DIM),
            );
            ui.add_space(8.0);
            theme::section_label(ui, tr("Identity fingerprint"), true);
            ui.label(egui::RichText::new(app.state.identity.fingerprint()).monospace());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(tr("Compare it through another channel (phone, message) with the person connecting."))
                    .size(11.0)
                    .color(theme::TEXT_MUTED),
            );
            ui.add_space(8.0);
            theme::section_label(ui, tr("Encryption"), false);
            ui.label(egui::RichText::new(tr("Video, input and control travel over end-to-end DTLS; the server only relays signaling.")).size(12.0).color(theme::TEXT_DIM));
            ui.label(egui::RichText::new(tr("The unattended-access password is stored only as an Argon2id hash and never crosses the network (HMAC challenge-response).")).size(12.0).color(theme::TEXT_DIM));
        });
    app.show_security = open;
}

/// Ventana flotante de ajustes (spec §8, §9, §24).
fn settings_window(app: &mut CleanDeskApp, ctx: &egui::Context) {
    if !app.show_settings {
        return;
    }
    let mut open = true;
    egui::Window::new(tr("Settings"))
        .id(egui::Id::new("cd-settings-window"))
        .open(&mut open)
        .collapsible(false)
        .default_width(400.0)
        .show(ctx, |ui| {
            egui::ScrollArea::vertical().max_height(560.0).show(ui, |ui| {
                language_settings(app, ui);
                ui.add_space(10.0);
                alias_settings(app, ui);
                ui.add_space(10.0);
                tray_settings(app, ui);
                ui.add_space(10.0);
                network_settings(app, ui);
                ui.add_space(10.0);

                theme::section_label(ui, tr("Default quality"), true);
                ui.horizontal(|ui| {
                    let mut quality = app.state.settings.read().quality;
                    let before = quality;
                    egui::ComboBox::from_id_salt("settings-quality")
                        .selected_text(quality_label(quality))
                        .show_ui(ui, |ui| {
                            for profile in QUALITY_PROFILES {
                                ui.selectable_value(&mut quality, *profile, quality_label(*profile));
                            }
                        });
                    if quality != before {
                        app.state.settings.write().quality = quality;
                        app.save_settings();
                    }
                });

                ui.add_space(10.0);
                unattended_settings(app, ui);
                ui.add_space(10.0);
                system_settings(app, ui);
            });
        });
    app.show_settings = open;
}

/// Alias del dispositivo (antes vivía en la tarjeta "Tu dirección").
fn alias_settings(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    theme::section_label(ui, tr("Device alias"), true);
    ui.horizontal(|ui| {
        let resp = ui.add(
            egui::TextEdit::singleline(&mut app.alias_edit)
                .hint_text(tr("office-pc"))
                .desired_width(200.0),
        );
        // Persistimos al perder el foco (por Enter o al hacer clic fuera), no
        // en cada pulsación.
        if resp.lost_focus() {
            persist_alias(app);
        }
    });
    ui.label(
        egui::RichText::new(tr("Shown to people you connect to and used to find you on the local network."))
            .size(11.0)
            .color(theme::TEXT_MUTED),
    );
}

/// Sub-sección "Bandeja": cerrar la ventana la oculta en la bandeja.
fn tray_settings(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    theme::section_label(ui, tr("Tray"), true);
    let mut to_tray = app.state.settings.read().minimize_to_tray;
    if ui
        .checkbox(&mut to_tray, tr("Closing the window minimizes to the tray (the host keeps running)"))
        .changed()
    {
        app.state.settings.write().minimize_to_tray = to_tray;
        app.save_settings();
    }
}

/// Sub-sección "Idioma": sistema, inglés o español. El cambio se aplica en el
/// acto y se persiste (`None` = seguir al sistema).
fn language_settings(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    theme::section_label(ui, tr("Language"), true);

    let current: Option<Lang> = app
        .state
        .settings
        .read()
        .language
        .as_deref()
        .map(Lang::from_tag);
    let mut choice = current;
    let label = |c: Option<Lang>| match c {
        None => tr("System default"),
        Some(Lang::En) => "English",
        Some(Lang::Es) => "Español",
    };
    egui::ComboBox::from_id_salt("settings-language")
        .selected_text(label(choice))
        .show_ui(ui, |ui| {
            for option in [None, Some(Lang::En), Some(Lang::Es)] {
                ui.selectable_value(&mut choice, option, label(option));
            }
        });
    if choice != current {
        app.state.settings.write().language = choice.map(|l| l.tag().to_string());
        app.save_settings();
        i18n::set_lang(choice.unwrap_or_else(Lang::system));
    }
}

/// Sub-sección de acceso desatendido.
fn unattended_settings(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    theme::section_label(ui, tr("Unattended access"), true);

    let mut enabled = app.state.settings.read().unattended_enabled;
    let toggled = ui
        .checkbox(&mut enabled, tr("Allow unattended connections"))
        .changed();

    ui.horizontal(|ui| {
        ui.label(tr("Password:"));
        ui.add(egui::TextEdit::singleline(&mut app.unattended_pw).password(true));
    });
    ui.label(
        egui::RichText::new(tr("Anyone connecting with this password gets in without your approval. Restart the app after changing it so the host picks it up."))
            .size(11.0)
            .color(theme::TEXT_MUTED),
    );

    if toggled {
        if enabled {
            let pw = app.unattended_pw.trim().to_string();
            if pw.len() < 6 {
                app.notice = Some(tr("The unattended-access password must be at least 6 characters long.").into());
                app.state.settings.write().unattended_enabled = false;
            } else {
                let host_id = app.id.value();
                let result = app.state.settings.write().enable_unattended(&pw, host_id);
                match result {
                    Ok(()) => {
                        app.unattended_pw.clear();
                        app.save_settings();
                        app.notice = Some(tr("Unattended access enabled.").into());
                    }
                    Err(e) => {
                        app.state.settings.write().unattended_enabled = false;
                        app.notice = Some(trf("Could not enable it: {err}", &[("err", &e.to_string())]));
                    }
                }
            }
        } else {
            app.state.settings.write().disable_unattended();
            app.save_settings();
            app.notice = Some(tr("Unattended access disabled.").into());
        }
    }
}

/// Guarda el alias en los ajustes (o lo borra si queda vacío) y persiste.
fn persist_alias(app: &mut CleanDeskApp) {
    let trimmed = app.alias_edit.trim();
    let new_alias = if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    };
    {
        let mut settings = app.state.settings.write();
        if settings.alias == new_alias {
            return;
        }
        settings.alias = new_alias;
    }
    app.save_settings();
}

/// "5 min ago", "3 h ago", "2 d ago" (traducido) a partir de un instante Unix.
pub fn format_when(unix: u64) -> String {
    let now = crate::app::unix_now();
    let secs = now.saturating_sub(unix);
    if secs < 60 {
        tr("just now").into()
    } else if secs < 3600 {
        trf("{n} min ago", &[("n", &(secs / 60).to_string())])
    } else if secs < 86_400 {
        trf("{n} h ago", &[("n", &(secs / 3600).to_string())])
    } else {
        trf("{n} d ago", &[("n", &(secs / 86_400).to_string())])
    }
}

/// Sub-sección "Sistema" (spec §24): arranque con la sesión y servicio de Windows.
fn system_settings(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    use cleandesk_platform::service::ServiceStatus;
    use cleandesk_platform::{service, startup};

    theme::section_label(ui, tr("System"), true);

    let stale = app
        .platform_checked_at
        .is_none_or(|t| t.elapsed() > std::time::Duration::from_secs(3));
    if stale {
        app.service_status = service::status();
        app.run_at_login = startup::is_run_at_login().unwrap_or(false);
        app.platform_checked_at = Some(std::time::Instant::now());
    }
    ui.ctx().request_repaint_after(std::time::Duration::from_secs(3));

    let exe = std::env::current_exe().ok();

    let mut run_at_login = app.run_at_login;
    if ui.checkbox(&mut run_at_login, tr("Start with Windows (at sign-in)")).changed() {
        match exe.as_deref().map(|e| startup::set_run_at_login(run_at_login, e, &[])) {
            Some(Ok(())) => {
                app.run_at_login = run_at_login;
                app.state.settings.write().start_with_windows = run_at_login;
                app.save_settings();
                app.notice = Some(if run_at_login {
                    tr("CleanDesk will open when you sign in.").into()
                } else {
                    tr("CleanDesk will no longer open when you sign in.").into()
                });
            }
            Some(Err(e)) => app.notice = Some(trf("Could not change startup: {err}", &[("err", &e.to_string())])),
            None => app.notice = Some(tr("Could not locate the executable.").into()),
        }
        app.platform_checked_at = None;
    }

    let installed = app.service_status != ServiceStatus::NotInstalled;
    let mut want_service = installed;
    let changed = ui
        .checkbox(&mut want_service, tr("Install as a service (unattended access before sign-in)"))
        .on_hover_text(tr("Requires administrator rights. The service keeps the unattended host running even when nobody is signed in; when you open CleanDesk, the GUI takes over."))
        .changed();
    let (status_text, status_color) = match app.service_status {
        ServiceStatus::Running => (tr("Service installed and running"), theme::ONLINE),
        ServiceStatus::Stopped => (tr("Service installed (stopped)"), theme::WARN),
        ServiceStatus::Other => (tr("Service changing state…"), theme::WARN),
        ServiceStatus::NotInstalled => (tr("Service not installed"), theme::TEXT_MUTED),
    };
    ui.horizontal(|ui| {
        theme::status_dot(ui, status_color, status_text);
    });
    if installed && !app.state.settings.read().unattended_enabled {
        ui.label(
            egui::RichText::new(tr("The service only handles unattended access: set a password above to make it useful."))
                .size(11.0)
                .color(theme::WARN),
        );
    }
    if changed {
        let result = match (want_service, exe.as_deref()) {
            (true, Some(e)) => service::request_install(e, &app.state.data_dir()),
            (false, Some(e)) => service::request_uninstall(e),
            (_, None) => Err(cleandesk_platform::PlatformError::Other(tr("Could not locate the executable.").into())),
        };
        match result {
            Ok(()) => {
                app.state.settings.write().install_service = want_service;
                app.save_settings();
                app.notice = Some(if want_service {
                    tr("CleanDesk service installed and started.").into()
                } else {
                    tr("CleanDesk service removed.").into()
                });
            }
            Err(cleandesk_platform::PlatformError::ElevationDeclined) => {
                app.notice = Some(tr("Operation cancelled: administrator rights are required.").into());
            }
            Err(e) => app.notice = Some(trf("Could not change the service: {err}", &[("err", &e.to_string())])),
        }
        app.platform_checked_at = None;
    }
}

/// Sub-sección "Red": modo comunitario (sin servidor) o servidor privado.
fn network_settings(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    use cleandesk_core::config::NetworkMode;

    theme::section_label(ui, tr("Network"), true);
    if let Some(url) = &app.signal_override {
        ui.label(
            egui::RichText::new(trf("Forced by --signal-url: {url}", &[("url", url)]))
                .size(11.0)
                .color(theme::WARN),
        );
        return;
    }

    let current = app.state.settings.read().network.clone();
    let mut community = current.is_community();
    let mut url = current.server_url().unwrap_or("ws://127.0.0.1:7420").to_string();
    let mut changed = false;

    changed |= ui
        .radio_value(&mut community, true, tr("Community (no server): LAN, BitTorrent DHT and Nostr relays"))
        .changed();
    changed |= ui
        .radio_value(&mut community, false, tr("Private CleanDesk server"))
        .changed();
    if !community {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(tr("URL:")).color(theme::TEXT_DIM));
            let resp = ui.add(egui::TextEdit::singleline(&mut url).hint_text(tr("ws://server:7420")).desired_width(240.0));
            if resp.lost_focus() {
                changed = true;
            }
        });
    }
    ui.label(
        egui::RichText::new(if community {
            tr("Your device announces itself, signed, on the DHT and your local network; nobody has to run servers. The first connection pins the remote device's key (fingerprint under Security).")
        } else {
            tr("All signaling goes through your server; useful for companies and closed networks.")
        })
        .size(11.0)
        .color(theme::TEXT_MUTED),
    );

    if changed {
        let new_mode = if community {
            NetworkMode::Community
        } else {
            let url = url.trim().to_string();
            if !(url.starts_with("ws://") || url.starts_with("wss://")) {
                app.notice = Some(tr("The server URL must start with ws:// or wss://").into());
                return;
            }
            NetworkMode::Server { url }
        };
        if new_mode != current {
            app.state.settings.write().network = new_mode;
            app.save_settings();
            app.restart_host();
            app.notice = Some(tr("Network mode updated; the host is restarting.").into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_when_buckets() {
        if i18n::lang() != Lang::En {
            return;
        }
        let now = crate::app::unix_now();
        assert_eq!(format_when(now), "just now");
        assert_eq!(format_when(now - 120), "2 min ago");
        assert_eq!(format_when(now - 7200), "2 h ago");
        assert_eq!(format_when(now - 3 * 86_400), "3 d ago");
        assert_eq!(format_when(now + 1000), "just now", "future timestamps never underflow");
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(format_duration(59), "0:59");
        assert_eq!(format_duration(600), "10:00");
        assert_eq!(format_duration(3_725), "1:02:05");
    }
}
