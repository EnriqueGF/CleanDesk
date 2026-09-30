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
        .frame(
            egui::Frame::new()
                .fill(theme::BG)
                .inner_margin(egui::Margin::symmetric(24, 18)),
        )
        .show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let width = ui.available_width().min(1360.0);
                    let inset = ((ui.available_width() - width) / 2.0).max(0.0);
                    ui.horizontal(|ui| {
                        ui.add_space(inset);
                        ui.vertical(|ui| {
                            ui.set_width(width);
                            if let Some(session) = app.host_session.clone() {
                                active_session_banner(app, ui, &session);
                                ui.add_space(12.0);
                            }
                            update_banner(app, ui);
                            notices(app, ui);
                            match app.page {
                                Page::Home => home_page(app, ui, ctx),
                                Page::Sessions => sessions_page(app, ui, ctx),
                                Page::Contacts => contacts_page(app, ui, ctx),
                                Page::Invitations => invitations_page(app, ui),
                            }
                        });
                    });
                });
        });

    settings_window(app, ctx);
    security_window(app, ctx);
    add_device_window(app, ctx);
    nearby_window(app, ctx);
    if let Some(target) = app.connecting_target() {
        egui::Modal::new(egui::Id::new("connection-progress")).show(ctx, |ui| {
            ui.set_max_width(360.0);
            ui.heading(tr("Connecting"));
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(target.to_string());
            });
            ui.label(tr(
                "Waiting for the remote device to accept and establish a secure connection.",
            ));
            if ui.button(tr("Cancel")).clicked() {
                app.cancel_connection();
            }
        });
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}

/// Avisos (errores de conexión, confirmaciones) con cierre y, si procede, el
/// botón para confiar en una identidad cambiada.
fn notices(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    let Some(notice) = app.notice.clone() else {
        return;
    };
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(255, 247, 230))
        .stroke(egui::Stroke::new(
            1.0_f32,
            egui::Color32::from_rgb(250, 214, 150),
        ))
        .corner_radius(egui::CornerRadius::same(theme::RADIUS_SM))
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new(notice).color(egui::Color32::from_rgb(120, 70, 10)));
                if let Some(id) = app.identity_alarm {
                    if ui
                        .add(theme::danger_button(tr("Trust the new identity")))
                        .on_hover_text(tr(
                            "Only if you verified the device fingerprint through another channel",
                        ))
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
                .inner_margin(egui::Margin::symmetric(20, 10)),
        )
        .show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                theme::brand(ui, 32.0);
                ui.label(
                    egui::RichText::new("CleanDesk")
                        .strong()
                        .size(21.0)
                        .color(theme::ACCENT_STRONG),
                );
                for (page, label) in [
                    (Page::Home, tr("Home")),
                    (Page::Sessions, tr("Sessions")),
                    (Page::Contacts, tr("Contacts")),
                    (Page::Invitations, tr("Invitations")),
                ] {
                    nav_tab(app, ui, page, "", label);
                }
                if ui.button(tr("Settings")).clicked() {
                    app.show_settings = true;
                }
                if ui.button(tr("Security")).clicked() {
                    app.show_security = true;
                }
            });
        });
}

/// Una pestaña de navegación con subrayado verde cuando está activa.
fn nav_tab(app: &mut CleanDeskApp, ui: &mut egui::Ui, page: Page, icon: &str, label: &str) {
    let selected = app.page == page;
    let color = if selected {
        theme::ACCENT_STRONG
    } else {
        theme::TEXT_DIM
    };
    let text = egui::RichText::new(format!("{icon}{label}"))
        .size(14.0)
        .color(color);
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
            ui.horizontal_wrapped(|ui| {
                let community = app.network_mode().is_community();
                let (text, color) = match (app.host_status(), community) {
                    (HostStatus::Online, _) if app.hosted_by_service => (
                        tr("Ready to connect (privileged, hosted by the service)"),
                        theme::ONLINE,
                    ),
                    (HostStatus::Online, true) => {
                        (tr("Ready to connect (community network)"), theme::ONLINE)
                    }
                    (HostStatus::Online, false) => {
                        (tr("Ready to connect (private server)"), theme::ONLINE)
                    }
                    (HostStatus::Connecting, true) => {
                        (tr("Announcing on the community network…"), theme::WARN)
                    }
                    (HostStatus::Connecting, false) => {
                        (tr("Connecting to the server…"), theme::WARN)
                    }
                    (HostStatus::Offline, _) => (tr("Offline; retrying"), theme::DANGER),
                };
                theme::status_dot(ui, color, text);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!("v{}", crate::VERSION))
                            .size(11.0)
                            .color(theme::TEXT_MUTED),
                    );
                    ui.label(
                        egui::RichText::new(tr("Secure connections. Your privacy first."))
                            .size(12.0)
                            .color(theme::TEXT_DIM),
                    );
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
            ui.horizontal_wrapped(|ui| {
                theme::status_dot(ui, theme::WARN, "");
                let who = session
                    .peer
                    .alias
                    .clone()
                    .unwrap_or_else(|| session.peer.hostname.clone());
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
                ui.label(
                    egui::RichText::new(perms.join(" · "))
                        .size(11.0)
                        .color(theme::TEXT_DIM),
                );
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

    ui.horizontal_wrapped(|ui| {
        ui.label(
            egui::RichText::new(tr("Recent sessions"))
                .size(16.0)
                .strong(),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .link(egui::RichText::new(format!("{} ›", tr("See all"))).color(theme::ACCENT))
                .clicked()
            {
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
    theme::card_tinted().show(ui, |ui| {
        ui.set_width(ui.available_width());
        if ui.available_width() >= 800.0 {
            ui.columns(2, |cols| {
                hero_intro(&mut cols[0]);
                hero_address(app, &mut cols[1]);
            });
        } else {
            hero_intro(ui);
            ui.add_space(12.0);
            hero_address(app, ui);
        }
    });
}

fn hero_intro(ui: &mut egui::Ui) {
    ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
        ui.horizontal(|ui| {
            theme::brand(ui, 48.0);
            ui.label(
                egui::RichText::new(tr("Your desktop,\nanywhere"))
                    .size(24.0)
                    .strong(),
            );
        });
        ui.add(
            egui::Label::new(
                egui::RichText::new(tr("Connect securely, quickly and simply with CleanDesk."))
                    .color(theme::TEXT_DIM),
            )
            .wrap(),
        );
    });
}

fn hero_address(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
        ui.label(egui::RichText::new(tr("Your CleanDesk address")).strong());
        theme::big_id(ui, app.id);
        ui.horizontal_wrapped(|ui| {
            if ui.button(tr("Copy")).clicked() {
                ui.ctx().copy_text(app.id.to_string());
                app.notice = Some(tr("ID copied to the clipboard.").into());
            }
            if ui.button(tr("Unattended access")).clicked() {
                app.settings_section = 2;
                app.show_settings = true;
            }
            if ui.add(theme::primary_button(tr("Invite"))).clicked() {
                app.page = Page::Invitations;
            }
        });
    });
}

/// Barra "Conectar a escritorio remoto".
fn connect_bar(app: &mut CleanDeskApp, ui: &mut egui::Ui, ctx: &egui::Context) {
    theme::card().inner_margin(egui::Margin::symmetric(18, 12)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        let connecting = app.is_connecting();
        let mut go = false;
        ui.horizontal_wrapped(|ui| {
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
        ui.horizontal_wrapped(|ui| {
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
                || e.alias
                    .as_deref()
                    .is_some_and(|a| a.to_lowercase() == needle)
        })
        .map(|e| e.id)
        .or_else(|| {
            app.nearby.lock().ok().and_then(|n| {
                n.iter()
                    .find(|d| {
                        d.alias
                            .as_deref()
                            .is_some_and(|a| a.to_lowercase() == needle)
                    })
                    .map(|d| d.id)
            })
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
    let count = if ui.available_width() >= 1100.0 { 4 } else { 2 };
    for row in 0..(4 / count) {
        ui.columns(count, |cols| {
            if row == 0 {
                action_card(
                    &mut cols[0],
                    true,
                    "news",
                    tr("What's new in CleanDesk?"),
                    tr("Discover the latest features and improvements."),
                    tr("See what's new"),
                    || {
                        url = Some("https://github.com/EnriqueGF/CleanDesk/releases");
                    },
                );
            }
            if row * count <= 1 && 1 < (row + 1) * count {
                action_card(
                    &mut cols[1 % count],
                    false,
                    "access",
                    tr("Unattended access"),
                    tr("Set a password so you can reach this device without anyone accepting."),
                    tr("Set up now"),
                    || {
                        open_settings = true;
                    },
                );
            }
            if row * count <= 2 && 2 < (row + 1) * count {
                action_card(
                    &mut cols[2 % count],
                    false,
                    "discover",
                    tr("Discover"),
                    tr("Find and connect to devices on your local network automatically."),
                    tr("Find devices"),
                    || {
                        discover = true;
                    },
                );
            }
            if row * count <= 3 && 3 < (row + 1) * count {
                action_card(
                    &mut cols[3 % count],
                    true,
                    "contacts",
                    tr("Work better as a team"),
                    tr("Share access, manage devices and keep everything secure."),
                    tr("Contacts"),
                    || {
                        page = Some(Page::Contacts);
                    },
                );
            }
        });
        ui.add_space(10.0);
    }
    if open_settings {
        app.settings_section = 2;
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

fn action_card(
    ui: &mut egui::Ui,
    tinted: bool,
    icon: &str,
    title: &str,
    text: &str,
    button: &str,
    mut on_click: impl FnMut(),
) {
    let frame = if tinted {
        theme::card_tinted()
    } else {
        theme::card()
    };
    let width = (ui.available_width() - 36.0).max(100.0);
    frame.show(ui, |ui| {
        ui.set_width(width);
        // `ui.columns` justifica el texto; volvemos a la alineación normal.
        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.set_min_height(170.0);
            let top = ui.cursor().top();
            let (rect, _) = ui.allocate_exact_size(egui::vec2(44.0, 44.0), egui::Sense::hover());
            ui.painter()
                .rect_filled(rect, theme::RADIUS_SM as f32, theme::ACCENT_DIM);
            theme::action_icon(ui.painter(), rect.center(), icon);
            ui.add_space(8.0);
            ui.add(egui::Label::new(egui::RichText::new(title).size(16.0).strong()).wrap());
            ui.add_space(4.0);
            ui.add(
                egui::Label::new(egui::RichText::new(text).size(12.0).color(theme::TEXT_DIM))
                    .wrap(),
            );
            ui.add_space((170.0 - 32.0 - (ui.cursor().top() - top)).max(8.0));
            if ui
                .add(theme::pill_button(&format!("{button}  ›")))
                .clicked()
            {
                on_click();
            }
        });
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
                name: entry
                    .map(|e| e.name.clone())
                    .unwrap_or_else(|| r.user.clone()),
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
fn device_grid(
    app: &mut CleanDeskApp,
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    cards: &[DeviceCard],
    with_new_card: bool,
) {
    if cards.is_empty() && !with_new_card {
        ui.label(
            egui::RichText::new(tr("You have not saved any device yet.")).color(theme::TEXT_MUTED),
        );
        return;
    }
    let mut actions = CardActions::default();
    let total = cards.len() + usize::from(with_new_card);
    let cols = ((ui.available_width() + 14.0) / (CARD_W + 14.0))
        .floor()
        .clamp(1.0, 5.0) as usize;
    egui::Grid::new(("cd-device-grid", ui.id()))
        .num_columns(cols)
        .spacing([14.0, 14.0])
        .show(ui, |ui| {
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
            Err(e) => {
                app.notice = Some(trf(
                    "Could not send the wake-up packet: {err}",
                    &[("err", &e.to_string())],
                ))
            }
        }
    }
    if let Some(id) = actions.connect {
        app.start_connection(id, ctx);
    }
}

/// Una tarjeta de equipo: miniatura (última sesión), estado, estrella y pie
/// con nombre, "conectado hace…" y menú de acciones.
fn device_card(
    app: &mut CleanDeskApp,
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    card: &DeviceCard,
    actions: &mut CardActions,
) {
    let online = app.is_online(card.id);
    let thumb = app.thumbnail(ctx, card.id);
    let hovered = ui.rect_contains_pointer(egui::Rect::from_min_size(
        ui.cursor().min,
        egui::vec2(CARD_W, THUMB_H + 64.0),
    ));
    theme::device_card(hovered).show(ui, |ui| {
        ui.vertical(|ui| {
            ui.set_width(CARD_W);
            ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
            // Miniatura (clic = conectar).
            let (rect, resp) =
                ui.allocate_exact_size(egui::vec2(CARD_W, THUMB_H), egui::Sense::click());
            let radius = egui::CornerRadius {
                nw: theme::RADIUS,
                ne: theme::RADIUS,
                sw: 0,
                se: 0,
            };
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
                    theme::leaf(
                        ui.painter(),
                        egui::pos2(rect.right() - 40.0, rect.bottom() - 20.0),
                        80.0,
                        40,
                    );
                    theme::monitor_icon(ui.painter(), rect.center(), 40.0, theme::ACCENT_LIGHT);
                }
            }
            ui.painter().rect_stroke(
                rect,
                radius,
                egui::Stroke::new(1.0_f32, theme::BORDER),
                egui::StrokeKind::Inside,
            );
            if resp.clicked() {
                actions.connect = Some(card.id);
            }
            resp.on_hover_text(tr("Connect"));

            // Punto de estado (arriba-izquierda) y estrella (arriba-derecha).
            let dot = egui::pos2(rect.left() + 16.0, rect.top() + 16.0);
            ui.painter().circle_filled(dot, 8.0, egui::Color32::WHITE);
            ui.painter().circle_filled(
                dot,
                5.5,
                if online {
                    theme::ONLINE
                } else {
                    theme::OFFLINE
                },
            );
            let star_rect = egui::Rect::from_center_size(
                egui::pos2(rect.right() - 18.0, rect.top() + 18.0),
                egui::vec2(24.0, 24.0),
            );
            ui.painter().circle_filled(
                star_rect.center(),
                12.0,
                egui::Color32::from_rgba_unmultiplied(255, 255, 255, 210),
            );
            let star = ui.put(
                star_rect,
                egui::Button::new(
                    egui::RichText::new(if card.favorite { "★" } else { "☆" })
                        .size(15.0)
                        .color(if card.favorite {
                            theme::STAR
                        } else {
                            theme::TEXT_DIM
                        }),
                )
                .frame(false),
            );
            if star
                .on_hover_text(tr("Add to / remove from favorites"))
                .clicked()
            {
                actions.toggle_fav = Some((card.id, card.name.clone(), card.favorite));
            }
            ui.advance_cursor_after_rect(rect);

            // Pie.
            egui::Frame::new()
                .inner_margin(egui::Margin::symmetric(12, 10))
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(8.0, 2.0);
                    ui.horizontal(|ui| {
                        let (ir, _) =
                            ui.allocate_exact_size(egui::vec2(24.0, 24.0), egui::Sense::hover());
                        theme::monitor_icon(ui.painter(), ir.center(), 18.0, theme::TEXT_DIM);
                        ui.vertical(|ui| {
                            ui.set_width(CARD_W - 96.0);
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&card.name).strong().size(14.0),
                                )
                                .truncate(),
                            );
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(format!(
                                        "{}{}",
                                        card.subtitle,
                                        if card.has_key { "  Key" } else { "" }
                                    ))
                                    .size(11.0)
                                    .color(theme::TEXT_MUTED),
                                )
                                .truncate(),
                            )
                            .on_hover_text(card.id.to_string());
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let response = ui
                                .add(egui::Button::new("").min_size(egui::vec2(26.0, 26.0)))
                                .on_hover_text(tr("Actions"));
                            // Paint the menu dots directly: the default font has no vertical ellipsis.
                            for offset in [-5.0, 0.0, 5.0] {
                                ui.painter().circle_filled(
                                    response.rect.center() + egui::vec2(0.0, offset),
                                    1.6,
                                    theme::TEXT_DIM,
                                );
                            }
                            egui::Popup::menu(&response).show(|ui| {
                                ui.set_min_width(180.0);
                                if ui.button(tr("Connect")).clicked() {
                                    actions.connect = Some(card.id);
                                    ui.close();
                                }
                                if ui.button(tr("Copy ID")).clicked() {
                                    ui.ctx().copy_text(card.id.to_string());
                                    ui.close();
                                }
                                let fav_label = if card.favorite {
                                    tr("Remove from favorites")
                                } else {
                                    tr("Add to favorites")
                                };
                                if ui.button(fav_label).clicked() {
                                    actions.toggle_fav =
                                        Some((card.id, card.name.clone(), card.favorite));
                                    ui.close();
                                }
                                if let Some(mac) = &card.mac {
                                    if ui.button(tr("Wake up (Wake-on-LAN)")).clicked() {
                                        actions.wake = Some(mac.clone());
                                        ui.close();
                                    }
                                }
                                if card.has_key
                                    && ui.button(tr("Forget remembered password")).clicked()
                                {
                                    actions.forget_key = Some(card.id);
                                    ui.close();
                                }
                            });
                        });
                    });
                });
        });
    });
}

/// Tarjeta punteada "Conectar a un nuevo dispositivo".
fn new_device_card(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    let (rect, resp) =
        ui.allocate_exact_size(egui::vec2(CARD_W, THUMB_H + 64.0), egui::Sense::click());
    let color = if resp.hovered() {
        theme::ACCENT_LIGHT
    } else {
        theme::BORDER_SOFT
    };
    dashed_rect(ui.painter(), rect, color);
    let c = rect.center();
    ui.painter().circle_stroke(
        egui::pos2(c.x, c.y - 26.0),
        16.0,
        egui::Stroke::new(2.0_f32, theme::ACCENT),
    );
    ui.painter().text(
        egui::pos2(c.x, c.y - 26.0),
        egui::Align2::CENTER_CENTER,
        "+",
        egui::FontId::proportional(24.0),
        theme::ACCENT,
    );
    ui.painter().text(
        egui::pos2(c.x, c.y + 8.0),
        egui::Align2::CENTER_CENTER,
        tr("Connect"),
        egui::FontId::proportional(15.0),
        theme::TEXT,
    );
    ui.painter().text(
        egui::pos2(c.x, c.y + 28.0),
        egui::Align2::CENTER_CENTER,
        tr("to a new device"),
        egui::FontId::proportional(13.0),
        theme::TEXT_DIM,
    );
    if resp.clicked() {
        app.show_add_device = true;
    }
}

/// Borde discontinuo (aproximado con los cuatro lados).
fn dashed_rect(painter: &egui::Painter, rect: egui::Rect, color: egui::Color32) {
    let s = egui::Stroke::new(1.5_f32, color);
    let r = rect.shrink(1.0);
    painter.add(egui::Shape::dashed_line(
        &[r.left_top(), r.right_top()],
        s,
        6.0,
        5.0,
    ));
    painter.add(egui::Shape::dashed_line(
        &[r.right_top(), r.right_bottom()],
        s,
        6.0,
        5.0,
    ));
    painter.add(egui::Shape::dashed_line(
        &[r.right_bottom(), r.left_bottom()],
        s,
        6.0,
        5.0,
    ));
    painter.add(egui::Shape::dashed_line(
        &[r.left_bottom(), r.left_top()],
        s,
        6.0,
        5.0,
    ));
}

// ---------------------------------------------------------------------------
// Páginas: Sesiones, Contactos, Invitaciones
// ---------------------------------------------------------------------------

fn sessions_page(app: &mut CleanDeskApp, ui: &mut egui::Ui, ctx: &egui::Context) {
    ui.label(egui::RichText::new(tr("Sessions")).size(20.0).strong());
    ui.label(
        egui::RichText::new(tr("Every connection made from or to this device."))
            .color(theme::TEXT_DIM),
    );
    ui.add_space(12.0);

    let records: Vec<_> = app
        .state
        .history
        .read()
        .recent(200)
        .into_iter()
        .cloned()
        .collect();
    if records.is_empty() {
        ui.label(
            egui::RichText::new(tr("No connections yet. Connect to an ID to see it here."))
                .color(theme::TEXT_MUTED),
        );
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
    theme::card()
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            egui::ScrollArea::horizontal()
                .id_salt("session-table-scroll")
                .show(ui, |ui| {
                    egui::Grid::new("cd-sessions-table")
                        .num_columns(7)
                        .striped(true)
                        .spacing([18.0, 8.0])
                        .show(ui, |ui| {
                            for h in [
                                tr("Device"),
                                tr("User"),
                                tr("When"),
                                tr("Duration"),
                                tr("Type"),
                                tr("State"),
                                "",
                            ] {
                                ui.label(egui::RichText::new(h).strong().color(theme::TEXT_DIM));
                            }
                            ui.end_row();
                            for r in &records {
                                let name = book_names
                                    .get(&r.device.value())
                                    .cloned()
                                    .unwrap_or_else(|| r.device.to_string());
                                ui.label(egui::RichText::new(name).strong())
                                    .on_hover_text(r.device.to_string());
                                ui.label(&r.user);
                                ui.label(format_when(r.started_at));
                                ui.label(
                                    r.duration_secs
                                        .map(format_duration)
                                        .unwrap_or_else(|| "—".into()),
                                );
                                ui.label(&r.connection_kind);
                                ui.label(session_state_label(&r.state));
                                if r.device != app.id
                                    && ui.add(theme::ghost_button(tr("Connect"))).clicked()
                                {
                                    connect = Some(r.device);
                                }
                                ui.end_row();
                            }
                        });
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
    ui.horizontal_wrapped(|ui| {
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(tr("Contacts")).size(20.0).strong());
            ui.label(
                egui::RichText::new(tr("Saved devices. Star a recent session to add it here."))
                    .color(theme::TEXT_DIM),
            );
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add(theme::primary_button(&format!("+ {}", tr("Add device"))))
                .clicked()
            {
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
          ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
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
            ui.horizontal_wrapped(|ui| {
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
        });
        theme::card().show(&mut cols[1], |ui| {
          ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
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
            ui.horizontal_wrapped(|ui| {
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
                ui.label(
                    egui::RichText::new(tr("No CleanDesk devices found on this network."))
                        .color(theme::TEXT_MUTED),
                );
            }
            for d in &list {
                ui.horizontal_wrapped(|ui| {
                    theme::status_dot(ui, theme::ONLINE, "");
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(
                                d.alias.clone().unwrap_or_else(|| d.id.to_string()),
                            )
                            .strong(),
                        );
                        ui.label(
                            egui::RichText::new(d.id.to_string())
                                .size(11.0)
                                .color(theme::TEXT_MUTED),
                        );
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
            ui.label(
                egui::RichText::new(tr("Save a permanent host to favorites"))
                    .color(theme::TEXT_DIM),
            );
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(tr("CleanDesk ID:"));
                ui.add(
                    egui::TextEdit::singleline(&mut app.add_device_id)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("548 291 743"),
                );
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(tr("Name:"));
                ui.add(
                    egui::TextEdit::singleline(&mut app.add_device_name)
                        .hint_text(tr("Office laptop")),
                );
            });
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
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
    let screen = ctx.screen_rect();
    egui::Window::new(tr("Settings"))
        .id(egui::Id::new("cd-settings-window"))
        .open(&mut open)
        .collapsible(false)
        .default_width((screen.width() - 80.0).min(724.0))
        .max_size(egui::vec2(
            (screen.width() - 80.0).max(500.0),
            (screen.height() - 100.0).max(280.0),
        ))
        .show(ctx, |ui| {
            let content_height = (screen.height() - 160.0).clamp(240.0, 420.0);
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), content_height),
                egui::Layout::left_to_right(egui::Align::Min),
                |ui| {
                    ui.vertical(|ui| {
                        ui.set_width(145.0);
                        for (i, label) in [
                            "General",
                            "Network",
                            "Unattended access",
                            "Default quality",
                            "System",
                            "Updates",
                        ]
                        .iter()
                        .enumerate()
                        {
                            ui.selectable_value(&mut app.settings_section, i, tr(label));
                        }
                    });
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .id_salt("settings-content")
                        .max_height(content_height)
                        .show(ui, |ui| {
                            ui.vertical(|ui| {
                                ui.set_width(ui.available_width().max(300.0));
                                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                                match app.settings_section {
                                    0 => {
                                        language_settings(app, ui);
                                        ui.separator();
                                        alias_settings(app, ui);
                                        ui.separator();
                                        tray_settings(app, ui);
                                    }
                                    1 => network_settings(app, ui),
                                    2 => unattended_settings(app, ui),
                                    3 => {
                                        theme::section_label(ui, tr("Default quality"), true);
                                        let mut quality = app.state.settings.read().quality;
                                        let before = quality;
                                        for profile in QUALITY_PROFILES {
                                            ui.radio_value(
                                                &mut quality,
                                                *profile,
                                                quality_label(*profile),
                                            );
                                        }
                                        if quality != before {
                                            app.state.settings.write().quality = quality;
                                            app.save_settings();
                                        }
                                    }
                                    4 => system_settings(app, ui),
                                    _ => update_settings(app, ui),
                                }
                            });
                        });
                },
            );
        });
    app.show_settings = open;
}

/// Alias del dispositivo (antes vivía en la tarjeta "Tu dirección").
fn alias_settings(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    theme::section_label(ui, tr("Device alias"), true);
    ui.horizontal_wrapped(|ui| {
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
        egui::RichText::new(tr(
            "Shown to people you connect to and used to find you on the local network.",
        ))
        .size(11.0)
        .color(theme::TEXT_MUTED),
    );
}

/// Sub-sección "Bandeja": cerrar la ventana la oculta en la bandeja.
fn tray_settings(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    theme::section_label(ui, tr("Tray"), true);
    let mut to_tray = app.state.settings.read().minimize_to_tray;
    if ui
        .checkbox(
            &mut to_tray,
            tr("Closing the window minimizes to the tray (the host keeps running)"),
        )
        .changed()
    {
        app.state.settings.write().minimize_to_tray = to_tray;
        app.save_settings();
    }
}

/// Banner de actualización disponible / en curso (página principal).
fn update_banner(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    use crate::updater::Phase;
    if !app.updater.banner_visible() {
        return;
    }
    let phase = app.updater.phase();
    let mut download = false;
    let mut install = false;
    let mut later = false;
    let mut open_notes: Option<String> = None;
    theme::card_tinted().inner_margin(egui::Margin::symmetric(14, 10)).show(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new("⬆").size(18.0).color(theme::ACCENT));
            match &phase {
                Phase::Available(r) => {
                    ui.label(egui::RichText::new(trf("CleanDesk {v} is available.", &[("v", &r.version_string())])).strong());
                    if ui.add(theme::primary_button(tr("Update now"))).clicked() {
                        download = true;
                    }
                    if ui.add(theme::ghost_button(tr("Release notes"))).clicked() {
                        open_notes = Some(r.html_url.clone());
                    }
                    if ui.add(theme::ghost_button(tr("Later"))).clicked() {
                        later = true;
                    }
                }
                Phase::Downloading { release, done, total } => {
                    ui.label(trf(
                        "Downloading {v}… {done} / {total}",
                        &[
                            ("v", &release.version_string()),
                            ("done", &crate::viewer::human_size(*done)),
                            ("total", &crate::viewer::human_size(*total)),
                        ],
                    ));
                    let frac = if *total > 0 { *done as f32 / *total as f32 } else { 0.0 };
                    ui.add(egui::ProgressBar::new(frac).desired_width(220.0));
                }
                Phase::Ready { release, .. } => {
                    ui.label(
                        egui::RichText::new(trf(
                            "Update downloaded and verified. CleanDesk will close, install {v} and reopen.",
                            &[("v", &release.version_string())],
                        ))
                        .strong(),
                    );
                    if ui.add(theme::primary_button(tr("Install and restart"))).clicked() {
                        install = true;
                    }
                }
                Phase::Installing => {
                    ui.spinner();
                    ui.label(tr("Installing…"));
                }
                _ => {}
            }
        });
    });
    ui.add_space(10.0);
    if download {
        let dir = app.state.data_dir().join("updates");
        app.updater.download(dir, ui.ctx());
    }
    if later {
        app.updater.dismiss();
    }
    if let Some(url) = open_notes {
        ui.ctx().open_url(egui::OpenUrl::new_tab(url));
    }
    if install {
        match app.updater.install() {
            // El instalador ya está en marcha en otro proceso: salimos para que
            // pueda sustituir el ejecutable (y soltamos el mutex de instancia).
            Ok(()) => std::process::exit(0),
            Err(e) => app.notice = Some(trf("Update failed: {err}", &[("err", &e)])),
        }
    }
}

/// Sub-sección "Actualizaciones" de Ajustes.
fn update_settings(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    use crate::updater::Phase;
    theme::section_label(ui, tr("Updates"), true);
    ui.label(
        egui::RichText::new(trf(
            "Current version: {v}",
            &[("v", &crate::updater::current_version())],
        ))
        .size(12.0)
        .color(theme::TEXT_DIM),
    );
    let mut auto = app.state.settings.read().check_updates;
    if ui
        .checkbox(&mut auto, tr("Check for updates automatically"))
        .changed()
    {
        app.state.settings.write().check_updates = auto;
        app.save_settings();
    }
    let mut check = false;
    let mut download = false;
    ui.horizontal_wrapped(|ui| {
        let phase = app.updater.phase();
        let busy = matches!(
            phase,
            Phase::Checking | Phase::Downloading { .. } | Phase::Installing
        );
        if ui
            .add_enabled(!busy, theme::ghost_button(tr("Check now")))
            .clicked()
        {
            check = true;
        }
        match &phase {
            Phase::Checking => {
                ui.spinner();
                ui.label(
                    egui::RichText::new(tr("Checking for updates…"))
                        .size(12.0)
                        .color(theme::TEXT_DIM),
                );
            }
            Phase::UpToDate => {
                ui.label(
                    egui::RichText::new(tr("You are up to date."))
                        .size(12.0)
                        .color(theme::ACCENT_STRONG),
                );
            }
            Phase::Available(r) => {
                ui.label(
                    egui::RichText::new(trf(
                        "CleanDesk {v} is available.",
                        &[("v", &r.version_string())],
                    ))
                    .size(12.0)
                    .color(theme::ACCENT_STRONG),
                );
                if ui.add(theme::primary_button(tr("Update now"))).clicked() {
                    download = true;
                }
            }
            Phase::Downloading { .. } | Phase::Ready { .. } | Phase::Installing => {
                ui.label(
                    egui::RichText::new(tr("See the banner on the Home page."))
                        .size(12.0)
                        .color(theme::TEXT_DIM),
                );
            }
            Phase::Error(e) => {
                ui.label(
                    egui::RichText::new(trf("Update failed: {err}", &[("err", e)]))
                        .size(12.0)
                        .color(theme::DANGER),
                );
            }
            Phase::Idle => {}
        }
    });
    if check {
        app.updater.check(ui.ctx());
    }
    if download {
        let dir = app.state.data_dir().join("updates");
        app.updater.download(dir, ui.ctx());
        app.page = Page::Home;
        app.show_settings = false;
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

    let (mut enabled, has_password) = {
        let s = app.state.settings.read();
        (s.unattended_enabled, s.unattended_key_bytes.is_some())
    };

    // El check solo enciende/apaga; la contraseña se guarda con su botón.
    // Sin contraseña guardada no se puede activar, y se explica aquí mismo
    // (el aviso general queda tapado por esta ventana).
    if ui
        .checkbox(&mut enabled, tr("Allow unattended connections"))
        .changed()
    {
        if enabled && !has_password {
            app.unattended_msg = Some((
                tr("Set a password below first (at least 10 characters).").into(),
                true,
            ));
        } else if enabled {
            app.state.settings.write().unattended_enabled = true;
            app.save_settings();
            app.restart_host();
            app.unattended_msg = Some((tr("Unattended access enabled.").into(), false));
        } else {
            app.state.settings.write().disable_unattended();
            app.save_settings();
            app.restart_host();
            app.unattended_msg = Some((tr("Unattended access disabled.").into(), false));
        }
    }

    let mut save = false;
    ui.horizontal_wrapped(|ui| {
        ui.label(tr("Password:"));
        let resp = ui.add(
            egui::TextEdit::singleline(&mut app.unattended_pw)
                .password(true)
                .hint_text(if has_password {
                    tr("(set; type a new one to replace it)")
                } else {
                    tr("at least 10 characters")
                })
                .desired_width(180.0),
        );
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            save = true;
        }
        let valid = app.unattended_pw.trim().chars().count() >= cleandesk_core::config::MIN_UNATTENDED_PASSWORD_LEN;
        if ui
            .add_enabled(valid, theme::primary_button(tr("Save password")))
            .clicked()
        {
            save = true;
        }
    });
    if save {
        let pw = app.unattended_pw.trim().to_string();
        if pw.chars().count() < cleandesk_core::config::MIN_UNATTENDED_PASSWORD_LEN {
            app.unattended_msg = Some((
                tr("The unattended-access password must be at least 10 characters long.").into(),
                true,
            ));
        } else {
            let host_id = app.id.value();
            let result = app.state.settings.write().enable_unattended(&pw, host_id);
            match result {
                Ok(()) => {
                    app.unattended_pw.clear();
                    app.save_settings();
                    app.restart_host();
                    app.unattended_msg = Some((
                        tr("Password saved; unattended access enabled.").into(),
                        false,
                    ));
                }
                Err(e) => {
                    app.unattended_msg = Some((
                        trf("Could not enable it: {err}", &[("err", &e.to_string())]),
                        true,
                    ));
                }
            }
        }
    }
    if let Some((msg, is_err)) = &app.unattended_msg {
        ui.label(egui::RichText::new(msg).size(12.0).color(if *is_err {
            theme::DANGER
        } else {
            theme::ACCENT_STRONG
        }));
    }
    ui.label(
        egui::RichText::new(tr("Anyone connecting with this password gets in without your approval. Only an Argon2id hash and a derived key are stored, never the password."))
            .size(11.0)
            .color(theme::TEXT_MUTED),
    );
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

    app.poll_platform_status(ui.ctx());
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_secs(3));

    let exe = std::env::current_exe().ok();

    let mut run_at_login = app.run_at_login;
    if ui
        .checkbox(&mut run_at_login, tr("Start with Windows (at sign-in)"))
        .changed()
    {
        match exe
            .as_deref()
            .map(|e| startup::set_run_at_login(run_at_login, e, &[]))
        {
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
            Some(Err(e)) => {
                app.notice = Some(trf(
                    "Could not change startup: {err}",
                    &[("err", &e.to_string())],
                ))
            }
            None => app.notice = Some(tr("Could not locate the executable.").into()),
        }
        app.platform_checked_at = None;
    }

    // Control privilegiado (ventanas de administrador y UAC).
    let mut privileged = app.state.settings.read().privileged_control;
    if ui
        .checkbox(&mut privileged, tr("Privileged control: drive administrator windows and UAC prompts"))
        .on_hover_text(tr("With the service installed, the service (LocalSystem) hosts and can show the UAC secure desktop; only unattended (password) connections are accepted then. Without the service, CleanDesk asks for elevation when it starts."))
        .changed()
    {
        app.state.settings.write().privileged_control = privileged;
        app.save_settings();
        app.notice = Some(tr("Restart CleanDesk to apply privileged control.").into());
    }
    let priv_state = if app.hosted_by_service {
        tr("Active: the service hosts as LocalSystem")
    } else if app.elevated {
        tr("Active: running elevated (administrator windows; UAC prompts need the service)")
    } else if privileged {
        tr("Not active in this run (elevation declined or pending restart)")
    } else {
        tr("Off: administrator windows cannot be controlled")
    };
    ui.label(
        egui::RichText::new(priv_state)
            .size(11.0)
            .color(theme::TEXT_MUTED),
    );
    ui.add_space(6.0);

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
    ui.horizontal_wrapped(|ui| {
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
            (_, None) => Err(cleandesk_platform::PlatformError::Other(
                tr("Could not locate the executable.").into(),
            )),
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
                app.notice =
                    Some(tr("Operation cancelled: administrator rights are required.").into());
            }
            Err(e) => {
                app.notice = Some(trf(
                    "Could not change the service: {err}",
                    &[("err", &e.to_string())],
                ))
            }
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
    let mut url = current
        .server_url()
        .unwrap_or("ws://127.0.0.1:7420")
        .to_string();
    let mut changed = false;

    changed |= ui
        .radio_value(
            &mut community,
            true,
            tr("Community (no server): LAN, BitTorrent DHT and Nostr relays"),
        )
        .changed();
    changed |= ui
        .radio_value(&mut community, false, tr("Private CleanDesk server"))
        .changed();
    if !community {
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new(tr("URL:")).color(theme::TEXT_DIM));
            let resp = ui.add(
                egui::TextEdit::singleline(&mut url)
                    .hint_text(tr("ws://server:7420"))
                    .desired_width(240.0),
            );
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
        assert_eq!(
            format_when(now + 1000),
            "just now",
            "future timestamps never underflow"
        );
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(format_duration(59), "0:59");
        assert_eq!(format_duration(600), "10:00");
        assert_eq!(format_duration(3_725), "1:02:05");
    }
}
