//! Ventana principal (spec §4): cabecera, "Tu dirección", "Conexión remota",
//! pestañas Recientes/Favoritos con rejilla de equipos, barra de estado inferior,
//! y las ventanas flotantes de Ajustes y Seguridad.

use cleandesk_proto::{id::CleanDeskId, quality::QualityProfile};

use crate::app::{CleanDeskApp, DeviceTab, HostStatus};
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

/// Una tarjeta de la rejilla de equipos.
struct DeviceCard {
    id: CleanDeskId,
    name: String,
    subtitle: String,
    favorite: bool,
    /// Hay una contraseña desatendida recordada para este equipo.
    has_key: bool,
}

/// Dibuja la ventana principal completa.
pub fn show(app: &mut CleanDeskApp, ctx: &egui::Context) {
    header(app, ctx);
    footer(app, ctx);

    egui::CentralPanel::default()
        .frame(egui::Frame::new().fill(theme::BG).inner_margin(egui::Margin::same(24)))
        .show(ctx, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                if let Some(session) = app.host_session.clone() {
                    active_session_banner(app, ui, &session);
                    ui.add_space(12.0);
                }

                if let Some(notice) = app.notice.clone() {
                    ui.horizontal(|ui| {
                        ui.colored_label(theme::WARN, notice);
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
                        if ui.small_button("✕").clicked() {
                            app.notice = None;
                            app.identity_alarm = None;
                        }
                    });
                    ui.add_space(8.0);
                }

                ui.columns(2, |cols| {
                    this_device(app, &mut cols[0]);
                    connect_panel(app, &mut cols[1], ctx);
                });

                ui.add_space(20.0);
                device_tabs(app, ui);
                ui.add_space(12.0);
                device_grid(app, ui, ctx);
            });
        });

    settings_window(app, ctx);
    security_window(app, ctx);
    add_device_window(app, ctx);
}

/// Cabecera: logo, pestaña de sesión y acciones (seguridad, ajustes).
fn header(app: &mut CleanDeskApp, ctx: &egui::Context) {
    egui::TopBottomPanel::top("cd-header")
        .frame(
            egui::Frame::new()
                .fill(theme::BG)
                .inner_margin(egui::Margin::symmetric(16, 10))
                .stroke(egui::Stroke::new(1.0_f32, theme::BORDER)),
        )
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                // Logo.
                let (rect, _) = ui.allocate_exact_size(egui::vec2(26.0, 26.0), egui::Sense::hover());
                ui.painter().rect(
                    rect,
                    egui::CornerRadius::same(7),
                    egui::Color32::from_rgba_unmultiplied(16, 185, 129, 50),
                    egui::Stroke::new(1.0_f32, theme::ACCENT),
                    egui::StrokeKind::Inside,
                );
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    "C",
                    egui::FontId::proportional(14.0),
                    theme::ACCENT,
                );
                ui.label(egui::RichText::new("Clean").strong().size(15.0));
                ui.add_space(-8.0);
                ui.label(egui::RichText::new("Desk").strong().size(15.0).color(theme::ACCENT));

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(4.0);

                // Pestaña de sesión.
                egui::Frame::new()
                    .fill(theme::PANEL)
                    .stroke(egui::Stroke::new(1.0_f32, theme::BORDER))
                    .corner_radius(egui::CornerRadius::same(8))
                    .inner_margin(egui::Margin::symmetric(10, 5))
                    .show(ui, |ui| {
                        let (text, color) = if app.host_session.is_some() {
                            (tr("Incoming session active"), theme::WARN)
                        } else if app.is_connecting() {
                            (tr("Connecting…"), theme::WARN)
                        } else {
                            (tr("New session"), theme::ACCENT)
                        };
                        theme::status_dot(ui, color, text);
                    });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add(egui::Button::new(format!("⚙ {}", tr("Settings"))).frame(false))
                        .on_hover_text(tr("Settings"))
                        .clicked()
                    {
                        app.show_settings = !app.show_settings;
                    }
                    if ui
                        .add(egui::Button::new(format!("🔒 {}", tr("Security"))).frame(false))
                        .on_hover_text(tr("Device identity and fingerprint"))
                        .clicked()
                    {
                        app.show_security = !app.show_security;
                    }
                });
            });
        });
}

/// Barra de estado inferior.
fn footer(app: &CleanDeskApp, ctx: &egui::Context) {
    egui::TopBottomPanel::bottom("cd-footer")
        .frame(
            egui::Frame::new()
                .fill(theme::BG)
                .inner_margin(egui::Margin::symmetric(20, 7))
                .stroke(egui::Stroke::new(1.0_f32, theme::BORDER)),
        )
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                let community = app.network_mode().is_community();
                let (text, color) = match (app.host_status(), community) {
                    (HostStatus::Online, true) => (tr("Community mode: announced (LAN · DHT · Nostr)"), theme::ACCENT),
                    (HostStatus::Online, false) => (tr("CleanDesk network ready (private server)"), theme::ACCENT),
                    (HostStatus::Connecting, true) => (tr("Announcing on the community network…"), theme::WARN),
                    (HostStatus::Connecting, false) => (tr("Connecting to the server…"), theme::WARN),
                    (HostStatus::Offline, _) => (tr("Offline; retrying"), theme::DANGER),
                };
                theme::status_dot(ui, color, text);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!("v{}", crate::VERSION))
                            .size(11.0)
                            .color(theme::TEXT_MUTED),
                    );
                    let mode = app.network_mode();
                    let label = match mode.server_url() {
                        Some(url) => url.to_string(),
                        None => tr("no server").to_string(),
                    };
                    ui.label(egui::RichText::new(label).size(11.0).color(theme::TEXT_MUTED))
                        .on_hover_text(tr("Network mode (Settings → Network)"));
                });
            });
        });
}

/// Aviso de sesión entrante activa (spec §18) con botón para finalizarla.
fn active_session_banner(app: &CleanDeskApp, ui: &mut egui::Ui, session: &crate::app::HostSession) {
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(45, 30, 8))
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

/// Tarjeta "Tu dirección".
fn this_device(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    theme::card_accent().show(ui, |ui| {
        ui.horizontal(|ui| {
            theme::status_dot(ui, theme::ACCENT, "");
            theme::section_label(ui, tr("Your address"), true);
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            theme::big_id(ui, app.id);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(theme::ghost_button(tr("Copy"))).clicked() {
                    ui.ctx().copy_text(app.id.to_string());
                    app.notice = Some(tr("ID copied to the clipboard.").into());
                }
            });
        });
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(tr(
                "Share this identifier so others can connect to your screen with your permission.",
            ))
            .size(12.0)
            .color(theme::TEXT_DIM),
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(tr("Alias:")).color(theme::TEXT_DIM));
            let resp = ui.add(
                egui::TextEdit::singleline(&mut app.alias_edit)
                    .hint_text(tr("office-pc"))
                    .desired_width(160.0),
            );
            // Persistimos al perder el foco (por Enter o al hacer clic fuera), no
            // en cada pulsación.
            if resp.lost_focus() {
                persist_alias(app);
            }
        });
    });
}

/// Tarjeta "Conexión remota".
fn connect_panel(app: &mut CleanDeskApp, ui: &mut egui::Ui, ctx: &egui::Context) {
    theme::card().show(ui, |ui| {
        theme::section_label(ui, tr("Remote connection"), false);
        ui.add_space(10.0);

        let connecting = app.is_connecting();
        let mut go = false;

        ui.horizontal(|ui| {
            ui.add_enabled_ui(!connecting, |ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut app.connect_input)
                        .hint_text(tr("Enter remote ID…"))
                        .font(egui::TextStyle::Monospace)
                        .desired_width(ui.available_width() - 110.0),
                );
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    go = true;
                }
            });
            if connecting {
                ui.spinner();
            } else if ui.add(theme::primary_button(tr("Connect ›"))).clicked() {
                go = true;
            }
        });

        ui.add_space(6.0);
        ui.checkbox(&mut app.show_connect_password, tr("Unattended access (with password)"));
        if app.show_connect_password {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(tr("Password:")).color(theme::TEXT_DIM));
                ui.add(
                    egui::TextEdit::singleline(&mut app.connect_password)
                        .password(true)
                        .desired_width(160.0),
                );
                ui.checkbox(&mut app.remember_password, tr("Remember"))
                    .on_hover_text(tr("Saves the device to favorites with its derived key (never the plaintext password)"));
            });
        } else {
            app.connect_password.clear();
        }

        if connecting {
            let target = app.connecting_target().map(|t| t.to_string()).unwrap_or_default();
            ui.label(
                egui::RichText::new(trf("Waiting for {target}…", &[("target", &target)])).size(12.0).color(theme::TEXT_DIM),
            );
        }

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("🔒").color(theme::ACCENT).size(12.0));
            ui.label(
                egui::RichText::new(tr("End-to-end encryption (DTLS) enabled by default"))
                    .size(11.0)
                    .color(theme::TEXT_MUTED),
            );
        });

        if go && !connecting {
            match CleanDeskId::parse(&app.connect_input) {
                Ok(id) => app.start_connection(id, ctx),
                Err(_) => {
                    app.notice = Some(tr("Invalid CleanDesk ID. Check the number.").into());
                }
            }
        }
    });
}

/// Pestañas Recientes / Favoritos.
fn device_tabs(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        for (tab, label) in [
            (DeviceTab::Recent, format!("🕓 {}", tr("Recent"))),
            (DeviceTab::Favorites, format!("★ {}", tr("Favorites"))),
        ] {
            let selected = app.tab == tab;
            let color = if selected { theme::ACCENT } else { theme::TEXT_DIM };
            let resp = ui.add(
                egui::Button::new(egui::RichText::new(label).color(color).strong()).frame(false),
            );
            if resp.clicked() {
                app.tab = tab;
            }
            if selected {
                let r = resp.rect;
                ui.painter().hline(
                    r.x_range(),
                    r.bottom() + 6.0,
                    egui::Stroke::new(2.0_f32, theme::ACCENT),
                );
            }
            ui.add_space(12.0);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(theme::ghost_button(&format!("+ {}", tr("Add device")))).clicked() {
                app.show_add_device = true;
            }
        });
    });
    ui.add_space(6.0);
    ui.separator();
}

/// Construye las tarjetas de la pestaña activa.
fn collect_cards(app: &CleanDeskApp) -> Vec<DeviceCard> {
    let book = app.state.addressbook.read();
    match app.tab {
        DeviceTab::Recent => {
            let history = app.state.history.read();
            let mut seen = std::collections::HashSet::new();
            history
                .recent(60)
                .into_iter()
                .filter(|r| r.device != app.id && seen.insert(r.device))
                .take(12)
                .map(|r| {
                    let entry = book.find_by_id(r.device);
                    DeviceCard {
                        id: r.device,
                        name: entry.map(|e| e.name.clone()).unwrap_or_else(|| r.user.clone()),
                        subtitle: format!("{} · {}", r.connection_kind, format_when(r.started_at)),
                        favorite: entry.is_some(),
                        has_key: entry.is_some_and(|e| e.unattended_key.is_some()),
                    }
                })
                .collect()
        }
        DeviceTab::Favorites => book
            .entries
            .iter()
            .map(|e| DeviceCard {
                id: e.id,
                name: e.name.clone(),
                subtitle: e
                    .last_connection
                    .map(|t| trf("last connection {when}", &[("when", &format_when(t))]))
                    .unwrap_or_else(|| tr("no connections").into()),
                favorite: true,
                has_key: e.unattended_key.is_some(),
            })
            .collect(),
    }
}

/// Rejilla de tarjetas de equipos.
fn device_grid(app: &mut CleanDeskApp, ui: &mut egui::Ui, ctx: &egui::Context) {
    let cards = collect_cards(app);
    if cards.is_empty() {
        let text = match app.tab {
            DeviceTab::Recent => tr("No connections yet. Connect to an ID to see it here."),
            DeviceTab::Favorites => tr("You have not saved any device yet."),
        };
        ui.label(egui::RichText::new(text).color(theme::TEXT_MUTED));
        return;
    }

    let mut connect_target: Option<CleanDeskId> = None;
    let mut toggle_fav: Option<(CleanDeskId, String, bool)> = None;
    let mut forget_key: Option<CleanDeskId> = None;

    let cols = ((ui.available_width() / 260.0).floor() as usize).clamp(1, 4);
    egui::Grid::new("cd-device-grid").num_columns(cols).spacing([14.0, 14.0]).show(ui, |ui| {
        for (i, card) in cards.iter().enumerate() {
            let hovered = ui.rect_contains_pointer(ui.available_rect_before_wrap());
            theme::device_card(hovered).show(ui, |ui| ui.vertical(|ui| {
                ui.set_width(230.0);
                // "Miniatura": bloque oscuro con icono de monitor y estrella.
                let (rect, _) = ui.allocate_exact_size(egui::vec2(230.0, 70.0), egui::Sense::hover());
                ui.painter().rect(
                    rect,
                    egui::CornerRadius::same(theme::RADIUS_SM),
                    theme::PANEL,
                    egui::Stroke::new(1.0_f32, theme::BORDER),
                    egui::StrokeKind::Inside,
                );
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    "🖥",
                    egui::FontId::proportional(30.0),
                    theme::BORDER_SOFT,
                );
                let star_rect = egui::Rect::from_center_size(
                    egui::pos2(rect.right() - 14.0, rect.top() + 14.0),
                    egui::vec2(20.0, 20.0),
                );
                let star = ui.put(
                    star_rect,
                    egui::Button::new(
                        egui::RichText::new(if card.favorite { "★" } else { "☆" })
                            .color(if card.favorite { theme::STAR } else { theme::TEXT_DIM }),
                    )
                    .frame(false),
                );
                if star.on_hover_text(tr("Add to / remove from favorites")).clicked() {
                    toggle_fav = Some((card.id, card.name.clone(), card.favorite));
                }
                if card.has_key {
                    let key_rect = egui::Rect::from_center_size(
                        egui::pos2(rect.left() + 14.0, rect.top() + 14.0),
                        egui::vec2(20.0, 20.0),
                    );
                    let k = ui.put(key_rect, egui::Button::new(egui::RichText::new("🔑").color(theme::ACCENT)).frame(false));
                    if k.on_hover_text(tr("Password remembered (click to forget it)")).clicked() {
                        forget_key = Some(card.id);
                    }
                }

                // `ui.put` deja el cursor bajo el último rect colocado (la estrella,
                // dentro de la miniatura); lo devolvemos al pie de la miniatura.
                ui.advance_cursor_after_rect(rect);
                ui.add_space(6.0);
                // Fila inferior con anchos fijos: la columna de texto trunca en
                // una línea (sin esto egui la estrechaba y el nombre se partía
                // letra a letra hacia abajo).
                let row = ui.available_rect_before_wrap();
                let text_w = 230.0 - 44.0;
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(text_w, 64.0),
                        egui::Layout::top_down(egui::Align::LEFT),
                        |ui| {
                            ui.set_max_width(text_w);
                            ui.add(egui::Label::new(egui::RichText::new(&card.name).strong()).truncate());
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(format!("{}{}", card.id, if card.has_key { "  🔑" } else { "" }))
                                        .monospace()
                                        .size(12.0)
                                        .color(theme::TEXT_MUTED),
                                )
                                .truncate(),
                            );
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&card.subtitle).size(10.0).color(theme::TEXT_MUTED),
                                )
                                .truncate(),
                            );
                        },
                    );
                    let btn = egui::Rect::from_center_size(
                        egui::pos2(row.right() - 18.0, row.top() + 30.0),
                        egui::vec2(34.0, 30.0),
                    );
                    if ui.put(btn, theme::primary_button("▶")).on_hover_text(tr("Connect")).clicked() {
                        connect_target = Some(card.id);
                    }
                });
            }));
            if (i + 1) % cols == 0 {
                ui.end_row();
            }
        }
    });

    if let Some((id, name, was_fav)) = toggle_fav {
        if was_fav {
            app.remove_favorite(id);
        } else {
            app.add_favorite(id, name);
        }
    }
    if let Some(id) = forget_key {
        app.forget_key(id);
        app.notice = Some(tr("Password forgotten.").into());
    }
    if let Some(id) = connect_target {
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
            if ui.add(theme::primary_button(tr("Save"))).clicked() {
                match CleanDeskId::parse(&app.add_device_id) {
                    Ok(id) => {
                        app.add_favorite(id, app.add_device_name.trim().to_string());
                        app.tab = DeviceTab::Favorites;
                        done = true;
                    }
                    Err(_) => app.notice = Some(tr("Invalid CleanDesk ID.").into()),
                }
            }
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
        .default_width(380.0)
        .show(ctx, |ui| {
            language_settings(app, ui);
            ui.add_space(10.0);

            tray_settings(app, ui);
            ui.add_space(10.0);

            network_settings(app, ui);
            ui.add_space(10.0);

            // --- Calidad por defecto ---
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
    app.show_settings = open;
}

/// Sub-sección "Idioma": sistema, inglés o español. El cambio se aplica en el
/// acto y se persiste (`None` = seguir al sistema).
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

fn language_settings(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    theme::section_label(ui, tr("Language"), true);

    // `None` = sistema; `Some(tag)` = idioma fijado por el usuario.
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

    // Campo de contraseña (solo relevante al activar).
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
            // Activamos: requiere contraseña.
            let pw = app.unattended_pw.trim().to_string();
            if pw.len() < 6 {
                app.notice = Some(tr("The unattended-access password must be at least 6 characters long.").into());
                // Revertimos el check hasta que haya contraseña.
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
            // Desactivamos y olvidamos los secretos.
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

    // Refrescamos el estado real del SO cada pocos segundos (consultar el SCM
    // cuesta unos milisegundos; no lo hacemos en cada fotograma).
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

    // --- Iniciar con Windows ---
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

    // --- Servicio de Windows ---
    let installed = app.service_status != ServiceStatus::NotInstalled;
    let mut want_service = installed;
    let changed = ui
        .checkbox(&mut want_service, tr("Install as a service (unattended access before sign-in)"))
        .on_hover_text(tr("Requires administrator rights. The service keeps the unattended host running even when nobody is signed in; when you open CleanDesk, the GUI takes over."))
        .changed();
    let (status_text, status_color) = match app.service_status {
        ServiceStatus::Running => (tr("Service installed and running"), theme::ACCENT),
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
        // El idioma es global al proceso; comprobamos en el estado por defecto
        // (inglés) sin tocarlo para no interferir con otros tests.
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
}
