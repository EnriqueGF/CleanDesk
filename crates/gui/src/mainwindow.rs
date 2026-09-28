//! Ventana principal (spec §4): cabecera, "Tu dirección", "Conexión remota",
//! pestañas Recientes/Favoritos con rejilla de equipos, barra de estado inferior,
//! y las ventanas flotantes de Ajustes y Seguridad.

use cleandesk_proto::{id::CleanDeskId, quality::QualityProfile};

use crate::app::{CleanDeskApp, DeviceTab, HostStatus};
use crate::theme;

/// Perfiles de calidad para el selector de ajustes (mismo orden que el visor).
pub const QUALITY_PROFILES: &[QualityProfile] = &[
    QualityProfile::Auto,
    QualityProfile::Max,
    QualityProfile::Balanced,
    QualityProfile::Performance,
];

pub fn quality_label(profile: QualityProfile) -> &'static str {
    match profile {
        QualityProfile::Auto => "Automática",
        QualityProfile::Max => "Máxima calidad",
        QualityProfile::Balanced => "Equilibrado",
        QualityProfile::Performance => "Máximo rendimiento",
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
                                .add(theme::danger_button("Confiar en la nueva identidad"))
                                .on_hover_text("Solo si has comprobado la huella del equipo por otro canal")
                                .clicked()
                            {
                                app.unpin_key(id);
                                app.identity_alarm = None;
                                app.notice = Some("Clave anterior olvidada; vuelve a conectar.".into());
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
                    "✦",
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
                            ("Sesión entrante activa", theme::WARN)
                        } else if app.is_connecting() {
                            ("Conectando…", theme::WARN)
                        } else {
                            ("Nueva sesión", theme::ACCENT)
                        };
                        theme::status_dot(ui, color, text);
                    });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add(egui::Button::new("⚙ Ajustes").frame(false))
                        .on_hover_text("Ajustes")
                        .clicked()
                    {
                        app.show_settings = !app.show_settings;
                    }
                    if ui
                        .add(egui::Button::new("🔒 Seguridad").frame(false))
                        .on_hover_text("Identidad y huella del dispositivo")
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
                    (HostStatus::Online, true) => ("Modo comunitario: anunciado (LAN · DHT · Nostr)", theme::ACCENT),
                    (HostStatus::Online, false) => ("Red CleanDesk lista (servidor privado)", theme::ACCENT),
                    (HostStatus::Connecting, true) => ("Anunciando en la red comunitaria…", theme::WARN),
                    (HostStatus::Connecting, false) => ("Conectando con el servidor…", theme::WARN),
                    (HostStatus::Offline, _) => ("Sin conexión; reintentando", theme::DANGER),
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
                        None => "sin servidor".to_string(),
                    };
                    ui.label(egui::RichText::new(label).size(11.0).color(theme::TEXT_MUTED))
                        .on_hover_text("Modo de red (Ajustes → Red)");
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
                    egui::RichText::new(format!("{who} ({}) está viendo tu pantalla", session.peer.id))
                        .strong(),
                );
                let perms: Vec<&str> = crate::approval::PERMISSION_ITEMS
                    .iter()
                    .filter(|(p, _)| session.granted.contains(*p))
                    .map(|(_, l)| *l)
                    .collect();
                ui.label(egui::RichText::new(perms.join(" · ")).size(11.0).color(theme::TEXT_DIM));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(theme::danger_button("Finalizar sesión")).clicked() {
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
            theme::section_label(ui, "Tu dirección", true);
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            theme::big_id(ui, app.id);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(theme::ghost_button("⎘ Copiar")).clicked() {
                    ui.ctx().copy_text(app.id.to_string());
                    app.notice = Some("ID copiado al portapapeles.".into());
                }
            });
        });
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "Comparte este identificador para que otros se conecten a tu pantalla con tu permiso.",
            )
            .size(12.0)
            .color(theme::TEXT_DIM),
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Alias:").color(theme::TEXT_DIM));
            let resp = ui.add(
                egui::TextEdit::singleline(&mut app.alias_edit)
                    .hint_text("pc-oficina")
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
        theme::section_label(ui, "Conexión remota", false);
        ui.add_space(10.0);

        let connecting = app.is_connecting();
        let mut go = false;

        ui.horizontal(|ui| {
            ui.add_enabled_ui(!connecting, |ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut app.connect_input)
                        .hint_text("Introduce ID remoto…")
                        .font(egui::TextStyle::Monospace)
                        .desired_width(ui.available_width() - 110.0),
                );
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    go = true;
                }
            });
            if connecting {
                ui.spinner();
            } else if ui.add(theme::primary_button("Conectar →")).clicked() {
                go = true;
            }
        });

        ui.add_space(6.0);
        ui.checkbox(&mut app.show_connect_password, "Acceso desatendido (con contraseña)");
        if app.show_connect_password {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Contraseña:").color(theme::TEXT_DIM));
                ui.add(
                    egui::TextEdit::singleline(&mut app.connect_password)
                        .password(true)
                        .desired_width(160.0),
                );
                ui.checkbox(&mut app.remember_password, "Recordar")
                    .on_hover_text("Guarda el equipo en favoritos con su clave derivada (nunca la contraseña en claro)");
            });
        } else {
            app.connect_password.clear();
        }

        if connecting {
            let target = app.connecting_target().map(|t| t.to_string()).unwrap_or_default();
            ui.label(
                egui::RichText::new(format!("Esperando a {target}…")).size(12.0).color(theme::TEXT_DIM),
            );
        }

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("🔒").color(theme::ACCENT).size(12.0));
            ui.label(
                egui::RichText::new("Cifrado extremo a extremo (DTLS) activado por defecto")
                    .size(11.0)
                    .color(theme::TEXT_MUTED),
            );
        });

        if go && !connecting {
            match CleanDeskId::parse(&app.connect_input) {
                Ok(id) => app.start_connection(id, ctx),
                Err(_) => {
                    app.notice = Some("CleanDesk ID no válido. Revisa el número.".into());
                }
            }
        }
    });
}

/// Pestañas Recientes / Favoritos.
fn device_tabs(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        for (tab, label) in [(DeviceTab::Recent, "🕓 Recientes"), (DeviceTab::Favorites, "★ Favoritos")] {
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
            if ui.add(theme::ghost_button("+ Añadir dispositivo")).clicked() {
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
                    .map(|t| format!("última conexión {}", format_when(t)))
                    .unwrap_or_else(|| "sin conexiones".into()),
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
            DeviceTab::Recent => "Sin conexiones todavía. Conecta a un ID para verlo aquí.",
            DeviceTab::Favorites => "Aún no has guardado ningún dispositivo.",
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
            theme::device_card(hovered).show(ui, |ui| {
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
                if star.on_hover_text("Guardar / quitar de favoritos").clicked() {
                    toggle_fav = Some((card.id, card.name.clone(), card.favorite));
                }
                if card.has_key {
                    let key_rect = egui::Rect::from_center_size(
                        egui::pos2(rect.left() + 14.0, rect.top() + 14.0),
                        egui::vec2(20.0, 20.0),
                    );
                    let k = ui.put(key_rect, egui::Button::new(egui::RichText::new("🔑").color(theme::ACCENT)).frame(false));
                    if k.on_hover_text("Contraseña recordada (clic para olvidarla)").clicked() {
                        forget_key = Some(card.id);
                    }
                }

                ui.add_space(6.0);
                // Fila inferior con anchos fijos: la columna de texto trunca en
                // una línea (sin esto egui la estrechaba y el nombre se partía
                // letra a letra hacia abajo).
                let row = ui.available_rect_before_wrap();
                let text_w = 230.0 - 44.0;
                ui.horizontal(|ui| {
                    ui.set_min_height(48.0);
                    ui.allocate_ui_with_layout(
                        egui::vec2(text_w, 48.0),
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
                        egui::pos2(row.right() - 18.0, row.top() + 24.0),
                        egui::vec2(34.0, 30.0),
                    );
                    if ui.put(btn, theme::primary_button("▶")).on_hover_text("Conectar").clicked() {
                        connect_target = Some(card.id);
                    }
                });
            });
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
        app.notice = Some("Contraseña olvidada.".into());
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
    egui::Window::new("Añadir dispositivo")
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .show(ctx, |ui| {
            ui.label(egui::RichText::new("Guardar un host permanente en favoritos").color(theme::TEXT_DIM));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("CleanDesk ID:");
                ui.add(
                    egui::TextEdit::singleline(&mut app.add_device_id)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("548 291 743"),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Nombre:");
                ui.add(egui::TextEdit::singleline(&mut app.add_device_name).hint_text("Portátil oficina"));
            });
            ui.add_space(8.0);
            if ui.add(theme::primary_button("Guardar")).clicked() {
                match CleanDeskId::parse(&app.add_device_id) {
                    Ok(id) => {
                        app.add_favorite(id, app.add_device_name.trim().to_string());
                        app.tab = DeviceTab::Favorites;
                        done = true;
                    }
                    Err(_) => app.notice = Some("CleanDesk ID no válido.".into()),
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
    egui::Window::new("Seguridad")
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .show(ctx, |ui| {
            ui.label(
                egui::RichText::new("La identidad de este equipo es un par de claves Ed25519. Tu CleanDesk ID se deriva de la clave pública y el servidor exige una firma para registrarlo: nadie puede suplantar tu ID sin la clave privada.")
                    .color(theme::TEXT_DIM),
            );
            ui.add_space(8.0);
            theme::section_label(ui, "Huella de identidad", true);
            ui.label(egui::RichText::new(app.state.identity.fingerprint()).monospace());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Compárala por otro canal (teléfono, mensaje) con la persona que se conecta.")
                    .size(11.0)
                    .color(theme::TEXT_MUTED),
            );
            ui.add_space(8.0);
            theme::section_label(ui, "Cifrado", false);
            ui.label(egui::RichText::new("Vídeo, input y control viajan por DTLS extremo a extremo; el servidor solo retransmite la señalización.").size(12.0).color(theme::TEXT_DIM));
            ui.label(egui::RichText::new("La contraseña de acceso desatendido se guarda solo como hash Argon2id y nunca cruza la red (reto-respuesta HMAC).").size(12.0).color(theme::TEXT_DIM));
        });
    app.show_security = open;
}

/// Ventana flotante de ajustes (spec §8, §9, §24).
fn settings_window(app: &mut CleanDeskApp, ctx: &egui::Context) {
    if !app.show_settings {
        return;
    }
    let mut open = true;
    egui::Window::new("Ajustes")
        .open(&mut open)
        .collapsible(false)
        .default_width(380.0)
        .show(ctx, |ui| {
            network_settings(app, ui);
            ui.add_space(10.0);

            // --- Calidad por defecto ---
            theme::section_label(ui, "Calidad por defecto", true);
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

/// Sub-sección de acceso desatendido.
fn unattended_settings(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    theme::section_label(ui, "Acceso desatendido", true);

    let mut enabled = app.state.settings.read().unattended_enabled;
    let toggled = ui
        .checkbox(&mut enabled, "Permitir conexiones desatendidas")
        .changed();

    // Campo de contraseña (solo relevante al activar).
    ui.horizontal(|ui| {
        ui.label("Contraseña:");
        ui.add(egui::TextEdit::singleline(&mut app.unattended_pw).password(true));
    });
    ui.label(
        egui::RichText::new("Quien conecte con esta contraseña entra sin que tengas que aceptar. Reinicia la app tras cambiarla para que el host la use.")
            .size(11.0)
            .color(theme::TEXT_MUTED),
    );

    if toggled {
        if enabled {
            // Activamos: requiere contraseña.
            let pw = app.unattended_pw.trim().to_string();
            if pw.len() < 6 {
                app.notice = Some("La contraseña de acceso desatendido debe tener al menos 6 caracteres.".into());
                // Revertimos el check hasta que haya contraseña.
                app.state.settings.write().unattended_enabled = false;
            } else {
                let host_id = app.id.value();
                let result = app.state.settings.write().enable_unattended(&pw, host_id);
                match result {
                    Ok(()) => {
                        app.unattended_pw.clear();
                        app.save_settings();
                        app.notice = Some("Acceso desatendido activado.".into());
                    }
                    Err(e) => {
                        app.state.settings.write().unattended_enabled = false;
                        app.notice = Some(format!("No se pudo activar: {e}"));
                    }
                }
            }
        } else {
            // Desactivamos y olvidamos los secretos.
            app.state.settings.write().disable_unattended();
            app.save_settings();
            app.notice = Some("Acceso desatendido desactivado.".into());
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

/// "hace 5 min", "hace 3 h", "hace 2 d" a partir de un instante Unix.
pub fn format_when(unix: u64) -> String {
    let now = crate::app::unix_now();
    let secs = now.saturating_sub(unix);
    if secs < 60 {
        "ahora".into()
    } else if secs < 3600 {
        format!("hace {} min", secs / 60)
    } else if secs < 86_400 {
        format!("hace {} h", secs / 3600)
    } else {
        format!("hace {} d", secs / 86_400)
    }
}


/// Sub-sección "Sistema" (spec §24): arranque con la sesión y servicio de Windows.
fn system_settings(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    use cleandesk_platform::service::ServiceStatus;
    use cleandesk_platform::{service, startup};

    theme::section_label(ui, "Sistema", true);

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
    if ui.checkbox(&mut run_at_login, "Iniciar con Windows (al iniciar sesión)").changed() {
        match exe.as_deref().map(|e| startup::set_run_at_login(run_at_login, e, &[])) {
            Some(Ok(())) => {
                app.run_at_login = run_at_login;
                app.state.settings.write().start_with_windows = run_at_login;
                app.save_settings();
                app.notice = Some(if run_at_login {
                    "CleanDesk se abrirá al iniciar sesión.".into()
                } else {
                    "CleanDesk ya no se abrirá al iniciar sesión.".into()
                });
            }
            Some(Err(e)) => app.notice = Some(format!("No se pudo cambiar el arranque: {e}")),
            None => app.notice = Some("No se pudo localizar el ejecutable.".into()),
        }
        app.platform_checked_at = None;
    }

    // --- Servicio de Windows ---
    let installed = app.service_status != ServiceStatus::NotInstalled;
    let mut want_service = installed;
    let changed = ui
        .checkbox(&mut want_service, "Instalar como servicio (acceso desatendido antes de iniciar sesión)")
        .on_hover_text("Pide permisos de administrador. El servicio mantiene el host desatendido activo aunque nadie haya iniciado sesión; cuando abres CleanDesk, la GUI toma el relevo.")
        .changed();
    let (status_text, status_color) = match app.service_status {
        ServiceStatus::Running => ("Servicio instalado y en ejecución", theme::ACCENT),
        ServiceStatus::Stopped => ("Servicio instalado (parado)", theme::WARN),
        ServiceStatus::Other => ("Servicio cambiando de estado…", theme::WARN),
        ServiceStatus::NotInstalled => ("Servicio no instalado", theme::TEXT_MUTED),
    };
    ui.horizontal(|ui| {
        theme::status_dot(ui, status_color, status_text);
    });
    if installed && !app.state.settings.read().unattended_enabled {
        ui.label(
            egui::RichText::new("El servicio solo atiende acceso desatendido: activa una contraseña arriba para que sea útil.")
                .size(11.0)
                .color(theme::WARN),
        );
    }
    if changed {
        let result = match (want_service, exe.as_deref()) {
            (true, Some(e)) => service::request_install(e, &app.state.data_dir()),
            (false, Some(e)) => service::request_uninstall(e),
            (_, None) => Err(cleandesk_platform::PlatformError::Other("no se pudo localizar el ejecutable".into())),
        };
        match result {
            Ok(()) => {
                app.state.settings.write().install_service = want_service;
                app.save_settings();
                app.notice = Some(if want_service {
                    "Servicio CleanDesk instalado y arrancado.".into()
                } else {
                    "Servicio CleanDesk eliminado.".into()
                });
            }
            Err(cleandesk_platform::PlatformError::ElevationDeclined) => {
                app.notice = Some("Operación cancelada: se necesitan permisos de administrador.".into());
            }
            Err(e) => app.notice = Some(format!("No se pudo cambiar el servicio: {e}")),
        }
        app.platform_checked_at = None;
    }
}


/// Sub-sección "Red": modo comunitario (sin servidor) o servidor privado.
fn network_settings(app: &mut CleanDeskApp, ui: &mut egui::Ui) {
    use cleandesk_core::config::NetworkMode;

    theme::section_label(ui, "Red", true);
    if let Some(url) = &app.signal_override {
        ui.label(
            egui::RichText::new(format!("Forzado por --signal-url: {url}"))
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
        .radio_value(&mut community, true, "Comunitario (sin servidor): LAN, DHT de BitTorrent y relés Nostr")
        .changed();
    changed |= ui
        .radio_value(&mut community, false, "Servidor privado CleanDesk")
        .changed();
    if !community {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("URL:").color(theme::TEXT_DIM));
            let resp = ui.add(egui::TextEdit::singleline(&mut url).hint_text("ws://servidor:7420").desired_width(240.0));
            if resp.lost_focus() {
                changed = true;
            }
        });
    }
    ui.label(
        egui::RichText::new(if community {
            "Tu equipo se anuncia firmado en la DHT y en tu red local; nadie tiene que mantener servidores. La primera conexión fija la clave del equipo remoto (huella en Seguridad)."
        } else {
            "Toda la señalización pasa por tu servidor; útil en empresas y redes cerradas."
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
                app.notice = Some("La URL del servidor debe empezar por ws:// o wss://".into());
                return;
            }
            NetworkMode::Server { url }
        };
        if new_mode != current {
            app.state.settings.write().network = new_mode;
            app.save_settings();
            app.restart_host();
            app.notice = Some("Modo de red actualizado; el host se reinicia.".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_when_buckets() {
        let now = crate::app::unix_now();
        assert_eq!(format_when(now), "ahora");
        assert_eq!(format_when(now - 120), "hace 2 min");
        assert_eq!(format_when(now - 7200), "hace 2 h");
        assert_eq!(format_when(now - 3 * 86_400), "hace 3 d");
        assert_eq!(format_when(now + 1000), "ahora", "future timestamps never underflow");
    }
}
