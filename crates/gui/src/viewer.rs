//! Visor de sesión (spec §7, §15, §16, §17, §26, §27).
//!
//! Cuando hay una [`ClientSession`] activa, este módulo:
//! * vacía el canal de frames quedándose con el último y lo sube a una textura
//!   reutilizada,
//! * dibuja la imagen ajustada a la ventana (o a escala 1:1), con conmutadores de
//!   pantalla completa y "ajustar a ventana",
//! * captura ratón y teclado sobre el rectángulo de la imagen y los reenvía como
//!   [`InputEvent`] normalizados, respetando los permisos concedidos,
//! * muestra una barra de herramientas con monitor, calidad, estadísticas, chat y
//!   un botón de desconexión.
//!
//! Todas las llamadas a la sesión son síncronas y no bloqueantes (encolan en
//! canales), así que el hilo de la interfaz nunca espera a la red.

use cleandesk_client::{ClientEvent, ClientSession};
use cleandesk_codec::DecodedImage;
use cleandesk_proto::{
    message::{InputEvent, MonitorInfo, MouseButton},
    permissions::Permissions,
    quality::QualityProfile,
    session::{DeviceInfo, SessionId, SessionStats},
};
use tracing::debug;

use crate::keymap::{key_to_vk, VK_CONTROL, VK_MENU, VK_SHIFT};
use crate::mainwindow::{quality_label, QUALITY_PROFILES};
use crate::theme;

/// Resultado de dibujar el visor en un fotograma.
pub enum ViewerOutcome {
    /// La sesión sigue activa.
    Continue,
    /// La sesión terminó; volver a la ventana principal con un aviso opcional.
    Disconnected(Option<String>),
}

/// Estado de los modificadores que ya hemos comunicado al host, para emitir solo
/// los cambios (pulsar/soltar) en lugar de reenviar el estado completo.
#[derive(Default, Clone, Copy)]
struct ModifierState {
    shift: bool,
    ctrl: bool,
    alt: bool,
}

/// Todo el estado vivo de una sesión en el visor.
pub struct ViewerState {
    session: ClientSession,
    /// Permisos concedidos, actualizados en vivo por el host.
    granted: Permissions,
    /// Quién está al otro lado (llega en el `Hello` del host).
    peer: Option<DeviceInfo>,
    /// Textura reutilizada donde subimos cada frame decodificado.
    texture: Option<egui::TextureHandle>,
    /// Tamaño del último frame recibido (px).
    frame_size: [usize; 2],
    /// Frames recibidos (para el contador de la barra).
    frames_received: u64,

    /// Estadísticas de sesión más recientes (para la barra).
    stats: Option<SessionStats>,
    /// Perfil de calidad seleccionado en la barra.
    quality: QualityProfile,
    /// Monitores del host y el seleccionado.
    monitors: Vec<MonitorInfo>,
    monitor: u16,

    /// Registro de chat de la sesión.
    chat_log: Vec<String>,
    /// Texto en edición del chat.
    chat_input: String,
    /// Si el panel de chat está visible.
    show_chat: bool,
    /// Mensajes sin leer mientras el panel está cerrado.
    unread_chat: usize,

    /// Ajustar la imagen a la ventana (si no, se muestra 1:1).
    fit_to_window: bool,
    /// Estado de pantalla completa (lo pedimos por ViewportCommand).
    fullscreen: bool,

    /// Estado de modificadores ya enviado al host.
    modifiers: ModifierState,
    /// Últimas coordenadas normalizadas enviadas, para no repetir moves idénticos.
    last_move: Option<(f32, f32)>,
}

impl ViewerState {
    /// Crea el estado del visor a partir de una sesión recién establecida.
    pub fn new(session: ClientSession) -> Self {
        let granted = session.granted;
        Self {
            session,
            granted,
            peer: None,
            texture: None,
            frame_size: [0, 0],
            frames_received: 0,
            stats: None,
            quality: QualityProfile::Auto,
            monitors: Vec::new(),
            monitor: 0,
            chat_log: Vec::new(),
            chat_input: String::new(),
            show_chat: false,
            unread_chat: 0,
            fit_to_window: true,
            fullscreen: false,
            modifiers: ModifierState::default(),
            last_move: None,
        }
    }

    pub fn session_id(&self) -> SessionId {
        self.session.session
    }

    pub fn is_fullscreen(&self) -> bool {
        self.fullscreen
    }

    /// Solicita el cierre ordenado de la sesión (best-effort, no bloquea).
    pub fn disconnect(&self) {
        self.release_modifiers();
        self.session.disconnect();
    }

    /// Suelta los modificadores que seguimos teniendo "pulsados" en el host.
    fn release_modifiers(&self) {
        for (held, code) in [
            (self.modifiers.shift, VK_SHIFT),
            (self.modifiers.ctrl, VK_CONTROL),
            (self.modifiers.alt, VK_MENU),
        ] {
            if held {
                self.session.send_input(InputEvent::Key { code, pressed: false });
            }
        }
    }

    /// ¿Se permite reenviar movimiento/clic de ratón?
    fn mouse_allowed(&self) -> bool {
        self.granted.contains(Permissions::CONTROL_MOUSE)
    }

    /// ¿Se permite reenviar teclado?
    fn keyboard_allowed(&self) -> bool {
        self.granted.contains(Permissions::CONTROL_KEYBOARD)
    }
}

/// Dibuja el visor durante un fotograma y devuelve si continúa o termina.
pub fn show(viewer: &mut ViewerState, ctx: &egui::Context) -> ViewerOutcome {
    // Mientras haya sesión, repintamos continuamente para un vídeo fluido.
    ctx.request_repaint();

    // 1) Procesar eventos de control de la sesión.
    if let Some(outcome) = drain_events(viewer) {
        return outcome;
    }

    // 2) Subir el último frame disponible a la textura.
    upload_latest_frame(viewer, ctx);

    // 3) Barra de herramientas superior.
    let mut disconnect_requested = false;
    egui::TopBottomPanel::top("viewer-toolbar")
        .frame(
            egui::Frame::new()
                .fill(theme::BG)
                .inner_margin(egui::Margin::symmetric(12, 8))
                .stroke(egui::Stroke::new(1.0_f32, theme::BORDER)),
        )
        .show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                let who = viewer
                    .peer
                    .as_ref()
                    .map(|p| p.alias.clone().unwrap_or_else(|| p.hostname.clone()))
                    .unwrap_or_else(|| "equipo remoto".into());
                theme::status_dot(ui, theme::ACCENT, "");
                ui.label(egui::RichText::new(who).strong());
                ui.separator();

                // Selector de monitor (spec §15).
                if viewer.monitors.len() > 1 {
                    ui.label(egui::RichText::new("Pantalla:").color(theme::TEXT_DIM));
                    let before = viewer.monitor;
                    egui::ComboBox::from_id_salt("viewer-monitor")
                        .selected_text(monitor_label(&viewer.monitors, viewer.monitor))
                        .show_ui(ui, |ui| {
                            for m in &viewer.monitors {
                                ui.selectable_value(&mut viewer.monitor, m.index, monitor_label(&viewer.monitors, m.index));
                            }
                        });
                    if viewer.monitor != before {
                        viewer.session.select_monitor(viewer.monitor);
                    }
                    ui.separator();
                }

                // Selector de calidad.
                ui.label(egui::RichText::new("Calidad:").color(theme::TEXT_DIM));
                let before = viewer.quality;
                egui::ComboBox::from_id_salt("viewer-quality")
                    .selected_text(quality_label(viewer.quality))
                    .show_ui(ui, |ui| {
                        for profile in QUALITY_PROFILES {
                            ui.selectable_value(&mut viewer.quality, *profile, quality_label(*profile));
                        }
                    });
                if viewer.quality != before {
                    viewer.session.set_quality(viewer.quality);
                }

                ui.separator();

                // Ajustar a ventana / pantalla completa.
                ui.checkbox(&mut viewer.fit_to_window, "Ajustar");
                if ui
                    .checkbox(&mut viewer.fullscreen, "Pantalla completa")
                    .changed()
                {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(viewer.fullscreen));
                }
                if ui.button("⟳").on_hover_text("Refrescar imagen (pedir keyframe)").clicked() {
                    viewer.session.request_keyframe();
                }

                ui.separator();
                let chat_label = if viewer.unread_chat > 0 {
                    format!("Chat ({})", viewer.unread_chat)
                } else {
                    "Chat".to_string()
                };
                if ui.toggle_value(&mut viewer.show_chat, chat_label).changed() && viewer.show_chat {
                    viewer.unread_chat = 0;
                }

                // Botón de desconexión, alineado a la derecha.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(theme::danger_button("Desconectar")).clicked() {
                        disconnect_requested = true;
                    }
                });
            });

            // Línea de estadísticas (spec §26).
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new(stats_line(viewer)).size(11.0).color(theme::TEXT_MUTED));
                // Aviso si no hay control.
                if !viewer.granted.contains(Permissions::CONTROL_MOUSE)
                    && !viewer.granted.contains(Permissions::CONTROL_KEYBOARD)
                {
                    ui.label(
                        egui::RichText::new("· Solo visualización (sin control concedido)")
                            .size(11.0)
                            .italics()
                            .color(theme::WARN),
                    );
                }
            });
        });

    if disconnect_requested {
        return ViewerOutcome::Disconnected(Some("Sesión finalizada.".into()));
    }

    // 4) Panel de chat opcional (spec §17).
    if viewer.show_chat {
        show_chat_panel(viewer, ctx);
    }

    // 5) Área central: la imagen remota + captura de input.
    egui::CentralPanel::default()
        .frame(egui::Frame::new().fill(egui::Color32::BLACK))
        .show(ctx, |ui| {
            render_video_and_input(viewer, ui);
        });

    ViewerOutcome::Continue
}

fn monitor_label(monitors: &[MonitorInfo], index: u16) -> String {
    match monitors.iter().find(|m| m.index == index) {
        Some(m) => format!(
            "{} {}×{}{}",
            m.index + 1,
            m.width,
            m.height,
            if m.primary { " (principal)" } else { "" }
        ),
        None => format!("{}", index + 1),
    }
}

/// Procesa los eventos de control de la sesión. Devuelve `Some` si la sesión
/// debe terminar.
fn drain_events(viewer: &mut ViewerState) -> Option<ViewerOutcome> {
    loop {
        match viewer.session.events.try_recv() {
            Ok(ClientEvent::Connected) => {}
            Ok(ClientEvent::Hello(info)) => viewer.peer = Some(info),
            Ok(ClientEvent::PermissionsUpdated(p)) => {
                debug!(?p, "permisos actualizados por el host");
                viewer.granted = p;
            }
            Ok(ClientEvent::Stats(s)) => {
                viewer.stats = Some(s);
            }
            Ok(ClientEvent::Chat(text)) => {
                viewer.chat_log.push(format!("Remoto: {text}"));
                if !viewer.show_chat {
                    viewer.unread_chat += 1;
                }
            }
            Ok(ClientEvent::Monitors(mons)) => {
                viewer.monitor = mons
                    .iter()
                    .find(|m| m.primary)
                    .or_else(|| mons.first())
                    .map(|m| m.index)
                    .unwrap_or(0);
                viewer.monitors = mons;
            }
            Ok(ClientEvent::AuthResult(ok)) => {
                if !ok {
                    return Some(ViewerOutcome::Disconnected(Some(
                        "Autenticación rechazada por el equipo remoto.".into(),
                    )));
                }
            }
            Ok(ClientEvent::Disconnected(reason)) => {
                return Some(ViewerOutcome::Disconnected(Some(format!(
                    "Desconectado: {reason}"
                ))));
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => return None,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                return Some(ViewerOutcome::Disconnected(Some(
                    "La sesión se cerró.".into(),
                )));
            }
        }
    }
}

/// Vacía el canal de frames quedándose con el último y lo sube a la textura.
fn upload_latest_frame(viewer: &mut ViewerState, ctx: &egui::Context) {
    let mut latest: Option<DecodedImage> = None;
    while let Ok(img) = viewer.session.frames.try_recv() {
        viewer.frames_received += 1;
        latest = Some(img);
    }
    let Some(img) = latest else { return };

    let size = [img.width as usize, img.height as usize];
    // Sanea el tamaño frente al buffer para no construir una imagen inválida.
    if size[0] == 0 || size[1] == 0 || img.rgba.len() != size[0] * size[1] * 4 {
        debug!(w = size[0], h = size[1], len = img.rgba.len(), "frame con tamaño inconsistente");
        return;
    }

    let color = egui::ColorImage::from_rgba_unmultiplied(size, &img.rgba);
    viewer.frame_size = size;

    match &mut viewer.texture {
        Some(tex) => tex.set(color, egui::TextureOptions::LINEAR),
        None => {
            viewer.texture =
                Some(ctx.load_texture("cleandesk-remote-screen", color, egui::TextureOptions::LINEAR));
        }
    }
}

/// Dibuja la imagen remota (o un aviso de espera) y captura el input sobre ella.
fn render_video_and_input(viewer: &mut ViewerState, ui: &mut egui::Ui) {
    let Some(tex) = viewer.texture.clone() else {
        ui.centered_and_justified(|ui| {
            ui.vertical_centered(|ui| {
                ui.spinner();
                ui.label(egui::RichText::new("Esperando imagen del equipo remoto…").color(theme::TEXT_DIM));
            });
        });
        return;
    };

    let avail = ui.available_size();
    let img_size = egui::vec2(viewer.frame_size[0] as f32, viewer.frame_size[1] as f32);
    if img_size.x <= 0.0 || img_size.y <= 0.0 {
        return;
    }

    // Tamaño en pantalla: ajustado a la ventana (preservando aspecto) o 1:1.
    let draw_size = if viewer.fit_to_window {
        let scale = (avail.x / img_size.x).min(avail.y / img_size.y).min(4.0);
        img_size * scale.max(0.01)
    } else {
        img_size
    };

    // Centramos el rectángulo de dibujo en el espacio disponible.
    let (rect, response) = if viewer.fit_to_window {
        let offset = ((avail - draw_size) * 0.5).max(egui::Vec2::ZERO);
        let rect = egui::Rect::from_min_size(ui.cursor().min + offset, draw_size);
        let response = ui.allocate_rect(rect, egui::Sense::click_and_drag());
        (rect, response)
    } else {
        ui.allocate_exact_size(draw_size, egui::Sense::click_and_drag())
    };

    // Pintamos la textura en el rect asignado.
    let uv = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
    ui.painter()
        .image(tex.id(), rect, uv, egui::Color32::WHITE);

    // El teclado solo se reenvía mientras el puntero está sobre la imagen o se
    // ha hecho clic en ella; así los atajos de la propia ventana no se cuelan.
    if response.clicked() || response.drag_started() {
        response.request_focus();
    }

    // Captura de input sobre la imagen.
    forward_input(viewer, ui, rect, &response);
}

/// Traduce y reenvía ratón y teclado al host, respetando permisos.
///
/// Recogemos primero todo lo necesario de `ui.input()` en variables propias para
/// no mantener prestado `viewer` mientras enviamos eventos y actualizamos su
/// estado (evita conflictos con el verificador de préstamos).
fn forward_input(
    viewer: &mut ViewerState,
    ui: &egui::Ui,
    rect: egui::Rect,
    response: &egui::Response,
) {
    let mouse_ok = viewer.mouse_allowed();
    let keyboard_ok = viewer.keyboard_allowed() && (response.hovered() || response.has_focus());
    if !mouse_ok && !keyboard_ok {
        return;
    }

    // Datos crudos de este fotograma (copias, sin préstamos sobre `ui`).
    struct FrameInput {
        buttons: Vec<(MouseButton, bool)>,
        scroll: egui::Vec2,
        keys: Vec<(u32, bool)>,
        modifiers: egui::Modifiers,
    }

    let hovered = response.hovered();
    let input = ui.input(|i| {
        let mut buttons = Vec::new();
        let mut keys = Vec::new();
        for ev in &i.events {
            match ev {
                egui::Event::PointerButton { button, pressed, .. } if mouse_ok && hovered => {
                    if let Some(mapped) = map_pointer_button(*button) {
                        buttons.push((mapped, *pressed));
                    }
                }
                // Ignoramos los `repeat`: el host gestiona su propio auto-repeat.
                egui::Event::Key { key, pressed, repeat, .. } if keyboard_ok && !*repeat => {
                    if let Some(vk) = key_to_vk(*key) {
                        keys.push((vk, *pressed));
                    }
                }
                _ => {}
            }
        }
        FrameInput {
            buttons,
            scroll: if mouse_ok && hovered { i.raw_scroll_delta } else { egui::Vec2::ZERO },
            keys,
            modifiers: i.modifiers,
        }
    });

    // --- Ratón ---
    if mouse_ok {
        // Movimiento: coordenadas normalizadas 0..=1 sobre la imagen mostrada.
        if let Some(pos) = response.hover_pos().or_else(|| response.interact_pointer_pos()) {
            if rect.width() > 0.0 && rect.height() > 0.0 {
                let nx = ((pos.x - rect.left()) / rect.width()).clamp(0.0, 1.0);
                let ny = ((pos.y - rect.top()) / rect.height()).clamp(0.0, 1.0);
                let this = (nx, ny);
                if viewer.last_move != Some(this) {
                    viewer.last_move = Some(this);
                    viewer.session.send_input(InputEvent::MouseMove { x: nx, y: ny });
                }
            }
        }

        for (button, pressed) in input.buttons {
            viewer
                .session
                .send_input(InputEvent::MouseButton { button, pressed });
        }

        if input.scroll != egui::Vec2::ZERO {
            // egui entrega el scroll en puntos; ~50 puntos ≈ una muesca de rueda.
            viewer.session.send_input(InputEvent::MouseScroll {
                delta_x: input.scroll.x / 50.0,
                delta_y: input.scroll.y / 50.0,
            });
        }
    }

    // --- Teclado ---
    if keyboard_ok {
        // Sincronizamos modificadores emitiendo solo los cambios respecto al
        // estado ya comunicado al host.
        sync_modifiers(viewer, input.modifiers);

        for (vk, pressed) in input.keys {
            viewer
                .session
                .send_input(InputEvent::Key { code: vk, pressed });
        }
    } else if viewer.modifiers.shift || viewer.modifiers.ctrl || viewer.modifiers.alt {
        // El foco salió de la imagen con modificadores pulsados: suéltalos.
        sync_modifiers(viewer, egui::Modifiers::NONE);
    }
}

/// Emite eventos de pulsar/soltar para Shift/Ctrl/Alt cuando su estado cambia.
fn sync_modifiers(viewer: &mut ViewerState, mods: egui::Modifiers) {
    let mut state = viewer.modifiers;

    if mods.shift != state.shift {
        viewer
            .session
            .send_input(InputEvent::Key { code: VK_SHIFT, pressed: mods.shift });
        state.shift = mods.shift;
    }
    if mods.ctrl != state.ctrl {
        viewer
            .session
            .send_input(InputEvent::Key { code: VK_CONTROL, pressed: mods.ctrl });
        state.ctrl = mods.ctrl;
    }
    if mods.alt != state.alt {
        viewer
            .session
            .send_input(InputEvent::Key { code: VK_MENU, pressed: mods.alt });
        state.alt = mods.alt;
    }

    viewer.modifiers = state;
}

/// Mapea el botón de puntero de egui a nuestro [`MouseButton`] de protocolo.
fn map_pointer_button(button: egui::PointerButton) -> Option<MouseButton> {
    match button {
        egui::PointerButton::Primary => Some(MouseButton::Left),
        egui::PointerButton::Secondary => Some(MouseButton::Right),
        egui::PointerButton::Middle => Some(MouseButton::Middle),
        egui::PointerButton::Extra1 => Some(MouseButton::Back),
        egui::PointerButton::Extra2 => Some(MouseButton::Forward),
    }
}

/// Construye la línea de estadísticas de sesión (spec §26).
fn stats_line(viewer: &ViewerState) -> String {
    match &viewer.stats {
        Some(s) => {
            let kind = if s.direct { "Directa" } else { "Relay" };
            format!(
                "Ping: {} ms  ·  FPS: {}  ·  {}×{}  ·  {} kb/s  ·  Códec: {}  ·  Conexión: {}  ·  Frames: {}",
                s.rtt_ms, s.fps, s.width, s.height, s.bandwidth_kbps, s.codec, kind, viewer.frames_received
            )
        }
        None => "Estableciendo estadísticas…".to_string(),
    }
}

/// Panel lateral de chat en sesión (spec §17).
fn show_chat_panel(viewer: &mut ViewerState, ctx: &egui::Context) {
    egui::SidePanel::right("viewer-chat")
        .resizable(true)
        .default_width(260.0)
        .frame(egui::Frame::new().fill(theme::PANEL).inner_margin(egui::Margin::same(12)))
        .show(ctx, |ui| {
            theme::section_label(ui, "Chat", true);
            ui.separator();

            let input_row = 40.0;
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height((ui.available_height() - input_row).max(0.0))
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &viewer.chat_log {
                        ui.label(line);
                    }
                });

            ui.separator();
            ui.horizontal(|ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut viewer.chat_input)
                        .hint_text("Escribe un mensaje…")
                        .desired_width(ui.available_width() - 70.0),
                );
                let send = ui.add(theme::primary_button("Enviar")).clicked()
                    || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                if send && !viewer.chat_input.trim().is_empty() {
                    let text = std::mem::take(&mut viewer.chat_input);
                    viewer.chat_log.push(format!("Yo: {text}"));
                    viewer.session.send_chat(text);
                    resp.request_focus();
                }
            });
        });
}
