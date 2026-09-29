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
    message::{InputEvent, MonitorInfo, MouseButton, RemoteAction},
    permissions::Permissions,
    quality::QualityProfile,
    session::{DeviceInfo, SessionId, SessionStats},
};
use tracing::debug;

use crate::i18n::{tr, trf};
use crate::keymap::{key_to_vk, VK_CONTROL, VK_ESCAPE, VK_LWIN, VK_MENU, VK_SHIFT};
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
    /// Último fotograma decodificado (para la miniatura de la sesión).
    last_frame: Option<DecodedImage>,

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

    /// Sincronización automática del portapapeles de texto (spec §16).
    clipboard_sync: bool,
    /// Hemos pedido bloquear el teclado/ratón local del host.
    local_input_locked: bool,
    /// Transferencias de archivos en curso o terminadas (spec §17).
    transfers: Vec<Transfer>,
    /// Ofertas del host pendientes de aceptar.
    offers: Vec<FileOffer>,
    /// Si el panel de archivos está visible.
    show_files: bool,
}

/// Una transferencia de archivo vista desde el visor.
struct Transfer {
    id: u64,
    name: String,
    transferred: u64,
    total: u64,
    state: TransferState,
}

enum TransferState {
    Running,
    Done(std::path::PathBuf),
    Failed(String),
}

/// Un archivo que el host nos ofrece.
struct FileOffer {
    id: u64,
    name: String,
    size: u64,
}

impl ViewerState {
    /// Crea el estado del visor a partir de una sesión recién establecida.
    pub fn new(session: ClientSession) -> Self {
        let granted = session.granted;
        session.enable_clipboard_sync();
        Self {
            session,
            granted,
            peer: None,
            texture: None,
            frame_size: [0, 0],
            frames_received: 0,
            last_frame: None,
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
            clipboard_sync: true,
            local_input_locked: false,
            transfers: Vec::new(),
            offers: Vec::new(),
            show_files: false,
        }
    }

    pub fn session_id(&self) -> SessionId {
        self.session.session
    }

    pub fn is_fullscreen(&self) -> bool {
        self.fullscreen
    }

    /// El último fotograma completo recibido, si lo hubo.
    pub fn last_frame(&self) -> Option<&DecodedImage> {
        self.last_frame.as_ref()
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
                self.session.send_input(InputEvent::Key {
                    code,
                    pressed: false,
                });
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
            // Una sola fila que nunca envuelve: los controles van en un área con
            // desplazamiento horizontal y "Desconectar" queda fijo a la derecha, así
            // la barra no se rompe al estrechar la ventana.
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(theme::danger_button(tr("Disconnect"))).clicked() {
                        disconnect_requested = true;
                    }
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        egui::ScrollArea::horizontal()
                            .id_salt("viewer-toolbar-scroll")
                            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                let who = viewer
                                    .peer
                                    .as_ref()
                                    .map(|p| p.alias.clone().unwrap_or_else(|| p.hostname.clone()))
                                    .unwrap_or_else(|| tr("remote device").into());
                                theme::status_dot(ui, theme::ACCENT, "");
                                ui.label(egui::RichText::new(who).strong());
                                ui.separator();

                                // Selector de monitor (spec §15).
                                if viewer.monitors.len() > 1 {
                                    ui.label(egui::RichText::new(tr("Screen:")).color(theme::TEXT_DIM));
                                    let before = viewer.monitor;
                                    egui::ComboBox::from_id_salt("viewer-monitor")
                                        .selected_text(monitor_label(&viewer.monitors, viewer.monitor))
                                        .show_ui(ui, |ui| {
                                            for m in &viewer.monitors {
                                                ui.selectable_value(
                                                    &mut viewer.monitor,
                                                    m.index,
                                                    monitor_label(&viewer.monitors, m.index),
                                                );
                                            }
                                        });
                                    if viewer.monitor != before {
                                        viewer.session.select_monitor(viewer.monitor);
                                    }
                                    ui.separator();
                                }

                                // Selector de calidad.
                                ui.label(egui::RichText::new(tr("Quality:")).color(theme::TEXT_DIM));
                                let before = viewer.quality;
                                egui::ComboBox::from_id_salt("viewer-quality")
                                    .selected_text(quality_label(viewer.quality))
                                    .show_ui(ui, |ui| {
                                        for profile in QUALITY_PROFILES {
                                            ui.selectable_value(
                                                &mut viewer.quality,
                                                *profile,
                                                quality_label(*profile),
                                            );
                                        }
                                    });
                                if viewer.quality != before {
                                    viewer.session.set_quality(viewer.quality);
                                }

                                ui.separator();

                                // Ajustar a ventana / pantalla completa.
                                ui.checkbox(&mut viewer.fit_to_window, tr("Fit"));
                                if ui
                                    .checkbox(&mut viewer.fullscreen, tr("Full screen"))
                                    .changed()
                                {
                                    ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(viewer.fullscreen));
                                }
                                if ui
                                    .button("⟳")
                                    .on_hover_text(tr("Refresh image (request a keyframe)"))
                                    .clicked()
                                {
                                    viewer.session.request_keyframe();
                                }

                                ui.separator();
                                let chat_label = if viewer.unread_chat > 0 {
                                    trf("Chat ({n})", &[("n", &viewer.unread_chat.to_string())])
                                } else {
                                    tr("Chat").to_string()
                                };
                                if ui.toggle_value(&mut viewer.show_chat, chat_label).changed() && viewer.show_chat
                                {
                                    viewer.unread_chat = 0;
                                }
                                let files_label = if viewer.offers.is_empty() {
                                    tr("Files").to_string()
                                } else {
                                    trf("Files ({n})", &[("n", &viewer.offers.len().to_string())])
                                };
                                ui.add_enabled_ui(viewer.granted.contains(Permissions::FILE_TRANSFER), |ui| {
                                    ui.toggle_value(&mut viewer.show_files, files_label)
                                        .on_disabled_hover_text(tr("File transfer was not granted by the host."));
                                });
                                ui.add_enabled_ui(viewer.granted.contains(Permissions::CLIPBOARD), |ui| {
                                    if ui
                                        .toggle_value(&mut viewer.clipboard_sync, tr("Clipboard"))
                                        .on_hover_text(tr("Keep the text clipboard in sync with the remote device"))
                                        .on_disabled_hover_text(tr("Clipboard access was not granted by the host."))
                                        .changed()
                                    {
                                        if viewer.clipboard_sync {
                                            viewer.session.enable_clipboard_sync();
                                        } else {
                                            viewer.session.disable_clipboard_sync();
                                        }
                                    }
                                });
                                actions_menu(viewer, ui);

                                });
                            });
                    });
                });
            });

            // Línea de estadísticas (spec §26).
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(stats_line(viewer))
                        .size(11.0)
                        .color(theme::TEXT_MUTED),
                );
                // Aviso si no hay control.
                if !viewer.granted.contains(Permissions::CONTROL_MOUSE)
                    && !viewer.granted.contains(Permissions::CONTROL_KEYBOARD)
                {
                    ui.label(
                        egui::RichText::new(tr("· View only (no control granted)"))
                            .size(11.0)
                            .italics()
                            .color(theme::WARN),
                    );
                }
            });
        });

    if disconnect_requested {
        return ViewerOutcome::Disconnected(Some(tr("Session ended.").into()));
    }

    // 4) Paneles opcionales: chat (spec §17) y archivos.
    if viewer.show_chat {
        show_chat_panel(viewer, ctx);
    }
    if viewer.show_files {
        show_files_panel(viewer, ctx);
    }
    // Soltar archivos sobre el visor los envía al host.
    let dropped: Vec<std::path::PathBuf> = ctx.input(|i| {
        i.raw
            .dropped_files
            .iter()
            .filter_map(|f| f.path.clone())
            .collect()
    });
    for path in dropped {
        offer_file(viewer, path);
    }

    // 5) Área central: la imagen remota + captura de input.
    egui::CentralPanel::default()
        .frame(egui::Frame::new().fill(egui::Color32::BLACK))
        .show(ctx, |ui| {
            render_video_and_input(viewer, ui);
        });

    ViewerOutcome::Continue
}

/// Menú "Actions": acciones privilegiadas en el host (spec §19). Cada entrada
/// solo se habilita si el host concedió el permiso correspondiente.
fn actions_menu(viewer: &mut ViewerState, ui: &mut egui::Ui) {
    ui.menu_button(tr("Actions"), |ui| {
        ui.set_min_width(240.0);
        let kb = viewer.granted.contains(Permissions::CONTROL_KEYBOARD);
        if ui
            .add_enabled(kb, egui::Button::new(tr("Send Ctrl+Alt+Del")))
            .on_hover_text(tr("Secure-attention sequence (best effort without the service)"))
            .clicked()
        {
            viewer.session.remote_action(RemoteAction::SecureAttention);
            ui.close();
        }
        if ui.add_enabled(kb, egui::Button::new(tr("Send Ctrl+Shift+Esc (Task Manager)"))).clicked() {
            send_chord(viewer, &[VK_CONTROL, VK_SHIFT, VK_ESCAPE]);
            ui.close();
        }
        if ui.add_enabled(kb, egui::Button::new(tr("Send Win+D (show desktop)"))).clicked() {
            send_chord(viewer, &[VK_LWIN, 0x44]);
            ui.close();
        }
        if ui.add_enabled(kb, egui::Button::new(tr("Lock remote session (Win+L)"))).clicked() {
            viewer.session.remote_action(RemoteAction::LockWorkstation);
            ui.close();
        }
        ui.separator();
        let can_lock = viewer.granted.contains(Permissions::LOCK_LOCAL_INPUT);
        let lock_label = if viewer.local_input_locked {
            tr("Unlock remote keyboard and mouse")
        } else {
            tr("Lock remote keyboard and mouse")
        };
        if ui
            .add_enabled(can_lock, egui::Button::new(lock_label))
            .on_hover_text(tr("Nobody at the remote device can use it while locked; it is always unlocked when the session ends."))
            .clicked()
        {
            viewer.local_input_locked = !viewer.local_input_locked;
            viewer.session.remote_action(RemoteAction::LockLocalInput { locked: viewer.local_input_locked });
            ui.close();
        }
        ui.separator();
        let can_restart = viewer.granted.contains(Permissions::RESTART_MACHINE);
        if ui
            .add_enabled(can_restart, egui::Button::new(egui::RichText::new(tr("Restart remote device")).color(theme::DANGER)))
            .on_hover_text(tr("Reboots the remote device now. Reconnect once it is back."))
            .clicked()
        {
            viewer.session.remote_action(RemoteAction::RestartMachine);
            ui.close();
        }
    });
}

/// Pulsa y suelta una combinación de teclas en el host (en orden).
fn send_chord(viewer: &ViewerState, codes: &[u32]) {
    for code in codes {
        viewer.session.send_input(InputEvent::Key {
            code: *code,
            pressed: true,
        });
    }
    for code in codes.iter().rev() {
        viewer.session.send_input(InputEvent::Key {
            code: *code,
            pressed: false,
        });
    }
}

/// Ofrece un archivo local al host y lo registra en la lista.
fn offer_file(viewer: &mut ViewerState, path: std::path::PathBuf) {
    if !viewer.granted.contains(Permissions::FILE_TRANSFER) {
        viewer
            .chat_log
            .push(tr("File transfer was not granted by the host.").into());
        return;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let total = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let id = viewer.session.send_file(path);
    viewer.transfers.push(Transfer {
        id,
        name,
        transferred: 0,
        total,
        state: TransferState::Running,
    });
    viewer.show_files = true;
}

/// Panel lateral de archivos: ofertas entrantes y progreso de transferencias.
fn show_files_panel(viewer: &mut ViewerState, ctx: &egui::Context) {
    egui::SidePanel::right("viewer-files")
        .frame(
            egui::Frame::new()
                .fill(theme::PANEL)
                .inner_margin(egui::Margin::same(10)),
        )
        .default_width(300.0)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(tr("Files")).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(theme::primary_button(tr("Send file…"))).clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            offer_file(viewer, path);
                        }
                    }
                });
            });
            ui.label(
                egui::RichText::new(tr("Drop files on the remote screen to send them."))
                    .size(11.0)
                    .color(theme::TEXT_MUTED),
            );
            ui.separator();

            let mut accept: Option<u64> = None;
            let mut reject: Option<u64> = None;
            for offer in &viewer.offers {
                theme::card_tinted().show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(trf(
                            "{name} ({size})",
                            &[("name", &offer.name), ("size", &human_size(offer.size))],
                        ))
                        .strong(),
                    );
                    ui.label(
                        egui::RichText::new(tr("The remote device wants to send you this file."))
                            .size(11.0)
                            .color(theme::TEXT_DIM),
                    );
                    ui.horizontal(|ui| {
                        if ui.add(theme::primary_button(tr("Accept"))).clicked() {
                            accept = Some(offer.id);
                        }
                        if ui.add(theme::ghost_button(tr("Reject"))).clicked() {
                            reject = Some(offer.id);
                        }
                    });
                });
            }
            if let Some(id) = accept {
                viewer.session.accept_file(id);
                if let Some(o) = viewer.offers.iter().find(|o| o.id == id) {
                    viewer.transfers.push(Transfer {
                        id,
                        name: o.name.clone(),
                        transferred: 0,
                        total: o.size,
                        state: TransferState::Running,
                    });
                }
                viewer.offers.retain(|o| o.id != id);
            }
            if let Some(id) = reject {
                viewer.session.cancel_file(id);
                viewer.offers.retain(|o| o.id != id);
            }

            let mut cancel: Option<u64> = None;
            let mut open: Option<std::path::PathBuf> = None;
            egui::ScrollArea::vertical().show(ui, |ui| {
                for t in viewer.transfers.iter().rev() {
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new(&t.name).strong());
                    match &t.state {
                        TransferState::Running => {
                            let frac = if t.total > 0 {
                                t.transferred as f32 / t.total as f32
                            } else {
                                0.0
                            };
                            ui.horizontal(|ui| {
                                ui.add(egui::ProgressBar::new(frac).desired_width(180.0).text(
                                    format!(
                                        "{} / {}",
                                        human_size(t.transferred),
                                        human_size(t.total)
                                    ),
                                ));
                                if ui.small_button("✕").on_hover_text(tr("Cancel")).clicked() {
                                    cancel = Some(t.id);
                                }
                            });
                        }
                        TransferState::Done(path) => {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(tr("Completed"))
                                        .size(11.0)
                                        .color(theme::ONLINE),
                                );
                                if ui
                                    .link(egui::RichText::new(tr("Show in folder")).size(11.0))
                                    .clicked()
                                {
                                    open = Some(path.clone());
                                }
                            });
                        }
                        TransferState::Failed(reason) => {
                            ui.label(
                                egui::RichText::new(trf("Failed: {reason}", &[("reason", reason)]))
                                    .size(11.0)
                                    .color(theme::DANGER),
                            );
                        }
                    }
                }
            });
            if let Some(id) = cancel {
                viewer.session.cancel_file(id);
            }
            if let Some(path) = open {
                let dir = path.parent().map(|p| p.to_path_buf()).unwrap_or(path);
                let _ = std::process::Command::new("explorer").arg(dir).spawn();
            }
        });
}

/// "1.2 MB" a partir de bytes.
pub(crate) fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

fn monitor_label(monitors: &[MonitorInfo], index: u16) -> String {
    match monitors.iter().find(|m| m.index == index) {
        Some(m) => format!(
            "{} {}×{}{}",
            m.index + 1,
            m.width,
            m.height,
            if m.primary { tr(" (primary)") } else { "" }
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
                viewer.chat_log.push(format!("{} {text}", tr("Remote:")));
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
                        tr("Authentication rejected by the remote device.").into(),
                    )));
                }
            }
            Ok(ClientEvent::Clipboard(_)) => {
                // El cliente ya lo aplicó al portapapeles local si la
                // sincronización está activa; nada que mostrar.
            }
            Ok(ClientEvent::FileOffer { id, name, size }) => {
                viewer.offers.push(FileOffer { id, name, size });
                viewer.show_files = true;
            }
            Ok(ClientEvent::FileProgress {
                id,
                transferred,
                total,
            }) => match viewer.transfers.iter_mut().find(|t| t.id == id) {
                Some(t) => {
                    t.transferred = transferred;
                    t.total = total;
                }
                None => {
                    let name = viewer
                        .offers
                        .iter()
                        .find(|o| o.id == id)
                        .map(|o| o.name.clone())
                        .unwrap_or_else(|| format!("#{id}"));
                    viewer.transfers.push(Transfer {
                        id,
                        name,
                        transferred,
                        total,
                        state: TransferState::Running,
                    });
                }
            },
            Ok(ClientEvent::FileDone { id, path }) => {
                viewer.offers.retain(|o| o.id != id);
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                match viewer.transfers.iter_mut().find(|t| t.id == id) {
                    Some(t) => {
                        t.transferred = t.total;
                        t.state = TransferState::Done(path);
                    }
                    None => viewer.transfers.push(Transfer {
                        id,
                        name,
                        transferred: 0,
                        total: 0,
                        state: TransferState::Done(path),
                    }),
                }
            }
            Ok(ClientEvent::FileFailed { id, reason }) => {
                viewer.offers.retain(|o| o.id != id);
                match viewer.transfers.iter_mut().find(|t| t.id == id) {
                    Some(t) => t.state = TransferState::Failed(reason),
                    None => viewer.transfers.push(Transfer {
                        id,
                        name: format!("#{id}"),
                        transferred: 0,
                        total: 0,
                        state: TransferState::Failed(reason),
                    }),
                }
                viewer.show_files = true;
            }
            Ok(ClientEvent::Disconnected(reason)) => {
                return Some(ViewerOutcome::Disconnected(Some(trf(
                    "Disconnected: {reason}",
                    &[("reason", crate::app::friendly_reason(&reason))],
                ))));
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => return None,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                return Some(ViewerOutcome::Disconnected(Some(
                    tr("The session was closed.").into(),
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
        debug!(
            w = size[0],
            h = size[1],
            len = img.rgba.len(),
            "frame con tamaño inconsistente"
        );
        return;
    }

    let color = egui::ColorImage::from_rgba_unmultiplied(size, &img.rgba);
    viewer.frame_size = size;

    match &mut viewer.texture {
        Some(tex) => tex.set(color, egui::TextureOptions::LINEAR),
        None => {
            viewer.texture = Some(ctx.load_texture(
                "cleandesk-remote-screen",
                color,
                egui::TextureOptions::LINEAR,
            ));
        }
    }
    viewer.last_frame = Some(img);
}

/// Dibuja la imagen remota (o un aviso de espera) y captura el input sobre ella.
fn render_video_and_input(viewer: &mut ViewerState, ui: &mut egui::Ui) {
    let Some(tex) = viewer.texture.clone() else {
        ui.centered_and_justified(|ui| {
            ui.vertical_centered(|ui| {
                ui.spinner();
                ui.label(
                    egui::RichText::new(tr("Waiting for the remote device's image…"))
                        .color(theme::TEXT_DIM),
                );
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
    ui.painter().image(tex.id(), rect, uv, egui::Color32::WHITE);

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
    let keyboard_ok = viewer.keyboard_allowed()
        && (response.has_focus() || (response.hovered() && !ui.ctx().wants_keyboard_input()));
    if !mouse_ok && !keyboard_ok {
        return;
    }

    // Datos crudos de este fotograma (copias, sin préstamos sobre `ui`).
    struct FrameInput {
        buttons: Vec<(MouseButton, bool)>,
        scroll: egui::Vec2,
        keys: Vec<(u32, bool)>,
        modifiers: egui::Modifiers,
        clipboard_events: Vec<egui::Event>,
    }

    let hovered = response.hovered();
    let input = ui.input(|i| {
        let mut buttons = Vec::new();
        let mut keys = Vec::new();
        let mut clipboard_events = Vec::new();
        for ev in &i.events {
            match ev {
                egui::Event::PointerButton {
                    button, pressed, ..
                } if mouse_ok && hovered => {
                    if let Some(mapped) = map_pointer_button(*button) {
                        buttons.push((mapped, *pressed));
                    }
                }
                // Ignoramos los `repeat`: el host gestiona su propio auto-repeat.
                egui::Event::Key {
                    key,
                    pressed,
                    repeat,
                    ..
                } if keyboard_ok && !*repeat => {
                    if let Some(vk) = key_to_vk(*key) {
                        keys.push((vk, *pressed));
                    }
                }
                egui::Event::Copy | egui::Event::Cut | egui::Event::Paste(_) if keyboard_ok => {
                    clipboard_events.push(ev.clone());
                }
                _ => {}
            }
        }
        FrameInput {
            buttons,
            scroll: if mouse_ok && hovered {
                i.raw_scroll_delta
            } else {
                egui::Vec2::ZERO
            },
            keys,
            modifiers: i.modifiers,
            clipboard_events,
        }
    });

    // --- Ratón ---
    if mouse_ok {
        // Movimiento: coordenadas normalizadas 0..=1 sobre la imagen mostrada.
        if let Some(pos) = response
            .hover_pos()
            .or_else(|| response.interact_pointer_pos())
        {
            if rect.width() > 0.0 && rect.height() > 0.0 {
                let nx = ((pos.x - rect.left()) / rect.width()).clamp(0.0, 1.0);
                let ny = ((pos.y - rect.top()) / rect.height()).clamp(0.0, 1.0);
                let this = (nx, ny);
                if viewer.last_move != Some(this) {
                    viewer.last_move = Some(this);
                    viewer
                        .session
                        .send_input(InputEvent::MouseMove { x: nx, y: ny });
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
        for event in input.clipboard_events {
            if let egui::Event::Paste(text) = &event {
                if viewer.clipboard_sync
                    && viewer.granted.contains(Permissions::CLIPBOARD)
                    && viewer.session.supports_clipboard_paste()
                {
                    viewer.session.paste_clipboard(text.clone());
                    continue;
                }
            }
            for event in clipboard_shortcut(&event, viewer.modifiers) {
                viewer.session.send_input(event);
            }
        }
    } else if viewer.modifiers.shift || viewer.modifiers.ctrl || viewer.modifiers.alt {
        // El foco salió de la imagen con modificadores pulsados: suéltalos.
        sync_modifiers(viewer, egui::Modifiers::NONE);
    }
}

// egui-winit consumes the key-down for Ctrl+C/X/V and emits these events.
// Preserve the modifier already held on the host, including Shift+Insert.
fn clipboard_shortcut(event: &egui::Event, modifiers: ModifierState) -> Vec<InputEvent> {
    let code = match event {
        egui::Event::Copy => 0x43,
        egui::Event::Cut => 0x58,
        egui::Event::Paste(_) => 0x56,
        _ => return Vec::new(),
    };
    let mut keys = Vec::new();
    for (code, held) in [(VK_SHIFT, modifiers.shift), (VK_MENU, modifiers.alt)] {
        if held {
            keys.push(InputEvent::Key { code, pressed: false });
        }
    }
    if !modifiers.ctrl {
        keys.push(InputEvent::Key { code: VK_CONTROL, pressed: true });
    }
    keys.push(InputEvent::Key { code, pressed: true });
    keys.push(InputEvent::Key { code, pressed: false });
    if !modifiers.ctrl {
        keys.push(InputEvent::Key { code: VK_CONTROL, pressed: false });
    }
    for (code, held) in [(VK_SHIFT, modifiers.shift), (VK_MENU, modifiers.alt)] {
        if held {
            keys.push(InputEvent::Key { code, pressed: true });
        }
    }
    keys
}

#[cfg(test)]
mod clipboard_tests {
    use super::*;

    #[test]
    fn copy_and_cut_restore_the_consumed_key_down() {
        let modifiers = ModifierState { ctrl: true, ..Default::default() };
        for (event, code) in [(egui::Event::Copy, 0x43), (egui::Event::Cut, 0x58)] {
            assert_eq!(clipboard_shortcut(&event, modifiers), vec![
                InputEvent::Key { code, pressed: true },
                InputEvent::Key { code, pressed: false },
            ]);
        }
    }

    #[test]
    fn shift_insert_paste_restores_shift_without_leaving_control_down() {
        let modifiers = ModifierState { shift: true, ..Default::default() };
        assert_eq!(clipboard_shortcut(&egui::Event::Paste("texto".into()), modifiers), vec![
            InputEvent::Key { code: VK_SHIFT, pressed: false },
            InputEvent::Key { code: VK_CONTROL, pressed: true },
            InputEvent::Key { code: 0x56, pressed: true },
            InputEvent::Key { code: 0x56, pressed: false },
            InputEvent::Key { code: VK_CONTROL, pressed: false },
            InputEvent::Key { code: VK_SHIFT, pressed: true },
        ]);
    }
}

/// Emite eventos de pulsar/soltar para Shift/Ctrl/Alt cuando su estado cambia.
fn sync_modifiers(viewer: &mut ViewerState, mods: egui::Modifiers) {
    let mut state = viewer.modifiers;

    if mods.shift != state.shift {
        viewer.session.send_input(InputEvent::Key {
            code: VK_SHIFT,
            pressed: mods.shift,
        });
        state.shift = mods.shift;
    }
    if mods.ctrl != state.ctrl {
        viewer.session.send_input(InputEvent::Key {
            code: VK_CONTROL,
            pressed: mods.ctrl,
        });
        state.ctrl = mods.ctrl;
    }
    if mods.alt != state.alt {
        viewer.session.send_input(InputEvent::Key {
            code: VK_MENU,
            pressed: mods.alt,
        });
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
            let kind = if s.direct { tr("Direct") } else { tr("Relay") };
            format!(
                "{}: {} ms  ·  FPS: {}  ·  {}×{}  ·  {} kb/s  ·  {}: {}  ·  {}: {} {} {}  ·  {}: {}",
                tr("Ping"),
                s.rtt_ms,
                s.fps,
                s.width,
                s.height,
                s.bandwidth_kbps,
                tr("Codec"),
                s.codec,
                tr("Connection"),
                kind,
                tr("via"),
                viewer.session.via,
                tr("Frames"),
                viewer.frames_received
            )
        }
        None => tr("Gathering statistics…").to_string(),
    }
}

/// Panel lateral de chat en sesión (spec §17).
fn show_chat_panel(viewer: &mut ViewerState, ctx: &egui::Context) {
    egui::SidePanel::right("viewer-chat")
        .resizable(true)
        .default_width(260.0)
        .min_width(200.0)
        .max_width(420.0)
        .frame(
            egui::Frame::new()
                .fill(theme::PANEL)
                .inner_margin(egui::Margin::same(12)),
        )
        .show(ctx, |ui| {
            theme::section_label(ui, tr("Chat"), true);
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
            // Botón primero (a la derecha) y el campo rellena lo que queda: pedir
            // `available_width() - 70` hacía crecer el panel en cada fotograma.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let send_clicked = ui.add(theme::primary_button(tr("Send"))).clicked();
                let resp = ui.add_sized(
                    [ui.available_width(), 24.0],
                    egui::TextEdit::singleline(&mut viewer.chat_input).hint_text(tr("Type a message…")),
                );
                let send = send_clicked
                    || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                if send && !viewer.chat_input.trim().is_empty() {
                    let text = std::mem::take(&mut viewer.chat_input);
                    viewer.chat_log.push(format!("{} {text}", tr("Me:")));
                    viewer.session.send_chat(text);
                    resp.request_focus();
                }
            });
        });
}
