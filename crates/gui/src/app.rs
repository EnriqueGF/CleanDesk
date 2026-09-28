//! La aplicación eframe: estado global, puente con tokio y bucle de `update`.
//!
//! `CleanDeskApp` es el `eframe::App`. Reúne:
//! * el `AppState` persistente compartido (identidad, ajustes, agenda, historial),
//! * un runtime de tokio propio para todo el trabajo asíncrono (conexión saliente
//!   y host entrante),
//! * el estado de la vista actual (ventana principal o visor de sesión),
//! * los canales por los que el host de fondo pide aprobación de conexiones y
//!   comunica el ciclo de vida de las sesiones entrantes.
//!
//! El bucle `update` no bloquea: sondea los receptores con `try_recv()` y, cuando
//! hay una sesión activa, pide repintado continuo para que el vídeo fluya.

use std::sync::{Arc, Mutex};

use cleandesk_client::{ClientConfig, ClientSession};
use cleandesk_core::{history::SessionRecord, AppState};
use cleandesk_host::{HostConfig, HostControl, HostEvent};
use cleandesk_proto::{
    id::CleanDeskId, permissions::Permissions, session::DeviceInfo, session::SessionId,
};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::approval::{GuiApprover, PendingRequest};
use crate::mainwindow;
use crate::theme;
use crate::viewer::ViewerState;

/// Estado del registro del host contra el servidor (barra de estado inferior).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    /// Aún no se ha intentado o se está (re)intentando registrar.
    Connecting,
    /// El host quedó registrado y escuchando conexiones entrantes.
    Online,
    /// El intento de registro falló; se reintentará.
    Offline,
}

/// Fase de la conexión saliente iniciada por el usuario.
enum ConnectPhase {
    /// Sin conexión saliente.
    Idle,
    /// Esperando el resultado de `client::connect` (aceptar/rechazar/conectar).
    Connecting {
        target: CleanDeskId,
        rx: oneshot::Receiver<anyhow::Result<ClientSession>>,
    },
    /// Sesión establecida: mostramos el visor.
    Active(Box<ViewerState>),
}

/// Una sesión entrante viva (alguien nos está viendo). Spec §18: confirmación
/// visual de sesión activa.
#[derive(Clone)]
pub struct HostSession {
    pub session: SessionId,
    pub peer: DeviceInfo,
    pub granted: Permissions,
}

/// Pestaña de la lista de equipos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTab {
    Recent,
    Favorites,
}

/// La aplicación completa.
pub struct CleanDeskApp {
    /// Estado persistente compartido con las tareas asíncronas.
    pub state: Arc<AppState>,
    /// Este dispositivo, tal y como se anuncia en señalización.
    pub device: DeviceInfo,
    /// Nuestro propio CleanDesk ID (derivado de la identidad).
    pub id: CleanDeskId,
    /// URL del servidor de señalización.
    pub signal_url: String,
    /// Runtime de tokio propiedad de la app; vive tanto como la ventana.
    pub rt: Arc<Runtime>,

    /// Fase de la conexión saliente.
    connect: ConnectPhase,
    /// Texto del campo "Introducir CleanDesk ID".
    pub connect_input: String,
    /// Contraseña para conectar a un host desatendido (vacía = interactivo).
    pub connect_password: String,
    /// Mostrar el campo de contraseña desatendida.
    pub show_connect_password: bool,
    /// Guardar la clave derivada en favoritos al conectar con éxito.
    pub remember_password: bool,
    /// Clave pendiente de guardar cuando la conexión en curso tenga éxito.
    pending_remember: Option<(CleanDeskId, [u8; 32])>,
    /// Aviso a mostrar en la ventana principal (error de conexión, desconexión…).
    pub notice: Option<String>,
    /// Pestaña activa de la lista de equipos.
    pub tab: DeviceTab,
    /// Ventana de ajustes visible.
    pub show_settings: bool,
    /// Ventana de seguridad (huella) visible.
    pub show_security: bool,
    /// Formulario "Añadir dispositivo" visible.
    pub show_add_device: bool,
    pub add_device_id: String,
    pub add_device_name: String,

    /// Estado del registro del host, compartido con su tarea supervisora.
    host_status: Arc<Mutex<HostStatus>>,
    /// Recepción de solicitudes de conexión entrantes (para el diálogo modal).
    incoming_rx: mpsc::Receiver<PendingRequest>,
    /// Eventos de ciclo de vida del host (sesión entrante iniciada/terminada).
    host_events_rx: mpsc::UnboundedReceiver<HostEvent>,
    /// Control local del host (finalizar sesión entrante).
    host_control: Arc<HostControl>,
    /// Sesión entrante activa, si la hay.
    pub host_session: Option<HostSession>,
    /// Cola de solicitudes pendientes de decisión (se muestra la primera).
    pending: Vec<PendingRequest>,
    /// Permisos seleccionados en el diálogo modal en curso (uno por solicitud).
    pending_perms: Permissions,

    // --- Estado del área de ajustes (edición en vivo antes de persistir) ---
    /// Alias en edición.
    pub alias_edit: String,
    /// Contraseña de acceso desatendido en edición.
    pub unattended_pw: String,
    /// Estado del servicio de Windows y del arranque con la sesión (se refrescan
    /// periódicamente mientras la ventana de ajustes está abierta).
    pub service_status: cleandesk_platform::service::ServiceStatus,
    pub run_at_login: bool,
    pub platform_checked_at: Option<std::time::Instant>,
    /// Marca "hay una GUI abierta" para que el host del servicio se aparte.
    _presence: Option<cleandesk_platform::presence::PresenceLock>,
}

impl CleanDeskApp {
    /// Construye la app, arranca el host de fondo y, si procede, la conexión
    /// automática inicial.
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        state: Arc<AppState>,
        device: DeviceInfo,
        rt: Arc<Runtime>,
        signal_url: String,
        initial_target: Option<CleanDeskId>,
    ) -> Self {
        theme::apply(&cc.egui_ctx);
        let id = state.identity.derive_id();
        let alias_edit = state.settings.read().alias.clone().unwrap_or_default();

        // Canales host -> interfaz.
        let (incoming_tx, incoming_rx) = mpsc::channel::<PendingRequest>(8);
        let (host_events_tx, host_events_rx) = mpsc::unbounded_channel::<HostEvent>();
        let host_status = Arc::new(Mutex::new(HostStatus::Connecting));
        let host_control = HostControl::new();
        let presence = match cleandesk_platform::presence::PresenceLock::acquire(&state.data_dir()) {
            Ok(lock) => Some(lock),
            Err(e) => {
                warn!(error = %e, "no se pudo crear el lock de presencia de la GUI");
                None
            }
        };

        // Arranca el host en segundo plano (best-effort).
        spawn_host(
            rt.clone(),
            state.clone(),
            device.clone(),
            signal_url.clone(),
            incoming_tx,
            host_events_tx,
            host_control.clone(),
            host_status.clone(),
            cc.egui_ctx.clone(),
        );

        let mut app = Self {
            state,
            device,
            id,
            signal_url,
            rt,
            connect: ConnectPhase::Idle,
            connect_input: String::new(),
            connect_password: String::new(),
            show_connect_password: false,
            remember_password: false,
            pending_remember: None,
            notice: None,
            tab: DeviceTab::Recent,
            show_settings: false,
            show_security: false,
            show_add_device: false,
            add_device_id: String::new(),
            add_device_name: String::new(),
            host_status,
            incoming_rx,
            host_events_rx,
            host_control,
            host_session: None,
            pending: Vec::new(),
            pending_perms: Permissions::empty(),
            alias_edit,
            unattended_pw: String::new(),
            service_status: cleandesk_platform::service::ServiceStatus::NotInstalled,
            run_at_login: false,
            platform_checked_at: None,
            _presence: presence,
        };

        // Conexión automática solicitada por `--connect`.
        if let Some(target) = initial_target {
            app.start_connection(target, &cc.egui_ctx);
        }

        app
    }

    /// Estado actual del registro del host.
    pub fn host_status(&self) -> HostStatus {
        read_status(&self.host_status)
    }

    /// ¿Hay una conexión saliente en curso (esperando aceptación)?
    pub fn is_connecting(&self) -> bool {
        matches!(self.connect, ConnectPhase::Connecting { .. })
    }

    /// El ID objetivo de la conexión en curso, si la hay.
    pub fn connecting_target(&self) -> Option<CleanDeskId> {
        match &self.connect {
            ConnectPhase::Connecting { target, .. } => Some(*target),
            _ => None,
        }
    }

    /// Finaliza la sesión entrante activa (botón "Finalizar" del aviso).
    pub fn terminate_host_session(&self) {
        self.host_control.terminate_session();
    }

    /// Lanza una conexión saliente hacia `target` usando permisos interactivos y
    /// la calidad por defecto de los ajustes. Si hay contraseña en el campo, la
    /// conexión se hace en modo desatendido.
    pub fn start_connection(&mut self, target: CleanDeskId, ctx: &egui::Context) {
        if self.is_connecting() || matches!(self.connect, ConnectPhase::Active(_)) {
            return; // una sesión a la vez (MVP)
        }
        if target == self.id {
            self.notice = Some("No puedes conectarte a tu propio ID.".into());
            return;
        }
        self.notice = None;

        let quality = self.state.settings.read().quality;
        let mut config = ClientConfig::new(
            self.signal_url.clone(),
            self.device.clone(),
            self.state.identity.clone(),
            target,
        );
        config.quality = quality;
        self.pending_remember = None;
        let pw = self.connect_password.trim();
        if !pw.is_empty() {
            // Derivamos la clave aquí (Argon2id, ~100 ms) para poder recordarla
            // sin guardar nunca la contraseña en claro.
            match cleandesk_crypto::password::unattended_key(pw, target.value()) {
                Ok(key) => {
                    config.unattended_key = Some(key);
                    if self.remember_password {
                        self.pending_remember = Some((target, key));
                    }
                }
                Err(e) => {
                    self.notice = Some(format!("No se pudo derivar la clave: {e}"));
                    return;
                }
            }
        } else if let Some(key) = self.state.addressbook.read().find_by_id(target).and_then(|e| e.unattended_key()) {
            // Equipo guardado con contraseña recordada: conexión desatendida directa.
            config.unattended_key = Some(key);
        }

        let (tx, rx) = oneshot::channel();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let result = cleandesk_client::connect(config).await;
            let _ = tx.send(result);
            ctx.request_repaint();
        });

        info!(%target, "iniciando conexión saliente");
        self.connect = ConnectPhase::Connecting { target, rx };
    }

    /// Persiste ajustes en disco, registrando (sin propagar) cualquier error.
    pub fn save_settings(&self) {
        if let Err(e) = self.state.save() {
            warn!(error = %e, "no se pudieron guardar los ajustes");
        }
    }

    /// Añade (o actualiza) un dispositivo en la agenda.
    pub fn add_favorite(&self, id: CleanDeskId, name: String) {
        use cleandesk_core::addressbook::DeviceEntry;
        let mut book = self.state.addressbook.write();
        if !book.update(id, |e| {
            if !name.trim().is_empty() {
                e.name = name.clone();
            }
        }) {
            let name = if name.trim().is_empty() { id.to_string() } else { name };
            book.add(DeviceEntry::new(id, name));
        }
        drop(book);
        self.save_settings();
    }

    /// Guarda la clave desatendida derivada para `id` (creando el favorito si no existe).
    pub fn remember_key(&self, id: CleanDeskId, key: [u8; 32]) {
        use cleandesk_core::addressbook::DeviceEntry;
        let mut book = self.state.addressbook.write();
        if !book.update(id, |e| e.unattended_key = Some(key.to_vec())) {
            let mut entry = DeviceEntry::new(id, id.to_string());
            entry.unattended_key = Some(key.to_vec());
            book.add(entry);
        }
        drop(book);
        self.save_settings();
    }

    /// Olvida la contraseña recordada de `id`.
    pub fn forget_key(&self, id: CleanDeskId) {
        if self.state.addressbook.write().update(id, |e| e.unattended_key = None) {
            self.save_settings();
        }
    }

    pub fn remove_favorite(&self, id: CleanDeskId) {
        self.state.addressbook.write().remove(id);
        self.save_settings();
    }

    /// Sondea el resultado de una conexión saliente en curso.
    fn poll_connecting(&mut self, ctx: &egui::Context) {
        let ConnectPhase::Connecting { rx, target } = &mut self.connect else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(session)) => {
                let target = *target;
                info!(%target, "conexión establecida");
                self.mark_connected(target);
                let record = SessionRecord::start(session.session, target, self.device.hostname.clone(), "p2p");
                if let Err(e) = self.state.record_session_start(record) {
                    warn!(error = %e, "no se pudo registrar el historial");
                }
                self.connect_password.clear();
                if let Some((id, key)) = self.pending_remember.take() {
                    self.remember_key(id, key);
                }
                self.connect = ConnectPhase::Active(Box::new(ViewerState::new(session)));
            }
            Ok(Err(e)) => {
                warn!(error = %e, "conexión fallida");
                self.notice = Some(format!("No se pudo conectar: {}", friendly_error(&e)));
                self.connect = ConnectPhase::Idle;
            }
            Err(oneshot::error::TryRecvError::Empty) => {
                // Aún esperando; repintamos para no quedarnos congelados.
                ctx.request_repaint_after(std::time::Duration::from_millis(100));
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                self.notice = Some("La conexión se interrumpió antes de establecerse.".into());
                self.connect = ConnectPhase::Idle;
            }
        }
    }

    /// Actualiza la fecha de última conexión en la agenda si el equipo está guardado.
    fn mark_connected(&self, target: CleanDeskId) {
        let now = unix_now();
        let updated = self.state.addressbook.write().update(target, |e| e.last_connection = Some(now));
        if updated {
            self.save_settings();
        }
    }

    /// Drena solicitudes entrantes hacia la cola de pendientes.
    fn drain_incoming(&mut self) {
        while let Ok(mut req) = self.incoming_rx.try_recv() {
            info!(from = %req.from.id, "solicitud de conexión entrante");
            // Aseguramos que VIEW_SCREEN esté marcado por defecto (base de sesión).
            req.requested.insert(Permissions::VIEW_SCREEN);
            // Prellenamos el checklist con lo solicitado la primera vez que se
            // muestra una solicitud.
            if self.pending.is_empty() {
                self.pending_perms = req.requested;
            }
            self.pending.push(req);
        }
    }

    /// Drena los eventos de ciclo de vida del host (sesiones entrantes).
    fn drain_host_events(&mut self) {
        while let Ok(ev) = self.host_events_rx.try_recv() {
            match ev {
                HostEvent::Registered(id) => {
                    if id != self.id {
                        warn!(%id, expected = %self.id, "el servidor confirmó un ID distinto");
                    }
                }
                HostEvent::SessionStarted { session, peer, granted } => {
                    let user = peer.alias.clone().unwrap_or_else(|| peer.hostname.clone());
                    let record = SessionRecord::start(session, peer.id, user, "p2p (entrante)");
                    if let Err(e) = self.state.record_session_start(record) {
                        warn!(error = %e, "no se pudo registrar el historial");
                    }
                    self.host_session = Some(HostSession { session, peer, granted });
                }
                HostEvent::SessionEnded { session, reason } => {
                    if let Err(e) = self.state.record_session_end(session, "closed") {
                        warn!(error = %e, "no se pudo cerrar el registro de historial");
                    }
                    if self.host_session.as_ref().is_some_and(|s| s.session == session) {
                        self.host_session = None;
                        self.notice = Some(format!("Sesión entrante finalizada: {reason}"));
                    }
                }
            }
        }
    }
}

impl eframe::App for CleanDeskApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1) Avanzar la conexión saliente si está en curso.
        self.poll_connecting(ctx);

        // 2) Recoger solicitudes/eventos entrantes y mostrar el modal si hay.
        self.drain_incoming();
        self.drain_host_events();
        self.show_approval_modal(ctx);

        // 3) Dibujar la vista actual.
        match &mut self.connect {
            ConnectPhase::Active(_) => {
                self.show_viewer(ctx);
            }
            _ => {
                mainwindow::show(self, ctx);
            }
        }
    }
}

impl CleanDeskApp {
    /// Muestra el diálogo modal de aprobación para la primera solicitud pendiente.
    fn show_approval_modal(&mut self, ctx: &egui::Context) {
        if self.pending.is_empty() {
            return;
        }
        ctx.request_repaint(); // mantener el modal vivo/responsivo

        let mut decision: Option<bool> = None; // Some(true)=aceptar, Some(false)=rechazar
        // Tomamos datos de la primera solicitud sin mover la solicitud en sí.
        let (name, id, os, auth) = {
            let req = &self.pending[0];
            (
                req.display_name(),
                req.from.id,
                req.from.os.clone(),
                req.auth,
            )
        };

        egui::Modal::new(egui::Id::new("cleandesk-approval-modal"))
            .frame(theme::card())
            .show(ctx, |ui| {
                ui.set_width(380.0);
                theme::section_label(ui, "Solicitud de conexión", true);
                ui.add_space(6.0);
                ui.label(egui::RichText::new(&name).size(18.0).strong());
                ui.label(egui::RichText::new(id.to_string()).monospace().color(theme::TEXT_DIM));
                if !os.is_empty() {
                    ui.label(egui::RichText::new(format!("Sistema: {os}")).color(theme::TEXT_DIM));
                }
                ui.label(
                    egui::RichText::new(format!("Autenticación: {}", crate::approval::auth_label(auth)))
                        .color(theme::TEXT_DIM),
                );
                ui.add_space(8.0);
                ui.separator();
                theme::section_label(ui, "Permisos concedidos", false);
                ui.add_space(4.0);

                for (perm, label) in crate::approval::PERMISSION_ITEMS {
                    let mut on = self.pending_perms.contains(*perm);
                    if ui.checkbox(&mut on, *label).changed() {
                        self.pending_perms.set(*perm, on);
                    }
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.add(theme::primary_button("Aceptar")).clicked() {
                        decision = Some(true);
                    }
                    if ui.add(theme::danger_button("Rechazar")).clicked() {
                        decision = Some(false);
                    }
                });
            });

        if let Some(accept) = decision {
            let mut req = self.pending.remove(0);
            if accept {
                req.answer(cleandesk_host::Decision::Accept(self.pending_perms));
            } else {
                req.answer(cleandesk_host::Decision::Reject(
                    cleandesk_proto::message::RejectReason::UserDeclined,
                ));
            }
            // Preparar el prellenado de la siguiente solicitud, si la hay.
            if let Some(next) = self.pending.first() {
                self.pending_perms = next.requested;
            }
        }
    }

    /// Dibuja el visor de sesión. Extraído para poder tomar prestado `self` con
    /// la sesión activa sin conflictos con el `match` del bucle.
    fn show_viewer(&mut self, ctx: &egui::Context) {
        // Necesitamos acceso mutable a la sesión y a `self` para acciones (p. ej.
        // desconectar). Sacamos la sesión temporalmente del enum.
        let mut viewer = match std::mem::replace(&mut self.connect, ConnectPhase::Idle) {
            ConnectPhase::Active(v) => v,
            other => {
                // No debería ocurrir, pero restauramos por seguridad.
                self.connect = other;
                return;
            }
        };

        let outcome = crate::viewer::show(&mut viewer, ctx);

        match outcome {
            crate::viewer::ViewerOutcome::Continue => {
                self.connect = ConnectPhase::Active(viewer);
            }
            crate::viewer::ViewerOutcome::Disconnected(notice) => {
                viewer.disconnect();
                if let Err(e) = self.state.record_session_end(viewer.session_id(), "closed") {
                    warn!(error = %e, "no se pudo cerrar el registro de historial");
                }
                if viewer.is_fullscreen() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
                }
                self.notice = notice;
                self.connect = ConnectPhase::Idle;
            }
        }
    }
}

/// Traduce los errores más comunes de conexión a un texto para el usuario.
fn friendly_error(e: &anyhow::Error) -> String {
    let s = format!("{e:#}");
    if s.contains("TargetOffline") {
        "el equipo remoto no está en línea.".into()
    } else if s.contains("Busy") {
        "el equipo remoto ya tiene una sesión activa.".into()
    } else if s.contains("UserDeclined") {
        "el equipo remoto rechazó la conexión.".into()
    } else if s.contains("AuthFailed") {
        "contraseña de acceso desatendido incorrecta o no configurada.".into()
    } else if s.contains("timed out waiting for the host") {
        "el equipo remoto no respondió a tiempo.".into()
    } else if s.contains("connecting to CleanDesk Server") {
        "no se pudo contactar con el servidor CleanDesk.".into()
    } else {
        s
    }
}

/// Arranca (y mantiene) el host en segundo plano, reintentando el registro.
#[allow(clippy::too_many_arguments)]
fn spawn_host(
    rt: Arc<Runtime>,
    state: Arc<AppState>,
    device: DeviceInfo,
    signal_url: String,
    incoming_tx: mpsc::Sender<PendingRequest>,
    events_tx: mpsc::UnboundedSender<HostEvent>,
    control: Arc<HostControl>,
    status: Arc<Mutex<HostStatus>>,
    ctx: egui::Context,
) {
    // El host vive tanto como el runtime (que la app suelta al cerrarse). No hay
    // señal de parada explícita: reintenta el registro indefinidamente.
    rt.spawn(async move {
        let approver: Arc<dyn cleandesk_host::Approver> =
            Arc::new(GuiApprover::new(incoming_tx));

        loop {
            let mut config = HostConfig::new(signal_url.clone(), device.clone(), state.identity.clone());
            {
                let settings = state.settings.read();
                config.unattended_key = settings.unattended_key();
                config.quality = settings.quality;
            }
            config.events = Some(events_tx.clone());
            config.control = Some(control.clone());

            set_status(&status, HostStatus::Connecting);
            ctx.request_repaint();

            // Observamos el evento `Registered` para marcar el host en línea.
            let (probe_tx, mut probe_rx) = mpsc::unbounded_channel::<HostEvent>();
            let events_fanout = events_tx.clone();
            let serve = cleandesk_host::serve(
                HostConfig { events: Some(probe_tx), ..config },
                approver.clone(),
            );
            tokio::pin!(serve);

            let result = loop {
                tokio::select! {
                    r = &mut serve => break r,
                    Some(ev) = probe_rx.recv() => {
                        if matches!(ev, HostEvent::Registered(_)) {
                            set_status(&status, HostStatus::Online);
                        }
                        let _ = events_fanout.send(ev);
                        ctx.request_repaint();
                    }
                }
            };

            match result {
                Ok(()) => warn!("el host dejó de escuchar; reintentando"),
                Err(e) => warn!(error = %e, "el host no pudo registrarse; reintentando"),
            }
            set_status(&status, HostStatus::Offline);
            ctx.request_repaint();

            // Espera antes de reintentar para no martillear el servidor.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

/// Lee el estado del host tolerando un mutex envenenado (recuperando el guard).
fn read_status(status: &Mutex<HostStatus>) -> HostStatus {
    match status.lock() {
        Ok(guard) => *guard,
        Err(poisoned) => *poisoned.into_inner(),
    }
}

/// Escribe el estado del host tolerando un mutex envenenado.
fn set_status(status: &Mutex<HostStatus>, value: HostStatus) {
    match status.lock() {
        Ok(mut guard) => *guard = value,
        Err(poisoned) => *poisoned.into_inner() = value,
    }
}

/// Segundos Unix actuales, tolerante a relojes anteriores a la época.
pub(crate) fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
