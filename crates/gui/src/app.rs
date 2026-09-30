//! La aplicación eframe: estado global, puente con tokio y bucle de `update`.
//!
//! `RotoDeskApp` es el `eframe::App`. Reúne:
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

use rotodesk_client::{ClientConfig, ClientSession};
use rotodesk_core::{history::SessionRecord, AppState};
use rotodesk_host::{HostConfig, HostControl, HostEvent};
use rotodesk_proto::{
    id::RotoDeskId, permissions::Permissions, session::DeviceInfo, session::SessionId,
};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::approval::{GuiApprover, PendingRequest};
use crate::i18n::{self, tr, trf, Lang};
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
        target: RotoDeskId,
        unattended: bool,
        rx: oneshot::Receiver<anyhow::Result<ClientSession>>,
        task: tokio::task::AbortHandle,
    },
    /// Sesión establecida: mostramos el visor.
    Active(Box<ViewerState>),
}

/// A rejected interactive request can be retried with explicit credentials.
pub struct PasswordPrompt {
    pub target: RotoDeskId,
    pub invalid_password: bool,
    pub focus_needed: bool,
}

impl PasswordPrompt {
    fn for_rejection(target: RotoDeskId, error: &str, unattended: bool) -> Option<Self> {
        let required = error.contains("UnattendedOnly");
        let invalid = unattended && error.contains("AuthFailed");
        (required || invalid).then_some(Self { target, invalid_password: invalid, focus_needed: true })
    }
}

/// Una sesión entrante viva (alguien nos está viendo). Spec §18: confirmación
/// visual de sesión activa.
#[derive(Clone)]
pub struct HostSession {
    pub session: SessionId,
    pub peer: DeviceInfo,
    pub granted: Permissions,
}

/// Página de la navegación superior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Page {
    #[default]
    Home,
    Sessions,
    Contacts,
    Invitations,
}

/// Un equipo visto en la red local (descubrimiento mDNS).
#[derive(Debug, Clone)]
pub struct NearbyDevice {
    pub id: RotoDeskId,
    pub alias: Option<String>,
    pub mac: Option<String>,
}

/// La aplicación completa.
pub struct RotoDeskApp {
    /// Estado persistente compartido con las tareas asíncronas.
    pub state: Arc<AppState>,
    /// Este dispositivo, tal y como se anuncia en señalización.
    pub device: DeviceInfo,
    /// Nuestro propio RotoDesk ID (derivado de la identidad).
    pub id: RotoDeskId,
    /// Servidor de señalización forzado desde la línea de órdenes (`--signal-url`);
    /// si es `None` manda el modo de red de los ajustes.
    pub signal_override: Option<String>,
    /// Avisa al bucle del host de que el modo de red cambió y debe reiniciarse.
    host_restart: Arc<tokio::sync::Notify>,
    /// Runtime de tokio propiedad de la app; vive tanto como la ventana.
    pub rt: Arc<Runtime>,

    /// Fase de la conexión saliente.
    connect: ConnectPhase,
    /// Texto del campo "Introducir RotoDesk ID".
    pub connect_input: String,
    /// Contraseña para conectar a un host desatendido (vacía = interactivo).
    pub connect_password: String,
    /// Mostrar el campo de contraseña desatendida.
    pub show_connect_password: bool,
    /// Guardar la clave derivada en favoritos al conectar con éxito.
    pub remember_password: bool,
    /// Clave pendiente de guardar cuando la conexión en curso tenga éxito.
    pending_remember: Option<(RotoDeskId, [u8; 32])>,
    /// Aviso a mostrar en la ventana principal (error de conexión, desconexión…).
    pub notice: Option<String>,
    pub password_prompt: Option<PasswordPrompt>,
    /// Equipo cuya identidad cambió respecto a la clave fijada; el usuario
    /// decide si confiar en la nueva (tras comprobar la huella).
    pub identity_alarm: Option<RotoDeskId>,
    /// Icono de bandeja (None si el sistema no lo permite).
    tray: Option<crate::tray::Tray>,
    /// Otra instancia pidió que mostremos la ventana (mutex de instancia única).
    pub show_requested: Arc<std::sync::atomic::AtomicBool>,
    /// Actualizador automático (GitHub Releases).
    pub updater: crate::updater::Updater,
    /// El usuario eligió "Salir": la siguiente petición de cierre se acepta.
    quitting: bool,
    /// Página activa de la navegación superior.
    pub page: Page,
    /// Último equipo al que se conectó con éxito (para la miniatura).
    pub last_target: Option<RotoDeskId>,
    /// Miniaturas de la última sesión por equipo (cargadas perezosamente;
    /// `None` = no hay fichero).
    pub thumbs: std::collections::HashMap<u64, Option<egui::TextureHandle>>,
    /// Equipos vistos en la red local en el último rastreo.
    pub nearby: Arc<Mutex<Vec<NearbyDevice>>>,
    /// Hay un rastreo mDNS en curso.
    pub discovering: Arc<std::sync::atomic::AtomicBool>,
    /// Ventana "Equipos cercanos" visible.
    pub show_nearby: bool,
    /// Instante del último rastreo automático.
    pub last_scan: Option<std::time::Instant>,
    /// Independent background presence monitor, including while hidden in tray.
    presence_monitor: crate::presence::Presence,
    /// Ventana de ajustes visible.
    pub show_settings: bool,
    pub settings_section: usize,
    #[cfg(debug_assertions)]
    capture_requested: bool,
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
    /// Mensaje de estado de la sección de acceso desatendido (dentro de la
    /// ventana de Ajustes, no en el aviso general): (texto, es_error).
    pub unattended_msg: Option<(String, bool)>,
    /// Estado del servicio de Windows y del arranque con la sesión (se refrescan
    /// periódicamente mientras la ventana de ajustes está abierta).
    pub service_status: rotodesk_platform::service::ServiceStatus,
    pub run_at_login: bool,
    pub platform_checked_at: Option<std::time::Instant>,
    /// Sonda en curso del estado del servicio / arranque (hilo aparte: `sc` y
    /// `reg` tardan cientos de ms y congelarían la interfaz).
    pub platform_probe:
        Option<std::sync::mpsc::Receiver<(rotodesk_platform::service::ServiceStatus, bool)>>,
    /// Marca "hay una GUI abierta" para que el host del servicio se aparte.
    _presence: Option<rotodesk_platform::presence::PresenceLock>,
    /// El servicio (LocalSystem) hace de host mientras la ventana está abierta
    /// (control privilegiado): la GUI no registra el ID ni acepta sesiones.
    pub hosted_by_service: bool,
    /// Este proceso corre elevado (control de ventanas de administrador).
    pub elevated: bool,
}

impl RotoDeskApp {
    /// Construye la app, arranca el host de fondo y, si procede, la conexión
    /// automática inicial.
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        state: Arc<AppState>,
        device: DeviceInfo,
        rt: Arc<Runtime>,
        signal_override: Option<String>,
        initial_target: Option<RotoDeskId>,
    ) -> Self {
        theme::apply(&cc.egui_ctx);
        // Idioma de la interfaz: el guardado en ajustes o, si no hay, el del sistema.
        let lang = state
            .settings
            .read()
            .language
            .as_deref()
            .map(Lang::from_tag)
            .unwrap_or_else(Lang::system);
        i18n::set_lang(lang);
        let id = state.identity.derive_id();
        let alias_edit = state.settings.read().alias.clone().unwrap_or_default();

        // Canales host -> interfaz.
        let (incoming_tx, incoming_rx) = mpsc::channel::<PendingRequest>(8);
        let (host_events_tx, host_events_rx) = mpsc::unbounded_channel::<HostEvent>();
        let host_status = Arc::new(Mutex::new(HostStatus::Connecting));
        let host_control = HostControl::new();
        let host_restart = Arc::new(tokio::sync::Notify::new());
        // Control privilegiado con el servicio en marcha: el host del servicio
        // (LocalSystem) sigue sirviendo y la GUI no toma el relevo. Sin el lock
        // de presencia el servicio no se aparta.
        let elevated = rotodesk_platform::elevation::is_elevated();
        let hosted_by_service = state.settings.read().privileged_control
            && rotodesk_platform::service::status() == rotodesk_platform::service::ServiceStatus::Running;
        let presence = if hosted_by_service {
            info!("privileged control: the RotoDesk service keeps hosting; GUI will not register");
            None
        } else {
            match rotodesk_platform::presence::PresenceLock::acquire(&state.data_dir()) {
                Ok(lock) => Some(lock),
                Err(e) => {
                    warn!(error = %e, "no se pudo crear el lock de presencia de la GUI");
                    None
                }
            }
        };

        // Arranca el host en segundo plano (best-effort).
        if hosted_by_service {
            if let Ok(mut s) = host_status.lock() {
                *s = HostStatus::Online;
            }
        } else {
        spawn_host(
            rt.clone(),
            state.clone(),
            device.clone(),
            signal_override.clone(),
            host_restart.clone(),
            incoming_tx,
            host_events_tx,
            host_control.clone(),
            host_status.clone(),
            cc.egui_ctx.clone(),
        );
        }

        let presence_monitor = crate::presence::Presence::start(&rt, state.clone(), device.clone(),
            signal_override.clone(), cc.egui_ctx.clone(), crate::tray::native_handle(cc));
        let mut app = Self {
            state,
            device,
            id,
            signal_override,
            host_restart,
            rt,
            hosted_by_service,
            elevated,
            connect: ConnectPhase::Idle,
            connect_input: String::new(),
            connect_password: String::new(),
            show_connect_password: false,
            remember_password: false,
            pending_remember: None,
            notice: None,
            password_prompt: None,
            identity_alarm: None,
            tray: match crate::tray::Tray::new(cc.egui_ctx.clone(), crate::tray::native_handle(cc))
            {
                Ok(t) => Some(t),
                Err(e) => {
                    warn!(error = %e, "tray icon unavailable");
                    None
                }
            },
            quitting: false,
            show_requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            updater: crate::updater::Updater::default(),
            page: Page::Home,
            last_target: None,
            thumbs: std::collections::HashMap::new(),
            nearby: Arc::new(Mutex::new(Vec::new())),
            discovering: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            show_nearby: false,
            last_scan: None,
            presence_monitor,
            // `ROTODESK_OPEN_SETTINGS=1` abre Ajustes al arrancar (capturas, soporte).
            settings_section: rotodesk_proto::compat::env("ROTODESK_SETTINGS_SECTION").ok().and_then(|v| v.parse().ok()).unwrap_or(0),
            #[cfg(debug_assertions)]
            capture_requested: false,
            show_settings: rotodesk_proto::compat::env("ROTODESK_OPEN_SETTINGS").is_ok_and(|v| v == "1"),
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
            unattended_msg: None,
            service_status: rotodesk_platform::service::ServiceStatus::NotInstalled,
            run_at_login: false,
            platform_checked_at: None,
            platform_probe: None,
            _presence: presence,
        };

        #[cfg(debug_assertions)]
        app.configure_showcase();

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
    pub fn connecting_target(&self) -> Option<RotoDeskId> {
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
    pub fn start_connection(&mut self, target: RotoDeskId, ctx: &egui::Context) {
        if self.is_connecting() || matches!(self.connect, ConnectPhase::Active(_)) {
            return; // una sesión a la vez (MVP)
        }
        if target == self.id {
            self.notice = Some(tr("You cannot connect to your own ID.").into());
            return;
        }
        self.notice = None;
        self.password_prompt = None;

        let quality = self.state.settings.read().quality;
        let mode = self.network_mode();
        let mut config = ClientConfig::new(
            mode.server_url().unwrap_or_default().to_string(),
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
            match rotodesk_crypto::password::unattended_key(pw, target.value()) {
                Ok(key) => {
                    config.unattended_key = Some(key);
                    if self.remember_password {
                        self.pending_remember = Some((target, key));
                    }
                }
                Err(e) => {
                    self.notice = Some(trf(
                        "Could not derive the key: {err}",
                        &[("err", &e.to_string())],
                    ));
                    return;
                }
            }
        } else if let Some(key) = self
            .state
            .addressbook
            .read()
            .find_by_id(target)
            .and_then(|e| e.unattended_key())
        {
            // Equipo guardado con contraseña recordada: conexión desatendida directa.
            config.unattended_key = Some(key);
        }

        let pinned = self
            .state
            .settings
            .read()
            .pinned_key(target)
            .map(str::to_string);
        // La clave fijada (TOFU) es la que el host debe demostrar en el
        // enlace de identidad, en cualquier modo de red; sin clave fijada, la
        // primera sesión la fija tras verificarla.
        config.expected_host_key = pinned.clone();
        let unattended = config.unattended_key.is_some();
        let (tx, rx) = oneshot::channel();
        let ctx = ctx.clone();
        let task = self.rt.spawn(async move {
            let result = if mode.is_community() {
                rotodesk_client::connect_community(config, pinned).await
            } else {
                rotodesk_client::connect(config).await
            };
            let _ = tx.send(result);
            ctx.request_repaint();
        });

        info!(%target, "iniciando conexión saliente");
        self.connect = ConnectPhase::Connecting { target, unattended, rx, task: task.abort_handle() };
    }

    pub fn cancel_connection(&mut self) {
        if let ConnectPhase::Connecting { task, .. } = &self.connect {
            task.abort();
            self.connect = ConnectPhase::Idle;
            self.pending_remember = None;
        }
    }

    /// Modo de red efectivo: `--signal-url` manda; si no, los ajustes.
    pub fn network_mode(&self) -> rotodesk_core::config::NetworkMode {
        match &self.signal_override {
            Some(url) => rotodesk_core::config::NetworkMode::Server { url: url.clone() },
            None => self.state.settings.read().network.clone(),
        }
    }

    /// Reinicia el host de fondo (tras cambiar el modo de red).
    pub fn restart_host(&self) {
        self.host_restart.notify_one();
    }

    /// Olvida la clave fijada de `id` (el usuario verificó el cambio de identidad).
    pub fn unpin_key(&self, id: RotoDeskId) {
        if self.state.settings.write().unpin_key(id) {
            self.save_settings();
        }
    }

    /// Persiste ajustes en disco, registrando (sin propagar) cualquier error.
    pub fn save_settings(&self) {
        if let Err(e) = self.state.save() {
            warn!(error = %e, "no se pudieron guardar los ajustes");
        }
    }

    /// Añade (o actualiza) un dispositivo en la agenda.
    pub fn add_favorite(&self, id: RotoDeskId, name: String) {
        use rotodesk_core::addressbook::DeviceEntry;
        let mut book = self.state.addressbook.write();
        if !book.update(id, |e| {
            if !name.trim().is_empty() {
                e.name = name.clone();
            }
        }) {
            let name = if name.trim().is_empty() {
                id.to_string()
            } else {
                name
            };
            book.add(DeviceEntry::new(id, name));
        }
        drop(book);
        // La clave anunciada por mDNS NO se fija: el TXT no va firmado y
        // cualquiera en la LAN podría colarnos una clave para un ID ajeno. La
        // fijación (TOFU) ocurre solo tras una sesión que demuestre la clave.
        let mac = self
            .nearby
            .lock()
            .ok()
            .and_then(|n| n.iter().find(|d| d.id == id).and_then(|d| d.mac.clone()));
        if let Some(mac) = mac {
            self.state
                .addressbook
                .write()
                .update(id, |e| e.mac = Some(mac.clone()));
        }
        self.save_settings();
    }

    /// Guarda la clave desatendida derivada para `id` (creando el favorito si no existe).
    pub fn remember_key(&self, id: RotoDeskId, key: [u8; 32]) {
        use rotodesk_core::addressbook::DeviceEntry;
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
    pub fn forget_key(&self, id: RotoDeskId) {
        if self
            .state
            .addressbook
            .write()
            .update(id, |e| e.unattended_key = None)
        {
            self.save_settings();
        }
    }

    pub fn remove_favorite(&self, id: RotoDeskId) {
        self.state.addressbook.write().remove(id);
        self.save_settings();
    }

    /// Sondea el resultado de una conexión saliente en curso.
    fn poll_connecting(&mut self, ctx: &egui::Context) {
        let ConnectPhase::Connecting { rx, target, unattended, .. } = &mut self.connect else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(session)) => {
                let target = *target;
                info!(%target, "conexión establecida");
                self.last_target = Some(target);
                self.mark_connected(target);
                let record = SessionRecord::start(
                    session.session,
                    target,
                    self.device.hostname.clone(),
                    "p2p",
                );
                if let Err(e) = self.state.record_session_start(record) {
                    warn!(error = %e, "no se pudo registrar el historial");
                }
                self.connect_password.clear();
                if let Some((id, key)) = self.pending_remember.take() {
                    self.remember_key(id, key);
                }
                // Trust on first use: recuerda la clave del equipo remoto.
                if let Some(pk) = &session.peer_public_key {
                    if self.state.settings.write().pin_key(target, pk) {
                        self.save_settings();
                    }
                }
                // Y su MAC, para poder despertarlo desde la agenda.
                if let Some(mac) = session.peer_mac.clone() {
                    self.remember_mac(target, mac);
                }
                self.connect = ConnectPhase::Active(Box::new(ViewerState::new(session)));
            }
            Ok(Err(e)) => {
                warn!(error = %e, "conexión fallida");
                let raw = format!("{e:#}");
                self.pending_remember = None;
                self.password_prompt = PasswordPrompt::for_rejection(*target, &raw, *unattended);
                if self.password_prompt.is_some() {
                    self.connect_input = target.to_string();
                    self.connect_password.clear();
                    self.show_connect_password = true;
                    self.notice = None;
                    self.connect = ConnectPhase::Idle;
                    return;
                }
                if is_identity_change(&raw) {
                    self.identity_alarm = Some(*target);
                }
                let text = friendly_error(&raw);
                self.notice = Some(trf("Could not connect: {err}", &[("err", &text)]));
                self.connect = ConnectPhase::Idle;
            }
            Err(oneshot::error::TryRecvError::Empty) => {
                // Aún esperando; repintamos para no quedarnos congelados.
                ctx.request_repaint_after(std::time::Duration::from_millis(100));
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                self.notice =
                    Some(tr("The connection was interrupted before it was established.").into());
                self.connect = ConnectPhase::Idle;
            }
        }
    }

    /// Actualiza la fecha de última conexión en la agenda si el equipo está guardado.
    fn mark_connected(&self, target: RotoDeskId) {
        let now = unix_now();
        let updated = self
            .state
            .addressbook
            .write()
            .update(target, |e| e.last_connection = Some(now));
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
                HostEvent::SessionStarted {
                    session,
                    peer,
                    granted,
                } => {
                    let user = peer.alias.clone().unwrap_or_else(|| peer.hostname.clone());
                    let record = SessionRecord::start(session, peer.id, user, "p2p (entrante)");
                    if let Err(e) = self.state.record_session_start(record) {
                        warn!(error = %e, "no se pudo registrar el historial");
                    }
                    self.host_session = Some(HostSession {
                        session,
                        peer,
                        granted,
                    });
                }
                HostEvent::SessionEnded { session, reason } => {
                    if let Err(e) = self.state.record_session_end(session, "closed") {
                        warn!(error = %e, "no se pudo cerrar el registro de historial");
                    }
                    if self
                        .host_session
                        .as_ref()
                        .is_some_and(|s| s.session == session)
                    {
                        self.host_session = None;
                        self.notice = Some(trf(
                            "Incoming session ended: {reason}",
                            &[("reason", friendly_reason(&reason))],
                        ));
                    }
                }
            }
        }
    }
}

impl eframe::App for RotoDeskApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 0) Bandeja: mostrar/salir, y cerrar = ocultar si así está configurado.
        self.handle_tray(ctx);
        let check_updates = self.state.settings.read().check_updates;
        self.updater.maybe_check(check_updates, ctx);

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
        #[cfg(debug_assertions)]
        self.capture_preview(ctx);
    }
}

impl RotoDeskApp {
    /// Procesa los eventos del icono de bandeja y la petición de cierre de la
    /// ventana. Con `minimize_to_tray` activo, cerrar solo oculta la ventana;
    /// "Salir" en el menú de la bandeja cierra de verdad.
    fn handle_tray(&mut self, ctx: &egui::Context) {
        use crate::tray::TrayAction;
        if self
            .show_requested
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        if let Some(tray) = &self.tray {
            match tray.poll() {
                TrayAction::Show => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TrayAction::Quit => {
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                TrayAction::None => {}
            }
        }
        if ctx.input(|i| i.viewport().close_requested()) {
            let to_tray = self.tray.is_some() && self.state.settings.read().minimize_to_tray;
            if to_tray && !self.quitting {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
        }
    }

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

        egui::Modal::new(egui::Id::new("rotodesk-approval-modal"))
            .frame(theme::card())
            .show(ctx, |ui| {
                ui.set_width(380.0);
                ui.horizontal(|ui| { theme::brand(ui, 34.0); theme::wordmark(ui, 27.0); });
                ui.add_space(8.0);
                theme::section_label(ui, tr("Connection request"), true);
                ui.add_space(6.0);
                ui.label(egui::RichText::new(&name).size(18.0).strong());
                ui.label(
                    egui::RichText::new(id.to_string())
                        .monospace()
                        .color(theme::TEXT_DIM),
                );
                if !os.is_empty() {
                    ui.label(
                        egui::RichText::new(trf("System: {os}", &[("os", &os)]))
                            .color(theme::TEXT_DIM),
                    );
                }
                ui.label(
                    egui::RichText::new(trf(
                        "Authentication: {auth}",
                        &[("auth", crate::approval::auth_label(auth))],
                    ))
                    .color(theme::TEXT_DIM),
                );
                ui.add_space(8.0);
                ui.separator();
                theme::section_label(ui, tr("Granted permissions"), false);
                ui.add_space(4.0);

                for (perm, label) in crate::approval::PERMISSION_ITEMS {
                    let mut on = self.pending_perms.contains(*perm);
                    if ui.checkbox(&mut on, tr(label)).changed() {
                        self.pending_perms.set(*perm, on);
                    }
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.add(theme::primary_button(tr("Accept"))).clicked() {
                        decision = Some(true);
                    }
                    if ui.add(theme::danger_button(tr("Decline"))).clicked() {
                        decision = Some(false);
                    }
                });
            });

        if let Some(accept) = decision {
            let mut req = self.pending.remove(0);
            if accept {
                req.answer(rotodesk_host::Decision::Accept(self.pending_perms));
            } else {
                req.answer(rotodesk_host::Decision::Reject(
                    rotodesk_proto::message::RejectReason::UserDeclined,
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

        let (notice, password_rejected) = match outcome {
            crate::viewer::ViewerOutcome::Continue => {
                self.connect = ConnectPhase::Active(viewer);
                return;
            }
            crate::viewer::ViewerOutcome::Disconnected(notice) => (notice, false),
            crate::viewer::ViewerOutcome::PasswordRejected => (None, true),
        };
        viewer.disconnect();
        if let (Some(target), Some(frame)) = (self.last_target, viewer.last_frame()) {
            self.save_thumbnail(target, frame);
        }
        if let Err(e) = self.state.record_session_end(viewer.session_id(), "closed") {
            warn!(error = %e, "no se pudo cerrar el registro de historial");
        }
        if viewer.is_fullscreen() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
        }
        self.notice = notice;
        self.pending_remember = None;
        if password_rejected {
            if let Some(target) = self.last_target {
                self.password_prompt = PasswordPrompt::for_rejection(target, "AuthFailed", true);
                self.connect_input = target.to_string();
                self.connect_password.clear();
                self.show_connect_password = true;
            }
        }
        self.connect = ConnectPhase::Idle;
    }
}

/// ¿El error de conexión (`{e:#}`) indica que la clave fijada del equipo
/// remoto ya no coincide? Acepta la redacción en inglés y en español de los
/// crates de descubrimiento/cliente.
fn is_identity_change(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    (l.contains("identity") && (l.contains("changed") || l.contains("mismatch")))
        || (l.contains("identidad") && l.contains("cambiado"))
}

/// Traduce los errores más comunes de conexión (ya formateados con `{e:#}`) a
/// un texto para el usuario. Los mensajes de otros crates se reconocen por
/// subcadenas, en inglés y en español.
fn friendly_error(s: &str) -> String {
    if is_identity_change(s) {
        tr("the remote device's identity has changed; verify its fingerprint before trusting the new key.").into()
    } else if s.contains("not announced") || s.contains("no está anunciado") {
        tr("the remote device is not announced (is it on, with RotoDesk running?).").into()
    } else if s.contains("several keys claim this id") {
        tr("Several devices claim this ID. Compare the fingerprint with the owner and connect only if it matches.").into()
    } else if s.contains("TargetOffline") {
        tr("the remote device is offline.").into()
    } else if s.contains("Busy") {
        tr("the remote device already has an active session.").into()
    } else if s.contains("UnattendedOnly") {
        tr("The remote device is served by its background service and only accepts unattended connections: tick \"Unattended access\" and enter its password.").into()
    } else if s.contains("UserDeclined") {
        tr("the remote device declined the connection.").into()
    } else if s.contains("AuthFailed") {
        tr("wrong or unconfigured unattended-access password.").into()
    } else if s.contains("timed out waiting for the host") {
        tr("the remote device did not respond in time.").into()
    } else if s.contains("connecting to RotoDesk Server") {
        tr("could not reach the RotoDesk server.").into()
    } else {
        s.to_string()
    }
}

/// Traduce los motivos de fin de sesión conocidos que emiten host/cliente.
pub(crate) fn friendly_reason(reason: &str) -> &str {
    if reason == "terminated by the host" || reason == "terminada por el host" {
        tr("terminated by the host")
    } else {
        reason
    }
}

/// Arranca (y mantiene) el host en segundo plano, reintentando el registro.
#[allow(clippy::too_many_arguments)]
fn spawn_host(
    rt: Arc<Runtime>,
    state: Arc<AppState>,
    device: DeviceInfo,
    signal_override: Option<String>,
    restart: Arc<tokio::sync::Notify>,
    incoming_tx: mpsc::Sender<PendingRequest>,
    events_tx: mpsc::UnboundedSender<HostEvent>,
    control: Arc<HostControl>,
    status: Arc<Mutex<HostStatus>>,
    ctx: egui::Context,
) {
    // El host vive tanto como el runtime (que la app suelta al cerrarse). No hay
    // señal de parada explícita: reintenta el registro indefinidamente.
    rt.spawn(async move {
        let approver: Arc<dyn rotodesk_host::Approver> = Arc::new(GuiApprover::new(incoming_tx));

        loop {
            let mode = match &signal_override {
                Some(url) => rotodesk_core::config::NetworkMode::Server { url: url.clone() },
                None => state.settings.read().network.clone(),
            };
            let mut config = HostConfig::new(
                mode.server_url().unwrap_or_default().to_string(),
                device.clone(),
                state.identity.clone(),
            );
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
            let config = HostConfig {
                events: Some(probe_tx),
                ..config
            };
            let serve: std::pin::Pin<
                Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>,
            > = if mode.is_community() {
                Box::pin(rotodesk_host::serve_community(config, approver.clone()))
            } else {
                Box::pin(rotodesk_host::serve(config, approver.clone()))
            };
            tokio::pin!(serve);

            let result = loop {
                tokio::select! {
                    r = &mut serve => break r,
                    _ = restart.notified() => {
                        info!("modo de red cambiado; reiniciando el host");
                        break Ok(());
                    }
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

// ---------------------------------------------------------------------------
// Miniaturas, descubrimiento LAN e invitaciones
// ---------------------------------------------------------------------------

impl RotoDeskApp {
    /// Ruta del PNG de miniatura de `id`.
    fn thumb_path(&self, id: RotoDeskId) -> std::path::PathBuf {
        self.state
            .data_dir()
            .join("thumbs")
            .join(format!("{}.png", id.value()))
    }

    /// Guarda una miniatura (≈320 px de ancho) del último fotograma de una
    /// sesión, para la tarjeta de "Sesiones recientes".
    pub fn save_thumbnail(&mut self, id: RotoDeskId, frame: &rotodesk_codec::DecodedImage) {
        if frame.width == 0 || frame.height == 0 {
            return;
        }
        let Some(src) = image::RgbaImage::from_raw(frame.width, frame.height, frame.rgba.clone())
        else {
            return;
        };
        let target_w = 320u32.min(frame.width);
        let target_h = ((frame.height as u64 * target_w as u64) / frame.width as u64).max(1) as u32;
        let small = image::imageops::resize(
            &src,
            target_w,
            target_h,
            image::imageops::FilterType::Triangle,
        );
        let path = self.thumb_path(id);
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Err(e) = small.save(&path) {
            warn!(error = %e, "could not save session thumbnail");
        }
        // Forzamos recarga en la siguiente pintura.
        self.thumbs.remove(&id.value());
    }

    /// Textura de la miniatura de `id`, cargándola del disco la primera vez.
    pub fn thumbnail(
        &mut self,
        ctx: &egui::Context,
        id: RotoDeskId,
    ) -> Option<egui::TextureHandle> {
        if let Some(cached) = self.thumbs.get(&id.value()) {
            return cached.clone();
        }
        let path = self.thumb_path(id);
        let loaded = image::open(&path).ok().map(|img| {
            let rgba = img.to_rgba8();
            let size = [rgba.width() as usize, rgba.height() as usize];
            let color = egui::ColorImage::from_rgba_unmultiplied(size, rgba.as_raw());
            ctx.load_texture(
                format!("thumb-{}", id.value()),
                color,
                egui::TextureOptions::LINEAR,
            )
        });
        self.thumbs.insert(id.value(), loaded.clone());
        loaded
    }

    /// Lanza un rastreo mDNS de la red local (no bloquea). Los resultados
    /// aparecen en `nearby` cuando termina.
    pub fn discover_nearby(&mut self, ctx: &egui::Context) {
        use std::sync::atomic::Ordering;
        if self.discovering.swap(true, Ordering::Relaxed) {
            return;
        }
        self.last_scan = Some(std::time::Instant::now());
        let nearby = self.nearby.clone();
        let flag = self.discovering.clone();
        let me = self.id;
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let peers =
                rotodesk_discovery::lan::browse_all(std::time::Duration::from_millis(2500)).await;
            let list: Vec<NearbyDevice> = peers
                .into_iter()
                .filter(|p| p.id != me)
                .map(|p| NearbyDevice {
                    id: p.id,
                    alias: p.alias,
                    mac: p.mac,
                })
                .collect();
            if let Ok(mut guard) = nearby.lock() {
                *guard = list;
            }
            flag.store(false, Ordering::Relaxed);
            ctx.request_repaint();
        });
    }

    pub fn is_online(&self, id: RotoDeskId) -> bool {
        self.presence_monitor.online.lock().is_ok_and(|online| online.contains(&id))
    }

    /// Refresca `service_status` / `run_at_login` sin bloquear: lanza la sonda
    /// en un hilo si toca y recoge el resultado cuando llega.
    pub fn poll_platform_status(&mut self, ctx: &egui::Context) {
        use rotodesk_platform::{service, startup};
        if let Some(rx) = &self.platform_probe {
            match rx.try_recv() {
                Ok((status, run)) => {
                    self.service_status = status;
                    self.run_at_login = run;
                    self.platform_checked_at = Some(std::time::Instant::now());
                    self.platform_probe = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => return,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => self.platform_probe = None,
            }
        }
        let stale = self
            .platform_checked_at
            .is_none_or(|t| t.elapsed() > std::time::Duration::from_secs(3));
        if !stale {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("rotodesk-platform-probe".into())
            .spawn(move || {
                let status = service::status();
                let run = startup::is_run_at_login().unwrap_or(false);
                let _ = tx.send((status, run));
                ctx.request_repaint();
            });
        match spawned {
            Ok(_) => self.platform_probe = Some(rx),
            Err(e) => {
                warn!(error = %e, "no se pudo lanzar la sonda de plataforma");
                self.platform_checked_at = Some(std::time::Instant::now());
            }
        }
    }

    /// Guarda la MAC de un contacto (solo si ya está en la agenda).
    pub fn remember_mac(&self, id: RotoDeskId, mac: String) {
        let changed = self.state.addressbook.write().update(id, |e| {
            if e.mac.as_deref() != Some(mac.as_str()) {
                e.mac = Some(mac.clone());
            }
        });
        if changed {
            self.save_settings();
        }
    }

    /// Texto de invitación listo para pegar en un chat o correo.
    pub fn invitation_text(&self) -> String {
        crate::i18n::trf(
            "Connect to my desktop with RotoDesk.\nMy RotoDesk ID: {id}\nFingerprint: {fp}\nDownload: https://github.com/EnriqueGF/RotoDesk/releases",
            &[("id", &self.id.to_string()), ("fp", &self.state.identity.fingerprint())],
        )
    }
}

#[cfg(debug_assertions)]
impl RotoDeskApp {
    /// Isolated, debug-only screenshot fixtures. No real profile or peer IDs.
    fn configure_showcase(&mut self) {
        if std::env::var("ROTODESK_SHOWCASE").is_err() || std::env::var("ROTODESK_SCREENSHOT").is_err() { return; }
        self.id = RotoDeskId::new(123456789).unwrap();
        self.alias_edit = "PC del shur".into();
        {
            let mut settings = self.state.settings.write();
            settings.check_updates = false;
            settings.alias = Some(self.alias_edit.clone());
            settings.language = Some("es".into());
        }
        i18n::set_lang(Lang::Es);
        if std::env::var("ROTODESK_PREVIEW_PASSWORD").is_ok_and(|v| v == "1") {
            self.password_prompt = PasswordPrompt::for_rejection(RotoDeskId::new(987654321).unwrap(), "UnattendedOnly", false);
            self.show_connect_password = true;
        }
        {
            let mut history = self.state.history.write();
            history.records.clear();
            for (n, name) in [(987654321, "PC de sobremesa"), (234567891, "Portátil"), (345678912, "PC de soporte")] {
                let mut record = SessionRecord::start(Default::default(), RotoDeskId::new(n).unwrap(), name, "P2P");
                record.finish("closed");
                record.duration_secs = Some(420);
                history.push(record);
            }
        }
        if std::env::var("ROTODESK_PREVIEW_REQUEST").is_ok_and(|v| v == "1") {
            let requested = Permissions::interactive();
            self.pending_perms = requested;
            self.pending.push(PendingRequest {
                from: DeviceInfo { id: RotoDeskId::new(987654321).unwrap(), alias: Some("Shur de soporte".into()),
                    hostname: "PC de soporte".into(), os: "Windows 11".into(), app_version: crate::VERSION.into() },
                requested, auth: rotodesk_proto::message::AuthKind::Interactive, respond: None,
            });
        }
    }

    /// Capture only our framebuffer for UI review, regardless of overlapping windows.
    fn capture_preview(&mut self, ctx: &egui::Context) {
        let Ok(path) = rotodesk_proto::compat::env("ROTODESK_SCREENSHOT") else { return };
        if !self.capture_requested && rotodesk_proto::compat::env("ROTODESK_PREVIEW_MAXIMIZED").is_ok_and(|v| v == "1") {
            ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(true));
        }
        if !self.capture_requested && ctx.input(|i| i.time) > 2.0 {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            self.capture_requested = true;
        }
        let capture = ctx.input(|i| i.events.iter().find_map(|e| {
            if let egui::Event::Screenshot { image, .. } = e { Some(image.clone()) } else { None }
        }));
        if let Some(capture) = capture {
            let rgba: Vec<u8> = capture.pixels.iter().flat_map(|p| p.to_array()).collect();
            let result = image::save_buffer(path, &rgba, capture.size[0] as u32, capture.size[1] as u32, image::ColorType::Rgba8);
            if let Err(err) = result { warn!(%err, "preview capture failed"); }
            self.quitting = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}

#[cfg(test)]
mod password_prompt_tests {
    use super::*;

    #[test]
    fn interactive_rejection_prompts_for_the_same_device() {
        let target = RotoDeskId::new(123456789).unwrap();
        let prompt = PasswordPrompt::for_rejection(target, "connection rejected: UnattendedOnly", false).unwrap();
        assert_eq!(prompt.target, target);
        assert!(!prompt.invalid_password);
        assert!(prompt.focus_needed);
    }

    #[test]
    fn authentication_rejection_only_retries_unattended_requests() {
        let target = RotoDeskId::new(123456789).unwrap();
        assert!(PasswordPrompt::for_rejection(target, "AuthFailed", true).unwrap().invalid_password);
        for reason in ["AuthFailed", "UserDeclined", "Busy", "Timeout", "identity mismatch"] {
            assert!(PasswordPrompt::for_rejection(target, reason, false).is_none());
        }
    }
}
