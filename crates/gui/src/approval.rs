//! Aprobación de solicitudes entrantes (spec §5, §6).
//!
//! El host corre en una tarea de fondo; cuando llega una solicitud de conexión
//! necesita una decisión humana. [`GuiApprover`] implementa [`Approver`]
//! reenviando cada solicitud a la interfaz por un canal, junto con un
//! `oneshot::Sender` por el que la interfaz devuelve la [`Decision`]. Mientras
//! tanto la tarea del host queda a la espera del oneshot.

use cleandesk_host::{Approver, Decision};
use cleandesk_proto::{
    message::{AuthKind, RejectReason},
    permissions::Permissions,
    session::DeviceInfo,
};
use tokio::sync::{mpsc, oneshot};

use crate::i18n::tr;

/// Una solicitud de conexión pendiente de decisión, entregada a la interfaz.
pub struct PendingRequest {
    /// Quién solicita la conexión.
    pub from: DeviceInfo,
    /// Permisos que pide (prellenan el checklist del diálogo).
    pub requested: Permissions,
    /// Cómo se autentica la solicitud (interactiva / desatendida / confianza).
    pub auth: AuthKind,
    /// Por aquí la interfaz devuelve la decisión del usuario. `Option` porque se
    /// consume (se mueve) al responder.
    pub respond: Option<oneshot::Sender<Decision>>,
}

impl PendingRequest {
    /// Nombre legible del solicitante para el diálogo.
    pub fn display_name(&self) -> String {
        match &self.from.alias {
            Some(alias) if !alias.is_empty() => alias.clone(),
            _ => self.from.hostname.clone(),
        }
    }

    /// Envía la decisión final y consume el canal de respuesta.
    pub fn answer(&mut self, decision: Decision) {
        if let Some(tx) = self.respond.take() {
            // Si el receptor ya no está (host cayó), no hay nada que hacer.
            let _ = tx.send(decision);
        }
    }
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        // Si el diálogo se descarta sin responder (p. ej. la app se cierra),
        // rechazamos por defecto para no dejar al host colgado esperando.
        if let Some(tx) = self.respond.take() {
            let _ = tx.send(Decision::Reject(RejectReason::UserDeclined));
        }
    }
}

/// [`Approver`] que delega cada decisión en la interfaz gráfica.
pub struct GuiApprover {
    requests: mpsc::Sender<PendingRequest>,
}

impl GuiApprover {
    pub fn new(requests: mpsc::Sender<PendingRequest>) -> Self {
        Self { requests }
    }
}

#[async_trait::async_trait]
impl Approver for GuiApprover {
    async fn on_request(
        &self,
        from: &DeviceInfo,
        requested: Permissions,
        auth: AuthKind,
    ) -> Decision {
        let (tx, rx) = oneshot::channel();
        let pending = PendingRequest {
            from: from.clone(),
            requested,
            auth,
            respond: Some(tx),
        };
        // Si la interfaz no puede recibir la solicitud, la rechazamos.
        if self.requests.send(pending).await.is_err() {
            return Decision::Reject(RejectReason::UserDeclined);
        }
        // Esperamos la decisión del usuario. Si el canal se cierra sin respuesta
        // (diálogo descartado), rechazamos por seguridad.
        match rx.await {
            Ok(decision) => decision,
            Err(_) => Decision::Reject(RejectReason::UserDeclined),
        }
    }
}

/// Los diez permisos de sesión (spec §6) con su clave de texto (en inglés;
/// traducir con `tr` al dibujar) para el checklist del diálogo de aprobación y
/// la barra de permisos.
pub const PERMISSION_ITEMS: &[(Permissions, &str)] = &[
    (Permissions::VIEW_SCREEN, "View screen"),
    (Permissions::CONTROL_KEYBOARD, "Control keyboard"),
    (Permissions::CONTROL_MOUSE, "Control mouse"),
    (Permissions::CLIPBOARD, "Clipboard"),
    (Permissions::FILE_TRANSFER, "File transfer"),
    (Permissions::AUDIO, "Remote audio"),
    (Permissions::RESTART_MACHINE, "Restart machine"),
    (Permissions::RESTART_CLEANDESK, "Restart CleanDesk"),
    (Permissions::ADMIN_ACTIONS, "Admin actions"),
    (Permissions::LOCK_LOCAL_INPUT, "Lock local keyboard/mouse"),
];

/// Etiqueta legible (ya traducida) del tipo de autenticación para el diálogo.
pub fn auth_label(auth: AuthKind) -> &'static str {
    match auth {
        AuthKind::Interactive => tr("Interactive"),
        AuthKind::UnattendedPassword => tr("Unattended access"),
        AuthKind::Trusted => tr("Trusted device"),
    }
}
