//! Aprobación de solicitudes entrantes (spec §5, §6).
//!
//! El host corre en una tarea de fondo; cuando llega una solicitud de conexión
//! necesita una decisión humana. [`GuiApprover`] implementa [`Approver`]
//! reenviando cada solicitud a la interfaz por un canal, junto con un
//! `oneshot::Sender` por el que la interfaz devuelve la [`Decision`]. Mientras
//! tanto la tarea del host queda a la espera del oneshot.

use rotodesk_host::{Approver, Decision};
use rotodesk_proto::{
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
    /// What an unattended (password) caller may get without a human. Same
    /// default as the headless host: the interactive set, everything with
    /// `ROTODESK_UNATTENDED_FULL=1`.
    unattended_allowed: Permissions,
}

/// Environment variable: `1` lets unattended callers request every permission
/// instead of only the interactive set (shared with the headless host).
pub const ENV_UNATTENDED_FULL: &str = "ROTODESK_UNATTENDED_FULL";

impl GuiApprover {
    pub fn new(requests: mpsc::Sender<PendingRequest>) -> Self {
        let full = rotodesk_proto::compat::env(ENV_UNATTENDED_FULL).is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes"));
        let unattended_allowed = if full { Permissions::full() } else { Permissions::interactive() };
        Self { requests, unattended_allowed }
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
        // Acceso desatendido: la autoridad es la contraseña, no un humano. El
        // host aún exige el reto/respuesta HMAC después de este `Accept`, así
        // que conceder aquí lo pedido no salta ninguna comprobación: si la
        // contraseña no cuadra, el host corta la sesión. Sin prompt, como
        // espera cualquier acceso desatendido.
        if matches!(auth, AuthKind::UnattendedPassword) {
            // La contraseña da acceso interactivo; reiniciar, transferir
            // archivos o bloquear el teclado local siguen exigiendo a la
            // persona del host (o `ROTODESK_UNATTENDED_FULL=1`).
            let granted = requested & self.unattended_allowed;
            if granted != requested {
                tracing::info!(from = %from.id, ?requested, ?granted, "narrowing unattended request (set {ENV_UNATTENDED_FULL}=1 to allow all)");
            }
            tracing::info!(from = %from.id, "unattended request accepted automatically (password verified by challenge)");
            return Decision::Accept(granted);
        }
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
    (Permissions::RESTART_ROTODESK, "Restart RotoDesk"),
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
