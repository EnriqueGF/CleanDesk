//! cleandesk-gui
//!
//! Interfaz de usuario de CleanDesk sobre **eframe/egui**: la ventana principal
//! (spec §4) y el visor de sesión (spec §7, §16, §17, §26, §27).
//!
//! El binario `app` llama a [`run`], que construye una ventana nativa de eframe y
//! bloquea hasta que se cierra. Todo el trabajo asíncrono (host entrante y
//! conexión saliente) vive en un runtime de tokio propiedad de la app; el bucle
//! de `update` de egui solo sondea canales con `try_recv()` y nunca bloquea en
//! rutas de red.

mod app;
mod approval;
mod i18n;
mod keymap;
mod mainwindow;
mod theme;
mod tray;
mod viewer;

use std::sync::Arc;

use cleandesk_core::AppState;
use cleandesk_proto::{id::CleanDeskId, session::DeviceInfo};

use crate::app::CleanDeskApp;

/// Versión del crate, útil para diagnósticos.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Arranca la interfaz gráfica y bloquea hasta que la ventana se cierra.
///
/// * `app_state` — estado persistente compartido (identidad, ajustes, agenda,
///   historial), ya cargado por el binario.
/// * `device` — información de este dispositivo tal como se anuncia en la
///   señalización.
/// * `signal_override` — URL del servidor forzada por `--signal-url`; `None` usa los ajustes.
/// * `initial_target` — si es `Some(id)`, se inicia automáticamente una conexión
///   saliente a ese ID al arrancar (lo usa `--connect`).
pub fn run(
    app_state: Arc<AppState>,
    device: DeviceInfo,
    signal_override: Option<String>,
    initial_target: Option<CleanDeskId>,
) -> anyhow::Result<()> {
    // Una sola instancia por carpeta de datos: si ya hay otra, le pedimos que
    // se muestre (puede estar en la bandeja) y salimos sin abrir ventana.
    use cleandesk_platform::single_instance::{self, Instance};
    let instance_key = single_instance::instance_key(&app_state.data_dir(), "gui");
    let guard = match single_instance::acquire(&instance_key) {
        Ok(Instance::Primary(guard)) => Some(guard),
        Ok(Instance::AlreadyRunning) => {
            tracing::info!("CleanDesk is already running for this data directory; asked it to show its window");
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(error = %e, "single-instance guard unavailable; continuing");
            None
        }
    };
    // Flag que el hilo de espera activa cuando otra instancia pide mostrarnos.
    let show_requested = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Un único runtime multi-hilo para todo el trabajo asíncrono de la sesión.
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
    );

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("CleanDesk")
            .with_icon(std::sync::Arc::new(tray::window_icon()))
            .with_inner_size([960.0, 620.0])
            .with_min_inner_size([720.0, 480.0]),
        ..Default::default()
    };

    // `run_native` toma un creador que construye el `App`. Movemos ahí el estado.
    let result = eframe::run_native(
        "CleanDesk",
        options,
        Box::new(move |cc| {
            if let Some(guard) = guard {
                let ctx = cc.egui_ctx.clone();
                let flag = show_requested.clone();
                let hwnd = crate::tray::native_handle(cc);
                std::thread::Builder::new()
                    .name("cleandesk-single-instance".into())
                    .spawn(move || {
                        while guard.wait_show_request() {
                            tracing::info!(hwnd = ?hwnd, "show request from another launch");
                            // Oculta en la bandeja no hay repintados: la mostramos
                            // por la API nativa y luego egui remata (foco, restaurar).
                            crate::tray::show_native_window(hwnd);
                            flag.store(true, std::sync::atomic::Ordering::Relaxed);
                            ctx.request_repaint();
                        }
                    })
                    .map(|_| ())
                    .unwrap_or_else(|e| tracing::warn!(error = %e, "could not spawn single-instance thread"));
            }
            let mut app = CleanDeskApp::new(cc, app_state, device, rt, signal_override, initial_target);
            app.show_requested = show_requested;
            Ok(Box::new(app))
        }),
    );

    // `eframe::Error` no es `Send + Sync` de forma directa; lo convertimos a un
    // error de `anyhow` por su representación textual.
    result.map_err(|e| anyhow::anyhow!("fallo de eframe: {e}"))
}
