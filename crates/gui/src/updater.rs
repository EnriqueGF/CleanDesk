//! Estado del actualizador automático en la GUI (spec §25). La lógica de red
//! y verificación vive en `rotodesk_platform::update`; aquí solo se lanza en
//! hilos aparte y se refleja el progreso para el banner y los Ajustes.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rotodesk_platform::update::{self, Release};
use tracing::{info, warn};

/// Cada cuánto se vuelve a consultar GitHub con la app abierta.
const CHECK_EVERY: Duration = Duration::from_secs(60 * 60);

/// Fase actual del actualizador.
#[derive(Debug, Clone)]
pub enum Phase {
    Idle,
    Checking,
    UpToDate,
    Available(Release),
    Downloading { release: Release, done: u64, total: u64 },
    Ready { release: Release, path: PathBuf },
    Installing,
    Error(String),
}

pub struct Updater {
    phase: Arc<Mutex<Phase>>,
    last_check: Option<Instant>,
    /// Versión que el usuario descartó con "Más tarde" (no se vuelve a
    /// mostrar el banner hasta que salga otra).
    dismissed: Option<String>,
}

impl Default for Updater {
    fn default() -> Self {
        Self { phase: Arc::new(Mutex::new(Phase::Idle)), last_check: None, dismissed: None }
    }
}

/// Versión en ejecución. `ROTODESK_FAKE_VERSION` permite probar el flujo
/// contra una release real sin publicar una nueva.
pub fn current_version() -> String {
    rotodesk_proto::compat::env("ROTODESK_FAKE_VERSION").unwrap_or_else(|_| crate::VERSION.to_string())
}

impl Updater {
    pub fn phase(&self) -> Phase {
        self.phase.lock().map(|p| p.clone()).unwrap_or(Phase::Idle)
    }

    fn set(phase: &Arc<Mutex<Phase>>, value: Phase) {
        if let Ok(mut p) = phase.lock() {
            *p = value;
        }
    }

    /// ¿Hay que mostrar el banner de la página principal?
    pub fn banner_visible(&self) -> bool {
        match self.phase() {
            Phase::Available(r) => self.dismissed.as_deref() != Some(&r.version_string()),
            Phase::Downloading { .. } | Phase::Ready { .. } | Phase::Installing => true,
            Phase::Error(_) => false,
            _ => false,
        }
    }

    pub fn dismiss(&mut self) {
        if let Phase::Available(r) = self.phase() {
            self.dismissed = Some(r.version_string());
        }
    }

    /// Consulta al arrancar y cada [`CHECK_EVERY`] si el usuario lo permite.
    pub fn maybe_check(&mut self, enabled: bool, ctx: &egui::Context) {
        if !enabled {
            return;
        }
        let due = self.last_check.is_none_or(|t| t.elapsed() > CHECK_EVERY);
        if due && matches!(self.phase(), Phase::Idle | Phase::UpToDate | Phase::Error(_)) {
            self.check(ctx);
        }
    }

    /// Consulta GitHub en un hilo aparte.
    pub fn check(&mut self, ctx: &egui::Context) {
        if matches!(self.phase(), Phase::Checking | Phase::Downloading { .. } | Phase::Installing) {
            return;
        }
        self.last_check = Some(Instant::now());
        Self::set(&self.phase, Phase::Checking);
        let phase = self.phase.clone();
        let ctx = ctx.clone();
        let current = current_version();
        spawn("rotodesk-update-check", move || {
            let result = update::check(&current);
            let next = match result {
                Ok(Some(release)) => {
                    info!(version = %release.version_string(), "update available");
                    Phase::Available(release)
                }
                Ok(None) => Phase::UpToDate,
                Err(e) => {
                    warn!(error = %e, "update check failed");
                    Phase::Error(e.to_string())
                }
            };
            Self::set(&phase, next);
            ctx.request_repaint();
        });
    }

    /// Descarga y verifica el MSI de la release disponible.
    pub fn download(&mut self, dir: PathBuf, ctx: &egui::Context) {
        let Phase::Available(release) = self.phase() else { return };
        Self::set(&self.phase, Phase::Downloading { release: release.clone(), done: 0, total: release.msi.size });
        let phase = self.phase.clone();
        let ctx = ctx.clone();
        spawn("rotodesk-update-download", move || {
            let r = release.clone();
            let p = phase.clone();
            let c = ctx.clone();
            let mut last_report = Instant::now();
            let result = update::download(&release, &dir, move |done, total| {
                // Un repintado cada ~100 ms basta para la barra.
                if last_report.elapsed() > Duration::from_millis(100) || done == total {
                    last_report = Instant::now();
                    Self::set(&p, Phase::Downloading { release: r.clone(), done, total });
                    c.request_repaint();
                }
            });
            let next = match result {
                Ok(path) => {
                    info!(path = %path.display(), "update downloaded and verified");
                    Phase::Ready { release, path }
                }
                Err(e) => {
                    warn!(error = %e, "update download failed");
                    Phase::Error(e.to_string())
                }
            };
            Self::set(&phase, next);
            ctx.request_repaint();
        });
    }

    /// Lanza el instalador. Si devuelve `Ok`, la app debe salir de inmediato.
    pub fn install(&mut self) -> Result<(), String> {
        let Phase::Ready { path, .. } = self.phase() else {
            return Err("no update ready".into());
        };
        let relaunch = std::env::current_exe().ok();
        update::install(&path, relaunch.as_deref()).map_err(|e| e.to_string())?;
        Self::set(&self.phase, Phase::Installing);
        Ok(())
    }
}

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) {
    if let Err(e) = std::thread::Builder::new().name(name.into()).spawn(f) {
        warn!(error = %e, thread = name, "could not spawn updater thread");
    }
}
