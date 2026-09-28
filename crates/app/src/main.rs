//! CleanDesk desktop application entry point.
//!
//! Modes:
//! * (default)        — launch the GUI (also registers as a host in the
//!   background, so the device is reachable while the window is open).
//! * `--connect <ID>` — launch the GUI and immediately open a viewer session to
//!   that CleanDesk ID.
//! * `--host`         — run headless as an *unattended* host (no GUI). Only
//!   requests that authenticate with the configured unattended password are
//!   accepted; everything else is refused. This is also what the Windows
//!   service launches inside the console session.
//! * `--service`      — run as the CleanDesk Windows service (started by the
//!   Service Control Manager, never by hand).
//! * `--install-service` / `--uninstall-service` — manage the service; need
//!   administrator rights (the GUI launches these through the UAC prompt).
//!
//! Options (each also has an environment variable, the flag wins):
//! * `--signal-url <ws://…>` / `CLEANDESK_SIGNAL_URL` — CleanDesk Server URL
//!   (default `ws://127.0.0.1:7420`).
//! * `--data-dir <path>` / `CLEANDESK_DATA_DIR` — where identity, settings and
//!   history live; lets several independent instances (each with its own
//!   CleanDesk ID) run on one machine, or a portable install.
//! * `--log-file <path>` / `CLEANDESK_LOG_FILE` — append logs to a file
//!   (the service and its helper use `service.log` / `host.log` in the data
//!   directory automatically, since they have no console).
//! * `CLEANDESK_STUN_URLS`, `CLEANDESK_TURN_URLS`, `CLEANDESK_TURN_USER`,
//!   `CLEANDESK_TURN_PASS` — ICE servers (see `cleandesk-transport`).

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use cleandesk_core::AppState;
use cleandesk_host::{Approver, Decision, HostConfig, HostError};
use cleandesk_platform::{presence, service};
use cleandesk_proto::{
    id::CleanDeskId,
    message::{AuthKind, RejectReason},
    permissions::Permissions,
    session::DeviceInfo,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;


#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Gui,
    Connect(CleanDeskId),
    Host,
    Service,
    InstallService,
    UninstallService,
}

/// Parsed command line.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    mode: Mode,
    /// `--signal-url` / `CLEANDESK_SIGNAL_URL`: forces private-server mode.
    /// `None` means "whatever the settings say" (community by default).
    signal_url: Option<String>,
    data_dir: Option<PathBuf>,
    log_file: Option<PathBuf>,
    help: bool,
}

/// Parse `args` (without the program name) against `env` (an injectable
/// lookup so the parser is unit-testable without touching the real
/// environment).
fn parse_args(args: impl IntoIterator<Item = String>, env: impl Fn(&str) -> Option<String>) -> Result<Options> {
    let mut opts = Options {
        mode: Mode::Gui,
        signal_url: env("CLEANDESK_SIGNAL_URL"),
        data_dir: env("CLEANDESK_DATA_DIR").map(PathBuf::from),
        log_file: env("CLEANDESK_LOG_FILE").map(PathBuf::from),
        help: false,
    };
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--host" => opts.mode = Mode::Host,
            "--service" => opts.mode = Mode::Service,
            "--install-service" => opts.mode = Mode::InstallService,
            "--uninstall-service" => opts.mode = Mode::UninstallService,
            "--connect" => {
                let raw = args.next().context("--connect requires a CleanDesk ID")?;
                let id = CleanDeskId::parse(&raw).context("invalid CleanDesk ID")?;
                opts.mode = Mode::Connect(id);
            }
            "--signal-url" => {
                opts.signal_url = Some(args.next().context("--signal-url requires a URL")?);
            }
            "--data-dir" => {
                opts.data_dir = Some(PathBuf::from(args.next().context("--data-dir requires a path")?));
            }
            "--log-file" => {
                opts.log_file = Some(PathBuf::from(args.next().context("--log-file requires a path")?));
            }
            "--help" | "-h" => opts.help = true,
            other => bail!("unknown argument: {other} (see --help)"),
        }
    }
    if let Some(url) = &opts.signal_url {
        if !(url.starts_with("ws://") || url.starts_with("wss://")) {
            bail!("the server URL must start with ws:// or wss:// (got: {url})");
        }
    }
    Ok(opts)
}

fn print_help() {
    println!(
        "CleanDesk {}\n\nUsage:\n  cleandesk                       Open the graphical interface\n  cleandesk --connect <ID>        Open the GUI and connect to a CleanDesk ID\n  cleandesk --host                Run as an unattended host (no GUI)\n  cleandesk --install-service     Install and start the Windows service (admin)\n  cleandesk --uninstall-service   Stop and remove the service (admin)\n\nOptions:\n  --signal-url <ws://host:port>   Use a private CleanDesk Server (or CLEANDESK_SIGNAL_URL);\n                                  without it the settings decide (community mode by default)\n  --data-dir <path>               Identity/settings folder (or CLEANDESK_DATA_DIR)\n  --log-file <path>               Append logs to a file (or CLEANDESK_LOG_FILE)\n\nNetwork environment variables:\n  CLEANDESK_STUN_URLS, CLEANDESK_TURN_URLS, CLEANDESK_TURN_USER, CLEANDESK_TURN_PASS, CLEANDESK_NOSTR_RELAYS",
        env!("CARGO_PKG_VERSION")
    );
}

/// Human-readable OS string for `DeviceInfo::os`.
fn os_string() -> String {
    let family = if cfg!(windows) {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else {
        "Linux"
    };
    format!("{family} ({})", std::env::consts::ARCH)
}

/// Build this device's descriptor from persistent state + the OS.
fn device_info(app: &AppState) -> DeviceInfo {
    let alias = app.settings.read().alias.clone();
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "cleandesk".to_string());
    DeviceInfo {
        id: app.identity.derive_id(),
        alias,
        hostname,
        os: os_string(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// Install the tracing subscriber: stderr by default, a file when asked.
fn init_logging(log_file: Option<&PathBuf>) -> Result<()> {
    // `mainline` logs every ICMP port-unreachable on its UDP socket as a
    // warning (Windows surfaces them as WSAECONNRESET), which floods the log.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,mainline=error".into());
    match log_file {
        Some(path) => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("opening log file {}", path.display()))?;
            tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_writer(file).init();
        }
        None => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }
    Ok(())
}

fn load_state(data_dir: &Option<PathBuf>) -> Result<Arc<AppState>> {
    Ok(Arc::new(match data_dir {
        Some(dir) => AppState::load_from_dir(dir.clone())
            .with_context(|| format!("loading CleanDesk state from {}", dir.display()))?,
        None => AppState::load().context("loading CleanDesk state")?,
    }))
}

fn main() -> Result<()> {
    let opts = parse_args(std::env::args().skip(1), |k| std::env::var(k).ok())?;
    if opts.help {
        print_help();
        return Ok(());
    }

    // Service-side modes have no console: log into the data directory.
    let data_dir_for_logs = match &opts.data_dir {
        Some(d) => Some(d.clone()),
        None => cleandesk_core::storage::Storage::locate().ok().map(|s| s.base_dir().to_path_buf()),
    };
    let default_log = |name: &str| data_dir_for_logs.as_ref().map(|d| d.join(name));
    let log_file = opts.log_file.clone().or_else(|| match opts.mode {
        Mode::Service => default_log("service.log"),
        Mode::InstallService | Mode::UninstallService => default_log("service-install.log"),
        Mode::Host if std::env::var_os("CLEANDESK_HELPER").is_some() => default_log("host.log"),
        _ => None,
    });
    init_logging(log_file.as_ref())?;

    // Service management needs no app state, only paths.
    let exe = std::env::current_exe().context("resolving own executable path")?;
    match opts.mode {
        Mode::InstallService => {
            let data_dir = data_dir_for_logs.clone().context("no data directory for the service")?;
            tracing::info!(exe = %exe.display(), data_dir = %data_dir.display(), "installing service");
            return service::install_here(&exe, &data_dir)
                .map_err(|e| {
                    tracing::error!(error = %e, "service install failed");
                    anyhow::anyhow!(e)
                })
                .map(|()| tracing::info!("service installed and started"));
        }
        Mode::UninstallService => {
            tracing::info!("uninstalling service");
            return service::uninstall_here()
                .map_err(|e| {
                    tracing::error!(error = %e, "service uninstall failed");
                    anyhow::anyhow!(e)
                })
                .map(|()| tracing::info!("service removed"));
        }
        Mode::Service => {
            let data_dir = data_dir_for_logs.clone().context("no data directory for the service")?;
            return service::run_service(exe, data_dir).map_err(|e| anyhow::anyhow!(e));
        }
        _ => {}
    }

    let app = load_state(&opts.data_dir)?;
    let device = device_info(&app);
    tracing::info!(id = %device.id, mode = ?opts.mode, signal = ?opts.signal_url, version = env!("CARGO_PKG_VERSION"), "CleanDesk starting");

    match opts.mode {
        Mode::Gui => cleandesk_gui::run(app, device, opts.signal_url, None),
        Mode::Connect(target) => cleandesk_gui::run(app, device, opts.signal_url, Some(target)),
        Mode::Host => run_headless_host(app, device, opts.signal_url),
        Mode::Service | Mode::InstallService | Mode::UninstallService => unreachable!("handled above"),
    }
}

/// How often the headless host re-checks for a running GUI / changed settings.
const HEADLESS_POLL: Duration = Duration::from_secs(3);

/// Headless unattended host: a blocking tokio runtime driving `host::serve`,
/// reconnecting whenever the link drops, standing aside while the GUI runs,
/// and picking up settings changes (new unattended password) from disk.
fn run_headless_host(app: Arc<AppState>, device: DeviceInfo, signal_override: Option<String>) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    let data_dir = app.data_dir();
    rt.block_on(async move {
        let approver: Arc<dyn Approver> = Arc::new(HeadlessApprover);
        let mut warned_gui = false;
        let mut warned_config = false;
        loop {
            // The GUI is the better host while it is open (it can show approval
            // dialogs); only take over once it is gone.
            if presence::gui_is_running(&data_dir) {
                if !warned_gui {
                    tracing::info!("GUI is running; headless host standing by");
                    warned_gui = true;
                }
                tokio::select! {
                    _ = tokio::time::sleep(HEADLESS_POLL) => continue,
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                }
            }
            warned_gui = false;

            if let Err(e) = app.reload() {
                tracing::warn!(error = %e, "could not reload settings; using the previous ones");
            }
            let unattended_key = app.settings.read().unattended_key();
            let Some(unattended_key) = unattended_key else {
                if !warned_config {
                    tracing::warn!(
                        "unattended access not configured: set a password in the GUI (Settings → Unattended access); waiting…"
                    );
                    warned_config = true;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(10)) => continue,
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                }
            };
            warned_config = false;

            let mode = match &signal_override {
                Some(url) => cleandesk_core::config::NetworkMode::Server { url: url.clone() },
                None => app.settings.read().network.clone(),
            };
            let mut config = HostConfig::new(
                mode.server_url().unwrap_or_default().to_string(),
                device.clone(),
                app.identity.clone(),
            );
            config.unattended_key = Some(unattended_key);
            config.quality = app.settings.read().quality;
            let stamp = app.app_data_modified();

            // Serve until: the link drops, we are replaced, the GUI appears,
            // the settings file changes, or Ctrl-C.
            let watcher = async {
                loop {
                    tokio::time::sleep(HEADLESS_POLL).await;
                    if presence::gui_is_running(&data_dir) {
                        return "GUI started";
                    }
                    if app.app_data_modified() != stamp {
                        return "settings changed";
                    }
                }
            };
            let outcome = tokio::select! {
                r = async {
                    if mode.is_community() {
                        cleandesk_host::serve_community(config, approver.clone()).await
                    } else {
                        cleandesk_host::serve(config, approver.clone()).await
                    }
                } => match r {
                    Ok(()) => "signaling connection closed",
                    Err(e) if e.downcast_ref::<HostError>().is_some() => {
                        tracing::info!("registration taken over by another instance; standing by");
                        "replaced"
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "host failed");
                        "error"
                    }
                },
                why = watcher => why,
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Ctrl-C: stopping headless host");
                    return Ok(());
                }
            };
            tracing::info!(reason = outcome, "headless host cycling");
            tokio::time::sleep(if outcome == "error" { Duration::from_secs(5) } else { Duration::from_secs(1) }).await;
        }
    })
}

/// Approver for headless mode: accept ONLY unattended-authenticated requests
/// (the host then verifies the password via challenge/response). Everything else
/// is refused, because there is no human present to approve interactive access.
struct HeadlessApprover;

#[async_trait]
impl Approver for HeadlessApprover {
    async fn on_request(&self, from: &DeviceInfo, requested: Permissions, auth: AuthKind) -> Decision {
        match auth {
            AuthKind::UnattendedPassword => {
                tracing::info!(from = %from.id, "accepting unattended request (pending auth)");
                Decision::Accept(requested)
            }
            _ => {
                tracing::warn!(from = %from.id, "refusing non-unattended request in headless mode");
                Decision::Reject(RejectReason::UserDeclined)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn defaults_to_gui_and_default_url() {
        let o = parse_args(args(&[]), no_env).unwrap();
        assert_eq!(o.mode, Mode::Gui);
        assert_eq!(o.signal_url, None);
        assert_eq!(o.data_dir, None);
        assert_eq!(o.log_file, None);
        assert!(!o.help);
    }

    #[test]
    fn flags_override_env() {
        let env = |k: &str| match k {
            "CLEANDESK_SIGNAL_URL" => Some("ws://env:1".to_string()),
            "CLEANDESK_DATA_DIR" => Some("C:/env".to_string()),
            _ => None,
        };
        let o = parse_args(args(&[]), env).unwrap();
        assert_eq!(o.signal_url.as_deref(), Some("ws://env:1"));
        assert_eq!(o.data_dir, Some(PathBuf::from("C:/env")));
        let o = parse_args(args(&["--signal-url", "wss://flag:2", "--data-dir", "D:/x", "--host"]), env).unwrap();
        assert_eq!(o.signal_url.as_deref(), Some("wss://flag:2"));
        assert_eq!(o.data_dir, Some(PathBuf::from("D:/x")));
        assert_eq!(o.mode, Mode::Host);
    }

    #[test]
    fn service_modes_and_log_file() {
        assert_eq!(parse_args(args(&["--service"]), no_env).unwrap().mode, Mode::Service);
        assert_eq!(parse_args(args(&["--install-service"]), no_env).unwrap().mode, Mode::InstallService);
        assert_eq!(parse_args(args(&["--uninstall-service"]), no_env).unwrap().mode, Mode::UninstallService);
        let o = parse_args(args(&["--log-file", "C:/l.log"]), no_env).unwrap();
        assert_eq!(o.log_file, Some(PathBuf::from("C:/l.log")));
    }

    #[test]
    fn connect_parses_grouped_ids_and_rejects_bad_ones() {
        let o = parse_args(args(&["--connect", "548 291 743"]), no_env).unwrap();
        assert_eq!(o.mode, Mode::Connect(CleanDeskId::new(548_291_743).unwrap()));
        assert!(parse_args(args(&["--connect", "12"]), no_env).is_err());
        assert!(parse_args(args(&["--connect"]), no_env).is_err());
    }

    #[test]
    fn unknown_args_and_bad_urls_are_errors() {
        assert!(parse_args(args(&["--bogus"]), no_env).is_err());
        assert!(parse_args(args(&["--signal-url", "http://x"]), no_env).is_err());
        assert!(parse_args(args(&["-h"]), no_env).unwrap().help);
    }
}
