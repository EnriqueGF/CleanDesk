//! rotodesk-platform
//!
//! Everything RotoDesk needs from the operating system beyond capture and
//! input (spec §24 "Servicio en segundo plano"):
//!
//! * [`startup`] — launch RotoDesk when the user logs in (`HKCU\...\Run`).
//! * [`service`] — install / query / remove the **RotoDesk Service**, and run
//!   as that service: a tiny supervisor that keeps a headless host alive in
//!   the interactive console session (so unattended access works before
//!   login and after logout).
//! * [`update`] — self-update from GitHub Releases: check, download with
//!   SHA-256 verification against the published `SHA256SUMS`, and hand the
//!   MSI to `msiexec`.
//! * [`elevation`] / [`desktop`] — privileged control: run elevated when the
//!   service is not available, and follow the input desktop (UAC) from the
//!   capture and input threads.
//! * [`presence`] — a lock file that tells the service's host that the GUI is
//!   running, so exactly one of them holds the device's registration.
//!
//! Only Windows has a real implementation; other platforms get stubs that
//! return [`PlatformError::Unsupported`] so the GUI can grey the options out.

pub mod desktop;
pub mod dpi;
pub mod elevation;
pub mod presence;
pub mod single_instance;
pub mod service;
pub mod startup;
pub mod update;

use thiserror::Error;

/// Errors from OS integration.
#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("not supported on this platform")]
    Unsupported,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{tool} failed (exit {code}): {output}")]
    Tool { tool: &'static str, code: i32, output: String },
    #[error("the user declined the elevation prompt")]
    ElevationDeclined,
    #[error("windows api error: {0}")]
    Win(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, PlatformError>;

/// Crate version string, handy for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Quote one argument for a Windows command line the way `CommandLineToArgvW`
/// expects (double quotes, backslashes before quotes doubled). Pure; tested.
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// Join arguments into one command line (see [`quote_arg`]).
pub fn build_command_line<'a>(args: impl IntoIterator<Item = &'a str>) -> String {
    args.into_iter().map(quote_arg).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_rules() {
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("C:\\Program Files\\cd.exe"), "\"C:\\Program Files\\cd.exe\"");
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_arg("trail\\"), "trail\\"); // no spaces: untouched
        assert_eq!(quote_arg("has space\\"), "\"has space\\\\\"");
        assert_eq!(
            build_command_line(["C:\\x y\\cd.exe", "--service", "--data-dir", "D:\\a b"]),
            "\"C:\\x y\\cd.exe\" --service --data-dir \"D:\\a b\""
        );
    }
}
