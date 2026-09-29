//! "Iniciar con Windows" (spec §24): a per-user `Run` registry value.
//!
//! Implemented with `reg.exe` rather than a registry crate: it is present on
//! every Windows install, needs no elevation for `HKCU`, and keeps this crate's
//! unsafe surface limited to the service module.

/// Registry value name under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
pub const RUN_VALUE: &str = "CleanDesk";

#[cfg(windows)]
mod imp {
    use super::RUN_VALUE;
    use crate::{build_command_line, PlatformError, Result};
    use std::path::Path;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

    fn run(args: &[&str]) -> Result<String> {
        // CREATE_NO_WINDOW: sin ventana de consola parpadeando sobre la GUI.
        let out = Command::new("reg.exe").args(args).creation_flags(0x0800_0000).output()?;
        let text = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        if out.status.success() {
            Ok(text)
        } else {
            Err(PlatformError::Tool { tool: "reg.exe", code: out.status.code().unwrap_or(-1), output: text })
        }
    }

    /// Register `exe` (plus `extra_args`) to start at login, or remove the entry.
    pub fn set_run_at_login(enabled: bool, exe: &Path, extra_args: &[&str]) -> Result<()> {
        if enabled {
            let exe = exe.to_string_lossy();
            let mut parts = vec![exe.as_ref()];
            parts.extend_from_slice(extra_args);
            let cmd = build_command_line(parts);
            run(&["add", RUN_KEY, "/v", RUN_VALUE, "/t", "REG_SZ", "/d", &cmd, "/f"])?;
        } else {
            // Deleting a missing value is not an error for us.
            match run(&["delete", RUN_KEY, "/v", RUN_VALUE, "/f"]) {
                Ok(_) => {}
                Err(PlatformError::Tool { output, .. }) if output.contains("unable to find") || output.contains("no se") => {}
                Err(PlatformError::Tool { code: 1, .. }) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Whether the run-at-login entry exists.
    pub fn is_run_at_login() -> Result<bool> {
        match run(&["query", RUN_KEY, "/v", RUN_VALUE]) {
            Ok(text) => Ok(text.contains(RUN_VALUE)),
            Err(PlatformError::Tool { code: 1, .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use crate::{PlatformError, Result};
    use std::path::Path;

    pub fn set_run_at_login(_enabled: bool, _exe: &Path, _extra_args: &[&str]) -> Result<()> {
        Err(PlatformError::Unsupported)
    }

    pub fn is_run_at_login() -> Result<bool> {
        Err(PlatformError::Unsupported)
    }
}

pub use imp::{is_run_at_login, set_run_at_login};
