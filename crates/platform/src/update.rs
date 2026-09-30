//! Self-update from GitHub Releases (spec §25).
//!
//! Flow: [`check`] asks the GitHub API for the latest release and compares its
//! tag with the running version; [`download`] fetches the MSI into a scratch
//! directory and verifies it against the `SHA256SUMS` asset published with
//! the release (a download whose hash does not match, or a release without
//! sums, is refused); [`install`] hands the MSI to `msiexec` in a detached
//! process that relaunches CleanDesk afterwards, so the caller just has to
//! exit. Everything here is blocking: run it on a worker thread.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::{PlatformError, Result};

/// GitHub repository that publishes the releases.
pub const REPO: &str = "EnriqueGF/CleanDesk";
/// API endpoint for the latest (non pre-release, non draft) release.
pub const LATEST_URL: &str = "https://api.github.com/repos/EnriqueGF/CleanDesk/releases/latest";
/// Name of the checksum asset published next to the MSI.
pub const SUMS_ASSET: &str = "SHA256SUMS";
/// Refuse absurd downloads (the MSI is ~13 MB).
const MAX_MSI_BYTES: u64 = 200 * 1024 * 1024;

/// A downloadable release file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    pub url: String,
    pub size: u64,
}

/// A newer release found on GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: (u16, u16, u16),
    pub tag: String,
    pub notes: String,
    pub html_url: String,
    pub msi: Asset,
    pub sums: Asset,
}

impl Release {
    /// "0.1.5"
    pub fn version_string(&self) -> String {
        let (a, b, c) = self.version;
        format!("{a}.{b}.{c}")
    }
}

/// Name the downloaded installer gets on disk, whatever the release calls it.
pub const LOCAL_MSI_NAME: &str = "CleanDesk-update.msi";

/// Hosts GitHub serves release assets from.
const ASSET_HOSTS: &[&str] = &["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"];

/// Is `url` an HTTPS link to one of GitHub's release-asset hosts?
pub fn is_release_asset_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let host = authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority);
    ASSET_HOSTS.iter().any(|h| host.eq_ignore_ascii_case(h))
}

/// Parse "v0.1.4" / "0.1.4" / "0.1.4-beta" (pre-release suffix ignored) into
/// a comparable triple.
pub fn parse_version(text: &str) -> Option<(u16, u16, u16)> {
    let core = text.trim().trim_start_matches(['v', 'V']);
    let core = core.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u16>().ok());
    let major = parts.next()??;
    let minor = parts.next()??;
    let patch = parts.next().unwrap_or(Some(0))?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Parse a `SHA256SUMS` file ("<hex>  <name>" or "<hex> *<name>" per line)
/// into name → lowercase hex.
pub fn parse_sums(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (hash, name) = line.split_once(char::is_whitespace)?;
            let name = name.trim().trim_start_matches('*').trim();
            let hash = hash.trim();
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) || name.is_empty() {
                return None;
            }
            Some((name.to_string(), hash.to_ascii_lowercase()))
        })
        .collect()
}

/// Turn the GitHub "latest release" JSON into a [`Release`] if it is newer
/// than `current` and ships both the x64 MSI and its checksums.
pub fn release_from_json(json: &serde_json::Value, current: (u16, u16, u16)) -> Result<Option<Release>> {
    if json["draft"].as_bool() == Some(true) || json["prerelease"].as_bool() == Some(true) {
        return Ok(None);
    }
    let tag = json["tag_name"].as_str().unwrap_or_default().to_string();
    let Some(version) = parse_version(&tag) else {
        return Err(PlatformError::Other(format!("unparseable release tag {tag:?}")));
    };
    if version <= current {
        return Ok(None);
    }
    let assets: Vec<Asset> = json["assets"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|a| {
                    Some(Asset {
                        name: a["name"].as_str()?.to_string(),
                        url: a["browser_download_url"].as_str()?.to_string(),
                        size: a["size"].as_u64().unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    // The asset name and URL come from the release JSON; only the exact
    // installer name for this version, served by GitHub, is acceptable
    // (the name also ends up on a command line).
    let (a, b, c) = version;
    let expected_msi = format!("CleanDesk-{a}.{b}.{c}-x64.msi");
    let msi = assets.iter().find(|a| a.name == expected_msi).cloned();
    let sums = assets.iter().find(|a| a.name == SUMS_ASSET).cloned();
    match (msi, sums) {
        (Some(msi), Some(sums)) if !is_release_asset_url(&msi.url) || !is_release_asset_url(&sums.url) => {
            Err(PlatformError::Other(format!("release {tag} serves assets from an unexpected host")))
        }
        (Some(msi), Some(sums)) => Ok(Some(Release {
            version,
            tag,
            notes: json["body"].as_str().unwrap_or_default().to_string(),
            html_url: json["html_url"].as_str().unwrap_or_default().to_string(),
            msi,
            sums,
        })),
        // A newer tag without an installable, verifiable MSI is treated as
        // "nothing to update to": we never install unverified files.
        _ => Ok(None),
    }
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(60))
        .user_agent(&format!("CleanDesk/{} (+https://github.com/{REPO})", env!("CARGO_PKG_VERSION")))
        .build()
}

fn http_err(e: ureq::Error) -> PlatformError {
    match e {
        ureq::Error::Status(code, resp) => {
            PlatformError::Other(format!("HTTP {code} from {}", resp.get_url()))
        }
        ureq::Error::Transport(t) => PlatformError::Other(format!("network error: {t}")),
    }
}

/// Ask GitHub for the latest release; `Ok(None)` means `current` is up to
/// date (or the newest release cannot be installed automatically).
pub fn check(current: &str) -> Result<Option<Release>> {
    let current = parse_version(current)
        .ok_or_else(|| PlatformError::Other(format!("bad current version {current:?}")))?;
    let resp = agent()
        .get(LATEST_URL)
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(http_err)?;
    let json: serde_json::Value = resp
        .into_json()
        .map_err(|e| PlatformError::Other(format!("bad release JSON: {e}")))?;
    release_from_json(&json, current)
}

/// Download `release.msi` into `dir`, verifying it against the release's
/// `SHA256SUMS`. `progress(downloaded, total)` is called as bytes arrive.
/// Returns the path of the verified MSI.
pub fn download(release: &Release, dir: &Path, mut progress: impl FnMut(u64, u64)) -> Result<PathBuf> {
    if release.msi.size > MAX_MSI_BYTES {
        return Err(PlatformError::Other("release asset is unexpectedly large".into()));
    }
    let agent = agent();

    // Checksums first: no point downloading what we cannot verify.
    let sums_text = agent
        .get(&release.sums.url)
        .call()
        .map_err(http_err)?
        .into_string()
        .map_err(|e| PlatformError::Other(format!("reading {}: {e}", SUMS_ASSET)))?;
    let expected = parse_sums(&sums_text)
        .remove(&release.msi.name)
        .ok_or_else(|| PlatformError::Other(format!("{} has no entry for {}", SUMS_ASSET, release.msi.name)))?;

    std::fs::create_dir_all(dir)?;
    // Leftovers from earlier attempts.
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }
    // Fixed local names: nothing from the release JSON becomes a path.
    let final_path = dir.join(LOCAL_MSI_NAME);
    let part_path = dir.join(format!("{LOCAL_MSI_NAME}.part"));

    let resp = agent.get(&release.msi.url).call().map_err(http_err)?;
    let total = resp
        .header("Content-Length")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(release.msi.size);
    let mut reader = resp.into_reader().take(MAX_MSI_BYTES + 1);
    let mut file = std::fs::File::create(&part_path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut done: u64 = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        done += n as u64;
        if done > MAX_MSI_BYTES {
            drop(file);
            let _ = std::fs::remove_file(&part_path);
            return Err(PlatformError::Other("download exceeded the size limit".into()));
        }
        progress(done, total.max(done));
    }
    file.flush()?;
    drop(file);

    let actual = hex(&hasher.finalize());
    if actual != expected {
        let _ = std::fs::remove_file(&part_path);
        return Err(PlatformError::Other(format!(
            "checksum mismatch for {}: expected {expected}, got {actual}",
            release.msi.name
        )));
    }
    std::fs::rename(&part_path, &final_path)?;
    Ok(final_path)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Start the installer in a detached process and return immediately. The
/// caller must exit right after (the MSI replaces the running executable).
/// `relaunch` is started once `msiexec` finishes, so the user gets the new
/// version back without lifting a finger.
pub fn install(msi: &Path, relaunch: Option<&Path>) -> Result<()> {
    imp::install(msi, relaunch)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const DETACHED_PROCESS: u32 = 0x0000_0008;

    pub fn install(msi: &Path, relaunch: Option<&Path>) -> Result<()> {
        if !msi.is_file() {
            return Err(PlatformError::Other(format!("installer not found: {}", msi.display())));
        }
        // `/passive` shows only a progress bar; `/norestart` because a remote
        // desktop tool must never reboot the machine behind the user's back.
        let mut script = format!(
            "start \"\" /wait msiexec.exe /i \"{}\" /passive /norestart",
            msi.display()
        );
        if let Some(exe) = relaunch {
            script.push_str(&format!(" & start \"\" \"{}\"", exe.display()));
        }
        spawn_detached_script(&script)?;
        Ok(())
    }

    /// Run a cmd.exe one-liner detached. `raw_arg` is essential: `arg` would
    /// wrap the script in quotes and escape the inner ones as `\"`, which
    /// cmd does not understand (`start` then tries to run `\` and fails with
    /// "file not found").
    pub(super) fn spawn_detached_script(script: &str) -> Result<()> {
        Command::new("cmd.exe")
            .arg("/d")
            .arg("/c")
            .raw_arg(script)
            .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
            .spawn()?;
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub fn install(_msi: &Path, _relaunch: Option<&Path>) -> Result<()> {
        Err(PlatformError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_and_compare() {
        assert_eq!(parse_version("v0.1.4"), Some((0, 1, 4)));
        assert_eq!(parse_version("1.2.3-beta.1"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.2"), Some((0, 2, 0)));
        assert_eq!(parse_version("nope"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert!(parse_version("v0.1.10").unwrap() > parse_version("v0.1.9").unwrap());
    }

    #[test]
    fn sums_file_parses_both_styles() {
        let text = "# comment\n\
                    0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef *CleanDesk-0.1.5-x64.msi\n\
                    ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789  other.zip\n\
                    garbage line\n\
                    tooshort  x.msi\n";
        let sums = parse_sums(text);
        assert_eq!(sums.len(), 2);
        assert_eq!(sums["CleanDesk-0.1.5-x64.msi"], "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        assert!(sums["other.zip"].starts_with("abcdef"));
    }

    fn fixture(tag: &str, with_sums: bool) -> serde_json::Value {
        let mut assets = vec![serde_json::json!({
            "name": format!("CleanDesk-{}-x64.msi", tag.trim_start_matches('v')),
            "browser_download_url": "https://github.com/EnriqueGF/CleanDesk/releases/download/v0.2.0/CleanDesk-0.2.0-x64.msi",
            "size": 12_000_000
        })];
        if with_sums {
            assets.push(serde_json::json!({
                "name": "SHA256SUMS",
                "browser_download_url": "https://github.com/EnriqueGF/CleanDesk/releases/download/v0.2.0/SHA256SUMS",
                "size": 200
            }));
        }
        serde_json::json!({
            "tag_name": tag,
            "draft": false,
            "prerelease": false,
            "html_url": "https://example.invalid/release",
            "body": "notes",
            "assets": assets
        })
    }

    #[test]
    fn newer_release_with_msi_and_sums_is_offered() {
        let r = release_from_json(&fixture("v0.2.0", true), (0, 1, 4)).unwrap().unwrap();
        assert_eq!(r.version, (0, 2, 0));
        assert_eq!(r.version_string(), "0.2.0");
        assert_eq!(r.msi.name, "CleanDesk-0.2.0-x64.msi");
        assert_eq!(r.sums.name, SUMS_ASSET);
    }

    #[test]
    fn assets_with_the_wrong_name_or_host_are_refused() {
        let mut json = fixture("v0.2.0", true);
        json["assets"][0]["name"] = serde_json::Value::String("CleanDesk-0.2.0-x64.msi\" & calc & \"".into());
        assert!(release_from_json(&json, (0, 1, 4)).unwrap().is_none(), "no exact installer name: nothing offered");
        let mut json = fixture("v0.2.0", true);
        json["assets"][0]["browser_download_url"] = serde_json::Value::String("https://evil.example/CleanDesk-0.2.0-x64.msi".into());
        assert!(release_from_json(&json, (0, 1, 4)).is_err());
        assert!(is_release_asset_url("https://objects.githubusercontent.com/x/y"));
        assert!(!is_release_asset_url("http://github.com/x"));
        assert!(!is_release_asset_url("https://github.com.evil.example/x"));
        assert!(!is_release_asset_url("https://user@github.com/x"));
    }

    #[test]
    fn same_or_older_release_is_not_offered() {
        assert!(release_from_json(&fixture("v0.1.4", true), (0, 1, 4)).unwrap().is_none());
        assert!(release_from_json(&fixture("v0.1.3", true), (0, 1, 4)).unwrap().is_none());
    }

    #[test]
    fn release_without_checksums_is_never_installed() {
        assert!(release_from_json(&fixture("v9.9.9", false), (0, 1, 4)).unwrap().is_none());
        let mut pre = fixture("v9.9.9", true);
        pre["prerelease"] = serde_json::Value::Bool(true);
        assert!(release_from_json(&pre, (0, 1, 4)).unwrap().is_none());
    }

    #[test]
    fn bad_tag_is_an_error_not_a_panic() {
        let mut j = fixture("v1.0.0", true);
        j["tag_name"] = serde_json::Value::String("latest".into());
        assert!(release_from_json(&j, (0, 1, 4)).is_err());
    }

    /// The detached cmd script must survive cmd's quoting rules: run one that
    /// waits on a child (like msiexec) and then "relaunches" (like CleanDesk),
    /// using paths with spaces, and check both steps happened.
    #[cfg(windows)]
    #[test]
    fn detached_script_waits_then_relaunches() {
        let dir = std::env::temp_dir().join("cleandesk update test dir");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let first = dir.join("first step.txt");
        let second = dir.join("second step.txt");
        let script = format!(
            "start \"\" /wait cmd.exe /c \"echo 1> \"{}\"\" & start \"\" cmd.exe /c \"echo 2> \"{}\"\"",
            first.display(),
            second.display()
        );
        super::imp::spawn_detached_script(&script).expect("spawn");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline && !(first.is_file() && second.is_file()) {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(first.is_file(), "first (waited) step did not run");
        assert!(second.is_file(), "relaunch step did not run");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Talks to GitHub for real: `cargo test -p cleandesk-platform -- --ignored`.
    #[test]
    #[ignore]
    fn live_check_against_github() {
        let newer = check("0.0.1").expect("GitHub reachable");
        let r = newer.expect("there is at least one published release with an MSI + SHA256SUMS");
        assert!(r.msi.size > 1_000_000);
        let dir = std::env::temp_dir().join("cleandesk-update-test");
        let path = download(&r, &dir, |_, _| {}).expect("download + checksum");
        assert!(path.is_file());
        let _ = std::fs::remove_dir_all(dir);
    }
}
