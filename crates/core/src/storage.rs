//! On-disk persistence: locating the app-data directory, the device identity
//! file, and the JSON blob holding everything else (settings, address book,
//! history, trust registry).
//!
//! ## Storage layout
//! ```text
//! <data_dir>/
//!   identity.pem   – PKCS#8 PEM, the device's Ed25519 signing key
//!   appdata.json   – Settings + AddressBook + History + TrustRegistry
//! ```
//!
//! `<data_dir>` is resolved via [`directories::ProjectDirs`]
//! (`ProjectDirs::from("roto", "RotoDesk", "RotoDesk").data_dir()`), i.e.
//! the OS-standard per-user application data location — never a path inside
//! this repository. [`Storage::at`] lets callers (tests, or a future portable
//! install mode) root the same logic at an arbitrary directory instead.
//!
//! ## Durability
//! Both files are written atomically through [`write_restricted`]: the bytes
//! go to a sibling temp file, are flushed to disk, and only then is the temp
//! file renamed over the destination. A crash or power loss mid-write leaves
//! either the previous complete file or the new complete file — never a
//! truncated `identity.pem` (which would change the device's RotoDesk ID on
//! the next start) or a half-written `appdata.json`.
//!
//! Should `appdata.json` nevertheless turn out unparseable (disk corruption,
//! a hand edit gone wrong, a downgrade), [`Storage::load_app_data_or_recover`]
//! moves it aside as `appdata.json.corrupt-<unix_ts>` and carries on with
//! defaults, so a single bad byte never bricks the app. The identity file is
//! deliberately **not** given that treatment: silently regenerating a key
//! would change this device's ID, and that is the user's call, not ours.
//!
//! ## Secrets at rest
//! `identity.pem` holds the device's private key; `appdata.json` embeds the
//! Argon2id unattended-password hash and trusted-device session tokens (never
//! a plaintext password — see `rotodesk_crypto::password`). Both files are
//! written through [`write_restricted`]:
//! * **Unix**: mode is set to `0600` (owner read/write only) on the temp
//!   file before it is renamed into place, so the final path is never
//!   observable with looser permissions.
//! * **Windows**: `%APPDATA%` is already ACL'd to the current user by the OS,
//!   and `std::fs` has no portable "owner-only" ACL API, so no extra step is
//!   taken here. The documented future hardening (tracked in
//!   `docs/SECURITY.md`) is to encrypt `identity.pem`'s bytes with **DPAPI**
//!   (`CryptProtectData`, user scope) before they touch disk, so the key is
//!   unreadable even to another process running as the same Windows user.
//!
//! Nothing in this module ever writes into the source tree, and callers must
//! not point [`Storage::at`] at one either — see `.gitignore`'s `/data`,
//! `*.identity`, `*.token` entries for the local-runtime-state paths this
//! historically covers.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use rotodesk_crypto::identity::Identity;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::{
    addressbook::AddressBook, config::Settings, error::CoreError, history::History,
    trust::TrustRegistry, unix_now, Result,
};

/// Everything persisted as one JSON document alongside the identity file.
///
/// `#[serde(default)]` so a blob written by an older build (missing sections
/// added since) still loads; missing parts simply take their defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppData {
    pub settings: Settings,
    pub addressbook: AddressBook,
    pub history: History,
    pub trust: TrustRegistry,
}

/// Outcome of [`Storage::load_app_data_or_recover`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    /// No `appdata.json` on disk yet (fresh install).
    Fresh,
    /// `appdata.json` existed but could not be parsed. It was moved to
    /// `backup` (never deleted) and the caller should proceed with
    /// [`AppData::default()`].
    Recovered {
        backup: PathBuf,
        /// Human-readable parse failure, for logging/diagnostics.
        error: String,
    },
    /// Parsed successfully.
    Data(AppData),
}

impl Loaded {
    /// Collapse into usable data: `Fresh` and `Recovered` both yield
    /// defaults. Callers that need to know *why* inspect the variant first.
    pub fn into_data(self) -> AppData {
        match self {
            Loaded::Data(data) => data,
            Loaded::Fresh | Loaded::Recovered { .. } => AppData::default(),
        }
    }
}

/// Filesystem-backed persistence, rooted at a single base directory.
///
/// Production code obtains one from [`Storage::locate`]. Tests use
/// [`Storage::at`] with a temp directory so they never touch the real user
/// profile.
#[derive(Debug, Clone)]
pub struct Storage {
    base_dir: PathBuf,
}

impl Storage {
    /// Resolve the real per-user RotoDesk data directory.
    pub fn locate() -> Result<Self> {
        let dirs =
            ProjectDirs::from("roto", "RotoDesk", "RotoDesk").ok_or(CoreError::NoDataDir)?;
        if let Some(legacy) = ProjectDirs::from("clean", rotodesk_proto::compat::LEGACY_PRODUCT, rotodesk_proto::compat::LEGACY_PRODUCT) {
            Self::migrate_legacy(legacy.data_dir(), dirs.data_dir())?;
        }
        Ok(Self::at(dirs.data_dir().to_path_buf()))
    }

    /// Copy a previous installation's data into the new product directory.
    /// Keep the original as a backup; never replace an existing identity.
    pub fn migrate_legacy(source: &Path, destination: &Path) -> Result<()> {
        if destination.join("identity.pem").exists() || !source.join("identity.pem").exists() || source == destination {
            return Ok(());
        }
        // Fail on a corrupt identity before creating anything. Regenerating it
        // would silently change this device's ID and break trusted access.
        let source_identity = crate::dpapi::unprotect(&fs::read(source.join("identity.pem"))?)?;
        Identity::from_pem(std::str::from_utf8(&source_identity).map_err(|e| CoreError::Other(e.to_string()))?)?;
        if destination.exists() {
            return Err(CoreError::Other("the new data directory exists without an identity; migration refused to overwrite it".into()));
        }
        let parent = destination.parent().ok_or(CoreError::NoDataDir)?;
        fs::create_dir_all(parent)?;
        let stage = parent.join(format!(".rotodesk-migration-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&stage)?;
        let copy = (|| -> Result<()> {
            for name in ["identity.pem", "appdata.json"] {
                let file = source.join(name);
                if file.exists() { write_restricted(&stage.join(name), &fs::read(file)?)?; }
            }
            let thumbs = source.join("thumbs");
            if thumbs.is_dir() && !fs::symlink_metadata(&thumbs)?.file_type().is_symlink() {
                fs::create_dir(stage.join("thumbs"))?;
                for entry in fs::read_dir(thumbs)? {
                    let entry = entry?;
                    if entry.file_type()?.is_file() && entry.path().extension().is_some_and(|e| e == "png") {
                        write_restricted(&stage.join("thumbs").join(entry.file_name()), &fs::read(entry.path())?)?;
                    }
                }
            }
            fs::rename(&stage, destination)?;
            Ok(())
        })();
        if copy.is_err() { let _ = fs::remove_dir_all(&stage); }
        copy
    }

    /// For a service using the standard Windows profile, migrate to the
    /// sibling RotoDesk location. Explicit custom data paths stay as configured.
    pub fn rebranded_service_dir(source: &Path) -> PathBuf {
        let old = rotodesk_proto::compat::LEGACY_PRODUCT;
        let suffix = PathBuf::from(old).join(old).join("data");
        if source.ends_with(&suffix) {
            if let Some(root) = source.parent().and_then(Path::parent).and_then(Path::parent) {
                return root.join("RotoDesk").join("RotoDesk").join("data");
            }
        }
        source.to_path_buf()
    }

    /// Root storage at an arbitrary directory. Intended for tests (and a
    /// possible future portable/USB install mode) — never point this at a
    /// path inside the source repository.
    pub fn at(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// The directory this `Storage` reads/writes.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn identity_path(&self) -> PathBuf {
        self.base_dir.join("identity.pem")
    }

    pub fn app_data_path(&self) -> PathBuf {
        self.base_dir.join("appdata.json")
    }

    fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.base_dir)?;
        Ok(())
    }

    /// Load the device identity, or generate and persist a fresh one if this
    /// is the first run (no `identity.pem` yet). An existing but unreadable
    /// or corrupt identity file is a hard error — see the module docs for
    /// why it is never silently replaced.
    pub fn load_or_create_identity(&self) -> Result<Identity> {
        let path = self.identity_path();
        if path.exists() {
            let stored = fs::read(&path)?;
            let plain = crate::dpapi::unprotect(&stored)?;
            let pem = String::from_utf8(plain).map_err(|e| CoreError::Other(format!("identity.pem: {e}")))?;
            let identity = Identity::from_pem(&pem)?;
            // A file from before at-rest protection existed: rewrite it
            // protected, but never at the cost of the identity itself.
            if !crate::dpapi::is_protected(&stored) {
                if let Err(e) = self.save_identity(&identity) {
                    tracing::warn!(error = %e, "could not rewrite identity.pem protected");
                }
            }
            Ok(identity)
        } else {
            let identity = Identity::generate();
            self.save_identity(&identity)?;
            Ok(identity)
        }
    }

    /// Overwrite the persisted identity. Normal operation never needs this
    /// after first run — it is exposed for tests and tooling.
    pub fn save_identity(&self, identity: &Identity) -> Result<()> {
        self.ensure_dir()?;
        let pem = identity.to_pem()?;
        write_restricted(&self.identity_path(), &crate::dpapi::protect(pem.as_bytes())?)
    }

    /// Load the JSON app-data blob, or `None` if it hasn't been created yet
    /// (fresh install). A file that exists but does not parse is returned
    /// as an error and left untouched; the app itself goes through
    /// [`Self::load_app_data_or_recover`], which handles that case.
    pub fn load_app_data(&self) -> Result<Option<AppData>> {
        let path = self.app_data_path();
        if !path.exists() {
            return Ok(None);
        }
        let bytes = crate::dpapi::unprotect(&fs::read(&path)?)?;
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    /// Like [`Self::load_app_data`], but a corrupt `appdata.json` is moved
    /// aside (to `appdata.json.corrupt-<unix_ts>`, never deleted) instead of
    /// failing, and [`Loaded::Recovered`] reports where it went. Only a
    /// genuine I/O failure — unreadable file, or the move-aside itself
    /// failing — is still an error: continuing with defaults in that case
    /// would risk the next [`Self::save_app_data`] overwriting data we could
    /// not preserve.
    pub fn load_app_data_or_recover(&self) -> Result<Loaded> {
        let path = self.app_data_path();
        if !path.exists() {
            return Ok(Loaded::Fresh);
        }
        // Raw bytes, not `read_to_string`: invalid UTF-8 is just another
        // form of corruption and must take the recovery path rather than
        // surface as an I/O error.
        let stored = fs::read(&path)?;
        // A blob this machine cannot unwrap is corruption for our purposes
        // (a profile copied from elsewhere): set it aside like bad JSON.
        let parsed = crate::dpapi::unprotect(&stored)
            .map_err(|e| e.to_string())
            .and_then(|bytes| serde_json::from_slice::<AppData>(&bytes).map_err(|e| e.to_string()));
        match parsed {
            Ok(data) => Ok(Loaded::Data(data)),
            Err(err) => {
                let backup = set_aside_corrupt(&path)?;
                tracing::warn!(
                    path = %path.display(),
                    backup = %backup.display(),
                    error = %err,
                    "app data file is corrupt; moved aside and continuing with defaults"
                );
                Ok(Loaded::Recovered {
                    backup,
                    error: err,
                })
            }
        }
    }

    /// Persist the JSON app-data blob, replacing any previous contents.
    pub fn save_app_data(&self, data: &AppData) -> Result<()> {
        self.ensure_dir()?;
        let text = serde_json::to_string_pretty(data)?;
        write_restricted(&self.app_data_path(), &crate::dpapi::protect(text.as_bytes())?)
    }
}

/// Rename `path` to `<path>.corrupt-<unix_ts>` (suffixed `-N` if that name
/// is somehow taken — two recoveries within one second, or a stuck clock)
/// and return the destination.
fn set_aside_corrupt(path: &Path) -> Result<PathBuf> {
    let stem = format!("{}.corrupt-{}", path.display(), unix_now());
    let mut backup = PathBuf::from(&stem);
    let mut n = 1u32;
    while backup.exists() {
        backup = PathBuf::from(format!("{stem}-{n}"));
        n += 1;
    }
    fs::rename(path, &backup)?;
    Ok(backup)
}

/// Atomically replace `path` with `bytes`, applying the most restrictive
/// permissions this platform's standard library exposes.
///
/// The bytes are written to `<name>.tmp-<uuid>` in the same directory (so
/// the final rename never crosses a filesystem), flushed with `sync_all`,
/// chmod'ed on Unix, and then renamed over `path`. `fs::rename` replaces an
/// existing destination on both Unix (`rename(2)`) and Windows
/// (`MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`), so readers only ever
/// see the old or the new complete file. On any failure the temp file is
/// removed and the previous contents of `path` are left as they were.
///
/// See the module-level docs for the permissions threat-model note; that
/// part is a best-effort hardening step, not a security boundary on its own.
fn write_restricted(path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| CoreError::Other(format!("invalid storage path: {}", path.display())))?;
    let tmp = path.with_file_name(format!("{file_name}.tmp-{}", uuid::Uuid::new_v4()));

    let result = write_and_sync(&tmp, bytes).and_then(|()| {
        fs::rename(&tmp, path)?;
        Ok(())
    });
    if result.is_err() {
        // Best effort: the temp file may never have been created, and a
        // failed cleanup must not mask the original error.
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn write_and_sync(tmp: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600);
        file.set_permissions(perms)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{addressbook::DeviceEntry, test_support::TempDir};
    use rotodesk_proto::RotoDeskId;

    #[test]
    fn rebranding_preserves_identity_settings_history_and_thumbnails() {
        let temp = TempDir::new("rebranding");
        let old = temp.path().join("previous");
        let new = temp.path().join("RotoDesk");
        let previous = Storage::at(old.clone());
        let identity = previous.load_or_create_identity().unwrap();
        let mut data = AppData::default();
        data.settings.alias = Some("My original PC".into());
        data.addressbook.add(DeviceEntry::new(RotoDeskId::new(123456789).unwrap(), "Favourite PC"));
        data.history.push(crate::history::SessionRecord::start(Default::default(), RotoDeskId::new(234567891).unwrap(), "Recent PC", "p2p"));
        previous.save_app_data(&data).unwrap();
        fs::create_dir(old.join("thumbs")).unwrap();
        fs::write(old.join("thumbs/123456789.png"), b"thumbnail fixture").unwrap();
        Storage::migrate_legacy(&old, &new).unwrap();
        let migrated = Storage::at(new.clone());
        assert_eq!(migrated.load_or_create_identity().unwrap().derive_id(), identity.derive_id());
        assert_eq!(migrated.load_app_data().unwrap().unwrap(), data);
        assert_eq!(fs::read(new.join("thumbs/123456789.png")).unwrap(), b"thumbnail fixture");
        assert!(old.join("identity.pem").exists(), "original is retained as a backup");
        let replacement = Identity::generate();
        migrated.save_identity(&replacement).unwrap();
        Storage::migrate_legacy(&old, &new).unwrap();
        assert_eq!(migrated.load_or_create_identity().unwrap().derive_id(), replacement.derive_id(), "existing data must never be overwritten");
    }

    #[test]
    fn service_migration_only_renames_the_standard_profile_path() {
        let root = PathBuf::from("C:/Users/example/AppData/Roaming");
        let old = rotodesk_proto::compat::LEGACY_PRODUCT;
        assert_eq!(Storage::rebranded_service_dir(&root.join(old).join(old).join("data")), root.join("RotoDesk/RotoDesk/data"));
        assert_eq!(Storage::rebranded_service_dir(Path::new("D:/custom-profile")), Path::new("D:/custom-profile"));
    }

    fn temp_files_in(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect()
    }

    #[test]
    fn app_data_roundtrips_through_temp_dir() {
        let dir = TempDir::new("appdata-roundtrip");
        let storage = Storage::at(dir.path());

        // Fresh install: nothing on disk yet.
        assert!(storage.load_app_data().unwrap().is_none());
        assert_eq!(storage.load_app_data_or_recover().unwrap(), Loaded::Fresh);

        let mut data = AppData::default();
        data.settings.alias = Some("pc-oficina.roto".into());
        data.addressbook.add(DeviceEntry::new(
            RotoDeskId::new(548_291_743).unwrap(),
            "Oficina",
        ));

        storage.save_app_data(&data).unwrap();
        let reloaded = storage.load_app_data().unwrap().expect("just saved");
        assert_eq!(data, reloaded);
        assert_eq!(
            storage.load_app_data_or_recover().unwrap(),
            Loaded::Data(data)
        );
    }

    #[test]
    fn identity_created_once_and_stable_across_reload() {
        let dir = TempDir::new("identity-stable");
        let storage = Storage::at(dir.path());

        let first = storage.load_or_create_identity().unwrap();
        assert!(
            storage.identity_path().exists(),
            "identity must be persisted on first run"
        );

        let second = storage.load_or_create_identity().unwrap();
        assert_eq!(
            first.public_key().to_bytes(),
            second.public_key().to_bytes()
        );
        assert_eq!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn storage_never_defaults_outside_the_supplied_base_dir() {
        let dir = TempDir::new("scoped");
        let storage = Storage::at(dir.path());
        assert!(storage.identity_path().starts_with(dir.path()));
        assert!(storage.app_data_path().starts_with(dir.path()));
    }

    #[test]
    fn atomic_write_overwrites_existing_file_and_leaves_no_temp_files() {
        let dir = TempDir::new("atomic-overwrite");
        let storage = Storage::at(dir.path());

        let mut first = AppData::default();
        first.settings.alias = Some("first".into());
        storage.save_app_data(&first).unwrap();

        // Second save must replace the file in place (rename over an
        // existing destination), not fail or append.
        let mut second = AppData::default();
        second.settings.alias = Some("second".into());
        storage.save_app_data(&second).unwrap();
        assert_eq!(storage.load_app_data().unwrap(), Some(second));

        let leftovers = temp_files_in(&dir.path());
        assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
    }

    #[test]
    fn atomic_write_failure_keeps_previous_contents() {
        let dir = TempDir::new("atomic-failure");
        let storage = Storage::at(dir.path());
        storage.save_app_data(&AppData::default()).unwrap();
        let before = fs::read(storage.app_data_path()).unwrap();

        // Make the rename fail by turning the destination into a non-empty
        // directory: the write to the temp file succeeds, the rename over
        // a directory does not, and the temp file must be cleaned up.
        let blocker = dir.path().join("blocker");
        fs::create_dir_all(blocker.join("child")).unwrap();
        assert!(write_restricted(&blocker, b"x").is_err());
        assert!(blocker.is_dir(), "failed write must not disturb the target");

        let leftovers = temp_files_in(&dir.path());
        assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
        assert_eq!(fs::read(storage.app_data_path()).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn written_files_are_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("perms");
        let storage = Storage::at(dir.path());
        storage.save_app_data(&AppData::default()).unwrap();
        let mode = fs::metadata(storage.app_data_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn corrupt_app_data_is_moved_aside_and_defaults_are_used() {
        let dir = TempDir::new("corrupt-appdata");
        let storage = Storage::at(dir.path());
        fs::write(storage.app_data_path(), b"{ this is not json").unwrap();

        // The strict loader still reports the problem...
        assert!(matches!(storage.load_app_data(), Err(CoreError::Json(_))));

        // ...while the recovering loader sets the file aside.
        let loaded = storage.load_app_data_or_recover().unwrap();
        let backup = match &loaded {
            Loaded::Recovered { backup, error } => {
                assert!(!error.is_empty());
                backup.clone()
            }
            other => panic!("expected Recovered, got {other:?}"),
        };
        assert!(backup.exists(), "user data must be preserved, not deleted");
        assert!(backup
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("appdata.json.corrupt-"));
        assert_eq!(fs::read(&backup).unwrap(), b"{ this is not json");
        assert!(!storage.app_data_path().exists());
        assert_eq!(loaded.into_data(), AppData::default());

        // Recovering twice in the same second must not clobber the first
        // backup.
        fs::write(storage.app_data_path(), b"also bad").unwrap();
        let second = storage.load_app_data_or_recover().unwrap();
        let Loaded::Recovered {
            backup: backup2, ..
        } = second
        else {
            panic!("expected Recovered");
        };
        assert_ne!(backup, backup2);
        assert!(backup.exists() && backup2.exists());
    }

    #[test]
    fn corrupt_identity_is_a_hard_error() {
        let dir = TempDir::new("corrupt-identity");
        let storage = Storage::at(dir.path());
        fs::write(storage.identity_path(), b"-----BEGIN GARBAGE-----").unwrap();

        assert!(storage.load_or_create_identity().is_err());
        // Never moved aside or regenerated: that would change the device ID.
        assert_eq!(
            fs::read(storage.identity_path()).unwrap(),
            b"-----BEGIN GARBAGE-----"
        );
    }

    #[test]
    fn app_data_deserializes_from_empty_object() {
        let data: AppData = serde_json::from_str("{}").unwrap();
        assert_eq!(data, AppData::default());
    }

    #[test]
    fn app_data_tolerates_partial_sections_from_older_versions() {
        // An older build that knew only a smaller Settings, an address book
        // entry lacking the optional columns, a history record without the
        // end-of-session fields and a trust entry with one flag must still
        // load; everything missing takes its default.
        let json = r#"{
            "settings": { "unattended_enabled": true },
            "addressbook": { "entries": [ { "id": 548291743, "name": "Oficina" } ] },
            "history": { "records": [ { "id": "6f6c9b8e-6a5c-4d5f-9c1e-2b3a4c5d6e7f",
                                         "device": 548291743, "user": "alice",
                                         "started_at": 100 } ] },
            "trust": { "devices": [ { "id": 548291743, "always_allow": true } ] }
        }"#;
        let data: AppData = serde_json::from_str(json).unwrap();
        assert!(data.settings.unattended_enabled);
        assert_eq!(data.settings.alias, None);
        assert_eq!(data.addressbook.entries.len(), 1);
        assert_eq!(data.addressbook.entries[0].name, "Oficina");
        assert_eq!(data.history.records.len(), 1);
        assert_eq!(data.history.records[0].started_at, 100);
        assert_eq!(data.history.records[0].ended_at, None);
        assert!(data.trust.devices[0].always_allow);
        assert!(!data.trust.devices[0].no_confirm);
        assert!(data.trust.devices[0].tokens.is_empty());
    }
}
