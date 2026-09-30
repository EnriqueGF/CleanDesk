//! cleandesk-core: persistent state and session orchestration.
//!
//! This crate owns everything that outlives a single connection:
//! * [`storage`] — where things live on disk, and how the device identity and
//!   the JSON app-data blob get there and back.
//! * [`config`] — user-configurable [`config::Settings`].
//! * [`addressbook`] — the saved-devices list (spec §11).
//! * [`history`] — the connection log (spec §12).
//! * [`trust`] — trusted-device policy and reconnection tokens (spec §10).
//! * [`session`] — the per-connection state machine and live permission
//!   enforcement (spec §6).
//!
//! [`AppState`] ties identity plus all of the above together as the one
//! shared, process-wide handle the GUI and the async host/client tasks hold.
//! See its doc comment for the concurrency model.

pub mod addressbook;
pub mod config;
pub mod error;
pub mod dpapi;
pub mod history;
pub mod session;
pub mod storage;
pub mod trust;

#[cfg(test)]
pub(crate) mod test_support;

pub use error::{CoreError, Result};

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use cleandesk_crypto::identity::Identity;
use parking_lot::RwLock;

use addressbook::AddressBook;
use cleandesk_proto::session::SessionId;
use config::Settings;
use history::{History, SessionRecord};
use storage::{AppData, Loaded, Storage};
use trust::TrustRegistry;

/// Crate version string, handy for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Current Unix time in whole seconds. Saturates to `0` on a pre-epoch clock
/// instead of panicking — a clock quirk is never worth crashing a session or
/// a history write over.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The single shared, process-wide application state.
///
/// ## Concurrency model
/// `identity` is resolved once at [`AppState::load`] time and never mutated
/// again for the life of the process — a device's Ed25519 keypair does not
/// change — so it is stored bare. `Identity` (and therefore `AppState`) is
/// `Send + Sync`; callers share one `AppState` across threads and async tasks
/// behind an `Arc<AppState>`.
///
/// The other four fields *are* mutated from multiple places concurrently in
/// the real program: the GUI thread edits settings and the address book while
/// async session tasks append history records and read trust policy at the
/// same time. Each field therefore gets its own `parking_lot::RwLock` rather
/// than one lock around the whole struct, so, e.g., appending a history
/// record never blocks a concurrent address-book lookup.
///
/// `parking_lot::RwLock` (a synchronous lock) was chosen over an async-aware
/// one such as `tokio::sync::RwLock`: every critical section here is a short,
/// synchronous read/clone or in-place mutation of plain data with no `.await`
/// inside it. An async lock only earns its keep when a lock must be held
/// across an await point; nothing in this crate does that, so the smaller,
/// faster, non-poisoning `parking_lot` lock is the better default. If a
/// future caller needs to hold one of these locks across an `.await`, that is
/// the signal to revisit this choice for that field.
pub struct AppState {
    pub identity: Identity,
    pub settings: RwLock<Settings>,
    pub addressbook: RwLock<AddressBook>,
    pub history: RwLock<History>,
    pub trust: RwLock<TrustRegistry>,
    storage: Storage,
}

impl AppState {
    /// Load from the real per-user application data directory
    /// (see [`storage::Storage::locate`]), creating and persisting a fresh
    /// device identity plus in-memory defaults for everything else on first
    /// run.
    pub fn load() -> Result<Self> {
        Self::load_from(Storage::locate()?)
    }

    /// Same as [`Self::load`], but rooted at an arbitrary directory. Exists
    /// so tests (and a possible future portable install mode) never touch
    /// the real user profile.
    pub fn load_from_dir(base_dir: PathBuf) -> Result<Self> {
        Self::load_from(Storage::at(base_dir))
    }

    /// A corrupt `appdata.json` is set aside and replaced with defaults (the
    /// storage layer already logs where the backup went); a corrupt
    /// `identity.pem` remains a hard error because regenerating it would
    /// silently change this device's CleanDesk ID.
    fn load_from(storage: Storage) -> Result<Self> {
        let identity = storage.load_or_create_identity()?;
        let data = match storage.load_app_data_or_recover()? {
            Loaded::Data(data) => data,
            Loaded::Fresh => AppData::default(),
            Loaded::Recovered { backup, .. } => {
                tracing::warn!(
                    backup = %backup.display(),
                    "starting with default settings, address book, history and trust registry"
                );
                AppData::default()
            }
        };
        Ok(Self {
            identity,
            settings: RwLock::new(data.settings),
            addressbook: RwLock::new(data.addressbook),
            history: RwLock::new(data.history),
            trust: RwLock::new(data.trust),
            storage,
        })
    }

    /// The directory this state is persisted in.
    pub fn data_dir(&self) -> PathBuf {
        self.storage.base_dir().to_path_buf()
    }

    /// Modification time of the app-data file, if it exists. Lets a headless
    /// host notice that the GUI changed settings and reload them.
    pub fn app_data_modified(&self) -> Option<std::time::SystemTime> {
        std::fs::metadata(self.storage.app_data_path()).ok()?.modified().ok()
    }

    /// Re-read settings/address book/history/trust from disk, replacing the
    /// in-memory copies. The identity is never reloaded.
    pub fn reload(&self) -> Result<()> {
        let data = self.storage.load_app_data_or_recover()?.into_data();
        *self.settings.write() = data.settings;
        *self.addressbook.write() = data.addressbook;
        *self.history.write() = data.history;
        *self.trust.write() = data.trust;
        Ok(())
    }

    /// Persist settings, address book, history and trust registry as one
    /// JSON blob. The identity file is immutable after first run and is not
    /// rewritten here.
    pub fn save(&self) -> Result<()> {
        let data = AppData {
            settings: self.settings.read().clone(),
            addressbook: self.addressbook.read().clone(),
            history: self.history.read().clone(),
            trust: self.trust.read().clone(),
        };
        self.storage.save_app_data(&data)
    }

    /// Append `record` to the history and persist immediately, so a crash
    /// mid-session still leaves a trace of the connection having started.
    /// The history lock is released before [`Self::save`] takes its own read
    /// locks.
    pub fn record_session_start(&self, record: SessionRecord) -> Result<()> {
        self.history.write().push(record);
        self.save()
    }

    /// Finish the open history record for `id` with `state` (see
    /// [`History::finish`]) and persist. An unknown or already-finished id
    /// is not an error — it is logged and nothing is written, since there
    /// is nothing new to save.
    pub fn record_session_end(&self, id: SessionId, state: &str) -> Result<()> {
        let finished = self.history.write().finish(id, state);
        if !finished {
            tracing::debug!(session_id = %id, state, "no open history record to finish");
            return Ok(());
        }
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use addressbook::DeviceEntry;
    use cleandesk_proto::CleanDeskId;

    #[test]
    fn app_state_round_trips_through_temp_dir() {
        let dir = test_support::TempDir::new("appstate-roundtrip");

        {
            let state = AppState::load_from_dir(dir.path()).unwrap();
            state.settings.write().alias = Some("pc-oficina.clean".into());
            state.addressbook.write().add(DeviceEntry::new(
                CleanDeskId::new(548_291_743).unwrap(),
                "Oficina",
            ));
            state.save().unwrap();
        }

        let reloaded = AppState::load_from_dir(dir.path()).unwrap();
        assert_eq!(
            reloaded.settings.read().alias.as_deref(),
            Some("pc-oficina.clean")
        );
        assert_eq!(reloaded.addressbook.read().entries.len(), 1);
    }

    #[test]
    fn identity_is_created_once_and_stable_across_reload() {
        let dir = test_support::TempDir::new("appstate-identity");

        let first_fingerprint = AppState::load_from_dir(dir.path())
            .unwrap()
            .identity
            .fingerprint();
        let second_fingerprint = AppState::load_from_dir(dir.path())
            .unwrap()
            .identity
            .fingerprint();

        assert_eq!(first_fingerprint, second_fingerprint);
    }

    #[test]
    fn load_never_touches_the_source_repository() {
        // AppState::load() (no directory argument) is the only entry point
        // that resolves a real OS path; every test must go through
        // load_from_dir with a temp directory instead. This test just pins
        // that load_from_dir actually uses the directory it was given.
        let dir = test_support::TempDir::new("scoped");
        let state = AppState::load_from_dir(dir.path()).unwrap();
        assert!(state.storage.base_dir().starts_with(dir.path()));
    }

    #[test]
    fn corrupt_app_data_does_not_prevent_startup() {
        let dir = test_support::TempDir::new("appstate-corrupt");
        let storage = Storage::at(dir.path());

        // First run creates the identity; then corrupt the data blob.
        let fingerprint = AppState::load_from_dir(dir.path())
            .unwrap()
            .identity
            .fingerprint();
        std::fs::write(storage.app_data_path(), b"\xff\xfe not json").unwrap();

        let state = AppState::load_from_dir(dir.path()).unwrap();
        assert_eq!(state.identity.fingerprint(), fingerprint, "identity untouched");
        assert_eq!(*state.settings.read(), Settings::default());
        let backups: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("appdata.json.corrupt-"))
            .collect();
        assert_eq!(backups.len(), 1, "corrupt file must be kept as a backup");
    }

    #[test]
    fn corrupt_identity_still_fails_startup() {
        let dir = test_support::TempDir::new("appstate-corrupt-identity");
        let storage = Storage::at(dir.path());
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(storage.identity_path(), b"garbage").unwrap();
        assert!(AppState::load_from_dir(dir.path()).is_err());
    }

    #[test]
    fn record_session_start_and_end_persist_history() {
        let dir = test_support::TempDir::new("appstate-history");
        let id = SessionId::new_v4();
        let device = CleanDeskId::new(548_291_743).unwrap();

        {
            let state = AppState::load_from_dir(dir.path()).unwrap();
            state
                .record_session_start(SessionRecord::start(id, device, "alice", "p2p"))
                .unwrap();
        }
        // The start alone was persisted.
        {
            let state = AppState::load_from_dir(dir.path()).unwrap();
            let history = state.history.read();
            assert_eq!(history.records.len(), 1);
            assert!(history.records[0].is_open());
        }

        {
            let state = AppState::load_from_dir(dir.path()).unwrap();
            state.record_session_end(id, "closed").unwrap();
            // Ending an unknown session is not an error.
            state
                .record_session_end(SessionId::new_v4(), "failed")
                .unwrap();
        }
        let state = AppState::load_from_dir(dir.path()).unwrap();
        let history = state.history.read();
        assert_eq!(history.records.len(), 1);
        assert_eq!(history.records[0].state, "closed");
        assert!(history.records[0].ended_at.is_some());
    }
}
