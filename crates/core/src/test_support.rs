//! Test-only helpers shared across this crate's unit tests.
//!
//! Persistence tests must never touch the real user profile (see the
//! `storage` module docs), so every test that needs a filesystem root uses
//! [`TempDir`] instead of `directories::ProjectDirs`. This is a tiny
//! hand-rolled temp directory rather than a dependency on the `tempfile`
//! crate: `std::env::temp_dir()` plus a `uuid` (already a dependency, used
//! elsewhere for session IDs) is enough to get a unique, self-cleaning
//! directory per test.

use std::path::PathBuf;

pub(crate) struct TempDir(PathBuf);

impl TempDir {
    /// Create a fresh, empty directory under the OS temp root. `tag` is only
    /// for human-readability when poking around a leftover directory; the
    /// actual uniqueness comes from the appended UUID.
    pub(crate) fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "cleandesk-core-test-{tag}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).expect("create temp test dir");
        Self(path)
    }

    pub(crate) fn path(&self) -> PathBuf {
        self.0.clone()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best-effort cleanup; leaving a stray temp dir behind is not worth
        // failing (or panicking inside) a test's teardown over.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
