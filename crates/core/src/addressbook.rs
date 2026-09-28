//! Saved devices — the "libreta de dispositivos" (spec §11).

use std::collections::BTreeMap;

use cleandesk_proto::{session::DeviceState, CleanDeskId};
use serde::{Deserialize, Serialize};

/// One saved device entry.
///
/// Only `id` and `name` are required on the wire; everything else is
/// `#[serde(default)]` so entries saved by an older build (or hand-edited)
/// still load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub id: CleanDeskId,
    pub name: String,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    /// Unix-seconds timestamp of the last successful connection.
    #[serde(default)]
    pub last_connection: Option<u64>,
    #[serde(default = "offline")]
    pub state: DeviceState,
    /// Remembered unattended-access credential for this device: the Argon2id
    /// *derived* HMAC key (32 bytes), never the plaintext password. It lets the
    /// viewer reconnect without retyping the password; anyone who reads it can
    /// authenticate to *that* host only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unattended_key: Option<Vec<u8>>,
    /// The device's Ed25519 public key (base64) as seen in the last
    /// successful session. In community mode this is what protects against
    /// someone else appearing under the same ID (see `cleandesk-discovery`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_key: Option<String>,
}

/// Serde default for [`DeviceEntry::state`]: a device we have not heard
/// from is offline until proven otherwise (`DeviceState` has no `Default`).
fn offline() -> DeviceState {
    DeviceState::Offline
}

impl DeviceEntry {
    /// A freshly saved entry: no alias/description/group/history yet, and
    /// reported offline until the address book hears otherwise.
    pub fn new(id: CleanDeskId, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            alias: None,
            description: None,
            group: None,
            last_connection: None,
            state: DeviceState::Offline,
            unattended_key: None,
            pinned_key: None,
        }
    }

    /// The remembered unattended key as a fixed array, if present and well-formed.
    pub fn unattended_key(&self) -> Option<[u8; 32]> {
        self.unattended_key.as_ref()?.as_slice().try_into().ok()
    }
}

/// The full set of saved devices.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AddressBook {
    pub entries: Vec<DeviceEntry>,
}

impl AddressBook {
    /// Add a new entry, or replace the existing one with the same [`CleanDeskId`].
    pub fn add(&mut self, entry: DeviceEntry) {
        match self.entries.iter_mut().find(|e| e.id == entry.id) {
            Some(existing) => *existing = entry,
            None => self.entries.push(entry),
        }
    }

    /// Remove the entry with `id`, returning it if it was present.
    pub fn remove(&mut self, id: CleanDeskId) -> Option<DeviceEntry> {
        let idx = self.entries.iter().position(|e| e.id == id)?;
        Some(self.entries.remove(idx))
    }

    /// Apply `f` to the entry with `id` in place. Returns `true` if an entry
    /// was found and updated.
    pub fn update(&mut self, id: CleanDeskId, f: impl FnOnce(&mut DeviceEntry)) -> bool {
        match self.find_by_id_mut(id) {
            Some(entry) => {
                f(entry);
                true
            }
            None => false,
        }
    }

    pub fn find_by_id(&self, id: CleanDeskId) -> Option<&DeviceEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn find_by_id_mut(&mut self, id: CleanDeskId) -> Option<&mut DeviceEntry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }

    /// Bucket entries by their `group` field (spec §11); ungrouped devices
    /// are keyed under `None`. Iteration order within a group follows the
    /// underlying `entries` order.
    pub fn group_by(&self) -> BTreeMap<Option<String>, Vec<&DeviceEntry>> {
        let mut map: BTreeMap<Option<String>, Vec<&DeviceEntry>> = BTreeMap::new();
        for entry in &self.entries {
            map.entry(entry.group.clone()).or_default().push(entry);
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> CleanDeskId {
        CleanDeskId::new(n).unwrap()
    }

    #[test]
    fn add_then_find_by_id() {
        let mut book = AddressBook::default();
        book.add(DeviceEntry::new(id(548_291_743), "Oficina"));
        assert!(book.find_by_id(id(548_291_743)).is_some());
        assert!(book.find_by_id(id(111_111_111)).is_none());
    }

    #[test]
    fn add_replaces_existing_entry_with_same_id() {
        let mut book = AddressBook::default();
        book.add(DeviceEntry::new(id(548_291_743), "Oficina"));
        book.add(DeviceEntry::new(id(548_291_743), "Oficina 2"));
        assert_eq!(book.entries.len(), 1);
        assert_eq!(book.find_by_id(id(548_291_743)).unwrap().name, "Oficina 2");
    }

    #[test]
    fn update_mutates_matching_entry_only() {
        let mut book = AddressBook::default();
        book.add(DeviceEntry::new(id(548_291_743), "Oficina"));

        assert!(book.update(id(548_291_743), |e| e.alias =
            Some("pc-oficina.clean".into())));
        assert_eq!(
            book.find_by_id(id(548_291_743)).unwrap().alias.as_deref(),
            Some("pc-oficina.clean")
        );
        assert!(!book.update(id(999_999_999), |_| {}));
    }

    #[test]
    fn remove_deletes_entry() {
        let mut book = AddressBook::default();
        book.add(DeviceEntry::new(id(548_291_743), "Oficina"));
        assert!(book.remove(id(548_291_743)).is_some());
        assert!(book.find_by_id(id(548_291_743)).is_none());
        assert!(book.remove(id(548_291_743)).is_none());
    }

    #[test]
    fn group_by_buckets_entries_and_keeps_ungrouped_under_none() {
        let mut book = AddressBook::default();
        let mut a = DeviceEntry::new(id(548_291_743), "A");
        a.group = Some("Oficina".into());
        let mut b = DeviceEntry::new(id(111_111_111), "B");
        b.group = Some("Oficina".into());
        let c = DeviceEntry::new(id(222_222_222), "C"); // ungrouped
        book.add(a);
        book.add(b);
        book.add(c);

        let groups = book.group_by();
        assert_eq!(groups.get(&Some("Oficina".to_string())).unwrap().len(), 2);
        assert_eq!(groups.get(&None).unwrap().len(), 1);
    }
}
