//! The CleanDesk ID: a stable, human-shareable numeric device identifier.
//!
//! Rendered grouped in threes for humans (`548 291 743`) but stored as a plain
//! integer. IDs are 9 digits by default, giving ~900 million addressable
//! devices; the type accepts up to 10 digits for future headroom.

use crate::error::ProtoError;
use serde::{Deserialize, Serialize};

/// Number of digits in a freshly generated CleanDesk ID.
pub const ID_DIGITS: u32 = 9;

const MIN_ID: u64 = 100_000_000; // smallest 9-digit number
const MAX_ID: u64 = 9_999_999_999; // largest 10-digit number

/// A unique CleanDesk device identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CleanDeskId(u64);

impl CleanDeskId {
    /// Build an ID from a raw integer, validating the digit range.
    pub fn new(value: u64) -> Result<Self, ProtoError> {
        if (MIN_ID..=MAX_ID).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ProtoError::InvalidId(format!(
                "value {value} out of range [{MIN_ID}, {MAX_ID}]"
            )))
        }
    }

    /// Generate a fresh 9-digit ID from a caller-supplied random source.
    ///
    /// The randomness is injected so this crate stays dependency-light and the
    /// caller controls the CSPRNG (see `cleandesk-crypto`).
    pub fn generate(rng: impl FnOnce() -> u64) -> Self {
        let span = MAX_ID_9 - MIN_ID + 1;
        Self(MIN_ID + (rng() % span))
    }

    /// The raw integer value.
    pub fn value(self) -> u64 {
        self.0
    }

    /// Parse from a string that may contain spaces or dashes as grouping.
    pub fn parse(s: &str) -> Result<Self, ProtoError> {
        let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return Err(ProtoError::InvalidId(format!("no digits in {s:?}")));
        }
        let value = digits
            .parse::<u64>()
            .map_err(|e| ProtoError::InvalidId(e.to_string()))?;
        Self::new(value)
    }
}

const MAX_ID_9: u64 = 999_999_999;

impl core::fmt::Display for CleanDeskId {
    /// Groups digits in threes from the left: `548 291 743`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.0.to_string();
        let bytes = s.as_bytes();
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 && (bytes.len() - i) % 3 == 0 {
                write!(f, " ")?;
            }
            write!(f, "{}", *b as char)?;
        }
        Ok(())
    }
}

impl core::str::FromStr for CleanDeskId {
    type Err = ProtoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_grouped() {
        let id = CleanDeskId::new(548_291_743).unwrap();
        assert_eq!(id.to_string(), "548 291 743");
    }

    #[test]
    fn parses_grouped_and_dashed() {
        assert_eq!(CleanDeskId::parse("548 291 743").unwrap().value(), 548_291_743);
        assert_eq!(CleanDeskId::parse("548-291-743").unwrap().value(), 548_291_743);
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(CleanDeskId::new(42).is_err());
        assert!(CleanDeskId::new(999).is_err());
    }

    #[test]
    fn generate_is_in_range() {
        let id = CleanDeskId::generate(|| 123_456_789_000);
        assert!((MIN_ID..=MAX_ID_9).contains(&id.value()));
    }
}
