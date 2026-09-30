//! At-rest protection of the files that hold secrets (`identity.pem`,
//! `appdata.json`).
//!
//! On Windows the bytes are wrapped with DPAPI in *machine* scope: the file
//! is only readable on the machine that wrote it, which is what stops a
//! copied profile, a backup or a disk mounted elsewhere from yielding the
//! device key and the unattended password material. Machine scope (rather
//! than user scope) because the Windows service reads the same files as
//! LocalSystem; the profile directory's ACL is what keeps other local users
//! out. Elsewhere the bytes are stored as they are (Unix gets `0600`).
//!
//! Files written before this existed are read as plain bytes and rewritten
//! protected on the next save.

use crate::{CoreError, Result};

/// Marker at the start of a protected file.
pub const MAGIC: &[u8] = b"ROTODESK-DPAPI-1\n";

/// Wrap `plain` for storage.
pub fn protect(plain: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(MAGIC.len() + plain.len() + 256);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&imp::protect(plain)?);
    Ok(out)
}

/// Undo [`protect`]; bytes without the marker are returned unchanged.
pub fn unprotect(stored: &[u8]) -> Result<Vec<u8>> {
    match stored.strip_prefix(MAGIC).or_else(|| stored.strip_prefix(rotodesk_proto::compat::LEGACY_DPAPI_MAGIC)) {
        Some(blob) => imp::unprotect(blob),
        None => Ok(stored.to_vec()),
    }
}

/// Is this file already protected?
pub fn is_protected(stored: &[u8]) -> bool {
    stored.starts_with(MAGIC) || stored.starts_with(rotodesk_proto::compat::LEGACY_DPAPI_MAGIC)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
        CRYPT_INTEGER_BLOB,
    };

    const FLAGS: u32 = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN;

    fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        // SAFETY: DPAPI filled `out` with `cbData` bytes at `pbData`, which we
        // copy out and release with `LocalFree` as documented.
        unsafe {
            let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            let _ = LocalFree(Some(HLOCAL(out.pbData as *mut _)));
            bytes
        }
    }

    pub fn protect(plain: &[u8]) -> Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB { cbData: plain.len() as u32, pbData: plain.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: `input` points at `plain` for the duration of the call.
        unsafe { CryptProtectData(&input, None, None, None, None, FLAGS, &mut out) }
            .map_err(|e| CoreError::Other(format!("DPAPI protect: {e}")))?;
        Ok(take(out))
    }

    pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB { cbData: blob.len() as u32, pbData: blob.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: as above.
        unsafe { CryptUnprotectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out) }
            .map_err(|e| CoreError::Other(format!("DPAPI unprotect: {e}")))?;
        Ok(take(out))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn protect(plain: &[u8]) -> Result<Vec<u8>> {
        Ok(plain.to_vec())
    }

    pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>> {
        Ok(blob.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_legacy_passthrough() {
        let secret = b"-----BEGIN PRIVATE KEY-----";
        let stored = protect(secret).unwrap();
        assert!(is_protected(&stored));
        assert_ne!(&stored[MAGIC.len()..], secret, "never stored in clear on this platform");
        assert_eq!(unprotect(&stored).unwrap(), secret);
        assert!(!is_protected(secret));
        assert_eq!(unprotect(secret).unwrap(), secret);
        let mut previous = rotodesk_proto::compat::LEGACY_DPAPI_MAGIC.to_vec();
        previous.extend_from_slice(&stored[MAGIC.len()..]);
        assert!(is_protected(&previous));
        assert_eq!(unprotect(&previous).unwrap(), secret);
    }

    #[cfg(windows)]
    #[test]
    fn tampered_blob_is_rejected() {
        let mut stored = protect(b"hello").unwrap();
        let last = stored.len() - 1;
        stored[last] ^= 0xff;
        assert!(unprotect(&stored).is_err());
    }
}
