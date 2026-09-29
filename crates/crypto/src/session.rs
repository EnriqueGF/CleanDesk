//! Session channel binding: tie the device identity to the DTLS session.
//!
//! WebRTC's DTLS handshake authenticates the peer certificate only against
//! the fingerprint carried in the SDP — and the SDP travels through whichever
//! rendezvous the peers used (CleanDesk Server, a LAN link, the DHT, Nostr).
//! A rendezvous that rewrites both fingerprints can therefore terminate two
//! DTLS sessions and sit in the middle. To close that gap, each peer signs,
//! with its long-lived Ed25519 key, the session id together with **both**
//! DTLS certificate fingerprints as it sees them. The other side recomputes
//! the message from its own view of the fingerprints (swapped) and verifies
//! the signature: a relay in the middle would have to forge a signature over
//! fingerprints it does not control.
//!
//! The message is domain-separated (`cleandesk-session-v1:`) and includes the
//! signer's role so a host proof can never be replayed as a viewer proof.

use crate::{identity::Identity, CryptoError};
use cleandesk_proto::session::SessionId;

/// Fixed prefix that keeps session proofs apart from every other signature a
/// device produces (registration, rendezvous records...).
pub const SESSION_PROOF_PREFIX: &[u8] = b"cleandesk-session-v1:";

/// Which side of the session is signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Host,
    Viewer,
}

impl SessionRole {
    fn tag(self) -> u8 {
        match self {
            SessionRole::Host => b'H',
            SessionRole::Viewer => b'V',
        }
    }

    /// The role of the peer on the other side.
    pub fn peer(self) -> SessionRole {
        match self {
            SessionRole::Host => SessionRole::Viewer,
            SessionRole::Viewer => SessionRole::Host,
        }
    }
}

/// Canonical form of a DTLS fingerprint for signing: trimmed and lowercase, so
/// `SHA-256 AB:CD` and `sha-256 ab:cd` bind to the same bytes.
fn canonical_fingerprint(fp: &str) -> Vec<u8> {
    fp.trim().to_ascii_lowercase().into_bytes()
}

/// The exact bytes a peer signs: prefix, role tag, the 16-byte session id and
/// both fingerprints, each length-prefixed so their boundary is unambiguous.
///
/// `local_fp` is the fingerprint of the signer's **own** DTLS certificate and
/// `remote_fp` the one of the certificate it is talking to.
pub fn session_proof_message(
    session: &SessionId,
    local_fp: &str,
    remote_fp: &str,
    role: SessionRole,
) -> Vec<u8> {
    let local = canonical_fingerprint(local_fp);
    let remote = canonical_fingerprint(remote_fp);
    let mut out = Vec::with_capacity(SESSION_PROOF_PREFIX.len() + 1 + 16 + 8 + local.len() + remote.len());
    out.extend_from_slice(SESSION_PROOF_PREFIX);
    out.push(role.tag());
    out.extend_from_slice(session.as_bytes());
    out.extend_from_slice(&(local.len() as u32).to_be_bytes());
    out.extend_from_slice(&local);
    out.extend_from_slice(&(remote.len() as u32).to_be_bytes());
    out.extend_from_slice(&remote);
    out
}

/// Sign this device's session proof; returns the base64 signature that goes
/// in `SessionMessage::IdentityProof`.
pub fn sign_session_proof(
    identity: &Identity,
    session: &SessionId,
    local_fp: &str,
    remote_fp: &str,
    role: SessionRole,
) -> String {
    identity.sign_b64(&session_proof_message(session, local_fp, remote_fp, role))
}

/// Verify a proof exactly as the signer built it (`local_fp`/`remote_fp` are
/// the **signer's** local and remote fingerprints).
pub fn verify_session_proof(
    public_key_b64: &str,
    session: &SessionId,
    local_fp: &str,
    remote_fp: &str,
    role: SessionRole,
    signature_b64: &str,
) -> Result<(), CryptoError> {
    crate::identity::verify_b64_sig(
        public_key_b64,
        &session_proof_message(session, local_fp, remote_fp, role),
        signature_b64,
    )
}

/// Verify the proof received from the peer, expressed in **our** terms: we
/// pass our own local and remote fingerprints and our own role; the peer
/// signed the same pair swapped, under the opposite role.
pub fn verify_peer_session_proof(
    public_key_b64: &str,
    session: &SessionId,
    my_local_fp: &str,
    my_remote_fp: &str,
    my_role: SessionRole,
    signature_b64: &str,
) -> Result<(), CryptoError> {
    verify_session_proof(public_key_b64, session, my_remote_fp, my_local_fp, my_role.peer(), signature_b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_FP: &str = "sha-256 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";
    const VIEWER_FP: &str = "sha-256 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00";

    #[test]
    fn message_is_prefixed_and_role_separated() {
        let s = SessionId::new_v4();
        let host = session_proof_message(&s, HOST_FP, VIEWER_FP, SessionRole::Host);
        assert!(host.starts_with(SESSION_PROOF_PREFIX));
        let viewer = session_proof_message(&s, HOST_FP, VIEWER_FP, SessionRole::Viewer);
        assert_ne!(host, viewer);
        // Case and whitespace do not matter: fingerprints are canonicalised.
        let upper = session_proof_message(&s, &HOST_FP.to_ascii_uppercase(), &format!(" {VIEWER_FP} "), SessionRole::Host);
        assert_eq!(host, upper);
        // The two fingerprints are length-prefixed: shifting bytes across the
        // boundary produces a different message.
        let shifted = session_proof_message(&s, &HOST_FP[..HOST_FP.len() - 1], &format!("{}{}", &HOST_FP[HOST_FP.len() - 1..], VIEWER_FP), SessionRole::Host);
        assert_ne!(host, shifted);
    }

    #[test]
    fn both_sides_verify_each_other() {
        let host = Identity::generate();
        let viewer = Identity::generate();
        let s = SessionId::new_v4();
        // Host sees (local = HOST_FP, remote = VIEWER_FP); viewer the opposite.
        let host_sig = sign_session_proof(&host, &s, HOST_FP, VIEWER_FP, SessionRole::Host);
        let viewer_sig = sign_session_proof(&viewer, &s, VIEWER_FP, HOST_FP, SessionRole::Viewer);
        assert!(verify_peer_session_proof(&host.public_key_b64(), &s, VIEWER_FP, HOST_FP, SessionRole::Viewer, &host_sig).is_ok());
        assert!(verify_peer_session_proof(&viewer.public_key_b64(), &s, HOST_FP, VIEWER_FP, SessionRole::Host, &viewer_sig).is_ok());
    }

    #[test]
    fn tampered_fingerprint_session_role_or_key_fails() {
        let host = Identity::generate();
        let s = SessionId::new_v4();
        let sig = sign_session_proof(&host, &s, HOST_FP, VIEWER_FP, SessionRole::Host);
        let pk = host.public_key_b64();
        let ok = |l: &str, r: &str, sess: &SessionId, role: SessionRole| {
            verify_peer_session_proof(&pk, sess, l, r, role, &sig).is_ok()
        };
        assert!(ok(VIEWER_FP, HOST_FP, &s, SessionRole::Viewer));
        // A relay in the middle: the viewer sees a different remote cert.
        let mitm = HOST_FP.replace("aa:bb", "aa:bc");
        assert!(!ok(VIEWER_FP, &mitm, &s, SessionRole::Viewer));
        // ...or a different local cert (the relay's own towards the viewer).
        let mitm_local = VIEWER_FP.replace("11:22", "11:23");
        assert!(!ok(&mitm_local, HOST_FP, &s, SessionRole::Viewer));
        // Swapped roles: a host proof replayed as if it were a viewer proof.
        assert!(!ok(HOST_FP, VIEWER_FP, &s, SessionRole::Host));
        // Wrong session.
        assert!(!ok(VIEWER_FP, HOST_FP, &SessionId::new_v4(), SessionRole::Viewer));
        // Wrong key, garbage signature.
        let other = Identity::generate().public_key_b64();
        assert!(verify_peer_session_proof(&other, &s, VIEWER_FP, HOST_FP, SessionRole::Viewer, &sig).is_err());
        assert!(verify_peer_session_proof(&pk, &s, VIEWER_FP, HOST_FP, SessionRole::Viewer, "not base64!").is_err());
        assert!(verify_peer_session_proof("nope", &s, VIEWER_FP, HOST_FP, SessionRole::Viewer, &sig).is_err());
    }

    #[test]
    fn a_registration_signature_is_not_a_session_proof() {
        let id = Identity::generate();
        let s = SessionId::new_v4();
        let reg = id.sign_b64(&cleandesk_proto::message::register_proof_message(s.as_bytes()));
        assert!(verify_session_proof(&id.public_key_b64(), &s, HOST_FP, VIEWER_FP, SessionRole::Host, &reg).is_err());
    }
}
