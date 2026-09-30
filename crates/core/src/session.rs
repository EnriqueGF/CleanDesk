//! Session lifecycle state machine and live permission enforcement (spec §6).
//!
//! The state machine mirrors the connection flow in `docs/ARCHITECTURE.md`
//! ("Flujo de conexión"):
//!
//! ```text
//! Idle -> Requesting -> AwaitingApproval -> Connecting -> Active -> Closing -> Closed
//!   |         |  |             |  |             |  |          |          |
//!   |         |  v             |  v             |  v          |          |
//!   |         | Rejected       | Rejected       | Rejected    |          |
//!   v         v                v                v             v          v
//! Failed    Failed           Failed           Failed        Failed     Failed
//! ```
//!
//! `Rejected` and `Failed` are terminal.
//!
//! * `Rejected` is reachable from `Requesting`, `AwaitingApproval` and
//!   `Connecting`: the server may answer the request with a `Reject`
//!   (`Busy`, `AuthFailed`, ...) before we ever learn the peer saw it, and it
//!   can equally arrive after the approval step while the transport is still
//!   being negotiated. Once `Active`, there is nothing left to reject.
//! * `Failed` is reachable from every non-terminal state, including `Idle`:
//!   a session can die before its request is even sent (signaling connect
//!   error, no route to the server) and still needs a terminal state to be
//!   recorded under.
//!
//! Nothing follows any terminal state — attempting a transition that is not
//! in this graph returns [`CoreError::IllegalTransition`].

use rotodesk_proto::{
    session::{DeviceInfo, SessionId, SessionStats},
    Permissions, QualityProfile,
};
use serde::{Deserialize, Serialize};

use crate::{error::CoreError, unix_now, Result};

/// The lifecycle state of one [`Session`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Freshly constructed; nothing sent yet.
    Idle,
    /// The connect request has been sent / is being dialed out.
    Requesting,
    /// The peer has the request; a human (or the unattended-auth check) must
    /// accept or reject it.
    AwaitingApproval,
    /// Approved; negotiating the P2P/relay transport (SDP + ICE + DTLS).
    Connecting,
    /// Data channels are up and `granted` is the permission set in force.
    Active { granted: Permissions },
    /// Teardown requested; still draining/closing channels (spec §28).
    Closing,
    /// Fully closed, ordinary end of life.
    Closed,
    /// The peer declined the request.
    Rejected { reason: String },
    /// Ended abnormally (auth failure, ICE failure, transport error, ...).
    Failed { reason: String },
}

impl SessionState {
    /// Stable, lowercase machine name — used in `tracing` fields and doubles
    /// as a natural value for [`crate::history::SessionRecord::state`].
    pub fn label(&self) -> &'static str {
        match self {
            SessionState::Idle => "idle",
            SessionState::Requesting => "requesting",
            SessionState::AwaitingApproval => "awaiting_approval",
            SessionState::Connecting => "connecting",
            SessionState::Active { .. } => "active",
            SessionState::Closing => "closing",
            SessionState::Closed => "closed",
            SessionState::Rejected { .. } => "rejected",
            SessionState::Failed { .. } => "failed",
        }
    }

    /// True for the three states nothing can leave: [`Self::Closed`],
    /// [`Self::Rejected`], [`Self::Failed`].
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SessionState::Closed | SessionState::Rejected { .. } | SessionState::Failed { .. }
        )
    }

    /// Whether `to` is a legal next state from `self`. Pure and side-effect
    /// free so the graph itself can be unit-tested without building a full
    /// [`Session`].
    pub fn can_transition_to(&self, to: &SessionState) -> bool {
        use SessionState::*;
        matches!(
            (self, to),
            (Idle, Requesting)
                | (Requesting, AwaitingApproval)
                | (AwaitingApproval, Connecting)
                | (Requesting, Rejected { .. })
                | (AwaitingApproval, Rejected { .. })
                | (Connecting, Rejected { .. })
                | (Connecting, Active { .. })
                | (Active { .. }, Closing)
                | (Closing, Closed)
                | (Idle, Failed { .. })
                | (Requesting, Failed { .. })
                | (AwaitingApproval, Failed { .. })
                | (Connecting, Failed { .. })
                | (Active { .. }, Failed { .. })
                | (Closing, Failed { .. })
        )
    }
}

/// A remote-desktop session, from either role's point of view (viewer or
/// host use the same shape; only which side calls which methods differs).
#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub id: SessionId,
    pub peer: DeviceInfo,
    /// What was asked for.
    pub requested: Permissions,
    /// What the host actually granted, once known (spec §6: the host is
    /// always the authority and may grant less than `requested`). Mirrors
    /// the payload carried by [`SessionState::Active`], but stays populated
    /// through `Closing`/`Closed` for reporting/history purposes.
    pub granted: Option<Permissions>,
    pub quality: QualityProfile,
    pub stats: Option<SessionStats>,
    pub created_at: u64,
    pub updated_at: u64,
    state: SessionState,
}

impl Session {
    /// A brand-new session in [`SessionState::Idle`].
    pub fn new(
        id: SessionId,
        peer: DeviceInfo,
        requested: Permissions,
        quality: QualityProfile,
    ) -> Self {
        let now = unix_now();
        Self {
            id,
            peer,
            requested,
            granted: None,
            quality,
            stats: None,
            created_at: now,
            updated_at: now,
            state: SessionState::Idle,
        }
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// `Idle` -> `Requesting`.
    pub fn request(&mut self) -> Result<()> {
        self.set_state(SessionState::Requesting)
    }

    /// `Requesting` -> `AwaitingApproval`.
    pub fn await_approval(&mut self) -> Result<()> {
        self.set_state(SessionState::AwaitingApproval)
    }

    /// `AwaitingApproval` -> `Connecting`. Records the granted permission set
    /// (spec §6); it need not equal `requested`.
    pub fn accept(&mut self, granted: Permissions) -> Result<()> {
        self.set_state(SessionState::Connecting)?;
        self.granted = Some(granted);
        Ok(())
    }

    /// `Requesting` | `AwaitingApproval` | `Connecting` -> `Rejected`.
    pub fn reject(&mut self, reason: impl Into<String>) -> Result<()> {
        self.set_state(SessionState::Rejected {
            reason: reason.into(),
        })
    }

    /// `Connecting` -> `Active`. Errors with
    /// [`CoreError::MissingGrantedPermissions`] if called before
    /// [`Self::accept`] recorded a granted set.
    pub fn activate(&mut self) -> Result<()> {
        let granted = self.granted.ok_or(CoreError::MissingGrantedPermissions)?;
        self.set_state(SessionState::Active { granted })
    }

    /// `Active` -> `Closing`: graceful teardown requested (spec §28).
    pub fn close(&mut self) -> Result<()> {
        self.set_state(SessionState::Closing)
    }

    /// `Closing` -> `Closed`: teardown complete.
    pub fn finish(&mut self) -> Result<()> {
        self.set_state(SessionState::Closed)
    }

    /// Any non-terminal state (including `Idle`) -> `Failed`.
    pub fn fail(&mut self, reason: impl Into<String>) -> Result<()> {
        self.set_state(SessionState::Failed {
            reason: reason.into(),
        })
    }

    /// Live permission change while [`SessionState::Active`] (spec §6:
    /// permissions may be tightened or loosened mid-session). Updates both
    /// the state's own payload and the mirrored [`Self::granted`] field;
    /// does not otherwise move the lifecycle state.
    pub fn update_granted(&mut self, granted: Permissions) -> Result<()> {
        if !matches!(self.state, SessionState::Active { .. }) {
            return Err(CoreError::Other(format!(
                "cannot update granted permissions while session is {}",
                self.state.label()
            )));
        }
        tracing::info!(session_id = %self.id, ?granted, "live permission update");
        self.state = SessionState::Active { granted };
        self.granted = Some(granted);
        self.updated_at = unix_now();
        Ok(())
    }

    pub fn update_stats(&mut self, stats: SessionStats) {
        self.stats = Some(stats);
        self.updated_at = unix_now();
    }

    pub fn set_quality(&mut self, quality: QualityProfile) {
        self.quality = quality;
        self.updated_at = unix_now();
    }

    fn set_state(&mut self, new: SessionState) -> Result<()> {
        if !self.state.can_transition_to(&new) {
            tracing::warn!(
                session_id = %self.id,
                from = self.state.label(),
                attempted = new.label(),
                "illegal session state transition"
            );
            return Err(CoreError::IllegalTransition {
                from: self.state.label(),
                attempted: new.label(),
            });
        }
        tracing::info!(session_id = %self.id, from = self.state.label(), to = new.label(), "session state transition");
        self.state = new;
        self.updated_at = unix_now();
        Ok(())
    }
}

/// Live enforcement of the permissions granted to the other side of a
/// session (spec §6). Kept separate from [`Session`] so hot paths — checking
/// a single incoming input event against the current grant — don't need to
/// touch the full lifecycle state machine, just this small `Copy` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionManager {
    granted: Permissions,
}

impl PermissionManager {
    pub fn new(granted: Permissions) -> Self {
        Self { granted }
    }

    /// The permission set currently in force.
    pub fn granted(&self) -> Permissions {
        self.granted
    }

    /// True when every bit in `required` is currently granted.
    pub fn check(&self, required: Permissions) -> bool {
        self.granted.allows(required)
    }

    /// Replace the granted set, e.g. on receiving
    /// `SessionMessage::PermissionsUpdate`. Permissions change live — the
    /// next [`Self::check`] immediately reflects the new set.
    pub fn update(&mut self, new_granted: Permissions) {
        tracing::info!(?new_granted, previous = ?self.granted, "permission manager updated");
        self.granted = new_granted;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rotodesk_proto::RotoDeskId;

    fn peer() -> DeviceInfo {
        DeviceInfo {
            id: RotoDeskId::new(548_291_743).unwrap(),
            alias: None,
            hostname: "REMOTE-PC".into(),
            os: "Windows 11 Pro".into(),
            app_version: "0.1.0".into(),
        }
    }

    fn new_session() -> Session {
        Session::new(
            SessionId::new_v4(),
            peer(),
            Permissions::interactive(),
            QualityProfile::Auto,
        )
    }

    #[test]
    fn happy_path_transitions_succeed() {
        let mut s = new_session();
        assert_eq!(s.state(), &SessionState::Idle);

        s.request().unwrap();
        assert_eq!(s.state(), &SessionState::Requesting);

        s.await_approval().unwrap();
        assert_eq!(s.state(), &SessionState::AwaitingApproval);

        s.accept(Permissions::VIEW_ONLY).unwrap();
        assert_eq!(s.state(), &SessionState::Connecting);
        assert_eq!(s.granted, Some(Permissions::VIEW_ONLY));

        s.activate().unwrap();
        assert_eq!(
            s.state(),
            &SessionState::Active {
                granted: Permissions::VIEW_ONLY
            }
        );

        s.close().unwrap();
        assert_eq!(s.state(), &SessionState::Closing);

        s.finish().unwrap();
        assert_eq!(s.state(), &SessionState::Closed);
        assert!(s.is_terminal());
    }

    #[test]
    fn rejection_is_terminal_from_awaiting_approval() {
        let mut s = new_session();
        s.request().unwrap();
        s.await_approval().unwrap();
        s.reject("user declined").unwrap();

        assert!(s.is_terminal());
        assert!(
            matches!(s.state(), SessionState::Rejected { reason } if reason == "user declined")
        );
        assert!(
            s.request().is_err(),
            "nothing legally follows a terminal state"
        );
    }

    #[test]
    fn rejection_reachable_before_and_after_awaiting_approval() {
        // Requesting -> Rejected: the server answers `Busy`/`AuthFailed`
        // before the peer is ever shown the request.
        let mut s = new_session();
        s.request().unwrap();
        s.reject("busy").unwrap();
        assert!(matches!(s.state(), SessionState::Rejected { reason } if reason == "busy"));
        assert!(s.is_terminal());

        // Connecting -> Rejected: a late reject while negotiating transport.
        let mut s = new_session();
        s.request().unwrap();
        s.await_approval().unwrap();
        s.accept(Permissions::VIEW_ONLY).unwrap();
        s.reject("auth failed").unwrap();
        assert!(s.is_terminal());

        // Idle and Active cannot be rejected: nothing was asked yet, or the
        // request was already granted.
        let mut s = new_session();
        assert!(s.reject("nope").is_err());
        assert_eq!(s.state(), &SessionState::Idle);

        let mut s = new_session();
        s.request().unwrap();
        s.await_approval().unwrap();
        s.accept(Permissions::VIEW_ONLY).unwrap();
        s.activate().unwrap();
        assert!(s.reject("nope").is_err());
        assert!(matches!(s.state(), SessionState::Active { .. }));
    }

    #[test]
    fn fail_reachable_from_every_non_terminal_state() {
        // Idle -> Failed: e.g. the signaling connection could not even be
        // opened, so the request was never sent.
        let mut s = new_session();
        s.fail("signaling connect error").unwrap();
        assert!(s.is_terminal());
        assert!(s.request().is_err(), "nothing follows Failed");

        // Requesting -> Failed.
        let mut s = new_session();
        s.request().unwrap();
        s.fail("boom").unwrap();
        assert!(s.is_terminal());

        // AwaitingApproval -> Failed.
        let mut s = new_session();
        s.request().unwrap();
        s.await_approval().unwrap();
        s.fail("boom").unwrap();
        assert!(s.is_terminal());

        // Connecting -> Failed.
        let mut s = new_session();
        s.request().unwrap();
        s.await_approval().unwrap();
        s.accept(Permissions::VIEW_ONLY).unwrap();
        s.fail("boom").unwrap();
        assert!(s.is_terminal());

        // Active -> Failed.
        let mut s = new_session();
        s.request().unwrap();
        s.await_approval().unwrap();
        s.accept(Permissions::VIEW_ONLY).unwrap();
        s.activate().unwrap();
        s.fail("boom").unwrap();
        assert!(s.is_terminal());

        // Closing -> Failed.
        let mut s = new_session();
        s.request().unwrap();
        s.await_approval().unwrap();
        s.accept(Permissions::VIEW_ONLY).unwrap();
        s.activate().unwrap();
        s.close().unwrap();
        s.fail("boom").unwrap();
        assert!(s.is_terminal());

        // Terminal states cannot fail (again).
        let mut s = new_session();
        s.request().unwrap();
        s.await_approval().unwrap();
        s.reject("declined").unwrap();
        assert!(s.fail("boom").is_err());
        assert!(matches!(s.state(), SessionState::Rejected { .. }));
    }

    #[test]
    fn illegal_transitions_are_rejected_without_mutating_state() {
        let mut s = new_session();
        // Can't skip straight from Idle to Connecting.
        let err = s.accept(Permissions::VIEW_ONLY).unwrap_err();
        assert!(matches!(err, CoreError::IllegalTransition { .. }));
        assert_eq!(
            s.state(),
            &SessionState::Idle,
            "failed transition must not change state"
        );

        s.request().unwrap();
        // Can't activate before accept()/Connecting.
        assert!(s.activate().is_err());
        // Can't finish() before close().
        assert!(s.finish().is_err());
    }

    #[test]
    fn activate_requires_a_prior_accept() {
        let mut s = new_session();
        s.request().unwrap();
        s.await_approval().unwrap();
        s.accept(Permissions::VIEW_ONLY).unwrap();

        // A caller resetting the public `granted` field bypasses accept()'s
        // bookkeeping; activate() must still refuse rather than invent a
        // permission set.
        s.granted = None;
        assert!(matches!(
            s.activate(),
            Err(CoreError::MissingGrantedPermissions)
        ));
    }

    #[test]
    fn update_granted_only_while_active() {
        let mut s = new_session();
        assert!(s.update_granted(Permissions::full()).is_err());

        s.request().unwrap();
        s.await_approval().unwrap();
        s.accept(Permissions::VIEW_ONLY).unwrap();
        s.activate().unwrap();

        s.update_granted(Permissions::full()).unwrap();
        assert_eq!(
            s.state(),
            &SessionState::Active {
                granted: Permissions::full()
            }
        );
        assert_eq!(s.granted, Some(Permissions::full()));
    }

    #[test]
    fn permission_manager_check_reflects_update() {
        let mut pm = PermissionManager::new(Permissions::VIEW_ONLY);
        assert!(pm.check(Permissions::VIEW_SCREEN));
        assert!(!pm.check(Permissions::CONTROL_KEYBOARD));

        pm.update(Permissions::interactive());
        assert!(pm.check(Permissions::CONTROL_KEYBOARD));
        assert!(!pm.check(Permissions::ADMIN_ACTIONS));
    }
}
