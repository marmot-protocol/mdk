use cgka_traits::{
    PairingSessionDescriptor, PairingSessionError, PairingSessionId, PairingSessionState,
};
use std::collections::HashMap;
use x25519_dalek::ReusableSecret;
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PairingSessionTransition {
    pub previous_state: Option<PairingSessionState>,
    pub new_state: PairingSessionState,
    pub reason: &'static str,
    pub expires_at_ms: u64,
}

pub(crate) struct PairingOperation<T> {
    pub result: T,
    pub transitions: Vec<PairingSessionTransition>,
}

struct ActivePairingSession {
    descriptor: PairingSessionDescriptor,
    private_key: ReusableSecret,
    state: PairingSessionState,
}

impl ActivePairingSession {
    fn wipe_private_key(&mut self) {
        self.private_key.zeroize();
    }
}

impl Drop for ActivePairingSession {
    fn drop(&mut self) {
        self.wipe_private_key();
    }
}

impl zeroize::ZeroizeOnDrop for ActivePairingSession {}

#[derive(Clone, Copy)]
struct TerminalPairingSession {
    state: PairingSessionState,
    expires_at_ms: u64,
}

#[derive(Default)]
pub(crate) struct PairingSessionManager {
    active: Option<ActivePairingSession>,
    terminal: HashMap<PairingSessionId, TerminalPairingSession>,
}

impl PairingSessionManager {
    pub fn contains(&self, session_id: &PairingSessionId) -> bool {
        self.active
            .as_ref()
            .is_some_and(|session| session.descriptor.session_id == *session_id)
            || self.terminal.contains_key(session_id)
    }

    pub fn start(
        &mut self,
        descriptor: PairingSessionDescriptor,
        private_key: ReusableSecret,
        now_ms: u64,
    ) -> PairingOperation<PairingSessionDescriptor> {
        self.prune_terminal(now_ms);
        let mut transitions = self.expire_active_if_due(now_ms);
        if self.active.is_some() {
            transitions.push(
                self.terminalize_active(PairingSessionState::Superseded, "new_session_started"),
            );
        }

        let returned_descriptor = descriptor.clone();
        transitions.push(PairingSessionTransition {
            previous_state: None,
            new_state: PairingSessionState::Active,
            reason: "started",
            expires_at_ms: descriptor.expires_at_ms,
        });
        self.active = Some(ActivePairingSession {
            descriptor,
            private_key,
            state: PairingSessionState::Active,
        });
        PairingOperation {
            result: returned_descriptor,
            transitions,
        }
    }

    pub fn state(
        &mut self,
        session_id: &PairingSessionId,
        now_ms: u64,
    ) -> PairingOperation<Result<PairingSessionState, PairingSessionError>> {
        let transitions = self.expire_active_if_due(now_ms);
        self.prune_terminal(now_ms);
        let result = if let Some(active) = self
            .active
            .as_ref()
            .filter(|session| session.descriptor.session_id == *session_id)
        {
            Ok(active.state)
        } else if let Some(terminal) = self.terminal.get(session_id) {
            Ok(terminal.state)
        } else {
            // Sessions are intentionally process-local. After restart there is
            // nothing to rehydrate, so any missing bearer capability fails
            // closed as expired rather than entering an ambiguous state.
            Err(PairingSessionError::Expired)
        };
        PairingOperation {
            result,
            transitions,
        }
    }

    pub fn scan(
        &mut self,
        session_id: &PairingSessionId,
        now_ms: u64,
    ) -> PairingOperation<Result<(), PairingSessionError>> {
        let mut transitions = self.expire_active_if_due(now_ms);
        self.prune_terminal(now_ms);
        let result = if let Some(active) = self
            .active
            .as_mut()
            .filter(|session| session.descriptor.session_id == *session_id)
        {
            match active.state {
                PairingSessionState::Active => {
                    active.state = PairingSessionState::Scanned;
                    transitions.push(PairingSessionTransition {
                        previous_state: Some(PairingSessionState::Active),
                        new_state: PairingSessionState::Scanned,
                        reason: "qr_scanned",
                        expires_at_ms: active.descriptor.expires_at_ms,
                    });
                    Ok(())
                }
                PairingSessionState::Scanned => Err(PairingSessionError::AlreadyScanned),
                _ => unreachable!("active slot contains only non-terminal states"),
            }
        } else if let Some(terminal) = self.terminal.get(session_id) {
            Err(error_for_terminal_state(terminal.state))
        } else {
            Err(PairingSessionError::Expired)
        };
        PairingOperation {
            result,
            transitions,
        }
    }

    pub fn approve(
        &mut self,
        session_id: &PairingSessionId,
        now_ms: u64,
    ) -> PairingOperation<Result<(), PairingSessionError>> {
        self.finish_scanned(
            session_id,
            now_ms,
            PairingSessionState::Approved,
            "local_user_approved",
        )
    }

    pub fn reject(
        &mut self,
        session_id: &PairingSessionId,
        now_ms: u64,
    ) -> PairingOperation<Result<(), PairingSessionError>> {
        self.finish_scanned(
            session_id,
            now_ms,
            PairingSessionState::Rejected,
            "local_user_rejected",
        )
    }

    fn finish_scanned(
        &mut self,
        session_id: &PairingSessionId,
        now_ms: u64,
        terminal_state: PairingSessionState,
        reason: &'static str,
    ) -> PairingOperation<Result<(), PairingSessionError>> {
        let mut transitions = self.expire_active_if_due(now_ms);
        self.prune_terminal(now_ms);
        let active_state = self
            .active
            .as_ref()
            .filter(|session| session.descriptor.session_id == *session_id)
            .map(|session| session.state);
        let result = match active_state {
            Some(PairingSessionState::Scanned) => {
                transitions.push(self.terminalize_active(terminal_state, reason));
                Ok(())
            }
            Some(PairingSessionState::Active) => Err(PairingSessionError::NotScanned),
            Some(_) => unreachable!("active slot contains only non-terminal states"),
            None => self
                .terminal
                .get(session_id)
                .map(|terminal| Err(error_for_terminal_state(terminal.state)))
                .unwrap_or(Err(PairingSessionError::Expired)),
        };
        PairingOperation {
            result,
            transitions,
        }
    }

    fn expire_active_if_due(&mut self, now_ms: u64) -> Vec<PairingSessionTransition> {
        if self
            .active
            .as_ref()
            .is_some_and(|session| now_ms >= session.descriptor.expires_at_ms)
        {
            vec![self.terminalize_active(PairingSessionState::Expired, "ttl_elapsed")]
        } else {
            Vec::new()
        }
    }

    fn terminalize_active(
        &mut self,
        state: PairingSessionState,
        reason: &'static str,
    ) -> PairingSessionTransition {
        debug_assert!(state.is_terminal());
        let active = self.active.as_mut().expect("active pairing session");
        let previous_state = active.state;
        let session_id = active.descriptor.session_id.clone();
        let expires_at_ms = active.descriptor.expires_at_ms;
        // Wipe the original in-place before moving/dropping the session. This
        // avoids leaving key bytes in the vacated `Option` payload.
        active.wipe_private_key();
        let retired = self.active.take().expect("active pairing session");
        drop(retired);
        self.terminal.insert(
            session_id,
            TerminalPairingSession {
                state,
                expires_at_ms,
            },
        );
        PairingSessionTransition {
            previous_state: Some(previous_state),
            new_state: state,
            reason,
            expires_at_ms,
        }
    }

    fn prune_terminal(&mut self, now_ms: u64) {
        self.terminal
            .retain(|_, session| now_ms < session.expires_at_ms);
    }
}

fn error_for_terminal_state(state: PairingSessionState) -> PairingSessionError {
    match state {
        PairingSessionState::Approved => PairingSessionError::AlreadyAccepted,
        PairingSessionState::Expired => PairingSessionError::Expired,
        PairingSessionState::Superseded => PairingSessionError::Superseded,
        PairingSessionState::Rejected => PairingSessionError::Rejected,
        PairingSessionState::Active | PairingSessionState::Scanned => {
            unreachable!("terminal map contains only terminal states")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_key_wipe_overwrites_private_material_in_place() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ActivePairingSession>();

        let mut session = ActivePairingSession {
            descriptor: PairingSessionDescriptor {
                session_id: PairingSessionId::new([1; 32]),
                ephemeral_public_key: [2; 32],
                expires_at_ms: 30_000,
            },
            private_key: ReusableSecret::random_from_rng(rand::rngs::OsRng),
            state: PairingSessionState::Scanned,
        };

        session.wipe_private_key();

        let public_after_wipe = x25519_dalek::PublicKey::from(&session.private_key);
        assert_eq!(
            public_after_wipe.as_bytes(),
            &x25519_dalek::x25519([0; 32], x25519_dalek::X25519_BASEPOINT_BYTES)
        );
    }
}
