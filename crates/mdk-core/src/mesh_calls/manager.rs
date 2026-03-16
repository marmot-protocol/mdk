//! Mesh Call Manager
//!
//! The main API for managing mesh calls. Handles call state, signaling,
//! WebRTC connections, and SFrame encryption.

use std::collections::HashMap;
use std::sync::Arc;

use nostr::{Event, PublicKey};
use tokio::sync::{mpsc, RwLock};

use crate::GroupId;
use super::signaling::{
    CallAnswerEvent, CallInitiationEvent, CallStateUpdateEvent, ICECandidateEvent,
    WebRTCSessionEvent, KIND_CALL_ANSWER, KIND_CALL_INITIATION, KIND_CALL_STATE_UPDATE,
    KIND_ICE_CANDIDATE, KIND_WEBRTC_SESSION,
};
use super::sframe::{derive_sframe_base_key, derive_sframe_key, SFrameContext};
use super::types::{
    CallAction, CallAnswer, CallAnswerStatus, CallId, CallInitiation, CallParticipant, CallState,
    CallType, ICECandidate, MediaType, MeshCallError, SFrameBits,
    SessionDescriptionType, WebRTCSessionDescription,
};
use super::webrtc::{IceTransportPolicy, WebRTCConfig, WebRTCPeerManager};

/// Timeout for ringing state before auto-ending
const RING_TIMEOUT_SECS: u64 = 30;
/// Timeout for setup state before auto-ending
const SETUP_TIMEOUT_SECS: u64 = 10;
/// Interval at which the cleanup task runs
const CLEANUP_INTERVAL_SECS: u64 = 5;

/// Information about an active call
#[derive(Debug, Clone)]
pub struct ActiveCall {
    /// Call ID
    pub call_id: CallId,
    /// MLS group ID
    pub group_id: GroupId,
    /// Call type
    pub call_type: CallType,
    /// Current state
    pub state: CallState,
    /// Participants in the call
    pub participants: Vec<CallParticipant>,
    /// SFrame bits configuration
    pub sframe_bits: SFrameBits,
    /// Own leaf index in MLS tree
    pub own_leaf_index: u32,
    /// SFrame context for encryption/decryption
    pub sframe_context: Arc<RwLock<SFrameContext>>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last state change timestamp
    pub state_changed_at: u64,
}

/// Outbound signaling event to be sent via MLS application message
#[derive(Debug, Clone)]
pub enum OutboundSignaling {
    /// Kind 450: Call Initiation
    Initiation(CallInitiationEvent),
    /// Kind 451: Call Answer
    Answer(CallAnswerEvent),
    /// Kind 452: WebRTC Session Description
    SessionDescription(WebRTCSessionEvent),
    /// Kind 453: ICE Candidate
    ICECandidate(ICECandidateEvent),
    /// Kind 454: Call State Update
    StateUpdate(CallStateUpdateEvent),
}

/// Callback for call events
pub trait CallEventCallback: Send + Sync {
    /// Called when a call is initiated
    fn on_call_initiated(&self, call: &ActiveCall);
    /// Called when a call is answered
    fn on_call_answered(&self, call_id: &CallId, status: CallAnswerStatus);
    /// Called when a participant joins
    fn on_participant_joined(&self, call_id: &CallId, participant: &CallParticipant);
    /// Called when a participant leaves
    fn on_participant_left(&self, call_id: &CallId, pubkey: &PublicKey);
    /// Called when media state changes
    fn on_media_state_changed(
        &self,
        call_id: &CallId,
        pubkey: &PublicKey,
        audio_muted: bool,
        video_muted: bool,
    );
    /// Called when ICE candidate is received
    fn on_ice_candidate(&self, call_id: &CallId, from_leaf: u32, candidate: &ICECandidate);
    /// Called when SDP offer/answer is received
    fn on_session_description(
        &self,
        call_id: &CallId,
        from_leaf: u32,
        desc: &WebRTCSessionDescription,
    );
    /// Called when call state changes
    fn on_call_state_changed(&self, call_id: &CallId, state: CallState);
    /// Called on error
    fn on_error(&self, call_id: Option<&CallId>, error: &MeshCallError);
}

/// Manager for mesh calls
pub struct MeshCallManager {
    /// Active calls by call ID
    active_calls: Arc<RwLock<HashMap<CallId, ActiveCall>>>,
    /// Active calls by group ID (maps group_id to call_id)
    group_calls: Arc<RwLock<HashMap<GroupId, CallId>>>,
    /// WebRTC peer managers by call ID
    peer_managers: Arc<RwLock<HashMap<CallId, Arc<WebRTCPeerManager>>>>,
    /// Callback for events
    callback: Option<Arc<dyn CallEventCallback>>,
    /// Outbound signaling channel
    signaling_tx: mpsc::UnboundedSender<OutboundSignaling>,
    /// Outbound signaling receiver (consumed by the application)
    signaling_rx: Arc<RwLock<mpsc::UnboundedReceiver<OutboundSignaling>>>,
    /// Shutdown signal for cleanup task
    cleanup_shutdown: Arc<tokio::sync::Notify>,
}

impl MeshCallManager {
    /// Create a new mesh call manager
    pub fn new() -> Self {
        let (signaling_tx, signaling_rx) = mpsc::unbounded_channel();
        let cleanup_shutdown = Arc::new(tokio::sync::Notify::new());

        let manager = Self {
            active_calls: Arc::new(RwLock::new(HashMap::new())),
            group_calls: Arc::new(RwLock::new(HashMap::new())),
            peer_managers: Arc::new(RwLock::new(HashMap::new())),
            callback: None,
            signaling_tx,
            signaling_rx: Arc::new(RwLock::new(signaling_rx)),
            cleanup_shutdown: cleanup_shutdown.clone(),
        };

        // Spawn cleanup task for call timeouts
        manager.spawn_cleanup_task();

        manager
    }

    /// Set callback for call events
    pub fn with_callback(mut self, callback: Arc<dyn CallEventCallback>) -> Self {
        self.callback = Some(callback);
        self
    }

    /// Receive the next outbound signaling event.
    /// The application should send these as MLS application messages (kind:445).
    pub async fn recv_signaling(&self) -> Option<OutboundSignaling> {
        self.signaling_rx.write().await.recv().await
    }

    /// Spawn the cleanup task that enforces call timeouts
    fn spawn_cleanup_task(&self) {
        let active_calls = self.active_calls.clone();
        let group_calls = self.group_calls.clone();
        let peer_managers = self.peer_managers.clone();
        let callback = self.callback.clone();
        let shutdown = self.cleanup_shutdown.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(CLEANUP_INTERVAL_SECS)) => {
                        Self::run_cleanup(
                            &active_calls,
                            &group_calls,
                            &peer_managers,
                            &callback,
                        ).await;
                    }
                    _ = shutdown.notified() => {
                        break;
                    }
                }
            }
        });
    }

    /// Check for timed-out calls and clean them up
    async fn run_cleanup(
        active_calls: &Arc<RwLock<HashMap<CallId, ActiveCall>>>,
        group_calls: &Arc<RwLock<HashMap<GroupId, CallId>>>,
        peer_managers: &Arc<RwLock<HashMap<CallId, Arc<WebRTCPeerManager>>>>,
        callback: &Option<Arc<dyn CallEventCallback>>,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut timed_out = Vec::new();

        {
            let calls = active_calls.read().await;
            for (call_id, call) in calls.iter() {
                let elapsed = now.saturating_sub(call.state_changed_at);
                let should_timeout = match call.state {
                    CallState::Setup => elapsed > SETUP_TIMEOUT_SECS,
                    CallState::Ringing => elapsed > RING_TIMEOUT_SECS,
                    _ => false,
                };
                if should_timeout {
                    timed_out.push(*call_id);
                }
            }
        }

        for call_id in timed_out {
            tracing::info!("Call {} timed out, cleaning up", call_id.to_hex());

            // Remove from active calls
            let call = active_calls.write().await.remove(&call_id);
            if let Some(call) = &call {
                group_calls.write().await.remove(&call.group_id);
            }

            // Close WebRTC connections
            if let Some(pm) = peer_managers.write().await.remove(&call_id) {
                let _ = pm.close_all().await;
            }

            if let Some(cb) = callback {
                cb.on_call_state_changed(&call_id, CallState::Ended);
            }
        }

        // Prune old SFrame keys from active calls
        {
            let calls = active_calls.read().await;
            for call in calls.values() {
                call.sframe_context.write().await.prune_old_keys();
            }
        }
    }

    /// Initiate a new call
    pub async fn initiate_call(
        &self,
        group_id: &GroupId,
        initiation: CallInitiation,
        own_pubkey: &PublicKey,
        own_leaf_index: u32,
        call_base_key: &[u8; 32],
    ) -> Result<CallId, MeshCallError> {
        // Check if group already has an active call
        if self.group_calls.read().await.contains_key(group_id) {
            return Err(MeshCallError::CallAlreadyExists);
        }

        let call_id = CallId::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create SFrame context and derive keys for own sender
        let mut sframe_context = SFrameContext::new(initiation.sframe_bits, own_leaf_index);
        for media_type in [MediaType::Audio, MediaType::Video] {
            let base_key = derive_sframe_base_key(call_base_key, media_type, own_leaf_index)?;
            let kid = initiation.sframe_bits.make_kid(media_type, own_leaf_index, 0);
            let sframe_key = derive_sframe_key(&base_key, kid)?;
            sframe_context.set_key(media_type, sframe_key);
        }

        let active_call = ActiveCall {
            call_id,
            group_id: group_id.clone(),
            call_type: initiation.call_type,
            state: CallState::Setup,
            participants: vec![CallParticipant {
                pubkey: *own_pubkey,
                leaf_index: own_leaf_index,
                audio_muted: false,
                video_muted: false,
                screen_sharing: false,
                is_speaking: false,
            }],
            sframe_bits: initiation.sframe_bits,
            own_leaf_index,
            sframe_context: Arc::new(RwLock::new(sframe_context)),
            created_at: now,
            state_changed_at: now,
        };

        // Store active call
        self.active_calls
            .write()
            .await
            .insert(call_id, active_call.clone());
        self.group_calls
            .write()
            .await
            .insert(group_id.clone(), call_id);

        // Create WebRTC peer manager
        let mut ice_servers = vec!["stun:stun.l.google.com:19302".to_string()];
        let mut ice_policy = IceTransportPolicy::All;

        if let Some(ref uri) = initiation.turn_uri {
            ice_servers.push(uri.clone());
            ice_policy = IceTransportPolicy::Relay;
        }

        let webrtc_config = WebRTCConfig {
            ice_servers,
            bundle: true,
            ice_transport_policy: ice_policy,
        };
        let peer_manager = Arc::new(WebRTCPeerManager::new(webrtc_config));
        self.peer_managers
            .write()
            .await
            .insert(call_id, peer_manager);

        // Notify callback
        if let Some(callback) = &self.callback {
            callback.on_call_initiated(&active_call);
        }

        // Produce kind 450 signaling event
        let sframe_bits_value =
            initiation.sframe_bits.epoch_bits + initiation.sframe_bits.sender_bits;
        let signaling_event = CallInitiationEvent::new(
            own_pubkey,
            &call_id,
            initiation.call_type,
            sframe_bits_value,
            initiation.turn_uri.as_deref(),
            initiation.turn_username.as_deref(),
            initiation.turn_credential.as_deref(),
        );
        let _ = self
            .signaling_tx
            .send(OutboundSignaling::Initiation(signaling_event));

        // Transition to ringing state
        self.update_call_state(&call_id, CallState::Ringing).await?;

        Ok(call_id)
    }

    /// Answer a call
    pub async fn answer_call(
        &self,
        call_id: &CallId,
        answer: CallAnswer,
        own_pubkey: &PublicKey,
        own_leaf_index: u32,
        call_base_key: &[u8; 32],
    ) -> Result<(), MeshCallError> {
        let active_call = self
            .active_calls
            .read()
            .await
            .get(call_id)
            .cloned()
            .ok_or(MeshCallError::CallNotFound)?;

        // Produce kind 451 signaling event
        let signaling_event = CallAnswerEvent::new(
            own_pubkey,
            call_id,
            answer.status,
            answer.reason.as_deref(),
        );
        let _ = self
            .signaling_tx
            .send(OutboundSignaling::Answer(signaling_event));

        match answer.status {
            CallAnswerStatus::Accept => {
                // Setup SFrame context
                let mut sframe_context =
                    SFrameContext::new(active_call.sframe_bits, own_leaf_index);

                for media_type in [MediaType::Audio, MediaType::Video] {
                    let base_key =
                        derive_sframe_base_key(call_base_key, media_type, own_leaf_index)?;
                    let kid =
                        active_call
                            .sframe_bits
                            .make_kid(media_type, own_leaf_index, 0);
                    let sframe_key = derive_sframe_key(&base_key, kid)?;
                    sframe_context.set_key(media_type, sframe_key);
                }

                // Also derive keys for existing participants so we can decrypt their frames
                for participant in &active_call.participants {
                    for media_type in [MediaType::Audio, MediaType::Video] {
                        let base_key = derive_sframe_base_key(
                            call_base_key,
                            media_type,
                            participant.leaf_index,
                        )?;
                        let kid = active_call.sframe_bits.make_kid(
                            media_type,
                            participant.leaf_index,
                            0,
                        );
                        let sframe_key = derive_sframe_key(&base_key, kid)?;
                        sframe_context.set_remote_key(
                            media_type,
                            0,
                            participant.leaf_index,
                            sframe_key,
                        );
                    }
                }

                // Update active call
                {
                    let mut calls = self.active_calls.write().await;
                    if let Some(call) = calls.get_mut(call_id) {
                        call.participants.push(CallParticipant {
                            pubkey: *own_pubkey,
                            leaf_index: own_leaf_index,
                            audio_muted: false,
                            video_muted: false,
                            screen_sharing: false,
                            is_speaking: false,
                        });
                        call.sframe_context = Arc::new(RwLock::new(sframe_context));
                    }
                }

                self.update_call_state(call_id, CallState::Active).await?;

                if let Some(callback) = &self.callback {
                    callback.on_call_answered(call_id, answer.status);
                }
            }
            CallAnswerStatus::Decline | CallAnswerStatus::Busy => {
                if let Some(callback) = &self.callback {
                    callback.on_call_answered(call_id, answer.status);
                }
            }
        }

        Ok(())
    }

    /// End a call
    pub async fn end_call(
        &self,
        call_id: &CallId,
        own_pubkey: &PublicKey,
    ) -> Result<(), MeshCallError> {
        let active_call = self
            .active_calls
            .read()
            .await
            .get(call_id)
            .cloned()
            .ok_or(MeshCallError::CallNotFound)?;

        // Produce kind 454 signaling event
        let signaling_event =
            CallStateUpdateEvent::new(own_pubkey, call_id, CallAction::End, None);
        let _ = self
            .signaling_tx
            .send(OutboundSignaling::StateUpdate(signaling_event));

        self.update_call_state(call_id, CallState::Ending).await?;

        // Close all WebRTC connections
        if let Some(peer_manager) = self.peer_managers.write().await.remove(call_id) {
            peer_manager.close_all().await?;
        }

        // Remove from active calls
        self.active_calls.write().await.remove(call_id);
        self.group_calls
            .write()
            .await
            .remove(&active_call.group_id);

        if let Some(callback) = &self.callback {
            callback.on_call_state_changed(call_id, CallState::Ended);
        }

        Ok(())
    }

    /// Send a WebRTC SDP offer/answer for a specific peer
    pub async fn send_session_description(
        &self,
        call_id: &CallId,
        own_pubkey: &PublicKey,
        desc: &WebRTCSessionDescription,
    ) -> Result<(), MeshCallError> {
        self.active_calls
            .read()
            .await
            .get(call_id)
            .ok_or(MeshCallError::CallNotFound)?;

        let signaling_event = WebRTCSessionEvent::new(
            own_pubkey,
            call_id,
            desc.sdp_type,
            desc.sdp.clone(),
            desc.target_leaf,
        );
        let _ = self
            .signaling_tx
            .send(OutboundSignaling::SessionDescription(signaling_event));

        Ok(())
    }

    /// Send an ICE candidate for a specific peer
    pub async fn send_ice_candidate(
        &self,
        call_id: &CallId,
        own_pubkey: &PublicKey,
        candidate: &ICECandidate,
    ) -> Result<(), MeshCallError> {
        self.active_calls
            .read()
            .await
            .get(call_id)
            .ok_or(MeshCallError::CallNotFound)?;

        let signaling_event = ICECandidateEvent::new(
            own_pubkey,
            call_id,
            candidate.candidate.clone(),
            candidate.target_leaf,
        );
        let _ = self
            .signaling_tx
            .send(OutboundSignaling::ICECandidate(signaling_event));

        Ok(())
    }

    /// Encrypt a media frame using SFrame
    pub async fn encrypt_media(
        &self,
        call_id: &CallId,
        media_type: MediaType,
        plaintext: &[u8],
        metadata: &[u8],
    ) -> Result<Vec<u8>, MeshCallError> {
        let call = self
            .active_calls
            .read()
            .await
            .get(call_id)
            .cloned()
            .ok_or(MeshCallError::CallNotFound)?;

        call.sframe_context
            .write()
            .await
            .encrypt(media_type, plaintext, metadata)
    }

    /// Decrypt a media frame using SFrame
    pub async fn decrypt_media(
        &self,
        call_id: &CallId,
        frame: &[u8],
        metadata: &[u8],
    ) -> Result<(MediaType, Vec<u8>), MeshCallError> {
        let call = self
            .active_calls
            .read()
            .await
            .get(call_id)
            .cloned()
            .ok_or(MeshCallError::CallNotFound)?;

        call.sframe_context.write().await.decrypt(frame, metadata)
    }

    /// Handle an MLS epoch change: re-derive keys for all participants
    pub async fn handle_epoch_change(
        &self,
        call_id: &CallId,
        new_epoch: u8,
        call_base_key: &[u8; 32],
    ) -> Result<(), MeshCallError> {
        let call = self
            .active_calls
            .read()
            .await
            .get(call_id)
            .cloned()
            .ok_or(MeshCallError::CallNotFound)?;

        let mut sframe_ctx = call.sframe_context.write().await;
        sframe_ctx.epoch_transition(new_epoch);

        // Re-derive keys for own sender
        for media_type in [MediaType::Audio, MediaType::Video] {
            let base_key =
                derive_sframe_base_key(call_base_key, media_type, call.own_leaf_index)?;
            let kid = call
                .sframe_bits
                .make_kid(media_type, call.own_leaf_index, new_epoch);
            let sframe_key = derive_sframe_key(&base_key, kid)?;
            sframe_ctx.set_key(media_type, sframe_key);
        }

        // Re-derive keys for all other participants
        for participant in &call.participants {
            if participant.leaf_index == call.own_leaf_index {
                continue;
            }
            for media_type in [MediaType::Audio, MediaType::Video] {
                let base_key =
                    derive_sframe_base_key(call_base_key, media_type, participant.leaf_index)?;
                let kid = call
                    .sframe_bits
                    .make_kid(media_type, participant.leaf_index, new_epoch);
                let sframe_key = derive_sframe_key(&base_key, kid)?;
                sframe_ctx.set_remote_key(media_type, new_epoch, participant.leaf_index, sframe_key);
            }
        }

        tracing::info!(
            "Epoch rotated to {} for call {}",
            new_epoch,
            call_id.to_hex()
        );

        Ok(())
    }

    /// Add a remote participant's SFrame keys (e.g., after they join)
    pub async fn add_participant_keys(
        &self,
        call_id: &CallId,
        participant_pubkey: &PublicKey,
        participant_leaf: u32,
        call_base_key: &[u8; 32],
    ) -> Result<(), MeshCallError> {
        let call = self
            .active_calls
            .read()
            .await
            .get(call_id)
            .cloned()
            .ok_or(MeshCallError::CallNotFound)?;

        let mut sframe_ctx = call.sframe_context.write().await;

        let current_epoch = sframe_ctx.epoch;
        for media_type in [MediaType::Audio, MediaType::Video] {
            let base_key =
                derive_sframe_base_key(call_base_key, media_type, participant_leaf)?;
            let kid = call
                .sframe_bits
                .make_kid(media_type, participant_leaf, current_epoch);
            let sframe_key = derive_sframe_key(&base_key, kid)?;
            sframe_ctx.set_remote_key(media_type, current_epoch, participant_leaf, sframe_key);
        }

        // Add to participants list
        {
            let mut calls = self.active_calls.write().await;
            if let Some(call) = calls.get_mut(call_id) {
                if !call.participants.iter().any(|p| p.leaf_index == participant_leaf) {
                    call.participants.push(CallParticipant {
                        pubkey: *participant_pubkey,
                        leaf_index: participant_leaf,
                        audio_muted: false,
                        video_muted: false,
                        screen_sharing: false,
                        is_speaking: false,
                    });

                    if let Some(cb) = &self.callback {
                        cb.on_participant_joined(
                            call_id,
                            call.participants.last().unwrap(),
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Update call state and notify
    async fn update_call_state(
        &self,
        call_id: &CallId,
        state: CallState,
    ) -> Result<(), MeshCallError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        {
            let mut calls = self.active_calls.write().await;
            if let Some(call) = calls.get_mut(call_id) {
                call.state = state;
                call.state_changed_at = now;
            }
        }

        if let Some(callback) = &self.callback {
            callback.on_call_state_changed(call_id, state);
        }

        Ok(())
    }

    /// Process an incoming signaling event
    /// This should be called when a kind:445 message is received with an inner call event
    pub async fn process_signaling_event(
        &self,
        event: Event,
        call_base_key: Option<&[u8; 32]>,
    ) -> Result<(), MeshCallError> {
        if event.kind == KIND_CALL_INITIATION {
            let initiation = parse_initiation_event(&event)?;
            self.handle_initiation(initiation, call_base_key).await?;
        } else if event.kind == KIND_CALL_ANSWER {
            let answer = parse_answer_event(&event)?;
            self.handle_answer(answer).await?;
        } else if event.kind == KIND_WEBRTC_SESSION {
            let session = parse_session_event(&event)?;
            self.handle_session_description(session).await?;
        } else if event.kind == KIND_ICE_CANDIDATE {
            let ice = parse_ice_event(&event)?;
            self.handle_ice_candidate(ice).await?;
        } else if event.kind == KIND_CALL_STATE_UPDATE {
            let update = parse_state_update_event(&event)?;
            self.handle_state_update(update).await?;
        } else {
            return Err(MeshCallError::Signaling(format!(
                "Unknown event kind: {}",
                event.kind
            )));
        }

        Ok(())
    }

    /// Handle incoming call initiation (kind 450)
    async fn handle_initiation(
        &self,
        event: CallInitiationEvent,
        _call_base_key: Option<&[u8; 32]>,
    ) -> Result<(), MeshCallError> {
        let call_id = event.get_call_id()?;
        let call_type = event.get_call_type()?;

        tracing::info!(
            "Received call initiation from {}: call_id={}, type={:?}",
            &event.pubkey[..8],
            &call_id.to_hex()[..16],
            call_type,
        );

        // Store as incoming call in Setup state (application decides whether to answer)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let caller_pubkey = PublicKey::from_hex(&event.pubkey)
            .map_err(|e| MeshCallError::Signaling(format!("Invalid pubkey: {}", e)))?;

        let sframe_bits_val = event.get_sframe_bits()?;
        let sframe_bits = SFrameBits::new(4, sframe_bits_val.saturating_sub(4));

        let sframe_context = SFrameContext::new(sframe_bits, 0); // own_leaf set later on answer

        let active_call = ActiveCall {
            call_id,
            group_id: GroupId::from_slice(&[]), // filled on answer
            call_type,
            state: CallState::Ringing,
            participants: vec![CallParticipant {
                pubkey: caller_pubkey,
                leaf_index: 0, // caller's leaf - will be resolved later
                audio_muted: false,
                video_muted: false,
                screen_sharing: false,
                is_speaking: false,
            }],
            sframe_bits,
            own_leaf_index: 0,
            sframe_context: Arc::new(RwLock::new(sframe_context)),
            created_at: now,
            state_changed_at: now,
        };

        self.active_calls
            .write()
            .await
            .insert(call_id, active_call.clone());

        if let Some(callback) = &self.callback {
            callback.on_call_initiated(&active_call);
        }

        Ok(())
    }

    /// Handle incoming call answer (kind 451)
    async fn handle_answer(&self, event: CallAnswerEvent) -> Result<(), MeshCallError> {
        let call_id = event.get_call_id()?;
        let status = event.get_status()?;

        tracing::info!(
            "Received call answer from {}: call_id={}, status={:?}",
            &event.pubkey[..8],
            &call_id.to_hex()[..16],
            status,
        );

        match status {
            CallAnswerStatus::Accept => {
                // Transition to active if we're the initiator
                let current_state = self
                    .active_calls
                    .read()
                    .await
                    .get(&call_id)
                    .map(|c| c.state);

                if current_state == Some(CallState::Ringing) {
                    self.update_call_state(&call_id, CallState::Active).await?;
                }
            }
            CallAnswerStatus::Decline | CallAnswerStatus::Busy => {
                // If all participants declined, end the call
                tracing::info!("Call {} declined/busy by {}", call_id.to_hex(), &event.pubkey[..8]);
            }
        }

        if let Some(callback) = &self.callback {
            callback.on_call_answered(&call_id, status);
        }

        Ok(())
    }

    /// Handle incoming session description (kind 452)
    async fn handle_session_description(
        &self,
        event: WebRTCSessionEvent,
    ) -> Result<(), MeshCallError> {
        let call_id = event.get_call_id()?;
        let sdp_type = event.get_sdp_type()?;
        let target_leaf = event.get_target_leaf();

        tracing::info!(
            "Received SDP {} from {} for call {}",
            match sdp_type {
                SessionDescriptionType::Offer => "offer",
                SessionDescriptionType::Answer => "answer",
            },
            &event.pubkey[..8],
            &call_id.to_hex()[..16],
        );

        // Get the peer manager and handle SDP
        let peer_managers = self.peer_managers.read().await;
        if let Some(peer_manager) = peer_managers.get(&call_id) {
            let from_leaf = target_leaf.unwrap_or(0);

            // Get or create peer for this sender
            let peer = if let Some(existing) = peer_manager.get_peer(from_leaf).await {
                existing
            } else {
                peer_manager.add_peer(from_leaf).await?
            };

            let desc = WebRTCSessionDescription {
                sdp_type,
                sdp: event.content.clone(),
                target_leaf,
            };

            peer.set_remote_description(&desc).await?;

            if sdp_type == SessionDescriptionType::Offer {
                // Auto-create answer
                let answer = peer.create_answer().await?;
                if let Some(callback) = &self.callback {
                    callback.on_session_description(&call_id, from_leaf, &answer);
                }
            }
        }

        Ok(())
    }

    /// Handle incoming ICE candidate (kind 453)
    async fn handle_ice_candidate(&self, event: ICECandidateEvent) -> Result<(), MeshCallError> {
        let call_id = event.get_call_id()?;
        let target_leaf = event.get_target_leaf();

        let peer_managers = self.peer_managers.read().await;
        if let Some(peer_manager) = peer_managers.get(&call_id) {
            let from_leaf = target_leaf.unwrap_or(0);

            if let Some(peer) = peer_manager.get_peer(from_leaf).await {
                let candidate = ICECandidate {
                    candidate: event.content.clone(),
                    target_leaf,
                };
                peer.add_ice_candidate(&candidate).await?;

                if let Some(callback) = &self.callback {
                    callback.on_ice_candidate(&call_id, from_leaf, &candidate);
                }
            }
        }

        Ok(())
    }

    /// Handle incoming state update (kind 454)
    async fn handle_state_update(
        &self,
        event: CallStateUpdateEvent,
    ) -> Result<(), MeshCallError> {
        let call_id = event.get_call_id()?;
        let action = event.get_action()?;

        let sender_pubkey = PublicKey::from_hex(&event.pubkey)
            .map_err(|e| MeshCallError::Signaling(format!("Invalid pubkey: {}", e)))?;

        tracing::info!(
            "Received state update {:?} from {} for call {}",
            action,
            &event.pubkey[..8],
            &call_id.to_hex()[..16],
        );

        match action {
            CallAction::End => {
                // Remote party ended the call
                self.update_call_state(&call_id, CallState::Ending).await?;

                if let Some(pm) = self.peer_managers.write().await.remove(&call_id) {
                    let _ = pm.close_all().await;
                }

                if let Some(call) = self.active_calls.write().await.remove(&call_id) {
                    self.group_calls.write().await.remove(&call.group_id);
                }

                if let Some(cb) = &self.callback {
                    cb.on_call_state_changed(&call_id, CallState::Ended);
                }
            }
            CallAction::Leave => {
                let mut calls = self.active_calls.write().await;
                if let Some(call) = calls.get_mut(&call_id) {
                    call.participants
                        .retain(|p| p.pubkey != sender_pubkey);

                    if let Some(cb) = &self.callback {
                        cb.on_participant_left(&call_id, &sender_pubkey);
                    }

                    // If only one participant left, end the call
                    if call.participants.len() <= 1 {
                        drop(calls);
                        self.update_call_state(&call_id, CallState::Ended).await?;
                    }
                }
            }
            CallAction::MuteAudio
            | CallAction::UnmuteAudio
            | CallAction::MuteVideo
            | CallAction::UnmuteVideo => {
                let mut calls = self.active_calls.write().await;
                if let Some(call) = calls.get_mut(&call_id) {
                    if let Some(participant) = call
                        .participants
                        .iter_mut()
                        .find(|p| p.pubkey == sender_pubkey)
                    {
                        match action {
                            CallAction::MuteAudio => participant.audio_muted = true,
                            CallAction::UnmuteAudio => participant.audio_muted = false,
                            CallAction::MuteVideo => participant.video_muted = true,
                            CallAction::UnmuteVideo => participant.video_muted = false,
                            _ => {}
                        }

                        if let Some(cb) = &self.callback {
                            cb.on_media_state_changed(
                                &call_id,
                                &sender_pubkey,
                                participant.audio_muted,
                                participant.video_muted,
                            );
                        }
                    }
                }
            }
            CallAction::Hold => {
                self.update_call_state(&call_id, CallState::OnHold).await?;
            }
            CallAction::Resume => {
                self.update_call_state(&call_id, CallState::Active).await?;
            }
            _ => {
                tracing::debug!("Unhandled call action: {:?}", action);
            }
        }

        Ok(())
    }

    /// Get active call by ID
    pub async fn get_call(&self, call_id: &CallId) -> Option<ActiveCall> {
        self.active_calls.read().await.get(call_id).cloned()
    }

    /// Get active call by group ID
    pub async fn get_call_by_group(&self, group_id: &GroupId) -> Option<ActiveCall> {
        let call_id = self.group_calls.read().await.get(group_id).cloned()?;
        self.get_call(&call_id).await
    }

    /// List all active calls
    pub async fn list_active_calls(&self) -> Vec<ActiveCall> {
        self.active_calls.read().await.values().cloned().collect()
    }

    /// Mute/unmute audio
    pub async fn set_audio_muted(
        &self,
        call_id: &CallId,
        muted: bool,
        own_pubkey: &PublicKey,
    ) -> Result<(), MeshCallError> {
        let action = if muted {
            CallAction::MuteAudio
        } else {
            CallAction::UnmuteAudio
        };

        // Update local state
        {
            let mut calls = self.active_calls.write().await;
            if let Some(call) = calls.get_mut(call_id) {
                if let Some(participant) = call
                    .participants
                    .iter_mut()
                    .find(|p| p.leaf_index == call.own_leaf_index)
                {
                    participant.audio_muted = muted;
                }
            } else {
                return Err(MeshCallError::CallNotFound);
            }
        }

        // Send signaling
        let signaling_event = CallStateUpdateEvent::new(own_pubkey, call_id, action, None);
        let _ = self
            .signaling_tx
            .send(OutboundSignaling::StateUpdate(signaling_event));

        Ok(())
    }

    /// Mute/unmute video
    pub async fn set_video_muted(
        &self,
        call_id: &CallId,
        muted: bool,
        own_pubkey: &PublicKey,
    ) -> Result<(), MeshCallError> {
        let action = if muted {
            CallAction::MuteVideo
        } else {
            CallAction::UnmuteVideo
        };

        {
            let mut calls = self.active_calls.write().await;
            if let Some(call) = calls.get_mut(call_id) {
                if let Some(participant) = call
                    .participants
                    .iter_mut()
                    .find(|p| p.leaf_index == call.own_leaf_index)
                {
                    participant.video_muted = muted;
                }
            } else {
                return Err(MeshCallError::CallNotFound);
            }
        }

        let signaling_event = CallStateUpdateEvent::new(own_pubkey, call_id, action, None);
        let _ = self
            .signaling_tx
            .send(OutboundSignaling::StateUpdate(signaling_event));

        Ok(())
    }

    /// Shutdown the call manager and clean up resources
    pub async fn shutdown(&self) {
        self.cleanup_shutdown.notify_one();

        // End all active calls
        let call_ids: Vec<CallId> = self.active_calls.read().await.keys().copied().collect();
        for call_id in call_ids {
            if let Some(pm) = self.peer_managers.write().await.remove(&call_id) {
                let _ = pm.close_all().await;
            }
        }
        self.active_calls.write().await.clear();
        self.group_calls.write().await.clear();
    }
}

// Helper functions to parse events
fn parse_initiation_event(event: &Event) -> Result<CallInitiationEvent, MeshCallError> {
    let tags: Vec<Vec<String>> = event
        .tags
        .iter()
        .map(|tag| {
            tag.clone()
                .to_vec()
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        })
        .collect();

    Ok(CallInitiationEvent {
        kind: 450,
        created_at: event.created_at.as_secs(),
        pubkey: event.pubkey.to_hex(),
        content: event.content.clone(),
        tags,
    })
}

fn parse_answer_event(event: &Event) -> Result<CallAnswerEvent, MeshCallError> {
    let tags: Vec<Vec<String>> = event
        .tags
        .iter()
        .map(|tag| {
            tag.clone()
                .to_vec()
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        })
        .collect();

    Ok(CallAnswerEvent {
        kind: 451,
        created_at: event.created_at.as_secs(),
        pubkey: event.pubkey.to_hex(),
        content: event.content.clone(),
        tags,
    })
}

fn parse_session_event(event: &Event) -> Result<WebRTCSessionEvent, MeshCallError> {
    let tags: Vec<Vec<String>> = event
        .tags
        .iter()
        .map(|tag| {
            tag.clone()
                .to_vec()
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        })
        .collect();

    Ok(WebRTCSessionEvent {
        kind: 452,
        created_at: event.created_at.as_secs(),
        pubkey: event.pubkey.to_hex(),
        content: event.content.clone(),
        tags,
    })
}

fn parse_ice_event(event: &Event) -> Result<ICECandidateEvent, MeshCallError> {
    let tags: Vec<Vec<String>> = event
        .tags
        .iter()
        .map(|tag| {
            tag.clone()
                .to_vec()
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        })
        .collect();

    Ok(ICECandidateEvent {
        kind: 453,
        created_at: event.created_at.as_secs(),
        pubkey: event.pubkey.to_hex(),
        content: event.content.clone(),
        tags,
    })
}

fn parse_state_update_event(event: &Event) -> Result<CallStateUpdateEvent, MeshCallError> {
    let tags: Vec<Vec<String>> = event
        .tags
        .iter()
        .map(|tag| {
            tag.clone()
                .to_vec()
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        })
        .collect();

    Ok(CallStateUpdateEvent {
        kind: 454,
        created_at: event.created_at.as_secs(),
        pubkey: event.pubkey.to_hex(),
        content: event.content.clone(),
        tags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active_call_creation() {
        let call_id = CallId::new();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);

        let active_call = ActiveCall {
            call_id,
            group_id,
            call_type: CallType::Video,
            state: CallState::Setup,
            participants: vec![],
            sframe_bits: SFrameBits::default(),
            own_leaf_index: 0,
            sframe_context: Arc::new(RwLock::new(SFrameContext::new(SFrameBits::default(), 0))),
            created_at: 1234567890,
            state_changed_at: 1234567890,
        };

        assert_eq!(active_call.call_id, call_id);
        assert_eq!(active_call.call_type, CallType::Video);
        assert_eq!(active_call.state, CallState::Setup);
    }
}
