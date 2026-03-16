//! WebRTC abstraction layer for mesh calls
//!
//! This module provides a simplified interface to webrtc-rs for mesh calling,
//! handling SDP negotiation, ICE, media track management, and SFrame integration.
//!
//! ## Media Pipeline
//!
//! ```text
//! Sender:
//!   raw audio → SFrame encrypt → RTP payload → WebRTC send
//!
//! Receiver:
//!   WebRTC receive → RTP payload → SFrame decrypt → raw audio
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use nostr::serde_json;
use tokio::sync::{mpsc, RwLock};
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;
use webrtc::track::track_local::{TrackLocal, TrackLocalWriter};
use webrtc::track::track_remote::TrackRemote;

use super::types::{ICECandidate, MeshCallError, SessionDescriptionType, WebRTCSessionDescription};

/// Configuration for WebRTC connections
#[derive(Debug, Clone)]
pub struct WebRTCConfig {
    /// ICE servers (STUN/TURN)
    pub ice_servers: Vec<String>,
    /// Whether to bundle audio and video
    pub bundle: bool,
    /// ICE transport policy
    pub ice_transport_policy: IceTransportPolicy,
}

impl Default for WebRTCConfig {
    fn default() -> Self {
        Self {
            ice_servers: vec!["stun:stun.l.google.com:19302".to_string()],
            bundle: true,
            ice_transport_policy: IceTransportPolicy::All,
        }
    }
}

/// ICE transport policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceTransportPolicy {
    /// All candidates allowed
    All,
    /// Only relay candidates (TURN)
    Relay,
}

/// A received media frame from a remote peer
#[derive(Debug, Clone)]
pub struct ReceivedFrame {
    /// The RTP payload (SFrame-encrypted content)
    pub payload: Vec<u8>,
    /// RTP sequence number
    pub sequence_number: u16,
    /// RTP timestamp
    pub timestamp: u32,
    /// SSRC of the sender
    pub ssrc: u32,
}

/// WebRTC peer connection wrapper
pub struct WebRTCPeer {
    /// The underlying peer connection
    connection: Arc<RTCPeerConnection>,
    /// ICE candidate sender
    ice_tx: mpsc::UnboundedSender<ICECandidate>,
    /// Local audio track for sending
    audio_track: RwLock<Option<Arc<TrackLocalStaticRTP>>>,
    /// RTP sequence number counter (must be monotonically increasing)
    rtp_seq: std::sync::atomic::AtomicU16,
    /// Channel for received frames from remote tracks
    received_frames_tx: mpsc::UnboundedSender<ReceivedFrame>,
    /// Receiver side of received frames channel
    received_frames_rx: Arc<RwLock<mpsc::UnboundedReceiver<ReceivedFrame>>>,
    /// Whether this peer has received remote description
    has_remote_desc: RwLock<bool>,
    /// Notified when peer connection reaches Connected state
    connected_notify: Arc<tokio::sync::Notify>,
}

impl WebRTCPeer {
    /// Create a new WebRTC peer connection
    pub async fn new(
        config: &WebRTCConfig,
        ice_tx: mpsc::UnboundedSender<ICECandidate>,
    ) -> Result<Self, MeshCallError> {
        // Create media engine
        let mut media_engine = MediaEngine::default();

        // Register default codecs (includes Opus for audio)
        media_engine
            .register_default_codecs()
            .map_err(|e| MeshCallError::WebRTC(format!("Failed to register codecs: {}", e)))?;

        // Create API
        let api = APIBuilder::new().with_media_engine(media_engine).build();

        // Create configuration
        let ice_servers = config
            .ice_servers
            .iter()
            .map(|url| webrtc::ice_transport::ice_server::RTCIceServer {
                urls: vec![url.clone()],
                ..Default::default()
            })
            .collect();

        let rtc_config = RTCConfiguration {
            ice_servers,
            ..Default::default()
        };

        // Create peer connection
        let connection = Arc::new(
            api.new_peer_connection(rtc_config)
                .await
                .map_err(|e| {
                    MeshCallError::WebRTC(format!("Failed to create peer connection: {}", e))
                })?,
        );

        let (received_frames_tx, received_frames_rx) = mpsc::unbounded_channel();
        let connected_notify = Arc::new(tokio::sync::Notify::new());

        let peer = Self {
            connection,
            ice_tx,
            audio_track: RwLock::new(None),
            rtp_seq: std::sync::atomic::AtomicU16::new(0),
            received_frames_tx,
            received_frames_rx: Arc::new(RwLock::new(received_frames_rx)),
            has_remote_desc: RwLock::new(false),
            connected_notify,
        };

        // Set up handlers
        peer.setup_ice_handler().await?;
        peer.setup_connection_state_handler().await?;
        peer.setup_on_track_handler().await?;

        Ok(peer)
    }

    /// Set up ICE candidate handler
    async fn setup_ice_handler(&self) -> Result<(), MeshCallError> {
        let ice_tx = self.ice_tx.clone();

        self.connection
            .on_ice_candidate(Box::new(move |candidate: Option<RTCIceCandidate>| {
                let ice_tx = ice_tx.clone();
                Box::pin(async move {
                    if let Some(candidate) = candidate {
                        let json = candidate.to_json().unwrap_or_default();
                        let ice_candidate = ICECandidate {
                            candidate: serde_json::to_string(&json).unwrap_or_default(),
                            target_leaf: None,
                        };
                        let _ = ice_tx.send(ice_candidate);
                    } else {
                        let ice_candidate = ICECandidate {
                            candidate: String::new(),
                            target_leaf: None,
                        };
                        let _ = ice_tx.send(ice_candidate);
                    }
                })
            }));

        Ok(())
    }

    /// Set up connection state handler
    async fn setup_connection_state_handler(&self) -> Result<(), MeshCallError> {
        let notify = self.connected_notify.clone();
        self.connection
            .on_peer_connection_state_change(Box::new(
                move |state: RTCPeerConnectionState| {
                    tracing::info!("WebRTC peer connection state changed: {:?}", state);
                    if state == RTCPeerConnectionState::Connected {
                        notify.notify_waiters();
                    }
                    Box::pin(async move {})
                },
            ));

        self.connection
            .on_ice_connection_state_change(Box::new(
                move |state: RTCIceConnectionState| {
                    tracing::info!("WebRTC ICE connection state changed: {:?}", state);
                    Box::pin(async move {})
                },
            ));

        Ok(())
    }

    /// Set up on_track handler to receive remote media
    async fn setup_on_track_handler(&self) -> Result<(), MeshCallError> {
        let frames_tx = self.received_frames_tx.clone();

        self.connection.on_track(Box::new(
            move |track: Arc<TrackRemote>, _receiver, _transceiver| {
                let frames_tx = frames_tx.clone();
                Box::pin(async move {
                    tracing::info!(
                        "Remote track received: codec={}, ssrc={}",
                        track.codec().capability.mime_type,
                        track.ssrc(),
                    );

                    // Spawn a task to continuously read from this track
                    let ssrc = track.ssrc();
                    tokio::spawn(async move {
                        loop {
                            match track.read_rtp().await {
                                Ok((rtp_packet, _attributes)) => {
                                    let frame = ReceivedFrame {
                                        payload: rtp_packet.payload.to_vec(),
                                        sequence_number: rtp_packet.header.sequence_number,
                                        timestamp: rtp_packet.header.timestamp,
                                        ssrc,
                                    };
                                    if frames_tx.send(frame).is_err() {
                                        break;
                                    }
                                }
                                Err(_) => {
                                    break;
                                }
                            }
                        }
                    });
                })
            },
        ));

        Ok(())
    }

    /// Add an audio track for sending.
    /// Returns the track so the caller can write encrypted frames to it.
    pub async fn add_audio_track(&self) -> Result<Arc<TrackLocalStaticRTP>, MeshCallError> {
        let track = Arc::new(TrackLocalStaticRTP::new(
            webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability {
                mime_type: "audio/opus".to_string(),
                clock_rate: 48000,
                channels: 1,
                sdp_fmtp_line: "minptime=10;useinbandfec=1".to_string(),
                rtcp_feedback: vec![],
            },
            "audio".to_string(),
            "marmot-audio".to_string(),
        ));

        self.connection
            .add_track(Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(|e| MeshCallError::WebRTC(format!("Failed to add audio track: {}", e)))?;

        *self.audio_track.write().await = Some(Arc::clone(&track));

        Ok(track)
    }

    /// Wait until the peer connection reaches Connected state.
    /// Call this before starting to send audio frames.
    pub async fn wait_connected(&self) {
        if self.connection.connection_state() == RTCPeerConnectionState::Connected {
            return;
        }
        self.connected_notify.notified().await;
    }

    /// Wait until connected with a timeout. Returns true if connected.
    pub async fn wait_connected_timeout(&self, timeout: Duration) -> bool {
        if self.connection.connection_state() == RTCPeerConnectionState::Connected {
            return true;
        }
        tokio::time::timeout(timeout, self.connected_notify.notified())
            .await
            .is_ok()
    }

    /// Write an SFrame-encrypted payload as an RTP packet on the audio track.
    ///
    /// Returns the number of bytes written. Returns 0 if the track is not yet
    /// bound (SDP negotiation incomplete) — caller should wait for connected state.
    pub async fn write_audio_frame(
        &self,
        encrypted_payload: &[u8],
        timestamp: u32,
    ) -> Result<usize, MeshCallError> {
        let track = self
            .audio_track
            .read()
            .await
            .clone()
            .ok_or_else(|| MeshCallError::WebRTC("No audio track added".into()))?;

        let seq = self
            .rtp_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let rtp_packet = webrtc::rtp::packet::Packet {
            header: webrtc::rtp::header::Header {
                version: 2,
                padding: false,
                extension: false,
                marker: false,
                payload_type: 111, // Opus
                sequence_number: seq,
                timestamp,
                ssrc: 0, // overridden by webrtc-rs binding
                ..Default::default()
            },
            payload: encrypted_payload.to_vec().into(),
        };

        let n = track
            .write_rtp(&rtp_packet)
            .await
            .map_err(|e| MeshCallError::WebRTC(format!("Failed to write RTP: {}", e)))?;

        Ok(n)
    }

    /// Receive the next frame from a remote track.
    /// The payload is SFrame-encrypted and needs decryption.
    pub async fn recv_frame(&self) -> Option<ReceivedFrame> {
        self.received_frames_rx.write().await.recv().await
    }

    /// Create an offer
    pub async fn create_offer(&self) -> Result<WebRTCSessionDescription, MeshCallError> {
        let offer = self
            .connection
            .create_offer(None)
            .await
            .map_err(|e| MeshCallError::WebRTC(format!("Failed to create offer: {}", e)))?;

        // Set unsanitized SDP as local description (webrtc-rs requires exact match)
        self.connection
            .set_local_description(offer.clone())
            .await
            .map_err(|e| {
                MeshCallError::WebRTC(format!("Failed to set local description: {}", e))
            })?;

        // Sanitize SDP before sending to remote peer (strip private IPs)
        Ok(WebRTCSessionDescription {
            sdp_type: SessionDescriptionType::Offer,
            sdp: sanitize_sdp(&offer.sdp),
            target_leaf: None,
        })
    }

    /// Create an answer
    pub async fn create_answer(&self) -> Result<WebRTCSessionDescription, MeshCallError> {
        if !*self.has_remote_desc.read().await {
            return Err(MeshCallError::WebRTC(
                "Cannot create answer without remote offer".into(),
            ));
        }

        let answer = self
            .connection
            .create_answer(None)
            .await
            .map_err(|e| MeshCallError::WebRTC(format!("Failed to create answer: {}", e)))?;

        // Set unsanitized SDP as local description
        self.connection
            .set_local_description(answer.clone())
            .await
            .map_err(|e| {
                MeshCallError::WebRTC(format!("Failed to set local description: {}", e))
            })?;

        // Sanitize SDP before sending to remote peer
        Ok(WebRTCSessionDescription {
            sdp_type: SessionDescriptionType::Answer,
            sdp: sanitize_sdp(&answer.sdp),
            target_leaf: None,
        })
    }

    /// Set remote description
    pub async fn set_remote_description(
        &self,
        desc: &WebRTCSessionDescription,
    ) -> Result<(), MeshCallError> {
        let session_desc = match desc.sdp_type {
            SessionDescriptionType::Offer => RTCSessionDescription::offer(desc.sdp.clone()),
            SessionDescriptionType::Answer => RTCSessionDescription::answer(desc.sdp.clone()),
        }
        .map_err(|e| {
            MeshCallError::WebRTC(format!("Failed to create session description: {}", e))
        })?;

        self.connection
            .set_remote_description(session_desc)
            .await
            .map_err(|e| {
                MeshCallError::WebRTC(format!("Failed to set remote description: {}", e))
            })?;

        *self.has_remote_desc.write().await = true;
        Ok(())
    }

    /// Add an ICE candidate
    pub async fn add_ice_candidate(&self, candidate: &ICECandidate) -> Result<(), MeshCallError> {
        let candidate_init: webrtc::ice_transport::ice_candidate::RTCIceCandidateInit =
            if candidate.candidate.is_empty() {
                Default::default()
            } else {
                serde_json::from_str(&candidate.candidate).map_err(|e| {
                    MeshCallError::IceError(format!("Failed to parse ICE candidate: {}", e))
                })?
            };

        self.connection
            .add_ice_candidate(candidate_init)
            .await
            .map_err(|e| {
                MeshCallError::IceError(format!("Failed to add ICE candidate: {}", e))
            })?;

        Ok(())
    }

    /// Close the peer connection
    pub async fn close(&self) -> Result<(), MeshCallError> {
        self.connection
            .close()
            .await
            .map_err(|e| MeshCallError::WebRTC(format!("Failed to close peer connection: {}", e)))?;
        Ok(())
    }

    /// Get connection state
    pub fn connection_state(&self) -> RTCPeerConnectionState {
        self.connection.connection_state()
    }
}

/// Sanitize SDP according to MIP-06 requirements:
/// - Remove private IP addresses (RFC 1918)
/// - Replace hostname in o= line
fn sanitize_sdp(sdp: &str) -> String {
    let mut lines: Vec<String> = Vec::new();

    for line in sdp.lines() {
        if line.starts_with("a=candidate:") && contains_private_ip(line) {
            continue;
        }

        if line.starts_with("o=") {
            let parts: Vec<&str> = line.split(' ').collect();
            if parts.len() >= 6 {
                let mut random_bytes = [0u8; 4];
                getrandom::fill(&mut random_bytes)
                    .expect("Failed to generate random hostname");
                let random_hostname =
                    format!("marmot-{:08x}", u32::from_be_bytes(random_bytes));
                let new_line = format!(
                    "o={} {} {} {} {} {}",
                    random_hostname, parts[1], parts[2], parts[3], parts[4], parts[5]
                );
                lines.push(new_line);
                continue;
            }
        }

        lines.push(line.to_string());
    }

    lines.join("\r\n")
}

/// Check if a line contains a private IP address (RFC 1918)
fn contains_private_ip(line: &str) -> bool {
    line.contains("192.168.")
        || line.contains("10.")
        || line.contains("172.16.")
        || line.contains("172.17.")
        || line.contains("172.18.")
        || line.contains("172.19.")
        || line.contains("172.20.")
        || line.contains("172.21.")
        || line.contains("172.22.")
        || line.contains("172.23.")
        || line.contains("172.24.")
        || line.contains("172.25.")
        || line.contains("172.26.")
        || line.contains("172.27.")
        || line.contains("172.28.")
        || line.contains("172.29.")
        || line.contains("172.30.")
        || line.contains("172.31.")
}

/// Manager for multiple WebRTC peer connections (one per participant)
pub struct WebRTCPeerManager {
    /// Peers by participant leaf index
    peers: RwLock<HashMap<u32, Arc<WebRTCPeer>>>,
    /// ICE candidate receiver
    ice_rx: RwLock<mpsc::UnboundedReceiver<(u32, ICECandidate)>>,
    /// ICE candidate sender (cloned for each peer)
    ice_tx: mpsc::UnboundedSender<(u32, ICECandidate)>,
    /// Configuration
    config: WebRTCConfig,
}

impl WebRTCPeerManager {
    /// Create a new peer manager
    pub fn new(config: WebRTCConfig) -> Self {
        let (ice_tx, ice_rx) = mpsc::unbounded_channel();
        Self {
            peers: RwLock::new(HashMap::new()),
            ice_rx: RwLock::new(ice_rx),
            ice_tx,
            config,
        }
    }

    /// Add a new peer for a participant
    pub async fn add_peer(&self, leaf_index: u32) -> Result<Arc<WebRTCPeer>, MeshCallError> {
        let (peer_ice_tx, mut peer_ice_rx) = mpsc::unbounded_channel::<ICECandidate>();
        let ice_tx = self.ice_tx.clone();

        tokio::spawn(async move {
            while let Some(candidate) = peer_ice_rx.recv().await {
                let _ = ice_tx.send((leaf_index, candidate));
            }
        });

        let peer = Arc::new(WebRTCPeer::new(&self.config, peer_ice_tx).await?);
        self.peers.write().await.insert(leaf_index, peer.clone());
        Ok(peer)
    }

    /// Get a peer by leaf index
    pub async fn get_peer(&self, leaf_index: u32) -> Option<Arc<WebRTCPeer>> {
        self.peers.read().await.get(&leaf_index).cloned()
    }

    /// Remove a peer
    pub async fn remove_peer(&self, leaf_index: u32) -> Result<(), MeshCallError> {
        if let Some(peer) = self.peers.write().await.remove(&leaf_index) {
            peer.close().await?;
        }
        Ok(())
    }

    /// Receive ICE candidates
    pub async fn receive_ice_candidate(&self) -> Option<(u32, ICECandidate)> {
        self.ice_rx.write().await.recv().await
    }

    /// Close all peers
    pub async fn close_all(&self) -> Result<(), MeshCallError> {
        let peers = self.peers.write().await.drain().collect::<Vec<_>>();
        for (_, peer) in peers {
            peer.close().await?;
        }
        Ok(())
    }

    /// Get all peer leaf indices
    pub async fn get_peer_leaf_indices(&self) -> Vec<u32> {
        self.peers.read().await.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdp_sanitization() {
        let sdp = "o=- 123 456 IN IP4 example.com\r\na=candidate:1 1 UDP 123 192.168.1.1 12345 typ host\r\na=candidate:2 1 UDP 124 10.0.0.1 12346 typ host\r\na=candidate:3 1 UDP 125 203.0.113.1 12347 typ host\r\n";

        let sanitized = sanitize_sdp(sdp);

        assert!(!sanitized.contains("192.168.1.1"));
        assert!(!sanitized.contains("10.0.0.1"));
        assert!(sanitized.contains("203.0.113.1"));
        assert!(!sanitized.contains("example.com"));
        assert!(sanitized.contains("o=marmot-"));
    }

    #[test]
    fn test_private_ip_detection() {
        assert!(contains_private_ip("192.168.1.1"));
        assert!(contains_private_ip("10.0.0.1"));
        assert!(contains_private_ip("172.16.0.1"));
        assert!(contains_private_ip("172.31.255.255"));
        assert!(!contains_private_ip("203.0.113.1"));
        assert!(!contains_private_ip("8.8.8.8"));
    }
}
