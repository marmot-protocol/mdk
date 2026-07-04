//! Per-connection broker stream handlers: demultiplex uni/bi streams into the
//! publish and subscribe loops that drive the broker room engine.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use transport_quic_stream::{AgentTextStreamReceiveAccumulator, AgentTextStreamReceiveLimits};

use crate::control::QuicBrokerControlTypeV1;
use crate::error::QuicBrokerError;
use crate::frame::{read_control_frame, read_record_frame, write_record_frame};
use crate::protocol::{MAX_FRAME_SIZE, RECORD_QUIET_GAP_DEADLINE};
use crate::state::BrokerState;

/// Per-stream knobs the server hands every connection handler.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BrokerStreamPolicy {
    pub(crate) max_streams_per_connection: usize,
    pub(crate) read_timeout: Duration,
    pub(crate) publish_limits: PublishForwardLimits,
}

/// Forward-role bounds for a publish stream, from `QuicBrokerConfig` — never
/// the subscriber-sized receive defaults. `max_frame_bytes` counts record
/// frame bytes as carried on the wire (the broker never decrypts):
/// ciphertext including the 16-byte AEAD tag per record for encrypted
/// previews, plaintext for unencrypted ones.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PublishForwardLimits {
    pub(crate) max_records: u64,
    pub(crate) max_frame_bytes: usize,
}

impl PublishForwardLimits {
    fn accumulator(self) -> AgentTextStreamReceiveAccumulator {
        // The accumulator's `max_plaintext_bytes` counts each record's frame
        // field. Subscribers observe records after decryption, so there it
        // is true plaintext; this publish handler observes them undecrypted,
        // so the same budget counts wire frame bytes here — hence the
        // frame-bytes name on the broker config knob.
        AgentTextStreamReceiveAccumulator::new(AgentTextStreamReceiveLimits {
            max_records: self.max_records,
            max_plaintext_bytes: self.max_frame_bytes,
            ..AgentTextStreamReceiveLimits::default()
        })
    }
}

pub(crate) async fn handle_connection(
    state: Arc<BrokerState>,
    connection: quinn::Connection,
    policy: BrokerStreamPolicy,
) -> Result<(), QuicBrokerError> {
    let stream_limiter = Arc::new(Semaphore::new(policy.max_streams_per_connection));
    loop {
        tokio::select! {
            uni = connection.accept_uni() => {
                let Ok(mut recv) = uni else {
                    return Ok(());
                };
                let Ok(permit) = Arc::clone(&stream_limiter).try_acquire_owned() else {
                    let _ = recv.stop(0_u32.into());
                    continue;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle_publish_stream(state, recv, policy).await;
                });
            }
            bi = connection.accept_bi() => {
                let Ok((mut send, mut recv)) = bi else {
                    return Ok(());
                };
                let Ok(permit) = Arc::clone(&stream_limiter).try_acquire_owned() else {
                    let _ = send.reset(0_u32.into());
                    let _ = recv.stop(0_u32.into());
                    continue;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle_subscribe_stream(state, send, recv, policy.read_timeout).await;
                });
            }
        }
    }
}

async fn handle_publish_stream(
    state: Arc<BrokerState>,
    mut recv: quinn::RecvStream,
    policy: BrokerStreamPolicy,
) -> Result<(), QuicBrokerError> {
    let control = read_control_frame(&mut recv, policy.read_timeout).await?;
    // Spec-mandated directionality: a subscribe envelope on a client-opened
    // unidirectional stream is rejected.
    if control.control_type != QuicBrokerControlTypeV1::Publish {
        let _ = recv.stop(0_u32.into());
        return Err(QuicBrokerError::SubscribeRequiresBidirectionalStream);
    }
    let key = control.key();
    state.wait_for_subscriber(&key).await?;
    // Forward-role limits come from the broker config: the subscriber-sized
    // receive defaults would truncate a legitimate long preview mid-stream and
    // close the room. Each subscriber still enforces its own receive limits.
    let mut limit_state = policy.publish_limits.accumulator();

    // The short `read_timeout` is a handshake deadline only: it bounds how
    // long an unauthenticated peer may stall before sending its publish
    // control frame. Record reads then fall under the shared 120s quiet-gap
    // deadline, matching the direct path's `record_read_timeout` and the
    // subscriber loop: agents legitimately go quiet between records (e.g. a
    // long tool call), but QUIC keepalives would sustain an alive-but-wedged
    // publisher forever, pinning its room. On a quiet-gap timeout the room is
    // finished, so subscribers observe a clean end of stream.
    let result = async {
        while let Some(record) =
            read_record_frame(&mut recv, Some(RECORD_QUIET_GAP_DEADLINE), MAX_FRAME_SIZE).await?
        {
            if record.stream_id != key.stream_id {
                return Err(QuicBrokerError::MixedStreamIds);
            }
            limit_state.observe(&record)?;
            state.publish(&key, record).await?;
        }
        Ok::<_, QuicBrokerError>(())
    }
    .await;

    if matches!(&result, Err(QuicBrokerError::MixedStreamIds)) {
        state.drop_room(&key).await;
    } else {
        state.finish_room(&key).await;
    }
    result
}

async fn handle_subscribe_stream(
    state: Arc<BrokerState>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    read_timeout: Duration,
) -> Result<(), QuicBrokerError> {
    let control = match read_control_frame(&mut recv, read_timeout).await {
        Ok(control) => control,
        Err(err) => {
            // Reset the return direction so the client observes the rejection
            // instead of a clean zero-record end of stream.
            let _ = send.reset(0_u32.into());
            return Err(err);
        }
    };
    // Spec-mandated directionality: a publish envelope on a bidirectional
    // stream is rejected.
    if control.control_type != QuicBrokerControlTypeV1::Subscribe {
        let _ = send.reset(0_u32.into());
        let _ = recv.stop(0_u32.into());
        return Err(QuicBrokerError::PublishRequiresUnidirectionalStream);
    }
    let key = control.key();
    let (subscriber_id, backlog, mut rx) = state.subscribe(key.clone()).await?;
    let result = async {
        for record in backlog {
            write_record_frame(&mut send, &record).await?;
        }
        while let Some(record) = rx.recv().await {
            write_record_frame(&mut send, &record).await?;
        }
        send.finish()?;
        Ok::<_, QuicBrokerError>(())
    }
    .await;
    state.unsubscribe(&key, subscriber_id).await;
    result
}
