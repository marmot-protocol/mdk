//! Per-connection broker stream handlers: demultiplex uni/bi streams into the
//! publish and subscribe loops that drive the broker room engine.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use transport_quic_stream::AgentTextStreamReceiveAccumulator;

use crate::control::QuicBrokerControlTypeV1;
use crate::error::QuicBrokerError;
use crate::frame::{read_control_frame, read_record_frame, write_record_frame};
use crate::protocol::MAX_FRAME_SIZE;
use crate::state::BrokerState;

pub(crate) async fn handle_connection(
    state: Arc<BrokerState>,
    connection: quinn::Connection,
    max_streams_per_connection: usize,
    read_timeout: Duration,
) -> Result<(), QuicBrokerError> {
    let stream_limiter = Arc::new(Semaphore::new(max_streams_per_connection));
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
                    let _ = handle_publish_stream(state, recv, read_timeout).await;
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
                    let _ = handle_subscribe_stream(state, send, recv, read_timeout).await;
                });
            }
        }
    }
}

async fn handle_publish_stream(
    state: Arc<BrokerState>,
    mut recv: quinn::RecvStream,
    read_timeout: Duration,
) -> Result<(), QuicBrokerError> {
    let control = read_control_frame(&mut recv, read_timeout).await?;
    // Spec-mandated directionality: a subscribe envelope on a client-opened
    // unidirectional stream is rejected.
    if control.control_type != QuicBrokerControlTypeV1::Publish {
        let _ = recv.stop(0_u32.into());
        return Err(QuicBrokerError::SubscribeRequiresBidirectionalStream);
    }
    let key = control.key();
    state.wait_for_subscriber(&key).await?;
    let mut limit_state = AgentTextStreamReceiveAccumulator::default();

    // The `read_timeout` is a handshake deadline only: it bounds how long an
    // unauthenticated peer may stall before sending its publish control frame.
    // Once a publisher has authenticated a room we must NOT apply a per-record
    // deadline. Agents legitimately go quiet between records (e.g. a long tool
    // call with no progress events); a per-frame deadline would error the
    // publish stream on that silence, which latches the composer's `live_error`
    // and kills the live preview for the rest of the response with no recovery.
    // QUIC liveness (max_idle_timeout + keep_alive_interval) still reaps a
    // genuinely dead publisher, and the resource caps (max_connections /
    // max_rooms / backlog budgets) still bound an idle-but-alive one, so reads
    // here are intentionally unbounded by the application-level deadline.
    let result = async {
        while let Some(record) = read_record_frame(&mut recv, None, MAX_FRAME_SIZE).await? {
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
