//! Length-prefixed broker framing: control/record/raw-byte frame readers and
//! writers plus the read-deadline and frame-length guards they share.

use std::future::Future;
use std::time::Duration;

use cgka_traits::agent_text_stream::AgentTextStreamRecordV1;
use tokio::time::timeout;

use crate::control::QuicBrokerControlEnvelopeV1;
use crate::error::QuicBrokerError;
use crate::protocol::{FRAME_LEN_BYTES, MAX_FRAME_SIZE};

pub(crate) async fn write_control_frame(
    send: &mut quinn::SendStream,
    control: &QuicBrokerControlEnvelopeV1,
) -> Result<(), QuicBrokerError> {
    let bytes = control.encode()?;
    write_bytes_frame(send, &bytes).await
}

pub(crate) async fn read_control_frame(
    recv: &mut quinn::RecvStream,
    read_timeout: Duration,
) -> Result<QuicBrokerControlEnvelopeV1, QuicBrokerError> {
    let bytes = read_bytes_frame(recv, Some(read_timeout), MAX_FRAME_SIZE)
        .await?
        .ok_or(QuicBrokerError::MissingControlFrame)?;
    QuicBrokerControlEnvelopeV1::decode(&bytes)
}

pub(crate) async fn write_record_frame(
    send: &mut quinn::SendStream,
    record: &AgentTextStreamRecordV1,
) -> Result<(), QuicBrokerError> {
    let bytes = record.encode()?;
    write_bytes_frame(send, &bytes).await
}

pub(crate) async fn read_record_frame(
    recv: &mut quinn::RecvStream,
    read_timeout: Option<Duration>,
    max_frame_len: usize,
) -> Result<Option<AgentTextStreamRecordV1>, QuicBrokerError> {
    let Some(bytes) = read_bytes_frame(recv, read_timeout, max_frame_len).await? else {
        return Ok(None);
    };
    Ok(Some(AgentTextStreamRecordV1::decode(&bytes)?))
}

pub(crate) async fn write_bytes_frame(
    send: &mut quinn::SendStream,
    bytes: &[u8],
) -> Result<(), QuicBrokerError> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| QuicBrokerError::FrameTooLarge(bytes.len()))?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(bytes).await?;
    Ok(())
}

pub(crate) async fn read_bytes_frame(
    recv: &mut quinn::RecvStream,
    read_timeout: Option<Duration>,
    max_frame_len: usize,
) -> Result<Option<Vec<u8>>, QuicBrokerError> {
    let mut len_bytes = [0_u8; FRAME_LEN_BYTES];
    let mut read = 0;
    while read < FRAME_LEN_BYTES {
        let chunk = match read_timeout {
            Some(read_timeout) => {
                broker_read_deadline(read_timeout, recv.read(&mut len_bytes[read..])).await?
            }
            None => recv.read(&mut len_bytes[read..]).await?,
        };
        match chunk {
            Some(0) => return Err(QuicBrokerError::TruncatedFrameLength),
            Some(n) => read += n,
            None if read == 0 => return Ok(None),
            None => return Err(QuicBrokerError::TruncatedFrameLength),
        }
    }

    let len = u32::from_be_bytes(len_bytes) as usize;
    validate_frame_len(len, max_frame_len)?;
    let mut bytes = vec![0_u8; len];
    match read_timeout {
        Some(read_timeout) => {
            broker_read_deadline(read_timeout, recv.read_exact(&mut bytes)).await?;
        }
        None => recv.read_exact(&mut bytes).await?,
    }
    Ok(Some(bytes))
}

pub(crate) async fn broker_read_deadline<T, E>(
    read_timeout: Duration,
    read: impl Future<Output = Result<T, E>>,
) -> Result<T, QuicBrokerError>
where
    QuicBrokerError: From<E>,
{
    timeout(read_timeout, read)
        .await
        .map_err(|_| QuicBrokerError::ReadTimeout)?
        .map_err(Into::into)
}

pub(crate) fn validate_frame_len(len: usize, max_frame_len: usize) -> Result<(), QuicBrokerError> {
    if len == 0 {
        return Err(QuicBrokerError::EmptyFrame);
    }
    if len > max_frame_len.min(MAX_FRAME_SIZE) {
        return Err(QuicBrokerError::FrameTooLarge(len));
    }
    Ok(())
}
