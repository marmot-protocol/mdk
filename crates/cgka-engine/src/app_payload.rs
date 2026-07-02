use cgka_traits::{EngineError, MarmotAppEvent, MemberId};

pub(crate) fn validate_app_payload_for_sender(
    payload: &[u8],
    sender: &MemberId,
) -> Result<MarmotAppEvent, EngineError> {
    let event = MarmotAppEvent::decode(payload)
        .map_err(|err| EngineError::InvalidAppMessagePayload(err.to_string()))?;
    let sender_hex = hex::encode(sender.as_slice());
    event
        .validate_sender(&sender_hex)
        .map_err(|err| EngineError::InvalidAppMessagePayload(err.to_string()))?;
    Ok(event)
}

pub(crate) fn app_payload_is_valid_for_sender(payload: &[u8], sender: &[u8]) -> bool {
    let event = match MarmotAppEvent::decode(payload) {
        Ok(event) => event,
        Err(_) => return false,
    };
    event.validate_sender(&hex::encode(sender)).is_ok()
}
