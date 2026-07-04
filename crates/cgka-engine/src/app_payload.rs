use cgka_traits::{EngineError, MarmotAppEvent, MemberId};

/// Shared application-payload sender validation for every inbound seam
/// (direct ingest, stored-convergence/replay). An application message is
/// surfaced only when its inner event's author matches the MLS-authenticated
/// sender; an empty sender is rejected outright so an unattributable message
/// can never validate, regardless of what the inner event claims.
pub(crate) fn validate_app_payload_for_sender(
    payload: &[u8],
    sender: &MemberId,
) -> Result<MarmotAppEvent, EngineError> {
    if sender.as_slice().is_empty() {
        return Err(EngineError::InvalidAppMessagePayload(
            "application message has no authenticated member sender".into(),
        ));
    }
    let event = MarmotAppEvent::decode(payload)
        .map_err(|err| EngineError::InvalidAppMessagePayload(err.to_string()))?;
    let sender_hex = hex::encode(sender.as_slice());
    event
        .validate_sender(&sender_hex)
        .map_err(|err| EngineError::InvalidAppMessagePayload(err.to_string()))?;
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::validate_app_payload_for_sender;
    use cgka_traits::{EngineError, MarmotAppEvent, MemberId};

    fn payload_from(pubkey: &str) -> Vec<u8> {
        MarmotAppEvent::new(pubkey, 1, 9, vec![], "hello")
            .encode()
            .expect("encode app event")
    }

    #[test]
    fn empty_sender_is_rejected_even_when_event_pubkey_is_empty() {
        // Regression for the S3 replay-seam gap (#383): an event whose
        // `pubkey` is the empty string must not validate against an empty
        // (unresolvable) MLS sender.
        let payload = payload_from("");
        let result = validate_app_payload_for_sender(&payload, &MemberId::new(Vec::new()));
        assert!(matches!(
            result,
            Err(EngineError::InvalidAppMessagePayload(_))
        ));
    }

    #[test]
    fn pubkey_mismatch_is_rejected() {
        let sender = MemberId::new(vec![0x11; 32]);
        let payload = payload_from(&hex::encode([0x22; 32]));
        let result = validate_app_payload_for_sender(&payload, &sender);
        assert!(matches!(
            result,
            Err(EngineError::InvalidAppMessagePayload(_))
        ));
    }

    #[test]
    fn matching_sender_validates() {
        let sender = MemberId::new(vec![0x11; 32]);
        let payload = payload_from(&hex::encode([0x11; 32]));
        let event =
            validate_app_payload_for_sender(&payload, &sender).expect("matching sender validates");
        assert_eq!(event.content, "hello");
    }
}
