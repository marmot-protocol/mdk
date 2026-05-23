use cgka_traits::app_event::MarmotAppEventError;
use cgka_traits::error::EngineError;
use cgka_traits::transport_adapter::TransportAdapterError;
use cgka_traits::types::{EpochId, GroupId, MemberId};

#[test]
fn engine_error_display_does_not_expose_group_or_member_ids() {
    let group_id = GroupId::new(vec![0xAA; 32]);
    let member_id = MemberId::new(vec![0xBB; 32]);
    let group_hex = hex::encode(group_id.as_slice());
    let member_hex = hex::encode(member_id.as_slice());
    let errors = [
        EngineError::UnknownGroup(group_id.clone()).to_string(),
        EngineError::NotAMember {
            group_id: group_id.clone(),
        }
        .to_string(),
        EngineError::NotGroupAdmin {
            group_id: group_id.clone(),
        }
        .to_string(),
        EngineError::UnknownMember {
            group_id: group_id.clone(),
            member: member_id.clone(),
        }
        .to_string(),
        EngineError::AdminCannotSelfRemove {
            group_id: group_id.clone(),
        }
        .to_string(),
        EngineError::AdminDepletion {
            group_id: group_id.clone(),
        }
        .to_string(),
        EngineError::ForkedEpoch {
            group_id,
            last_stable: EpochId(1),
            conflicting_epoch: EpochId(2),
        }
        .to_string(),
    ];

    for error in errors {
        assert!(!error.contains(&group_hex), "{error}");
        assert!(!error.contains(&member_hex), "{error}");
    }
}

#[test]
fn transport_and_app_event_error_display_do_not_expose_pubkeys() {
    let pubkey = "cc".repeat(32);

    let inactive = TransportAdapterError::AccountNotActive(MemberId::new(vec![0xCC; 32]));
    assert!(!inactive.to_string().contains(&pubkey));

    let mismatch = MarmotAppEventError::PubkeyMismatch {
        expected: pubkey.clone(),
        found: "dd".repeat(32),
    };
    assert!(!mismatch.to_string().contains(&pubkey));
}
