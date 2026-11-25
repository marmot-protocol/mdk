### Breaking changes

- `StoredMessagePayload::OutboundWelcome` and `StagedInviteWelcome` gain `expiry: Option<message::WelcomeExpiry>`,
  the durable expiry mark of an outbound Welcome (mdk#3589), stored as payload variants 16 and 17; a Welcome without
  one keeps its bytes. `welcome_expiry` and `with_welcome_expiry` read and set it.
- `OpenMlsContentFilter::NoOpenMlsMessage` lets a listing read only rows whose payload carries no OpenMLS message,
  such as retained outbound Welcomes.
