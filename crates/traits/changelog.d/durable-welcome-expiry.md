### Breaking changes

- `StoredMessagePayload::OutboundWelcome` gains `expiry: Option<message::WelcomeExpiry>`, the durable expiry mark
  of an owed outbound Welcome (mdk#3589), stored as payload variant 16; a Welcome without one keeps its bytes, and a
  staged Welcome never carries one. `welcome_expiry` and `with_welcome_expiry` read and set it.
- `OpenMlsContentFilter::NoOpenMlsMessage` lets a listing read only rows whose payload carries no OpenMLS message,
  such as retained outbound Welcomes.
