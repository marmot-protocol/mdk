### Added

- `InviteDeliveryProblemFfi::InboxLookupFailed` (mdk#2261): no usable inbox relay is known for the recipient and MDK's
  latest lookup of their inbox relay list failed; MDK looks it up again at its next retry. A host that matches the enum
  exhaustively must handle it.
