### Fixed

- `marmot_invite_deliveries` keeps reporting `MARMOT_INVITE_DELIVERY_STATE_KIND_UNDELIVERABLE` for an invite's Welcome
  that no relay acknowledged by its delivery deadline (7 days after it was staged with the invite, or its KeyPackage's
  expiry if sooner; mdk#3589), even if the device clock is set back, and the change is announced once: on the next start
  when the deadline passed while the app was closed.
