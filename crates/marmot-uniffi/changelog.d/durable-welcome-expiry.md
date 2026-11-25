### Fixed

- An invite's Welcome that no relay acknowledged by its delivery deadline (7 days after it was staged with the invite,
  or its KeyPackage's expiry if sooner; mdk#3589) reads `Undeliverable` in `invite_deliveries` for good, even if the
  device clock is set back, and `InviteDeliveryChanged` announces it once: on the next start when the deadline passed
  while the app was closed.
