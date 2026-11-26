### Fixed

- An invite's Welcome past its delivery deadline (mdk#3589) reads `Undeliverable` in `invite_deliveries` for good once
  MDK has seen the deadline pass with the Welcome owed (its commit confirmed), even if the device clock is set back, with one `InviteDeliveryChanged`: on the next
  start when the deadline passed while the app was closed, sent before the account worker's first turn. A relay attempt that started before the deadline and fails
  after it no longer reports `WelcomeDeliveryPending`.
