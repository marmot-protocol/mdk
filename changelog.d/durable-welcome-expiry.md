### Fixed

- An invite's or new chat's Welcome that reaches its delivery deadline (mdk#3589) now ends for good the first time MDK
  sees the deadline passed: a device clock set back afterwards no longer makes it sendable again, and
  `redeliver_welcome` publishes nothing for it. Its v5 `welcome_withdrawn` row with reason `expired` and its
  `InviteDeliveryChanged` are recorded once, also when the deadline passed while the app was closed: then on the next
  start. A relay attempt that started before the deadline and fails after it no longer reports
  `WelcomeDeliveryPending`. On the first start after this upgrade, every Welcome already past its deadline is recorded
  this way.
