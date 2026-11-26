### Fixed

- An invite's Welcome whose recipient has no usable inbox relay (no kind-10050 list known, an empty one, or none this
  device may dial) is now delivered once the recipient's list can be found, without a re-invite (mdk#2261). After each
  paced retry that finds no route (10 minutes, doubling, at most 6 hours, and once per app start), MDK looks the
  recipient's inbox relay list up again beside the account worker, at most four lookups per account at once and 30
  seconds each, and sends the Welcome as soon as the list gives a route. Nothing is looked up for a Welcome that is
  withdrawn, expired or delivered. A failed lookup is recorded as the new `InboxLookupFailed` problem in
  `invite_deliveries` and as the existing v5 `route_resolution_failed` reason.
