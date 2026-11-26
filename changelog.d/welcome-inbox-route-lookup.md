### Fixed

- An invite's Welcome whose recipient has no usable inbox relay (no kind-10050 list known, an empty one, or none this
  device may dial) is now delivered once the recipient's list can be found, without a re-invite (mdk#2261). After each
  paced retry that finds no route (10 minutes, doubling, at most 6 hours, and once per app start), MDK looks the
  recipient's inbox relay list up again beside the account worker, at most four lookups per account at once and 30
  seconds each, and sends the Welcome as soon as the list gives a route. Whether an owed Welcome still needs the
  lookup is checked when it starts and at each worker turn. A failed lookup shows as the new `InboxLookupFailed`
  problem in `invite_deliveries`, and the next attempt that finds no route records the existing v5
  `route_resolution_failed` reason.
