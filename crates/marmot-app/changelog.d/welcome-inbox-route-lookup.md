### Fixed

- An owed invite Welcome with no usable inbox route is delivered once the account worker's lookup of the recipient's
  inbox relay list finds one (mdk#2261): the worker looks the list up after each paced retry that found no route, and
  sends the Welcome without a re-invite.

### Added

- `WelcomeDeliveryProblem::InboxLookupFailed`: no usable inbox relay is known for the recipient and the latest lookup
  of their inbox relay list failed. `invite_deliveries` reports it as `last_problem`, and as `Undeliverable`'s cause
  when it was the last attempt's problem.
