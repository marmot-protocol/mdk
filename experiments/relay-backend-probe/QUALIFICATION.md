# MDK #1358 transport qualification

## Scope and revision

This probe uses the exact Git `rev` in `Cargo.toml` and `Cargo.lock` for the
fork SDK. It is an opt-in Cargo workspace. MDK's production dependency graph,
recovery owner, scheduler, peeler, schema, and bindings are not changed here.
Only loopback WebSocket relays and synthetic signed events are used.
The qualified SDK integration revision is
`e08022dc4fa588e8effbe8eb4b4238e7871cbd14`.

The test-only `CandidateRelay` implements the existing `NostrRelayClient`
subscription and publication seam, and the test activates accounts through
`NostrTransportAdapter`. It uses one immutable authenticator per account, a
separate anonymous client, and a separate write-only publisher client. An
account's disconnect, same-object reactivation, generation replacement, and
removal do not replace Bob's client or subscriptions. The live inbox receives
an event after Alice reconnects and after an Alice history request is cancelled.
The anonymous client reads public data, then observes an AUTH challenge and
an `auth-required` CLOSED for a private inbox without an account authenticator.
The publish-only connection causes zero `REQ` queries. The probe rejects
non-loopback endpoints; it is not an MDK dialer or TLS/privacy implementation.

## Request limits and projection

The known-inventory experiment selects at most two relays per call, uses a
three-EVENT item budget and a 64 KiB serialized-event-JSON budget per relay,
and sets a three-second deadline. It runs one acquisition handle at a time on
that client. The client relay notification channel has 256 slots; its pool,
WebSocket, parser, temporary JSON, and object overhead remain outside the
request budget. Other scenarios use a 4 KiB byte budget for a 16 KiB event
and a 64 KiB byte budget for cancellation. The publication probe allows one
endpoint per send, a three-second connect wait and 150 ms OK wait. The auth
probe has distinct Alice/Bob sockets plus an anonymous socket. The boundary
probe has two account clients and one publisher client, at most two loopback
endpoints per subscription, and exactly one endpoint per publish. These are
scenario limits, not a process-wide concurrency or memory ceiling. Production
MDK must cap concurrent requests across accounts and combine that cap with
its chosen connection buffer and parser limits.

`BatchEvidence::from_sdk` maps every `AcquisitionEnd` variant into an
MDK-owned `RequestEnd`. It preserves partial `Event`s, relay endpoint,
received item and serialized-event-byte counters, duplicate count, and
retained-state high-water counters. Its values are transport evidence only:
`ExitPolicySatisfied` means this request met its exit policy. It does not
mean durable MDK admission or complete historical coverage.

| SDK terminal | MDK probe terminal | Coverage implication |
| --- | --- | --- |
| `Completed` | `ExitPolicySatisfied` | Request ended normally; admission and history remain MDK decisions. |
| `ExitLimitReached` | `ExitCount` | Incomplete. |
| `ItemBudgetExceeded` / `ByteBudgetExceeded` | `ItemLimit` / `ByteLimit` | Incomplete, preserve partial events. |
| `Cancelled` / `TimedOut` | `Cancelled` / `TimedOut` | Incomplete, preserve partial events. |
| `Disconnected` / `ReceiveLoss` / `ReceiverClosed` | Corresponding typed values | Incomplete; loss count is receiver-local, not unique events. |
| `AuthenticationFailed` / `Rejected` / `Failed` | `AuthenticationFailed` / `Rejected` / `SetupFailed` | Incomplete; no string matching. |

The existing production `NostrRelayClient` trait has no acquisition or
notification-gap method. The projection is therefore a proposed adapter
contract exercised beside the existing seam; it is not wired into the
production adapter. The owner must receive typed gap and request evidence
with attempt identity before it can make durable retry decisions. The probe
never supplies a pagination cursor. Explicit-ID batches only prove eventual
acquisition for an inventory MDK already knows.

## Observed local results

A 12-event known inventory produced one three-item-limited partial batch,
then six two-ID batches. All 12 IDs were acquired with seven requests and
16 EVENT notifications; three of those were reacquisition across requests.
A sample run recorded 5,651 serialized event JSON bytes, 10,145 connection
text bytes received, and 1,491 connection text bytes sent (11,636 total).
Within-request duplicate count was zero. Connection text bytes include Nostr
message envelopes and are not WebSocket wire bytes. Values can vary with
signed event timestamps and subscription IDs; tests print the current run.

A 16 KiB content event exceeded a 4 KiB request byte budget; the result
retained zero events and reported the over-budget event. A separate cancelled
request reports the events actually retained before cancellation, which can
be zero when cancellation wins the race. Its unrelated metadata subscription
delivered after cancel.
The SDK saturation tests additionally print retained high-water state and
control/cancel/drop latency under sustained large-event and duplicate bursts.

A deliberately stalled four-slot client receiver reported a gap of 125
notifications in one run and retained 2 of 64 EVENTs before EOSE. It then
received a later metadata event. An explicit re-fetch got all 64 known IDs.
An owned four-slot admission sketch dropped 60 of 64 events and did not treat
EOSE as completion; a bounded retry admitted all 64, including four repeats.
It measured 24,198 inbound connection text bytes for each pass (48,396 over
two passes). The sketch is not a production backend or discovery algorithm.

The boundary publication test observed: `OK true` maps to accepted; an
explicit relay rejection maps to `TerminalRejected`; a silent relay received
the EVENT but gave no OK, so the result maps to `PossiblyExposed`. Mapping is
based on typed SDK status/error kind, not relay error text. A silent server
cannot prove that the event was stored or forwarded. Both local publication
relays saw zero read queries from the publisher.
An unavailable loopback endpoint returned `RetryableUnavailable` before an
EVENT send attempt.

## Production migration gate under #1358

1. Add a narrow typed acquisition/gap operation at MDK's relay-client boundary,
   carrying account/route/attempt identity and bounded partial events. Feed
   this to the #1946 owner without making the SDK decide retry or coverage.
2. Replace the current shared 0.44 client with immutable account-scoped 0.45
   authenticators, an explicit anonymous directory client, and scoped
   publish-only connections. Preserve existing endpoint validation, dial
   safety, TLS/proxy policy, URL/key redaction, group-route reconciliation,
   live subscription restoration, and per-account removal.
3. Adapt the production notification bridge from `RelayPoolNotification` to
   `ClientNotification` plus `NotificationUpdate::Lagged`; ensure the peeler
   receives verified 445/1059 carriers and that gaps reach owner evidence.
   The probe's synthetic GiftWrap envelopes test relay access control, not
   Marmot decryption or peeler admission.
4. Run adapter, peeler, directory, app real-relay and KeyPackage/Welcome tests;
   `just fast-ci`; MarmotKit/UniFFI generation; Android/iOS binding and
   artifact validation. The probe does not qualify those production surfaces.

## Reconnect contract and regression

`Terminated` reports that termination was requested and automatic retry has
stopped. It does not join the old connection task or prove its WebSocket has
closed. The earlier ignored diagnostic treated `try_connect_relay` as a
reactivation barrier. That one-shot API can return a state error while the old
task owns the relay; it queues a replacement connection but does not report
success for it. The supported immediate same-object operation is
`connect_relay`, followed by observing a new connected status and restored
subscription EOSE before relying on live traffic. An adapter can also retire
the old relay object and add a new generation when replacing its own account
route; the boundary probe continues to test that path.

The active `sdk_immediate_reconnect_after_terminated_restores_live_delivery`
regression exercises same-object reactivation without sleeps or retries. It
asserts live delivery on Alice's restored subscription, live delivery on Bob's
unrelated subscription, a new Alice socket, no new Bob query socket, unchanged
Bob authenticator count, and denied cross-account reads after reconnect.
The SDK's teardown-barrier tests force the old task to retain ownership and
check queued reconnection and the one-shot state error. Twelve consecutive
local runs of the active MDK regression passed at the final SDK pin.
