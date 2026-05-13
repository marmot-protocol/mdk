# marmot-account

Thin account-device orchestration layer for the future Marmot app core.

This crate sits above `cgka-session` and a `TransportAdapter`. It is the first place where app-level routing starts to
appear: account inbox endpoints, group transport endpoints, publish acknowledgement thresholds, key-package publication,
and pending publish confirmation.

## What this crate does

- Activates the transport account for one local `AccountDeviceSession`.
- Publishes fresh KeyPackages through an injected boundary.
- Turns `SessionEffects.publish` work into `TransportPublishRequest`s.
- Confirms or rolls back pending session state after adapter publish reports.
- Keeps transport routing policy generic so the first implementation can be Nostr without baking Nostr into the session
  or engine crates.

## Routing model

`TransportRoutingPolicy` is the transport-generic boundary. It answers:

- which account inbox endpoints to subscribe to for welcomes;
- which group subscriptions to keep active;
- which endpoints should receive a given outbound transport message;
- which endpoints should receive fresh KeyPackages;
- how many publish acknowledgements are required before pending work is confirmed.

For Nostr, a production implementation should derive those answers from Nostr state rather than hard-coded
configuration:

- account inbox relays are the user's always-on welcome / gift-wrap relays;
- group subscriptions and group-message publish targets come from the group's current
  `marmot.transport.nostr.routing.v1` app component;
- KeyPackage publication targets come from the user's NIP-65-style KeyPackage relay-list discovery data, currently
  documented in the Marmot drafts as kind `10051`;
- publish acknowledgement thresholds remain app policy over the chosen endpoint set.

`StaticTransportRouting` is only the simple configured implementation used by tests and early harnesses.

The current `KeyPackagePublisher` trait is a temporary boundary for the first account-runtime slice. The likely
production shape is for KeyPackage publication to move into the transport adapter family, so the account runtime can ask
the active transport to publish a KeyPackage without knowing whether that means Marmot Nostr kind `30443`, another
relay-plane format, or a future non-Nostr transport.

## What it does not do

- No UI projection or message database.
- No account key derivation or recovery.
- No derivation of full MIP-00 KeyPackage metadata from fresh engine KeyPackage bytes yet.
- No relay auth, Nostr routing-component reader, or relay-list discovery yet.

## Run tests

```sh
cargo test -p marmot-account
```
