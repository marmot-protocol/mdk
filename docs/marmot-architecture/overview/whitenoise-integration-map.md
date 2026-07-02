---
title: "whitenoise-rs Integration Map"
created: 2026-05-11
updated: 2026-06-07
tags: [marmot, overview, cgka, integration, whitenoise]
status: working-note
---

# whitenoise-rs Integration Map

This note maps the current engine/session/account boundary to the first whitenoise-rs integration path.

The likely first path is a shim. A direct whitenoise-rs interface change may be cleaner later, but a shim lets us test
the engine boundary against the existing account, relay, and event-processing shape.

## Boundary Goal

The engine side should own:

- MLS group state;
- publish-before-apply;
- commit convergence;
- application-message acceptance and invalidation;
- engine events and pending publish refs.

whitenoise-rs should keep owning:

- account creation and login flows;
- Nostr key custody;
- user directory and relationship cache;
- relay-list publication and repair;
- shared multi-account relay connections and subscriptions;
- chat projection, notifications, and UI-facing state.

## Current Session Surface

`AccountDeviceSession` already has the core methods a shim needs:

| Need | Current method |
| --- | --- |
| Open one account-device database | `AccountDeviceSession::open(SessionConfig)` |
| Create fresh KeyPackage bytes | `fresh_key_package()` |
| Create group | `create_group(CreateGroupRequest)` |
| Send application message / invite / leave / group data update | `send(SendIntent)` |
| Ingest peeled transport work through the engine | `ingest(TransportMessage)` |
| Advance convergence after sync/timer batches | `advance_convergence(&GroupId)` |
| Confirm published pending state | `confirm_published(PendingStateRef)` |
| Roll back failed pending state | `publish_failed(PendingStateRef)` |
| Drain side effects | `drain()` |
| Inspect basic group state | `epoch(&GroupId)`, `members(&GroupId)` |
| Get local member id | `self_id()` |
| Tune convergence policy | `set_convergence_policy(CanonicalizationPolicy)` |

`marmot-account` adds a first coordinator shell:

| Need | Current method |
| --- | --- |
| Activate account transport | `activate_transport(since)` |
| Refresh group subscriptions | `sync_transport_groups(since)` |
| Publish fresh KeyPackage through an injected boundary | `publish_fresh_key_package()` |
| Publish session effects and resolve pending state | `publish_session_effects(SessionEffects)` |
| Run create/send/ingest through publish confirmation | `create_group`, `send`, `ingest_delivery` |

## Shim Responsibilities

A first whitenoise-rs shim would need to do the following.

### Account Open

- derive or retrieve the SQLCipher key for one account-device identity;
- construct the Nostr peeler with the local signer/decrypter;
- construct `SessionConfig`;
- pass the feature registry and convergence policy;
- open `AccountDeviceSession`.

### Account Bootstrap

- ensure NIP-65 relay list state exists (its relays are also the outbox for KeyPackage publication);
- ensure inbox relay list state exists;
- publish or repair missing account relay-list events before normal runtime publication depends on them.

### KeyPackage Publication

- call `fresh_key_package`;
- publish kind `30443` KeyPackage events to the account's kind `10002` NIP-65 relays;
- record enough result state to decide whether the account setup needs repair.

This probably belongs in the Nostr transport/account service, not inside the engine.

### Group Send And Publish Resolution

- call `send(SendIntent)`;
- publish all `PublishWork` messages through the relay plane;
- confirm a pending ref only after the transport reports enough accepted publishes;
- roll back pending state when publication fails or lacks required acknowledgements.

### Inbound Sync

- deliver account-aware Nostr relay events to the correct account runtime;
- peel Nostr transport envelopes;
- call `ingest`;
- drain events;
- call `advance_convergence` after relay sync batches, reconnect catch-up, or timer ticks.

### Group Routing

- read `marmot.transport.nostr.routing.v1` from signed MLS app data;
- project it into group subscriptions and group publish targets;
- apply local relay safety policy before connecting or publishing;
- never rewrite signed group routing state as a side effect of local filtering.

## API Friction Points

These are the current points likely to hurt during integration.

1. `AccountDeviceSession` does not expose a group list or app-facing group summaries. A shim needs another source of
   known group ids.
2. `CreateGroupRequest` still carries profile fields directly. That now feeds `marmot.group.profile.v1`; richer
   component-specific creation inputs are not modeled yet.
3. `KeyPackagePublisher` is separate from `TransportAdapter`. Production Nostr KeyPackage publication should probably
   live with the Nostr transport/account service.
4. `TransportRoutingPolicy` is synchronous and local-snapshot shaped. A real Nostr implementation depends on directory
   state, account bootstrap state, group component state, relay health, and safety policy.
5. `TransportAdapter` is account-aware, but the trait does not model a shared multi-account relay plane. whitenoise-rs
   already needs cross-account subscription dedupe.
6. Scenario vectors now capture pending confirmations and rollbacks. They do not yet capture selected stale outcomes.
   Some integration behavior is tested in Rust but not portable.
8. Error values are engine-oriented. Login/setup flows may need higher-level recovery actions such as "publish missing
   kind 10002 NIP-65 relays" or "repair inbox relays".

## First Shim Methods

A thin integration layer would likely expose methods like:

- `open_account_device(account_id, device_id, database_key)`;
- `ensure_nostr_account_state(account_id)`;
- `publish_fresh_key_package(account_id)`;
- `activate_account_transport(account_id, since)`;
- `sync_account_groups(account_id, since)`;
- `create_group(account_id, request)`;
- `send_group_message(account_id, group_id, payload)`;
- `invite_members(account_id, group_id, key_packages)`;
- `leave_group(account_id, group_id)`;
- `ingest_transport_delivery(account_id, delivery)`;
- `advance_group_convergence(account_id, group_id)`;
- `resolve_publish_report(account_id, pending, report)`;
- `group_snapshot(account_id, group_id)`.

The first implementation can be narrower, but these names describe the shape whitenoise-rs will probably need.

## Near-Term Engine Work From This Map

This map points to three engine-adjacent tasks:

1. Expose enough group/app-component snapshot state for Nostr routing without leaking OpenMLS internals.
2. Extend portable scenario traces to include selected stale outcomes.
3. Keep `marmot-account` as the small coordinator shell while resisting a full app-core rebuild inside this repository.
