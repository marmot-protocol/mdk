# Relay Compatibility Tests

This directory contains a tool for testing Nostr relay compatibility with NIP-70 protected events, which is required for MLS key package publishing (kind 443) in the Marmot Protocol.

## The Problem

MDK publishes MLS key packages as kind 443 events tagged with NIP-70 protected (`["-"]`). However, according to NIP-70:

> The default behavior of a relay MUST be to reject any event that contains `["-"]`.

This means many popular public relays reject protected events outright, preventing key package publishing from succeeding.

### Why This Matters

1. **whitenoise-rs has a bug**: It uses the same default relays (`relay.damus.io`, `relay.primal.net`, `nos.lol`) for all relay types, including key package relays
2. **These relays reject protected events**: All three default relays block NIP-70 protected events
3. **NIP-42 AUTH doesn't help**: These relays don't even offer an AUTH challenge - they reject outright

## The Solution

Applications using MDK should:

1. **Use separate relay lists** for key packages vs general events
2. **Publish kind 10051** ("MLS Key Package Relays") to advertise key package relays
3. **Only use relays that accept NIP-70 protected events** for key packages

See [whitenoise-rs](https://github.com/marmot-protocol/whitenoise-rs) for a reference implementation (though it currently has the bug described above).

## Usage

```bash
# Build
cd relay-tests
cargo build --release

# Test all default relays
cargo run -- --all

# Test with NIP-42 authentication
cargo run -- --all --with-auth

# Discover relays via NIP-66 and test them
cargo run -- --discover

# Discover up to 100 relays
cargo run -- --discover --discover-limit 100

# Test specific relays
cargo run -- --relays wss://relay.damus.io,wss://nos.lol

# Output JSON for CI/tooling
cargo run -- --all --json

# Update the relay status file
cargo run -- --all --update-status
```

### NIP-66 Relay Discovery

The `--discover` flag uses [NIP-66](https://github.com/nostr-protocol/nips/blob/master/66.md) to discover relays dynamically. It queries known relays for kind 30166 events published by relay monitors, extracts relay URLs, and tests them.

### NIP-42 Authentication Testing

The `--with-auth` flag tests whether NIP-42 authentication helps with protected events:

1. Connects to relay and waits for AUTH challenge
2. If challenge received, signs and sends AUTH event (kind 22242)
3. Tests protected events again after authentication
4. Reports whether AUTH made a difference

## Findings Summary

### Key Discovery: AUTH Does NOT Help

Testing with `--with-auth` revealed that **NIP-42 authentication does NOT solve the problem** with major relays:

| Relay                      | AUTH Challenge Sent? | Protected Accepted After AUTH?         |
| -------------------------- | -------------------- | -------------------------------------- |
| `wss://relay.damus.io`     | **No**               | N/A - no AUTH offered                  |
| `wss://relay.primal.net`   | **No**               | N/A - no AUTH offered                  |
| `wss://nos.lol`            | **No**               | N/A - no AUTH offered                  |
| `wss://wot.nostr.party`    | Yes                  | No - requires trust network membership |
| `wss://relay.satlantis.io` | No                   | Already accepts without AUTH           |

**The major relays (Damus, Primal, nos.lol) reject NIP-70 protected events without even offering an AUTH challenge.** They simply block them outright per NIP-70 spec default behavior.

### Why NIP-70 Exists

Per NIP-70, the protected tag is meant to prevent unauthorized republishing of events. Relays that want to accept protected events should:

1. Require NIP-42 AUTH
2. Verify the authenticated pubkey matches the event author
3. Only then accept the event

However, most relays simply reject all protected events as the "safe default".

## Current Relay Status (as of 2026-02-08)

### Working Relays (accept NIP-70 protected events)

These relays accept both unprotected and NIP-70 protected events for kind 1 and kind 443:

| Relay                           | Notes                 |
| ------------------------------- | --------------------- |
| `wss://nostr-pub.wellorder.net` | Consistently reliable |
| `wss://relay.wellorder.net`     | Consistently reliable |
| `wss://relay.satlantis.io`      | Consistently reliable |

### Rejecting Relays (block NIP-70 protected events)

These relays reject protected events per NIP-70 default behavior:

| Relay                      | Rejection Reason                   | AUTH Offered? |
| -------------------------- | ---------------------------------- | ------------- |
| `wss://relay.damus.io`     | blocked: event marked as protected | No            |
| `wss://relay.primal.net`   | blocked: event marked as protected | No            |
| `wss://nos.lol`            | blocked: event marked as protected | No            |
| `wss://relay.snort.social` | blocked: event marked as protected | No            |

### Auth-Required Relays

These relays require authentication but still don't accept protected events from new users:

| Relay                   | Notes                                                          |
| ----------------------- | -------------------------------------------------------------- |
| `wss://wot.nostr.party` | Web of Trust relay - requires being in someone's trust network |
| `wss://purplepag.es`    | Long-form content relay - AUTH required but not sufficient     |

### Tested but Unreachable

These relays were unreachable during testing (may be temporary):

- `wss://relay.nostr.band`
- `wss://relay.nostr.wine`
- `wss://eden.nostr.land`
- `wss://nostr.land`
- `wss://nostr.mutinywallet.com`
- `wss://cache1.primal.net`
- `wss://filter.nostr1.com`
- `wss://relay.nostr.dev.br`
- `wss://relay.nostr.inosta.cc`
- `wss://relay.nostr.pub`
- `wss://nostr.rocks`
- `wss://relay.nostr.info`
- `wss://relay.nostrich.de`
- `wss://nostr-01.yakihonne.com`
- `wss://nostr-02.yakihonne.com`
- `wss://relay.bitcoiner.social`
- `wss://relay.current.fyi`

## Architecture Recommendation

Based on our findings, applications should use this relay architecture:

```
Application
├── General Relays (NIP-65, kind 10002)
│   └── wss://relay.damus.io, wss://nos.lol, etc.
│       (for metadata, profiles, regular events)
│
├── Inbox Relays (NIP-17, kind 10050)
│   └── (for DMs and gift-wrapped messages)
│
└── Key Package Relays (kind 10051)
    └── wss://nostr-pub.wellorder.net, wss://relay.satlantis.io
        (for MLS key packages with NIP-70 protected tag)
```

### Recommended Key Package Relays

Use these relays for kind 10051 (MLS Key Package Relays):

```
wss://nostr-pub.wellorder.net
wss://relay.wellorder.net
wss://relay.satlantis.io
```

### Fetching Key Packages

When fetching another user's key packages:

1. First check their kind 10051 relay list
2. Fall back to kind 10002 (NIP-65) if not published
3. Query union of both for maximum discoverability

## Bug in whitenoise-rs

The whitenoise-rs reference implementation currently has a bug where it uses the same default relays for all relay types:

```rust
// src/whitenoise/relays.rs:88-97
pub(crate) fn defaults() -> Vec<Relay> {
    let urls: &[&str] = if cfg!(debug_assertions) {
        &["ws://localhost:8080", "ws://localhost:7777"]
    } else {
        &[
            "wss://relay.damus.io",    // Rejects protected events!
            "wss://relay.primal.net",  // Rejects protected events!
            "wss://nos.lol",           // Rejects protected events!
        ]
    };
    // ...
}
```

This means key package publishing to default relays **will fail** because all three reject NIP-70 protected events.

### Suggested Fix

whitenoise-rs should use different defaults for key package relays:

```rust
pub(crate) fn key_package_defaults() -> Vec<Relay> {
    let urls: &[&str] = &[
        "wss://nostr-pub.wellorder.net",
        "wss://relay.wellorder.net",
        "wss://relay.satlantis.io",
    ];
    // ...
}
```

## Output Format

The `--json` flag outputs a structured format:

```json
{
  "last_updated": "2026-02-08T15:31:09.617126Z",
  "relays": [
    {
      "url": "wss://relay.example.com",
      "reachable": true,
      "auth_challenge_received": false,
      "auth_success": false,
      "kind_results": {
        "1": {
          "unprotected_accepted": true,
          "protected_accepted": false,
          "protected_rejection_reason": "blocked: event marked as protected"
        },
        "443": {
          "unprotected_accepted": true,
          "protected_accepted": true
        }
      },
      "kind_results_with_auth": null,
      "tested_at": "2026-02-08T15:30:35.853122Z"
    }
  ]
}
```

## Related

- [NIP-66: Relay Discovery](https://github.com/nostr-protocol/nips/blob/master/66.md) - Used for `--discover`
- [NIP-70: Protected Events](https://github.com/nostr-protocol/nips/blob/master/70.md) - Why key packages are rejected
- [NIP-42: Authentication](https://github.com/nostr-protocol/nips/blob/master/42.md) - Used for `--with-auth`
- [MDK Issue #168](https://github.com/marmot-protocol/mdk/issues/168) - Original issue report
- [Marmot Protocol](https://github.com/marmot-protocol/marmot) - Protocol specification
- [whitenoise-rs](https://github.com/marmot-protocol/whitenoise-rs) - Reference implementation
- [nostr.co.uk/relays](https://nostr.co.uk/relays/) - Relay directory
