# Message Processing System

This document describes how MDK handles message creation, processing, and state management for MLS group messages.

## Overview

MDK uses two related but distinct record types to track messages:

1. **`Message`** - Stores the decrypted content (the "rumor" - the inner Nostr event)
2. **`ProcessedMessage`** - Tracks whether we've seen and handled a wrapper event

The separation exists because:
- Not all processed events contain application messages (commits, proposals don't have `Message` records)
- We need to track processing state even when decryption fails
- Own messages need special handling since MLS can't decrypt messages we sent

## Record Types

### Message

Stores the decrypted rumor content for application messages only.

```rust
struct Message {
    id: EventId,              // Rumor event ID
    pubkey: PublicKey,        // Author
    kind: Kind,               // Nostr event kind
    mls_group_id: GroupId,    // Which group this belongs to
    created_at: Timestamp,    // When the rumor was created
    content: String,          // Message content
    tags: Tags,               // Nostr tags
    event: UnsignedEvent,     // Full rumor event
    wrapper_event_id: EventId, // The kind:445 wrapper
    epoch: Option<u64>,       // MLS epoch when processed
    state: MessageState,      // Current state
}
```

**MessageState values:**
| State | Meaning |
|-------|---------|
| `Created` | We sent this message; not yet confirmed by relay |
| `Processed` | Successfully decrypted and stored |
| `Deleted` | Deleted by original sender |
| `EpochInvalidated` | Decrypted with wrong epoch keys; content invalid. This only happens in the rare case that an epoch has to be rolled back because of a race condition |

### ProcessedMessage

Tracks processing state for ALL wrapper events (messages, commits, proposals).

```rust
struct ProcessedMessage {
    wrapper_event_id: EventId,        // The kind:445 wrapper event
    message_event_id: Option<EventId>, // Rumor ID (only for app messages)
    processed_at: Timestamp,          // When we processed it
    epoch: Option<u64>,               // MLS epoch (if known)
    mls_group_id: Option<GroupId>,    // Group ID (if known)
    state: ProcessedMessageState,     // Current state
    failure_reason: Option<String>,   // Why it failed (if applicable)
}
```

**ProcessedMessageState values:**
| State | Meaning |
|-------|---------|
| `Created` | We sent this; awaiting relay confirmation |
| `Processed` | Successfully processed |
| `ProcessedCommit` | This was a commit message we processed |
| `Failed` | Processing failed permanently |
| `EpochInvalidated` | Was processed but epoch rolled back |
| `Retryable` | Failed but eligible for retry after rollback |

---

## State Machines

### Sending a Message (Own Messages)

When we create and send a message:

```
┌─────────────────────────────────────────────────────────────────┐
│                      create_message()                           │
│                                                                 │
│  1. Encrypt rumor with MLS group keys                          │
│  2. Create kind:445 wrapper event                              │
│  3. Store Message with state=Created                           │
│  4. Store ProcessedMessage with state=Created                  │
│  5. Return wrapper event for publishing to relays              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  Message: Created             │
              │  ProcessedMessage: Created    │
              │                               │
              │  (cached locally, not yet     │
              │   confirmed by relays)        │
              └───────────────────────────────┘
                              │
                              │ App publishes to relays
                              │ Message comes back via subscription
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      process_message()                          │
│                                                                 │
│  1. Try to decrypt → fails with CannotDecryptOwnMessage        │
│  2. Look up ProcessedMessage by wrapper_event_id               │
│  3. See state=Created → this is our own message                │
│  4. Update Message state to Processed                          │
│  5. Update ProcessedMessage state to Processed                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  Message: Processed           │
              │  ProcessedMessage: Processed  │
              │                               │
              │  (confirmed: relay round-trip │
              │   successful)                 │
              └───────────────────────────────┘
```

**Key insight**: The `Created` → `Processed` transition confirms that the message successfully round-tripped through the relay network.

---

### Receiving a Message (Others' Messages - Happy Path)

When we receive a message from another group member:

```
              ┌───────────────────────────────┐
              │  Wrapper event arrives        │
              │  from relay subscription      │
              └───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      process_message()                          │
│                                                                 │
│  1. Validate event format and extract group ID                  │
│  2. Load group and decrypt NIP-44 layer                         │
│  3. Decrypt MLS layer → get rumor                               │
│  4. Verify author matches MLS sender credential                 │
│  5. Store Message with state=Processed                          │
│  6. Store ProcessedMessage with state=Processed                 │
│  7. Update group's last_message_at/last_message_id              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  Message: Processed           │
              │  ProcessedMessage: Processed  │
              │                               │
              │  (content available, fully    │
              │   processed)                  │
              └───────────────────────────────┘
```

---

### Receiving a Message (Failure - Permanent)

When decryption fails and won't ever succeed:

```
              ┌───────────────────────────────┐
              │  Wrapper event arrives        │
              │  from relay subscription      │
              └───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      process_message()                          │
│                                                                 │
│  1. Validation fails OR                                        │
│  2. Decryption fails (wrong keys, corrupted, etc.)             │
│  3. Store ProcessedMessage with state=Failed                   │
│     - Include mls_group_id and epoch if known                  │
│     - Include sanitized failure_reason                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  No Message record            │
              │  ProcessedMessage: Failed     │
              │                               │
              │  (blocked from reprocessing)  │
              └───────────────────────────────┘
```

**Note**: Failed messages are blocked from reprocessing on subsequent encounters. This prevents expensive repeated decryption attempts for permanently invalid messages.

---

### Epoch Rollback Scenario

This is the most complex flow. It occurs when we receive a "better" commit for an epoch we already processed.

**Background**: MIP-03 defines deterministic commit ordering. When two commits compete for the same epoch, the one with the earlier timestamp (or smaller event ID as tiebreaker) wins.

```
┌─────────────────────────────────────────────────────────────────┐
│                    INITIAL STATE                                │
│                                                                 │
│  - We applied Commit A for epoch N                              │
│  - We decrypted messages M1, M2, M3 using Commit A's keys       │
│  - Message M4 arrived but failed to decrypt                     │
│                                                                 │
│  M1, M2, M3: Message=Processed, ProcessedMessage=Processed      │
│  M4: No Message, ProcessedMessage=Failed                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Commit B arrives for epoch N
                              │ Commit B is "better" than Commit A
                              │ (earlier timestamp or smaller ID)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ROLLBACK TRIGGERED                           │
│                                                                 │
│  1. Restore group state to before epoch N                       │
│  2. Apply Commit B instead of Commit A                          │
│  3. Update message states:                                      │
│                                                                 │
│     M1, M2, M3 (decrypted with wrong keys):                     │
│       Message: Processed → EpochInvalidated                     │
│       ProcessedMessage: Processed → EpochInvalidated            │
│       (application decides to show/hide with message)           │
│                                                                 │
│     M4 (failed to decrypt):                                     │
│       ProcessedMessage: Failed → Retryable                      │
│       (might decrypt now with correct keys)                     │
│                                                                 │
│  4. Notify app via callback with:                               │
│     - invalidated_messages: [M1, M2, M3]                        │
│     - messages_needing_refetch: [M4]                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ App re-fetches M4 from relays
                              │ and calls process_message() again
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    RETRY PROCESSING                             │
│                                                                 │
│  1. Check ProcessedMessage state                                │
│  2. See state=Retryable → allow reprocessing                    │
│  3. Decrypt with correct epoch keys → success!                  │
│  4. Create Message with state=Processed                         │
│  5. Update ProcessedMessage to state=Processed                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  M4 now has:                  │
              │  Message: Processed           │
              │  ProcessedMessage: Processed  │
              │                               │
              │  (correctly decrypted with    │
              │   Commit B's keys)            │
              └───────────────────────────────┘
```

---

### Commit Processing

Commits have their own flow and use `ProcessedCommit` state:

```
              ┌───────────────────────────────┐
              │  Commit event arrives         │
              └───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│               process_commit_message_for_group()                │
│                                                                 │
│  1. Validate sender is authorized (admin or self-update)        │
│  2. Validate no identity changes in proposals                   │
│  3. Create epoch snapshot (for potential rollback)              │
│  4. Merge staged commit into group state                        │
│  5. Save exporter secret for new epoch                          │
│  6. Sync group metadata                                         │
│  7. Store ProcessedMessage with state=ProcessedCommit           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  No Message record            │
              │  ProcessedMessage:            │
              │    ProcessedCommit            │
              │                               │
              │  (commit applied, group       │
              │   state updated)              │
              └───────────────────────────────┘
```

**Note**: Commits do NOT go through the `EpochInvalidated`/`Retryable` flow. Only application messages do.

---

### Proposal Processing

Proposals are stored as pending and don't create `Message` records:

```
              ┌───────────────────────────────┐
              │  Proposal event arrives       │
              └───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              process_proposal_message_for_group()               │
│                                                                 │
│  Depending on proposal type:                                    │
│                                                                 │
│  Add/Remove proposals:                                          │
│    → Store as pending for admin approval                        │
│    → ProcessedMessage with state=Processed                      │
│                                                                 │
│  Self-remove (leave) + receiver is admin:                       │
│    → Auto-commit the proposal                                   │
│    → ProcessedMessage with state=Processed                      │
│                                                                 │
│  Extension/Update/Other:                                        │
│    → Ignore with warning                                        │
│    → ProcessedMessage with state=Processed                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## State Transition Summary

### MessageState Transitions

```
Created ─────────────► Processed
   │                      │
   │                      │ (rollback)
   │                      ▼
   │                 EpochInvalidated
   │
   └──────────────────► Deleted (via delete event)
```

### ProcessedMessageState Transitions

```
                    ┌──────────────────┐
                    │     Created      │ (own messages only)
                    └────────┬─────────┘
                             │
                             ▼
┌──────────┐         ┌──────────────────┐         ┌─────────────────┐
│  Failed  │◄────────│    Processed     │────────►│ EpochInvalidated│
└────┬─────┘         └──────────────────┘         └─────────────────┘
     │                       ▲
     │ (rollback)            │
     ▼                       │
┌──────────┐                 │
│Retryable │─────────────────┘
└──────────┘    (retry succeeds)


┌──────────────────┐
│ ProcessedCommit  │ (commits only, no transitions out)
└──────────────────┘
```

---

## Which States Apply to Which Message Types

| Message Type | Creates `Message` record? | Valid `ProcessedMessageState` values |
|--------------|---------------------------|--------------------------------------|
| **Own application message** | Yes | `Created` → `Processed` |
| **Others' application message** | Yes | `Processed`, `Failed`, `Retryable`, `EpochInvalidated` |
| **Commit** | No | `ProcessedCommit` |
| **Proposal** | No | `Processed` |
| **External Join Proposal** | No | `Processed` |

---

## Deduplication Behavior

When `process_message()` encounters a wrapper event we've seen before:

| Existing State | Behavior |
|----------------|----------|
| `Created` | Continue processing (own message returning from relay) |
| `Processed` | Continue processing (idempotent) |
| `ProcessedCommit` | Continue processing (idempotent) |
| `Failed` | **Block** - return `Unprocessable` |
| `EpochInvalidated` | **Block** - return `Unprocessable` |
| `Retryable` | Continue processing (retry after rollback) |

---

## Key Implementation Functions

| Function | Purpose |
|----------|---------|
| `create_message()` | Send a new message - creates `Message` + `ProcessedMessage` in `Created` state |
| `process_message()` | Main entry point for incoming messages - orchestrates the full flow |
| `process_application_message()` | Handle decrypted application messages |
| `process_commit()` | Handle commit messages |
| `process_proposal()` | Handle proposal messages |
| `handle_processing_error()` | Error recovery including own-message detection |
| `record_failure()` | Persist failure state to block reprocessing |

---

## Invariants

1. **Own messages never enter `Failed` or `Retryable` state** - They start in `Created` and go to `Processed`

2. **`Message` records only exist for application messages** - Commits and proposals don't have content to store

3. **`EpochInvalidated` means content is lost** - Messages decrypted with wrong epoch keys cannot be recovered

4. **`Retryable` means content might be recoverable** - Messages that failed to decrypt may succeed after rollback

5. **`ProcessedCommit` is terminal** - Commits don't transition to other states

6. **Failed messages block reprocessing** - Prevents expensive repeated attempts on permanently invalid messages
