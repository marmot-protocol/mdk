---
title: "Private moderation reports to the deployment operator"
created: 2026-10-10
updated: 2026-10-10
tags: [marmot, moderation, nip-56, nip-59, white-noise]
---

# Private moderation reports to the deployment operator

White Noise users can privately report another account to the deployment's moderation team, the Internet Privacy
Foundation (IPF). This is a second channel. It is additive: in-group moderation (`report_message`, `content_reports`,
`dismiss_reports`, admin `delete_message`; see [content moderation](./overview/content-moderation.md)) is unchanged and
stays the primary path, because admins moderate their own groups. A moderation report lets the operator act at the
account level, for example by refusing an npub on the relays it operates.

This page is the wire contract for the operator's reader. The implementation lives in
`crates/marmot-app/src/moderation_reports.rs`. The host API is `submit_moderation_report` in
[MarmotKit](../../crates/marmot-uniffi/API-REFERENCE.md#marmotsubmit_moderation_report).

## What a report contains

A report contains only these three things:

- the reported account's public key;
- a NIP-56 report type: `nudity`, `malware`, `profanity`, `illegal`, `spam`, `impersonation` or `other`;
- the reporter's optional explanation, trimmed and cut to at most 1,000 Unicode scalar values. An empty explanation is
  sent as empty content.

It never contains message content, message ids, MLS or Nostr group ids, relay or group metadata, or timestamps of the
reported message. There is no `e` tag. Inner Marmot message ids are not public, and MDK does not share them.

## Event layers

Every report is a NIP-59 gift wrap of a NIP-56 rumor. MDK builds it with the same NIP-59 construction it uses for
Welcomes (`transport_nostr_peeler::gift_wrap_rumor`).

### Rumor: kind 1984, unsigned

| Field | Value |
| --- | --- |
| `pubkey` | the reporter's account key |
| `created_at` | the time of submission |
| `content` | the explanation, or `""` |
| `tags` | exactly the three below, in this order |

```json
["p", "<reported pubkey hex>", "<report type>"]
["L", "chat.whitenoise.report"]
["l", "<report | block>", "chat.whitenoise.report"]
```

The `l` value records the user action. `report` is a plain Report. `block` comes from "Block and Report". The host
picks the report type, and a Block and Report action sends `other` unless the user chose one. Blocking is a separate,
account-private NIP-51 operation (`block_user`), and the report does not reveal it.

### Seal: kind 13

The seal is signed by the reporter's account key and has no tags. Its content is the NIP-44 encryption of the rumor
JSON to the moderation team's reports key. Its `created_at` is randomized up to two days into the past.

### Gift wrap: kind 1059

The wrap is signed by a one-time key that is generated for this report and dropped once the wrap is signed. Its content
is the NIP-44 encryption of the seal JSON to the reports key. Its only tag is `["p", "<reports pubkey hex>"]`. Its
`created_at` is randomized up to two days into the past.

Relays and outside observers see only a kind-1059 event from an unlinkable key, addressed to the reports key. MDK
publishes the wrap through a client that never sends NIP-42 AUTH as the reporter, and only to the configured reports
relays. It never uses the reporter's general relay list or outbox.

## Reading reports

Each deployment configures a reports key and a relay set per build flavor, so production and staging never mix.
A reader:

1. subscribes on those relays to `{"kinds": [1059], "#p": ["<reports pubkey hex>"]}`. Use a `since` at least nine
   days before the reader's last checkpoint: a wrap's `created_at` is randomized up to two days into the past, and a
   client may keep retrying the same signed wrap for up to seven days before a relay accepts it. Relay receipt time is
   not in the event, so a shorter lookback can miss a late first publication; deduplication (step 6) makes the overlap
   harmless;
2. verifies the wrap signature, NIP-44-decrypts the content with the reports key, and parses the seal;
3. verifies the seal signature. The seal's `pubkey` is the authenticated reporter;
4. NIP-44-decrypts the seal content using the seal's `pubkey`, parses the rumor, and rejects it unless
   `rumor.pubkey == seal.pubkey`;
5. accepts kind 1984 only, requires exactly one `p` tag carrying a valid 32-byte key and a known report type, and reads
   the `l` label in the `chat.whitenoise.report` namespace. It should treat unknown tags as unexpected rather than
   meaningful;
6. deduplicates by wrap event id. A retried report is the same signed wrap, so it has the same id.

rust-nostr's `UnwrappedGift::from_gift_wrap` does steps 2–4. The authenticated reporter lets the operator rate-limit
reports and weigh them against abuse. A report is a claim by its reporter, not proof.

## Client behavior

- **Configuration.** Hosts pass `MarmotOptions.moderation_report_config` (`recipient_pubkey` as hex or `npub`, plus
  `relays`) or call `configure_moderation_reporting`. Each relay must pass the relay safety policy. Any bad key or
  relay rejects the whole configuration, and `moderation_reporting_available()` then returns false. Without a valid
  configuration, `submit_moderation_report` returns `ModerationReportingNotConfigured` and publishes nothing.
- **Outcomes.** These follow send summaries. `Published` means a configured relay accepted the wrap.
  `AcceptedPending` means no relay accepted it yet, and every failure provably never left the device.
  `CompletionUnknown` means a relay may have received it without acknowledging, and it stays `CompletionUnknown` until
  a relay accepts the wrap. Neither retained state is a failure.
- **Durability.** The signed wrap is staged in the account's SQLCipher database before any relay sees it. Each
  `catch_up_accounts` call starts a background retry for accounts with queued reports. Runtime shutdown cancels an
  in-flight publish and leaves the report queued. The queued row holds only the ciphertext wrap, the recipient key, an
  opaque local id and a one-way dedupe key. The wrap is deleted once a relay accepts it. A queued report addressed to a
  different recipient than the current configuration is dropped, never redirected. An unpublished report is abandoned
  after seven days.
- **Idempotency.** The same account, reported key, report type and origin within 10 minutes return the existing
  outcome and do not mint a new wrap.
- **Rate limit.** Each account may submit 20 reports per rolling hour. Beyond that the call returns
  `ModerationReportRateLimited`. This only guards against runaway clients; it is not abuse protection.
- **Validation.** Reporting your own key returns `CannotReportSelf`. A key that is not 64-character hex or `npub`
  returns `InvalidReportedPublicKey`.
- **Account isolation.** Queued reports live in the reporting account's database. `sign_out` and `sign_out_and_wipe`
  cancel in-flight report work, delete the account's queued and published report rows, and refuse new reports and
  retries until the sign-out or wipe has committed. If that purge fails, sign-out reports its local cleanup as
  incomplete. Signed-out accounts cannot report.
- **Telemetry.** Logs and traces carry only aggregate fields, such as the `moderation_report_submitted` event with
  `origin` and `outcome`, and retry-pass counts. They never carry the reported key, the explanation, the one-time key
  or event ids.
- **No other dependencies.** Reporting needs no NIP-17 DM, MLS group or KeyPackage. The reports key does not need to
  be a White Noise account.
