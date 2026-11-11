# Changelog

## Unreleased

### Fixed

- Report each relay's answer to a publish under the spelling the group or
  inbox list gave it (#3305). A relay spelled with an upper-case host or an
  explicit default port read as possibly exposed whatever it answered, so a
  group whose only relay was spelled that way never confirmed or rolled back a
  commit.
- Fetch independent directory queries concurrently, so KeyPackage and deletion
  reads overlap their relay waits while retaining separate event limits (#1813).
- Reuse notification settings, chat mutes, group records, and directory users
  across live subscription events (#1800). Track settings, mute, and group
  changes at the shared storage boundary, including engine-side forgets across
  connections. Honor timed mute expiry and skip non-notifying kinds before
  storage reads or blocking-task dispatch.
- Remove a redundant connected-relay restart from the manual relay lifetime test
  that timed out in the merge queue (#3287). Connected-relay reconnect coverage
  remains in the socket-watch and SDK tests.

## 0.15.0 - 2026-11-09

### Added

- Add host-driven automatic rejoin for eligible Unrecoverable group copies,
  with bounded retries and Rust status and explicit-retry APIs. Accepted
  recovery controls are durably retained before their inbox source is
  acknowledged. Live retries preserve the handshake; quarantined coordinators
  retain publication debt without scheduling more work.

### Security

- Verify live directory events independently at MDK's relay forwarding and
  directory ingestion boundaries before forwarding or persisting profiles,
  follow edges, relay lists, or KeyPackages (mdk#2521). Reject unsigned,
  tampered, and invalidly signed records even when a producer claims prior
  verification.
- Update the pinned Nostr SDK fork to reject tampered event content and invalid
  signatures even when the event ID is in its verification cache. This ports
  upstream nostrdevkit/nostr commits `0e08c3062186fbc6665161769037873e0a981cd5`
  and `a991ff004975deaf1ef5279969ba1c6a85f79203` (#1508).
