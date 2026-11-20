---
title: "Replies and Thread Messages"
created: 2026-11-20
updated: 2026-11-20
tags: [marmot, overview, messages, threads, nip-22, clients]
status: overview
---

# Replies and Thread Messages

White Noise has two ways to answer a message. Every client reads and writes both the same way, with or without a
thread view. Full threads (thread graphs, paged descendants, thread summaries, per-thread read state) are
[mdk#2787](https://github.com/marmot-protocol/mdk/issues/2787); nothing on this page changes when they arrive.

## Two kinds of answer

| | Inline reply | Thread message |
| --- | --- | --- |
| Event | kind 9 chat with `["e", target]` and `["q", target]` | kind 1111 [NIP-22](https://github.com/nostr-protocol/nips/blob/master/22.md) comment |
| Send with | `reply_to_message` | `send_thread_message` (text, attachments or both, plus tags) |
| Who sends it | every client | clients with a thread view |

They are separate things. MDK never turns one into the other, and historical kind 9 replies stay as they are. An
inline reply to a thread message is still kind 9.

## Wire format

MDK builds every tag of a new thread message from the parent's row:

| Tag | Names |
| --- | --- |
| `["E", <root id>, "", <root author>]`, `["K", <root kind>]`, `["P", <root author>]` | the thread root |
| `["e", <parent id>, "", <parent author>]`, `["k", <parent kind>]` | the immediate parent |

A parent outside any thread is the root. A parent that is itself in a thread passes its root on, so a thread started
on a thread message nests under the same root. The first lowercase `e` is always the parent, which is what White
Noise Linux already reads.

MDK leaves out NIP-22's optional parent-author `p`. On Marmot messages a `p` tag is a mention (NIP-27): it raises the
@-badge and breaks through a muted chat, which an ordinary thread answer must not. Mentions in the text get their `p`
tags as on kind 9.

A poll or sticker joins a thread with `E`/`K`/`P` message tags (`create_tagged_poll`, `send_tagged_sticker`). An `e`
on a poll or sticker always means "inline reply to", never "in this thread".

### Older forms MDK still reads

| Form | Sent by | Read as |
| --- | --- | --- |
| kind 1111 with `e` + `k`, no `E` | White Noise Linux since 2026-11-17 | parent is `e`; root found by walking parents |
| kind 1111 with `e` only | White Noise Linux before 2026-11-17 | the same; migration 0217 repairs stored rows |
| kind 1068 poll with a plain `e` | White Noise Linux | an inline reply to `e`, not placed in a thread |

The root walk follows stored parents while each is a thread message without `E`. It stops at an ancestor that names a
root with `E` (that root), at one outside any thread (that ancestor), or at one not stored on this device (that id,
until the ancestor arrives). A kind 1111 with neither a lowercase `e` nor a numeric `k` stays a custom event.

## What rows expose

Every timeline record, conversation-window message and reply preview carries:

- `reply_to_message_id_hex`: what a client without a thread view quotes. For an inline reply, poll or sticker it is
  the reply target; for a thread message it is the parent.
- `thread`: `root_message_id_hex` and `parent_message_id_hex`, set for every thread message and for a chat, sticker or
  poll that joined a thread with `E`. A joined row without its own reply target answers the root. `thread` is null
  everywhere else, including on an inline reply to a thread message (its reply preview carries the target's `thread`).

Clients never parse these tags.

## Chat activity

A thread message counts wherever kind 9 does: chat-list preview, order, unread count, mentions and the @-badge,
chat-list text search and timeline search, the `NewMessage` live update, Markdown content tokens and mention
identities, local notifications, background-wake notifications, push to the other members (also when Linux sends it
through `send_custom_event`, or the queue publishes it later), bringing back a locally deleted chat, author edits and
deletes, history import, and retention of its media keys. Kind 1111 events without a
parent stay custom events and do none of this.

## Display rules

- **Clients without a thread view** (iOS, macOS and Android today) show every thread message inline in the main
  timeline with a one-level quote of its parent, exactly like an inline reply, and answer any message, thread
  messages included, with `reply_to_message`.
- **Clients with a thread view** (Linux) build it from `thread`: `parent_message_id_hex` to nest, `root_message_id_hex`
  to group. They send with `send_thread_message`, and put polls and stickers in a thread with `E`/`K`/`P` tags naming
  `root_message_id_hex`.

## Fixtures

[`crates/storage-sqlite/fixtures/thread-messages.json`](../../../crates/storage-sqlite/fixtures/thread-messages.json)
lists every wire form above with the reply target, root and parent each one projects. The storage test
`thread_message_fixtures_project_reply_target_and_thread` replays it; client teams can reuse it for their own checks.
