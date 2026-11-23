---
title: "Replies and Thread Messages"
created: 2026-11-20
updated: 2026-11-23
tags: [marmot, overview, messages, threads, nip-22, clients, agents]
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
on a thread message nests under the same root. When this device no longer stores the root, its kind and author come
from the `K`/`P` of the nearest ancestor that names it; with none, the send is refused. The first lowercase `e` is
always the parent, which is what White Noise Linux already reads.

MDK leaves out NIP-22's optional parent-author `p`. On Marmot messages a `p` tag is a mention (NIP-27): it raises the
@-badge and breaks through a muted chat, which an ordinary thread answer must not. Mentions in the text get their `p`
tags as on kind 9.

A poll or sticker joins a thread with `E`/`K`/`P` message tags (`create_tagged_poll`, `send_tagged_sticker`). An `e`
on a poll or sticker always means "inline reply to", never "in this thread".

### Agent items in threads

A subagent is a thread hanging from its `task` item, kind 1201 (marmot-agents D-121). Every event in a subagent's tree
carries all six NIP-22 tags, as NIP-22 defines them:

| Tag | Names |
| --- | --- |
| `["E", <task item>, "", <agent>]`, `["K", "1201"]`, `["P", <agent>]` | the root: the top-level subagent's `task` item |
| `["e", <parent>, "", <agent>]`, `["k", "1201"]`, `["p", <agent>]` | the parent: the `task` item of the subagent the event belongs to |

For a top-level subagent's own events root and parent are the same item. A nested subagent's `task` item has the
subagent that started it as its parent, so the whole tree shares one root and nesting is read from the parent. A
top-level `task` item carries no thread tags.

- **Items.** A kind 1201 with `E` joins that thread and answers the item its `e` names, or the root without one. Its
  `reply_to_message_id_hex` is that parent, unless the item names a turn's starting message with `started_by`. MDK
  refuses an `e` on a kind 1201 without an `E`: there it would read as an edit's target.
- **Edits.** A later version is a kind-1009 edit whose one `e` names its target, so it carries no parent `e`. It may
  repeat `E`/`K`/`P`. The item stays where its first event placed it, whatever thread tags an edit carries.
- **The agent's words** are kind 1111 comments with the same tags. One with an `E`, whose `K` is 1201 and whose `P` is
  its own author, neither notifies, wakes members nor counts as unread (D-122). Items in the thread keep their own
  alert rule (D-024): a subagent's approval or question alerts.
- **The parent `p`** always names the event's own author. A `p` is a mention only for the account it names, and an
  account's own messages never notify, raise the @-badge or count as unread, so it is never a mention.
- **A person writing in the thread** sends an ordinary thread message with `send_thread_message`. Answering any item
  in the tree names the top-level `task` item as root and the item answered as parent.

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
  the reply target; for a thread message it is the parent. For an agent item it is the message that started its turn
  (`started_by`), else its thread parent.
- `thread`: `root_message_id_hex` and `parent_message_id_hex`, set for every thread message and for a chat, sticker,
  poll or agent item that joined a thread with `E`. A joined row without its own reply target answers the root; an
  agent item answers its `e`, or else the root, never its `started_by`. `thread` is null
  everywhere else, including on an inline reply to a thread message (its reply preview carries the target's `thread`).

A deleted row keeps both fields: deletion hides its content, not where it sits, so a thread view can show the
placeholder in place. Clients never parse these tags.

## Chat activity

A thread message counts wherever kind 9 does: chat-list preview, order, unread count, mentions and the @-badge,
edits of the chat-list preview, the sender's own read position, chat-list text search and timeline search, the
`NewMessage` live update, Markdown content tokens and mention identities, local notifications, background-wake
notifications, push to the other members (also when Linux sends it through `send_custom_event`, or the queue publishes
it later), bringing back a locally deleted chat, author edits and deletes, history import, retention of its media
keys in storage and in the engine, and the `wn-agent` feed (incoming messages with their parent as the reply target,
edits and deletes, live and on replay; a message deleted before the agent sees it reaches the agent only as its
deletion). The agent's own words in a thread under one of its items are the one exception: they send no
notification, wake no one and are never unread, so they raise neither the unread count nor the @-badge
([above](#agent-items-in-threads)). They count everywhere else, the chat-list preview and order included.

A kind 1111 with a numeric `k` but no lowercase `e` is a comment without a parent. Like every comment it keeps its
author's edits and deletes and its attachments, and timeline search matches it as it matches every row. It stays a
custom row, though: it is not chat activity, so the rest of the list does not apply. A kind 1111 with neither is a plain
custom event.

A deletion can reach the `wn-agent` feed after the message it deletes: a message deleted before the connector writes
it is dropped, but one deleted after it was written arrives as the message followed by its deletion, live or on
replay.

Admin removal is the exception: a group admin removing another member's message applies to kind 9 only, on the sending
and the receiving side. Extending it changes what receivers accept, so it needs its own change.

## Display rules

- **Clients without a thread view** (iOS, macOS and Android today) show every thread message inline in the main
  timeline with a one-level quote of its parent, exactly like an inline reply, and answer any message, thread
  messages included, with `reply_to_message`. An agent item in a thread is shown the same way, quoting
  `reply_to_message_id_hex`; it is never hidden.
- **Clients with a thread view** (Linux) build it from `thread`: `parent_message_id_hex` to nest, `root_message_id_hex`
  to group. They send with `send_thread_message`, and put polls and stickers in a thread with `E`/`K`/`P` tags naming
  `root_message_id_hex`.

## Fixtures

[`crates/storage-sqlite/fixtures/thread-messages.json`](../../../crates/storage-sqlite/fixtures/thread-messages.json)
lists every wire form above with the reply target, root and parent each one projects. The storage test
`thread_message_fixtures_project_reply_target_and_thread` replays it; client teams can reuse it for their own checks.
