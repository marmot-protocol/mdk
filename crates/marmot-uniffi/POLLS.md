# Polls

MDK carries [NIP-88](https://github.com/nostr-protocol/nips/blob/master/88.md) poll events inside encrypted MLS
application messages. Poll and vote data never become public relay-query metadata: outer Marmot transport remains kind
445 and MDK omits NIP-88 `relay` tags.

Use `createPoll` with a question, two through ten option labels, `singleChoice` or `multipleChoice`, and an optional Unix
seconds deadline. MDK assigns stable option ids in display order (`"0"` through `"9"`). Questions are limited to 1024
UTF-8 bytes, labels to 256 bytes, and deadlines to at most 30 days after creation. Empty, whitespace-padded, control, and
bidirectional-override text is rejected. Poll creation follows MDK's canonical conversation classification: a named
conversation is a group even with two members, while an unnamed two-member conversation is direct and cannot create
a poll. An already-accepted open poll remains votable if the conversation is later classified as direct.

Use `castPollVote` with the poll event id and the complete selected option-id list. It is a replacement, not a delta:
send one id for single choice and one through ten unique ids for multiple choice. The poll must already be a valid local
timeline row in the same group and still be open. An empty selection is not an unvote operation.
MDK checks openness when the command is accepted and again against the response event's actual `created_at` timestamp
at the shared send boundary. If the deadline passes while the command is queued, the call fails and no response is
locally projected or confirmed.

`TimelineMessageRecordFfi.poll` is present on valid kind-1068 rows. It contains the ordered options and counts, total
participating authenticated identities, the account's effective sent selection, creator, deadline, and current open
state. Kind-1018 responses do not form timeline rows. For each authenticated author MDK selects the response with the
greatest `(created_at, canonical event id)`; author deletion, an accepted moderator deletion, or retention expiry falls
back to the newest retained valid response. Projection work considers at most the newest 64 retained responses per
author.
That bound is applied before full response validation: if one author publishes 64 newer malformed or out-of-window
replacements, an older valid response is no longer counted. This is an intentional per-author work bound and cannot
change another participant's vote. Deletion and retention can therefore also change a projected tally after `endsAt`.

If `kind == 1068` while `poll == nil`, the event used unsupported or invalid poll semantics. Render a localized
unsupported-poll state rather than presenting the raw question as a usable poll. Chat-list previews carry `kind` but
not the full poll projection; for kind 1068, hosts should render a localized poll label instead of the bare plaintext
question. Receive-side parsing ignores bounded unknown extension tags (including NIP-88 relay hints), while keeping
known tag shapes and the profile's question, option, and deadline limits strict.

`open` is recomputed whenever the timeline row is read or reprojected. A host that keeps a row on screen across its
deadline should also close its controls from the `endsAt` timestamp instead of waiting for another message. Local block
lists suppress alerts and presentation for blocked senders but do not rewrite the shared poll tally; every authenticated
member's valid response remains part of the group result.

Polls are coordination tools, not anonymous or election-grade voting. Every group member receives authenticated voter
identity with each response, and distributed clients/relays do not provide a global sequencer at the closing boundary.
Hosts must not describe the feature as anonymous or use the result for high-stakes elections.

The C surface mirrors this contract as `marmot_create_poll`, `marmot_cast_poll_vote`, and the nullable
`MarmotTimelineMessageRecord.poll`. Recompile C clients against the matching generated header because the timeline record
layout changes.
