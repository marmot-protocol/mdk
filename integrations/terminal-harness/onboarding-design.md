# First-use experience for terminal agent connectors

Product proposal, 2026-10-05. This document describes the intended experience
and its delivery order. It does not claim that the proposed pairing, title, or
completion defaults are already shipped.

The first successful experience should be: choose the agent you already run,
copy setup from White Noise, approve the concrete installation on your trusted
computer, verify the connector account, and receive a reply in one reusable task
group. Extra groups and preferences can follow that first success.

Current capability references: [`prepare_prompt` in the shared bridge](src/bridge.rs)
applies the privately stored goal on each invocation;
[`SessionStore`](src/store.rs) retains independent group goals and sessions.
[`GroupCreate` in agent-control](../../crates/agent-control/src/lib.rs) provides
group creation, and [bootstrap](../../crates/agent-connector/src/bootstrap.rs)
owns the existing identity/KeyPackage handoff. These capabilities do not provide
the verified pairing or typed completion flow proposed below.

The mobile observations are pinned to the inspected
[Android agent list](https://github.com/marmot-protocol/whitenoise-android/blob/be4fd6adfcd8e7606380a12c9d61a220fc401c74/app/src/main/java/dev/ipf/whitenoise/android/ui/settings/AgentConnector.kt),
[Android setup prompts](https://github.com/marmot-protocol/whitenoise-android/blob/be4fd6adfcd8e7606380a12c9d61a220fc401c74/app/src/main/res/values/strings.xml),
and [iOS connector prompts](https://github.com/marmot-protocol/whitenoise-ios/blob/94edeaf9595fc8faad0432a0ec865efa8756482b/whitenoise-ios/Settings/AIAgentConnector.swift).
These source observations are not a claim about every installed app version.

## Defaults

| Decision | Recommended default |
| --- | --- |
| Identity | A separate private connector account per installation; no public kind-0 profile |
| Recognition | A private nickname for that verified account, editable by the user |
| Navigation | Stable connector emoji, optional stable project emoji, short task label |
| Titles | Rename early for a new task; preserve the title on completion and during follow-ups |
| Sessions | One persistent backend session/workspace per group; start with one group |
| First contact | Explicit invitation and full-key check until verified pairing is available |
| Completion | Offer the existing completion-mention instruction; build a typed completion signal separately |
| Execution | Preserve the backend's existing permission and sandbox settings |

Suggested connector cues are `🧑‍💻` for Codex, `🦀` for Claude Code, `🥧` for Pi,
and `🛠️` for OpenCode. They identify the connector family, not the installation
or signer. Users can choose other cues. A local nickname can distinguish two Codex installations;
only the verified public key establishes which account is which.

## Identity and first contact

Names, profile pictures, and group titles are attacker-controlled presentation.
A message containing "I am your agent" is not a verification step. Compare the
entire connector npub from the trusted computer with the actual account in the
phone app. A QR or a copied nprofile carries the same public key more conveniently;
its name and relay hints do not establish trust. Key changes require a fresh
verification, rather than silently inheriting a nickname's trust.

Bootstrap already creates an isolated account and advertises its KeyPackage
without publishing a public kind-0 profile. This is not anonymity: public-key
and KeyPackage metadata can still be observable. Retain that behavior. A private
nickname belongs in the phone's local contact data, not the Nostr directory.
Do not import the person's signing key into the connector.

The existing mobile setup prompt asks for installation approval. Keep that
approval: installing persistent services and exposing a local coding agent to
remote prompts deserves a concrete explanation. The installer should keep its
checksum-verified release flow and existing sender allowlist. It must distinguish
files installed, service startup, identity available, invitation accepted, and
backend reply verified. Neither `/status` nor a service-start acknowledgement
proves that the authenticated backend can answer.

The smallest reliable workflow today is user-created: add the verified account,
create one normal group, select a workspace, and check a harmless backend reply containing a
fresh word chosen by the user. That word distinguishes a new test from stale
replies; it does not authenticate the key. After installing a title-capable
connector/harness release, admin permission for title edits should be a
deliberate grant to the verified account. It confers broader group authority;
ordinary messaging does not require it. Avoid
making ten empty groups on installation. Let users add groups with the same
account as their workflow grows.

### Agent-created groups

The control API already exposes `GroupCreate`; no new messaging protocol is
needed just to create a group. Creation alone does not establish that an incoming
invitation came from the locally installed connector.

A future guided pairing flow should bind a setup attempt to the phone account,
the newly established connector public key, and the intended initial group. The
phone should display an explicit verification step against the trusted laptop,
then save the verified key association and offer a local nickname. An unsolicited
invite from a different key must remain unverified, even if its title matches.
Do not run phone tasks or grant remembered trust before that check succeeds.

Make this flow bounded, cancellable, and safe to resume. Persist the pairing
intent before creating a group or sending the welcome message; reconcile an
uncertain response rather than creating another group. Limit a completed setup
attempt to one initial group and one welcome send. Report relay, key-package,
invite, and backend failures at the stage where they occur. Cancelled or expired
attempts must not silently revive after a restart.

An agent can send its first message promptly, but the app must show the pending
verification state before treating that conversation as trusted. A design that
lets the phone pin the expected key from an authenticated local handoff could
remove the manual comparison later; copying only the person's public npub does
not provide that handoff. Do not label a pairing code or invite as authenticated
without specifying and reviewing exactly how its key binding is protected.

## Task titles and reusable groups

Keep the first cue fixed per connector and project cues stable across its groups.
Use a short label such as `🧑‍💻💬 Improve invite setup`: usually two to four words
after the cues and at most 32 displayed units overall. Omit the project emoji
when no workspace/project is known. Do not put full paths, account keys, personal
details, URLs, or secrets in titles.

Rename only for a meaningful new task. A follow-up, correction, approval,
compaction, test run, temporary error, or finished task should not cause title
churn. Keep the last task label so the group remains findable. Use the current
authenticated account/group route; never locate a target by its title or by
guessing from the working directory. Verify the update, and reconcile an unknown
write outcome without replaying it. Lack of admin permission should leave the
title alone while authorized work continues.

The model can choose the task words during its normal turn; avoid another model
call solely to name the group. The shared harness should supply the policy and
current-group tool context on each turn so compaction does not erase it. Provide
an opt-out and user-owned connector/project cue preferences; a user's explicit
title request overrides the automatic policy. No host-specific script or fixed
operator account should be required for an ordinary installation.

Existing per-group session, workspace, goal, and reset-generation state should
remain the source of session continuity. `/new` ends the stored session when
handled and preserves the workspace; it does not cancel in-flight work or erase
backend transcripts. A new topic and a fresh backend session are different
choices. Follow-ups while work is active must continue the unfinished objective.
Do not promise identical live steering across backends that have different
invocation contracts.

The phone needs truthful working, pending-delivery, and idle presentation to help
users choose a free group. Derive it from the current run and durable delivery
state, not task titles, missing recent text, or the existence of a session id.
Status must recover across disconnects and app restarts without declaring an
uncertain task finished. This is a separate capability from automatic titles.

## Completion notifications

Keep the user-reported `@npub` workaround available as an advisory per-group goal,
targeted at the user's full verified account key and limited to a final answer.
Explain that `/goal <text>` replaces an existing goal. Let users remove the
preference and never hard-code the operator's account into a shipped prompt.
The [Markdown tokenizer](../../crates/marmot-markdown/src/inline.rs) recognizes
`@npub` mentions, and the inspected
[Android channel mapping](https://github.com/marmot-protocol/whitenoise-android/blob/be4fd6adfcd8e7606380a12c9d61a220fc401c74/app/src/main/java/dev/ipf/whitenoise/android/notifications/NotificationChannelSpec.kt)
exposes Mentions separately from group-message notifications. This candidate
has not been tested for notification delivery on devices; iOS needs its own
supported notification presentation and controls.

Do not append a mention to every assistant text block. Claude can emit completed
assistant text between tool calls; other backends also have distinct text and
terminal events. A text block, zero exit code, task status question, or early
model final is insufficient proof that the accepted objective and its durable
delivery are complete. On resumable or uncertain failures, preserve work and
report the real state rather than sending a success notification.

The durable solution is a shared completion classification with a current turn
identity, the relevant user recipient, terminal outcome, and final-delivery
receipt. Review how it fits existing MDK activity/message types before adding
another wire event. Derive it in the connector/runtime rather than asking the
model to decide push urgency. Preserve the classification through bindings and
each app's notification path. Deduplicate by the durable completion identity,
respect mute/notification preferences, and avoid repeating alerts during
reconnect or final-message reconciliation. A mention fallback must not cause a
second alert for the same completion.

## Delivery order and verification

1. **Installer handoff:** full-key comparison, private nickname guidance,
   one normal group without an admin grant, workspace selection, and pending
   round-trip status.
   This patch changes that handoff and the canonical quickstart. It does not
   publish profiles, create groups, change permissions, or enable auto-titles.
2. **Title defaults:** build on the
   [harness group-profile exposure (PR 2115)](https://github.com/marmot-protocol/mdk/pull/2115)
   once included in a matching release. Add per-turn default policy and editable preferences,
   including non-admin, concurrent-group, compaction, and unknown-write tests.
3. **Mobile parity and pairing:** the inspected Android source offers Codex but not Claude
   or Pi in its agent list; iOS offers all three. Align their installation prompts
   and key-verification handoff first, then build the bound agent-created flow.
   Exercise wrong keys, forged display names, replay, expiry, cancellation,
   disconnect, and restart. A real phone/backend reply is the acceptance test.
4. **Activity and completion:** verify per-backend terminal semantics and durable
   delivery, then expose separate app notification preferences. Test intermediate
   assistant text, failures, pending work, chunked finals, media finals, replay,
   muted groups, and restart. Physical Android and iOS behavior both matter.

Keep these changes reviewable and sequential where they depend on shared MDK
capabilities. The new product work does not authorize releases, merges, or
changing deployed agent services. A proposal or fake-backend fixture is not
proof that the full first-use experience is already working on a phone.
