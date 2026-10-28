# Invitation and Unrecoverable group recovery

When a locally published invite loses branch selection, its Welcome may already have installed the losing branch
on the recipient. The inviter's success report does not prove that the invitation survived convergence (#1735).

The engine retains the original invitation intent with a durable recovery record. The app resolves fresh KeyPackages
using the ordinary safe directory-discovery path. Every invite fetches fresh packages; recovery additionally
refreshes relay discovery instead of reusing prewarmed routes. The engine rejects
packages consumed by the lost invitation, changed or duplicate recipient identities, and loss of inviter authority.
Only recipients absent from the canonical roster are invited again. Fresh intent replaces the recovery record in the
same transaction that queues it; publication uses the ordinary outbound queue and acknowledgement rules.
If a requested admin joined through another path without that grant, recovery reports `Conflict` and asks for
a new admin action. Invitations for missing recipients still proceed, including their requested initial grants;
already-present admins do not cause a conflict.

One lookup is reserved durably before each network attempt. Each attempt uses the ordinary 50-second
member-resolution deadline. Eight attempts are allowed, with delays of 5 seconds, 30 seconds, 2 minutes, 10 minutes,
1 hour, 6 hours, then 24 hours twice. The last lookup occurs about 31 hours after the first; exhaustion is recorded
after the final 24-hour wait. The later delays allow sleeping recipients time to replenish material. Restart and
cancellation preserve the budget. At most two
successive supersessions are reissued, matching the existing own-intent policy. `GroupRecoveryStatus` exposes pending
and failed fresh-material recovery counts; exhausted recovery requires a new user-initiated invitation. Network
availability and fresh recipient material remain prerequisites, not outcomes this mechanism can guarantee.

A fully validated replacement Welcome for an active group is stored as an offer (at most four per group and 64 per
account); a full inbox atomically retires its oldest unconsented offer and records only its wrapper dedup marker
before storing the new one, so user decisions cannot pin the account transport cursor. Eviction leaves the Welcome content retryable
under another wrapper and invalidates both affected groups' projections if the account-wide cap evicts across groups.
Neither its epoch number nor its author's admin role on the incoming branch authorizes replacement.
`group_recovery_status` returns the authenticated author, Welcome id, incoming epoch, and a token for the local branch
being discarded. A host must show that author and the effect of replacing the current group copy, obtain explicit
recipient consent, then call `confirm_group_rejoin` with the displayed id and token. A changed local branch rejects a
stale token; refresh the query and obtain consent again. The incoming epoch can be lower than the local fork's epoch.
Ordinary `accept_group_invite` is separate and never authorizes replacement of active MLS state.
Absence of authenticated peer traffic is not replacement authority either: an incoming fork admin could otherwise
silently move a newly joined, quiet recipient onto another branch.

Confirmation validates and installs the Welcome atomically with KeyPackage consumption, replacement state, the new
retained anchor, offer retirement, dedup markers, and a durable explicitly-confirmed `GroupJoined` event. Old rewind
anchors are discarded so delayed evidence cannot restore the branch the user discarded. Stored application history
is preserved. Publication already in flight must resolve before replacement. Failure rolls back tentative writes;
restart replays the join event without asking the user to accept the same rejoin again. Declining removes only the
selected offer and records both transport and content dedup markers, including against a new wrapper of that Welcome.
Dismissal only requires the stored offer and remains possible when live MLS state is unavailable. Per-group recovery
queries filter offer metadata before loading MLS state; confirmation only loads the selected offer's group.
Trusted-removal reentry and the existing Unrecoverable repair exception retain their automatic behavior.

The durable `automatic_recovery_failed` flag is raised only after three relay-confirmed full-history replays
complete without recovering anything. It reuses the existing confirmed-fruitless-replay evidence and its threshold,
not the undecryptable-message threshold or the less conservative arm-count escalation. Initial backfill arms,
transport errors, timeouts, and unconfirmed drains cannot raise this warning. Any kept delivery or observed epoch
progress during a replay suppresses that replay's failure evidence for all tracked groups; this intentionally
favors delayed warnings on busy accounts over false alarms.

Hosts may describe the flag as **"Unable to restore group synchronization."** It is neither proof of removal nor
authorization to replace cryptographic state. Authenticated current-epoch application traffic from another member,
or a successful join, clears the warning and saved replay evidence. Local self-updates and other epoch advances
alone do not clear a latched warning. A quiet group can therefore retain the warning until authenticated peer
traffic arrives. Evidence collected before a local epoch change is no longer counted toward a future warning,
so repeated local movement may delay detection; it cannot erase an already-reported failure. Recovery continues
under the existing backoff policy after the warning is shown. The warning never changes `pending_confirmation`
or the authoritative roster. The query suppresses it once removal or disband is authoritative; an Unrecoverable
copy still awaiting repair can continue to display it. Hosts subscribe to `GroupStateUpdated` and reread the recovery query after account open.

Migration 67 gates the new serialized recovery fields against older writers and adds the recovery-failure latch. Replay evidence and newly earned warnings are written atomically. Authenticated recovery also
clears persisted replay evidence so reopening cannot resurrect a resolved warning.
Existing history and invitation acceptance are preserved on upgrade. An intent already deleted by a previous MDK
version cannot be reconstructed: an affected existing group can still expose the advisory warning and recover through
a new invitation plus explicit rejoin. Client applications must adopt the new query and confirmation APIs to render
these controls; this MDK change does not install a client UI or publish new binding artifacts.

Regression coverage includes a deterministic losing inviter at the engine layer, a strict public-runtime invite/rename
journey with recipient reopen before and after consent, refusal of self-promoted replacement forks without consent,
stale-token rejection, content-based decline, persisted retry exhaustion, and SQLCipher upgrade/reopen and evidence
bounds. Protocol bootstrap trust is documented in the canonical specification's
[joining contract](https://github.com/marmot-protocol/marmot/blob/master/protocol-core/joining.md).

## Automatic rejoin of an Unrecoverable copy

The account worker automatically requests a fresh group copy when both the durable group record and native epoch
state are `Unrecoverable`. The account signer, persisted MLS device signer and frozen local copy must remain
available. A recovery warning, unreadable message, higher peer epoch or incoming request never creates this authority.
Usable forks still require the explicit rejoin consent described above. Removed, leaving, disbanding and disbanded
copies cannot request automatic reentry.

Both Unrecoverable checks are local client gates, not remotely attested conditions. The coordinator verifies
current membership, device-key possession, the exact source and the fresh package; it cannot inspect the recipient's
database or prove that its history is lost.

The halted device contacts one known admin account at a time through its advertised inbox, then its own account
as a fallback. A healthy authorized coordinator finds the device's current leaf by its persisted signing-key hash
and challenges that exact leaf on its settled
branch. The frozen device's old leaf position is not identity: a prior replacement may have moved it even when its
Welcome was lost. A removed signing key cannot select a new device that reused the same position.
The recipient publishes a fresh compatible KeyPackage,
retains its publication event reference, and signs a grant with its existing MLS device key. The grant binds the
group, coordinator account and device-key hash, nonce, expiry, source epoch/authenticator hash, exact leaf/hash,
target device-key hash and complete
KeyPackage. Possessing the account key or copying a sibling's public KeyPackage is insufficient to replace that
sibling. When account-devices is required, a healthy non-admin sibling may use the existing own-account member-edit
authority; replacing another account's device remains admin-only. The coordinator's own leaf is never a target.
The recipient selects the first challenged coordinator device for each nonce. Other devices of that admin account
cannot change the selection or stage the resulting grant; the selected device may refresh its source after an epoch
advance. This prevents shared-account inbox delivery from producing competing recovery Commits.

The coordinator revalidates current membership, member-edit authority, source state, package compatibility and device
proof immediately before staging one atomic remove-and-add Commit. It preserves account admin roles and unrelated
device leaves. The ordinary publish-before-apply path confirms the Commit before releasing its fresh Welcome.
The existing authenticated Welcome repair installs the copy on the running recipient, preserves stored application
history and retires obsolete convergence residue. It cannot reconstruct messages whose epoch secrets were pruned.

The repair transaction records the installed epoch in `Group::local_copy_install_epoch` and the Welcome's creation
time in `Group::local_copy_welcome_created_at`, clamped to the local clock. History recovery can read those durable
fields after reopen; no additional rejoined event is required. Zero or `None` means that a bound is unknown.
The timestamp is only a soft scheduling hint. Delayed messages may retain an old compose time while being encrypted
at the current epoch, and retained anchors may still decrypt previous membership intervals. A replacement therefore
resets `join_epoch` to zero and retires obsolete commits, not every older raw application row. Do not turn the
Welcome timestamp into a terminal ciphertext-deletion cutoff.

A delayed Welcome can heal the recipient while another recovery grant is already in flight. If that replacement
then removes its old leaf, the ordinary trusted-removal retry installs the queued Welcome after the native copy
becomes inactive, even if the account remains in the roster. A durable removal marker alone never bypasses
consent for a usable native copy.

These controls are an MDK-private NIP-59 extension: outer kind `1059` has no recovery discriminator. After one
authenticated unwrap, the inner rumor's kind `1159` and exactly one `["mdk_group_recovery", "1"]` tag distinguish
it from a Welcome. They use the account inbox, not the broken group's encryption context, and create no chat entries.
Kind `1159` is proposed, not allocated; the wire contract and older-client rollout questions are tracked in
[marmot#451](https://github.com/marmot-protocol/marmot/issues/451).

Migration 0124 follows the recovery-coverage ledger's migration 0123. It adds the protocol-owned `cgka_group_rejoin`
journal and gates older writers. Retry reservations precede directory and network work. One recipient episode
permits 32 reservations across nonce rotation, request expiry, phase changes, cancellation and reopen. A newer
authenticated coordinator epoch may refill that budget once. Its durable one-shot permission survives nonce rotation
and reopen; further remote claims cannot refill it. At most 64 reservations occur before the known admin set or
native epoch advances, or the user explicitly retries. Exhaustion stops new reservations; parking waits for the current
request to expire, leaving a live grant time to complete. Elapsed time and restart alone never rearm an episode.

The journal keeps the native epoch baseline separate from its authenticated remote epoch high-water mark. A frozen
losing branch can be taller than the winning branch: its height never rejects a coordinator's first Challenge or
the resulting replacement Welcome. Native height is only a baseline for detecting fresh evidence.

Requests expire after ten minutes; delays are 5, 15, 30, 60 and then 120 seconds, revisited by ordinary maintenance.
Expiry rotates to the next candidate without resetting episode cost. A coordinator durably reserves a 600-second
per-group/member Commit cooldown before staging; a new nonce cannot bypass it. The runtime admits at most 64
recipient jobs per account, 256 coordinator jobs per account and 16 per group; compatible grants batch at most 16
recipients per turn. Capacity refusal never evicts an active grant. Paused maintenance, frozen cursor mode and
closed storage suppress automatic execution.

Recovery evolution ownership is durable before MLS staging. A crash in unexposed preparation atomically abandons
the pending Commit and staged Welcomes. A prepared publication resumes its original Commit, pending reference and
linked Welcomes; expiry cannot discard publication already owned by that lifecycle. No relay acknowledgement is
invented after failure. A reachable eligible admin, compatible implementations, fresh material and eventual network
delivery remain prerequisites.
Existing membership-profile cutover rules still apply: a current-profile coordinator cannot recover a leaf in a
legacy group. A recipient whose fresh KeyPackages use a different profile skips recovery before publishing one.
Quarantined group records retire their stale recipient jobs without blocking recovery in other groups.

`MarmotAppRuntime` drives this automatically. Lower-level Rust hosts drive `prepare_group_recovery`, resolve only
the returned members' safe inbox routes, then call `advance_group_recovery` in their existing account loop. Both
methods belong to the same runtime owner; preparation durably reserves each turn before cancellable lookup work.
Hosts can read `group_rejoin_status` as `Inactive`, `Pending { attempts }` or `Parked { attempts }`. A parked episode
raises the existing app recovery-failure signal so a host can ask the user to retry or request an admin re-add.
`retry_group_rejoin` explicitly starts a new budget only for an eligible Unrecoverable copy; it grants no authority
to overwrite a usable copy. It clears the remote epoch high-water mark and restores the one-shot permission, so a
dishonest coordinator cannot poison every later user-authorized episode. An unexpired grant retains its nonce,
selected coordinator and exact signed artifact: Retry does not create a second live authorization. The app's existing
Repair action uses that runtime-owned
path. A withdrawn coordinator publication that expires or loses eligibility retires its commit link; the retained
cooldown row cannot continually reschedule it.
