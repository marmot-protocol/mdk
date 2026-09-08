# Superseded invitation recovery

When a locally published invite loses branch selection, its Welcome may already have installed the losing branch
on the recipient. The inviter's success report does not prove that the invitation survived convergence (#1735).

The engine retains the original invitation intent with a durable recovery record. The app resolves fresh KeyPackages
using the ordinary safe directory-discovery path, bypassing the initial cache/prewarm shortcut. The engine rejects
packages consumed by the lost invitation, changed or duplicate recipient identities, and loss of inviter authority.
Only recipients absent from the canonical roster are invited again. Fresh intent replaces the recovery record in the
same transaction that queues it; publication uses the ordinary outbound queue and acknowledgement rules.

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
or the authoritative roster. Hosts subscribe to `GroupStateUpdated` and reread the recovery query after account open.

Migration 66 gates the new serialized recovery fields against older writers. Migration 67 removes the superseded
early-warning evidence tables and adds the recovery-failure latch; old early warnings are discarded, not promoted
into failure claims. Replay evidence and newly earned warnings are written atomically. Authenticated recovery also
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
