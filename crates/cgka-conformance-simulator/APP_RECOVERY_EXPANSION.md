# App recovery expansion, first increment

Base: merged #1837, `dcb3c1c37`. The existing 72-case campaign remains the default.
This increment is an independent opt-in selection, not a rerun of that baseline.

## Plan and harness boundary

1. Extend concurrent-call/public recovery support into generated invite/profile coverage.
2. Reuse the journey model for bounded repeated activity in one harness lifetime.
3. Add retained-history pressure using distinct public operations and controlled late delivery.
4. Validate generator contracts, then small process canaries, then repository checks.

The existing shared process runner, separate SQLCipher participant roots, real local
relay, socket interruption, history visibility and public projection assertions are reused.
New harness support is limited to the invite/profile action and its append-only evidence.
It chooses the higher credential identity as inviter, races that call with the other
actor's rename, and requires a validated explicit rejoin offer. Acceptance of both calls
alone is insufficient. Refusals remain classified outcomes in a failed coverage report;
there is no automatic retry or conversion of an unexercised race into a pass.

## Versioned generators

| Family | Bounded selection | Meaningful variation |
| --- | --- | --- |
| `public-app-invite-profile-recovery/v1` | 2 cases/seed | Two of three admin actors; prior traffic length/sender; observer offline visibility; actor restart before race; offer restart arm; relay interruption after recovery |
| `public-app-longevity/v1` | 2 cases/seed | Two or three cycles; shuffled message/profile/remove-reinvite motifs; offline participant, removed participant, senders, burst lengths and socket outage duration |
| `public-app-retained-traffic/v1` | 2 cases/seed | Same cycles with 16–24-message bursts, repeated real membership/profile operations, repeated history repair and one hidden historical message per cycle |
| `public-app-longevity-extended/v1` | explicit only | 48 cycles in one harness, using the same identities and databases; not a wall-clock duration guarantee |

Invite/profile is generator version `2`, retained traffic version `3`, and longevity version `1`.
The version-1 race input omitted the named creation acknowledgement and correctly
failed its pending-resolution oracle; saved version-1 inputs remain unchanged. Existing families and their versions are
unchanged. Indices are independently seeded, so increasing case count preserves prefixes.
OS scheduling and cryptographic identities remain nondeterministic; saved inputs pin the
schedule, not a promise that a race will occur. The runtime evidence must prove recovery.

Race acceptance requires retained publication correlation, both accepted mutations,
a validated offer, explicit consent and confirmation persistence after reopening the
invitee. The even case also requires offer persistence before consent. Subsequent public
assertions require the complete roster/profile and bidirectional fresh messages.

Activity scenarios create one group once. In longevity cases Alice stays in the same running process;
other participants close/reopen for offline periods and explicit alternating-cycle
restarts using their existing roots. Whole accumulated payload multisets and public
roster/profile assertions detect loss, duplicates and membership divergence each cycle.
No cycle reconstructs participant identities or databases.

Pressure uses an all-offline boundary to remove an event from the shared relay,
then reopens the caught-up peers on their same databases before traffic resumes.
It is not same-process longevity evidence. Version 1 incorrectly requested a
duplicate-copy relay control unavailable on the app adapter; version 2 uses
repeated full-history requests. Version 2 then exposed the relay selector contract:
the real relay accepts an action-id-only selector; version 3 uses that exact selector
and the contract tests require it to resolve to a send action. Relay configuration now has a distinct preflight
capability, so unsupported configuration fails before action zero.

Pressure first proves a hidden message is absent after initial recovery, then releases
that exact correlated relay event and requires its delivery exactly once while fresh
traffic is interleaved. These bounded histories require delivery, not terminal invalidation.
They do not assert below-anchor private dispositions or continuously overlapping traffic.

## Commands and evidence

```sh
# Independent selection: never selects the existing 72-case baseline.
python3 scripts/app_stack_campaign.py target/recovery-expansion-new \
  --catalog expansion --generated-only --mode canary --seeds 7 --jobs 1

# Broaden only after inspecting the canary, including refusal/unexercised races.
python3 scripts/app_stack_campaign.py target/recovery-expansion-matrix-new \
  --catalog expansion --generated-only --mode full --seeds 7 42 17001 --jobs 1

# Extended activity: build/freeze the matching helper and record source/binary hashes first.
RUST_MIN_STACK=4194304 target/release/cgka-conformance-campaign \
  --family public-app-longevity-extended/v1 --seed 7 --cases 1 \
  --storage file --case-timeout-secs 7200 --out target/longevity-extended-new
```

Use fresh roots. The campaign freezes helpers and records source, binaries, exact inputs,
reports, failures and timing. `--mode full` deliberately repeats its canary in the matrix;
keep those execution receipts distinct. Diagnostic retries require separate roots and
must not replace initial failed verdicts. Expensive generated executions are opt-in;
only cheap generator/oracle contract tests join ordinary PR testing.

## Negative discovery scan investigation

Current `message_processor/application_replay.rs` visits Created, Retryable and
ConvergenceDeferred records from epoch zero and decodes payloads until it finds enough
applications. A negative query therefore decodes its whole eligible non-application
prefix. The engine README measurement uses duplicate synthetic commit payloads to
isolate this cost; it is not legitimate distinct-history app acceptance evidence.
Clipping to the retained anchor would miss late old applications requiring invalidation.
No production change is justified by these facts alone. A future classifier/index must
preserve late arrivals, replacement, cross-connection writes and restart behavior.

## Remaining gates

- Concurrent removals/additional profile fields and relay interruption inside recipient recovery.
- Runtime evidence that fresh messages complete while recovery remains incomplete, with continuous traffic.
- Long wall-clock same-process execution and larger retained histories.
- Public terminal disposition coverage for a late message beyond the retained anchor.
- Latency attribution across scan work, relay retry, settlement and background scheduling.

Short canaries do not establish full-catalog, long-duration or production-service success.
