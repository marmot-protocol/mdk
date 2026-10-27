# Incident send trace v1

This private incident artifact is opt-in at build time and follows existing forensic audit consent.
It contains a random capture nonce and process-local opaque numeric owner/operation tokens. No account,
group, message, relay, payload, caller token, path, error text, key material or identity hash is serialized.
Private lookup keys remain in bounded memory maps. The sidecar is neither tracing/OTLP nor audit-v5 data.

Files are four `segment-N.jsonl` files (N=0..3, each <=262144 bytes, complete rows <=512 bytes) and
`manifest.json` (<=262144 bytes), with private 0700 directory/0600 files. The writer uses `manifest.tmp`
then rename. Existing nonregular artifacts are rejected. A 1024-record nonblocking queue drops rather
than backpressures. Capture counters report lock contention, queue/map/snapshot capacity loss and
write failures; disk failure can prevent a final updated manifest. `recording=true` may be stale after
process death. Exported files are not an atomic snapshot, so host export coverage must be checked too.

## Rows

Fixed order: `schema` (1), `process` (32 lowercase hex random nonce), `seq`, `elapsed_ms`, `kind`,
`owner`, `operation`, `values` (eight unsigned 64-bit integers). Zero owner/operation is unknown.
`seq` is monotonic within the app instance, not reset on enable; a first sequence above one alone
is not proof of loss. Monotonic milliseconds are relative to capture start. `started_unix_ms` anchors
that start to wall time, subject to wall-clock uncertainty. The closed enum and numeric value meanings
are documented at the top of `incident_send_trace.rs`.

Branch phases: command=1, convergence=2, receive=3, avatar=4, presentation=5, attachment=6,
maintenance=7, media=8, native replay admission=9, generic worker loop=10, comparison admission or
network completion=11, welcome completion=12, select wait=13, local submission service=14.
Phase 10 is intentionally broad/unknown work, not idle. Phase 13 includes polling select futures and
must not itself be interpreted as proof the task is asleep. Startup before the steady worker loop is
not covered by worker phases. `worker_state.pending` and `commands` are command queue counts, not
durable-message queue depth. Durable head sequence/depth remain unknown; no diagnostic database scans
are added. BranchCounts covers branches1..8 only; owner phase-entry counter covers all phase scopes.

History samples worker state, command kind, and branch timing at most every250ms per category. Counts
and live phase changes update on every instrumented transition independently of history sampling.
Drops invalidate absence/completeness inference. Branch RAII guards restore the prior phase only if
its unique phase token is still active. Phase end means scope exit, including cancellation/error;
it is not a success assertion.

## Manifest live snapshots

Fixed scalar fields: `schema`, `process`, `started_unix_ms`, `dropped`, `write_failures`, `rotations`,
`active_segment`, `recording`, `last_written_seq`, `first_written_seq`, `clear_count`,
`sample_period_ms` (250), `live_snapshot_seq`, `live_snapshot_elapsed_ms`; then `owners` and `operations`.
`live_snapshot_elapsed_ms` is sampled by the writer at publication independently of worker progress.
The arrays are cloned under one short lock; producer contention is counted as loss, never awaited.
A manifest normally updates within250ms but thread/disk scheduling is unbounded. A stall or process
termination can leave it stale. Active duration at snapshot is snapshot elapsed minus phase start,
not duration up to the later host export time.

`owners` has at most64 arrays of16 u64s:
0 owner;1 worker generation;2 active phase;3 phase-start elapsed_ms;4 unique phase token;
5 last command kind (reset0 at command-phase entry);6 last update elapsed_ms;
7..14 last WorkerState values[0..7];15 cumulative phase-scope entries.
Use command kind as active only in phase1; elsewhere it is merely last observed. Worker-state values
are observations at loop entry and may be stale during a long phase. Aliases are refreshed each loop
when consent/capture changes. A phase already in progress when capture is enabled is unknown until
a new instrumented transition. Unknown/zero values cannot prove idle or no work.

`operations` has at most256 arrays of20 u64s:
0 operation;1 owner;2 milestone validity mask with bit63 terminal;3 latest update elapsed_ms;
4 admission begin;5 worker acquired;6 gate wait;7 gate acquired;8 admission committed;
9 selected;10 execution begin;11 pre-engine sync begin;12 pre-engine sync end;
13 runtime send begin;14 runtime send end;15 true engine entry;16 execution end;17 completion;
18 first-entry recorder token;19 first-entry SendEntry ordinal.
For indices4..17, bit(index-4) indicates presence; zero milliseconds can be valid. Milestones retain
first observed occurrence, including retries; detailed success/failure remains in rows. Terminal means
admission failed/duplicate call or successful queue completion, not network delivery. A failed queue
completion remains pending. A duplicate call token is distinct from its original operation (row value0
links them). Pending snapshots survive history rotation. At capacity the oldest terminal snapshot is
replaced; if all256 are pending, new snapshots are dropped and counted. Maps never evict private
correlations into a false join. More than1024 distinct operation correlations per capture produces
unknown aliases and counted loss. Clear resets live snapshots; subsequent observations are partial.

## Engine/audit join and limits

The recorder decorator observes the actual engine SendEntry callback and forwards the original audit
record unchanged. `runtime_send_begin` is only the pre-engine API boundary. Engine calls are serialized
by the owning engine's mutable send path. Engine-entry values are recorder token, per-recorder SendEntry
ordinal, and diagnostic recorder-call count. The call count is NOT audit-v5 sequence. RecorderOpen value1
is the count of entries before capture registration (zero for a fresh recorder); nonzero means the
recorder was already active in an earlier capture. Ordinals can join only a uniquely identified,
complete corresponding recorder session with verified audit capture health. Multiple possible sessions,
missing prefix/rotation/drop, or recorder failures make the join inconclusive. No cross-file identity
hash is introduced to conceal that uncertainty. Snapshots retain the first entry's ordinal/timestamp.

The public runtime consent toggle installs/removes recorders in already-running engines. The lower-level
app settings setter alone does not propagate to existing workers. Worker propagation can fail or time
out, so missing RecorderOpen/entry coverage cannot prove pre-engine delay; verify successful recorder
activation. Already-in-flight phases at enable remain unknown until the next instrumented transition. Stored native event timestamps, UI optimistic timestamps and sidecar timings
remain separate evidence. This trace diagnoses stages/owner phases; it does not itself prove CPU
attribution, scheduler starvation, fork causality, transport delivery, or a production-ready fix.

Producer paths add bounded allocation/locking/clock work. They do not add awaits, yields, DB queries or
change branch ordering. No zero-perturbation claim is made. The focused overhead sanity test compares
1000 identical in-memory forensic callbacks with capture off/on and prints time/max callback/drops;
that debug-host micro-workload is not phone workload qualification. Enable/disable waits for the writer
outside worker selection. Persistent disk/OS stalls can therefore delay that control operation.
