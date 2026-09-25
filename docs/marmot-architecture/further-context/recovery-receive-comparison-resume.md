---
title: Ordinary receive comparison resume
updated: 2026-09-25
status: Narrow execution slice
---

# Ordinary receive comparison resume

After an ordinary delivery is claimed, the account worker still completes its
engine ingest, incidental publication, app projection, visible runtime summary,
post-join subscription work and convergence scheduling before selecting any
pending recovery. The `WorkerReceive` observation still ends after ingest and
projection, before the recovery tail. A completed or incomplete account-wide
overflow replay keeps its existing inline behavior.

For an ordinary delivery, the existing owner selects one frozen grant. Only a
grant whose comparison revision, route shape and obligation plan pass the
shared eligibility checks moves its immutable SDK request into the existing
one-job-per-account slot. The worker activates that grant before the task and
joins its result to check the original fences, admit returned events, drain,
checkpoint, settle and report. An ineligible grant uses the same grant on the
inline executor. A comparison-only attempt without a shared credit defers
before owner reservation; independent selected debt keeps its inline path.

The original Receive tail schedules the delivery's audit tracker update and,
for a joined group, retries the client's current durable push-registration
intent and publishes pending applied updates. It runs after recovery reporting
whether the result was inline, deferred, stale, failed or joined from the task.
If the job slot is already occupied, this delivery completes and reports
recovery deferred without selecting another grant. A later delivery can
therefore publish and finish its own tail before an earlier delivery's held
comparison joins. The durable push intent, rather than a captured request,
remains the source of truth for retry. Shutdown cancels and reaps the network
task; an unjoined result is never admitted.

The two-relay SQLCipher regression starts with a naturally requested startup
comparison and leaves it pending after an incomplete periodic attempt. A
one-shot sender then publishes a real MLS app event. The target's ordinary
receive commits and publishes it; a target-scoped, test-only witness records
the Receive-selected owner attempt and comparison revision. An exact SDK query
on one relay stays active while a normal status command runs, and a second
ordinary delivery arrives through the independent live relay without another
owner selection. The same tightened fixture on parent `03c1dc30` times out the
status command while that request is held; the resumed path answers while the
task still owns its shared credit. The regression also checks credit release
after join and on shutdown.

The fixture does not measure wire bytes, process memory, device behavior or
latency of activation, subscription registration, admission, drain or
checkpoint. Startup, explicit catch-up and account-wide overflow waits remain
separate work. The private bounded known-event executor remains disabled. The
shared comparison limits, cursor and admission contract are described in
[periodic comparison worker resume](recovery-worker-comparison-resume.md).
