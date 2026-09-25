---
title: Scheduled post-convergence comparison resume
updated: 2026-09-25
status: Narrow execution slice
---

# Scheduled post-convergence comparison resume

The scheduled convergence arm still performs its local subscription refresh,
convergence advance, projection publication and next-pass scheduling on the
account worker. If its already-pending recovery owner selects an eligible
comparison, the worker activates the grant, starts the same network job used by
periodic maintenance, and resumes its command loop while the SDK comparison
waits. The job does not create a new recovery trigger or owner lease.

Only the immutable comparison request moves to the job. The worker retains one
job slot per account and the shared two-credit limit. It joins the result,
checks the frozen grant and subscription attempt, admits returned events,
drains, checkpoints, settles, reports recovery, and schedules the convergence
audit tracker update through the existing owner path. A join failure still
releases credit and reaches reporting. The convergence performance observation
spans this continuation.

If that account's job slot is occupied, the scheduled arm completes its local
pass and reports recovery deferred without selecting another grant; pending
debt stays durable. An ineligible frozen grant uses the existing inline
executor. Read-only status commands can run during an offloaded SDK wait;
explicit catch-up and later mutations retain worker FIFO ordering behind the
active job. Activation, registration, drain and checkpoint can still hold the
worker. Startup, explicit catch-up and receive-triggered comparison waits stay
inline. The bounded known-event worker remains separately gated.

The relay-backed regression arms a real stored convergence pass, leaves a
startup comparison pending, then witnesses the scheduled selection enter a
held relay NEG-OPEN query. It asserts status responsiveness, one owner attempt,
durable pending debt and credit release after join. It does not measure wire
bytes, process memory or downstream device delivery. The underlying job's
limits and cursor/admission rules are in
[periodic comparison worker resume](recovery-worker-comparison-resume.md).
