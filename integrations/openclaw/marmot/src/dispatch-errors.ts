// Typed, privacy-safe inbound dispatch failures surfaced to the inbound queue.

/** Inbound dispatch failed because outbound group readiness never converged. */
export class MarmotDispatchNotReadyError extends Error {
  readonly reason: "timeout" | "non_retryable";

  constructor(reason: "timeout" | "non_retryable") {
    super(
      reason === "timeout"
        ? "marmot: outbound group readiness timed out; inbound dispatch failed"
        : "marmot: outbound group readiness check failed; inbound dispatch failed",
    );
    this.name = "MarmotDispatchNotReadyError";
    this.reason = reason;
  }
}
