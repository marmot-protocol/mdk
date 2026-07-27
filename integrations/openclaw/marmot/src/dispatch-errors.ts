// Typed, privacy-safe inbound dispatch failures surfaced to the inbound queue.

/** Inbound dispatch failed because a durable reply never landed with a definite receipt. */
export class MarmotDispatchAmbiguousDeliveryError extends Error {
  constructor() {
    super(
      "marmot: durable reply delivery ended with an ambiguous outcome; inbound dispatch failed",
    );
    this.name = "MarmotDispatchAmbiguousDeliveryError";
  }
}

/** Inbound dispatch failed because OpenClaw reported a terminal final delivery failure. */
export class MarmotDispatchDeliveryFailedError extends Error {
  constructor() {
    super("marmot: reply final delivery failed; inbound dispatch failed");
    this.name = "MarmotDispatchDeliveryFailedError";
  }
}

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
