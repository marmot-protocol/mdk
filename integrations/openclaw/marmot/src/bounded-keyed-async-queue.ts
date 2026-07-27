import { KeyedAsyncQueue } from "openclaw/plugin-sdk/keyed-async-queue";

import {
  MarmotDispatchAmbiguousDeliveryError,
  MarmotDispatchDeliveryFailedError,
  MarmotDispatchNotReadyError,
} from "./dispatch-errors.js";

export const DEFAULT_INBOUND_QUEUE_MAX_DEPTH = 32;

/**
 * Map queue task failures onto fixed privacy-safe operator categories. Never
 * forward an arbitrary error message because it may contain route or payload
 * material from an upstream SDK failure.
 */
export function inboundDispatchFailureCategory(error: unknown): string {
  if (error instanceof MarmotDispatchAmbiguousDeliveryError) {
    return "ambiguous_delivery";
  }
  if (error instanceof MarmotDispatchDeliveryFailedError) {
    return "delivery_failed";
  }
  if (error instanceof MarmotDispatchNotReadyError) {
    return "not_ready";
  }
  return "unexpected";
}

/**
 * Per-key FIFO dispatch with a bounded queue depth. When a key is at capacity,
 * the incoming turn is shed (not the already-queued work) and an optional
 * privacy-safe log hook fires.
 */
export class BoundedKeyedAsyncQueue {
  private readonly queue = new KeyedAsyncQueue();
  private readonly depths = new Map<string, number>();
  private readonly maxDepthPerKey: number;

  constructor(
    maxDepthPerKey: number = DEFAULT_INBOUND_QUEUE_MAX_DEPTH,
    private readonly onShed?: (message: string) => void,
  ) {
    this.maxDepthPerKey = Math.max(1, maxDepthPerKey);
  }

  /** Returns false when the per-key depth cap rejects the task. */
  enqueue(key: string, task: () => Promise<void>): boolean {
    const depth = this.depths.get(key) ?? 0;
    if (depth >= this.maxDepthPerKey) {
      this.onShed?.("marmot: inbound queue depth exceeded; shedding turn");
      return false;
    }
    this.depths.set(key, depth + 1);
    void this.queue
      .enqueue(key, async () => {
        try {
          await task();
        } finally {
          const next = (this.depths.get(key) ?? 1) - 1;
          if (next <= 0) {
            this.depths.delete(key);
          } else {
            this.depths.set(key, next);
          }
        }
      })
      .catch((error) =>
        this.onShed?.(
          `marmot: inbound dispatch task failed (${inboundDispatchFailureCategory(error)})`,
        ),
      );
    return true;
  }
}
