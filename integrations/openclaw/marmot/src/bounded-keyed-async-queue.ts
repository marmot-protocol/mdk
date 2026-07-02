import { KeyedAsyncQueue } from "openclaw/plugin-sdk/keyed-async-queue";

export const DEFAULT_INBOUND_QUEUE_MAX_DEPTH = 32;

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

  enqueue(key: string, task: () => Promise<void>): void {
    const depth = this.depths.get(key) ?? 0;
    if (depth >= this.maxDepthPerKey) {
      this.onShed?.("marmot: inbound queue depth exceeded; shedding turn");
      return;
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
      .catch(() => this.onShed?.("marmot: inbound dispatch task failed"));
  }
}
