// The dedicated keyed-async-queue subpath lost its declarations in
// 2026.7.2-beta. The core barrel exports the same runtime value and declarations
// on both stable and beta.
import { KeyedAsyncQueue } from "openclaw/plugin-sdk/core";

export const DEFAULT_INBOUND_QUEUE_MAX_DEPTH = 32;

// Copied from the OpenClaw host assertion. This classification is best-effort:
// an upstream wording change safely degrades to the generic `error` bucket.
const OPENCLAW_DISPATCH_LIFECYCLE_ERROR =
  "runChannelInboundEvent prepared turns must declare runDispatchLifecycle when creating runDispatch";

/**
 * Reduce an arbitrary dispatch failure to a fixed, privacy-safe class. Never
 * include Error.message: upstream failures can embed prompts, paths, ids, or
 * other conversation-specific data.
 */
export function classifyInboundDispatchFailure(error: unknown): string {
  if (error instanceof Error && error.message === OPENCLAW_DISPATCH_LIFECYCLE_ERROR) {
    return "openclaw_dispatch_lifecycle_contract";
  }
  if (error instanceof Error && error.name === "SessionStoreAgentIdRequiredError") {
    return "openclaw_session_store_agent_id_required";
  }
  if (error instanceof Error) {
    return "error";
  }
  return "non_error";
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
      .catch((error: unknown) =>
        this.onShed?.(
          `marmot: inbound dispatch task failed (class=${classifyInboundDispatchFailure(error)})`,
        ),
      );
  }
}
