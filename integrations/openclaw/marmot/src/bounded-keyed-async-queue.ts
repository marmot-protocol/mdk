// The dedicated keyed-async-queue subpath lost its declarations in
// 2026.7.2-beta. The core barrel exports the same runtime value and declarations
// on both stable and beta.
import { KeyedAsyncQueue } from "openclaw/plugin-sdk/core";

export const DEFAULT_INBOUND_QUEUE_MAX_DEPTH = 32;
export const DEFAULT_INBOUND_QUEUE_MAX_TRACKED_GROUPS = 256;

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

export type InboundQueueOverloadReason = "per_group_depth" | "tracked_group_limit";

export interface InboundQueuePressureSignal {
  reason: InboundQueueOverloadReason;
  activeGroups: number;
  maxDepthPerGroup: number;
  maxTrackedGroups: number;
}

export type InboundQueueAdmission =
  | { outcome: "admitted" }
  | { outcome: "overloaded"; reason: InboundQueueOverloadReason };

/**
 * Per-group FIFO dispatch with bounded per-group depth and bounded group state.
 * Rejection is explicit so callers can keep the inbound event retryable. The
 * pressure callback contains aggregate counts only, never group/message ids.
 */
export class BoundedKeyedAsyncQueue {
  private readonly queue = new KeyedAsyncQueue();
  private readonly depths = new Map<string, number>();
  private readonly maxDepthPerKey: number;
  private readonly maxTrackedKeys: number;

  constructor(
    maxDepthPerKey: number = DEFAULT_INBOUND_QUEUE_MAX_DEPTH,
    private readonly onPressure?: (signal: InboundQueuePressureSignal) => void,
    maxTrackedKeys: number = DEFAULT_INBOUND_QUEUE_MAX_TRACKED_GROUPS,
    private readonly onTaskFailure?: (message: string) => void,
  ) {
    this.maxDepthPerKey = Math.max(1, Math.trunc(maxDepthPerKey));
    this.maxTrackedKeys = Math.max(1, Math.trunc(maxTrackedKeys));
  }

  enqueue(key: string, task: () => Promise<void>): InboundQueueAdmission {
    const depth = this.depths.get(key) ?? 0;
    const reason: InboundQueueOverloadReason | undefined =
      depth >= this.maxDepthPerKey
        ? "per_group_depth"
        : depth === 0 && this.depths.size >= this.maxTrackedKeys
          ? "tracked_group_limit"
          : undefined;
    if (reason) {
      this.onPressure?.({
        reason,
        activeGroups: this.depths.size,
        maxDepthPerGroup: this.maxDepthPerKey,
        maxTrackedGroups: this.maxTrackedKeys,
      });
      return { outcome: "overloaded", reason };
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
        this.onTaskFailure?.(
          `marmot: inbound dispatch task failed (class=${classifyInboundDispatchFailure(error)})`,
        ),
      );
    return { outcome: "admitted" };
  }
}
