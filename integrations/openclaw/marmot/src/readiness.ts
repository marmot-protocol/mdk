// Bounded readiness wait before the first agent turn on a fresh group.

import { isRetryable, type GroupInfoResponse, type MarmotAgentControlClient } from "./client.js";

export interface GroupReadinessClient {
  groupInfo(accountIdHex: string, groupIdHex: string): Promise<GroupInfoResponse>;
}

export interface WaitForGroupReadinessOptions {
  client: GroupReadinessClient;
  accountIdHex: string;
  groupIdHex: string;
  maxAttempts?: number;
  backoffMs?: readonly number[];
  log?: (message: string) => void;
}

const DEFAULT_BACKOFF_MS = [50, 100, 200] as const;

export type GroupReadinessResult =
  | { status: "ready"; groupInfo: GroupInfoResponse }
  | { status: "not_ready"; reason: "timeout" | "non_retryable" };

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Wait until wn-agent can resolve the local MLS group for outbound sends. Used
 * immediately after invite convergence so the first turn does not race group
 * state. Bounded: returns `not_ready` after `maxAttempts` so the caller can fail
 * the inbound dispatch instead of silently skipping.
 */
export async function waitForGroupReadiness(
  options: WaitForGroupReadinessOptions,
): Promise<GroupReadinessResult> {
  const backoff = options.backoffMs ?? DEFAULT_BACKOFF_MS;
  const maxAttempts = options.maxAttempts ?? backoff.length + 1;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const groupInfo = await options.client.groupInfo(options.accountIdHex, options.groupIdHex);
      if (attempt > 0) {
        options.log?.("marmot: outbound group readiness established after retry");
      }
      return { status: "ready", groupInfo };
    } catch (error) {
      const retryable = isRetryable(error);
      if (!retryable) {
        options.log?.("marmot: outbound group readiness check failed (non-retryable)");
        return { status: "not_ready", reason: "non_retryable" };
      }
      if (attempt >= maxAttempts - 1) {
        options.log?.("marmot: outbound group readiness timed out");
        return { status: "not_ready", reason: "timeout" };
      }
      options.log?.(
        `marmot: outbound group not ready; retrying (attempt ${attempt + 1}/${maxAttempts - 1})`,
      );
      await sleep(backoff[Math.min(attempt, backoff.length - 1)] ?? 100);
    }
  }
  return { status: "not_ready", reason: "timeout" };
}

export type OutboundReadinessClient = Pick<MarmotAgentControlClient, "groupInfo">;
