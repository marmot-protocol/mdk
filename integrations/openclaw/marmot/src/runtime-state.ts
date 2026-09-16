// Process-local runtime status for the Marmot channel subscription.
//
// Compatibility snapshots for status tests and hosts that do not surface the
// gateway account status directly. The primary lifecycle owner is
// `gateway.startAccount`. State is keyed by the OpenClaw channel-account
// routing key so one account's start/stop/retry cannot overwrite another.

import type { ChannelAccountSnapshot } from "openclaw/plugin-sdk/status-helpers";

export const DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID = "default";

/** Stable machine-readable policy-readiness failure published on snapshots. */
export const MARMOT_ALLOWLIST_SYNC_FAILED = "marmot_allowlist_sync_failed";

export type MarmotAllowlistPolicyState = "pending" | "unmanaged" | "reconciled" | "failed";

export type MarmotAllowlistSyncResult =
  | { state: "unmanaged" }
  | { state: "reconciled" }
  | { state: "failed"; reason: MarmotAllowlistSyncFailureReason };

export type MarmotAllowlistSyncFailureReason =
  | "config_resolution"
  | "account_resolution"
  | "control"
  | "unverified";

interface AccountLiveFacts {
  accountId: string;
  running: boolean;
  inboundAcknowledged: boolean;
  inboundError: string | null;
  policy: MarmotAllowlistPolicyState;
  reconnectAttempts: number;
  lastStartAt: number | null;
  lastStopAt: number | null;
  lastInboundAt?: number;
  lastOutboundAt?: number;
}

const live = new Map<string, AccountLiveFacts>();

export function accountIdOrDefault(accountId: string | null | undefined): string {
  const trimmed = String(accountId ?? "").trim();
  return trimmed.length > 0 ? trimmed : DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID;
}

function emptyFacts(accountId: string, policy: MarmotAllowlistPolicyState): AccountLiveFacts {
  return {
    accountId,
    running: false,
    inboundAcknowledged: false,
    inboundError: null,
    policy,
    reconnectAttempts: 0,
    lastStartAt: null,
    lastStopAt: null,
  };
}

function project(facts: AccountLiveFacts): ChannelAccountSnapshot {
  const policyReady = facts.policy === "unmanaged" || facts.policy === "reconciled";
  return {
    accountId: facts.accountId,
    running: facts.running,
    connected: facts.inboundAcknowledged && policyReady,
    reconnectAttempts: facts.reconnectAttempts,
    lastStartAt: facts.lastStartAt,
    lastStopAt: facts.lastStopAt,
    lastError:
      facts.policy === "failed" ? MARMOT_ALLOWLIST_SYNC_FAILED : facts.inboundError,
    lastInboundAt: facts.lastInboundAt,
    lastOutboundAt: facts.lastOutboundAt,
  };
}

function write(next: AccountLiveFacts): ChannelAccountSnapshot {
  live.set(next.accountId, next);
  return project(next);
}

function stoppedSnapshot(accountId: string): ChannelAccountSnapshot {
  return project(emptyFacts(accountId, "unmanaged"));
}

/**
 * Start a new gateway generation for this channel account. Managed policy
 * begins pending and does not inherit a prior reconciled success.
 */
export function beginMarmotAccountLifecycle(accountId?: string | null): ChannelAccountSnapshot {
  const nextAccountId = accountIdOrDefault(accountId);
  return write({
    ...emptyFacts(nextAccountId, "pending"),
    running: true,
    lastStartAt: Date.now(),
  });
}

export function markMarmotAllowlistSyncResult(
  accountId: string | null | undefined,
  result: MarmotAllowlistSyncResult,
): ChannelAccountSnapshot {
  const nextAccountId = accountIdOrDefault(accountId);
  const prev = live.get(nextAccountId) ?? emptyFacts(nextAccountId, "pending");
  const policy: MarmotAllowlistPolicyState =
    result.state === "unmanaged"
      ? "unmanaged"
      : result.state === "reconciled"
        ? "reconciled"
        : "failed";
  return write({
    ...prev,
    accountId: nextAccountId,
    policy,
  });
}

export function markMarmotInboundStarting(accountId?: string | null): ChannelAccountSnapshot {
  const nextAccountId = accountIdOrDefault(accountId);
  const prev = live.get(nextAccountId);
  const sameAccount = prev?.accountId === nextAccountId;
  return write({
    accountId: nextAccountId,
    running: true,
    inboundAcknowledged: false,
    inboundError: null,
    policy: prev?.policy ?? "unmanaged",
    reconnectAttempts: sameAccount ? (prev.reconnectAttempts ?? 0) : 0,
    lastStartAt: sameAccount && prev.lastStartAt ? prev.lastStartAt : Date.now(),
    lastStopAt: null,
    lastInboundAt: prev?.lastInboundAt,
    lastOutboundAt: prev?.lastOutboundAt,
  });
}

export function markMarmotInboundReady(accountId?: string | null): ChannelAccountSnapshot {
  const nextAccountId = accountIdOrDefault(accountId);
  const prev = live.get(nextAccountId);
  if (!prev?.running) {
    return prev ? project(prev) : stoppedSnapshot(nextAccountId);
  }
  return write({
    ...prev,
    inboundAcknowledged: true,
    inboundError: null,
    lastStartAt: prev.lastStartAt ?? Date.now(),
    lastStopAt: null,
  });
}

export function markMarmotInboundReceived(accountId?: string | null): ChannelAccountSnapshot {
  const nextAccountId = accountIdOrDefault(accountId);
  const prev = live.get(nextAccountId);
  if (!prev) {
    return stoppedSnapshot(nextAccountId);
  }
  return write({
    ...prev,
    lastInboundAt: Date.now(),
  });
}

/** Record a durable outbound receipt for channel status/probe reporting. */
export function markMarmotOutboundSent(
  accountId?: string | null,
  sentAt: number = Date.now(),
): ChannelAccountSnapshot | null {
  const nextAccountId = accountIdOrDefault(accountId);
  const prev = live.get(nextAccountId);
  // A send for an account with no live inbound/lifecycle state must not
  // synthesize or evict another account's snapshot.
  if (!prev) {
    return null;
  }
  return write({
    ...prev,
    lastOutboundAt: sentAt,
  });
}

export function markMarmotInboundReconnect(accountId?: string | null): ChannelAccountSnapshot {
  const nextAccountId = accountIdOrDefault(accountId);
  const prev = live.get(nextAccountId);
  if (!prev?.running) {
    return prev ? project(prev) : stoppedSnapshot(nextAccountId);
  }
  return write({
    ...prev,
    inboundAcknowledged: false,
    inboundError: "inbound subscription dropped",
    reconnectAttempts: (prev.reconnectAttempts ?? 0) + 1,
  });
}

export function markMarmotInboundStopped(accountId?: string | null): ChannelAccountSnapshot {
  const nextAccountId = accountIdOrDefault(accountId);
  const prev = live.get(nextAccountId) ?? emptyFacts(nextAccountId, "unmanaged");
  return write({
    ...prev,
    running: false,
    inboundAcknowledged: false,
    lastStopAt: Date.now(),
  });
}

export function markMarmotInboundSetupFailed(
  accountId?: string | null,
  inboundError = "could not resolve agent account",
): ChannelAccountSnapshot {
  const nextAccountId = accountIdOrDefault(accountId);
  const prev = live.get(nextAccountId) ?? emptyFacts(nextAccountId, "unmanaged");
  // A replaced generation that already acknowledged must not be stopped by a
  // stale setup failure from the previous attempt.
  if (prev.running && prev.inboundAcknowledged) {
    return project(prev);
  }
  return write({
    ...prev,
    running: false,
    inboundAcknowledged: false,
    inboundError,
    lastStopAt: Date.now(),
  });
}

export function marmotInboundRuntimeSnapshot(accountId?: string | null): ChannelAccountSnapshot {
  const nextAccountId = accountIdOrDefault(accountId);
  const prev = live.get(nextAccountId);
  if (!prev) {
    return stoppedSnapshot(nextAccountId);
  }
  return project(prev);
}

export function marmotAllowlistPolicyState(
  accountId?: string | null,
): MarmotAllowlistPolicyState | null {
  return live.get(accountIdOrDefault(accountId))?.policy ?? null;
}

export function resetMarmotInboundRuntimeForTests(): void {
  live.clear();
}
