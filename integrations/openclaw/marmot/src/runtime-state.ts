// Process-local runtime status for the Marmot channel subscription.
//
// Compatibility snapshots for status tests and hosts that do not surface the
// gateway account status directly. The primary lifecycle owner is
// `gateway.startAccount`. State is keyed by the OpenClaw channel-account
// routing key so one account's start/stop/retry cannot overwrite another.

import type { ChannelAccountSnapshot } from "openclaw/plugin-sdk/status-helpers";
import {
  senderPolicyErrorCode,
  senderPolicyIsReady,
  type SenderAuthorizerLifecycle,
  type SenderPolicyReadinessState,
  type SenderPolicyResolution,
} from "./sender-policy.js";

export const DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID = "default";

/** Stable machine-readable policy-readiness failure published on snapshots. */
export const MARMOT_ALLOWLIST_SYNC_FAILED = "marmot_allowlist_sync_failed";
export {
  MARMOT_SENDER_POLICY_INVALID,
  MARMOT_SENDER_POLICY_MISSING,
} from "./sender-policy.js";

export type MarmotAllowlistPolicyState = "pending" | "unmanaged" | "reconciled" | "failed";
export type MarmotSenderPolicyState = SenderPolicyReadinessState;

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
  senderPolicy: MarmotSenderPolicyState;
  senderPolicyAllowedUserCount: number;
  senderAuthorizerLifecycle: SenderAuthorizerLifecycle;
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

function emptyFacts(
  accountId: string,
  policy: MarmotAllowlistPolicyState,
  senderPolicy: MarmotSenderPolicyState = "pending",
): AccountLiveFacts {
  return {
    accountId,
    running: false,
    inboundAcknowledged: false,
    inboundError: null,
    policy,
    senderPolicy,
    senderPolicyAllowedUserCount: 0,
    senderAuthorizerLifecycle: "pending",
    reconnectAttempts: 0,
    lastStartAt: null,
    lastStopAt: null,
  };
}

function project(facts: AccountLiveFacts): ChannelAccountSnapshot {
  const welcomerReady = facts.policy === "unmanaged" || facts.policy === "reconciled";
  const senderReady = senderPolicyIsReady(facts.senderPolicy);
  const authorizerReady = facts.senderAuthorizerLifecycle === "active";
  const senderError = senderPolicyErrorCode(facts.senderPolicy);
  return {
    accountId: facts.accountId,
    running: facts.running,
    connected: facts.inboundAcknowledged && welcomerReady && senderReady && authorizerReady,
    reconnectAttempts: facts.reconnectAttempts,
    lastStartAt: facts.lastStartAt,
    lastStopAt: facts.lastStopAt,
    lastError:
      senderError ??
      (facts.policy === "failed" ? MARMOT_ALLOWLIST_SYNC_FAILED : facts.inboundError),
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
    ...emptyFacts(nextAccountId, "pending", "pending"),
    running: true,
    lastStartAt: Date.now(),
  });
}

export function markMarmotSenderPolicyResult(
  accountId: string | null | undefined,
  result: SenderPolicyResolution | { state: MarmotSenderPolicyState; allowedUserCount?: number },
): ChannelAccountSnapshot {
  const nextAccountId = accountIdOrDefault(accountId);
  const prev = live.get(nextAccountId) ?? emptyFacts(nextAccountId, "unmanaged", "pending");
  return write({
    ...prev,
    accountId: nextAccountId,
    senderPolicy: result.state,
    senderPolicyAllowedUserCount:
      "allowedUserCount" in result && typeof result.allowedUserCount === "number"
        ? result.allowedUserCount
        : 0,
  });
}

export function markMarmotSenderAuthorizerLifecycle(
  accountId: string | null | undefined,
  lifecycle: SenderAuthorizerLifecycle,
): ChannelAccountSnapshot {
  const nextAccountId = accountIdOrDefault(accountId);
  const prev = live.get(nextAccountId) ?? emptyFacts(nextAccountId, "unmanaged", "pending");
  return write({
    ...prev,
    accountId: nextAccountId,
    senderAuthorizerLifecycle: lifecycle,
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
    senderPolicy: prev?.senderPolicy ?? "pending",
    senderPolicyAllowedUserCount: prev?.senderPolicyAllowedUserCount ?? 0,
    senderAuthorizerLifecycle: prev?.senderAuthorizerLifecycle ?? "pending",
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
    // First successful ack may promote a still-pending gate. Stopped, replaced,
    // and invalid authorizers stay terminal so a stale retry cannot look healthy.
    senderAuthorizerLifecycle:
      prev.senderAuthorizerLifecycle === "pending" ? "active" : prev.senderAuthorizerLifecycle,
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

export function marmotSenderPolicyState(
  accountId?: string | null,
): MarmotSenderPolicyState | null {
  return live.get(accountIdOrDefault(accountId))?.senderPolicy ?? null;
}

export function marmotSenderAuthorizerLifecycle(
  accountId?: string | null,
): SenderAuthorizerLifecycle | null {
  return live.get(accountIdOrDefault(accountId))?.senderAuthorizerLifecycle ?? null;
}

export function resetMarmotInboundRuntimeForTests(): void {
  live.clear();
}
