// Process-local runtime status for the Marmot channel subscription.
//
// Compatibility snapshot for status tests and hosts that do not surface the
// gateway account status directly. The primary lifecycle owner is now
// `gateway.startAccount`.

import type { ChannelAccountSnapshot } from "openclaw/plugin-sdk/status-helpers";

export const DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID = "default";

let inboundRuntime: ChannelAccountSnapshot = stoppedSnapshot(DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID);

function accountIdOrDefault(accountId: string | null | undefined): string {
  const trimmed = String(accountId ?? "").trim();
  return trimmed.length > 0 ? trimmed : DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID;
}

function stoppedSnapshot(accountId: string): ChannelAccountSnapshot {
  return {
    accountId,
    running: false,
    connected: false,
    reconnectAttempts: 0,
    lastStartAt: null,
    lastStopAt: null,
    lastError: null,
  };
}

export function markMarmotInboundStarting(accountId?: string | null): void {
  const nextAccountId = accountIdOrDefault(accountId);
  const sameAccount = inboundRuntime.accountId === nextAccountId;
  inboundRuntime = {
    ...inboundRuntime,
    accountId: nextAccountId,
    running: true,
    connected: false,
    reconnectAttempts: sameAccount ? (inboundRuntime.reconnectAttempts ?? 0) : 0,
    lastStartAt: sameAccount && inboundRuntime.lastStartAt ? inboundRuntime.lastStartAt : Date.now(),
    lastStopAt: null,
    lastError: null,
  };
}

export function markMarmotInboundReady(accountId?: string | null): void {
  const nextAccountId = accountIdOrDefault(accountId);
  inboundRuntime = {
    ...inboundRuntime,
    accountId: nextAccountId,
    running: true,
    connected: true,
    lastStartAt: inboundRuntime.lastStartAt ?? Date.now(),
    lastStopAt: null,
    lastError: null,
  };
}

export function markMarmotInboundReceived(accountId?: string | null): void {
  inboundRuntime = {
    ...inboundRuntime,
    accountId: accountIdOrDefault(accountId),
    lastInboundAt: Date.now(),
  };
}

/** Record a durable outbound receipt for channel status/probe reporting. */
export function markMarmotOutboundSent(
  accountId?: string | null,
  sentAt: number = Date.now(),
): void {
  const nextAccountId = accountIdOrDefault(accountId);
  const base = inboundRuntime.accountId === nextAccountId
    ? inboundRuntime
    : stoppedSnapshot(nextAccountId);
  inboundRuntime = {
    ...base,
    lastOutboundAt: sentAt,
  };
}

export function markMarmotInboundReconnect(accountId?: string | null): void {
  inboundRuntime = {
    ...inboundRuntime,
    accountId: accountIdOrDefault(accountId),
    running: true,
    connected: false,
    reconnectAttempts: (inboundRuntime.reconnectAttempts ?? 0) + 1,
    lastError: "inbound subscription dropped",
  };
}

export function markMarmotInboundStopped(accountId?: string | null): void {
  inboundRuntime = {
    ...inboundRuntime,
    accountId: accountIdOrDefault(accountId),
    running: false,
    connected: false,
    lastStopAt: Date.now(),
  };
}

export function marmotInboundRuntimeSnapshot(accountId?: string | null): ChannelAccountSnapshot {
  const nextAccountId = accountIdOrDefault(accountId);
  if (inboundRuntime.accountId !== nextAccountId) {
    return stoppedSnapshot(nextAccountId);
  }
  return { ...inboundRuntime };
}

export function resetMarmotInboundRuntimeForTests(): void {
  inboundRuntime = stoppedSnapshot(DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID);
}
