import { afterEach, describe, expect, it } from "vitest";

import {
  beginMarmotAccountLifecycle,
  markMarmotAllowlistSyncResult,
  markMarmotInboundReady,
  markMarmotInboundReceived,
  markMarmotInboundReconnect,
  markMarmotInboundSetupFailed,
  markMarmotInboundStarting,
  markMarmotInboundStopped,
  markMarmotOutboundSent,
  markMarmotSenderAuthorizerLifecycle,
  markMarmotSenderPolicyResult,
  marmotAllowlistPolicyState,
  marmotInboundRuntimeSnapshot,
  marmotSenderAuthorizerLifecycle,
  marmotSenderPolicyState,
  MARMOT_ALLOWLIST_SYNC_FAILED,
  MARMOT_SENDER_POLICY_MISSING,
  resetMarmotInboundRuntimeForTests,
} from "../src/runtime-state.js";

afterEach(() => {
  resetMarmotInboundRuntimeForTests();
});

describe("per-account composed readiness", () => {
  it("keeps pending disconnected without publishing a policy failure", () => {
    beginMarmotAccountLifecycle("work");
    expect(marmotAllowlistPolicyState("work")).toBe("pending");
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      accountId: "work",
      running: true,
      connected: false,
      lastError: null,
    });
  });

  it("stays degraded after ack when policy failed, and stays disconnected after reconcile without ack", () => {
    beginMarmotAccountLifecycle("work");
    markMarmotAllowlistSyncResult("work", { state: "failed", reason: "unverified" });
    markMarmotInboundStarting("work");
    markMarmotInboundReady("work");
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      connected: false,
      lastError: MARMOT_ALLOWLIST_SYNC_FAILED,
    });

    markMarmotInboundStopped("work");
    beginMarmotAccountLifecycle("work");
    markMarmotAllowlistSyncResult("work", { state: "reconciled" });
    markMarmotSenderPolicyResult("work", { state: "allowlist", allowedUserCount: 1 });
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      connected: false,
      lastError: null,
    });
    markMarmotInboundStarting("work");
    markMarmotInboundReady("work");
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      running: true,
      connected: true,
      lastError: null,
    });
  });

  it("gives policy failure diagnostic precedence over an inbound transport error", () => {
    beginMarmotAccountLifecycle("work");
    markMarmotInboundStarting("work");
    markMarmotInboundReady("work");
    markMarmotInboundReconnect("work");
    markMarmotAllowlistSyncResult("work", { state: "failed", reason: "control" });
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      connected: false,
      lastError: MARMOT_ALLOWLIST_SYNC_FAILED,
    });

    markMarmotAllowlistSyncResult("work", { state: "reconciled" });
    markMarmotSenderPolicyResult("work", { state: "allow_all", allowedUserCount: 0 });
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      connected: false,
      lastError: "inbound subscription dropped",
    });
  });

  it("does not let inbound receipt, outbound receipt, or a late ready resurrect a stopped account", () => {
    beginMarmotAccountLifecycle("work");
    markMarmotAllowlistSyncResult("work", { state: "failed", reason: "unverified" });
    markMarmotInboundStarting("work");
    markMarmotInboundReady("work");
    markMarmotInboundReceived("work");
    const inboundAt = marmotInboundRuntimeSnapshot("work").lastInboundAt;
    markMarmotInboundStopped("work");

    markMarmotInboundReceived("work");
    markMarmotOutboundSent("work", 99);
    markMarmotInboundReady("work");

    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      running: false,
      connected: false,
      lastError: MARMOT_ALLOWLIST_SYNC_FAILED,
      lastOutboundAt: 99,
      lastInboundAt: expect.any(Number),
    });
    expect(marmotInboundRuntimeSnapshot("work").lastInboundAt).toBeGreaterThanOrEqual(inboundAt ?? 0);
  });

  it("isolates two channel accounts and ignores outbound-only traffic for an unknown account", () => {
    beginMarmotAccountLifecycle("alpha");
    markMarmotAllowlistSyncResult("alpha", { state: "failed", reason: "control" });
    markMarmotInboundStarting("alpha");
    markMarmotInboundReady("alpha");

    beginMarmotAccountLifecycle("beta");
    markMarmotAllowlistSyncResult("beta", { state: "reconciled" });
    markMarmotSenderPolicyResult("beta", { state: "allowlist", allowedUserCount: 1 });
    markMarmotInboundStarting("beta");
    markMarmotInboundReady("beta");
    markMarmotInboundReceived("beta");

    expect(marmotInboundRuntimeSnapshot("alpha")).toMatchObject({
      accountId: "alpha",
      connected: false,
      lastError: MARMOT_ALLOWLIST_SYNC_FAILED,
    });
    expect(marmotInboundRuntimeSnapshot("beta")).toMatchObject({
      accountId: "beta",
      connected: true,
      lastError: null,
    });
    expect(marmotInboundRuntimeSnapshot("beta").lastInboundAt).toEqual(expect.any(Number));
    expect(marmotInboundRuntimeSnapshot("alpha").lastInboundAt).toBeUndefined();

    expect(markMarmotOutboundSent("gamma", 7)).toBeNull();
    expect(marmotInboundRuntimeSnapshot("gamma")).toMatchObject({
      running: false,
      connected: false,
      lastOutboundAt: undefined,
    });
    expect(marmotInboundRuntimeSnapshot("alpha").lastError).toBe(MARMOT_ALLOWLIST_SYNC_FAILED);
  });

  it("keeps setup failure visible without inheriting another account's policy", () => {
    beginMarmotAccountLifecycle("alpha");
    markMarmotAllowlistSyncResult("alpha", { state: "reconciled" });
    markMarmotInboundSetupFailed("beta");
    expect(marmotInboundRuntimeSnapshot("beta")).toMatchObject({
      accountId: "beta",
      running: false,
      connected: false,
      lastError: "could not resolve agent account",
    });
    expect(marmotInboundRuntimeSnapshot("alpha")).toMatchObject({
      connected: false,
      lastError: null,
    });
  });

  it("keeps missing or invalid sender policy disconnected after a welcomer-ready ack", () => {
    beginMarmotAccountLifecycle("work");
    markMarmotAllowlistSyncResult("work", { state: "reconciled" });
    markMarmotSenderPolicyResult("work", { state: "missing", allowedUserCount: 0 });
    markMarmotInboundStarting("work");
    markMarmotInboundReady("work");
    expect(marmotSenderPolicyState("work")).toBe("missing");
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      connected: false,
      lastError: MARMOT_SENDER_POLICY_MISSING,
    });

    markMarmotSenderPolicyResult("work", { state: "invalid", allowedUserCount: 0 });
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      connected: false,
      lastError: "marmot_sender_policy_invalid",
    });
    expect(JSON.stringify(marmotInboundRuntimeSnapshot("work"))).not.toContain("aa".repeat(32));
  });

  it("does not report connected while the bound authorizer lifecycle is stopped", () => {
    beginMarmotAccountLifecycle("work");
    markMarmotAllowlistSyncResult("work", { state: "reconciled" });
    markMarmotSenderPolicyResult("work", { state: "allowlist", allowedUserCount: 1 });
    markMarmotSenderAuthorizerLifecycle("work", "stopped");
    markMarmotInboundStarting("work");
    markMarmotInboundReady("work");
    expect(marmotSenderAuthorizerLifecycle("work")).toBe("stopped");
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      running: true,
      connected: false,
      lastError: null,
    });

    markMarmotSenderAuthorizerLifecycle("work", "active");
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      running: true,
      connected: true,
      lastError: null,
    });
  });

  it("ignores a stale setup failure after the current generation is acknowledged", () => {
    beginMarmotAccountLifecycle("work");
    markMarmotAllowlistSyncResult("work", { state: "reconciled" });
    markMarmotSenderPolicyResult("work", { state: "allowlist", allowedUserCount: 1 });
    markMarmotInboundStarting("work");
    markMarmotInboundReady("work");
    markMarmotInboundSetupFailed("work");
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      running: true,
      connected: true,
      lastError: null,
    });
  });
});
