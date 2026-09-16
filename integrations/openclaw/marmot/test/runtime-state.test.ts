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
  marmotAllowlistPolicyState,
  marmotInboundRuntimeSnapshot,
  MARMOT_ALLOWLIST_SYNC_FAILED,
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
});
