import { afterEach, describe, expect, it } from "vitest";

import { createMarmotChannelPlugin, resolveMarmotChannelAccount } from "../src/channel.js";
import {
  markMarmotInboundReady,
  markMarmotInboundReceived,
  resetMarmotInboundRuntimeForTests,
} from "../src/runtime-state.js";

type Cfg = Parameters<typeof resolveMarmotChannelAccount>[0];

afterEach(() => {
  resetMarmotInboundRuntimeForTests();
});

describe("resolveMarmotChannelAccount", () => {
  it("uses the root slice in single-account mode", () => {
    const cfg = { channels: { marmot: { socketPath: "/root.sock" } } } as unknown as Cfg;
    expect(resolveMarmotChannelAccount(cfg, "default").socketPath).toBe("/root.sock");
    expect(resolveMarmotChannelAccount(cfg, null).socketPath).toBe("/root.sock");
  });

  it("resolves accounts.default (and named accounts) in multi-account mode", () => {
    const cfg = {
      channels: {
        marmot: {
          accounts: {
            default: { socketPath: "/d.sock" },
            alice: { socketPath: "/a.sock" },
          },
        },
      },
    } as unknown as Cfg;
    expect(resolveMarmotChannelAccount(cfg, "default").socketPath).toBe("/d.sock");
    expect(resolveMarmotChannelAccount(cfg, "alice").socketPath).toBe("/a.sock");
    expect(resolveMarmotChannelAccount(cfg, null).socketPath).toBe("/d.sock");
  });

  it("throws for an unknown account id in multi-account mode", () => {
    const cfg = {
      channels: { marmot: { accounts: { default: { socketPath: "/d.sock" } } } },
    } as unknown as Cfg;
    expect(() => resolveMarmotChannelAccount(cfg, "bob")).toThrow(/unknown Marmot account/);
  });

  it("reports the active inbound subscription through channel status", async () => {
    const cfg = { channels: { marmot: { profileNameOnboarding: false } } } as unknown as Cfg;
    const plugin = createMarmotChannelPlugin();
    const status = plugin.status;
    if (!status?.buildAccountSnapshot || !status.buildChannelSummary) {
      throw new Error("Marmot plugin should expose channel status hooks");
    }
    const account = resolveMarmotChannelAccount(cfg, "default");
    const probe = { ok: true, accounts: 1, localSigningAccounts: 1 };

    markMarmotInboundReady("default");
    markMarmotInboundReceived("default");

    const snapshot = await status.buildAccountSnapshot({
      account,
      cfg,
      runtime: undefined,
      probe,
      audit: undefined,
    });
    expect(snapshot).toMatchObject({
      accountId: "default",
      running: true,
      connected: true,
      enabled: true,
      configured: true,
      mode: "block",
      dmPolicy: "allowlist",
      probe,
    });
    expect(snapshot.lastInboundAt).toEqual(expect.any(Number));

    const summary = await status.buildChannelSummary({
      account,
      cfg,
      defaultAccountId: "default",
      snapshot,
    });
    expect(summary).toMatchObject({
      configured: true,
      running: true,
      connected: true,
      mode: "block",
      probe,
    });
  });
});
