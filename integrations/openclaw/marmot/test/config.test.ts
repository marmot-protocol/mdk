import { describe, expect, it } from "vitest";

import { resolveMarmotAccount, type ResolveDeps } from "../src/config.js";

function deps(env: Record<string, string | undefined>): ResolveDeps {
  return {
    env,
    homeDir: () => "/home/agent",
    readTextFile: (path: string) =>
      path === "/home/agent/.marmot/control.token" ? "tok-123\n" : `UNEXPECTED:${path}`,
  };
}

describe("resolveMarmotAccount", () => {
  it("defaults the socket under ~/.marmot and reads MARMOT_* env", () => {
    const resolved = resolveMarmotAccount(undefined, "openclaw-acct", deps({
      MARMOT_ACCOUNT_ID_HEX: "aa",
      MARMOT_QUIC_CANDIDATES: "quic://a:1, quic://b:2",
    }));
    expect(resolved.socketPath).toBe("/home/agent/.marmot/dev/dm-agent.sock");
    expect(resolved.marmotAccountIdHex).toBe("aa");
    expect(resolved.quicCandidates).toEqual(["quic://a:1", "quic://b:2"]);
    expect(resolved.streamMode).toBe("block");
    expect(resolved.blockStreaming).toBe(true);
    expect(resolved.accountId).toBe("openclaw-acct");
  });

  it("lets channel config override env", () => {
    const resolved = resolveMarmotAccount(
      { socketPath: "/tmp/x.sock", accountIdHex: "bb", quicCandidates: ["quic://c:3"], streaming: false },
      null,
      deps({ MARMOT_AGENT_SOCKET: "/env.sock", MARMOT_ACCOUNT_ID_HEX: "aa" }),
    );
    expect(resolved.socketPath).toBe("/tmp/x.sock");
    expect(resolved.marmotAccountIdHex).toBe("bb");
    expect(resolved.quicCandidates).toEqual(["quic://c:3"]);
    expect(resolved.streamMode).toBe("off");
    expect(resolved.blockStreaming).toBe(false);
  });

  it("resolves explicit block-streaming controls", () => {
    expect(
      resolveMarmotAccount(
        { quicCandidates: ["quic://c:3"], blockStreaming: false },
        null,
        deps({}),
      ).blockStreaming,
    ).toBe(false);
    expect(
      resolveMarmotAccount(
        { streaming: { mode: "block", block: { enabled: true } } },
        null,
        deps({}),
      ).blockStreaming,
    ).toBe(true);
    expect(resolveMarmotAccount({}, null, deps({ MARMOT_BLOCK_STREAMING: "true" })).blockStreaming).toBe(true);
  });

  it("derives the socket path from MARMOT_HOME", () => {
    const resolved = resolveMarmotAccount(undefined, null, deps({ MARMOT_HOME: "/data/agent" }));
    expect(resolved.socketPath).toBe("/data/agent/dev/dm-agent.sock");
  });

  it("reads the auth token from a (~-expanded) file when no inline token is set", () => {
    const resolved = resolveMarmotAccount({ authTokenFile: "~/.marmot/control.token" }, null, deps({}));
    expect(resolved.authToken).toBe("tok-123");
  });

  it("maps the dm policy and allow-from list", () => {
    const resolved = resolveMarmotAccount(
      { dm: { policy: "allowlist", allowFrom: ["aa", "bb"] } },
      null,
      deps({}),
    );
    expect(resolved.dmPolicy).toBe("allowlist");
    expect(resolved.allowFrom).toEqual(["aa", "bb"]);
  });
});
