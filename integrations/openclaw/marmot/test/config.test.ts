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
    }));
    expect(resolved.socketPath).toBe("/home/agent/.marmot/dev/wn-agent.sock");
    expect(resolved.marmotAccountIdHex).toBe("aa");
    expect(resolved.accountId).toBe("openclaw-acct");
  });

  it("lets channel config override env", () => {
    const resolved = resolveMarmotAccount(
      { socketPath: "/tmp/x.sock", accountIdHex: "bb" },
      null,
      deps({ MARMOT_AGENT_SOCKET: "/env.sock", MARMOT_ACCOUNT_ID_HEX: "aa" }),
    );
    expect(resolved.socketPath).toBe("/tmp/x.sock");
    expect(resolved.marmotAccountIdHex).toBe("bb");
  });

  it("derives the socket path from MARMOT_HOME", () => {
    const resolved = resolveMarmotAccount(undefined, null, deps({ MARMOT_HOME: "/data/agent" }));
    expect(resolved.socketPath).toBe("/data/agent/dev/wn-agent.sock");
  });

  it("reads the auth token from a (~-expanded) file when no inline token is set", () => {
    const resolved = resolveMarmotAccount({ authTokenFile: "~/.marmot/control.token" }, null, deps({}));
    expect(resolved.authToken).toBe("tok-123");
  });

  it("resolves the inbound debounce window (off by default; config wins over env)", () => {
    expect(resolveMarmotAccount(undefined, null, deps({})).debounceMs).toBe(0);
    expect(resolveMarmotAccount(undefined, null, deps({ MARMOT_DEBOUNCE_MS: "750" })).debounceMs).toBe(750);
    expect(resolveMarmotAccount({ debounceMs: 1200 }, null, deps({ MARMOT_DEBOUNCE_MS: "750" })).debounceMs).toBe(1200);
    expect(resolveMarmotAccount(undefined, null, deps({ MARMOT_DEBOUNCE_MS: "nope" })).debounceMs).toBe(0);
  });

  it("resolves group activation and mention patterns (defaults: mention, none)", () => {
    const def = resolveMarmotAccount(undefined, null, deps({}));
    expect(def.groupActivation).toBe("mention");
    expect(def.mentionPatterns).toEqual([]);

    const fromConfig = resolveMarmotAccount(
      { groupActivation: "always", mentionPatterns: ["bot", "assistant"] },
      null,
      deps({}),
    );
    expect(fromConfig.groupActivation).toBe("always");
    expect(fromConfig.mentionPatterns).toEqual(["bot", "assistant"]);

    const fromEnv = resolveMarmotAccount(
      undefined,
      null,
      deps({ MARMOT_GROUP_ACTIVATION: "always", MARMOT_MENTION_PATTERNS: "x, y" }),
    );
    expect(fromEnv.groupActivation).toBe("always");
    expect(fromEnv.mentionPatterns).toEqual(["x", "y"]);
  });

  it("resolves senderPolicy atomically and does not infer owners from welcomers", () => {
    const sender = "bb".repeat(32);
    const missing = resolveMarmotAccount({ dm: { allowFrom: [sender] } }, null, deps({}));
    expect(missing.senderPolicy.state).toBe("missing");
    expect(missing.allowFrom).toEqual([sender]);

    const fromEnv = resolveMarmotAccount(undefined, null, deps({ MARMOT_ALLOWED_USERS: sender }));
    expect(fromEnv.senderPolicy).toMatchObject({ state: "allowlist", allowedUsers: [sender] });

    const overridden = resolveMarmotAccount(
      { senderPolicy: { allowedUsers: [] } },
      null,
      deps({ MARMOT_ALLOW_ALL_USERS: "true", MARMOT_ALLOWED_USERS: sender }),
    );
    expect(overridden.senderPolicy.state).toBe("missing");

    const allowAll = resolveMarmotAccount({ senderPolicy: { allowAll: true } }, null, deps({}));
    expect(allowAll.senderPolicy.state).toBe("allow_all");
  });
});
