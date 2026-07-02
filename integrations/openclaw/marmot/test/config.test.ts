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

  it("accepts the singular MARMOT_QUIC_CANDIDATE and filters to the quic:// scheme", () => {
    // Singular env var (Hermes parity: plural is preferred, singular is the fallback).
    expect(
      resolveMarmotAccount(undefined, null, deps({ MARMOT_QUIC_CANDIDATE: "quic://solo:1" }))
        .quicCandidates,
    ).toEqual(["quic://solo:1"]);

    // Plural wins when both are set and non-empty.
    expect(
      resolveMarmotAccount(
        undefined,
        null,
        deps({ MARMOT_QUIC_CANDIDATES: "quic://plural:1", MARMOT_QUIC_CANDIDATE: "quic://solo:1" }),
      ).quicCandidates,
    ).toEqual(["quic://plural:1"]);

    // An empty plural falls through to the singular (firstNonEmpty semantics).
    expect(
      resolveMarmotAccount(
        undefined,
        null,
        deps({ MARMOT_QUIC_CANDIDATES: "  ", MARMOT_QUIC_CANDIDATE: "quic://solo:1" }),
      ).quicCandidates,
    ).toEqual(["quic://solo:1"]);

    // Non-quic:// candidates are dropped so a malformed entry never reaches the connector.
    expect(
      resolveMarmotAccount(
        undefined,
        null,
        deps({ MARMOT_QUIC_CANDIDATES: "quic://ok:1, https://bad:2, ws://nope:3, quic://ok:2" }),
      ).quicCandidates,
    ).toEqual(["quic://ok:1", "quic://ok:2"]);

    // The scheme filter also applies to channel config candidates.
    expect(
      resolveMarmotAccount(
        { quicCandidates: ["quic://ok:1", "tcp://bad:2"] },
        null,
        deps({}),
      ).quicCandidates,
    ).toEqual(["quic://ok:1"]);
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
