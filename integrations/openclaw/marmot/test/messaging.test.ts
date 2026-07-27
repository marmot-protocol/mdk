import { describe, expect, it } from "vitest";

import { createMarmotChannelPlugin } from "../src/channel.js";
import {
  createMarmotMessagingAdapter,
  isMarmotGroupIdHex,
  looksLikeMarmotTarget,
  MARMOT_TARGET_PREFIX,
  normalizeMarmotTarget,
} from "../src/messaging.js";
import { MarmotTargetError } from "../src/target.js";

async function resolveThroughOpenClawTargetResolver(input: string): Promise<unknown> {
  const plugin = createMarmotChannelPlugin();
  const resolverUrl = new URL(
    "../node_modules/openclaw/dist/target-resolver-BWTwFOHy.js",
    import.meta.url,
  ).href;
  const resolver = (await import(/* @vite-ignore */ resolverUrl)) as {
    i: (params: {
      cfg: Record<string, never>;
      channel: string;
      input: string;
      plugin: ReturnType<typeof createMarmotChannelPlugin>;
    }) => Promise<{ ok: boolean; error?: unknown; target?: unknown }>;
  };
  const resolved = await resolver.i({
    cfg: {},
    channel: "marmot",
    input,
    plugin,
  });
  if (!resolved.ok) {
    throw resolved.error;
  }
  return resolved.target;
}

// 16-byte (OpenMLS default) and 32-byte group ids, lowercase hex.
const GID16 = "a".repeat(32);
const GID32 = "b".repeat(64);

describe("isMarmotGroupIdHex", () => {
  it("accepts any non-empty even-length lowercase hex", () => {
    expect(isMarmotGroupIdHex(GID16)).toBe(true);
    expect(isMarmotGroupIdHex(GID32)).toBe(true);
    expect(isMarmotGroupIdHex("ab")).toBe(true);
    expect(isMarmotGroupIdHex("abcd")).toBe(true);
  });

  it("rejects empty, odd-length, non-hex, and uppercase input", () => {
    expect(isMarmotGroupIdHex("")).toBe(false);
    expect(isMarmotGroupIdHex("a".repeat(31))).toBe(false); // odd length
    expect(isMarmotGroupIdHex(`zz${"a".repeat(30)}`)).toBe(false); // non-hex
    expect(isMarmotGroupIdHex("A".repeat(32))).toBe(false); // not normalized
  });
});

describe("normalizeMarmotTarget", () => {
  it("returns the bare hex for a plain group id", () => {
    expect(normalizeMarmotTarget(GID16)).toBe(GID16);
  });

  it("strips the marmot: prefix, a 0x prefix, whitespace, and uppercases", () => {
    expect(normalizeMarmotTarget(`  ${MARMOT_TARGET_PREFIX}:${GID16}  `)).toBe(GID16);
    expect(normalizeMarmotTarget(`0x${GID16}`)).toBe(GID16);
    expect(normalizeMarmotTarget(`MARMOT:0X${"A".repeat(32)}`)).toBe(GID16);
    expect(normalizeMarmotTarget(`group:${GID16}`)).toBe(GID16);
  });

  it("returns undefined for non-group-id input", () => {
    expect(normalizeMarmotTarget("alice")).toBeUndefined();
    expect(normalizeMarmotTarget("@alice")).toBeUndefined();
    expect(normalizeMarmotTarget("")).toBeUndefined();
    expect(normalizeMarmotTarget(`${MARMOT_TARGET_PREFIX}:not-hex`)).toBeUndefined();
  });
});

describe("looksLikeMarmotTarget", () => {
  it("is true for a bare group id and any marmot:-prefixed input", () => {
    expect(looksLikeMarmotTarget(GID16)).toBe(true);
    expect(looksLikeMarmotTarget(`${MARMOT_TARGET_PREFIX}:${GID16}`)).toBe(true);
    // The explicit channel prefix qualifies even before hex validation, so a
    // malformed remainder still routes here (and fails later with a clear error).
    expect(looksLikeMarmotTarget(`${MARMOT_TARGET_PREFIX}:whatever`)).toBe(true);
  });

  it("is false for unprefixed non-id input", () => {
    expect(looksLikeMarmotTarget("alice")).toBe(false);
    expect(looksLikeMarmotTarget("#general")).toBe(false);
  });

  it("claims session keys and decorated group routes so Marmot can reject them locally", () => {
    expect(looksLikeMarmotTarget(`agent:main:${MARMOT_TARGET_PREFIX}:group:${GID16}`)).toBe(true);
    expect(looksLikeMarmotTarget(`group:zz${"a".repeat(30)}`)).toBe(true);
  });
});

describe("createMarmotMessagingAdapter", () => {
  const adapter = createMarmotMessagingAdapter();

  it("declares the marmot target prefix and infers every conversation as a group", () => {
    expect(adapter.targetPrefixes).toEqual([MARMOT_TARGET_PREFIX]);
    expect(adapter.inferTargetChatType?.({ to: GID16 })).toBe("group");
  });

  it("normalizes targets to the bare hex wn-agent expects", () => {
    expect(adapter.normalizeTarget?.(`${MARMOT_TARGET_PREFIX}:${GID16}`)).toBe(GID16);
    expect(adapter.normalizeTarget?.("nope")).toBeUndefined();
  });

  it("resolves a group id (bare or prefixed) to a group target", async () => {
    const resolveTarget = adapter.targetResolver?.resolveTarget;
    expect(resolveTarget).toBeTypeOf("function");
    await expect(
      resolveTarget!({ cfg: {} as never, input: GID16, normalized: GID16 }),
    ).resolves.toEqual({ to: GID16, kind: "group", source: "normalized" });
    await expect(
      resolveTarget!({
        cfg: {} as never,
        input: `${MARMOT_TARGET_PREFIX}:${GID16}`,
        normalized: GID16,
      }),
    ).resolves.toEqual({ to: GID16, kind: "group", source: "normalized" });
  });

  it("throws MarmotTargetError from resolveTarget for a non-group-id target", async () => {
    const resolveTarget = adapter.targetResolver?.resolveTarget;
    await expect(
      resolveTarget!({ cfg: {} as never, input: "alice", normalized: "alice" }),
    ).rejects.toBeInstanceOf(MarmotTargetError);
  });

  it("rejects session keys through OpenClaw target resolution without leaking the raw target", async () => {
    const sensitive = `agent:main:${MARMOT_TARGET_PREFIX}:group:${GID16}`;
    await expect(resolveThroughOpenClawTargetResolver(sensitive)).rejects.toMatchObject({
      name: "MarmotTargetError",
      category: "session_key",
    });
    try {
      await resolveThroughOpenClawTargetResolver(sensitive);
    } catch (error) {
      expect((error as Error).message).not.toContain(sensitive);
      expect((error as Error).message).not.toContain(GID16);
    }
  });

  it("rejects malformed group routes through OpenClaw target resolution without leaking the raw target", async () => {
    const sensitive = `group:zz${"a".repeat(30)}`;
    await expect(resolveThroughOpenClawTargetResolver(sensitive)).rejects.toBeInstanceOf(
      MarmotTargetError,
    );
    try {
      await resolveThroughOpenClawTargetResolver(sensitive);
    } catch (error) {
      expect((error as Error).message).not.toContain(sensitive);
    }
  });

  it("rejects cross-channel targets through OpenClaw target resolution without leaking the raw target", async () => {
    const sensitive = `telegram:${GID16}`;
    await expect(resolveThroughOpenClawTargetResolver(sensitive)).rejects.toMatchObject({
      name: "MarmotTargetError",
      category: "cross_channel",
    });
    try {
      await resolveThroughOpenClawTargetResolver(sensitive);
    } catch (error) {
      expect((error as Error).message).not.toContain(sensitive);
      expect((error as Error).message).not.toContain(GID16);
    }
  });
});
