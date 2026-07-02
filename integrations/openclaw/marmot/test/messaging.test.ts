import { describe, expect, it } from "vitest";

import {
  createMarmotMessagingAdapter,
  isMarmotGroupIdHex,
  looksLikeMarmotTarget,
  MARMOT_TARGET_PREFIX,
  normalizeMarmotTarget,
} from "../src/messaging.js";

// 16-byte (OpenMLS default) and 32-byte group ids, lowercase hex.
const GID16 = "a".repeat(32);
const GID32 = "b".repeat(64);

describe("isMarmotGroupIdHex", () => {
  it("accepts 16-byte and 32-byte lowercase hex", () => {
    expect(isMarmotGroupIdHex(GID16)).toBe(true);
    expect(isMarmotGroupIdHex(GID32)).toBe(true);
  });

  it("rejects too-short, odd-length, non-hex, and uppercase input", () => {
    expect(isMarmotGroupIdHex("ab")).toBe(false); // too short
    expect(isMarmotGroupIdHex("a".repeat(31))).toBe(false); // odd length
    expect(isMarmotGroupIdHex(`zz${"a".repeat(30)}`)).toBe(false); // non-hex
    expect(isMarmotGroupIdHex("A".repeat(32))).toBe(false); // not normalized
    expect(isMarmotGroupIdHex("a".repeat(130))).toBe(false); // beyond the band
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
});

describe("createMarmotMessagingAdapter", () => {
  const adapter = createMarmotMessagingAdapter();

  it("declares the marmot target prefix and infers every conversation as a group", () => {
    expect(adapter.targetPrefixes).toEqual([MARMOT_TARGET_PREFIX]);
    expect(adapter.inferTargetChatType?.({ to: GID16 })).toBe("group");
  });

  it("normalizes targets to the bare hex dm-agent expects", () => {
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

  it("returns null from resolveTarget for a non-group-id target", async () => {
    const resolveTarget = adapter.targetResolver?.resolveTarget;
    await expect(
      resolveTarget!({ cfg: {} as never, input: "alice", normalized: "alice" }),
    ).resolves.toBeNull();
  });
});
