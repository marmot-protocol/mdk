import { describe, expect, it } from "vitest";

import { MARMOT_TARGET_PREFIX } from "../src/target.js";
import {
  canonicalizeMarmotExternalTarget,
  canonicalizeMarmotGroupTarget,
  MarmotTargetError,
  marmotTargetRejectMessage,
  tryCanonicalizeMarmotGroupTarget,
} from "../src/target.js";

const GID = "a".repeat(32);

describe("canonicalizeMarmotGroupTarget", () => {
  it("accepts bare hex, marmot:, and internal group: prefixes", () => {
    expect(canonicalizeMarmotGroupTarget(GID)).toBe(GID);
    expect(canonicalizeMarmotGroupTarget(`${MARMOT_TARGET_PREFIX}:${GID}`)).toBe(GID);
    expect(canonicalizeMarmotGroupTarget(`group:${GID}`)).toBe(GID);
    expect(canonicalizeMarmotGroupTarget(`GROUP:${GID.toUpperCase()}`)).toBe(GID);
  });

  it("rejects implausible bare unprefixed input only at the external target boundary", () => {
    expect(canonicalizeMarmotGroupTarget("1234567890")).toBe("1234567890");
    expect(() => canonicalizeMarmotExternalTarget("1234567890")).toThrow(MarmotTargetError);
    try {
      canonicalizeMarmotExternalTarget("1234567890");
    } catch (error) {
      expect((error as MarmotTargetError).category).toBe("invalid_hex");
      expect((error as MarmotTargetError).message).not.toContain("1234567890");
    }
  });

  it("allows shorter variable-length ids under explicit marmot: or group: prefixes", () => {
    expect(canonicalizeMarmotGroupTarget(`group:ab`)).toBe("ab");
    expect(canonicalizeMarmotGroupTarget(`${MARMOT_TARGET_PREFIX}:abcd`)).toBe("abcd");
  });

  it("rejects session keys without echoing the target", () => {
    expect(() => canonicalizeMarmotGroupTarget(`agent:main:${MARMOT_TARGET_PREFIX}:group:${GID}`)).toThrow(
      MarmotTargetError,
    );
    try {
      canonicalizeMarmotGroupTarget(`agent:main:${MARMOT_TARGET_PREFIX}:group:${GID}`);
    } catch (error) {
      expect(error).toBeInstanceOf(MarmotTargetError);
      expect((error as MarmotTargetError).category).toBe("session_key");
      expect((error as MarmotTargetError).message).not.toContain(GID);
    }
  });

  it("rejects cross-channel and decorated routes locally", () => {
    expect(() => canonicalizeMarmotGroupTarget("telegram:123")).toThrow(MarmotTargetError);
    expect(() => canonicalizeMarmotGroupTarget("group:not-hex")).toThrow(MarmotTargetError);
    expect(() => canonicalizeMarmotGroupTarget(`group:user:${GID}`)).toThrow(MarmotTargetError);
    try {
      canonicalizeMarmotGroupTarget(`group:user:${GID}`);
    } catch (error) {
      expect((error as MarmotTargetError).category).toBe("decorated_route");
      expect((error as MarmotTargetError).message).not.toContain(GID);
    }
  });

  it.each([
    "user:",
    "channel:",
    "room:",
    "conversation:",
    "dm:",
  ] as const)("rejects %s<validhex> even when the suffix is valid group-id hex", (prefix) => {
    expect(() => canonicalizeMarmotGroupTarget(`${prefix}${GID}`)).toThrow(MarmotTargetError);
    try {
      canonicalizeMarmotGroupTarget(`${prefix}${GID}`);
    } catch (error) {
      expect(error).toBeInstanceOf(MarmotTargetError);
      expect((error as MarmotTargetError).category).toBe("decorated_route");
      expect((error as MarmotTargetError).message).not.toContain(GID);
      expect((error as MarmotTargetError).message).not.toMatch(/lowercase/i);
    }
  });

  it("rejects combined channel/kind decorations even with valid hex", () => {
    for (const target of [
      `marmot:group:${GID}`,
      `marmot:user:${GID}`,
      `marmot:channel:${GID}`,
    ]) {
      expect(() => canonicalizeMarmotGroupTarget(target)).toThrow(MarmotTargetError);
    }
  });

  it("rejects malformed hex without leaking the value", () => {
    for (const target of ["a".repeat(31), `group:zz${"a".repeat(30)}`]) {
      try {
        canonicalizeMarmotGroupTarget(target);
        throw new Error(`expected rejection for ${target.length} char form`);
      } catch (error) {
        expect(error).toBeInstanceOf(MarmotTargetError);
        expect((error as MarmotTargetError).message).not.toContain(target);
      }
    }
  });

  it("keeps the low-level MLS canonicalizer variable-length", () => {
    expect(canonicalizeMarmotGroupTarget("ab")).toBe("ab");
    expect(canonicalizeMarmotGroupTarget(`group:ab`)).toBe("ab");
    expect(canonicalizeMarmotGroupTarget(`marmot:abcd`)).toBe("abcd");
    expect(canonicalizeMarmotExternalTarget(`marmot:abcd`)).toBe("abcd");
  });

  it("maps reject categories to actionable privacy-safe messages", () => {
    expect(marmotTargetRejectMessage("invalid_hex")).toContain("group-id hex");
    expect(marmotTargetRejectMessage("invalid_hex")).not.toMatch(/lowercase/i);
    expect(marmotTargetRejectMessage("session_key")).toContain("session key");
    expect(tryCanonicalizeMarmotGroupTarget("telegram:123")).toBeUndefined();
  });
});
