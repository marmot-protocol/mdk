import { describe, expect, it } from "vitest";

import {
  canonicalizeTurnSourceMessageIds,
  deriveTurnIdempotencyKey,
  deriveTurnIdempotencyKeyFromInbound,
} from "../src/turn-idempotency.js";

const HEX = (b: string) => b.repeat(32);

describe("deriveTurnIdempotencyKey", () => {
  it("is deterministic for the same account, group, and source message set", () => {
    const params = {
      marmotAccountIdHex: HEX("aa"),
      groupIdHex: HEX("cc"),
      sourceMessageIdsHex: [HEX("dd"), HEX("ee")],
    };
    const first = deriveTurnIdempotencyKey(params);
    const second = deriveTurnIdempotencyKey(params);
    expect(first).toBe(second);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(first).not.toContain(HEX("aa"));
    expect(first).not.toContain(HEX("cc"));
    expect(first).not.toContain(HEX("dd"));
  });

  it("canonicalizes coalesced source ids as a sorted unique set", () => {
    const account = HEX("aa");
    const group = HEX("cc");
    const primary = HEX("01");
    const secondary = HEX("02");
    const ordered = deriveTurnIdempotencyKey({
      marmotAccountIdHex: account,
      groupIdHex: group,
      sourceMessageIdsHex: [primary, secondary],
    });
    const reversed = deriveTurnIdempotencyKey({
      marmotAccountIdHex: account,
      groupIdHex: group,
      sourceMessageIdsHex: [secondary, primary, primary],
    });
    expect(reversed).toBe(ordered);
    expect(canonicalizeTurnSourceMessageIds(primary, [secondary, primary])).toEqual([
      primary,
      secondary,
    ]);
  });

  it("derives the same key from inbound messages across process restarts", () => {
    const inbound = {
      accountIdHex: HEX("aa"),
      groupIdHex: HEX("cc"),
      messageIdHex: HEX("dd"),
      coalescedMessageIdsHex: [HEX("ee"), HEX("dd")],
    };
    const processA = deriveTurnIdempotencyKeyFromInbound(inbound);
    const processB = deriveTurnIdempotencyKeyFromInbound({
      ...inbound,
      coalescedMessageIdsHex: [HEX("ee")],
    });
    expect(processB).toBe(processA);
  });
});
