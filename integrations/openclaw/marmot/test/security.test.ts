import { describe, expect, it } from "vitest";

import { normalizeWelcomerId, syncAllowlist, type AllowlistClient } from "../src/security.js";

const HEX32 = (b: string) => b.repeat(32);

function stubAllowlist(current: string[]): {
  client: AllowlistClient;
  adds: string[];
  removes: string[];
} {
  const adds: string[] = [];
  const removes: string[] = [];
  const client = {
    async allowlistList() {
      return { type: "allowlist", account_id_hex: HEX32("aa"), welcomer_account_ids_hex: current };
    },
    async allowlistAdd(_account: string, id: string) {
      adds.push(id);
      return { type: "ack" };
    },
    async allowlistRemove(_account: string, id: string) {
      removes.push(id);
      return { type: "ack" };
    },
  } as unknown as AllowlistClient;
  return { client, adds, removes };
}

describe("syncAllowlist", () => {
  it("adds missing hex welcomers and removes extras", async () => {
    const { client, adds, removes } = stubAllowlist([HEX32("11"), HEX32("22")]);
    const result = await syncAllowlist(client, HEX32("aa"), [
      `0x${HEX32("22")}`,
      HEX32("33"),
      "alice", // non-hex, ignored
    ]);
    expect(adds).toEqual([HEX32("33")]);
    expect(removes).toEqual([HEX32("11")]);
    expect(result).toEqual({ added: [HEX32("33")], removed: [HEX32("11")] });
  });

  it("ignores non-hex allow entries", async () => {
    const { client, adds, removes } = stubAllowlist([]);
    await syncAllowlist(client, HEX32("aa"), ["alice", "bob"]);
    expect(adds).toEqual([]);
    expect(removes).toEqual([]);
  });
});

describe("normalizeWelcomerId", () => {
  it("lowercases and strips 0x", () => {
    expect(normalizeWelcomerId("0xABcd")).toBe("abcd");
    expect(normalizeWelcomerId(42)).toBe("42");
  });
});
