import { describe, expect, it } from "vitest";

import { normalizeWelcomerId, syncAllowlist, type AllowlistClient } from "../src/security.js";

const HEX32 = (b: string) => b.repeat(32);

interface StubOptions {
  /** Ids whose `allowlist_add` throws. */
  failAdds?: string[];
  /** Ids whose `allowlist_remove` throws. */
  failRemoves?: string[];
  /** Runs on every read-back (list call after the first); may mutate or throw. */
  onReadBack?: (effective: Set<string>) => void;
}

/**
 * Stub that models wn-agent's authoritative set, so tests can assert the
 * effective final allowlist and not only the attempted calls.
 */
function stubAllowlist(
  current: string[],
  options: StubOptions = {},
): {
  client: AllowlistClient;
  adds: string[];
  removes: string[];
  effective: Set<string>;
} {
  const effective = new Set(current);
  const failAdds = new Set(options.failAdds ?? []);
  const failRemoves = new Set(options.failRemoves ?? []);
  const adds: string[] = [];
  const removes: string[] = [];
  let listCalls = 0;
  const client = {
    async allowlistList() {
      listCalls += 1;
      if (listCalls > 1) {
        options.onReadBack?.(effective);
      }
      return {
        type: "allowlist",
        account_id_hex: HEX32("aa"),
        welcomer_account_ids_hex: [...effective],
      };
    },
    async allowlistAdd(_account: string, id: string) {
      adds.push(id);
      if (failAdds.has(id)) {
        throw new Error("allowlist_add failed");
      }
      effective.add(id);
      return { type: "ack" };
    },
    async allowlistRemove(_account: string, id: string) {
      removes.push(id);
      if (failRemoves.has(id)) {
        throw new Error("allowlist_remove failed");
      }
      effective.delete(id);
      return { type: "ack" };
    },
  } as unknown as AllowlistClient;
  return { client, adds, removes, effective };
}

describe("syncAllowlist", () => {
  it("adds missing hex welcomers and removes extras", async () => {
    const { client, adds, removes, effective } = stubAllowlist([HEX32("11"), HEX32("22")]);
    const result = await syncAllowlist(client, HEX32("aa"), [
      `0x${HEX32("22")}`,
      HEX32("33"),
      "alice", // non-hex, ignored
    ]);
    expect(adds).toEqual([HEX32("33")]);
    expect(removes).toEqual([HEX32("11")]);
    expect(result).toEqual({
      added: [HEX32("33")],
      removed: [HEX32("11")],
      failedAdds: [],
      failedRemovals: [],
      verified: true,
    });
    expect([...effective].sort()).toEqual([HEX32("22"), HEX32("33")].sort());
  });

  it("ignores non-hex allow entries", async () => {
    const { client, adds, removes } = stubAllowlist([]);
    const result = await syncAllowlist(client, HEX32("aa"), ["alice", "bob"]);
    expect(adds).toEqual([]);
    expect(removes).toEqual([]);
    expect(result.verified).toBe(true);
  });

  it("revokes before adding, so a failed addition cannot skip a revocation", async () => {
    const stale = HEX32("11");
    const fresh = HEX32("33");
    const { client, removes, effective } = stubAllowlist([stale], { failAdds: [fresh] });

    const result = await syncAllowlist(client, HEX32("aa"), [fresh]);

    expect(removes).toEqual([stale]);
    expect(effective.has(stale)).toBe(false);
    expect(result.removed).toEqual([stale]);
    expect(result.failedAdds).toEqual([fresh]);
  });

  it("keeps revoking after a failed revocation and still applies additions", async () => {
    const stuck = HEX32("11");
    const later = HEX32("22");
    const fresh = HEX32("33");
    const { client, removes, effective } = stubAllowlist([stuck, later], {
      failRemoves: [stuck],
    });

    const result = await syncAllowlist(client, HEX32("aa"), [fresh]);

    expect(removes).toEqual([stuck, later]);
    expect(result.removed).toEqual([later]);
    expect(result.failedRemovals).toEqual([stuck]);
    expect(result.added).toEqual([fresh]);
    expect([...effective].sort()).toEqual([stuck, fresh].sort());
    expect(result.verified).toBe(false);
  });

  it("never reports an entry whose control-plane call failed", async () => {
    const stuck = HEX32("11");
    const fresh = HEX32("33");
    const { client } = stubAllowlist([stuck], { failRemoves: [stuck], failAdds: [fresh] });

    const result = await syncAllowlist(client, HEX32("aa"), [fresh]);

    expect(result.removed).not.toContain(stuck);
    expect(result.added).not.toContain(fresh);
    expect(result.failedRemovals).toEqual([stuck]);
    expect(result.failedAdds).toEqual([fresh]);
    expect(result.verified).toBe(false);
  });

  it("reports read-back divergence as unverified even when every call succeeded", async () => {
    const rogue = HEX32("44");
    const { client } = stubAllowlist([], {
      onReadBack: (effective) => {
        effective.add(rogue); // another writer on the shared account
      },
    });

    const result = await syncAllowlist(client, HEX32("aa"), [HEX32("33")]);

    expect(result.added).toEqual([HEX32("33")]);
    expect(result.failedAdds).toEqual([]);
    expect(result.verified).toBe(false);
  });

  it("reports an unreadable effective set as unverified", async () => {
    const { client } = stubAllowlist([], {
      onReadBack: () => {
        throw new Error("allowlist_list failed");
      },
    });

    const result = await syncAllowlist(client, HEX32("aa"), [HEX32("33")]);

    expect(result.added).toEqual([HEX32("33")]);
    expect(result.verified).toBe(false);
  });

  it("propagates a failure to read the current allowlist before mutating anything", async () => {
    const client = {
      async allowlistList() {
        throw new Error("allowlist_list failed");
      },
      async allowlistAdd() {
        throw new Error("must not be called");
      },
      async allowlistRemove() {
        throw new Error("must not be called");
      },
    } as unknown as AllowlistClient;

    await expect(syncAllowlist(client, HEX32("aa"), [HEX32("33")])).rejects.toThrow();
  });
});

describe("normalizeWelcomerId", () => {
  it("lowercases and strips 0x", () => {
    expect(normalizeWelcomerId("0xABcd")).toBe("abcd");
    expect(normalizeWelcomerId(42)).toBe("42");
  });
});
