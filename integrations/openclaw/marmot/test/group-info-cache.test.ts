import { describe, expect, it } from "vitest";

import {
  GROUP_INFO_CACHE_CAPACITY,
  GROUP_INFO_LABEL_COOLDOWN_MS,
  GroupInfoCache,
  normalizeGroupInfoLabel,
  parseGroupInfoFacts,
} from "../src/group-info-cache.js";

const ACCOUNT_A = "aa".repeat(32);
const ACCOUNT_B = "bb".repeat(32);
const GROUP_32 = "cc".repeat(32);
const GROUP_16 = "dd".repeat(16);
const GROUP_OTHER = "ee".repeat(32);

function info(opts: {
  account?: string;
  group?: string;
  isDirect?: boolean;
  subject?: unknown;
  type?: string;
}): Record<string, unknown> {
  return {
    type: opts.type ?? "group_info",
    account_id_hex: opts.account ?? ACCOUNT_A,
    group_id_hex: opts.group ?? GROUP_32,
    member_count: opts.isDirect === false ? 5 : 2,
    is_direct: opts.isDirect ?? true,
    subject: opts.subject,
  };
}

describe("normalizeGroupInfoLabel", () => {
  it("trims strings and omits blank, nullish, and non-string values", () => {
    expect(normalizeGroupInfoLabel("  Project Marmot  ")).toBe("Project Marmot");
    expect(normalizeGroupInfoLabel("")).toBeUndefined();
    expect(normalizeGroupInfoLabel("   ")).toBeUndefined();
    expect(normalizeGroupInfoLabel(null)).toBeUndefined();
    expect(normalizeGroupInfoLabel(undefined)).toBeUndefined();
    expect(normalizeGroupInfoLabel(12)).toBeUndefined();
    expect(normalizeGroupInfoLabel({ name: "nope" })).toBeUndefined();
  });
});

describe("parseGroupInfoFacts", () => {
  it("keeps isDirect when the subject is malformed", () => {
    expect(parseGroupInfoFacts(info({ isDirect: true, subject: 7 }), ACCOUNT_A, GROUP_32)).toEqual({
      isDirect: true,
    });
  });

  it("rejects unbound or untyped responses", () => {
    expect(parseGroupInfoFacts(info({ account: ACCOUNT_B }), ACCOUNT_A, GROUP_32)).toBeUndefined();
    expect(parseGroupInfoFacts(info({ group: GROUP_OTHER }), ACCOUNT_A, GROUP_32)).toBeUndefined();
    expect(parseGroupInfoFacts(info({ type: "timeline_page" }), ACCOUNT_A, GROUP_32)).toBeUndefined();
    expect(parseGroupInfoFacts("nope", ACCOUNT_A, GROUP_32)).toBeUndefined();
  });
});

describe("GroupInfoCache", () => {
  it("caches named and unnamed hits and shares one in-flight fetch", async () => {
    let calls = 0;
    let resolveFetch!: (value: unknown) => void;
    const cache = new GroupInfoCache();
    const pending = cache.lookup(ACCOUNT_A, GROUP_32, "activation", () => {
      calls += 1;
      return new Promise((resolve) => {
        resolveFetch = resolve;
      });
    });
    const shared = cache.lookup(ACCOUNT_A, GROUP_32, "label", () => {
      calls += 1;
      return Promise.resolve(info({ subject: "ignored" }));
    });
    expect(calls).toBe(1);
    expect(cache.size()).toBe(1);
    expect(cache.peek(ACCOUNT_A, GROUP_32)).toBe("pending");
    resolveFetch(info({ subject: "  Project  " }));
    await expect(pending).resolves.toEqual({
      status: "ok",
      facts: { isDirect: true, label: "Project" },
    });
    await expect(shared).resolves.toEqual({
      status: "ok",
      facts: { isDirect: true, label: "Project" },
    });
    await expect(
      cache.lookup(ACCOUNT_A, GROUP_32, "label", () => {
        calls += 1;
        return Promise.resolve(info({ subject: "later" }));
      }),
    ).resolves.toEqual({ status: "ok", facts: { isDirect: true, label: "Project" } });
    expect(calls).toBe(1);

    const unnamed = new GroupInfoCache();
    await expect(
      unnamed.lookup(ACCOUNT_A, GROUP_OTHER, "label", async () =>
        info({ group: GROUP_OTHER, subject: null }),
      ),
    ).resolves.toEqual({ status: "ok", facts: { isDirect: true } });
    await expect(
      unnamed.lookup(ACCOUNT_A, GROUP_OTHER, "activation", async () => {
        throw new Error("must not refetch unnamed");
      }),
    ).resolves.toEqual({ status: "ok", facts: { isDirect: true } });
  });

  it("keeps distinct keys for account, group, and 16-byte MLS ids", async () => {
    const cache = new GroupInfoCache();
    await cache.lookup(ACCOUNT_A, GROUP_32, "label", async () =>
      info({ subject: "A", isDirect: false }),
    );
    await cache.lookup(ACCOUNT_B, GROUP_32, "label", async () =>
      info({ account: ACCOUNT_B, subject: "B" }),
    );
    await cache.lookup(ACCOUNT_A, GROUP_16, "label", async () =>
      info({ group: GROUP_16, subject: "Sixteen", isDirect: false }),
    );
    expect(cache.size()).toBe(3);
    await expect(
      cache.lookup(ACCOUNT_A, GROUP_32, "label", async () => {
        throw new Error("hit");
      }),
    ).resolves.toMatchObject({ facts: { label: "A", isDirect: false } });
    await expect(
      cache.lookup(ACCOUNT_B, GROUP_32, "label", async () => {
        throw new Error("hit");
      }),
    ).resolves.toMatchObject({ facts: { label: "B" } });
    await expect(
      cache.lookup(ACCOUNT_A, GROUP_16, "label", async () => {
        throw new Error("hit");
      }),
    ).resolves.toMatchObject({ facts: { label: "Sixteen" } });
  });

  it("cools a label-only failure and lets activation retry immediately", async () => {
    let now = 1_000;
    let calls = 0;
    const cache = new GroupInfoCache({
      cooldownMs: GROUP_INFO_LABEL_COOLDOWN_MS,
      now: () => now,
    });
    await expect(
      cache.lookup(ACCOUNT_A, GROUP_32, "label", async () => {
        calls += 1;
        throw new Error("label failed");
      }),
    ).resolves.toEqual({ status: "unavailable" });
    expect(cache.peek(ACCOUNT_A, GROUP_32)).toBe("cooldown");
    await expect(
      cache.lookup(ACCOUNT_A, GROUP_32, "label", async () => {
        calls += 1;
        return info({ subject: "late" });
      }),
    ).resolves.toEqual({ status: "unavailable" });
    expect(calls).toBe(1);

    await expect(
      cache.lookup(ACCOUNT_A, GROUP_32, "activation", async () => {
        calls += 1;
        return info({ subject: "fresh" });
      }),
    ).resolves.toEqual({ status: "ok", facts: { isDirect: true, label: "fresh" } });
    expect(calls).toBe(2);

    now = 2_000;
    const cooling = new GroupInfoCache({ now: () => now });
    await cooling.lookup(ACCOUNT_A, GROUP_32, "label", async () => {
      throw new Error("cool");
    });
    now = 2_000 + GROUP_INFO_LABEL_COOLDOWN_MS;
    await expect(
      cooling.lookup(ACCOUNT_A, GROUP_32, "label", async () => info({ subject: "after" })),
    ).resolves.toMatchObject({ facts: { label: "after" } });
  });

  it("does not cache an activation error as isDirect false", async () => {
    let calls = 0;
    const cache = new GroupInfoCache();
    await expect(
      cache.lookup(ACCOUNT_A, GROUP_32, "activation", async () => {
        calls += 1;
        throw new Error("membership failed");
      }),
    ).resolves.toEqual({ status: "failed" });
    expect(cache.size()).toBe(0);
    await expect(
      cache.lookup(ACCOUNT_A, GROUP_32, "activation", async () => {
        calls += 1;
        return info({ isDirect: true, subject: "DM" });
      }),
    ).resolves.toEqual({ status: "ok", facts: { isDirect: true, label: "DM" } });
    expect(calls).toBe(2);
  });

  it("evicts LRU settled entries and refuses work at all-pending capacity", async () => {
    let now = 10;
    const cache = new GroupInfoCache({ capacity: 2, now: () => now });
    await cache.lookup(ACCOUNT_A, GROUP_32, "label", async () => info({ subject: "old" }));
    now = 20;
    await cache.lookup(ACCOUNT_A, GROUP_OTHER, "label", async () =>
      info({ group: GROUP_OTHER, subject: "newer" }),
    );
    now = 30;
    await cache.lookup(ACCOUNT_B, GROUP_32, "label", async () =>
      info({ account: ACCOUNT_B, subject: "third" }),
    );
    expect(cache.size()).toBe(2);
    expect(cache.peek(ACCOUNT_A, GROUP_32)).toBeUndefined();
    expect(cache.peek(ACCOUNT_A, GROUP_OTHER)).toBe("facts");
    expect(cache.peek(ACCOUNT_B, GROUP_32)).toBe("facts");

    const deferred: Array<(value: unknown) => void> = [];
    const pendingCache = new GroupInfoCache({ capacity: 2 });
    const first = pendingCache.lookup(ACCOUNT_A, GROUP_32, "label", () => {
      return new Promise((resolve) => deferred.push(resolve));
    });
    const second = pendingCache.lookup(ACCOUNT_A, GROUP_OTHER, "activation", () => {
      return new Promise((resolve) => deferred.push(resolve));
    });
    await expect(
      pendingCache.lookup(ACCOUNT_B, GROUP_32, "label", async () => info({ account: ACCOUNT_B })),
    ).resolves.toEqual({ status: "unavailable" });
    await expect(
      pendingCache.lookup(ACCOUNT_B, GROUP_32, "activation", async () => info({ account: ACCOUNT_B })),
    ).resolves.toEqual({ status: "unavailable" });
    expect(pendingCache.size()).toBe(2);
    deferred[0]?.(info({ subject: "one" }));
    deferred[1]?.(info({ group: GROUP_OTHER, subject: "two" }));
    await first;
    await second;
    expect(pendingCache.size()).toBe(2);
  });

  it("invalidates in-flight generations and ignores a late stale completion", async () => {
    let resolveOld!: (value: unknown) => void;
    let resolveNew!: (value: unknown) => void;
    const cache = new GroupInfoCache();
    const oldLookup = cache.lookup(ACCOUNT_A, GROUP_32, "label", () => {
      return new Promise((resolve) => {
        resolveOld = resolve;
      });
    });
    cache.invalidate(ACCOUNT_A, GROUP_32);
    expect(cache.size()).toBe(0);
    const newLookup = cache.lookup(ACCOUNT_A, GROUP_32, "label", () => {
      return new Promise((resolve) => {
        resolveNew = resolve;
      });
    });
    resolveOld(info({ subject: "stale" }));
    await expect(oldLookup).resolves.toEqual({
      status: "ok",
      facts: { isDirect: true, label: "stale" },
    });
    expect(cache.peek(ACCOUNT_A, GROUP_32)).toBe("pending");
    resolveNew(info({ subject: "fresh" }));
    await expect(newLookup).resolves.toEqual({
      status: "ok",
      facts: { isDirect: true, label: "fresh" },
    });
    await expect(
      cache.lookup(ACCOUNT_A, GROUP_32, "label", async () => {
        throw new Error("must stay on fresh");
      }),
    ).resolves.toMatchObject({ facts: { label: "fresh" } });

    const cleared = new GroupInfoCache();
    let resolveCleared!: (value: unknown) => void;
    const inflight = cleared.lookup(ACCOUNT_A, GROUP_32, "activation", () => {
      return new Promise((resolve) => {
        resolveCleared = resolve;
      });
    });
    cleared.clear();
    resolveCleared(info({ subject: "ghost" }));
    await inflight;
    expect(cleared.size()).toBe(0);
  });

  it("counts cooldown entries toward capacity", async () => {
    const cache = new GroupInfoCache({ capacity: 1 });
    await cache.lookup(ACCOUNT_A, GROUP_32, "label", async () => {
      throw new Error("cool");
    });
    expect(cache.size()).toBe(1);
    await cache.lookup(ACCOUNT_A, GROUP_OTHER, "label", async () =>
      info({ group: GROUP_OTHER, subject: "kept" }),
    );
    expect(cache.peek(ACCOUNT_A, GROUP_32)).toBeUndefined();
    expect(cache.peek(ACCOUNT_A, GROUP_OTHER)).toBe("facts");
  });

  it("uses the default production bounds", () => {
    expect(GROUP_INFO_CACHE_CAPACITY).toBe(256);
    expect(GROUP_INFO_LABEL_COOLDOWN_MS).toBe(5_000);
  });
});
