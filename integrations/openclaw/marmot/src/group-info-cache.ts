// Bounded per-(account, group) cache of group-info facts used for both
// activation (`is_direct`) and native conversation display (normalized subject).
// One cache is owned by one dispatcher/subscription instance. Keys are the full
// account and group hex ids; subjects are never keys, log content, or routes.

export const GROUP_INFO_CACHE_CAPACITY = 256;
export const GROUP_INFO_LABEL_COOLDOWN_MS = 5_000;

export interface GroupInfoFacts {
  isDirect: boolean;
  label?: string;
}

export type GroupInfoLookupPurpose = "activation" | "label";

export type GroupInfoLookupResult =
  | { status: "ok"; facts: GroupInfoFacts }
  | { status: "unavailable" }
  | { status: "failed" };

type PendingEntry = {
  kind: "pending";
  generation: number;
  membershipRequired: boolean;
  promise: Promise<GroupInfoLookupResult>;
  lastUsed: number;
};

type FactsEntry = {
  kind: "facts";
  facts: GroupInfoFacts;
  lastUsed: number;
};

type CooldownEntry = {
  kind: "cooldown";
  untilMs: number;
  lastUsed: number;
};

type CacheEntry = PendingEntry | FactsEntry | CooldownEntry;

export interface GroupInfoCacheOptions {
  capacity?: number;
  cooldownMs?: number;
  now?: () => number;
}

/** Trim a subject to display text. Non-strings, blank, and nullish values are omitted. */
export function normalizeGroupInfoLabel(subject: unknown): string | undefined {
  if (typeof subject !== "string") {
    return undefined;
  }
  const trimmed = subject.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Validate a runtime `group_info` object and the account/group binding. A
 * malformed subject is dropped without discarding a valid `is_direct` fact.
 */
export function parseGroupInfoFacts(
  raw: unknown,
  accountIdHex: string,
  groupIdHex: string,
): GroupInfoFacts | undefined {
  if (raw == null || typeof raw !== "object") {
    return undefined;
  }
  const value = raw as Record<string, unknown>;
  if (value.type !== "group_info") {
    return undefined;
  }
  if (typeof value.account_id_hex !== "string" || value.account_id_hex !== accountIdHex) {
    return undefined;
  }
  if (typeof value.group_id_hex !== "string" || value.group_id_hex !== groupIdHex) {
    return undefined;
  }
  if (typeof value.is_direct !== "boolean") {
    return undefined;
  }
  const label = normalizeGroupInfoLabel(value.subject);
  return label === undefined ? { isDirect: value.is_direct } : { isDirect: value.is_direct, label };
}

function cacheKey(accountIdHex: string, groupIdHex: string): string {
  return `${accountIdHex}:${groupIdHex}`;
}

export class GroupInfoCache {
  private readonly entries = new Map<string, CacheEntry>();
  private readonly capacity: number;
  private readonly cooldownMs: number;
  private readonly now: () => number;
  private nextGeneration = 1;

  constructor(options: GroupInfoCacheOptions = {}) {
    this.capacity = Math.max(1, Math.trunc(options.capacity ?? GROUP_INFO_CACHE_CAPACITY));
    this.cooldownMs = Math.max(0, Math.trunc(options.cooldownMs ?? GROUP_INFO_LABEL_COOLDOWN_MS));
    this.now = options.now ?? Date.now;
  }

  size(): number {
    return this.entries.size;
  }

  peek(accountIdHex: string, groupIdHex: string): CacheEntry["kind"] | undefined {
    return this.entries.get(cacheKey(accountIdHex, groupIdHex))?.kind;
  }

  invalidate(accountIdHex: string, groupIdHex: string): void {
    this.entries.delete(cacheKey(accountIdHex, groupIdHex));
  }

  clear(): void {
    this.entries.clear();
  }

  async lookup(
    accountIdHex: string,
    groupIdHex: string,
    purpose: GroupInfoLookupPurpose,
    fetch: () => Promise<unknown>,
  ): Promise<GroupInfoLookupResult> {
    const key = cacheKey(accountIdHex, groupIdHex);
    const now = this.now();
    const existing = this.entries.get(key);

    if (existing?.kind === "facts") {
      existing.lastUsed = now;
      return { status: "ok", facts: existing.facts };
    }

    if (existing?.kind === "pending") {
      existing.lastUsed = now;
      if (purpose === "activation") {
        existing.membershipRequired = true;
      }
      return existing.promise;
    }

    if (existing?.kind === "cooldown") {
      if (purpose === "label" && now < existing.untilMs) {
        existing.lastUsed = now;
        return { status: "unavailable" };
      }
      this.entries.delete(key);
    }

    if (!this.entries.has(key) && this.entries.size >= this.capacity && !this.evictLruSettled()) {
      return { status: "unavailable" };
    }

    return this.startFetch(key, accountIdHex, groupIdHex, purpose, fetch);
  }

  private startFetch(
    key: string,
    accountIdHex: string,
    groupIdHex: string,
    purpose: GroupInfoLookupPurpose,
    fetch: () => Promise<unknown>,
  ): Promise<GroupInfoLookupResult> {
    const generation = this.nextGeneration;
    this.nextGeneration += 1;
    const pending: PendingEntry = {
      kind: "pending",
      generation,
      membershipRequired: purpose === "activation",
      promise: undefined as unknown as Promise<GroupInfoLookupResult>,
      lastUsed: this.now(),
    };
    const promise = this.runFetch(key, accountIdHex, groupIdHex, generation, fetch);
    pending.promise = promise;
    this.entries.set(key, pending);
    return promise;
  }

  private async runFetch(
    key: string,
    accountIdHex: string,
    groupIdHex: string,
    generation: number,
    fetch: () => Promise<unknown>,
  ): Promise<GroupInfoLookupResult> {
    let raw: unknown;
    try {
      raw = await fetch();
    } catch {
      return this.finishFailure(key, generation, "failed");
    }
    const facts = parseGroupInfoFacts(raw, accountIdHex, groupIdHex);
    if (!facts) {
      return this.finishFailure(key, generation, "failed");
    }
    if (this.isCurrentPending(key, generation)) {
      this.entries.set(key, { kind: "facts", facts, lastUsed: this.now() });
    }
    return { status: "ok", facts };
  }

  private finishFailure(
    key: string,
    generation: number,
    status: "failed" | "unavailable",
  ): GroupInfoLookupResult {
    if (!this.isCurrentPending(key, generation)) {
      return { status };
    }
    const pending = this.entries.get(key);
    if (pending?.kind === "pending" && !pending.membershipRequired) {
      this.entries.set(key, {
        kind: "cooldown",
        untilMs: this.now() + this.cooldownMs,
        lastUsed: this.now(),
      });
      return { status: "unavailable" };
    }
    this.entries.delete(key);
    return { status };
  }

  private isCurrentPending(key: string, generation: number): boolean {
    const entry = this.entries.get(key);
    return entry?.kind === "pending" && entry.generation === generation;
  }

  private evictLruSettled(): boolean {
    let oldestKey: string | undefined;
    let oldest = Number.POSITIVE_INFINITY;
    for (const [key, entry] of this.entries) {
      if (entry.kind === "pending") {
        continue;
      }
      if (entry.lastUsed < oldest) {
        oldest = entry.lastUsed;
        oldestKey = key;
      }
    }
    if (oldestKey === undefined) {
      return false;
    }
    this.entries.delete(oldestKey);
    return true;
  }
}
