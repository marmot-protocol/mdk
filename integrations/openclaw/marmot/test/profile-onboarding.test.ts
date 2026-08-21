import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  buildProfilePrompt,
  MAX_PROFILE_NAME_CHARS,
  maybeHandleProfileOnboardingInbound,
  maybeSendProfilePromptOnJoin,
  parseProfileNameReply,
  PROFILE_NAME_EMPTY,
  PROFILE_NAME_PUBLISH_FAILED,
  PROFILE_NAME_PUBLISHED,
  PROFILE_NAME_SKIPPED,
  PROFILE_NAME_TOO_LONG,
  PROFILE_PROMPT_NO_NAME,
  ProfileLookupGate,
  ProfileNameOnboardingStore,
  type OnboardingRecord,
  type ProfileOnboardingClient,
  type ProfileOnboardingStateStore,
} from "../src/profile-onboarding.js";

const HEX = (b: string) => b.repeat(32);
const ACCOUNT = HEX("aa");
const GROUP = HEX("cc");
const MSG = HEX("11");

interface Calls {
  lookup: number;
  sendFinal: string[];
  sendFinalKeys: (string | undefined)[];
  publish: { name: string; displayName: string | null }[];
}

function emptyCalls(): Calls {
  return { lookup: 0, sendFinal: [], sendFinalKeys: [], publish: [] };
}

function stubClient(
  calls: Calls,
  opts: {
    failPublish?: boolean;
    failSend?: boolean;
    profileStatus?: "profile_found" | "profile_not_found" | "indeterminate";
  } = {},
): ProfileOnboardingClient {
  return {
    async accountLookupProfile() {
      calls.lookup += 1;
      return {
        type: "profile_lookup",
        status: opts.profileStatus ?? "profile_not_found",
        retryable: opts.profileStatus === "indeterminate",
      };
    },
    async sendFinal(_account, _group, text, _replyTo, idempotencyKey) {
      calls.sendFinal.push(text);
      calls.sendFinalKeys.push(idempotencyKey);
      if (opts.failSend) {
        throw new Error("send failed");
      }
      return { type: "final_sent" };
    },
    async accountPublishProfile(_account, name, displayName) {
      if (opts.failPublish) {
        throw new Error("publish failed");
      }
      calls.publish.push({ name, displayName: displayName ?? null });
      return { type: "profile_published" };
    },
  };
}

class MemStore implements ProfileOnboardingStateStore {
  rec: Partial<OnboardingRecord> = {};
  async get(): Promise<Partial<OnboardingRecord>> {
    return { ...this.rec };
  }
  async tryClaimPrompt(
    _account: string,
    groupIdHex: string,
    suggestedName: string | undefined,
  ): Promise<boolean> {
    if (this.rec.status) {
      return false;
    }
    this.rec = {
      status: "prompted",
      group_id_hex: groupIdHex,
      ...(suggestedName ? { suggested_name: suggestedName } : {}),
    };
    return true;
  }
  async markPublished(_account: string, name: string): Promise<void> {
    this.rec = { status: "published", name };
  }
  async markSkipped(): Promise<void> {
    this.rec = { status: "skipped" };
  }
  async markProfileExists(): Promise<void> {
    this.rec = { status: "profile_exists" };
  }
  async clear(): Promise<void> {
    this.rec = {};
  }
}

function msg(text: string, groupIdHex = GROUP) {
  return { accountIdHex: ACCOUNT, groupIdHex, messageIdHex: MSG, text };
}

describe("parseProfileNameReply", () => {
  it("treats empty as invalid", () => {
    expect(parseProfileNameReply("   ")).toEqual({ action: "invalid", response: PROFILE_NAME_EMPTY });
  });
  it("recognizes skip words", () => {
    for (const word of ["skip", "/skip", "no", "No Thanks", "CANCEL"]) {
      expect(parseProfileNameReply(word).action).toBe("skip");
    }
  });
  it("recognizes affirmative words", () => {
    for (const word of ["yes", "Y", "yeah", "sure", "OK", "publish it"]) {
      expect(parseProfileNameReply(word).action).toBe("affirm");
    }
  });
  it("strips one pair of surrounding quotes and collapses whitespace", () => {
    expect(parseProfileNameReply('  "Ada   Lovelace" ')).toMatchObject({
      action: "name",
      name: "Ada Lovelace",
    });
  });
  it("rejects names over the max length", () => {
    expect(parseProfileNameReply("x".repeat(MAX_PROFILE_NAME_CHARS + 1))).toEqual({
      action: "invalid",
      response: PROFILE_NAME_TOO_LONG,
    });
  });
  it("accepts a normal name", () => {
    expect(parseProfileNameReply("Ada")).toEqual({ action: "name", name: "Ada", response: "" });
  });
});

describe("buildProfilePrompt", () => {
  it("offers the configured name when present", () => {
    const prompt = buildProfilePrompt("Marmot Bot");
    expect(prompt).toContain('"Marmot Bot"');
    expect(prompt.toLowerCase()).toContain("yes");
  });
  it("asks for a name when none is configured", () => {
    expect(buildProfilePrompt(undefined)).toBe(PROFILE_PROMPT_NO_NAME);
  });
});

describe("maybeSendProfilePromptOnJoin", () => {
  it("persists profile_exists and stays quiet when kind-0 already exists", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    const client = stubClient(calls, { profileStatus: "profile_found" });

    await maybeSendProfilePromptOnJoin({
      store,
      client,
      accountIdHex: ACCOUNT,
      groupIdHex: GROUP,
      configuredName: "Marmot Bot",
    });
    await maybeSendProfilePromptOnJoin({
      store,
      client,
      accountIdHex: ACCOUNT,
      groupIdHex: HEX("dd"),
      configuredName: "Marmot Bot",
    });

    expect(calls.lookup).toBe(1);
    expect(calls.sendFinal).toEqual([]);
    expect(store.rec).toEqual({ status: "profile_exists" });
  });

  it("backs off an indeterminate lookup without prompting, then retries later", async () => {
    let now = 10_000;
    const gate = new ProfileLookupGate({ now: () => now, backoffMs: [1_000, 5_000] });
    const calls = emptyCalls();
    const store = new MemStore();
    const statuses = ["indeterminate", "profile_not_found"] as const;
    const client = stubClient(calls);
    client.accountLookupProfile = async () => {
      calls.lookup += 1;
      const status = statuses[Math.min(calls.lookup - 1, statuses.length - 1)]!;
      return { type: "profile_lookup", status, retryable: status === "indeterminate" };
    };

    const trigger = () =>
      maybeSendProfilePromptOnJoin({
        store,
        client,
        lookupGate: gate,
        accountIdHex: ACCOUNT,
        groupIdHex: GROUP,
      });
    await trigger();
    await trigger();
    expect(calls.lookup).toBe(1);
    expect(calls.sendFinal).toEqual([]);
    expect(store.rec).toEqual({});

    now += 1_000;
    await trigger();
    expect(calls.lookup).toBe(2);
    expect(calls.sendFinal).toEqual([PROFILE_PROMPT_NO_NAME]);
  });

  it("deduplicates concurrent account lookups and prompts once", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    let releaseLookup!: () => void;
    const lookupReleased = new Promise<void>((resolve) => {
      releaseLookup = resolve;
    });
    const client = stubClient(calls);
    client.accountLookupProfile = async () => {
      calls.lookup += 1;
      await lookupReleased;
      return { type: "profile_lookup", status: "profile_not_found", retryable: false };
    };

    const first = maybeSendProfilePromptOnJoin({
      store,
      client,
      accountIdHex: ACCOUNT,
      groupIdHex: GROUP,
    });
    const second = maybeSendProfilePromptOnJoin({
      store,
      client,
      accountIdHex: ACCOUNT,
      groupIdHex: HEX("dd"),
    });
    await Promise.resolve();
    releaseLookup();
    await Promise.all([first, second]);

    expect(calls.lookup).toBe(1);
    expect(calls.sendFinal).toHaveLength(1);
  });

  it("prompts with the configured name and records the suggestion", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    await maybeSendProfilePromptOnJoin({
      store,
      client: stubClient(calls),
      accountIdHex: ACCOUNT,
      groupIdHex: GROUP,
      configuredName: "Marmot Bot",
    });
    expect(calls.sendFinal).toEqual([buildProfilePrompt("Marmot Bot")]);
    expect(store.rec).toEqual({ status: "prompted", group_id_hex: GROUP, suggested_name: "Marmot Bot" });
  });

  it("prompts without a name when none is configured", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    await maybeSendProfilePromptOnJoin({
      store,
      client: stubClient(calls),
      accountIdHex: ACCOUNT,
      groupIdHex: GROUP,
      configuredName: null,
    });
    expect(calls.sendFinal).toEqual([PROFILE_PROMPT_NO_NAME]);
    expect(store.rec.status).toBe("prompted");
    expect(store.rec.suggested_name).toBeUndefined();
  });

  it("does nothing once a status exists (joining a second group)", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    store.rec = { status: "published", name: "Ada" };
    await maybeSendProfilePromptOnJoin({
      store,
      client: stubClient(calls),
      accountIdHex: ACCOUNT,
      groupIdHex: GROUP,
      configuredName: "Marmot Bot",
    });
    expect(calls.sendFinal).toEqual([]);
  });

  it("releases the prompt slot if the prompt fails to send", async () => {
    const store = new MemStore();
    await maybeSendProfilePromptOnJoin({
      store,
      client: stubClient(emptyCalls(), { failSend: true }),
      accountIdHex: ACCOUNT,
      groupIdHex: GROUP,
      configuredName: "Marmot Bot",
    });
    expect(store.rec).toEqual({}); // cleared so a later trigger retries
  });

  it("reuses the proactive prompt key after a failed send is retried", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    const trigger = () =>
      maybeSendProfilePromptOnJoin({
        store,
        client: stubClient(calls, { failSend: true }),
        accountIdHex: ACCOUNT,
        groupIdHex: GROUP,
        configuredName: "Marmot Bot",
      });

    await trigger();
    await trigger();

    expect(calls.sendFinal).toEqual([
      buildProfilePrompt("Marmot Bot"),
      buildProfilePrompt("Marmot Bot"),
    ]);
    expect(calls.sendFinalKeys[0]).toMatch(/^marmot-final-v1:[0-9a-f]{64}$/);
    expect(calls.sendFinalKeys[1]).toBe(calls.sendFinalKeys[0]);
  });
});

describe("maybeHandleProfileOnboardingInbound", () => {
  it("does not consume the triggering message when a profile already exists", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    const intercepted = await maybeHandleProfileOnboardingInbound({
      store,
      client: stubClient(calls, { profileStatus: "profile_found" }),
      message: msg("hello"),
    });

    expect(intercepted).toBe(false);
    expect(calls.lookup).toBe(1);
    expect(calls.sendFinal).toEqual([]);
    expect(store.rec).toEqual({ status: "profile_exists" });
  });

  it("does not consume the triggering message when profile lookup is indeterminate", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    const intercepted = await maybeHandleProfileOnboardingInbound({
      store,
      client: stubClient(calls, { profileStatus: "indeterminate" }),
      message: msg("hello"),
    });

    expect(intercepted).toBe(false);
    expect(calls.lookup).toBe(1);
    expect(calls.sendFinal).toEqual([]);
    expect(store.rec).toEqual({});
  });

  it("publishes the suggested name on an affirmative reply", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    store.rec = { status: "prompted", group_id_hex: GROUP, suggested_name: "Marmot Bot" };
    const intercepted = await maybeHandleProfileOnboardingInbound({
      store,
      client: stubClient(calls),
      message: msg("yes"),
    });
    expect(intercepted).toBe(true);
    expect(calls.publish).toEqual([{ name: "Marmot Bot", displayName: "Marmot Bot" }]);
    expect(calls.sendFinal).toEqual([PROFILE_NAME_PUBLISHED.replace("{name}", "Marmot Bot")]);
    expect(store.rec.status).toBe("published");
  });

  it("publishes a different name supplied in the reply", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    store.rec = { status: "prompted", group_id_hex: GROUP, suggested_name: "Marmot Bot" };
    await maybeHandleProfileOnboardingInbound({ store, client: stubClient(calls), message: msg("Ada") });
    expect(calls.publish).toEqual([{ name: "Ada", displayName: "Ada" }]);
    expect(store.rec).toMatchObject({ status: "published", name: "Ada" });
  });

  it("re-asks on an affirmative reply when there is no suggested name", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    store.rec = { status: "prompted", group_id_hex: GROUP };
    const intercepted = await maybeHandleProfileOnboardingInbound({
      store,
      client: stubClient(calls),
      message: msg("yes"),
    });
    expect(intercepted).toBe(true);
    expect(calls.publish).toEqual([]);
    expect(calls.sendFinal).toEqual([PROFILE_NAME_EMPTY]);
    expect(store.rec.status).toBe("prompted");
  });

  it("reuses the response key for an identical inbound replay and changes it for a new message", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    store.rec = { status: "prompted", group_id_hex: GROUP };
    const client = stubClient(calls);

    await maybeHandleProfileOnboardingInbound({ store, client, message: msg("yes") });
    await maybeHandleProfileOnboardingInbound({
      store,
      client,
      message: { ...msg("yes"), messageIdHex: `0x${MSG.toUpperCase()}` },
    });
    await maybeHandleProfileOnboardingInbound({
      store,
      client,
      message: { ...msg("yes"), messageIdHex: HEX("22") },
    });

    expect(calls.sendFinal).toEqual([PROFILE_NAME_EMPTY, PROFILE_NAME_EMPTY, PROFILE_NAME_EMPTY]);
    expect(calls.sendFinalKeys[0]).toMatch(/^marmot-final-v1:[0-9a-f]{64}$/);
    expect(calls.sendFinalKeys[1]).toBe(calls.sendFinalKeys[0]);
    expect(calls.sendFinalKeys[2]).not.toBe(calls.sendFinalKeys[0]);
  });

  it("skips on a skip reply", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    store.rec = { status: "prompted", group_id_hex: GROUP, suggested_name: "Marmot Bot" };
    await maybeHandleProfileOnboardingInbound({ store, client: stubClient(calls), message: msg("skip") });
    expect(store.rec.status).toBe("skipped");
    expect(calls.sendFinal).toEqual([PROFILE_NAME_SKIPPED]);
    expect(calls.publish).toEqual([]);
  });

  it("stays prompted and reports failure when publish throws", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    store.rec = { status: "prompted", group_id_hex: GROUP, suggested_name: "Marmot Bot" };
    await maybeHandleProfileOnboardingInbound({
      store,
      client: stubClient(calls, { failPublish: true }),
      message: msg("yes"),
    });
    expect(calls.sendFinal).toEqual([PROFILE_NAME_PUBLISH_FAILED]);
    expect(store.rec.status).toBe("prompted");
  });

  it("falls back to prompting on a first message when no status exists", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    const intercepted = await maybeHandleProfileOnboardingInbound({
      store,
      client: stubClient(calls),
      message: msg("hi"),
      configuredName: "Marmot Bot",
    });
    expect(intercepted).toBe(true);
    expect(calls.publish).toEqual([]);
    expect(calls.sendFinal).toEqual([buildProfilePrompt("Marmot Bot")]);
    expect(store.rec).toMatchObject({ status: "prompted", suggested_name: "Marmot Bot" });
  });

  it("does not intercept a reply that arrives in a different conversation", async () => {
    const calls = emptyCalls();
    const store = new MemStore();
    store.rec = { status: "prompted", group_id_hex: HEX("dd") };
    const intercepted = await maybeHandleProfileOnboardingInbound({
      store,
      client: stubClient(calls),
      message: msg("Ada"),
    });
    expect(intercepted).toBe(false);
    expect(calls.publish).toEqual([]);
  });

  it("does nothing once published or skipped", async () => {
    for (const status of ["profile_exists", "published", "skipped"] as const) {
      const calls = emptyCalls();
      const store = new MemStore();
      store.rec = { status };
      const intercepted = await maybeHandleProfileOnboardingInbound({
        store,
        client: stubClient(calls),
        message: msg("hello"),
        configuredName: "Marmot Bot",
      });
      expect(intercepted).toBe(false);
      expect(calls.publish).toEqual([]);
      expect(calls.sendFinal).toEqual([]);
    }
  });
});

describe("ProfileNameOnboardingStore", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "marmot-onboarding-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("claims the prompt slot atomically and persists transitions", async () => {
    const path = join(dir, "nested", "profile-onboarding.json");
    const store = new ProfileNameOnboardingStore(path);
    expect(await store.get(ACCOUNT)).toEqual({});

    expect(await store.tryClaimPrompt(ACCOUNT, GROUP, "Marmot Bot")).toBe(true);
    // a racing second claim is rejected
    expect(await store.tryClaimPrompt(ACCOUNT, GROUP, "Other")).toBe(false);
    expect(await store.get(ACCOUNT)).toEqual({
      status: "prompted",
      group_id_hex: GROUP,
      suggested_name: "Marmot Bot",
    });

    await store.markPublished(ACCOUNT, "Ada");
    const reopened = new ProfileNameOnboardingStore(path);
    expect(await reopened.get(ACCOUNT)).toEqual({ status: "published", name: "Ada" });

    await reopened.clear(ACCOUNT);
    await reopened.markProfileExists(ACCOUNT);
    const reopenedWithProfile = new ProfileNameOnboardingStore(path);
    expect(await reopenedWithProfile.get(ACCOUNT)).toEqual({ status: "profile_exists" });

    await reopenedWithProfile.clear(ACCOUNT);
    expect(await reopenedWithProfile.get(ACCOUNT)).toEqual({});
    // after clear, a fresh claim succeeds again
    expect(await reopenedWithProfile.tryClaimPrompt(ACCOUNT, GROUP, undefined)).toBe(true);
  });
});
