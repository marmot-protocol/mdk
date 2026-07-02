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
  sendFinal: string[];
  publish: { name: string; displayName: string | null }[];
}

function emptyCalls(): Calls {
  return { sendFinal: [], publish: [] };
}

function stubClient(
  calls: Calls,
  opts: { failPublish?: boolean; failSend?: boolean } = {},
): ProfileOnboardingClient {
  return {
    async sendFinal(_account, _group, text) {
      if (opts.failSend) {
        throw new Error("send failed");
      }
      calls.sendFinal.push(text);
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
});

describe("maybeHandleProfileOnboardingInbound", () => {
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
    for (const status of ["published", "skipped"] as const) {
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
    expect(await reopened.get(ACCOUNT)).toEqual({});
    // after clear, a fresh claim succeeds again
    expect(await reopened.tryClaimPrompt(ACCOUNT, GROUP, undefined)).toBe(true);
  });
});
