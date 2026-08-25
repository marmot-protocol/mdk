import { describe, expect, it } from "vitest";
import type { ChannelMessageSendTextContext } from "openclaw/plugin-sdk/channel-outbound";

import type { MarmotAgentControlClient } from "../src/client.js";
import { createMarmotMessageAdapter } from "../src/outbound.js";
import {
  maybeHandleProfileOnboardingInbound,
  maybeSendProfilePromptOnJoin,
  type OnboardingRecord,
  type ProfileOnboardingClient,
  type ProfileOnboardingStateStore,
} from "../src/profile-onboarding.js";
import { DeduplicatingFinalConnector } from "./deduplicating-final-connector.js";

const HEX32 = (byte: string) => byte.repeat(32);
const ACCOUNT = HEX32("aa");
const GROUP = HEX32("cc");
const FIRST_REPLY = HEX32("dd");
const SECOND_REPLY = HEX32("ee");

class MemoryOnboardingStore implements ProfileOnboardingStateStore {
  record: Partial<OnboardingRecord> = {};

  async get(): Promise<Partial<OnboardingRecord>> {
    return { ...this.record };
  }

  async tryClaimPrompt(
    _accountIdHex: string,
    groupIdHex: string,
    suggestedName: string | undefined,
  ): Promise<boolean> {
    if (this.record.status) return false;
    this.record = {
      status: "prompted",
      group_id_hex: groupIdHex,
      ...(suggestedName ? { suggested_name: suggestedName } : {}),
    };
    return true;
  }

  async markPublished(_accountIdHex: string, name: string): Promise<void> {
    this.record = { status: "published", name };
  }

  async markSkipped(): Promise<void> {
    this.record = { status: "skipped" };
  }

  async markProfileExists(): Promise<void> {
    this.record = { status: "profile_exists" };
  }

  async clear(): Promise<void> {
    this.record = {};
  }
}

describe("retry after ambiguous send_final success", () => {
  it("deduplicates equivalent prefixed and unprefixed hexadecimal ids", async () => {
    const connector = new DeduplicatingFinalConnector();
    const idempotencyKey = "stable-key";

    const first = await connector.sendFinal(
      `0x${ACCOUNT.toUpperCase()}`,
      `0x${GROUP.toUpperCase()}`,
      "same durable result",
      `0x${FIRST_REPLY.toUpperCase()}`,
      idempotencyKey,
    );
    const second = await connector.sendFinal(
      ACCOUNT,
      GROUP,
      "same durable result",
      FIRST_REPLY,
      idempotencyKey,
    );

    expect(second).toEqual(first);
    expect(connector.encryptedKind9Posts).toHaveLength(1);
  });

  it("reuses the outbound key so connector dedup publishes one encrypted kind-9", async () => {
    const connector = new DeduplicatingFinalConnector();
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({
        client: connector as unknown as MarmotAgentControlClient,
        marmotAccountIdHex: ACCOUNT,
      }),
    });
    const ctx = {
      cfg: {},
      to: GROUP,
      text: "durable result",
      replyToId: FIRST_REPLY,
      deliveryQueueId: "ambiguous-turn:0",
    } as unknown as ChannelMessageSendTextContext;

    connector.armPostSuccessDisconnect();
    await expect(adapter.send!.text!(ctx)).rejects.toMatchObject({
      code: "connection_closed",
      retryable: true,
    });
    const retried = await adapter.send!.text!(ctx);

    expect(connector.encryptedKind9Posts).toHaveLength(1);
    expect(retried.receipt.platformMessageIds).toEqual(
      connector.encryptedKind9Posts[0]?.messageIdsHex,
    );

    await adapter.send!.text!({ ...ctx, text: "different durable result" });
    await adapter.send!.text!({ ...ctx, replyToId: SECOND_REPLY });

    expect(connector.encryptedKind9Posts).toHaveLength(3);
    expect(new Set(connector.encryptedKind9Posts.map((post) => post.idempotencyKey)).size).toBe(3);
    expect(connector.encryptedKind9Posts.map((post) => [post.text, post.replyToMessageIdHex])).toEqual([
      ["durable result", FIRST_REPLY],
      ["different durable result", FIRST_REPLY],
      ["durable result", SECOND_REPLY],
    ]);
  });

  it("reuses onboarding prompt and reply keys but separates a new reply anchor", async () => {
    const connector = new DeduplicatingFinalConnector();
    const store = new MemoryOnboardingStore();
    const client: ProfileOnboardingClient = {
      accountLookupProfile: async () => ({
        type: "profile_lookup",
        status: "profile_not_found",
        retryable: false,
      }),
      sendFinal: connector.sendFinal.bind(connector),
      accountPublishProfile: async () => ({ type: "profile_published" }),
    };
    const triggerPrompt = (configuredName: string | null = null) =>
      maybeSendProfilePromptOnJoin({
        store,
        client,
        accountIdHex: ACCOUNT,
        groupIdHex: GROUP,
        configuredName,
      });

    connector.armPostSuccessDisconnect();
    expect(await triggerPrompt("Original Name")).toBe(false);
    expect(await triggerPrompt("Changed Name")).toBe(true);
    expect(connector.encryptedKind9Posts).toHaveLength(1);
    expect(connector.encryptedKind9Posts[0]?.text).toContain('"Original Name"');
    expect(connector.encryptedKind9Posts[0]?.text).not.toContain('"Changed Name"');

    const firstReply = {
      accountIdHex: ACCOUNT,
      groupIdHex: GROUP,
      messageIdHex: FIRST_REPLY,
      text: "yes",
    };
    connector.armPostSuccessDisconnect();
    expect(
      await maybeHandleProfileOnboardingInbound({ store, client, message: firstReply }),
    ).toBe(true);
    expect(connector.encryptedKind9Posts).toHaveLength(2);
    expect(connector.encryptedKind9Posts[1]?.replyToMessageIdHex).toBe(FIRST_REPLY);

    expect(
      await maybeHandleProfileOnboardingInbound({
        store,
        client,
        message: { ...firstReply, messageIdHex: SECOND_REPLY },
      }),
    ).toBe(false);
    expect(connector.encryptedKind9Posts).toHaveLength(2);
  });
});
