import type {
  OpenClawPluginApi,
  OpenClawPluginToolContext,
} from "openclaw/plugin-sdk/core";

import { resolveSingleAccount } from "./account.js";
import { resolveMarmotChannelAccount } from "./channel.js";
import { clientForAccount } from "./config.js";

type HistoryToolArgs = {
  group_id_hex?: string;
  message_id_hex?: string;
  before_recorded_at?: number;
  before_message_id_hex?: string;
  limit?: number;
};

function textResult(details: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(details) }],
    details,
  };
}

export function createMarmotHistoryTool(
  ctx: OpenClawPluginToolContext,
  fallbackConfig: unknown,
) {
  const cfg =
    ctx.getRuntimeConfig?.() ??
    ctx.runtimeConfig ??
    ctx.config ??
    fallbackConfig;
  const deliveryAccountId =
    ctx.deliveryContext?.channel === "marmot"
      ? ctx.deliveryContext.accountId
      : undefined;
  const resolved = resolveMarmotChannelAccount(
    cfg as Parameters<typeof resolveMarmotChannelAccount>[0],
    deliveryAccountId ?? ctx.agentAccountId ?? null,
  );
  const client = clientForAccount(resolved);

  return {
    name: "marmot_history",
    label: "Marmot History",
    description:
      "Read authoritative Marmot conversation history with durable message ids. " +
      "Use message_id_hex for one message, or page older messages with a before cursor.",
    parameters: {
      type: "object",
      additionalProperties: false,
      properties: {
        group_id_hex: {
          type: "string",
          description: "Marmot group id hex from the current conversation metadata.",
        },
        message_id_hex: {
          type: "string",
          description: "Optional exact Marmot message id hex to fetch.",
        },
        before_recorded_at: {
          type: "number",
          description: "Optional timeline cursor Unix time for paging older messages.",
        },
        before_message_id_hex: {
          type: "string",
          description: "Message id paired with before_recorded_at.",
        },
        limit: {
          type: "number",
          minimum: 1,
          maximum: 50,
          description: "Maximum messages to return (default 20, maximum 50).",
        },
      },
      required: ["group_id_hex"],
    },
    async execute(_toolCallId: string, rawArgs: HistoryToolArgs) {
      const groupIdHex = String(rawArgs.group_id_hex ?? "").trim();
      if (!groupIdHex) {
        return textResult({ ok: false, error: "group_id_hex required" });
      }
      const accountIdHex =
        resolved.marmotAccountIdHex ?? (await resolveSingleAccount(client));
      const messageIdHex = String(rawArgs.message_id_hex ?? "").trim();
      if (messageIdHex) {
        const response = await client.timelineMessageGet(
          accountIdHex,
          groupIdHex,
          messageIdHex,
        );
        return textResult({ ok: true, ...response });
      }
      const beforeRecordedAt = rawArgs.before_recorded_at;
      const beforeMessageIdHex = String(
        rawArgs.before_message_id_hex ?? "",
      ).trim();
      if (
        (beforeRecordedAt === undefined) !==
        (beforeMessageIdHex.length === 0)
      ) {
        return textResult({
          ok: false,
          error:
            "before_recorded_at and before_message_id_hex must be supplied together",
        });
      }
      const response = await client.timelineList(accountIdHex, groupIdHex, {
        ...(beforeRecordedAt !== undefined
          ? {
              before: {
                recorded_at: beforeRecordedAt,
                message_id_hex: beforeMessageIdHex,
              },
            }
          : {}),
        limit: rawArgs.limit,
      });
      return textResult({ ok: true, ...response });
    },
  };
}

export function registerMarmotHistoryTool(api: OpenClawPluginApi): void {
  api.registerTool(
    (ctx) => createMarmotHistoryTool(ctx, api.config) as never,
    { name: "marmot_history" },
  );
}
