import type { OpenClawPluginApi, OpenClawPluginToolContext } from "openclaw/plugin-sdk/core";
import { resolveSingleAccount } from "./account.js";
import { resolveMarmotChannelAccount } from "./channel.js";
import { AgentControlError } from "./client.js";
import { clientForAccount } from "./config.js";

type ProfileArgs = { group_id_hex?: string; name?: string; description?: string };

function textResult(details: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(details) }], details };
}

export function createMarmotGroupProfileTool(ctx: OpenClawPluginToolContext, fallbackConfig: unknown) {
  return {
    name: "marmot_group_profile",
    label: "Marmot Group Profile",
    description: "Update a Marmot group's name, description, or both when the selected account is a current group admin. " +
      "Omitted fields keep their values; an empty string clears a field. An unknown outcome may already have committed: inspect current group details before retrying.",
    parameters: {
      type: "object", additionalProperties: false,
      properties: {
        group_id_hex: { type: "string", description: "Marmot group id from conversation metadata." },
        name: { type: "string", description: "Optional new name, at most 256 UTF-8 bytes; empty string clears." },
        description: { type: "string", description: "Optional description, at most 4096 UTF-8 bytes; empty string clears." },
      },
      required: ["group_id_hex"],
    },
    async execute(_toolCallId: string, args: ProfileArgs) {
      if (typeof args.group_id_hex !== "string" || !/^(?:[0-9a-fA-F]{2})+$/.test(args.group_id_hex) ||
          (args.name === undefined && args.description === undefined) ||
          (args.name !== undefined && (typeof args.name !== "string" || Buffer.byteLength(args.name, "utf8") > 256)) ||
          (args.description !== undefined && (typeof args.description !== "string" || Buffer.byteLength(args.description, "utf8") > 4096))) {
        return textResult({ ok: false, error: "invalid_group_profile_input" });
      }
      // Resolve each call against current host config and the inbound delivery account.
      const cfg = ctx.getRuntimeConfig?.() ?? ctx.runtimeConfig ?? ctx.config ?? fallbackConfig;
      const deliveryAccountId = ctx.deliveryContext?.channel === "marmot" ? ctx.deliveryContext.accountId : undefined;
      let client;
      let accountIdHex: string;
      try {
        const resolved = resolveMarmotChannelAccount(cfg as Parameters<typeof resolveMarmotChannelAccount>[0], deliveryAccountId ?? ctx.agentAccountId ?? null);
        client = clientForAccount(resolved);
        accountIdHex = resolved.marmotAccountIdHex ?? await resolveSingleAccount(client);
      } catch {
        return textResult({ ok: false, error: "group_profile_configuration_invalid" });
      }
      try {
        const response = await client.groupProfileUpdate(accountIdHex, args.group_id_hex, {
          ...(args.name !== undefined ? { name: args.name } : {}),
          ...(args.description !== undefined ? { description: args.description } : {}),
        });
        return textResult({ ok: true, ...response });
      } catch (error) {
        if (error instanceof AgentControlError && !error.retryable &&
            ["not_group_admin", "invalid_group_profile", "unauthorized", "invalid_hex"].includes(error.code)) {
          return textResult({ ok: false, error: error.code, outcome: "rejected", retryable: false,
            control_retryable: error.retryable });
        }
        return textResult({ ok: false, error: "group_profile_outcome_unknown", outcome: "unknown", retryable: false,
          ...(error instanceof AgentControlError ? { control_error: error.code, control_retryable: error.retryable } : {}),
          hint: "Check the current group details before retrying; the update may have committed." });
      }
    },
  };
}

export function registerMarmotGroupProfileTool(api: OpenClawPluginApi): void {
  api.registerTool((ctx) => createMarmotGroupProfileTool(ctx, api.config) as never, { name: "marmot_group_profile" });
}
