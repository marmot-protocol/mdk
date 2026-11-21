// Channel config schema + resolution. Mirrors the Hermes plugin's env knobs so
// the same wn-agent deployment serves both gateways. Config can come from the
// OpenClaw channel config block or from MARMOT_* environment variables.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";

import { buildJsonChannelConfigSchema } from "openclaw/plugin-sdk/channel-config-schema";

import { MarmotAgentControlClient } from "./client.js";
import {
  resolveSenderPolicy,
  type SenderPolicyResolution,
} from "./sender-policy.js";

export const DEFAULT_MARMOT_HOME = "~/.marmot";

/**
 * When the agent replies in a group. `mention` (default): only when addressed
 * (the agent is `p`-tagged, a configured trigger matches, or the conversation is
 * an effective DM — exactly two members). `always`: every message (the prior
 * behavior). Effective DMs always get a reply regardless of this setting.
 */
export type GroupActivation = "mention" | "always";

/** Per-account channel config (also the shape validated by the manifest schema). */
export interface MarmotChannelAccountConfig {
  home?: string;
  socketPath?: string;
  accountIdHex?: string;
  authToken?: string;
  authTokenFile?: string;
  groupIdHex?: string;
  /** Coalesce rapid same-sender/group inbound messages within this window into one turn (ms). 0 = off. */
  debounceMs?: number;
  /** When to reply in a multi-party group: "mention" (default) or "always". */
  groupActivation?: GroupActivation;
  /** Extra case-insensitive trigger phrases that count as addressing the agent. */
  mentionPatterns?: string[] | string;
  profileNameOnboarding?: boolean;
  dm?: {
    enabled?: boolean;
    policy?: string;
    allowFrom?: Array<string | number>;
  };
  /**
   * Account-global inbound sender ACL. Distinct from `dm.allowFrom`, which
   * only reconciles wn-agent welcomers. Presence of this property replaces the
   * `MARMOT_ALLOWED_USERS` / `MARMOT_ALLOW_ALL_USERS` environment fallback.
   */
  senderPolicy?: {
    allowedUsers?: string[];
    allowAll?: boolean;
  };
}

/** Fully-resolved Marmot connection + policy for one OpenClaw account. */
export interface ResolvedMarmotAccount {
  accountId?: string | null;
  socketPath: string;
  authToken?: string;
  marmotAccountIdHex?: string;
  groupIdHex?: string;
  debounceMs: number;
  groupActivation: GroupActivation;
  mentionPatterns: string[];
  profileNameOnboarding: boolean;
  profileOnboardingStatePath: string;
  dmPolicy?: string;
  allowFrom: Array<string | number>;
  senderPolicy: SenderPolicyResolution;
}

export interface ResolveDeps {
  env?: Record<string, string | undefined>;
  homeDir?: () => string;
  readTextFile?: (path: string) => string;
}

/** Per-account config properties (shared by the root slice and `accounts.<id>`). */
const MARMOT_ACCOUNT_PROPERTIES = {
  home: { type: "string", description: "wn-agent home directory (default ~/.marmot)." },
  socketPath: { type: "string", description: "wn-agent control socket path." },
  accountIdHex: {
    type: "string",
    description: "Marmot agent account id hex; required when wn-agent has more than one account.",
  },
  authToken: { type: "string", description: "Bearer token for a token-gated control socket." },
  authTokenFile: { type: "string", description: "Path to a bearer token file." },
  groupIdHex: { type: "string", description: "Optional inbound Marmot group id filter." },
  // Live QUIC previews were removed. Earlier installers wrote these keys and the
  // schema rejects unknown keys, so they stay accepted and are ignored.
  quicCandidates: {
    type: "array",
    items: { type: "string" },
    description: "Ignored; live previews were removed.",
  },
  streaming: { type: ["object", "boolean"], description: "Ignored; live previews were removed." },
  blockStreaming: { type: "boolean", description: "Ignored; live previews were removed." },
  debounceMs: {
    type: "number",
    description:
      "Coalesce rapid same-sender/group inbound messages within this window (ms) into a single agent turn. 0 disables (default).",
  },
  groupActivation: {
    type: "string",
    enum: ["mention", "always"],
    description:
      "When to reply in a multi-party group: 'mention' (only when addressed; default) or 'always'. Effective DMs (two members) always reply.",
  },
  mentionPatterns: {
    type: "array",
    items: { type: "string" },
    description: "Extra case-insensitive phrases that count as addressing the agent.",
  },
  profileNameOnboarding: { type: "boolean" },
  dm: {
    type: "object",
    additionalProperties: false,
    properties: {
      enabled: { type: "boolean" },
      policy: { type: "string", enum: ["open", "allowlist", "pairing", "disabled"] },
      allowFrom: { type: "array", items: { type: ["string", "number"] } },
    },
  },
  senderPolicy: {
    type: "object",
    additionalProperties: false,
    description:
      "Account-global inbound sender ACL. Distinct from dm.allowFrom welcomer admission. Raw 64-character Marmot account hex only.",
    properties: {
      allowedUsers: {
        type: "array",
        items: { type: "string" },
        description: "Exact 64-character Marmot account hex ids allowed to invoke the agent.",
      },
      allowAll: {
        type: "boolean",
        description: "Explicit opt-in to accept any authenticated non-self sender.",
      },
    },
  },
};

/** JSON Schema for the marmot channel config (used for the plugin manifest too). */
export const MARMOT_CONFIG_JSON_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    ...MARMOT_ACCOUNT_PROPERTIES,
    accounts: {
      type: "object",
      description: "Per-account configs for multi-account mode, keyed by account id.",
      additionalProperties: {
        type: "object",
        additionalProperties: false,
        properties: MARMOT_ACCOUNT_PROPERTIES,
      },
    },
  },
};

/** Build the OpenClaw channel config schema from the shared JSON Schema. */
export function marmotChannelConfigSchema(): ReturnType<typeof buildJsonChannelConfigSchema> {
  return buildJsonChannelConfigSchema(
    MARMOT_CONFIG_JSON_SCHEMA as unknown as Parameters<typeof buildJsonChannelConfigSchema>[0],
  );
}

function expandHome(path: string, home: string): string {
  if (path === "~") {
    return home;
  }
  if (path.startsWith("~/")) {
    return `${home}/${path.slice(2)}`;
  }
  return path;
}

function splitCandidates(value: string[] | string | undefined): string[] {
  if (value === undefined) {
    return [];
  }
  const parts = Array.isArray(value) ? value : value.split(",");
  return parts.map((part) => String(part).trim()).filter((part) => part.length > 0);
}

function firstNonEmpty(...values: Array<string | undefined>): string | undefined {
  for (const value of values) {
    if (value !== undefined && String(value).trim() !== "") {
      return String(value).trim();
    }
  }
  return undefined;
}

function parseBoolEnv(value: string | undefined): boolean | undefined {
  if (value === undefined) {
    return undefined;
  }
  const v = value.trim().toLowerCase();
  if (v === "") {
    return undefined;
  }
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

/** Parse a non-negative integer from config (number) or env (string); undefined if absent/invalid. */
function resolveNonNegInt(
  configValue: number | undefined,
  envValue: string | undefined,
): number | undefined {
  if (typeof configValue === "number" && Number.isFinite(configValue) && configValue >= 0) {
    return Math.floor(configValue);
  }
  if (envValue !== undefined && envValue.trim() !== "") {
    const parsed = Number(envValue.trim());
    if (Number.isFinite(parsed) && parsed >= 0) {
      return Math.floor(parsed);
    }
  }
  return undefined;
}

function normalizeGroupActivation(value: string | undefined): GroupActivation {
  return String(value ?? "").trim().toLowerCase() === "always" ? "always" : "mention";
}

/**
 * Resolve the wn-agent connection + policy for an OpenClaw account, layering
 * channel config over MARMOT_* environment variables (config wins).
 */
export function resolveMarmotAccount(
  config: MarmotChannelAccountConfig | undefined,
  accountId: string | null | undefined,
  deps: ResolveDeps = {},
): ResolvedMarmotAccount {
  const cfg = config ?? {};
  const env = deps.env ?? process.env;
  const home = (deps.homeDir ?? homedir)();
  const readTextFile = deps.readTextFile ?? ((path: string) => readFileSync(path, "utf8"));

  const marmotHome = expandHome(
    firstNonEmpty(cfg.home, env.MARMOT_HOME) ?? DEFAULT_MARMOT_HOME,
    home,
  );
  const socketPath = expandHome(
    firstNonEmpty(cfg.socketPath, env.MARMOT_AGENT_SOCKET) ?? `${marmotHome}/dev/wn-agent.sock`,
    home,
  );

  let authToken = firstNonEmpty(cfg.authToken, env.MARMOT_AGENT_AUTH_TOKEN);
  if (authToken === undefined) {
    const tokenFile = firstNonEmpty(cfg.authTokenFile, env.MARMOT_AGENT_AUTH_TOKEN_FILE);
    if (tokenFile !== undefined) {
      authToken = readTextFile(expandHome(tokenFile, home)).trim();
    }
  }

  const profileOnboardingStatePath = expandHome(
    firstNonEmpty(env.MARMOT_PROFILE_ONBOARDING_STATE) ??
      `${marmotHome}/dev/profile-onboarding.json`,
    home,
  );

  const debounceMs = resolveNonNegInt(cfg.debounceMs, env.MARMOT_DEBOUNCE_MS) ?? 0;
  const groupActivation = normalizeGroupActivation(
    firstNonEmpty(cfg.groupActivation, env.MARMOT_GROUP_ACTIVATION),
  );
  const mentionPatterns = splitCandidates(cfg.mentionPatterns ?? env.MARMOT_MENTION_PATTERNS);

  return {
    accountId: accountId ?? null,
    socketPath,
    authToken: authToken && authToken.trim() ? authToken.trim() : undefined,
    marmotAccountIdHex: firstNonEmpty(cfg.accountIdHex, env.MARMOT_ACCOUNT_ID_HEX),
    groupIdHex: firstNonEmpty(cfg.groupIdHex, env.MARMOT_GROUP_ID_HEX),
    debounceMs,
    groupActivation,
    mentionPatterns,
    // On by default: the agent always offers to publish a profile on join; the
    // user's in-chat choice is the consent. Operators can disable it explicitly.
    profileNameOnboarding:
      cfg.profileNameOnboarding ?? parseBoolEnv(env.MARMOT_PROFILE_NAME_ONBOARDING) ?? true,
    profileOnboardingStatePath,
    dmPolicy: cfg.dm?.policy,
    allowFrom: cfg.dm?.allowFrom ?? [],
    senderPolicy: resolveSenderPolicy(cfg, env),
  };
}

/** Construct a control client for a resolved account. */
export function clientForAccount(resolved: ResolvedMarmotAccount): MarmotAgentControlClient {
  return new MarmotAgentControlClient({
    socketPath: resolved.socketPath,
    authToken: resolved.authToken,
  });
}
