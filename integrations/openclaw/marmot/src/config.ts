// Channel config schema + resolution. Mirrors the Hermes plugin's env knobs so
// the same dm-agent deployment serves both gateways. Config can come from the
// OpenClaw channel config block or from MARMOT_* environment variables.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";

import { buildJsonChannelConfigSchema } from "openclaw/plugin-sdk/channel-config-schema";

import { MarmotAgentControlClient } from "./client.js";

export const DEFAULT_MARMOT_HOME = "~/.marmot";

/** OpenClaw preview-streaming mode (we map any non-"off" mode onto QUIC previews). */
export type StreamMode = "off" | "partial" | "block" | "progress";

/**
 * When the agent replies in a group. `mention` (default): only when addressed
 * (the agent is `p`-tagged, a configured trigger matches, or the conversation is
 * an effective DM — exactly two members). `always`: every message (the prior
 * behavior). Effective DMs always get a reply regardless of this setting.
 */
export type GroupActivation = "mention" | "always";

/** The subset of OpenClaw's `channels.<id>.streaming` object we read. */
export interface MarmotStreamingConfig {
  mode?: StreamMode;
  block?: { enabled?: boolean };
}

/** Per-account channel config (also the shape validated by the manifest schema). */
export interface MarmotChannelAccountConfig {
  home?: string;
  socketPath?: string;
  accountIdHex?: string;
  authToken?: string;
  authTokenFile?: string;
  groupIdHex?: string;
  quicCandidates?: string[] | string;
  streaming?: MarmotStreamingConfig | boolean;
  blockStreaming?: boolean;
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
}

/** Fully-resolved Marmot connection + policy for one OpenClaw account. */
export interface ResolvedMarmotAccount {
  accountId?: string | null;
  socketPath: string;
  authToken?: string;
  marmotAccountIdHex?: string;
  groupIdHex?: string;
  quicCandidates: string[];
  streamMode: StreamMode;
  blockStreaming: boolean;
  debounceMs: number;
  groupActivation: GroupActivation;
  mentionPatterns: string[];
  profileNameOnboarding: boolean;
  profileOnboardingStatePath: string;
  dmPolicy?: string;
  allowFrom: Array<string | number>;
}

export interface ResolveDeps {
  env?: Record<string, string | undefined>;
  homeDir?: () => string;
  readTextFile?: (path: string) => string;
}

/** Per-account config properties (shared by the root slice and `accounts.<id>`). */
const MARMOT_ACCOUNT_PROPERTIES = {
  home: { type: "string", description: "dm-agent home directory (default ~/.marmot)." },
  socketPath: { type: "string", description: "dm-agent control socket path." },
  accountIdHex: {
    type: "string",
    description: "Marmot agent account id hex; required when dm-agent has more than one account.",
  },
  authToken: { type: "string", description: "Bearer token for a token-gated control socket." },
  authTokenFile: { type: "string", description: "Path to a bearer token file." },
  groupIdHex: { type: "string", description: "Optional inbound Marmot group id filter." },
  quicCandidates: {
    type: "array",
    items: { type: "string" },
    description: "quic:// preview broker candidates for live previews.",
  },
  streaming: {
    type: ["object", "boolean"],
    description:
      "Live QUIC preview streaming: { mode: off|partial|block|progress }. 'block' is the default; 'partial'/'progress' are handled best-effort with transcript-backed final recovery. Boolean accepted for legacy on/off.",
  },
  blockStreaming: {
    type: "boolean",
    description:
      "Enable OpenClaw completed-block delivery into Marmot's live preview sink. Defaults on when QUIC candidates are configured and Marmot streaming is not off.",
  },
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

/**
 * Resolve QUIC preview broker candidates with the same semantics as the Hermes
 * resolver (`resolve_quic_candidates` in integrations/hermes/marmot/adapter.py):
 * channel config wins; otherwise fall back to env, preferring plural
 * `MARMOT_QUIC_CANDIDATES` then singular `MARMOT_QUIC_CANDIDATE`. Candidates are
 * filtered to the `quic://` scheme so a malformed entry never reaches the
 * connector (which would reject it).
 */
function resolveQuicCandidates(
  cfg: MarmotChannelAccountConfig,
  env: Record<string, string | undefined>,
): string[] {
  const configured =
    cfg.quicCandidates ?? firstNonEmpty(env.MARMOT_QUIC_CANDIDATES, env.MARMOT_QUIC_CANDIDATE);
  return splitCandidates(configured).filter((candidate) => candidate.startsWith("quic://"));
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

function normalizeStreamMode(value: string | undefined): StreamMode | undefined {
  const v = String(value ?? "").trim().toLowerCase();
  return v === "off" || v === "partial" || v === "block" || v === "progress" ? v : undefined;
}

/**
 * Resolve the preview-streaming mode. OpenClaw drives previews through the
 * channel's reply `deliver` callback, gated on this mode (see src/dispatch.ts);
 * any non-"off" mode runs the QUIC preview. `block` is the natural default for
 * Marmot's append-only preview stream. `partial`/`progress` can deliver windowed
 * OpenClaw preview text, so the reply sink recovers the complete durable answer
 * from the fresh OpenClaw session transcript before committing. A boolean is
 * accepted for the legacy on/off knob. Defaults to `block` so previews fire
 * wherever QUIC candidates and block streaming are configured.
 */
function resolveStreamMode(
  streaming: MarmotStreamingConfig | boolean | undefined,
  envMode: string | undefined,
): StreamMode {
  const fromEnv = normalizeStreamMode(envMode);
  if (fromEnv) {
    return fromEnv;
  }
  if (typeof streaming === "boolean") {
    return streaming ? "block" : "off";
  }
  if (streaming && typeof streaming === "object") {
    return normalizeStreamMode(streaming.mode) ?? "block";
  }
  return "block";
}

function resolveBlockStreaming(
  cfg: MarmotChannelAccountConfig,
  env: Record<string, string | undefined>,
  streamMode: StreamMode,
  quicCandidates: string[],
): boolean {
  const fromEnv = parseBoolEnv(env.MARMOT_BLOCK_STREAMING);
  if (fromEnv !== undefined) {
    return fromEnv;
  }
  if (typeof cfg.blockStreaming === "boolean") {
    return cfg.blockStreaming;
  }
  if (typeof cfg.streaming === "object" && typeof cfg.streaming.block?.enabled === "boolean") {
    return cfg.streaming.block.enabled;
  }
  return streamMode !== "off" && quicCandidates.length > 0;
}

/**
 * Resolve the dm-agent connection + policy for an OpenClaw account, layering
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
    firstNonEmpty(cfg.socketPath, env.MARMOT_AGENT_SOCKET) ?? `${marmotHome}/dev/dm-agent.sock`,
    home,
  );

  let authToken = firstNonEmpty(cfg.authToken, env.MARMOT_AGENT_AUTH_TOKEN);
  if (authToken === undefined) {
    const tokenFile = firstNonEmpty(cfg.authTokenFile, env.MARMOT_AGENT_AUTH_TOKEN_FILE);
    if (tokenFile !== undefined) {
      authToken = readTextFile(expandHome(tokenFile, home)).trim();
    }
  }

  const quicCandidates = resolveQuicCandidates(cfg, env);

  const profileOnboardingStatePath = expandHome(
    firstNonEmpty(env.MARMOT_PROFILE_ONBOARDING_STATE) ??
      `${marmotHome}/dev/profile-onboarding.json`,
    home,
  );

  const streamMode = resolveStreamMode(cfg.streaming, env.MARMOT_STREAM_MODE);
  const blockStreaming = resolveBlockStreaming(cfg, env, streamMode, quicCandidates);
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
    quicCandidates,
    streamMode,
    blockStreaming,
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
  };
}

/** Construct a control client for a resolved account. */
export function clientForAccount(resolved: ResolvedMarmotAccount): MarmotAgentControlClient {
  return new MarmotAgentControlClient({
    socketPath: resolved.socketPath,
    authToken: resolved.authToken,
  });
}
