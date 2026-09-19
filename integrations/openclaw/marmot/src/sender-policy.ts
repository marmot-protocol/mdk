// Account-global inbound sender ACL. Distinct from `dm.allowFrom` welcomer
// reconciliation: this decides whether an authenticated Marmot sender may
// invoke the OpenClaw agent. Parsing is strict and fail-closed.

export const MARMOT_ACCOUNT_ID_HEX = /^[0-9a-fA-F]{64}$/;
export const MARMOT_SENDER_POLICY_MISSING = "marmot_sender_policy_missing";
export const MARMOT_SENDER_POLICY_INVALID = "marmot_sender_policy_invalid";

const ENV_ALLOWED_USERS = "MARMOT_ALLOWED_USERS";
const ENV_ALLOW_ALL = "MARMOT_ALLOW_ALL_USERS";
const TRUE_FLAGS = new Set(["true", "1", "yes", "on"]);
const FALSE_FLAGS = new Set(["false", "0", "no", "off"]);

export type SenderPolicyReadinessState =
  | "pending"
  | "missing"
  | "invalid"
  | "allowlist"
  | "allow_all";

export type SenderPolicyInvalidReason =
  | "wrong_type"
  | "unknown_field"
  | "invalid_entry"
  | "invalid_boolean";

export type SenderPolicyResolution =
  | { state: "missing"; allowedUserCount: 0 }
  | { state: "invalid"; reason: SenderPolicyInvalidReason; allowedUserCount: 0 }
  | { state: "allowlist"; allowedUsers: readonly string[]; allowedUserCount: number }
  | { state: "allow_all"; allowedUsers: readonly string[]; allowedUserCount: number };

export type SenderDenyReason =
  | "missing_authorizer"
  | "missing_policy"
  | "invalid_policy"
  | "sender_not_allowed"
  | "missing_actor"
  | "missing_self_flag"
  | "malformed_sender"
  | "inconsistent_sender"
  | "self_sender"
  | "self_id_equality"
  | "receiving_account_mismatch"
  | "lifecycle_pending"
  | "lifecycle_stopped"
  | "lifecycle_replaced"
  | "lifecycle_unbound"
  | "lifecycle_invalid";

export type SenderAuthorizationDecision =
  | { outcome: "allow"; reason: "allowlist" | "allow_all" }
  | { outcome: "deny"; reason: SenderDenyReason };

export type SenderAuthorizerLifecycle =
  | "pending"
  | "active"
  | "stopped"
  | "replaced"
  | "unbound"
  | "invalid";

export interface SenderAuthorizationInput {
  receivingAccountIdHex: unknown;
  mappedSenderAccountIdHex: unknown;
  sender?: {
    account_id_hex?: unknown;
    is_self?: unknown;
  } | null;
}

export interface MarmotSenderAuthorizer {
  readonly policy: SenderPolicyResolution;
  boundReceivingAccountIdHex(): string | null;
  lifecycle(): SenderAuthorizerLifecycle;
  bindReceivingAccount(accountIdHex: string): boolean;
  setLifecycle(next: SenderAuthorizerLifecycle): void;
  authorize(input: SenderAuthorizationInput): SenderAuthorizationDecision;
}

export interface SenderPolicyConfigSlice {
  senderPolicy?: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasOwnSenderPolicy(config: unknown): boolean {
  return isRecord(config) && Object.prototype.hasOwnProperty.call(config, "senderPolicy");
}

function uniqueLowerHex(ids: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const id of ids) {
    const lower = id.toLowerCase();
    if (seen.has(lower)) {
      continue;
    }
    seen.add(lower);
    out.push(lower);
  }
  return out;
}

function parsePolicyId(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (!MARMOT_ACCOUNT_ID_HEX.test(trimmed)) {
    return null;
  }
  return trimmed.toLowerCase();
}

function parseAllowedUsers(value: unknown): { ok: true; ids: string[] } | { ok: false } {
  if (value === undefined) {
    return { ok: true, ids: [] };
  }
  if (!Array.isArray(value)) {
    return { ok: false };
  }
  const ids: string[] = [];
  for (const entry of value) {
    const parsed = parsePolicyId(entry);
    if (parsed === null) {
      return { ok: false };
    }
    ids.push(parsed);
  }
  return { ok: true, ids: uniqueLowerHex(ids) };
}

function parseEnvBoolean(value: string | undefined): boolean | "invalid" | undefined {
  if (value === undefined) {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (normalized === "") {
    return "invalid";
  }
  if (TRUE_FLAGS.has(normalized)) {
    return true;
  }
  if (FALSE_FLAGS.has(normalized)) {
    return false;
  }
  return "invalid";
}

function finishPolicy(
  allowedUsers: readonly string[],
  allowAll: boolean,
): SenderPolicyResolution {
  if (allowAll) {
    return {
      state: "allow_all",
      allowedUsers,
      allowedUserCount: allowedUsers.length,
    };
  }
  if (allowedUsers.length === 0) {
    return { state: "missing", allowedUserCount: 0 };
  }
  return {
    state: "allowlist",
    allowedUsers,
    allowedUserCount: allowedUsers.length,
  };
}

export function parseConfigSenderPolicy(value: unknown): SenderPolicyResolution {
  if (value === undefined) {
    return { state: "missing", allowedUserCount: 0 };
  }
  if (!isRecord(value)) {
    return { state: "invalid", reason: "wrong_type", allowedUserCount: 0 };
  }
  const keys = Object.keys(value);
  for (const key of keys) {
    if (key !== "allowedUsers" && key !== "allowAll") {
      return { state: "invalid", reason: "unknown_field", allowedUserCount: 0 };
    }
  }
  if (value.allowAll !== undefined && typeof value.allowAll !== "boolean") {
    return { state: "invalid", reason: "invalid_boolean", allowedUserCount: 0 };
  }
  const allowed = parseAllowedUsers(value.allowedUsers);
  if (!allowed.ok) {
    return { state: "invalid", reason: "invalid_entry", allowedUserCount: 0 };
  }
  return finishPolicy(allowed.ids, value.allowAll === true);
}

export function parseEnvironmentSenderPolicy(
  env: Record<string, string | undefined>,
): SenderPolicyResolution {
  const allowedPresent = Object.prototype.hasOwnProperty.call(env, ENV_ALLOWED_USERS);
  const allowAllPresent = Object.prototype.hasOwnProperty.call(env, ENV_ALLOW_ALL);
  if (!allowedPresent && !allowAllPresent) {
    return { state: "missing", allowedUserCount: 0 };
  }
  const allowAll = parseEnvBoolean(allowAllPresent ? env[ENV_ALLOW_ALL] : undefined);
  if (allowAll === "invalid") {
    return { state: "invalid", reason: "invalid_boolean", allowedUserCount: 0 };
  }
  let ids: string[] = [];
  if (allowedPresent) {
    const raw = env[ENV_ALLOWED_USERS] ?? "";
    const parts = raw.split(",").map((part) => part.trim()).filter((part) => part.length > 0);
    const parsed = parseAllowedUsers(parts);
    if (!parsed.ok) {
      return { state: "invalid", reason: "invalid_entry", allowedUserCount: 0 };
    }
    ids = parsed.ids;
  }
  return finishPolicy(ids, allowAll === true);
}

/**
 * Resolve the selected account's sender policy. An explicit `senderPolicy`
 * property replaces the environment atomically; it never unions with env and
 * never falls through on invalid or empty config.
 */
export function resolveSenderPolicy(
  config: SenderPolicyConfigSlice | undefined,
  env: Record<string, string | undefined> = {},
): SenderPolicyResolution {
  if (hasOwnSenderPolicy(config)) {
    return parseConfigSenderPolicy(config!.senderPolicy);
  }
  return parseEnvironmentSenderPolicy(env);
}

export function senderPolicyErrorCode(
  state: SenderPolicyReadinessState | SenderPolicyResolution["state"],
): string | null {
  if (state === "missing") {
    return MARMOT_SENDER_POLICY_MISSING;
  }
  if (state === "invalid") {
    return MARMOT_SENDER_POLICY_INVALID;
  }
  return null;
}

export function senderPolicyIsReady(
  state: SenderPolicyReadinessState | SenderPolicyResolution["state"],
): boolean {
  return state === "allowlist" || state === "allow_all";
}

function envelopeAccountId(value: unknown): string | null {
  return typeof value === "string" && MARMOT_ACCOUNT_ID_HEX.test(value)
    ? value.toLowerCase()
    : null;
}

export function authorizeSenderIdentity(
  input: SenderAuthorizationInput,
  boundReceivingAccountIdHex: string | null,
): SenderAuthorizationDecision | { outcome: "identity"; senderId: string; receivingId: string } {
  if (input.sender === undefined || input.sender === null || !isRecord(input.sender)) {
    return { outcome: "deny", reason: "missing_actor" };
  }
  if (typeof input.sender.is_self !== "boolean") {
    return { outcome: "deny", reason: "missing_self_flag" };
  }
  const actorId = envelopeAccountId(input.sender.account_id_hex);
  if (actorId === null) {
    return { outcome: "deny", reason: "malformed_sender" };
  }
  const mappedId = envelopeAccountId(input.mappedSenderAccountIdHex);
  if (mappedId === null) {
    return { outcome: "deny", reason: "malformed_sender" };
  }
  if (actorId !== mappedId) {
    return { outcome: "deny", reason: "inconsistent_sender" };
  }
  if (input.sender.is_self === true) {
    return { outcome: "deny", reason: "self_sender" };
  }
  const receivingId = envelopeAccountId(input.receivingAccountIdHex);
  if (receivingId === null) {
    return { outcome: "deny", reason: "receiving_account_mismatch" };
  }
  if (boundReceivingAccountIdHex === null) {
    return { outcome: "deny", reason: "lifecycle_unbound" };
  }
  if (receivingId !== boundReceivingAccountIdHex) {
    return { outcome: "deny", reason: "receiving_account_mismatch" };
  }
  if (actorId === receivingId) {
    return { outcome: "deny", reason: "self_id_equality" };
  }
  return { outcome: "identity", senderId: actorId, receivingId };
}

function decisionForPolicy(
  policy: SenderPolicyResolution,
  senderId: string,
): SenderAuthorizationDecision {
  if (policy.state === "missing") {
    return { outcome: "deny", reason: "missing_policy" };
  }
  if (policy.state === "invalid") {
    return { outcome: "deny", reason: "invalid_policy" };
  }
  if (policy.state === "allow_all") {
    return { outcome: "allow", reason: "allow_all" };
  }
  return policy.allowedUsers.includes(senderId)
    ? { outcome: "allow", reason: "allowlist" }
    : { outcome: "deny", reason: "sender_not_allowed" };
}

function lifecycleDeny(lifecycle: SenderAuthorizerLifecycle): SenderDenyReason | null {
  switch (lifecycle) {
    case "active":
      return null;
    case "pending":
      return "lifecycle_pending";
    case "stopped":
      return "lifecycle_stopped";
    case "replaced":
      return "lifecycle_replaced";
    case "unbound":
      return "lifecycle_unbound";
    case "invalid":
      return "lifecycle_invalid";
  }
}

export function createSenderAuthorizer(options: {
  policy: SenderPolicyResolution;
  receivingAccountIdHex?: string | null;
  lifecycle?: SenderAuthorizerLifecycle;
}): MarmotSenderAuthorizer {
  let bound =
    typeof options.receivingAccountIdHex === "string"
      ? envelopeAccountId(options.receivingAccountIdHex)
      : null;
  let lifecycle: SenderAuthorizerLifecycle =
    options.lifecycle ?? (bound ? "active" : "unbound");
  if (options.policy.state === "invalid" && lifecycle === "active") {
    lifecycle = "invalid";
  }
  return {
    policy: options.policy,
    boundReceivingAccountIdHex: () => bound,
    lifecycle: () => lifecycle,
    bindReceivingAccount(accountIdHex: string): boolean {
      const parsed = envelopeAccountId(accountIdHex);
      if (parsed === null) {
        bound = null;
        lifecycle = "unbound";
        return false;
      }
      bound = parsed;
      if (lifecycle === "unbound" || lifecycle === "pending") {
        lifecycle = options.policy.state === "invalid" ? "invalid" : "active";
      }
      return true;
    },
    setLifecycle(next: SenderAuthorizerLifecycle): void {
      lifecycle = next;
    },
    authorize(input: SenderAuthorizationInput): SenderAuthorizationDecision {
      const blocked = lifecycleDeny(lifecycle);
      if (blocked) {
        return { outcome: "deny", reason: blocked };
      }
      const identity = authorizeSenderIdentity(input, bound);
      if (identity.outcome !== "identity") {
        return identity;
      }
      return decisionForPolicy(options.policy, identity.senderId);
    },
  };
}

export function authorizeInboundSender(
  authorizer: MarmotSenderAuthorizer | null | undefined,
  input: SenderAuthorizationInput,
): SenderAuthorizationDecision {
  if (!authorizer) {
    return { outcome: "deny", reason: "missing_authorizer" };
  }
  return authorizer.authorize(input);
}

export function senderAuthorizationInputFromMessage(message: {
  accountIdHex: unknown;
  senderAccountIdHex: unknown;
  sender?: SenderAuthorizationInput["sender"];
}): SenderAuthorizationInput {
  return {
    receivingAccountIdHex: message.accountIdHex,
    mappedSenderAccountIdHex: message.senderAccountIdHex,
    sender: message.sender,
  };
}
