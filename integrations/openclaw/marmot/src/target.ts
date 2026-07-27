// Outbound target canonicalization for Marmot MLS group ids.
//
// Every wn-agent send/delete path must receive bare lowercase even-length
// group-id hex (MLS GroupId is variable-length opaque bytes). Internal OpenClaw
// routes (including announce fallbacks) may arrive as `group:<hex>`; explicit
// agent targets may use bare hex or `marmot:<hex>`. Invalid forms are rejected
// locally with a privacy-safe category error — never forwarded to
// sendFinal/sendMedia/delete. Do not conflate MLS group ids with 32-byte Nostr
// routing ids.

/** Explicit cross-channel target prefix, e.g. `marmot:<groupIdHex>`. */
export const MARMOT_TARGET_PREFIX = "marmot";

const INTERNAL_GROUP_PREFIX = "group:";
const REJECTED_KIND_PREFIXES = [
  "user:",
  "channel:",
  "room:",
  "conversation:",
  "dm:",
] as const;

/** True for a non-empty even-length lowercase hex string (MLS group id bytes). */
export function isMarmotGroupIdHex(value: string): boolean {
  if (value.length === 0 || value.length % 2 !== 0) {
    return false;
  }
  return /^[0-9a-f]+$/.test(value);
}

export type MarmotTargetRejectCategory =
  | "empty"
  | "session_key"
  | "cross_channel"
  | "decorated_route"
  | "invalid_hex";

export function looksLikeMarmotSessionKey(value: string): boolean {
  const lower = value.toLowerCase();
  if (lower.startsWith("agent:")) {
    return true;
  }
  // Composite OpenClaw session routes embed the channel id between colons.
  return lower.includes(`:${MARMOT_TARGET_PREFIX}:`);
}

function looksLikeSessionKey(value: string): boolean {
  return looksLikeMarmotSessionKey(value);
}

export function looksLikeMarmotCrossChannelTarget(value: string): boolean {
  const match = /^([a-z][a-z0-9-]*):/.exec(value.toLowerCase());
  if (!match) {
    return false;
  }
  const prefix = match[1];
  return prefix !== MARMOT_TARGET_PREFIX && prefix !== "group";
}

function looksLikeCrossChannelTarget(value: string): boolean {
  return looksLikeMarmotCrossChannelTarget(value);
}

export function hasMarmotRejectedKindPrefix(value: string): boolean {
  const lower = value.toLowerCase();
  return REJECTED_KIND_PREFIXES.some((prefix) => lower.startsWith(prefix));
}

export function marmotTargetRejectMessage(category: MarmotTargetRejectCategory): string {
  switch (category) {
    case "empty":
      return "marmot: outbound target is required";
    case "session_key":
      return (
        "marmot: outbound target must be a Marmot group id, not an OpenClaw session key; " +
        "use bare group-id hex or marmot:<hex>"
      );
    case "cross_channel":
      return (
        "marmot: outbound target must stay on the Marmot channel; " +
        "use bare group-id hex, marmot:<hex>, or group:<hex>"
      );
    case "decorated_route":
      return (
        "marmot: outbound target is not a Marmot group id; " +
        "use bare group-id hex, marmot:<hex>, or group:<hex>"
      );
    case "invalid_hex":
      return (
        "marmot: outbound target must be even-length group-id hex " +
        "(optionally prefixed marmot: or group:)"
      );
  }
}

export class MarmotTargetError extends Error {
  readonly category: MarmotTargetRejectCategory;

  constructor(category: MarmotTargetRejectCategory) {
    super(marmotTargetRejectMessage(category));
    this.name = "MarmotTargetError";
    this.category = category;
  }
}

/**
 * Canonicalize a raw outbound target to bare group-id hex for wn-agent, or throw
 * {@link MarmotTargetError} when the value is not a Marmot group conversation id.
 */
export function canonicalizeMarmotGroupTarget(raw: string): string {
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed) {
    throw new MarmotTargetError("empty");
  }
  if (looksLikeSessionKey(trimmed)) {
    throw new MarmotTargetError("session_key");
  }
  if (hasMarmotRejectedKindPrefix(trimmed)) {
    throw new MarmotTargetError("decorated_route");
  }
  if (looksLikeCrossChannelTarget(trimmed)) {
    throw new MarmotTargetError("cross_channel");
  }

  let candidate = trimmed;
  if (candidate.startsWith(`${MARMOT_TARGET_PREFIX}:`)) {
    candidate = candidate.slice(MARMOT_TARGET_PREFIX.length + 1).trim();
    // Prefix composition is an internal/session route, not a channel target.
    if (candidate.includes(":")) {
      throw new MarmotTargetError("decorated_route");
    }
  } else if (candidate.startsWith(INTERNAL_GROUP_PREFIX)) {
    candidate = candidate.slice(INTERNAL_GROUP_PREFIX.length);
  }
  if (candidate.startsWith("0x")) {
    candidate = candidate.slice(2);
  }
  candidate = candidate.trim().toLowerCase();

  if (isMarmotGroupIdHex(candidate)) {
    return candidate;
  }
  throw new MarmotTargetError("invalid_hex");
}

/** Whether Marmot should own target resolution for this raw message-tool input. */
export function isMarmotOwnedTargetCandidate(raw: string): boolean {
  const trimmed = raw.trim();
  if (!trimmed) {
    return false;
  }
  const lower = trimmed.toLowerCase();
  if (lower.startsWith(`${MARMOT_TARGET_PREFIX}:`)) {
    return true;
  }
  if (lower.startsWith(INTERNAL_GROUP_PREFIX)) {
    return true;
  }
  if (looksLikeMarmotSessionKey(lower)) {
    return true;
  }
  if (hasMarmotRejectedKindPrefix(lower)) {
    return true;
  }
  if (looksLikeMarmotCrossChannelTarget(lower)) {
    return true;
  }
  return tryCanonicalizeMarmotGroupTarget(trimmed) !== undefined;
}

/** Best-effort normalize for target resolution; returns undefined when invalid. */
export function tryCanonicalizeMarmotGroupTarget(raw: string): string | undefined {
  try {
    return canonicalizeMarmotGroupTarget(raw);
  } catch (error) {
    if (error instanceof MarmotTargetError) {
      return undefined;
    }
    throw error;
  }
}
