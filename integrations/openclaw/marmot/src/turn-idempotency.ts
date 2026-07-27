// Deterministic, versioned, privacy-preserving idempotency keys for one inbound
// turn's durable reply. Derived from account/group identity and the complete
// logical source-message set so a plugin process restart can safely replay the
// same wn-agent send_final without double-posting.

import { createHash } from "node:crypto";

import type { MarmotInboundMessage } from "./inbound.js";

const TURN_IDEMPOTENCY_DOMAIN = "openclaw.marmot.turn-reply.v1";

export interface DeriveTurnIdempotencyKeyParams {
  marmotAccountIdHex: string;
  groupIdHex: string;
  /** Primary inbound message id plus any coalesced source ids for this turn. */
  sourceMessageIdsHex: readonly string[];
}

function encodeLengthPrefixedUtf8(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const len = Buffer.alloc(2);
  len.writeUInt16BE(bytes.length);
  return Buffer.concat([len, bytes]);
}

function encodeLengthPrefixedHex(value: string): Buffer {
  const normalized = value.trim().toLowerCase();
  const bytes = Buffer.from(normalized, "hex");
  if (bytes.length === 0 || bytes.length * 2 !== normalized.length) {
    throw new Error("marmot: turn idempotency requires normalized hex ids");
  }
  const len = Buffer.alloc(2);
  len.writeUInt16BE(bytes.length);
  return Buffer.concat([len, bytes]);
}

/** Canonical sorted unique source ids for one logical inbound turn. */
export function canonicalizeTurnSourceMessageIds(
  primaryMessageIdHex: string,
  coalescedMessageIdsHex?: readonly string[],
): string[] {
  const ids = new Set<string>();
  const add = (value: string | undefined | null) => {
    const trimmed = value?.trim().toLowerCase();
    if (trimmed) {
      ids.add(trimmed);
    }
  };
  add(primaryMessageIdHex);
  for (const id of coalescedMessageIdsHex ?? []) {
    add(id);
  }
  return [...ids].sort();
}

/** Derive a stable idempotency key that does not expose raw account/group/message ids. */
export function deriveTurnIdempotencyKey(params: DeriveTurnIdempotencyKeyParams): string {
  const sourceIds = [...new Set(
    params.sourceMessageIdsHex.map((id) => id.trim().toLowerCase()).filter(Boolean),
  )].sort();
  if (sourceIds.length === 0) {
    throw new Error("marmot: turn idempotency requires at least one source message id");
  }
  const parts: Buffer[] = [
    encodeLengthPrefixedUtf8(TURN_IDEMPOTENCY_DOMAIN),
    encodeLengthPrefixedHex(params.marmotAccountIdHex),
    encodeLengthPrefixedHex(params.groupIdHex),
  ];
  const count = Buffer.alloc(2);
  count.writeUInt16BE(sourceIds.length);
  parts.push(count);
  for (const id of sourceIds) {
    parts.push(encodeLengthPrefixedHex(id));
  }
  return createHash("sha256").update(Buffer.concat(parts)).digest("hex");
}

export function deriveTurnIdempotencyKeyFromInbound(
  message: Pick<
    MarmotInboundMessage,
    "accountIdHex" | "groupIdHex" | "messageIdHex" | "coalescedMessageIdsHex"
  >,
): string {
  const sourceIds = canonicalizeTurnSourceMessageIds(
    message.messageIdHex,
    message.coalescedMessageIdsHex,
  );
  return deriveTurnIdempotencyKey({
    marmotAccountIdHex: message.accountIdHex,
    groupIdHex: message.groupIdHex,
    sourceMessageIdsHex: sourceIds,
  });
}
