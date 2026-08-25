import { createHash } from "node:crypto";

import { normalizeHex } from "./client.js";

const IDEMPOTENCY_KEY_PREFIX = "marmot-final-v1:";

export interface DurableFinalIdempotencyInput {
  sessionBinding: string;
  turnBinding: string;
  accountIdHex: string;
  groupIdHex: string;
  replyToMessageIdHex?: string | null;
  text: string;
}

export interface DurableFinalIdempotency {
  replyAnchor: string | null;
  contentFingerprint: string;
  idempotencyKey: string;
}

function requireNonEmpty(value: string, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${field} must not be empty`);
  }
  return value;
}

function normalizeReplyAnchor(value?: string | null): string | null {
  if (value == null || value.trim().length === 0) {
    return null;
  }
  return normalizeHex(value, "replyToMessageIdHex");
}

function rejectUnpairedSurrogates(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new TypeError("text contains an unpaired UTF-16 surrogate");
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new TypeError("text contains an unpaired UTF-16 surrogate");
    }
  }
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * Derive the connector-compatible durable-final key. Callers must pass host
 * identities that are persisted before the first send attempt; this function
 * never invents retry-local identity.
 */
export function deriveDurableFinalIdempotency(
  input: DurableFinalIdempotencyInput,
): DurableFinalIdempotency {
  const sessionBinding = requireNonEmpty(input.sessionBinding, "sessionBinding");
  const turnBinding = requireNonEmpty(input.turnBinding, "turnBinding");
  const accountIdHex = normalizeHex(input.accountIdHex, "accountIdHex");
  const groupIdHex = normalizeHex(input.groupIdHex, "groupIdHex");
  const replyAnchor = normalizeReplyAnchor(input.replyToMessageIdHex);
  if (typeof input.text !== "string") {
    throw new TypeError("text must be a string");
  }
  const text = input.text;
  rejectUnpairedSurrogates(text);

  const contentFingerprint = sha256Hex(
    JSON.stringify([1, accountIdHex, groupIdHex, text, replyAnchor]),
  );
  const keyPreimage = JSON.stringify([
    1,
    sessionBinding,
    turnBinding,
    replyAnchor,
    contentFingerprint,
  ]);

  return {
    replyAnchor,
    contentFingerprint,
    idempotencyKey: `${IDEMPOTENCY_KEY_PREFIX}${sha256Hex(keyPreimage)}`,
  };
}
